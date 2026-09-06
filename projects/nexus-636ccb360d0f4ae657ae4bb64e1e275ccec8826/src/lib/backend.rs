use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
    SemanticMutationReceipt, SemanticMutationRelation,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace, TraceSignal};
use nexus_common::cpu::Registers;
use nexus_common::memory::{MemoryRecord, MemoryRecords};
use nexus_common::riscv::register::Register;
use nexus_vm::emulator::{Emulator, HarvardEmulator};
use nexus_vm::error::VMError;
use nexus_vm::trace::{Block, Step, UniformTrace};
use serde::{Deserialize, Serialize};

use crate::trace::NexusTrace;

const ZERO_REG_INJECT_KIND: &str = "nexus.semantic.decode.zero_register_immutability";
const OPERAND_ROUTING_INJECT_KIND: &str = "nexus.semantic.decode.operand_index_routing";
const DEST_BINDING_INJECT_KIND: &str = "nexus.semantic.exec.dest_binding";
const FIELD_RANGE_INJECT_KIND: &str = "nexus.semantic.decode.field_range";
const IMM_SIGNEXT_INJECT_KIND: &str = "nexus.semantic.decode.immediate_sign_extension";
const UPPER_IMM_INJECT_KIND: &str = "nexus.semantic.decode.upper_immediate_materialization";
const FORMAT_IMM_INJECT_KIND: &str = "nexus.semantic.decode.format_immediate_reassembly";
const OP_SELECTOR_INJECT_KIND: &str = "nexus.semantic.exec.op_selector_binding";
const ALU_IMM_INJECT_KIND: &str = "nexus.semantic.alu.immediate_limb_consistency";
const SHIFT_INJECT_KIND: &str = "nexus.semantic.alu.shift_mod32";
const CMP_BOOL_INJECT_KIND: &str = "nexus.semantic.alu.comparison_booleanity";
const SUB_BORROW_INJECT_KIND: &str = "nexus.semantic.alu.subtraction_borrow_chain";
const CMP_AUX_INJECT_KIND: &str = "nexus.semantic.alu.comparison_auxiliary_chain";
const CONTROL_FLOW_INJECT_KIND: &str = "nexus.semantic.exec.control_flow_binding";
const ENTRYPOINT_INJECT_KIND: &str = "nexus.semantic.control.entrypoint_binding";
const ECALL_WORD_INJECT_KIND: &str = "nexus.semantic.control.ecall_word_validity";
const TIME_BOUNDARY_INJECT_KIND: &str = "nexus.semantic.time.boundary_origin_consistency";
const ADDRESS_ALIGNMENT_INJECT_KIND: &str = "nexus.semantic.memory.address_alignment_consistency";
const LOAD_VALUE_INJECT_KIND: &str = "nexus.semantic.memory.load_value_binding";
const ADDRESS_POINTER_INJECT_KIND: &str = "nexus.semantic.memory.address_pointer_consistency";
const ADDRESS_PROGRESSION_INJECT_KIND: &str =
    "nexus.semantic.memory.address_progression_consistency";
const TIME_MONOTONIC_INJECT_KIND: &str = "nexus.semantic.time.monotonic_access_ordering";
const FLOW_PAYLOAD_INJECT_KIND: &str = "nexus.semantic.memory.store_load_payload_flow";
const WRITE_PAYLOAD_INJECT_KIND: &str = "nexus.semantic.memory.write_payload_consistency";
const KIND_SELECTOR_INJECT_KIND: &str = "nexus.semantic.memory.kind_selector_consistency";
const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";
const BEAK_NEXUS_SEMANTIC_RECEIPT_ENV: &str = "BEAK_NEXUS_SEMANTIC_MUTATION_RECEIPT";
pub const NEXUS_PRODUCTION_MAX_PROGRAM_WORDS: usize = 256;
pub const NEXUS_PRODUCTION_MAX_TRACE_STEPS: usize = 32;
pub const NEXUS_PRODUCTION_MAX_MEMORY_BYTES: usize = 256;
pub const NEXUS_PRODUCTION_MAX_PROVER_COMPONENT_ROWS: usize = 256;
const BEAK_NEXUS_STORE_LOAD_FLOW_ENV: [&str; 6] = [
    "BEAK_NEXUS_STORE_LOAD_FLOW_ADDR",
    "BEAK_NEXUS_STORE_LOAD_FLOW_CLK",
    "BEAK_NEXUS_STORE_LOAD_FLOW_BYTE",
    "BEAK_NEXUS_STORE_LOAD_FLOW_STORE_STEP",
    "BEAK_NEXUS_STORE_LOAD_FLOW_BEFORE",
    "BEAK_NEXUS_STORE_LOAD_FLOW_AFTER",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NexusProductionResourceRecord {
    pub program_words: usize,
    pub trace_steps: usize,
    pub memory_access_bytes: usize,
    pub prover_log_size: u32,
    pub prover_component_rows: usize,
    pub max_program_words: usize,
    pub max_trace_steps: usize,
    pub max_memory_bytes: usize,
    pub max_prover_component_rows: usize,
}

#[derive(Debug, Clone)]
struct WitnessInjectionPlan {
    kind: String,
    step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub backend_error: Option<String>,
    pub observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pub injection_applied: bool,
    #[serde(default)]
    pub semantic_mutation_receipt: Option<SemanticMutationReceipt>,
    #[serde(default)]
    pub executed_exception_receipt: Option<beak_core::fuzz::benchmark::ExecutedExceptionReceipt>,
    #[serde(default)]
    pub production_resource: Option<NexusProductionResourceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub request_id: u64,
    pub words: Vec<u32>,
    pub iteration: u64,
    pub inject_kind: Option<String>,
    pub inject_step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub request_id: u64,
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub backend_error: Option<String>,
    pub observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pub injection_applied: bool,
    #[serde(default)]
    pub semantic_mutation_receipt: Option<SemanticMutationReceipt>,
    #[serde(default)]
    pub executed_exception_receipt: Option<beak_core::fuzz::benchmark::ExecutedExceptionReceipt>,
    #[serde(default)]
    pub production_resource: Option<NexusProductionResourceRecord>,
}

impl WorkerResponse {
    pub fn from_run_response(request_id: u64, resp: RunResponse) -> Self {
        Self {
            request_id,
            final_regs: resp.final_regs,
            micro_op_count: resp.micro_op_count,
            bucket_hits: resp.bucket_hits,
            trace_signals: resp.trace_signals,
            backend_error: resp.backend_error,
            observed_injection_sites: resp.observed_injection_sites,
            injection_applied: resp.injection_applied,
            semantic_mutation_receipt: resp.semantic_mutation_receipt,
            executed_exception_receipt: resp.executed_exception_receipt,
            production_resource: resp.production_resource,
        }
    }

    pub fn error(request_id: u64, error: String) -> Self {
        Self {
            request_id,
            final_regs: None,
            micro_op_count: 0,
            bucket_hits: Vec::new(),
            trace_signals: Vec::new(),
            backend_error: Some(error),
            observed_injection_sites: BTreeMap::new(),
            injection_applied: false,
            semantic_mutation_receipt: None,
            executed_exception_receipt: None,
            production_resource: None,
        }
    }
}

const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";

fn panic_payload_to_string(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        return format!("panic: {s}");
    }
    if let Some(s) = p.downcast_ref::<String>() {
        return format!("panic: {s}");
    }
    "panic: non-string payload".to_string()
}

fn catch_unwind_nonfatal<T, F>(f: F) -> std::thread::Result<T>
where
    F: FnOnce() -> T + std::panic::UnwindSafe,
{
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_panic_info| {}));
    let res = std::panic::catch_unwind(f);
    std::panic::set_hook(prev_hook);
    res
}

fn record_site(sites: &mut BTreeMap<String, Vec<u64>>, kind: &str, step: u64) {
    let steps = sites.entry(kind.to_string()).or_default();
    if steps.last().copied() != Some(step) {
        steps.push(step);
    }
}

fn is_i_alu_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai"
    )
}

fn is_shift_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sll" | "slli" | "srl" | "srli" | "sra" | "srai")
}

fn is_comparison_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "slt" | "slti" | "sltu" | "sltiu")
}

fn is_supported_sub_borrow_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sub" | "slt" | "slti" | "sltu" | "sltiu")
}

fn is_format_imm_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sb" | "sh" | "sw" | "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "jal")
}

fn collect_observed_injection_sites(trace: &UniformTrace) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    let mut flat_step = 0u64;
    for block in &trace.blocks {
        for step in &block.steps {
            if let Some(decoded) = RV32IMInstruction::decode_with_pc(step.raw_instruction, step.pc)
            {
                let mnemonic = decoded.mnemonic.as_str();
                record_site(&mut sites, FIELD_RANGE_INJECT_KIND, flat_step);
                record_site(&mut sites, OP_SELECTOR_INJECT_KIND, flat_step);
                record_site(&mut sites, OPERAND_ROUTING_INJECT_KIND, flat_step);
                if decoded.rd.is_some() {
                    record_site(&mut sites, ZERO_REG_INJECT_KIND, flat_step);
                    record_site(&mut sites, DEST_BINDING_INJECT_KIND, flat_step);
                }
                if decoded.imm.is_some() {
                    record_site(&mut sites, IMM_SIGNEXT_INJECT_KIND, flat_step);
                }
                if matches!(mnemonic, "lui" | "auipc") {
                    record_site(&mut sites, UPPER_IMM_INJECT_KIND, flat_step);
                }
                if is_format_imm_mnemonic(mnemonic) {
                    record_site(&mut sites, FORMAT_IMM_INJECT_KIND, flat_step);
                }
                if is_i_alu_mnemonic(mnemonic) {
                    record_site(&mut sites, ALU_IMM_INJECT_KIND, flat_step);
                }
                if is_shift_mnemonic(mnemonic) {
                    record_site(&mut sites, SHIFT_INJECT_KIND, flat_step);
                }
                if is_comparison_mnemonic(mnemonic) {
                    record_site(&mut sites, CMP_BOOL_INJECT_KIND, flat_step);
                    record_site(&mut sites, CMP_AUX_INJECT_KIND, flat_step);
                }
                if is_supported_sub_borrow_mnemonic(mnemonic) {
                    record_site(&mut sites, SUB_BORROW_INJECT_KIND, flat_step);
                }
                record_site(&mut sites, CONTROL_FLOW_INJECT_KIND, flat_step);
                if mnemonic == "ecall" {
                    record_site(&mut sites, ECALL_WORD_INJECT_KIND, flat_step);
                }
                if flat_step == 0 {
                    record_site(&mut sites, ENTRYPOINT_INJECT_KIND, flat_step);
                    record_site(&mut sites, TIME_BOUNDARY_INJECT_KIND, flat_step);
                }
            }
            if step
                .memory_records
                .iter()
                .any(|record| matches!(record, MemoryRecord::StoreRecord(_, _)))
            {
                record_site(&mut sites, WRITE_PAYLOAD_INJECT_KIND, flat_step);
                record_site(&mut sites, FLOW_PAYLOAD_INJECT_KIND, flat_step);
            }
            if step.memory_records.iter().any(|record| {
                matches!(record, MemoryRecord::StoreRecord(_, _) | MemoryRecord::LoadRecord(_, _))
            }) {
                record_site(&mut sites, KIND_SELECTOR_INJECT_KIND, flat_step);
                record_site(&mut sites, ADDRESS_ALIGNMENT_INJECT_KIND, flat_step);
                record_site(&mut sites, ADDRESS_POINTER_INJECT_KIND, flat_step);
                record_site(&mut sites, ADDRESS_PROGRESSION_INJECT_KIND, flat_step);
                record_site(&mut sites, TIME_MONOTONIC_INJECT_KIND, flat_step);
            }
            if step
                .memory_records
                .iter()
                .any(|record| matches!(record, MemoryRecord::LoadRecord(_, _)))
            {
                record_site(&mut sites, LOAD_VALUE_INJECT_KIND, flat_step);
            }
            flat_step = flat_step.saturating_add(1);
        }
    }
    sites
}

fn read_prover_injection_applied() -> bool {
    std::env::var(BEAK_NEXUS_INJECTION_APPLIED_ENV).ok().as_deref() == Some("true")
}

fn read_semantic_mutation_receipt(
    expected_kind: Option<&str>,
    expected_step: u64,
    executed_hits: &[BucketHit],
) -> Option<SemanticMutationReceipt> {
    if expected_kind != Some(FLOW_PAYLOAD_INJECT_KIND) {
        return None;
    }
    let raw = std::env::var(BEAK_NEXUS_SEMANTIC_RECEIPT_ENV).ok()?;
    let receipt = serde_json::from_str::<SemanticMutationReceipt>(&raw).ok()?;
    if receipt.inject_kind != expected_kind?
        || (expected_step != u64::MAX && receipt.step != expected_step)
        || !valid_store_load_payload_receipt(&receipt)
        || !receipt_matches_unique_store_load_hit(&receipt, executed_hits)
    {
        return None;
    }
    Some(receipt)
}

fn valid_store_load_payload_equation(receipt: &SemanticMutationReceipt) -> bool {
    let context = &receipt.effect.context;
    let string = |key: &str| context.get(key).and_then(|value| value.as_str());
    let number = |key: &str| context.get(key).and_then(|value| value.as_u64());
    if receipt.inject_kind != FLOW_PAYLOAD_INJECT_KIND
        || receipt.site != "load_store.store_value_lower_byte"
        || receipt.field != "load_store.payload"
        || receipt.effect.relation != SemanticMutationRelation::StoreLoadPayloadEquation
        || string("bucket_id") != Some("sem.memory.store_load_payload_flow")
        || string("obligation_id") != Some("me1")
        || string("cell_id") != Some("me1.sw_lw")
        || string("backend") != Some("nexus")
        || string("commit") != Some("636ccb360d0f4ae657ae4bb64e1e275ccec8826")
        || string("trace_source") != Some("memory")
        || string("mutation_mode") != Some("replace_low_byte_5a_a5")
        || string("manifestation") != Some("store_and_load_payload_changed")
        || context.get("executed_store").and_then(|value| value.as_bool()) != Some(true)
        || context.get("executed_load").and_then(|value| value.as_bool()) != Some(true)
    {
        return false;
    }
    let (
        Some(store_step),
        Some(load_step),
        Some(store_timestamp),
        Some(load_timestamp),
        Some(store_pc),
        Some(load_pc),
        Some(store_raw_word),
        Some(load_raw_word),
        Some(store_address),
        Some(load_address),
        Some(store_width),
        Some(load_width),
        Some(store_value),
        Some(store_before),
        Some(store_after),
        Some(load_before),
        Some(load_after),
    ) = (
        number("store_step_idx"),
        number("load_step_idx"),
        number("store_timestamp"),
        number("load_timestamp"),
        number("store_pc"),
        number("load_pc"),
        number("store_raw_word"),
        number("load_raw_word"),
        number("store_address"),
        number("load_address"),
        number("store_width"),
        number("load_width"),
        number("store_value"),
        number("store_value_before"),
        number("store_value_after"),
        number("load_value_before"),
        number("load_value_after"),
    )
    else {
        return false;
    };
    if [
        store_pc,
        load_pc,
        store_raw_word,
        load_raw_word,
        store_address,
        load_address,
        store_value,
        store_before,
        store_after,
        load_before,
        load_after,
    ]
        .iter()
        .any(|value| *value > u32::MAX as u64)
    {
        return false;
    }
    let store_opcode = format!("0x{store_raw_word:08x}");
    let load_opcode = format!("0x{load_raw_word:08x}");
    let expected_low = if store_before as u8 == 0x5a { 0xa5 } else { 0x5a };
    let expected_after = (store_before & 0xffff_ff00) | expected_low;
    store_step == receipt.step
        && store_step < load_step
        && store_timestamp < load_timestamp
        && store_pc != load_pc
        && store_raw_word & 0x7f == 0x23
        && (store_raw_word >> 12) & 0x7 == 2
        && load_raw_word & 0x7f == 0x03
        && (load_raw_word >> 12) & 0x7 == 2
        && string("store_opcode") == Some(store_opcode.as_str())
        && string("load_opcode") == Some(load_opcode.as_str())
        && string("store_mnemonic") == Some("sw")
        && string("load_mnemonic") == Some("lw")
        && store_address == load_address
        && store_width == 4
        && load_width == 4
        && store_value == store_before
        && store_before == load_before
        && store_after == expected_after
        && store_after == load_after
        && store_after != store_before
        && receipt.before.as_u64() == Some(store_before)
        && receipt.after.as_u64() == Some(store_after)
}

fn store_load_hit_matches_receipt(hit: &BucketHit, receipt: &SemanticMutationReceipt) -> bool {
    let context = &receipt.effect.context;
    let string = |key: &str| context.get(key).and_then(|value| value.as_str());
    let number = |key: &str| context.get(key).and_then(|value| value.as_u64());
    hit.bucket_id == "sem.memory.store_load_payload_flow"
        && detail_str(hit, "obligation_id") == Some("me1")
        && detail_str(hit, "cell_id") == Some("me1.sw_lw")
        && detail_str(hit, "backend") == Some("nexus")
        && detail_str(hit, "commit") == Some("636ccb360d0f4ae657ae4bb64e1e275ccec8826")
        && detail_str(hit, "trace_source") == Some("memory")
        && detail_str(hit, "mnemonic") == Some("sw")
        && detail_str(hit, "load_mnemonic") == Some("lw")
        && detail_u64(hit, "op_idx") == number("store_step_idx")
        && detail_u64(hit, "step_idx") == number("store_step_idx")
        && detail_u64(hit, "store_step_idx") == number("store_step_idx")
        && detail_u64(hit, "load_step_idx") == number("load_step_idx")
        && detail_u64(hit, "timestamp") == number("store_timestamp")
        && detail_u64(hit, "store_timestamp") == number("store_timestamp")
        && detail_u64(hit, "load_timestamp") == number("load_timestamp")
        && detail_u64(hit, "pc") == number("store_pc")
        && detail_u64(hit, "store_pc") == number("store_pc")
        && detail_u64(hit, "load_pc") == number("load_pc")
        && detail_u64(hit, "raw_word") == number("store_raw_word")
        && detail_u64(hit, "store_raw_word") == number("store_raw_word")
        && detail_u64(hit, "load_raw_word") == number("load_raw_word")
        && detail_str(hit, "opcode") == string("store_opcode")
        && detail_str(hit, "store_opcode") == string("store_opcode")
        && detail_str(hit, "load_opcode") == string("load_opcode")
        && detail_str(hit, "store_mnemonic") == string("store_mnemonic")
        && detail_str(hit, "load_mnemonic") == string("load_mnemonic")
        && detail_u64(hit, "effective_ptr") == number("store_address")
        && detail_u64(hit, "store_address") == number("store_address")
        && detail_u64(hit, "store_effective_ptr") == number("store_address")
        && detail_u64(hit, "load_address") == number("load_address")
        && detail_u64(hit, "load_effective_ptr") == number("load_address")
        && detail_u64(hit, "width") == number("store_width")
        && detail_u64(hit, "store_width") == number("store_width")
        && detail_u64(hit, "load_width") == number("load_width")
        && detail_u64(hit, "write_data") == number("store_value")
        && detail_u64(hit, "store_value") == number("store_value")
        && detail_u64(hit, "store_value_before") == number("store_value_before")
        && detail_u64(hit, "read_data") == number("load_value_before")
        && detail_u64(hit, "load_value_before") == number("load_value_before")
}

fn receipt_matches_unique_store_load_hit(
    receipt: &SemanticMutationReceipt,
    executed_hits: &[BucketHit],
) -> bool {
    let mut matches = executed_hits
        .iter()
        .filter(|hit| store_load_hit_matches_receipt(hit, receipt));
    matches.next().is_some() && matches.next().is_none()
}

fn valid_store_load_payload_receipt(receipt: &SemanticMutationReceipt) -> bool {
    valid_store_load_payload_equation(receipt)
}

fn arm_prover_injection_env(inject_kind: Option<&str>, inject_step: u64) -> EnvRestore {
    let previous_kind = std::env::var(BEAK_NEXUS_INJECT_KIND_ENV).ok();
    let previous_step = std::env::var(BEAK_NEXUS_INJECT_STEP_ENV).ok();
    let previous_applied = std::env::var(BEAK_NEXUS_INJECTION_APPLIED_ENV).ok();
    let previous_receipt = std::env::var(BEAK_NEXUS_SEMANTIC_RECEIPT_ENV).ok();
    let previous_flow = BEAK_NEXUS_STORE_LOAD_FLOW_ENV.map(|key| std::env::var(key).ok());
    std::env::remove_var(BEAK_NEXUS_INJECTION_APPLIED_ENV);
    std::env::remove_var(BEAK_NEXUS_SEMANTIC_RECEIPT_ENV);
    for key in BEAK_NEXUS_STORE_LOAD_FLOW_ENV {
        std::env::remove_var(key);
    }
    if let Some(kind) = inject_kind {
        std::env::set_var(BEAK_NEXUS_INJECT_KIND_ENV, kind);
        std::env::set_var(BEAK_NEXUS_INJECT_STEP_ENV, inject_step.to_string());
    } else {
        std::env::remove_var(BEAK_NEXUS_INJECT_KIND_ENV);
        std::env::remove_var(BEAK_NEXUS_INJECT_STEP_ENV);
    }
    EnvRestore { previous_kind, previous_step, previous_applied, previous_receipt, previous_flow }
}

struct EnvRestore {
    previous_kind: Option<String>,
    previous_step: Option<String>,
    previous_applied: Option<String>,
    previous_receipt: Option<String>,
    previous_flow: [Option<String>; 6],
}

impl EnvRestore {
    fn restore(self) {
        restore_env(BEAK_NEXUS_INJECT_KIND_ENV, self.previous_kind);
        restore_env(BEAK_NEXUS_INJECT_STEP_ENV, self.previous_step);
        restore_env(BEAK_NEXUS_INJECTION_APPLIED_ENV, self.previous_applied);
        restore_env(BEAK_NEXUS_SEMANTIC_RECEIPT_ENV, self.previous_receipt);
        for (key, value) in BEAK_NEXUS_STORE_LOAD_FLOW_ENV.into_iter().zip(self.previous_flow) {
            restore_env(key, value);
        }
    }
}

fn restore_env(key: &str, value: Option<String>) {
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}

fn validate_production_program(words: &[u32]) -> Result<(), String> {
    if words.is_empty() {
        return Err("nexus production resource guard: empty program".to_string());
    }
    if words.len() > NEXUS_PRODUCTION_MAX_PROGRAM_WORDS {
        return Err(format!(
            "nexus production resource guard: {} program words exceed limit {}",
            words.len(),
            NEXUS_PRODUCTION_MAX_PROGRAM_WORDS,
        ));
    }
    if words.iter().any(|word| RV32IMInstruction::decode(*word).is_none()) {
        return Err("nexus production resource guard: program is not RV32IM".to_string());
    }
    Ok(())
}

fn fetch_next_instruction(
    emulator: &mut HarvardEmulator,
) -> Result<Option<(u32, nexus_vm::riscv::Instruction)>, String> {
    let pc = emulator.get_executor().cpu.pc.value;
    let entry = match emulator.fetch_block(pc) {
        Ok(entry) => entry,
        Err(VMError::VMOutOfInstructions) => return Ok(None),
        Err(error) => return Err(format!("nexus instruction fetch failed: {error}")),
    };
    let byte_offset = pc.checked_sub(entry.start).ok_or_else(|| {
        format!(
            "nexus production resource guard: pc 0x{pc:08x} precedes block 0x{:08x}",
            entry.start,
        )
    })? as usize;
    if byte_offset % nexus_vm::WORD_SIZE != 0 {
        return Err(format!(
            "nexus production resource guard: unaligned pc 0x{pc:08x}",
        ));
    }
    let word_offset = byte_offset / nexus_vm::WORD_SIZE;
    let instruction = entry.block.0.get(word_offset).cloned().ok_or_else(|| {
        format!(
            "nexus production resource guard: pc 0x{pc:08x} is outside decoded block",
        )
    })?;
    Ok(Some((pc, instruction)))
}

fn add_memory_access_bytes(total: &mut usize, records: &MemoryRecords) -> Result<(), String> {
    let added = records.iter().try_fold(0usize, |sum, record| {
        sum.checked_add(record.get_size() as usize)
    });
    *total = total
        .checked_add(added.ok_or_else(|| {
            "nexus production resource guard: memory byte count overflow".to_string()
        })?)
        .ok_or_else(|| {
            "nexus production resource guard: memory byte count overflow".to_string()
        })?;
    if *total > NEXUS_PRODUCTION_MAX_MEMORY_BYTES {
        return Err(format!(
            "nexus production resource guard: {total} memory-access bytes exceed limit {}",
            NEXUS_PRODUCTION_MAX_MEMORY_BYTES,
        ));
    }
    Ok(())
}

fn final_regs(emulator: &HarvardEmulator) -> [u32; 32] {
    let mut out = [0u32; 32];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = emulator.get_executor().cpu.registers.read(Register::from(idx as u8));
    }
    out
}

fn execute_final_regs(words: &[u32]) -> Result<[u32; 32], String> {
    validate_production_program(words)?;
    let program = nexus_vm::riscv::decode_instructions(words);
    let mut emulator = HarvardEmulator::from_basic_blocks(&program.blocks);
    let mut executed_steps = 0usize;
    let mut memory_access_bytes = 0usize;
    loop {
        let Some((_pc, instruction)) = fetch_next_instruction(&mut emulator)? else {
            break;
        };
        if executed_steps == NEXUS_PRODUCTION_MAX_TRACE_STEPS {
            return Err(format!(
                "nexus production resource guard: execution exceeds {} steps",
                NEXUS_PRODUCTION_MAX_TRACE_STEPS,
            ));
        }
        match emulator.execute_instruction(&instruction, false) {
            Ok((_result, records)) => {
                add_memory_access_bytes(&mut memory_access_bytes, &records)?;
                executed_steps += 1;
            }
            Err(VMError::VMExited(_)) => {
                executed_steps += 1;
                break;
            }
            Err(error) => return Err(format!("nexus execute failed: {error}")),
        }
    }
    Ok(final_regs(&emulator))
}

fn bounded_uniform_trace(words: &[u32]) -> Result<(nexus_vm::emulator::View, UniformTrace, usize), String> {
    validate_production_program(words)?;
    let program = nexus_vm::riscv::decode_instructions(words);
    let mut emulator = HarvardEmulator::from_basic_blocks(&program.blocks);
    let mut trace = UniformTrace {
        memory_layout: Default::default(),
        k: 1,
        start: 0,
        blocks: Vec::new(),
    };
    let mut memory_access_bytes = 0usize;

    loop {
        let starting_regs = emulator.get_executor().cpu.registers;
        let Some((pc, instruction)) = fetch_next_instruction(&mut emulator)? else {
            break;
        };
        if trace.blocks.len() == NEXUS_PRODUCTION_MAX_TRACE_STEPS {
            return Err(format!(
                "nexus production resource guard: trace exceeds {} steps",
                NEXUS_PRODUCTION_MAX_TRACE_STEPS,
            ));
        }
        let timestamp = emulator.get_executor().global_clock as u32;
        match emulator.execute_instruction(&instruction, true) {
            Ok((result, memory_records)) => {
                add_memory_access_bytes(&mut memory_access_bytes, &memory_records)?;
                let next_pc = emulator.get_executor().cpu.pc.value;
                trace.blocks.push(Block {
                    regs: starting_regs,
                    steps: vec![Step {
                        timestamp,
                        pc,
                        next_pc,
                        raw_instruction: instruction.encode(),
                        instruction,
                        result,
                        memory_records,
                    }],
                });
            }
            Err(VMError::VMExited(_)) => {
                trace.blocks.push(Block {
                    regs: starting_regs,
                    steps: vec![Step {
                        timestamp,
                        pc,
                        next_pc: pc,
                        raw_instruction: instruction.encode(),
                        instruction,
                        result: None,
                        memory_records: MemoryRecords::default(),
                    }],
                });
                break;
            }
            Err(error) => return Err(format!("nexus trace execution failed: {error}")),
        }
    }

    Ok((emulator.finalize(), trace, memory_access_bytes))
}

fn production_resource_record(
    program_words: usize,
    trace_steps: usize,
    memory_access_bytes: usize,
) -> Result<NexusProductionResourceRecord, String> {
    let max_rows_input = program_words.max(trace_steps).max(1).next_power_of_two();
    let prover_log_size = max_rows_input
        .trailing_zeros()
        .max(nexus_vm_prover::trace::PreprocessedTraces::MIN_LOG_SIZE);
    let prover_component_rows = 1usize.checked_shl(prover_log_size).ok_or_else(|| {
        "nexus production resource guard: prover row calculation overflow".to_string()
    })?;
    if prover_component_rows > NEXUS_PRODUCTION_MAX_PROVER_COMPONENT_ROWS {
        return Err(format!(
            "nexus production resource guard: {prover_component_rows} prover rows exceed limit {}",
            NEXUS_PRODUCTION_MAX_PROVER_COMPONENT_ROWS,
        ));
    }
    Ok(NexusProductionResourceRecord {
        program_words,
        trace_steps,
        memory_access_bytes,
        prover_log_size,
        prover_component_rows,
        max_program_words: NEXUS_PRODUCTION_MAX_PROGRAM_WORDS,
        max_trace_steps: NEXUS_PRODUCTION_MAX_TRACE_STEPS,
        max_memory_bytes: NEXUS_PRODUCTION_MAX_MEMORY_BYTES,
        max_prover_component_rows: NEXUS_PRODUCTION_MAX_PROVER_COMPONENT_ROWS,
    })
}

pub fn run_backend_once(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RunResponse, String> {
    let final_regs = execute_final_regs(words)?;

    let (view, trace, memory_access_bytes) = bounded_uniform_trace(words)?;
    let trace_steps = trace.blocks.iter().map(|block| block.steps.len()).sum();
    let production_resource =
        production_resource_record(words.len(), trace_steps, memory_access_bytes)?;

    let observed_injection_sites = collect_observed_injection_sites(&trace);
    let derived = NexusTrace::from_words_and_uniform_trace(words, &trace);
    let env_restore = arm_prover_injection_env(inject_kind, inject_step);
    let backend_error = match catch_unwind_nonfatal(std::panic::AssertUnwindSafe(|| {
        match nexus_vm_prover::prove(&trace, &view) {
            Ok(proof) => nexus_vm_prover::verify(proof, &view)
                .err()
                .map(|e| format!("nexus verify failed: {e}")),
            Err(e) => Some(format!("nexus prove failed: {e}")),
        }
    })) {
        Ok(err) => err,
        Err(payload) => Some(panic_payload_to_string(&*payload)),
    };
    let injection_applied = read_prover_injection_applied();
    let semantic_mutation_receipt = read_semantic_mutation_receipt(
        inject_kind,
        inject_step,
        derived.bucket_hits(),
    );
    env_restore.restore();

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count: derived.step_count(),
        bucket_hits: derived.bucket_hits().to_vec(),
        trace_signals: derived.trace_signals().to_vec(),
        backend_error,
        observed_injection_sites,
        injection_applied,
        semantic_mutation_receipt,
        executed_exception_receipt: None,
        production_resource: Some(production_resource),
    })
}

struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    responses_rx: Receiver<Result<WorkerResponse, String>>,
    reader_thread: JoinHandle<()>,
}

pub struct NexusBackend {
    max_instructions: usize,
    eval: BackendEval,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    current_iteration: u64,
    next_request_id: u64,
    pending_injection: Option<WitnessInjectionPlan>,
    worker: Option<WorkerProcess>,
}

impl NexusBackend {
    pub fn new(max_instructions: usize) -> Self {
        Self {
            max_instructions,
            eval: BackendEval::default(),
            last_observed_injection_sites: BTreeMap::new(),
            current_iteration: 0,
            next_request_id: 1,
            pending_injection: None,
            worker: None,
        }
    }

    fn start_worker(&mut self) -> Result<(), String> {
        if self.worker.is_some() {
            return Ok(());
        }
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("resolve current executable for worker failed: {e}"))?;
        let mut child = Command::new(exe_path)
            .arg("--worker-loop")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn backend worker failed: {e}"))?;

        let stdin =
            child.stdin.take().ok_or_else(|| "capture backend worker stdin failed".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "capture backend worker stdout failed".to_string())?;

        let (tx, rx) = mpsc::channel::<Result<WorkerResponse, String>>();
        let reader_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || !trimmed.starts_with(WORKER_RESPONSE_PREFIX) {
                            continue;
                        }
                        let payload = &trimmed[WORKER_RESPONSE_PREFIX.len()..];
                        let parsed = serde_json::from_str::<WorkerResponse>(payload).map_err(|e| {
                            let mut preview = payload.chars().take(200).collect::<String>();
                            if payload.chars().count() > 200 {
                                preview.push_str("...");
                            }
                            format!("parse worker response failed: {e}; raw={preview:?}")
                        });
                        if tx.send(parsed).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("read worker response failed: {e}")));
                        break;
                    }
                }
            }
        });

        self.worker = Some(WorkerProcess { child, stdin, responses_rx: rx, reader_thread });
        Ok(())
    }

    fn stop_worker(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            let _ = worker.child.kill();
            let _ = worker.child.wait();
            drop(worker.stdin);
            let _ = worker.reader_thread.join();
        }
    }
}

impl BenchmarkBackend for NexusBackend {
    fn is_usable_seed(&self, words: &[u32]) -> bool {
        if words.is_empty()
            || words.len() > self.max_instructions.min(NEXUS_PRODUCTION_MAX_PROGRAM_WORDS)
        {
            return false;
        }
        words.iter().all(|w| RV32IMInstruction::decode(*w).is_some())
    }

    fn prepare_for_run(&mut self, _rng_seed: u64) {
        self.eval = BackendEval::default();
        self.last_observed_injection_sites.clear();
        self.current_iteration = self.current_iteration.saturating_add(1);
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval = BackendEval::default();
        self.start_worker()?;
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        let req = WorkerRequest {
            request_id,
            words: words.to_vec(),
            iteration: self.current_iteration,
            inject_kind: self.pending_injection.as_ref().map(|p| p.kind.clone()),
            inject_step: self.pending_injection.as_ref().map(|p| p.step).unwrap_or(0),
        };
        {
            let worker =
                self.worker.as_mut().ok_or_else(|| "backend worker unavailable".to_string())?;
            let mut payload = serde_json::to_vec(&req)
                .map_err(|e| format!("serialize worker request failed: {e}"))?;
            payload.push(b'\n');
            worker
                .stdin
                .write_all(&payload)
                .map_err(|e| format!("write worker request failed: {e}"))?;
            worker.stdin.flush().map_err(|e| format!("flush worker request failed: {e}"))?;
        }

        let resp = loop {
            let recv = {
                let worker =
                    self.worker.as_ref().ok_or_else(|| "backend worker unavailable".to_string())?;
                worker.responses_rx.recv()
            };
            match recv {
                Ok(Ok(resp)) if resp.request_id == request_id => break resp,
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => {
                    self.stop_worker();
                    self.eval.backend_error = Some(e.clone());
                    return Err(e);
                }
                Err(_) => {
                    self.stop_worker();
                    let msg = "backend worker disconnected".to_string();
                    self.eval.backend_error = Some(msg.clone());
                    return Err(msg);
                }
            }
        };
        self.stop_worker();
        self.last_observed_injection_sites = resp.observed_injection_sites;
        self.eval.final_regs = resp.final_regs;
        self.eval.micro_op_count = resp.micro_op_count;
        self.eval.bucket_hits = resp.bucket_hits;
        self.eval.trace_signals = resp.trace_signals;
        self.eval.backend_error = resp.backend_error;
        self.eval.semantic_injection_applied = resp.injection_applied;
        self.eval.semantic_mutation_receipt = resp.semantic_mutation_receipt;
        self.eval.executed_exception_receipt = resp.executed_exception_receipt;
        resp.final_regs.ok_or_else(|| "nexus backend returned no final_regs".to_string())
    }

    fn collect_eval(&mut self) -> BackendEval {
        self.eval.clone()
    }

    fn clear_semantic_injection(&mut self) {
        self.pending_injection = None;
    }

    fn arm_semantic_injection(&mut self, kind: &str, step: u64) -> Result<(), String> {
        self.pending_injection = Some(WitnessInjectionPlan { kind: kind.to_string(), step });
        Ok(())
    }

    fn semantic_injection_candidates(&self, hits: &[BucketHit]) -> Vec<SemanticInjectionCandidate> {
        hits.iter().filter_map(candidate_from_hit).collect()
    }

    fn semantic_mutation_relation(
        &self,
        candidate: &SemanticInjectionCandidate,
    ) -> Option<SemanticMutationRelation> {
        (candidate.inject_kind == FLOW_PAYLOAD_INJECT_KIND
            && candidate.bucket_id == "sem.memory.store_load_payload_flow"
            && candidate.semantic_class == "semantic.memory.write_payload_flow_consistency"
            && matches!(candidate.schedule, InjectionSchedule::Exact(_)))
            .then_some(SemanticMutationRelation::StoreLoadPayloadEquation)
    }
}

impl Drop for NexusBackend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}

fn candidate_from_hit(hit: &BucketHit) -> Option<SemanticInjectionCandidate> {
    let mnemonic = detail_str(hit, "mnemonic");
    let (inject_kind, semantic_class) = match hit.bucket_id.as_str() {
        "sem.decode.zero_register_immutability" => {
            (ZERO_REG_INJECT_KIND, "semantic.decode.zero_register_immutability")
        }
        "sem.decode.operand_index_routing" => {
            (OPERAND_ROUTING_INJECT_KIND, "semantic.decode.operand_index_routing")
        }
        "sem.exec.dest_binding" => (DEST_BINDING_INJECT_KIND, "semantic.exec.dest_binding"),
        "sem.decode.field_range" => (FIELD_RANGE_INJECT_KIND, "semantic.decode.field_range"),
        "sem.decode.immediate_sign_extension" => {
            (IMM_SIGNEXT_INJECT_KIND, "semantic.decode.immediate_sign_extension")
        }
        "sem.decode.upper_immediate_materialization" => {
            (UPPER_IMM_INJECT_KIND, "semantic.decode.upper_immediate_materialization")
        }
        "sem.decode.format_immediate_reassembly" => {
            (FORMAT_IMM_INJECT_KIND, "semantic.decode.format_immediate_reassembly")
        }
        "sem.exec.op_selector_binding" => {
            (OP_SELECTOR_INJECT_KIND, "semantic.exec.op_selector_binding")
        }
        "sem.alu.immediate_limb_consistency" => {
            (ALU_IMM_INJECT_KIND, "semantic.alu.immediate_limb_consistency")
        }
        "sem.alu.shift_mod32" if mnemonic.is_some_and(is_shift_mnemonic) => {
            (SHIFT_INJECT_KIND, "semantic.alu.shift_mod32")
        }
        "sem.alu.comparison_booleanity" if mnemonic.is_some_and(is_comparison_mnemonic) => {
            (CMP_BOOL_INJECT_KIND, "semantic.alu.comparison_booleanity")
        }
        "sem.alu.subtraction_borrow_chain"
            if mnemonic.is_some_and(is_supported_sub_borrow_mnemonic) =>
        {
            (SUB_BORROW_INJECT_KIND, "semantic.alu.subtraction_borrow_chain")
        }
        "sem.alu.comparison_auxiliary_chain" if mnemonic.is_some_and(is_comparison_mnemonic) => {
            (CMP_AUX_INJECT_KIND, "semantic.alu.comparison_auxiliary_chain")
        }
        "sem.exec.control_flow_binding" => {
            (CONTROL_FLOW_INJECT_KIND, "semantic.exec.control_flow_binding")
        }
        "sem.control.entrypoint_binding" => {
            (ENTRYPOINT_INJECT_KIND, "semantic.control.entrypoint_binding")
        }
        "sem.control.ecall_word_validity" => {
            (ECALL_WORD_INJECT_KIND, "semantic.control.ecall_word_validity")
        }
        "sem.time.boundary_origin_consistency" => {
            (TIME_BOUNDARY_INJECT_KIND, "semantic.time.boundary_origin_consistency")
        }
        "sem.memory.address_alignment_consistency" => {
            (ADDRESS_ALIGNMENT_INJECT_KIND, "semantic.memory.address_alignment_consistency")
        }
        "sem.memory.load_value_binding" => {
            (LOAD_VALUE_INJECT_KIND, "semantic.memory.load_value_binding")
        }
        "sem.memory.address_boundary_range" => {
            (ADDRESS_POINTER_INJECT_KIND, "semantic.memory.address_boundary_range")
        }
        "sem.memory.address_progression_consistency" => {
            (ADDRESS_PROGRESSION_INJECT_KIND, "semantic.memory.address_progression_consistency")
        }
        "sem.time.monotonic_access_ordering" => {
            (TIME_MONOTONIC_INJECT_KIND, "semantic.time.monotonic_access_ordering")
        }
        "sem.memory.store_load_payload_flow" if exact_store_load_hit(hit) => {
            (FLOW_PAYLOAD_INJECT_KIND, "semantic.memory.write_payload_flow_consistency")
        }
        "sem.memory.store_load_payload_flow" => return None,
        "sem.memory.write_payload_consistency" => {
            (WRITE_PAYLOAD_INJECT_KIND, "semantic.memory.write_payload_flow_consistency")
        }
        "sem.memory.kind_selector_consistency" => {
            (KIND_SELECTOR_INJECT_KIND, "semantic.memory.kind_selector_consistency")
        }
        "sem.row.table_power2_boundary" => {
            // Bucket-only for now: Nexus RamInitFinal table sizing has no safe witness hook yet.
            return None;
        }
        _ => return None,
    };
    let step = detail_u64(hit, "store_step_idx")
        .or_else(|| detail_u64(hit, "op_idx"))
        .or_else(|| detail_u64(hit, "step_idx"))?;
    Some(SemanticInjectionCandidate {
        bucket_id: hit.bucket_id.clone(),
        trigger_signal_id: None,
        semantic_class: semantic_class.to_string(),
        inject_kind: inject_kind.to_string(),
        schedule: InjectionSchedule::Exact(step),
    })
}

fn exact_store_load_hit(hit: &BucketHit) -> bool {
    let (Some(store_step), Some(load_step), Some(store_word), Some(load_word)) = (
        detail_u64(hit, "store_step_idx"),
        detail_u64(hit, "load_step_idx"),
        detail_u64(hit, "raw_word"),
        detail_u64(hit, "load_raw_word"),
    ) else {
        return false;
    };
    hit.bucket_id == "sem.memory.store_load_payload_flow"
        && detail_str(hit, "obligation_id") == Some("me1")
        && detail_str(hit, "cell_id") == Some("me1.sw_lw")
        && detail_str(hit, "backend") == Some("nexus")
        && detail_str(hit, "commit") == Some("636ccb360d0f4ae657ae4bb64e1e275ccec8826")
        && detail_str(hit, "trace_source") == Some("memory")
        && detail_str(hit, "mnemonic") == Some("sw")
        && detail_str(hit, "load_mnemonic") == Some("lw")
        && detail_u64(hit, "op_idx") == Some(store_step)
        && store_step < load_step
        && detail_u64(hit, "timestamp")
            .zip(detail_u64(hit, "load_timestamp"))
            .is_some_and(|(store, load)| store < load)
        && detail_u64(hit, "width") == Some(4)
        && detail_u64(hit, "write_data") == detail_u64(hit, "read_data")
        && store_word <= u32::MAX as u64
        && load_word <= u32::MAX as u64
        && store_word & 0x7f == 0x23
        && (store_word >> 12) & 0x7 == 2
        && load_word & 0x7f == 0x03
        && (load_word >> 12) & 0x7 == 2
}

fn detail_str<'a>(hit: &'a BucketHit, key: &str) -> Option<&'a str> {
    hit.details.get(key).and_then(|value| value.as_str())
}

fn detail_u64(hit: &BucketHit, key: &str) -> Option<u64> {
    hit.details.get(key).and_then(|value| {
        value.as_u64().or_else(|| value.as_i64().and_then(|n| u64::try_from(n).ok()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use beak_core::fuzz::benchmark::{run_benchmark, BenchmarkConfig};
    use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel};
    use serde_json::json;
    use std::collections::HashMap;

    fn flow_hit() -> BucketHit {
        let details = HashMap::from([
            ("obligation_id".to_string(), json!("me1")),
            ("cell_id".to_string(), json!("me1.sw_lw")),
            ("backend".to_string(), json!("nexus")),
            (
                "commit".to_string(),
                json!("636ccb360d0f4ae657ae4bb64e1e275ccec8826"),
            ),
            ("trace_source".to_string(), json!("memory")),
            ("op_idx".to_string(), json!(1)),
            ("store_step_idx".to_string(), json!(1)),
            ("load_step_idx".to_string(), json!(2)),
            ("timestamp".to_string(), json!(2)),
            ("load_timestamp".to_string(), json!(3)),
            ("pc".to_string(), json!(0x1004)),
            ("load_pc".to_string(), json!(0x1008)),
            ("opcode".to_string(), json!("0x0020a023")),
            ("raw_word".to_string(), json!(0x0020_a023u64)),
            ("load_opcode".to_string(), json!("0x0000a183")),
            ("load_raw_word".to_string(), json!(0x0000_a183u64)),
            ("mnemonic".to_string(), json!("sw")),
            ("load_mnemonic".to_string(), json!("lw")),
            ("effective_ptr".to_string(), json!(64)),
            ("write_data".to_string(), json!(0x1122_3344u64)),
            ("read_data".to_string(), json!(0x1122_3344u64)),
            ("width".to_string(), json!(4)),
        ]);
        BucketHit { bucket_id: "sem.memory.store_load_payload_flow".to_string(), details }
    }

    fn complete_receipt() -> SemanticMutationReceipt {
        serde_json::from_value(json!({
            "inject_kind": FLOW_PAYLOAD_INJECT_KIND,
            "site": "load_store.store_value_lower_byte",
            "field": "load_store.payload",
            "step": 1,
            "before": 0x1122_3344u64,
            "after": 0x1122_335au64,
            "effect": {
                "relation": "store_load_payload_equation",
                "context": {
                    "bucket_id": "sem.memory.store_load_payload_flow",
                    "obligation_id": "me1",
                    "cell_id": "me1.sw_lw",
                    "backend": "nexus",
                    "commit": "636ccb360d0f4ae657ae4bb64e1e275ccec8826",
                    "trace_source": "memory",
                    "executed_store": true,
                    "executed_load": true,
                    "mutation_mode": "replace_low_byte_5a_a5",
                    "manifestation": "store_and_load_payload_changed",
                    "store_step_idx": 1,
                    "load_step_idx": 2,
                    "store_timestamp": 2,
                    "load_timestamp": 3,
                    "store_pc": 0x1004,
                    "load_pc": 0x1008,
                    "store_raw_word": 0x0020_a023u64,
                    "load_raw_word": 0x0000_a183u64,
                    "store_opcode": "0x0020a023",
                    "load_opcode": "0x0000a183",
                    "store_mnemonic": "sw",
                    "load_mnemonic": "lw",
                    "store_address": 64,
                    "load_address": 64,
                    "store_width": 4,
                    "load_width": 4,
                    "store_value": 0x1122_3344u64,
                    "store_value_before": 0x1122_3344u64,
                    "store_value_after": 0x1122_335au64,
                    "load_value_before": 0x1122_3344u64,
                    "load_value_after": 0x1122_335au64
                }
            }
        }))
        .expect("complete receipt")
    }

    #[test]
    fn store_load_candidate_maps_to_exact_relation_and_anchor() {
        let backend = NexusBackend::new(8);
        let candidates = backend.semantic_injection_candidates(&[flow_hit()]);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].inject_kind, FLOW_PAYLOAD_INJECT_KIND);
        assert!(matches!(candidates[0].schedule, InjectionSchedule::Exact(1)));
        assert_eq!(
            backend.semantic_mutation_relation(&candidates[0]),
            Some(SemanticMutationRelation::StoreLoadPayloadEquation)
        );

        let mut wrong_kind = candidates[0].clone();
        wrong_kind.inject_kind = WRITE_PAYLOAD_INJECT_KIND.to_string();
        assert_eq!(backend.semantic_mutation_relation(&wrong_kind), None);
        let mut wrong_bucket = candidates[0].clone();
        wrong_bucket.bucket_id = "sem.memory.write_payload_consistency".to_string();
        assert_eq!(backend.semantic_mutation_relation(&wrong_bucket), None);
    }

    #[test]
    #[ignore = "r2 resource quarantine: this real Nexus trace path reached about 50 GiB RSS; use the pure candidate-map and core constructive-route tests"]
    fn ordinary_corpus_carrier_reaches_exact_semantic_schedule() {
        // storage/fuzzing_seeds/initial.jsonl:893, an ordinary corpus row rather
        // than the historical three-word replay seed.
        let words = [
            0x00c0_0313,
            0x0000_0393,
            0xaabb_d6b7,
            0xcdd6_8693,
            0x0000_2617,
            0xc446_0613,
            0x00d6_2023,
            0x0006_2703,
            0xaabb_d3b7,
            0xcdd3_8393,
            0x0077_1063,
            0x0013_8393,
            0x0020_0293,
            0x0053_9063,
        ];
        let program = nexus_vm::riscv::decode_instructions(&words);
        let (_, trace) = nexus_vm::trace::k_trace_direct(&program.blocks, 1)
            .expect("ordinary corpus carrier must execute in the Nexus frontend");
        let derived = NexusTrace::from_words_and_uniform_trace(&words, &trace);
        let backend = NexusBackend::new(256);
        let candidate = backend
            .semantic_injection_candidates(derived.bucket_hits())
            .into_iter()
            .find(|candidate| {
                candidate.bucket_id == "sem.memory.store_load_payload_flow"
                    && candidate.inject_kind == FLOW_PAYLOAD_INJECT_KIND
            })
            .expect("executed carrier hit must become an ordinary semantic candidate");

        assert!(matches!(candidate.schedule, InjectionSchedule::Exact(6)));
        assert_eq!(
            backend.semantic_mutation_relation(&candidate),
            Some(SemanticMutationRelation::StoreLoadPayloadEquation)
        );
    }

    #[test]
    fn typed_receipt_parser_fails_closed_on_missing_or_untyped_data() {
        assert!(serde_json::from_str::<SemanticMutationReceipt>("{}").is_err());
        assert!(serde_json::from_value::<SemanticMutationReceipt>(json!({
            "inject_kind": FLOW_PAYLOAD_INJECT_KIND,
            "site": "load_store.store_value_lower_byte",
            "field": "load_store.payload",
            "step": "stale",
            "before": 7,
            "after": 7,
            "effect": {"relation": "store_load_payload_equation", "context": {}}
        }))
        .is_err());
    }

    #[test]
    fn store_load_receipt_validator_recomputes_mutated_payload_and_fails_closed() {
        let receipt = complete_receipt();
        assert!(valid_store_load_payload_receipt(&receipt));

        let rejects = |mutate: fn(&mut SemanticMutationReceipt)| {
            let mut receipt = complete_receipt();
            mutate(&mut receipt);
            assert!(!valid_store_load_payload_receipt(&receipt));
        };
        rejects(|receipt| receipt.inject_kind = WRITE_PAYLOAD_INJECT_KIND.to_string());
        rejects(|receipt| receipt.site = "caller_forged".to_string());
        rejects(|receipt| receipt.field = "caller_forged".to_string());
        rejects(|receipt| receipt.effect.relation = SemanticMutationRelation::WitnessValueChanged);
        rejects(|receipt| receipt.step = 0);
        rejects(|receipt| {
            receipt.effect.context.remove("store_value_after");
        });
        rejects(|receipt| {
            receipt.effect.context.insert("mutation_mode".into(), json!("caller_forged"));
        });
        rejects(|receipt| {
            receipt.effect.context.insert("store_value".into(), json!(0x1122_3345u64));
        });
        rejects(|receipt| {
            receipt.effect.context.insert("store_value_after".into(), json!(0x1122_3344u64));
            receipt.after = json!(0x1122_3344u64);
        });
        rejects(|receipt| {
            receipt.effect.context.insert("store_value_after".into(), json!(0x1222_335au64));
            receipt.effect.context.insert("load_value_after".into(), json!(0x1222_335au64));
            receipt.after = json!(0x1222_335au64);
        });
        rejects(|receipt| {
            receipt.effect.context.insert("load_value_after".into(), json!(0x1122_335bu64));
        });
        rejects(|receipt| {
            receipt.effect.context.insert("executed_load".into(), json!(false));
        });
        rejects(|receipt| {
            receipt.effect.context.insert("commit".into(), json!("stale"));
        });
        rejects(|receipt| {
            receipt.effect.context.insert("load_step_idx".into(), json!(1));
        });
    }

    #[test]
    fn store_load_flow_state_tracks_every_receipt_input() {
        assert_eq!(BEAK_NEXUS_STORE_LOAD_FLOW_ENV.len(), 6);
        for required in [
            "BEAK_NEXUS_STORE_LOAD_FLOW_ADDR",
            "BEAK_NEXUS_STORE_LOAD_FLOW_CLK",
            "BEAK_NEXUS_STORE_LOAD_FLOW_BYTE",
            "BEAK_NEXUS_STORE_LOAD_FLOW_STORE_STEP",
            "BEAK_NEXUS_STORE_LOAD_FLOW_BEFORE",
            "BEAK_NEXUS_STORE_LOAD_FLOW_AFTER",
        ] {
            assert!(BEAK_NEXUS_STORE_LOAD_FLOW_ENV.contains(&required));
        }
    }
}
