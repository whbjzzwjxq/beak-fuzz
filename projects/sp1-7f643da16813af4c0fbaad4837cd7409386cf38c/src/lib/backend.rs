use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
    SemanticMutationReceipt, SemanticMutationRelation,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use serde::{Deserialize, Serialize};
use sp1_core_executor::{ByteOpcode, ExecutionRecord, Executor, ExecutorMode, Opcode, Register};
use sp1_core_machine::utils::run_test;
use sp1_stark::{CpuProver, SP1CoreOpts};

use crate::trace::{build_sp1_program, executed_ecall_register_states, Sp1Trace};

#[derive(Debug, Clone)]
struct WitnessInjectionPlan {
    kind: String,
    step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub request_id: u64,
    pub words: Vec<u32>,
    pub iteration: u64,
    #[serde(default)]
    pub inject_kind: Option<String>,
    #[serde(default)]
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
}

const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RealRunnerResponse {
    final_regs: Option<[u32; 32]>,
    micro_op_count: usize,
    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,
    prove_ok: bool,
    verify_ok: bool,
    error: Option<String>,
    observed_injection_sites: BTreeMap<String, Vec<u64>>,
    injection_applied: bool,
    semantic_mutation_receipt: Option<SemanticMutationReceipt>,
}

const S28_INJECT_KIND: &str = "sp1.semantic.exec.control_flow_binding";
const SP1_COMMIT: &str = "7f643da16813af4c0fbaad4837cd7409386cf38c";
const SP1_WRITE_SYSCALL_ID: u32 = 2;
const IS_MEMORY_INJECT_KIND: &str = "sp1.semantic.exec.memory_effect_binding";
const MEMORY_ADDRESS_INJECT_KIND: &str = "sp1.semantic.memory.address_pointer_consistency";
const MEMORY_VALUE_INJECT_KIND: &str = "sp1.semantic.memory.value_payload_consistency";
const MEMORY_STORE_LOAD_INJECT_KIND: &str = "sp1.semantic.memory.store_load_payload_flow";
const MEMORY_KIND_SELECTOR_INJECT_KIND: &str = "sp1.semantic.memory.kind_selector_consistency";
const TIME_MONOTONIC_INJECT_KIND: &str = "sp1.semantic.time.monotonic_access_ordering";
const LOOKUP_BOOLEAN_INJECT_KIND: &str = "sp1.semantic.lookup.boolean_multiplicity";
const PADDING_INTERACTION_SEND_INJECT_KIND: &str = "sp1.semantic.row.padding_interaction_send";
const RF1_INJECT_KIND: &str = "sp1.semantic.decode.zero_register_immutability";
const RF2_INJECT_KIND: &str = "sp1.semantic.decode.operand_index_routing";
const RF3_INJECT_KIND: &str = "sp1.semantic.exec.dest_binding";
const ID1_INJECT_KIND: &str = "sp1.semantic.decode.field_range";
const ID2_INJECT_KIND: &str = "sp1.semantic.decode.immediate_sign_extension";
const ID4_INJECT_KIND: &str = "sp1.semantic.exec.op_selector_binding";
const ID5_INJECT_KIND: &str = "sp1.semantic.decode.format_immediate_reassembly";
const AL1_INJECT_KIND: &str = "sp1.semantic.alu.immediate_limb_consistency";
const AL2_INJECT_KIND: &str = "sp1.semantic.alu.shift_mod32";
const AL3_INJECT_KIND: &str = "sp1.semantic.alu.comparison_booleanity";
const AL4_INJECT_KIND: &str = "sp1.semantic.alu.subtraction_borrow_chain";
const AL5_INJECT_KIND: &str = "sp1.semantic.alu.comparison_auxiliary_chain";
const MD_SPECIAL_INJECT_KIND: &str = "sp1.semantic.arithmetic.special_case_consistency";
const MD3_INJECT_KIND: &str = "sp1.semantic.arithmetic.division_remainder_bound";
const MD4_INJECT_KIND: &str = "sp1.semantic.arithmetic.product_decomposition";
const MD5_INJECT_KIND: &str = "sp1.semantic.arithmetic.signed_unsigned_product_correction";
static WITNESS_RUN_SEQ: AtomicU64 = AtomicU64::new(1);

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn receipt_context_u64(receipt: &SemanticMutationReceipt, key: &str) -> Option<u64> {
    receipt.effect.context.get(key).and_then(|value| value.as_u64())
}

fn receipt_context_u32(receipt: &SemanticMutationReceipt, key: &str) -> Option<u32> {
    u32::try_from(receipt_context_u64(receipt, key)?).ok()
}

fn receipt_context_str<'a>(receipt: &'a SemanticMutationReceipt, key: &str) -> Option<&'a str> {
    receipt.effect.context.get(key).and_then(|value| value.as_str())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutedControlFlowAnchor {
    step: u64,
    op_idx: u64,
    pc: u32,
    observed_next_pc: u32,
    rv_instruction: u32,
    sp1_opcode: u32,
    mnemonic: String,
    ecall_registers: [u32; 4],
}

fn nondegenerate_ecall_register_state([x5, _x10, x11, x12]: [u32; 4]) -> bool {
    x5 != SP1_WRITE_SYSCALL_ID
        || (x12 > 0 && x11.checked_add(x12.saturating_sub(1)).is_some())
}

fn executed_control_flow_anchors(
    records: &[ExecutionRecord],
) -> BTreeMap<u64, ExecutedControlFlowAnchor> {
    let mut anchors = BTreeMap::new();
    let ecall_register_states = executed_ecall_register_states(records);
    let mut flat_cpu_idx = 0u64;
    for record in records {
        for event in &record.cpu_events {
            let instruction = record.program.fetch(event.pc);
            if instruction.opcode == Opcode::ECALL {
                if let Some(ecall_registers) = ecall_register_states.get(&flat_cpu_idx).copied() {
                    anchors.insert(
                        flat_cpu_idx,
                        ExecutedControlFlowAnchor {
                            step: flat_cpu_idx,
                            op_idx: flat_cpu_idx,
                            pc: event.pc,
                            observed_next_pc: event.next_pc,
                            rv_instruction: 0x0000_0073,
                            sp1_opcode: instruction.opcode as u32,
                            mnemonic: instruction.opcode.mnemonic().to_string(),
                            ecall_registers,
                        },
                    );
                }
            }
            flat_cpu_idx = flat_cpu_idx.saturating_add(1);
        }
    }
    anchors
}

fn valid_executed_control_flow_receipt(
    receipt: &SemanticMutationReceipt,
    requested_kind: &str,
    resolved_step: u64,
    executed_anchor: &ExecutedControlFlowAnchor,
) -> bool {
    let requested_mode = inject_variant_value(requested_kind, "mode");
    let Some(receipt_ecall_registers) = (|| {
        Some([
            receipt_context_u32(receipt, "ecall_x5")?,
            receipt_context_u32(receipt, "ecall_x10")?,
            receipt_context_u32(receipt, "ecall_x11")?,
            receipt_context_u32(receipt, "ecall_x12")?,
        ])
    })() else {
        return false;
    };
    if base_inject_kind(requested_kind) != S28_INJECT_KIND
        || inject_variant_family(requested_kind) != Some("ecall")
        || !matches!(requested_mode, Some("near_jump" | "mid_jump" | "legacy_far_jump"))
        || receipt.inject_kind != requested_kind
        || receipt.site != "executor.execute_instruction"
        || receipt.field != "next_pc"
        || receipt.step != resolved_step
        || receipt.effect.relation != SemanticMutationRelation::ExecutedControlFlowEquation
        || receipt_context_str(receipt, "bucket_id")
            != Some(semantic::exec::CONTROL_FLOW_BINDING.id)
        || receipt_context_str(receipt, "obligation_id") != Some("cf6")
        || receipt_context_str(receipt, "cell_id") != Some("cf6.normal")
        || receipt_context_str(receipt, "backend") != Some("sp1")
        || receipt_context_str(receipt, "commit") != Some(SP1_COMMIT)
        || receipt_context_str(receipt, "trace_source") != Some("instruction")
        || receipt_context_str(receipt, "control_flow_family") != Some("ecall")
        || receipt_context_str(receipt, "mnemonic") != Some("ecall")
        || receipt_context_u64(receipt, "opcode") != Some(0x0000_0073)
        || receipt_context_str(receipt, "family") != Some("ecall")
        || receipt_context_str(receipt, "mode") != requested_mode
        || receipt.effect.context.get("executed_instruction") != Some(&serde_json::json!(true))
        || receipt_context_u64(receipt, "anchor") != Some(resolved_step)
        || executed_anchor.step != resolved_step
        || executed_anchor.observed_next_pc != executed_anchor.pc.wrapping_add(4)
        || !nondegenerate_ecall_register_state(executed_anchor.ecall_registers)
        || receipt_ecall_registers != executed_anchor.ecall_registers
    {
        return false;
    }
    let Some(pc) = receipt_context_u64(receipt, "pc") else {
        return false;
    };
    let Some(expected_next_pc) = receipt_context_u64(receipt, "expected_next_pc") else {
        return false;
    };
    let before = receipt.before.as_u64();
    let after = receipt.after.as_u64();
    let Some(expected_after) = requested_mode.map(|mode| match mode {
        "near_jump" => executed_anchor.pc.wrapping_add(8),
        "mid_jump" => executed_anchor.pc.wrapping_add(0x40),
        "legacy_far_jump" => executed_anchor.pc.wrapping_add(0x10000),
        _ => unreachable!("validated control-flow mode"),
    }) else {
        return false;
    };
    pc == executed_anchor.pc as u64
        && receipt_context_u64(receipt, "op_idx") == Some(executed_anchor.op_idx)
        && receipt_context_u64(receipt, "sp1_opcode") == Some(executed_anchor.sp1_opcode as u64)
        && receipt_context_u64(receipt, "source_selector")
            == Some(executed_anchor.sp1_opcode as u64)
        && executed_anchor.rv_instruction == 0x0000_0073
        && executed_anchor.sp1_opcode == Opcode::ECALL as u32
        && executed_anchor.mnemonic == "ecall"
        && expected_next_pc == (pc as u32).wrapping_add(4) as u64
        && receipt_context_u64(receipt, "step") == Some(resolved_step)
        && receipt_context_u64(receipt, "observed_next_pc_before") == before
        && receipt_context_u64(receipt, "observed_next_pc_after") == after
        && before == Some(expected_next_pc)
        && after == Some(expected_after as u64)
}

fn take_valid_semantic_mutation_receipt(
    raw: Option<serde_json::Value>,
    requested_kind: Option<&str>,
    resolved_step: Option<u64>,
    executed_anchors: &BTreeMap<u64, ExecutedControlFlowAnchor>,
) -> Result<Option<SemanticMutationReceipt>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let receipt: SemanticMutationReceipt = serde_json::from_value(raw)
        .map_err(|error| format!("decode SP1 semantic mutation receipt failed: {error}"))?;
    let valid = requested_kind
        .zip(resolved_step)
        .and_then(|(kind, step)| executed_anchors.get(&step).map(|anchor| (kind, step, anchor)))
        .is_some_and(|(kind, step, anchor)| {
            valid_executed_control_flow_receipt(&receipt, kind, step, anchor)
        });
    if !valid {
        return Err("SP1 semantic mutation receipt failed local relation validation".to_string());
    }
    Ok(Some(receipt))
}

fn inject_kind_with_variant(kind: &str, variant: &str) -> String {
    if variant.is_empty() {
        kind.to_string()
    } else {
        format!("{kind}::{variant}")
    }
}

fn supports_official_injection_kind(kind: &str) -> bool {
    matches!(
        base_inject_kind(kind),
        S28_INJECT_KIND
            | IS_MEMORY_INJECT_KIND
            | MEMORY_ADDRESS_INJECT_KIND
            | MEMORY_VALUE_INJECT_KIND
            | MEMORY_STORE_LOAD_INJECT_KIND
            | MEMORY_KIND_SELECTOR_INJECT_KIND
            | TIME_MONOTONIC_INJECT_KIND
            | LOOKUP_BOOLEAN_INJECT_KIND
            | PADDING_INTERACTION_SEND_INJECT_KIND
            | RF1_INJECT_KIND
            | RF2_INJECT_KIND
            | RF3_INJECT_KIND
            | ID1_INJECT_KIND
            | ID2_INJECT_KIND
            | ID4_INJECT_KIND
            | ID5_INJECT_KIND
            | AL1_INJECT_KIND
            | AL2_INJECT_KIND
            | AL3_INJECT_KIND
            | AL4_INJECT_KIND
            | AL5_INJECT_KIND
            | MD_SPECIAL_INJECT_KIND
            | MD3_INJECT_KIND
            | MD4_INJECT_KIND
            | MD5_INJECT_KIND
    )
}

fn inject_variant_value<'a>(kind: &'a str, key: &str) -> Option<&'a str> {
    let (_, variant) = kind.split_once("::")?;
    for field in variant.split(',') {
        let (field_key, field_value) = field.split_once('=')?;
        if field_key == key {
            return Some(field_value);
        }
    }
    None
}

#[cfg(test)]
fn inject_variant_mode(kind: &str) -> Option<&str> {
    inject_variant_value(kind, "mode")
}

fn inject_variant_family(kind: &str) -> Option<&str> {
    inject_variant_value(kind, "family")
}

fn control_flow_family_for_mnemonic(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => Some("branch"),
        "jal" | "jalr" => Some("jump"),
        "ecall" => Some("ecall"),
        _ => None,
    }
}

fn normalize_control_flow_family(family: &str) -> Option<&'static str> {
    match family {
        "branch" => Some("branch"),
        "jump" => Some("jump"),
        "ecall" => Some("ecall"),
        _ => None,
    }
}

fn control_flow_family_for_opcode(opcode: Opcode) -> Option<&'static str> {
    match opcode {
        Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
            Some("branch")
        }
        Opcode::JAL | Opcode::JALR => Some("jump"),
        Opcode::ECALL => Some("ecall"),
        _ => None,
    }
}

fn control_flow_site_key(family: &str) -> String {
    inject_kind_with_variant(S28_INJECT_KIND, &format!("family={family}"))
}

fn control_flow_semantic_class(family: Option<&str>) -> String {
    match family {
        Some(family) => {
            format!("{}.{}", semantic::exec::CONTROL_FLOW_BINDING.semantic_class, family)
        }
        None => semantic::exec::CONTROL_FLOW_BINDING.semantic_class.to_string(),
    }
}

#[cfg(test)]
fn branch_next_pc_mutation(mode: Option<&str>, pc: u32, observed_next_pc: u32) -> Option<u32> {
    let sequential = pc.wrapping_add(4);
    match mode {
        Some("force_fallthrough") => Some(sequential),
        Some("force_taken_near") => {
            let near_taken =
                if observed_next_pc == sequential { pc.wrapping_add(8) } else { sequential };
            Some(near_taken)
        }
        _ => Some(pc.wrapping_add(0x10000)),
    }
}

#[cfg(test)]
fn jump_next_pc_mutation(mode: Option<&str>, pc: u32, observed_next_pc: u32) -> Option<u32> {
    let sequential = pc.wrapping_add(4);
    match mode {
        Some("force_sequential") => {
            Some(if observed_next_pc == sequential { pc.wrapping_add(8) } else { sequential })
        }
        Some("force_near_jump") => Some(if observed_next_pc == pc.wrapping_add(8) {
            pc.wrapping_add(12)
        } else {
            pc.wrapping_add(8)
        }),
        _ => Some(pc.wrapping_add(0x10000)),
    }
}

#[cfg(test)]
fn ecall_next_pc_mutation(mode: Option<&str>, pc: u32, observed_next_pc: u32) -> Option<u32> {
    match mode {
        Some("near_jump") => Some(if observed_next_pc == pc.wrapping_add(8) {
            pc.wrapping_add(12)
        } else {
            pc.wrapping_add(8)
        }),
        Some("mid_jump") => Some(if observed_next_pc == pc.wrapping_add(0x40) {
            pc.wrapping_add(0x44)
        } else {
            pc.wrapping_add(0x40)
        }),
        _ => Some(pc.wrapping_add(0x10000)),
    }
}

#[cfg(test)]
fn mutated_control_flow_next_pc(
    kind: &str,
    opcode: Opcode,
    pc: u32,
    observed_next_pc: u32,
) -> Option<u32> {
    let family = inject_variant_family(kind).or_else(|| control_flow_family_for_opcode(opcode));
    match family {
        Some("branch")
            if matches!(
                opcode,
                Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU
            ) =>
        {
            branch_next_pc_mutation(inject_variant_mode(kind), pc, observed_next_pc)
        }
        Some("jump") if matches!(opcode, Opcode::JAL | Opcode::JALR) => {
            jump_next_pc_mutation(inject_variant_mode(kind), pc, observed_next_pc)
        }
        Some("ecall") if opcode == Opcode::ECALL => {
            ecall_next_pc_mutation(inject_variant_mode(kind), pc, observed_next_pc)
        }
        None if opcode == Opcode::ECALL => {
            ecall_next_pc_mutation(inject_variant_mode(kind), pc, observed_next_pc)
        }
        _ => None,
    }
}

fn record_site(sites: &mut BTreeMap<String, Vec<u64>>, kind: &str, step: u64) {
    let steps = sites.entry(kind.to_string()).or_default();
    if steps.last().copied() != Some(step) {
        steps.push(step);
    }
}

fn record_alu_muldiv_chip_sites(sites: &mut BTreeMap<String, Vec<u64>>, opcode: Opcode, step: u64) {
    match opcode {
        Opcode::ADD | Opcode::XOR | Opcode::OR | Opcode::AND => {
            record_site(sites, AL1_INJECT_KIND, step);
        }
        Opcode::SUB => {
            record_site(sites, AL4_INJECT_KIND, step);
        }
        Opcode::SLL | Opcode::SRL | Opcode::SRA => {
            record_site(sites, AL1_INJECT_KIND, step);
            record_site(sites, AL2_INJECT_KIND, step);
        }
        Opcode::SLT | Opcode::SLTU => {
            record_site(sites, AL1_INJECT_KIND, step);
            record_site(sites, AL3_INJECT_KIND, step);
            record_site(sites, AL4_INJECT_KIND, step);
            record_site(sites, AL5_INJECT_KIND, step);
        }
        Opcode::DIV | Opcode::DIVU | Opcode::REM | Opcode::REMU => {
            record_site(sites, MD_SPECIAL_INJECT_KIND, step);
            record_site(sites, MD3_INJECT_KIND, step);
        }
        Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {
            record_site(sites, MD4_INJECT_KIND, step);
            if opcode == Opcode::MULHSU {
                record_site(sites, MD5_INJECT_KIND, step);
            }
        }
        _ => {}
    }
}

fn record_memory_instr_sites(sites: &mut BTreeMap<String, Vec<u64>>, opcode: Opcode, step: u64) {
    match opcode {
        Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW => {
            record_site(sites, MEMORY_ADDRESS_INJECT_KIND, step);
            record_site(sites, MEMORY_VALUE_INJECT_KIND, step);
            record_site(sites, MEMORY_KIND_SELECTOR_INJECT_KIND, step);
            record_site(sites, TIME_MONOTONIC_INJECT_KIND, step);
        }
        Opcode::SB | Opcode::SH | Opcode::SW => {
            record_site(sites, MEMORY_ADDRESS_INJECT_KIND, step);
            record_site(sites, MEMORY_VALUE_INJECT_KIND, step);
            record_site(sites, MEMORY_STORE_LOAD_INJECT_KIND, step);
            record_site(sites, MEMORY_KIND_SELECTOR_INJECT_KIND, step);
            record_site(sites, TIME_MONOTONIC_INJECT_KIND, step);
        }
        _ => {}
    }
}

fn byte_lookup_step(opcode: ByteOpcode, a1: u16, b: u8, c: u8) -> u64 {
    let row = if opcode != ByteOpcode::U16Range {
        (((b as u16) << 8) + c as u16) as u64
    } else {
        a1 as u64
    };
    row.saturating_mul(9).saturating_add(opcode as u64)
}

fn syscall_instr_padded_rows(real_rows: usize) -> usize {
    if real_rows == 0 {
        0
    } else {
        real_rows.next_power_of_two().max(16)
    }
}

fn panic_payload_to_string(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn collect_observed_injection_sites(records: &[ExecutionRecord]) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    let mut flat_cpu_idx = 0u64;
    let mut memory_hook_step = 0u64;
    for record in records {
        for event in &record.cpu_events {
            let instruction = record.program.fetch(event.pc);
            let chip_step = (event.pc / 4) as u64;
            record_alu_muldiv_chip_sites(&mut sites, instruction.opcode, chip_step);
            if let Some(family) = control_flow_family_for_opcode(instruction.opcode) {
                record_site(&mut sites, S28_INJECT_KIND, flat_cpu_idx);
                record_site(&mut sites, &control_flow_site_key(family), flat_cpu_idx);
            }
            for kind in [
                RF1_INJECT_KIND,
                RF2_INJECT_KIND,
                RF3_INJECT_KIND,
                ID1_INJECT_KIND,
                ID2_INJECT_KIND,
                ID4_INJECT_KIND,
                ID5_INJECT_KIND,
            ] {
                record_site(&mut sites, kind, flat_cpu_idx);
            }
            match instruction.opcode {
                Opcode::LB
                | Opcode::LBU
                | Opcode::LH
                | Opcode::LHU
                | Opcode::LW
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW => {
                    record_site(&mut sites, IS_MEMORY_INJECT_KIND, flat_cpu_idx);
                }
                _ => {}
            }
            flat_cpu_idx = flat_cpu_idx.saturating_add(1);
        }
        for event in &record.memory_instr_events {
            record_memory_instr_sites(&mut sites, event.opcode, memory_hook_step);
            memory_hook_step = memory_hook_step.saturating_add(1);
        }
        let real_syscall_rows = record.syscall_events.len();
        let padded_syscall_rows = syscall_instr_padded_rows(real_syscall_rows);
        for row_idx in real_syscall_rows..padded_syscall_rows {
            record_site(&mut sites, PADDING_INTERACTION_SEND_INJECT_KIND, row_idx as u64);
        }
        for (lookup, mult) in &record.byte_lookups {
            if *mult == 0 {
                continue;
            }
            record_site(
                &mut sites,
                LOOKUP_BOOLEAN_INJECT_KIND,
                byte_lookup_step(lookup.opcode, lookup.a1, lookup.b, lookup.c),
            );
        }
    }
    sites
}

fn resolve_runtime_injection_step(
    inject_kind: Option<&str>,
    inject_step: u64,
    observed_injection_sites: &BTreeMap<String, Vec<u64>>,
) -> Option<u64> {
    let kind = inject_kind?;
    if !supports_official_injection_kind(kind) {
        return None;
    }
    let lookup_kind = if base_inject_kind(kind) == S28_INJECT_KIND {
        inject_variant_family(kind)
            .map(control_flow_site_key)
            .unwrap_or_else(|| S28_INJECT_KIND.to_string())
    } else {
        base_inject_kind(kind).to_string()
    };
    let steps = observed_injection_sites.get(lookup_kind.as_str())?;
    if inject_step == u64::MAX {
        steps.first().copied()
    } else if steps.contains(&inject_step) {
        Some(inject_step)
    } else {
        None
    }
}

fn with_scoped_witness_injection_env<T>(
    inject_kind: Option<&str>,
    inject_step: Option<u64>,
    f: impl FnOnce() -> T,
) -> T {
    let prev_kind = std::env::var("BEAK_SP1_WITNESS_INJECT_KIND").ok();
    let prev_step = std::env::var("BEAK_SP1_WITNESS_INJECT_STEP").ok();
    let prev_run_id = std::env::var("BEAK_SP1_WITNESS_RUN_ID").ok();
    let run_id = WITNESS_RUN_SEQ.fetch_add(1, Ordering::Relaxed).to_string();

    match (inject_kind, inject_step) {
        (Some(kind), Some(step)) => {
            std::env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", kind);
            std::env::set_var("BEAK_SP1_WITNESS_INJECT_STEP", step.to_string());
        }
        _ => {
            std::env::remove_var("BEAK_SP1_WITNESS_INJECT_KIND");
            std::env::remove_var("BEAK_SP1_WITNESS_INJECT_STEP");
        }
    }
    std::env::set_var("BEAK_SP1_WITNESS_RUN_ID", &run_id);

    let result = f();

    match prev_kind {
        Some(v) => std::env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", v),
        None => std::env::remove_var("BEAK_SP1_WITNESS_INJECT_KIND"),
    }
    match prev_step {
        Some(v) => std::env::set_var("BEAK_SP1_WITNESS_INJECT_STEP", v),
        None => std::env::remove_var("BEAK_SP1_WITNESS_INJECT_STEP"),
    }
    match prev_run_id {
        Some(v) => std::env::set_var("BEAK_SP1_WITNESS_RUN_ID", v),
        None => std::env::remove_var("BEAK_SP1_WITNESS_RUN_ID"),
    }

    result
}

fn run_sp1_executor(
    program: &sp1_core_executor::Program,
    inject_kind: Option<&str>,
    inject_step: Option<u64>,
) -> Result<Executor<'static>, String> {
    let mut executor = Executor::new(program.clone(), SP1CoreOpts::default());
    executor.executor_mode = ExecutorMode::Trace;
    with_scoped_witness_injection_env(
        inject_kind.filter(|kind| supports_official_injection_kind(kind)),
        inject_step,
        || executor.run(),
    )
    .map_err(|e| format!("sp1 executor run failed: {e}"))?;
    Ok(executor)
}

fn supports_official_injection(inject_kind: Option<&str>) -> bool {
    inject_kind.map(supports_official_injection_kind).unwrap_or(true)
}

fn run_sp1_real_backend(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RealRunnerResponse, String> {
    let program = build_sp1_program(words)?;
    let mut executor = run_sp1_executor(&program, None, None)?;
    let baseline_records = std::mem::take(&mut executor.records);
    let observed_injection_sites = collect_observed_injection_sites(&baseline_records);
    let executed_anchors = executed_control_flow_anchors(&baseline_records);
    if !supports_official_injection(inject_kind) {
        let trace = Sp1Trace::from_execution_records(words, &baseline_records)?;
        let mut regs = [0u32; 32];
        for i in 0..32usize {
            regs[i] = executor.register(Register::from_u8(i as u8));
        }
        return Ok(RealRunnerResponse {
            final_regs: Some(regs),
            micro_op_count: trace.instruction_count(),
            bucket_hits: trace.bucket_hits().to_vec(),
            trace_signals: trace.trace_signals().to_vec(),
            prove_ok: false,
            verify_ok: false,
            error: Some(format!(
                "sp1 official prove path has no installed hook/applied signal for requested kind {}; mapped hooks include CPU-row decode/register/control hooks, {IS_MEMORY_INJECT_KIND}, v4 memory-instruction hooks, byte-table multiplicity hooks, and SyscallInstrs padding hooks",
                inject_kind.unwrap_or_default()
            )),
            observed_injection_sites,
            injection_applied: false,
            semantic_mutation_receipt: None,
        });
    }

    let runtime_injection_step =
        resolve_runtime_injection_step(inject_kind, inject_step, &observed_injection_sites);
    let injection_was_scheduled = runtime_injection_step.is_some();
    let records = if injection_was_scheduled {
        executor = run_sp1_executor(&program, inject_kind, runtime_injection_step)?;
        std::mem::take(&mut executor.records)
    } else {
        baseline_records
    };

    let trace = Sp1Trace::from_execution_records(words, &records)?;
    let (
        prove_ok,
        verify_ok,
        prove_verify_error,
        proof_injection_applied,
        semantic_mutation_receipt,
    ) = run_sp1_prove_verify_with_run_test(
        &executor.program,
        inject_kind,
        runtime_injection_step,
        &executed_anchors,
    );

    let mut regs = [0u32; 32];
    for i in 0..32usize {
        regs[i] = executor.register(Register::from_u8(i as u8));
    }

    Ok(RealRunnerResponse {
        final_regs: Some(regs),
        micro_op_count: trace.instruction_count(),
        bucket_hits: trace.bucket_hits().to_vec(),
        trace_signals: trace.trace_signals().to_vec(),
        prove_ok,
        verify_ok,
        error: prove_verify_error,
        observed_injection_sites,
        injection_applied: injection_was_scheduled && proof_injection_applied,
        semantic_mutation_receipt,
    })
}

fn run_sp1_prove_verify_with_run_test(
    program: &sp1_core_executor::Program,
    inject_kind: Option<&str>,
    witness_injection_step: Option<u64>,
    executed_anchors: &BTreeMap<u64, ExecutedControlFlowAnchor>,
) -> (bool, bool, Option<String>, bool, Option<SemanticMutationReceipt>) {
    let mut injection_applied = false;
    let mut raw_semantic_mutation_receipt = None;
    let prove_result = with_scoped_witness_injection_env(
        inject_kind.filter(|kind| supports_official_injection_kind(kind)),
        witness_injection_step,
        || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_test::<CpuProver<_, _>>(program.clone())
            }));
            injection_applied = fuzzer_utils::injection_was_applied();
            raw_semantic_mutation_receipt = fuzzer_utils::take_semantic_mutation_receipt();
            result
        },
    );

    let semantic_mutation_receipt = match take_valid_semantic_mutation_receipt(
        raw_semantic_mutation_receipt,
        inject_kind,
        witness_injection_step,
        executed_anchors,
    ) {
        Ok(receipt) => receipt,
        Err(error) => return (true, false, Some(error), injection_applied, None),
    };

    match prove_result {
        Ok(Ok(_)) => (true, true, None, injection_applied, semantic_mutation_receipt),
        Ok(Err(e)) => (
            true,
            false,
            Some(format!("sp1 run_test prove/verify failed: {e}")),
            injection_applied,
            semantic_mutation_receipt,
        ),
        Err(p) => (
            true,
            false,
            Some(format!(
                "sp1 run_test prove/verify panicked: {}",
                panic_payload_to_string(p.as_ref())
            )),
            injection_applied,
            semantic_mutation_receipt,
        ),
    }
}

pub fn run_backend_once(
    request_id: u64,
    words: &[u32],
    _current_iteration: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<WorkerResponse, String> {
    let runner_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_sp1_real_backend(words, inject_kind, inject_step)
    }));
    let resp = match runner_res {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(e),
        Err(p) => {
            let msg = panic_payload_to_string(p.as_ref());
            return Err(format!("backend panic: {msg}"));
        }
    };

    let backend_error = if let Some(err) = resp.error.clone() {
        Some(err)
    } else if !resp.prove_ok || !resp.verify_ok {
        Some(format!(
            "sp1 real backend did not complete prove+verify successfully (prove_ok={}, verify_ok={})",
            resp.prove_ok, resp.verify_ok
        ))
    } else {
        None
    };

    Ok(WorkerResponse {
        request_id,
        final_regs: resp.final_regs,
        micro_op_count: resp.micro_op_count,
        bucket_hits: resp.bucket_hits,
        trace_signals: resp.trace_signals,
        backend_error,
        observed_injection_sites: resp.observed_injection_sites,
        injection_applied: resp.injection_applied,
        semantic_mutation_receipt: resp.semantic_mutation_receipt,
    })
}

pub struct Sp1Backend {
    max_instructions: usize,
    eval: BackendEval,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    current_iteration: u64,
    next_request_id: u64,
    pending_injection: Option<WitnessInjectionPlan>,
    worker: Option<WorkerProcess>,
}

struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    responses_rx: Receiver<Result<WorkerResponse, String>>,
    reader_thread: JoinHandle<()>,
}

impl Sp1Backend {
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

    fn ordered_steps_around_anchor(steps: &[u64], anchor: u64) -> Vec<u64> {
        let mut ordered = steps.to_vec();
        ordered.sort_by_key(|step| {
            let dist = if *step >= anchor {
                step.saturating_sub(anchor)
            } else {
                anchor.saturating_sub(*step)
            };
            (dist, *step)
        });
        ordered.dedup();
        ordered
    }

    fn step_from_hit(hit: &BucketHit) -> u64 {
        hit.details
            .get("op_idx")
            .and_then(|v| v.as_u64())
            .or_else(|| hit.details.get("step_idx").and_then(|v| v.as_u64()))
            .unwrap_or(0)
    }

    fn pc_word_step_from_hit(hit: &BucketHit) -> u64 {
        hit.details
            .get("pc")
            .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse::<u64>().ok()))
            .map(|pc| pc / 4)
            .unwrap_or_else(|| Self::step_from_hit(hit))
    }

    fn memory_hook_step_from_hit(hit: &BucketHit) -> u64 {
        hit.details
            .get("store_step_idx")
            .and_then(|v| v.as_u64())
            .or_else(|| hit.details.get("memory_hook_step").and_then(|v| v.as_u64()))
            .unwrap_or_else(|| Self::step_from_hit(hit))
    }

    fn byte_lookup_step_from_hit(hit: &BucketHit) -> u64 {
        hit.details
            .get("byte_lookup_step")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| Self::step_from_hit(hit))
    }

    fn is_syscall_instr_padding_hit(hit: &BucketHit) -> bool {
        hit.details.get("trace_source").and_then(|value| value.as_str())
            == Some("syscall_instruction_padding")
            && hit.details.get("table_name").and_then(|value| value.as_str())
                == Some("SyscallInstrs")
            && hit.details.get("is_padding").and_then(|value| value.as_bool()) == Some(true)
    }

    fn mnemonic_from_hit(hit: &BucketHit) -> Option<&str> {
        hit.details.get("mnemonic").and_then(|value| value.as_str())
    }

    fn control_flow_family_from_hit(hit: &BucketHit) -> Option<&'static str> {
        hit.details
            .get("control_flow_family")
            .and_then(|value| value.as_str())
            .and_then(normalize_control_flow_family)
            .or_else(|| Self::mnemonic_from_hit(hit).and_then(control_flow_family_for_mnemonic))
    }

    fn ecall_register_state_from_hit(hit: &BucketHit) -> Option<[u32; 4]> {
        let value = |key: &str| {
            hit.details
                .get(key)
                .and_then(|value| value.as_u64())
                .and_then(|value| u32::try_from(value).ok())
        };
        Some([
            value("ecall_x5")?,
            value("ecall_x10")?,
            value("ecall_x11")?,
            value("ecall_x12")?,
        ])
    }

    fn is_bound_sequential_ecall_hit(hit: &BucketHit) -> bool {
        let Some(pc) = hit
            .details
            .get("pc")
            .and_then(|value| value.as_u64())
            .and_then(|value| u32::try_from(value).ok())
        else {
            return false;
        };
        let Some(next_pc) = hit
            .details
            .get("next_pc")
            .and_then(|value| value.as_u64())
            .and_then(|value| u32::try_from(value).ok())
        else {
            return false;
        };
        next_pc == pc.wrapping_add(4)
            && Self::ecall_register_state_from_hit(hit)
                .is_some_and(nondegenerate_ecall_register_state)
    }

    fn is_chip_scheduled_bucket(bucket_id: &str) -> bool {
        bucket_id == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id
            || bucket_id == semantic::alu::SHIFT_MOD32.id
            || bucket_id == semantic::alu::COMPARISON_BOOLEANITY.id
            || bucket_id == semantic::alu::SUBTRACTION_BORROW_CHAIN.id
            || bucket_id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id
            || bucket_id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id
            || bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id
            || bucket_id == semantic::arithmetic::PRODUCT_DECOMPOSITION.id
            || bucket_id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id
    }

    fn is_memory_hook_bucket(bucket_id: &str) -> bool {
        bucket_id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id
            || bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id
            || bucket_id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id
            || bucket_id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id
            || bucket_id == semantic::memory::LOAD_VALUE_BINDING.id
            || bucket_id == semantic::memory::WRITE_PAYLOAD_CONSISTENCY.id
            || bucket_id == semantic::exec::PARTIAL_WORD_WRITE_CONSISTENCY.id
            || bucket_id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id
            || bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id
            || bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id
    }

    fn s28_variant_specs_for_family(family: &str) -> Vec<String> {
        match family {
            "branch" => vec![
                "family=branch,mode=force_fallthrough".to_string(),
                "family=branch,mode=force_taken_near".to_string(),
                "family=branch,mode=legacy_far_jump".to_string(),
            ],
            "jump" => vec![
                "family=jump,mode=force_sequential".to_string(),
                "family=jump,mode=force_near_jump".to_string(),
                "family=jump,mode=legacy_far_jump".to_string(),
            ],
            _ => vec![
                "family=ecall,mode=near_jump".to_string(),
                "family=ecall,mode=mid_jump".to_string(),
                "family=ecall,mode=legacy_far_jump".to_string(),
            ],
        }
    }

    fn semantic_candidate_priority(candidate: &SemanticInjectionCandidate) -> u8 {
        let bucket_id = candidate.bucket_id.as_str();
        if bucket_id == semantic::row::PADDING_INTERACTION_SEND.id {
            0
        } else if bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id {
            1
        } else if matches!(
            bucket_id,
            id if id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id
                || id == semantic::decode::OPERAND_INDEX_ROUTING.id
                || id == semantic::exec::DEST_BINDING.id
                || id == semantic::decode::FIELD_RANGE.id
                || id == semantic::decode::IMMEDIATE_SIGN_EXTENSION.id
                || id == semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.id
                || id == semantic::exec::OP_SELECTOR_BINDING.id
        ) {
            2
        } else if bucket_id == semantic::exec::MEMORY_EFFECT_BINDING.id {
            3
        } else if bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id {
            4
        } else if bucket_id == semantic::lookup::BOOLEAN_MULTIPLICITY.id {
            5
        } else {
            6
        }
    }

    fn semantic_candidate_from_hit(&self, hit: &BucketHit) -> Vec<SemanticInjectionCandidate> {
        let bucket_id = hit.bucket_id.as_str();
        let anchor = if Self::is_chip_scheduled_bucket(bucket_id) {
            Self::pc_word_step_from_hit(hit)
        } else if bucket_id == semantic::lookup::BOOLEAN_MULTIPLICITY.id {
            Self::byte_lookup_step_from_hit(hit)
        } else if Self::is_memory_hook_bucket(bucket_id) {
            Self::memory_hook_step_from_hit(hit)
        } else {
            Self::step_from_hit(hit)
        };
        let control_flow_family = Self::control_flow_family_from_hit(hit);
        let control_flow_site_key = control_flow_family.map(control_flow_site_key);
        let (semantic_class, inject_kinds, schedule_lookup_key, fallback_schedule) = if bucket_id
            == semantic::exec::CONTROL_FLOW_BINDING.id
        {
            let Some(control_flow_family) = control_flow_family else {
                return Vec::new();
            };
            if control_flow_family == "ecall" && !Self::is_bound_sequential_ecall_hit(hit) {
                return Vec::new();
            }
            (
                control_flow_semantic_class(Some(control_flow_family)),
                Self::s28_variant_specs_for_family(control_flow_family)
                    .into_iter()
                    .map(|variant| inject_kind_with_variant(S28_INJECT_KIND, &variant))
                    .collect::<Vec<_>>(),
                control_flow_site_key.unwrap_or_else(|| S28_INJECT_KIND.to_string()),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::exec::MEMORY_EFFECT_BINDING.id {
            (
                semantic::exec::MEMORY_EFFECT_BINDING.semantic_class.to_string(),
                vec![IS_MEMORY_INJECT_KIND.to_string()],
                IS_MEMORY_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id {
            (
                semantic::memory::STORE_LOAD_PAYLOAD_FLOW.semantic_class.to_string(),
                vec![inject_kind_with_variant(MEMORY_STORE_LOAD_INJECT_KIND, "site=access_value")],
                MEMORY_STORE_LOAD_INJECT_KIND.to_string(),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id
            || bucket_id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id
            || bucket_id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id
        {
            let semantic_class = if bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id
            {
                semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.semantic_class
            } else if bucket_id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id {
                semantic::memory::ADDRESS_BOUNDARY_RANGE.semantic_class
            } else {
                semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.semantic_class
            };
            (
                semantic_class.to_string(),
                vec![inject_kind_with_variant(MEMORY_ADDRESS_INJECT_KIND, "site=addr_word")],
                MEMORY_ADDRESS_INJECT_KIND.to_string(),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::memory::LOAD_VALUE_BINDING.id
            || bucket_id == semantic::memory::WRITE_PAYLOAD_CONSISTENCY.id
            || bucket_id == semantic::exec::PARTIAL_WORD_WRITE_CONSISTENCY.id
        {
            let semantic_class = if bucket_id == semantic::memory::LOAD_VALUE_BINDING.id {
                semantic::memory::LOAD_VALUE_BINDING.semantic_class
            } else {
                semantic::memory::WRITE_PAYLOAD_CONSISTENCY.semantic_class
            };
            (
                semantic_class.to_string(),
                vec![inject_kind_with_variant(MEMORY_VALUE_INJECT_KIND, "site=access_value")],
                MEMORY_VALUE_INJECT_KIND.to_string(),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id {
            (
                semantic::memory::KIND_SELECTOR_CONSISTENCY.semantic_class.to_string(),
                vec![inject_kind_with_variant(
                    MEMORY_KIND_SELECTOR_INJECT_KIND,
                    "site=kind_selector",
                )],
                MEMORY_KIND_SELECTOR_INJECT_KIND.to_string(),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id {
            (
                semantic::time::MONOTONIC_ACCESS_ORDERING.semantic_class.to_string(),
                vec![inject_kind_with_variant(TIME_MONOTONIC_INJECT_KIND, "site=prev_clk")],
                TIME_MONOTONIC_INJECT_KIND.to_string(),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id {
            (
                semantic::time::MONOTONIC_ACCESS_ORDERING.semantic_class.to_string(),
                vec![inject_kind_with_variant(TIME_MONOTONIC_INJECT_KIND, "site=prev_clk")],
                TIME_MONOTONIC_INJECT_KIND.to_string(),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::lookup::BOOLEAN_MULTIPLICITY.id {
            (
                semantic::lookup::BOOLEAN_MULTIPLICITY.semantic_class.to_string(),
                vec![LOOKUP_BOOLEAN_INJECT_KIND.to_string()],
                LOOKUP_BOOLEAN_INJECT_KIND.to_string(),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::row::PADDING_INTERACTION_SEND.id {
            if !Self::is_syscall_instr_padding_hit(hit) {
                return Vec::new();
            }
            (
                semantic::row::PADDING_INTERACTION_SEND.semantic_class.to_string(),
                vec![inject_kind_with_variant(
                    PADDING_INTERACTION_SEND_INJECT_KIND,
                    "site=syscall_instr_padding_send_table",
                )],
                PADDING_INTERACTION_SEND_INJECT_KIND.to_string(),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id {
            (
                semantic::decode::ZERO_REGISTER_IMMUTABILITY.semantic_class.to_string(),
                vec![inject_kind_with_variant(RF1_INJECT_KIND, "site=op_a_access")],
                RF1_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::decode::OPERAND_INDEX_ROUTING.id {
            (
                semantic::decode::OPERAND_INDEX_ROUTING.semantic_class.to_string(),
                vec![inject_kind_with_variant(RF2_INJECT_KIND, "site=op_b_access")],
                RF2_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::exec::DEST_BINDING.id {
            (
                semantic::exec::DEST_BINDING.semantic_class.to_string(),
                vec![inject_kind_with_variant(RF3_INJECT_KIND, "site=op_a_access")],
                RF3_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::decode::FIELD_RANGE.id {
            (
                semantic::decode::FIELD_RANGE.semantic_class.to_string(),
                vec![inject_kind_with_variant(ID1_INJECT_KIND, "site=instruction_op_a")],
                ID1_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::decode::IMMEDIATE_SIGN_EXTENSION.id {
            (
                semantic::decode::IMMEDIATE_SIGN_EXTENSION.semantic_class.to_string(),
                vec![inject_kind_with_variant(ID2_INJECT_KIND, "site=instruction_op_c")],
                ID2_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::exec::OP_SELECTOR_BINDING.id {
            (
                semantic::exec::OP_SELECTOR_BINDING.semantic_class.to_string(),
                vec![inject_kind_with_variant(ID4_INJECT_KIND, "site=opcode")],
                ID4_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.id {
            (
                semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.semantic_class.to_string(),
                vec![inject_kind_with_variant(ID5_INJECT_KIND, "site=instruction_op_c")],
                ID5_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id {
            let Some(mnemonic) = Self::mnemonic_from_hit(hit) else {
                return Vec::new();
            };
            if !matches!(
                mnemonic,
                "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai"
            ) {
                return Vec::new();
            }
            (
                semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.semantic_class.to_string(),
                vec![AL1_INJECT_KIND.to_string()],
                AL1_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::alu::SHIFT_MOD32.id {
            (
                semantic::alu::SHIFT_MOD32.semantic_class.to_string(),
                vec![AL2_INJECT_KIND.to_string()],
                AL2_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::alu::COMPARISON_BOOLEANITY.id {
            (
                semantic::alu::COMPARISON_BOOLEANITY.semantic_class.to_string(),
                vec![AL3_INJECT_KIND.to_string()],
                AL3_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::alu::SUBTRACTION_BORROW_CHAIN.id {
            let Some(mnemonic) = Self::mnemonic_from_hit(hit) else {
                return Vec::new();
            };
            if !matches!(mnemonic, "sub" | "slt" | "slti" | "sltu" | "sltiu") {
                return Vec::new();
            }
            (
                semantic::alu::SUBTRACTION_BORROW_CHAIN.semantic_class.to_string(),
                vec![AL4_INJECT_KIND.to_string()],
                AL4_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id {
            (
                semantic::alu::COMPARISON_AUXILIARY_CHAIN.semantic_class.to_string(),
                vec![AL5_INJECT_KIND.to_string()],
                AL5_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id {
            (
                semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.semantic_class.to_string(),
                vec![MD_SPECIAL_INJECT_KIND.to_string()],
                MD_SPECIAL_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id {
            (
                semantic::arithmetic::DIVISION_REMAINDER_BOUND.semantic_class.to_string(),
                vec![MD3_INJECT_KIND.to_string()],
                MD3_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::arithmetic::PRODUCT_DECOMPOSITION.id {
            (
                semantic::arithmetic::PRODUCT_DECOMPOSITION.semantic_class.to_string(),
                vec![MD4_INJECT_KIND.to_string()],
                MD4_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id {
            (
                semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.semantic_class.to_string(),
                vec![MD5_INJECT_KIND.to_string()],
                MD5_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else {
            return Vec::new();
        };
        let schedule = self
            .last_observed_injection_sites
            .get(schedule_lookup_key.as_str())
            .map(|steps| {
                InjectionSchedule::Explicit(Self::ordered_steps_around_anchor(steps, anchor))
            })
            .unwrap_or(fallback_schedule);
        inject_kinds
            .into_iter()
            .map(|kind| SemanticInjectionCandidate {
                bucket_id: hit.bucket_id.clone(),
                trigger_signal_id: None,
                semantic_class: semantic_class.clone(),
                inject_kind: kind,
                schedule: schedule.clone(),
            })
            .collect()
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
                        if trimmed.is_empty() {
                            continue;
                        }
                        if !trimmed.starts_with(WORKER_RESPONSE_PREFIX) {
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
            let worker_pid = worker.child.id();
            // Best-effort reap for nested runner children that may outlive the worker.
            let _ =
                Command::new("pkill").arg("-KILL").arg("-P").arg(worker_pid.to_string()).status();
            let _ = worker.child.kill();
            let _ = worker.child.wait();
            let _ =
                Command::new("pkill").arg("-KILL").arg("-P").arg(worker_pid.to_string()).status();
            drop(worker.stdin);
            let _ = worker.reader_thread.join();
        }
    }
}

impl BenchmarkBackend for Sp1Backend {
    fn is_usable_seed(&self, words: &[u32]) -> bool {
        if words.is_empty() || words.len() > self.max_instructions {
            return false;
        }
        words.iter().all(|w| RV32IMInstruction::decode(*w).is_some())
    }

    fn prepare_for_run(&mut self, _rng_seed: u64) {
        self.eval = BackendEval::default();
        self.current_iteration = self.current_iteration.saturating_add(1);
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval.backend_error = None;
        self.eval.bucket_hits.clear();
        self.eval.micro_op_count = 0;
        self.eval.final_regs = None;
        self.eval.semantic_injection_applied = false;
        self.eval.semantic_mutation_receipt = None;
        self.eval.executed_exception_receipt = None;
        self.last_observed_injection_sites.clear();
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
                Ok(Ok(resp)) => {
                    if resp.request_id == request_id {
                        break resp;
                    }
                }
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
        self.eval = BackendEval {
            micro_op_count: resp.micro_op_count,
            bucket_hits: resp.bucket_hits,
            trace_signals: resp.trace_signals,
            final_regs: resp.final_regs,
            backend_error: resp.backend_error.clone(),
            semantic_injection_applied: resp.injection_applied,
            semantic_mutation_receipt: resp.semantic_mutation_receipt,
            executed_exception_receipt: None,
            production_resource: None,
        };
        self.last_observed_injection_sites = resp.observed_injection_sites;

        if let Some(err) = resp.backend_error {
            return Err(err);
        }
        resp.final_regs.ok_or_else(|| "sp1 backend did not return final regs".to_string())
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

    fn semantic_mutation_relation(
        &self,
        candidate: &SemanticInjectionCandidate,
    ) -> Option<SemanticMutationRelation> {
        (candidate.bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id
            && base_inject_kind(candidate.inject_kind.as_str()) == S28_INJECT_KIND
            && inject_variant_family(candidate.inject_kind.as_str()) == Some("ecall")
            && matches!(
                inject_variant_value(candidate.inject_kind.as_str(), "mode"),
                Some("near_jump" | "mid_jump" | "legacy_far_jump")
            ))
        .then_some(SemanticMutationRelation::ExecutedControlFlowEquation)
    }

    fn semantic_injection_candidates(&self, hits: &[BucketHit]) -> Vec<SemanticInjectionCandidate> {
        let mut candidates: Vec<_> =
            hits.iter().flat_map(|hit| self.semantic_candidate_from_hit(hit)).collect();
        candidates.sort_by_key(Self::semantic_candidate_priority);
        candidates
    }
}

impl Drop for Sp1Backend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        control_flow_semantic_class, control_flow_site_key, inject_kind_with_variant,
        mutated_control_flow_next_pc, resolve_runtime_injection_step, run_backend_once,
        valid_executed_control_flow_receipt, ExecutedControlFlowAnchor, InjectionSchedule, Opcode,
        SemanticMutationReceipt, SemanticMutationRelation, Sp1Backend, S28_INJECT_KIND,
    };
    use beak_core::fuzz::benchmark::BenchmarkBackend;
    use beak_core::trace::{semantic, BucketHit};
    use serde_json::json;
    use std::collections::{BTreeMap, HashMap};

    fn ecall_anchor() -> ExecutedControlFlowAnchor {
        ExecutedControlFlowAnchor {
            step: 9,
            op_idx: 9,
            pc: 16,
            observed_next_pc: 20,
            rv_instruction: 0x0000_0073,
            sp1_opcode: Opcode::ECALL as u32,
            mnemonic: "ecall".to_string(),
            ecall_registers: [1, 3, 0x1000, 4],
        }
    }

    fn ecall_receipt(mode: &str, observed_after: u32) -> SemanticMutationReceipt {
        let inject_kind =
            format!("sp1.semantic.exec.control_flow_binding::family=ecall,mode={mode}");
        serde_json::from_value(json!({
            "inject_kind": inject_kind,
            "site": "executor.execute_instruction",
            "field": "next_pc",
            "step": 9,
            "before": 20,
            "after": observed_after,
            "effect": {
                "relation": "executed_control_flow_equation",
                "context": {
                    "bucket_id": "sem.exec.control_flow_binding",
                    "obligation_id": "cf6",
                    "cell_id": "cf6.normal",
                    "backend": "sp1",
                    "commit": "7f643da16813af4c0fbaad4837cd7409386cf38c",
                    "trace_source": "instruction",
                    "anchor": 9,
                    "step": 9,
                    "op_idx": 9,
                    "pc": 16,
                    "opcode": 0x0000_0073,
                    "sp1_opcode": 28,
                    "source_selector": 28,
                    "mnemonic": "ecall",
                    "control_flow_family": "ecall",
                    "family": "ecall",
                    "mode": mode,
                    "expected_next_pc": 20,
                    "observed_next_pc_before": 20,
                    "observed_next_pc_after": observed_after,
                    "ecall_x5": 1,
                    "ecall_x10": 3,
                    "ecall_x11": 4096,
                    "ecall_x12": 4,
                    "executed_instruction": true
                }
            }
        }))
        .expect("typed ECALL control-flow receipt")
    }

    #[test]
    fn s28_mutation_is_family_scoped() {
        let branch_kind =
            inject_kind_with_variant(S28_INJECT_KIND, "family=branch,mode=force_fallthrough");
        assert_eq!(mutated_control_flow_next_pc(&branch_kind, Opcode::BEQ, 0x20, 0x28), Some(0x24));
        assert_eq!(mutated_control_flow_next_pc(&branch_kind, Opcode::ECALL, 0x20, 0x24), None);

        let jump_kind =
            inject_kind_with_variant(S28_INJECT_KIND, "family=jump,mode=force_sequential");
        assert_eq!(mutated_control_flow_next_pc(&jump_kind, Opcode::JAL, 0x40, 0x80), Some(0x44));

        let ecall_kind = inject_kind_with_variant(S28_INJECT_KIND, "family=ecall,mode=near_jump");
        assert_eq!(
            mutated_control_flow_next_pc(&ecall_kind, Opcode::ECALL, 0x80, 0x84),
            Some(0x88)
        );
    }

    #[test]
    fn control_flow_hit_uses_family_specific_schedule_and_class() {
        let mut backend = Sp1Backend::new(16);
        backend
            .last_observed_injection_sites
            .insert(control_flow_site_key("branch"), vec![12, 4, 9]);

        let mut details = HashMap::new();
        details.insert("step_idx".to_string(), json!(8));
        details.insert("control_flow_family".to_string(), json!("branch"));
        let hit = BucketHit::semantic(semantic::exec::CONTROL_FLOW_BINDING, details);

        let candidates = backend.semantic_candidate_from_hit(&hit);
        assert!(!candidates.is_empty());
        assert!(candidates.iter().all(
            |candidate| candidate.semantic_class == control_flow_semantic_class(Some("branch"))
        ));
        assert!(candidates.iter().all(|candidate| candidate.inject_kind.contains("family=branch")));

        match &candidates[0].schedule {
            InjectionSchedule::Explicit(steps) => assert_eq!(steps, &vec![9, 4, 12]),
            other => panic!("expected explicit branch schedule, got {other:?}"),
        }
    }

    #[test]
    fn control_flow_hit_derives_family_from_mnemonic_without_defaulting_to_ecall() {
        let backend = Sp1Backend::new(16);
        let mut details = HashMap::new();
        details.insert("step_idx".to_string(), json!(3));
        details.insert("mnemonic".to_string(), json!("beq"));
        let hit = BucketHit::semantic(semantic::exec::CONTROL_FLOW_BINDING, details);

        let candidates = backend.semantic_candidate_from_hit(&hit);
        assert!(!candidates.is_empty());
        assert!(candidates.iter().all(|candidate| candidate.inject_kind.contains("family=branch")));
        assert!(candidates.iter().all(|candidate| !candidate.inject_kind.contains("family=ecall")));
    }

    #[test]
    fn familyless_non_control_flow_hit_does_not_produce_ecall_candidate() {
        let backend = Sp1Backend::new(16);
        let mut details = HashMap::new();
        details.insert("step_idx".to_string(), json!(3));
        details.insert("mnemonic".to_string(), json!("addi"));
        let hit = BucketHit::semantic(semantic::exec::CONTROL_FLOW_BINDING, details);

        let candidates = backend.semantic_candidate_from_hit(&hit);
        assert!(candidates.is_empty());
    }

    #[test]
    fn s28_family_specs_contain_only_real_mutations() {
        let specs = Sp1Backend::s28_variant_specs_for_family("ecall");
        assert_eq!(specs[0], "family=ecall,mode=near_jump");
        assert_eq!(specs[1], "family=ecall,mode=mid_jump");
        assert_eq!(specs[2], "family=ecall,mode=legacy_far_jump");
        assert_eq!(specs.len(), 3);
        assert!(specs.iter().all(|spec| !spec.contains("noop_prefix")));
    }

    #[test]
    fn s28_receipt_recomputes_each_real_mode_from_baseline_executed_anchor() {
        for (mode, after) in [("near_jump", 24), ("mid_jump", 80), ("legacy_far_jump", 65_552)] {
            let kind = format!("sp1.semantic.exec.control_flow_binding::family=ecall,mode={mode}");
            assert!(valid_executed_control_flow_receipt(
                &ecall_receipt(mode, after),
                &kind,
                9,
                &ecall_anchor(),
            ));
        }
    }

    #[test]
    fn s28_receipt_rejects_wrong_relation_kind_anchor_opcode_pc_context_and_noop() {
        let kind = "sp1.semantic.exec.control_flow_binding::family=ecall,mode=near_jump";
        let check = |receipt: &SemanticMutationReceipt, requested_kind: &str, step: u64| {
            valid_executed_control_flow_receipt(receipt, requested_kind, step, &ecall_anchor())
        };

        let mut wrong_relation = ecall_receipt("near_jump", 24);
        wrong_relation.effect.relation = SemanticMutationRelation::MemorySelectorEquation;
        assert!(!check(&wrong_relation, kind, 9));

        let mut wrong_kind = ecall_receipt("near_jump", 24);
        wrong_kind.inject_kind = S28_INJECT_KIND.to_string();
        assert!(!check(&wrong_kind, kind, 9));

        let mut wrong_anchor = ecall_receipt("near_jump", 24);
        wrong_anchor.effect.context.insert("anchor".to_string(), json!(8));
        assert!(!check(&wrong_anchor, kind, 9));
        assert!(!check(&ecall_receipt("near_jump", 24), kind, 8));

        let mut wrong_opcode = ecall_receipt("near_jump", 24);
        wrong_opcode.effect.context.insert("opcode".to_string(), json!(0x63));
        assert!(!check(&wrong_opcode, kind, 9));

        let mut wrong_source_selector = ecall_receipt("near_jump", 24);
        wrong_source_selector.effect.context.insert("sp1_opcode".to_string(), json!(18));
        assert!(!check(&wrong_source_selector, kind, 9));

        let mut wrong_pc = ecall_receipt("near_jump", 24);
        wrong_pc.effect.context.insert("pc".to_string(), json!(20));
        assert!(!check(&wrong_pc, kind, 9));

        let mut wrong_op_idx = ecall_receipt("near_jump", 24);
        wrong_op_idx.effect.context.insert("op_idx".to_string(), json!(8));
        assert!(!check(&wrong_op_idx, kind, 9));

        let mut stale_commit = ecall_receipt("near_jump", 24);
        stale_commit.effect.context.insert("commit".to_string(), json!("stale"));
        assert!(!check(&stale_commit, kind, 9));

        let mut wrong_bucket = ecall_receipt("near_jump", 24);
        wrong_bucket.effect.context.insert("bucket_id".to_string(), json!("sem.exec.dest_binding"));
        assert!(!check(&wrong_bucket, kind, 9));

        let mut wrong_cell = ecall_receipt("near_jump", 24);
        wrong_cell.effect.context.insert("cell_id".to_string(), json!("cf6.near_segment_end"));
        assert!(!check(&wrong_cell, kind, 9));

        let mut wrong_mode = ecall_receipt("near_jump", 24);
        wrong_mode.effect.context.insert("mode".to_string(), json!("mid_jump"));
        assert!(!check(&wrong_mode, kind, 9));

        assert!(!check(&ecall_receipt("near_jump", 80), kind, 9));
        let noop_kind =
            "sp1.semantic.exec.control_flow_binding::family=ecall,mode=noop_prefix,rank=0";
        assert!(!check(&ecall_receipt("noop_prefix", 20), noop_kind, 9));
    }

    #[test]
    fn s28_route_maps_only_ecall_candidates_to_executed_control_flow_equation() {
        let backend = Sp1Backend::new(16);
        let mut details = HashMap::new();
        details.insert("step_idx".to_string(), json!(9));
        details.insert("mnemonic".to_string(), json!("ecall"));
        details.insert("control_flow_family".to_string(), json!("ecall"));
        details.insert("pc".to_string(), json!(16));
        details.insert("next_pc".to_string(), json!(20));
        details.insert("ecall_x5".to_string(), json!(1));
        details.insert("ecall_x10".to_string(), json!(3));
        details.insert("ecall_x11".to_string(), json!(0x1000));
        details.insert("ecall_x12".to_string(), json!(4));
        let hit = BucketHit::semantic(semantic::exec::CONTROL_FLOW_BINDING, details);
        let candidates = backend.semantic_candidate_from_hit(&hit);
        let real_candidates: Vec<_> = candidates
            .iter()
            .filter(|candidate| !candidate.inject_kind.contains("mode=noop_prefix"))
            .collect();
        assert_eq!(real_candidates.len(), 3);
        assert!(real_candidates.iter().all(|candidate| {
            backend.semantic_mutation_relation(candidate)
                == Some(SemanticMutationRelation::ExecutedControlFlowEquation)
        }));

        let mut wrong_family = (*real_candidates[0]).clone();
        wrong_family.inject_kind =
            inject_kind_with_variant(S28_INJECT_KIND, "family=branch,mode=force_fallthrough");
        assert_eq!(backend.semantic_mutation_relation(&wrong_family), None);

        let mut wrong_bucket = (*real_candidates[0]).clone();
        wrong_bucket.bucket_id = semantic::exec::DEST_BINDING.id.to_string();
        assert_eq!(backend.semantic_mutation_relation(&wrong_bucket), None);
    }

    #[test]
    fn family_qualified_control_flow_steps_are_family_scoped() {
        let mut sites = BTreeMap::new();
        sites.insert(S28_INJECT_KIND.to_string(), vec![4, 9]);
        sites.insert(control_flow_site_key("branch"), vec![4]);
        sites.insert(control_flow_site_key("ecall"), vec![9]);

        let ecall_kind = inject_kind_with_variant(S28_INJECT_KIND, "family=ecall,mode=near_jump");
        let branch_kind =
            inject_kind_with_variant(S28_INJECT_KIND, "family=branch,mode=force_fallthrough");

        assert_eq!(resolve_runtime_injection_step(Some(&ecall_kind), 9, &sites), Some(9));
        assert_eq!(resolve_runtime_injection_step(Some(&ecall_kind), 4, &sites), None);
        assert_eq!(resolve_runtime_injection_step(Some(&ecall_kind), u64::MAX, &sites), Some(9));
        assert_eq!(resolve_runtime_injection_step(Some(&branch_kind), 4, &sites), Some(4));
        assert_eq!(resolve_runtime_injection_step(Some(&branch_kind), 9, &sites), None);
    }

    #[test]
    #[ignore = "diagnostic SP1 prover run; r2 validation uses focused source-level relation tests"]
    fn s28_official_run_test_path_applies_injection() {
        let words = vec![0x0020_0293, 0x0030_0513, 0x0000_0593, 0x0000_0613, 0x0000_0073];

        let baseline = run_backend_once(1, &words, 10_000, None, 0).expect("baseline run");
        assert!(
            baseline.backend_error.is_none(),
            "baseline backend_error={:?}",
            baseline.backend_error
        );

        let injected = run_backend_once(
            2,
            &words,
            10_000,
            Some("sp1.semantic.exec.control_flow_binding::family=ecall,mode=near_jump"),
            u64::MAX,
        )
        .expect("injected run");

        assert!(injected.injection_applied, "s28 official path did not apply injection");
        assert!(
            injected.semantic_mutation_receipt.is_some(),
            "s28 official path did not return a validated typed receipt; backend_error={:?}",
            injected.backend_error,
        );
    }
}
