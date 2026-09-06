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
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use serde::{Deserialize, Serialize};
use sp1_core_executor::{ByteOpcode, ExecutionRecord, Executor, ExecutorMode, Opcode};
use sp1_core_machine::{io::SP1Stdin, utils::run_test};
use sp1_stark::{CpuProver, SP1CoreOpts};

use crate::trace::{build_sp1_program, decode_word_to_sp1_instruction, Sp1Trace};

const MEMORY_EFFECT_INJECT_KIND: &str = "sp1.semantic.exec.memory_effect_binding";
const SP1_COMMIT: &str = "39ab52fce38172c9d23feed7248198dc14c164a9";
const MEMORY_ADDRESS_INJECT_KIND: &str = "sp1.semantic.memory.address_pointer_consistency";
const MEMORY_VALUE_INJECT_KIND: &str = "sp1.semantic.memory.value_payload_consistency";
const MEMORY_STORE_LOAD_INJECT_KIND: &str = "sp1.semantic.memory.store_load_payload_flow";
const MEMORY_KIND_SELECTOR_INJECT_KIND: &str = "sp1.semantic.memory.kind_selector_consistency";
const TIME_MONOTONIC_INJECT_KIND: &str = "sp1.semantic.time.monotonic_access_ordering";
const LOOKUP_BOOLEAN_INJECT_KIND: &str = "sp1.semantic.lookup.boolean_multiplicity";
const CONTROL_FLOW_INJECT_KIND: &str = "sp1.semantic.exec.control_flow_binding";
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
const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";
static WITNESS_RUN_SEQ: AtomicU64 = AtomicU64::new(1);

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

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn receipt_context_u64(receipt: &SemanticMutationReceipt, key: &str) -> Option<u64> {
    receipt.effect.context.get(key).and_then(|value| value.as_u64())
}

fn receipt_context_str<'a>(receipt: &'a SemanticMutationReceipt, key: &str) -> Option<&'a str> {
    receipt.effect.context.get(key).and_then(|value| value.as_str())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutedMemorySelectorAnchor {
    step: u64,
    op_idx: u64,
    pc: u32,
    rv_instruction: u32,
    sp1_opcode: u32,
    mnemonic: String,
}

fn encode_memory_rv_instruction(instruction: &sp1_core_executor::Instruction) -> Option<u32> {
    let funct3 = match instruction.opcode {
        Opcode::LB | Opcode::SB => 0,
        Opcode::LH | Opcode::SH => 1,
        Opcode::LW | Opcode::SW => 2,
        Opcode::LBU => 4,
        Opcode::LHU => 5,
        _ => return None,
    };
    let imm = instruction.op_c & 0x0fff;
    Some(if instruction.is_memory_load_instruction() {
        (imm << 20)
            | ((instruction.op_b & 31) << 15)
            | (funct3 << 12)
            | ((instruction.op_a as u32 & 31) << 7)
            | 0x03
    } else {
        (((imm >> 5) & 0x7f) << 25)
            | ((instruction.op_a as u32 & 31) << 20)
            | ((instruction.op_b & 31) << 15)
            | (funct3 << 12)
            | ((imm & 0x1f) << 7)
            | 0x23
    })
}

fn memory_selector_anchors(
    records: &[ExecutionRecord],
) -> BTreeMap<u64, ExecutedMemorySelectorAnchor> {
    let mut anchors = BTreeMap::new();
    let mut flat_cpu_idx = 0u64;
    for record in records {
        for event in &record.cpu_events {
            let instruction = record.program.fetch(event.pc);
            if instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction()
            {
                let step = flat_cpu_idx;
                let Some(rv_instruction) = encode_memory_rv_instruction(instruction) else {
                    flat_cpu_idx = flat_cpu_idx.saturating_add(1);
                    continue;
                };
                anchors.insert(
                    step,
                    ExecutedMemorySelectorAnchor {
                        step,
                        op_idx: flat_cpu_idx,
                        pc: event.pc,
                        rv_instruction,
                        sp1_opcode: instruction.opcode as u32,
                        mnemonic: instruction.opcode.mnemonic().to_string(),
                    },
                );
            }
            flat_cpu_idx = flat_cpu_idx.saturating_add(1);
        }
    }
    anchors
}

fn valid_memory_selector_receipt(
    receipt: &SemanticMutationReceipt,
    requested_kind: &str,
    resolved_step: u64,
    executed_anchor: &ExecutedMemorySelectorAnchor,
) -> bool {
    if base_inject_kind(requested_kind) != MEMORY_EFFECT_INJECT_KIND
        || receipt.inject_kind != requested_kind
        || receipt.site != "cpu_chip.generate_trace"
        || receipt.field != "is_memory"
        || receipt.step != resolved_step
        || receipt.effect.relation != SemanticMutationRelation::MemorySelectorEquation
        || receipt_context_str(receipt, "bucket_id")
            != Some(semantic::exec::MEMORY_EFFECT_BINDING.id)
        || receipt_context_str(receipt, "obligation_id") != Some("me10")
        || receipt_context_str(receipt, "backend") != Some("sp1")
        || receipt_context_str(receipt, "commit") != Some(SP1_COMMIT)
        || receipt_context_str(receipt, "trace_source") != Some("instruction")
        || receipt.effect.context.get("executed_cpu_row") != Some(&serde_json::json!(true))
        || receipt_context_u64(receipt, "anchor") != Some(resolved_step)
        || executed_anchor.step != resolved_step
    {
        return false;
    }
    let Some(opcode) = receipt_context_u64(receipt, "opcode") else {
        return false;
    };
    let Some(mnemonic) = receipt_context_str(receipt, "mnemonic") else {
        return false;
    };
    let Some(sp1_opcode) = receipt_context_u64(receipt, "sp1_opcode") else {
        return false;
    };
    let expected_cell = match (opcode & 0x7f, sp1_opcode, mnemonic) {
        (0x03, value, "lb") if value == Opcode::LB as u64 => "me10.load",
        (0x03, value, "lh") if value == Opcode::LH as u64 => "me10.load",
        (0x03, value, "lw") if value == Opcode::LW as u64 => "me10.load",
        (0x03, value, "lbu") if value == Opcode::LBU as u64 => "me10.load",
        (0x03, value, "lhu") if value == Opcode::LHU as u64 => "me10.load",
        (0x23, value, "sb") if value == Opcode::SB as u64 => "me10.store",
        (0x23, value, "sh") if value == Opcode::SH as u64 => "me10.store",
        (0x23, value, "sw") if value == Opcode::SW as u64 => "me10.store",
        _ => return false,
    };
    let before = receipt.before.as_u64();
    let after = receipt.after.as_u64();
    receipt_context_str(receipt, "cell_id") == Some(expected_cell)
        && receipt_context_u64(receipt, "expected_is_memory") == Some(1)
        && receipt_context_u64(receipt, "step") == Some(resolved_step)
        && receipt_context_u64(receipt, "op_idx") == Some(executed_anchor.op_idx)
        && receipt_context_u64(receipt, "pc") == Some(executed_anchor.pc as u64)
        && opcode == executed_anchor.rv_instruction as u64
        && sp1_opcode == executed_anchor.sp1_opcode as u64
        && mnemonic == executed_anchor.mnemonic
        && receipt_context_u64(receipt, "source_selector") == Some(sp1_opcode)
        && receipt_context_u64(receipt, "selector_before") == before
        && receipt_context_u64(receipt, "selector_after") == after
        && before == Some(1)
        && after == Some(0)
}

fn take_valid_semantic_mutation_receipt(
    raw: Option<serde_json::Value>,
    requested_kind: Option<&str>,
    resolved_step: Option<u64>,
    executed_anchors: &BTreeMap<u64, ExecutedMemorySelectorAnchor>,
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
            valid_memory_selector_receipt(&receipt, kind, step, anchor)
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
    inject_kind_with_variant(CONTROL_FLOW_INJECT_KIND, &format!("family={family}"))
}

fn control_flow_semantic_class(family: Option<&str>) -> String {
    match family {
        Some(family) => {
            format!("{}.{}", semantic::exec::CONTROL_FLOW_BINDING.semantic_class, family)
        }
        None => semantic::exec::CONTROL_FLOW_BINDING.semantic_class.to_string(),
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

fn supports_official_injection_kind(kind: &str) -> bool {
    matches!(
        base_inject_kind(kind),
        MEMORY_EFFECT_INJECT_KIND
            | MEMORY_ADDRESS_INJECT_KIND
            | MEMORY_VALUE_INJECT_KIND
            | MEMORY_STORE_LOAD_INJECT_KIND
            | MEMORY_KIND_SELECTOR_INJECT_KIND
            | TIME_MONOTONIC_INJECT_KIND
            | LOOKUP_BOOLEAN_INJECT_KIND
            | CONTROL_FLOW_INJECT_KIND
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

fn supports_official_injection(inject_kind: Option<&str>) -> bool {
    inject_kind.map(supports_official_injection_kind).unwrap_or(true)
}

fn panic_payload_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
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

            let memory_effect_witness_step = flat_cpu_idx;
            let cpu_semantic_witness_step = flat_cpu_idx.saturating_mul(2).saturating_add(1);
            if instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction()
            {
                record_site(&mut sites, MEMORY_EFFECT_INJECT_KIND, memory_effect_witness_step);
            }
            if let Some(family) = control_flow_family_for_opcode(instruction.opcode) {
                record_site(&mut sites, CONTROL_FLOW_INJECT_KIND, flat_cpu_idx);
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
                record_site(&mut sites, kind, cpu_semantic_witness_step);
            }
            flat_cpu_idx = flat_cpu_idx.saturating_add(1);
        }
        for event in &record.memory_instr_events {
            record_memory_instr_sites(&mut sites, event.opcode, memory_hook_step);
            memory_hook_step = memory_hook_step.saturating_add(1);
        }
        for (syscall_event, _) in record.precompile_events.all_events() {
            record_site(&mut sites, MEMORY_ADDRESS_INJECT_KIND, syscall_event.clk as u64);
        }
        for event in &record.global_memory_initialize_events {
            if event.used != 0 {
                record_site(&mut sites, MEMORY_ADDRESS_INJECT_KIND, event.timestamp as u64);
            }
        }
        for event in &record.global_memory_finalize_events {
            if event.used != 0 {
                record_site(&mut sites, MEMORY_ADDRESS_INJECT_KIND, event.timestamp as u64);
            }
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

fn resolve_injection_step(
    inject_kind: Option<&str>,
    inject_step: u64,
    observed_injection_sites: &BTreeMap<String, Vec<u64>>,
) -> Option<u64> {
    let kind = inject_kind?;
    if !supports_official_injection_kind(kind) {
        return None;
    }
    let steps = observed_injection_sites.get(base_inject_kind(kind))?;
    if inject_step == u64::MAX {
        steps.first().copied()
    } else if steps.contains(&inject_step) {
        Some(inject_step)
    } else {
        None
    }
}

fn with_scoped_injection_env<T>(
    inject_kind: Option<&str>,
    inject_step: Option<u64>,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let prev_kind = std::env::var("BEAK_SP1_WITNESS_INJECT_KIND").ok();
    let prev_step = std::env::var("BEAK_SP1_WITNESS_INJECT_STEP").ok();
    let prev_run_id = std::env::var("BEAK_SP1_WITNESS_RUN_ID").ok();
    let run_id = WITNESS_RUN_SEQ.fetch_add(1, Ordering::Relaxed);

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
    std::env::set_var("BEAK_SP1_WITNESS_RUN_ID", format!("sp1-39ab52fc-{run_id}"));

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

fn run_sp1_prove_verify(
    program: sp1_core_executor::Program,
    inject_kind: Option<&str>,
    inject_step: u64,
    observed_injection_sites: &BTreeMap<String, Vec<u64>>,
    executed_anchors: &BTreeMap<u64, ExecutedMemorySelectorAnchor>,
) -> (bool, bool, Option<String>, bool, Option<SemanticMutationReceipt>) {
    if !supports_official_injection(inject_kind) {
        return (
            false,
            false,
            Some(format!(
                "sp1-39ab52fc has no installed hook/applied signal for requested kind {}; mapped hooks are CPU-row decode/register hooks, ALU/mul/div chip hooks, {MEMORY_EFFECT_INJECT_KIND}, {CONTROL_FLOW_INJECT_KIND}, v4 memory-instruction hooks, and byte-table multiplicity hooks",
                inject_kind.unwrap_or_default()
            )),
            false,
            None,
        );
    }
    let resolved_step = resolve_injection_step(inject_kind, inject_step, observed_injection_sites);
    let injection_scheduled = inject_kind.is_some() && resolved_step.is_some();
    let mut proof_injection_applied = false;
    let mut raw_semantic_mutation_receipt = None;

    let prove_result = with_scoped_injection_env(
        inject_kind.filter(|kind| supports_official_injection_kind(kind)),
        resolved_step,
        || {
            let previous_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_test::<CpuProver<_, _>>(program, SP1Stdin::new())
            }));
            proof_injection_applied = fuzzer_utils::injection_was_applied();
            raw_semantic_mutation_receipt = fuzzer_utils::take_semantic_mutation_receipt();
            std::panic::set_hook(previous_hook);
            match result {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(err)) => Err(format!("sp1 v4 prove/verify failed: {err}")),
                Err(panic) => {
                    Err(format!("sp1 v4 prove/verify panicked: {}", panic_payload_message(&*panic)))
                }
            }
        },
    );

    let semantic_mutation_receipt = match take_valid_semantic_mutation_receipt(
        raw_semantic_mutation_receipt,
        inject_kind,
        resolved_step,
        executed_anchors,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            return (
                true,
                false,
                Some(error),
                injection_scheduled && proof_injection_applied,
                None,
            );
        }
    };

    match prove_result {
        Ok(()) => (
            true,
            true,
            None,
            injection_scheduled && proof_injection_applied,
            semantic_mutation_receipt,
        ),
        Err(err) => (
            true,
            false,
            Some(err),
            injection_scheduled && proof_injection_applied,
            semantic_mutation_receipt,
        ),
    }
}

fn run_sp1_real_backend(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RealRunnerResponse, String> {
    let program = build_sp1_program(words)?;
    let mut executor = Executor::new(program.clone(), SP1CoreOpts::default());
    executor.executor_mode = ExecutorMode::Trace;
    executor.run().map_err(|e| format!("sp1 executor run failed: {e}"))?;

    let trace = Sp1Trace::from_execution_records(words, &executor.records)?;
    let observed_injection_sites = collect_observed_injection_sites(&executor.records);
    let executed_anchors = memory_selector_anchors(&executor.records);
    let (prove_ok, verify_ok, prove_verify_error, injection_applied, semantic_mutation_receipt) =
        run_sp1_prove_verify(
            program,
            inject_kind,
            inject_step,
            &observed_injection_sites,
            &executed_anchors,
        );

    Ok(RealRunnerResponse {
        final_regs: Some(executor.registers()),
        micro_op_count: trace.instruction_count(),
        bucket_hits: trace.bucket_hits().to_vec(),
        trace_signals: trace.trace_signals().to_vec(),
        prove_ok,
        verify_ok,
        error: prove_verify_error,
        observed_injection_sites,
        injection_applied,
        semantic_mutation_receipt,
    })
}

pub fn run_backend_once(
    request_id: u64,
    words: &[u32],
    _current_iteration: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<WorkerResponse, String> {
    let mut backend_error = None;
    let mut final_regs = None;
    let mut micro_op_count = 0usize;
    let mut bucket_hits = Vec::new();
    let mut trace_signals = Vec::new();
    let mut observed_injection_sites = BTreeMap::new();
    let mut injection_applied = false;
    let mut semantic_mutation_receipt = None;

    let runner_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_sp1_real_backend(words, inject_kind, inject_step)
    }));
    match runner_res {
        Ok(Ok(resp)) => {
            final_regs = resp.final_regs;
            micro_op_count = resp.micro_op_count;
            bucket_hits = resp.bucket_hits;
            trace_signals = resp.trace_signals;
            observed_injection_sites = resp.observed_injection_sites;
            injection_applied = resp.injection_applied;
            semantic_mutation_receipt = resp.semantic_mutation_receipt;
            if let Some(err) = resp.error {
                backend_error = Some(err);
            } else if !resp.prove_ok || !resp.verify_ok {
                backend_error = Some(format!(
                    "sp1 v4 backend did not complete prove+verify successfully (prove_ok={}, verify_ok={})",
                    resp.prove_ok, resp.verify_ok
                ));
            }
        }
        Ok(Err(e)) => {
            backend_error = Some(e);
        }
        Err(p) => {
            let msg = panic_payload_message(&*p);
            backend_error = Some(format!("backend panic: {msg}"));
        }
    }

    Ok(WorkerResponse {
        request_id,
        final_regs,
        micro_op_count,
        bucket_hits,
        trace_signals,
        backend_error,
        observed_injection_sites,
        injection_applied,
        semantic_mutation_receipt,
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
            .get("syscall_clk")
            .and_then(|v| v.as_u64())
            .or_else(|| hit.details.get("timestamp").and_then(|v| v.as_u64()))
            .or_else(|| hit.details.get("store_step_idx").and_then(|v| v.as_u64()))
            .or_else(|| hit.details.get("memory_hook_step").and_then(|v| v.as_u64()))
            .unwrap_or_else(|| Self::step_from_hit(hit))
    }

    fn detail_str<'a>(hit: &'a BucketHit, key: &str) -> Option<&'a str> {
        hit.details.get(key).and_then(|value| value.as_str())
    }

    fn detail_u64(hit: &BucketHit, key: &str) -> Option<u64> {
        hit.details
            .get(key)
            .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse::<u64>().ok()))
    }

    fn memory_address_inject_kind_from_hit(hit: &BucketHit) -> String {
        match Self::detail_str(hit, "trace_source") {
            Some("precompile_events") => {
                let phase = Self::detail_str(hit, "precompile_phase");
                let site = if hit.bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id {
                    "precompile_global_alignment"
                } else {
                    match phase {
                        Some("sha_compress.w_read") => "sha_compress_w_slice",
                        Some("sha_compress.h_read") | Some("sha_compress.h_write") => {
                            "sha_compress_h_slice"
                        }
                        Some(phase) if phase.starts_with("sha_extend.") => "sha_extend_w_slice",
                        _ => "precompile_slice",
                    }
                };
                let mut fields =
                    vec!["site=".to_string() + site, "trace_source=precompile_events".to_string()];
                if let Some(precompile) = Self::detail_str(hit, "precompile") {
                    fields.push(format!("precompile={precompile}"));
                }
                if let Some(phase) = phase {
                    fields.push(format!("phase={phase}"));
                }
                if let Some(ptr) = Self::detail_u64(hit, "effective_ptr") {
                    fields.push(format!("effective_ptr={ptr}"));
                }
                if let Some(width) = Self::detail_u64(hit, "width") {
                    fields.push(format!("width={width}"));
                }
                if let Some(slice_len_words) = Self::detail_u64(hit, "slice_len_words") {
                    fields.push(format!("slice_len_words={slice_len_words}"));
                }
                if hit.details.get("is_read").and_then(|v| v.as_bool()) == Some(true) {
                    fields.push("access=read".to_string());
                } else if hit.details.get("is_write").and_then(|v| v.as_bool()) == Some(true) {
                    fields.push("access=write".to_string());
                }
                inject_kind_with_variant(MEMORY_ADDRESS_INJECT_KIND, &fields.join(","))
            }
            Some("global_memory_initialize_event") | Some("global_memory_finalize_event") => {
                let mut fields = vec!["site=global_event".to_string()];
                if let Some(source) = Self::detail_str(hit, "trace_source") {
                    fields.push(format!("trace_source={source}"));
                }
                if let Some(phase) = Self::detail_str(hit, "phase") {
                    fields.push(format!("phase={phase}"));
                }
                if let Some(ptr) = Self::detail_u64(hit, "effective_ptr") {
                    fields.push(format!("effective_ptr={ptr}"));
                }
                if let Some(event_idx) = Self::detail_u64(hit, "global_memory_event_idx") {
                    fields.push(format!("event_idx={event_idx}"));
                }
                inject_kind_with_variant(MEMORY_ADDRESS_INJECT_KIND, &fields.join(","))
            }
            _ => inject_kind_with_variant(MEMORY_ADDRESS_INJECT_KIND, "site=addr_word"),
        }
    }

    fn uses_detail_scheduled_memory_address_hook(inject_kind: &str) -> bool {
        if base_inject_kind(inject_kind) != MEMORY_ADDRESS_INJECT_KIND {
            return false;
        }
        inject_kind.contains("site=global_event")
            || inject_kind.contains("site=precompile_global_alignment")
            || inject_kind.contains("site=precompile_slice")
            || inject_kind.contains("site=sha_compress_")
            || inject_kind.contains("site=sha_extend_")
    }

    fn byte_lookup_step_from_hit(hit: &BucketHit) -> u64 {
        hit.details
            .get("byte_lookup_step")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| Self::step_from_hit(hit))
    }

    fn mnemonic_from_hit(hit: &BucketHit) -> Option<&str> {
        hit.details.get("mnemonic").and_then(|value| value.as_str())
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

    fn inject_kinds_for_base(inject_kind: &str) -> Vec<String> {
        match inject_kind {
            CONTROL_FLOW_INJECT_KIND => {
                vec![
                    inject_kind.to_string(),
                    inject_kind_with_variant(inject_kind, "family=branch"),
                    inject_kind_with_variant(inject_kind, "family=jump"),
                    inject_kind_with_variant(inject_kind, "family=ecall"),
                ]
            }
            _ => vec![inject_kind.to_string()],
        }
    }

    fn control_family_from_hit(hit: &BucketHit) -> Option<&'static str> {
        hit.details
            .get("control_flow_family")
            .and_then(|v| v.as_str())
            .or_else(|| hit.details.get("semantic_subclass").and_then(|v| v.as_str()))
            .and_then(|family| match family {
                "branch" => Some("branch"),
                "jump" => Some("jump"),
                "ecall" => Some("ecall"),
                _ => None,
            })
            .or_else(|| {
                hit.details.get("cell_id").and_then(|v| v.as_str()).and_then(|cell| match cell {
                    cell if cell.starts_with("cf1.") => Some("branch"),
                    cell if cell.starts_with("cf2.") || cell.starts_with("cf3.") => Some("jump"),
                    cell if cell.starts_with("cf7.") => Some("ecall"),
                    _ => None,
                })
            })
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
        let (semantic_class, inject_kind, fallback_schedule) = if bucket_id
            == semantic::exec::MEMORY_EFFECT_BINDING.id
        {
            (
                semantic::exec::MEMORY_EFFECT_BINDING.semantic_class.to_string(),
                MEMORY_EFFECT_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id {
            (
                semantic::memory::STORE_LOAD_PAYLOAD_FLOW.semantic_class.to_string(),
                inject_kind_with_variant(MEMORY_STORE_LOAD_INJECT_KIND, "site=access_value"),
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
                Self::memory_address_inject_kind_from_hit(hit),
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
                inject_kind_with_variant(MEMORY_VALUE_INJECT_KIND, "site=access_value"),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id {
            (
                semantic::memory::KIND_SELECTOR_CONSISTENCY.semantic_class.to_string(),
                inject_kind_with_variant(MEMORY_KIND_SELECTOR_INJECT_KIND, "site=kind_selector"),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id
            || bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id
        {
            (
                semantic::time::MONOTONIC_ACCESS_ORDERING.semantic_class.to_string(),
                inject_kind_with_variant(TIME_MONOTONIC_INJECT_KIND, "site=prev_clk"),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::lookup::BOOLEAN_MULTIPLICITY.id {
            (
                semantic::lookup::BOOLEAN_MULTIPLICITY.semantic_class.to_string(),
                LOOKUP_BOOLEAN_INJECT_KIND.to_string(),
                InjectionSchedule::Explicit(vec![anchor]),
            )
        } else if bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id {
            let family = Self::control_family_from_hit(hit);
            (
                control_flow_semantic_class(family),
                family
                    .map(control_flow_site_key)
                    .unwrap_or_else(|| CONTROL_FLOW_INJECT_KIND.to_string()),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id {
            (
                semantic::decode::ZERO_REGISTER_IMMUTABILITY.semantic_class.to_string(),
                inject_kind_with_variant(RF1_INJECT_KIND, "site=op_a_access"),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::decode::OPERAND_INDEX_ROUTING.id {
            (
                semantic::decode::OPERAND_INDEX_ROUTING.semantic_class.to_string(),
                inject_kind_with_variant(RF2_INJECT_KIND, "site=op_b_access"),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::exec::DEST_BINDING.id {
            (
                semantic::exec::DEST_BINDING.semantic_class.to_string(),
                inject_kind_with_variant(RF3_INJECT_KIND, "site=op_a_access"),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::decode::FIELD_RANGE.id {
            (
                semantic::decode::FIELD_RANGE.semantic_class.to_string(),
                inject_kind_with_variant(ID1_INJECT_KIND, "site=instruction_op_a"),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::decode::IMMEDIATE_SIGN_EXTENSION.id {
            (
                semantic::decode::IMMEDIATE_SIGN_EXTENSION.semantic_class.to_string(),
                inject_kind_with_variant(ID2_INJECT_KIND, "site=instruction_op_c"),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::exec::OP_SELECTOR_BINDING.id {
            (
                semantic::exec::OP_SELECTOR_BINDING.semantic_class.to_string(),
                inject_kind_with_variant(ID4_INJECT_KIND, "site=opcode"),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.id {
            (
                semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.semantic_class.to_string(),
                inject_kind_with_variant(ID5_INJECT_KIND, "site=instruction_op_c"),
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
                AL1_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::alu::SHIFT_MOD32.id {
            (
                semantic::alu::SHIFT_MOD32.semantic_class.to_string(),
                AL2_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::alu::COMPARISON_BOOLEANITY.id {
            (
                semantic::alu::COMPARISON_BOOLEANITY.semantic_class.to_string(),
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
                AL4_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id {
            (
                semantic::alu::COMPARISON_AUXILIARY_CHAIN.semantic_class.to_string(),
                AL5_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id {
            (
                semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.semantic_class.to_string(),
                MD_SPECIAL_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id {
            (
                semantic::arithmetic::DIVISION_REMAINDER_BOUND.semantic_class.to_string(),
                MD3_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::arithmetic::PRODUCT_DECOMPOSITION.id {
            (
                semantic::arithmetic::PRODUCT_DECOMPOSITION.semantic_class.to_string(),
                MD4_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else if bucket_id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id {
            (
                semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.semantic_class.to_string(),
                MD5_INJECT_KIND.to_string(),
                InjectionSchedule::AroundAnchor(anchor),
            )
        } else {
            return Vec::new();
        };

        let schedule_key = base_inject_kind(inject_kind.as_str());
        let schedule = if Self::uses_detail_scheduled_memory_address_hook(inject_kind.as_str()) {
            fallback_schedule
        } else {
            self.last_observed_injection_sites
                .get(schedule_key)
                .map(|steps| {
                    InjectionSchedule::Explicit(Self::ordered_steps_around_anchor(steps, anchor))
                })
                .unwrap_or(fallback_schedule)
        };

        Self::inject_kinds_for_base(inject_kind.as_str())
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

    fn semantic_candidate_priority(candidate: &SemanticInjectionCandidate) -> u8 {
        let bucket_id = candidate.bucket_id.as_str();
        if (bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id
            || bucket_id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id)
            && Self::uses_detail_scheduled_memory_address_hook(candidate.inject_kind.as_str())
        {
            0
        } else if bucket_id == semantic::exec::MEMORY_EFFECT_BINDING.id {
            1
        } else if bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id {
            2
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
            3
        } else {
            4
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
        words.iter().all(|w| decode_word_to_sp1_instruction(*w).is_ok())
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
        (candidate.bucket_id == semantic::exec::MEMORY_EFFECT_BINDING.id
            && base_inject_kind(candidate.inject_kind.as_str()) == MEMORY_EFFECT_INJECT_KIND)
            .then_some(SemanticMutationRelation::MemorySelectorEquation)
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
mod relation_tests {
    use super::{
        valid_memory_selector_receipt, ExecutedMemorySelectorAnchor, SemanticMutationReceipt,
        SemanticMutationRelation, Sp1Backend, MEMORY_EFFECT_INJECT_KIND,
    };
    use beak_core::fuzz::benchmark::BenchmarkBackend;
    use beak_core::trace::{semantic, BucketHit};
    use serde_json::json;
    use std::collections::HashMap;

    fn anchor() -> ExecutedMemorySelectorAnchor {
        ExecutedMemorySelectorAnchor {
            step: 3,
            op_idx: 3,
            pc: 0x0020_0400,
            rv_instruction: 0x0041_2203,
            sp1_opcode: 12,
            mnemonic: "lw".to_string(),
        }
    }

    fn receipt() -> SemanticMutationReceipt {
        serde_json::from_value(json!({
            "inject_kind": MEMORY_EFFECT_INJECT_KIND,
            "site": "cpu_chip.generate_trace",
            "field": "is_memory",
            "step": 3,
            "before": 1,
            "after": 0,
            "effect": {
                "relation": "memory_selector_equation",
                "context": {
                    "bucket_id": "sem.exec.memory_effect_binding",
                    "obligation_id": "me10",
                    "cell_id": "me10.load",
                    "backend": "sp1",
                    "commit": "39ab52fce38172c9d23feed7248198dc14c164a9",
                    "trace_source": "instruction",
                    "anchor": 3,
                    "step": 3,
                    "op_idx": 3,
                    "pc": 0x0020_0400u64,
                    "opcode": 0x0041_2203u64,
                    "sp1_opcode": 12,
                    "source_selector": 12,
                    "mnemonic": "lw",
                    "expected_is_memory": 1,
                    "selector_before": 1,
                    "selector_after": 0,
                    "executed_cpu_row": true
                }
            }
        }))
        .expect("typed memory selector receipt")
    }

    #[test]
    fn memory_selector_receipt_binds_executed_row_and_equation() {
        assert!(
            valid_memory_selector_receipt(&receipt(), MEMORY_EFFECT_INJECT_KIND, 3, &anchor(),)
        );
    }

    #[test]
    fn memory_selector_receipt_rejects_wrong_relation_kind_anchor_opcode_pc_and_context() {
        let check = |receipt: &SemanticMutationReceipt, kind: &str, step: u64| {
            valid_memory_selector_receipt(receipt, kind, step, &anchor())
        };

        let mut wrong_relation = receipt();
        wrong_relation.effect.relation = SemanticMutationRelation::ExecutedControlFlowEquation;
        assert!(!check(&wrong_relation, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut wrong_kind = receipt();
        wrong_kind.inject_kind = "sp1.semantic.exec.dest_binding".to_string();
        assert!(!check(&wrong_kind, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut wrong_anchor = receipt();
        wrong_anchor.effect.context.insert("anchor".to_string(), json!(4));
        assert!(!check(&wrong_anchor, MEMORY_EFFECT_INJECT_KIND, 3));
        assert!(!check(&receipt(), MEMORY_EFFECT_INJECT_KIND, 4));

        let mut wrong_opcode = receipt();
        wrong_opcode.effect.context.insert("opcode".to_string(), json!(0x13));
        assert!(!check(&wrong_opcode, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut wrong_source_selector = receipt();
        wrong_source_selector.effect.context.insert("sp1_opcode".to_string(), json!(17));
        assert!(!check(&wrong_source_selector, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut wrong_pc = receipt();
        wrong_pc.effect.context.insert("pc".to_string(), json!(0x0020_0404u64));
        assert!(!check(&wrong_pc, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut wrong_op_idx = receipt();
        wrong_op_idx.effect.context.insert("op_idx".to_string(), json!(4));
        assert!(!check(&wrong_op_idx, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut stale_commit = receipt();
        stale_commit.effect.context.insert("commit".to_string(), json!("stale"));
        assert!(!check(&stale_commit, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut wrong_site = receipt();
        wrong_site.site = "caller.supplied".to_string();
        assert!(!check(&wrong_site, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut forged = receipt();
        forged.effect.context.insert("expected_is_memory".to_string(), json!(0));
        assert!(!check(&forged, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut wrong_bucket = receipt();
        wrong_bucket.effect.context.insert("bucket_id".to_string(), json!("sem.exec.dest_binding"));
        assert!(!check(&wrong_bucket, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut wrong_cell = receipt();
        wrong_cell.effect.context.insert("cell_id".to_string(), json!("me10.store"));
        assert!(!check(&wrong_cell, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut unchanged = receipt();
        unchanged.after = json!(1);
        unchanged.effect.context.insert("selector_after".to_string(), json!(1));
        assert!(!check(&unchanged, MEMORY_EFFECT_INJECT_KIND, 3));

        let mut non_boolean = receipt();
        non_boolean.after = json!(2);
        non_boolean.effect.context.insert("selector_after".to_string(), json!(2));
        assert!(!check(&non_boolean, MEMORY_EFFECT_INJECT_KIND, 3));
    }

    #[test]
    fn s27_route_maps_only_memory_effect_candidates_to_memory_selector_equation() {
        let backend = Sp1Backend::new(16);
        let mut details = HashMap::new();
        details.insert("step_idx".to_string(), json!(3));
        let hit = BucketHit::semantic(semantic::exec::MEMORY_EFFECT_BINDING, details);
        let candidates = backend.semantic_candidate_from_hit(&hit);
        assert!(!candidates.is_empty());
        assert!(candidates.iter().all(|candidate| {
            backend.semantic_mutation_relation(candidate)
                == Some(SemanticMutationRelation::MemorySelectorEquation)
        }));

        let mut wrong_bucket = candidates[0].clone();
        wrong_bucket.bucket_id = semantic::exec::DEST_BINDING.id.to_string();
        assert_eq!(backend.semantic_mutation_relation(&wrong_bucket), None);

        let mut wrong_kind = candidates[0].clone();
        wrong_kind.inject_kind = "sp1.semantic.exec.dest_binding".to_string();
        assert_eq!(backend.semantic_mutation_relation(&wrong_kind), None);
    }
}
