use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use serde::{Deserialize, Serialize};
use sp1_core_executor::{ByteOpcode, ExecutionRecord, Executor, ExecutorMode, Opcode, Register};
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::utils::run_test;
use sp1_stark::{CpuProver, SP1CoreOpts};

use crate::trace::{build_sp1_program, Sp1Trace};

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
}

const MEMORY_EFFECT_INJECT_KIND: &str = "sp1.semantic.exec.memory_effect_binding";
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
static WITNESS_RUN_SEQ: AtomicU64 = AtomicU64::new(1);

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
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

fn collect_observed_injection_sites(
    records: &[Box<ExecutionRecord>],
) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    let mut flat_cpu_idx = 0u64;
    let mut memory_hook_step = 0u64;
    for record in records {
        for event in &record.cpu_events {
            let instruction = record.program.fetch(event.pc);
            let chip_step = (event.pc / 4) as u64;
            record_alu_muldiv_chip_sites(&mut sites, instruction.opcode, chip_step);
            let is_memory_effect_witness_step = flat_cpu_idx.saturating_mul(2);
            let cpu_semantic_witness_step = is_memory_effect_witness_step.saturating_add(1);
            if instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction()
            {
                record_site(&mut sites, MEMORY_EFFECT_INJECT_KIND, is_memory_effect_witness_step);
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
    let Some(kind) = inject_kind else {
        return None;
    };
    let steps = observed_injection_sites.get(base_inject_kind(kind))?;
    if inject_step == u64::MAX {
        steps.first().copied()
    } else {
        steps.contains(&inject_step).then_some(inject_step)
    }
}

fn supports_official_injection(inject_kind: Option<&str>) -> bool {
    inject_kind.map(supports_official_injection_kind).unwrap_or(true)
}

fn run_sp1_official_trace_prove_verify(
    program: &sp1_core_executor::Program,
    inject_kind: Option<&str>,
    inject_step: Option<u64>,
) -> (bool, bool, Option<String>, bool) {
    let run_id = WITNESS_RUN_SEQ.fetch_add(1, Ordering::Relaxed);
    if let (Some(kind), Some(step)) = (inject_kind, inject_step) {
        std::env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", kind);
        std::env::set_var("BEAK_SP1_WITNESS_INJECT_STEP", step.to_string());
        std::env::set_var("BEAK_SP1_WITNESS_RUN_ID", format!("sp1-811a3f2c-{run_id}"));
    } else {
        std::env::remove_var("BEAK_SP1_WITNESS_INJECT_KIND");
        std::env::remove_var("BEAK_SP1_WITNESS_INJECT_STEP");
        std::env::set_var("BEAK_SP1_WITNESS_RUN_ID", format!("sp1-811a3f2c-baseline-{run_id}"));
    }
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_test::<CpuProver<_, _>>(program.clone(), SP1Stdin::new())
    }));
    let injection_applied = fuzzer_utils::injection_was_applied();
    std::panic::set_hook(previous_hook);
    std::env::remove_var("BEAK_SP1_WITNESS_INJECT_KIND");
    std::env::remove_var("BEAK_SP1_WITNESS_INJECT_STEP");
    std::env::remove_var("BEAK_SP1_WITNESS_RUN_ID");
    match result {
        Ok(Ok(_)) => (true, true, None, injection_applied),
        Ok(Err(err)) => {
            (true, false, Some(format!("sp1 official verify failed: {err}")), injection_applied)
        }
        Err(panic) => {
            let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "non-string panic payload".to_string()
            };
            (true, false, Some(format!("sp1 official verify panicked: {msg}")), injection_applied)
        }
    }
}

fn run_sp1_real_backend(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RealRunnerResponse, String> {
    let program = build_sp1_program(words)?;
    let mut executor = Executor::new(program, SP1CoreOpts::default());
    executor.executor_mode = ExecutorMode::Trace;
    executor.run().map_err(|e| format!("sp1 executor run failed: {e}"))?;

    let records = std::mem::take(&mut executor.records);
    let observed_injection_sites = collect_observed_injection_sites(&records);
    let trace = Sp1Trace::from_execution_records(words, &records)?;
    if !supports_official_injection(inject_kind) {
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
                "sp1 official prove path for 811a3f2c has no installed hook/applied signal for requested kind {}; mapped hooks are CPU-row decode/register hooks plus {MEMORY_EFFECT_INJECT_KIND}, {CONTROL_FLOW_INJECT_KIND}, v4 memory-instruction hooks, and byte-table multiplicity hooks",
                inject_kind.unwrap_or_default()
            )),
            observed_injection_sites,
            injection_applied: false,
        });
    }

    let resolved_inject_step =
        resolve_injection_step(inject_kind, inject_step, &observed_injection_sites);
    let injection_was_scheduled = inject_kind.is_some() && resolved_inject_step.is_some();
    let (prove_ok, verify_ok, prove_verify_error, proof_injection_applied) =
        run_sp1_official_trace_prove_verify(&executor.program, inject_kind, resolved_inject_step);

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

    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let runner_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_sp1_real_backend(words, inject_kind, inject_step)
    }));
    std::panic::set_hook(previous_hook);
    match runner_res {
        Ok(Ok(resp)) => {
            final_regs = resp.final_regs;
            micro_op_count = resp.micro_op_count;
            bucket_hits = resp.bucket_hits;
            trace_signals = resp.trace_signals;
            observed_injection_sites = resp.observed_injection_sites;
            injection_applied = resp.injection_applied;
            if let Some(err) = resp.error {
                backend_error = Some(err);
            } else if !resp.prove_ok || !resp.verify_ok {
                backend_error = Some(format!(
                    "sp1 real backend did not complete prove+verify successfully (prove_ok={}, verify_ok={})",
                    resp.prove_ok, resp.verify_ok
                ));
            }
        }
        Ok(Err(e)) => {
            backend_error = Some(e);
        }
        Err(p) => {
            let msg = if let Some(s) = p.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = p.downcast_ref::<String>() {
                s.clone()
            } else {
                "non-string panic payload".to_string()
            };
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

    fn mnemonic_from_hit(hit: &BucketHit) -> Option<&str> {
        hit.details.get("mnemonic").and_then(|value| value.as_str())
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
                inject_kind_with_variant(MEMORY_ADDRESS_INJECT_KIND, "site=addr_word"),
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
        let schedule = self
            .last_observed_injection_sites
            .get(schedule_key)
            .map(|steps| {
                InjectionSchedule::Explicit(Self::ordered_steps_around_anchor(steps, anchor))
            })
            .unwrap_or(fallback_schedule);
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
        if bucket_id == semantic::exec::MEMORY_EFFECT_BINDING.id {
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
        } else {
            3
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
