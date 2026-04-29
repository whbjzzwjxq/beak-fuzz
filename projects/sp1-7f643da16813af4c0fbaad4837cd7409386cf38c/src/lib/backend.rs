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
use sp1_core_executor::{
    syscalls::SyscallCode, ExecutionRecord, Executor, ExecutorMode, Opcode, Register,
};
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

const S28_INJECT_KIND: &str = "sp1.semantic.exec.control_flow_binding";
const ADDRESS_PROGRESSION_INJECT_KIND: &str = "sp1.semantic.memory.address_progression_consistency";
const ADDRESS_ALIGNMENT_INJECT_KIND: &str = "sp1.semantic.memory.address_alignment_consistency";
const LOAD_VALUE_BINDING_INJECT_KIND: &str = "sp1.semantic.memory.load_value_binding";
const PARTIAL_WORD_WRITE_INJECT_KIND: &str = "sp1.semantic.exec.partial_word_write_consistency";
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

fn supports_official_injection_kind(kind: &str) -> bool {
    matches!(
        base_inject_kind(kind),
        S28_INJECT_KIND
            | ADDRESS_PROGRESSION_INJECT_KIND
            | ADDRESS_ALIGNMENT_INJECT_KIND
            | LOAD_VALUE_BINDING_INJECT_KIND
            | PARTIAL_WORD_WRITE_INJECT_KIND
    )
}

#[cfg(test)]
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

#[cfg(test)]
fn inject_variant_family(kind: &str) -> Option<&str> {
    inject_variant_value(kind, "family")
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
        Some("noop_prefix") => None,
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
        Some("noop_prefix") => None,
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
        Some("noop_prefix") => None,
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

fn collect_observed_injection_sites(records: &[ExecutionRecord]) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    let mut flat_cpu_idx = 0u64;
    for record in records {
        for event in &record.cpu_events {
            let instruction = record.program.fetch(event.pc);
            if let Some(family) = control_flow_family_for_opcode(instruction.opcode) {
                record_site(&mut sites, S28_INJECT_KIND, flat_cpu_idx);
                record_site(&mut sites, &control_flow_site_key(family), flat_cpu_idx);
            }
            match instruction.opcode {
                Opcode::LH | Opcode::LHU | Opcode::LW | Opcode::SH | Opcode::SW => {
                    record_site(&mut sites, ADDRESS_ALIGNMENT_INJECT_KIND, flat_cpu_idx);
                }
                Opcode::ECALL => {
                    let syscall = SyscallCode::from_u32(event.a);
                    if syscall.should_send() == 1 {
                        record_site(&mut sites, ADDRESS_ALIGNMENT_INJECT_KIND, flat_cpu_idx);
                    }
                }
                _ => {}
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
                    record_site(&mut sites, ADDRESS_PROGRESSION_INJECT_KIND, flat_cpu_idx);
                }
                _ => {}
            }
            match instruction.opcode {
                Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW => {
                    record_site(&mut sites, LOAD_VALUE_BINDING_INJECT_KIND, flat_cpu_idx);
                }
                _ => {}
            }
            match instruction.opcode {
                Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU => {
                    record_site(&mut sites, PARTIAL_WORD_WRITE_INJECT_KIND, flat_cpu_idx);
                }
                _ => {}
            }
            flat_cpu_idx = flat_cpu_idx.saturating_add(1);
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
    let steps = observed_injection_sites.get(base_inject_kind(kind))?;
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
                "sp1 official prove path only supports baseline and {S28_INJECT_KIND}; requested {} still depended on the removed raw-record shortcut",
                inject_kind.unwrap_or_default()
            )),
            observed_injection_sites,
            injection_applied: false,
        });
    }

    let runtime_injection_step =
        resolve_runtime_injection_step(inject_kind, inject_step, &observed_injection_sites);
    let injection_applied = runtime_injection_step.is_some();
    let records = if injection_applied {
        executor = run_sp1_executor(&program, inject_kind, runtime_injection_step)?;
        std::mem::take(&mut executor.records)
    } else {
        baseline_records
    };

    let trace = Sp1Trace::from_execution_records(words, &records)?;
    let (prove_ok, verify_ok, prove_verify_error) =
        run_sp1_prove_verify_with_run_test(&executor.program, inject_kind, runtime_injection_step);

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
        injection_applied,
    })
}

fn run_sp1_prove_verify_with_run_test(
    program: &sp1_core_executor::Program,
    inject_kind: Option<&str>,
    witness_injection_step: Option<u64>,
) -> (bool, bool, Option<String>) {
    let prove_result = with_scoped_witness_injection_env(
        inject_kind.filter(|kind| supports_official_injection_kind(kind)),
        witness_injection_step,
        || run_test::<CpuProver<_, _>>(program.clone()),
    );

    match prove_result {
        Ok(_) => (true, true, None),
        Err(e) => (true, false, Some(format!("sp1 run_test prove/verify failed: {e}"))),
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
            let msg = if let Some(s) = p.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = p.downcast_ref::<String>() {
                s.clone()
            } else {
                "non-string panic payload".to_string()
            };
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

    fn s28_variant_specs_for_family(family: &str) -> Vec<String> {
        let mut specs = Vec::new();
        for rank in 0..768u32 {
            specs.push(format!("family={family},mode=noop_prefix,rank={rank}"));
        }
        match family {
            "branch" => {
                specs.push("family=branch,mode=force_fallthrough".to_string());
                specs.push("family=branch,mode=force_taken_near".to_string());
                specs.push("family=branch,mode=legacy_far_jump".to_string());
            }
            "jump" => {
                specs.push("family=jump,mode=force_sequential".to_string());
                specs.push("family=jump,mode=force_near_jump".to_string());
                specs.push("family=jump,mode=legacy_far_jump".to_string());
            }
            _ => {
                specs.push("family=ecall,mode=near_jump".to_string());
                specs.push("family=ecall,mode=mid_jump".to_string());
                specs.push("family=ecall,mode=legacy_far_jump".to_string());
            }
        }
        specs
    }

    fn address_progression_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for rank in 0..512u32 {
            specs.push(format!("mode=noop_prefix,rank={rank}"));
        }
        specs.push("mode=advance_width".to_string());
        specs.push("mode=advance_word".to_string());
        specs.push("mode=far_page".to_string());
        specs
    }

    fn address_alignment_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for rank in 0..512u32 {
            specs.push(format!("mode=noop_prefix,rank={rank}"));
        }
        specs.push("mode=misalign_plus_one".to_string());
        specs.push("mode=misalign_plus_three".to_string());
        specs.push("mode=precompile_ptr_plus_one".to_string());
        specs.push("mode=precompile_ptr_plus_two".to_string());
        specs.push("mode=global_event_plus_one".to_string());
        specs.push("mode=global_event_plus_two".to_string());
        specs
    }

    fn load_value_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for rank in 0..512u32 {
            specs.push(format!("mode=noop_prefix,rank={rank}"));
        }
        specs.push("mode=xor_low_bit".to_string());
        specs.push("mode=flip_sign_bit".to_string());
        specs.push("mode=legacy_xor_mask".to_string());
        specs
    }

    fn partial_word_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for rank in 0..512u32 {
            specs.push(format!("mode=noop_prefix,rank={rank}"));
        }
        specs.push("mode=flip_upper_bits".to_string());
        specs.push("mode=set_upper_ones".to_string());
        specs
    }

    fn semantic_candidate_priority(candidate: &SemanticInjectionCandidate) -> u8 {
        let bucket_id = candidate.bucket_id.as_str();
        if bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id {
            1
        } else if bucket_id == semantic::memory::LOAD_VALUE_BINDING.id {
            2
        } else if bucket_id == semantic::exec::PARTIAL_WORD_WRITE_CONSISTENCY.id {
            3
        } else if bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id {
            4
        } else if bucket_id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id {
            5
        } else {
            6
        }
    }

    fn semantic_candidate_from_hit(&self, hit: &BucketHit) -> Vec<SemanticInjectionCandidate> {
        let anchor = Self::step_from_hit(hit);
        let bucket_id = hit.bucket_id.as_str();
        let control_flow_family =
            hit.details.get("control_flow_family").and_then(|value| value.as_str());
        let control_flow_site_key = control_flow_family.map(control_flow_site_key);
        let (semantic_class, inject_kinds, schedule_lookup_key, fallback_schedule) =
            if bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id {
                (
                    control_flow_semantic_class(control_flow_family),
                    Self::s28_variant_specs_for_family(control_flow_family.unwrap_or("ecall"))
                        .into_iter()
                        .map(|variant| inject_kind_with_variant(S28_INJECT_KIND, &variant))
                        .collect::<Vec<_>>(),
                    control_flow_site_key.unwrap_or_else(|| S28_INJECT_KIND.to_string()),
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id {
                (
                    semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.semantic_class.to_string(),
                    Self::address_progression_variant_specs()
                        .into_iter()
                        .map(|variant| {
                            inject_kind_with_variant(ADDRESS_PROGRESSION_INJECT_KIND, &variant)
                        })
                        .collect::<Vec<_>>(),
                    ADDRESS_PROGRESSION_INJECT_KIND.to_string(),
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id {
                (
                    semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.semantic_class.to_string(),
                    Self::address_alignment_variant_specs()
                        .into_iter()
                        .map(|variant| {
                            inject_kind_with_variant(ADDRESS_ALIGNMENT_INJECT_KIND, &variant)
                        })
                        .collect::<Vec<_>>(),
                    ADDRESS_ALIGNMENT_INJECT_KIND.to_string(),
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::memory::LOAD_VALUE_BINDING.id {
                (
                    semantic::memory::LOAD_VALUE_BINDING.semantic_class.to_string(),
                    Self::load_value_variant_specs()
                        .into_iter()
                        .map(|variant| {
                            inject_kind_with_variant(LOAD_VALUE_BINDING_INJECT_KIND, &variant)
                        })
                        .collect::<Vec<_>>(),
                    LOAD_VALUE_BINDING_INJECT_KIND.to_string(),
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::exec::PARTIAL_WORD_WRITE_CONSISTENCY.id {
                (
                    semantic::exec::PARTIAL_WORD_WRITE_CONSISTENCY.semantic_class.to_string(),
                    Self::partial_word_variant_specs()
                        .into_iter()
                        .map(|variant| {
                            inject_kind_with_variant(PARTIAL_WORD_WRITE_INJECT_KIND, &variant)
                        })
                        .collect::<Vec<_>>(),
                    PARTIAL_WORD_WRITE_INJECT_KIND.to_string(),
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

#[cfg(test)]
mod tests {
    use super::{
        control_flow_semantic_class, control_flow_site_key, inject_kind_with_variant,
        mutated_control_flow_next_pc, run_backend_once, InjectionSchedule, Opcode, Sp1Backend,
        S28_INJECT_KIND,
    };
    use beak_core::trace::{semantic, BucketHit};
    use serde_json::json;
    use std::collections::HashMap;

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
        let mut backend = Sp1Backend::new(16, 1000);
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
    fn s28_official_run_test_path_applies_injection() {
        let words = vec![0x0020_0293, 0x0030_0513, 0x0000_0593, 0x0000_0613, 0x0000_0073];

        let baseline = run_backend_once(1, &words, 10_000, 0, None, 0).expect("baseline run");
        assert!(
            baseline.backend_error.is_none(),
            "baseline backend_error={:?}",
            baseline.backend_error
        );

        let injected = run_backend_once(
            2,
            &words,
            10_000,
            0,
            Some("sp1.semantic.exec.control_flow_binding::family=ecall,mode=near_jump"),
            u64::MAX,
        )
        .expect("injected run");

        assert!(injected.injection_applied, "s28 official path did not apply injection");
    }
}
