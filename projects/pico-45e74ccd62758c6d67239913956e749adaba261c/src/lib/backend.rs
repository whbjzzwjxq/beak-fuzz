use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::Duration;

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use serde::{Deserialize, Serialize};

use crate::trace::{PicoExecutedInsn, PicoTrace};

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
struct RealRunnerRequest {
    words: Vec<u32>,
    do_prove_verify: bool,
    inject_kind: Option<String>,
    inject_step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RealRunnerResponse {
    final_regs: Option<[u32; 32]>,
    micro_op_count: usize,
    prove_ok: bool,
    verify_ok: bool,
    error: Option<String>,
    observed_injection_sites: BTreeMap<String, Vec<u64>>,
    injection_applied: bool,
    #[serde(default)]
    executed_insns: Vec<PicoExecutedInsn>,
}

const TIMESTAMP_INJECT_KIND: &str = "pico.semantic.memory.timestamped_load_path";
const BOOL_INJECT_KIND: &str = "pico.semantic.lookup.boolean_multiplicity";
const OP_SELECTOR_INJECT_KIND: &str = "pico.semantic.exec.op_selector_binding";
const READ_WRITE_OP_SELECTOR_INJECT_KIND: &str =
    "pico.semantic.exec.op_selector_binding.read_write";
const ECALL_ARG_INJECT_KIND: &str = "pico.semantic.control.ecall_argument_decomposition";
const ZERO_REG_INJECT_KIND: &str = "pico.semantic.decode.zero_register_immutability";
const OPERAND_ROUTING_INJECT_KIND: &str = "pico.semantic.decode.operand_index_routing";
const DEST_BINDING_INJECT_KIND: &str = "pico.semantic.exec.dest_binding";
const FIELD_RANGE_INJECT_KIND: &str = "pico.semantic.decode.field_range";
const IMM_SIGN_INJECT_KIND: &str = "pico.semantic.decode.immediate_sign_extension";
const UPPER_IMM_INJECT_KIND: &str = "pico.semantic.decode.upper_immediate_materialization";
const FORMAT_IMM_INJECT_KIND: &str = "pico.semantic.decode.format_immediate_reassembly";
const ALU_IMM_INJECT_KIND: &str = "pico.semantic.alu.immediate_limb_consistency";
const SHIFT_INJECT_KIND: &str = "pico.semantic.alu.shift_mod32";
const CMP_BOOL_INJECT_KIND: &str = "pico.semantic.alu.comparison_booleanity";
const SUB_BORROW_INJECT_KIND: &str = "pico.semantic.alu.subtraction_borrow_chain";
const CMP_AUX_INJECT_KIND: &str = "pico.semantic.alu.comparison_auxiliary_chain";
const DIV_SPECIAL_INJECT_KIND: &str = "pico.semantic.arithmetic.special_case_consistency";
const DIV_BOUND_INJECT_KIND: &str = "pico.semantic.arithmetic.division_remainder_bound";
const PRODUCT_INJECT_KIND: &str = "pico.semantic.arithmetic.product_decomposition";
const MULHSU_INJECT_KIND: &str = "pico.semantic.arithmetic.signed_unsigned_product_correction";
const MEM_STORE_LOAD_INJECT_KIND: &str = "pico.semantic.memory.store_load_payload_flow";
const MEM_ADDR_ALIGN_INJECT_KIND: &str = "pico.semantic.memory.address_alignment_consistency";
const MEM_LOAD_VALUE_INJECT_KIND: &str = "pico.semantic.memory.load_value_binding";
const MEM_WRITE_PAYLOAD_INJECT_KIND: &str = "pico.semantic.memory.write_payload_consistency";
const MEM_ADDR_BOUNDARY_INJECT_KIND: &str = "pico.semantic.memory.address_boundary_range";
const MEM_ADDR_PROGRESS_INJECT_KIND: &str = "pico.semantic.memory.address_progression_consistency";
const MEM_KIND_INJECT_KIND: &str = "pico.semantic.memory.kind_selector_consistency";
const CONTROL_FLOW_INJECT_KIND: &str = "pico.semantic.exec.control_flow_binding";
const ENTRYPOINT_INJECT_KIND: &str = "pico.semantic.control.entrypoint_binding";
const TIME_BOUNDARY_INJECT_KIND: &str = "pico.semantic.time.boundary_origin_consistency";

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

fn real_runner_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pico-real-backend").join("Cargo.toml")
}

fn run_pico_real_backend(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RealRunnerResponse, String> {
    let manifest = real_runner_manifest_path();
    if !manifest.exists() {
        return Err(format!("missing real backend manifest: {}", manifest.display()));
    }

    let req = RealRunnerRequest {
        words: words.to_vec(),
        do_prove_verify: true,
        inject_kind: inject_kind.map(|s| s.to_string()),
        inject_step,
    };
    let req_json = serde_json::to_vec(&req)
        .map_err(|e| format!("failed to serialize real runner request: {e}"))?;

    let mut child = Command::new("cargo")
        .arg("+nightly-2024-11-27")
        .arg("run")
        .arg("--release")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(&manifest)
        .env("RUSTFLAGS", "--cap-lints allow")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn pico real backend: {e}"))?;

    {
        let Some(mut stdin) = child.stdin.take() else {
            return Err("failed to open stdin for pico real backend".to_string());
        };
        stdin
            .write_all(&req_json)
            .map_err(|e| format!("failed to write request to pico real backend: {e}"))?;
        // Important: close stdin so pico-real-backend can finish read_to_string().
        drop(stdin);
    }

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("failed to wait pico real backend: {e}")),
        }
    }

    let mut out_stdout = Vec::new();
    let mut out_stderr = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_end(&mut out_stdout);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_end(&mut out_stderr);
    }
    let status =
        child.wait().map_err(|e| format!("failed to finalize pico real backend child: {e}"))?;

    if !status.success() {
        let stderr = String::from_utf8_lossy(&out_stderr);
        let tail = stderr
            .lines()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ");
        return Err(format!(
            "pico real backend failed with {}: {}",
            status,
            if tail.is_empty() { "<no stderr>" } else { &tail }
        ));
    }

    let stdout = String::from_utf8(out_stdout)
        .map_err(|e| format!("invalid utf8 from pico real backend stdout: {e}"))?;
    let line = stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| "empty stdout from pico real backend".to_string())?;

    serde_json::from_str::<RealRunnerResponse>(line.trim())
        .map_err(|e| format!("invalid response json from pico real backend: {e}; raw={line}"))
}

pub fn run_backend_once(
    request_id: u64,
    words: &[u32],
    _current_iteration: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<WorkerResponse, String> {
    let mut eval = BackendEval::default();
    let mut observed_injection_sites = BTreeMap::new();
    let mut injection_applied = false;

    let runner_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_pico_real_backend(words, inject_kind, inject_step)
    }));

    match &runner_res {
        Ok(Ok(resp)) => {
            observed_injection_sites = resp.observed_injection_sites.clone();
            injection_applied = resp.injection_applied;
            eval.final_regs = resp.final_regs;
            eval.micro_op_count = resp.micro_op_count;
            if let Some(err) = &resp.error {
                eval.backend_error = Some(err.clone());
            } else if !resp.prove_ok || !resp.verify_ok {
                eval.backend_error = Some(format!(
                    "pico real backend did not complete prove+verify successfully (prove_ok={}, verify_ok={})",
                    resp.prove_ok, resp.verify_ok
                ));
            }
        }
        Ok(Err(e)) => {
            eval.backend_error = Some(e.clone());
        }
        Err(p) => {
            let msg = if let Some(s) = p.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = p.downcast_ref::<String>() {
                s.clone()
            } else {
                "non-string panic payload".to_string()
            };
            eval.backend_error = Some(format!("backend panic: {msg}"));
        }
    }

    let trace = if let Ok(Ok(resp)) = &runner_res {
        PicoTrace::from_executed(&resp.executed_insns)?
    } else {
        PicoTrace::from_words(words)?
    };
    if eval.micro_op_count == 0 {
        eval.micro_op_count = trace.instruction_count();
    }
    eval.bucket_hits = trace.bucket_hits().to_vec();
    eval.trace_signals = trace.trace_signals().to_vec();

    Ok(WorkerResponse {
        request_id,
        final_regs: eval.final_regs,
        micro_op_count: eval.micro_op_count,
        bucket_hits: eval.bucket_hits,
        trace_signals: eval.trace_signals,
        backend_error: eval.backend_error,
        observed_injection_sites,
        injection_applied,
    })
}

pub struct PicoBackend {
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

impl PicoBackend {
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

    fn timestamp_variant_specs() -> Vec<String> {
        vec![String::new()]
    }

    fn bool_variant_specs() -> Vec<String> {
        vec![String::new()]
    }

    fn inject_kinds_for_base(inject_kind: &str) -> Vec<String> {
        match inject_kind {
            TIMESTAMP_INJECT_KIND => Self::timestamp_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            BOOL_INJECT_KIND => Self::bool_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            _ => vec![inject_kind.to_string()],
        }
    }

    fn semantic_candidate_from_hit(&self, hit: &BucketHit) -> Vec<SemanticInjectionCandidate> {
        let anchor = Self::step_from_hit(hit);
        let bucket_id = hit.bucket_id.as_str();
        let (semantic_class, inject_kind, fallback_schedule) =
            if bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id {
                (
                    semantic::memory::TIMESTAMPED_LOAD_PATH.semantic_class,
                    TIMESTAMP_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::lookup::BOOLEAN_MULTIPLICITY.id {
                (
                    semantic::lookup::BOOLEAN_MULTIPLICITY.semantic_class,
                    BOOL_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::exec::OP_SELECTOR_BINDING.id {
                let is_read_write_cell = hit
                    .details
                    .get("cell_id")
                    .and_then(|v| v.as_str())
                    .is_some_and(|cell| matches!(cell, "id4.load" | "id4.store"))
                    || hit
                        .details
                        .get("mnemonic")
                        .and_then(|v| v.as_str())
                        .is_some_and(is_memory_mnemonic);
                (
                    semantic::exec::OP_SELECTOR_BINDING.semantic_class,
                    if is_read_write_cell {
                        READ_WRITE_OP_SELECTOR_INJECT_KIND
                    } else {
                        OP_SELECTOR_INJECT_KIND
                    },
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id {
                (
                    semantic::control::ECALL_ARGUMENT_DECOMPOSITION.semantic_class,
                    ECALL_ARG_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id {
                (
                    semantic::decode::ZERO_REGISTER_IMMUTABILITY.semantic_class,
                    ZERO_REG_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::decode::OPERAND_INDEX_ROUTING.id {
                (
                    semantic::decode::OPERAND_INDEX_ROUTING.semantic_class,
                    OPERAND_ROUTING_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::exec::DEST_BINDING.id {
                (
                    semantic::exec::DEST_BINDING.semantic_class,
                    DEST_BINDING_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::decode::FIELD_RANGE.id {
                (
                    semantic::decode::FIELD_RANGE.semantic_class,
                    FIELD_RANGE_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::decode::IMMEDIATE_SIGN_EXTENSION.id {
                (
                    semantic::decode::IMMEDIATE_SIGN_EXTENSION.semantic_class,
                    IMM_SIGN_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION.id {
                (
                    semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION.semantic_class,
                    UPPER_IMM_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.id {
                (
                    semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.semantic_class,
                    FORMAT_IMM_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id {
                (
                    semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.semantic_class,
                    ALU_IMM_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::alu::SHIFT_MOD32.id {
                (
                    semantic::alu::SHIFT_MOD32.semantic_class,
                    SHIFT_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::alu::COMPARISON_BOOLEANITY.id {
                (
                    semantic::alu::COMPARISON_BOOLEANITY.semantic_class,
                    CMP_BOOL_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::alu::SUBTRACTION_BORROW_CHAIN.id {
                (
                    semantic::alu::SUBTRACTION_BORROW_CHAIN.semantic_class,
                    SUB_BORROW_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id {
                (
                    semantic::alu::COMPARISON_AUXILIARY_CHAIN.semantic_class,
                    CMP_AUX_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id {
                (
                    semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.semantic_class,
                    DIV_SPECIAL_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id {
                (
                    semantic::arithmetic::DIVISION_REMAINDER_BOUND.semantic_class,
                    DIV_BOUND_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::arithmetic::PRODUCT_DECOMPOSITION.id {
                (
                    semantic::arithmetic::PRODUCT_DECOMPOSITION.semantic_class,
                    PRODUCT_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id {
                (
                    semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.semantic_class,
                    MULHSU_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id {
                (
                    semantic::memory::STORE_LOAD_PAYLOAD_FLOW.semantic_class,
                    MEM_STORE_LOAD_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id {
                (
                    semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.semantic_class,
                    MEM_ADDR_ALIGN_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::memory::LOAD_VALUE_BINDING.id {
                (
                    semantic::memory::LOAD_VALUE_BINDING.semantic_class,
                    MEM_LOAD_VALUE_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::memory::WRITE_PAYLOAD_CONSISTENCY.id {
                (
                    semantic::memory::WRITE_PAYLOAD_CONSISTENCY.semantic_class,
                    MEM_WRITE_PAYLOAD_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id {
                (
                    semantic::memory::ADDRESS_BOUNDARY_RANGE.semantic_class,
                    MEM_ADDR_BOUNDARY_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id {
                (
                    semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.semantic_class,
                    MEM_ADDR_PROGRESS_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id {
                (
                    semantic::memory::KIND_SELECTOR_CONSISTENCY.semantic_class,
                    MEM_KIND_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id {
                (
                    semantic::time::MONOTONIC_ACCESS_ORDERING.semantic_class,
                    TIMESTAMP_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id {
                (
                    semantic::exec::CONTROL_FLOW_BINDING.semantic_class,
                    CONTROL_FLOW_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::control::ENTRYPOINT_BINDING.id {
                (
                    semantic::control::ENTRYPOINT_BINDING.semantic_class,
                    ENTRYPOINT_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id {
                (
                    semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.semantic_class,
                    TIME_BOUNDARY_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else {
                return Vec::new();
            };
        let schedule = self
            .last_observed_injection_sites
            .get(base_inject_kind(inject_kind))
            .map(|steps| {
                InjectionSchedule::Explicit(Self::ordered_steps_around_anchor(steps, anchor))
            })
            .unwrap_or(fallback_schedule);
        Self::inject_kinds_for_base(inject_kind)
            .into_iter()
            .map(|kind| SemanticInjectionCandidate {
                bucket_id: hit.bucket_id.clone(),
                trigger_signal_id: None,
                semantic_class: semantic_class.to_string(),
                inject_kind: kind,
                schedule: schedule.clone(),
            })
            .collect()
    }

    fn semantic_candidate_priority(candidate: &SemanticInjectionCandidate) -> u8 {
        let bucket_id = candidate.bucket_id.as_str();
        if bucket_id == semantic::exec::OP_SELECTOR_BINDING.id {
            0
        } else if bucket_id == semantic::lookup::BOOLEAN_MULTIPLICITY.id {
            1
        } else if bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id {
            2
        } else if bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id {
            3
        } else if bucket_id.starts_with("sem.decode.")
            || bucket_id.starts_with("sem.exec.")
            || bucket_id.starts_with("sem.control.")
            || bucket_id.starts_with("sem.time.")
        {
            4
        } else if bucket_id.starts_with("sem.alu.") || bucket_id.starts_with("sem.arithmetic.") {
            5
        } else if bucket_id.starts_with("sem.memory.") {
            6
        } else {
            7
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

fn is_memory_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "lb" | "lh" | "lw" | "lbu" | "lhu" | "sb" | "sh" | "sw")
}

impl BenchmarkBackend for PicoBackend {
    fn is_usable_seed(&self, words: &[u32]) -> bool {
        if words.is_empty() || words.len() > self.max_instructions {
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
        self.eval.backend_error = None;
        self.eval.bucket_hits.clear();
        self.eval.micro_op_count = 0;
        self.eval.final_regs = None;
        self.eval.semantic_injection_applied = false;
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
        };
        self.last_observed_injection_sites = resp.observed_injection_sites;

        if let Some(err) = resp.backend_error {
            return Err(err);
        }
        resp.final_regs.ok_or_else(|| "pico backend did not return final regs".to_string())
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

impl Drop for PicoBackend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beak_core::trace::Trace;

    #[test]
    fn id4_load_store_candidates_use_read_write_selector_hook() {
        let trace = PicoTrace::from_words(&[0x0000_2083]).expect("lw trace");
        let hit = trace
            .bucket_hits()
            .iter()
            .find(|hit| {
                hit.bucket_id == semantic::exec::OP_SELECTOR_BINDING.id
                    && hit.details.get("cell_id").and_then(|v| v.as_str()) == Some("id4.load")
            })
            .expect("id4 load hit")
            .clone();

        let backend = PicoBackend::new(8);
        let candidates =
            <PicoBackend as BenchmarkBackend>::semantic_injection_candidates(&backend, &[hit]);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].bucket_id, semantic::exec::OP_SELECTOR_BINDING.id);
        assert_eq!(candidates[0].inject_kind, READ_WRITE_OP_SELECTOR_INJECT_KIND);
    }

    #[test]
    fn cf5_candidates_use_ecall_argument_hook() {
        let trace = PicoTrace::from_executed(&[PicoExecutedInsn {
            step_idx: 0,
            chunk: 0,
            clk: 0,
            pc: 0x1000,
            next_pc: 0,
            word: 0x0000_0073,
            opcode: "ecall".to_string(),
            a: 0,
            b: 0,
            c: 0,
            memory: None,
            ecall_syscall_id: Some(0),
            ecall_operand_to_check: Some(0),
        }])
        .expect("ecall trace");
        let hit = trace
            .bucket_hits()
            .iter()
            .find(|hit| hit.bucket_id == semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id)
            .expect("cf5 hit")
            .clone();

        let backend = PicoBackend::new(8);
        let candidates =
            <PicoBackend as BenchmarkBackend>::semantic_injection_candidates(&backend, &[hit]);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].inject_kind, ECALL_ARG_INJECT_KIND);
    }

    #[test]
    fn timestamp_monotonic_candidate_precedes_timestamped_helper_bucket() {
        let trace = PicoTrace::from_executed(&[
            PicoExecutedInsn {
                step_idx: 0,
                chunk: 1,
                clk: 0,
                pc: 0x1000,
                next_pc: 0x1004,
                word: 0x0400_0213,
                opcode: "add".to_string(),
                a: 64,
                b: 0,
                c: 64,
                memory: None,
                ecall_syscall_id: None,
                ecall_operand_to_check: None,
            },
            PicoExecutedInsn {
                step_idx: 1,
                chunk: 1,
                clk: 4,
                pc: 0x1004,
                next_pc: 0x1008,
                word: 0x0010_0293,
                opcode: "add".to_string(),
                a: 1,
                b: 0,
                c: 1,
                memory: None,
                ecall_syscall_id: None,
                ecall_operand_to_check: None,
            },
            PicoExecutedInsn {
                step_idx: 2,
                chunk: 1,
                clk: 8,
                pc: 0x1008,
                next_pc: 0x100c,
                word: 0x0052_2023,
                opcode: "sw".to_string(),
                a: 1,
                b: 64,
                c: 0,
                memory: Some(1),
                ecall_syscall_id: None,
                ecall_operand_to_check: None,
            },
            PicoExecutedInsn {
                step_idx: 3,
                chunk: 1,
                clk: 12,
                pc: 0x100c,
                next_pc: 0x1010,
                word: 0x0002_2303,
                opcode: "lw".to_string(),
                a: 1,
                b: 64,
                c: 0,
                memory: Some(1),
                ecall_syscall_id: None,
                ecall_operand_to_check: None,
            },
        ])
        .expect("timestamp trace");

        let backend = PicoBackend::new(8);
        let candidates = <PicoBackend as BenchmarkBackend>::semantic_injection_candidates(
            &backend,
            trace.bucket_hits(),
        );

        assert!(candidates.iter().any(|candidate| {
            candidate.bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id
        }));
        assert_eq!(candidates[0].bucket_id, semantic::time::MONOTONIC_ACCESS_ORDERING.id);
        assert_eq!(candidates[0].inject_kind, TIMESTAMP_INJECT_KIND);
    }
}
