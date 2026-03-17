use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic};
use serde::{Deserialize, Serialize};
use sp1_core_executor::{
    ExecutionRecord, Executor, ExecutorMode, Opcode, Register, events::MemoryRecordEnum,
};
use sp1_prover::SP1Prover;
use sp1_stark::{MachineProver, SP1CoreOpts, StarkGenericConfig};

use crate::trace::{Sp1Trace, build_sp1_program};

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
    pub timeout_ms: u64,
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

const TIMESTAMP_INJECT_KIND: &str = "sp1.audit_timestamp.mem_row_wraparound";
const BOOL_INJECT_KIND: &str = "sp1.audit_multiplicity_bool_constraint.local_event_row";
const S27_INJECT_KIND: &str = "sp1.audit_s27.is_memory_lw_zero";
const S28_INJECT_KIND: &str = "sp1.audit_s28.next_pc_ecall_arbitrary";

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn inject_kind_with_variant(kind: &str, variant: &str) -> String {
    if variant.is_empty() { kind.to_string() } else { format!("{kind}::{variant}") }
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

fn inject_variant_mode(kind: &str) -> Option<&str> {
    inject_variant_value(kind, "mode")
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
            if event.memory_record.is_some() {
                record_site(&mut sites, TIMESTAMP_INJECT_KIND, flat_cpu_idx);
            }
            if matches!(event.memory_record.as_ref(), Some(MemoryRecordEnum::Write(_))) {
                record_site(&mut sites, BOOL_INJECT_KIND, flat_cpu_idx);
            }
            if event.instruction.opcode == Opcode::LW {
                record_site(&mut sites, S27_INJECT_KIND, flat_cpu_idx);
            }
            if event.instruction.opcode == Opcode::ECALL {
                record_site(&mut sites, S28_INJECT_KIND, flat_cpu_idx);
            }
            flat_cpu_idx = flat_cpu_idx.saturating_add(1);
        }
    }
    sites
}

fn apply_injection_to_records(
    records: &mut [ExecutionRecord],
    inject_kind: Option<&str>,
    inject_step: u64,
    observed_injection_sites: &BTreeMap<String, Vec<u64>>,
) -> bool {
    let Some(kind) = inject_kind else {
        return false;
    };
    let base_kind = base_inject_kind(kind);

    if inject_step != u64::MAX
        && !observed_injection_sites
            .get(base_kind)
            .map(|steps| steps.contains(&inject_step))
            .unwrap_or(false)
    {
        return false;
    }

    let mut flat_cpu_idx = 0u64;
    let target_step = if inject_step == u64::MAX { None } else { Some(inject_step) };
    for record in records.iter_mut() {
        for event in &mut record.cpu_events {
            let step_match = target_step.map(|s| s == flat_cpu_idx).unwrap_or(true);
            if !step_match {
                flat_cpu_idx = flat_cpu_idx.saturating_add(1);
                continue;
            }
            match base_kind {
                // Simulate timestamp wraparound style witness corruption on memory accesses.
                TIMESTAMP_INJECT_KIND => {
                    event.clk = event.clk.wrapping_add(u32::MAX);
                    if let Some(mem) = event.memory_record.as_mut() {
                        match mem {
                            MemoryRecordEnum::Read(r) => {
                                r.prev_timestamp = r.timestamp;
                                r.timestamp = 0;
                                return true;
                            }
                            MemoryRecordEnum::Write(w) => {
                                w.prev_timestamp = w.timestamp;
                                w.timestamp = 0;
                                return true;
                            }
                        }
                    }
                }
                // Simulate local-event multiplicity corruption.
                BOOL_INJECT_KIND => {
                    if let Some(MemoryRecordEnum::Write(w)) = event.memory_record.as_mut() {
                        w.value ^= 1;
                        return true;
                    }
                }
                // s27: force LW row to look non-memory by breaking opcode->memory selector relation.
                S27_INJECT_KIND => {
                    if event.instruction.opcode == Opcode::LW {
                        match inject_variant_mode(kind) {
                            Some("noop_prefix") => {}
                            Some("opcode_alias_only") => {
                                event.instruction.opcode = Opcode::ADD;
                                return true;
                            }
                            Some("memory_drop_only") => {
                                event.memory = None;
                                event.memory_record = None;
                                return true;
                            }
                            _ => {
                                event.instruction.opcode = Opcode::ADD;
                                event.memory = None;
                                event.memory_record = None;
                                return true;
                            }
                        }
                    }
                }
                // s28: forge an arbitrary ECALL next_pc.
                S28_INJECT_KIND => {
                    if event.instruction.opcode == Opcode::ECALL {
                        match inject_variant_mode(kind) {
                            Some("noop_prefix") => {}
                            Some("near_jump") => {
                                event.next_pc = event.pc.wrapping_add(8);
                                return true;
                            }
                            Some("mid_jump") => {
                                event.next_pc = event.pc.wrapping_add(0x40);
                                return true;
                            }
                            _ => {
                                event.next_pc = event.pc.wrapping_add(0x10000);
                                return true;
                            }
                        }
                    }
                }
                _ => {}
            }
            if target_step.is_some() {
                return false;
            }
            flat_cpu_idx = flat_cpu_idx.saturating_add(1);
        }
    }
    false
}

fn run_sp1_real_backend(
    words: &[u32],
    _timeout_ms: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RealRunnerResponse, String> {
    let prover: SP1Prover = SP1Prover::new();
    let program = build_sp1_program(words)?;
    let mut executor = Executor::new(program, SP1CoreOpts::default());
    executor.executor_mode = ExecutorMode::Trace;
    executor.run().map_err(|e| format!("sp1 executor run failed: {e}"))?;

    let mut records = std::mem::take(&mut executor.records);
    let observed_injection_sites = collect_observed_injection_sites(&records);
    let injection_applied = apply_injection_to_records(
        &mut records,
        inject_kind,
        inject_step,
        &observed_injection_sites,
    );
    let trace = Sp1Trace::from_execution_records(words, &records)?;
    let (prove_ok, verify_ok, prove_verify_error) =
        run_sp1_prove_verify_with_prover(&prover, &executor.program, &records);

    let mut regs = [0u32; 32];
    for i in 0..32usize {
        regs[i] = executor.register(Register::from_u32(i as u32));
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

fn run_sp1_prove_verify_with_prover(
    prover: &SP1Prover,
    program: &sp1_core_executor::Program,
    records: &[ExecutionRecord],
) -> (bool, bool, Option<String>) {
    let (pk, vk) = prover.core_prover.setup(program);
    let mut prove_challenger = prover.core_prover.config().challenger();
    let mut prove_records = records.to_vec();
    for (idx, shard) in prove_records.iter_mut().enumerate() {
        shard.public_values.shard = (idx + 1) as u32;
    }

    let proof = match prover.core_prover.prove(
        &pk,
        prove_records,
        &mut prove_challenger,
        SP1CoreOpts::default(),
    ) {
        Ok(p) => p,
        Err(e) => {
            return (false, false, Some(format!("sp1 core prove failed: {e}")));
        }
    };

    let mut verify_challenger = prover.core_prover.config().challenger();
    if let Err(e) = prover.core_prover.machine().verify(&vk, &proof, &mut verify_challenger) {
        return (true, false, Some(format!("sp1 core verify failed: {e}")));
    }

    (true, true, None)
}

pub fn run_backend_once(
    request_id: u64,
    words: &[u32],
    timeout_ms: u64,
    _current_iteration: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<WorkerResponse, String> {
    let runner_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_sp1_real_backend(words, timeout_ms, inject_kind, inject_step)
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
    timeout_ms: u64,
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
    pub fn new(max_instructions: usize, timeout_ms: u64) -> Self {
        Self {
            max_instructions,
            timeout_ms,
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

    fn s27_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for rank in 0..768u32 {
            specs.push(format!("mode=noop_prefix,rank={rank}"));
        }
        specs.push("mode=opcode_alias_only".to_string());
        specs.push("mode=memory_drop_only".to_string());
        specs.push("mode=legacy_selector_break".to_string());
        specs
    }

    fn s28_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for rank in 0..768u32 {
            specs.push(format!("mode=noop_prefix,rank={rank}"));
        }
        specs.push("mode=near_jump".to_string());
        specs.push("mode=mid_jump".to_string());
        specs.push("mode=legacy_far_jump".to_string());
        specs
    }

    fn inject_kinds_for_base(inject_kind: &str) -> Vec<String> {
        match inject_kind {
            S27_INJECT_KIND => Self::s27_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            S28_INJECT_KIND => Self::s28_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            _ => vec![inject_kind.to_string()],
        }
    }

    fn semantic_candidate_priority(candidate: &SemanticInjectionCandidate) -> u8 {
        let bucket_id = candidate.bucket_id.as_str();
        if bucket_id == semantic::control::ECALL_NEXT_PC.id {
            0
        } else if bucket_id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id {
            1
        } else {
            2
        }
    }

    fn semantic_candidate_from_hit(&self, hit: &BucketHit) -> Vec<SemanticInjectionCandidate> {
        let anchor = Self::step_from_hit(hit);
        let bucket_id = hit.bucket_id.as_str();
        let (semantic_class, inject_kind, fallback_schedule) =
            if bucket_id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id {
                (
                    semantic::memory::KIND_SELECTOR_CONSISTENCY.semantic_class,
                    S27_INJECT_KIND,
                    InjectionSchedule::AroundAnchor(anchor),
                )
            } else if bucket_id == semantic::control::ECALL_NEXT_PC.id {
                (
                    semantic::control::ECALL_NEXT_PC.semantic_class,
                    S28_INJECT_KIND,
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
        let timeout = Duration::from_millis(self.timeout_ms);
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
            timeout_ms: self.timeout_ms,
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

        let started = Instant::now();
        let resp = loop {
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                self.stop_worker();
                let msg = format!(
                    "backend trace build timed out after {} ms (worker killed)",
                    self.timeout_ms
                );
                self.eval.backend_error = Some(msg.clone());
                return Err(msg);
            }
            let remaining = timeout - elapsed;
            let recv = {
                let worker =
                    self.worker.as_ref().ok_or_else(|| "backend worker unavailable".to_string())?;
                worker.responses_rx.recv_timeout(remaining)
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
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.stop_worker();
                    let msg = format!(
                        "backend trace build timed out after {} ms (worker killed)",
                        self.timeout_ms
                    );
                    self.eval.backend_error = Some(msg.clone());
                    return Err(msg);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
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
