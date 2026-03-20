use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel, RISCVOracle};
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic};
use serde::{Deserialize, Serialize};
use sp1_core_machine::{io::SP1Stdin, utils::run_test};
use sp1_stark::CpuProver;

use crate::trace::{Sp1Trace, build_sp1_program, decode_word_to_sp1_instruction};

const IS_MEMORY_INJECT_KIND: &str = "sp1.audit_v4.is_memory_instruction_interaction";
const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";

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

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn record_site(sites: &mut BTreeMap<String, Vec<u64>>, kind: &str, step: u64) {
    let steps = sites.entry(kind.to_string()).or_default();
    if steps.last().copied() != Some(step) {
        steps.push(step);
    }
}

fn sp1_oracle_config() -> OracleConfig {
    OracleConfig {
        memory_model: OracleMemoryModel::SplitCodeData,
        code_base: 0x1000,
        data_size_bytes: 0,
    }
}

fn collect_observed_injection_sites(words: &[u32]) -> Result<BTreeMap<String, Vec<u64>>, String> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    for (step, &word) in words.iter().enumerate() {
        let instruction = decode_word_to_sp1_instruction(word)?;
        if instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction() {
            record_site(&mut sites, IS_MEMORY_INJECT_KIND, step as u64);
        }
    }
    Ok(sites)
}

fn resolve_injection_step(
    inject_kind: Option<&str>,
    inject_step: u64,
    observed_injection_sites: &BTreeMap<String, Vec<u64>>,
) -> Option<u64> {
    let kind = inject_kind?;
    if base_inject_kind(kind) != IS_MEMORY_INJECT_KIND {
        return None;
    }
    let steps = observed_injection_sites.get(IS_MEMORY_INJECT_KIND)?;
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

    let result = f();

    match prev_kind {
        Some(v) => std::env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", v),
        None => std::env::remove_var("BEAK_SP1_WITNESS_INJECT_KIND"),
    }
    match prev_step {
        Some(v) => std::env::set_var("BEAK_SP1_WITNESS_INJECT_STEP", v),
        None => std::env::remove_var("BEAK_SP1_WITNESS_INJECT_STEP"),
    }

    result
}

fn run_sp1_prove_verify(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
    observed_injection_sites: &BTreeMap<String, Vec<u64>>,
) -> (bool, bool, Option<String>, bool) {
    let resolved_step = resolve_injection_step(inject_kind, inject_step, observed_injection_sites);
    let injection_applied = resolved_step.is_some();
    let program = match build_sp1_program(words) {
        Ok(program) => program,
        Err(err) => return (false, false, Some(err), false),
    };

    let prove_result = with_scoped_injection_env(
        inject_kind.filter(|kind| base_inject_kind(kind) == IS_MEMORY_INJECT_KIND),
        resolved_step,
        || {
            run_test::<CpuProver<_, _>>(program, SP1Stdin::new())
                .map(|_| ())
                .map_err(|err| format!("sp1 v4 prove/verify failed: {err}"))
        },
    );

    match prove_result {
        Ok(()) => (true, true, None, injection_applied),
        Err(err) => (true, false, Some(err), injection_applied),
    }
}

fn run_sp1_real_backend(
    words: &[u32],
    _timeout_ms: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RealRunnerResponse, String> {
    let trace = Sp1Trace::from_words(words)?;
    let observed_injection_sites = collect_observed_injection_sites(words)?;
    let (prove_ok, verify_ok, prove_verify_error, injection_applied) =
        run_sp1_prove_verify(words, inject_kind, inject_step, &observed_injection_sites);

    Ok(RealRunnerResponse {
        final_regs: Some(RISCVOracle::execute_with_config(words, sp1_oracle_config())),
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

pub fn run_backend_once(
    request_id: u64,
    words: &[u32],
    timeout_ms: u64,
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

    let runner_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_sp1_real_backend(words, timeout_ms, inject_kind, inject_step)
    }));
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
                    "sp1 v4 backend did not complete prove+verify successfully (prove_ok={}, verify_ok={})",
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

    fn semantic_candidate_from_hit(&self, hit: &BucketHit) -> Vec<SemanticInjectionCandidate> {
        let bucket_id = hit.bucket_id.as_str();
        if bucket_id != semantic::memory::TIMESTAMPED_LOAD_PATH.id
            && bucket_id != semantic::lookup::BOOLEAN_MULTIPLICITY.id
        {
            return Vec::new();
        }

        let anchor = Self::step_from_hit(hit);
        let schedule = self
            .last_observed_injection_sites
            .get(IS_MEMORY_INJECT_KIND)
            .map(|steps| {
                InjectionSchedule::Explicit(Self::ordered_steps_around_anchor(steps, anchor))
            })
            .unwrap_or(InjectionSchedule::AroundAnchor(anchor));

        vec![SemanticInjectionCandidate {
            bucket_id: hit.bucket_id.clone(),
            trigger_signal_id: None,
            semantic_class: if bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id {
                semantic::memory::TIMESTAMPED_LOAD_PATH.semantic_class.to_string()
            } else {
                semantic::lookup::BOOLEAN_MULTIPLICITY.semantic_class.to_string()
            },
            inject_kind: IS_MEMORY_INJECT_KIND.to_string(),
            schedule,
        }]
    }

    fn semantic_candidate_priority(candidate: &SemanticInjectionCandidate) -> u8 {
        let bucket_id = candidate.bucket_id.as_str();
        if bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id {
            0
        } else if bucket_id == semantic::lookup::BOOLEAN_MULTIPLICITY.id {
            1
        } else {
            2
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
