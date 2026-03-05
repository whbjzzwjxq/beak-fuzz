use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use beak_core::fuzz::loop1::{BackendEval, LoopBackend};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace};
use serde::{Deserialize, Serialize};
use sp1_prover::SP1Prover;
use sp1_core_executor::{events::MemoryRecordEnum, ExecutionRecord, Executor, ExecutorMode, Register};
use sp1_stark::{MachineProver, SP1CoreOpts, StarkGenericConfig};

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
    pub backend_error: Option<String>,
}

const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RealRunnerResponse {
    final_regs: Option<[u32; 32]>,
    micro_op_count: usize,
    bucket_hits: Vec<BucketHit>,
    prove_ok: bool,
    verify_ok: bool,
    error: Option<String>,
}

fn apply_injection_to_records(records: &mut [ExecutionRecord], inject_kind: Option<&str>, inject_step: u64) {
    let Some(kind) = inject_kind else {
        return;
    };

    let mut flat_cpu_idx = 0u64;
    let target_step = if inject_step == u64::MAX { None } else { Some(inject_step) };
    for record in records.iter_mut() {
        for event in &mut record.cpu_events {
            let step_match = target_step.map(|s| s == flat_cpu_idx).unwrap_or(true);
            if !step_match {
                flat_cpu_idx = flat_cpu_idx.saturating_add(1);
                continue;
            }
            match kind {
                // Simulate timestamp wraparound style witness corruption on memory accesses.
                "sp1.audit_timestamp.mem_row_wraparound" => {
                    event.clk = event.clk.wrapping_add(u32::MAX);
                    if let Some(mem) = event.memory_record.as_mut() {
                        match mem {
                            MemoryRecordEnum::Read(r) => {
                                r.prev_timestamp = r.timestamp;
                                r.timestamp = 0;
                            }
                            MemoryRecordEnum::Write(w) => {
                                w.prev_timestamp = w.timestamp;
                                w.timestamp = 0;
                            }
                        }
                    }
                }
                // Simulate local-event multiplicity corruption.
                "sp1.audit_multiplicity_bool_constraint.local_event_row" => {
                    if let Some(mem) = event.memory_record.as_mut() {
                        if let MemoryRecordEnum::Write(w) = mem {
                            w.value ^= 1;
                        }
                    }
                }
                _ => {}
            }
            return;
        }
        flat_cpu_idx = flat_cpu_idx.saturating_add(record.cpu_events.len() as u64);
    }
}

fn run_sp1_real_backend(
    words: &[u32],
    _timeout_ms: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RealRunnerResponse, String> {
    let program = build_sp1_program(words)?;
    let mut executor = Executor::new(program, SP1CoreOpts::default());
    executor.executor_mode = ExecutorMode::Trace;
    executor
        .run()
        .map_err(|e| format!("sp1 executor run failed: {e}"))?;

    let mut records = std::mem::take(&mut executor.records);
    apply_injection_to_records(&mut records, inject_kind, inject_step);
    let trace = Sp1Trace::from_execution_records(words, &records)?;
    let (prove_ok, verify_ok, prove_verify_error) = run_sp1_prove_verify(&executor.program, &records);

    let mut regs = [0u32; 32];
    for i in 0..32usize {
        regs[i] = executor.register(Register::from_u32(i as u32));
    }

    Ok(RealRunnerResponse {
        final_regs: Some(regs),
        micro_op_count: trace.instruction_count(),
        bucket_hits: trace.bucket_hits().to_vec(),
        prove_ok,
        verify_ok,
        error: prove_verify_error,
    })
}

fn run_sp1_prove_verify(
    program: &sp1_core_executor::Program,
    records: &[ExecutionRecord],
) -> (bool, bool, Option<String>) {
    let prover: SP1Prover = SP1Prover::new();
    let (pk, vk) = prover.core_prover.setup(program);
    let mut prove_challenger = prover.core_prover.config().challenger();

    let proof = match prover
        .core_prover
        .prove(&pk, records.to_vec(), &mut prove_challenger, SP1CoreOpts::default())
    {
        Ok(p) => p,
        Err(e) => {
            return (
                false,
                false,
                Some(format!("sp1 core prove failed: {e}")),
            );
        }
    };

    let mut verify_challenger = prover.core_prover.config().challenger();
    if let Err(e) = prover
        .core_prover
        .machine()
        .verify(&vk, &proof, &mut verify_challenger)
    {
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

    if let Some(err) = resp.error {
        return Err(err);
    }
    if !resp.prove_ok || !resp.verify_ok {
        return Err(format!(
            "sp1 real backend did not complete prove+verify successfully (prove_ok={}, verify_ok={})",
            resp.prove_ok, resp.verify_ok
        ));
    }

    Ok(WorkerResponse {
        request_id,
        final_regs: resp.final_regs,
        micro_op_count: resp.micro_op_count,
        bucket_hits: resp.bucket_hits,
        backend_error: None,
    })
}

pub struct Sp1Backend {
    max_instructions: usize,
    timeout_ms: u64,
    eval: BackendEval,
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
            current_iteration: 0,
            next_request_id: 1,
            pending_injection: None,
            worker: None,
        }
    }

    fn map_bucket_to_injection(bucket_id: &str, step: u64) -> Option<WitnessInjectionPlan> {
        let (kind, step) = match bucket_id {
            // Row-level witness injection in MemoryReadWrite + MemoryInitializeFinalize.
            "sp1.loop2.target.mem_load_path" => ("sp1.audit_timestamp.mem_row_wraparound", u64::MAX),
            // Row-level witness injection in MemoryLocal (is_real column).
            "sp1.loop2.target.multiplicity_bool_constraint" => (
                "sp1.audit_multiplicity_bool_constraint.local_event_row",
                step,
            ),
            _ => return None,
        };
        Some(WitnessInjectionPlan {
            kind: kind.to_string(),
            step,
        })
    }

    fn step_from_hit(hit: &BucketHit) -> u64 {
        hit.details
            .get("op_idx")
            .and_then(|v| v.as_u64())
            .or_else(|| hit.details.get("step_idx").and_then(|v| v.as_u64()))
            .unwrap_or(0)
    }

    fn select_injection_from_hits(hits: &[BucketHit]) -> Option<WitnessInjectionPlan> {
        const TARGET_PRIORITY: [&str; 2] = [
            "sp1.loop2.target.multiplicity_bool_constraint",
            "sp1.loop2.target.mem_load_path",
        ];
        for target in TARGET_PRIORITY {
            if let Some(hit) = hits.iter().find(|h| h.bucket_id == target) {
                if let Some(plan) = Self::map_bucket_to_injection(&hit.bucket_id, Self::step_from_hit(hit)) {
                    return Some(plan);
                }
            }
        }
        for hit in hits {
            if let Some(plan) = Self::map_bucket_to_injection(&hit.bucket_id, Self::step_from_hit(hit)) {
                return Some(plan);
            }
        }
        None
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

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "capture backend worker stdin failed".to_string())?;
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

        self.worker = Some(WorkerProcess {
            child,
            stdin,
            responses_rx: rx,
            reader_thread,
        });
        Ok(())
    }

    fn stop_worker(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            let worker_pid = worker.child.id();
            // Best-effort reap for nested runner children that may outlive the worker.
            let _ = Command::new("pkill")
                .arg("-KILL")
                .arg("-P")
                .arg(worker_pid.to_string())
                .status();
            let _ = worker.child.kill();
            let _ = worker.child.wait();
            let _ = Command::new("pkill")
                .arg("-KILL")
                .arg("-P")
                .arg(worker_pid.to_string())
                .status();
            drop(worker.stdin);
            let _ = worker.reader_thread.join();
        }
    }
}

impl LoopBackend for Sp1Backend {
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
            let worker = self
                .worker
                .as_mut()
                .ok_or_else(|| "backend worker unavailable".to_string())?;
            let mut payload =
                serde_json::to_vec(&req).map_err(|e| format!("serialize worker request failed: {e}"))?;
            payload.push(b'\n');
            worker
                .stdin
                .write_all(&payload)
                .map_err(|e| format!("write worker request failed: {e}"))?;
            worker
                .stdin
                .flush()
                .map_err(|e| format!("flush worker request failed: {e}"))?;
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
                let worker = self
                    .worker
                    .as_ref()
                    .ok_or_else(|| "backend worker unavailable".to_string())?;
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
            final_regs: resp.final_regs,
            backend_error: resp.backend_error.clone(),
        };

        if let Some(err) = resp.backend_error {
            return Err(err);
        }
        resp.final_regs
            .ok_or_else(|| "sp1 backend did not return final regs".to_string())
    }

    fn collect_eval(&mut self) -> BackendEval {
        self.eval.clone()
    }

    fn bucket_has_direct_injection(&self, bucket_id: &str) -> bool {
        Self::map_bucket_to_injection(bucket_id, 0).is_some()
    }

    fn clear_direct_injection(&mut self) {
        self.pending_injection = None;
    }

    fn arm_direct_injection_from_hits(&mut self, hits: &[BucketHit]) -> Option<String> {
        self.pending_injection = Self::select_injection_from_hits(hits);
        self.pending_injection.as_ref().map(|p| p.kind.clone())
    }
}

impl Drop for Sp1Backend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}
