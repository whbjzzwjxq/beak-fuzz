use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use beak_core::fuzz::loop1::{BackendEval, LoopBackend};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace};
use serde::{Deserialize, Serialize};

use crate::trace::PicoTrace;

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
}

fn real_runner_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("pico-real-backend")
        .join("Cargo.toml")
}

fn run_pico_real_backend(
    words: &[u32],
    timeout_ms: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RealRunnerResponse, String> {
    let manifest = real_runner_manifest_path();
    if !manifest.exists() {
        return Err(format!(
            "missing real backend manifest: {}",
            manifest.display()
        ));
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

    let started = Instant::now();
    let timeout = Duration::from_millis(timeout_ms.max(1));
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if started.elapsed() >= timeout {
                    // Best-effort: kill direct children first, then the runner itself.
                    let _ = Command::new("pkill")
                        .arg("-KILL")
                        .arg("-P")
                        .arg(child.id().to_string())
                        .status();
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "pico real backend timed out after {} ms (child killed)",
                        timeout_ms
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
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
    let status = child
        .wait()
        .map_err(|e| format!("failed to finalize pico real backend child: {e}"))?;

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
    timeout_ms: u64,
    _current_iteration: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<WorkerResponse, String> {
    let mut eval = BackendEval::default();

    let runner_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_pico_real_backend(words, timeout_ms, inject_kind, inject_step)
    }));

    match runner_res {
        Ok(Ok(resp)) => {
            eval.final_regs = resp.final_regs;
            eval.micro_op_count = resp.micro_op_count;
            if let Some(err) = resp.error {
                eval.backend_error = Some(err);
            } else if !resp.prove_ok || !resp.verify_ok {
                eval.backend_error = Some(format!(
                    "pico real backend did not complete prove+verify successfully (prove_ok={}, verify_ok={})",
                    resp.prove_ok, resp.verify_ok
                ));
            }
        }
        Ok(Err(e)) => {
            eval.backend_error = Some(e);
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

    let trace = PicoTrace::from_words(words)?;
    if eval.micro_op_count == 0 {
        eval.micro_op_count = trace.instruction_count();
    }
    eval.bucket_hits = trace.bucket_hits().to_vec();

    Ok(WorkerResponse {
        request_id,
        final_regs: eval.final_regs,
        micro_op_count: eval.micro_op_count,
        bucket_hits: eval.bucket_hits,
        backend_error: eval.backend_error,
    })
}

pub struct PicoBackend {
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

impl PicoBackend {
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

    fn map_bucket_to_injection(bucket_id: &str, _step: u64) -> Option<WitnessInjectionPlan> {
        let (kind, step) = match bucket_id {
            // Row-level witness injection in MemoryReadWrite + MemoryInitializeFinalize.
            "pico.loop2.target.mem_load_path" => ("pico.audit_timestamp.mem_row_wraparound", u64::MAX),
            // Row-level witness injection in MemoryLocal (is_real column).
            "pico.loop2.target.multiplicity_bool_constraint" => (
                "pico.audit_multiplicity_bool_constraint.local_event_row",
                u64::MAX,
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
            "pico.loop2.target.multiplicity_bool_constraint",
            "pico.loop2.target.mem_load_path",
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

impl LoopBackend for PicoBackend {
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
            .ok_or_else(|| "pico backend did not return final regs".to_string())
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

impl Drop for PicoBackend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}
