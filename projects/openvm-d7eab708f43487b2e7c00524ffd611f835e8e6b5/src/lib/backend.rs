use beak_core::fuzz::loop1::{BackendEval, LoopBackend};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::Trace;

use crate::trace::OpenVMTrace;
use crate::bucket_id::OpenVMBucketId;
use openvm_instructions::exe::VmExe;
use openvm_instructions::instruction::Instruction;
use openvm_instructions::program::Program;
use openvm_instructions::riscv::RV32_REGISTER_AS;
use openvm_instructions::LocalOpcode;
use openvm_instructions::SystemOpcode;
use openvm_rv32im_transpiler::{Rv32ITranspilerExtension, Rv32MTranspilerExtension};
use openvm_sdk::config::AppConfig;
use openvm_sdk::prover::vm::new_local_prover;
use openvm_sdk::{DefaultStarkEngine, Sdk, StdIn, F};
use openvm_transpiler::transpiler::Transpiler;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

fn build_sdk() -> Sdk {
    let mut app_config = AppConfig::riscv32();
    app_config.app_vm_config.system.config =
        app_config.app_vm_config.system.config.with_max_segment_len(256).with_continuations();
    let fast_test = std::env::var("FAST_TEST").as_deref() == Ok("1");
    if fast_test {
        // Fast, insecure proving parameters for local fuzzing/debugging.
        // Mirrors `openvm_stark_sdk::config::FriParameters::new_for_testing` when FAST_TEST=1.
        app_config.app_fri_params.fri_params.log_final_poly_len = 0;
        app_config.app_fri_params.fri_params.num_queries = 2;
        app_config.app_fri_params.fri_params.proof_of_work_bits = 0;
    }
    Sdk::new(app_config).expect("sdk init")
}

fn build_exe(words: &[u32]) -> Result<std::sync::Arc<VmExe<F>>, String> {
    let transpiler = Transpiler::<F>::default()
        .with_extension(Rv32ITranspilerExtension)
        .with_extension(Rv32MTranspilerExtension);
    let transpiled = transpiler.transpile(words).map_err(|e| format!("transpile failed: {e:?}"))?;

    let mut instructions: Vec<Instruction<F>> = Vec::new();
    for opt in transpiled.into_iter().flatten() {
        instructions.push(opt);
    }
    instructions.push(Instruction::from_usize(SystemOpcode::TERMINATE.global_opcode(), [0, 0, 0]));

    let program = Program::from_instructions(&instructions);
    Ok(std::sync::Arc::new(VmExe::new(program)))
}

fn is_openvm_supported_rv32_word(word: u32) -> bool {
    // We still keep fence filtered in this harness.
    let opcode = word & 0x7f;
    opcode != 0x0f
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub request_id: u64,
    pub words: Vec<u32>,
    pub iteration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub request_id: u64,
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<beak_core::trace::BucketHit>,
    pub backend_error: Option<String>,
}

const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";

pub fn run_backend_once(
    request_id: u64,
    words: &[u32],
    current_iteration: u64,
) -> Result<WorkerResponse, String> {
    let t_total = Instant::now();
    let mut eval = BackendEval::default();
    let _ = fuzzer_utils::take_json_logs();

    let t0 = Instant::now();
    let exe = build_exe(words).map_err(|e| {
        eval.backend_error = Some(e.clone());
        e
    })?;
    let ms_build_exe = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let sdk = build_sdk();
    let app_pk = sdk.app_pk();
    let mut instance = new_local_prover::<DefaultStarkEngine, _>(
        sdk.app_vm_builder().clone(),
        &app_pk.app_vm_pk,
        exe,
    )
    .map_err(|e| {
        let msg = format!("new_local_prover failed: {e:?}");
        eval.backend_error = Some(msg.clone());
        msg
    })?;
    let ms_instance = t1.elapsed().as_millis();

    let t2 = Instant::now();
    // Split the proving pipeline:
    // - metered execution: determine continuation segments + per-air trace heights
    // - preflight execution: produce record arenas (witness-like data)
    // - tracegen: `generate_proving_ctx` runs chip trace generation (hits `fill_trace_row`)
    // - skip `engine.prove` (FRI, commitments, queries), which is the expensive part
    let input = StdIn::default();
    instance.reset_state(input.clone());

    let exe = instance.exe().clone();
    let metered_ctx = instance.vm.build_metered_ctx(exe.as_ref());
    let metered_interpreter = instance.vm.metered_interpreter(exe.as_ref()).map_err(|e| {
        let msg = format!("metered_interpreter failed: {e:?}");
        eval.backend_error = Some(msg.clone());
        msg
    })?;
    let (segments, _) = metered_interpreter
        .execute_metered(input, metered_ctx)
        .map_err(|e| {
            let msg = format!("execute_metered failed: {e:?}");
            eval.backend_error = Some(msg.clone());
            msg
        })?;

    let mut state = instance.state_mut().take();
    let (vm, interpreter) = (&mut instance.vm, &mut instance.interpreter);
    for segment in segments {
        let from_state = Option::take(&mut state).ok_or_else(|| "no state".to_string())?;
        vm.transport_init_memory_to_device(&from_state.memory);

        let out = vm
            .execute_preflight(
                interpreter,
                from_state,
                Some(segment.num_insns),
                &segment.trace_heights,
            )
            .map_err(|e| {
                let msg = format!("execute_preflight failed: {e:?}");
                eval.backend_error = Some(msg.clone());
                msg
            })?;
        state = Some(out.to_state);

        let _ctx = vm
            .generate_proving_ctx(out.system_records, out.record_arenas)
            .map_err(|e| {
                let msg = format!("generate_proving_ctx failed: {e:?}");
                eval.backend_error = Some(msg.clone());
                msg
            })?;
    }
    let ms_trace_only = t2.elapsed().as_millis();

    let t3 = Instant::now();
    let state = state.as_ref().ok_or_else(|| "no final state".to_string())?;
    let mut regs = [0u32; 32];
    for i in 0..32u32 {
        let bytes: [u8; 4] = unsafe { state.memory.read::<u8, 4>(RV32_REGISTER_AS, i * 4) };
        regs[i as usize] = u32::from_le_bytes(bytes);
    }
    eval.final_regs = Some(regs);
    let ms_read_regs = t3.elapsed().as_millis();

    let t4 = Instant::now();
    let logs = fuzzer_utils::take_json_logs();
    let ms_take_logs = t4.elapsed().as_millis();
    let logs_len = logs.len();

    let t5 = Instant::now();
    match OpenVMTrace::from_logs(logs) {
        Ok(trace) => {
            let insn_count = trace.instructions().len();
            let row_count = trace.chip_rows().len();
            let hit_count = trace.bucket_hits().len();
            eval.micro_op_count = trace.instruction_count();
            eval.bucket_hits = trace.bucket_hits().to_vec();
            let ms_parse = t5.elapsed().as_millis();
            eprintln!(
                "[openvm-backend-worker] iter={} logs_len={logs_len} insn_count={insn_count} chip_rows={row_count} bucket_hits={hit_count} build_exe_ms={ms_build_exe} instance_ms={ms_instance} trace_only_ms={ms_trace_only} read_regs_ms={ms_read_regs} take_logs_ms={ms_take_logs} parse_ms={ms_parse} total_ms={}",
                current_iteration,
                t_total.elapsed().as_millis()
            );
        }
        Err(e) => {
            let ms_parse = t5.elapsed().as_millis();
            eval.backend_error = Some(e.clone());
            eprintln!(
                "[openvm-backend-worker] iter={} ERROR parse_logs ({e}); logs_len={logs_len} build_exe_ms={ms_build_exe} instance_ms={ms_instance} trace_only_ms={ms_trace_only} read_regs_ms={ms_read_regs} take_logs_ms={ms_take_logs} parse_ms={ms_parse} total_ms={}",
                current_iteration,
                t_total.elapsed().as_millis()
            );
        }
    }

    Ok(WorkerResponse {
        request_id,
        final_regs: eval.final_regs,
        micro_op_count: eval.micro_op_count,
        bucket_hits: eval.bucket_hits,
        backend_error: eval.backend_error,
    })
}

struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    responses_rx: Receiver<Result<WorkerResponse, String>>,
    reader_thread: JoinHandle<()>,
}

pub struct OpenVmBackend {
    max_instructions: usize,
    timeout_ms: u64,
    eval: BackendEval,
    last_words: Vec<u32>,
    current_iteration: u64,
    next_request_id: u64,
    worker: Option<WorkerProcess>,
}

impl OpenVmBackend {
    pub fn new(max_instructions: usize, timeout_ms: u64) -> Self {
        Self {
            max_instructions,
            timeout_ms,
            eval: BackendEval::default(),
            last_words: Vec::new(),
            current_iteration: 0,
            next_request_id: 1,
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
                            // Ignore non-protocol stdout noise from dependencies.
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
            let _ = worker.child.kill();
            let _ = worker.child.wait();
            drop(worker.stdin);
            let _ = worker.reader_thread.join();
        }
    }
}

impl LoopBackend for OpenVmBackend {
    fn is_usable_seed(&self, words: &[u32]) -> bool {
        if words.is_empty() {
            return false;
        }
        if words.len() > self.max_instructions {
            return false;
        }
        words
            .iter()
            .all(|w| is_openvm_supported_rv32_word(*w) && RV32IMInstruction::from_word(*w).is_ok())
    }

    fn prepare_for_run(&mut self, _rng_seed: u64) {
        self.current_iteration = self.current_iteration.saturating_add(1);
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        let timeout = Duration::from_millis(self.timeout_ms);
        self.eval.backend_error = None;
        self.eval.bucket_hits.clear();
        self.eval.micro_op_count = 0;
        self.eval.final_regs = None;
        self.last_words = words.to_vec();
        self.start_worker()?;
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        let req = WorkerRequest {
            request_id,
            words: words.to_vec(),
            iteration: self.current_iteration,
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
        let worker_resp = loop {
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

        self.eval.micro_op_count = worker_resp.micro_op_count;
        self.eval.bucket_hits = worker_resp.bucket_hits;
        self.eval.backend_error = worker_resp.backend_error.clone();
        self.eval.final_regs = worker_resp.final_regs;

        match worker_resp.final_regs {
            Some(regs) => Ok(regs),
            None => Err(worker_resp
                .backend_error
                .unwrap_or_else(|| "backend worker returned no final regs".to_string())),
        }
    }

    fn collect_eval(&mut self) -> BackendEval {
        // Input-level buckets help guide seed evolution, even when the backend rejects or
        // does not fully model certain instruction classes.
        let details = HashMap::new();
        let mut saw_ecall = false;
        let mut saw_csr = false;
        let mut saw_fence = false;
        for &w in &self.last_words {
            let opcode = w & 0x7f;
            if opcode == 0x0f {
                saw_fence = true;
                continue;
            }
            if opcode != 0x73 {
                continue;
            }
            if let Ok(insn) = RV32IMInstruction::from_word(w) {
                match insn.mnemonic.as_str() {
                    "ecall" | "ebreak" => saw_ecall = true,
                    // Any CSR family op.
                    "csrrw" | "csrrs" | "csrrc" | "csrrwi" | "csrrsi" | "csrrci" => saw_csr = true,
                    _ => {}
                }
            }
        }
        if saw_ecall {
            self.eval.bucket_hits.push(beak_core::trace::BucketHit::new(
                OpenVMBucketId::InputHasEcall.as_ref().to_string(),
                details.clone(),
            ));
        }
        if saw_csr {
            self.eval.bucket_hits.push(beak_core::trace::BucketHit::new(
                OpenVMBucketId::InputHasCsr.as_ref().to_string(),
                details.clone(),
            ));
        }
        if saw_fence {
            self.eval.bucket_hits.push(beak_core::trace::BucketHit::new(
                OpenVMBucketId::InputHasFence.as_ref().to_string(),
                details.clone(),
            ));
        }

        self.eval.clone()
    }
}

impl Drop for OpenVmBackend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}
