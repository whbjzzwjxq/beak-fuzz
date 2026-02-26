use beak_core::fuzz::loop1::{BackendEval, LoopBackend};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::Trace;

use crate::trace::OpenVMTrace;
use crate::bucket_id::OpenVMBucketId;
use openvm_circuit::arch::VmExecutor;
use openvm_instructions::exe::VmExe;
use openvm_instructions::instruction::Instruction;
use openvm_instructions::program::Program;
use openvm_instructions::riscv::RV32_REGISTER_AS;
use openvm_instructions::LocalOpcode;
use openvm_instructions::SystemOpcode;
use openvm_rv32im_transpiler::{Rv32ITranspilerExtension, Rv32MTranspilerExtension};
use openvm_sdk::config::{AppConfig, SdkVmConfig};
use openvm_sdk::{Sdk, StdIn, F};
use openvm_stark_backend::p3_field::PrimeField32;
use openvm_transpiler::transpiler::Transpiler;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

fn build_sdk() -> Sdk {
    Sdk
}

fn build_vm_config() -> SdkVmConfig {
    let mut vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .build();
    vm_config.system.config = vm_config
        .system
        .config
        .clone()
        .with_max_segment_len(256)
        .with_continuations();
    vm_config
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
    pub inject_kind: Option<String>,
    pub inject_step: u64,
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
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<WorkerResponse, String> {
    let t_total = Instant::now();
    let mut eval = BackendEval::default();
    fuzzer_utils::configure_witness_injection(inject_kind, inject_step);
    let _ = fuzzer_utils::take_json_logs();

    let t0 = Instant::now();
    let exe = build_exe(words).map_err(|e| {
        eval.backend_error = Some(e.clone());
        e
    })?;
    let ms_build_exe = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let sdk = build_sdk();
    let vm_config = build_vm_config();
    let app_config = AppConfig {
        app_fri_params: Default::default(),
        app_vm_config: vm_config,
        leaf_fri_params: Default::default(),
        compiler_options: Default::default(),
    };
    let app_pk = std::sync::Arc::new(sdk.app_keygen(app_config).map_err(|e| {
        let msg = format!("app_keygen failed: {e:?}");
        eval.backend_error = Some(msg.clone());
        msg
    })?);
    let app_committed_exe = sdk
        .commit_app_exe(app_pk.app_vm_pk.fri_params, exe.as_ref().clone())
        .map_err(|e| {
            let msg = format!("commit_app_exe failed: {e:?}");
            eval.backend_error = Some(msg.clone());
            msg
        })?;
    let app_vm = VmExecutor::new(app_pk.app_vm_pk.vm_config.clone());
    let ms_instance = t1.elapsed().as_millis();

    let t2 = Instant::now();
    let input = StdIn::default();
    let vm_result = app_vm
        .execute_and_generate_with_cached_program(app_committed_exe, input)
        .map_err(|e| {
            let msg = format!("execute_and_generate_with_cached_program failed: {e:?}");
            eval.backend_error = Some(msg.clone());
            msg
        })?;
    let ms_trace_only = t2.elapsed().as_millis();

    let t3 = Instant::now();
    let state = vm_result
        .final_memory
        .as_ref()
        .ok_or_else(|| "no final state".to_string())?;
    let mut regs = [0u32; 32];
    for i in 0..32u32 {
        let limbs = state.get_range::<4>(&(RV32_REGISTER_AS, i * 4));
        let bytes: [u8; 4] = limbs.map(|x| x.as_canonical_u32() as u8);
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

#[derive(Debug, Clone)]
struct WitnessInjectionPlan {
    kind: String,
    step: u64,
}

pub struct OpenVmBackend {
    max_instructions: usize,
    timeout_ms: u64,
    eval: BackendEval,
    last_words: Vec<u32>,
    current_iteration: u64,
    next_request_id: u64,
    pending_injection: Option<WitnessInjectionPlan>,
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
            pending_injection: None,
            worker: None,
        }
    }

    fn map_bucket_to_injection(bucket_id: &str) -> Option<WitnessInjectionPlan> {
        let kind = match bucket_id {
            "openvm.loop2.target.base_alu_imm_limbs" => "openvm.audit_o5.rs2_imm_limbs",
            "openvm.auipc.seen" => "openvm.audit_o7.auipc_pc_limbs",
            "openvm.mem.access_seen" => "openvm.audit_o8.loadstore_imm_sign",
            "openvm.divrem.div_by_zero"
            | "openvm.divrem.overflow_case"
            | "openvm.divrem.rs1_eq_rs2" => "openvm.audit_o15.divrem_special_case_on_invalid",
            _ => return None,
        };
        Some(WitnessInjectionPlan {
            kind: kind.to_string(),
            step: 0,
        })
    }

    fn select_injection_from_hits(
        hits: &[beak_core::trace::BucketHit],
    ) -> Option<WitnessInjectionPlan> {
        for hit in hits {
            if let Some(plan) = Self::map_bucket_to_injection(&hit.bucket_id) {
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
        self.pending_injection = Self::select_injection_from_hits(&self.eval.bucket_hits);
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

    fn bucket_has_direct_injection(&self, bucket_id: &str) -> bool {
        Self::map_bucket_to_injection(bucket_id).is_some()
    }
}

impl Drop for OpenVmBackend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}
