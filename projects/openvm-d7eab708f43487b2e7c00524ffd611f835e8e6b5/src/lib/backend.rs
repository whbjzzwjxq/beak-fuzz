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
use std::collections::HashMap;
use std::time::Instant;

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

pub struct OpenVmBackend {
    sdk: Sdk,
    max_instructions: usize,
    eval: BackendEval,
    /// Trace built from fuzzer_utils logs after a successful prove.
    trace: Option<OpenVMTrace>,
    last_words: Vec<u32>,
    current_iteration: u64,
}

impl OpenVmBackend {
    pub fn new(max_instructions: usize) -> Self {
        Self {
            sdk: build_sdk(),
            max_instructions,
            eval: BackendEval::default(),
            trace: None,
            last_words: Vec::new(),
            current_iteration: 0,
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
        let t_total = Instant::now();
        self.eval.backend_error = None;
        self.trace = None;
        self.last_words = words.to_vec();
        // Avoid accidentally mixing logs from a previous run with this input.
        let _ = fuzzer_utils::take_json_logs();

        let t0 = Instant::now();
        let exe = build_exe(words).map_err(|e| {
            self.eval.backend_error = Some(e.clone());
            e
        })?;
        let ms_build_exe = t0.elapsed().as_millis();

        let t1 = Instant::now();
        let app_pk = self.sdk.app_pk();
        let mut instance = new_local_prover::<DefaultStarkEngine, _>(
            self.sdk.app_vm_builder().clone(),
            &app_pk.app_vm_pk,
            exe,
        )
        .map_err(|e| {
            let msg = format!("new_local_prover failed: {e:?}");
            self.eval.backend_error = Some(msg.clone());
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
            self.eval.backend_error = Some(msg.clone());
            msg
        })?;
        let (segments, _) = metered_interpreter
            .execute_metered(input, metered_ctx)
            .map_err(|e| {
                let msg = format!("execute_metered failed: {e:?}");
                self.eval.backend_error = Some(msg.clone());
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
                    self.eval.backend_error = Some(msg.clone());
                    msg
                })?;
            state = Some(out.to_state);

            // This triggers trace generation and therefore fuzzer_utils micro-op emission.
            let _ctx = vm
                .generate_proving_ctx(out.system_records, out.record_arenas)
                .map_err(|e| {
                    let msg = format!("generate_proving_ctx failed: {e:?}");
                    self.eval.backend_error = Some(msg.clone());
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
        self.eval.final_regs = Some(regs);
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
                self.trace = Some(trace);
                let ms_parse = t5.elapsed().as_millis();
                eprintln!(
                    "[openvm-backend] iter={} logs_len={logs_len} insn_count={insn_count} chip_rows={row_count} bucket_hits={hit_count} build_exe_ms={ms_build_exe} instance_ms={ms_instance} trace_only_ms={ms_trace_only} read_regs_ms={ms_read_regs} take_logs_ms={ms_take_logs} parse_ms={ms_parse} total_ms={}",
                    self.current_iteration,
                    t_total.elapsed().as_millis()
                );
                Ok(regs)
            }
            Err(e) => {
                self.eval.backend_error = Some(e.clone());
                let ms_parse = t5.elapsed().as_millis();
                eprintln!(
                    "[openvm-backend] iter={} ERROR parse_logs ({e}); logs_len={logs_len} build_exe_ms={ms_build_exe} instance_ms={ms_instance} trace_only_ms={ms_trace_only} read_regs_ms={ms_read_regs} take_logs_ms={ms_take_logs} parse_ms={ms_parse} total_ms={}",
                    self.current_iteration,
                    t_total.elapsed().as_millis()
                );
                Err(e)
            }
        }
    }

    fn collect_eval(&mut self) -> BackendEval {
        if let Some(ref trace) = self.trace {
            self.eval.micro_op_count = trace.instruction_count();
            self.eval.bucket_hits = trace.bucket_hits().to_vec();
        }

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
