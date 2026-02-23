use beak_core::fuzz::loop1::{BackendEval, LoopBackend};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::Trace;

use crate::trace::OpenVMTrace;
use openvm_instructions::exe::VmExe;
use openvm_instructions::instruction::Instruction;
use openvm_instructions::program::Program;
use openvm_instructions::riscv::RV32_REGISTER_AS;
use openvm_instructions::LocalOpcode;
use openvm_instructions::SystemOpcode;
use openvm_rv32im_transpiler::{Rv32ITranspilerExtension, Rv32MTranspilerExtension};
use openvm_sdk::config::AppConfig;
use openvm_sdk::{Sdk, StdIn, F};
use openvm_transpiler::transpiler::Transpiler;

fn build_sdk() -> Sdk {
    let mut app_config = AppConfig::riscv32();
    app_config.app_vm_config.system.config =
        app_config.app_vm_config.system.config.with_max_segment_len(256).with_continuations();
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
    // OpenVM's RV32IM toolchain does not currently support system/CSR or fence in our harness.
    // Avoid feeding them to the transpiler/prover since it may terminate the process.
    let opcode = word & 0x7f;
    opcode != 0x73 && opcode != 0x0f
}

pub struct OpenVmBackend {
    sdk: Sdk,
    max_instructions: usize,
    eval: BackendEval,
    /// Trace built from fuzzer_utils logs after a successful prove.
    trace: Option<OpenVMTrace>,
}

impl OpenVmBackend {
    pub fn new(max_instructions: usize) -> Self {
        Self {
            sdk: build_sdk(),
            max_instructions,
            eval: BackendEval::default(),
            trace: None,
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

    fn prepare_for_run(&mut self, rng_seed: u64) {
        // Nothing to do here.
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval.backend_error = None;
        self.trace = None;

        let exe = build_exe(words).map_err(|e| {
            self.eval.backend_error = Some(e.clone());
            e
        })?;
        let mut app_prover = self.sdk.app_prover(exe).map_err(|e| {
            let msg = format!("app_prover failed: {e:?}");
            self.eval.backend_error = Some(msg.clone());
            msg
        })?;
        let _proof = app_prover.prove(StdIn::default()).map_err(|e| {
            let msg = format!("prove failed: {e:?}");
            self.eval.backend_error = Some(msg.clone());
            msg
        })?;

        let state =
            app_prover.instance().state().as_ref().ok_or_else(|| "no final state".to_string())?;
        let mut regs = [0u32; 32];
        for i in 0..32u32 {
            let bytes: [u8; 4] = unsafe { state.memory.read::<u8, 4>(RV32_REGISTER_AS, i * 4) };
            regs[i as usize] = u32::from_le_bytes(bytes);
        }
        self.eval.final_regs = Some(regs);

        let logs = fuzzer_utils::take_json_logs();
        match OpenVMTrace::from_logs(logs) {
            Ok(trace) => {
                self.trace = Some(trace);
                Ok(regs)
            }
            Err(e) => {
                self.eval.backend_error = Some(e.clone());
                Err(e)
            }
        }
    }

    fn collect_eval(&mut self) -> BackendEval {
        if let Some(ref trace) = self.trace {
            self.eval.micro_op_count = trace.instruction_count();
            self.eval.bucket_hits = trace.bucket_hits().to_vec();
        }
        self.eval.clone()
    }
}
