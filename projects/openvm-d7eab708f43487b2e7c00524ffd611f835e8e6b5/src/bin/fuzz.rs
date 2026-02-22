use std::path::{Path, PathBuf};

use clap::{Arg, Command};

use beak_core::fuzz::loop1::{run_loop1_threaded, BackendEval, Loop1Config, LoopBackend, DEFAULT_RNG_SEED};
use beak_core::rv32im::instruction::RV32IMInstruction;

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

const ZKVM_COMMIT: &str = "d7eab708f43487b2e7c00524ffd611f835e8e6b5";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn resolve_path(root: &Path, arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.is_absolute() {
        p
    } else {
        root.join(p)
    }
}

fn build_sdk() -> Sdk {
    let mut app_config = AppConfig::riscv32();
    app_config.app_vm_config.system.config = app_config
        .app_vm_config
        .system
        .config
        .with_max_segment_len(256)
        .with_continuations();
    Sdk::new(app_config).expect("sdk init")
}

fn build_exe(words: &[u32]) -> Result<std::sync::Arc<VmExe<F>>, String> {
    let transpiler = Transpiler::<F>::default()
        .with_extension(Rv32ITranspilerExtension)
        .with_extension(Rv32MTranspilerExtension);
    let transpiled = transpiler
        .transpile(words)
        .map_err(|e| format!("transpile failed: {e:?}"))?;

    let mut instructions: Vec<Instruction<F>> = Vec::new();
    for opt in transpiled.into_iter().flatten() {
        instructions.push(opt);
    }
    instructions.push(Instruction::from_usize(
        SystemOpcode::TERMINATE.global_opcode(),
        [0, 0, 0],
    ));

    let program = Program::from_instructions(&instructions);
    Ok(std::sync::Arc::new(VmExe::new(program)))
}

fn is_openvm_supported_rv32_word(word: u32) -> bool {
    // OpenVM's RV32IM toolchain does not currently support system/CSR or fence in our harness.
    // Avoid feeding them to the transpiler/prover since it may terminate the process.
    let opcode = word & 0x7f;
    opcode != 0x73 && opcode != 0x0f
}

struct OpenVmBackend {
    sdk: Sdk,
    max_instructions: usize,
}

impl OpenVmBackend {
    fn new(max_instructions: usize) -> Self {
        Self {
            sdk: build_sdk(),
            max_instructions,
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
        words.iter().all(|w| is_openvm_supported_rv32_word(*w) && RV32IMInstruction::from_word(*w).is_ok())
    }

    fn prepare_for_run(&mut self, rng_seed: u64) {
        // NOTE: `reset_for_new_run()` is intended for in-process fuzzing, but we keep it disabled
        // for now because OpenVM internals may depend on some global fuzzer_utils state across the
        // prove pipeline (preflight -> tracegen). Re-enable once validated.
        fuzzer_utils::set_seed(rng_seed);
        fuzzer_utils::set_trace_logging(true);
        fuzzer_utils::disable_assertions();
        fuzzer_utils::enable_json_capture();
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        let exe = build_exe(words)?;
        let mut app_prover = self
            .sdk
            .app_prover(exe)
            .map_err(|e| format!("app_prover failed: {e:?}"))?;
        let _proof = app_prover
            .prove(StdIn::default())
            .map_err(|e| format!("prove failed: {e:?}"))?;

        let state = app_prover
            .instance()
            .state()
            .as_ref()
            .ok_or_else(|| "no final state".to_string())?;
        let mut regs = [0u32; 32];
        for i in 0..32u32 {
            let bytes: [u8; 4] = unsafe { state.memory.read::<u8, 4>(RV32_REGISTER_AS, i * 4) };
            regs[i as usize] = u32::from_le_bytes(bytes);
        }
        Ok(regs)
    }

    fn collect_eval(&mut self) -> BackendEval {
        // TODO: The user is refactoring `crates/beak-core/src/trace/**`.
        // Once trace/bucket evaluation is stable again, populate:
        // - bucket_ids (preferred) or bucket_sig
        // - micro_ops_len/op_count/bucket_hit_count
        BackendEval::default()
    }
}

fn main() {
    let matches = Command::new("beak-fuzz")
        .about("Loop1: fuzz OpenVM prover vs oracle, bucket-guided.")
        .arg(
            Arg::new("seeds_jsonl")
                .long("seeds-jsonl")
                .default_value("storage/fuzzing_seeds/initial.jsonl")
                .help("Path to the initial seed JSONL (relative to workspace root unless absolute)."),
        )
        .arg(
            Arg::new("timeout_ms")
                .long("timeout-ms")
                .default_value("2000")
                .help("Best-effort per-seed wall-time timeout in milliseconds."),
        )
        .arg(
            Arg::new("initial_limit")
                .long("initial-limit")
                .default_value("0")
                .help("Limit number of initial seeds loaded (0 = no limit)."),
        )
        .arg(
            Arg::new("no_initial_eval")
                .long("no-initial-eval")
                .action(clap::ArgAction::SetTrue)
                .help("Skip the initial corpus evaluation pass (useful for smoke tests)."),
        )
        .arg(
            Arg::new("max_instructions")
                .long("max-instructions")
                .default_value("256")
                .help("Maximum number of RISC-V instruction words in a seed."),
        )
        .arg(
            Arg::new("iters")
                .long("iters")
                .default_value("100")
                .help("Number of fuzz iterations (in addition to initial corpus evaluation)."),
        )
        .get_matches();

    let root = workspace_root();
    let seeds_arg = matches.get_one::<String>("seeds_jsonl").unwrap().to_string();
    let seeds_path = resolve_path(&root, &seeds_arg);

    let timeout_ms: u64 = matches
        .get_one::<String>("timeout_ms")
        .unwrap()
        .parse()
        .expect("timeout-ms");
    let initial_limit: usize = matches
        .get_one::<String>("initial_limit")
        .unwrap()
        .parse()
        .expect("initial-limit");
    let no_initial_eval = matches.get_flag("no_initial_eval");
    let max_instructions: usize = matches
        .get_one::<String>("max_instructions")
        .unwrap()
        .parse()
        .expect("max-instructions");
    let iters: usize = matches
        .get_one::<String>("iters")
        .unwrap()
        .parse()
        .expect("iters");

    let cfg = Loop1Config {
        zkvm_tag: "openvm".to_string(),
        zkvm_commit: ZKVM_COMMIT.to_string(),
        rng_seed: DEFAULT_RNG_SEED,
        timeout_ms,
        seeds_jsonl: seeds_path,
        out_dir: root.join("storage/fuzzing_seeds"),
        output_prefix: None,
        initial_limit,
        no_initial_eval,
        max_instructions,
        iters,
        stack_size_bytes: 256 * 1024 * 1024,
    };

    let res = run_loop1_threaded(cfg, move || OpenVmBackend::new(max_instructions));
    match res {
        Ok(out) => {
            println!("Wrote corpus JSONL: {}", out.corpus_path.display());
            println!("Wrote bugs   JSONL: {}", out.bugs_path.display());
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

