use std::sync::Arc;

use clap::{Arg, Command};

use openvm_instructions::LocalOpcode;
use openvm_instructions::{
    exe::VmExe, instruction::Instruction, program::Program, riscv::RV32_REGISTER_AS, SystemOpcode,
};
use openvm_rv32im_transpiler::{Rv32ITranspilerExtension, Rv32MTranspilerExtension};
use openvm_sdk::{config::AppConfig, prover::verify_app_proof, Sdk, StdIn, F};
use openvm_transpiler::transpiler::Transpiler;

use beak_core::rv32im::oracle::RISCVOracle;
use serde_json::Value;

fn main() {
    let matches = Command::new("beak-trace")
        .about("Run oracle vs OpenVM and optionally print captured trace JSON logs.")
        .arg(
            Arg::new("bin")
                .long("bin")
                .help("Hex encoded RISC-V instruction word. Can be specified multiple times, or pass a space/comma separated list.")
                .num_args(1..)
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("print_micro_ops")
                .long("print-micro-ops")
                .help("Print captured JSON trace records (raw).")
                .action(clap::ArgAction::SetTrue),
        )
        .after_help(
            "Example:\n  beak-trace --bin 12345017 --bin 00000533\n  beak-trace --bin \"12345017 00000533\"",
        )
        .get_matches();

    let mut input_words = Vec::new();

    if let Some(values) = matches.get_many::<String>("bin") {
        for value in values {
            // Split by spaces and commas, accept both delimiters
            for token in value.split(|c: char| c.is_whitespace() || c == ',') {
                let s = token.trim();
                if !s.is_empty() {
                    input_words.push(s.to_owned());
                }
            }
        }
    }

    if input_words.is_empty() {
        eprintln!("Error: No instruction words given.");
        eprintln!("Usage: beak-trace --bin <hex1> [--bin <hex2> ...]");
        eprintln!("Or:    beak-trace --bin \"<hex1> <hex2> ...\"");
        std::process::exit(1);
    }

    let args = input_words;
    let print_micro_ops = matches.get_flag("print_micro_ops");

    let words: Vec<u32> = args
        .iter()
        .map(|s| u32::from_str_radix(s, 16).unwrap_or_else(|_| panic!("invalid hex: {s}")))
        .collect();

    println!("=== Input: {} instruction word(s) ===", words.len());
    for (i, w) in words.iter().enumerate() {
        println!("  [{i}] 0x{w:08x}");
    }

    // Run on a large stack thread (zkVM can be stack-intensive).
    let result = std::thread::Builder::new()
        .name("trace-main".into())
        .stack_size(256 * 1024 * 1024)
        .spawn(move || run_trace(&words, print_micro_ops))
        .expect("spawn thread")
        .join()
        .expect("thread panicked");

    if !result {
        std::process::exit(1);
    }
}

fn run_trace(words: &[u32], print_micro_ops: bool) -> bool {
    // --- 1. Oracle ---
    println!("\n=== Oracle (rrs-lib) ===");
    let oracle_regs = RISCVOracle::execute(words);
    for i in 0..32 {
        if oracle_regs[i] != 0 {
            println!("  x{i} = 0x{:08x}", oracle_regs[i]);
        }
    }

    // --- 2. Transpile ---
    println!("\n=== Transpile ===");
    let transpiler = Transpiler::<F>::default()
        .with_extension(Rv32ITranspilerExtension)
        .with_extension(Rv32MTranspilerExtension);

    let transpiled = transpiler.transpile(words).expect("transpile failed");

    let mut instructions: Vec<Instruction<F>> = Vec::new();
    for (i, opt) in transpiled.into_iter().enumerate() {
        match opt {
            Some(inst) => instructions.push(inst),
            None => eprintln!("  WARNING: word [{i}] 0x{:08x} not transpiled", words[i]),
        }
    }
    instructions.push(Instruction::from_usize(
        SystemOpcode::TERMINATE.global_opcode(),
        [0, 0, 0],
    ));
    println!("  {} OpenVM instructions (incl. TERMINATE)", instructions.len());

    let program = Program::from_instructions(&instructions);
    let exe = Arc::new(VmExe::new(program));

    // --- 3. SDK setup ---
    println!("\n=== OpenVM SDK ===");
    let mut app_config = AppConfig::riscv32();
    app_config.app_vm_config.system.config =
        app_config.app_vm_config.system.config.with_max_segment_len(256).with_continuations();

    let sdk = Sdk::new(app_config).expect("sdk init");
    let app_vk = sdk.app_pk().get_app_vk();

    // --- 4. Prove ---
    println!("\n=== Prove ===");
    let mut app_prover = sdk.app_prover(exe).expect("app prover");
    let proof = app_prover.prove(StdIn::default()).expect("prove");
    println!("  Proof generated.");

    // --- 5. Verify ---
    println!("\n=== Verify ===");
    let _verified = verify_app_proof(&app_vk, &proof).expect("verify");
    println!("  Proof verified.");

    let json_logs = fuzzer_utils::take_json_logs();
    println!("\n=== Captured JSON logs ===");
    println!("  {} entr(y/ies)", json_logs.len());

    // --- 6. Print captured JSON records (raw) ---
    //
    // Note: `beak-trace` prints raw JSON records captured from the instrumented OpenVM snapshot.
    // Typed parsing lives in the backend project (e.g. `OpenVMTrace::from_logs`).
    if print_micro_ops {
        for (i, v) in json_logs.iter().enumerate() {
            print_json_log_line(i, v);
        }
    }

    // --- 6. Read zkVM registers ---
    println!("\n=== OpenVM registers ===");
    let state = app_prover.instance().state().as_ref().expect("no final state");
    let mut openvm_regs = [0u32; 32];
    for i in 0..32u32 {
        let bytes: [u8; 4] = unsafe { state.memory.read::<u8, 4>(RV32_REGISTER_AS, i * 4) };
        openvm_regs[i as usize] = u32::from_le_bytes(bytes);
    }
    for i in 0..32 {
        if openvm_regs[i] != 0 {
            println!("  x{i} = 0x{:08x}", openvm_regs[i]);
        }
    }

    // --- 7. Compare ---
    println!("\n=== Comparison ===");
    let mut mismatch = false;
    for i in 0..32 {
        if oracle_regs[i] != openvm_regs[i] {
            println!(
                "  MISMATCH x{i}: oracle=0x{:08x}  openvm=0x{:08x}",
                oracle_regs[i], openvm_regs[i]
            );
            mismatch = true;
        }
    }
    if mismatch {
        println!("\n*** SOUNDNESS BUG DETECTED ***");
    } else {
        println!("  All 32 registers match.");
    }

    !mismatch
}

fn print_json_log_line(idx: usize, v: &Value) {
    println!("  [{idx}] {v}");
}

