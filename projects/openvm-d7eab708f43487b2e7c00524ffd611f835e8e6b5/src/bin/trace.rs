use std::collections::HashMap;
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
use beak_core::trace::micro_ops::{
    ChipRow, ChipRowKind, CustomInteraction, GateValue, Interaction, InteractionBase,
    InteractionKind, InteractionMultiplicity, InteractionScope, InteractionType, MicroOp,
};

fn main() {
    let matches = Command::new("beak-trace")
        .about("Disassembles and traces RISC-V instruction words (hex).")
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
                .help("Parse captured <record> JSON into beak-core MicroOp and print them.")
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
    fuzzer_utils::set_trace_logging(true);
    fuzzer_utils::disable_assertions();
    fuzzer_utils::enable_json_capture();

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

    // --- 6. Parse captured records into beak-core MicroOps ---
    let micro_ops = micro_ops_from_json_logs(&json_logs);
    println!("\n=== MicroOps (beak-core) ===");
    println!("  micro_ops={}", micro_ops.len());
    if print_micro_ops {
        for (i, uop) in micro_ops.iter().enumerate() {
            print_micro_op_line(i, uop);
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

fn chip_kind_from_name(chip: &str) -> ChipRowKind {
    // Heuristics only; we can refine once we start consuming these in fuzz.
    if chip.contains("Program") {
        ChipRowKind::PROGRAM
    } else if chip.contains("Connector") {
        ChipRowKind::CONNECTOR
    } else if chip.contains("Memory") || chip.contains("Load") || chip.contains("Store") {
        ChipRowKind::MEMORY
    } else if chip.contains("Alu") || chip.contains("(ADD)") || chip.contains("(SUB)") || chip.contains("(MUL)") {
        ChipRowKind::ALU
    } else if chip.contains("Exec(") {
        ChipRowKind::CPU
    } else {
        ChipRowKind::CUSTOM
    }
}

fn parse_gate_map(v: &serde_json::Value) -> HashMap<String, GateValue> {
    let mut out = HashMap::new();
    let Some(obj) = v.as_object() else {
        return out;
    };
    for (k, vv) in obj {
        let n: Option<u64> = if let Some(b) = vv.as_bool() {
            Some(if b { 1 } else { 0 })
        } else {
            vv.as_u64()
        };
        if let Some(n) = n {
            out.insert(k.clone(), GateValue::from(n));
        }
    }
    out
}

fn parse_interaction_kind(s: Option<&str>) -> InteractionKind {
    match s.unwrap_or("") {
        "memory" => InteractionKind::MEMORY,
        "program" => InteractionKind::PROGRAM,
        "instruction" => InteractionKind::INSTRUCTION,
        "alu" => InteractionKind::ALU,
        "byte" => InteractionKind::BYTE,
        "range" => InteractionKind::RANGE,
        "field" => InteractionKind::FIELD,
        "syscall" => InteractionKind::SYSCALL,
        "global" => InteractionKind::GLOBAL,
        "poseidon2" => InteractionKind::POSEIDON2,
        "bitwise" => InteractionKind::BITWISE,
        "keccak" => InteractionKind::KECCAK,
        "sha256" => InteractionKind::SHA256,
        _ => InteractionKind::CUSTOM,
    }
}

fn parse_interaction_type(s: Option<&str>) -> Option<InteractionType> {
    match s? {
        "send" => Some(InteractionType::SEND),
        "recv" => Some(InteractionType::RECV),
        _ => None,
    }
}

fn parse_interaction_scope(s: Option<&str>) -> Option<InteractionScope> {
    match s? {
        "global" => Some(InteractionScope::GLOBAL),
        "local" => Some(InteractionScope::LOCAL),
        _ => None,
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    // Small deterministic hash for collapsing arbitrary JSON payloads into a few FieldElements.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn micro_ops_from_json_logs(json_logs: &[serde_json::Value]) -> Vec<MicroOp> {
    let mut out = Vec::new();

    for entry in json_logs {
        let tag = entry.get("tag").and_then(|v| v.as_str());
        if tag != Some("record") {
            continue;
        }
        let Some(payload) = entry.get("payload") else {
            continue;
        };
        if payload.get("context").and_then(|v| v.as_str()) != Some("micro_op") {
            continue;
        }
        let Some(micro_op_type) = payload.get("micro_op_type").and_then(|v| v.as_str()) else {
            continue;
        };

        match micro_op_type {
            "chip_row" => {
                let row_id = payload
                    .get("row_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let domain = payload
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let chip = payload
                    .get("chip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if row_id.is_empty() || domain.is_empty() || chip.is_empty() {
                    continue;
                }
                let gates = payload
                    .get("gates")
                    .map(parse_gate_map)
                    .unwrap_or_else(HashMap::new);
                let kind = chip_kind_from_name(&chip);
                out.push(MicroOp::ChipRow(ChipRow {
                    row_id,
                    domain,
                    chip,
                    kind,
                    gates,
                    event_id: None,
                }));
            }
            "interaction" => {
                let table_id = payload
                    .get("table_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let io = parse_interaction_type(payload.get("io").and_then(|v| v.as_str()));
                if table_id.is_empty() || io.is_none() {
                    continue;
                }

                let mut base = InteractionBase::default();
                base.table_id = table_id;
                base.io = io.unwrap();
                base.scope = parse_interaction_scope(payload.get("scope").and_then(|v| v.as_str()));
                base.anchor_row_id = payload
                    .get("anchor_row_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                base.event_id = payload
                    .get("event_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                base.kind = parse_interaction_kind(payload.get("kind").and_then(|v| v.as_str()));

                if let Some(mult) = payload.get("multiplicity").and_then(|v| v.as_object()) {
                    let value = mult
                        .get("value")
                        .and_then(|v| v.as_u64())
                        .map(|n| GateValue::from(n));
                    let ref_ = mult
                        .get("ref")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    base.multiplicity = Some(InteractionMultiplicity { value, ref_ });
                }

                let payload_json = payload
                    .get("payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let h = fnv1a64(payload_json.to_string().as_bytes());
                let ci = CustomInteraction {
                    base,
                    a0: GateValue::from(h),
                    a1: GateValue::from(0u64),
                    a2: GateValue::from(0u64),
                    a3: GateValue::from(0u64),
                };
                out.push(MicroOp::Interaction(Interaction::Custom(ci)));
            }
            _ => {}
        }
    }

    out
}

fn print_micro_op_line(idx: usize, uop: &MicroOp) {
    match uop {
        MicroOp::ChipRow(r) => {
            let is_real = r
                .gates
                .get("is_real")
                .map(|v| format!("{v:?}"))
                .unwrap_or_else(|| "n/a".to_string());
            println!(
                "  [{idx}] chip_row kind={:?} domain={} chip={} row_id={} gates.is_real={}",
                r.kind, r.domain, r.chip, r.row_id, is_real
            );
        }
        MicroOp::Interaction(i) => {
            let base = i.base();
            let anchor = base.anchor_row_id.as_deref().unwrap_or("-");
            println!(
                "  [{idx}] interaction kind={:?} table_id={} io={:?} scope={:?} anchor_row_id={}",
                base.kind, base.table_id, base.io, base.scope, anchor
            );
        }
    }
}

