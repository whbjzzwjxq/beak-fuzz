use clap::{Arg, Command};

use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel, RISCVOracle};
use beak_jolt_d67f5a2a::backend::run_backend_once;
use beak_jolt_d67f5a2a::JOLT_ORACLE_CODE_BASE;

fn main() {
    let matches = Command::new("beak-trace")
        .about("Run oracle vs Jolt d67 RV64/Dory backend for an inline RISC-V word seed.")
        .arg(
            Arg::new("bin")
                .long("bin")
                .help("Hex encoded RISC-V instruction word. Can be specified multiple times, or pass a space/comma separated list.")
                .num_args(1..)
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("oracle_memory_model")
                .long("oracle-memory-model")
                .default_value("split-code-data")
                .help("Oracle memory model: shared-code-data | split-code-data."),
        )
        .arg(
            Arg::new("oracle_code_base")
                .long("oracle-code-base")
                .default_value("0x80000000")
                .help("Oracle code base address for split-code-data mode (u32, hex or decimal)."),
        )
        .arg(
            Arg::new("oracle_data_size_bytes")
                .long("oracle-data-size-bytes")
                .default_value("0")
                .help("Oracle zeroed data RAM bytes for split-code-data mode."),
        )
        .after_help("Example:\n  beak-trace --bin 00700593")
        .get_matches();

    let mut input_words = Vec::new();
    if let Some(values) = matches.get_many::<String>("bin") {
        for value in values {
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
        std::process::exit(1);
    }

    let oracle_memory_model =
        OracleMemoryModel::parse(matches.get_one::<String>("oracle_memory_model").unwrap())
            .expect("oracle-memory-model");
    let oracle_code_base =
        parse_u32_arg(matches.get_one::<String>("oracle_code_base").unwrap(), "oracle-code-base");
    let oracle_data_size_bytes = parse_u32_arg(
        matches.get_one::<String>("oracle_data_size_bytes").unwrap(),
        "oracle-data-size-bytes",
    );
    let oracle_cfg = OracleConfig {
        memory_model: oracle_memory_model,
        code_base: oracle_code_base,
        data_size_bytes: oracle_data_size_bytes,
    };

    let words: Vec<u32> = input_words.iter().map(|s| parse_hex_word(s)).collect();
    println!("=== Input: {} instruction word(s) ===", words.len());
    for (i, w) in words.iter().enumerate() {
        println!("  [{i}] 0x{w:08x}");
    }
    println!("\n=== Oracle (rrs-lib) ===");
    println!("  oracle_code_base = 0x{JOLT_ORACLE_CODE_BASE:08x}");
    let oracle_regs = RISCVOracle::execute_with_config(&words, oracle_cfg);
    for i in 0..32 {
        if oracle_regs[i] != 0 {
            println!("  x{i} = 0x{:08x}", oracle_regs[i]);
        }
    }

    println!("\n=== Jolt d67 RV64/Dory backend ===");
    let backend_resp = match run_backend_once(&words) {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("  backend error: {e}");
            std::process::exit(1);
        }
    };
    println!("  micro_op_count = {}", backend_resp.micro_op_count);
    println!("  injection_applied = {}", backend_resp.injection_applied);
    if let Some(err) = &backend_resp.backend_error {
        println!("  backend_error = {err}");
    }
    for hit in &backend_resp.bucket_hits {
        println!("  bucket_hit = {}", serde_json::to_string(hit).expect("serialize bucket hit"));
    }
    if let Some(receipt) = &backend_resp.executed_exception_receipt {
        println!(
            "  executed_exception_receipt = {}",
            serde_json::to_string(receipt).expect("serialize executed exception receipt")
        );
    }

    println!("\n=== Jolt registers ===");
    let Some(jolt_regs) = backend_resp.final_regs else {
        println!("  no final_regs returned.");
        std::process::exit(1);
    };
    for i in 0..32 {
        if jolt_regs[i] != 0 {
            println!("  x{i} = 0x{:08x}", jolt_regs[i]);
        }
    }

    println!("\n=== Comparison ===");
    let mut mismatch = false;
    for i in 0..32 {
        if oracle_regs[i] != jolt_regs[i] {
            println!(
                "  MISMATCH x{i}: oracle=0x{:08x}  jolt=0x{:08x}",
                oracle_regs[i], jolt_regs[i]
            );
            mismatch = true;
        }
    }
    if mismatch {
        println!("\n*** SOUNDNESS BUG DETECTED ***");
        std::process::exit(1);
    } else {
        println!("  All 32 registers match.");
    }
}

fn parse_u32_arg(value: &str, name: &str) -> u32 {
    let s = value.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("invalid {name}: {value}"))
    } else {
        s.parse::<u32>().unwrap_or_else(|_| panic!("invalid {name}: {value}"))
    }
}

fn parse_hex_word(value: &str) -> u32 {
    let s = value.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(s, 16).unwrap_or_else(|_| panic!("invalid hex word: {value}"))
}
