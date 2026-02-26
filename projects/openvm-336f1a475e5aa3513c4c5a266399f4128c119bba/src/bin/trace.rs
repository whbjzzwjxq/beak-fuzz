use clap::{Arg, Command};

use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel, RISCVOracle};
use beak_core::trace::sorted_signatures_from_hits;
use beak_openvm_336f1a47::backend::run_backend_once;

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
                .help("Reserved for compatibility (raw micro-op logs are not exposed by run_backend_once).")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("print_buckets")
                .long("print-buckets")
                .help("Parse captured logs and print derived bucket hits (signatures).")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("oracle_memory_model")
                .long("oracle-memory-model")
                .default_value("shared-code-data")
                .help("Oracle memory model: shared-code-data | split-code-data."),
        )
        .arg(
            Arg::new("oracle_code_base")
                .long("oracle-code-base")
                .default_value("0x0")
                .help("Oracle code base address for split-code-data mode (u32, hex or decimal)."),
        )
        .arg(
            Arg::new("oracle_data_size_bytes")
                .long("oracle-data-size-bytes")
                .default_value("65536")
                .help("Oracle zeroed data RAM bytes for split-code-data mode."),
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
    let print_buckets = matches.get_flag("print_buckets");
    let oracle_memory_model = OracleMemoryModel::parse(
        matches.get_one::<String>("oracle_memory_model").unwrap(),
    )
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
        .spawn(move || run_trace(&words, print_micro_ops, print_buckets, oracle_cfg))
        .expect("spawn thread")
        .join()
        .expect("thread panicked");

    if !result {
        std::process::exit(1);
    }
}

fn run_trace(words: &[u32], print_micro_ops: bool, print_buckets: bool, oracle_cfg: OracleConfig) -> bool {
    // --- 1. Oracle ---
    println!("\n=== Oracle (rrs-lib) ===");
    let oracle_regs = RISCVOracle::execute_with_config(words, oracle_cfg);
    for i in 0..32 {
        if oracle_regs[i] != 0 {
            println!("  x{i} = 0x{:08x}", oracle_regs[i]);
        }
    }

    // --- 2. Backend (same single-run implementation used by fuzz worker path) ---
    println!("\n=== OpenVM backend (run_backend_once) ===");
    let backend_resp = match run_backend_once(1, words, 0, None, 0) {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("  backend error: {e}");
            return false;
        }
    };
    println!("  micro_op_count = {}", backend_resp.micro_op_count);

    if let Some(err) = &backend_resp.backend_error {
        println!("  backend_error = {err}");
    }

    if print_micro_ops {
        println!("  NOTE: raw micro-op JSON logs are not returned by run_backend_once.");
    }

    if print_buckets {
        println!("\n=== Derived bucket hits ===");
        println!("  {} hit(s)", backend_resp.bucket_hits.len());
        for sig in sorted_signatures_from_hits(&backend_resp.bucket_hits) {
            println!("  {sig}");
        }
    }

    // --- 3. Read backend final registers ---
    println!("\n=== OpenVM registers ===");
    let Some(openvm_regs) = backend_resp.final_regs else {
        println!("  no final_regs returned.");
        return false;
    };
    for i in 0..32 {
        if openvm_regs[i] != 0 {
            println!("  x{i} = 0x{:08x}", openvm_regs[i]);
        }
    }

    // --- 4. Compare ---
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

    !mismatch && backend_resp.backend_error.is_none()
}

fn parse_u32_arg(value: &str, name: &str) -> u32 {
    let s = value.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("invalid {name}: {value}"))
    } else {
        s.parse::<u32>().unwrap_or_else(|_| panic!("invalid {name}: {value}"))
    }
}
