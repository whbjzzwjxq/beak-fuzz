use clap::{Arg, Command};

use beak_core::trace::{Trace, sorted_signatures_from_hits, sorted_signatures_from_signals};
use beak_risc0_c0db0713::RISC0_ORACLE_CODE_BASE;
use beak_risc0_c0db0713::backend::run_backend_once;
use beak_risc0_c0db0713::trace::Risc0Trace;

fn main() {
    let matches = Command::new("beak-trace")
        .about("Run RISC0 backend and print derived semantic hits.")
        .arg(
            Arg::new("bin")
                .long("bin")
                .help("Hex encoded RISC-V instruction word. Can be specified multiple times, or pass a space/comma separated list.")
                .num_args(1..)
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("print_buckets")
                .long("print-buckets")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("inject_kind")
                .long("inject-kind")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("inject_step")
                .long("inject-step")
                .default_value("0")
                .required(false),
        )
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

    let words: Vec<u32> = input_words
        .iter()
        .map(|s| u32::from_str_radix(s, 16).unwrap_or_else(|_| panic!("invalid hex: {s}")))
        .collect();

    let trace = Risc0Trace::from_words(&words).expect("build risc0 trace from input words");
    let inject_kind = matches.get_one::<String>("inject_kind").map(|s| s.as_str());
    let inject_step: u64 = matches
        .get_one::<String>("inject_step")
        .unwrap()
        .parse()
        .expect("inject-step");
    let resp = run_backend_once(&words, inject_kind, inject_step);

    println!("=== Input: {} instruction word(s) ===", words.len());
    println!("oracle_code_base = 0x{RISC0_ORACLE_CODE_BASE:08x}");
    for (idx, word) in words.iter().enumerate() {
        println!("  [{idx}] 0x{word:08x}");
    }

    println!("\n=== Derived Semantic Hits ===");
    for sig in sorted_signatures_from_hits(trace.bucket_hits()) {
        println!("  {sig}");
    }

    println!("\n=== Trace Signals ===");
    for sig in sorted_signatures_from_signals(trace.trace_signals()) {
        println!("  {sig}");
    }

    println!("\n=== Backend ===");
    match resp {
        Ok(resp) => {
            println!("  micro_op_count = {}", resp.micro_op_count);
            println!("  injection_applied = {}", resp.injection_applied);
            if let Some(kind) = inject_kind {
                println!("  inject_kind = {kind}");
                println!("  inject_step = {inject_step}");
            }
            if let Some(err) = &resp.backend_error {
                println!("  backend_error = {err}");
            }
            if matches.get_flag("print_buckets") {
                for hit in &resp.bucket_hits {
                    println!("  {} {}", hit.bucket_id, serde_json::to_string(&hit.details).unwrap());
                }
            }
        }
        Err(err) => {
            println!("  micro_op_count = {}", trace.instruction_count());
            println!("  injection_applied = false");
            if let Some(kind) = inject_kind {
                println!("  inject_kind = {kind}");
                println!("  inject_step = {inject_step}");
            }
            println!("  backend_error = {err}");
        }
    }
}
