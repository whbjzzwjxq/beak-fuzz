use clap::{Arg, Command};

use beak_core::fuzz::benchmark::{BenchmarkBackend, InjectionSchedule};
use beak_core::trace::sorted_signatures_from_hits;
use beak_jolt_5fb4b437::backend::{run_backend_once, JoltBackend};

fn main() {
    let matches = Command::new("beak-trace")
        .about("Run the latest-layout Jolt trace harness and optionally print semantic buckets.")
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
                .help("Print derived bucket hit signatures.")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("print_candidates")
                .long("print-candidates")
                .help("Print semantic injection candidates derived from bucket hits.")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("inject_kind")
                .long("inject-kind")
                .help("Explicit witness injection kind for smoke/integration checks.")
                .num_args(1),
        )
        .arg(
            Arg::new("inject_step")
                .long("inject-step")
                .default_value("0")
                .help("Injection step. Use 18446744073709551615 for wildcard/auto-site hooks."),
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
        .map(|s| parse_hex_word(s).unwrap_or_else(|| panic!("invalid hex: {s}")))
        .collect();
    let inject_kind = matches.get_one::<String>("inject_kind").map(|s| s.as_str());
    let inject_step: u64 =
        matches.get_one::<String>("inject_step").unwrap().parse().expect("inject-step");

    println!("=== Input: {} instruction word(s) ===", words.len());
    for (i, w) in words.iter().enumerate() {
        println!("  [{i}] 0x{w:08x}");
    }

    let backend_resp = match run_backend_once(&words, inject_kind, inject_step) {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("backend error: {e}");
            std::process::exit(1);
        }
    };

    println!("\n=== Jolt latest trace ===");
    println!("  micro_op_count = {}", backend_resp.micro_op_count);
    println!("  injection_applied = {}", backend_resp.injection_applied);
    if let Some(kind) = inject_kind {
        println!("  inject_kind = {kind}");
        println!("  inject_step = {inject_step}");
    }
    if let Some(err) = &backend_resp.backend_error {
        println!("  backend_error = {err}");
    }

    if matches.get_flag("print_buckets") {
        println!("\n=== Derived bucket hits ===");
        println!("  {} hit(s)", backend_resp.bucket_hits.len());
        for sig in sorted_signatures_from_hits(&backend_resp.bucket_hits) {
            println!("  {sig}");
        }
    }

    if matches.get_flag("print_candidates") {
        let backend = JoltBackend::new(words.len().max(1));
        let candidates = backend.semantic_injection_candidates(&backend_resp.bucket_hits);
        println!("\n=== Semantic injection candidates ===");
        println!("  {} candidate(s)", candidates.len());
        for candidate in candidates {
            println!(
                "  bucket={} class={} kind={} schedule={}",
                candidate.bucket_id,
                candidate.semantic_class,
                candidate.inject_kind,
                format_schedule(&candidate.schedule)
            );
        }
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

    if inject_kind.is_some() && !backend_resp.injection_applied {
        eprintln!("explicit injection did not fire");
        std::process::exit(2);
    }
}

fn parse_hex_word(value: &str) -> Option<u32> {
    let s = value.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(s, 16).ok()
}

fn format_schedule(schedule: &InjectionSchedule) -> String {
    match schedule {
        InjectionSchedule::Exact(step) => format!("Exact({step})"),
        InjectionSchedule::AroundAnchor(step) => format!("AroundAnchor({step})"),
        InjectionSchedule::Explicit(steps) => format!("Explicit({steps:?})"),
        InjectionSchedule::Sweep { start, end } => format!("Sweep({start}..={end})"),
    }
}
