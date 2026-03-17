use std::io::{BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::{Path, PathBuf};

use clap::{Arg, Command};
use serde_json::json;

use beak_core::fuzz::benchmark::{run_benchmark_threaded, BenchmarkConfig, DEFAULT_RNG_SEED};
use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel};

use beak_sp1_811a3f2c::backend::{run_backend_once, Sp1Backend, WorkerRequest, WorkerResponse};

const ZKVM_COMMIT: &str = "811a3f2c03914088c7c9e1774266934a3f9f5359";
const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";

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

fn collect_bin_words(matches: &clap::ArgMatches) -> Vec<u32> {
    let mut out = Vec::new();
    if let Some(values) = matches.get_many::<String>("bin") {
        for value in values {
            for token in value.split(|c: char| c.is_whitespace() || c == ',') {
                let t = token.trim();
                if !t.is_empty() {
                    out.push(parse_hex_word(t));
                }
            }
        }
    }
    out
}

fn write_inline_seed_jsonl(root: &Path, words: &[u32]) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dir = root.join("storage/fuzzing_seeds");
    std::fs::create_dir_all(&dir).expect("create storage/fuzzing_seeds");
    let path = dir.join(format!(".tmp-inline-sp1-811a3f2c-{ts}.jsonl"));
    let line = json!({
        "instructions": words,
        "metadata": {
            "source": "cli_bin",
            "label": "inline_bin",
        }
    })
    .to_string();
    std::fs::write(&path, format!("{line}\n")).expect("write inline seed jsonl");
    path
}

fn main() {
    let matches = Command::new("beak-fuzz")
        .about("Initial-corpus benchmark with semantic witness search (oracle vs SP1).")
        .arg(
            Arg::new("bin")
                .long("bin")
                .help("Hex encoded RISC-V instruction word(s). Can be repeated, or passed as a space/comma separated list.")
                .num_args(1..)
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("seeds_jsonl")
                .long("seeds-jsonl")
                .default_value("storage/fuzzing_seeds/initial.jsonl")
                .help(
                    "Path to the initial seed JSONL (relative to workspace root unless absolute).",
                ),
        )
        .arg(
            Arg::new("timeout_ms")
                .long("timeout-ms")
                .default_value("500")
                .help("Best-effort per-seed wall-time timeout in milliseconds."),
        )
        .arg(
            Arg::new("initial_limit")
                .long("initial-limit")
                .default_value("0")
                .help("Limit number of initial seeds loaded (0 = no limit)."),
        )
        .arg(
            Arg::new("max_instructions")
                .long("max-instructions")
                .default_value("256")
                .help("Maximum number of RISC-V instruction words in a seed."),
        )
        .arg(
            Arg::new("semantic_window_before")
                .long("semantic-window-before")
                .default_value("16")
                .help("Search this many witness steps before a matched semantic anchor."),
        )
        .arg(
            Arg::new("semantic_window_after")
                .long("semantic-window-after")
                .default_value("64")
                .help("Search this many witness steps after a matched semantic anchor."),
        )
        .arg(
            Arg::new("semantic_step_stride")
                .long("semantic-step-stride")
                .default_value("1")
                .help("Stride used when expanding semantic witness search windows."),
        )
        .arg(
            Arg::new("semantic_max_trials_per_bucket")
                .long("semantic-max-trials-per-bucket")
                .default_value("64")
                .help("Maximum injected replay attempts for each semantic bucket on a seed."),
        )
        .arg(
            Arg::new("oracle_precheck_max_steps")
                .long("oracle-precheck-max-steps")
                .default_value("0")
                .help("If > 0, run a cheap oracle step-bounded precheck and skip likely non-terminating seeds."),
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
                .default_value("0x1000")
                .help("Oracle code base address for split-code-data mode (u32, hex or decimal)."),
        )
        .arg(
            Arg::new("oracle_data_size_bytes")
                .long("oracle-data-size-bytes")
                .default_value("0")
                .help("Oracle zeroed data RAM bytes for split-code-data mode."),
        )
        .arg(
            Arg::new("worker_loop")
                .long("worker-loop")
                .hide(true)
                .action(clap::ArgAction::SetTrue)
                .help("Run persistent backend worker loop from stdin JSONL."),
        )
        .get_matches();

    if matches.get_flag("worker_loop") {
        run_worker_loop();
        return;
    }

    let root = workspace_root();
    let inline_words = collect_bin_words(&matches);
    let seeds_path = if inline_words.is_empty() {
        let seeds_arg = matches.get_one::<String>("seeds_jsonl").unwrap().to_string();
        resolve_path(&root, &seeds_arg)
    } else {
        write_inline_seed_jsonl(&root, &inline_words)
    };

    let timeout_ms: u64 =
        matches.get_one::<String>("timeout_ms").unwrap().parse().expect("timeout-ms");
    let requested_initial_limit: usize =
        matches.get_one::<String>("initial_limit").unwrap().parse().expect("initial-limit");
    let requested_max_instructions: usize =
        matches.get_one::<String>("max_instructions").unwrap().parse().expect("max-instructions");
    let precheck_oracle_max_steps: u32 = matches
        .get_one::<String>("oracle_precheck_max_steps")
        .unwrap()
        .parse()
        .expect("oracle-precheck-max-steps");
    let semantic_window_before: u64 = matches
        .get_one::<String>("semantic_window_before")
        .unwrap()
        .parse()
        .expect("semantic-window-before");
    let semantic_window_after: u64 = matches
        .get_one::<String>("semantic_window_after")
        .unwrap()
        .parse()
        .expect("semantic-window-after");
    let semantic_step_stride: u64 = matches
        .get_one::<String>("semantic_step_stride")
        .unwrap()
        .parse()
        .expect("semantic-step-stride");
    let semantic_max_trials_per_bucket: usize = matches
        .get_one::<String>("semantic_max_trials_per_bucket")
        .unwrap()
        .parse()
        .expect("semantic-max-trials-per-bucket");
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

    let initial_limit: usize = if inline_words.is_empty() {
        requested_initial_limit
    } else {
        1
    };
    let max_instructions: usize = if inline_words.is_empty() {
        requested_max_instructions
    } else {
        inline_words.len().max(1)
    };

    let cfg = BenchmarkConfig {
        zkvm_tag: "sp1".to_string(),
        zkvm_commit: ZKVM_COMMIT.to_string(),
        rng_seed: DEFAULT_RNG_SEED,
        timeout_ms,
        oracle: OracleConfig {
            memory_model: oracle_memory_model,
            code_base: oracle_code_base,
            data_size_bytes: oracle_data_size_bytes,
        },
        seeds_jsonl: seeds_path,
        out_dir: root.join("storage/fuzzing_seeds"),
        output_prefix: None,
        initial_limit,
        max_instructions,
        precheck_oracle_max_steps,
        semantic_search_enabled: true,
        semantic_window_before,
        semantic_window_after,
        semantic_step_stride,
        semantic_max_trials_per_bucket,
        stack_size_bytes: 256 * 1024 * 1024,
    };

    let res = run_benchmark_threaded(cfg, move || Sp1Backend::new(max_instructions, timeout_ms));
    match res {
        Ok(out) => {
            println!("Wrote corpus JSONL: {}", out.corpus_path.display());
            println!("Wrote bugs   JSONL: {}", out.bugs_path.display());
            if let Some(runs_path) = out.runs_path.as_ref() {
                println!("Wrote runs   JSONL: {}", runs_path.display());
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn run_worker_loop() {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    loop {
        let mut line = String::new();
        match input.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let req: WorkerRequest = match serde_json::from_str(trimmed) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("parse worker request failed: {e}");
                        continue;
                    }
                };
                let resp = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_backend_once(
                        req.request_id,
                        &req.words,
                        req.timeout_ms,
                        req.iteration,
                        req.inject_kind.as_deref(),
                        req.inject_step,
                    )
                })) {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => WorkerResponse {
                        request_id: req.request_id,
                        final_regs: None,
                        micro_op_count: 0,
                        bucket_hits: Vec::new(),
                        trace_signals: Vec::new(),
                        backend_error: Some(e),
                        observed_injection_sites: std::collections::BTreeMap::new(),
                        injection_applied: false,
                    },
                    Err(p) => WorkerResponse {
                        request_id: req.request_id,
                        final_regs: None,
                        micro_op_count: 0,
                        bucket_hits: Vec::new(),
                        trace_signals: Vec::new(),
                        backend_error: Some(format!(
                            "worker panic in run_backend_once: {}",
                            panic_payload_to_string(p.as_ref())
                        )),
                        observed_injection_sites: std::collections::BTreeMap::new(),
                        injection_applied: false,
                    },
                };
                let payload = match serde_json::to_vec(&resp) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("serialize worker response failed: {e}");
                        continue;
                    }
                };
                if out.write_all(WORKER_RESPONSE_PREFIX.as_bytes()).is_err() {
                    break;
                }
                if out.write_all(&payload).is_err() {
                    break;
                }
                if out.write_all(b"\n").is_err() {
                    break;
                }
                if out.flush().is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn panic_payload_to_string(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = p.downcast_ref::<String>() {
        return s.clone();
    }
    "non-string panic payload".to_string()
}
