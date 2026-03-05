use std::io::{BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::{Path, PathBuf};

use clap::{Arg, Command};
use serde_json::json;

use beak_core::fuzz::loop1::{run_loop1_threaded, Loop1Config, DEFAULT_RNG_SEED};
use beak_core::fuzz::loop2::run_direct_bucket_mutate_threaded;
use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel};

use beak_pico_45e74ccd::backend::{run_backend_once, PicoBackend, WorkerRequest, WorkerResponse};

const ZKVM_COMMIT: &str = "45e74ccd62758c6d67239913956e749adaba261c";
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
    let path = dir.join(format!(".tmp-inline-pico-45e74ccd-{ts}.jsonl"));
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
        .about("Loop1: in-process mutational fuzzing (oracle vs Pico) with bucket-guided feedback.")
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
            Arg::new("iters")
                .long("iters")
                .default_value("100")
                .help("Number of fuzz iterations (in addition to initial corpus evaluation)."),
        )
        .arg(
            Arg::new("bucket_direct_mutate")
                .long("bucket-direct-mutate")
                .action(clap::ArgAction::SetTrue)
                .help("Direct mode: hit bucket then immediately rerun same seed with witness injection (no random fuzz loop)."),
        )
        .arg(
            Arg::new("chain_direct_injection")
                .long("chain-direct-injection")
                .action(clap::ArgAction::SetTrue)
                .help("Enable loop2 chained direct-injection replay from loop1 baseline hits."),
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
    let requested_iters: usize = matches.get_one::<String>("iters").unwrap().parse().expect("iters");
    let bucket_direct_mutate = matches.get_flag("bucket_direct_mutate");
    let chain_direct_injection = matches.get_flag("chain_direct_injection");
    let precheck_oracle_max_steps: u32 = matches
        .get_one::<String>("oracle_precheck_max_steps")
        .unwrap()
        .parse()
        .expect("oracle-precheck-max-steps");
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
    let iters: usize = if bucket_direct_mutate { 1 } else { requested_iters };

    let cfg = Loop1Config {
        zkvm_tag: "pico".to_string(),
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
        iters,
        chain_direct_injection: !bucket_direct_mutate && chain_direct_injection,
        precheck_oracle_max_steps,
        stack_size_bytes: 256 * 1024 * 1024,
    };

    let res = if bucket_direct_mutate {
        run_direct_bucket_mutate_threaded(cfg, move || PicoBackend::new(max_instructions, timeout_ms))
    } else {
        run_loop1_threaded(cfg, move || PicoBackend::new(max_instructions, timeout_ms))
    };
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
                        backend_error: Some(e),
                    },
                    Err(p) => WorkerResponse {
                        request_id: req.request_id,
                        final_regs: None,
                        micro_op_count: 0,
                        bucket_hits: Vec::new(),
                        backend_error: Some(format!(
                            "worker panic in run_backend_once: {}",
                            panic_payload_to_string(p.as_ref())
                        )),
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
