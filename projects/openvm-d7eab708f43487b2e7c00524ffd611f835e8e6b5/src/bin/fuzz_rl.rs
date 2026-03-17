use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use clap::{Arg, Command};

use beak_core::fuzz::loop1::{run_loop1_threaded, Loop1Config};
use beak_core::fuzz::policy::PolicyType;
use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel};

use beak_openvm_d7eab708::backend::{
    run_backend_once, OpenVmBackend, WorkerRequest, WorkerResponse,
};

const ZKVM_COMMIT: &str = "d7eab708f43487b2e7c00524ffd611f835e8e6b5";
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

fn main() {
    let matches = Command::new("beak-fuzz-rl")
        .about("RL-driven fuzzing loop (oracle vs OpenVM).")
        .arg(
            Arg::new("policy")
                .long("policy")
                .default_value("bandit")
                .help("Policy type: random, bandit, linucb, rl (external PPO agent)."),
        )
        .arg(
            Arg::new("iters")
                .long("iters")
                .default_value("1000")
                .help("Number of fuzzing iterations."),
        )
        .arg(
            Arg::new("metrics_interval")
                .long("metrics-interval")
                .default_value("10")
                .help("Emit metrics every N iterations (0 = disabled)."),
        )
        .arg(
            Arg::new("rl_socket_path")
                .long("rl-socket-path")
                .default_value("/tmp/beak-rl.sock")
                .help("Unix socket path for external RL policy server."),
        )
        .arg(
            Arg::new("rl_timeout_ms")
                .long("rl-timeout-ms")
                .default_value("200")
                .help("Timeout in ms for external RL policy requests."),
        )
        .arg(
            Arg::new("seeds_jsonl")
                .long("seeds-jsonl")
                .default_value("storage/fuzzing_seeds/initial.jsonl")
                .help("Path to the initial seed JSONL."),
        )
        .arg(
            Arg::new("timeout_ms")
                .long("timeout-ms")
                .default_value("500")
                .help("Per-seed wall-time timeout in ms."),
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
            Arg::new("oracle_precheck_max_steps")
                .long("oracle-precheck-max-steps")
                .default_value("0")
                .help("If > 0, skip likely non-terminating seeds."),
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
                .default_value("0x0")
                .help("Oracle code base address."),
        )
        .arg(
            Arg::new("oracle_data_size_bytes")
                .long("oracle-data-size-bytes")
                .default_value("65536")
                .help("Oracle zeroed data RAM bytes."),
        )
        .arg(
            Arg::new("chain_direct_injection")
                .long("chain-direct-injection")
                .action(clap::ArgAction::SetTrue)
                .help("Enable direct injection chaining."),
        )
        .arg(
            Arg::new("rng_seed")
                .long("rng-seed")
                .default_value("2026")
                .help("RNG seed for reproducibility."),
        )
        .arg(
            Arg::new("output_prefix")
                .long("output-prefix")
                .help("Custom prefix for output files."),
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

    let policy_type: PolicyType = matches
        .get_one::<String>("policy")
        .unwrap()
        .parse()
        .expect("invalid --policy value");

    let iters: usize = matches.get_one::<String>("iters").unwrap().parse().expect("--iters");
    let metrics_interval: usize = matches
        .get_one::<String>("metrics_interval")
        .unwrap()
        .parse()
        .expect("--metrics-interval");
    let rl_socket_path = matches.get_one::<String>("rl_socket_path").unwrap().clone();
    let rl_timeout_ms: u64 = matches
        .get_one::<String>("rl_timeout_ms")
        .unwrap()
        .parse()
        .expect("--rl-timeout-ms");
    let timeout_ms: u64 = matches.get_one::<String>("timeout_ms").unwrap().parse().expect("--timeout-ms");
    let initial_limit: usize = matches
        .get_one::<String>("initial_limit")
        .unwrap()
        .parse()
        .expect("--initial-limit");
    let max_instructions: usize = matches
        .get_one::<String>("max_instructions")
        .unwrap()
        .parse()
        .expect("--max-instructions");
    let precheck: u32 = matches
        .get_one::<String>("oracle_precheck_max_steps")
        .unwrap()
        .parse()
        .expect("--oracle-precheck-max-steps");
    let oracle_memory_model =
        OracleMemoryModel::parse(matches.get_one::<String>("oracle_memory_model").unwrap())
            .expect("--oracle-memory-model");
    let oracle_code_base =
        parse_u32_arg(matches.get_one::<String>("oracle_code_base").unwrap(), "oracle-code-base");
    let oracle_data_size_bytes = parse_u32_arg(
        matches.get_one::<String>("oracle_data_size_bytes").unwrap(),
        "oracle-data-size-bytes",
    );
    let rng_seed: u64 = matches.get_one::<String>("rng_seed").unwrap().parse().expect("--rng-seed");
    let chain_direct_injection = matches.get_flag("chain_direct_injection");
    let output_prefix = matches.get_one::<String>("output_prefix").cloned();

    let seeds_path = resolve_path(
        &root,
        matches.get_one::<String>("seeds_jsonl").unwrap(),
    );

    let rl_socket = if policy_type == PolicyType::External {
        Some(PathBuf::from(&rl_socket_path))
    } else {
        None
    };

    let cfg = Loop1Config {
        zkvm_tag: "openvm".to_string(),
        zkvm_commit: ZKVM_COMMIT.to_string(),
        rng_seed,
        timeout_ms,
        oracle: OracleConfig {
            memory_model: oracle_memory_model,
            code_base: oracle_code_base,
            data_size_bytes: oracle_data_size_bytes,
        },
        seeds_jsonl: seeds_path,
        out_dir: root.join("storage/fuzzing_seeds"),
        output_prefix,
        initial_limit,
        max_instructions,
        iters,
        chain_direct_injection,
        precheck_oracle_max_steps: precheck,
        stack_size_bytes: 256 * 1024 * 1024,
        policy_type,
        rl_socket_path: rl_socket,
        rl_fallback_timeout_ms: rl_timeout_ms,
        metrics_interval,
    };

    println!("[beak-fuzz-rl] backend=openvm policy={policy_type} iters={iters} metrics_interval={metrics_interval}");

    let res = run_loop1_threaded(cfg, move || OpenVmBackend::new(max_instructions, timeout_ms));
    match res {
        Ok(out) => {
            println!("Wrote corpus  JSONL: {}", out.corpus_path.display());
            println!("Wrote bugs    JSONL: {}", out.bugs_path.display());
            if let Some(runs_path) = out.runs_path.as_ref() {
                println!("Wrote runs    JSONL: {}", runs_path.display());
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
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
                    run_backend_once(req.request_id, &req.words, req.iteration)
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
