use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use beak_core::fuzz::benchmark::{run_benchmark_threaded, BenchmarkConfig, DEFAULT_RNG_SEED};
use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel};
use beak_sp1_3561f006::backend::Sp1Backend;
use clap::{Arg, Command};
use serde_json::json;

const ZKVM_COMMIT: &str = "3561f0065dfe7d9f85144dd54bc5e9b10e5f7df1";
const UINT256_DIV_CARRIER_NOP: u32 = 0x0000_0013;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn resolve_path(root: &Path, arg: &str) -> PathBuf {
    let path = PathBuf::from(arg);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
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

fn write_uint256_seed_jsonl(root: &Path, dividend: u64, divisor: u64) -> PathBuf {
    let ts_millis = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let dir = root.join("storage/fuzzing_seeds");
    std::fs::create_dir_all(&dir).expect("create storage/fuzzing_seeds");
    let path = dir
        .join(format!(".tmp-sp1-3561f006-uint256-div-{ts_millis}-pid{}.jsonl", std::process::id()));
    let line = json!({
        "instructions": [UINT256_DIV_CARRIER_NOP],
        "metadata": {
            "source": "manual/sp1-3561f006-uint256-div",
            "label": "sp1_uint256_div_precompile",
            "semantic_entrypoint": "sp1.uint256_div",
            "dividend_u64": dividend,
            "divisor_u64": divisor.max(1),
        }
    })
    .to_string();
    std::fs::write(&path, format!("{line}\n")).expect("write uint256 seed jsonl");
    path
}

fn main() {
    let matches = Command::new("beak-fuzz")
        .about("SP1-356 uint256-div benchmark with semantic witness search.")
        .arg(Arg::new("dividend").long("dividend").default_value("7"))
        .arg(Arg::new("divisor").long("divisor").default_value("3"))
        .arg(
            Arg::new("seeds_jsonl")
                .long("seeds-jsonl")
                .help("Optional carrier seed JSONL. Defaults to a generated uint256-div seed."),
        )
        .arg(
            Arg::new("out_dir")
                .long("out-dir")
                .default_value("storage/fuzzing_seeds")
                .help("Output directory for benchmark corpus/bugs/runs JSONL."),
        )
        .arg(Arg::new("output_prefix").long("output-prefix"))
        .arg(Arg::new("initial_limit").long("initial-limit").default_value("1"))
        .arg(Arg::new("mutation_iters").long("mutation-iters").alias("iters").default_value("0"))
        .arg(Arg::new("max_instructions").long("max-instructions").default_value("1"))
        .arg(Arg::new("semantic_window_before").long("semantic-window-before").default_value("0"))
        .arg(Arg::new("semantic_window_after").long("semantic-window-after").default_value("0"))
        .arg(Arg::new("semantic_step_stride").long("semantic-step-stride").default_value("1"))
        .arg(
            Arg::new("semantic_max_trials_per_bucket")
                .long("semantic-max-trials-per-bucket")
                .default_value("1"),
        )
        .arg(
            Arg::new("oracle_precheck_max_steps")
                .long("oracle-precheck-max-steps")
                .default_value("0"),
        )
        .arg(
            Arg::new("oracle_memory_model")
                .long("oracle-memory-model")
                .default_value("split-code-data"),
        )
        .arg(Arg::new("oracle_code_base").long("oracle-code-base").default_value("0x1000"))
        .arg(Arg::new("oracle_data_size_bytes").long("oracle-data-size-bytes").default_value("0"))
        .get_matches();

    let root = workspace_root();
    let dividend: u64 = matches.get_one::<String>("dividend").unwrap().parse().expect("dividend");
    let divisor: u64 =
        matches.get_one::<String>("divisor").unwrap().parse::<u64>().expect("divisor").max(1);
    let seeds_path = matches
        .get_one::<String>("seeds_jsonl")
        .map(|path| resolve_path(&root, path))
        .unwrap_or_else(|| write_uint256_seed_jsonl(&root, dividend, divisor));
    let out_dir = resolve_path(&root, matches.get_one::<String>("out_dir").unwrap());
    let output_prefix = matches.get_one::<String>("output_prefix").cloned();
    let initial_limit: usize =
        matches.get_one::<String>("initial_limit").unwrap().parse().expect("initial-limit");
    let mutation_iterations: usize =
        matches.get_one::<String>("mutation_iters").unwrap().parse().expect("mutation-iters");
    let max_instructions: usize =
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
    let oracle_memory_model =
        OracleMemoryModel::parse(matches.get_one::<String>("oracle_memory_model").unwrap())
            .expect("oracle-memory-model");
    let oracle_code_base =
        parse_u32_arg(matches.get_one::<String>("oracle_code_base").unwrap(), "oracle-code-base");
    let oracle_data_size_bytes = parse_u32_arg(
        matches.get_one::<String>("oracle_data_size_bytes").unwrap(),
        "oracle-data-size-bytes",
    );

    let cfg = BenchmarkConfig {
        zkvm_tag: "sp1".to_string(),
        zkvm_commit: ZKVM_COMMIT.to_string(),
        rng_seed: DEFAULT_RNG_SEED,
        oracle: OracleConfig {
            memory_model: oracle_memory_model,
            code_base: oracle_code_base,
            data_size_bytes: oracle_data_size_bytes,
        },
        seeds_jsonl: seeds_path,
        out_dir,
        output_prefix,
        initial_limit,
        mutation_iterations,
        max_instructions,
        precheck_oracle_max_steps,
        semantic_search_enabled: true,
        semantic_window_before,
        semantic_window_after,
        semantic_step_stride,
        semantic_max_trials_per_bucket,
        stack_size_bytes: 256 * 1024 * 1024,
    };

    let res = run_benchmark_threaded(cfg, move || {
        Sp1Backend::new_uint256_div(max_instructions, dividend, divisor)
    });
    match res {
        Ok(out) => {
            println!("Wrote corpus JSONL: {}", out.corpus_path.display());
            println!("Wrote bugs   JSONL: {}", out.bugs_path.display());
            if let Some(runs_path) = out.runs_path.as_ref() {
                println!("Wrote runs   JSONL: {}", runs_path.display());
            }
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}
