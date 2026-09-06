use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, Command};
use serde_json::json;

use beak_core::fuzz::benchmark::{run_benchmark_threaded, BenchmarkConfig, DEFAULT_RNG_SEED};
use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel};

use beak_risc0_98387806::backend::Risc0Backend;
use beak_risc0_98387806::RISC0_ORACLE_CODE_BASE;

const ZKVM_COMMIT: &str = "98387806fe8348d87e32974468c6f35853356ad5";

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

fn parse_u8_arg(value: &str, name: &str) -> u8 {
    let parsed = parse_u32_arg(value, name);
    u8::try_from(parsed).unwrap_or_else(|_| panic!("invalid {name}: {value}"))
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

fn write_inline_seed_jsonl(
    root: &Path,
    words: &[u32],
    frontend: &str,
    v1compat_host_read_fill: u8,
) -> PathBuf {
    let ts_millis = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let dir = root.join("storage/fuzzing_seeds");
    std::fs::create_dir_all(&dir).expect("create storage/fuzzing_seeds");
    let path =
        dir.join(format!(".tmp-inline-risc0-98387806-{ts_millis}-pid{}.jsonl", std::process::id()));
    let mut metadata = serde_json::Map::new();
    metadata.insert("source".to_string(), json!("cli_bin"));
    metadata.insert(
        "label".to_string(),
        json!(if frontend == "v1compat" { "inline_v1compat_user" } else { "inline_bin" }),
    );
    metadata.insert("risc0_frontend".to_string(), json!(frontend));
    if frontend == "v1compat" {
        metadata.insert("host_read_contract".to_string(), json!("fill_requested_buffer_with_byte"));
        metadata.insert("host_read_fill_byte".to_string(), json!(v1compat_host_read_fill));
        metadata.insert("postcondition".to_string(), json!("read_user_regs_addr"));
    }
    let line = json!({
        "instructions": words,
        "metadata": metadata,
    })
    .to_string();
    std::fs::write(&path, format!("{line}\n")).expect("write inline seed jsonl");
    path
}

fn main() {
    let matches = Command::new("beak-fuzz")
        .about("Initial-corpus benchmark with semantic trace search (oracle vs RISC0).")
        .arg(
            Arg::new("bin")
                .long("bin")
                .help("Hex encoded RISC-V instruction word(s). Can be repeated, or passed as a space/comma separated list.")
                .num_args(1..)
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("risc0_frontend")
                .long("risc0-frontend")
                .help("RISC0 execution frontend: kernel or v1compat.")
                .default_value("kernel"),
        )
        .arg(
            Arg::new("v1compat_host_read_fill")
                .long("v1compat-host-read-fill")
                .help("Byte used by the v1compat frontend host_read implementation.")
                .default_value("0x12"),
        )
        .arg(
            Arg::new("seeds_jsonl")
                .long("seeds-jsonl")
                .default_value("storage/fuzzing_seeds/initial.jsonl"),
        )
        .arg(Arg::new("initial_limit").long("initial-limit").default_value("0"))
        .arg(
            Arg::new("mutation_iters")
                .long("mutation-iters")
                .alias("iters")
                .default_value("0"),
        )
        .arg(Arg::new("max_instructions").long("max-instructions").default_value("256"))
        .arg(
            Arg::new("long_tail_max_instructions")
                .long("long-tail-max-instructions")
                .default_value("0")
                .help("Absolute length ceiling for long-tail scheduling; 0 keeps the hard cap at max-instructions."),
        )
        .arg(Arg::new("semantic_window_before").long("semantic-window-before").default_value("8"))
        .arg(Arg::new("semantic_window_after").long("semantic-window-after").default_value("24"))
        .arg(Arg::new("semantic_step_stride").long("semantic-step-stride").default_value("1"))
        .arg(
            Arg::new("semantic_max_trials_per_bucket")
                .long("semantic-max-trials-per-bucket")
                .default_value("32"),
        )
        .arg(
            Arg::new("oracle_precheck_max_steps")
                .long("oracle-precheck-max-steps")
                .default_value("32"),
        )
        .arg(
            Arg::new("oracle_memory_model")
                .long("oracle-memory-model")
                .default_value("split-code-data"),
        )
        .arg(
            Arg::new("oracle_code_base")
                .long("oracle-code-base")
                .default_value("0x10004"),
        )
        .arg(
            Arg::new("oracle_data_size_bytes")
                .long("oracle-data-size-bytes")
                .default_value("0"),
        )
        .get_matches();

    let root = workspace_root();
    let frontend = matches.get_one::<String>("risc0_frontend").unwrap().as_str();
    if !matches!(frontend, "kernel" | "v1compat") {
        eprintln!("invalid --risc0-frontend: {frontend}; expected kernel or v1compat");
        std::process::exit(2);
    }
    let v1compat_mode = frontend == "v1compat";
    let v1compat_host_read_fill = parse_u8_arg(
        matches.get_one::<String>("v1compat_host_read_fill").unwrap(),
        "v1compat-host-read-fill",
    );
    let inline_words = collect_bin_words(&matches);
    let seeds_path = if inline_words.is_empty() {
        resolve_path(&root, matches.get_one::<String>("seeds_jsonl").unwrap())
    } else {
        write_inline_seed_jsonl(&root, &inline_words, frontend, v1compat_host_read_fill)
    };
    let requested_initial_limit: usize =
        matches.get_one::<String>("initial_limit").unwrap().parse().expect("initial-limit");
    let requested_mutation_iterations: usize =
        matches.get_one::<String>("mutation_iters").unwrap().parse().expect("mutation-iters");
    let requested_max_instructions: usize =
        matches.get_one::<String>("max_instructions").unwrap().parse().expect("max-instructions");
    let requested_long_tail_max: usize = matches
        .get_one::<String>("long_tail_max_instructions")
        .unwrap()
        .parse()
        .expect("long-tail-max-instructions");
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

    let initial_limit: usize = if inline_words.is_empty() { requested_initial_limit } else { 1 };
    let mutation_iterations: usize =
        if inline_words.is_empty() { requested_mutation_iterations } else { 0 };
    let max_instructions: usize = if inline_words.is_empty() {
        requested_max_instructions
    } else {
        inline_words.len().max(1)
    };
    let long_tail_max_instructions: usize = if inline_words.is_empty() {
        requested_long_tail_max
    } else {
        0
    };
    let backend_max_instructions = long_tail_max_instructions.max(max_instructions);

    let cfg = BenchmarkConfig {
        zkvm_tag: "risc0".to_string(),
        zkvm_commit: ZKVM_COMMIT.to_string(),
        rng_seed: DEFAULT_RNG_SEED,
        oracle: OracleConfig {
            memory_model: oracle_memory_model,
            code_base: oracle_code_base,
            data_size_bytes: oracle_data_size_bytes,
        },
        seeds_jsonl: seeds_path,
        out_dir: root.join("storage/fuzzing_seeds"),
        output_prefix: None,
        initial_limit,
        mutation_iterations,
        max_instructions,
        long_tail_max_instructions,
        precheck_oracle_max_steps,
        semantic_search_enabled: !v1compat_mode,
        semantic_window_before,
        semantic_window_after,
        semantic_step_stride,
        semantic_max_trials_per_bucket,
        stack_size_bytes: 256 * 1024 * 1024,
    };

    println!("oracle_code_base = 0x{RISC0_ORACLE_CODE_BASE:08x}");
    let res = run_benchmark_threaded(cfg, move || {
        if v1compat_mode {
            Risc0Backend::new_v1compat(backend_max_instructions, v1compat_host_read_fill)
        } else {
            Risc0Backend::new(backend_max_instructions)
        }
    });
    match res {
        Ok(out) => {
            println!("Wrote corpus JSONL: {}", out.corpus_path.display());
            println!("Wrote bugs JSONL: {}", out.bugs_path.display());
            if let Some(runs_path) = out.runs_path.as_ref() {
                println!("Wrote runs JSONL: {}", runs_path.display());
            }
        }
        Err(e) => {
            eprintln!("benchmark failed: {e}");
            std::process::exit(1);
        }
    }
}
