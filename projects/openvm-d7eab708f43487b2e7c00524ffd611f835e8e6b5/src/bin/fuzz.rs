use std::path::{Path, PathBuf};

use clap::{Arg, Command};

use beak_core::fuzz::loop1::{run_loop1_threaded, Loop1Config, DEFAULT_RNG_SEED};

use beak_openvm_d7eab708::backend::OpenVmBackend;

const ZKVM_COMMIT: &str = "d7eab708f43487b2e7c00524ffd611f835e8e6b5";

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

fn main() {
    let matches = Command::new("beak-fuzz")
        .about("Loop1: in-process mutational fuzzing (oracle vs OpenVM) with bucket-guided feedback.")
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
                .default_value("2000")
                .help("Best-effort per-seed wall-time timeout in milliseconds."),
        )
        .arg(
            Arg::new("initial_limit")
                .long("initial-limit")
                .default_value("0")
                .help("Limit number of initial seeds loaded (0 = no limit)."),
        )
        .arg(
            Arg::new("no_initial_eval")
                .long("no-initial-eval")
                .action(clap::ArgAction::SetTrue)
                .help("Skip the initial corpus evaluation pass (useful for smoke tests)."),
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
        .get_matches();

    let root = workspace_root();
    let seeds_arg = matches.get_one::<String>("seeds_jsonl").unwrap().to_string();
    let seeds_path = resolve_path(&root, &seeds_arg);

    let timeout_ms: u64 =
        matches.get_one::<String>("timeout_ms").unwrap().parse().expect("timeout-ms");
    let initial_limit: usize =
        matches.get_one::<String>("initial_limit").unwrap().parse().expect("initial-limit");
    let no_initial_eval = matches.get_flag("no_initial_eval");
    let max_instructions: usize =
        matches.get_one::<String>("max_instructions").unwrap().parse().expect("max-instructions");
    let iters: usize = matches.get_one::<String>("iters").unwrap().parse().expect("iters");

    let cfg = Loop1Config {
        zkvm_tag: "openvm".to_string(),
        zkvm_commit: ZKVM_COMMIT.to_string(),
        rng_seed: DEFAULT_RNG_SEED,
        timeout_ms,
        seeds_jsonl: seeds_path,
        out_dir: root.join("storage/fuzzing_seeds"),
        output_prefix: None,
        initial_limit,
        no_initial_eval,
        max_instructions,
        iters,
        stack_size_bytes: 256 * 1024 * 1024,
    };

    let res = run_loop1_threaded(cfg, move || OpenVmBackend::new(max_instructions));
    match res {
        Ok(out) => {
            println!("Wrote corpus JSONL: {}", out.corpus_path.display());
            println!("Wrote bugs   JSONL: {}", out.bugs_path.display());
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
