use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, Command};
use serde_json::json;

use beak_core::fuzz::benchmark::{run_benchmark_threaded, BenchmarkConfig, DEFAULT_RNG_SEED};
use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel};

use beak_sp1_7f643da1::backend::{run_backend_once, Sp1Backend, WorkerRequest, WorkerResponse};

const ZKVM_COMMIT: &str = "7f643da16813af4c0fbaad4837cd7409386cf38c";
const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";
const SP1_WRITE_SYSCALL: i32 = 2;
const ECALL_WORD: u32 = 0x0000_0073;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OrdinaryWriteEcallState {
    fd: u32,
    write_ptr: u32,
    write_len: u32,
}

const ORDINARY_WRITE_ECALL_STATES: [OrdinaryWriteEcallState; 3] = [
    OrdinaryWriteEcallState { fd: 3, write_ptr: 0x100, write_len: 1 },
    OrdinaryWriteEcallState { fd: 4, write_ptr: 0x140, write_len: 2 },
    OrdinaryWriteEcallState { fd: 1, write_ptr: 0x180, write_len: 4 },
];

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
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let dir = root.join("storage/fuzzing_seeds");
    std::fs::create_dir_all(&dir).expect("create storage/fuzzing_seeds");
    let path = dir.join(format!(".tmp-inline-sp1-7f643da1-{ts}.jsonl"));
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

fn encode_addi(rd: u32, imm: i32) -> u32 {
    (((imm as u32) & 0x0fff) << 20) | (rd << 7) | 0x13
}

fn ordinary_write_ecall_carrier(state: OrdinaryWriteEcallState) -> Vec<u32> {
    vec![
        encode_addi(5, SP1_WRITE_SYSCALL),
        encode_addi(10, state.fd as i32),
        encode_addi(11, state.write_ptr as i32),
        encode_addi(12, state.write_len as i32),
        ECALL_WORD,
    ]
}

fn ordinary_write_ecall_carrier_lines() -> Vec<String> {
    ORDINARY_WRITE_ECALL_STATES
        .into_iter()
        .enumerate()
        .map(|(lane_idx, state)| {
            json!({
                "instructions": ordinary_write_ecall_carrier(state),
                "metadata": {
                    "source": "generated_initial_corpus",
                    "generator": "sp1_nonzero_write_ecall_family_v2",
                    "carrier_family": "ecall",
                    "syscall_family": "write",
                    "lane_idx": lane_idx,
                    "ecall_register_state": {
                        "x5": SP1_WRITE_SYSCALL,
                        "x10": state.fd,
                        "x11": state.write_ptr,
                        "x12": state.write_len,
                    },
                    "write_range_start": state.write_ptr,
                    "write_range_end_exclusive": state.write_ptr + state.write_len,
                }
            })
            .to_string()
        })
        .collect()
}

fn ordinary_write_ecall_augmented_contents(original_contents: &str) -> (String, usize) {
    let carrier_lines = ordinary_write_ecall_carrier_lines();
    let mut contents = carrier_lines.join("\n");
    contents.push('\n');
    if !original_contents.is_empty() {
        contents.push_str(original_contents);
        if !original_contents.ends_with('\n') {
            contents.push('\n');
        }
    }
    (contents, carrier_lines.len())
}

fn write_ordinary_write_ecall_seed_jsonl(root: &Path, original: &Path) -> (PathBuf, usize) {
    let original_contents = std::fs::read_to_string(original)
        .unwrap_or_else(|err| panic!("read ordinary seeds JSONL {}: {err}", original.display()));
    let (contents, carrier_count) = ordinary_write_ecall_augmented_contents(&original_contents);
    let ts_millis = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let dir = root.join("storage/fuzzing_seeds");
    std::fs::create_dir_all(&dir).expect("create storage/fuzzing_seeds");
    let path = dir.join(format!(
        ".tmp-sp1-write-ecall-corpus-{ts_millis}-pid{}.jsonl",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("write ordinary SP1 ECALL carrier JSONL");
    (path, carrier_count)
}

fn effective_initial_limit(requested: usize, carrier_count: usize, inline: bool) -> usize {
    if inline {
        1
    } else if requested == 0 {
        0
    } else {
        requested.saturating_add(carrier_count)
    }
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
            Arg::new("initial_limit")
                .long("initial-limit")
                .default_value("0")
                .help("Limit number of initial seeds loaded (0 = no limit)."),
        )
        .arg(
            Arg::new("mutation_iters")
                .long("mutation-iters")
                .alias("iters")
                .default_value("0")
                .help("Number of feedback-guided mutation iterations after initial corpus evaluation."),
        )
        .arg(
            Arg::new("max_instructions")
                .long("max-instructions")
                .default_value("256")
                .help("Maximum number of RISC-V instruction words in a seed."),
        )
        .arg(
            Arg::new("long_tail_max_instructions")
                .long("long-tail-max-instructions")
                .default_value("0")
                .help("Absolute length ceiling for long-tail scheduling; 0 keeps the hard cap at max-instructions."),
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
                .default_value("32")
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
                .default_value("0x100000")
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
    let (seeds_path, ordinary_write_ecall_carrier_count) = if inline_words.is_empty() {
        let seeds_arg = matches.get_one::<String>("seeds_jsonl").unwrap().to_string();
        write_ordinary_write_ecall_seed_jsonl(&root, &resolve_path(&root, &seeds_arg))
    } else {
        (write_inline_seed_jsonl(&root, &inline_words), 0)
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

    let initial_limit = effective_initial_limit(
        requested_initial_limit,
        ordinary_write_ecall_carrier_count,
        !inline_words.is_empty(),
    );
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
        zkvm_tag: "sp1".to_string(),
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
        semantic_search_enabled: true,
        semantic_window_before,
        semantic_window_after,
        semantic_step_stride,
        semantic_max_trials_per_bucket,
        stack_size_bytes: 256 * 1024 * 1024,
    };

    println!("ordinary_write_ecall_carriers = {ordinary_write_ecall_carrier_count}");
    let res = run_benchmark_threaded(cfg, move || Sp1Backend::new(backend_max_instructions));
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
                        semantic_mutation_receipt: None,
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
                        semantic_mutation_receipt: None,
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

#[cfg(test)]
mod ordinary_carrier_tests {
    use std::collections::BTreeSet;

    use super::{
        effective_initial_limit, encode_addi, ordinary_write_ecall_augmented_contents,
        ordinary_write_ecall_carrier_lines, ECALL_WORD, ORDINARY_WRITE_ECALL_STATES,
        SP1_WRITE_SYSCALL,
    };

    fn executed_ecall_state(words: &[u32]) -> [u32; 4] {
        let mut registers = [0u32; 32];
        for &word in words {
            if word == ECALL_WORD {
                return [registers[5], registers[10], registers[11], registers[12]];
            }
            assert_eq!(word & 0x7f, 0x13, "carrier setup must be ADDI");
            assert_eq!((word >> 12) & 0x7, 0, "carrier setup must be ADDI");
            let rd = ((word >> 7) & 0x1f) as usize;
            let rs1 = ((word >> 15) & 0x1f) as usize;
            let raw_imm = (word >> 20) & 0x0fff;
            let imm = ((raw_imm << 20) as i32 >> 20) as u32;
            if rd != 0 {
                registers[rd] = registers[rs1].wrapping_add(imm);
            }
        }
        panic!("carrier has no executed ECALL")
    }

    #[test]
    fn ordinary_write_ecall_generator_is_byte_and_state_distinct_from_history() {
        let historical = vec![
            0x0020_0293,
            0x0010_0513,
            0x0000_0593,
            0x0000_0613,
            ECALL_WORD,
        ];
        let historical_state = executed_ecall_state(&historical);
        let lines = ordinary_write_ecall_carrier_lines();
        assert_eq!(lines.len(), ORDINARY_WRITE_ECALL_STATES.len());
        let mut observed_bytes = BTreeSet::new();
        let mut observed_states = BTreeSet::new();

        for line in lines {
            let row: serde_json::Value = serde_json::from_str(&line).unwrap();
            let words = row["instructions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|word| word.as_u64().unwrap() as u32)
                .collect::<Vec<_>>();
            let state = executed_ecall_state(&words);

            assert_eq!(words.len(), 5);
            assert_eq!(words.last(), Some(&ECALL_WORD));
            assert!(words[..words.len() - 1].contains(&encode_addi(5, SP1_WRITE_SYSCALL)));
            assert_ne!(words, historical);
            assert_ne!(state, historical_state, "historical zero-length ECALL state was rebuilt");
            assert_eq!(state[0], SP1_WRITE_SYSCALL as u32);
            assert_ne!(state[2], 0, "write pointer must be nonzero");
            assert_ne!(state[3], 0, "write length must be nonzero");
            assert!(state[2].checked_add(state[3]).is_some(), "write range must not wrap");
            assert_eq!(row["metadata"]["ecall_register_state"]["x5"], state[0]);
            assert_eq!(row["metadata"]["ecall_register_state"]["x10"], state[1]);
            assert_eq!(row["metadata"]["ecall_register_state"]["x11"], state[2]);
            assert_eq!(row["metadata"]["ecall_register_state"]["x12"], state[3]);
            assert_eq!(row["metadata"]["source"], "generated_initial_corpus");
            assert_eq!(row["metadata"]["generator"], "sp1_nonzero_write_ecall_family_v2");
            assert!(row["metadata"].get("case_id").is_none());
            observed_bytes.insert(words);
            observed_states.insert(state);
        }

        assert_eq!(observed_bytes.len(), ORDINARY_WRITE_ECALL_STATES.len());
        assert_eq!(observed_states.len(), ORDINARY_WRITE_ECALL_STATES.len());
    }

    #[test]
    fn ordinary_write_ecall_family_is_prepended_and_admitted_by_a_bounded_limit() {
        let original = r#"{"instructions":[19],"metadata":{"source":"ordinary"}}"#;
        let (contents, carrier_count) = ordinary_write_ecall_augmented_contents(original);
        let lines = contents.lines().collect::<Vec<_>>();

        assert_eq!(carrier_count, ORDINARY_WRITE_ECALL_STATES.len());
        assert_eq!(lines.len(), carrier_count + 1);
        assert_eq!(lines.last(), Some(&original));
        assert!(lines[..carrier_count]
            .iter()
            .all(|line| line.contains("sp1_nonzero_write_ecall_family_v2")));
        assert_eq!(effective_initial_limit(0, carrier_count, false), 0);
        assert_eq!(effective_initial_limit(1, carrier_count, false), 4);
        assert_eq!(effective_initial_limit(1, carrier_count, true), 1);
    }
}
