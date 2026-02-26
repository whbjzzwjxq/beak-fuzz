use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libafl::inputs::BytesInput;
use serde_json::json;

use crate::fuzz::jsonl::{BugRecord, CorpusRecord, JsonlWriter};
use crate::fuzz::loop1::{Loop1Config, Loop1Outputs, LoopBackend};
use crate::fuzz::seed::FuzzingSeed;
use crate::rv32im::instruction::RV32IMInstruction;
use crate::rv32im::oracle::RISCVOracle;
use crate::trace::{sorted_signatures_from_hits, BucketHit};

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD_RED: &str = "\x1b[1;31m";
const ANSI_BOLD_YELLOW: &str = "\x1b[1;33m";
const ANSI_BOLD_GREEN: &str = "\x1b[1;32m";

#[derive(Debug, Clone, Default)]
struct DirectRunStats {
    bucket_hits_sig: String,
    micro_op_count: usize,
    bucket_hits: Vec<BucketHit>,
    mismatch_regs: Vec<(u32, u32, u32)>,
    backend_error: Option<String>,
    oracle_error: Option<String>,
    timed_out: bool,
}

fn ansi_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM")
            .map(|term| term != "dumb")
            .unwrap_or(true)
}

fn colorize(text: &str, code: &str) -> String {
    if ansi_enabled() {
        format!("{code}{text}{ANSI_RESET}")
    } else {
        text.to_string()
    }
}

fn now_ts_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn decode_words_from_input(input: &BytesInput, max_instructions: usize) -> Vec<u32> {
    let bytes: &[u8] = input.as_ref();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= bytes.len() && out.len() < max_instructions {
        let w = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        out.push(w);
        i += 4;
    }
    out
}

fn encode_words(words: &[u32]) -> BytesInput {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for &w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    BytesInput::new(bytes)
}

fn load_initial_seeds(
    path: &Path,
    max_instructions: usize,
    is_usable: &dyn Fn(&[u32]) -> bool,
) -> Vec<(BytesInput, serde_json::Value)> {
    let f = File::open(path).expect("open initial seeds");
    let r = BufReader::new(f);
    let mut out = Vec::new();
    for line in r.lines().flatten() {
        let s = line.trim();
        if s.is_empty() {
            continue;
        }
        let seed: FuzzingSeed = serde_json::from_str(s).expect("parse seed jsonl");
        let mut words = seed.instructions;
        words.truncate(max_instructions);
        if !is_usable(&words) {
            continue;
        }
        if words.iter().any(|w| RV32IMInstruction::from_word(*w).is_err()) {
            continue;
        }
        out.push((encode_words(&words), serde_json::Value::Object(seed.metadata)));
    }
    out
}

fn mismatch_regs(oracle: &[u32; 32], prover: &[u32; 32]) -> Vec<(u32, u32, u32)> {
    let mut out = Vec::new();
    for i in 0..32u32 {
        let a = oracle[i as usize];
        let b = prover[i as usize];
        if a != b {
            out.push((i, a, b));
        }
    }
    out
}

fn panic_payload_to_string(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        return format!("panic: {s}");
    }
    if let Some(s) = p.downcast_ref::<String>() {
        return format!("panic: {s}");
    }
    "panic: non-string payload".to_string()
}

fn catch_unwind_nonfatal<T, F>(f: F) -> std::thread::Result<T>
where
    F: FnOnce() -> T + std::panic::UnwindSafe,
{
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_panic_info| {}));
    let res = std::panic::catch_unwind(f);
    std::panic::set_hook(prev_hook);
    res
}

fn canonical_bucket_sig(sigs: &[String]) -> String {
    let mut seen = HashSet::<&str>::new();
    let mut out: Vec<&str> = Vec::new();
    for sig in sigs {
        let t = sig.trim();
        if t.is_empty() {
            continue;
        }
        if seen.insert(t) {
            out.push(t);
        }
    }
    out.join(";")
}

fn run_single_eval<B: LoopBackend>(cfg: &Loop1Config, backend: &mut B, words: &[u32]) -> DirectRunStats {
    let start = Instant::now();
    backend.prepare_for_run(cfg.rng_seed);

    let oracle_regs =
        catch_unwind_nonfatal(std::panic::AssertUnwindSafe(|| RISCVOracle::execute_with_config(words, cfg.oracle)));
    let panic_oracle_error = match oracle_regs.as_ref() {
        Err(p) => Some(panic_payload_to_string(p.as_ref())),
        _ => None,
    };

    let backend_regs = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        backend.prove_and_read_final_regs(words)
    }));
    let panic_backend_error = match backend_regs.as_ref() {
        Err(p) => Some(panic_payload_to_string(p.as_ref())),
        _ => None,
    };
    let final_regs = match backend_regs {
        Ok(Ok(r)) => Some(r),
        Ok(Err(_)) => None,
        Err(_) => None,
    };
    let mismatches = match (oracle_regs.as_ref(), final_regs.as_ref()) {
        (Ok(oracle), Some(regs)) => mismatch_regs(oracle, regs),
        _ => Vec::new(),
    };

    let eval = backend.collect_eval();
    let backend_error = eval.backend_error.clone().or(panic_backend_error);
    let oracle_error = panic_oracle_error.map(|e| format!("oracle {e}"));
    let bucket_sigs = sorted_signatures_from_hits(&eval.bucket_hits);
    let sig = canonical_bucket_sig(&bucket_sigs);
    let backend_timed_out = backend_error
        .as_deref()
        .map(|e| e.contains("timed out"))
        .unwrap_or(false);
    let timed_out = start.elapsed() > Duration::from_millis(cfg.timeout_ms) || backend_timed_out;

    DirectRunStats {
        bucket_hits_sig: sig,
        micro_op_count: eval.micro_op_count,
        bucket_hits: eval.bucket_hits,
        mismatch_regs: mismatches,
        backend_error,
        oracle_error,
        timed_out,
    }
}

pub fn run_direct_bucket_mutate_threaded<B, F>(
    cfg: Loop1Config,
    build_backend: F,
) -> Result<Loop1Outputs, String>
where
    B: LoopBackend,
    F: FnOnce() -> B + Send + 'static,
{
    let stack = cfg.stack_size_bytes.max(16 * 1024 * 1024);
    let handle = std::thread::Builder::new()
        .name("beak-loop2-direct".into())
        .stack_size(stack)
        .spawn(move || {
            let backend = build_backend();
            run_direct_bucket_mutate(cfg, backend)
        })
        .map_err(|e| format!("spawn direct loop thread failed: {e}"))?;
    handle
        .join()
        .map_err(|_| "direct loop thread panicked".to_string())?
}

pub fn run_direct_bucket_mutate<B: LoopBackend>(
    cfg: Loop1Config,
    mut backend: B,
) -> Result<Loop1Outputs, String> {
    std::fs::create_dir_all(&cfg.out_dir)
        .map_err(|e| format!("create out_dir {} failed: {e}", cfg.out_dir.display()))?;

    let base_prefix = cfg.output_prefix.clone().unwrap_or_else(|| {
        format!(
            "loop2-direct-{}-{}-seed{}-{}",
            cfg.zkvm_tag,
            &cfg.zkvm_commit[..cfg.zkvm_commit.len().min(8)],
            cfg.rng_seed,
            now_ts_secs()
        )
    });
    let prefix = format!("{base_prefix}-iter{}", cfg.iters);
    let corpus_path = cfg.out_dir.join(format!("{prefix}-corpus.jsonl"));
    let bugs_path = cfg.out_dir.join(format!("{prefix}-bugs.jsonl"));
    let corpus_writer = JsonlWriter::open_append(&corpus_path)?;
    let bug_writer = JsonlWriter::open_append(&bugs_path)?;

    let seeds = load_initial_seeds(&cfg.seeds_jsonl, cfg.max_instructions, &|words| {
        backend.is_usable_seed(words)
    });
    if seeds.is_empty() {
        return Err(format!(
            "No usable initial seeds loaded from {}",
            cfg.seeds_jsonl.display()
        ));
    }

    let mut bug_count = 0usize;
    let take_n = if cfg.initial_limit == 0 {
        seeds.len()
    } else {
        cfg.initial_limit.min(seeds.len())
    };
    for (seed_idx, (input, seed_meta)) in seeds.into_iter().take(take_n).enumerate() {
        let words = decode_words_from_input(&input, cfg.max_instructions);
        if words.is_empty() || !backend.is_usable_seed(&words) {
            continue;
        }

        let baseline_probe = run_single_eval(&cfg, &mut backend, &words);
        let has_direct_injection_target = baseline_probe
            .bucket_hits
            .iter()
            .any(|h| backend.bucket_has_direct_injection(&h.bucket_id));
        let mut phases = vec![("baseline", false, baseline_probe)];
        if has_direct_injection_target {
            phases.push(("injected", true, run_single_eval(&cfg, &mut backend, &words)));
        }
        for (phase_name, is_injected_phase, stats) in phases {
            let mismatch = !stats.mismatch_regs.is_empty();
            let mut metadata = match seed_meta.clone() {
                serde_json::Value::Object(m) => m,
                _ => serde_json::Map::new(),
            };
            metadata.insert("mode".to_string(), json!("loop2_direct"));
            metadata.insert("phase".to_string(), json!(phase_name));
            metadata.insert("seed_index".to_string(), json!(seed_idx));
            metadata.insert("injected_phase".to_string(), json!(is_injected_phase));
            metadata.insert(
                "has_direct_injection_target".to_string(),
                json!(has_direct_injection_target),
            );

            let corpus = CorpusRecord {
                zkvm_commit: cfg.zkvm_commit.clone(),
                rng_seed: cfg.rng_seed,
                timeout_ms: cfg.timeout_ms,
                timed_out: stats.timed_out,
                mismatch,
                bucket_hits_sig: stats.bucket_hits_sig.clone(),
                instructions: words.clone(),
                metadata: serde_json::Value::Object(metadata.clone()),
            };
            corpus_writer.append_json_line(&corpus)?;

            let underconstrained_candidate = is_injected_phase
                && has_direct_injection_target
                && stats.backend_error.is_none()
                && stats.oracle_error.is_none();
            if mismatch
                || stats.backend_error.is_some()
                || stats.oracle_error.is_some()
                || underconstrained_candidate
            {
                let kind = if stats.backend_error.is_some() || stats.oracle_error.is_some() {
                    "exception"
                } else if mismatch {
                    "mismatch"
                } else {
                    "underconstrained_candidate"
                };
                metadata.insert("kind".to_string(), json!(kind));
                metadata.insert(
                    "underconstrained_candidate".to_string(),
                    json!(underconstrained_candidate),
                );
                let bug = BugRecord {
                    zkvm_commit: cfg.zkvm_commit.clone(),
                    rng_seed: cfg.rng_seed,
                    timeout_ms: cfg.timeout_ms,
                    timed_out: stats.timed_out,
                    bucket_hits_sig: stats.bucket_hits_sig.clone(),
                    micro_op_count: stats.micro_op_count,
                    backend_error: stats.backend_error.clone(),
                    oracle_error: stats.oracle_error.clone(),
                    bucket_hits: stats.bucket_hits.clone(),
                    mismatch_regs: stats.mismatch_regs.clone(),
                    instructions: words.clone(),
                    metadata: serde_json::Value::Object(metadata),
                };
                bug_writer.append_json_line(&bug)?;
                bug_count += 1;
                let marker = if kind == "underconstrained_candidate" {
                    colorize("[LOOP2][UNDERCONSTRAINED]", ANSI_BOLD_YELLOW)
                } else {
                    colorize("[LOOP2][BUG]", ANSI_BOLD_RED)
                };
                eprintln!(
                    "{marker} kind={kind} phase={phase_name} seed_idx={seed_idx} mismatches={} sig={}",
                    stats.mismatch_regs.len(),
                    stats.bucket_hits_sig
                );
            }
        }
    }

    corpus_writer.flush()?;
    bug_writer.flush()?;
    let summary = if bug_count > 0 {
        colorize(&format!("[LOOP2][DONE] bug_records={bug_count}"), ANSI_BOLD_RED)
    } else {
        colorize("[LOOP2][DONE] bug_records=0", ANSI_BOLD_GREEN)
    };
    eprintln!("{summary}");

    Ok(Loop1Outputs {
        corpus_path,
        bugs_path,
    })
}
