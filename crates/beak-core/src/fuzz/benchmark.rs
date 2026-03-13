use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libafl::inputs::BytesInput;
use serde_json::json;

use crate::fuzz::jsonl::{BugRecord, CorpusRecord, JsonlWriter, RunRecord};
use crate::fuzz::seed::FuzzingSeed;
use crate::rv32im::instruction::RV32IMInstruction;
use crate::rv32im::oracle::{OracleConfig, RISCVOracle};
use crate::trace::{sorted_signatures_from_hits, BucketHit};

pub use crate::fuzz::loop1::{BackendEval, DEFAULT_RNG_SEED};

#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub zkvm_tag: String,
    pub zkvm_commit: String,
    pub rng_seed: u64,
    pub timeout_ms: u64,
    pub oracle: OracleConfig,

    pub seeds_jsonl: PathBuf,
    pub out_dir: PathBuf,
    pub output_prefix: Option<String>,

    pub initial_limit: usize,
    pub max_instructions: usize,
    pub precheck_oracle_max_steps: u32,
    pub semantic_search_enabled: bool,
    pub semantic_window_before: u64,
    pub semantic_window_after: u64,
    pub semantic_step_stride: u64,
    pub semantic_max_trials_per_bucket: usize,
    pub stack_size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct BenchmarkOutputs {
    pub corpus_path: PathBuf,
    pub bugs_path: PathBuf,
    pub runs_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum InjectionSchedule {
    Exact(u64),
    AroundAnchor(u64),
    Explicit(Vec<u64>),
    Sweep { start: u64, end: u64 },
}

#[derive(Debug, Clone)]
pub struct SemanticInjectionCandidate {
    pub bucket_id: String,
    pub semantic_class: String,
    pub inject_kind: String,
    pub schedule: InjectionSchedule,
}

pub trait BenchmarkBackend {
    fn is_usable_seed(&self, _words: &[u32]) -> bool {
        true
    }

    fn prepare_for_run(&mut self, _rng_seed: u64) {}

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String>;

    fn collect_eval(&mut self) -> BackendEval;

    fn clear_semantic_injection(&mut self) {}

    fn arm_semantic_injection(&mut self, _kind: &str, _step: u64) -> Result<(), String> {
        Ok(())
    }

    fn semantic_injection_candidates(&self, _hits: &[BucketHit]) -> Vec<SemanticInjectionCandidate> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Default)]
struct EvalStats {
    bucket_hits_sig: String,
    bucket_hits_detail_sig: String,
    micro_op_count: usize,
    bucket_hits: Vec<BucketHit>,
    mismatch_regs: Vec<(u32, u32, u32)>,
    backend_error: Option<String>,
    oracle_error: Option<String>,
    timed_out: bool,
    phase: String,
    semantic_class: Option<String>,
    inject_kind: Option<String>,
    inject_step: Option<u64>,
    trigger_bucket_id: Option<String>,
    baseline_bucket_hits_sig: Option<String>,
    underconstrained_candidate: bool,
    semantic_injection_applied: bool,
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

fn canonical_bucket_detail_sig(hits: &[BucketHit]) -> String {
    let mut out: Vec<String> = hits
        .iter()
        .map(|hit| {
            let details = canonical_json_value(&serde_json::json!(hit.details));
            format!("{}|{}", hit.bucket_id, details)
        })
        .collect();
    out.sort();
    out.join(";")
}

fn canonical_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()),
        serde_json::Value::Array(items) => {
            let mut out = String::from("[");
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json_value(item));
            }
            out.push(']');
            out
        }
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&str, &serde_json::Value)> =
                map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = String::from("{");
            for (idx, (key, value)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string()));
                out.push(':');
                out.push_str(&canonical_json_value(value));
            }
            out.push('}');
            out
        }
    }
}

fn eval_once<B: BenchmarkBackend>(
    cfg: &BenchmarkConfig,
    timeout: Duration,
    backend: &mut B,
    words: &[u32],
) -> EvalStats {
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
    let detail_sig = canonical_bucket_detail_sig(&eval.bucket_hits);
    let backend_timed_out = backend_error
        .as_deref()
        .map(|e| e.contains("timed out"))
        .unwrap_or(false);
    let timed_out = start.elapsed() > timeout || backend_timed_out;

    EvalStats {
        bucket_hits_sig: sig,
        bucket_hits_detail_sig: detail_sig,
        micro_op_count: eval.micro_op_count,
        bucket_hits: eval.bucket_hits,
        mismatch_regs: mismatches,
        backend_error,
        oracle_error,
        timed_out,
        phase: "baseline".to_string(),
        semantic_class: None,
        inject_kind: None,
        inject_step: None,
        trigger_bucket_id: None,
        baseline_bucket_hits_sig: None,
        underconstrained_candidate: false,
        semantic_injection_applied: eval.semantic_injection_applied,
    }
}

fn metadata_object(seed_meta: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    match seed_meta.clone() {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    }
}

fn bug_kind(stats: &EvalStats) -> Option<&'static str> {
    let semantic_injected =
        stats.phase == "semantic_search" && stats.semantic_injection_applied;
    if stats.phase == "semantic_search" && !stats.semantic_injection_applied {
        return None;
    }
    if !semantic_injected
        && (stats.backend_error.is_some() || stats.oracle_error.is_some() || stats.timed_out)
    {
        Some("exception")
    } else if !stats.mismatch_regs.is_empty() {
        Some("mismatch")
    } else if stats.underconstrained_candidate {
        Some("underconstrained_candidate")
    } else {
        None
    }
}

fn semantic_search_solved(stats: &EvalStats) -> bool {
    stats.phase == "semantic_search" && stats.underconstrained_candidate
}

fn write_run_record(
    cfg: &BenchmarkConfig,
    writer: &JsonlWriter,
    eval_id: u64,
    words: &[u32],
    seed_index: usize,
    seed_meta: &serde_json::Value,
    stats: &EvalStats,
    attempt_index: Option<usize>,
) -> Result<(), String> {
    let mut metadata = metadata_object(seed_meta);
    metadata.insert("mode".to_string(), json!("benchmark"));
    metadata.insert("phase".to_string(), json!(stats.phase));
    metadata.insert("seed_index".to_string(), json!(seed_index));
    metadata.insert("semantic_class".to_string(), json!(stats.semantic_class));
    metadata.insert("inject_kind".to_string(), json!(stats.inject_kind));
    metadata.insert("inject_step".to_string(), json!(stats.inject_step));
    metadata.insert("trigger_bucket_id".to_string(), json!(stats.trigger_bucket_id));
    metadata.insert(
        "baseline_bucket_hits_sig".to_string(),
        json!(stats.baseline_bucket_hits_sig),
    );
    metadata.insert(
        "underconstrained_candidate".to_string(),
        json!(stats.underconstrained_candidate),
    );
    metadata.insert(
        "semantic_injection_applied".to_string(),
        json!(stats.semantic_injection_applied),
    );
    metadata.insert("attempt_index".to_string(), json!(attempt_index));
    metadata.insert("kind".to_string(), json!("run"));
    metadata.insert("is_bug".to_string(), json!(bug_kind(stats).is_some()));

    let rec = RunRecord {
        zkvm_commit: cfg.zkvm_commit.clone(),
        rng_seed: cfg.rng_seed,
        timeout_ms: cfg.timeout_ms,
        eval_id,
        timed_out: stats.timed_out,
        bucket_hits_sig: stats.bucket_hits_sig.clone(),
        micro_op_count: stats.micro_op_count,
        backend_error: stats.backend_error.clone(),
        oracle_error: stats.oracle_error.clone(),
        mismatch_regs: stats.mismatch_regs.clone(),
        instructions: words.to_vec(),
        metadata: serde_json::Value::Object(metadata),
    };
    writer.append_json_line(&rec)
}

fn write_corpus_record(
    cfg: &BenchmarkConfig,
    writer: &JsonlWriter,
    words: &[u32],
    seed_index: usize,
    seed_meta: &serde_json::Value,
    stats: &EvalStats,
) -> Result<(), String> {
    let mut metadata = metadata_object(seed_meta);
    metadata.insert("mode".to_string(), json!("benchmark"));
    metadata.insert("phase".to_string(), json!(stats.phase));
    metadata.insert("seed_index".to_string(), json!(seed_index));
    metadata.insert("kind".to_string(), json!("baseline_seed"));

    let rec = CorpusRecord {
        zkvm_commit: cfg.zkvm_commit.clone(),
        rng_seed: cfg.rng_seed,
        timeout_ms: cfg.timeout_ms,
        timed_out: stats.timed_out,
        mismatch: !stats.mismatch_regs.is_empty(),
        bucket_hits_sig: stats.bucket_hits_sig.clone(),
        instructions: words.to_vec(),
        metadata: serde_json::Value::Object(metadata),
    };
    writer.append_json_line(&rec)
}

fn write_bug_record(
    cfg: &BenchmarkConfig,
    writer: &JsonlWriter,
    words: &[u32],
    seed_index: usize,
    seed_meta: &serde_json::Value,
    stats: &EvalStats,
    attempt_index: Option<usize>,
) -> Result<bool, String> {
    let Some(kind) = bug_kind(stats) else {
        return Ok(false);
    };
    let mut metadata = metadata_object(seed_meta);
    metadata.insert("mode".to_string(), json!("benchmark"));
    metadata.insert("phase".to_string(), json!(stats.phase));
    metadata.insert("seed_index".to_string(), json!(seed_index));
    metadata.insert("kind".to_string(), json!(kind));
    metadata.insert("semantic_class".to_string(), json!(stats.semantic_class));
    metadata.insert("inject_kind".to_string(), json!(stats.inject_kind));
    metadata.insert("inject_step".to_string(), json!(stats.inject_step));
    metadata.insert("trigger_bucket_id".to_string(), json!(stats.trigger_bucket_id));
    metadata.insert(
        "baseline_bucket_hits_sig".to_string(),
        json!(stats.baseline_bucket_hits_sig),
    );
    metadata.insert(
        "underconstrained_candidate".to_string(),
        json!(stats.underconstrained_candidate),
    );
    metadata.insert(
        "semantic_injection_applied".to_string(),
        json!(stats.semantic_injection_applied),
    );
    metadata.insert("attempt_index".to_string(), json!(attempt_index));

    let rec = BugRecord {
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
        instructions: words.to_vec(),
        metadata: serde_json::Value::Object(metadata),
    };
    writer.append_json_line(&rec)?;
    Ok(true)
}

fn centered_steps(
    anchor: u64,
    before: u64,
    after: u64,
    stride: u64,
    max_trials: usize,
) -> Vec<u64> {
    let step = stride.max(1);
    let start = anchor.saturating_sub(before);
    let end = anchor.saturating_add(after);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut dist = 0u64;

    while out.len() < max_trials {
        let mut emitted = false;
        if dist == 0 {
            if seen.insert(anchor) {
                out.push(anchor);
                emitted = true;
            }
        } else {
            if let Some(left) = anchor.checked_sub(dist) {
                if left >= start && seen.insert(left) {
                    out.push(left);
                    emitted = true;
                    if out.len() >= max_trials {
                        break;
                    }
                }
            }
            let right = anchor.saturating_add(dist);
            if right <= end && seen.insert(right) {
                out.push(right);
                emitted = true;
            }
        }
        if !emitted && anchor.saturating_add(dist) > end && dist > before {
            break;
        }
        dist = dist.saturating_add(step);
    }

    out
}

fn sweep_steps(start: u64, end: u64, stride: u64, max_trials: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let step = stride.max(1);
    let mut cur = start;
    while cur <= end && out.len() < max_trials {
        out.push(cur);
        if let Some(next) = cur.checked_add(step) {
            cur = next;
        } else {
            break;
        }
    }
    out
}

fn candidate_steps(cfg: &BenchmarkConfig, candidate: &SemanticInjectionCandidate) -> Vec<u64> {
    match candidate.schedule {
        InjectionSchedule::Exact(step) => vec![step],
        InjectionSchedule::Explicit(ref steps) => steps.clone(),
        InjectionSchedule::AroundAnchor(anchor) => centered_steps(
            anchor,
            cfg.semantic_window_before,
            cfg.semantic_window_after,
            cfg.semantic_step_stride,
            cfg.semantic_max_trials_per_bucket.max(1),
        ),
        InjectionSchedule::Sweep { start, end } => sweep_steps(
            start,
            end,
            cfg.semantic_step_stride,
            cfg.semantic_max_trials_per_bucket.max(1),
        ),
    }
}

pub fn run_benchmark_threaded<B, F>(cfg: BenchmarkConfig, build_backend: F) -> Result<BenchmarkOutputs, String>
where
    B: BenchmarkBackend,
    F: FnOnce() -> B + Send + 'static,
{
    let stack = cfg.stack_size_bytes.max(16 * 1024 * 1024);
    let handle = std::thread::Builder::new()
        .name("beak-benchmark".into())
        .stack_size(stack)
        .spawn(move || {
            let backend = build_backend();
            run_benchmark(cfg, backend)
        })
        .map_err(|e| format!("spawn benchmark thread failed: {e}"))?;
    handle
        .join()
        .map_err(|_| "benchmark thread panicked".to_string())?
}

pub fn run_benchmark<B: BenchmarkBackend>(
    cfg: BenchmarkConfig,
    mut backend: B,
) -> Result<BenchmarkOutputs, String> {
    std::fs::create_dir_all(&cfg.out_dir)
        .map_err(|e| format!("create out_dir {} failed: {e}", cfg.out_dir.display()))?;

    let base_prefix = cfg.output_prefix.clone().unwrap_or_else(|| {
        format!(
            "benchmark-{}-{}-seed{}-{}",
            cfg.zkvm_tag,
            &cfg.zkvm_commit[..cfg.zkvm_commit.len().min(8)],
            cfg.rng_seed,
            now_ts_secs()
        )
    });
    let corpus_path = cfg.out_dir.join(format!("{base_prefix}-corpus.jsonl"));
    let bugs_path = cfg.out_dir.join(format!("{base_prefix}-bugs.jsonl"));
    let runs_path = cfg.out_dir.join(format!("{base_prefix}-runs.jsonl"));

    let corpus_writer = JsonlWriter::open_append(&corpus_path)?;
    let bug_writer = JsonlWriter::open_append(&bugs_path)?;
    let run_writer = JsonlWriter::open_append(&runs_path)?;

    let seeds = load_initial_seeds(&cfg.seeds_jsonl, cfg.max_instructions, &|words| {
        backend.is_usable_seed(words)
    });
    if seeds.is_empty() {
        return Err(format!(
            "No usable initial seeds loaded from {}",
            cfg.seeds_jsonl.display()
        ));
    }

    let timeout = Duration::from_millis(cfg.timeout_ms);
    let take_n = if cfg.initial_limit == 0 {
        seeds.len()
    } else {
        cfg.initial_limit.min(seeds.len())
    };

    let mut bug_count = 0usize;
    let mut eval_id: u64 = 0;

    for (seed_index, (input, seed_meta)) in seeds.into_iter().take(take_n).enumerate() {
        let words = decode_words_from_input(&input, cfg.max_instructions);
        if words.is_empty() || !backend.is_usable_seed(&words) {
            continue;
        }

        if cfg.precheck_oracle_max_steps > 0 {
            let pre = RISCVOracle::execute_with_step_limit(&words, cfg.oracle, cfg.precheck_oracle_max_steps);
            if pre.hit_step_limit {
                let mut skipped = EvalStats::default();
                skipped.phase = "baseline".to_string();
                skipped.oracle_error = Some("oracle_precheck_step_limit".to_string());
                eval_id = eval_id.saturating_add(1);
                write_run_record(&cfg, &run_writer, eval_id, &words, seed_index, &seed_meta, &skipped, None)?;
                continue;
            }
        }

        backend.clear_semantic_injection();
        let baseline = eval_once(&cfg, timeout, &mut backend, &words);
        eval_id = eval_id.saturating_add(1);
        write_corpus_record(&cfg, &corpus_writer, &words, seed_index, &seed_meta, &baseline)?;
        write_run_record(&cfg, &run_writer, eval_id, &words, seed_index, &seed_meta, &baseline, None)?;
        if write_bug_record(&cfg, &bug_writer, &words, seed_index, &seed_meta, &baseline, None)? {
            bug_count = bug_count.saturating_add(1);
        }

        if !cfg.semantic_search_enabled {
            continue;
        }

        let candidates = backend.semantic_injection_candidates(&baseline.bucket_hits);
        let mut attempted = HashSet::<(String, u64)>::new();

        for candidate in candidates {
            let steps = candidate_steps(&cfg, &candidate);
            if steps.is_empty() {
                continue;
            }
            let mut consecutive_noops = 0usize;

            for (attempt_index, step) in steps.into_iter().enumerate() {
                let attempt_key = (candidate.inject_kind.clone(), step);
                if !attempted.insert(attempt_key) {
                    continue;
                }

                backend.clear_semantic_injection();
                backend.arm_semantic_injection(&candidate.inject_kind, step)?;

                let mut injected = eval_once(&cfg, timeout, &mut backend, &words);
                injected.phase = "semantic_search".to_string();
                injected.semantic_class = Some(candidate.semantic_class.clone());
                injected.inject_kind = Some(candidate.inject_kind.clone());
                injected.inject_step = Some(step);
                injected.trigger_bucket_id = Some(candidate.bucket_id.clone());
                injected.baseline_bucket_hits_sig = Some(baseline.bucket_hits_sig.clone());
                injected.underconstrained_candidate = injected.backend_error.is_none()
                    && injected.oracle_error.is_none()
                    && injected.mismatch_regs.is_empty()
                    && !injected.timed_out
                    && injected.semantic_injection_applied;

                eval_id = eval_id.saturating_add(1);
                write_run_record(
                    &cfg,
                    &run_writer,
                    eval_id,
                    &words,
                    seed_index,
                    &seed_meta,
                    &injected,
                    Some(attempt_index),
                )?;
                if write_bug_record(
                    &cfg,
                    &bug_writer,
                    &words,
                    seed_index,
                    &seed_meta,
                    &injected,
                    Some(attempt_index),
                )? {
                    bug_count = bug_count.saturating_add(1);
                    if semantic_search_solved(&injected) {
                        break;
                    }
                }
                if injected.semantic_injection_applied {
                    consecutive_noops = 0;
                } else {
                    consecutive_noops = consecutive_noops.saturating_add(1);
                    if consecutive_noops >= 4 {
                        break;
                    }
                }
            }
        }

        backend.clear_semantic_injection();
    }

    corpus_writer.flush()?;
    bug_writer.flush()?;
    run_writer.flush()?;

    if bug_count > 0 {
        eprintln!("[BENCHMARK][DONE] bug_records={bug_count}");
    } else {
        eprintln!("[BENCHMARK][DONE] bug_records=0");
    }

    Ok(BenchmarkOutputs {
        corpus_path,
        bugs_path,
        runs_path: Some(runs_path),
    })
}

#[cfg(test)]
mod tests {
    use super::{centered_steps, sweep_steps};

    #[test]
    fn centered_steps_expand_from_anchor() {
        assert_eq!(centered_steps(10, 2, 3, 1, 16), vec![10, 9, 11, 8, 12, 13]);
    }

    #[test]
    fn centered_steps_obey_stride_and_limit() {
        assert_eq!(centered_steps(10, 6, 6, 2, 3), vec![10, 8, 12]);
    }

    #[test]
    fn sweep_steps_respects_stride() {
        assert_eq!(sweep_steps(3, 10, 3, 8), vec![3, 6, 9]);
    }
}
