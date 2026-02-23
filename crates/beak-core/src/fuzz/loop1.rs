use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libafl::prelude::*;
use libafl_bolts::rands::StdRand;
use libafl_bolts::tuples::tuple_list;
use libafl_bolts::Named;

use crate::fuzz::jsonl::{BugRecord, CorpusRecord, JsonlWriter};
use crate::fuzz::seed::FuzzingSeed;
use crate::rv32im::instruction::RV32IMInstruction;
use crate::rv32im::oracle::RISCVOracle;
use crate::trace::{sorted_signatures_from_hits, BucketHit};

use super::mutators::SeedMutator;

pub const DEFAULT_RNG_SEED: u64 = 2026;

type LoopState =
    StdState<InMemoryCorpus<BytesInput>, BytesInput, StdRand, InMemoryCorpus<BytesInput>>;

#[derive(Debug, Clone)]
pub struct Loop1Config {
    pub zkvm_tag: String,
    pub zkvm_commit: String,
    pub rng_seed: u64,
    pub timeout_ms: u64,

    pub seeds_jsonl: PathBuf,
    pub out_dir: PathBuf,
    pub output_prefix: Option<String>,

    pub initial_limit: usize,
    pub no_initial_eval: bool,
    pub max_instructions: usize,
    pub iters: usize,

    pub stack_size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct Loop1Outputs {
    pub corpus_path: PathBuf,
    pub bugs_path: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct BackendEval {
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub final_regs: Option<[u32; 32]>,
    pub backend_error: Option<String>,
}

pub trait LoopBackend {
    /// Filter seeds that are known to be invalid/unsupported for this backend.
    fn is_usable_seed(&self, _words: &[u32]) -> bool {
        true
    }

    /// Backend-specific per-run setup (e.g. enable JSON capture, disable assertions).
    fn prepare_for_run(&mut self, _rng_seed: u64) {}

    /// Prove (or otherwise execute) and return final architectural regs (best-effort).
    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String>;

    /// Collect trace-derived feedback (bucket ids, hit count, trace stats). This is allowed to be
    /// best-effort; failures should be reflected in `backend_error`.
    fn collect_eval(&mut self) -> BackendEval;
}

#[derive(Debug, Clone, Default)]
struct RunStats {
    bucket_hits_sig: String,
    bucket_hit_count: usize,
    micro_op_count: usize,
    bucket_hits: Vec<BucketHit>,
    mismatch_regs: Vec<(u32, u32, u32)>,
    timed_out: bool,
}

static LAST_RUN: LazyLock<Mutex<RunStats>> = LazyLock::new(|| Mutex::new(RunStats::default()));

fn now_ts_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs()
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

/// Canonicalize bucket hit signatures into a single stable signature string.
///
/// Contract:
/// - Input must already be sorted canonically (by `BucketType` order, then signature string).
/// - Deduplicates while preserving the input order.
/// - Joins with '\n'.
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
    out.join("\n")
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
        // Also filter out decode-invalid words (generic RISC-V sanity).
        if words.iter().any(|w| RV32IMInstruction::from_word(*w).is_err()) {
            continue;
        }
        out.push((encode_words(&words), serde_json::Value::Object(seed.metadata)));
    }
    out
}

/// Feedback: keep inputs that yield a previously unseen bucket signature.
struct BucketNoveltyFeedback {
    seen: HashSet<String>,
    corpus_writer: JsonlWriter,
    cfg: Loop1Config,
    name: std::borrow::Cow<'static, str>,
}

impl BucketNoveltyFeedback {
    fn new(corpus_writer: JsonlWriter, cfg: Loop1Config) -> Self {
        Self { seen: HashSet::new(), corpus_writer, cfg, name: "BucketNoveltyFeedback".into() }
    }
}

impl Named for BucketNoveltyFeedback {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        &self.name
    }
}

impl StateInitializer<LoopState> for BucketNoveltyFeedback {}

impl<EM, OT> Feedback<EM, BytesInput, OT, LoopState> for BucketNoveltyFeedback {
    fn is_interesting(
        &mut self,
        _state: &mut LoopState,
        _mgr: &mut EM,
        input: &BytesInput,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let stats = LAST_RUN.lock().unwrap().clone();
        let sig = stats.bucket_hits_sig;
        if sig.is_empty() {
            return Ok(false);
        }
        if !self.seen.insert(sig.clone()) {
            return Ok(false);
        }

        let words = decode_words_from_input(input, 2048);
        let rec = CorpusRecord {
            zkvm_commit: self.cfg.zkvm_commit.clone(),
            rng_seed: self.cfg.rng_seed,
            timeout_ms: self.cfg.timeout_ms,
            timed_out: stats.timed_out,
            mismatch: !stats.mismatch_regs.is_empty(),
            bucket_hits_sig: sig,
            instructions: words,
            metadata: serde_json::json!({ "kind": "interesting" }),
        };
        self.corpus_writer.append_json_line(&rec).map_err(|e| Error::unknown(e))?;
        Ok(true)
    }
}

/// Objective: treat mismatch as a \"crash\" signal and write a bug record.
struct MismatchObjective {
    bug_writer: JsonlWriter,
    cfg: Loop1Config,
    name: std::borrow::Cow<'static, str>,
}

impl MismatchObjective {
    fn new(bug_writer: JsonlWriter, cfg: Loop1Config) -> Self {
        Self { bug_writer, cfg, name: "MismatchObjective".into() }
    }
}

impl Named for MismatchObjective {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        &self.name
    }
}

impl StateInitializer<LoopState> for MismatchObjective {}

impl<EM, OT> Feedback<EM, BytesInput, OT, LoopState> for MismatchObjective {
    fn is_interesting(
        &mut self,
        _state: &mut LoopState,
        _mgr: &mut EM,
        input: &BytesInput,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        if !matches!(exit_kind, ExitKind::Crash) {
            return Ok(false);
        }
        let stats = LAST_RUN.lock().unwrap().clone();
        let words = decode_words_from_input(input, 2048);
        let rec = BugRecord {
            zkvm_commit: self.cfg.zkvm_commit.clone(),
            rng_seed: self.cfg.rng_seed,
            timeout_ms: self.cfg.timeout_ms,
            timed_out: stats.timed_out,
            bucket_hits_sig: stats.bucket_hits_sig,
            micro_op_count: stats.micro_op_count,
            bucket_hits: stats.bucket_hits.clone(),
            mismatch_regs: stats.mismatch_regs,
            instructions: words,
            metadata: serde_json::json!({ "kind": "mismatch" }),
        };
        self.bug_writer.append_json_line(&rec).map_err(|e| Error::unknown(e))?;
        Ok(true)
    }
}

pub fn run_loop1_threaded<B, F>(cfg: Loop1Config, build_backend: F) -> Result<Loop1Outputs, String>
where
    B: LoopBackend,
    F: FnOnce() -> B + Send + 'static,
{
    let stack = cfg.stack_size_bytes.max(16 * 1024 * 1024);
    let handle = std::thread::Builder::new()
        .name("beak-loop1".into())
        .stack_size(stack)
        .spawn(move || {
            let backend = build_backend();
            run_loop1(cfg, backend)
        })
        .map_err(|e| format!("spawn loop thread failed: {e}"))?;
    handle.join().map_err(|_| "loop thread panicked".to_string())?
}

pub fn run_loop1<B: LoopBackend>(cfg: Loop1Config, mut backend: B) -> Result<Loop1Outputs, String> {
    std::fs::create_dir_all(&cfg.out_dir)
        .map_err(|e| format!("create out_dir {} failed: {e}", cfg.out_dir.display()))?;

    let prefix = cfg.output_prefix.clone().unwrap_or_else(|| {
        format!(
            "loop1-{}-{}-seed{}-{}",
            cfg.zkvm_tag,
            &cfg.zkvm_commit[..cfg.zkvm_commit.len().min(8)],
            cfg.rng_seed,
            now_ts_secs()
        )
    });
    let corpus_path = cfg.out_dir.join(format!("{prefix}-corpus.jsonl"));
    let bugs_path = cfg.out_dir.join(format!("{prefix}-bugs.jsonl"));

    let corpus_writer = JsonlWriter::open_append(&corpus_path)?;
    let bug_writer = JsonlWriter::open_append(&bugs_path)?;

    // --- libAFL setup ---
    let rand = StdRand::with_seed(cfg.rng_seed);
    let corpus = InMemoryCorpus::<BytesInput>::new();
    let solutions = InMemoryCorpus::<BytesInput>::new();

    let mut feedback = BucketNoveltyFeedback::new(corpus_writer.clone(), cfg.clone());
    let mut objective = MismatchObjective::new(bug_writer.clone(), cfg.clone());
    let mut state: LoopState =
        StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
            .map_err(|e| format!("create state failed: {e}"))?;

    // Seed corpus with the initial JSONL.
    for (input, _meta) in load_initial_seeds(&cfg.seeds_jsonl, cfg.max_instructions, &|words| {
        backend.is_usable_seed(words)
    })
    .into_iter()
    .take(if cfg.initial_limit == 0 { usize::MAX } else { cfg.initial_limit })
    {
        state
            .corpus_mut()
            .add(Testcase::new(input))
            .map_err(|e| format!("add initial seed failed: {e}"))?;
    }
    if state.corpus().count() == 0 {
        return Err(format!("No usable initial seeds loaded from {}", cfg.seeds_jsonl.display()));
    }

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let monitor = SimpleMonitor::new(|_s| {});
    let mut mgr = SimpleEventManager::new(monitor);

    // Executor harness: run prove, build trace, compute signature, compare regs.
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let mut harness = |input: &BytesInput| -> ExitKind {
        let start = Instant::now();
        let words = decode_words_from_input(input, cfg.max_instructions);
        if !backend.is_usable_seed(&words)
            || words.iter().any(|w| RV32IMInstruction::from_word(*w).is_err())
        {
            let mut last = LAST_RUN.lock().unwrap();
            *last = RunStats::default();
            return ExitKind::Ok;
        }

        backend.prepare_for_run(cfg.rng_seed);

        let oracle_regs = RISCVOracle::execute(&words);
        let backend_regs = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            backend.prove_and_read_final_regs(&words)
        }));
        let final_regs = match backend_regs {
            Ok(Ok(r)) => Some(r),
            Ok(Err(_)) => None,
            Err(_) => None,
        };
        let mismatches =
            final_regs.as_ref().map(|r| mismatch_regs(&oracle_regs, r)).unwrap_or_default();

        let eval = backend.collect_eval();
        let bucket_sigs = sorted_signatures_from_hits(&eval.bucket_hits);
        let sig = canonical_bucket_sig(&bucket_sigs);
        let bucket_hit_count = eval.bucket_hits.len();

        let timed_out = start.elapsed() > timeout;

        let mut last = LAST_RUN.lock().unwrap();
        *last = RunStats {
            bucket_hits_sig: sig,
            bucket_hit_count,
            micro_op_count: eval.micro_op_count,
            bucket_hits: eval.bucket_hits.clone(),
            mismatch_regs: mismatches.clone(),
            timed_out,
        };

        if timed_out {
            ExitKind::Timeout
        } else if !mismatches.is_empty() {
            ExitKind::Crash
        } else {
            ExitKind::Ok
        }
    };

    let observers = tuple_list!();
    let mut executor =
        InProcessExecutor::new(&mut harness, observers, &mut fuzzer, &mut state, &mut mgr)
            .map_err(|e| format!("create executor failed: {e}"))?;

    let mut stages = tuple_list!(StdMutationalStage::new(SeedMutator::new(cfg.max_instructions)));

    if !cfg.no_initial_eval {
        let initial_count = state.corpus().count();
        for idx in 0..initial_count {
            let id = CorpusId::from(idx);
            let Ok(tc_cell) = state.corpus().get(id) else { continue };
            let tc = tc_cell.borrow();
            let Some(input) = tc.input().as_ref().cloned() else { continue };
            drop(tc);
            let _ = fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, &input);
        }
    }

    for _ in 0..cfg.iters {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .map_err(|e| format!("fuzz_one failed: {e}"))?;
    }

    corpus_writer.flush()?;
    bug_writer.flush()?;

    Ok(Loop1Outputs { corpus_path, bugs_path })
}
