use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libafl::prelude::*;
use libafl_bolts::rands::{Rand, StdRand};
use libafl_bolts::tuples::tuple_list;
use libafl_bolts::Named;
use crate::fuzz::jsonl::{BugRecord, CorpusRecord, JsonlWriter, RunRecord};
use crate::fuzz::seed::FuzzingSeed;
use crate::rv32im::instruction::RV32IMInstruction;
use crate::rv32im::oracle::{OracleConfig, RISCVOracle};
use crate::trace::{sorted_signatures_from_hits, BucketHit};

use super::bandit;
use super::mutators::{SeedMutator, SEED_MUTATOR_NUM_ARMS};
use super::policy::{
    FuzzerState, MetricsRecord, PolicyProvider, PolicyType, RewardWindow,
};

pub const DEFAULT_RNG_SEED: u64 = 2026;

type LoopState =
    StdState<InMemoryCorpus<BytesInput>, BytesInput, StdRand, InMemoryCorpus<BytesInput>>;

#[derive(Debug, Clone)]
pub struct Loop1Config {
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
    pub iters: usize,
    pub chain_direct_injection: bool,
    /// If > 0, run a cheap oracle pre-check and skip backend execution when the input reaches
    /// this step bound (likely non-terminating path).
    pub precheck_oracle_max_steps: u32,

    pub stack_size_bytes: usize,

    /// Policy type for mutator selection / seed scheduling.
    pub policy_type: PolicyType,
    /// Unix socket path for external RL policy.
    pub rl_socket_path: Option<PathBuf>,
    /// Timeout in ms for external RL policy requests.
    pub rl_fallback_timeout_ms: u64,
    /// Emit metrics every N iterations (0 = disabled).
    pub metrics_interval: usize,
}

#[derive(Debug, Clone)]
pub struct Loop1Outputs {
    pub corpus_path: PathBuf,
    pub bugs_path: PathBuf,
    pub runs_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct BackendEval {
    /// Backend-defined trace size metric used for reporting.
    ///
    /// Note: this is not necessarily “total micro-ops”. Some backends may report instruction count
    /// as a proxy until full micro-op accounting is wired up.
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub final_regs: Option<[u32; 32]>,
    pub backend_error: Option<String>,
    pub semantic_injection_applied: bool,
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

    /// Whether this backend has a direct witness-injection mapping for a bucket id.
    /// Used by direct bucket->injection mode.
    fn bucket_has_direct_injection(&self, _bucket_id: &str) -> bool {
        false
    }

    /// Clear any pending direct witness-injection plan for the next run.
    fn clear_direct_injection(&mut self) {}

    /// Select and arm a direct witness-injection plan from current bucket hits.
    /// Returns the selected injection kind if armed.
    fn arm_direct_injection_from_hits(&mut self, _hits: &[BucketHit]) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone, Default)]
struct RunStats {
    eval_id: u64,
    bucket_hits_sig: String,
    /// Copied from `BackendEval::micro_op_count` for logging/bug records.
    micro_op_count: usize,
    bucket_hits: Vec<BucketHit>,
    mismatch_regs: Vec<(u32, u32, u32)>,
    backend_error: Option<String>,
    oracle_error: Option<String>,
    timed_out: bool,
    has_direct_injection_target: bool,
    injected_phase: bool,
    direct_injection_kind: Option<String>,
    target_buckets: Vec<String>,
    baseline_bucket_hits_sig: Option<String>,
    underconstrained_candidate: bool,
    skip_reason: Option<String>,
}

static LAST_RUN: LazyLock<Mutex<RunStats>> = LazyLock::new(|| Mutex::new(RunStats::default()));

fn eval_once<B: LoopBackend>(
    cfg: &Loop1Config,
    timeout: Duration,
    backend: &mut B,
    words: &[u32],
) -> RunStats {
    let start = Instant::now();
    backend.prepare_for_run(cfg.rng_seed);

    let oracle_regs = catch_unwind_nonfatal(std::panic::AssertUnwindSafe(|| {
        RISCVOracle::execute_with_config(words, cfg.oracle)
    }));
    let panic_oracle_error = match oracle_regs.as_ref() {
        Err(p) => Some(panic_payload_to_string(p.as_ref())),
        _ => None,
    };
    let backend_regs = catch_unwind_nonfatal(std::panic::AssertUnwindSafe(|| {
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
    let timed_out = start.elapsed() > timeout || backend_timed_out;

    RunStats {
        eval_id: 0,
        bucket_hits_sig: sig,
        micro_op_count: eval.micro_op_count,
        bucket_hits: eval.bucket_hits,
        mismatch_regs: mismatches,
        backend_error,
        oracle_error,
        timed_out,
        has_direct_injection_target: false,
        injected_phase: false,
        direct_injection_kind: None,
        target_buckets: Vec::new(),
        baseline_bucket_hits_sig: None,
        underconstrained_candidate: false,
        skip_reason: None,
    }
}

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

fn panic_payload_to_string(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        return format!("panic: {s}");
    }
    if let Some(s) = p.downcast_ref::<String>() {
        return format!("panic: {s}");
    }
    "panic: non-string payload".to_string()
}

/// Run a closure with a temporary non-fatal panic hook and catch unwind.
///
/// This prevents libAFL's in-process panic hook from aborting the whole process
/// for panics that we intentionally treat as per-input "exception" outcomes.
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

/// Canonicalize bucket hit signatures into a single stable signature string.
///
/// Contract:
/// - Input must already be sorted canonically (by bucket id string).
/// - Deduplicates while preserving the input order.
/// - Joins with ';'.
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
    seen_bucket_ids: HashSet<String>,
    corpus_writer: JsonlWriter,
    bug_writer: JsonlWriter,
    run_writer: JsonlWriter,
    cfg: Loop1Config,
    name: std::borrow::Cow<'static, str>,
    written_bug_keys: HashSet<String>,
    seen_bug_sigs: HashSet<String>,
    /// Shared policy for updating after each evaluation.
    policy: Option<Arc<Mutex<dyn PolicyProvider>>>,
    /// Shared mutable fuzzer state, kept in sync after each evaluation.
    fuzzer_state: Option<Arc<Mutex<FuzzerState>>>,
    reward_window: RewardWindow,
    iteration_counter: u64,
    last_novel_iteration: u64,
    cumulative_reward: f64,
    bug_count: usize,
    metrics_writer: Option<JsonlWriter>,
    start_time: Instant,
}

impl BucketNoveltyFeedback {
    fn new(corpus_writer: JsonlWriter, bug_writer: JsonlWriter, run_writer: JsonlWriter, cfg: Loop1Config) -> Self {
        Self {
            seen: HashSet::new(),
            seen_bucket_ids: HashSet::new(),
            corpus_writer,
            bug_writer,
            run_writer,
            cfg,
            name: "BucketNoveltyFeedback".into(),
            written_bug_keys: HashSet::new(),
            seen_bug_sigs: HashSet::new(),
            policy: None,
            fuzzer_state: None,
            reward_window: RewardWindow::new(SEED_MUTATOR_NUM_ARMS, 100),
            iteration_counter: 0,
            last_novel_iteration: 0,
            cumulative_reward: 0.0,
            bug_count: 0,
            metrics_writer: None,
            start_time: Instant::now(),
        }
    }

    fn with_policy(
        mut self,
        policy: Arc<Mutex<dyn PolicyProvider>>,
        fuzzer_state: Arc<Mutex<FuzzerState>>,
    ) -> Self {
        self.policy = Some(policy);
        self.fuzzer_state = Some(fuzzer_state);
        self
    }

    fn with_metrics_writer(mut self, writer: JsonlWriter) -> Self {
        self.metrics_writer = Some(writer);
        self
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

        // Per-bucket novelty is computed independently of corpus signature novelty.
        // This will later serve as a finer-grained reward signal (vs. only new combinations).
        let mut new_bucket_id_count = 0usize;
        for hit in &stats.bucket_hits {
            if self.seen_bucket_ids.insert(hit.bucket_id.clone()) {
                new_bucket_id_count += 1;
            }
        }

        let underconstrained_candidate = stats.underconstrained_candidate;
        let mismatch = !stats.mismatch_regs.is_empty();
        let has_exception = !stats.injected_phase
            && (stats.timed_out || stats.backend_error.is_some() || stats.oracle_error.is_some());
        let is_bug = mismatch || has_exception || underconstrained_candidate;
        if is_bug {
            let words = decode_words_from_input(input, 2048);
            let kind = if has_exception {
                "exception"
            } else if mismatch {
                "mismatch"
            } else {
                "underconstrained_candidate"
            };
            let backend_err = stats.backend_error.clone().unwrap_or_else(|| "none".to_string());
            let oracle_err = stats.oracle_error.clone().unwrap_or_else(|| "none".to_string());
            let bug_key = format!(
                "{kind}|{}|{}|{}|{}|{}",
                stats.bucket_hits_sig,
                backend_err,
                oracle_err,
                stats.direct_injection_kind.clone().unwrap_or_else(|| "none".to_string()),
                words.iter().map(|w| format!("{w:08x}")).collect::<Vec<_>>().join(",")
            );
            if self.written_bug_keys.insert(bug_key) {
                eprintln!(
                    "[LOOP1][BUG] eval_id={} kind={} mismatches={} timed_out={} injected={} sig={}",
                    stats.eval_id,
                    kind,
                    stats.mismatch_regs.len(),
                    stats.timed_out,
                    stats.injected_phase,
                    stats.bucket_hits_sig
                );
                let rec = BugRecord {
                    zkvm_commit: self.cfg.zkvm_commit.clone(),
                    rng_seed: self.cfg.rng_seed,
                    timeout_ms: self.cfg.timeout_ms,
                    timed_out: stats.timed_out,
                    bucket_hits_sig: stats.bucket_hits_sig.clone(),
                    micro_op_count: stats.micro_op_count,
                    backend_error: stats.backend_error.clone(),
                    oracle_error: stats.oracle_error.clone(),
                    bucket_hits: stats.bucket_hits.clone(),
                    mismatch_regs: if mismatch { stats.mismatch_regs.clone() } else { Vec::new() },
                    instructions: words,
                    metadata: serde_json::json!({
                        "kind": kind,
                        "timed_out": stats.timed_out,
                        "injected_phase": stats.injected_phase,
                        "has_direct_injection_target": stats.has_direct_injection_target,
                        "direct_injection_kind": stats.direct_injection_kind,
                        "target_buckets": stats.target_buckets,
                        "baseline_bucket_hits_sig": stats.baseline_bucket_hits_sig,
                        "underconstrained_candidate": underconstrained_candidate,
                    }),
                };
                self.bug_writer.append_json_line(&rec).map_err(|e| Error::unknown(e))?;
            }
        }

        let sig = stats.bucket_hits_sig.clone();
        let is_new_combo = !sig.is_empty() && self.seen.insert(sig.clone());

        let mismatch = !stats.mismatch_regs.is_empty();
        let is_bug_here = mismatch || has_exception || underconstrained_candidate;

        let reward =
            (if is_new_combo { 10.0 } else { 0.0 })
            + (new_bucket_id_count as f64) * 5.0
            + (stats.bucket_hits.len() as f64) * 0.002
            + 0.05;

        self.iteration_counter += 1;
        self.cumulative_reward += reward;
        if is_bug_here {
            self.bug_count += 1;
        }
        if is_new_combo {
            self.last_novel_iteration = self.iteration_counter;
        }

        if let Some(arm_idx) = bandit::take_last_arm() {
            self.reward_window.push(arm_idx, reward);

            if let Some(policy) = &self.policy {
                let fs = self.fuzzer_state.as_ref().map(|f| f.lock().unwrap().clone())
                    .unwrap_or_default();
                policy.lock().unwrap().update_mutator(arm_idx, reward, &fs);
            } else {
                bandit::update(arm_idx, reward);
            }
        }

        // Update shared FuzzerState.
        if let Some(fs_arc) = &self.fuzzer_state {
            let mut fs = fs_arc.lock().unwrap();
            fs.corpus_size = self.seen.len();
            fs.unique_bucket_ids = self.seen_bucket_ids.len();
            fs.unique_signatures = self.seen.len();
            fs.iteration = self.iteration_counter;
            fs.time_since_last_novel = self.iteration_counter.saturating_sub(self.last_novel_iteration);
            fs.recent_arm_rewards = self.reward_window.means();
            fs.cumulative_reward = self.cumulative_reward;
            fs.bug_count = self.bug_count;
        }

        // Emit metrics periodically.
        if self.cfg.metrics_interval > 0
            && self.iteration_counter % (self.cfg.metrics_interval as u64) == 0
        {
            if let Some(mw) = &self.metrics_writer {
                let policy_name = self.policy.as_ref()
                    .map(|p| p.lock().unwrap().name().to_string())
                    .unwrap_or_else(|| "bandit".to_string());
                let arm_pulls = self.policy.as_ref()
                    .map(|p| p.lock().unwrap().arm_pulls())
                    .unwrap_or_default();
                let arm_means = self.policy.as_ref()
                    .map(|p| p.lock().unwrap().arm_mean_rewards())
                    .unwrap_or_default();
                let rec = MetricsRecord {
                    iteration: self.iteration_counter,
                    wall_time_sec: self.start_time.elapsed().as_secs_f64(),
                    corpus_size: self.seen.len(),
                    unique_bucket_ids: self.seen_bucket_ids.len(),
                    unique_signatures: self.seen.len(),
                    bug_count: self.bug_count,
                    policy_type: policy_name,
                    arm_pulls,
                    arm_rewards_mean: arm_means,
                    recent_reward_100: self.reward_window.overall_recent_mean(),
                    time_since_last_novel: self.iteration_counter.saturating_sub(self.last_novel_iteration),
                    cumulative_reward: self.cumulative_reward,
                };
                let _ = mw.append_json_line(&rec);
            }
        }

        let words = decode_words_from_input(input, 2048);
        let run_rec = RunRecord {
            zkvm_commit: self.cfg.zkvm_commit.clone(),
            rng_seed: self.cfg.rng_seed,
            timeout_ms: self.cfg.timeout_ms,
            eval_id: stats.eval_id,
            timed_out: stats.timed_out,
            bucket_hits_sig: stats.bucket_hits_sig.clone(),
            micro_op_count: stats.micro_op_count,
            backend_error: stats.backend_error.clone(),
            oracle_error: stats.oracle_error.clone(),
            mismatch_regs: stats.mismatch_regs.clone(),
            instructions: words.clone(),
            metadata: serde_json::json!({
                "kind": "run",
                "is_bug": is_bug,
                "is_interesting": is_new_combo,
                "new_bucket_id_count": new_bucket_id_count,
                "skip_reason": stats.skip_reason,
                "injected_phase": stats.injected_phase,
                "has_direct_injection_target": stats.has_direct_injection_target,
                "direct_injection_kind": stats.direct_injection_kind,
                "target_buckets": stats.target_buckets,
                "baseline_bucket_hits_sig": stats.baseline_bucket_hits_sig,
                "underconstrained_candidate": stats.underconstrained_candidate,
            }),
        };
        self.run_writer.append_json_line(&run_rec).map_err(|e| Error::unknown(e))?;

        if !is_new_combo {
            return Ok(false);
        }

        let rec = CorpusRecord {
            zkvm_commit: self.cfg.zkvm_commit.clone(),
            rng_seed: self.cfg.rng_seed,
            timeout_ms: self.cfg.timeout_ms,
            timed_out: stats.timed_out,
            mismatch: !stats.mismatch_regs.is_empty(),
            bucket_hits_sig: sig,
            instructions: words,
            metadata: serde_json::json!({
                "kind": "interesting",
                "new_bucket_id_count": new_bucket_id_count,
                "injected_phase": stats.injected_phase,
                "has_direct_injection_target": stats.has_direct_injection_target,
                "direct_injection_kind": stats.direct_injection_kind,
                "target_buckets": stats.target_buckets,
                "baseline_bucket_hits_sig": stats.baseline_bucket_hits_sig,
                "underconstrained_candidate": stats.underconstrained_candidate,
            }),
        };
        self.corpus_writer.append_json_line(&rec).map_err(|e| Error::unknown(e))?;
        Ok(true)
    }
}

/// Objective: never mark an input as a "solution".
///
/// We still record mismatches to `bugs.jsonl` in the feedback, so objective must stay "false"
/// to let libAFL evaluate feedback (and thus write `corpus.jsonl`).
struct NeverObjective {
    name: std::borrow::Cow<'static, str>,
}

impl NeverObjective {
    fn new() -> Self {
        Self { name: "NeverObjective".into() }
    }
}

impl Named for NeverObjective {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        &self.name
    }
}

impl StateInitializer<LoopState> for NeverObjective {}

impl<EM, OT> Feedback<EM, BytesInput, OT, LoopState> for NeverObjective {
    fn is_interesting(
        &mut self,
        _state: &mut LoopState,
        _mgr: &mut EM,
        _input: &BytesInput,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(false)
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

    let base_prefix = cfg.output_prefix.clone().unwrap_or_else(|| {
        format!(
            "loop1-{}-{}-seed{}-{}",
            cfg.zkvm_tag,
            &cfg.zkvm_commit[..cfg.zkvm_commit.len().min(8)],
            cfg.rng_seed,
            now_ts_secs()
        )
    });
    let prefix = format!("{base_prefix}-iter{}", cfg.iters);
    let corpus_path = cfg.out_dir.join(format!("{prefix}-corpus.jsonl"));
    let bugs_path = cfg.out_dir.join(format!("{prefix}-bugs.jsonl"));
    let runs_path = cfg.out_dir.join(format!("{prefix}-runs.jsonl"));

    let corpus_writer = JsonlWriter::open_append(&corpus_path)?;
    let bug_writer = JsonlWriter::open_append(&bugs_path)?;
    let run_writer = JsonlWriter::open_append(&runs_path)?;

    // --- Policy setup ---
    let policy: Arc<Mutex<dyn PolicyProvider>> = match cfg.policy_type {
        PolicyType::Random => {
            Arc::new(Mutex::new(super::policy::RandomPolicy::new(SEED_MUTATOR_NUM_ARMS)))
        }
        PolicyType::Bandit => {
            Arc::new(Mutex::new(super::bandit::BanditPolicy::new(SEED_MUTATOR_NUM_ARMS)))
        }
        PolicyType::LinUCB => {
            let feature_dim = 15.min(FuzzerState::default().to_feature_vec().len());
            Arc::new(Mutex::new(super::linucb::LinUCBPolicy::new(
                SEED_MUTATOR_NUM_ARMS,
                feature_dim,
                1.5,
            )))
        }
        PolicyType::External => {
            let sock = cfg.rl_socket_path.clone()
                .unwrap_or_else(|| PathBuf::from("/tmp/beak-rl.sock"));
            Arc::new(Mutex::new(super::external_policy::ExternalPolicy::new(
                sock,
                cfg.rl_fallback_timeout_ms.max(50),
                SEED_MUTATOR_NUM_ARMS,
            )))
        }
    };
    let fuzzer_state_shared: Arc<Mutex<FuzzerState>> = Arc::new(Mutex::new(FuzzerState::default()));

    eprintln!("[LOOP1] policy={}", cfg.policy_type);

    // Optional metrics writer.
    let metrics_writer = if cfg.metrics_interval > 0 {
        let metrics_path = cfg.out_dir.join(format!("{prefix}-metrics.jsonl"));
        Some(JsonlWriter::open_append(&metrics_path)?)
    } else {
        None
    };

    // --- libAFL setup ---
    let rand = StdRand::with_seed(cfg.rng_seed);
    let corpus = InMemoryCorpus::<BytesInput>::new();
    let solutions = InMemoryCorpus::<BytesInput>::new();

    let feedback = BucketNoveltyFeedback::new(
        corpus_writer.clone(), bug_writer.clone(), run_writer.clone(), cfg.clone(),
    )
    .with_policy(Arc::clone(&policy), Arc::clone(&fuzzer_state_shared));
    let mut feedback = if let Some(mw) = metrics_writer {
        feedback.with_metrics_writer(mw)
    } else {
        feedback
    };
    let mut objective = NeverObjective::new();
    let mut state: LoopState =
        StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
            .map_err(|e| format!("create state failed: {e}"))?;

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

    // Initialize legacy bandit as well (for backward compat in feedback path).
    bandit::init(SEED_MUTATOR_NUM_ARMS);

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let monitor = SimpleMonitor::new(|_s| {});
    let mut mgr = SimpleEventManager::new(monitor);
    let mut resolved_direct_buckets: HashSet<String> = HashSet::new();
    let mut eval_id_counter: u64 = 0;

    // Executor harness: run backend execution, collect trace/eval, and compare regs.
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let mut harness = |input: &BytesInput| -> ExitKind {
        eval_id_counter = eval_id_counter.saturating_add(1);
        let eval_id = eval_id_counter;
        let words = decode_words_from_input(input, cfg.max_instructions);
        if !backend.is_usable_seed(&words)
            || words.iter().any(|w| RV32IMInstruction::from_word(*w).is_err())
        {
            let mut last = LAST_RUN.lock().unwrap();
            *last = RunStats {
                eval_id,
                skip_reason: Some("invalid_or_unusable_seed".to_string()),
                ..RunStats::default()
            };
            return ExitKind::Ok;
        }
        if cfg.precheck_oracle_max_steps > 0 {
            let pre = RISCVOracle::execute_with_step_limit(&words, cfg.oracle, cfg.precheck_oracle_max_steps);
            if pre.hit_step_limit {
                eprintln!(
                    "[LOOP1][WARN] skip seed: oracle precheck hit step limit (steps={} limit={} words={})",
                    pre.steps,
                    cfg.precheck_oracle_max_steps,
                    words.len()
                );
                let mut last = LAST_RUN.lock().unwrap();
                *last = RunStats {
                    eval_id,
                    skip_reason: Some("oracle_precheck_step_limit".to_string()),
                    ..RunStats::default()
                };
                return ExitKind::Ok;
            }
        }

        backend.clear_direct_injection();
        let baseline = eval_once(&cfg, timeout, &mut backend, &words);
        let mut final_stats = baseline.clone();

        if cfg.chain_direct_injection {
            // De-duplicate and deterministically order target buckets so replay order is stable.
            let mut target_buckets: Vec<String> = baseline
                .bucket_hits
                .iter()
                .filter(|h| backend.bucket_has_direct_injection(&h.bucket_id))
                .filter(|h| !resolved_direct_buckets.contains(&h.bucket_id))
                .map(|h| h.bucket_id.clone())
                .collect();
            target_buckets.sort();
            target_buckets.dedup();

            if !target_buckets.is_empty() {
                final_stats.has_direct_injection_target = true;
                final_stats.target_buckets = target_buckets.clone();

                let mut best_injected: Option<RunStats> = None;
                for bucket_id in &target_buckets {
                    let filtered_hits: Vec<BucketHit> = baseline
                        .bucket_hits
                        .iter()
                        .filter(|h| h.bucket_id == *bucket_id)
                        .cloned()
                        .collect();
                    if filtered_hits.is_empty() {
                        continue;
                    }

                    backend.clear_direct_injection();
                    let Some(inject_kind) = backend.arm_direct_injection_from_hits(&filtered_hits) else {
                        continue;
                    };

                    let mut injected = eval_once(&cfg, timeout, &mut backend, &words);
                    injected.has_direct_injection_target = true;
                    injected.injected_phase = true;
                    injected.direct_injection_kind = Some(inject_kind);
                    injected.target_buckets = vec![bucket_id.clone()];
                    injected.baseline_bucket_hits_sig = Some(baseline.bucket_hits_sig.clone());
                    injected.underconstrained_candidate =
                        baseline.backend_error.is_none()
                            && baseline.oracle_error.is_none()
                            && injected.backend_error.is_none()
                            && injected.oracle_error.is_none();

                    if injected.underconstrained_candidate {
                        // Mark resolved only for true underconstrained signals.
                        // mismatch/exception/timeout are intentionally not resolved.
                        resolved_direct_buckets.insert(bucket_id.clone());
                    }

                    let rank = |s: &RunStats| -> u8 {
                        if s.underconstrained_candidate {
                            5
                        } else if !s.mismatch_regs.is_empty() {
                            4
                        } else if s.backend_error.is_some() || s.oracle_error.is_some() {
                            3
                        } else if s.timed_out {
                            2
                        } else {
                            0
                        }
                    };
                    let replace = match best_injected.as_ref() {
                        None => true,
                        Some(prev) => rank(&injected) > rank(prev),
                    };
                    if replace {
                        best_injected = Some(injected);
                    }
                }

                if let Some(injected) = best_injected {
                    final_stats = injected;
                }
            }
        }
        backend.clear_direct_injection();
        final_stats.eval_id = eval_id;

        let mut last = LAST_RUN.lock().unwrap();
        *last = final_stats;

        // We treat timeouts as a *soft* signal (recorded in `RunStats`) and do not propagate
        // `ExitKind::Timeout` to libAFL, as it may short-circuit feedback/corpus logic on some
        // platforms. The in-process hard timeout is handled separately.
        ExitKind::Ok
    };

    // IMPORTANT: libAFL hard timeout on macOS may terminate the whole process (Error 55).
    // Keep hard timeout large as a safety net only; use cfg.timeout_ms as the soft timeout
    // signal recorded in corpus/bug metadata so fuzzing can continue across slow inputs.
    let inproc_hard_timeout = Duration::from_secs(10 * 60);

    let observers = tuple_list!();
    let mut executor = InProcessExecutor::with_timeout::<NeverObjective>(
        &mut harness,
        observers,
        &mut fuzzer,
        &mut state,
        &mut mgr,
        inproc_hard_timeout,
    )
    .map_err(|e| format!("create executor failed: {e}"))?;

    let mut mutator = SeedMutator::with_policy(
        cfg.max_instructions,
        Arc::clone(&policy),
        Arc::clone(&fuzzer_state_shared),
    );

    let initial_count = state.corpus().count();
    for idx in 0..initial_count {
        eprintln!(
            "[LOOP1][initial {}/{}] evaluating seed corpus entry",
            idx + 1,
            initial_count
        );
        let id = CorpusId::from(idx);
        let Ok(tc_cell) = state.corpus().get(id) else { continue };
        let tc = tc_cell.borrow();
        let Some(input) = tc.input().as_ref().cloned() else { continue };
        drop(tc);
        let _ = fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, &input);
    }

    // 1 iter = 1 mutation + 1 execution (not libAFL's default 1-128 per fuzz_one).
    for i in 0..cfg.iters {
        let corpus_count = state.corpus().count();
        if corpus_count == 0 {
            break;
        }
        let pick = state.rand_mut().below(NonZeroUsize::new(corpus_count).unwrap());
        let id = CorpusId::from(pick);
        let mut input = {
            let Ok(tc_cell) = state.corpus().get(id) else { continue };
            let tc = tc_cell.borrow();
            tc.input().as_ref().cloned().unwrap_or_else(|| BytesInput::new(vec![]))
        };
        let _ = mutator.mutate(&mut state, &mut input);

        let _ = fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, &input);
        let s = LAST_RUN.lock().unwrap().clone();
        let kind = if s.underconstrained_candidate {
            "underconstrained_candidate"
        } else if !s.mismatch_regs.is_empty() {
            "mismatch"
        } else if s.timed_out || s.backend_error.is_some() || s.oracle_error.is_some() {
            "exception"
        } else if s.skip_reason.is_some() {
            "skip"
        } else {
            "ok"
        };
        eprintln!(
            "[LOOP1][iter {}/{}] eval_id={} kind={} mismatches={} timed_out={} sig={}",
            i + 1,
            cfg.iters,
            s.eval_id,
            kind,
            s.mismatch_regs.len(),
            s.timed_out,
            s.bucket_hits_sig
        );
    }

    corpus_writer.flush()?;
    bug_writer.flush()?;
    run_writer.flush()?;

    Ok(Loop1Outputs {
        corpus_path,
        bugs_path,
        runs_path: Some(runs_path),
    })
}
