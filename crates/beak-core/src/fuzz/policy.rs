use serde::{Deserialize, Serialize};

use crate::rv32im::instruction::RV32IMInstruction;

/// Instruction format indices used in `SeedFeatures::type_distribution`.
/// Order: R=0, I=1, S=2, B=3, U=4, J=5
const FORMAT_COUNT: usize = 6;

fn classify_mnemonic(m: &str) -> usize {
    match m {
        "add" | "sub" | "sll" | "slt" | "sltu" | "xor" | "srl" | "sra" | "or" | "and"
        | "mul" | "mulh" | "mulhsu" | "mulhu" | "div" | "divu" | "rem" | "remu" => 0,
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai"
        | "lb" | "lh" | "lw" | "lbu" | "lhu" | "jalr" | "ecall" | "ebreak" => 1,
        "sb" | "sh" | "sw" => 2,
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => 3,
        "lui" | "auipc" => 4,
        "jal" => 5,
        _ => 1,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedFeatures {
    pub instruction_count: usize,
    /// Distribution of instruction formats: [R, I, S, B, U, J], normalized to [0, 1].
    pub type_distribution: [f32; FORMAT_COUNT],
    pub bucket_hit_count: usize,
}

impl Default for SeedFeatures {
    fn default() -> Self {
        Self {
            instruction_count: 0,
            type_distribution: [0.0; FORMAT_COUNT],
            bucket_hit_count: 0,
        }
    }
}

impl SeedFeatures {
    pub fn from_words(words: &[u32]) -> Self {
        let mut counts = [0u32; FORMAT_COUNT];
        for &w in words {
            if let Ok(insn) = RV32IMInstruction::from_word(w) {
                let idx = classify_mnemonic(&insn.mnemonic);
                counts[idx] += 1;
            }
        }
        let total = words.len().max(1) as f32;
        let mut dist = [0.0f32; FORMAT_COUNT];
        for i in 0..FORMAT_COUNT {
            dist[i] = counts[i] as f32 / total;
        }
        Self {
            instruction_count: words.len(),
            type_distribution: dist,
            bucket_hit_count: 0,
        }
    }
}

/// Observable state of the fuzzer at decision time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerState {
    pub corpus_size: usize,
    pub unique_bucket_ids: usize,
    pub unique_signatures: usize,
    pub iteration: u64,
    pub time_since_last_novel: u64,
    /// Per-arm windowed mean reward (length = num_arms).
    pub recent_arm_rewards: Vec<f64>,
    pub seed_features: SeedFeatures,
    pub cumulative_reward: f64,
    pub bug_count: usize,
}

impl Default for FuzzerState {
    fn default() -> Self {
        Self {
            corpus_size: 0,
            unique_bucket_ids: 0,
            unique_signatures: 0,
            iteration: 0,
            time_since_last_novel: 0,
            recent_arm_rewards: Vec::new(),
            seed_features: SeedFeatures::default(),
            cumulative_reward: 0.0,
            bug_count: 0,
        }
    }
}

impl FuzzerState {
    /// Flatten into a fixed-size feature vector for RL consumption.
    /// Layout: [corpus_size, unique_bucket_ids, unique_signatures, iteration,
    ///          time_since_last_novel, cumulative_reward, bug_count,
    ///          seed.instruction_count, seed.bucket_hit_count,
    ///          seed.type_dist[0..6], recent_arm_rewards[0..N]]
    pub fn to_feature_vec(&self) -> Vec<f64> {
        let mut v = Vec::with_capacity(32);
        v.push(self.corpus_size as f64);
        v.push(self.unique_bucket_ids as f64);
        v.push(self.unique_signatures as f64);
        v.push(self.iteration as f64);
        v.push(self.time_since_last_novel as f64);
        v.push(self.cumulative_reward);
        v.push(self.bug_count as f64);
        v.push(self.seed_features.instruction_count as f64);
        v.push(self.seed_features.bucket_hit_count as f64);
        for &d in &self.seed_features.type_distribution {
            v.push(d as f64);
        }
        for &r in &self.recent_arm_rewards {
            v.push(r);
        }
        v
    }
}

/// Describes a semantic injection candidate for RL-driven selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionCandidate {
    pub bucket_id: String,
    pub semantic_class: String,
    pub inject_kind: String,
    pub attempted_steps: usize,
    pub best_step_so_far: Option<u64>,
}

/// Policy type selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyType {
    Random,
    Bandit,
    LinUCB,
    External,
}

impl std::str::FromStr for PolicyType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "random" | "uniform" => Ok(Self::Random),
            "bandit" | "ucb1" => Ok(Self::Bandit),
            "linucb" | "contextual" => Ok(Self::LinUCB),
            "rl" | "external" | "ppo" | "dqn" => Ok(Self::External),
            _ => Err(format!("unknown policy type: {s}")),
        }
    }
}

impl std::fmt::Display for PolicyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyType::Random => write!(f, "random"),
            PolicyType::Bandit => write!(f, "bandit"),
            PolicyType::LinUCB => write!(f, "linucb"),
            PolicyType::External => write!(f, "external"),
        }
    }
}

/// Core trait for all policy implementations.
///
/// A policy decides which mutation operator to apply (`select_mutator`),
/// which seed to fuzz next (`select_seed`), and optionally which semantic
/// injection step to try (`select_injection_step`).
///
/// The `random_seed` parameter provides a source of randomness without
/// requiring generic Rand bounds (which would prevent dyn dispatch).
pub trait PolicyProvider: Send {
    fn name(&self) -> &str;

    fn select_mutator(&mut self, state: &FuzzerState, random_seed: u64) -> usize;

    fn update_mutator(&mut self, arm: usize, reward: f64, state: &FuzzerState);

    /// Select which corpus entry to fuzz next. Returns an index in [0, corpus_size).
    fn select_seed(&mut self, state: &FuzzerState, corpus_size: usize, random_seed: u64) -> usize {
        if corpus_size == 0 {
            return 0;
        }
        let _ = state;
        (random_seed as usize) % corpus_size
    }

    /// Select which injection candidate and step to try.
    /// Returns `Some((candidate_index, step))` or `None` to skip.
    fn select_injection_step(
        &mut self,
        _state: &FuzzerState,
        _candidates: &[InjectionCandidate],
    ) -> Option<(usize, u64)> {
        None
    }

    /// Called when an injection attempt completes with a result.
    fn update_injection(&mut self, _candidate_idx: usize, _step: u64, _reward: f64) {}

    /// Per-arm pull counts (for metrics/logging).
    fn arm_pulls(&self) -> Vec<u64> {
        Vec::new()
    }

    /// Per-arm mean rewards (for metrics/logging).
    fn arm_mean_rewards(&self) -> Vec<f64> {
        Vec::new()
    }
}

/// Uniform random policy — no learning, no strategy, pure baseline.
pub struct RandomPolicy {
    num_arms: usize,
    pulls: Vec<u64>,
}

impl RandomPolicy {
    pub fn new(num_arms: usize) -> Self {
        Self {
            num_arms,
            pulls: vec![0; num_arms],
        }
    }
}

impl PolicyProvider for RandomPolicy {
    fn name(&self) -> &str {
        "random"
    }

    fn select_mutator(&mut self, _state: &FuzzerState, random_seed: u64) -> usize {
        let arm = (random_seed as usize) % self.num_arms;
        self.pulls[arm] += 1;
        arm
    }

    fn update_mutator(&mut self, _arm: usize, _reward: f64, _state: &FuzzerState) {}

    fn arm_pulls(&self) -> Vec<u64> {
        self.pulls.clone()
    }
}

/// Metrics snapshot emitted by the fuzzer for evaluation/visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsRecord {
    pub iteration: u64,
    pub wall_time_sec: f64,
    pub corpus_size: usize,
    pub unique_bucket_ids: usize,
    pub unique_signatures: usize,
    pub bug_count: usize,
    pub policy_type: String,
    pub arm_pulls: Vec<u64>,
    pub arm_rewards_mean: Vec<f64>,
    pub recent_reward_100: f64,
    pub time_since_last_novel: u64,
    pub cumulative_reward: f64,
}

/// Windowed reward tracker for per-arm statistics.
#[derive(Debug, Clone)]
pub struct RewardWindow {
    window_size: usize,
    per_arm: Vec<std::collections::VecDeque<f64>>,
}

impl RewardWindow {
    pub fn new(num_arms: usize, window_size: usize) -> Self {
        Self {
            window_size,
            per_arm: (0..num_arms)
                .map(|_| std::collections::VecDeque::with_capacity(window_size))
                .collect(),
        }
    }

    pub fn push(&mut self, arm: usize, reward: f64) {
        if arm >= self.per_arm.len() {
            return;
        }
        let q = &mut self.per_arm[arm];
        if q.len() >= self.window_size {
            q.pop_front();
        }
        q.push_back(reward);
    }

    pub fn mean(&self, arm: usize) -> f64 {
        if arm >= self.per_arm.len() {
            return 0.0;
        }
        let q = &self.per_arm[arm];
        if q.is_empty() {
            return 0.0;
        }
        q.iter().sum::<f64>() / q.len() as f64
    }

    pub fn means(&self) -> Vec<f64> {
        (0..self.per_arm.len()).map(|i| self.mean(i)).collect()
    }

    pub fn overall_recent_mean(&self) -> f64 {
        let total: f64 = self.per_arm.iter().flat_map(|q| q.iter()).sum();
        let count: usize = self.per_arm.iter().map(|q| q.len()).sum();
        if count == 0 {
            0.0
        } else {
            total / count as f64
        }
    }
}
