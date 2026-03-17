use std::num::NonZeroUsize;
use std::sync::{LazyLock, Mutex};

use libafl_bolts::rands::Rand;

use super::policy::{FuzzerState, PolicyProvider};

/// Simple splitmix64-style hash for converting a u64 seed into pseudo-random values.
fn splitmix(seed: u64, index: u64) -> u64 {
    let mut z = seed.wrapping_add(index.wrapping_mul(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n.max(1)).unwrap()
}

#[derive(Debug, Clone)]
struct BanditArmStats {
    pulls: u64,
    total_reward: f64,
}

impl BanditArmStats {
    fn new() -> Self {
        Self { pulls: 0, total_reward: 0.0 }
    }

    fn mean_reward(&self) -> f64 {
        if self.pulls == 0 {
            0.0
        } else {
            self.total_reward / (self.pulls as f64)
        }
    }
}

#[derive(Debug, Clone)]
pub struct BanditPolicy {
    arms: Vec<BanditArmStats>,
    epsilon: f64,
    ucb_c: f64,
}

impl BanditPolicy {
    pub fn new(num_arms: usize) -> Self {
        Self {
            arms: (0..num_arms).map(|_| BanditArmStats::new()).collect(),
            epsilon: 0.05,
            ucb_c: 1.5,
        }
    }

    pub fn reset(&mut self, num_arms: usize) {
        *self = Self::new(num_arms);
    }

    fn select_arm_impl<R: Rand>(&self, rand: &mut R) -> usize {
        let n = self.arms.len();
        if n == 0 {
            return 0;
        }

        let unpulled: Vec<usize> = self
            .arms
            .iter()
            .enumerate()
            .filter_map(|(i, s)| if s.pulls == 0 { Some(i) } else { None })
            .collect();
        if !unpulled.is_empty() {
            let idx = rand.below(nz(unpulled.len()));
            return unpulled[idx];
        }

        if self.epsilon > 0.0 {
            let roll = rand.below(nz(10_000));
            let threshold = (self.epsilon * 10_000.0) as usize;
            if roll < threshold {
                return rand.below(nz(n));
            }
        }

        let total_pulls: u64 = self.arms.iter().map(|a| a.pulls).sum();
        let log_total = (total_pulls.max(1) as f64).ln();

        let mut best_i = 0usize;
        let mut best_score = f64::NEG_INFINITY;
        for (i, arm) in self.arms.iter().enumerate() {
            let mean = arm.mean_reward();
            let bonus = self.ucb_c * (log_total / (arm.pulls as f64)).sqrt();
            let score = mean + bonus;
            if score > best_score {
                best_score = score;
                best_i = i;
            }
        }
        best_i
    }

    fn update_impl(&mut self, arm_idx: usize, reward: f64) {
        if self.arms.is_empty() {
            return;
        }
        let i = arm_idx.min(self.arms.len() - 1);
        self.arms[i].pulls = self.arms[i].pulls.saturating_add(1);
        self.arms[i].total_reward += reward;
    }
}

impl PolicyProvider for BanditPolicy {
    fn name(&self) -> &str {
        "bandit"
    }

    fn select_mutator(&mut self, _state: &FuzzerState, random_seed: u64) -> usize {
        let n = self.arms.len();
        if n == 0 {
            return 0;
        }

        let unpulled: Vec<usize> = self
            .arms
            .iter()
            .enumerate()
            .filter_map(|(i, s)| if s.pulls == 0 { Some(i) } else { None })
            .collect();
        if !unpulled.is_empty() {
            return unpulled[(splitmix(random_seed, 0) as usize) % unpulled.len()];
        }

        if self.epsilon > 0.0 {
            let roll = (splitmix(random_seed, 1) % 10_000) as usize;
            let threshold = (self.epsilon * 10_000.0) as usize;
            if roll < threshold {
                return (splitmix(random_seed, 2) as usize) % n;
            }
        }

        let total_pulls: u64 = self.arms.iter().map(|a| a.pulls).sum();
        let log_total = (total_pulls.max(1) as f64).ln();

        let mut best_i = 0usize;
        let mut best_score = f64::NEG_INFINITY;
        for (i, arm) in self.arms.iter().enumerate() {
            let mean = arm.mean_reward();
            let bonus = self.ucb_c * (log_total / (arm.pulls as f64)).sqrt();
            let score = mean + bonus;
            if score > best_score {
                best_score = score;
                best_i = i;
            }
        }
        best_i
    }

    fn update_mutator(&mut self, arm: usize, reward: f64, _state: &FuzzerState) {
        self.update_impl(arm, reward);
    }

    fn arm_pulls(&self) -> Vec<u64> {
        self.arms.iter().map(|a| a.pulls).collect()
    }

    fn arm_mean_rewards(&self) -> Vec<f64> {
        self.arms.iter().map(|a| a.mean_reward()).collect()
    }
}

// ---------------------------------------------------------------------------
// Legacy global API (kept for backward compatibility during migration)
// ---------------------------------------------------------------------------

static BANDIT: LazyLock<Mutex<BanditPolicy>> = LazyLock::new(|| Mutex::new(BanditPolicy::new(1)));

static LAST_ARM: LazyLock<Mutex<Option<usize>>> = LazyLock::new(|| Mutex::new(None));

pub fn init(num_arms: usize) {
    let mut b = BANDIT.lock().unwrap();
    b.reset(num_arms.max(1));
}

pub fn select_arm<R: Rand>(rand: &mut R) -> usize {
    let b = BANDIT.lock().unwrap();
    b.select_arm_impl(rand)
}

pub fn update(arm_idx: usize, reward: f64) {
    let mut b = BANDIT.lock().unwrap();
    b.update_impl(arm_idx, reward);
}

pub fn set_last_arm(arm_idx: usize) {
    *LAST_ARM.lock().unwrap() = Some(arm_idx);
}

pub fn take_last_arm() -> Option<usize> {
    LAST_ARM.lock().unwrap().take()
}
