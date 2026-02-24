use std::num::NonZeroUsize;
use std::sync::{LazyLock, Mutex};

use libafl_bolts::rands::Rand;

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
struct Bandit {
    arms: Vec<BanditArmStats>,
    /// Exploration probability (epsilon-greedy). Keep small; UCB is the main driver.
    epsilon: f64,
    /// UCB exploration constant.
    ucb_c: f64,
}

impl Bandit {
    fn new(num_arms: usize) -> Self {
        Self {
            arms: (0..num_arms).map(|_| BanditArmStats::new()).collect(),
            epsilon: 0.05,
            ucb_c: 1.5,
        }
    }

    fn reset(&mut self, num_arms: usize) {
        *self = Self::new(num_arms);
    }

    fn select_arm<R: Rand>(&self, rand: &mut R) -> usize {
        let n = self.arms.len();
        if n == 0 {
            return 0;
        }

        // First, pull each arm at least once.
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

        // Epsilon-greedy exploration.
        // libafl_bolts::Rand doesn't expose f64 directly; approximate with u32.
        if self.epsilon > 0.0 {
            let roll = rand.below(nz(10_000));
            let threshold = (self.epsilon * 10_000.0) as usize;
            if roll < threshold {
                return rand.below(nz(n));
            }
        }

        // UCB1 selection.
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

    fn update(&mut self, arm_idx: usize, reward: f64) {
        if self.arms.is_empty() {
            return;
        }
        let i = arm_idx.min(self.arms.len() - 1);
        self.arms[i].pulls = self.arms[i].pulls.saturating_add(1);
        self.arms[i].total_reward += reward;
    }
}

static BANDIT: LazyLock<Mutex<Bandit>> = LazyLock::new(|| Mutex::new(Bandit::new(1)));

/// Last mutation arm used for the most recent execution.
///
/// This is written by the mutator and consumed by the feedback.
static LAST_ARM: LazyLock<Mutex<Option<usize>>> = LazyLock::new(|| Mutex::new(None));

pub fn init(num_arms: usize) {
    let mut b = BANDIT.lock().unwrap();
    b.reset(num_arms.max(1));
}

pub fn select_arm<R: Rand>(rand: &mut R) -> usize {
    let b = BANDIT.lock().unwrap();
    b.select_arm(rand)
}

pub fn update(arm_idx: usize, reward: f64) {
    let mut b = BANDIT.lock().unwrap();
    b.update(arm_idx, reward);
}

pub fn set_last_arm(arm_idx: usize) {
    *LAST_ARM.lock().unwrap() = Some(arm_idx);
}

pub fn take_last_arm() -> Option<usize> {
    LAST_ARM.lock().unwrap().take()
}

