use libafl_bolts::rands::Rand;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};

const NUM_ARMS: usize = 8;

static ARM_COUNTS: [AtomicUsize; NUM_ARMS] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

static ITER_COUNTER: AtomicUsize = AtomicUsize::new(0);

static BANDIT: LazyLock<Mutex<LinUcb>> =
    LazyLock::new(|| Mutex::new(LinUcb::new(NUM_ARMS, 7, 1.0)));

pub struct LinUcbArm {
    a_inv: Vec<f64>, // d × d
    b: Vec<f64>,     // d
}

pub struct LinUcb {
    arms: Vec<LinUcbArm>,
    d: usize,
    alpha: f64,
}

impl LinUcbArm {
    fn new(d: usize) -> Self {
        let mut a_inv = vec![0.0; d * d];

        for i in 0..d {
            a_inv[i * d + i] = 1.0; // identity
        }

        Self {
            a_inv,
            b: vec![0.0; d],
        }
    }
}

impl LinUcb {
    pub fn new(num_arms: usize, d: usize, alpha: f64) -> Self {
        let arms = (0..num_arms).map(|_| LinUcbArm::new(d)).collect();
        Self { arms, d, alpha }
    }

    pub fn select_arm<R: Rand>(&self, rand: &mut R, x: &[f64]) -> usize {
        assert_eq!(x.len(), self.d);

        const EPSILON: f64 = 0.1;

        let r = (rand.next() as f64) / (u64::MAX as f64);

        if r < EPSILON {
            return (rand.next() as usize) % self.arms.len();
        }

        let mut best_arm = 0;
        let mut best_score = f64::NEG_INFINITY;

        for (i, arm) in self.arms.iter().enumerate() {

            // θ = A_inv * b
            let theta = mat_vec_mul(&arm.a_inv, &arm.b, self.d);

            let exploit = dot(&theta, x);

            // exploration
            let tmp = mat_vec_mul(&arm.a_inv, x, self.d);
            let explore = dot(x, &tmp).sqrt();

            let score = exploit + self.alpha * explore;

            if score > best_score {
                best_score = score;
                best_arm = i;
            }
        }

        best_arm
    }

    pub fn update(&mut self, arm_id: usize, x: &[f64], reward: f64) {
        let arm = &mut self.arms[arm_id];
        let d = self.d;

        // A_inv * x
        let a_inv_x = mat_vec_mul(&arm.a_inv, x, d);

        // x^T * A_inv * x
        let denom = 1.0 + dot(x, &a_inv_x);

        // Sherman–Morrison update
        for i in 0..d {
            for j in 0..d {
                arm.a_inv[i * d + j] -= (a_inv_x[i] * a_inv_x[j]) / denom;
            }
        }

        // update b
        for i in 0..d {
            arm.b[i] += reward * x[i];
        }
    }
}

pub fn select_arm<R: Rand>(rand: &mut R, ctx: &[f64]) -> usize {
    let bandit = BANDIT.lock().unwrap();

    let arm = bandit.select_arm(rand, ctx);

    ARM_COUNTS[arm].fetch_add(1, Ordering::Relaxed);

    arm
}

pub fn update(arm: usize, ctx: &[f64], reward: f64) {
    let mut bandit = BANDIT.lock().unwrap();
    bandit.update(arm, ctx, reward);
}

pub fn diagnostic_tick() {
    let iter = ITER_COUNTER.fetch_add(1, Ordering::Relaxed);

    if iter % 100 == 0 {
        let counts: Vec<usize> =
            ARM_COUNTS.iter().map(|c| c.load(Ordering::Relaxed)).collect();

        println!("Bandit arm distribution: {:?}", counts);
    }
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn mat_vec_mul(a: &[f64], x: &[f64], d: usize) -> Vec<f64> {
    let mut out = vec![0.0; d];

    for i in 0..d {
        for j in 0..d {
            out[i] += a[i * d + j] * x[j];
        }
    }

    out
}
