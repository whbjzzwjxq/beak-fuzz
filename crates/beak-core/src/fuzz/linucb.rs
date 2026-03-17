use super::policy::{FuzzerState, PolicyProvider};

fn splitmix(seed: u64, index: u64) -> u64 {
    let mut z = seed.wrapping_add(index.wrapping_mul(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// LinUCB contextual bandit implementation.
///
/// Each arm maintains a d x d matrix A and d-dimensional vector b.
/// Selection: argmax_a (theta_a^T * x + alpha * sqrt(x^T * A_a^{-1} * x))
/// where theta_a = A_a^{-1} * b_a.
///
/// Uses a simplified dense representation suitable for the small feature
/// dimensions (~20) in this fuzzing context.
#[derive(Debug, Clone)]
pub struct LinUCBPolicy {
    num_arms: usize,
    dim: usize,
    alpha: f64,
    epsilon: f64,
    /// Per-arm: flattened d x d matrix A (row-major).
    a_matrices: Vec<Vec<f64>>,
    /// Per-arm: d-dimensional vector b.
    b_vectors: Vec<Vec<f64>>,
    pulls: Vec<u64>,
    total_rewards: Vec<f64>,
}

impl LinUCBPolicy {
    pub fn new(num_arms: usize, feature_dim: usize, alpha: f64) -> Self {
        let mut a_matrices = Vec::with_capacity(num_arms);
        let b_vectors: Vec<Vec<f64>> = (0..num_arms)
            .map(|_| vec![0.0; feature_dim])
            .collect();

        for _ in 0..num_arms {
            let mut a = vec![0.0; feature_dim * feature_dim];
            for i in 0..feature_dim {
                a[i * feature_dim + i] = 1.0;
            }
            a_matrices.push(a);
        }

        Self {
            num_arms,
            dim: feature_dim,
            alpha,
            epsilon: 0.05,
            a_matrices,
            b_vectors,
            pulls: vec![0; num_arms],
            total_rewards: vec![0.0; num_arms],
        }
    }

    fn normalize_features(state: &FuzzerState) -> Vec<f64> {
        let raw = state.to_feature_vec();
        let max_vals: Vec<f64> = vec![
            10000.0, // corpus_size
            500.0,   // unique_bucket_ids
            10000.0, // unique_signatures
            100000.0,// iteration
            10000.0, // time_since_last_novel
            10000.0, // cumulative_reward
            100.0,   // bug_count
            256.0,   // instruction_count
            100.0,   // bucket_hit_count
            1.0, 1.0, 1.0, 1.0, 1.0, 1.0, // type_distribution (already [0,1])
        ];

        raw.iter()
            .enumerate()
            .map(|(i, &v)| {
                let cap = if i < max_vals.len() { max_vals[i] } else { 1.0 };
                (v / cap).min(1.0).max(-1.0)
            })
            .collect()
    }

    /// Solve A * theta = b for theta using Cholesky-like approach.
    /// Falls back to regularized pseudoinverse for numerical stability.
    fn solve_linear(&self, arm: usize) -> Vec<f64> {
        let d = self.dim;
        let a = &self.a_matrices[arm];
        let b = &self.b_vectors[arm];

        // Simple iterative solve via (A + lambda*I)^{-1} * b using Gauss-Jordan.
        let mut aug = vec![0.0; d * (d + 1)];
        for i in 0..d {
            for j in 0..d {
                aug[i * (d + 1) + j] = a[i * d + j];
            }
            aug[i * (d + 1) + d] = b[i];
        }

        for col in 0..d {
            let mut max_row = col;
            let mut max_val = aug[col * (d + 1) + col].abs();
            for row in (col + 1)..d {
                let v = aug[row * (d + 1) + col].abs();
                if v > max_val {
                    max_val = v;
                    max_row = row;
                }
            }

            if max_val < 1e-12 {
                continue;
            }

            if max_row != col {
                for k in 0..=(d) {
                    let tmp = aug[col * (d + 1) + k];
                    aug[col * (d + 1) + k] = aug[max_row * (d + 1) + k];
                    aug[max_row * (d + 1) + k] = tmp;
                }
            }

            let pivot = aug[col * (d + 1) + col];
            for k in col..=(d) {
                aug[col * (d + 1) + k] /= pivot;
            }

            for row in 0..d {
                if row == col {
                    continue;
                }
                let factor = aug[row * (d + 1) + col];
                for k in col..=(d) {
                    aug[row * (d + 1) + k] -= factor * aug[col * (d + 1) + k];
                }
            }
        }

        (0..d).map(|i| aug[i * (d + 1) + d]).collect()
    }

    /// Compute x^T * A^{-1} * x. We approximate by solving A * z = x, then dot(x, z).
    fn quadratic_form_inv(&self, arm: usize, x: &[f64]) -> f64 {
        let d = self.dim;
        let a = &self.a_matrices[arm];

        let mut aug = vec![0.0; d * (d + 1)];
        for i in 0..d {
            for j in 0..d {
                aug[i * (d + 1) + j] = a[i * d + j];
            }
            aug[i * (d + 1) + d] = x[i];
        }

        for col in 0..d {
            let mut max_row = col;
            let mut max_val = aug[col * (d + 1) + col].abs();
            for row in (col + 1)..d {
                let v = aug[row * (d + 1) + col].abs();
                if v > max_val {
                    max_val = v;
                    max_row = row;
                }
            }
            if max_val < 1e-12 {
                continue;
            }
            if max_row != col {
                for k in 0..=(d) {
                    let tmp = aug[col * (d + 1) + k];
                    aug[col * (d + 1) + k] = aug[max_row * (d + 1) + k];
                    aug[max_row * (d + 1) + k] = tmp;
                }
            }
            let pivot = aug[col * (d + 1) + col];
            for k in col..=(d) {
                aug[col * (d + 1) + k] /= pivot;
            }
            for row in 0..d {
                if row == col {
                    continue;
                }
                let factor = aug[row * (d + 1) + col];
                for k in col..=(d) {
                    aug[row * (d + 1) + k] -= factor * aug[col * (d + 1) + k];
                }
            }
        }

        let z: Vec<f64> = (0..d).map(|i| aug[i * (d + 1) + d]).collect();
        x.iter().zip(z.iter()).map(|(&a, &b)| a * b).sum::<f64>().max(0.0)
    }
}

impl PolicyProvider for LinUCBPolicy {
    fn name(&self) -> &str {
        "linucb"
    }

    fn select_mutator(&mut self, state: &FuzzerState, random_seed: u64) -> usize {
        if self.num_arms == 0 {
            return 0;
        }

        if self.epsilon > 0.0 {
            let roll = (splitmix(random_seed, 0) % 10_000) as usize;
            let threshold = (self.epsilon * 10_000.0) as usize;
            if roll < threshold {
                return (splitmix(random_seed, 1) as usize) % self.num_arms;
            }
        }

        let x = Self::normalize_features(state);
        let x = if x.len() >= self.dim {
            &x[..self.dim]
        } else {
            return (splitmix(random_seed, 2) as usize) % self.num_arms;
        };

        let mut best_arm = 0usize;
        let mut best_score = f64::NEG_INFINITY;

        for arm in 0..self.num_arms {
            let theta = self.solve_linear(arm);
            let mean: f64 = theta.iter().zip(x.iter()).map(|(&t, &xi)| t * xi).sum();
            let uncertainty = self.quadratic_form_inv(arm, x).sqrt();
            let score = mean + self.alpha * uncertainty;
            if score > best_score {
                best_score = score;
                best_arm = arm;
            }
        }

        best_arm
    }

    fn update_mutator(&mut self, arm: usize, reward: f64, state: &FuzzerState) {
        if arm >= self.num_arms {
            return;
        }

        let x = Self::normalize_features(state);
        let x = if x.len() >= self.dim {
            &x[..self.dim]
        } else {
            return;
        };

        let d = self.dim;

        // A_arm += x * x^T
        for i in 0..d {
            for j in 0..d {
                self.a_matrices[arm][i * d + j] += x[i] * x[j];
            }
        }

        // b_arm += reward * x
        for i in 0..d {
            self.b_vectors[arm][i] += reward * x[i];
        }

        self.pulls[arm] = self.pulls[arm].saturating_add(1);
        self.total_rewards[arm] += reward;
    }

    fn arm_pulls(&self) -> Vec<u64> {
        self.pulls.clone()
    }

    fn arm_mean_rewards(&self) -> Vec<f64> {
        self.pulls
            .iter()
            .zip(self.total_rewards.iter())
            .map(|(&p, &r)| if p == 0 { 0.0 } else { r / p as f64 })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linucb_basic_learning() {
        let mut policy = LinUCBPolicy::new(3, 15, 1.5);
        let state = FuzzerState::default();

        for i in 0u64..100 {
            let arm = policy.select_mutator(&state, i * 1000);
            let reward = if arm == 0 { 1.0 } else { 0.0 };
            policy.update_mutator(arm, reward, &state);
        }

        let mut counts = [0u32; 3];
        for i in 0u64..100 {
            let arm = policy.select_mutator(&state, 200_000 + i);
            counts[arm] += 1;
            policy.update_mutator(arm, if arm == 0 { 1.0 } else { 0.0 }, &state);
        }
        assert!(counts[0] > counts[1] && counts[0] > counts[2]);
    }
}
