use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::bandit::BanditPolicy;
use super::policy::{FuzzerState, InjectionCandidate, PolicyProvider};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum Request<'a> {
    #[serde(rename = "select_mutator")]
    SelectMutator {
        state: &'a FuzzerState,
        request_id: u64,
    },
    #[serde(rename = "update_mutator")]
    UpdateMutator {
        arm: usize,
        reward: f64,
        state: &'a FuzzerState,
        request_id: u64,
    },
    #[serde(rename = "select_seed")]
    SelectSeed {
        state: &'a FuzzerState,
        corpus_size: usize,
        request_id: u64,
    },
    #[serde(rename = "select_injection")]
    SelectInjection {
        state: &'a FuzzerState,
        candidates: &'a [InjectionCandidate],
        request_id: u64,
    },
    #[serde(rename = "update_injection")]
    UpdateInjection {
        candidate_idx: usize,
        step: u64,
        reward: f64,
        request_id: u64,
    },
}

#[derive(Debug, Deserialize)]
struct ActionResponse {
    action: serde_json::Value,
    #[allow(dead_code)]
    request_id: u64,
}

#[derive(Debug, Deserialize)]
struct InjectionResponse {
    candidate_idx: Option<usize>,
    step: Option<u64>,
    #[allow(dead_code)]
    request_id: u64,
}

/// External RL policy that communicates with a Python agent via Unix domain socket.
///
/// Falls back to a BanditPolicy if the Python agent is unreachable or times out.
pub struct ExternalPolicy {
    socket_path: PathBuf,
    timeout: Duration,
    connection: Option<(BufReader<UnixStream>, UnixStream)>,
    fallback: BanditPolicy,
    fallback_count: u64,
    success_count: u64,
}

impl std::fmt::Debug for ExternalPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalPolicy")
            .field("socket_path", &self.socket_path)
            .field("timeout", &self.timeout)
            .field("connected", &self.connection.is_some())
            .field("fallback_count", &self.fallback_count)
            .field("success_count", &self.success_count)
            .finish()
    }
}

impl ExternalPolicy {
    pub fn new(socket_path: PathBuf, timeout_ms: u64, num_arms: usize) -> Self {
        Self {
            socket_path,
            timeout: Duration::from_millis(timeout_ms),
            connection: None,
            fallback: BanditPolicy::new(num_arms),
            fallback_count: 0,
            success_count: 0,
        }
    }

    fn ensure_connected(&mut self) -> bool {
        if self.connection.is_some() {
            return true;
        }
        match UnixStream::connect(&self.socket_path) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(self.timeout));
                let _ = stream.set_write_timeout(Some(self.timeout));
                let reader = BufReader::new(stream.try_clone().unwrap());
                self.connection = Some((reader, stream));
                true
            }
            Err(e) => {
                eprintln!("[ExternalPolicy] connect failed: {e}");
                false
            }
        }
    }

    fn send_recv(&mut self, payload: &str) -> Option<String> {
        if !self.ensure_connected() {
            return None;
        }

        let (reader, writer) = self.connection.as_mut().unwrap();

        if writeln!(writer, "{}", payload).is_err() {
            self.connection = None;
            return None;
        }
        if writer.flush().is_err() {
            self.connection = None;
            return None;
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => {
                self.connection = None;
                None
            }
            Ok(_) => Some(line),
        }
    }

    fn send_fire_and_forget(&mut self, payload: &str) {
        if !self.ensure_connected() {
            return;
        }
        let failed = {
            let (_, writer) = self.connection.as_mut().unwrap();
            let write_ok = writeln!(writer, "{}", payload).is_ok() && writer.flush().is_ok();
            !write_ok
        };
        if failed {
            self.connection = None;
            return;
        }
        // Read and discard ack.
        let mut buf = String::new();
        if let Some((reader, _)) = self.connection.as_mut() {
            let _ = reader.read_line(&mut buf);
        }
    }
}

impl PolicyProvider for ExternalPolicy {
    fn name(&self) -> &str {
        "external"
    }

    fn select_mutator(&mut self, state: &FuzzerState, random_seed: u64) -> usize {
        let req_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let req = Request::SelectMutator {
            state,
            request_id: req_id,
        };
        let payload = match serde_json::to_string(&req) {
            Ok(s) => s,
            Err(_) => {
                self.fallback_count += 1;
                return self.fallback.select_mutator(state, random_seed);
            }
        };

        match self.send_recv(&payload) {
            Some(resp_str) => {
                if let Ok(resp) = serde_json::from_str::<ActionResponse>(&resp_str) {
                    if let Some(action) = resp.action.as_u64() {
                        self.success_count += 1;
                        return action as usize;
                    }
                }
                self.fallback_count += 1;
                self.fallback.select_mutator(state, random_seed)
            }
            None => {
                self.fallback_count += 1;
                self.fallback.select_mutator(state, random_seed)
            }
        }
    }

    fn update_mutator(&mut self, arm: usize, reward: f64, state: &FuzzerState) {
        self.fallback.update_mutator(arm, reward, state);

        let req_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let req = Request::UpdateMutator {
            arm,
            reward,
            state,
            request_id: req_id,
        };
        if let Ok(payload) = serde_json::to_string(&req) {
            self.send_fire_and_forget(&payload);
        }
    }

    fn select_seed(&mut self, state: &FuzzerState, corpus_size: usize, random_seed: u64) -> usize {
        if corpus_size == 0 {
            return 0;
        }

        let req_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let req = Request::SelectSeed {
            state,
            corpus_size,
            request_id: req_id,
        };
        let payload = match serde_json::to_string(&req) {
            Ok(s) => s,
            Err(_) => return (random_seed as usize) % corpus_size,
        };

        match self.send_recv(&payload) {
            Some(resp_str) => {
                if let Ok(resp) = serde_json::from_str::<ActionResponse>(&resp_str) {
                    if let Some(idx) = resp.action.as_u64() {
                        let idx = idx as usize;
                        if idx < corpus_size {
                            return idx;
                        }
                    }
                }
                (random_seed as usize) % corpus_size
            }
            None => (random_seed as usize) % corpus_size,
        }
    }

    fn select_injection_step(
        &mut self,
        state: &FuzzerState,
        candidates: &[InjectionCandidate],
    ) -> Option<(usize, u64)> {
        if candidates.is_empty() {
            return None;
        }

        let req_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let req = Request::SelectInjection {
            state,
            candidates,
            request_id: req_id,
        };
        let payload = serde_json::to_string(&req).ok()?;

        let resp_str = self.send_recv(&payload)?;
        let resp: InjectionResponse = serde_json::from_str(&resp_str).ok()?;
        Some((resp.candidate_idx?, resp.step?))
    }

    fn update_injection(&mut self, candidate_idx: usize, step: u64, reward: f64) {
        let req_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let req = Request::UpdateInjection {
            candidate_idx,
            step,
            reward,
            request_id: req_id,
        };
        if let Ok(payload) = serde_json::to_string(&req) {
            self.send_fire_and_forget(&payload);
        }
    }

    fn arm_pulls(&self) -> Vec<u64> {
        self.fallback.arm_pulls()
    }

    fn arm_mean_rewards(&self) -> Vec<f64> {
        self.fallback.arm_mean_rewards()
    }
}
