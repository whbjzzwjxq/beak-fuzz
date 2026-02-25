use std::fs::{File, OpenOptions};
use std::io::{LineWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::trace::BucketHit;

#[derive(Debug, Clone, Serialize)]
pub struct CorpusRecord {
    pub zkvm_commit: String,
    pub rng_seed: u64,
    pub timeout_ms: u64,
    pub timed_out: bool,
    pub mismatch: bool,
    /// Canonical bucket signature for this run (backend-defined or derived from bucket hit signatures).
    pub bucket_hits_sig: String,
    pub instructions: Vec<u32>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct BugRecord {
    pub zkvm_commit: String,
    pub rng_seed: u64,
    pub timeout_ms: u64,
    pub timed_out: bool,
    /// Canonical bucket signature for this run (backend-defined or derived from bucket hit signatures).
    pub bucket_hits_sig: String,
    /// Backend-defined trace size metric (see `BackendEval::micro_op_count`).
    pub micro_op_count: usize,
    pub backend_error: Option<String>,
    pub oracle_error: Option<String>,
    pub bucket_hits: Vec<BucketHit>,
    pub mismatch_regs: Vec<(u32, u32, u32)>, // (idx, oracle, backend)
    pub instructions: Vec<u32>,
    pub metadata: serde_json::Value,
}

#[derive(Clone)]
pub struct JsonlWriter {
    // LineWriter flushes on newline, so corpus/bugs entries appear even for long runs.
    inner: Arc<Mutex<LineWriter<File>>>,
}

impl JsonlWriter {
    pub fn open_append(path: &Path) -> Result<Self, String> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("open {} failed: {e}", path.display()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(LineWriter::new(f))),
        })
    }

    pub fn append_json_line<T: Serialize>(&self, value: &T) -> Result<(), String> {
        let line = serde_json::to_string(value).map_err(|e| format!("json encode failed: {e}"))?;
        let mut w = self.inner.lock().map_err(|_| "writer mutex poisoned".to_string())?;
        writeln!(w, "{line}").map_err(|e| format!("write jsonl failed: {e}"))?;
        Ok(())
    }

    pub fn flush(&self) -> Result<(), String> {
        let mut w = self.inner.lock().map_err(|_| "writer mutex poisoned".to_string())?;
        w.flush().map_err(|e| format!("flush failed: {e}"))?;
        Ok(())
    }
}

