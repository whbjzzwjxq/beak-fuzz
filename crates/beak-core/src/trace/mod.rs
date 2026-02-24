use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketHit {
    pub bucket_id: String,

    // The details of the bucket hit.
    // Never use this field for bucket matching and signature computation; it is only for reporting.
    pub details: HashMap<String, Value>,
}

impl BucketHit {
    pub fn new(bucket_id: String, details: HashMap<String, Value>) -> Self {
        Self { bucket_id, details }
    }

    pub fn signature(&self) -> &str {
        &self.bucket_id
    }
}

/// Derive a canonical `Vec<String>` of bucket signatures from all `BucketHit`s.
///
/// Contract:
/// - Includes *all* hits (no deduplication).
/// - Sorts deterministically by signature string.
/// - The resulting vector can be further canonicalized (e.g. dedup/sorted/joined) by the caller.
pub fn sorted_signatures_from_hits(hits: &[BucketHit]) -> Vec<String> {
    let mut ordered: Vec<&BucketHit> = hits.iter().collect();
    ordered.sort_unstable_by(|a, b| a.signature().cmp(b.signature()));
    ordered.into_iter().map(|h| h.signature().to_string()).collect()
}

/// Backend-provided trace representation for a single run.
///
/// The fuzz loop uses trace-derived bucket hits as feedback. The canonical signature list is
/// derived by taking *all* bucket hits, sorting by signature string, then mapping to strings.
pub trait Trace {
    /// Return *all* bucket hits for this run.
    fn bucket_hits(&self) -> &[BucketHit];
}
