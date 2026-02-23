use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Cross-backend bucket categories used for trace-derived feedback.
///
/// Ordering is meaningful: fuzzing feedback must sort `BucketHit`s by `BucketType` order
/// (enum declaration order) before converting them into signature strings.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum BucketType {
    /// Placeholder bucket type until the cross-zkvm taxonomy is defined.
    Unknown = 0,
    // TODO: Define the full cross-zkvm bucket taxonomy here.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketHit {
    pub bucket_id: String,
    pub bucket_type: BucketType,

    // The details of the bucket hit.
    // Never use this field for bucket matching and signature computation; it is only for reporting.
    pub details: HashMap<String, Value>,
}

impl BucketHit {
    pub fn new(
        bucket_id: String,
        bucket_type: BucketType,
        details: HashMap<String, Value>,
    ) -> Self {
        Self { bucket_id, bucket_type, details }
    }

    pub fn signature(&self) -> &str {
        &self.bucket_id
    }
}

/// Derive a canonical `Vec<String>` of bucket signatures from all `BucketHit`s.
///
/// Contract:
/// - Includes *all* hits (no deduplication).
/// - Sorts deterministically by `BucketType` order, then by signature string.
/// - The resulting vector can be further canonicalized (e.g. dedup/sorted/joined) by the caller.
pub fn sorted_signatures_from_hits(hits: &[BucketHit]) -> Vec<String> {
    let mut ordered: Vec<&BucketHit> = hits.iter().collect();
    ordered.sort_unstable_by(|a, b| {
        a.bucket_type.cmp(&b.bucket_type).then_with(|| a.signature().cmp(b.signature()))
    });
    ordered.into_iter().map(|h| h.signature().to_string()).collect()
}

pub trait Bucket: Send + Sync {
    fn bucket_type(&self) -> BucketType;
}

/// Backend-provided trace representation for a single run.
///
/// The fuzz loop uses trace-derived bucket hits as feedback. The canonical signature list is
/// derived by taking *all* bucket hits, sorting by `BucketType` order (enum declaration order),
/// then mapping to signature strings.
pub trait Trace {
    /// Return *all* bucket hits for this run.
    fn bucket_hits(&self) -> &[BucketHit];
}
