pub mod observations;
pub mod semantic;
pub mod semantic_matchers;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const EMPTY_TRACE_SIGNALS: [TraceSignal; 0] = [];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceSignal {
    HasLoad,
    HasStore,
    HasAuipc,
    HasEcall,
    HasLoadStore,
    ObservedVolatileBoundaryRange,
}

impl TraceSignal {
    pub const fn id(self) -> &'static str {
        match self {
            Self::HasLoad => "signal.input.has_load",
            Self::HasStore => "signal.input.has_store",
            Self::HasAuipc => "signal.input.has_auipc",
            Self::HasEcall => "signal.input.has_ecall",
            Self::HasLoadStore => "signal.input.has_load_store",
            Self::ObservedVolatileBoundaryRange => {
                "signal.derived.observed_volatile_boundary_range"
            }
        }
    }

    pub fn by_id(id: &str) -> Option<Self> {
        match id {
            "signal.input.has_load" => Some(Self::HasLoad),
            "signal.input.has_store" => Some(Self::HasStore),
            "signal.input.has_auipc" => Some(Self::HasAuipc),
            "signal.input.has_ecall" => Some(Self::HasEcall),
            "signal.input.has_load_store" => Some(Self::HasLoadStore),
            "signal.derived.observed_volatile_boundary_range" => {
                Some(Self::ObservedVolatileBoundaryRange)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketHit {
    pub bucket_id: String,

    // The details of the bucket hit.
    // Never use this field for bucket matching and signature computation; it is only for reporting.
    pub details: HashMap<String, Value>,
}

impl BucketHit {
    pub fn semantic(bucket: semantic::SemanticBucket, details: HashMap<String, Value>) -> Self {
        Self { bucket_id: bucket.id.to_string(), details }
    }

    pub fn semantic_id(bucket_id: impl Into<String>, details: HashMap<String, Value>) -> Self {
        let bucket_id = bucket_id.into();
        assert!(
            semantic::by_id(&bucket_id).is_some(),
            "BucketHit must use a registered sem.* bucket id, got {bucket_id}"
        );
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

pub fn sorted_signatures_from_signals(signals: &[TraceSignal]) -> Vec<String> {
    let mut ordered: Vec<String> = signals.iter().map(|signal| signal.id().to_string()).collect();
    ordered.sort_unstable();
    ordered
}

/// Backend-provided trace representation for a single run.
///
/// The fuzz loop uses trace-derived bucket hits as feedback. The canonical signature list is
/// derived by taking *all* bucket hits, sorting by signature string, then mapping to strings.
pub trait Trace {
    /// Return semantic bucket hits for this run. Every id must be registered by `semantic::by_id`.
    fn bucket_hits(&self) -> &[BucketHit];

    /// Return non-semantic trace-level signals such as input features or synthetic probes.
    fn trace_signals(&self) -> &[TraceSignal] {
        &EMPTY_TRACE_SIGNALS
    }
}
