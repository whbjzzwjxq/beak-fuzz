use crate::trace::bucket::{sorted_signatures_from_hits, BucketHit};

/// Backend-provided trace representation for a single run.
///
/// The fuzz loop uses trace-derived bucket hits as feedback. The canonical signature list is
/// derived by taking *all* bucket hits, sorting by `BucketType` order (enum declaration order),
/// then mapping to signature strings.
pub trait Trace {
    /// Return *all* bucket hits for this run.
    fn bucket_hits(&self) -> &[BucketHit];
}

/// A simple owned trace container suitable for backends that just want to return hits.
#[derive(Debug, Clone, Default)]
pub struct OwnedTrace {
    pub bucket_hits: Vec<BucketHit>,
}

impl Trace for OwnedTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }
}

/// Derive the canonical ordered signature vector from a trace.
pub fn sorted_bucket_signatures<T: Trace + ?Sized>(trace: &T) -> Vec<String> {
    sorted_signatures_from_hits(trace.bucket_hits())
}
