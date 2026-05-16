use beak_core::trace::{BucketHit, Trace, TraceSignal};

#[derive(Debug, Clone, Default)]
pub struct JoltTrace {
    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,
}

impl JoltTrace {
    pub fn empty() -> Self {
        Self::default()
    }
}

impl Trace for JoltTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }

    fn trace_signals(&self) -> &[TraceSignal] {
        &self.trace_signals
    }
}
