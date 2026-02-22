use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::trace::micro_ops::chip_row::ChipRow;
use crate::trace::micro_ops::insn::Insn;
use crate::trace::micro_ops::interaction::Interaction;
use crate::trace::micro_ops::trace::Trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BucketType {
    // TODO
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketHit {
    pub bucket_id: String,
    pub bucket_type: BucketType,

    // The global sequence indices of the core instructions, chip rows, and interactions that matched the bucket.
    // Never use this field for bucket matching and signature computation; it is only for reporting.
    pub core_instructions: Vec<usize>,
    pub core_chip_rows: Vec<usize>,
    pub core_interactions: Vec<usize>,

    // The details of the bucket hit.
    // Never use this field for bucket matching and signature computation; it is only for reporting.
    pub details: HashMap<String, Value>,
}

impl BucketHit {
    pub fn new(
        bucket_id: String,
        bucket_type: BucketType,
        core_instructions: Vec<usize>,
        core_chip_rows: Vec<usize>,
        core_interactions: Vec<usize>,
        details: HashMap<String, Value>,
    ) -> Self {
        Self {
            bucket_id,
            bucket_type,
            core_instructions,
            core_chip_rows,
            core_interactions,
            details,
        }
    }

    pub fn signature(&self) -> &str {
        &self.bucket_id
    }
}

pub trait Bucket<T: Trace<I, C, X>, I: Interaction, C: ChipRow, X: Insn>: Send + Sync {
    fn bucket_type(&self) -> BucketType;

    /// Returns a hit if this bucket matches the op-level micro-ops.
    fn match_hit(&self, ctx: &T, step_idx: usize) -> Option<BucketHit>;
}
