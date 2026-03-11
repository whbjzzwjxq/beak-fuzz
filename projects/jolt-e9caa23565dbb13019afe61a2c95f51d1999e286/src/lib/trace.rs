use std::collections::HashMap;

use beak_core::trace::{BucketHit, Trace};
use common::constants::RAM_START_ADDRESS;
use serde_json::json;

pub struct JoltTrace {
    bucket_hits: Vec<BucketHit>,
    instruction_count: usize,
}

fn is_upper_immediate_materialization(word: u32) -> bool {
    matches!(word & 0x7f, 0x17 | 0x37)
}

impl JoltTrace {
    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        let mut bucket_hits = Vec::new();
        for (idx, word) in words.iter().enumerate() {
            let pc = RAM_START_ADDRESS + (idx as u64) * 4;
            if is_upper_immediate_materialization(*word) {
                let mut details = HashMap::new();
                details.insert("op_idx".to_string(), json!(idx as u64));
                details.insert("pc".to_string(), json!(pc));
                details.insert("raw_word".to_string(), json!(word));
                details.insert("rd".to_string(), json!((word >> 7) & 0x1f));
                details.insert("u_imm20".to_string(), json!((word >> 12) & 0x000f_ffff));
                details.insert("semantic_family".to_string(), json!("upper_immediate"));
                bucket_hits.push(BucketHit::new(
                    "jolt.sem.decode.upper_immediate_materialization".to_string(),
                    details,
                ));
            }
        }

        Ok(Self {
            bucket_hits,
            instruction_count: words.len(),
        })
    }

    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }
}

impl Trace for JoltTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }
}
