use beak_core::trace::observations::UpperImmediateInsnObservation;
use beak_core::trace::{BucketHit, Trace, semantic, semantic_matchers};
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
        let observations = words
            .iter()
            .enumerate()
            .filter(|(_, word)| is_upper_immediate_materialization(**word))
            .map(|(idx, word)| UpperImmediateInsnObservation {
                op_idx: idx as u64,
                pc: RAM_START_ADDRESS + (idx as u64) * 4,
                raw_word: *word,
            })
            .collect::<Vec<_>>();
        let mut bucket_hits = Vec::new();
        if !words.is_empty() {
            bucket_hits.push(BucketHit::semantic(
                semantic::control::ENTRYPOINT_BINDING,
                std::collections::HashMap::from([
                    ("op_idx".to_string(), json!(0)),
                    ("step_idx".to_string(), json!(0)),
                    ("pc".to_string(), json!(RAM_START_ADDRESS)),
                    ("semantic_family".to_string(), json!("entrypoint_binding")),
                ]),
            ));
        }
        bucket_hits.extend(semantic_matchers::match_upper_immediate_semantic_hits(&observations));

        Ok(Self { bucket_hits, instruction_count: words.len() })
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
