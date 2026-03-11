use std::collections::HashMap;

use beak_core::trace::{BucketHit, Trace};
use nexus_common::memory::MemoryRecord;
use nexus_vm::trace::UniformTrace;
use serde_json::json;

pub struct NexusTrace {
    bucket_hits: Vec<BucketHit>,
    step_count: usize,
}

fn opcode(word: u32) -> u32 {
    word & 0x7f
}

fn funct3(word: u32) -> u32 {
    (word >> 12) & 0x7
}

fn rs1(word: u32) -> u32 {
    (word >> 15) & 0x1f
}

fn decode_i_imm(word: u32) -> i32 {
    (word as i32) >> 20
}

fn decode_s_imm(word: u32) -> i32 {
    let imm = (((word >> 25) & 0x7f) << 5) | ((word >> 7) & 0x1f);
    ((imm as i32) << 20) >> 20
}

fn is_load(word: u32) -> bool {
    opcode(word) == 0x03
}

fn is_store(word: u32) -> bool {
    opcode(word) == 0x23
}

fn has_followup_load(words: &[u32], store_idx: usize) -> bool {
    let Some(&store_word) = words.get(store_idx) else {
        return false;
    };
    if !is_store(store_word) {
        return false;
    }
    let store_rs1 = rs1(store_word);
    let store_imm = decode_s_imm(store_word);
    let store_width = funct3(store_word);
    words
        .iter()
        .skip(store_idx + 1)
        .any(|&word| is_load(word) && rs1(word) == store_rs1 && decode_i_imm(word) == store_imm && funct3(word) == store_width)
}

impl NexusTrace {
    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        let program = nexus_vm::riscv::decode_instructions(words);
        let (_view, trace) = nexus_vm::trace::k_trace_direct(&program.blocks, 1)
            .map_err(|e| format!("nexus k_trace_direct failed: {e}"))?;
        Ok(Self::from_words_and_uniform_trace(words, &trace))
    }

    pub fn from_words_and_uniform_trace(words: &[u32], trace: &UniformTrace) -> Self {
        let mut bucket_hits = Vec::new();
        let mut global_step = 0u64;

        for block in &trace.blocks {
            for step in &block.steps {
                for record in &step.memory_records {
                    if let MemoryRecord::StoreRecord((size, address, value, prev_value), _) = record {
                        if has_followup_load(words, global_step as usize) {
                            let mut forwarding = HashMap::new();
                            forwarding.insert("op_idx".to_string(), json!(global_step));
                            forwarding.insert("pc".to_string(), json!(step.pc));
                            forwarding.insert("address".to_string(), json!(address));
                            forwarding.insert("size_bytes".to_string(), json!(*size as u8));
                            forwarding.insert("value".to_string(), json!(value));
                            forwarding.insert("prev_value".to_string(), json!(prev_value));
                            forwarding.insert("semantic_family".to_string(), json!("store_to_load_payload_flow"));
                            bucket_hits.push(BucketHit::new(
                                "nexus.sem.memory.store_load_payload_flow".to_string(),
                                forwarding,
                            ));
                        }

                        let mut details = HashMap::new();
                        details.insert("op_idx".to_string(), json!(global_step));
                        details.insert("pc".to_string(), json!(step.pc));
                        details.insert("address".to_string(), json!(address));
                        details.insert("size_bytes".to_string(), json!(*size as u8));
                        details.insert("value".to_string(), json!(value));
                        details.insert("prev_value".to_string(), json!(prev_value));
                        details.insert("value_low_bits".to_string(), json!(value & 0xff));
                        details.insert("semantic_family".to_string(), json!("memory_write_payload"));
                        bucket_hits.push(BucketHit::new(
                            "nexus.sem.memory.write_payload_consistency".to_string(),
                            details,
                        ));
                    }
                }
                global_step = global_step.saturating_add(1);
            }
        }

        Self {
            bucket_hits,
            step_count: trace.blocks.iter().map(|block| block.steps.len()).sum(),
        }
    }

    pub fn step_count(&self) -> usize {
        self.step_count
    }

    pub fn from_uniform_trace(trace: &UniformTrace) -> Self {
        Self::from_words_and_uniform_trace(&[], trace)
    }
}

impl Trace for NexusTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }
}
