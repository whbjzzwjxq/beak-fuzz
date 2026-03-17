use beak_core::trace::observations::MemoryWriteObservation;
use beak_core::trace::{BucketHit, Trace, semantic_matchers};
use nexus_common::memory::MemoryRecord;
use nexus_vm::trace::UniformTrace;

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
    words.iter().skip(store_idx + 1).any(|&word| {
        is_load(word)
            && rs1(word) == store_rs1
            && decode_i_imm(word) == store_imm
            && funct3(word) == store_width
    })
}

impl NexusTrace {
    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        let program = nexus_vm::riscv::decode_instructions(words);
        let (_view, trace) = nexus_vm::trace::k_trace_direct(&program.blocks, 1)
            .map_err(|e| format!("nexus k_trace_direct failed: {e}"))?;
        Ok(Self::from_words_and_uniform_trace(words, &trace))
    }

    pub fn from_words_and_uniform_trace(words: &[u32], trace: &UniformTrace) -> Self {
        let mut observations = Vec::new();
        let mut global_step = 0u64;

        for block in &trace.blocks {
            for step in &block.steps {
                for record in &step.memory_records {
                    if let MemoryRecord::StoreRecord((size, address, value, prev_value), _) = record
                    {
                        observations.push(MemoryWriteObservation {
                            op_idx: global_step,
                            pc: step.pc,
                            address: *address,
                            size_bytes: *size as u8,
                            value: *value,
                            prev_value: *prev_value,
                            has_followup_load: has_followup_load(words, global_step as usize),
                        });
                    }
                }
                global_step = global_step.saturating_add(1);
            }
        }

        let bucket_hits = semantic_matchers::match_memory_write_semantic_hits(&observations);
        Self { bucket_hits, step_count: trace.blocks.iter().map(|block| block.steps.len()).sum() }
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
