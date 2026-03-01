use std::collections::HashMap;

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace};

use crate::chip_row::{PicoChipRow, PicoChipRowBase, PicoChipRowKind, PicoChipRowPayload};
use crate::insn::PicoInsn;
use crate::interaction::{
    InteractionDirection, PicoInteraction, PicoInteractionBase, PicoInteractionKind,
    PicoInteractionPayload,
};

#[derive(Debug, Clone)]
pub struct PicoTrace {
    instructions: Vec<PicoInsn>,
    chip_rows: Vec<PicoChipRow>,
    interactions: Vec<PicoInteraction>,
    bucket_hits: Vec<BucketHit>,

    insn_by_step: Vec<Option<usize>>,
    chip_rows_by_step: Vec<Vec<usize>>,
    interactions_by_step: Vec<Vec<usize>>,
    interactions_by_row_id: HashMap<String, Vec<usize>>,
}

impl PicoTrace {
    fn ensure_len<T: Default + Clone>(v: &mut Vec<T>, idx: usize) {
        if v.len() <= idx {
            v.resize(idx + 1, T::default());
        }
    }

    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        let mut instructions = Vec::new();
        let mut chip_rows = Vec::new();
        let mut interactions = Vec::new();

        let mut seq = 0u64;
        let mut pc = 0u32;
        let mut ts = 0u32;

        for (step_idx, &word) in words.iter().enumerate() {
            let dec = RV32IMInstruction::from_word(word)
                .map_err(|e| format!("decode failed at step {step_idx}: {e}"))?;

            let insn = PicoInsn::from_decoded(seq, step_idx as u64, pc, ts, dec.clone());
            instructions.push(insn.clone());
            seq = seq.saturating_add(1);

            let cpu_row = PicoChipRow {
                base: PicoChipRowBase {
                    seq,
                    step_idx: step_idx as u64,
                    op_idx: 0,
                    is_valid: true,
                    timestamp: Some(ts),
                    chip_name: "pico_cpu".to_string(),
                },
                kind: PicoChipRowKind::Cpu,
                payload: PicoChipRowPayload::Cpu {
                    mnemonic: dec.mnemonic.clone(),
                    rd: dec.rd,
                    rs1: dec.rs1,
                    rs2: dec.rs2,
                    imm: dec.imm,
                },
            };
            chip_rows.push(cpu_row);
            seq = seq.saturating_add(1);

            let row_id = format!("step{}_cpu0", step_idx);
            interactions.push(PicoInteraction {
                base: PicoInteractionBase {
                    seq,
                    step_idx: step_idx as u64,
                    op_idx: 0,
                    row_id: row_id.clone(),
                    direction: InteractionDirection::Send,
                    kind: PicoInteractionKind::Execution,
                    timestamp: Some(ts),
                },
                payload: PicoInteractionPayload::Execution { pc },
            });
            seq = seq.saturating_add(1);

            if dec.mnemonic == "lw" || dec.mnemonic == "sw" {
                let mem_row = PicoChipRow {
                    base: PicoChipRowBase {
                        seq,
                        step_idx: step_idx as u64,
                        op_idx: 1,
                        is_valid: true,
                        timestamp: Some(ts),
                        chip_name: "pico_memory".to_string(),
                    },
                    kind: PicoChipRowKind::Memory,
                    payload: PicoChipRowPayload::Memory {
                        is_load: dec.mnemonic == "lw",
                        is_store: dec.mnemonic == "sw",
                        base_reg: dec.rs1,
                        offset: dec.imm,
                    },
                };
                chip_rows.push(mem_row);
                seq = seq.saturating_add(1);

                let effective_addr = match (dec.rs1, dec.imm) {
                    (Some(0), Some(imm)) => Some(imm as u32),
                    _ => None,
                };
                interactions.push(PicoInteraction {
                    base: PicoInteractionBase {
                        seq,
                        step_idx: step_idx as u64,
                        op_idx: 1,
                        row_id: format!("step{}_mem1", step_idx),
                        direction: InteractionDirection::Send,
                        kind: PicoInteractionKind::Memory,
                        timestamp: Some(ts),
                    },
                    payload: PicoInteractionPayload::Memory { effective_addr },
                });
                seq = seq.saturating_add(1);
            }

            pc = pc.wrapping_add(4);
            ts = ts.saturating_add(1);
        }

        Ok(Self::new(instructions, chip_rows, interactions))
    }

    pub fn new(
        instructions: Vec<PicoInsn>,
        chip_rows: Vec<PicoChipRow>,
        interactions: Vec<PicoInteraction>,
    ) -> Self {
        let mut insn_by_step = Vec::<Option<usize>>::new();
        let mut chip_rows_by_step = Vec::<Vec<usize>>::new();
        let mut interactions_by_step = Vec::<Vec<usize>>::new();
        let mut interactions_by_row_id = HashMap::<String, Vec<usize>>::new();

        for (i, insn) in instructions.iter().enumerate() {
            let step = insn.step_idx as usize;
            Self::ensure_len(&mut insn_by_step, step);
            insn_by_step[step] = Some(i);
        }
        for (i, row) in chip_rows.iter().enumerate() {
            let step = row.base().step_idx as usize;
            Self::ensure_len(&mut chip_rows_by_step, step);
            chip_rows_by_step[step].push(i);
        }
        for (i, ia) in interactions.iter().enumerate() {
            let step = ia.base().step_idx as usize;
            Self::ensure_len(&mut interactions_by_step, step);
            interactions_by_step[step].push(i);
            interactions_by_row_id
                .entry(ia.base().row_id.clone())
                .or_default()
                .push(i);
        }

        let mut out = Self {
            instructions,
            chip_rows,
            interactions,
            bucket_hits: Vec::new(),
            insn_by_step,
            chip_rows_by_step,
            interactions_by_step,
            interactions_by_row_id,
        };
        out.bucket_hits = crate::bucket::match_bucket_hits(&out);
        out
    }

    pub fn instructions(&self) -> &[PicoInsn] {
        &self.instructions
    }

    pub fn chip_rows(&self) -> &[PicoChipRow] {
        &self.chip_rows
    }

    pub fn interactions(&self) -> &[PicoInteraction] {
        &self.interactions
    }

    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    pub fn get_instruction_in_step(&self, step_idx: usize, op_idx: usize) -> &PicoInsn {
        assert_eq!(op_idx, 0, "PicoInsn is 1-per-step; op_idx must be 0");
        let i = self.insn_by_step[step_idx].expect("missing instruction for step");
        &self.instructions[i]
    }

    pub fn chip_row_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.chip_rows_by_step
            .get(step_idx)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn interaction_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.interactions_by_step
            .get(step_idx)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn interaction_indices_by_row_id(&self, row_id: &str) -> &[usize] {
        self.interactions_by_row_id
            .get(row_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

impl Trace for PicoTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }
}
