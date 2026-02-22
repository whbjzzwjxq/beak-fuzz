use std::collections::HashMap;

use beak_core::trace::micro_ops::trace::Trace;

use crate::chip_row::OpenVMChipRow;
use crate::insn::OpenVMInsn;
use crate::interaction::OpenVMInteraction;

#[derive(Debug, Clone)]
pub struct OpenVMTrace {
    instructions: Vec<OpenVMInsn>,
    chip_rows: Vec<OpenVMChipRow>,
    interactions: Vec<OpenVMInteraction>,

    // ---- Global indexing by per-record `seq` (u64, stored as usize index) ----
    insn_index_by_seq: Vec<Option<usize>>,
    chip_row_index_by_seq: Vec<Option<usize>>,
    interaction_index_by_seq: Vec<Option<usize>>,

    // ---- Step/op indexing (step_idx/op_idx are u64 on records) ----
    insn_index_by_step: Vec<Option<usize>>,
    chip_row_index_by_step_op: Vec<HashMap<u64, usize>>,
    interaction_index_by_step_op: Vec<HashMap<u64, usize>>,

    // ---- Slice-returning indexes (owned, small duplication is ok) ----
    interactions_by_row_id: HashMap<String, Vec<OpenVMInteraction>>,
    interactions_by_table_id: HashMap<String, Vec<OpenVMInteraction>>,
}

impl OpenVMTrace {
    fn get_index_by_seq(map: &[Option<usize>], seq: usize) -> usize {
        map.get(seq)
            .copied()
            .flatten()
            .unwrap_or_else(|| panic!("missing record for global seq={}", seq))
    }

    fn ensure_len_opt(map: &mut Vec<Option<usize>>, idx: usize) {
        if map.len() <= idx {
            map.resize(idx + 1, None);
        }
    }

    fn ensure_len_map<T>(map: &mut Vec<T>, idx: usize)
    where
        T: Default + Clone,
    {
        if map.len() <= idx {
            map.resize(idx + 1, T::default());
        }
    }
}

impl Trace<OpenVMInteraction, OpenVMChipRow, OpenVMInsn> for OpenVMTrace {
    fn instructions(&self) -> &[OpenVMInsn] {
        &self.instructions
    }

    fn chip_rows(&self) -> &[OpenVMChipRow] {
        &self.chip_rows
    }

    fn interactions(&self) -> &[OpenVMInteraction] {
        &self.interactions
    }

    fn get_instruction_global(&self, seq: usize) -> &OpenVMInsn {
        let i = Self::get_index_by_seq(&self.insn_index_by_seq, seq);
        &self.instructions[i]
    }

    fn get_chip_row_global(&self, seq: usize) -> &OpenVMChipRow {
        let i = Self::get_index_by_seq(&self.chip_row_index_by_seq, seq);
        &self.chip_rows[i]
    }

    fn get_interaction_global(&self, seq: usize) -> &OpenVMInteraction {
        let i = Self::get_index_by_seq(&self.interaction_index_by_seq, seq);
        &self.interactions[i]
    }

    fn get_instruction_in_step(&self, step_idx: usize, op_idx: usize) -> &OpenVMInsn {
        if op_idx != 0 {
            panic!("OpenVMInsn is one-per-step; expected op_idx=0 (got {})", op_idx);
        }
        let i = self
            .insn_index_by_step
            .get(step_idx)
            .copied()
            .flatten()
            .unwrap_or_else(|| panic!("missing instruction for step_idx={}", step_idx));
        &self.instructions[i]
    }

    fn get_chip_row_in_step(&self, step_idx: usize, op_idx: usize) -> &OpenVMChipRow {
        let m = self
            .chip_row_index_by_step_op
            .get(step_idx)
            .unwrap_or_else(|| panic!("missing chip-row step bucket for step_idx={}", step_idx));
        let i = m
            .get(&(op_idx as u64))
            .copied()
            .unwrap_or_else(|| panic!("missing chip row for step_idx={}, op_idx={}", step_idx, op_idx));
        &self.chip_rows[i]
    }

    fn get_interaction_in_step(&self, step_idx: usize, op_idx: usize) -> &OpenVMInteraction {
        let m = self
            .interaction_index_by_step_op
            .get(step_idx)
            .unwrap_or_else(|| panic!("missing interaction step bucket for step_idx={}", step_idx));
        let i = m
            .get(&(op_idx as u64))
            .copied()
            .unwrap_or_else(|| panic!("missing interaction for step_idx={}, op_idx={}", step_idx, op_idx));
        &self.interactions[i]
    }

    fn get_interactions_by_row_id(&self, row_id: &str) -> &[OpenVMInteraction] {
        match self.interactions_by_row_id.get(row_id) {
            Some(v) => v.as_slice(),
            None => &[],
        }
    }

    fn get_interactions_by_table_id(&self, table_id: &str) -> &[OpenVMInteraction] {
        match self.interactions_by_table_id.get(table_id) {
            Some(v) => v.as_slice(),
            None => &[],
        }
    }

    fn new(
        instructions: Vec<OpenVMInsn>,
        chip_rows: Vec<OpenVMChipRow>,
        interactions: Vec<OpenVMInteraction>,
    ) -> Self {
        let mut insn_index_by_seq: Vec<Option<usize>> = Vec::new();
        let mut chip_row_index_by_seq: Vec<Option<usize>> = Vec::new();
        let mut interaction_index_by_seq: Vec<Option<usize>> = Vec::new();

        let mut insn_index_by_step: Vec<Option<usize>> = Vec::new();
        let mut chip_row_index_by_step_op: Vec<HashMap<u64, usize>> = Vec::new();
        let mut interaction_index_by_step_op: Vec<HashMap<u64, usize>> = Vec::new();

        let mut interactions_by_row_id: HashMap<String, Vec<OpenVMInteraction>> = HashMap::new();
        let mut interactions_by_table_id: HashMap<String, Vec<OpenVMInteraction>> = HashMap::new();

        for (i, insn) in instructions.iter().enumerate() {
            let seq = insn.seq as usize;
            let step = insn.step_idx as usize;

            Self::ensure_len_opt(&mut insn_index_by_seq, seq);
            if insn_index_by_seq[seq].is_some() {
                panic!("duplicate OpenVMInsn.seq={}", seq);
            }
            insn_index_by_seq[seq] = Some(i);

            Self::ensure_len_opt(&mut insn_index_by_step, step);
            if insn_index_by_step[step].is_some() {
                panic!("duplicate OpenVMInsn.step_idx={}", step);
            }
            insn_index_by_step[step] = Some(i);
        }

        for (i, row) in chip_rows.iter().enumerate() {
            let base = row.base();
            let seq = base.seq as usize;
            let step = base.step_idx as usize;
            let op = base.op_idx;

            Self::ensure_len_opt(&mut chip_row_index_by_seq, seq);
            if chip_row_index_by_seq[seq].is_some() {
                panic!("duplicate OpenVMChipRow.seq={}", seq);
            }
            chip_row_index_by_seq[seq] = Some(i);

            Self::ensure_len_map(&mut chip_row_index_by_step_op, step);
            if chip_row_index_by_step_op[step].insert(op, i).is_some() {
                panic!(
                    "duplicate OpenVMChipRow for step_idx={}, op_idx={}",
                    base.step_idx, base.op_idx
                );
            }
        }

        for (i, uop) in interactions.iter().enumerate() {
            let base = uop.base();
            let seq = base.seq as usize;
            let step = base.step_idx as usize;
            let op = base.op_idx;

            Self::ensure_len_opt(&mut interaction_index_by_seq, seq);
            if interaction_index_by_seq[seq].is_some() {
                panic!("duplicate OpenVMInteraction.seq={}", seq);
            }
            interaction_index_by_seq[seq] = Some(i);

            Self::ensure_len_map(&mut interaction_index_by_step_op, step);
            if interaction_index_by_step_op[step].insert(op, i).is_some() {
                panic!(
                    "duplicate OpenVMInteraction for step_idx={}, op_idx={}",
                    base.step_idx, base.op_idx
                );
            }

            interactions_by_row_id.entry(base.row_id.clone()).or_default().push(uop.clone());
            interactions_by_table_id
                .entry(base.table_name.clone())
                .or_default()
                .push(uop.clone());
        }

        Self {
            instructions,
            chip_rows,
            interactions,
            insn_index_by_seq,
            chip_row_index_by_seq,
            interaction_index_by_seq,
            insn_index_by_step,
            chip_row_index_by_step_op,
            interaction_index_by_step_op,
            interactions_by_row_id,
            interactions_by_table_id,
        }
    }
}