use crate::trace::micro_ops::chip_row::ChipRow;
use crate::trace::micro_ops::insn::Insn;
use crate::trace::micro_ops::interaction::Interaction;

pub trait Trace<I: Interaction, C: ChipRow, X: Insn> {
    fn instructions(&self) -> &[X];
    fn chip_rows(&self) -> &[C];
    fn interactions(&self) -> &[I];

    fn get_instruction_global(&self, seq: usize) -> &X;
    fn get_chip_row_global(&self, seq: usize) -> &C;
    fn get_interaction_global(&self, seq: usize) -> &I;

    fn get_instruction_in_step(&self, step_idx: usize, op_idx: usize) -> &X;
    fn get_chip_row_in_step(&self, step_idx: usize, op_idx: usize) -> &C;
    fn get_interaction_in_step(&self, step_idx: usize, op_idx: usize) -> &I;

    fn get_interactions_by_row_id(&self, row_id: &str) -> &[I];
    fn get_interactions_by_table_id(&self, table_id: &str) -> &[I];

    fn new(instructions: Vec<X>, chip_rows: Vec<C>, interactions: Vec<I>) -> Self;
}
