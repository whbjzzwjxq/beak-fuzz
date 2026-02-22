use beak_core::trace::micro_ops::insn::Insn;
use serde::{Deserialize, Serialize};

use crate::chip_row::{Pc, Timestamp};

/// Instruction-level trace record (one per executed instruction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVMInsn {
    /// Global sequence number emitted by the zkvm.
    pub seq: u64,

    /// Step index of the instruction.
    /// All other micro-ops in the same step have the same step_idx.
    pub step_idx: u64,

    /// Program counter of the instruction.
    pub pc: Pc,

    /// OpenVM has the concept of timestamp.
    pub timestamp: Option<Timestamp>,

    /// Next program counter of the instruction.
    /// It might be missing if the instruction is the last one in the step or the zkvm does not support it.
    pub next_pc: Option<Pc>,

    /// All RV32IM instructions are 32 bits long.
    pub word: u32,
}

impl OpenVMInsn {
    pub fn new(
        seq: u64,
        step_idx: u64,
        pc: Pc,
        timestamp: Option<Timestamp>,
        next_pc: Option<Pc>,
        word: u32,
    ) -> Self {
        Self { seq, step_idx, pc, timestamp, next_pc, word }
    }
}

impl Insn for OpenVMInsn {}
