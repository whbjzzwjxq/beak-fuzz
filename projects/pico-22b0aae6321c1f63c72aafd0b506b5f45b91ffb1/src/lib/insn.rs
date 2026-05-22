use beak_core::rv32im::instruction::RV32IMInstruction;
use serde::{Deserialize, Serialize};

use crate::{Pc, Timestamp};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PicoInsn {
    pub seq: u64,
    pub step_idx: u64,
    pub pc: Pc,
    pub timestamp: Timestamp,
    pub next_pc: Pc,
    pub next_timestamp: Timestamp,
    pub word: u32,
    pub mnemonic: String,
    pub rd: Option<u32>,
    pub rs1: Option<u32>,
    pub rs2: Option<u32>,
    pub imm: Option<i32>,
    pub chunk: Option<u32>,
    pub runtime_a: Option<u32>,
    pub runtime_b: Option<u32>,
    pub runtime_c: Option<u32>,
    pub memory_value: Option<u32>,
    pub ecall_syscall_id: Option<u32>,
    pub ecall_operand_to_check: Option<u32>,
    pub asm: String,
}

impl PicoInsn {
    pub fn from_decoded(
        seq: u64,
        step_idx: u64,
        pc: Pc,
        timestamp: Timestamp,
        insn: RV32IMInstruction,
    ) -> Self {
        Self {
            seq,
            step_idx,
            pc,
            timestamp,
            next_pc: pc.wrapping_add(4),
            next_timestamp: timestamp.saturating_add(1),
            word: insn.word,
            mnemonic: insn.mnemonic,
            rd: insn.rd,
            rs1: insn.rs1,
            rs2: insn.rs2,
            imm: insn.imm,
            chunk: None,
            runtime_a: None,
            runtime_b: None,
            runtime_c: None,
            memory_value: None,
            ecall_syscall_id: None,
            ecall_operand_to_check: None,
            asm: insn.asm,
        }
    }
}
