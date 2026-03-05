use beak_core::rv32im::instruction::RV32IMInstruction;
use serde::{Deserialize, Serialize};

use crate::{Pc, Timestamp};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sp1Insn {
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
    pub asm: String,
}

impl Sp1Insn {
    pub fn from_decoded(seq: u64, step_idx: u64, pc: Pc, timestamp: Timestamp, insn: RV32IMInstruction) -> Self {
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
            asm: insn.asm,
        }
    }
}
