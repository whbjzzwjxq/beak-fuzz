use serde::{Deserialize, Serialize};

/// Instruction-level trace record (one per executed instruction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Insn {
    /// Global sequence number emitted by the zkvm.
    pub seq: u64,

    /// Step index of the instruction.
    /// All other micro-ops in the same step have the same step_idx.
    pub step_idx: u64,

    /// Program counter of the instruction.
    pub pc: u64,

    /// Some zkvm like sp1 have the concept clk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clk: Option<u64>,

    /// Next program counter of the instruction.
    /// It might be missing if the instruction is the last one in the step or the zkvm does not support it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_pc: Option<u64>,

    /// All RV32IM instructions are 32 bits long.
    pub word: u32,
}

impl Insn {
    pub fn new(
        seq: u64,
        step_idx: u64,
        pc: u64,
        clk: Option<u64>,
        next_pc: Option<u64>,
        word: u32,
    ) -> Self {
        Self { seq, step_idx, pc, clk, next_pc, word }
    }
}

impl std::str::FromStr for Insn {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl TryFrom<&Insn> for String {
    type Error = serde_json::Error;

    fn try_from(value: &Insn) -> Result<Self, Self::Error> {
        serde_json::to_string(value)
    }
}
