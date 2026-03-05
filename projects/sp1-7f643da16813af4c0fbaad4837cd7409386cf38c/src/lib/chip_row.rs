use serde::{Deserialize, Serialize};

use crate::Timestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sp1ChipRowBase {
    pub seq: u64,
    pub step_idx: u64,
    pub op_idx: u64,
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
    pub chip_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sp1ChipRowKind {
    Cpu,
    Memory,
    Padding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sp1ChipRowEnvelope {
    pub base: Sp1ChipRowBase,
    pub kind: Sp1ChipRowKind,
    pub payload: Sp1ChipRowPayload,
}

pub type Sp1ChipRow = Sp1ChipRowEnvelope;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Sp1ChipRowPayload {
    Cpu {
        mnemonic: String,
        rd: Option<u32>,
        rs1: Option<u32>,
        rs2: Option<u32>,
        imm: Option<i32>,
    },
    Memory {
        is_load: bool,
        is_store: bool,
        base_reg: Option<u32>,
        offset: Option<i32>,
    },
    Padding,
}

impl Sp1ChipRowEnvelope {
    pub fn base(&self) -> &Sp1ChipRowBase {
        &self.base
    }
}
