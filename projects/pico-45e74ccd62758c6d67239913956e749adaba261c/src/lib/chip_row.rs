use serde::{Deserialize, Serialize};

use crate::Timestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PicoChipRowBase {
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
pub enum PicoChipRowKind {
    Cpu,
    Memory,
    Padding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PicoChipRowEnvelope {
    pub base: PicoChipRowBase,
    pub kind: PicoChipRowKind,
    pub payload: PicoChipRowPayload,
}

pub type PicoChipRow = PicoChipRowEnvelope;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum PicoChipRowPayload {
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

impl PicoChipRowEnvelope {
    pub fn base(&self) -> &PicoChipRowBase {
        &self.base
    }
}
