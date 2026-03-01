use serde::{Deserialize, Serialize};

use crate::{Pc, Timestamp};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionDirection {
    Send,
    Receive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PicoInteractionKind {
    Execution,
    Memory,
    Lookup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PicoInteractionBase {
    pub seq: u64,
    pub step_idx: u64,
    pub op_idx: u64,
    pub row_id: String,
    pub direction: InteractionDirection,
    pub kind: PicoInteractionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PicoInteractionEnvelope {
    pub base: PicoInteractionBase,
    pub payload: PicoInteractionPayload,
}

pub type PicoInteraction = PicoInteractionEnvelope;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum PicoInteractionPayload {
    Execution { pc: Pc },
    Memory { effective_addr: Option<u32> },
    Lookup { table: String },
}

impl PicoInteractionEnvelope {
    pub fn base(&self) -> &PicoInteractionBase {
        &self.base
    }
}
