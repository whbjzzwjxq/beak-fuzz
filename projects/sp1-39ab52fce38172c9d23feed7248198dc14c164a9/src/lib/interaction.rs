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
pub enum Sp1InteractionKind {
    Execution,
    Memory,
    Lookup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sp1InteractionBase {
    pub seq: u64,
    pub step_idx: u64,
    pub op_idx: u64,
    pub row_id: String,
    pub direction: InteractionDirection,
    pub kind: Sp1InteractionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sp1InteractionEnvelope {
    pub base: Sp1InteractionBase,
    pub payload: Sp1InteractionPayload,
}

pub type Sp1Interaction = Sp1InteractionEnvelope;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Sp1InteractionPayload {
    Execution { pc: Pc },
    Memory { effective_addr: Option<u32> },
    Lookup { table: String },
}

impl Sp1InteractionEnvelope {
    pub fn base(&self) -> &Sp1InteractionBase {
        &self.base
    }
}
