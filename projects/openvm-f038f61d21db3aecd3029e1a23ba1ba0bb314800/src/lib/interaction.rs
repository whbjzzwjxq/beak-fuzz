use openvm_instructions::VmOpcode;
use serde::{Deserialize, Serialize};

use crate::{FieldElement, Pc, Timestamp};

// ---------------------------------------------------------------------------
// Direction & Kind
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionDirection {
    Send,
    Receive,
}

/// The five core buses/kinds we model for OpenVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVMInteractionKind {
    Execution,
    Program,
    Memory,
    RangeCheck,
    Bitwise,
}

// ---------------------------------------------------------------------------
// Base (Envelope header)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVMInteractionBase {
    pub seq: u64,
    pub step_idx: u64,

    /// Interaction index within a step (0..N-1).
    pub op_idx: u64,

    /// Anchor chip-row id (ties interactions back to the row emitted for this step).
    pub row_id: String,

    pub direction: InteractionDirection,

    pub kind: OpenVMInteractionKind,

    /// Some interactions (memory/execution) always have timestamp; others might not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
}

/// One JSON object per interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVMInteractionEnvelope {
    pub base: OpenVMInteractionBase,
    pub payload: OpenVMInteractionPayload,
}

/// Public type used throughout this crate.
///
/// We keep the `Envelope` name for JSON clarity but expose a shorter alias for code.
pub type OpenVMInteraction = OpenVMInteractionEnvelope;

// ---------------------------------------------------------------------------
// Payload (serde oneof)
// ---------------------------------------------------------------------------
//
// JSON shape:
//   { "base": {...}, "payload": { "type": "...", "data": {...} } }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum OpenVMInteractionPayload {
    // ExecutionBus (PermutationCheck): (pc, timestamp)
    Execution {
        pc: Pc,
        timestamp: Timestamp,
    },

    // ProgramBus (Lookup): (pc, opcode, operands[7])
    Program {
        pc: Pc,
        opcode: VmOpcode,
        operands: [FieldElement; 7],
    },

    // MemoryBus (PermutationCheck): (address_space, pointer, data[], timestamp)
    Memory {
        address_space: FieldElement,
        pointer: FieldElement,
        data: Vec<FieldElement>,
        timestamp: Timestamp,
    },

    // VariableRangeCheckerBus (Lookup): (value, max_bits)
    RangeCheck {
        value: FieldElement,
        max_bits: u32,
    },

    // BitwiseOperationLookupBus (Lookup): (x, y, z, op)
    Bitwise {
        x: FieldElement,
        y: FieldElement,
        z: FieldElement,
        /// 0 = range-check mode, 1 = XOR.
        op: u32,
    },
}

// ---------------------------------------------------------------------------
// Optional helpers
// ---------------------------------------------------------------------------

impl OpenVMInteractionEnvelope {
    pub fn base(&self) -> &OpenVMInteractionBase {
        &self.base
    }

    pub fn validate_kind_matches_payload(&self) -> Result<(), String> {
        let expected = match &self.payload {
            OpenVMInteractionPayload::Execution { .. } => OpenVMInteractionKind::Execution,
            OpenVMInteractionPayload::Program { .. } => OpenVMInteractionKind::Program,
            OpenVMInteractionPayload::Memory { .. } => OpenVMInteractionKind::Memory,
            OpenVMInteractionPayload::RangeCheck { .. } => OpenVMInteractionKind::RangeCheck,
            OpenVMInteractionPayload::Bitwise { .. } => OpenVMInteractionKind::Bitwise,
        };

        if self.base.kind != expected {
            return Err(format!(
                "interaction kind/payload mismatch: base.kind={:?}, payload expects {:?}",
                self.base.kind, expected
            ));
        }
        Ok(())
    }
}
