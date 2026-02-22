use beak_core::trace::micro_ops::interaction::Interaction;
use openvm_instructions::VmOpcode;
use serde::{Deserialize, Serialize};

use crate::insn::{FieldElement, Pc, Timestamp};

// ---------------------------------------------------------------------------
// Direction & Bus kind
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum InteractionDirection {
    Send,
    Receive,
}

/// The five core buses in OpenVM.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BusKind {
    /// PermutationCheck bus carrying (pc, timestamp) execution-state edges.
    Execution,
    /// Lookup bus verifying (pc, opcode, a..g) against the program ROM.
    Program,
    /// PermutationCheck bus for memory reads/writes (address_space, pointer, data[], timestamp).
    Memory,
    /// Lookup bus for variable-width range checks (value, max_bits).
    RangeCheck,
    /// Lookup bus for bitwise operations (x, y, z, op).
    Bitwise,
}

// ---------------------------------------------------------------------------
// Base
// ---------------------------------------------------------------------------

/// Fields shared by every interaction record.
///
/// `op_idx` is retained here (unlike ChipRow) because one instruction
/// execution produces multiple interactions on various buses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVMInteractionBase {
    /// Global sequence number.
    pub seq: u64,

    /// Step index — matches `OpenVMInsn.step_idx`.
    pub step_idx: u64,

    /// Micro-op index within the step (interactions are sequentially numbered
    /// within a single step, starting from 0).
    pub op_idx: u64,

    /// Identifier of the chip row that produced this interaction (links back
    /// to `OpenVMChipRowBase`).
    pub row_id: String,

    /// Send (producer) or Receive (consumer).
    pub direction: InteractionDirection,

    /// Which bus this interaction is on.
    pub bus: BusKind,

    /// Timestamp, when applicable to the bus payload.
    pub timestamp: Option<Timestamp>,
}

// ---------------------------------------------------------------------------
// Bus-specific payloads (one struct per OpenVM bus)
// ---------------------------------------------------------------------------

/// ExecutionBus (PermutationCheck): execution-state edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionInteraction {
    pub base: OpenVMInteractionBase,
    pub pc: Pc,
    pub timestamp: Timestamp,
}

/// ProgramBus (Lookup): verify instruction at given PC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInteraction {
    pub base: OpenVMInteractionBase,
    pub pc: Pc,
    pub opcode: VmOpcode,
    pub operands: [FieldElement; 7],
}

/// MemoryBus (PermutationCheck): a single memory access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInteraction {
    pub base: OpenVMInteractionBase,
    pub address_space: FieldElement,
    pub pointer: FieldElement,
    pub data: Vec<FieldElement>,
    pub timestamp: Timestamp,
}

/// VariableRangeCheckerBus (Lookup): assert value in [0, 2^max_bits).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeCheckInteraction {
    pub base: OpenVMInteractionBase,
    pub value: FieldElement,
    pub max_bits: u32,
}

/// BitwiseOperationLookupBus (Lookup): bitwise op lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitwiseInteraction {
    pub base: OpenVMInteractionBase,
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    /// 0 = range-check mode, 1 = XOR.
    pub op: u32,
}

// ---------------------------------------------------------------------------
// Top-level enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpenVMInteraction {
    Execution(ExecutionInteraction),
    Program(ProgramInteraction),
    Memory(MemoryInteraction),
    RangeCheck(RangeCheckInteraction),
    Bitwise(BitwiseInteraction),
}

impl OpenVMInteraction {
    pub fn base(&self) -> &OpenVMInteractionBase {
        match self {
            Self::Execution(x) => &x.base,
            Self::Program(x) => &x.base,
            Self::Memory(x) => &x.base,
            Self::RangeCheck(x) => &x.base,
            Self::Bitwise(x) => &x.base,
        }
    }

    pub fn bus(&self) -> BusKind {
        match self {
            Self::Execution(_) => BusKind::Execution,
            Self::Program(_) => BusKind::Program,
            Self::Memory(_) => BusKind::Memory,
            Self::RangeCheck(_) => BusKind::RangeCheck,
            Self::Bitwise(_) => BusKind::Bitwise,
        }
    }
}
