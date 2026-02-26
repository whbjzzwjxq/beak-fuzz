use crate::{FieldElement, Pc, Timestamp};

use openvm_instructions::VmOpcode;
use serde::{Deserialize, Serialize};

/// One record per instruction execution (per "step").
///
/// Stores the OpenVM instruction format (opcode + 7 operands), NOT the raw
/// RISC-V 32-bit word, which is lost after transpilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVMInsn {
    /// Global sequence number emitted by the tracer.
    pub seq: u64,

    /// Logical step index.  All chip rows and interactions that belong to the
    /// same instruction execution share this value.
    pub step_idx: u64,

    /// Program counter at which this instruction lives.
    pub pc: Pc,

    /// Starting timestamp of this execution instance.
    pub timestamp: Timestamp,

    /// Program counter after this instruction completes.
    pub next_pc: Pc,

    /// Timestamp after this instruction completes.
    pub next_timestamp: Timestamp,

    /// OpenVM global opcode.
    pub opcode: VmOpcode,

    /// OpenVM instruction operands: [a, b, c, d, e, f, g].
    pub operands: [FieldElement; 7],
}
