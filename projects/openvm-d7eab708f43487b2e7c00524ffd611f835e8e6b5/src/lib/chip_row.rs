use beak_core::trace::micro_ops::chip_row::ChipRow;
use openvm_instructions::VmOpcode;
use openvm_rv32im_transpiler::{
    BaseAluOpcode, BranchEqualOpcode, BranchLessThanOpcode, DivRemOpcode,
    LessThanOpcode, MulHOpcode, MulOpcode, Rv32AuipcOpcode, Rv32JalLuiOpcode,
    Rv32JalrOpcode, Rv32LoadStoreOpcode, ShiftOpcode,
};
use serde::{Deserialize, Serialize};

use crate::{FieldElement, Pc, Timestamp};

// ---------------------------------------------------------------------------
// Base
// ---------------------------------------------------------------------------

/// Fields shared by every chip row.
///
/// Key differences from the previous design:
/// - No `op_idx`: each instruction execution maps to exactly one chip row.
/// - No `kind` enum: the variant of `OpenVMChipRow` itself carries the kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVMChipRowBase {
    /// Global sequence number.
    pub seq: u64,

    /// Step index — matches `OpenVMInsn.step_idx` for the same execution.
    pub step_idx: u64,

    /// Whether this row is a real execution (vs. padding).
    pub is_valid: bool,

    /// Starting timestamp of the execution that produced this row.
    pub timestamp: Timestamp,

    /// Human-readable name of the chip instance (e.g. "Rv32BaseAlu").
    pub chip_name: String,
}

// ---------------------------------------------------------------------------
// rs2 source (shared by ALU-family chips)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rs2Source {
    Reg { ptr: u32 },
    Imm { value: i32 },
}

// ---------------------------------------------------------------------------
// Chip-specific rows (one struct per OpenVM chip)
// ---------------------------------------------------------------------------

// ---- ALU family (always-write, no needs_write) ----------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseAluChipRow {
    pub base: OpenVMChipRowBase,
    pub op: BaseAluOpcode,
    pub rd_ptr: u32,
    pub rs1_ptr: u32,
    pub rs2: Rs2Source,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShiftChipRow {
    pub base: OpenVMChipRowBase,
    pub op: ShiftOpcode,
    pub rd_ptr: u32,
    pub rs1_ptr: u32,
    pub rs2: Rs2Source,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LessThanChipRow {
    pub base: OpenVMChipRowBase,
    pub op: LessThanOpcode,
    pub rd_ptr: u32,
    pub rs1_ptr: u32,
    pub rs2: Rs2Source,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulChipRow {
    pub base: OpenVMChipRowBase,
    pub op: MulOpcode,
    pub rd_ptr: u32,
    pub rs1_ptr: u32,
    pub rs2_ptr: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulHChipRow {
    pub base: OpenVMChipRowBase,
    pub op: MulHOpcode,
    pub rd_ptr: u32,
    pub rs1_ptr: u32,
    pub rs2_ptr: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivRemChipRow {
    pub base: OpenVMChipRowBase,
    pub op: DivRemOpcode,
    pub rd_ptr: u32,
    pub rs1_ptr: u32,
    pub rs2_ptr: u32,
}

// ---- Branch family (no register writes) -----------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchEqualChipRow {
    pub base: OpenVMChipRowBase,
    pub op: BranchEqualOpcode,
    pub rs1_ptr: u32,
    pub rs2_ptr: u32,
    pub imm: i32,
    pub is_taken: bool,
    pub from_pc: Pc,
    pub to_pc: Pc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchLessThanChipRow {
    pub base: OpenVMChipRowBase,
    pub op: BranchLessThanOpcode,
    pub rs1_ptr: u32,
    pub rs2_ptr: u32,
    pub imm: i32,
    pub is_taken: bool,
    pub from_pc: Pc,
    pub to_pc: Pc,
}

// ---- Jump family (conditional write) --------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JalLuiChipRow {
    pub base: OpenVMChipRowBase,
    pub op: Rv32JalLuiOpcode,
    pub rd_ptr: u32,
    pub imm: i32,
    pub needs_write: bool,
    pub from_pc: Pc,
    pub to_pc: Pc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JalrChipRow {
    pub base: OpenVMChipRowBase,
    pub op: Rv32JalrOpcode,
    pub rd_ptr: u32,
    pub rs1_ptr: u32,
    pub imm: i32,
    pub needs_write: bool,
    pub from_pc: Pc,
    pub to_pc: Pc,
}

// ---- AUIPC (always-write, the soundness-bug chip) -------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuipcChipRow {
    pub base: OpenVMChipRowBase,
    pub op: Rv32AuipcOpcode,
    pub rd_ptr: u32,
    pub imm: u32,
}

// ---- Load / Store (conditional write for loads) ---------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadStoreChipRow {
    pub base: OpenVMChipRowBase,
    pub op: Rv32LoadStoreOpcode,
    pub rs1_ptr: u32,
    pub rd_rs2_ptr: u32,
    pub imm: i32,
    pub imm_sign: bool,
    pub mem_as: u32,
    pub effective_ptr: u32,
    pub is_store: bool,
    /// true when the op actually writes back to a register (load to x0 is gated off).
    pub needs_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadSignExtendChipRow {
    pub base: OpenVMChipRowBase,
    pub op: Rv32LoadStoreOpcode,
    pub rs1_ptr: u32,
    pub rd_ptr: u32,
    pub imm: i32,
    pub imm_sign: bool,
    pub mem_as: u32,
    pub effective_ptr: u32,
    pub needs_write: bool,
}

// ---- System chips ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhantomChipRow {
    pub base: OpenVMChipRowBase,
}

/// Program chip: one row per instruction in the program (not per execution).
/// Tracks execution frequency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramChipRow {
    pub base: OpenVMChipRowBase,
    pub opcode: VmOpcode,
    pub operands: [FieldElement; 7],
    pub execution_frequency: u32,
}

/// Connector chip: exactly 2 rows per segment (initial + final boundary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorChipRow {
    pub base: OpenVMChipRowBase,
    pub from_pc: Pc,
    pub to_pc: Pc,
    pub from_timestamp: Timestamp,
    pub to_timestamp: Timestamp,
    pub is_terminate: bool,
    pub exit_code: Option<u32>,
}

// ---------------------------------------------------------------------------
// Top-level enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpenVMChipRow {
    BaseAlu(BaseAluChipRow),
    Shift(ShiftChipRow),
    LessThan(LessThanChipRow),
    Mul(MulChipRow),
    MulH(MulHChipRow),
    DivRem(DivRemChipRow),
    BranchEqual(BranchEqualChipRow),
    BranchLessThan(BranchLessThanChipRow),
    JalLui(JalLuiChipRow),
    Jalr(JalrChipRow),
    Auipc(AuipcChipRow),
    LoadStore(LoadStoreChipRow),
    LoadSignExtend(LoadSignExtendChipRow),
    Phantom(PhantomChipRow),
    Program(ProgramChipRow),
    Connector(ConnectorChipRow),
}

impl OpenVMChipRow {
    pub fn base(&self) -> &OpenVMChipRowBase {
        match self {
            Self::BaseAlu(r) => &r.base,
            Self::Shift(r) => &r.base,
            Self::LessThan(r) => &r.base,
            Self::Mul(r) => &r.base,
            Self::MulH(r) => &r.base,
            Self::DivRem(r) => &r.base,
            Self::BranchEqual(r) => &r.base,
            Self::BranchLessThan(r) => &r.base,
            Self::JalLui(r) => &r.base,
            Self::Jalr(r) => &r.base,
            Self::Auipc(r) => &r.base,
            Self::LoadStore(r) => &r.base,
            Self::LoadSignExtend(r) => &r.base,
            Self::Phantom(r) => &r.base,
            Self::Program(r) => &r.base,
            Self::Connector(r) => &r.base,
        }
    }
}
