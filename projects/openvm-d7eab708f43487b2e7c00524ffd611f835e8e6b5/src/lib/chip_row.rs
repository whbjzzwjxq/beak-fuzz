use openvm_instructions::VmOpcode;
use serde::{Deserialize, Serialize};

use crate::{FieldElement, Pc, Timestamp};

// -----------------------------
// Envelope/base
// -----------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVMChipRowBase {
    pub seq: u64,
    pub step_idx: u64,

    /// Chip-row index within a step (0..N-1).
    ///
    /// This enables representing multiple chip rows per instruction execution.
    pub op_idx: u64,
    pub is_valid: bool,

    /// Prefer Some(..). If you truly can't get it, emit None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,

    /// Human-readable chip instance name, e.g. "Rv32BaseAlu".
    pub chip_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVMChipRowKind {
    BaseAlu,
    Shift,
    LessThan,
    Mul,
    MulH,
    DivRem,
    BranchEqual,
    BranchLessThan,
    JalLui,
    Jalr,
    Auipc,
    LoadStore,
    LoadSignExtend,
    Phantom,
    Program,
    Connector,
    Padding,
}

/// One JSON object per chip row:
/// - `base` is uniform
/// - `kind` is uniform
/// - `payload` is a serde-oneof tagged enum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVMChipRowEnvelope {
    pub base: OpenVMChipRowBase,
    pub kind: OpenVMChipRowKind,
    pub payload: OpenVMChipRowPayload,
}

/// Public type used throughout this crate.
///
/// We keep the `Envelope` name for JSON clarity but expose a shorter alias for code.
pub type OpenVMChipRow = OpenVMChipRowEnvelope;

// -----------------------------
// Shared helper types
// -----------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "src", rename_all = "snake_case")]
pub enum Rs2Source {
    Reg { ptr: u32 },
    Imm { value: i32 },
}

// -----------------------------
// Payload (oneof)
// -----------------------------
//
// We encode payload as:
// { "type": "...", "data": { ... } }
//
// This keeps JSON stable and explicit.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum OpenVMChipRowPayload {
    // ---- ALU family (always-write) ----
    BaseAlu {
        /// Local opcode value emitted by the instrumented OpenVM snapshot.
        ///
        /// Note: the tracer currently emits `u32` (not enum strings), so we keep this as `u32`
        /// to ensure logs are always parseable.
        op: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2: Rs2Source,
        /// Output limbs (rd value).
        a: Vec<u8>,
        /// Input limbs (rs1 value).
        b: Vec<u8>,
        /// Input limbs (rs2 value / imm-expanded limbs).
        c: Vec<u8>,
    },

    Shift {
        op: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2: Rs2Source,
        a: Vec<u8>,
        b: Vec<u8>,
        c: Vec<u8>,
    },

    LessThan {
        op: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2: Rs2Source,
        a: Vec<u8>,
        b: Vec<u8>,
        c: Vec<u8>,
    },

    Mul {
        op: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2_ptr: u32,
        a: Vec<u8>,
        b: Vec<u8>,
        c: Vec<u8>,
    },

    MulH {
        op: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2_ptr: u32,
        a: Vec<u8>,
        b: Vec<u8>,
        c: Vec<u8>,
    },

    DivRem {
        op: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2_ptr: u32,
        a: Vec<u8>,
        b: Vec<u8>,
        c: Vec<u8>,
    },

    // ---- Branch family (no writes) ----
    BranchEqual {
        op: u32,
        rs1_ptr: u32,
        rs2_ptr: u32,
        /// Signed immediate as used by the RISC-V-style branch.
        imm: i32,
        is_taken: bool,
        from_pc: Pc,
        to_pc: Pc,
        /// Core-side input limbs.
        a: Vec<u8>,
        b: Vec<u8>,
        /// Core comparison result (`cmp_result` column).
        cmp_result: bool,
    },

    BranchLessThan {
        op: u32,
        rs1_ptr: u32,
        rs2_ptr: u32,
        imm: i32,
        is_taken: bool,
        from_pc: Pc,
        to_pc: Pc,
        a: Vec<u8>,
        b: Vec<u8>,
        cmp_result: bool,
    },

    // ---- Jump family (conditional write) ----
    JalLui {
        op: u32,
        rd_ptr: u32,
        imm: u32,
        needs_write: bool,
        from_pc: Pc,
        to_pc: Pc,
        rd_data: Vec<u8>,
        is_jal: bool,
    },

    Jalr {
        op: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        imm: i32,
        imm_sign: bool,
        needs_write: bool,
        from_pc: Pc,
        to_pc: Pc,
        rs1_val: u32,
        rd_data: Vec<u8>,
    },

    // ---- AUIPC ----
    Auipc {
        op: u32,
        rd_ptr: u32,
        imm: u32,
        from_pc: Pc,
        rd_data: Vec<u8>,
    },

    // ---- Load/Store ----
    LoadStore {
        op: u32,
        rs1_ptr: u32,
        rd_rs2_ptr: u32,
        imm: i32,
        imm_sign: bool,
        mem_as: u32,
        effective_ptr: u32,
        is_store: bool,
        needs_write: bool,
        is_load: bool,
        /// Core flags (usually 4 entries for the RV32IM load/store chip).
        flags: [u32; 4],
        read_data: Vec<u8>,
        prev_data: Vec<u32>,
        write_data: Vec<u32>,
    },

    LoadSignExtend {
        /// Typically LOADB / LOADH variants.
        op: u32,
        rs1_ptr: u32,
        rd_ptr: u32,
        imm: i32,
        imm_sign: bool,
        mem_as: u32,
        effective_ptr: u32,
        needs_write: bool,
        prev_data: Vec<u8>,
        shifted_read_data: Vec<u8>,
        data_most_sig_bit: bool,
        shift_most_sig_bit: bool,
        opcode_loadh_flag: bool,
        opcode_loadb_flag1: bool,
        opcode_loadb_flag0: bool,
    },

    // ---- System chips ----
    Phantom {},

    Program {
        opcode: VmOpcode,
        operands: [FieldElement; 7],
        execution_frequency: u32,
    },

    Connector {
        from_pc: Pc,
        to_pc: Pc,
        #[serde(skip_serializing_if = "Option::is_none")]
        from_timestamp: Option<Timestamp>,
        #[serde(skip_serializing_if = "Option::is_none")]
        to_timestamp: Option<Timestamp>,
        is_terminate: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_code: Option<u32>,
    },

    Padding {
        data: String,
    },
}

// -----------------------------
// Optional: consistency checks
// -----------------------------
//
// If you want, you can enforce that `kind` matches `payload` at runtime.
// (Good to catch bugs early.)

impl OpenVMChipRowEnvelope {
    pub fn base(&self) -> &OpenVMChipRowBase {
        &self.base
    }

    pub fn validate_kind_matches_payload(&self) -> Result<(), String> {
        let expected = match &self.payload {
            OpenVMChipRowPayload::BaseAlu { .. } => OpenVMChipRowKind::BaseAlu,

            OpenVMChipRowPayload::Shift { .. } => OpenVMChipRowKind::Shift,

            OpenVMChipRowPayload::LessThan { .. } => OpenVMChipRowKind::LessThan,

            OpenVMChipRowPayload::Mul { .. } => OpenVMChipRowKind::Mul,

            OpenVMChipRowPayload::MulH { .. } => OpenVMChipRowKind::MulH,

            OpenVMChipRowPayload::DivRem { .. } => OpenVMChipRowKind::DivRem,

            OpenVMChipRowPayload::BranchEqual { .. } => OpenVMChipRowKind::BranchEqual,

            OpenVMChipRowPayload::BranchLessThan { .. } => OpenVMChipRowKind::BranchLessThan,

            OpenVMChipRowPayload::JalLui { .. } => OpenVMChipRowKind::JalLui,

            OpenVMChipRowPayload::Jalr { .. } => OpenVMChipRowKind::Jalr,

            OpenVMChipRowPayload::Auipc { .. } => OpenVMChipRowKind::Auipc,

            OpenVMChipRowPayload::LoadStore { .. } => OpenVMChipRowKind::LoadStore,

            OpenVMChipRowPayload::LoadSignExtend { .. } => OpenVMChipRowKind::LoadSignExtend,

            OpenVMChipRowPayload::Phantom { .. } => OpenVMChipRowKind::Phantom,
            OpenVMChipRowPayload::Program { .. } => OpenVMChipRowKind::Program,
            OpenVMChipRowPayload::Connector { .. } => OpenVMChipRowKind::Connector,
            OpenVMChipRowPayload::Padding { .. } => OpenVMChipRowKind::Padding,
        };

        if self.kind != expected {
            return Err(format!(
                "kind/payload mismatch: kind={:?}, payload expects {:?}",
                self.kind, expected
            ));
        }
        Ok(())
    }
}
