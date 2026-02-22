use beak_core::trace::micro_ops::chip_row::ChipRow;
use openvm_instructions::VmOpcode;
use openvm_rv32im_transpiler::{
    BaseAluOpcode, DivRemOpcode, LessThanOpcode, MulHOpcode, Rv32LoadStoreOpcode,
    ShiftOpcode,
};
use serde::{Deserialize, Serialize};
use strum::{EnumString, VariantNames};

use crate::MemorySize;

/// OpenVM uses a boolean gate value.
pub type GateValue = bool;

/// OpenVM uses a 32-bit timestamp.
pub type Timestamp = u32;

/// OpenVM uses a 32-bit PC.
pub type Pc = u32;

/// OpenVM uses a 32-bit field element.
pub type FieldElement = u32;

/// Kind of chip row in the trace.
#[derive(Debug, Clone, Copy, EnumString, VariantNames, Serialize, Deserialize)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OpenVMChipRowKind {
    Program,
    Controlflow,
    Alu,
    Memory,
    Connector,
    Cpu,
    Hash,
    Syscall,
}

/// A single row in a zkVM AIR/chip trace; use the enum for typed chip-specific rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVMChipRowBase {
    /// Global sequence number emitted by the openvm.
    pub seq: u64,

    /// Step index of the instruction.
    /// Use this to group chip rows by step and refer to the Insn fields.
    pub step_idx: u64,

    /// Micro-op index within a single `step`.
    pub op_idx: u64,

    /// Unique identifier of the chip row.
    pub row_id: String,

    /// Whether the chip row is valid.
    pub is_valid: GateValue,

    /// Kind of the chip row.
    pub kind: OpenVMChipRowKind,

    /// OpenVM has the concept of timestamp.
    /// But some chip rows like connector do not have timestamp.
    pub timestamp: Option<Timestamp>,

    /// Name of the chip.
    pub chip_name: String,
}

// ---- Typed chip rows (one struct per chip, optional columns) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramChipRow {
    pub base: OpenVMChipRowBase,

    /// OpenVM opcode (global/system opcode).
    pub opcode: VmOpcode,

    /// OpenVM instruction operands (a..g).
    pub operands: [u32; 7],
}

/// Kind of chip row in the trace.
#[derive(Debug, Clone, Copy, EnumString, VariantNames, Serialize, Deserialize)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ControlFlowKind {
    Branch,
    Jump,
    Terminal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowChipRow {
    pub base: OpenVMChipRowBase,

    /// Control-flow edge.
    pub from_pc: Pc,
    pub to_pc: Pc,

    /// Optional clock edge (OpenVM's timestamp).
    pub from_timestamp: Option<Timestamp>,
    pub to_timestamp: Option<Timestamp>,

    /// Branch semantics
    pub kind: ControlFlowKind,
    pub rs1: Option<u32>,
    pub rs2: Option<u32>,
    pub imm: Option<i32>,
    pub is_taken: Option<GateValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rs2Source {
    Reg { rs2_ptr: u32 },
    Imm { imm: i32, imm_limbs: [u8; 4] },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AluOp {
    BaseAlu(BaseAluOpcode),
    Shift(ShiftOpcode),
    LessThan(LessThanOpcode),
    /// RV32IM `MUL` (OpenVM currently models this as a singleton local opcode).
    Mul,
    MulH(MulHOpcode),
    DivRem(DivRemOpcode),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AluChipRow {
    pub base: OpenVMChipRowBase,

    /// Which ALU semantics this row is about.
    pub op: AluOp,

    /// Architectural register pointers (not values).
    pub rd_ptr: u32,
    pub rs1_ptr: u32,

    /// rs2 source selection (this is the key gating signal).
    pub rs2: Rs2Source,

    /// Whether a register write is supposed to happen (ties into gating buckets).
    pub needs_write: GateValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryOp {
    Rv32LoadStore(Rv32LoadStoreOpcode),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryChipRow {
    pub base: OpenVMChipRowBase,

    pub op: MemoryOp,

    /// OpenVM address space selector (raw).
    pub mem_as: u32,

    /// Base register pointer (rs1) in register address space.
    pub rs1_ptr: u32,

    /// For LOAD: destination register pointer. For STORE: source register pointer.
    pub rd_rs2_ptr: u32,

    /// Signed immediate offset and its sign bit (explicit for buckets).
    pub imm: i32,
    pub imm_sign: bool,

    /// Access size / direction.
    pub is_write: GateValue,
    pub size: MemorySize,

    /// Effective address/pointer actually used on the memory bus (after shift/sign).
    pub effective_ptr: u32,

    /// Whether the op actually writes back to reg (e.g. load to x0 should be gated off).
    pub needs_write: GateValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorChipRow {
    pub base: OpenVMChipRowBase,

    /// Execution-state edge constrained by the connector (execution bus).
    pub from_pc: Pc,
    pub to_pc: Pc,
    pub from_timestamp: Option<Timestamp>,
    pub to_timestamp: Option<Timestamp>,

    /// Segment termination marker (connector public values / termination semantics).
    pub is_terminate: GateValue,
    pub exit_code: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuChipRow {
    pub base: OpenVMChipRowBase,

    /// OpenVM opcode (global opcode).
    pub opcode: VmOpcode,

    /// OpenVM instruction operands (a..g) as canonical u32 values.
    pub operands: [u32; 7],
}

#[derive(Debug, Clone, Copy, EnumString, VariantNames, Serialize, Deserialize)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum HashOp {
    Poseidon2,
    Keccak,
    Sha256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashChipRow {
    pub base: OpenVMChipRowBase,

    /// Hash family.
    pub op: HashOp,

    /// Canonical hash payload (shape matches the hash interaction payload buckets).
    pub block_idx: u64,
    pub in_lo: FieldElement,
    pub in_hi: FieldElement,
    pub out_lo: FieldElement,
    pub out_hi: FieldElement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallChipRow {
    pub base: OpenVMChipRowBase,

    /// Syscall identifier (canonical).
    pub syscall_id: u32,

    /// Optional return value if observed at this layer.
    pub ret0: Option<FieldElement>,
}

/// Enum of all chip row types for “one of” handling and pattern matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpenVMChipRow {
    Program(ProgramChipRow),
    ControlFlow(ControlFlowChipRow),
    Alu(AluChipRow),
    Memory(MemoryChipRow),
    Connector(ConnectorChipRow),
    Cpu(CpuChipRow),
    Hash(HashChipRow),
    Syscall(SyscallChipRow),
}

impl OpenVMChipRow {
    pub fn base(&self) -> &OpenVMChipRowBase {
        match self {
            OpenVMChipRow::Program(r) => &r.base,
            OpenVMChipRow::ControlFlow(r) => &r.base,
            OpenVMChipRow::Alu(r) => &r.base,
            OpenVMChipRow::Memory(r) => &r.base,
            OpenVMChipRow::Connector(r) => &r.base,
            OpenVMChipRow::Cpu(r) => &r.base,
            OpenVMChipRow::Hash(r) => &r.base,
            OpenVMChipRow::Syscall(r) => &r.base,
        }
    }

    pub fn kind(&self) -> OpenVMChipRowKind {
        match self {
            OpenVMChipRow::Program(r) => r.base.kind,
            OpenVMChipRow::ControlFlow(r) => r.base.kind,
            OpenVMChipRow::Alu(r) => r.base.kind,
            OpenVMChipRow::Memory(r) => r.base.kind,
            OpenVMChipRow::Connector(r) => r.base.kind,
            OpenVMChipRow::Cpu(r) => r.base.kind,
            OpenVMChipRow::Hash(r) => r.base.kind,
            OpenVMChipRow::Syscall(r) => r.base.kind,
        }
    }
}

impl ChipRow for OpenVMChipRow {}
