use beak_core::trace::micro_ops::interaction::Interaction;
use openvm_instructions::VmOpcode;
use serde::{Deserialize, Serialize};
use strum::{EnumString, VariantNames};

use crate::chip_row::{FieldElement, Pc, Timestamp};
use crate::{MemorySize, MemorySpace};

/// Direction of an interaction: send (producer) or receive (consumer).
#[derive(Debug, Clone, Copy, EnumString, VariantNames, Serialize, Deserialize)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum InteractionType {
    /// Send interaction.
    Send,
    /// Receive interaction.
    Recv,
}

/// Balancing domain for the interaction: local (permutation/logup) or global (ledger/digest).
#[derive(Debug, Clone, Copy, EnumString, VariantNames, Serialize, Deserialize)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum InteractionScope {
    /// Balanced via a global ledger/table, often anchored to a public digest/sum.
    Global,
    /// Balanced within a private permutation/logup domain.
    Local,
}

/// Proof-domain kind of the interaction (memory, ALU, hash, etc.).
#[derive(Debug, Clone, Copy, EnumString, VariantNames, Serialize, Deserialize)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum InteractionKind {
    Memory,
    Program,
    Instruction,
    Alu,
    Byte,
    Range,
    Field,
    Syscall,
    Global,
    Poseidon2,
    Bitwise,
    Keccak,
    Sha256,
}

/// Multiplicity (count/weight) for balancing; optional ref to anchor-row field for provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionMultiplicity {
    /// The effective multiplicity/weight \(m\) as a field element.
    ///
    /// Convention: if `OpenVMInteractionBase.multiplicity` is `None`, consumers treat \(m = 1\).
    pub value: FieldElement,
    /// Optional provenance pointer to the anchor-row gate/column that produced this multiplicity.
    ///
    /// Convention: "gates.<key>" or "<attr>" on the anchor row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_path: Option<String>,
}

/// Common fields for every interaction.
///
/// Style intentionally mirrors `OpenVMChipRowBase`: `seq`, `step_idx`, `op_idx`, and then
/// typed payload structs for per-kind fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVMInteractionBase {
    /// Global sequence number emitted by the openvm.
    pub seq: u64,

    /// Step index of the instruction.
    /// Use this to group chip rows by step and refer to the Insn fields.
    pub step_idx: u64,

    /// Micro-op index within a single `step`.
    pub op_idx: u64,

    /// Unique identifier of the chip row.
    pub row_id: String,

    /// Kind of the interaction.
    pub kind: InteractionKind,

    /// Balancing scope.
    pub scope: InteractionScope,

    /// OpenVM has the concept of timestamp.
    /// But some interactions like xxx do not have timestamp.
    pub timestamp: Option<Timestamp>,

    /// Name of the interaction table.
    pub table_name: String,

    /// Direction: send (producer) or recv (consumer).
    pub io: InteractionType,

    /// Balancing multiplicity.
    pub multiplicity: InteractionMultiplicity,
}

// ---- Interaction payload structs (base + kind-specific fields) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInteraction {
    pub base: OpenVMInteractionBase,
    pub space: MemorySpace,
    pub addr: u64,
    pub size: MemorySize,
    pub value: FieldElement,
    pub is_write: bool,
    pub wen: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInteraction {
    pub base: OpenVMInteractionBase,
    pub pc: Pc,
    pub inst_word: u32,
    pub next_pc: Pc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInteraction {
    pub base: OpenVMInteractionBase,
    /// OpenVM global/system opcode.
    pub opcode: VmOpcode,
    pub rd: u32,
    pub rs1: u32,
    pub rs2: u32,
    pub imm: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AluInteraction {
    pub base: OpenVMInteractionBase,
    pub op: u64,
    pub a: FieldElement,
    pub b: FieldElement,
    pub out: FieldElement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteInteraction {
    pub base: OpenVMInteractionBase,
    pub value: FieldElement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeInteraction {
    pub base: OpenVMInteractionBase,
    pub value: FieldElement,
    pub bits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInteraction {
    pub base: OpenVMInteractionBase,
    pub value: FieldElement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInteraction {
    pub base: OpenVMInteractionBase,
    pub syscall_id: u64,
    pub arg0: FieldElement,
    pub arg1: FieldElement,
    pub arg2: FieldElement,
    pub arg3: FieldElement,
    pub ret0: FieldElement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalInteraction {
    pub base: OpenVMInteractionBase,
    pub local_kind: InteractionKind,
    pub digest_lo: FieldElement,
    pub digest_hi: FieldElement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitwiseInteraction {
    pub base: OpenVMInteractionBase,
    pub op: u64,
    pub a: FieldElement,
    pub b: FieldElement,
    pub out: FieldElement,
}

/// Common payload shape for hash-like chips (POSEIDON2 / KECCAK / SHA256).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashInteractionPayload {
    pub block_idx: u64,
    pub in_lo: FieldElement,
    pub in_hi: FieldElement,
    pub out_lo: FieldElement,
    pub out_hi: FieldElement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Poseidon2Interaction {
    pub base: OpenVMInteractionBase,
    pub hash: HashInteractionPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeccakInteraction {
    pub base: OpenVMInteractionBase,
    pub hash: HashInteractionPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sha256Interaction {
    pub base: OpenVMInteractionBase,
    pub hash: HashInteractionPayload,
}

/// Enum of all interaction types for "one of" handling and payload access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpenVMInteraction {
    Memory(MemoryInteraction),
    Program(ProgramInteraction),
    Instruction(InstructionInteraction),
    Alu(AluInteraction),
    Byte(ByteInteraction),
    Range(RangeInteraction),
    Field(FieldInteraction),
    Syscall(SyscallInteraction),
    Global(GlobalInteraction),
    Bitwise(BitwiseInteraction),
    Poseidon2(Poseidon2Interaction),
    Keccak(KeccakInteraction),
    Sha256(Sha256Interaction),
}

impl OpenVMInteraction {
    pub fn base(&self) -> &OpenVMInteractionBase {
        match self {
            OpenVMInteraction::Memory(x) => &x.base,
            OpenVMInteraction::Program(x) => &x.base,
            OpenVMInteraction::Instruction(x) => &x.base,
            OpenVMInteraction::Alu(x) => &x.base,
            OpenVMInteraction::Byte(x) => &x.base,
            OpenVMInteraction::Range(x) => &x.base,
            OpenVMInteraction::Field(x) => &x.base,
            OpenVMInteraction::Syscall(x) => &x.base,
            OpenVMInteraction::Global(x) => &x.base,
            OpenVMInteraction::Bitwise(x) => &x.base,
            OpenVMInteraction::Poseidon2(x) => &x.base,
            OpenVMInteraction::Keccak(x) => &x.base,
            OpenVMInteraction::Sha256(x) => &x.base,
        }
    }

    pub fn kind(&self) -> InteractionKind {
        match self {
            OpenVMInteraction::Memory(x) => x.base.kind,
            OpenVMInteraction::Program(x) => x.base.kind,
            OpenVMInteraction::Instruction(x) => x.base.kind,
            OpenVMInteraction::Alu(x) => x.base.kind,
            OpenVMInteraction::Byte(x) => x.base.kind,
            OpenVMInteraction::Range(x) => x.base.kind,
            OpenVMInteraction::Field(x) => x.base.kind,
            OpenVMInteraction::Syscall(x) => x.base.kind,
            OpenVMInteraction::Global(x) => x.base.kind,
            OpenVMInteraction::Bitwise(x) => x.base.kind,
            OpenVMInteraction::Poseidon2(x) => x.base.kind,
            OpenVMInteraction::Keccak(x) => x.base.kind,
            OpenVMInteraction::Sha256(x) => x.base.kind,
        }
    }
}

impl Interaction for OpenVMInteraction {}
