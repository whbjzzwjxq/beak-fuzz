use std::collections::HashMap;

use crypto_bigint::U256;

pub type GateValue = U256;
/// Trace column value (field element as u256 for cross-VM portability).
pub type FieldElement = U256;

/// Direction of an interaction: send (producer) or receive (consumer).
#[derive(Debug, Clone)]
pub enum InteractionType {
    /// Send interaction.
    SEND,
    /// Receive interaction.
    RECV,
}

/// Balancing domain for the interaction: local (permutation/logup) or global (ledger/digest).
#[derive(Debug, Clone)]
pub enum InteractionScope {
    /// Balanced via a global ledger/table, often anchored to a public digest/sum.
    GLOBAL,
    /// Balanced within a private permutation/logup domain.
    LOCAL,
}

/// Proof-domain kind of the interaction (memory, ALU, hash, etc.).
#[derive(Debug, Clone, Copy)]
pub enum InteractionKind {
    MEMORY,
    PROGRAM,
    INSTRUCTION,
    ALU,
    BYTE,
    RANGE,
    FIELD,
    SYSCALL,
    GLOBAL,
    POSEIDON2,
    BITWISE,
    KECCAK,
    SHA256,
    CUSTOM,
}

/// Address space for memory interactions (RAM, registers, volatile, I/O).
#[derive(Debug, Clone, Copy, Default)]
pub enum MemorySpace {
    #[default]
    RAM,
    REG,
    VOLATILE,
    IO,
}

/// Size of a memory access in bytes.
#[derive(Debug, Clone, Copy, Default)]
pub enum MemorySize {
    BYTE,
    HALF,
    #[default]
    WORD,
}

impl MemorySize {
    pub fn len(self) -> usize {
        match self {
            MemorySize::BYTE => 1,
            MemorySize::HALF => 2,
            MemorySize::WORD => 4,
        }
    }
}

/// Kind of chip row in the trace; coarse but cross-zkVM friendly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChipRowKind {
    PROGRAM,
    CONTROLFLOW,
    ALU,
    MEMORY,
    CONNECTOR,
    CPU,
    HASH,
    SYSCALL,
    CUSTOM,
}

/// Shared fields for every chip row (row_id, domain, chip, gates, event_id).
#[derive(Debug, Clone)]
pub struct ChipRowBase {
    pub row_id: String,
    pub domain: String,
    pub chip: String,
    pub gates: HashMap<String, GateValue>,
    pub event_id: Option<String>,
}

/// A single row in a zkVM AIR/chip trace; use the enum for typed chip-specific rows.
#[derive(Debug, Clone)]
pub struct ChipRow {
    pub row_id: String,
    pub domain: String,
    pub chip: String,
    pub kind: ChipRowKind,
    pub gates: HashMap<String, GateValue>,
    pub event_id: Option<String>,
}

// ---- Typed chip rows (one struct per chip, optional columns) ----

#[derive(Debug, Clone)]
pub struct ProgramChipRow {
    pub base: ChipRowBase,
    pub pc: Option<FieldElement>,
    pub opcode: Option<FieldElement>,
    pub op_a: Option<FieldElement>,
    pub op_b: Option<FieldElement>,
    pub op_c: Option<FieldElement>,
    pub imm_b: Option<bool>,
    pub imm_c: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ControlFlowChipRow {
    pub base: ChipRowBase,
    pub pc: Option<FieldElement>,
    pub next_pc: Option<FieldElement>,
    pub from_pc: Option<FieldElement>,
    pub to_pc: Option<FieldElement>,
    pub from_timestamp: Option<FieldElement>,
    pub to_timestamp: Option<FieldElement>,
    pub opcode: Option<FieldElement>,
    pub clk: Option<FieldElement>,
    pub op_a: Option<FieldElement>,
    pub op_b: Option<FieldElement>,
    pub op_c: Option<FieldElement>,
    pub imm_b: Option<bool>,
    pub imm_c: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct AluChipRow {
    pub base: ChipRowBase,
    pub pc: Option<FieldElement>,
    pub clk: Option<FieldElement>,
    pub opcode: Option<FieldElement>,
    pub rd: Option<FieldElement>,
    pub rs1: Option<FieldElement>,
    pub rs2: Option<FieldElement>,
    pub imm: Option<FieldElement>,
    pub value: Option<FieldElement>,
    pub op_a: Option<FieldElement>,
    pub op_b: Option<FieldElement>,
    pub op_c: Option<FieldElement>,
    pub imm_b: Option<bool>,
    pub imm_c: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct MemoryChipRow {
    pub base: ChipRowBase,
    pub pc: Option<FieldElement>,
    pub clk: Option<FieldElement>,
    pub opcode: Option<FieldElement>,
    pub from_pc: Option<FieldElement>,
    pub to_pc: Option<FieldElement>,
    pub from_timestamp: Option<FieldElement>,
    pub to_timestamp: Option<FieldElement>,
    pub addr: Option<FieldElement>,
    pub value: Option<FieldElement>,
    pub size_bytes: Option<FieldElement>,
    pub space: Option<FieldElement>,
    pub is_write: Option<bool>,
    pub rd: Option<FieldElement>,
    pub rs1: Option<FieldElement>,
    pub rs2: Option<FieldElement>,
    pub op_a: Option<FieldElement>,
    pub op_b: Option<FieldElement>,
    pub op_c: Option<FieldElement>,
    pub imm_b: Option<bool>,
    pub imm_c: Option<bool>,
    pub record_id: Option<FieldElement>,
    pub length: Option<FieldElement>,
    pub access_count: Option<FieldElement>,
}

#[derive(Debug, Clone)]
pub struct ConnectorChipRow {
    pub base: ChipRowBase,
    pub pc: Option<FieldElement>,
    pub from_pc: Option<FieldElement>,
    pub to_pc: Option<FieldElement>,
    pub timestamp: Option<FieldElement>,
    pub from_timestamp: Option<FieldElement>,
    pub to_timestamp: Option<FieldElement>,
    pub access_count: Option<FieldElement>,
    pub width: Option<FieldElement>,
}

#[derive(Debug, Clone)]
pub struct CpuChipRow {
    pub base: ChipRowBase,
    pub pc: Option<FieldElement>,
    pub clk: Option<FieldElement>,
    pub opcode: Option<FieldElement>,
    pub op_a: Option<FieldElement>,
    pub op_b: Option<FieldElement>,
    pub op_c: Option<FieldElement>,
    pub imm_b: Option<bool>,
    pub imm_c: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct HashChipRow {
    pub base: ChipRowBase,
    pub pc: Option<FieldElement>,
    pub clk: Option<FieldElement>,
    pub opcode: Option<FieldElement>,
    pub value: Option<FieldElement>,
}

#[derive(Debug, Clone)]
pub struct SyscallChipRow {
    pub base: ChipRowBase,
    pub pc: Option<FieldElement>,
    pub clk: Option<FieldElement>,
    pub opcode: Option<FieldElement>,
    pub syscall_id: Option<FieldElement>,
}

#[derive(Debug, Clone)]
pub struct CustomChipRow {
    pub base: ChipRowBase,
    pub pc: Option<FieldElement>,
    pub opcode: Option<FieldElement>,
}

/// Enum of all chip row types for “one of” handling and pattern matching.
#[derive(Debug, Clone)]
pub enum ChipRowTyped {
    Program(ProgramChipRow),
    ControlFlow(ControlFlowChipRow),
    Alu(AluChipRow),
    Memory(MemoryChipRow),
    Connector(ConnectorChipRow),
    Cpu(CpuChipRow),
    Hash(HashChipRow),
    Syscall(SyscallChipRow),
    Custom(CustomChipRow),
}

impl ChipRowTyped {
    pub fn kind(&self) -> ChipRowKind {
        match self {
            ChipRowTyped::Program(_) => ChipRowKind::PROGRAM,
            ChipRowTyped::ControlFlow(_) => ChipRowKind::CONTROLFLOW,
            ChipRowTyped::Alu(_) => ChipRowKind::ALU,
            ChipRowTyped::Memory(_) => ChipRowKind::MEMORY,
            ChipRowTyped::Connector(_) => ChipRowKind::CONNECTOR,
            ChipRowTyped::Cpu(_) => ChipRowKind::CPU,
            ChipRowTyped::Hash(_) => ChipRowKind::HASH,
            ChipRowTyped::Syscall(_) => ChipRowKind::SYSCALL,
            ChipRowTyped::Custom(_) => ChipRowKind::CUSTOM,
        }
    }

    pub fn base(&self) -> &ChipRowBase {
        match self {
            ChipRowTyped::Program(r) => &r.base,
            ChipRowTyped::ControlFlow(r) => &r.base,
            ChipRowTyped::Alu(r) => &r.base,
            ChipRowTyped::Memory(r) => &r.base,
            ChipRowTyped::Connector(r) => &r.base,
            ChipRowTyped::Cpu(r) => &r.base,
            ChipRowTyped::Hash(r) => &r.base,
            ChipRowTyped::Syscall(r) => &r.base,
            ChipRowTyped::Custom(r) => &r.base,
        }
    }
}


/// Multiplicity (count/weight) for balancing; optional ref to anchor-row field for provenance.
#[derive(Debug, Clone)]
pub struct InteractionMultiplicity {
    pub value: Option<FieldElement>,
    /// Convention: "gates.<key>" or "<attr>" on the anchor row.
    pub ref_: Option<String>,
}

/// Common fields for every interaction (table_id, io, scope, anchor, event_id, kind, multiplicity).
#[derive(Debug, Clone)]
pub struct InteractionBase {
    pub table_id: String,
    pub io: InteractionType,
    pub scope: Option<InteractionScope>,
    pub anchor_row_id: Option<String>,
    pub event_id: Option<String>,
    pub kind: InteractionKind,
    pub multiplicity: Option<InteractionMultiplicity>,
}

impl Default for InteractionBase {
    fn default() -> Self {
        Self {
            table_id: String::new(),
            io: InteractionType::SEND,
            scope: None,
            anchor_row_id: None,
            event_id: None,
            kind: InteractionKind::CUSTOM,
            multiplicity: None,
        }
    }
}

fn encode_memory_space(space: MemorySpace) -> FieldElement {
    let n = match space {
        MemorySpace::RAM => 0u64,
        MemorySpace::REG => 1,
        MemorySpace::VOLATILE => 2,
        MemorySpace::IO => 3,
    };
    FieldElement::from(n)
}

fn hash_payload_to_vec(h: &HashInteractionPayload) -> Vec<FieldElement> {
    vec![
        FieldElement::from(h.block_idx),
        h.in_lo,
        h.in_hi,
        h.out_lo,
        h.out_hi,
    ]
}

fn encode_interaction_kind(kind: InteractionKind) -> FieldElement {
    let n = match kind {
        InteractionKind::MEMORY => 0u64,
        InteractionKind::PROGRAM => 1,
        InteractionKind::INSTRUCTION => 2,
        InteractionKind::ALU => 3,
        InteractionKind::BYTE => 4,
        InteractionKind::RANGE => 5,
        InteractionKind::FIELD => 6,
        InteractionKind::SYSCALL => 7,
        InteractionKind::GLOBAL => 8,
        InteractionKind::POSEIDON2 => 9,
        InteractionKind::BITWISE => 10,
        InteractionKind::KECCAK => 11,
        InteractionKind::SHA256 => 12,
        InteractionKind::CUSTOM => 13,
    };
    FieldElement::from(n)
}

// ---- Interaction payload structs (base + kind-specific fields) ----

#[derive(Debug, Clone)]
pub struct MemoryInteraction {
    pub base: InteractionBase,
    pub space: MemorySpace,
    pub addr: u64,
    pub size: MemorySize,
    pub value: FieldElement,
    pub is_write: bool,
    pub wen: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ProgramInteraction {
    pub base: InteractionBase,
    pub pc: u64,
    pub inst_word: u64,
    pub next_pc: u64,
}

#[derive(Debug, Clone)]
pub struct InstructionInteraction {
    pub base: InteractionBase,
    pub opcode: u64,
    pub rd: u64,
    pub rs1: u64,
    pub rs2: u64,
    pub imm: u64,
}

#[derive(Debug, Clone)]
pub struct AluInteraction {
    pub base: InteractionBase,
    pub op: u64,
    pub a: FieldElement,
    pub b: FieldElement,
    pub out: FieldElement,
}

#[derive(Debug, Clone)]
pub struct ByteInteraction {
    pub base: InteractionBase,
    pub value: FieldElement,
}

#[derive(Debug, Clone)]
pub struct RangeInteraction {
    pub base: InteractionBase,
    pub value: FieldElement,
    pub bits: u64,
}

#[derive(Debug, Clone)]
pub struct FieldInteraction {
    pub base: InteractionBase,
    pub value: FieldElement,
}

#[derive(Debug, Clone)]
pub struct SyscallInteraction {
    pub base: InteractionBase,
    pub syscall_id: u64,
    pub arg0: FieldElement,
    pub arg1: FieldElement,
    pub arg2: FieldElement,
    pub arg3: FieldElement,
    pub ret0: FieldElement,
}

#[derive(Debug, Clone)]
pub struct GlobalInteraction {
    pub base: InteractionBase,
    pub local_kind: InteractionKind,
    pub digest_lo: FieldElement,
    pub digest_hi: FieldElement,
}

#[derive(Debug, Clone)]
pub struct BitwiseInteraction {
    pub base: InteractionBase,
    pub op: u64,
    pub a: FieldElement,
    pub b: FieldElement,
    pub out: FieldElement,
}

/// Common payload shape for hash-like chips (POSEIDON2 / KECCAK / SHA256).
#[derive(Debug, Clone)]
pub struct HashInteractionPayload {
    pub block_idx: u64,
    pub in_lo: FieldElement,
    pub in_hi: FieldElement,
    pub out_lo: FieldElement,
    pub out_hi: FieldElement,
}

#[derive(Debug, Clone)]
pub struct Poseidon2Interaction {
    pub base: InteractionBase,
    pub hash: HashInteractionPayload,
}

#[derive(Debug, Clone)]
pub struct KeccakInteraction {
    pub base: InteractionBase,
    pub hash: HashInteractionPayload,
}

#[derive(Debug, Clone)]
pub struct Sha256Interaction {
    pub base: InteractionBase,
    pub hash: HashInteractionPayload,
}

#[derive(Debug, Clone)]
pub struct CustomInteraction {
    pub base: InteractionBase,
    pub a0: FieldElement,
    pub a1: FieldElement,
    pub a2: FieldElement,
    pub a3: FieldElement,
}

/// Enum of all interaction types for "one of" handling and payload access.
#[derive(Debug, Clone)]
pub enum Interaction {
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
    Custom(CustomInteraction),
}

impl Interaction {
    pub fn kind(&self) -> InteractionKind {
        match self {
            Interaction::Memory(_) => InteractionKind::MEMORY,
            Interaction::Program(_) => InteractionKind::PROGRAM,
            Interaction::Instruction(_) => InteractionKind::INSTRUCTION,
            Interaction::Alu(_) => InteractionKind::ALU,
            Interaction::Byte(_) => InteractionKind::BYTE,
            Interaction::Range(_) => InteractionKind::RANGE,
            Interaction::Field(_) => InteractionKind::FIELD,
            Interaction::Syscall(_) => InteractionKind::SYSCALL,
            Interaction::Global(_) => InteractionKind::GLOBAL,
            Interaction::Bitwise(_) => InteractionKind::BITWISE,
            Interaction::Poseidon2(_) => InteractionKind::POSEIDON2,
            Interaction::Keccak(_) => InteractionKind::KECCAK,
            Interaction::Sha256(_) => InteractionKind::SHA256,
            Interaction::Custom(_) => InteractionKind::CUSTOM,
        }
    }

    pub fn base(&self) -> &InteractionBase {
        match self {
            Interaction::Memory(x) => &x.base,
            Interaction::Program(x) => &x.base,
            Interaction::Instruction(x) => &x.base,
            Interaction::Alu(x) => &x.base,
            Interaction::Byte(x) => &x.base,
            Interaction::Range(x) => &x.base,
            Interaction::Field(x) => &x.base,
            Interaction::Syscall(x) => &x.base,
            Interaction::Global(x) => &x.base,
            Interaction::Bitwise(x) => &x.base,
            Interaction::Poseidon2(x) => &x.base,
            Interaction::Keccak(x) => &x.base,
            Interaction::Sha256(x) => &x.base,
            Interaction::Custom(x) => &x.base,
        }
    }

    pub fn payload_schema(&self) -> &'static [&'static str] {
        match self {
            Interaction::Memory(_) => &["space", "addr", "size_bytes", "value", "is_write", "wen"],
            Interaction::Program(_) => &["pc", "inst_word", "next_pc"],
            Interaction::Instruction(_) => &["opcode", "rd", "rs1", "rs2", "imm"],
            Interaction::Alu(_) => &["op", "a", "b", "out"],
            Interaction::Byte(_) => &["value"],
            Interaction::Range(_) => &["value", "bits"],
            Interaction::Field(_) => &["value"],
            Interaction::Syscall(_) => &["syscall_id", "arg0", "arg1", "arg2", "arg3", "ret0"],
            Interaction::Global(_) => &["local_kind", "digest_lo", "digest_hi"],
            Interaction::Bitwise(_) => &["op", "a", "b", "out"],
            Interaction::Poseidon2(_) | Interaction::Keccak(_) | Interaction::Sha256(_) => {
                &["block_idx", "in_lo", "in_hi", "out_lo", "out_hi"]
            }
            Interaction::Custom(_) => &["a0", "a1", "a2", "a3"],
        }
    }

    pub fn payload(&self) -> Vec<FieldElement> {
        match self {
            Interaction::Memory(x) => vec![
                encode_memory_space(x.space),
                FieldElement::from(x.addr),
                FieldElement::from(x.size.len() as u64),
                x.value,
                FieldElement::from(if x.is_write { 1u64 } else { 0 }),
                FieldElement::from(x.wen.map(|b| if b { 1u64 } else { 0 }).unwrap_or(1)),
            ],
            Interaction::Program(x) => {
                vec![FieldElement::from(x.pc), FieldElement::from(x.inst_word), FieldElement::from(x.next_pc)]
            }
            Interaction::Instruction(x) => vec![
                FieldElement::from(x.opcode),
                FieldElement::from(x.rd),
                FieldElement::from(x.rs1),
                FieldElement::from(x.rs2),
                FieldElement::from(x.imm),
            ],
            Interaction::Alu(x) => vec![FieldElement::from(x.op), x.a, x.b, x.out],
            Interaction::Byte(x) => vec![x.value],
            Interaction::Range(x) => vec![x.value, FieldElement::from(x.bits)],
            Interaction::Field(x) => vec![x.value],
            Interaction::Syscall(x) => vec![
                FieldElement::from(x.syscall_id),
                x.arg0,
                x.arg1,
                x.arg2,
                x.arg3,
                x.ret0,
            ],
            Interaction::Global(x) => vec![
                encode_interaction_kind(x.local_kind),
                x.digest_lo,
                x.digest_hi,
            ],
            Interaction::Bitwise(x) => vec![FieldElement::from(x.op), x.a, x.b, x.out],
            Interaction::Poseidon2(x) => hash_payload_to_vec(&x.hash),
            Interaction::Keccak(x) => hash_payload_to_vec(&x.hash),
            Interaction::Sha256(x) => hash_payload_to_vec(&x.hash),
            Interaction::Custom(x) => vec![x.a0, x.a1, x.a2, x.a3],
        }
    }

    pub fn payload_value(&self, name: &str) -> Option<FieldElement> {
        let schema = self.payload_schema();
        let idx = schema.iter().position(|s| *s == name)?;
        let payload = self.payload();
        payload.get(idx).cloned()
    }

    pub fn payload_as_dict(&self) -> HashMap<String, FieldElement> {
        let schema = self.payload_schema();
        let payload = self.payload();
        schema
            .iter()
            .zip(payload.iter())
            .map(|(k, v)| (k.to_string(), *v))
            .collect()
    }
}

/// A micro-op is either a chip row or an interaction.
#[derive(Debug, Clone)]
pub enum MicroOp {
    ChipRow(ChipRow),
    Interaction(Interaction),
}

/// Ordered list of micro-ops plus indexed views (by table, by chip row id, by anchor, op_spans).
#[derive(Debug, Clone)]
pub struct ZKVMTrace {
    pub micro_ops: Vec<MicroOp>,
    /// Optional op-level grouping: each span is indices into `micro_ops` for one "core instruction".
    pub op_spans: Option<Vec<Vec<usize>>>,
    pub chip_rows: Vec<ChipRow>,
    pub interactions: Vec<Interaction>,
    pub interactions_by_table: HashMap<String, Vec<Interaction>>,
    pub chip_rows_by_id: HashMap<String, ChipRow>,
    pub chip_rows_by_kind: HashMap<ChipRowKind, Vec<ChipRow>>,
    pub interactions_by_anchor_row_id: HashMap<String, Vec<Interaction>>,
}

impl ZKVMTrace {
    /// Build a trace from `micro_ops`, optional extra `chip_rows`, and optional `op_spans`.
    pub fn new(
        micro_ops: Vec<MicroOp>,
        chip_rows: Option<Vec<ChipRow>>,
        op_spans: Option<Vec<Vec<usize>>>,
    ) -> Result<Self, String> {
        let len = micro_ops.len();
        if let Some(ref spans) = op_spans {
            for (op_idx, span) in spans.iter().enumerate() {
                if span.is_empty() {
                    return Err(format!("op_spans[{}] is empty", op_idx));
                }
                for &i in span {
                    if i >= len {
                        return Err(format!(
                            "op_spans[{}] contains out-of-range index {} (len(micro_ops)={})",
                            op_idx, i, len
                        ));
                    }
                }
            }
        }

        let chip_rows: Vec<ChipRow> = micro_ops
            .iter()
            .filter_map(|u| match u {
                MicroOp::ChipRow(r) => Some(r.clone()),
                _ => None,
            })
            .chain(chip_rows.into_iter().flatten())
            .collect();

        let interactions: Vec<Interaction> = micro_ops
            .iter()
            .filter_map(|u| match u {
                MicroOp::Interaction(i) => Some(i.clone()),
                _ => None,
            })
            .collect();

        let mut interactions_by_table: HashMap<String, Vec<Interaction>> = HashMap::new();
        for uop in &interactions {
            interactions_by_table
                .entry(uop.base().table_id.clone())
                .or_default()
                .push(uop.clone());
        }

        let chip_rows_by_id: HashMap<String, ChipRow> =
            chip_rows.iter().map(|r| (r.row_id.clone(), r.clone())).collect();

        let mut chip_rows_by_kind: HashMap<ChipRowKind, Vec<ChipRow>> = HashMap::new();
        for row in &chip_rows {
            chip_rows_by_kind
                .entry(row.kind.clone())
                .or_default()
                .push(row.clone());
        }

        let mut interactions_by_anchor_row_id: HashMap<String, Vec<Interaction>> = HashMap::new();
        for uop in &interactions {
            if let Some(ref aid) = uop.base().anchor_row_id {
                interactions_by_anchor_row_id
                    .entry(aid.clone())
                    .or_default()
                    .push(uop.clone());
            }
        }

        Ok(Self {
            micro_ops,
            op_spans,
            chip_rows,
            interactions,
            interactions_by_table,
            chip_rows_by_id,
            chip_rows_by_kind,
            interactions_by_anchor_row_id,
        })
    }

    pub fn by_table_id(&self, table_id: &str) -> &[Interaction] {
        self.interactions_by_table
            .get(table_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn chip_row(&self, row_id: &str) -> Option<&ChipRow> {
        self.chip_rows_by_id.get(row_id)
    }

    pub fn chip_rows_of_kind(&self, kind: &ChipRowKind) -> &[ChipRow] {
        self.chip_rows_by_kind
            .get(kind)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn by_anchor_row_id(&self, row_id: &str) -> &[Interaction] {
        self.interactions_by_anchor_row_id
            .get(row_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn op_micro_ops(&self, op_idx: usize) -> Result<Vec<MicroOp>, String> {
        let spans = self
            .op_spans
            .as_ref()
            .ok_or_else(|| "Trace has no op_spans; op-level access is unavailable".to_string())?;
        let span = spans
            .get(op_idx)
            .ok_or_else(|| format!("op_spans has no index {}", op_idx))?;
        Ok(span.iter().filter_map(|&i| self.micro_ops.get(i).cloned()).collect())
    }

    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.micro_ops.is_empty() {
            errors.push("Trace is empty".to_string());
            return errors;
        }
        if self.chip_rows_by_id.len() != self.chip_rows.len() {
            errors.push("Trace has duplicate ChipRow.row_id values".to_string());
        }
        for uop in &self.interactions {
            if let Some(ref aid) = uop.base().anchor_row_id {
                if !self.chip_rows_by_id.contains_key(aid) {
                    errors.push(format!("Interaction references missing anchor_row_id={:?}", aid));
                }
            }
        }
        errors
    }
}
