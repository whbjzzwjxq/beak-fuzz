#[derive(Debug, Clone)]
pub struct SequenceInsnObservation {
    pub step_idx: u64,
    pub word: u32,
    pub mnemonic: String,
    pub rs1: Option<u32>,
    pub imm: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
pub struct SequenceSemanticMatcherProfile {
    pub emit_padding_interaction_send: bool,
    pub emit_boolean_on_store: bool,
    pub emit_boolean_on_load_after_store: bool,
    pub emit_kind_selector: bool,
    pub emit_digest_route: bool,
    pub emit_ecall_next_pc: bool,
}

#[derive(Debug, Clone)]
pub struct UpperImmediateInsnObservation {
    pub op_idx: u64,
    pub pc: u64,
    pub raw_word: u32,
}

#[derive(Debug, Clone)]
pub struct MemoryWriteObservation {
    pub op_idx: u64,
    pub pc: u32,
    pub address: u32,
    pub size_bytes: u8,
    pub value: u32,
    pub prev_value: u32,
    pub has_followup_load: bool,
}

#[derive(Debug, Clone)]
pub struct ImmediateLimbObservation {
    pub step_idx: u64,
    pub op_idx: u64,
    pub kind: String,
    pub chip_name: String,
    pub imm: i32,
}

#[derive(Debug, Clone)]
pub struct XorMultiplicityObservation {
    pub step_idx: u64,
    pub op_idx: u64,
    pub kind: String,
    pub chip_name: String,
    pub lhs: u32,
    pub rhs: u32,
}

#[derive(Debug, Clone)]
pub struct AuipcPcLimbObservation {
    pub step_idx: u64,
    pub op_idx: u64,
    pub kind: String,
    pub chip_name: String,
    pub from_pc: u32,
    pub imm: u32,
}

#[derive(Debug, Clone)]
pub struct MemoryImmediateSignObservation {
    pub step_idx: u64,
    pub op_idx: u64,
    pub kind: String,
    pub chip_name: String,
    pub imm: i32,
    pub imm_sign: bool,
}

#[derive(Debug, Clone)]
pub struct MemoryAddressSpaceObservation {
    pub step_idx: u64,
    pub op_idx: u64,
    pub kind: String,
    pub chip_name: String,
    pub mem_as: u32,
}

#[derive(Debug, Clone)]
pub struct BoundaryOriginObservation {
    pub step_idx: u64,
    pub op_idx: u64,
    pub kind: String,
    pub chip_name: String,
    pub from_timestamp: Option<u32>,
    pub to_timestamp: Option<u32>,
    pub is_terminate: bool,
}

#[derive(Debug, Clone)]
pub struct VolatileBoundaryObservation {
    pub step_idx: u64,
    pub op_idx: u64,
    pub kind: String,
    pub chip_name: String,
}

#[derive(Debug, Clone)]
pub struct ArithmeticSpecialCaseObservation {
    pub step_idx: u64,
    pub op_idx: u64,
    pub rs1: u32,
    pub rs2: u32,
}
