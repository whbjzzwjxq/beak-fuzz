#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticBucketCategory {
    Alu,
    Arithmetic,
    Control,
    Decode,
    Exec,
    Interaction,
    Lookup,
    Memory,
    Row,
    Time,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticBucket {
    pub id: &'static str,
    pub semantic_class: &'static str,
    pub category: SemanticBucketCategory,
}

impl SemanticBucket {
    pub const fn new(
        id: &'static str,
        semantic_class: &'static str,
        category: SemanticBucketCategory,
    ) -> Self {
        Self { id, semantic_class, category }
    }
}

pub mod alu {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const COMPARISON_AUXILIARY_CHAIN: SemanticBucket = SemanticBucket::new(
        "sem.alu.comparison_auxiliary_chain",
        "semantic.alu.comparison_auxiliary_chain",
        SemanticBucketCategory::Alu,
    );

    pub const COMPARISON_BOOLEANITY: SemanticBucket = SemanticBucket::new(
        "sem.alu.comparison_booleanity",
        "semantic.alu.comparison_booleanity",
        SemanticBucketCategory::Alu,
    );

    pub const IMMEDIATE_LIMB_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.alu.immediate_limb_consistency",
        "semantic.alu.immediate_limb_consistency",
        SemanticBucketCategory::Alu,
    );

    pub const SHIFT_MOD32: SemanticBucket = SemanticBucket::new(
        "sem.alu.shift_mod32",
        "semantic.alu.shift_mod32",
        SemanticBucketCategory::Alu,
    );

    pub const SUBTRACTION_BORROW_CHAIN: SemanticBucket = SemanticBucket::new(
        "sem.alu.subtraction_borrow_chain",
        "semantic.alu.subtraction_borrow_chain",
        SemanticBucketCategory::Alu,
    );
}

pub mod arithmetic {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const DIVISION_REMAINDER_BOUND: SemanticBucket = SemanticBucket::new(
        "sem.arithmetic.division_remainder_bound",
        "semantic.arithmetic.division_remainder_bound",
        SemanticBucketCategory::Arithmetic,
    );

    pub const PRODUCT_DECOMPOSITION: SemanticBucket = SemanticBucket::new(
        "sem.arithmetic.product_decomposition",
        "semantic.arithmetic.product_decomposition",
        SemanticBucketCategory::Arithmetic,
    );

    pub const SIGNED_UNSIGNED_PRODUCT_CORRECTION: SemanticBucket = SemanticBucket::new(
        "sem.arithmetic.signed_unsigned_product_correction",
        "semantic.arithmetic.signed_unsigned_product_correction",
        SemanticBucketCategory::Arithmetic,
    );

    pub const SPECIAL_CASE_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.arithmetic.special_case_consistency",
        "semantic.arithmetic.special_case_consistency",
        SemanticBucketCategory::Arithmetic,
    );
}

pub mod control {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const AUIPC_PC_LIMB_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.control.auipc_pc_limb_consistency",
        "semantic.control.auipc_pc_limb_consistency",
        SemanticBucketCategory::Control,
    );

    pub const ECALL_ARGUMENT_DECOMPOSITION: SemanticBucket = SemanticBucket::new(
        "sem.control.ecall_argument_decomposition",
        "semantic.control.ecall_argument_decomposition",
        SemanticBucketCategory::Control,
    );

    pub const ECALL_WORD_VALIDITY: SemanticBucket = SemanticBucket::new(
        "sem.control.ecall_word_validity",
        "semantic.control.ecall_word_validity",
        SemanticBucketCategory::Control,
    );

    pub const ENTRYPOINT_BINDING: SemanticBucket = SemanticBucket::new(
        "sem.control.entrypoint_binding",
        "semantic.control.entrypoint_binding",
        SemanticBucketCategory::Control,
    );
}

pub mod decode {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const FIELD_RANGE: SemanticBucket = SemanticBucket::new(
        "sem.decode.field_range",
        "semantic.decode.field_range",
        SemanticBucketCategory::Decode,
    );

    pub const FORMAT_IMMEDIATE_REASSEMBLY: SemanticBucket = SemanticBucket::new(
        "sem.decode.format_immediate_reassembly",
        "semantic.decode.format_immediate_reassembly",
        SemanticBucketCategory::Decode,
    );

    pub const IMMEDIATE_SIGN_EXTENSION: SemanticBucket = SemanticBucket::new(
        "sem.decode.immediate_sign_extension",
        "semantic.decode.immediate_sign_extension",
        SemanticBucketCategory::Decode,
    );

    pub const OPERAND_INDEX_ROUTING: SemanticBucket = SemanticBucket::new(
        "sem.decode.operand_index_routing",
        "semantic.decode.operand_index_routing",
        SemanticBucketCategory::Decode,
    );

    pub const RD_BIT_DECOMPOSITION: SemanticBucket = SemanticBucket::new(
        "sem.decode.rd_bit_decomposition",
        "semantic.decode.rd_bit_decomposition",
        SemanticBucketCategory::Decode,
    );

    pub const UPPER_IMMEDIATE_MATERIALIZATION: SemanticBucket = SemanticBucket::new(
        "sem.decode.upper_immediate_materialization",
        "semantic.decode.upper_immediate_materialization",
        SemanticBucketCategory::Decode,
    );

    pub const ZERO_REGISTER_IMMUTABILITY: SemanticBucket = SemanticBucket::new(
        "sem.decode.zero_register_immutability",
        "semantic.decode.zero_register_immutability",
        SemanticBucketCategory::Decode,
    );
}

pub mod exec {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const SOURCE_OPERAND_BINDING: SemanticBucket = SemanticBucket::new(
        "sem.exec.source_operand_binding",
        "semantic.exec.source_operand_binding",
        SemanticBucketCategory::Exec,
    );

    pub const DEST_BINDING: SemanticBucket = SemanticBucket::new(
        "sem.exec.dest_binding",
        "semantic.exec.dest_binding",
        SemanticBucketCategory::Exec,
    );

    pub const OP_SELECTOR_BINDING: SemanticBucket = SemanticBucket::new(
        "sem.exec.op_selector_binding",
        "semantic.exec.op_selector_binding",
        SemanticBucketCategory::Exec,
    );

    pub const CONTROL_FLOW_BINDING: SemanticBucket = SemanticBucket::new(
        "sem.exec.control_flow_binding",
        "semantic.exec.control_flow_binding",
        SemanticBucketCategory::Exec,
    );

    pub const MEMORY_EFFECT_BINDING: SemanticBucket = SemanticBucket::new(
        "sem.exec.memory_effect_binding",
        "semantic.exec.memory_effect_binding",
        SemanticBucketCategory::Exec,
    );

    pub const PARTIAL_WORD_WRITE_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.exec.partial_word_write_consistency",
        "semantic.exec.partial_word_write_consistency",
        SemanticBucketCategory::Exec,
    );
}

pub mod interaction {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const DIGEST_KIND_ROUTE: SemanticBucket = SemanticBucket::new(
        "sem.interaction.digest_kind_route",
        "semantic.interaction.digest_kind_route",
        SemanticBucketCategory::Interaction,
    );
}

pub mod lookup {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const BOOLEAN_MULTIPLICITY: SemanticBucket = SemanticBucket::new(
        "sem.lookup.boolean_multiplicity",
        "semantic.lookup.boolean_multiplicity_consistency",
        SemanticBucketCategory::Lookup,
    );

    pub const XOR_MULTIPLICITY_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.lookup.xor_multiplicity_consistency",
        "semantic.lookup.multiplicity_consistency",
        SemanticBucketCategory::Lookup,
    );
}

pub mod memory {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const ADDRESS_ALIGNMENT_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.memory.address_alignment_consistency",
        "semantic.memory.address_alignment_consistency",
        SemanticBucketCategory::Memory,
    );

    pub const ADDRESS_PROGRESSION_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.memory.address_progression_consistency",
        "semantic.memory.address_progression_consistency",
        SemanticBucketCategory::Memory,
    );

    pub const ADDRESS_SPACE_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.memory.address_space_consistency",
        "semantic.memory.address_space_consistency",
        SemanticBucketCategory::Memory,
    );

    pub const ADDRESS_BOUNDARY_RANGE: SemanticBucket = SemanticBucket::new(
        "sem.memory.address_boundary_range",
        "semantic.memory.address_boundary_range",
        SemanticBucketCategory::Memory,
    );

    pub const IMMEDIATE_SIGN_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.memory.immediate_sign_consistency",
        "semantic.memory.immediate_sign_consistency",
        SemanticBucketCategory::Memory,
    );

    pub const FINALIZATION_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.memory.finalization_consistency",
        "semantic.memory.finalization_consistency",
        SemanticBucketCategory::Memory,
    );

    pub const INITIAL_VALUE_BINDING: SemanticBucket = SemanticBucket::new(
        "sem.memory.initial_value_binding",
        "semantic.memory.initial_value_binding",
        SemanticBucketCategory::Memory,
    );

    pub const KIND_SELECTOR_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.memory.kind_selector_consistency",
        "semantic.memory.kind_selector_consistency",
        SemanticBucketCategory::Memory,
    );

    pub const LOAD_VALUE_BINDING: SemanticBucket = SemanticBucket::new(
        "sem.memory.load_value_binding",
        "semantic.memory.load_value_binding",
        SemanticBucketCategory::Memory,
    );

    pub const STORE_LOAD_PAYLOAD_FLOW: SemanticBucket = SemanticBucket::new(
        "sem.memory.store_load_payload_flow",
        "semantic.memory.write_payload_flow_consistency",
        SemanticBucketCategory::Memory,
    );

    pub const TIMESTAMPED_LOAD_PATH: SemanticBucket = SemanticBucket::new(
        "sem.memory.timestamped_load_path",
        "semantic.memory.timestamped_load_path_consistency",
        SemanticBucketCategory::Memory,
    );

    pub const VOLATILE_BOUNDARY_RANGE: SemanticBucket = SemanticBucket::new(
        "sem.memory.volatile_boundary_range",
        "semantic.memory.volatile_boundary_range",
        SemanticBucketCategory::Memory,
    );

    pub const WRITE_PAYLOAD_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.memory.write_payload_consistency",
        "semantic.memory.write_payload_flow_consistency",
        SemanticBucketCategory::Memory,
    );
}

pub mod row {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const PADDING_INTERACTION_SEND: SemanticBucket = SemanticBucket::new(
        "sem.row.padding_interaction_send",
        "semantic.row.padding_interaction_send",
        SemanticBucketCategory::Row,
    );

    pub const TABLE_POWER2_BOUNDARY: SemanticBucket = SemanticBucket::new(
        "sem.row.table_power2_boundary",
        "semantic.row.table_power2_boundary",
        SemanticBucketCategory::Row,
    );

    pub const BYTECODE_TABLE_BOUNDARY: SemanticBucket = SemanticBucket::new(
        "sem.row.bytecode_table_boundary",
        "semantic.row.bytecode_table_boundary",
        SemanticBucketCategory::Row,
    );
}

pub mod time {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const BOUNDARY_ORIGIN_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.time.boundary_origin_consistency",
        "semantic.time.boundary_origin_consistency",
        SemanticBucketCategory::Time,
    );

    pub const MONOTONIC_ACCESS_ORDERING: SemanticBucket = SemanticBucket::new(
        "sem.time.monotonic_access_ordering",
        "semantic.time.monotonic_access_ordering",
        SemanticBucketCategory::Time,
    );
}

pub const ALL_BUCKETS: &[SemanticBucket] = &[
    alu::COMPARISON_AUXILIARY_CHAIN,
    alu::COMPARISON_BOOLEANITY,
    alu::IMMEDIATE_LIMB_CONSISTENCY,
    alu::SHIFT_MOD32,
    alu::SUBTRACTION_BORROW_CHAIN,
    arithmetic::DIVISION_REMAINDER_BOUND,
    arithmetic::PRODUCT_DECOMPOSITION,
    arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION,
    arithmetic::SPECIAL_CASE_CONSISTENCY,
    control::AUIPC_PC_LIMB_CONSISTENCY,
    control::ECALL_ARGUMENT_DECOMPOSITION,
    control::ECALL_WORD_VALIDITY,
    control::ENTRYPOINT_BINDING,
    decode::FIELD_RANGE,
    decode::FORMAT_IMMEDIATE_REASSEMBLY,
    decode::IMMEDIATE_SIGN_EXTENSION,
    decode::OPERAND_INDEX_ROUTING,
    decode::RD_BIT_DECOMPOSITION,
    decode::UPPER_IMMEDIATE_MATERIALIZATION,
    decode::ZERO_REGISTER_IMMUTABILITY,
    exec::SOURCE_OPERAND_BINDING,
    exec::DEST_BINDING,
    exec::OP_SELECTOR_BINDING,
    exec::CONTROL_FLOW_BINDING,
    exec::MEMORY_EFFECT_BINDING,
    exec::PARTIAL_WORD_WRITE_CONSISTENCY,
    interaction::DIGEST_KIND_ROUTE,
    lookup::BOOLEAN_MULTIPLICITY,
    lookup::XOR_MULTIPLICITY_CONSISTENCY,
    memory::ADDRESS_ALIGNMENT_CONSISTENCY,
    memory::ADDRESS_BOUNDARY_RANGE,
    memory::ADDRESS_PROGRESSION_CONSISTENCY,
    memory::ADDRESS_SPACE_CONSISTENCY,
    memory::FINALIZATION_CONSISTENCY,
    memory::IMMEDIATE_SIGN_CONSISTENCY,
    memory::INITIAL_VALUE_BINDING,
    memory::KIND_SELECTOR_CONSISTENCY,
    memory::LOAD_VALUE_BINDING,
    memory::STORE_LOAD_PAYLOAD_FLOW,
    memory::TIMESTAMPED_LOAD_PATH,
    memory::VOLATILE_BOUNDARY_RANGE,
    memory::WRITE_PAYLOAD_CONSISTENCY,
    row::PADDING_INTERACTION_SEND,
    row::TABLE_POWER2_BOUNDARY,
    row::BYTECODE_TABLE_BOUNDARY,
    time::BOUNDARY_ORIGIN_CONSISTENCY,
    time::MONOTONIC_ACCESS_ORDERING,
];

pub fn by_id(id: &str) -> Option<SemanticBucket> {
    ALL_BUCKETS.iter().copied().find(|bucket| bucket.id == id)
}
