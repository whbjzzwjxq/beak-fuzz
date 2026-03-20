#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticBucketCategory {
    Alu,
    Arithmetic,
    Control,
    Decode,
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

    pub const IMMEDIATE_LIMB_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.alu.immediate_limb_consistency",
        "semantic.alu.immediate_limb_consistency",
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

    pub const ECALL_NEXT_PC: SemanticBucket = SemanticBucket::new(
        "sem.control.ecall_next_pc",
        "semantic.control.ecall_next_pc",
        SemanticBucketCategory::Control,
    );

    pub const ECALL_ARGUMENT_DECOMPOSITION: SemanticBucket = SemanticBucket::new(
        "sem.control.ecall_argument_decomposition",
        "semantic.control.ecall_argument_decomposition",
        SemanticBucketCategory::Control,
    );
}

pub mod decode {
    use super::{SemanticBucket, SemanticBucketCategory};

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

    pub const ADDRESS_SPACE_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.memory.address_space_consistency",
        "semantic.memory.address_space_consistency",
        SemanticBucketCategory::Memory,
    );

    pub const IMMEDIATE_SIGN_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.memory.immediate_sign_consistency",
        "semantic.memory.immediate_sign_consistency",
        SemanticBucketCategory::Memory,
    );

    pub const KIND_SELECTOR_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.memory.kind_selector_consistency",
        "semantic.memory.kind_selector_consistency",
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
}

pub mod time {
    use super::{SemanticBucket, SemanticBucketCategory};

    pub const BOUNDARY_ORIGIN_CONSISTENCY: SemanticBucket = SemanticBucket::new(
        "sem.time.boundary_origin_consistency",
        "semantic.time.boundary_origin_consistency",
        SemanticBucketCategory::Time,
    );
}

pub const ALL_BUCKETS: &[SemanticBucket] = &[
    alu::IMMEDIATE_LIMB_CONSISTENCY,
    arithmetic::DIVISION_REMAINDER_BOUND,
    arithmetic::SPECIAL_CASE_CONSISTENCY,
    control::AUIPC_PC_LIMB_CONSISTENCY,
    control::ECALL_ARGUMENT_DECOMPOSITION,
    control::ECALL_NEXT_PC,
    decode::OPERAND_INDEX_ROUTING,
    decode::RD_BIT_DECOMPOSITION,
    decode::UPPER_IMMEDIATE_MATERIALIZATION,
    decode::ZERO_REGISTER_IMMUTABILITY,
    interaction::DIGEST_KIND_ROUTE,
    lookup::BOOLEAN_MULTIPLICITY,
    lookup::XOR_MULTIPLICITY_CONSISTENCY,
    memory::ADDRESS_SPACE_CONSISTENCY,
    memory::IMMEDIATE_SIGN_CONSISTENCY,
    memory::KIND_SELECTOR_CONSISTENCY,
    memory::STORE_LOAD_PAYLOAD_FLOW,
    memory::TIMESTAMPED_LOAD_PATH,
    memory::VOLATILE_BOUNDARY_RANGE,
    memory::WRITE_PAYLOAD_CONSISTENCY,
    row::PADDING_INTERACTION_SEND,
    time::BOUNDARY_ORIGIN_CONSISTENCY,
];

pub fn by_id(id: &str) -> Option<SemanticBucket> {
    ALL_BUCKETS.iter().copied().find(|bucket| bucket.id == id)
}
