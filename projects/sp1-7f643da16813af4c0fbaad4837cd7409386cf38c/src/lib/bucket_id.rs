use strum::{AsRefStr, EnumIter, EnumString, VariantNames};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, EnumString, VariantNames, AsRefStr)]
pub enum Sp1BucketId {
    #[strum(serialize = "sp1.input.has_load")]
    InputHasLoad,
    #[strum(serialize = "sp1.input.has_store")]
    InputHasStore,
    #[strum(serialize = "sp1.input.has_auipc")]
    InputHasAuipc,

    #[strum(serialize = "sp1.loop1.oracle.regzero_store_addr0")]
    Loop1OracleRegzeroStoreAddr0,

    #[strum(serialize = "sp1.loop2.target.mem_load_path")]
    Loop2TargetMemLoadPath,
    #[strum(serialize = "sp1.loop2.target.multiplicity_bool_constraint")]
    Loop2TargetMultiplicityBoolConstraint,

    #[strum(serialize = "sp1.loop2.target.s26_padding_send_to_table")]
    Loop2TargetS26PaddingSendToTable,
    #[strum(serialize = "sp1.loop2.target.s27_memory_is_memory")]
    Loop2TargetS27MemoryIsMemory,
    #[strum(serialize = "sp1.loop2.target.s28_ecall_next_pc")]
    Loop2TargetS28EcallNextPc,
    #[strum(serialize = "sp1.loop2.target.s29_digest_interaction_kind")]
    Loop2TargetS29DigestInteractionKind,
}
