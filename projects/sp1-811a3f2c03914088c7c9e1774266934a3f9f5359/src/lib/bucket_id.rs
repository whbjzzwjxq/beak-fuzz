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
}
