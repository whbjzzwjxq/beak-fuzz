use strum::{AsRefStr, EnumIter, EnumString, VariantNames};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, EnumString, VariantNames, AsRefStr)]
pub enum PicoBucketId {
    #[strum(serialize = "pico.input.has_load")]
    InputHasLoad,
    #[strum(serialize = "pico.input.has_store")]
    InputHasStore,
    #[strum(serialize = "pico.input.has_auipc")]
    InputHasAuipc,

    #[strum(serialize = "pico.loop1.oracle.regzero_store_addr0")]
    Loop1OracleRegzeroStoreAddr0,

    #[strum(serialize = "pico.loop2.target.mem_load_path")]
    Loop2TargetMemLoadPath,
    #[strum(serialize = "pico.loop2.target.multiplicity_bool_constraint")]
    Loop2TargetMultiplicityBoolConstraint,
}
