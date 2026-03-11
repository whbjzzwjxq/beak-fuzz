use strum::{AsRefStr, EnumIter, EnumString, VariantNames};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, EnumString, VariantNames, AsRefStr)]
pub enum Sp1BucketId {
    #[strum(serialize = "sp1.input.has_load")]
    InputHasLoad,
    #[strum(serialize = "sp1.input.has_store")]
    InputHasStore,
    #[strum(serialize = "sp1.input.has_auipc")]
    InputHasAuipc,

    #[strum(serialize = "sp1.reg.store_addr_zero_via_x0")]
    RegStoreAddrZeroViaX0,

    #[strum(serialize = "sp1.sem.memory.timestamped_load_path")]
    SemMemoryTimestampedLoadPath,
    #[strum(serialize = "sp1.sem.lookup.boolean_multiplicity")]
    SemLookupBooleanMultiplicity,
}
