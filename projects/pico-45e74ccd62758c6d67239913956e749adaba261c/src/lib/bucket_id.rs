use strum::{AsRefStr, EnumIter, EnumString, VariantNames};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, EnumString, VariantNames, AsRefStr)]
pub enum PicoBucketId {
    #[strum(serialize = "pico.input.has_load")]
    InputHasLoad,
    #[strum(serialize = "pico.input.has_store")]
    InputHasStore,
    #[strum(serialize = "pico.input.has_auipc")]
    InputHasAuipc,

    #[strum(serialize = "pico.reg.store_addr_zero_via_x0")]
    RegStoreAddrZeroViaX0,

    #[strum(serialize = "pico.sem.memory.timestamped_load_path")]
    SemMemoryTimestampedLoadPath,
    #[strum(serialize = "pico.sem.lookup.boolean_multiplicity")]
    SemLookupBooleanMultiplicity,
}
