use strum::{AsRefStr, EnumIter, EnumString, VariantNames};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, EnumString, VariantNames, AsRefStr)]
pub enum OpenVMBucketId {
    #[strum(serialize = "openvm.input.has_ecall")]
    InputHasEcall,
    #[strum(serialize = "openvm.input.has_csr")]
    InputHasCsr,
    #[strum(serialize = "openvm.input.has_fence")]
    InputHasFence,

    #[strum(serialize = "openvm.time.start_nonzero")]
    TimeStartNonzero,
    #[strum(serialize = "openvm.time.non_monotonic")]
    TimeNonMonotonic,
    #[strum(serialize = "openvm.time.delta_not_one")]
    TimeDeltaNotOne,
    #[strum(serialize = "openvm.time.row_timestamp_missing")]
    TimeRowTimestampMissing,

    #[strum(serialize = "openvm.row.invalid_in_kind")]
    RowInvalidInKind,
    #[strum(serialize = "openvm.row.invalid_seen")]
    RowInvalidSeen,
    #[strum(serialize = "openvm.row.padding_kind_seen")]
    RowPaddingKindSeen,

    #[strum(serialize = "openvm.reg.write_x0")]
    RegWriteX0,
    #[strum(serialize = "openvm.reg.read_rs1_x0")]
    RegReadRs1X0,
    #[strum(serialize = "openvm.reg.read_rs2_x0")]
    RegReadRs2X0,
    #[strum(serialize = "openvm.reg.alias.rd_eq_rs1")]
    RegAliasRdEqRs1,
    #[strum(serialize = "openvm.reg.alias.rd_eq_rs2")]
    RegAliasRdEqRs2,
    #[strum(serialize = "openvm.reg.alias.rs1_eq_rs2")]
    RegAliasRs1EqRs2,

    #[strum(serialize = "openvm.imm.rs2_is_imm")]
    ImmRs2IsImm,
    #[strum(serialize = "openvm.imm.value.0")]
    ImmValue0,
    #[strum(serialize = "openvm.imm.value.minus1")]
    ImmValueMinus1,
    #[strum(serialize = "openvm.imm.value.min")]
    ImmValueMin,
    #[strum(serialize = "openvm.imm.value.max")]
    ImmValueMax,
    #[strum(serialize = "openvm.imm.sign_true")]
    ImmSignTrue,

    #[strum(serialize = "openvm.alu.base_alu_seen")]
    AluBaseAluSeen,

    #[strum(serialize = "openvm.divrem.div_by_zero")]
    DivRemDivByZero,
    #[strum(serialize = "openvm.divrem.overflow_case")]
    DivRemOverflowCase,
    #[strum(serialize = "openvm.divrem.rs1_eq_rs2")]
    DivRemRs1EqRs2,

    #[strum(serialize = "openvm.branch.imm.0")]
    BranchImm0,
    #[strum(serialize = "openvm.branch.imm.pm2")]
    BranchImmPm2,
    #[strum(serialize = "openvm.branch.imm.pm2048")]
    BranchImmPm2048,

    #[strum(serialize = "openvm.auipc.seen")]
    AuipcSeen,

    #[strum(serialize = "openvm.mem.access_seen")]
    MemAccessSeen,
    #[strum(serialize = "openvm.mem.addr_space.is_0")]
    MemAddrSpaceIs0,
    #[strum(serialize = "openvm.mem.addr_space.is_reg")]
    MemAddrSpaceIsReg,
    #[strum(serialize = "openvm.mem.addr_space.is_other")]
    MemAddrSpaceIsOther,
    #[strum(serialize = "openvm.mem.imm_sign_true")]
    MemImmSignTrue,
    #[strum(serialize = "openvm.mem.effective_ptr_zero")]
    MemEffectivePtrZero,
    #[strum(serialize = "openvm.mem.effective_ptr_unaligned2")]
    MemEffectivePtrUnaligned2,
    #[strum(serialize = "openvm.mem.effective_ptr_unaligned4")]
    MemEffectivePtrUnaligned4,
    #[strum(serialize = "openvm.mem.alias.rs1_eq_rd_rs2.load")]
    MemAliasRs1EqRdRs2Load,
    #[strum(serialize = "openvm.mem.alias.rs1_eq_rd_rs2.store")]
    MemAliasRs1EqRdRs2Store,
    #[strum(serialize = "openvm.mem.alias.rs1_eq_rd_rs2.other")]
    MemAliasRs1EqRdRs2Other,

    #[strum(serialize = "openvm.system.terminate")]
    SystemTerminate,
    #[strum(serialize = "openvm.system.program_row")]
    SystemProgramRow,

    #[strum(serialize = "openvm.interaction.range_check.seen")]
    InteractionRangeCheckSeen,
    #[strum(serialize = "openvm.interaction.range_check.max_bits_0")]
    InteractionRangeCheckMaxBits0,
    #[strum(serialize = "openvm.interaction.range_check.max_bits_gt_32")]
    InteractionRangeCheckMaxBitsGt32,
    #[strum(serialize = "openvm.interaction.range_check.value_out_of_range")]
    InteractionRangeCheckValueOutOfRange,

    #[strum(serialize = "openvm.interaction.execution.seen")]
    InteractionExecutionSeen,
    #[strum(serialize = "openvm.interaction.execution.pc_zero")]
    InteractionExecutionPcZero,
    #[strum(serialize = "openvm.interaction.execution.timestamp_non_monotonic")]
    InteractionExecutionTimestampNonMonotonic,

    #[strum(serialize = "openvm.interaction.memory.seen")]
    InteractionMemorySeen,
    #[strum(serialize = "openvm.interaction.memory.addr_space.is_0")]
    InteractionMemoryAddrSpaceIs0,
    #[strum(serialize = "openvm.interaction.memory.addr_space.is_reg")]
    InteractionMemoryAddrSpaceIsReg,
    #[strum(serialize = "openvm.interaction.memory.addr_space.is_other")]
    InteractionMemoryAddrSpaceIsOther,
    #[strum(serialize = "openvm.interaction.memory.pointer_zero")]
    InteractionMemoryPointerZero,
    #[strum(serialize = "openvm.interaction.memory.timestamp_non_monotonic")]
    InteractionMemoryTimestampNonMonotonic,

    #[strum(serialize = "openvm.interaction.bitwise.seen")]
    InteractionBitwiseSeen,
    #[strum(serialize = "openvm.interaction.bitwise.op_range_mode")]
    InteractionBitwiseOpRangeMode,
    #[strum(serialize = "openvm.interaction.bitwise.op_xor")]
    InteractionBitwiseOpXor,
    #[strum(serialize = "openvm.interaction.bitwise.x_eq_y")]
    InteractionBitwiseXEqY,
    #[strum(serialize = "openvm.interaction.bitwise.z_eq_0")]
    InteractionBitwiseZEq0,

    #[strum(serialize = "openvm.loop2.inactive_row.step_has_interaction")]
    Loop2InactiveRowStepHasInteraction,
    #[strum(serialize = "openvm.loop2.target.base_alu_imm_limbs")]
    Loop2TargetBaseAluImmLimbs,
}
