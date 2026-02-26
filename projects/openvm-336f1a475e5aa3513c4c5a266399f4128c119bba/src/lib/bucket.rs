use std::collections::{HashMap, HashSet};

use beak_core::trace::BucketHit;
use serde_json::{json, Value};

use crate::bucket_id::OpenVMBucketId;
use crate::chip_row::{OpenVMChipRowKind, OpenVMChipRowPayload, Rs2Source};
use crate::interaction::OpenVMInteractionPayload;
use crate::trace::OpenVMTrace;
use openvm_instructions::riscv::RV32_REGISTER_AS;

fn kind_snake(kind: OpenVMChipRowKind) -> String {
    // `OpenVMChipRowKind` has `#[serde(rename_all = "snake_case")]`, so serializing it yields
    // the canonical snake_case string we want.
    match serde_json::to_value(kind) {
        Ok(Value::String(s)) => s,
        _ => format!("{kind:?}").to_lowercase(),
    }
}

fn le_u32_from_bytes(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[..4]);
    Some(u32::from_le_bytes(arr))
}

fn rs2_reg_ptr(rs2: &Rs2Source) -> Option<u32> {
    match rs2 {
        Rs2Source::Reg { ptr } => Some(*ptr),
        Rs2Source::Imm { .. } => None,
    }
}

fn rs2_imm_value(rs2: &Rs2Source) -> Option<i32> {
    match rs2 {
        Rs2Source::Imm { value } => Some(*value),
        Rs2Source::Reg { .. } => None,
    }
}

fn access_alignment_buckets(
    hits: &mut Vec<BucketHit>,
    seen: &mut HashSet<String>,
    effective_ptr: u32,
) {
    if effective_ptr % 2 != 0 {
        push_hit(
            hits,
            seen,
            OpenVMBucketId::MemEffectivePtrUnaligned2,
            details_kv(&[("effective_ptr", json!(effective_ptr))]),
        );
    }
    if effective_ptr % 4 != 0 {
        push_hit(
            hits,
            seen,
            OpenVMBucketId::MemEffectivePtrUnaligned4,
            details_kv(&[("effective_ptr", json!(effective_ptr))]),
        );
    }
}

fn push_hit(
    hits: &mut Vec<BucketHit>,
    seen: &mut HashSet<String>,
    bucket_id: OpenVMBucketId,
    details: HashMap<String, Value>,
) {
    let id = bucket_id.as_ref().to_string();
    if !seen.insert(id.clone()) {
        return;
    }
    hits.push(BucketHit::new(id, details));
}

fn details_kv(kvs: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    for (k, v) in kvs {
        out.insert((*k).to_string(), v.clone());
    }
    out
}

fn classify_imm_value(v: i32) -> Option<&'static str> {
    match v {
        0 => Some("0"),
        -1 => Some("minus1"),
        i32::MIN => Some("min"),
        i32::MAX => Some("max"),
        _ => None,
    }
}

/// Match OpenVM buckets from the typed trace.
///
/// Contract:
/// - Returns a per-trace deduplicated set of bucket hits (yes/no multi-hot semantics).
/// - Bucket ids are stable strings; details are for reporting only.
pub fn match_bucket_hits(trace: &OpenVMTrace) -> Vec<BucketHit> {
    let mut hits: Vec<BucketHit> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut last_exec_ts: Option<u32> = None;
    let mut last_mem_ts: Option<u32> = None;

    for ia in trace.interactions() {
        match &ia.payload {
            OpenVMInteractionPayload::Execution { pc, timestamp } => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    OpenVMBucketId::InteractionExecutionSeen,
                    HashMap::new(),
                );
                if *pc == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::InteractionExecutionPcZero,
                        details_kv(&[("timestamp", json!(*timestamp))]),
                    );
                }
                if let Some(prev) = last_exec_ts {
                    if *timestamp <= prev {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::InteractionExecutionTimestampNonMonotonic,
                            details_kv(&[("prev", json!(prev)), ("cur", json!(*timestamp))]),
                        );
                    }
                }
                last_exec_ts = Some(*timestamp);
            }
            OpenVMInteractionPayload::RangeCheck { value, max_bits } => {
                push_hit(&mut hits, &mut seen, OpenVMBucketId::InteractionRangeCheckSeen, HashMap::new());

                if *max_bits == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::InteractionRangeCheckMaxBits0,
                        details_kv(&[("value", json!(*value))]),
                    );
                }
                if *max_bits > 32 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::InteractionRangeCheckMaxBitsGt32,
                        details_kv(&[
                            ("value", json!(*value)),
                            ("max_bits", json!(*max_bits)),
                        ]),
                    );
                }
                if *max_bits < 32 && *max_bits > 0 {
                    let limit = 1u64 << (*max_bits as u64);
                    if (*value as u64) >= limit {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::InteractionRangeCheckValueOutOfRange,
                            details_kv(&[
                                ("value", json!(*value)),
                                ("max_bits", json!(*max_bits)),
                            ]),
                        );
                    }
                }
            }
            OpenVMInteractionPayload::Memory {
                address_space,
                pointer,
                data: _,
                timestamp,
            } => {
                push_hit(&mut hits, &mut seen, OpenVMBucketId::InteractionMemorySeen, HashMap::new());

                let as_u32 = *address_space as u32;
                let as_bucket = if as_u32 == 0 {
                    OpenVMBucketId::InteractionMemoryAddrSpaceIs0
                } else if as_u32 == RV32_REGISTER_AS {
                    OpenVMBucketId::InteractionMemoryAddrSpaceIsReg
                } else {
                    OpenVMBucketId::InteractionMemoryAddrSpaceIsOther
                };
                push_hit(
                    &mut hits,
                    &mut seen,
                    as_bucket,
                    details_kv(&[("address_space", json!(as_u32))]),
                );

                if (*pointer as u32) == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::InteractionMemoryPointerZero,
                        details_kv(&[("address_space", json!(as_u32)), ("timestamp", json!(*timestamp))]),
                    );
                }

                if let Some(prev) = last_mem_ts {
                    if *timestamp <= prev {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::InteractionMemoryTimestampNonMonotonic,
                            details_kv(&[("prev", json!(prev)), ("cur", json!(*timestamp))]),
                        );
                    }
                }
                last_mem_ts = Some(*timestamp);
            }
            OpenVMInteractionPayload::Bitwise { x, y, z, op } => {
                push_hit(&mut hits, &mut seen, OpenVMBucketId::InteractionBitwiseSeen, HashMap::new());
                if *op == 0 {
                    push_hit(&mut hits, &mut seen, OpenVMBucketId::InteractionBitwiseOpRangeMode, HashMap::new());
                } else {
                    push_hit(&mut hits, &mut seen, OpenVMBucketId::InteractionBitwiseOpXor, HashMap::new());
                }
                if x == y {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::InteractionBitwiseXEqY,
                        details_kv(&[("x", json!(*x)), ("op", json!(*op))]),
                    );
                }
                if (*z as u32) == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::InteractionBitwiseZEq0,
                        details_kv(&[("x", json!(*x)), ("y", json!(*y)), ("op", json!(*op))]),
                    );
                }
            }
            _ => {}
        }
    }

    // -----------------
    // Instruction-level time buckets
    // -----------------
    if let Some(first) = trace.instructions().first() {
        if first.timestamp != 0 {
            push_hit(
                &mut hits,
                &mut seen,
                OpenVMBucketId::TimeStartNonzero,
                details_kv(&[("timestamp", json!(first.timestamp))]),
            );
        }
    }
    for insn in trace.instructions() {
        if insn.next_timestamp <= insn.timestamp {
            push_hit(
                &mut hits,
                &mut seen,
                OpenVMBucketId::TimeNonMonotonic,
                details_kv(&[
                    ("step_idx", json!(insn.step_idx)),
                    ("timestamp", json!(insn.timestamp)),
                    ("next_timestamp", json!(insn.next_timestamp)),
                ]),
            );
        } else {
            let dt = insn.next_timestamp - insn.timestamp;
            if dt != 1 {
                push_hit(
                    &mut hits,
                    &mut seen,
                    OpenVMBucketId::TimeDeltaNotOne,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("delta", json!(dt)),
                    ]),
                );
            }
        }
    }

    // -----------------
    // Chip-row buckets
    // -----------------
    let mut saw_invalid_row = false;
    let mut saw_padding_kind = false;
    let mut saw_missing_row_timestamp = false;

    for row in trace.chip_rows() {
        let base = row.base();
        let kind = kind_snake(row.kind);
        if !base.is_valid {
            saw_invalid_row = true;
            push_hit(
                &mut hits,
                &mut seen,
                OpenVMBucketId::RowInvalidInKind,
                details_kv(&[
                    ("chip_name", json!(base.chip_name)),
                    ("step_idx", json!(base.step_idx)),
                    ("op_idx", json!(base.op_idx)),
                    ("kind", json!(kind)),
                ]),
            );
        }
        if base.timestamp.is_none() {
            saw_missing_row_timestamp = true;
        }
        if row.kind == OpenVMChipRowKind::Padding {
            saw_padding_kind = true;
        }

        match &row.payload {
            // ---- ALU family (always-write) ----
            OpenVMChipRowPayload::BaseAlu { op: _op, rd_ptr, rs1_ptr, rs2, .. } => {
                // x0 boundary
                if *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegWriteX0,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("chip_name", json!(base.chip_name)),
                        ]),
                    );
                }
                if *rs1_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegReadRs1X0,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("chip_name", json!(base.chip_name)),
                        ]),
                    );
                }
                if let Some(p) = rs2_reg_ptr(rs2) {
                    if p == 0 {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::RegReadRs2X0,
                            details_kv(&[
                                ("kind", json!(kind)),
                                ("chip_name", json!(base.chip_name)),
                            ]),
                        );
                    }
                    if p == *rs1_ptr {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::RegAliasRs1EqRs2,
                            details_kv(&[
                                ("kind", json!(kind)),
                                ("rs1_ptr", json!(*rs1_ptr)),
                                ("rs2_ptr", json!(p)),
                            ]),
                        );
                    }
                    if p == *rd_ptr {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::RegAliasRdEqRs2,
                            details_kv(&[
                                ("kind", json!(kind)),
                                ("rd_ptr", json!(*rd_ptr)),
                                ("rs2_ptr", json!(p)),
                            ]),
                        );
                    }
                }
                if *rd_ptr == *rs1_ptr {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegAliasRdEqRs1,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("rd_ptr", json!(*rd_ptr)),
                            ("rs1_ptr", json!(*rs1_ptr)),
                        ]),
                    );
                }

                // Immediate proxy buckets
                if let Some(v) = rs2_imm_value(rs2) {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::ImmRs2IsImm,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("imm", json!(v)),
                        ]),
                    );
                    if let Some(tag) = classify_imm_value(v) {
                        let id = match tag {
                            "0" => OpenVMBucketId::ImmValue0,
                            "minus1" => OpenVMBucketId::ImmValueMinus1,
                            "min" => OpenVMBucketId::ImmValueMin,
                            "max" => OpenVMBucketId::ImmValueMax,
                            _ => continue,
                        };
                        push_hit(
                            &mut hits,
                            &mut seen,
                            id,
                            details_kv(&[("imm", json!(v))]),
                        );
                    }

                    // Loop2 target (audit-o5 candidate): mutate immediate-limb paths on
                    // ALU-family rows where rs2 comes from an immediate.
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::Loop2TargetBaseAluImmLimbs,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("imm", json!(v)),
                        ]),
                    );
                }

                // Proxy: record base-ALU local opcode id (keeps bucket space bounded by opcode set).
                push_hit(
                    &mut hits,
                    &mut seen,
                    OpenVMBucketId::AluBaseAluSeen,
                    HashMap::new(),
                );
            }

            OpenVMChipRowPayload::Shift { rd_ptr, rs1_ptr, rs2, .. }
            | OpenVMChipRowPayload::LessThan { rd_ptr, rs1_ptr, rs2, .. } => {
                // x0 boundary
                if *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegWriteX0,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("chip_name", json!(base.chip_name)),
                        ]),
                    );
                }
                if *rs1_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegReadRs1X0,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("chip_name", json!(base.chip_name)),
                        ]),
                    );
                }
                if let Some(p) = rs2_reg_ptr(rs2) {
                    if p == 0 {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::RegReadRs2X0,
                            details_kv(&[
                                ("kind", json!(kind)),
                                ("chip_name", json!(base.chip_name)),
                            ]),
                        );
                    }
                    if p == *rs1_ptr {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::RegAliasRs1EqRs2,
                            details_kv(&[
                                ("kind", json!(kind)),
                                ("rs1_ptr", json!(*rs1_ptr)),
                                ("rs2_ptr", json!(p)),
                            ]),
                        );
                    }
                    if p == *rd_ptr {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::RegAliasRdEqRs2,
                            details_kv(&[
                                ("kind", json!(kind)),
                                ("rd_ptr", json!(*rd_ptr)),
                                ("rs2_ptr", json!(p)),
                            ]),
                        );
                    }
                }
                if *rd_ptr == *rs1_ptr {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegAliasRdEqRs1,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("rd_ptr", json!(*rd_ptr)),
                            ("rs1_ptr", json!(*rs1_ptr)),
                        ]),
                    );
                }

                // Immediate proxy buckets
                if let Some(v) = rs2_imm_value(rs2) {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::ImmRs2IsImm,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("imm", json!(v)),
                        ]),
                    );
                    if let Some(tag) = classify_imm_value(v) {
                        let id = match tag {
                            "0" => OpenVMBucketId::ImmValue0,
                            "minus1" => OpenVMBucketId::ImmValueMinus1,
                            "min" => OpenVMBucketId::ImmValueMin,
                            "max" => OpenVMBucketId::ImmValueMax,
                            _ => continue,
                        };
                        push_hit(
                            &mut hits,
                            &mut seen,
                            id,
                            details_kv(&[("imm", json!(v))]),
                        );
                    }
                }
            }

            OpenVMChipRowPayload::Mul { rd_ptr, rs1_ptr, rs2_ptr, .. }
            | OpenVMChipRowPayload::MulH { rd_ptr, rs1_ptr, rs2_ptr, .. }
            | OpenVMChipRowPayload::DivRem { rd_ptr, rs1_ptr, rs2_ptr, .. } => {
                if *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegWriteX0,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("chip_name", json!(base.chip_name)),
                        ]),
                    );
                }
                if *rs1_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegReadRs1X0,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("chip_name", json!(base.chip_name)),
                        ]),
                    );
                }
                if *rs2_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegReadRs2X0,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("chip_name", json!(base.chip_name)),
                        ]),
                    );
                }

                if *rs1_ptr == *rs2_ptr {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegAliasRs1EqRs2,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("rs_ptr", json!(*rs1_ptr)),
                        ]),
                    );
                }
                if *rd_ptr == *rs1_ptr {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegAliasRdEqRs1,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("rd_ptr", json!(*rd_ptr)),
                            ("rs1_ptr", json!(*rs1_ptr)),
                        ]),
                    );
                }
                if *rd_ptr == *rs2_ptr {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegAliasRdEqRs2,
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("rd_ptr", json!(*rd_ptr)),
                            ("rs2_ptr", json!(*rs2_ptr)),
                        ]),
                    );
                }

                // Div/Rem semantic edge cases (proxy for special-case paths).
                if let OpenVMChipRowPayload::DivRem { b, c, rs1_ptr, rs2_ptr, .. } = &row.payload {
                    let rs1 = le_u32_from_bytes(b);
                    let rs2 = le_u32_from_bytes(c);
                    if let (Some(rs1), Some(rs2)) = (rs1, rs2) {
                        if rs2 == 0 {
                            push_hit(
                                &mut hits,
                                &mut seen,
                                OpenVMBucketId::DivRemDivByZero,
                                details_kv(&[
                                    ("rs1", json!(rs1)),
                                    ("rs2", json!(rs2)),
                                    ("rs1_ptr", json!(*rs1_ptr)),
                                    ("rs2_ptr", json!(*rs2_ptr)),
                                ]),
                            );
                        }
                        if rs1 == 0x8000_0000 && rs2 == 0xFFFF_FFFF {
                            push_hit(
                                &mut hits,
                                &mut seen,
                                OpenVMBucketId::DivRemOverflowCase,
                                details_kv(&[
                                    ("rs1", json!(rs1)),
                                    ("rs2", json!(rs2)),
                                ]),
                            );
                        }
                    }
                    if rs1_ptr == rs2_ptr {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::DivRemRs1EqRs2,
                            details_kv(&[("rs_ptr", json!(*rs1_ptr))]),
                        );
                    }
                }
            }

            // ---- Branch family (no writes) ----
            OpenVMChipRowPayload::BranchEqual { rs1_ptr, rs2_ptr, imm, is_taken, .. }
            | OpenVMChipRowPayload::BranchLessThan { rs1_ptr, rs2_ptr, imm, is_taken, .. } => {
                if *rs1_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegReadRs1X0,
                        details_kv(&[("kind", json!(kind))]),
                    );
                }
                if *rs2_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegReadRs2X0,
                        details_kv(&[("kind", json!(kind))]),
                    );
                }
                if rs1_ptr == rs2_ptr {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegAliasRs1EqRs2,
                        details_kv(&[("rs_ptr", json!(*rs1_ptr))]),
                    );
                }

                // Branch immediate extremes.
                match *imm {
                    0 => push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::BranchImm0,
                        details_kv(&[("is_taken", json!(*is_taken))]),
                    ),
                    2 | -2 => push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::BranchImmPm2,
                        details_kv(&[("imm", json!(*imm)), ("is_taken", json!(*is_taken))]),
                    ),
                    2048 | -2048 => push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::BranchImmPm2048,
                        details_kv(&[("imm", json!(*imm)), ("is_taken", json!(*is_taken))]),
                    ),
                    _ => {}
                }
            }

            // ---- Jump family (conditional write) ----
            OpenVMChipRowPayload::JalLui { rd_ptr, needs_write, is_jal, .. } => {
                if *needs_write {
                    if *rd_ptr == 0 {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            OpenVMBucketId::RegWriteX0,
                            details_kv(&[("is_jal", json!(*is_jal))]),
                        );
                    }
                }
            }

            OpenVMChipRowPayload::Jalr { rd_ptr, rs1_ptr, imm, imm_sign, needs_write, .. } => {
                if *rs1_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegReadRs1X0,
                        details_kv(&[]),
                    );
                }
                if *needs_write && *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegWriteX0,
                        details_kv(&[]),
                    );
                }
                if *imm_sign {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::ImmSignTrue,
                        details_kv(&[("imm", json!(*imm))]),
                    );
                }
            }

            // ---- AUIPC ----
            OpenVMChipRowPayload::Auipc { rd_ptr, .. } => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    OpenVMBucketId::AuipcSeen,
                    details_kv(&[]),
                );
                if *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegWriteX0,
                        details_kv(&[]),
                    );
                }
            }

            // ---- Load/Store ----
            OpenVMChipRowPayload::LoadStore {
                op: _op,
                rs1_ptr,
                rd_rs2_ptr,
                imm_sign,
                mem_as,
                effective_ptr,
                is_store,
                is_load,
                needs_write,
                ..
            } => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    OpenVMBucketId::MemAccessSeen,
                    details_kv(&[]),
                );

                let mem_as_bucket = if *mem_as == 0 {
                    OpenVMBucketId::MemAddrSpaceIs0
                } else if *mem_as == RV32_REGISTER_AS {
                    OpenVMBucketId::MemAddrSpaceIsReg
                } else {
                    OpenVMBucketId::MemAddrSpaceIsOther
                };
                push_hit(
                    &mut hits,
                    &mut seen,
                    mem_as_bucket,
                    details_kv(&[("mem_as", json!(*mem_as))]),
                );

                if *imm_sign {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::MemImmSignTrue,
                        details_kv(&[]),
                    );
                }

                if *effective_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::MemEffectivePtrZero,
                        details_kv(&[]),
                    );
                }
                access_alignment_buckets(&mut hits, &mut seen, *effective_ptr);

                if *rs1_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegReadRs1X0,
                        details_kv(&[]),
                    );
                }

                // rd_rs2_ptr is rd for loads, rs2 for stores.
                if *is_store && *rd_rs2_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegReadRs2X0,
                        details_kv(&[]),
                    );
                }
                if *is_load && *needs_write && *rd_rs2_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegWriteX0,
                        details_kv(&[]),
                    );
                }

                if rs1_ptr == rd_rs2_ptr {
                    let id = if *is_store {
                        OpenVMBucketId::MemAliasRs1EqRdRs2Store
                    } else if *is_load {
                        OpenVMBucketId::MemAliasRs1EqRdRs2Load
                    } else {
                        OpenVMBucketId::MemAliasRs1EqRdRs2Other
                    };
                    push_hit(
                        &mut hits,
                        &mut seen,
                        id,
                        details_kv(&[
                            ("rs1_ptr", json!(*rs1_ptr)),
                            ("rd_rs2_ptr", json!(*rd_rs2_ptr)),
                        ]),
                    );
                }

            }

            OpenVMChipRowPayload::LoadSignExtend {
                op: _op,
                rs1_ptr,
                rd_ptr,
                imm_sign,
                mem_as,
                effective_ptr,
                needs_write,
                ..
            } => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    OpenVMBucketId::MemAccessSeen,
                    details_kv(&[]),
                );
                if *imm_sign {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::MemImmSignTrue,
                        details_kv(&[]),
                    );
                }

                let mem_as_bucket = if *mem_as == 0 {
                    OpenVMBucketId::MemAddrSpaceIs0
                } else if *mem_as == RV32_REGISTER_AS {
                    OpenVMBucketId::MemAddrSpaceIsReg
                } else {
                    OpenVMBucketId::MemAddrSpaceIsOther
                };
                push_hit(
                    &mut hits,
                    &mut seen,
                    mem_as_bucket,
                    details_kv(&[("mem_as", json!(*mem_as))]),
                );
                if *effective_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::MemEffectivePtrZero,
                        details_kv(&[]),
                    );
                }
                access_alignment_buckets(&mut hits, &mut seen, *effective_ptr);

                if *rs1_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegReadRs1X0,
                        details_kv(&[]),
                    );
                }
                if *needs_write && *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::RegWriteX0,
                        details_kv(&[]),
                    );
                }

            }

            // ---- System chips ----
            OpenVMChipRowPayload::Connector { is_terminate, exit_code, .. } => {
                if *is_terminate {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        OpenVMBucketId::SystemTerminate,
                        details_kv(&[("exit_code", json!(exit_code))]),
                    );
                }
            }

            OpenVMChipRowPayload::Program { .. } => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    OpenVMBucketId::SystemProgramRow,
                    details_kv(&[]),
                );
            }

            OpenVMChipRowPayload::Padding { .. } | OpenVMChipRowPayload::Phantom { .. } => {}
        }
    }

    if saw_invalid_row {
        push_hit(
            &mut hits,
            &mut seen,
            OpenVMBucketId::RowInvalidSeen,
            HashMap::new(),
        );
    }
    if saw_padding_kind {
        push_hit(
            &mut hits,
            &mut seen,
            OpenVMBucketId::RowPaddingKindSeen,
            HashMap::new(),
        );
    }
    if saw_missing_row_timestamp {
        push_hit(
            &mut hits,
            &mut seen,
            OpenVMBucketId::TimeRowTimestampMissing,
            HashMap::new(),
        );
    }

    // Coarse loop2 candidate (audit-o3): if the same step contains inactive rows
    // and still has interactions, treat it as a mutation target.
    let max_steps = trace.instructions().len();
    for step in 0..max_steps {
        let has_invalid = trace.chip_rows_for_step(step).any(|r| !r.base().is_valid);
        if !has_invalid {
            continue;
        }
        let ia_count = trace.interaction_indices_for_step(step).len();
        if ia_count == 0 {
            continue;
        }
        push_hit(
            &mut hits,
            &mut seen,
            OpenVMBucketId::Loop2InactiveRowStepHasInteraction,
            details_kv(&[
                ("step_idx", json!(step)),
                ("interaction_count", json!(ia_count)),
            ]),
        );
    }

    hits
}
