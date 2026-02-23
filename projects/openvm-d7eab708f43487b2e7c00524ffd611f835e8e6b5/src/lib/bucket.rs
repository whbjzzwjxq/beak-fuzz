use std::collections::{HashMap, HashSet};

use beak_core::trace::{BucketHit, BucketType};
use serde_json::{json, Value};

use crate::chip_row::{OpenVMChipRowKind, OpenVMChipRowPayload, Rs2Source};
use crate::trace::OpenVMTrace;

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
    // We keep this opcode-agnostic because the tracer currently emits local opcodes as integers.
    if effective_ptr % 2 != 0 {
        push_hit(
            hits,
            seen,
            BucketType::Memory,
            "openvm.mem.effective_ptr_unaligned2".to_string(),
            details_kv(&[("effective_ptr", json!(effective_ptr))]),
        );
    }
    if effective_ptr % 4 != 0 {
        push_hit(
            hits,
            seen,
            BucketType::Memory,
            "openvm.mem.effective_ptr_unaligned4".to_string(),
            details_kv(&[("effective_ptr", json!(effective_ptr))]),
        );
    }
}

fn push_hit(
    hits: &mut Vec<BucketHit>,
    seen: &mut HashSet<String>,
    bucket_type: BucketType,
    bucket_id: String,
    details: HashMap<String, Value>,
) {
    if !seen.insert(bucket_id.clone()) {
        return;
    }
    hits.push(BucketHit::new(bucket_id, bucket_type, details));
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

    // -----------------
    // Instruction-level time buckets
    // -----------------
    if let Some(first) = trace.instructions().first() {
        if first.timestamp != 0 {
            push_hit(
                &mut hits,
                &mut seen,
                BucketType::Time,
                "openvm.time.start_nonzero".to_string(),
                details_kv(&[("timestamp", json!(first.timestamp))]),
            );
        }
    }
    for insn in trace.instructions() {
        if insn.next_timestamp <= insn.timestamp {
            push_hit(
                &mut hits,
                &mut seen,
                BucketType::Time,
                "openvm.time.non_monotonic".to_string(),
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
                    BucketType::Time,
                    "openvm.time.delta_not_one".to_string(),
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
            let kid = format!("openvm.row.invalid_in.{kind}");
            push_hit(
                &mut hits,
                &mut seen,
                BucketType::RowValidity,
                kid,
                details_kv(&[
                    ("chip_name", json!(base.chip_name)),
                    ("step_idx", json!(base.step_idx)),
                    ("op_idx", json!(base.op_idx)),
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
            OpenVMChipRowPayload::BaseAlu { op, rd_ptr, rs1_ptr, rs2, .. } => {
                // x0 boundary
                if *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.write_x0".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.read_rs1_x0".to_string(),
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
                            BucketType::Reg,
                            "openvm.reg.read_rs2_x0".to_string(),
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
                            BucketType::Reg,
                            "openvm.reg.alias.rs1_eq_rs2".to_string(),
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
                            BucketType::Reg,
                            "openvm.reg.alias.rd_eq_rs2".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.alias.rd_eq_rs1".to_string(),
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
                        BucketType::Immediate,
                        "openvm.imm.rs2_is_imm".to_string(),
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("imm", json!(v)),
                        ]),
                    );
                    if let Some(tag) = classify_imm_value(v) {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            BucketType::Immediate,
                            format!("openvm.imm.value.{tag}"),
                            details_kv(&[("imm", json!(v))]),
                        );
                    }
                }

                // Proxy: record base-ALU local opcode id (keeps bucket space bounded by opcode set).
                push_hit(
                    &mut hits,
                    &mut seen,
                    BucketType::AluBitwise,
                    "openvm.alu.base_alu_seen".to_string(),
                    HashMap::new(),
                );
                push_hit(
                    &mut hits,
                    &mut seen,
                    BucketType::AluBitwise,
                    format!("openvm.alu.op.{op}"),
                    details_kv(&[("op", json!(*op))]),
                );
            }

            OpenVMChipRowPayload::Shift { rd_ptr, rs1_ptr, rs2, .. }
            | OpenVMChipRowPayload::LessThan { rd_ptr, rs1_ptr, rs2, .. } => {
                // x0 boundary
                if *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.write_x0".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.read_rs1_x0".to_string(),
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
                            BucketType::Reg,
                            "openvm.reg.read_rs2_x0".to_string(),
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
                            BucketType::Reg,
                            "openvm.reg.alias.rs1_eq_rs2".to_string(),
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
                            BucketType::Reg,
                            "openvm.reg.alias.rd_eq_rs2".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.alias.rd_eq_rs1".to_string(),
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
                        BucketType::Immediate,
                        "openvm.imm.rs2_is_imm".to_string(),
                        details_kv(&[
                            ("kind", json!(kind)),
                            ("imm", json!(v)),
                        ]),
                    );
                    if let Some(tag) = classify_imm_value(v) {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            BucketType::Immediate,
                            format!("openvm.imm.value.{tag}"),
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
                        BucketType::Reg,
                        "openvm.reg.write_x0".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.read_rs1_x0".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.read_rs2_x0".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.alias.rs1_eq_rs2".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.alias.rd_eq_rs1".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.alias.rd_eq_rs2".to_string(),
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
                                BucketType::DivRem,
                                "openvm.divrem.div_by_zero".to_string(),
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
                                BucketType::DivRem,
                                "openvm.divrem.overflow_case".to_string(),
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
                            BucketType::DivRem,
                            "openvm.divrem.rs1_eq_rs2".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.read_rs1_x0".to_string(),
                        details_kv(&[("kind", json!(kind))]),
                    );
                }
                if *rs2_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.read_rs2_x0".to_string(),
                        details_kv(&[("kind", json!(kind))]),
                    );
                }
                if rs1_ptr == rs2_ptr {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.alias.rs1_eq_rs2".to_string(),
                        details_kv(&[("rs_ptr", json!(*rs1_ptr))]),
                    );
                }

                // Branch immediate extremes.
                match *imm {
                    0 => push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Immediate,
                        "openvm.branch.imm.0".to_string(),
                        details_kv(&[("is_taken", json!(*is_taken))]),
                    ),
                    2 | -2 => push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Immediate,
                        "openvm.branch.imm.pm2".to_string(),
                        details_kv(&[("imm", json!(*imm)), ("is_taken", json!(*is_taken))]),
                    ),
                    2048 | -2048 => push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Immediate,
                        "openvm.branch.imm.pm2048".to_string(),
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
                            BucketType::Reg,
                            "openvm.reg.write_x0".to_string(),
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
                        BucketType::Reg,
                        "openvm.reg.read_rs1_x0".to_string(),
                        details_kv(&[]),
                    );
                }
                if *needs_write && *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.write_x0".to_string(),
                        details_kv(&[]),
                    );
                }
                if *imm_sign {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Immediate,
                        "openvm.imm.sign_true".to_string(),
                        details_kv(&[("imm", json!(*imm))]),
                    );
                }
            }

            // ---- AUIPC ----
            OpenVMChipRowPayload::Auipc { rd_ptr, .. } => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    BucketType::Immediate,
                    "openvm.auipc.seen".to_string(),
                    details_kv(&[]),
                );
                if *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.write_x0".to_string(),
                        details_kv(&[]),
                    );
                }
            }

            // ---- Load/Store ----
            OpenVMChipRowPayload::LoadStore {
                op,
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
                    BucketType::Memory,
                    "openvm.mem.access_seen".to_string(),
                    details_kv(&[]),
                );

                if *imm_sign {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Memory,
                        "openvm.mem.imm_sign_true".to_string(),
                        details_kv(&[]),
                    );
                }

                push_hit(
                    &mut hits,
                    &mut seen,
                    BucketType::Memory,
                    format!("openvm.mem.space.{mem_as}"),
                    details_kv(&[]),
                );

                if *effective_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Memory,
                        "openvm.mem.effective_ptr_zero".to_string(),
                        details_kv(&[]),
                    );
                }
                access_alignment_buckets(&mut hits, &mut seen, *effective_ptr);

                if *rs1_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.read_rs1_x0".to_string(),
                        details_kv(&[]),
                    );
                }

                // rd_rs2_ptr is rd for loads, rs2 for stores.
                if *is_store && *rd_rs2_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.read_rs2_x0".to_string(),
                        details_kv(&[]),
                    );
                }
                if *is_load && *needs_write && *rd_rs2_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.write_x0".to_string(),
                        details_kv(&[]),
                    );
                }

                if rs1_ptr == rd_rs2_ptr {
                    let suffix = if *is_store { "store" } else if *is_load { "load" } else { "other" };
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        format!("openvm.mem.alias.rs1_eq_rd_rs2.{suffix}"),
                        details_kv(&[
                            ("rs1_ptr", json!(*rs1_ptr)),
                            ("rd_rs2_ptr", json!(*rd_rs2_ptr)),
                        ]),
                    );
                }

                // Also bucket the local opcode id.
                push_hit(
                    &mut hits,
                    &mut seen,
                    BucketType::Memory,
                    format!("openvm.mem.op.{op}"),
                    details_kv(&[("op", json!(*op))]),
                );
            }

            OpenVMChipRowPayload::LoadSignExtend {
                op,
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
                    BucketType::Memory,
                    "openvm.mem.access_seen".to_string(),
                    details_kv(&[]),
                );
                if *imm_sign {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Memory,
                        "openvm.mem.imm_sign_true".to_string(),
                        details_kv(&[]),
                    );
                }
                push_hit(
                    &mut hits,
                    &mut seen,
                    BucketType::Memory,
                    format!("openvm.mem.space.{mem_as}"),
                    details_kv(&[]),
                );
                if *effective_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Memory,
                        "openvm.mem.effective_ptr_zero".to_string(),
                        details_kv(&[]),
                    );
                }
                access_alignment_buckets(&mut hits, &mut seen, *effective_ptr);

                if *rs1_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.read_rs1_x0".to_string(),
                        details_kv(&[]),
                    );
                }
                if *needs_write && *rd_ptr == 0 {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::Reg,
                        "openvm.reg.write_x0".to_string(),
                        details_kv(&[]),
                    );
                }

                push_hit(
                    &mut hits,
                    &mut seen,
                    BucketType::Memory,
                    format!("openvm.mem.op.{op}"),
                    details_kv(&[("op", json!(*op))]),
                );
            }

            // ---- System chips ----
            OpenVMChipRowPayload::Connector { is_terminate, exit_code, .. } => {
                if *is_terminate {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        BucketType::System,
                        "openvm.system.terminate".to_string(),
                        details_kv(&[("exit_code", json!(exit_code))]),
                    );
                }
            }

            OpenVMChipRowPayload::Program { .. } => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    BucketType::System,
                    "openvm.system.program_row".to_string(),
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
            BucketType::RowValidity,
            "openvm.row.invalid_seen".to_string(),
            HashMap::new(),
        );
    }
    if saw_padding_kind {
        push_hit(
            &mut hits,
            &mut seen,
            BucketType::RowValidity,
            "openvm.row.padding_kind_seen".to_string(),
            HashMap::new(),
        );
    }
    if saw_missing_row_timestamp {
        push_hit(
            &mut hits,
            &mut seen,
            BucketType::Time,
            "openvm.time.row_timestamp_missing".to_string(),
            HashMap::new(),
        );
    }

    hits
}
