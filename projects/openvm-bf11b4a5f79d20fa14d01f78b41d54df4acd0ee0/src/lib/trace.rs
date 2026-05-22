use std::collections::{HashMap, HashSet};

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::observations::{
    ArithmeticSpecialCaseObservation, AuipcPcLimbObservation, BoundaryOriginObservation,
    ImmediateLimbObservation, MemoryAddressSpaceObservation, MemoryImmediateSignObservation,
    TimestampedLoadPathObservation, VolatileBoundaryObservation, XorMultiplicityObservation,
};
use beak_core::trace::{semantic, semantic_matchers, BucketHit, Trace, TraceSignal};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::chip_row::{OpenVMChipRow, OpenVMChipRowKind, OpenVMChipRowPayload, Rs2Source};
use crate::insn::OpenVMInsn;
use crate::interaction::OpenVMInteraction;

const OPENVM_COMMIT: &str = "bf11b4a5f79d20fa14d01f78b41d54df4acd0ee0";

#[derive(Debug, Clone)]
pub struct OpenVMTrace {
    instructions: Vec<OpenVMInsn>,
    chip_rows: Vec<OpenVMChipRow>,
    interactions: Vec<OpenVMInteraction>,
    memory_accesses: Vec<OpenVMMemoryAccess>,
    memory_inits: Vec<OpenVMMemoryInit>,
    memory_finalizations: Vec<OpenVMMemoryFinalization>,
    lookup_multiplicities: Vec<OpenVMLookupMultiplicity>,

    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,

    // ---- Global seq -> vec index -------------------------------------------
    insn_by_seq: Vec<Option<usize>>,
    chip_row_by_seq: Vec<Option<usize>>,
    interaction_by_seq: Vec<Option<usize>>,

    // ---- step_idx -> vec index (1:1 for insn and chip_row) -----------------
    insn_by_step: Vec<Option<usize>>,
    // NOTE: chip rows are 1:N per step (one insn can touch multiple chips/rows).
    chip_rows_by_step: Vec<Vec<usize>>,

    // ---- step_idx -> vec of interaction indices (1:N) -----------------------
    interactions_by_step: Vec<Vec<usize>>,

    // ---- row_id / bus_kind -> interaction indices (no cloning) --------------
    interactions_by_row_id: HashMap<String, Vec<usize>>,
    interactions_by_bus: HashMap<crate::interaction::OpenVMInteractionKind, Vec<usize>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenVMMemoryAccess {
    seq: u64,
    step_idx: u64,
    op_idx: u64,
    #[serde(default)]
    pc: Option<u32>,
    row_op_idx: u64,
    opcode: u32,
    rs1_ptr: u32,
    rd_rs2_ptr: u32,
    imm: i32,
    imm_sign: bool,
    address_space: u32,
    raw_ptr: u32,
    effective_ptr: u32,
    aligned_ptr: u32,
    byte_offset: u32,
    width: u32,
    is_load: bool,
    is_store: bool,
    needs_write: bool,
    timestamp: u32,
    read_data: Vec<u32>,
    prev_data: Vec<u32>,
    #[serde(default)]
    write_data: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenVMMemoryInit {
    seq: u64,
    op_idx: u64,
    address_space: u32,
    pointer: u32,
    value: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenVMMemoryFinalization {
    seq: u64,
    op_idx: u64,
    address_space: u32,
    pointer: u32,
    timestamp: u32,
    values: Vec<u32>,
    was_initial: bool,
    changed_from_initial: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenVMLookupMultiplicity {
    seq: u64,
    step_idx: u64,
    table_name: String,
    row_idx: u64,
    multiplicity: u32,
    is_real: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenVmMemoryObservationProfile {
    ImmediateSign,
}

#[derive(Debug, Clone, Copy)]
struct OpenVmObservationProfile {
    emit_alu_immediate_limb_semantic: bool,
    emit_xor_multiplicity_semantic: bool,
    emit_auipc_pc_limb_semantic: bool,
    emit_padding_interaction_semantic: bool,
    memory_semantic: OpenVmMemoryObservationProfile,
    emit_boundary_origin_semantic: bool,
    emit_volatile_boundary_semantic: bool,
    emit_arithmetic_special_case_semantic: bool,
}

fn kind_snake(kind: OpenVMChipRowKind) -> String {
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

fn rs2_imm_value(rs2: &Rs2Source) -> Option<i32> {
    match rs2 {
        Rs2Source::Imm { value } => Some(*value),
        Rs2Source::Reg { .. } => None,
    }
}

fn flipped_sign_ptr(effective_ptr: u32, imm_sign: bool) -> (u32, i32) {
    if imm_sign {
        (effective_ptr.wrapping_add(1 << 16), 1 << 16)
    } else {
        (effective_ptr.wrapping_sub(1 << 16), -(1 << 16))
    }
}

fn writes_rd(mnemonic: &str) -> bool {
    !matches!(
        mnemonic,
        "sb" | "sh"
            | "sw"
            | "beq"
            | "bne"
            | "blt"
            | "bge"
            | "bltu"
            | "bgeu"
            | "ecall"
            | "ebreak"
            | "fence"
    )
}

fn alu_r_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "add" | "sub" | "sll" | "slt" | "sltu" | "xor" | "srl" | "sra" | "or" | "and"
    )
}

fn alu_i_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai"
    )
}

fn mul_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "mul" | "mulh" | "mulhsu" | "mulhu")
}

fn div_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "div" | "divu" | "rem" | "remu")
}

fn signed_div_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "div" | "rem")
}

fn high_mul_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "mulh" | "mulhsu" | "mulhu")
}

fn load_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "lb" | "lh" | "lw" | "lbu" | "lhu")
}

fn store_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sb" | "sh" | "sw")
}

fn memory_width_bytes(mnemonic: &str) -> Option<u32> {
    match mnemonic {
        "lb" | "lbu" | "sb" => Some(1),
        "lh" | "lhu" | "sh" => Some(2),
        "lw" | "sw" => Some(4),
        _ => None,
    }
}

fn load_sign_cell(mnemonic: &str, read_data: &[u32], byte_offset: u32) -> Option<&'static str> {
    let off = usize::try_from(byte_offset).ok()?;
    match mnemonic {
        "lb" => {
            let byte = *read_data.get(off)? & 0xff;
            Some(if byte & 0x80 == 0 { "me3.lb_pos" } else { "me3.lb_neg" })
        }
        "lh" => {
            let lo = *read_data.get(off)? & 0xff;
            let hi = *read_data.get(off + 1)? & 0xff;
            let half = lo | (hi << 8);
            Some(if half & 0x8000 == 0 { "me3.lh_pos" } else { "me3.lh_neg" })
        }
        "lbu" => Some("me3.lbu"),
        "lhu" => Some("me3.lhu"),
        _ => None,
    }
}

fn access_byte(data: &[u32], byte_offset: u32) -> Option<u32> {
    data.get(byte_offset as usize).copied().map(|byte| byte & 0xff)
}

fn access_bytes(data: &[u32], byte_offset: u32, width: u32) -> Option<Vec<u32>> {
    (0..width).map(|i| access_byte(data, byte_offset + i)).collect()
}

fn branch_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu")
}

fn control_flow_mnemonic(mnemonic: &str) -> bool {
    branch_mnemonic(mnemonic) || matches!(mnemonic, "jal" | "jalr" | "ecall" | "ebreak")
}

fn me1_cell(store_mnemonic: &str, load_mnemonic: &str) -> Option<&'static str> {
    match (store_mnemonic, load_mnemonic) {
        ("sw", "lw") => Some("me1.sw_lw"),
        ("sb", "lb") => Some("me1.sb_lb"),
        ("sh", "lh") => Some("me1.sh_lh"),
        ("sb", "lw") => Some("me1.sb_lw"),
        ("sw", "lb") => Some("me1.sw_lb"),
        ("sw", "lhu") => Some("me1.sw_lhu"),
        _ => None,
    }
}

fn i_signext_cell(mnemonic: &str, imm: i32) -> Option<&'static str> {
    if alu_i_mnemonic(mnemonic) || load_mnemonic(mnemonic) || mnemonic == "jalr" {
        Some(if imm < 0 { "id2.i_neg" } else { "id2.i_pos" })
    } else {
        None
    }
}

fn id4_cell(mnemonic: &str) -> Option<&'static str> {
    if alu_r_mnemonic(mnemonic) {
        Some("id4.alu_r")
    } else if alu_i_mnemonic(mnemonic) {
        Some("id4.alu_i")
    } else if load_mnemonic(mnemonic) {
        Some("id4.load")
    } else if store_mnemonic(mnemonic) {
        Some("id4.store")
    } else if branch_mnemonic(mnemonic) {
        Some("id4.branch")
    } else if mnemonic == "jal" {
        Some("id4.jal")
    } else if mnemonic == "jalr" {
        Some("id4.jalr")
    } else if mnemonic == "lui" {
        Some("id4.lui")
    } else if mnemonic == "auipc" {
        Some("id4.auipc")
    } else if mnemonic == "ecall" {
        Some("id4.ecall")
    } else if mul_mnemonic(mnemonic) {
        Some("id4.mul")
    } else if div_mnemonic(mnemonic) {
        Some("id4.div")
    } else {
        None
    }
}

fn rf1_cell(mnemonic: &str) -> Option<&'static str> {
    if alu_r_mnemonic(mnemonic) {
        Some("rf1.alu_r")
    } else if alu_i_mnemonic(mnemonic) {
        Some("rf1.alu_i")
    } else if mnemonic == "lui" {
        Some("rf1.lui")
    } else if mnemonic == "auipc" {
        Some("rf1.auipc")
    } else if load_mnemonic(mnemonic) {
        Some("rf1.load")
    } else if mnemonic == "jal" {
        Some("rf1.jal")
    } else if mnemonic == "jalr" {
        Some("rf1.jalr")
    } else if mul_mnemonic(mnemonic) {
        Some("rf1.mul")
    } else if div_mnemonic(mnemonic) {
        Some("rf1.div")
    } else {
        None
    }
}

fn rf3_cell(mnemonic: &str) -> Option<&'static str> {
    if alu_r_mnemonic(mnemonic) || alu_i_mnemonic(mnemonic) {
        Some("rf3.alu")
    } else if load_mnemonic(mnemonic) {
        Some("rf3.load")
    } else if matches!(mnemonic, "jal" | "jalr") {
        Some("rf3.link")
    } else if matches!(mnemonic, "lui" | "auipc") {
        Some("rf3.upper")
    } else if mul_mnemonic(mnemonic) || div_mnemonic(mnemonic) {
        Some("rf3.muldiv")
    } else {
        None
    }
}

fn al1_cell(imm: i32) -> &'static str {
    if matches!(imm, 255 | 256 | -1 | -2048 | 2047) {
        "al1.boundary"
    } else if imm < 0 {
        "al1.negative"
    } else if imm <= 255 {
        "al1.single_limb"
    } else {
        "al1.cross_01"
    }
}

fn limb_cross_borrow(lhs: u32, rhs: u32) -> bool {
    let lhs_bytes = lhs.to_le_bytes();
    let rhs_bytes = rhs.to_le_bytes();
    let mut borrow = 0i16;
    for i in 0..3 {
        let diff = lhs_bytes[i] as i16 - rhs_bytes[i] as i16 - borrow;
        let next_borrow = i16::from(diff < 0);
        if next_borrow != borrow {
            return true;
        }
        borrow = next_borrow;
    }
    false
}

fn alternating_borrow(lhs: u32, rhs: u32) -> bool {
    let lhs_bytes = lhs.to_le_bytes();
    let rhs_bytes = rhs.to_le_bytes();
    let mut borrow = 0i16;
    let mut transitions = 0;
    for i in 0..4 {
        let diff = lhs_bytes[i] as i16 - rhs_bytes[i] as i16 - borrow;
        let next_borrow = i16::from(diff < 0);
        if i > 0 && next_borrow != borrow {
            transitions += 1;
        }
        borrow = next_borrow;
    }
    transitions >= 2
}

fn signed_i32(value: u32) -> i32 {
    value as i32
}

fn signed_i64(value: u32) -> i64 {
    i64::from(signed_i32(value))
}

fn div_by_zero_cell(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        "div" => Some("md1.div_zero"),
        "divu" => Some("md1.divu_zero"),
        "rem" => Some("md1.rem_zero"),
        "remu" => Some("md1.remu_zero"),
        _ => None,
    }
}

fn dividend_sign_cell(dividend: u32) -> &'static str {
    match signed_i32(dividend).cmp(&0) {
        std::cmp::Ordering::Greater => "md1.dividend_pos",
        std::cmp::Ordering::Less => "md1.dividend_neg",
        std::cmp::Ordering::Equal => "md1.dividend_zero",
    }
}

fn signed_product_words(lhs: u32, rhs: u32) -> (u32, u32, i128) {
    let product = i128::from(signed_i64(lhs)) * i128::from(signed_i64(rhs));
    let product_u64 = product as i64 as u64;
    (product_u64 as u32, (product_u64 >> 32) as u32, product)
}

fn signed_unsigned_product_words(lhs: u32, rhs: u32) -> (u32, u32, i128) {
    let product = i128::from(signed_i64(lhs)) * i128::from(u64::from(rhs));
    let product_u64 = product as i64 as u64;
    (product_u64 as u32, (product_u64 >> 32) as u32, product)
}

fn unsigned_product_words(lhs: u32, rhs: u32) -> (u32, u32, u128) {
    let product = u128::from(lhs) * u128::from(rhs);
    (product as u32, (product >> 32) as u32, product)
}

fn product_hex(product: impl std::fmt::LowerHex) -> String {
    format!("0x{product:x}")
}

fn record_signal(
    signals: &mut Vec<TraceSignal>,
    seen: &mut HashSet<TraceSignal>,
    signal: TraceSignal,
) {
    if seen.insert(signal) {
        signals.push(signal);
    }
}

fn derive_semantic_feedback(
    trace: &OpenVMTrace,
    profile: OpenVmObservationProfile,
) -> (Vec<BucketHit>, Vec<TraceSignal>) {
    let mut signals = Vec::new();
    let mut seen_signals = HashSet::new();
    let mut immediate_limb = Vec::new();
    let mut xor_multiplicity = Vec::new();
    let mut auipc_pc_limb = Vec::new();
    let mut memory_immediate_sign = Vec::new();
    let mut memory_address_space = Vec::new();
    let mut boundary_origin = Vec::new();
    let mut timestamped_load_path = Vec::new();
    let mut volatile_boundary = Vec::new();
    let mut arithmetic_special_case = Vec::new();
    let mut saw_padding_interaction_candidate = false;

    let mut saw_system_terminate = false;
    let mut saw_missing_row_timestamp = false;
    let mut saw_memory_access = false;
    let has_memory_access_records = !trace.memory_accesses.is_empty();

    for row in trace.chip_rows() {
        let base = row.base();
        let kind = kind_snake(row.kind);
        if base.timestamp.is_none() {
            saw_missing_row_timestamp = true;
        }
        if base.chip_name.contains("Volatile") {
            record_signal(
                &mut signals,
                &mut seen_signals,
                TraceSignal::ObservedVolatileBoundaryRange,
            );
            if profile.emit_volatile_boundary_semantic {
                volatile_boundary.push(VolatileBoundaryObservation {
                    step_idx: base.step_idx,
                    op_idx: base.op_idx,
                    kind: kind.clone(),
                    chip_name: base.chip_name.clone(),
                });
            }
        }

        match &row.payload {
            OpenVMChipRowPayload::BaseAlu { rs2, a, b, c, .. } => {
                saw_padding_interaction_candidate = true;
                if profile.emit_alu_immediate_limb_semantic {
                    if let Some(imm) = rs2_imm_value(rs2) {
                        immediate_limb.push(ImmediateLimbObservation {
                            step_idx: base.step_idx,
                            op_idx: base.op_idx,
                            kind: kind.clone(),
                            chip_name: base.chip_name.clone(),
                            imm,
                        });
                    }
                }
                if profile.emit_xor_multiplicity_semantic {
                    if let (Some(out), Some(lhs), Some(rhs)) =
                        (le_u32_from_bytes(a), le_u32_from_bytes(b), le_u32_from_bytes(c))
                    {
                        if out == (lhs ^ rhs) && (lhs & rhs) != 0 {
                            xor_multiplicity.push(XorMultiplicityObservation {
                                step_idx: base.step_idx,
                                op_idx: base.op_idx,
                                kind: kind.clone(),
                                chip_name: base.chip_name.clone(),
                                lhs,
                                rhs,
                            });
                        }
                    }
                }
            }
            OpenVMChipRowPayload::DivRem { b, c, .. } => {
                if profile.emit_arithmetic_special_case_semantic {
                    if let (Some(rs1), Some(rs2)) = (le_u32_from_bytes(b), le_u32_from_bytes(c)) {
                        if rs2 == 0 || (rs1 == 0x8000_0000 && rs2 == 0xFFFF_FFFF) {
                            arithmetic_special_case.push(ArithmeticSpecialCaseObservation {
                                step_idx: base.step_idx,
                                op_idx: base.op_idx,
                                rs1,
                                rs2,
                            });
                        }
                    }
                }
            }
            OpenVMChipRowPayload::Auipc { imm, from_pc, .. } => {
                if profile.emit_auipc_pc_limb_semantic {
                    auipc_pc_limb.push(AuipcPcLimbObservation {
                        step_idx: base.step_idx,
                        op_idx: base.op_idx,
                        kind: kind.clone(),
                        chip_name: base.chip_name.clone(),
                        from_pc: *from_pc,
                        imm: *imm,
                    });
                }
            }
            OpenVMChipRowPayload::LoadStore {
                op,
                rs1_ptr,
                rd_rs2_ptr,
                imm,
                imm_sign,
                mem_as,
                effective_ptr,
                is_store,
                needs_write,
                is_load,
                ..
            } => {
                saw_memory_access = true;
                if *is_load {
                    record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoad);
                    record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoadStore);
                }
                if *is_store {
                    record_signal(&mut signals, &mut seen_signals, TraceSignal::HasStore);
                    record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoadStore);
                }
                if !has_memory_access_records {
                    timestamped_load_path.push(TimestampedLoadPathObservation {
                        step_idx: base.step_idx,
                        op_idx: base.op_idx,
                        kind: kind.clone(),
                        chip_name: base.chip_name.clone(),
                        timestamp: base.timestamp,
                        is_load: *is_load,
                        is_store: *is_store,
                    });
                    match profile.memory_semantic {
                        OpenVmMemoryObservationProfile::ImmediateSign => {
                            let (alt_effective_ptr, alt_ptr_delta) =
                                flipped_sign_ptr(*effective_ptr, *imm_sign);
                            memory_immediate_sign.push(MemoryImmediateSignObservation {
                                step_idx: base.step_idx,
                                op_idx: base.op_idx,
                                kind: kind.clone(),
                                chip_name: base.chip_name.clone(),
                                op: *op,
                                imm: *imm,
                                imm_sign: *imm_sign,
                                rs1_ptr: *rs1_ptr,
                                rd_rs2_ptr: *rd_rs2_ptr,
                                mem_as: *mem_as,
                                effective_ptr: *effective_ptr,
                                alt_effective_ptr,
                                alt_ptr_delta,
                                alt_ptr_in_range_29: u64::from(alt_effective_ptr) < (1u64 << 29),
                                is_load: *is_load,
                                is_store: *is_store,
                                needs_write: *needs_write,
                            });
                        }
                    }
                }
            }
            OpenVMChipRowPayload::LoadSignExtend {
                op,
                rs1_ptr,
                rd_ptr,
                imm,
                imm_sign,
                mem_as,
                effective_ptr,
                needs_write,
                ..
            } => {
                saw_memory_access = true;
                record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoad);
                record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoadStore);
                timestamped_load_path.push(TimestampedLoadPathObservation {
                    step_idx: base.step_idx,
                    op_idx: base.op_idx,
                    kind: kind.clone(),
                    chip_name: base.chip_name.clone(),
                    timestamp: base.timestamp,
                    is_load: true,
                    is_store: false,
                });
                match profile.memory_semantic {
                    OpenVmMemoryObservationProfile::ImmediateSign => {
                        let (alt_effective_ptr, alt_ptr_delta) =
                            flipped_sign_ptr(*effective_ptr, *imm_sign);
                        memory_immediate_sign.push(MemoryImmediateSignObservation {
                            step_idx: base.step_idx,
                            op_idx: base.op_idx,
                            kind: kind.clone(),
                            chip_name: base.chip_name.clone(),
                            op: *op,
                            imm: *imm,
                            imm_sign: *imm_sign,
                            rs1_ptr: *rs1_ptr,
                            rd_rs2_ptr: *rd_ptr,
                            mem_as: *mem_as,
                            effective_ptr: *effective_ptr,
                            alt_effective_ptr,
                            alt_ptr_delta,
                            alt_ptr_in_range_29: u64::from(alt_effective_ptr) < (1u64 << 29),
                            is_load: true,
                            is_store: false,
                            needs_write: *needs_write,
                        });
                    }
                }
            }
            OpenVMChipRowPayload::Connector {
                from_timestamp, to_timestamp, is_terminate, ..
            } => {
                if *is_terminate {
                    saw_system_terminate = true;
                    record_signal(&mut signals, &mut seen_signals, TraceSignal::HasEcall);
                }
                if profile.emit_boundary_origin_semantic
                    && saw_memory_access
                    && matches!(from_timestamp, Some(0))
                {
                    boundary_origin.push(BoundaryOriginObservation {
                        step_idx: base.step_idx,
                        op_idx: base.op_idx,
                        kind: kind.clone(),
                        chip_name: base.chip_name.clone(),
                        from_timestamp: *from_timestamp,
                        to_timestamp: *to_timestamp,
                        is_terminate: *is_terminate,
                    });
                }
            }
            _ => {}
        }
    }

    for access in &trace.memory_accesses {
        let kind = "memory_access".to_string();
        if access.is_load {
            record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoad);
            record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoadStore);
        }
        if access.is_store {
            record_signal(&mut signals, &mut seen_signals, TraceSignal::HasStore);
            record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoadStore);
        }
        timestamped_load_path.push(TimestampedLoadPathObservation {
            step_idx: access.step_idx,
            op_idx: access.op_idx,
            kind: kind.clone(),
            chip_name: "Rv32LoadStoreAdapter".to_string(),
            timestamp: Some(access.timestamp),
            is_load: access.is_load,
            is_store: access.is_store,
        });
        memory_address_space.push(MemoryAddressSpaceObservation {
            step_idx: access.step_idx,
            op_idx: access.op_idx,
            kind: kind.clone(),
            chip_name: "Rv32LoadStoreAdapter".to_string(),
            mem_as: access.address_space,
        });
        match profile.memory_semantic {
            OpenVmMemoryObservationProfile::ImmediateSign => {
                let (alt_effective_ptr, alt_ptr_delta) =
                    flipped_sign_ptr(access.effective_ptr, access.imm_sign);
                memory_immediate_sign.push(MemoryImmediateSignObservation {
                    step_idx: access.step_idx,
                    op_idx: access.op_idx,
                    kind,
                    chip_name: "Rv32LoadStoreAdapter".to_string(),
                    op: access.opcode,
                    imm: access.imm,
                    imm_sign: access.imm_sign,
                    rs1_ptr: access.rs1_ptr,
                    rd_rs2_ptr: access.rd_rs2_ptr,
                    mem_as: access.address_space,
                    effective_ptr: access.effective_ptr,
                    alt_effective_ptr,
                    alt_ptr_delta,
                    alt_ptr_in_range_29: u64::from(alt_effective_ptr) < (1u64 << 29),
                    is_load: access.is_load,
                    is_store: access.is_store,
                    needs_write: access.needs_write,
                });
            }
        }
    }

    let _ = (saw_system_terminate, saw_missing_row_timestamp);

    let mut bucket_hits = Vec::new();
    bucket_hits.extend(semantic_matchers::match_immediate_limb_semantic_hits(&immediate_limb));
    bucket_hits.extend(semantic_matchers::match_xor_multiplicity_semantic_hits(&xor_multiplicity));
    bucket_hits.extend(semantic_matchers::match_auipc_pc_limb_semantic_hits(&auipc_pc_limb));
    bucket_hits.extend(semantic_matchers::match_memory_immediate_sign_semantic_hits(
        &memory_immediate_sign,
    ));
    bucket_hits
        .extend(semantic_matchers::match_memory_address_space_semantic_hits(&memory_address_space));
    bucket_hits.extend(semantic_matchers::match_boundary_origin_semantic_hits(&boundary_origin));
    bucket_hits.extend(semantic_matchers::match_timestamped_load_path_semantic_hits(
        &timestamped_load_path,
    ));
    bucket_hits
        .extend(semantic_matchers::match_volatile_boundary_semantic_hits(&volatile_boundary));
    bucket_hits.extend(semantic_matchers::match_arithmetic_special_case_semantic_hits(
        &arithmetic_special_case,
    ));
    if profile.emit_padding_interaction_semantic && saw_padding_interaction_candidate {
        bucket_hits.push(BucketHit::semantic(
            semantic::row::PADDING_INTERACTION_SEND,
            HashMap::from([("scope".to_string(), Value::String("base_alu".to_string()))]),
        ));
    }
    (bucket_hits, signals)
}

impl OpenVMTrace {
    fn ensure_len<T: Default + Clone>(v: &mut Vec<T>, idx: usize) {
        if v.len() <= idx {
            v.resize(idx + 1, T::default());
        }
    }

    /// Build an `OpenVMTrace` from fuzzer_utils emitted JSON logs.
    ///
    /// Each log entry is `{ "type": "instruction"|"chip_row"|"interaction", "data": {...} }`.
    pub fn from_logs(logs: Vec<Value>) -> Result<Self, String> {
        let mut instructions = Vec::new();
        let mut chip_rows = Vec::new();
        let mut interactions = Vec::new();
        let mut memory_accesses = Vec::new();
        let mut memory_inits = Vec::new();
        let mut memory_finalizations = Vec::new();
        let mut lookup_multiplicities = Vec::new();

        for (idx, log) in logs.into_iter().enumerate() {
            let obj = log.as_object().ok_or_else(|| format!("log[{}]: not an object", idx))?;
            let ty = obj
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("log[{}]: missing or invalid \"type\"", idx))?;
            let data = obj
                .get("data")
                .cloned()
                .ok_or_else(|| format!("log[{}]: missing \"data\"", idx))?;

            match ty {
                "instruction" => {
                    let insn: OpenVMInsn = serde_json::from_value(data)
                        .map_err(|e| format!("log[{}] instruction: {}", idx, e))?;
                    instructions.push(insn);
                }
                "chip_row" => {
                    let row: OpenVMChipRow = serde_json::from_value(data)
                        .map_err(|e| format!("log[{}] chip_row: {}", idx, e))?;
                    chip_rows.push(row);
                }
                "interaction" => {
                    let ia: OpenVMInteraction = serde_json::from_value(data)
                        .map_err(|e| format!("log[{}] interaction: {}", idx, e))?;
                    interactions.push(ia);
                }
                "memory_access" => {
                    let access: OpenVMMemoryAccess = serde_json::from_value(data)
                        .map_err(|e| format!("log[{}] memory_access: {}", idx, e))?;
                    memory_accesses.push(access);
                }
                "memory_init" => {
                    let init: OpenVMMemoryInit = serde_json::from_value(data)
                        .map_err(|e| format!("log[{}] memory_init: {}", idx, e))?;
                    memory_inits.push(init);
                }
                "memory_finalization" => {
                    let finalization: OpenVMMemoryFinalization = serde_json::from_value(data)
                        .map_err(|e| format!("log[{}] memory_finalization: {}", idx, e))?;
                    memory_finalizations.push(finalization);
                }
                "lookup_multiplicity" => {
                    let row: OpenVMLookupMultiplicity = serde_json::from_value(data)
                        .map_err(|e| format!("log[{}] lookup_multiplicity: {}", idx, e))?;
                    lookup_multiplicities.push(row);
                }
                _ => return Err(format!("log[{}]: unknown type \"{}\"", idx, ty)),
            }
        }

        Ok(Self::new(
            instructions,
            chip_rows,
            interactions,
            memory_accesses,
            memory_inits,
            memory_finalizations,
            lookup_multiplicities,
        ))
    }

    pub fn from_logs_with_words(logs: Vec<Value>, words: &[u32]) -> Result<Self, String> {
        let mut trace = Self::from_logs(logs)?;
        trace.extend_instruction_local_obligation_hits(words);
        Ok(trace)
    }
}

impl OpenVMTrace {
    /// Instructions, chip_rows, and interactions with index maps. Use `from_logs` to build from JSON.
    pub fn new(
        instructions: Vec<OpenVMInsn>,
        chip_rows: Vec<OpenVMChipRow>,
        interactions: Vec<OpenVMInteraction>,
        memory_accesses: Vec<OpenVMMemoryAccess>,
        memory_inits: Vec<OpenVMMemoryInit>,
        memory_finalizations: Vec<OpenVMMemoryFinalization>,
        lookup_multiplicities: Vec<OpenVMLookupMultiplicity>,
    ) -> Self {
        let mut insn_by_seq: Vec<Option<usize>> = Vec::new();
        let mut chip_row_by_seq: Vec<Option<usize>> = Vec::new();
        let mut interaction_by_seq: Vec<Option<usize>> = Vec::new();

        let mut insn_by_step: Vec<Option<usize>> = Vec::new();
        let mut chip_rows_by_step: Vec<Vec<usize>> = Vec::new();
        let mut interactions_by_step: Vec<Vec<usize>> = Vec::new();

        let mut interactions_by_row_id: HashMap<String, Vec<usize>> = HashMap::new();
        let mut interactions_by_bus: HashMap<
            crate::interaction::OpenVMInteractionKind,
            Vec<usize>,
        > = HashMap::new();

        for (i, insn) in instructions.iter().enumerate() {
            let seq = insn.seq as usize;
            let step = insn.step_idx as usize;

            Self::ensure_len(&mut insn_by_seq, seq);
            assert!(insn_by_seq[seq].is_none(), "duplicate insn seq={}", seq);
            insn_by_seq[seq] = Some(i);

            Self::ensure_len(&mut insn_by_step, step);
            assert!(insn_by_step[step].is_none(), "duplicate insn step_idx={}", step);
            insn_by_step[step] = Some(i);
        }

        for (i, row) in chip_rows.iter().enumerate() {
            let b = row.base();
            let seq = b.seq as usize;
            let step = b.step_idx as usize;

            Self::ensure_len(&mut chip_row_by_seq, seq);
            assert!(chip_row_by_seq[seq].is_none(), "duplicate chip_row seq={}", seq);
            chip_row_by_seq[seq] = Some(i);

            Self::ensure_len(&mut chip_rows_by_step, step);
            // Enforce uniqueness of op_idx within a step.
            let op_idx = b.op_idx;
            if chip_rows_by_step[step].iter().any(|&j| chip_rows[j].base().op_idx == op_idx) {
                panic!("duplicate chip_row op_idx={} for step_idx={}", op_idx, step);
            }
            chip_rows_by_step[step].push(i);
        }

        for (i, ia) in interactions.iter().enumerate() {
            let b = ia.base();
            let seq = b.seq as usize;
            let step = b.step_idx as usize;

            Self::ensure_len(&mut interaction_by_seq, seq);
            assert!(interaction_by_seq[seq].is_none(), "duplicate interaction seq={}", seq);
            interaction_by_seq[seq] = Some(i);

            Self::ensure_len(&mut interactions_by_step, step);
            interactions_by_step[step].push(i);

            interactions_by_row_id.entry(b.row_id.clone()).or_default().push(i);
            interactions_by_bus.entry(b.kind).or_default().push(i);
        }

        let mut out = Self {
            instructions,
            chip_rows,
            interactions,
            memory_accesses,
            memory_inits,
            memory_finalizations,
            lookup_multiplicities,
            bucket_hits: Vec::new(),
            trace_signals: Vec::new(),
            insn_by_seq,
            chip_row_by_seq,
            interaction_by_seq,
            insn_by_step,
            chip_rows_by_step,
            interactions_by_step,
            interactions_by_row_id,
            interactions_by_bus,
        };

        let (bucket_hits, trace_signals) = derive_semantic_feedback(
            &out,
            OpenVmObservationProfile {
                emit_alu_immediate_limb_semantic: true,
                emit_xor_multiplicity_semantic: true,
                emit_auipc_pc_limb_semantic: true,
                emit_padding_interaction_semantic: true,
                memory_semantic: OpenVmMemoryObservationProfile::ImmediateSign,
                emit_boundary_origin_semantic: true,
                emit_volatile_boundary_semantic: false,
                emit_arithmetic_special_case_semantic: true,
            },
        );
        out.bucket_hits = bucket_hits;
        out.trace_signals = trace_signals;
        out
    }

    fn pc_for_op_idx(&self, op_idx: u64) -> u64 {
        self.insn_by_step
            .get(op_idx as usize)
            .and_then(|slot| slot.map(|idx| self.instructions[idx].pc as u64))
            .unwrap_or(op_idx.saturating_mul(4))
    }

    fn obligation_details(
        &self,
        insn: &RV32IMInstruction,
        op_idx: u64,
        obligation_id: &str,
        cell_id: &str,
        trace_source: &str,
    ) -> HashMap<String, Value> {
        HashMap::from([
            ("obligation_id".to_string(), json!(obligation_id)),
            ("cell_id".to_string(), json!(cell_id)),
            ("op_idx".to_string(), json!(op_idx)),
            ("pc".to_string(), json!(self.pc_for_op_idx(op_idx))),
            ("opcode".to_string(), json!(insn.word)),
            ("mnemonic".to_string(), json!(insn.mnemonic)),
            ("backend".to_string(), json!("openvm")),
            ("commit".to_string(), json!(OPENVM_COMMIT)),
            ("trace_source".to_string(), json!(trace_source)),
        ])
    }

    fn push_obligation_hit(
        &self,
        hits: &mut Vec<BucketHit>,
        bucket: semantic::SemanticBucket,
        insn: &RV32IMInstruction,
        op_idx: u64,
        obligation_id: &str,
        cell_id: &str,
        trace_source: &str,
        extras: &[(&str, Value)],
    ) {
        let mut details =
            self.obligation_details(insn, op_idx, obligation_id, cell_id, trace_source);
        for (key, value) in extras {
            details.insert((*key).to_string(), value.clone());
        }
        hits.push(BucketHit::semantic(bucket, details));
    }

    fn decode_word_for_executed_pc(words: &[u32], pc: u64) -> Option<RV32IMInstruction> {
        let direct_idx = usize::try_from(pc).ok();
        let byte_idx = (pc % 4 == 0).then(|| usize::try_from(pc / 4).ok()).flatten();

        [byte_idx, direct_idx]
            .into_iter()
            .flatten()
            .filter_map(|idx| words.get(idx).copied())
            .find_map(|word| RV32IMInstruction::from_word(word).ok())
    }

    fn executed_decoded_words(&self, words: &[u32]) -> Vec<(u64, RV32IMInstruction)> {
        self.instructions
            .iter()
            .filter_map(|insn| {
                Self::decode_word_for_executed_pc(words, insn.pc as u64)
                    .map(|decoded| (insn.step_idx, decoded))
            })
            .collect()
    }

    fn extend_instruction_local_obligation_hits(&mut self, words: &[u32]) {
        let decoded = self.executed_decoded_words(words);
        let mut hits = Vec::new();
        self.derive_decoded_obligation_hits(&decoded, &mut hits);
        self.derive_control_flow_obligation_hits(&decoded, &mut hits);
        self.derive_chip_row_obligation_hits(&decoded, &mut hits);
        self.derive_memory_access_obligation_hits(&decoded, &mut hits);
        self.derive_memory_lifecycle_obligation_hits(&mut hits);
        self.derive_timestamp_obligation_hits(&mut hits);
        self.derive_timestamp_memory_order_hits(&decoded, &mut hits);
        self.derive_lookup_multiplicity_obligation_hits(&mut hits);
        self.bucket_hits.extend(hits);
    }

    fn derive_decoded_obligation_hits(
        &self,
        decoded: &[(u64, RV32IMInstruction)],
        hits: &mut Vec<BucketHit>,
    ) {
        for (op_idx, insn) in decoded {
            let op_idx = *op_idx;
            let mnemonic = insn.mnemonic.as_str();
            let rd_bits = (insn.word >> 7) & 0x1f;
            let rs1_bits = (insn.word >> 15) & 0x1f;
            let rs2_bits = (insn.word >> 20) & 0x1f;
            let funct3 = (insn.word >> 12) & 0x7;
            let funct7 = (insn.word >> 25) & 0x7f;

            if writes_rd(mnemonic) && insn.rd == Some(0) {
                if let Some(cell_id) = rf1_cell(mnemonic) {
                    self.push_obligation_hit(
                        hits,
                        semantic::decode::ZERO_REGISTER_IMMUTABILITY,
                        insn,
                        op_idx,
                        "rf1",
                        cell_id,
                        "decoded_instruction",
                        &[("rd", json!(0))],
                    );
                }
            }

            let mut rf2_cells = HashSet::new();
            if let (Some(rs1), Some(rs2)) = (insn.rs1, insn.rs2) {
                if rs1 == rs2 {
                    rf2_cells.insert("rf2.rs1_eq_rs2");
                }
                if let Some(rd) = insn.rd {
                    if rs1 == rd && rs2 == rd {
                        rf2_cells.insert("rf2.all_same");
                    } else {
                        if rs1 == rd {
                            rf2_cells.insert("rf2.rs1_eq_rd");
                        }
                        if rs2 == rd {
                            rf2_cells.insert("rf2.rs2_eq_rd");
                        }
                    }
                    if rs1 != rs2 && rs1 != rd && rs2 != rd {
                        rf2_cells.insert("rf2.no_alias");
                    }
                }
            }
            if insn.rs1 == Some(0) {
                rf2_cells.insert("rf2.rs1_x0");
            }
            if insn.rs2 == Some(0) {
                rf2_cells.insert("rf2.rs2_x0");
            }
            for cell_id in rf2_cells {
                self.push_obligation_hit(
                    hits,
                    semantic::decode::OPERAND_INDEX_ROUTING,
                    insn,
                    op_idx,
                    "rf2",
                    cell_id,
                    "decoded_instruction",
                    &[("rd", json!(insn.rd)), ("rs1", json!(insn.rs1)), ("rs2", json!(insn.rs2))],
                );
            }

            if writes_rd(mnemonic) && insn.rd.is_some_and(|rd| rd != 0) {
                if let Some(cell_id) = rf3_cell(mnemonic) {
                    self.push_obligation_hit(
                        hits,
                        semantic::exec::DEST_BINDING,
                        insn,
                        op_idx,
                        "rf3",
                        cell_id,
                        "decoded_instruction",
                        &[("rd", json!(insn.rd))],
                    );
                }
            }

            for (field_name, field_value) in [("rd", rd_bits), ("rs1", rs1_bits), ("rs2", rs2_bits)]
            {
                let cell_id = if field_value == 0 {
                    "id1.reg_zero"
                } else if field_value == 31 {
                    "id1.reg_max"
                } else {
                    "id1.reg_mid"
                };
                self.push_obligation_hit(
                    hits,
                    semantic::decode::FIELD_RANGE,
                    insn,
                    op_idx,
                    "id1",
                    cell_id,
                    "decoded_instruction",
                    &[("field_name", json!(field_name)), ("field_value", json!(field_value))],
                );
            }
            if funct3 == 7 || funct7 == 127 {
                self.push_obligation_hit(
                    hits,
                    semantic::decode::FIELD_RANGE,
                    insn,
                    op_idx,
                    "id1",
                    "id1.funct_max",
                    "decoded_instruction",
                    &[("funct3", json!(funct3)), ("funct7", json!(funct7))],
                );
            }

            if let Some(imm) = insn.imm {
                let id2_cell = if let Some(cell) = i_signext_cell(mnemonic, imm) {
                    Some(cell)
                } else if store_mnemonic(mnemonic) {
                    Some(if imm < 0 { "id2.s_neg" } else { "id2.s_pos" })
                } else if branch_mnemonic(mnemonic) {
                    Some(if imm < 0 { "id2.b_neg" } else { "id2.b_pos" })
                } else if mnemonic == "jal" {
                    Some(if imm < 0 { "id2.j_neg" } else { "id2.j_pos" })
                } else {
                    None
                };
                if let Some(cell_id) = id2_cell {
                    self.push_obligation_hit(
                        hits,
                        semantic::decode::IMMEDIATE_SIGN_EXTENSION,
                        insn,
                        op_idx,
                        "id2",
                        cell_id,
                        "decoded_instruction",
                        &[("imm", json!(imm))],
                    );
                }
            }

            if matches!(mnemonic, "lui" | "auipc") {
                let u_imm20 = (insn.word >> 12) & 0x000f_ffff;
                let cell_id = if mnemonic == "lui" {
                    if u_imm20 == 0 {
                        "id3.lui_zero"
                    } else if u_imm20 == 0x000f_ffff {
                        "id3.lui_max"
                    } else {
                        "id3.lui_mid"
                    }
                } else {
                    let pc = self.pc_for_op_idx(op_idx) as u32;
                    let upper = u_imm20 << 12;
                    if u64::from(pc) + u64::from(upper) >= (1u64 << 32) {
                        "id3.auipc_wrap"
                    } else {
                        "id3.auipc_no_wrap"
                    }
                };
                self.push_obligation_hit(
                    hits,
                    semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION,
                    insn,
                    op_idx,
                    "id3",
                    cell_id,
                    "decoded_instruction",
                    &[("u_imm20", json!(u_imm20))],
                );
                if mnemonic == "auipc" {
                    self.push_obligation_hit(
                        hits,
                        semantic::control::AUIPC_PC_LIMB_CONSISTENCY,
                        insn,
                        op_idx,
                        "id3",
                        cell_id,
                        "decoded_instruction",
                        &[("u_imm20", json!(u_imm20))],
                    );
                }
            }

            if let Some(cell_id) = id4_cell(mnemonic) {
                self.push_obligation_hit(
                    hits,
                    semantic::exec::OP_SELECTOR_BINDING,
                    insn,
                    op_idx,
                    "id4",
                    cell_id,
                    "decoded_instruction",
                    &[("opcode_low7", json!(insn.word & 0x7f))],
                );
            }

            let id5_cell = if store_mnemonic(mnemonic) {
                Some("id5.s_type")
            } else if branch_mnemonic(mnemonic) {
                Some("id5.b_type")
            } else if mnemonic == "jal" {
                Some("id5.j_type")
            } else {
                None
            };
            if let Some(cell_id) = id5_cell {
                self.push_obligation_hit(
                    hits,
                    semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY,
                    insn,
                    op_idx,
                    "id5",
                    cell_id,
                    "decoded_instruction",
                    &[("imm", json!(insn.imm))],
                );
                if insn.word.count_ones() > 8 {
                    self.push_obligation_hit(
                        hits,
                        semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY,
                        insn,
                        op_idx,
                        "id5",
                        "id5.cross_field",
                        "decoded_instruction",
                        &[("imm", json!(insn.imm))],
                    );
                }
            }

            if alu_i_mnemonic(mnemonic) {
                if let Some(imm) = insn.imm {
                    self.push_obligation_hit(
                        hits,
                        semantic::alu::IMMEDIATE_LIMB_CONSISTENCY,
                        insn,
                        op_idx,
                        "al1",
                        al1_cell(imm),
                        "decoded_instruction",
                        &[("imm", json!(imm))],
                    );
                }
            }
        }
    }

    fn trace_instruction_for_step(&self, step_idx: u64) -> Option<&OpenVMInsn> {
        self.insn_by_step
            .get(step_idx as usize)
            .and_then(|slot| slot.map(|idx| &self.instructions[idx]))
    }

    fn openvm_sequential_next_pc(pc: u32) -> u32 {
        pc.wrapping_add(1)
    }

    fn branch_primary_cell(mnemonic: &str, taken: bool) -> Option<&'static str> {
        match (mnemonic, taken) {
            ("blt", true) => Some("cf1.blt_taken"),
            ("blt", false) => Some("cf1.blt_not_taken"),
            ("bge", true) => Some("cf1.bge_taken"),
            ("bge", false) => Some("cf1.bge_not_taken"),
            ("bltu", true) => Some("cf1.bltu_taken"),
            ("bltu", false) => Some("cf1.bltu_not_taken"),
            ("bgeu", true) => Some("cf1.bgeu_taken"),
            ("bgeu", false) => Some("cf1.bgeu_not_taken"),
            ("beq", true) => Some("cf1.beq_equal"),
            ("bne", true) => Some("cf1.bne_not_equal"),
            _ => None,
        }
    }

    fn derive_control_flow_obligation_hits(
        &self,
        decoded: &[(u64, RV32IMInstruction)],
        hits: &mut Vec<BucketHit>,
    ) {
        if let Some((op_idx, first_decoded)) = decoded.first() {
            if let Some(first_trace) = self.trace_instruction_for_step(*op_idx) {
                let cell_id =
                    if first_trace.pc == 0 { "cf4.default_entry" } else { "cf4.custom_entry" };
                self.push_obligation_hit(
                    hits,
                    semantic::control::ENTRYPOINT_BINDING,
                    first_decoded,
                    *op_idx,
                    "cf4",
                    cell_id,
                    "instruction",
                    &[
                        ("entry_pc", json!(first_trace.pc)),
                        ("pc_unit", json!("openvm_instruction_index")),
                    ],
                );
            }
        }

        for (idx, (op_idx, insn)) in decoded.iter().enumerate() {
            let Some(trace_insn) = self.trace_instruction_for_step(*op_idx) else {
                continue;
            };
            let mnemonic = insn.mnemonic.as_str();
            let sequential_next = Self::openvm_sequential_next_pc(trace_insn.pc);
            let next_pc = trace_insn.next_pc;

            if branch_mnemonic(mnemonic) {
                let taken = next_pc != sequential_next;
                let branch_target = insn
                    .imm
                    .map(|imm| (i64::from(trace_insn.pc)).wrapping_add(i64::from(imm)) as u32);
                if let Some(cell_id) = Self::branch_primary_cell(mnemonic, taken) {
                    self.push_obligation_hit(
                        hits,
                        semantic::exec::CONTROL_FLOW_BINDING,
                        insn,
                        *op_idx,
                        "cf1",
                        cell_id,
                        "instruction",
                        &[
                            ("next_pc", json!(next_pc)),
                            ("sequential_next_pc", json!(sequential_next)),
                            ("target_pc", json!(branch_target)),
                            ("taken", json!(taken)),
                            ("pc_unit", json!("openvm_instruction_index")),
                        ],
                    );
                }
            }

            if mnemonic == "jal" || mnemonic == "jalr" {
                let cell_id = match (mnemonic, insn.rd == Some(0)) {
                    ("jal", false) => "cf2.jal_rd",
                    ("jal", true) => "cf2.jal_x0",
                    ("jalr", false) => "cf2.jalr_rd",
                    ("jalr", true) => "cf2.jalr_x0",
                    _ => continue,
                };
                self.push_obligation_hit(
                    hits,
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    *op_idx,
                    "cf2",
                    cell_id,
                    "instruction",
                    &[
                        ("link_pc", json!(sequential_next)),
                        ("next_pc", json!(next_pc)),
                        ("rd", json!(insn.rd)),
                        ("pc_unit", json!("openvm_instruction_index")),
                    ],
                );
            }

            if mnemonic == "jalr" {
                let imm = insn.imm.unwrap_or_default();
                let cell_id = if imm == 0 {
                    "cf3.imm_zero"
                } else if imm > 0 {
                    "cf3.imm_pos"
                } else {
                    "cf3.imm_neg"
                };
                self.push_obligation_hit(
                    hits,
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    *op_idx,
                    "cf3",
                    cell_id,
                    "instruction",
                    &[
                        ("imm", json!(imm)),
                        ("next_pc", json!(next_pc)),
                        ("pc_unit", json!("openvm_instruction_index")),
                    ],
                );
            }

            if !control_flow_mnemonic(mnemonic) && next_pc == sequential_next {
                self.push_obligation_hit(
                    hits,
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    *op_idx,
                    "cf6",
                    "cf6.normal",
                    "instruction",
                    &[
                        ("next_pc", json!(next_pc)),
                        ("sequential_next_pc", json!(sequential_next)),
                        ("pc_unit", json!("openvm_instruction_index")),
                    ],
                );
                if idx > 0 {
                    let (prev_op_idx, prev_insn) = &decoded[idx - 1];
                    if branch_mnemonic(&prev_insn.mnemonic) {
                        if let Some(prev_trace) = self.trace_instruction_for_step(*prev_op_idx) {
                            if prev_trace.next_pc == Self::openvm_sequential_next_pc(prev_trace.pc)
                            {
                                self.push_obligation_hit(
                                    hits,
                                    semantic::exec::CONTROL_FLOW_BINDING,
                                    insn,
                                    *op_idx,
                                    "cf6",
                                    "cf6.after_branch_not_taken",
                                    "instruction",
                                    &[
                                        ("prev_op_idx", json!(prev_op_idx)),
                                        ("next_pc", json!(next_pc)),
                                        ("pc_unit", json!("openvm_instruction_index")),
                                    ],
                                );
                            }
                        }
                    }
                }
            }

            if mnemonic == "ecall" && insn.word == 0x0000_0073 {
                self.push_obligation_hit(
                    hits,
                    semantic::control::ECALL_WORD_VALIDITY,
                    insn,
                    *op_idx,
                    "cf7",
                    "cf7.standard",
                    "instruction",
                    &[("next_pc", json!(next_pc))],
                );
            }
        }
    }

    fn derive_memory_access_obligation_hits(
        &self,
        decoded: &[(u64, RV32IMInstruction)],
        hits: &mut Vec<BucketHit>,
    ) {
        let decoded_by_step =
            decoded.iter().map(|(step_idx, insn)| (*step_idx, insn)).collect::<HashMap<_, _>>();
        let decoded_by_pc = decoded
            .iter()
            .filter_map(|(step_idx, insn)| {
                self.trace_instruction_for_step(*step_idx)
                    .map(|trace_insn| (trace_insn.pc, (*step_idx, insn)))
            })
            .collect::<HashMap<_, _>>();
        let mut previous_subword: Option<(&OpenVMMemoryAccess, &RV32IMInstruction)> = None;
        #[derive(Clone)]
        struct StoreByte {
            mnemonic: String,
            step_idx: u64,
            byte: u32,
        }
        let mut last_store_by_addr: HashMap<(u32, u32), StoreByte> = HashMap::new();
        let mut store_count_by_addr: HashMap<(u32, u32), u32> = HashMap::new();

        for access in &self.memory_accesses {
            let decoded_entry =
                access.pc.and_then(|pc| decoded_by_pc.get(&pc).copied()).or_else(|| {
                    decoded_by_step.get(&access.step_idx).map(|insn| (access.step_idx, *insn))
                });
            let Some((hit_op_idx, insn)) = decoded_entry else {
                continue;
            };
            let mnemonic = insn.mnemonic.as_str();
            if !(load_mnemonic(mnemonic) || store_mnemonic(mnemonic)) {
                continue;
            }
            let width = memory_width_bytes(mnemonic).unwrap_or(access.width);
            let byte_offset = access.byte_offset & 0x3;
            let common = vec![
                ("row_op_idx", json!(access.row_op_idx)),
                ("memory_seq", json!(access.seq)),
                ("memory_op_idx", json!(access.op_idx)),
                ("memory_step_idx", json!(access.step_idx)),
                ("memory_pc", json!(access.pc)),
                ("row_opcode", json!(access.opcode)),
                ("rs1_ptr", json!(access.rs1_ptr)),
                ("rd_rs2_ptr", json!(access.rd_rs2_ptr)),
                ("imm", json!(access.imm)),
                ("imm_sign", json!(access.imm_sign)),
                ("address_space", json!(access.address_space)),
                ("raw_ptr", json!(access.raw_ptr)),
                ("effective_ptr", json!(access.effective_ptr)),
                ("aligned_ptr", json!(access.aligned_ptr)),
                ("byte_offset", json!(byte_offset)),
                ("width", json!(width)),
                ("is_load", json!(access.is_load)),
                ("is_store", json!(access.is_store)),
                ("needs_write", json!(access.needs_write)),
                ("timestamp", json!(access.timestamp)),
                ("read_data", json!(access.read_data)),
                ("prev_data", json!(access.prev_data)),
                ("write_data", json!(access.write_data)),
            ];

            if access.is_load {
                let accessed_keys = (0..width)
                    .filter_map(|i| access.effective_ptr.checked_add(i))
                    .map(|addr| (access.address_space, addr))
                    .collect::<Vec<_>>();
                let prior_stores = accessed_keys
                    .iter()
                    .filter_map(|key| last_store_by_addr.get(key))
                    .collect::<Vec<_>>();
                if prior_stores.len() == accessed_keys.len() && !prior_stores.is_empty() {
                    if let Some(cell_id) = me1_cell(&prior_stores[0].mnemonic, mnemonic) {
                        let loaded_bytes =
                            access_bytes(&access.read_data, byte_offset, width).unwrap_or_default();
                        let stored_bytes =
                            prior_stores.iter().map(|store| store.byte).collect::<Vec<_>>();
                        self.push_obligation_hit(
                            hits,
                            semantic::memory::STORE_LOAD_PAYLOAD_FLOW,
                            insn,
                            hit_op_idx,
                            "me1",
                            cell_id,
                            "memory_access",
                            &[
                                common.as_slice(),
                                &[
                                    ("store_step_idx", json!(prior_stores[0].step_idx)),
                                    ("store_mnemonic", json!(prior_stores[0].mnemonic)),
                                    ("loaded_bytes", json!(loaded_bytes)),
                                    ("stored_bytes", json!(stored_bytes)),
                                ],
                            ]
                            .concat(),
                        );
                    }
                    if accessed_keys
                        .iter()
                        .any(|key| store_count_by_addr.get(key).copied().unwrap_or(0) > 1)
                    {
                        self.push_obligation_hit(
                            hits,
                            semantic::memory::STORE_LOAD_PAYLOAD_FLOW,
                            insn,
                            hit_op_idx,
                            "me1",
                            "me1.overwrite",
                            "memory_access",
                            &common,
                        );
                    }
                } else if accessed_keys.iter().all(|key| !store_count_by_addr.contains_key(key)) {
                    let loaded_bytes =
                        access_bytes(&access.read_data, byte_offset, width).unwrap_or_default();
                    let cell_id = if loaded_bytes.iter().all(|byte| *byte == 0) {
                        "me7.bss_zero"
                    } else {
                        "me7.data_loaded"
                    };
                    self.push_obligation_hit(
                        hits,
                        semantic::memory::INITIAL_VALUE_BINDING,
                        insn,
                        hit_op_idx,
                        "me7",
                        cell_id,
                        "memory_access",
                        &[common.as_slice(), &[("loaded_bytes", json!(loaded_bytes))]].concat(),
                    );
                }
            }

            let last_byte = access.effective_ptr.checked_add(width.saturating_sub(1));
            if last_byte.is_none() || last_byte.is_some_and(|addr| addr > 0xffff_ffef) {
                let cell_id = match mnemonic {
                    "lw" => Some("me6.near_max_lw"),
                    "sw" => Some("me6.near_max_sw"),
                    "lh" | "lhu" => Some("me6.near_max_lh"),
                    "sb" if access.effective_ptr == 0xffff_ffff => Some("me6.near_max_sb"),
                    _ => None,
                };
                if let Some(cell_id) = cell_id {
                    self.push_obligation_hit(
                        hits,
                        semantic::memory::ADDRESS_BOUNDARY_RANGE,
                        insn,
                        hit_op_idx,
                        "me6",
                        cell_id,
                        "memory_access",
                        &common,
                    );
                }
            }
            if u64::from(access.effective_ptr) + u64::from(width) >= (1u64 << 29) - 16 {
                self.push_obligation_hit(
                    hits,
                    semantic::memory::ADDRESS_BOUNDARY_RANGE,
                    insn,
                    hit_op_idx,
                    "me6",
                    "me6.heap_boundary",
                    "memory_access",
                    &common,
                );
            }

            if width == 1 {
                self.push_obligation_hit(
                    hits,
                    semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                    insn,
                    hit_op_idx,
                    "me2",
                    "me2.byte_any",
                    "memory_access",
                    &common,
                );
            } else if width == 2 && byte_offset % 2 == 1 {
                self.push_obligation_hit(
                    hits,
                    semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                    insn,
                    hit_op_idx,
                    "me2",
                    "me2.half_off1",
                    "memory_access",
                    &common,
                );
            } else if width == 4 && byte_offset != 0 {
                let cell_id = match byte_offset {
                    1 => "me2.word_off1",
                    2 => "me2.word_off2",
                    3 => "me2.word_off3",
                    _ => "me2.word_off1",
                };
                self.push_obligation_hit(
                    hits,
                    semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                    insn,
                    hit_op_idx,
                    "me2",
                    cell_id,
                    "memory_access",
                    &common,
                );
            }

            if let Some(cell_id) = load_sign_cell(mnemonic, &access.read_data, byte_offset) {
                self.push_obligation_hit(
                    hits,
                    semantic::memory::LOAD_VALUE_BINDING,
                    insn,
                    hit_op_idx,
                    "me3",
                    cell_id,
                    "memory_access",
                    &common,
                );
            }

            if mnemonic == "sb" {
                let cell_id = match byte_offset {
                    0 => "me4.sb_off0",
                    1 => "me4.sb_off1",
                    2 => "me4.sb_off2",
                    _ => "me4.sb_off3",
                };
                self.push_obligation_hit(
                    hits,
                    semantic::memory::WRITE_PAYLOAD_CONSISTENCY,
                    insn,
                    hit_op_idx,
                    "me4",
                    cell_id,
                    "memory_access",
                    &common,
                );
            } else if mnemonic == "sh" {
                let cell_id = match byte_offset {
                    0 => Some("me4.sh_off0"),
                    2 => Some("me4.sh_off2"),
                    _ => None,
                };
                if let Some(cell_id) = cell_id {
                    self.push_obligation_hit(
                        hits,
                        semantic::memory::WRITE_PAYLOAD_CONSISTENCY,
                        insn,
                        hit_op_idx,
                        "me4",
                        cell_id,
                        "memory_access",
                        &common,
                    );
                }
            }

            for cell_id in if access.is_load {
                ["me5.mem_read", "me5.reg_write"].as_slice()
            } else {
                ["me5.mem_write", "me5.reg_read"].as_slice()
            } {
                self.push_obligation_hit(
                    hits,
                    semantic::memory::ADDRESS_SPACE_CONSISTENCY,
                    insn,
                    hit_op_idx,
                    "me5",
                    cell_id,
                    "memory_access",
                    &common,
                );
            }

            if width < 4 {
                let cell_id = match byte_offset {
                    0 => "me9.off0",
                    1 => "me9.off1",
                    2 => "me9.off2",
                    _ => "me9.off3",
                };
                self.push_obligation_hit(
                    hits,
                    semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY,
                    insn,
                    hit_op_idx,
                    "me9",
                    cell_id,
                    "memory_access",
                    &common,
                );

                if let Some((prev_access, _)) = previous_subword {
                    if access.effective_ptr.abs_diff(prev_access.effective_ptr) == 1 {
                        let cell_id = if access.aligned_ptr == prev_access.aligned_ptr {
                            "me9.adjacent_same_word"
                        } else {
                            "me9.adjacent_diff_word"
                        };
                        self.push_obligation_hit(
                            hits,
                            semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY,
                            insn,
                            hit_op_idx,
                            "me9",
                            cell_id,
                            "memory_access",
                            &common,
                        );
                    }
                }
                previous_subword = Some((access, insn));
            }

            let cell_id = if access.is_load { "me10.load" } else { "me10.store" };
            self.push_obligation_hit(
                hits,
                semantic::memory::KIND_SELECTOR_CONSISTENCY,
                insn,
                hit_op_idx,
                "me10",
                cell_id,
                "memory_access",
                &common,
            );

            if access.is_store {
                for i in 0..width {
                    let Some(addr) = access.effective_ptr.checked_add(i) else {
                        continue;
                    };
                    let byte_offset_in_word = byte_offset + i;
                    let byte = access_byte(&access.write_data, byte_offset_in_word)
                        .or_else(|| access_byte(&access.read_data, byte_offset_in_word))
                        .unwrap_or(0);
                    let key = (access.address_space, addr);
                    last_store_by_addr.insert(
                        key,
                        StoreByte { mnemonic: mnemonic.to_string(), step_idx: hit_op_idx, byte },
                    );
                    *store_count_by_addr.entry(key).or_insert(0) += 1;
                }
            }
        }
    }

    fn push_memory_lifecycle_hit(
        &self,
        hits: &mut Vec<BucketHit>,
        bucket: semantic::SemanticBucket,
        op_idx: u64,
        obligation_id: &str,
        cell_id: &str,
        trace_source: &str,
        extras: &[(&str, Value)],
    ) {
        let mut details = HashMap::from([
            ("obligation_id".to_string(), json!(obligation_id)),
            ("cell_id".to_string(), json!(cell_id)),
            ("op_idx".to_string(), json!(op_idx)),
            ("backend".to_string(), json!("openvm")),
            ("commit".to_string(), json!(OPENVM_COMMIT)),
            ("trace_source".to_string(), json!(trace_source)),
        ]);
        for (key, value) in extras {
            details.insert((*key).to_string(), value.clone());
        }
        hits.push(BucketHit::semantic(bucket, details));
    }

    fn derive_memory_lifecycle_obligation_hits(&self, hits: &mut Vec<BucketHit>) {
        let mut seen_init_addrs = HashSet::new();
        for init in &self.memory_inits {
            let cell_id = if init.value == 0 { "me7.bss_zero" } else { "me7.data_loaded" };
            let common = [
                ("memory_seq", json!(init.seq)),
                ("address_space", json!(init.address_space)),
                ("pointer", json!(init.pointer)),
                ("value", json!(init.value)),
            ];
            self.push_memory_lifecycle_hit(
                hits,
                semantic::memory::INITIAL_VALUE_BINDING,
                init.op_idx,
                "me7",
                cell_id,
                "memory_init",
                &common,
            );
            let conflict_cell = if seen_init_addrs.insert((init.address_space, init.pointer)) {
                "me8.no_conflict"
            } else {
                "me8.double_init"
            };
            self.push_memory_lifecycle_hit(
                hits,
                semantic::memory::INITIAL_VALUE_BINDING,
                init.op_idx,
                "me8",
                conflict_cell,
                "memory_init",
                &common,
            );
        }

        for finalization in &self.memory_finalizations {
            let cell_id = if finalization.changed_from_initial {
                "me11.written_cells"
            } else {
                "me11.read_only_cells"
            };
            self.push_memory_lifecycle_hit(
                hits,
                semantic::memory::FINALIZATION_CONSISTENCY,
                finalization.op_idx,
                "me11",
                cell_id,
                "memory_finalization",
                &[
                    ("memory_seq", json!(finalization.seq)),
                    ("address_space", json!(finalization.address_space)),
                    ("pointer", json!(finalization.pointer)),
                    ("timestamp", json!(finalization.timestamp)),
                    ("values", json!(finalization.values)),
                    ("was_initial", json!(finalization.was_initial)),
                    ("changed_from_initial", json!(finalization.changed_from_initial)),
                ],
            );
        }
    }

    fn derive_timestamp_obligation_hits(&self, hits: &mut Vec<BucketHit>) {
        let Some(first) = self.instructions.first() else {
            return;
        };
        if first.timestamp == 0 {
            hits.push(BucketHit::semantic(
                semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
                HashMap::from([
                    ("obligation_id".to_string(), json!("ts1")),
                    ("cell_id".to_string(), json!("ts1.standard")),
                    ("op_idx".to_string(), json!(first.step_idx)),
                    ("pc".to_string(), json!(first.pc)),
                    ("opcode".to_string(), json!(first.opcode)),
                    ("backend".to_string(), json!("openvm")),
                    ("commit".to_string(), json!(OPENVM_COMMIT)),
                    ("trace_source".to_string(), json!("instruction")),
                    ("timestamp".to_string(), json!(first.timestamp)),
                    ("next_timestamp".to_string(), json!(first.next_timestamp)),
                ]),
            ));
        }
        hits.push(BucketHit::semantic(
            semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
            HashMap::from([
                ("obligation_id".to_string(), json!("ts3")),
                ("cell_id".to_string(), json!("ts3.standard")),
                ("op_idx".to_string(), json!(first.step_idx)),
                ("pc".to_string(), json!(first.pc)),
                ("opcode".to_string(), json!(first.opcode)),
                ("backend".to_string(), json!("openvm")),
                ("commit".to_string(), json!(OPENVM_COMMIT)),
                ("trace_source".to_string(), json!("instruction")),
                ("timestamp".to_string(), json!(first.timestamp)),
            ]),
        ));
    }

    fn derive_timestamp_memory_order_hits(
        &self,
        decoded: &[(u64, RV32IMInstruction)],
        hits: &mut Vec<BucketHit>,
    ) {
        let decoded_by_step =
            decoded.iter().map(|(step_idx, insn)| (*step_idx, insn)).collect::<HashMap<_, _>>();
        let decoded_by_pc = decoded
            .iter()
            .filter_map(|(step_idx, insn)| {
                self.trace_instruction_for_step(*step_idx)
                    .map(|trace_insn| (trace_insn.pc, (*step_idx, insn)))
            })
            .collect::<HashMap<_, _>>();
        let mut last_by_access_key: HashMap<(u32, u32), (&OpenVMMemoryAccess, u64)> =
            HashMap::new();

        for access in &self.memory_accesses {
            let decoded_entry =
                access.pc.and_then(|pc| decoded_by_pc.get(&pc).copied()).or_else(|| {
                    decoded_by_step.get(&access.step_idx).map(|insn| (access.step_idx, *insn))
                });
            let Some((hit_op_idx, insn)) = decoded_entry else {
                continue;
            };
            let key = (access.address_space, access.effective_ptr);
            if let Some((prev_access, prev_op_idx)) = last_by_access_key.get(&key) {
                let ts_diff = access.timestamp.wrapping_sub(prev_access.timestamp);
                let mut cells = Vec::new();
                if ts_diff == 1 {
                    cells.push("ts2.consecutive");
                }
                if ts_diff <= 16 {
                    cells.push("ts2.small_gap");
                }
                if ts_diff >= 128 {
                    cells.push("ts2.large_gap");
                }
                for cell_id in cells {
                    self.push_obligation_hit(
                        hits,
                        semantic::time::MONOTONIC_ACCESS_ORDERING,
                        insn,
                        hit_op_idx,
                        "ts2",
                        cell_id,
                        "memory_access",
                        &[
                            ("previous_step_idx", json!(prev_op_idx)),
                            ("previous_memory_step_idx", json!(prev_access.step_idx)),
                            ("memory_step_idx", json!(access.step_idx)),
                            ("memory_pc", json!(access.pc)),
                            ("previous_timestamp", json!(prev_access.timestamp)),
                            ("timestamp", json!(access.timestamp)),
                            ("ts_diff", json!(ts_diff)),
                            ("address_space", json!(access.address_space)),
                            ("effective_ptr", json!(access.effective_ptr)),
                            ("width", json!(access.width)),
                            ("is_load", json!(access.is_load)),
                            ("is_store", json!(access.is_store)),
                        ],
                    );
                }
            }
            last_by_access_key.insert(key, (access, hit_op_idx));
        }
    }

    fn derive_lookup_multiplicity_obligation_hits(&self, hits: &mut Vec<BucketHit>) {
        for row in &self.lookup_multiplicities {
            if !row.is_real && row.multiplicity == 0 {
                continue;
            }
            let cell_id = if row.is_real {
                if row.multiplicity > 1 {
                    "bu1.multi_send"
                } else {
                    "bu1.real_row"
                }
            } else {
                "bu1.padding_row"
            };
            hits.push(BucketHit::semantic(
                semantic::lookup::BOOLEAN_MULTIPLICITY,
                HashMap::from([
                    ("obligation_id".to_string(), json!("bu1")),
                    ("cell_id".to_string(), json!(cell_id)),
                    ("op_idx".to_string(), json!(row.step_idx)),
                    ("step_idx".to_string(), json!(row.step_idx)),
                    ("backend".to_string(), json!("openvm")),
                    ("commit".to_string(), json!(OPENVM_COMMIT)),
                    ("trace_source".to_string(), json!("lookup_multiplicity")),
                    ("lookup_seq".to_string(), json!(row.seq)),
                    ("table_name".to_string(), json!(row.table_name)),
                    ("row_idx".to_string(), json!(row.row_idx)),
                    ("multiplicity".to_string(), json!(row.multiplicity)),
                    ("is_real".to_string(), json!(row.is_real)),
                ]),
            ));
        }
    }

    fn reg_ptr_matches(ptr: u32, reg: Option<u32>) -> bool {
        reg.map(|reg| ptr == reg || ptr == reg * 4).unwrap_or(false)
    }

    fn rs2_source_matches(rs2: &Rs2Source, insn: &RV32IMInstruction) -> bool {
        match rs2 {
            Rs2Source::Reg { ptr } => Self::reg_ptr_matches(*ptr, insn.rs2),
            Rs2Source::Imm { value } => insn.imm == Some(*value),
        }
    }

    fn decoded_for_trace_pc<'a>(
        &'a self,
        decoded: &'a [(u64, RV32IMInstruction)],
        pc: u32,
    ) -> Option<(u64, &'a RV32IMInstruction)> {
        decoded.iter().find_map(|(op_idx, insn)| {
            let trace_pc =
                self.trace_instruction_for_step(*op_idx).map(|trace_insn| trace_insn.pc)?;
            (trace_pc == pc).then_some((*op_idx, insn))
        })
    }

    fn chip_row_matches_decoded(row: &OpenVMChipRow, insn: &RV32IMInstruction) -> bool {
        let mnemonic = insn.mnemonic.as_str();
        match &row.payload {
            OpenVMChipRowPayload::BaseAlu { rd_ptr, rs1_ptr, rs2, .. } => {
                (alu_r_mnemonic(mnemonic) || alu_i_mnemonic(mnemonic))
                    && Self::reg_ptr_matches(*rd_ptr, insn.rd)
                    && Self::reg_ptr_matches(*rs1_ptr, insn.rs1)
                    && Self::rs2_source_matches(rs2, insn)
            }
            OpenVMChipRowPayload::Shift { rd_ptr, rs1_ptr, rs2, .. } => {
                matches!(mnemonic, "sll" | "srl" | "sra" | "slli" | "srli" | "srai")
                    && Self::reg_ptr_matches(*rd_ptr, insn.rd)
                    && Self::reg_ptr_matches(*rs1_ptr, insn.rs1)
                    && Self::rs2_source_matches(rs2, insn)
            }
            OpenVMChipRowPayload::LessThan { rd_ptr, rs1_ptr, rs2, .. } => {
                matches!(mnemonic, "slt" | "sltu" | "slti" | "sltiu")
                    && Self::reg_ptr_matches(*rd_ptr, insn.rd)
                    && Self::reg_ptr_matches(*rs1_ptr, insn.rs1)
                    && Self::rs2_source_matches(rs2, insn)
            }
            OpenVMChipRowPayload::Mul { rd_ptr, rs1_ptr, rs2_ptr, .. } => {
                mnemonic == "mul"
                    && Self::reg_ptr_matches(*rd_ptr, insn.rd)
                    && Self::reg_ptr_matches(*rs1_ptr, insn.rs1)
                    && Self::reg_ptr_matches(*rs2_ptr, insn.rs2)
            }
            OpenVMChipRowPayload::MulH { rd_ptr, rs1_ptr, rs2_ptr, .. } => {
                high_mul_mnemonic(mnemonic)
                    && Self::reg_ptr_matches(*rd_ptr, insn.rd)
                    && Self::reg_ptr_matches(*rs1_ptr, insn.rs1)
                    && Self::reg_ptr_matches(*rs2_ptr, insn.rs2)
            }
            OpenVMChipRowPayload::DivRem { rd_ptr, rs1_ptr, rs2_ptr, .. } => {
                div_mnemonic(mnemonic)
                    && Self::reg_ptr_matches(*rd_ptr, insn.rd)
                    && Self::reg_ptr_matches(*rs1_ptr, insn.rs1)
                    && Self::reg_ptr_matches(*rs2_ptr, insn.rs2)
            }
            OpenVMChipRowPayload::BranchEqual { rs1_ptr, rs2_ptr, .. }
            | OpenVMChipRowPayload::BranchLessThan { rs1_ptr, rs2_ptr, .. } => {
                branch_mnemonic(mnemonic)
                    && Self::reg_ptr_matches(*rs1_ptr, insn.rs1)
                    && Self::reg_ptr_matches(*rs2_ptr, insn.rs2)
            }
            OpenVMChipRowPayload::JalLui { is_jal, rd_ptr, .. } => {
                ((*is_jal && mnemonic == "jal") || (!*is_jal && mnemonic == "lui"))
                    && Self::reg_ptr_matches(*rd_ptr, insn.rd)
            }
            OpenVMChipRowPayload::Jalr { rd_ptr, rs1_ptr, .. } => {
                mnemonic == "jalr"
                    && Self::reg_ptr_matches(*rd_ptr, insn.rd)
                    && Self::reg_ptr_matches(*rs1_ptr, insn.rs1)
            }
            OpenVMChipRowPayload::Auipc { rd_ptr, .. } => {
                mnemonic == "auipc" && Self::reg_ptr_matches(*rd_ptr, insn.rd)
            }
            _ => false,
        }
    }

    fn chip_row_decoded_anchor<'a>(
        &'a self,
        row: &'a OpenVMChipRow,
        decoded_by_step: &HashMap<u64, &'a RV32IMInstruction>,
        decoded: &'a [(u64, RV32IMInstruction)],
    ) -> Option<(u64, &'a RV32IMInstruction)> {
        let base = row.base();
        if let Some(insn) = decoded_by_step.get(&base.step_idx) {
            if Self::chip_row_matches_decoded(row, insn) {
                return Some((base.step_idx, *insn));
            }
        }

        let from_pc = match &row.payload {
            OpenVMChipRowPayload::BranchEqual { from_pc, .. }
            | OpenVMChipRowPayload::BranchLessThan { from_pc, .. }
            | OpenVMChipRowPayload::JalLui { from_pc, .. }
            | OpenVMChipRowPayload::Jalr { from_pc, .. }
            | OpenVMChipRowPayload::Auipc { from_pc, .. } => Some(*from_pc),
            _ => None,
        };
        if let Some(from_pc) = from_pc {
            if let Some((op_idx, insn)) = self.decoded_for_trace_pc(decoded, from_pc) {
                if Self::chip_row_matches_decoded(row, insn) {
                    return Some((op_idx, insn));
                }
            }
        }

        decoded.iter().find_map(|(op_idx, insn)| {
            Self::chip_row_matches_decoded(row, insn).then_some((*op_idx, insn))
        })
    }

    fn derive_chip_row_obligation_hits(
        &self,
        decoded: &[(u64, RV32IMInstruction)],
        hits: &mut Vec<BucketHit>,
    ) {
        let decoded_by_step =
            decoded.iter().map(|(step_idx, insn)| (*step_idx, insn)).collect::<HashMap<_, _>>();
        for row in &self.chip_rows {
            let base = row.base();
            let Some((instr_op_idx, insn)) =
                self.chip_row_decoded_anchor(row, &decoded_by_step, decoded)
            else {
                continue;
            };
            let mnemonic = insn.mnemonic.as_str();
            let row_extras = [
                ("row_step_idx", json!(base.step_idx)),
                ("row_op_idx", json!(base.op_idx)),
                ("chip_name", json!(base.chip_name)),
                ("kind", json!(kind_snake(row.kind))),
            ];

            match &row.payload {
                OpenVMChipRowPayload::DivRem { op, rd_ptr, rs1_ptr, rs2_ptr, a, b, c }
                    if div_mnemonic(mnemonic) =>
                {
                    if let (Some(rd_val), Some(rs1_val), Some(rs2_val)) =
                        (le_u32_from_bytes(a), le_u32_from_bytes(b), le_u32_from_bytes(c))
                    {
                        let mut extras = row_extras.to_vec();
                        extras.extend([
                            ("row_opcode", json!(op)),
                            ("rd_ptr", json!(rd_ptr)),
                            ("rs1_ptr", json!(rs1_ptr)),
                            ("rs2_ptr", json!(rs2_ptr)),
                            ("rd_val", json!(rd_val)),
                            ("rs1_val", json!(rs1_val)),
                            ("rs2_val", json!(rs2_val)),
                            ("rs1_signed", json!(signed_i32(rs1_val))),
                            ("rs2_signed", json!(signed_i32(rs2_val))),
                        ]);

                        if rs2_val == 0 {
                            if let Some(cell_id) = div_by_zero_cell(mnemonic) {
                                self.push_obligation_hit(
                                    hits,
                                    semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                                    insn,
                                    instr_op_idx,
                                    "md1",
                                    cell_id,
                                    "chip_row",
                                    &extras,
                                );
                            }
                            self.push_obligation_hit(
                                hits,
                                semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                                insn,
                                instr_op_idx,
                                "md1",
                                dividend_sign_cell(rs1_val),
                                "chip_row",
                                &extras,
                            );
                        } else {
                            let is_unsigned = matches!(mnemonic, "divu" | "remu");
                            let is_signed_overflow = signed_div_mnemonic(mnemonic)
                                && rs1_val == 0x8000_0000
                                && rs2_val == 0xffff_ffff;
                            let mut md3_cells = Vec::new();
                            if is_unsigned {
                                md3_cells.push("md3.unsigned");
                                let quotient = rs1_val / rs2_val;
                                let remainder = rs1_val % rs2_val;
                                if remainder == 0 {
                                    md3_cells.push("md3.exact");
                                }
                                if quotient >= 0x8000_0000 {
                                    md3_cells.push("md3.large_q");
                                }
                                if rs2_val == 1 {
                                    md3_cells.push("md3.one");
                                }
                                extras.extend([
                                    ("quotient_model", json!(quotient)),
                                    ("remainder_model", json!(remainder)),
                                ]);
                            } else {
                                let dividend = signed_i64(rs1_val);
                                let divisor = signed_i64(rs2_val);
                                match (dividend.cmp(&0), divisor.cmp(&0)) {
                                    (std::cmp::Ordering::Greater, std::cmp::Ordering::Greater) => {
                                        md3_cells.push("md3.pp");
                                    }
                                    (std::cmp::Ordering::Greater, std::cmp::Ordering::Less) => {
                                        md3_cells.push("md3.pn");
                                    }
                                    (std::cmp::Ordering::Less, std::cmp::Ordering::Greater) => {
                                        md3_cells.push("md3.np");
                                    }
                                    (std::cmp::Ordering::Less, std::cmp::Ordering::Less) => {
                                        md3_cells.push("md3.nn");
                                    }
                                    _ => {}
                                }
                                let quotient = dividend / divisor;
                                let remainder = dividend % divisor;
                                if remainder == 0 {
                                    md3_cells.push("md3.exact");
                                }
                                if quotient.unsigned_abs() >= (1u64 << 30) {
                                    md3_cells.push("md3.large_q");
                                }
                                if divisor.unsigned_abs() == 1 {
                                    md3_cells.push("md3.one");
                                }
                                extras.extend([
                                    ("quotient_model", json!(quotient)),
                                    ("remainder_model", json!(remainder)),
                                    ("signed_overflow_special", json!(is_signed_overflow)),
                                ]);
                            }
                            for cell_id in md3_cells {
                                self.push_obligation_hit(
                                    hits,
                                    semantic::arithmetic::DIVISION_REMAINDER_BOUND,
                                    insn,
                                    instr_op_idx,
                                    "md3",
                                    cell_id,
                                    "chip_row",
                                    &extras,
                                );
                            }

                            if is_signed_overflow {
                                let cell_id = match mnemonic {
                                    "div" => Some("md2.div_overflow"),
                                    "rem" => Some("md2.rem_overflow"),
                                    _ => None,
                                };
                                if let Some(cell_id) = cell_id {
                                    self.push_obligation_hit(
                                        hits,
                                        semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                                        insn,
                                        instr_op_idx,
                                        "md2",
                                        cell_id,
                                        "chip_row",
                                        &extras,
                                    );
                                }
                            }
                        }
                    }
                }
                OpenVMChipRowPayload::Mul { op, rd_ptr, rs1_ptr, rs2_ptr, a, b, c }
                    if mnemonic == "mul" =>
                {
                    if let (Some(rd_val), Some(rs1_val), Some(rs2_val)) =
                        (le_u32_from_bytes(a), le_u32_from_bytes(b), le_u32_from_bytes(c))
                    {
                        let (product_lo, product_hi, product) =
                            unsigned_product_words(rs1_val, rs2_val);
                        let mut extras = row_extras.to_vec();
                        extras.extend([
                            ("row_opcode", json!(op)),
                            ("rd_ptr", json!(rd_ptr)),
                            ("rs1_ptr", json!(rs1_ptr)),
                            ("rs2_ptr", json!(rs2_ptr)),
                            ("rd_val", json!(rd_val)),
                            ("rs1_val", json!(rs1_val)),
                            ("rs2_val", json!(rs2_val)),
                            ("product_lo", json!(product_lo)),
                            ("product_hi", json!(product_hi)),
                            ("product_model_hex", json!(product_hex(product))),
                        ]);
                        let primary =
                            if product_hi == 0 { "md4.mul_small" } else { "md4.mul_overflow" };
                        self.push_obligation_hit(
                            hits,
                            semantic::arithmetic::PRODUCT_DECOMPOSITION,
                            insn,
                            instr_op_idx,
                            "md4",
                            primary,
                            "chip_row",
                            &extras,
                        );
                        if rs1_val == 0 || rs2_val == 0 {
                            self.push_obligation_hit(
                                hits,
                                semantic::arithmetic::PRODUCT_DECOMPOSITION,
                                insn,
                                instr_op_idx,
                                "md4",
                                "md4.zero_op",
                                "chip_row",
                                &extras,
                            );
                        }
                        if (rs1_val == 0xffff_ffff && rs2_val == 0xffff_ffff)
                            || (rs1_val == 0x7fff_ffff && rs2_val == 0x7fff_ffff)
                        {
                            self.push_obligation_hit(
                                hits,
                                semantic::arithmetic::PRODUCT_DECOMPOSITION,
                                insn,
                                instr_op_idx,
                                "md4",
                                "md4.max_product",
                                "chip_row",
                                &extras,
                            );
                        }
                    }
                }
                OpenVMChipRowPayload::MulH { op, rd_ptr, rs1_ptr, rs2_ptr, a, b, c }
                    if high_mul_mnemonic(mnemonic) =>
                {
                    if let (Some(rd_val), Some(rs1_val), Some(rs2_val)) =
                        (le_u32_from_bytes(a), le_u32_from_bytes(b), le_u32_from_bytes(c))
                    {
                        let (product_lo, product_hi, product_hex_value, signed_unsigned) =
                            match mnemonic {
                                "mulh" => {
                                    let (lo, hi, product) = signed_product_words(rs1_val, rs2_val);
                                    (lo, hi, product_hex(product), false)
                                }
                                "mulhsu" => {
                                    let (lo, hi, product) =
                                        signed_unsigned_product_words(rs1_val, rs2_val);
                                    (lo, hi, product_hex(product), true)
                                }
                                "mulhu" => {
                                    let (lo, hi, product) =
                                        unsigned_product_words(rs1_val, rs2_val);
                                    (lo, hi, product_hex(product), false)
                                }
                                _ => continue,
                            };
                        let mut extras = row_extras.to_vec();
                        extras.extend([
                            ("row_opcode", json!(op)),
                            ("rd_ptr", json!(rd_ptr)),
                            ("rs1_ptr", json!(rs1_ptr)),
                            ("rs2_ptr", json!(rs2_ptr)),
                            ("rd_val", json!(rd_val)),
                            ("rs1_val", json!(rs1_val)),
                            ("rs2_val", json!(rs2_val)),
                            ("rs1_signed", json!(signed_i32(rs1_val))),
                            ("rs2_signed", json!(signed_i32(rs2_val))),
                            ("product_lo", json!(product_lo)),
                            ("product_hi", json!(product_hi)),
                            ("product_model_hex", json!(product_hex_value)),
                        ]);

                        if mnemonic == "mulh" {
                            let cell_id =
                                match (signed_i32(rs1_val).cmp(&0), signed_i32(rs2_val).cmp(&0)) {
                                    (
                                        std::cmp::Ordering::Greater | std::cmp::Ordering::Equal,
                                        std::cmp::Ordering::Greater | std::cmp::Ordering::Equal,
                                    ) => "md4.mulh_pp",
                                    (std::cmp::Ordering::Less, std::cmp::Ordering::Less) => {
                                        "md4.mulh_nn"
                                    }
                                    _ => "md4.mulh_pn",
                                };
                            self.push_obligation_hit(
                                hits,
                                semantic::arithmetic::PRODUCT_DECOMPOSITION,
                                insn,
                                instr_op_idx,
                                "md4",
                                cell_id,
                                "chip_row",
                                &extras,
                            );
                        } else if mnemonic == "mulhu" {
                            self.push_obligation_hit(
                                hits,
                                semantic::arithmetic::PRODUCT_DECOMPOSITION,
                                insn,
                                instr_op_idx,
                                "md4",
                                "md4.mulhu",
                                "chip_row",
                                &extras,
                            );
                        }
                        if rs1_val == 0 || rs2_val == 0 {
                            self.push_obligation_hit(
                                hits,
                                semantic::arithmetic::PRODUCT_DECOMPOSITION,
                                insn,
                                instr_op_idx,
                                "md4",
                                "md4.zero_op",
                                "chip_row",
                                &extras,
                            );
                        }
                        if (rs1_val == 0xffff_ffff && rs2_val == 0xffff_ffff)
                            || (rs1_val == 0x7fff_ffff && rs2_val == 0x7fff_ffff)
                        {
                            self.push_obligation_hit(
                                hits,
                                semantic::arithmetic::PRODUCT_DECOMPOSITION,
                                insn,
                                instr_op_idx,
                                "md4",
                                "md4.max_product",
                                "chip_row",
                                &extras,
                            );
                        }

                        if signed_unsigned {
                            let correction_applies = signed_i32(rs1_val) < 0;
                            let cell_id = if !correction_applies {
                                "md5.pos_any"
                            } else if rs1_val == 0xffff_ffff && rs2_val == 0xffff_ffff {
                                "md5.neg_max"
                            } else if rs2_val == 1 {
                                "md5.neg_one"
                            } else if rs2_val <= 0xff {
                                "md5.neg_small"
                            } else {
                                "md5.neg_large"
                            };
                            let mut md5_extras = extras.clone();
                            md5_extras.extend([
                                ("correction_applies", json!(correction_applies)),
                                ("correction_subtrahend", json!(rs2_val)),
                            ]);
                            self.push_obligation_hit(
                                hits,
                                semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION,
                                insn,
                                instr_op_idx,
                                "md5",
                                cell_id,
                                "chip_row",
                                &md5_extras,
                            );
                        }
                    }
                }
                OpenVMChipRowPayload::Jalr {
                    op,
                    rd_ptr,
                    rs1_ptr,
                    imm,
                    imm_sign,
                    needs_write,
                    from_pc,
                    to_pc,
                    rs1_val,
                    target_before_lsb_clear,
                    ..
                } if mnemonic == "jalr" => {
                    let computed_target = rs1_val.wrapping_add(*imm as u32);
                    let pre_mask_target = target_before_lsb_clear.unwrap_or(computed_target);
                    let target_sum = i64::from(*rs1_val) + i64::from(*imm);
                    let wrapped = !(0..=i64::from(u32::MAX)).contains(&target_sum);
                    let mut extras = row_extras.to_vec();
                    extras.extend([
                        ("row_opcode", json!(op)),
                        ("rd_ptr", json!(rd_ptr)),
                        ("rs1_ptr", json!(rs1_ptr)),
                        ("rs1_val", json!(rs1_val)),
                        ("imm", json!(imm)),
                        ("imm_sign", json!(imm_sign)),
                        ("needs_write", json!(needs_write)),
                        ("from_pc", json!(from_pc)),
                        ("next_pc", json!(to_pc)),
                        ("target_sum_i64", json!(target_sum)),
                        ("target_before_lsb_clear", json!(pre_mask_target)),
                        ("target_after_lsb_clear", json!(pre_mask_target & !1)),
                        ("target_low_bit", json!(pre_mask_target & 1)),
                        ("wraparound", json!(wrapped)),
                        ("pc_unit", json!("openvm_instruction_index")),
                    ]);
                    let lsb_cell =
                        if pre_mask_target & 1 == 1 { "cf3.clear_lsb" } else { "cf3.even" };
                    self.push_obligation_hit(
                        hits,
                        semantic::exec::CONTROL_FLOW_BINDING,
                        insn,
                        instr_op_idx,
                        "cf3",
                        lsb_cell,
                        "chip_row",
                        &extras,
                    );
                    if wrapped {
                        self.push_obligation_hit(
                            hits,
                            semantic::exec::CONTROL_FLOW_BINDING,
                            insn,
                            instr_op_idx,
                            "cf3",
                            "cf3.wrap",
                            "chip_row",
                            &extras,
                        );
                    }
                }
                OpenVMChipRowPayload::Shift { b, c, .. }
                    if matches!(mnemonic, "sll" | "srl" | "sra") =>
                {
                    if let (Some(rs1_val), Some(rs2_val)) =
                        (le_u32_from_bytes(b), le_u32_from_bytes(c))
                    {
                        let shamt = rs2_val & 0x1f;
                        let primary = match mnemonic {
                            "sll" if rs2_val >= 32 => "al2.sll_ge32",
                            "sll" => "al2.sll_lt32",
                            "srl" if rs2_val >= 32 => "al2.srl_ge32",
                            "srl" => "al2.srl_lt32",
                            "sra" if rs2_val >= 32 && (rs1_val as i32) < 0 => "al2.sra_ge32_neg",
                            "sra" if rs2_val >= 32 => "al2.sra_ge32_pos",
                            "sra" if (rs1_val as i32) < 0 => "al2.sra_lt32_neg",
                            "sra" => "al2.sra_lt32_pos",
                            _ => continue,
                        };
                        let mut extras = row_extras.to_vec();
                        extras.extend([
                            ("rs1_val", json!(rs1_val)),
                            ("rs2_val", json!(rs2_val)),
                            ("effective_shamt", json!(shamt)),
                        ]);
                        self.push_obligation_hit(
                            hits,
                            semantic::alu::SHIFT_MOD32,
                            insn,
                            instr_op_idx,
                            "al2",
                            primary,
                            "chip_row",
                            &extras,
                        );
                        if shamt == 0 {
                            self.push_obligation_hit(
                                hits,
                                semantic::alu::SHIFT_MOD32,
                                insn,
                                instr_op_idx,
                                "al2",
                                "al2.shamt_zero",
                                "chip_row",
                                &extras,
                            );
                        }
                    }
                }
                OpenVMChipRowPayload::LessThan { a, b, c, .. }
                    if matches!(mnemonic, "slt" | "sltu" | "slti" | "sltiu") =>
                {
                    if let (Some(out), Some(lhs), Some(rhs)) =
                        (le_u32_from_bytes(a), le_u32_from_bytes(b), le_u32_from_bytes(c))
                    {
                        let is_signed = matches!(mnemonic, "slt" | "slti");
                        let result = out != 0;
                        let primary = match (is_signed, result) {
                            (true, true) => "al3.slt_true",
                            (true, false) => "al3.slt_false",
                            (false, true) => "al3.sltu_true",
                            (false, false) => "al3.sltu_false",
                        };
                        let mut extras = row_extras.to_vec();
                        extras.extend([
                            ("rd_val", json!(out)),
                            ("rs1_val", json!(lhs)),
                            ("rs2_or_imm_val", json!(rhs)),
                        ]);
                        self.push_obligation_hit(
                            hits,
                            semantic::alu::COMPARISON_BOOLEANITY,
                            insn,
                            instr_op_idx,
                            "al3",
                            primary,
                            "chip_row",
                            &extras,
                        );
                        if lhs == rhs {
                            self.push_obligation_hit(
                                hits,
                                semantic::alu::COMPARISON_BOOLEANITY,
                                insn,
                                instr_op_idx,
                                "al3",
                                "al3.equal",
                                "chip_row",
                                &extras,
                            );
                        }
                        if ((lhs as i32) < (rhs as i32)) != (lhs < rhs) {
                            self.push_obligation_hit(
                                hits,
                                semantic::alu::COMPARISON_BOOLEANITY,
                                insn,
                                instr_op_idx,
                                "al3",
                                "al3.sign_disagree",
                                "chip_row",
                                &extras,
                            );
                        }
                        self.push_comparison_aux_hits(hits, insn, instr_op_idx, &extras, lhs, rhs);
                    }
                }
                OpenVMChipRowPayload::BaseAlu { b, c, .. } if mnemonic == "sub" => {
                    if let (Some(lhs), Some(rhs)) = (le_u32_from_bytes(b), le_u32_from_bytes(c)) {
                        let primary = if lhs == rhs {
                            "al4.equal"
                        } else if lhs < rhs {
                            "al4.borrow"
                        } else {
                            "al4.no_borrow"
                        };
                        let mut extras = row_extras.to_vec();
                        extras.extend([("rs1_val", json!(lhs)), ("rs2_val", json!(rhs))]);
                        self.push_obligation_hit(
                            hits,
                            semantic::alu::SUBTRACTION_BORROW_CHAIN,
                            insn,
                            instr_op_idx,
                            "al4",
                            primary,
                            "chip_row",
                            &extras,
                        );
                        if limb_cross_borrow(lhs, rhs) {
                            self.push_obligation_hit(
                                hits,
                                semantic::alu::SUBTRACTION_BORROW_CHAIN,
                                insn,
                                instr_op_idx,
                                "al4",
                                "al4.cross_limb",
                                "chip_row",
                                &extras,
                            );
                        }
                    }
                }
                OpenVMChipRowPayload::BranchLessThan { a, b, .. } => {
                    if let (Some(lhs), Some(rhs)) = (le_u32_from_bytes(a), le_u32_from_bytes(b)) {
                        let mut extras = row_extras.to_vec();
                        extras.extend([("rs1_val", json!(lhs)), ("rs2_val", json!(rhs))]);
                        self.push_comparison_aux_hits(hits, insn, instr_op_idx, &extras, lhs, rhs);
                        if branch_mnemonic(mnemonic) && ((lhs as i32) < 0) != ((rhs as i32) < 0) {
                            self.push_obligation_hit(
                                hits,
                                semantic::exec::CONTROL_FLOW_BINDING,
                                insn,
                                instr_op_idx,
                                "cf1",
                                "cf1.sign_flip",
                                "chip_row",
                                &extras,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn push_comparison_aux_hits(
        &self,
        hits: &mut Vec<BucketHit>,
        insn: &RV32IMInstruction,
        op_idx: u64,
        extras: &[(&str, Value)],
        lhs: u32,
        rhs: u32,
    ) {
        let cell_id = if lhs == rhs {
            "al5.all_equal"
        } else if alternating_borrow(lhs, rhs) {
            "al5.alternating_borrow"
        } else {
            let lhs_bytes = lhs.to_le_bytes();
            let rhs_bytes = rhs.to_le_bytes();
            let highest_diff = (0..4).rev().find(|idx| lhs_bytes[*idx] != rhs_bytes[*idx]);
            if highest_diff == Some(0) {
                "al5.last_limb_diff"
            } else {
                "al5.first_limb_diff"
            }
        };
        self.push_obligation_hit(
            hits,
            semantic::alu::COMPARISON_AUXILIARY_CHAIN,
            insn,
            op_idx,
            "al5",
            cell_id,
            "chip_row",
            extras,
        );
    }

    pub fn instructions(&self) -> &[OpenVMInsn] {
        &self.instructions
    }

    pub fn chip_rows(&self) -> &[OpenVMChipRow] {
        &self.chip_rows
    }

    pub fn interactions(&self) -> &[OpenVMInteraction] {
        &self.interactions
    }

    pub fn get_instruction_global(&self, seq: usize) -> &OpenVMInsn {
        let i = self.insn_by_seq[seq].expect("missing insn for seq");
        &self.instructions[i]
    }

    pub fn get_chip_row_global(&self, seq: usize) -> &OpenVMChipRow {
        let i = self.chip_row_by_seq[seq].expect("missing chip_row for seq");
        &self.chip_rows[i]
    }

    pub fn get_interaction_global(&self, seq: usize) -> &OpenVMInteraction {
        let i = self.interaction_by_seq[seq].expect("missing interaction for seq");
        &self.interactions[i]
    }

    pub fn get_instruction_in_step(&self, step_idx: usize, op_idx: usize) -> &OpenVMInsn {
        assert_eq!(op_idx, 0, "OpenVMInsn is 1-per-step; op_idx must be 0");
        let i = self.insn_by_step[step_idx].expect("missing insn for step");
        &self.instructions[i]
    }

    pub fn get_chip_row_in_step(&self, step_idx: usize, op_idx: usize) -> &OpenVMChipRow {
        let indices = self
            .chip_rows_by_step
            .get(step_idx)
            .unwrap_or_else(|| panic!("missing chip_rows for step={}", step_idx));
        let i = indices
            .iter()
            .find(|&&idx| self.chip_rows[idx].base().op_idx == op_idx as u64)
            .copied()
            .unwrap_or_else(|| panic!("missing chip_row for step={}, op_idx={}", step_idx, op_idx));
        &self.chip_rows[i]
    }

    pub fn get_interaction_in_step(&self, step_idx: usize, op_idx: usize) -> &OpenVMInteraction {
        let indices = &self.interactions_by_step[step_idx];
        let i = indices
            .iter()
            .find(|&&idx| self.interactions[idx].base().op_idx == op_idx as u64)
            .copied()
            .unwrap_or_else(|| {
                panic!("missing interaction for step={}, op_idx={}", step_idx, op_idx)
            });
        &self.interactions[i]
    }

    /// Slice of interactions for a row_id.
    ///
    /// Note: this is currently not implemented (would require allocation to materialize a slice of
    /// references). Prefer `interaction_indices_by_row_id` / `interactions_for_step` instead.
    pub fn get_interactions_by_row_id(&self, _row_id: &str) -> &[OpenVMInteraction] {
        &[]
    }

    /// Slice of interactions for a table_id.
    ///
    /// Note: currently not implemented; keep the API surface minimal until we settle on a stable
    /// table-id taxonomy.
    pub fn get_interactions_by_table_id(&self, _table_id: &str) -> &[OpenVMInteraction] {
        &[]
    }
}

impl OpenVMTrace {
    /// All chip row indices for a given step (zero-copy).
    pub fn chip_row_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.chip_rows_by_step.get(step_idx).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// All interaction indices for a given step (zero-copy).
    pub fn interaction_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.interactions_by_step.get(step_idx).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// All interaction indices produced by a specific chip row.
    pub fn interaction_indices_by_row_id(&self, row_id: &str) -> &[usize] {
        self.interactions_by_row_id.get(row_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// All interaction indices on a specific bus (interaction kind).
    pub fn interaction_indices_by_bus(
        &self,
        kind: crate::interaction::OpenVMInteractionKind,
    ) -> &[usize] {
        self.interactions_by_bus.get(&kind).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Iterate over all interactions for a step, yielding references.
    pub fn interactions_for_step(
        &self,
        step_idx: usize,
    ) -> impl Iterator<Item = &OpenVMInteraction> {
        self.interaction_indices_for_step(step_idx).iter().map(|&i| &self.interactions[i])
    }

    /// Iterate over all chip rows for a step, yielding references.
    pub fn chip_rows_for_step(&self, step_idx: usize) -> impl Iterator<Item = &OpenVMChipRow> {
        self.chip_row_indices_for_step(step_idx).iter().map(|&i| &self.chip_rows[i])
    }

    /// Number of instructions in this trace (for micro_op_count / feedback).
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}

impl Trace for OpenVMTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }

    fn trace_signals(&self) -> &[TraceSignal] {
        &self.trace_signals
    }
}

#[cfg(test)]
mod tests {
    use beak_core::rv32im::instruction::RV32IMInstruction;
    use beak_core::trace::{semantic, Trace};

    use crate::chip_row::{
        OpenVMChipRowBase, OpenVMChipRowEnvelope, OpenVMChipRowKind, OpenVMChipRowPayload,
    };

    use super::{OpenVMLookupMultiplicity, OpenVMMemoryAccess, OpenVMTrace};

    #[test]
    fn decoded_group_1_3_hits_use_registered_contract_buckets() {
        let words = [
            RV32IMInstruction::from_parts("addi", Some(0), Some(0), None, Some(1)).unwrap().word,
            RV32IMInstruction::from_parts("addi", Some(1), Some(0), None, Some(-1)).unwrap().word,
            RV32IMInstruction::from_parts("lui", Some(2), None, None, Some(0x1000)).unwrap().word,
            RV32IMInstruction::from_parts("sw", None, Some(1), Some(2), Some(12)).unwrap().word,
            RV32IMInstruction::from_parts("jal", Some(0), None, None, Some(8)).unwrap().word,
        ];

        let trace = OpenVMTrace::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let decoded = words
            .iter()
            .enumerate()
            .map(|(idx, word)| {
                (idx as u64, RV32IMInstruction::from_word(*word).expect("decode test word"))
            })
            .collect::<Vec<_>>();
        let mut hits = Vec::new();
        trace.derive_decoded_obligation_hits(&decoded, &mut hits);
        assert!(hits.iter().all(|hit| semantic::by_id(&hit.bucket_id).is_some()));
        assert!(hits.iter().any(|hit| {
            hit.bucket_id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id
                && hit.details.get("obligation_id").and_then(|v| v.as_str()) == Some("rf1")
        }));
        assert!(hits.iter().any(|hit| {
            hit.bucket_id == semantic::decode::IMMEDIATE_SIGN_EXTENSION.id
                && hit.details.get("obligation_id").and_then(|v| v.as_str()) == Some("id2")
        }));
        assert!(hits.iter().any(|hit| {
            hit.bucket_id == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id
                && hit.details.get("obligation_id").and_then(|v| v.as_str()) == Some("al1")
        }));
        assert!(hits.iter().all(|hit| {
            if hit.details.contains_key("obligation_id") {
                hit.details.contains_key("cell_id")
                    && hit.details.contains_key("op_idx")
                    && hit.details.contains_key("pc")
                    && hit.details.contains_key("opcode")
                    && hit.details.contains_key("mnemonic")
                    && hit.details.get("backend").and_then(|v| v.as_str()) == Some("openvm")
                    && hit.details.get("commit").and_then(|v| v.as_str()).is_some()
                    && hit.details.get("trace_source").and_then(|v| v.as_str()).is_some()
            } else {
                true
            }
        }));
    }

    #[test]
    fn from_logs_with_words_does_not_emit_obligation_hits_without_executed_trace() {
        let words =
            [RV32IMInstruction::from_parts("addi", Some(0), Some(0), None, Some(1)).unwrap().word];

        let trace = OpenVMTrace::from_logs_with_words(Vec::new(), &words).expect("trace");
        assert!(trace.bucket_hits().iter().all(|hit| !hit.details.contains_key("obligation_id")));
    }

    fn row_base(step_idx: u64, kind: OpenVMChipRowKind) -> OpenVMChipRowBase {
        OpenVMChipRowBase {
            seq: step_idx,
            step_idx,
            op_idx: 0,
            is_valid: true,
            timestamp: Some(step_idx as u32),
            chip_name: format!("{kind:?}"),
        }
    }

    fn word_bytes(value: u32) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    #[test]
    fn group_4_muldiv_hits_use_chip_row_operands_and_registered_buckets() {
        let decoded = ["divu", "div", "remu", "mul", "mulhsu"]
            .into_iter()
            .enumerate()
            .map(|(idx, mnemonic)| {
                (
                    idx as u64,
                    RV32IMInstruction::from_parts(mnemonic, Some(3), Some(1), Some(2), None)
                        .expect("encode muldiv test word"),
                )
            })
            .collect::<Vec<_>>();
        let rows = vec![
            OpenVMChipRowEnvelope {
                base: row_base(0, OpenVMChipRowKind::DivRem),
                kind: OpenVMChipRowKind::DivRem,
                payload: OpenVMChipRowPayload::DivRem {
                    op: 0,
                    rd_ptr: 3,
                    rs1_ptr: 1,
                    rs2_ptr: 2,
                    a: word_bytes(0xffff_ffff),
                    b: word_bytes(7),
                    c: word_bytes(0),
                },
            },
            OpenVMChipRowEnvelope {
                base: row_base(1, OpenVMChipRowKind::DivRem),
                kind: OpenVMChipRowKind::DivRem,
                payload: OpenVMChipRowPayload::DivRem {
                    op: 0,
                    rd_ptr: 3,
                    rs1_ptr: 1,
                    rs2_ptr: 2,
                    a: word_bytes(0x8000_0000),
                    b: word_bytes(0x8000_0000),
                    c: word_bytes(0xffff_ffff),
                },
            },
            OpenVMChipRowEnvelope {
                base: row_base(2, OpenVMChipRowKind::DivRem),
                kind: OpenVMChipRowKind::DivRem,
                payload: OpenVMChipRowPayload::DivRem {
                    op: 0,
                    rd_ptr: 3,
                    rs1_ptr: 1,
                    rs2_ptr: 2,
                    a: word_bytes(1),
                    b: word_bytes(9),
                    c: word_bytes(4),
                },
            },
            OpenVMChipRowEnvelope {
                base: row_base(3, OpenVMChipRowKind::Mul),
                kind: OpenVMChipRowKind::Mul,
                payload: OpenVMChipRowPayload::Mul {
                    op: 0,
                    rd_ptr: 3,
                    rs1_ptr: 1,
                    rs2_ptr: 2,
                    a: word_bytes(1),
                    b: word_bytes(0xffff_ffff),
                    c: word_bytes(0xffff_ffff),
                },
            },
            OpenVMChipRowEnvelope {
                base: row_base(4, OpenVMChipRowKind::MulH),
                kind: OpenVMChipRowKind::MulH,
                payload: OpenVMChipRowPayload::MulH {
                    op: 0,
                    rd_ptr: 3,
                    rs1_ptr: 1,
                    rs2_ptr: 2,
                    a: word_bytes(0xffff_ffff),
                    b: word_bytes(0xffff_fffe),
                    c: word_bytes(0x0001_0000),
                },
            },
        ];
        let trace = OpenVMTrace::new(
            Vec::new(),
            rows,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut hits = Vec::new();
        trace.derive_chip_row_obligation_hits(&decoded, &mut hits);

        assert!(hits.iter().all(|hit| semantic::by_id(&hit.bucket_id).is_some()));
        for (obligation_id, cell_id, bucket_id) in [
            ("md1", "md1.divu_zero", semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id),
            ("md2", "md2.div_overflow", semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id),
            ("md3", "md3.unsigned", semantic::arithmetic::DIVISION_REMAINDER_BOUND.id),
            ("md4", "md4.mul_overflow", semantic::arithmetic::PRODUCT_DECOMPOSITION.id),
            ("md4", "md4.max_product", semantic::arithmetic::PRODUCT_DECOMPOSITION.id),
            ("md5", "md5.neg_large", semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id),
        ] {
            assert!(hits.iter().any(|hit| {
                hit.bucket_id == bucket_id
                    && hit.details.get("obligation_id").and_then(|v| v.as_str())
                        == Some(obligation_id)
                    && hit.details.get("cell_id").and_then(|v| v.as_str()) == Some(cell_id)
                    && hit.details.get("trace_source").and_then(|v| v.as_str()) == Some("chip_row")
                    && hit.details.contains_key("row_op_idx")
                    && hit.details.contains_key("rs1_val")
                    && hit.details.contains_key("rs2_val")
            }));
        }
    }

    #[test]
    fn jalr_chip_rows_emit_pre_mask_target_cf3_cells() {
        let decoded = vec![
            (
                0,
                RV32IMInstruction::from_parts("jalr", Some(1), Some(2), None, Some(2))
                    .expect("encode jalr wrap test word"),
            ),
            (
                1,
                RV32IMInstruction::from_parts("jalr", Some(1), Some(2), None, Some(2))
                    .expect("encode jalr even test word"),
            ),
        ];
        let rows = vec![
            OpenVMChipRowEnvelope {
                base: row_base(0, OpenVMChipRowKind::Jalr),
                kind: OpenVMChipRowKind::Jalr,
                payload: OpenVMChipRowPayload::Jalr {
                    op: 0,
                    rd_ptr: 1,
                    rs1_ptr: 2,
                    imm: 2,
                    imm_sign: false,
                    needs_write: true,
                    from_pc: 0,
                    to_pc: 0,
                    rs1_val: 0xffff_ffff,
                    target_before_lsb_clear: Some(1),
                    rd_data: word_bytes(1),
                },
            },
            OpenVMChipRowEnvelope {
                base: row_base(1, OpenVMChipRowKind::Jalr),
                kind: OpenVMChipRowKind::Jalr,
                payload: OpenVMChipRowPayload::Jalr {
                    op: 0,
                    rd_ptr: 1,
                    rs1_ptr: 2,
                    imm: 2,
                    imm_sign: false,
                    needs_write: true,
                    from_pc: 1,
                    to_pc: 6,
                    rs1_val: 4,
                    target_before_lsb_clear: Some(6),
                    rd_data: word_bytes(2),
                },
            },
        ];
        let trace = OpenVMTrace::new(
            Vec::new(),
            rows,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut hits = Vec::new();
        trace.derive_chip_row_obligation_hits(&decoded, &mut hits);

        for cell_id in ["cf3.clear_lsb", "cf3.wrap", "cf3.even"] {
            assert!(hits.iter().any(|hit| {
                hit.bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id
                    && hit.details.get("obligation_id").and_then(|v| v.as_str()) == Some("cf3")
                    && hit.details.get("cell_id").and_then(|v| v.as_str()) == Some(cell_id)
                    && hit.details.get("trace_source").and_then(|v| v.as_str()) == Some("chip_row")
                    && hit.details.contains_key("rs1_val")
                    && hit.details.contains_key("target_before_lsb_clear")
            }));
        }
    }

    #[test]
    fn memory_access_hits_use_adapter_effective_ptr_not_core_placeholder() {
        let decoded = vec![(
            0,
            RV32IMInstruction::from_parts("lb", Some(3), Some(1), None, Some(1))
                .expect("encode lb test word"),
        )];
        let trace = OpenVMTrace::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![OpenVMMemoryAccess {
                seq: 1,
                step_idx: 0,
                op_idx: 0,
                pc: None,
                row_op_idx: 0,
                opcode: 0,
                rs1_ptr: 1,
                rd_rs2_ptr: 3,
                imm: 1,
                imm_sign: false,
                address_space: 2,
                raw_ptr: 0x1001,
                effective_ptr: 0x1001,
                aligned_ptr: 0x1000,
                byte_offset: 1,
                width: 1,
                is_load: true,
                is_store: false,
                needs_write: true,
                timestamp: 7,
                read_data: vec![0, 0x80, 0, 0],
                prev_data: vec![0, 0, 0, 0],
                write_data: vec![0, 0x80, 0, 0],
            }],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut hits = Vec::new();
        trace.derive_memory_access_obligation_hits(&decoded, &mut hits);

        assert!(hits.iter().any(|hit| {
            hit.bucket_id == semantic::memory::LOAD_VALUE_BINDING.id
                && hit.details.get("obligation_id").and_then(|v| v.as_str()) == Some("me3")
                && hit.details.get("cell_id").and_then(|v| v.as_str()) == Some("me3.lb_neg")
                && hit.details.get("effective_ptr").and_then(|v| v.as_u64()) == Some(0x1001)
                && hit.details.get("aligned_ptr").and_then(|v| v.as_u64()) == Some(0x1000)
        }));
        assert!(hits.iter().any(|hit| {
            hit.bucket_id == semantic::memory::ADDRESS_SPACE_CONSISTENCY.id
                && hit.details.get("cell_id").and_then(|v| v.as_str()) == Some("me5.mem_read")
        }));
        assert!(hits.iter().any(|hit| {
            hit.bucket_id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id
                && hit.details.get("cell_id").and_then(|v| v.as_str()) == Some("me9.off1")
        }));
        assert!(hits.iter().any(|hit| {
            hit.bucket_id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id
                && hit.details.get("cell_id").and_then(|v| v.as_str()) == Some("me10.load")
        }));
    }

    #[test]
    fn memory_history_and_timestamp_hits_use_adapter_access_sequence() {
        let decoded = vec![
            (
                0,
                RV32IMInstruction::from_parts("sw", None, Some(1), Some(2), Some(0))
                    .expect("encode sw test word"),
            ),
            (
                1,
                RV32IMInstruction::from_parts("lw", Some(3), Some(1), None, Some(0))
                    .expect("encode lw test word"),
            ),
        ];
        let trace = OpenVMTrace::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![
                OpenVMMemoryAccess {
                    seq: 1,
                    step_idx: 0,
                    op_idx: 0,
                    pc: None,
                    row_op_idx: 0,
                    opcode: 0,
                    rs1_ptr: 1,
                    rd_rs2_ptr: 2,
                    imm: 0,
                    imm_sign: false,
                    address_space: 2,
                    raw_ptr: 0x2000,
                    effective_ptr: 0x2000,
                    aligned_ptr: 0x2000,
                    byte_offset: 0,
                    width: 4,
                    is_load: false,
                    is_store: true,
                    needs_write: false,
                    timestamp: 10,
                    read_data: vec![0x44, 0x33, 0x22, 0x11],
                    prev_data: vec![0, 0, 0, 0],
                    write_data: vec![0x44, 0x33, 0x22, 0x11],
                },
                OpenVMMemoryAccess {
                    seq: 2,
                    step_idx: 1,
                    op_idx: 0,
                    pc: None,
                    row_op_idx: 0,
                    opcode: 0,
                    rs1_ptr: 1,
                    rd_rs2_ptr: 3,
                    imm: 0,
                    imm_sign: false,
                    address_space: 2,
                    raw_ptr: 0x2000,
                    effective_ptr: 0x2000,
                    aligned_ptr: 0x2000,
                    byte_offset: 0,
                    width: 4,
                    is_load: true,
                    is_store: false,
                    needs_write: true,
                    timestamp: 11,
                    read_data: vec![0x44, 0x33, 0x22, 0x11],
                    prev_data: vec![0x44, 0x33, 0x22, 0x11],
                    write_data: vec![0x44, 0x33, 0x22, 0x11],
                },
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut hits = Vec::new();
        trace.derive_memory_access_obligation_hits(&decoded, &mut hits);
        trace.derive_timestamp_memory_order_hits(&decoded, &mut hits);

        assert!(hits.iter().any(|hit| {
            hit.bucket_id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id
                && hit.details.get("cell_id").and_then(|v| v.as_str()) == Some("me1.sw_lw")
                && hit.details.get("store_step_idx").and_then(|v| v.as_u64()) == Some(0)
        }));
        assert!(hits.iter().any(|hit| {
            hit.bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id
                && hit.details.get("cell_id").and_then(|v| v.as_str()) == Some("ts2.consecutive")
                && hit.details.get("ts_diff").and_then(|v| v.as_u64()) == Some(1)
        }));
    }

    #[test]
    fn lookup_multiplicity_rows_emit_bu1_cells() {
        let trace = OpenVMTrace::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![OpenVMLookupMultiplicity {
                seq: 7,
                step_idx: 42,
                table_name: "bitwise_op_lookup.xor".to_string(),
                row_idx: 42,
                multiplicity: 2,
                is_real: true,
            }],
        );
        let mut hits = Vec::new();
        trace.derive_lookup_multiplicity_obligation_hits(&mut hits);

        assert!(hits.iter().any(|hit| {
            hit.bucket_id == semantic::lookup::BOOLEAN_MULTIPLICITY.id
                && hit.details.get("obligation_id").and_then(|v| v.as_str()) == Some("bu1")
                && hit.details.get("cell_id").and_then(|v| v.as_str()) == Some("bu1.multi_send")
                && hit.details.get("table_name").and_then(|v| v.as_str())
                    == Some("bitwise_op_lookup.xor")
                && hit.details.get("multiplicity").and_then(|v| v.as_u64()) == Some(2)
        }));
    }
}
