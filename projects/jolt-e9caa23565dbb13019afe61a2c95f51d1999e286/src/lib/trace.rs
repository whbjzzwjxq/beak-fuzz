use std::collections::{HashMap, HashSet};

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, Trace};
use common::constants::{RAM_START_ADDRESS, REGISTER_COUNT};
use common::rv_trace::{JoltDevice, MemoryLayout, MemoryOp, MemoryState, RVTraceRow, RV32IM};
use jolt::jolt_core::jolt::vm::JoltTraceStep;
use jolt::RV32I;
use serde_json::{json, Value};

const BACKEND: &str = "jolt";
const COMMIT: &str = "e9caa23565dbb13019afe61a2c95f51d1999e286";
const RAM_OP_INDEX: usize = 3;

pub struct JoltTrace {
    bucket_hits: Vec<BucketHit>,
    instruction_count: usize,
}

fn user_word_for_row(words: &[u32], row: &RVTraceRow) -> Option<u32> {
    let pc = row.instruction.address;
    if pc < RAM_START_ADDRESS || (pc - RAM_START_ADDRESS) % 4 != 0 {
        return None;
    }
    words.get(((pc - RAM_START_ADDRESS) / 4) as usize).copied()
}

fn jolt_mnemonic(opcode: RV32IM) -> String {
    format!("{opcode:?}").to_ascii_lowercase()
}

fn push_row_hit(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    row: &RVTraceRow,
    op_idx: u64,
    raw_word: u32,
    decoded: &RV32IMInstruction,
    obligation_id: &str,
    cell_id: &str,
) {
    push_row_hit_extra(hits, bucket, row, op_idx, raw_word, decoded, obligation_id, cell_id, &[]);
}

fn push_row_hit_extra(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    row: &RVTraceRow,
    op_idx: u64,
    raw_word: u32,
    decoded: &RV32IMInstruction,
    obligation_id: &str,
    cell_id: &str,
    extras: &[(&str, Value)],
) {
    let mut details = HashMap::from([
        ("obligation_id".to_string(), json!(obligation_id)),
        ("cell_id".to_string(), json!(cell_id)),
        ("op_idx".to_string(), json!(op_idx)),
        ("step_idx".to_string(), json!(op_idx)),
        ("pc".to_string(), json!(row.instruction.address)),
        ("opcode".to_string(), json!(format!("0x{raw_word:08x}"))),
        ("mnemonic".to_string(), json!(decoded.mnemonic)),
        ("backend".to_string(), json!(BACKEND)),
        ("commit".to_string(), json!(COMMIT)),
        ("trace_source".to_string(), json!("instruction")),
        ("jolt_opcode".to_string(), json!(jolt_mnemonic(row.instruction.opcode))),
    ]);
    if let Some(rd) = row.instruction.rd {
        details.insert("rd".to_string(), json!(rd));
    }
    if let Some(rs1) = row.instruction.rs1 {
        details.insert("rs1".to_string(), json!(rs1));
    }
    if let Some(rs2) = row.instruction.rs2 {
        details.insert("rs2".to_string(), json!(rs2));
    }
    if let Some(rd_val) = row.register_state.rd_post_val {
        details.insert("rd_val".to_string(), json!(rd_val));
    }
    if let Some(imm) = row.instruction.imm {
        details.insert("imm".to_string(), json!(imm));
    }
    if let Some(rs1_val) = row.register_state.rs1_val {
        details.insert("rs1_val".to_string(), json!(rs1_val));
    }
    if let Some(rs2_val) = row.register_state.rs2_val {
        details.insert("rs2_val".to_string(), json!(rs2_val));
    }
    if let Some(width) = memory_width(decoded.mnemonic.as_str()) {
        details.insert("width".to_string(), json!(width));
    }
    if let Some(memory) = row.memory_state.as_ref() {
        match memory {
            MemoryState::Read { address, value } => {
                details.insert("raw_ptr".to_string(), json!(address));
                details.insert("effective_ptr".to_string(), json!(address));
                details.insert("aligned_ptr".to_string(), json!(address & !3));
                details.insert("byte_offset".to_string(), json!(address & 3));
                details.insert("read_data".to_string(), json!(value));
                details.insert("is_load".to_string(), json!(true));
                details.insert("is_store".to_string(), json!(false));
            }
            MemoryState::Write { address, pre_value, post_value } => {
                details.insert("raw_ptr".to_string(), json!(address));
                details.insert("effective_ptr".to_string(), json!(address));
                details.insert("aligned_ptr".to_string(), json!(address & !3));
                details.insert("byte_offset".to_string(), json!(address & 3));
                details.insert("prev_data".to_string(), json!(pre_value));
                details.insert("write_data".to_string(), json!(post_value));
                details.insert("is_load".to_string(), json!(false));
                details.insert("is_store".to_string(), json!(true));
            }
        }
        details.insert("address_space".to_string(), json!("ram"));
    }
    for (key, value) in extras {
        details.insert((*key).to_string(), value.clone());
    }
    hits.push(BucketHit::semantic(bucket, details));
}

fn push_table_hit_extra(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    obligation_id: &str,
    cell_id: &str,
    trace_source: &str,
    step_idx: u64,
    extras: &[(&str, Value)],
) {
    let mut details = HashMap::from([
        ("obligation_id".to_string(), json!(obligation_id)),
        ("cell_id".to_string(), json!(cell_id)),
        ("op_idx".to_string(), json!(step_idx)),
        ("step_idx".to_string(), json!(step_idx)),
        ("backend".to_string(), json!(BACKEND)),
        ("commit".to_string(), json!(COMMIT)),
        ("trace_source".to_string(), json!(trace_source)),
    ]);
    for (key, value) in extras {
        details.insert((*key).to_string(), value.clone());
    }
    hits.push(BucketHit::semantic(bucket, details));
}

fn upper_immediate_cell(row: &RVTraceRow, decoded: &RV32IMInstruction) -> Option<&'static str> {
    let upper = decoded.word >> 12;
    match decoded.mnemonic.as_str() {
        "lui" if upper == 0 => Some("id3.lui_zero"),
        "lui" if upper == 0x000f_ffff => Some("id3.lui_max"),
        "lui" => Some("id3.lui_mid"),
        "auipc" => {
            let addend = (upper << 12) as u64;
            if row.instruction.address.saturating_add(addend) > u32::MAX as u64 {
                Some("id3.auipc_wrap")
            } else {
                Some("id3.auipc_no_wrap")
            }
        }
        _ => None,
    }
}

fn branch_cell(row: &RVTraceRow, decoded: &RV32IMInstruction) -> Option<&'static str> {
    let rs1 = row.register_state.rs1_val? as u32;
    let rs2 = row.register_state.rs2_val? as u32;
    match decoded.mnemonic.as_str() {
        "beq" if rs1 == rs2 => Some("cf1.beq_equal"),
        "bne" if rs1 != rs2 => Some("cf1.bne_not_equal"),
        "blt" if (rs1 as i32) < (rs2 as i32) => Some("cf1.blt_taken"),
        "blt" => Some("cf1.blt_not_taken"),
        "bge" if (rs1 as i32) >= (rs2 as i32) => Some("cf1.bge_taken"),
        "bge" => Some("cf1.bge_not_taken"),
        "bltu" if rs1 < rs2 => Some("cf1.bltu_taken"),
        "bltu" => Some("cf1.bltu_not_taken"),
        "bgeu" if rs1 >= rs2 => Some("cf1.bgeu_taken"),
        "bgeu" => Some("cf1.bgeu_not_taken"),
        _ => None,
    }
}

fn mnemonic_class(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        "add" | "sub" | "sll" | "slt" | "sltu" | "xor" | "srl" | "sra" | "or" | "and" => {
            Some("alu_r")
        }
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai" => {
            Some("alu_i")
        }
        "lb" | "lh" | "lw" | "lbu" | "lhu" => Some("load"),
        "sb" | "sh" | "sw" => Some("store"),
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => Some("branch"),
        "jal" => Some("jal"),
        "jalr" => Some("jalr"),
        "lui" => Some("lui"),
        "auipc" => Some("auipc"),
        "ecall" => Some("ecall"),
        "mul" | "mulh" | "mulhu" | "mulhsu" => Some("mul"),
        "div" | "divu" | "rem" | "remu" => Some("div"),
        _ => None,
    }
}

fn memory_width(mnemonic: &str) -> Option<u64> {
    match mnemonic {
        "lb" | "lbu" | "sb" => Some(1),
        "lh" | "lhu" | "sh" => Some(2),
        "lw" | "sw" => Some(4),
        _ => None,
    }
}

fn is_load(mnemonic: &str) -> bool {
    matches!(mnemonic, "lb" | "lh" | "lw" | "lbu" | "lhu")
}

fn is_store(mnemonic: &str) -> bool {
    matches!(mnemonic, "sb" | "sh" | "sw")
}

fn write_source_cell(mnemonic: &str) -> Option<&'static str> {
    match mnemonic_class(mnemonic)? {
        "alu_r" => Some("rf1.alu_r"),
        "alu_i" => Some("rf1.alu_i"),
        "load" => Some("rf1.load"),
        "jal" => Some("rf1.jal"),
        "jalr" => Some("rf1.jalr"),
        "lui" => Some("rf1.lui"),
        "auipc" => Some("rf1.auipc"),
        "mul" => Some("rf1.mul"),
        "div" => Some("rf1.div"),
        _ => None,
    }
}

fn dest_binding_cell(mnemonic: &str) -> Option<&'static str> {
    match mnemonic_class(mnemonic)? {
        "alu_r" | "alu_i" => Some("rf3.alu"),
        "load" => Some("rf3.load"),
        "jal" | "jalr" => Some("rf3.link"),
        "lui" | "auipc" => Some("rf3.upper"),
        "mul" | "div" => Some("rf3.muldiv"),
        _ => None,
    }
}

fn rf2_cell(decoded: &RV32IMInstruction) -> Option<&'static str> {
    let (rs1, rs2, rd) = (decoded.rs1, decoded.rs2, decoded.rd);
    if rs1.is_none() && rs2.is_none() {
        return None;
    }
    Some(match (rs1, rs2, rd) {
        (Some(a), Some(b), Some(c)) if a == b && b == c => "rf2.all_same",
        (Some(a), Some(b), _) if a == b => "rf2.rs1_eq_rs2",
        (Some(a), _, Some(c)) if a == c => "rf2.rs1_eq_rd",
        (_, Some(b), Some(c)) if b == c => "rf2.rs2_eq_rd",
        (Some(0), _, _) => "rf2.rs1_x0",
        (_, Some(0), _) => "rf2.rs2_x0",
        _ => "rf2.no_alias",
    })
}

fn id1_cell(decoded: &RV32IMInstruction) -> &'static str {
    let funct3 = (decoded.word >> 12) & 0x7;
    let funct7 = (decoded.word >> 25) & 0x7f;
    if [decoded.rd, decoded.rs1, decoded.rs2].into_iter().flatten().any(|r| r == 31) {
        "id1.reg_max"
    } else if [decoded.rd, decoded.rs1, decoded.rs2].into_iter().flatten().any(|r| r == 0) {
        "id1.reg_zero"
    } else if funct3 == 7 || funct7 == 127 {
        "id1.funct_max"
    } else {
        "id1.reg_mid"
    }
}

fn id2_cell(decoded: &RV32IMInstruction) -> Option<&'static str> {
    let imm = decoded.imm?;
    match decoded.mnemonic.as_str() {
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai" | "lb"
        | "lh" | "lw" | "lbu" | "lhu" | "jalr" => {
            Some(if imm < 0 { "id2.i_neg" } else { "id2.i_pos" })
        }
        "sb" | "sh" | "sw" => Some(if imm < 0 { "id2.s_neg" } else { "id2.s_pos" }),
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
            Some(if imm < 0 { "id2.b_neg" } else { "id2.b_pos" })
        }
        "jal" => Some(if imm < 0 { "id2.j_neg" } else { "id2.j_pos" }),
        _ => None,
    }
}

fn id5_cell(decoded: &RV32IMInstruction) -> Option<&'static str> {
    let imm = decoded.imm?;
    match decoded.mnemonic.as_str() {
        "sb" | "sh" | "sw" => Some(if imm.abs() > 0x7f { "id5.cross_field" } else { "id5.s_type" }),
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
            Some(if imm.abs() > 0x7f { "id5.cross_field" } else { "id5.b_type" })
        }
        "jal" => Some(if imm.abs() > 0x7ff { "id5.cross_field" } else { "id5.j_type" }),
        _ => None,
    }
}

fn al1_cell(decoded: &RV32IMInstruction) -> Option<&'static str> {
    let imm = decoded.imm?;
    Some(if matches!(imm, 255 | 256 | -1 | -2048 | 2047) {
        "al1.boundary"
    } else if imm < 0 {
        "al1.negative"
    } else if imm <= 255 {
        "al1.single_limb"
    } else {
        "al1.cross_01"
    })
}

fn rhs_value(row: &RVTraceRow, decoded: &RV32IMInstruction) -> Option<u32> {
    decoded
        .rs2
        .and(row.register_state.rs2_val.map(|v| v as u32))
        .or_else(|| decoded.imm.map(|imm| imm as u32))
}

fn al2_cell(row: &RVTraceRow, decoded: &RV32IMInstruction) -> &'static str {
    let raw_shamt = rhs_value(row, decoded).unwrap_or(0);
    let ge32 = raw_shamt >= 32;
    let shamt = raw_shamt & 0x1f;
    match decoded.mnemonic.as_str() {
        "sll" | "slli" if shamt == 0 => "al2.shamt_zero",
        "sll" | "slli" if ge32 => "al2.sll_ge32",
        "sll" | "slli" => "al2.sll_lt32",
        "srl" | "srli" if shamt == 0 => "al2.shamt_zero",
        "srl" | "srli" if ge32 => "al2.srl_ge32",
        "srl" | "srli" => "al2.srl_lt32",
        "sra" | "srai" if shamt == 0 => "al2.shamt_zero",
        "sra" | "srai" => {
            let neg = row.register_state.rs1_val.map(|v| (v as u32 as i32) < 0).unwrap_or(false);
            match (ge32, neg) {
                (true, true) => "al2.sra_ge32_neg",
                (true, false) => "al2.sra_ge32_pos",
                (false, true) => "al2.sra_lt32_neg",
                (false, false) => "al2.sra_lt32_pos",
            }
        }
        _ => "al2.shamt_zero",
    }
}

fn al3_cell(row: &RVTraceRow, decoded: &RV32IMInstruction) -> Option<&'static str> {
    let lhs = row.register_state.rs1_val? as u32;
    let rhs = rhs_value(row, decoded)?;
    let signed_lt = (lhs as i32) < (rhs as i32);
    let unsigned_lt = lhs < rhs;
    Some(if lhs == rhs {
        "al3.equal"
    } else if signed_lt != unsigned_lt {
        "al3.sign_disagree"
    } else if matches!(decoded.mnemonic.as_str(), "sltu" | "sltiu") {
        if unsigned_lt {
            "al3.sltu_true"
        } else {
            "al3.sltu_false"
        }
    } else if signed_lt {
        "al3.slt_true"
    } else {
        "al3.slt_false"
    })
}

fn al4_cell(row: &RVTraceRow, decoded: &RV32IMInstruction) -> Option<&'static str> {
    let lhs = row.register_state.rs1_val? as u32;
    let rhs = rhs_value(row, decoded)?;
    Some(if lhs == rhs {
        "al4.equal"
    } else if lhs < rhs {
        "al4.borrow"
    } else if (lhs & 0xff) < (rhs & 0xff) {
        "al4.cross_limb"
    } else {
        "al4.no_borrow"
    })
}

fn al5_cell(row: &RVTraceRow, decoded: &RV32IMInstruction) -> Option<&'static str> {
    let lhs = row.register_state.rs1_val? as u32;
    let rhs = rhs_value(row, decoded)?;
    Some(if lhs == rhs {
        "al5.all_equal"
    } else if (lhs >> 24) != (rhs >> 24) {
        "al5.first_limb_diff"
    } else if (lhs & 0xff) != (rhs & 0xff) {
        "al5.last_limb_diff"
    } else {
        "al5.alternating_borrow"
    })
}

fn div_special_cell(
    row: &RVTraceRow,
    decoded: &RV32IMInstruction,
) -> Option<(&'static str, &'static str)> {
    let dividend = row.register_state.rs1_val? as u32;
    let divisor = row.register_state.rs2_val? as u32;
    if divisor == 0 {
        let cell = match decoded.mnemonic.as_str() {
            "div" => "md1.div_zero",
            "divu" => "md1.divu_zero",
            "rem" => "md1.rem_zero",
            "remu" => "md1.remu_zero",
            _ => return None,
        };
        return Some(("md1", cell));
    }
    if dividend == 0x8000_0000 && divisor == 0xffff_ffff {
        let cell = match decoded.mnemonic.as_str() {
            "div" => "md2.div_overflow",
            "rem" => "md2.rem_overflow",
            _ => return None,
        };
        return Some(("md2", cell));
    }
    None
}

fn md3_cell(row: &RVTraceRow, decoded: &RV32IMInstruction) -> Option<&'static str> {
    let lhs = row.register_state.rs1_val? as u32;
    let rhs = row.register_state.rs2_val? as u32;
    Some(if matches!(decoded.mnemonic.as_str(), "divu" | "remu") {
        "md3.unsigned"
    } else if rhs == 1 || rhs == 0xffff_ffff {
        "md3.one"
    } else if rhs != 0 && lhs % rhs == 0 {
        "md3.exact"
    } else if (lhs as i32) < 0 && (rhs as i32) < 0 {
        "md3.nn"
    } else if (lhs as i32) < 0 {
        "md3.np"
    } else if (rhs as i32) < 0 {
        "md3.pn"
    } else {
        "md3.pp"
    })
}

fn md4_cell(row: &RVTraceRow, decoded: &RV32IMInstruction) -> Option<&'static str> {
    let lhs = row.register_state.rs1_val? as u32;
    let rhs = row.register_state.rs2_val? as u32;
    Some(match decoded.mnemonic.as_str() {
        "mul" if lhs == 0 || rhs == 0 => "md4.zero_op",
        "mul" if (lhs as u64) * (rhs as u64) > u32::MAX as u64 => "md4.mul_overflow",
        "mul" => "md4.mul_small",
        "mulhu" => "md4.mulhu",
        "mulhsu" => "md4.mulh_pn",
        "mulh" if (lhs as i32) < 0 && (rhs as i32) < 0 => "md4.mulh_nn",
        "mulh" if (lhs as i32) < 0 || (rhs as i32) < 0 => "md4.mulh_pn",
        "mulh" => "md4.mulh_pp",
        _ => return None,
    })
}

fn md5_cell(row: &RVTraceRow) -> Option<&'static str> {
    let lhs = row.register_state.rs1_val? as u32;
    Some(if lhs == 0xffff_ffff {
        "md5.neg_one"
    } else if lhs == 0x8000_0000 {
        "md5.neg_max"
    } else if (lhs as i32) < 0 && lhs < 0xffff_0000 {
        "md5.neg_large"
    } else if (lhs as i32) < 0 {
        "md5.neg_small"
    } else {
        "md5.pos_any"
    })
}

fn branch_taken(row: &RVTraceRow, decoded: &RV32IMInstruction) -> Option<bool> {
    let rs1 = row.register_state.rs1_val? as u32;
    let rs2 = row.register_state.rs2_val? as u32;
    match decoded.mnemonic.as_str() {
        "beq" => Some(rs1 == rs2),
        "bne" => Some(rs1 != rs2),
        "blt" => Some((rs1 as i32) < (rs2 as i32)),
        "bge" => Some((rs1 as i32) >= (rs2 as i32)),
        "bltu" => Some(rs1 < rs2),
        "bgeu" => Some(rs1 >= rs2),
        _ => None,
    }
}

fn cf3_cell(decoded: &RV32IMInstruction) -> Option<&'static str> {
    Some(match decoded.imm?.cmp(&0) {
        std::cmp::Ordering::Less => "cf3.imm_neg",
        std::cmp::Ordering::Equal => "cf3.imm_zero",
        std::cmp::Ordering::Greater => "cf3.imm_pos",
    })
}

fn me2_cell(address: u64, width: u64) -> &'static str {
    match width {
        2 if address % 2 == 1 => "me2.half_off1",
        4 => match address % 4 {
            1 => "me2.word_off1",
            2 => "me2.word_off2",
            3 => "me2.word_off3",
            _ => "me2.byte_any",
        },
        _ => "me2.byte_any",
    }
}

fn me9_cell(address: u64) -> &'static str {
    match address & 3 {
        0 => "me9.off0",
        1 => "me9.off1",
        2 => "me9.off2",
        _ => "me9.off3",
    }
}

fn memory_state_address(memory: &MemoryState) -> u64 {
    match memory {
        MemoryState::Read { address, .. } | MemoryState::Write { address, .. } => *address,
    }
}

fn witness_index_for_address(address: u64, layout: &MemoryLayout) -> Option<u64> {
    if address >= layout.input_start {
        Some(REGISTER_COUNT + (address - layout.input_start) / 4)
    } else if address < REGISTER_COUNT {
        Some(address)
    } else {
        None
    }
}

fn ram_op_address(op: MemoryOp) -> u64 {
    match op {
        MemoryOp::Read(address) | MemoryOp::Write(address, _) => address,
    }
}

fn padded_trace_len(len: usize) -> usize {
    len.max(1).next_power_of_two()
}

fn me6_cell(address: u64, width: u64, layout: &MemoryLayout) -> Option<&'static str> {
    let end = address.checked_add(width.saturating_sub(1))?;
    if end > u32::MAX as u64 || address > u32::MAX as u64 - width.saturating_sub(1) {
        return Some("me6.near_max");
    }
    let boundaries = [
        layout.stack_end,
        layout.input_start,
        layout.input_end,
        layout.output_start,
        layout.output_end,
        RAM_START_ADDRESS,
        layout.memory_end,
    ];
    boundaries
        .into_iter()
        .any(|boundary| address <= boundary && end >= boundary.saturating_sub(1))
        .then_some("me6.heap_boundary")
}

fn build_initial_words(memory_init: &[(u64, u8)], io_device: &JoltDevice) -> HashMap<u64, u32> {
    let mut bytes = HashMap::<u64, [u8; 4]>::new();
    for (address, value) in memory_init {
        let aligned = *address & !3;
        bytes.entry(aligned).or_default()[(*address & 3) as usize] = *value;
    }
    for (offset, chunk) in io_device.inputs.chunks(4).enumerate() {
        let mut word = [0u8; 4];
        for (idx, byte) in chunk.iter().enumerate() {
            word[idx] = *byte;
        }
        bytes.insert(io_device.memory_layout.input_start + (offset as u64 * 4), word);
    }
    bytes.into_iter().map(|(address, bytes)| (address, u32::from_le_bytes(bytes))).collect()
}

fn memory_witness_size(
    trace: &[JoltTraceStep<RV32I>],
    memory_init: &[(u64, u8)],
    io_device: &JoltDevice,
) -> usize {
    let layout = &io_device.memory_layout;
    let max_trace = trace
        .iter()
        .filter_map(|step| {
            witness_index_for_address(ram_op_address(step.memory_ops[RAM_OP_INDEX]), layout)
        })
        .max()
        .unwrap_or(0);
    let max_init = build_initial_words(memory_init, io_device)
        .keys()
        .filter_map(|address| witness_index_for_address(*address, layout))
        .max()
        .unwrap_or(0);
    max_trace.max(max_init).saturating_add(1).max(8).next_power_of_two() as usize
}

fn emit_initialization_hits(
    hits: &mut Vec<BucketHit>,
    memory_init: &[(u64, u8)],
    io_device: &JoltDevice,
) {
    let layout = &io_device.memory_layout;
    let initial_words = build_initial_words(memory_init, io_device);
    if let Some((address, value, witness_index)) =
        initial_words.iter().find_map(|(address, value)| {
            witness_index_for_address(*address, layout).map(|idx| (*address, *value, idx))
        })
    {
        push_table_hit_extra(
            hits,
            semantic::memory::INITIAL_VALUE_BINDING,
            "me7",
            "me7.data_loaded",
            "read_write_memory.initialization",
            witness_index,
            &[
                ("address", json!(address)),
                ("witness_index", json!(witness_index)),
                ("initial_value", json!(value)),
                ("source_kind", json!("memory_init")),
            ],
        );
    }

    let mut seen = HashSet::<u64>::new();
    let duplicate =
        memory_init.iter().map(|(address, _)| *address).find(|address| !seen.insert(*address));
    if let Some(address) = duplicate {
        let witness_index = witness_index_for_address(address & !3, layout).unwrap_or(0);
        push_table_hit_extra(
            hits,
            semantic::memory::INITIAL_VALUE_BINDING,
            "me8",
            "me8.double_init",
            "read_write_memory.initialization",
            witness_index,
            &[
                ("address", json!(address)),
                ("witness_index", json!(witness_index)),
                ("conflict_kind", json!("duplicate_byte")),
            ],
        );
    } else if let Some((address, _)) = memory_init.first() {
        let witness_index = witness_index_for_address(*address & !3, layout).unwrap_or(0);
        push_table_hit_extra(
            hits,
            semantic::memory::INITIAL_VALUE_BINDING,
            "me8",
            "me8.no_conflict",
            "read_write_memory.initialization",
            witness_index,
            &[
                ("address", json!(address)),
                ("witness_index", json!(witness_index)),
                ("initialized_bytes", json!(memory_init.len())),
                ("conflict_kind", json!("none")),
            ],
        );
    }
}

fn emit_finalization_hits(
    hits: &mut Vec<BucketHit>,
    trace: &[JoltTraceStep<RV32I>],
    memory_init: &[(u64, u8)],
    io_device: &JoltDevice,
) {
    let layout = &io_device.memory_layout;
    let memory_size = memory_witness_size(trace, memory_init, io_device);
    let mut v_init = vec![0u32; memory_size];
    for (address, value) in build_initial_words(memory_init, io_device) {
        if let Some(idx) = witness_index_for_address(address, layout) {
            if let Some(slot) = v_init.get_mut(idx as usize) {
                *slot = value;
            }
        }
    }

    let mut v_final = v_init.clone();
    let mut t_final = vec![0u64; memory_size];
    let mut read_cells = HashSet::<usize>::new();
    let mut written_cells = HashSet::<usize>::new();
    let padded_len = padded_trace_len(trace.len());
    for idx in 0..padded_len {
        let op =
            trace.get(idx).map(|step| step.memory_ops[RAM_OP_INDEX]).unwrap_or(MemoryOp::Read(0));
        let Some(witness_index) = witness_index_for_address(ram_op_address(op), layout) else {
            continue;
        };
        let witness_index = witness_index as usize;
        if witness_index >= memory_size {
            continue;
        }
        match op {
            MemoryOp::Read(address) => {
                t_final[witness_index] = idx as u64;
                if idx < trace.len() && address >= layout.input_start {
                    read_cells.insert(witness_index);
                }
            }
            MemoryOp::Write(address, value) => {
                v_final[witness_index] = value as u32;
                t_final[witness_index] = idx as u64;
                if idx < trace.len() && address >= layout.input_start {
                    written_cells.insert(witness_index);
                }
            }
        }
    }

    if let Some(idx) = written_cells
        .iter()
        .copied()
        .find(|idx| v_final[*idx] != v_init[*idx])
        .or_else(|| written_cells.iter().copied().next())
    {
        push_table_hit_extra(
            hits,
            semantic::memory::FINALIZATION_CONSISTENCY,
            "me11",
            "me11.written_cells",
            "read_write_memory.finalization",
            idx as u64,
            &[
                ("witness_index", json!(idx)),
                ("initial_value", json!(v_init[idx])),
                ("final_value", json!(v_final[idx])),
                ("timestamp", json!(t_final[idx])),
                ("cell_role", json!("written")),
            ],
        );
    }

    if let Some(idx) = read_cells
        .iter()
        .copied()
        .find(|idx| !written_cells.contains(idx) && v_final[*idx] == v_init[*idx])
    {
        push_table_hit_extra(
            hits,
            semantic::memory::FINALIZATION_CONSISTENCY,
            "me11",
            "me11.read_only_cells",
            "read_write_memory.finalization",
            idx as u64,
            &[
                ("witness_index", json!(idx)),
                ("initial_value", json!(v_init[idx])),
                ("final_value", json!(v_final[idx])),
                ("timestamp", json!(t_final[idx])),
                ("cell_role", json!("read_only")),
            ],
        );
    }

    let preferred_untouched = witness_index_for_address(RAM_START_ADDRESS, layout)
        .and_then(|idx| (idx as usize <= memory_size).then_some(idx as usize));
    if let Some(idx) = preferred_untouched
        .filter(|idx| *idx < memory_size && t_final[*idx] == 0)
        .or_else(|| (REGISTER_COUNT as usize..memory_size).find(|idx| t_final[*idx] == 0))
    {
        push_table_hit_extra(
            hits,
            semantic::memory::FINALIZATION_CONSISTENCY,
            "me11",
            "me11.untouched_cells",
            "read_write_memory.finalization",
            idx as u64,
            &[
                ("witness_index", json!(idx)),
                ("initial_value", json!(v_init[idx])),
                ("final_value", json!(v_final[idx])),
                ("timestamp", json!(t_final[idx])),
                ("cell_role", json!("untouched")),
            ],
        );
    }
}

fn emit_lookup_and_padding_hits(hits: &mut Vec<BucketHit>, trace: &[JoltTraceStep<RV32I>]) {
    if let Some((idx, step)) =
        trace.iter().enumerate().find(|(_, step)| step.instruction_lookup.is_some())
    {
        push_table_hit_extra(
            hits,
            semantic::lookup::BOOLEAN_MULTIPLICITY,
            "bu1",
            "bu1.real_row",
            "instruction_lookups",
            idx as u64,
            &[
                ("table_name", json!("instruction_lookups")),
                ("multiplicity", json!(1)),
                ("is_real", json!(true)),
                ("instruction_lookup", json!(format!("{:?}", step.instruction_lookup))),
            ],
        );
    }

    let padded_len = padded_trace_len(trace.len());
    if padded_len > trace.len() {
        let first_padding = trace.len() as u64;
        push_table_hit_extra(
            hits,
            semantic::lookup::BOOLEAN_MULTIPLICITY,
            "bu1",
            "bu1.padding_row",
            "instruction_lookups",
            first_padding,
            &[
                ("table_name", json!("instruction_lookups")),
                ("multiplicity", json!(0)),
                ("is_real", json!(false)),
                ("padded_len", json!(padded_len)),
            ],
        );
        for (cell_id, table_name) in [
            ("pd1.exec_padding", "jolt_trace"),
            ("pd1.mem_padding", "read_write_memory"),
            ("pd1.lookup_padding", "instruction_lookups"),
        ] {
            push_table_hit_extra(
                hits,
                semantic::row::PADDING_INTERACTION_SEND,
                "pd1",
                cell_id,
                table_name,
                first_padding,
                &[
                    ("table_name", json!(table_name)),
                    ("is_padding", json!(true)),
                    ("first_padding_step", json!(first_padding)),
                    ("unpadded_len", json!(trace.len())),
                    ("padded_len", json!(padded_len)),
                ],
            );
        }
    }
}

impl JoltTrace {
    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        Ok(Self { bucket_hits: Vec::new(), instruction_count: words.len() })
    }

    pub fn from_executed_rows(words: &[u32], rows: &[RVTraceRow]) -> Result<Self, String> {
        let layout = MemoryLayout::new(&common::rv_trace::MemoryConfig::default());
        Self::from_executed_rows_with_layout(words, rows, &layout)
    }

    fn from_executed_rows_with_layout(
        words: &[u32],
        rows: &[RVTraceRow],
        layout: &MemoryLayout,
    ) -> Result<Self, String> {
        let mut bucket_hits = Vec::new();
        let mut seen_pcs = HashSet::new();
        let mut executed = Vec::new();

        for (idx, row) in rows.iter().enumerate() {
            let Some(raw_word) = user_word_for_row(words, row) else {
                continue;
            };
            if !seen_pcs.insert(row.instruction.address) {
                continue;
            }
            let Some(decoded) =
                RV32IMInstruction::decode_with_pc(raw_word, row.instruction.address as u32)
            else {
                continue;
            };
            executed.push((idx, row, raw_word, decoded));
        }

        let mut last_store = HashMap::<(u64, u64), u64>::new();
        let mut last_access = HashMap::<(u64, u64), u64>::new();
        let mut first_load = HashSet::<(u64, u64)>::new();
        let mut prev_branch_not_taken = false;

        for (exec_idx, (idx, row, raw_word, decoded)) in executed.iter().enumerate() {
            let op_idx = *idx as u64;
            let mnemonic = decoded.mnemonic.as_str();

            for (slot, register_index) in [("rs1", decoded.rs1), ("rs2", decoded.rs2)] {
                if let Some(register_index) = register_index {
                    push_row_hit_extra(
                        &mut bucket_hits,
                        semantic::memory::ADDRESS_SPACE_CONSISTENCY,
                        row,
                        op_idx,
                        *raw_word,
                        decoded,
                        "me5",
                        "me5.reg_read",
                        &[
                            ("address_space", json!("register")),
                            ("memory_op_slot", json!(slot)),
                            ("register_index", json!(register_index)),
                            ("witness_index", json!(register_index)),
                            ("is_read", json!(true)),
                            ("is_write", json!(false)),
                        ],
                    );
                }
            }
            if let Some(register_index) = decoded.rd {
                push_row_hit_extra(
                    &mut bucket_hits,
                    semantic::memory::ADDRESS_SPACE_CONSISTENCY,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "me5",
                    "me5.reg_write",
                    &[
                        ("address_space", json!("register")),
                        ("memory_op_slot", json!("rd")),
                        ("register_index", json!(register_index)),
                        ("witness_index", json!(register_index)),
                        ("is_read", json!(false)),
                        ("is_write", json!(true)),
                    ],
                );
            }

            if exec_idx == 0 {
                push_row_hit(
                    &mut bucket_hits,
                    semantic::control::ENTRYPOINT_BINDING,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "cf4",
                    "cf4.default_entry",
                );
                push_row_hit(
                    &mut bucket_hits,
                    semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "ts1",
                    "ts1.standard",
                );
                push_row_hit(
                    &mut bucket_hits,
                    semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "ts3",
                    "ts3.standard",
                );
            }

            if let Some(cell_id) = write_source_cell(mnemonic).filter(|_| decoded.rd == Some(0)) {
                push_row_hit(
                    &mut bucket_hits,
                    semantic::decode::ZERO_REGISTER_IMMUTABILITY,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "rf1",
                    cell_id,
                );
            }

            if let Some(cell_id) = rf2_cell(decoded) {
                push_row_hit(
                    &mut bucket_hits,
                    semantic::decode::OPERAND_INDEX_ROUTING,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "rf2",
                    cell_id,
                );
            }

            if decoded.rd.is_some_and(|rd| rd != 0) {
                if let Some(cell_id) = dest_binding_cell(mnemonic) {
                    push_row_hit(
                        &mut bucket_hits,
                        semantic::exec::DEST_BINDING,
                        row,
                        op_idx,
                        *raw_word,
                        decoded,
                        "rf3",
                        cell_id,
                    );
                }
            }

            push_row_hit(
                &mut bucket_hits,
                semantic::decode::FIELD_RANGE,
                row,
                op_idx,
                *raw_word,
                decoded,
                "id1",
                id1_cell(decoded),
            );

            if let Some(cell_id) = id2_cell(decoded) {
                push_row_hit(
                    &mut bucket_hits,
                    semantic::decode::IMMEDIATE_SIGN_EXTENSION,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "id2",
                    cell_id,
                );
            }

            if let Some(cell_id) = id5_cell(decoded) {
                push_row_hit(
                    &mut bucket_hits,
                    semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "id5",
                    cell_id,
                );
            }

            if let Some(cell_id) = upper_immediate_cell(row, &decoded) {
                push_row_hit(
                    &mut bucket_hits,
                    semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "id3",
                    cell_id,
                );
            }

            if let Some(class) = mnemonic_class(mnemonic) {
                let cell_id = format!("id4.{class}");
                push_row_hit(
                    &mut bucket_hits,
                    semantic::exec::OP_SELECTOR_BINDING,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "id4",
                    &cell_id,
                );
            }

            if matches!(
                mnemonic,
                "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai"
            ) {
                if let Some(cell_id) = al1_cell(decoded) {
                    push_row_hit(
                        &mut bucket_hits,
                        semantic::alu::IMMEDIATE_LIMB_CONSISTENCY,
                        row,
                        op_idx,
                        *raw_word,
                        decoded,
                        "al1",
                        cell_id,
                    );
                }
            }

            if matches!(mnemonic, "sll" | "slli" | "srl" | "srli" | "sra" | "srai") {
                push_row_hit(
                    &mut bucket_hits,
                    semantic::alu::SHIFT_MOD32,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "al2",
                    al2_cell(row, decoded),
                );
            }

            if matches!(mnemonic, "slt" | "slti" | "sltu" | "sltiu") {
                if let Some(cell_id) = al3_cell(row, decoded) {
                    push_row_hit(
                        &mut bucket_hits,
                        semantic::alu::COMPARISON_BOOLEANITY,
                        row,
                        op_idx,
                        *raw_word,
                        decoded,
                        "al3",
                        cell_id,
                    );
                }
                if let Some(cell_id) = al5_cell(row, decoded) {
                    push_row_hit(
                        &mut bucket_hits,
                        semantic::alu::COMPARISON_AUXILIARY_CHAIN,
                        row,
                        op_idx,
                        *raw_word,
                        decoded,
                        "al5",
                        cell_id,
                    );
                }
            }

            if matches!(
                mnemonic,
                "sub"
                    | "slt"
                    | "slti"
                    | "sltu"
                    | "sltiu"
                    | "beq"
                    | "bne"
                    | "blt"
                    | "bge"
                    | "bltu"
                    | "bgeu"
            ) {
                if let Some(cell_id) = al4_cell(row, decoded) {
                    push_row_hit(
                        &mut bucket_hits,
                        semantic::alu::SUBTRACTION_BORROW_CHAIN,
                        row,
                        op_idx,
                        *raw_word,
                        decoded,
                        "al4",
                        cell_id,
                    );
                }
            }

            match mnemonic {
                "div" | "divu" | "rem" | "remu" => {
                    if let Some((obligation_id, cell_id)) = div_special_cell(row, decoded) {
                        push_row_hit(
                            &mut bucket_hits,
                            semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                            row,
                            op_idx,
                            *raw_word,
                            decoded,
                            obligation_id,
                            cell_id,
                        );
                    } else if let Some(cell_id) = md3_cell(row, decoded) {
                        push_row_hit(
                            &mut bucket_hits,
                            semantic::arithmetic::DIVISION_REMAINDER_BOUND,
                            row,
                            op_idx,
                            *raw_word,
                            decoded,
                            "md3",
                            cell_id,
                        );
                    }
                }
                "mul" | "mulh" | "mulhu" | "mulhsu" => {
                    if let Some(cell_id) = md4_cell(row, decoded) {
                        push_row_hit(
                            &mut bucket_hits,
                            semantic::arithmetic::PRODUCT_DECOMPOSITION,
                            row,
                            op_idx,
                            *raw_word,
                            decoded,
                            "md4",
                            cell_id,
                        );
                    }
                    if mnemonic == "mulhsu" {
                        if let Some(cell_id) = md5_cell(row) {
                            push_row_hit(
                                &mut bucket_hits,
                                semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION,
                                row,
                                op_idx,
                                *raw_word,
                                decoded,
                                "md5",
                                cell_id,
                            );
                        }
                    }
                }
                _ => {}
            }

            if (is_load(mnemonic) || is_store(mnemonic)) && memory_width(mnemonic).is_some() {
                let cell_id = if is_load(mnemonic) { "me10.load" } else { "me10.store" };
                push_row_hit(
                    &mut bucket_hits,
                    semantic::memory::KIND_SELECTOR_CONSISTENCY,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "me10",
                    cell_id,
                );
            }

            if let (Some(memory), Some(width)) = (row.memory_state.as_ref(), memory_width(mnemonic))
            {
                let address = memory_state_address(memory);
                let witness_index = witness_index_for_address(address, layout);
                let is_memory_read = matches!(memory, MemoryState::Read { .. });
                push_row_hit_extra(
                    &mut bucket_hits,
                    semantic::memory::ADDRESS_SPACE_CONSISTENCY,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "me5",
                    if is_memory_read { "me5.mem_read" } else { "me5.mem_write" },
                    &[
                        ("address_space", json!("main_memory")),
                        ("memory_op_slot", json!("ram")),
                        ("witness_index", json!(witness_index)),
                        ("width", json!(width)),
                        ("is_read", json!(is_memory_read)),
                        ("is_write", json!(!is_memory_read)),
                    ],
                );
                if let Some(cell_id) = me6_cell(address, width, layout) {
                    push_row_hit_extra(
                        &mut bucket_hits,
                        semantic::memory::ADDRESS_BOUNDARY_RANGE,
                        row,
                        op_idx,
                        *raw_word,
                        decoded,
                        "me6",
                        cell_id,
                        &[
                            ("address", json!(address)),
                            ("witness_index", json!(witness_index)),
                            ("width", json!(width)),
                            (
                                "boundary_kind",
                                json!(cell_id.strip_prefix("me6.").unwrap_or(cell_id)),
                            ),
                        ],
                    );
                }
                if let Some(prev_timestamp) = last_access.get(&(address, width)).copied() {
                    let ts_diff = op_idx.saturating_sub(prev_timestamp);
                    let cell_id = if ts_diff == 1 {
                        "ts2.consecutive"
                    } else if ts_diff <= 4 {
                        "ts2.small_gap"
                    } else {
                        "ts2.large_gap"
                    };
                    push_row_hit_extra(
                        &mut bucket_hits,
                        semantic::time::MONOTONIC_ACCESS_ORDERING,
                        row,
                        op_idx,
                        *raw_word,
                        decoded,
                        "ts2",
                        cell_id,
                        &[
                            ("address", json!(address)),
                            ("witness_index", json!(witness_index)),
                            ("prev_timestamp", json!(prev_timestamp)),
                            ("timestamp", json!(op_idx)),
                            ("ts_diff", json!(ts_diff)),
                            ("width", json!(width)),
                        ],
                    );
                }
                last_access.insert((address, width), op_idx);
                push_row_hit(
                    &mut bucket_hits,
                    semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "me2",
                    me2_cell(address, width),
                );
                if width < 4 {
                    push_row_hit(
                        &mut bucket_hits,
                        semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY,
                        row,
                        op_idx,
                        *raw_word,
                        decoded,
                        "me9",
                        me9_cell(address),
                    );
                }
                if is_store(mnemonic) && width < 4 {
                    let cell_id = match (mnemonic, address & 3) {
                        ("sb", 0) => "me4.sb_off0",
                        ("sb", 1) => "me4.sb_off1",
                        ("sb", 2) => "me4.sb_off2",
                        ("sb", _) => "me4.sb_off3",
                        ("sh", 0) => "me4.sh_off0",
                        ("sh", _) => "me4.sh_off2",
                        _ => "me4.sb_off0",
                    };
                    push_row_hit(
                        &mut bucket_hits,
                        semantic::memory::WRITE_PAYLOAD_CONSISTENCY,
                        row,
                        op_idx,
                        *raw_word,
                        decoded,
                        "me4",
                        cell_id,
                    );
                }
                if is_load(mnemonic) {
                    if !last_store.contains_key(&(address, width))
                        && first_load.insert((address, width))
                    {
                        if let MemoryState::Read { value, .. } = memory {
                            push_row_hit_extra(
                                &mut bucket_hits,
                                semantic::memory::INITIAL_VALUE_BINDING,
                                row,
                                op_idx,
                                *raw_word,
                                decoded,
                                "me7",
                                if *value == 0 { "me7.bss_zero" } else { "me7.data_loaded" },
                                &[
                                    ("address", json!(address)),
                                    ("witness_index", json!(witness_index)),
                                    ("initial_value", json!(value)),
                                    ("source_kind", json!("first_load_no_prior_write")),
                                ],
                            );
                        }
                    }
                    if let Some(store_step_idx) = last_store.get(&(address, width)) {
                        push_row_hit_extra(
                            &mut bucket_hits,
                            semantic::memory::STORE_LOAD_PAYLOAD_FLOW,
                            row,
                            op_idx,
                            *raw_word,
                            decoded,
                            "me1",
                            match (mnemonic, width) {
                                ("lw", 4) => "me1.sw_lw",
                                ("lh", 2) => "me1.sh_lh",
                                ("lb", 1) => "me1.sb_lb",
                                ("lhu", 2) => "me1.sw_lhu",
                                _ => "me1.overwrite",
                            },
                            &[("store_step_idx", json!(store_step_idx))],
                        );
                    }
                    if let MemoryState::Read { value, .. } = memory {
                        let cell_id = match mnemonic {
                            "lb" if (value & 0x80) == 0 => Some("me3.lb_pos"),
                            "lb" => Some("me3.lb_neg"),
                            "lh" if (value & 0x8000) == 0 => Some("me3.lh_pos"),
                            "lh" => Some("me3.lh_neg"),
                            "lbu" => Some("me3.lbu"),
                            "lhu" => Some("me3.lhu"),
                            _ => None,
                        };
                        if let Some(cell_id) = cell_id {
                            push_row_hit(
                                &mut bucket_hits,
                                semantic::memory::LOAD_VALUE_BINDING,
                                row,
                                op_idx,
                                *raw_word,
                                decoded,
                                "me3",
                                cell_id,
                            );
                        }
                    }
                } else if is_store(mnemonic) {
                    last_store.insert((address, width), op_idx);
                }
            }

            if let Some(cell_id) = branch_cell(row, &decoded) {
                let taken = branch_taken(row, decoded).unwrap_or(false);
                let target_pc = decoded
                    .imm
                    .map(|imm| (row.instruction.address as i64).wrapping_add(imm as i64) as u64);
                let next_pc = if taken {
                    target_pc.unwrap_or(row.instruction.address + 4)
                } else {
                    row.instruction.address + 4
                };
                push_row_hit_extra(
                    &mut bucket_hits,
                    semantic::exec::CONTROL_FLOW_BINDING,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "cf1",
                    cell_id,
                    &[
                        ("taken", json!(taken)),
                        ("next_pc", json!(next_pc)),
                        ("target_pc", json!(target_pc)),
                    ],
                );
                prev_branch_not_taken = !taken;
                continue;
            }

            if matches!(mnemonic, "jal" | "jalr") {
                let cell_id = if mnemonic == "jal" {
                    if decoded.rd == Some(0) {
                        "cf2.jal_x0"
                    } else {
                        "cf2.jal_rd"
                    }
                } else if decoded.rd == Some(0) {
                    "cf2.jalr_x0"
                } else {
                    "cf2.jalr_rd"
                };
                push_row_hit_extra(
                    &mut bucket_hits,
                    semantic::exec::CONTROL_FLOW_BINDING,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "cf2",
                    cell_id,
                    &[("link_pc", json!(row.instruction.address + 4))],
                );
                if mnemonic == "jalr" {
                    if let Some(cell_id) = cf3_cell(decoded) {
                        push_row_hit(
                            &mut bucket_hits,
                            semantic::exec::CONTROL_FLOW_BINDING,
                            row,
                            op_idx,
                            *raw_word,
                            decoded,
                            "cf3",
                            cell_id,
                        );
                    }
                }
            } else if mnemonic == "ecall" {
                push_row_hit(
                    &mut bucket_hits,
                    semantic::control::ECALL_WORD_VALIDITY,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "cf7",
                    "cf7.standard",
                );
            } else if exec_idx > 0 {
                let cell_id =
                    if prev_branch_not_taken { "cf6.after_branch_not_taken" } else { "cf6.normal" };
                push_row_hit_extra(
                    &mut bucket_hits,
                    semantic::exec::CONTROL_FLOW_BINDING,
                    row,
                    op_idx,
                    *raw_word,
                    decoded,
                    "cf6",
                    cell_id,
                    &[("next_pc", json!(row.instruction.address + 4))],
                );
            }
            prev_branch_not_taken = false;
        }

        Ok(Self { bucket_hits, instruction_count: executed.len() })
    }

    pub fn from_execution(
        words: &[u32],
        rows: &[RVTraceRow],
        trace: &[JoltTraceStep<RV32I>],
        memory_init: &[(u64, u8)],
        io_device: &JoltDevice,
    ) -> Result<Self, String> {
        let mut derived =
            Self::from_executed_rows_with_layout(words, rows, &io_device.memory_layout)?;
        emit_initialization_hits(&mut derived.bucket_hits, memory_init, io_device);
        emit_finalization_hits(&mut derived.bucket_hits, trace, memory_init, io_device);
        emit_lookup_and_padding_hits(&mut derived.bucket_hits, trace);
        Ok(derived)
    }

    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }
}

impl Trace for JoltTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }
}
