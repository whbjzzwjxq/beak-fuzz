use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, Trace};
use common::constants::RAM_START_ADDRESS;
use common::rv_trace::{MemoryState, RVTraceRow, RV32IM};
use serde_json::{json, Value};

const BACKEND: &str = "jolt";
const COMMIT: &str = "e9caa23565dbb13019afe61a2c95f51d1999e286";

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
    let mut details = std::collections::HashMap::from([
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

impl JoltTrace {
    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        Ok(Self { bucket_hits: Vec::new(), instruction_count: words.len() })
    }

    pub fn from_executed_rows(words: &[u32], rows: &[RVTraceRow]) -> Result<Self, String> {
        let mut bucket_hits = Vec::new();
        let mut seen_pcs = std::collections::HashSet::new();
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

        let mut last_store = std::collections::HashMap::<(u64, u64), u64>::new();
        let mut prev_branch_not_taken = false;

        for (exec_idx, (idx, row, raw_word, decoded)) in executed.iter().enumerate() {
            let op_idx = *idx as u64;
            let mnemonic = decoded.mnemonic.as_str();

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
                let address = match memory {
                    MemoryState::Read { address, .. } | MemoryState::Write { address, .. } => {
                        *address
                    }
                };
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

    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }
}

impl Trace for JoltTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }
}
