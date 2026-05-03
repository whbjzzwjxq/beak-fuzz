use std::collections::{HashMap, HashSet};

use beak_core::rv32im::{
    instruction::RV32IMInstruction,
    oracle::{OracleConfig, OracleMemoryModel, RISCVOracle},
};
use beak_core::trace::observations::SequenceInsnObservation;
use beak_core::trace::{semantic, semantic_matchers, BucketHit, Trace, TraceSignal};
use serde_json::{json, Value};

const BACKEND: &str = "risc0";
const COMMIT: &str = crate::RISC0_COMMIT;
const ORACLE_MAX_TRACE_STEPS: u32 = 1000;

#[derive(Debug, Clone)]
pub struct Risc0Trace {
    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,
    instruction_count: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct Risc0Insn {
    pub(crate) step_idx: u64,
    pub(crate) pc: u32,
    pub(crate) word: u32,
    pub(crate) mnemonic: String,
    pub(crate) rd: Option<u32>,
    pub(crate) rs1: Option<u32>,
    pub(crate) rs2: Option<u32>,
    pub(crate) regs_before: [u32; 32],
    next_pc: u32,
    imm: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct Risc0PreflightMemoryTxn {
    pub segment_idx: u64,
    pub row_idx: u64,
    pub row_step_idx: u64,
    pub row_pc: u32,
    pub major: u8,
    pub minor: u8,
    pub machine_mode: u8,
    pub txn_idx: u64,
    pub row_txn_start: u64,
    pub row_txn_end: u64,
    pub addr_word: u32,
    pub txn_cycle: u32,
    pub word: u32,
    pub prev_cycle: u32,
    pub prev_word: u32,
    pub is_load: bool,
    pub is_store: bool,
}

#[derive(Debug, Clone)]
pub struct Risc0PreflightSegmentSummary {
    pub segment_idx: u64,
    pub table_split_cycle: u64,
    pub padding_start_row: u64,
    pub total_rows: u64,
    pub lookup_table_rows: u64,
}

#[derive(Debug, Clone)]
pub struct Risc0ExecutedInsnRecord {
    pub step_idx: u64,
    pub pc: u32,
    pub word: u32,
}

fn risc0_trace_oracle_config() -> OracleConfig {
    OracleConfig {
        memory_model: OracleMemoryModel::SplitCodeData,
        code_base: crate::RISC0_ORACLE_CODE_BASE,
        data_size_bytes: 0,
    }
}

pub(crate) fn executed_instructions(words: &[u32]) -> Result<Vec<Risc0Insn>, String> {
    let cfg = risc0_trace_oracle_config();
    let executed_steps =
        RISCVOracle::executed_steps_with_config(words, cfg, ORACLE_MAX_TRACE_STEPS);
    let mut instructions = Vec::with_capacity(executed_steps.len());

    for executed in executed_steps {
        let dec = RV32IMInstruction::from_word(executed.word)
            .map_err(|e| format!("decode failed at step {}: {e}", executed.step_idx))?;
        let regs_before = RISCVOracle::execute_with_step_limit(words, cfg, executed.step_idx).regs;
        instructions.push(Risc0Insn {
            step_idx: executed.step_idx as u64,
            pc: executed.pc,
            next_pc: executed.pc.wrapping_add(4),
            word: executed.word,
            mnemonic: dec.mnemonic,
            rd: dec.rd,
            rs1: dec.rs1,
            rs2: dec.rs2,
            imm: dec.imm,
            regs_before,
        });
    }

    let next_expected_pc = instructions
        .last()
        .map(|insn| insn.pc.wrapping_add(4))
        .unwrap_or(crate::RISC0_ORACLE_CODE_BASE);
    if let Some((idx, &word)) = words.iter().enumerate().find(|(idx, word)| {
        let pc = crate::RISC0_ORACLE_CODE_BASE.wrapping_add((*idx as u32) * 4);
        pc == next_expected_pc
            && !instructions.iter().any(|insn| insn.pc == pc)
            && RV32IMInstruction::decode(**word).is_some_and(|dec| dec.mnemonic == "ecall")
    }) {
        let dec = RV32IMInstruction::from_word(word)
            .map_err(|e| format!("decode failed at synthetic ecall step {idx}: {e}"))?;
        let regs_before =
            RISCVOracle::execute_with_step_limit(words, cfg, instructions.len() as u32).regs;
        instructions.push(Risc0Insn {
            step_idx: instructions.len() as u64,
            pc: next_expected_pc,
            next_pc: next_expected_pc.wrapping_add(4),
            word,
            mnemonic: dec.mnemonic,
            rd: dec.rd,
            rs1: dec.rs1,
            rs2: dec.rs2,
            imm: dec.imm,
            regs_before,
        });
    }

    let next_pcs = instructions
        .iter()
        .skip(1)
        .map(|insn| insn.pc)
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    for (insn, next_pc) in instructions.iter_mut().zip(next_pcs) {
        if next_pc != 0 {
            insn.next_pc = next_pc;
        }
    }

    Ok(instructions)
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

fn imm_format_cell(mnemonic: &str, imm: i32) -> Option<&'static str> {
    match mnemonic {
        "sb" | "sh" | "sw" => Some(if imm.abs() > 0x7f { "id5.cross_field" } else { "id5.s_type" }),
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
            Some(if imm.abs() > 0x7f { "id5.cross_field" } else { "id5.b_type" })
        }
        "jal" => Some(if imm.abs() > 0x7ff { "id5.cross_field" } else { "id5.j_type" }),
        _ => None,
    }
}

fn base_details(insn: &Risc0Insn, obligation_id: &str, cell_id: &str) -> HashMap<String, Value> {
    let mut details = HashMap::new();
    details.insert("obligation_id".to_string(), json!(obligation_id));
    details.insert("cell_id".to_string(), json!(cell_id));
    details.insert("backend".to_string(), json!(BACKEND));
    details.insert("commit".to_string(), json!(COMMIT));
    details.insert("trace_source".to_string(), json!("instruction"));
    details.insert("op_idx".to_string(), json!(insn.step_idx));
    details.insert("step_idx".to_string(), json!(insn.step_idx));
    details.insert("pc".to_string(), json!(insn.pc));
    details.insert("opcode".to_string(), json!(format!("0x{:08x}", insn.word)));
    details.insert("raw_word".to_string(), json!(insn.word));
    details.insert("mnemonic".to_string(), json!(insn.mnemonic));
    if let Some(rd) = insn.rd {
        details.insert("rd".to_string(), json!(rd));
    }
    if let Some(rs1) = insn.rs1 {
        details.insert("rs1".to_string(), json!(rs1));
        details.insert("rs1_val".to_string(), json!(insn.regs_before[rs1 as usize]));
    }
    if let Some(rs2) = insn.rs2 {
        details.insert("rs2".to_string(), json!(rs2));
        details.insert("rs2_val".to_string(), json!(insn.regs_before[rs2 as usize]));
    }
    if let Some(imm) = insn.imm {
        details.insert("imm".to_string(), json!(imm));
    }
    if insn.mnemonic == "ecall" {
        details.insert("a0".to_string(), json!(insn.regs_before[10]));
        details.insert("a1".to_string(), json!(insn.regs_before[11]));
        details.insert("a7".to_string(), json!(insn.regs_before[17]));
    }
    details
}

fn push_obligation_hit(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    insn: &Risc0Insn,
    obligation_id: &str,
    cell_id: &str,
) {
    hits.push(BucketHit::semantic(bucket, base_details(insn, obligation_id, cell_id)));
}

fn push_write_hit(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    insn: &Risc0Insn,
    obligation_id: &str,
    cell_id: &str,
) {
    let mut details = base_details(insn, obligation_id, cell_id);
    if let Some(write_source) = cell_id.split_once('.').map(|(_, source)| source) {
        details.insert("write_source".to_string(), json!(write_source));
    }
    hits.push(BucketHit::semantic(bucket, details));
}

fn control_flow_details(
    insn: &Risc0Insn,
    obligation_id: &str,
    cell_id: &str,
) -> HashMap<String, Value> {
    let mut details = base_details(insn, obligation_id, cell_id);
    details.insert("next_pc".to_string(), json!(insn.next_pc));
    details.insert("taken".to_string(), json!(insn.next_pc != insn.pc.wrapping_add(4)));
    match insn.mnemonic.as_str() {
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "jal" => {
            if let Some(imm) = insn.imm {
                details.insert("target_pc".to_string(), json!(insn.pc.wrapping_add(imm as u32)));
            }
        }
        "jalr" => {
            if let Some(rs1) = insn.rs1 {
                let base = insn.regs_before[rs1 as usize];
                let before_clear = base.wrapping_add(insn.imm.unwrap_or(0) as u32);
                details.insert("target_before_lsb_clear".to_string(), json!(before_clear));
                details.insert("target_after_lsb_clear".to_string(), json!(before_clear & !1));
                details.insert("target_pc".to_string(), json!(before_clear & !1));
            }
        }
        _ => {}
    }
    if matches!(insn.mnemonic.as_str(), "jal" | "jalr") {
        details.insert("link_pc".to_string(), json!(insn.pc.wrapping_add(4)));
    }
    details
}

fn push_control_flow_hit(
    hits: &mut Vec<BucketHit>,
    insn: &Risc0Insn,
    obligation_id: &str,
    cell_id: &str,
) {
    hits.push(BucketHit::semantic(
        semantic::exec::CONTROL_FLOW_BINDING,
        control_flow_details(insn, obligation_id, cell_id),
    ));
}

fn shift_amount(insn: &Risc0Insn) -> (u32, u32) {
    if let Some(rs2) = insn.rs2 {
        let raw = insn.regs_before[rs2 as usize];
        return (raw, raw & 0x1f);
    }
    let raw = insn.imm.unwrap_or(0) as u32 & 0x1f;
    (raw, raw)
}

fn al2_cell(insn: &Risc0Insn) -> &'static str {
    let (raw_shamt, effective_shamt) = shift_amount(insn);
    match insn.mnemonic.as_str() {
        "sll" | "slli" if effective_shamt == 0 => "al2.shamt_zero",
        "sll" if raw_shamt >= 32 => "al2.sll_ge32",
        "sll" | "slli" => "al2.sll_lt32",
        "srl" | "srli" if effective_shamt == 0 => "al2.shamt_zero",
        "srl" if raw_shamt >= 32 => "al2.srl_ge32",
        "srl" | "srli" => "al2.srl_lt32",
        "sra" | "srai" if effective_shamt == 0 => "al2.shamt_zero",
        "sra" | "srai" => {
            if insn.rs1.map(|rs1| (insn.regs_before[rs1 as usize] as i32) < 0).unwrap_or(false) {
                if raw_shamt >= 32 {
                    "al2.sra_ge32_neg"
                } else {
                    "al2.sra_lt32_neg"
                }
            } else if raw_shamt >= 32 {
                "al2.sra_ge32_pos"
            } else {
                "al2.sra_lt32_pos"
            }
        }
        _ => "al2.shamt_zero",
    }
}

fn al3_cell(insn: &Risc0Insn) -> &'static str {
    let Some(rs1) = insn.rs1 else {
        return "al3.equal";
    };
    let lhs = insn.regs_before[rs1 as usize];
    let rhs = insn
        .rs2
        .map(|rs2| insn.regs_before[rs2 as usize])
        .or_else(|| insn.imm.map(|imm| imm as u32))
        .unwrap_or(0);
    let signed_lt = (lhs as i32) < (rhs as i32);
    let unsigned_lt = lhs < rhs;
    if lhs == rhs {
        "al3.equal"
    } else if signed_lt != unsigned_lt {
        "al3.sign_disagree"
    } else if matches!(insn.mnemonic.as_str(), "sltu" | "sltiu") {
        if unsigned_lt {
            "al3.sltu_true"
        } else {
            "al3.sltu_false"
        }
    } else if signed_lt {
        "al3.slt_true"
    } else {
        "al3.slt_false"
    }
}

fn al4_cell(insn: &Risc0Insn) -> &'static str {
    let lhs = insn.rs1.map(|rs1| insn.regs_before[rs1 as usize]).unwrap_or(0);
    let rhs = insn
        .rs2
        .map(|rs2| insn.regs_before[rs2 as usize])
        .or_else(|| insn.imm.map(|imm| imm as u32))
        .unwrap_or(0);
    if lhs == rhs {
        "al4.equal"
    } else if lhs < rhs {
        "al4.borrow"
    } else if (lhs & 0xff) < (rhs & 0xff) {
        "al4.cross_limb"
    } else {
        "al4.no_borrow"
    }
}

fn al5_cell(insn: &Risc0Insn) -> &'static str {
    let lhs = insn.rs1.map(|rs1| insn.regs_before[rs1 as usize]).unwrap_or(0);
    let rhs = insn
        .rs2
        .map(|rs2| insn.regs_before[rs2 as usize])
        .or_else(|| insn.imm.map(|imm| imm as u32))
        .unwrap_or(0);
    if lhs == rhs {
        "al5.all_equal"
    } else if (lhs >> 24) != (rhs >> 24) {
        "al5.first_limb_diff"
    } else if (lhs & 0xff) != (rhs & 0xff) {
        "al5.last_limb_diff"
    } else {
        "al5.alternating_borrow"
    }
}

fn div_special_cell(insn: &Risc0Insn) -> Option<(&'static str, &'static str)> {
    let rs1 = insn.rs1?;
    let rs2 = insn.rs2?;
    let dividend = insn.regs_before[rs1 as usize];
    let divisor = insn.regs_before[rs2 as usize];
    if divisor == 0 {
        let cell = match insn.mnemonic.as_str() {
            "div" => "md1.div_zero",
            "divu" => "md1.divu_zero",
            "rem" => "md1.rem_zero",
            "remu" => "md1.remu_zero",
            _ => return None,
        };
        return Some(("md1", cell));
    }
    if dividend == 0x8000_0000 && divisor == 0xffff_ffff {
        let cell = match insn.mnemonic.as_str() {
            "div" => "md2.div_overflow",
            "rem" => "md2.rem_overflow",
            _ => return None,
        };
        return Some(("md2", cell));
    }
    None
}

fn md3_cell(insn: &Risc0Insn) -> &'static str {
    let rs1 = insn.rs1.map(|rs1| insn.regs_before[rs1 as usize]).unwrap_or(0);
    let rs2 = insn.rs2.map(|rs2| insn.regs_before[rs2 as usize]).unwrap_or(0);
    if matches!(insn.mnemonic.as_str(), "divu" | "remu") {
        "md3.unsigned"
    } else if rs1 == rs2.saturating_mul(rs1 / rs2.max(1)) {
        "md3.exact"
    } else if rs2 == 1 || rs2 == 0xffff_ffff {
        "md3.one"
    } else if (rs1 as i32) < 0 && (rs2 as i32) < 0 {
        "md3.nn"
    } else if (rs1 as i32) < 0 {
        "md3.np"
    } else if (rs2 as i32) < 0 {
        "md3.pn"
    } else {
        "md3.pp"
    }
}

fn md4_cell(insn: &Risc0Insn) -> &'static str {
    let lhs = insn.rs1.map(|rs1| insn.regs_before[rs1 as usize]).unwrap_or(0);
    let rhs = insn.rs2.map(|rs2| insn.regs_before[rs2 as usize]).unwrap_or(0);
    match insn.mnemonic.as_str() {
        "mul" if lhs == 0 || rhs == 0 => "md4.zero_op",
        "mul" if (lhs as u64) * (rhs as u64) > u32::MAX as u64 => "md4.mul_overflow",
        "mul" => "md4.mul_small",
        "mulhu" => "md4.mulhu",
        "mulhsu" => "md4.mulh_pn",
        "mulh" if (lhs as i32) < 0 && (rhs as i32) < 0 => "md4.mulh_nn",
        "mulh" if (lhs as i32) < 0 || (rhs as i32) < 0 => "md4.mulh_pn",
        "mulh" => "md4.mulh_pp",
        _ => "md4.mul_small",
    }
}

fn md5_cell(insn: &Risc0Insn) -> &'static str {
    let lhs = insn.rs1.map(|rs1| insn.regs_before[rs1 as usize]).unwrap_or(0);
    if lhs == 0xffff_ffff {
        "md5.neg_one"
    } else if lhs == 0x8000_0000 {
        "md5.neg_max"
    } else if (lhs as i32) < 0 && lhs < 0xffff_0000 {
        "md5.neg_large"
    } else if (lhs as i32) < 0 {
        "md5.neg_small"
    } else {
        "md5.pos_any"
    }
}

fn cf1_cell(insn: &Risc0Insn) -> Option<&'static str> {
    let taken = insn.next_pc != insn.pc.wrapping_add(4);
    match insn.mnemonic.as_str() {
        "blt" if taken => Some("cf1.blt_taken"),
        "blt" => Some("cf1.blt_not_taken"),
        "bge" if taken => Some("cf1.bge_taken"),
        "bge" => Some("cf1.bge_not_taken"),
        "bltu" if taken => Some("cf1.bltu_taken"),
        "bltu" => Some("cf1.bltu_not_taken"),
        "bgeu" if taken => Some("cf1.bgeu_taken"),
        "bgeu" => Some("cf1.bgeu_not_taken"),
        "beq" if taken => Some("cf1.beq_equal"),
        "bne" if taken => Some("cf1.bne_not_equal"),
        _ => None,
    }
}

fn cf3_cell(insn: &Risc0Insn) -> &'static str {
    match insn.imm.unwrap_or(0).cmp(&0) {
        std::cmp::Ordering::Less => "cf3.imm_neg",
        std::cmp::Ordering::Equal => "cf3.imm_zero",
        std::cmp::Ordering::Greater => "cf3.imm_pos",
    }
}

fn cf3_target_cell(insn: &Risc0Insn) -> Option<&'static str> {
    let rs1 = insn.rs1?;
    let base = insn.regs_before[rs1 as usize];
    let imm = insn.imm.unwrap_or(0) as u32;
    let (target_before_clear, wrapped) = base.overflowing_add(imm);
    if wrapped {
        Some("cf3.wrap")
    } else if target_before_clear & 1 == 1 {
        Some("cf3.clear_lsb")
    } else {
        Some("cf3.even")
    }
}

const RISC0_USER_REGS_WORD_ADDR: u32 = 0xffff_0080 / 4;
const RISC0_MACHINE_REGS_WORD_ADDR: u32 = 0xffff_0000 / 4;
const RISC0_REG_COUNT: u32 = 32;

#[derive(Debug, Clone)]
struct Risc0MemoryAccess {
    insn: Risc0Insn,
    segment_idx: u64,
    row_idx: u64,
    row_pc: u32,
    txn_idx: u64,
    effective_ptr: u32,
    aligned_ptr: u32,
    byte_offset: u32,
    width: u8,
    is_load: bool,
    is_store: bool,
    timestamp: u32,
    prev_timestamp: Option<u32>,
    read_data: Option<u32>,
    prev_data: Option<u32>,
    write_data: Option<u32>,
    loaded_value: Option<u32>,
}

fn memory_width(mnemonic: &str) -> Option<u8> {
    match mnemonic {
        "lb" | "lbu" | "sb" => Some(1),
        "lh" | "lhu" | "sh" => Some(2),
        "lw" | "sw" => Some(4),
        _ => None,
    }
}

fn is_load_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "lb" | "lh" | "lw" | "lbu" | "lhu")
}

fn is_store_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sb" | "sh" | "sw")
}

fn clean_prev_timestamp(txn: &Risc0PreflightMemoryTxn) -> Option<u32> {
    (txn.prev_cycle != u32::MAX && txn.prev_cycle < txn.txn_cycle).then_some(txn.prev_cycle)
}

fn load_value(mnemonic: &str, word: u32, byte_offset: u32) -> u32 {
    let shift = 8 * byte_offset;
    match mnemonic {
        "lb" => {
            let byte = (word >> shift) & 0xff;
            if byte & 0x80 != 0 {
                byte | 0xffff_ff00
            } else {
                byte
            }
        }
        "lbu" => (word >> shift) & 0xff,
        "lh" => {
            let half = (word >> shift) & 0xffff;
            if half & 0x8000 != 0 {
                half | 0xffff_0000
            } else {
                half
            }
        }
        "lhu" => (word >> shift) & 0xffff,
        "lw" => word,
        _ => word,
    }
}

fn store_word(mnemonic: &str, prev_word: u32, rs2_val: u32, byte_offset: u32) -> u32 {
    let shift = 8 * byte_offset;
    match mnemonic {
        "sb" => (prev_word & !(0xff << shift)) | ((rs2_val & 0xff) << shift),
        "sh" => (prev_word & !(0xffff << shift)) | ((rs2_val & 0xffff) << shift),
        "sw" => rs2_val,
        _ => prev_word,
    }
}

fn register_index_from_word_addr(addr_word: u32) -> Option<u32> {
    if (RISC0_USER_REGS_WORD_ADDR..RISC0_USER_REGS_WORD_ADDR + RISC0_REG_COUNT).contains(&addr_word)
    {
        return Some(addr_word - RISC0_USER_REGS_WORD_ADDR);
    }
    if (RISC0_MACHINE_REGS_WORD_ADDR..RISC0_MACHINE_REGS_WORD_ADDR + RISC0_REG_COUNT)
        .contains(&addr_word)
    {
        return Some(addr_word - RISC0_MACHINE_REGS_WORD_ADDR);
    }
    None
}

fn regs_before_from_preflight(step_idx: u64, txns: &[Risc0PreflightMemoryTxn]) -> [u32; 32] {
    let mut regs = [0u32; 32];
    for txn in txns.iter().filter(|txn| txn.row_step_idx == step_idx && txn.is_load) {
        let Some(reg_idx) = register_index_from_word_addr(txn.addr_word) else {
            continue;
        };
        if reg_idx != 0 && (reg_idx as usize) < regs.len() {
            regs[reg_idx as usize] = txn.prev_word;
        }
    }
    regs[0] = 0;
    regs
}

fn preflight_executed_instructions(
    records: &[Risc0ExecutedInsnRecord],
    txns: &[Risc0PreflightMemoryTxn],
) -> Result<Vec<Risc0Insn>, String> {
    let mut instructions = Vec::with_capacity(records.len());
    for (idx, record) in records.iter().enumerate() {
        let dec = RV32IMInstruction::from_word(record.word).map_err(|e| {
            format!("decode failed at risc0 preflight step {}: {e}", record.step_idx)
        })?;
        let regs_before = regs_before_from_preflight(record.step_idx, txns);
        let next_pc = records.get(idx + 1).map(|next| next.pc).unwrap_or(record.pc.wrapping_add(4));
        instructions.push(Risc0Insn {
            step_idx: record.step_idx,
            pc: record.pc,
            next_pc,
            word: record.word,
            mnemonic: dec.mnemonic,
            rd: dec.rd,
            rs1: dec.rs1,
            rs2: dec.rs2,
            regs_before,
            imm: dec.imm,
        });
    }
    Ok(instructions)
}

fn preflight_memory_accesses(
    instructions: &[Risc0Insn],
    txns: &[Risc0PreflightMemoryTxn],
) -> Vec<Risc0MemoryAccess> {
    let mut txns_by_step: HashMap<u64, Vec<&Risc0PreflightMemoryTxn>> = HashMap::new();
    for txn in txns {
        txns_by_step.entry(txn.row_step_idx).or_default().push(txn);
    }

    let mut accesses = Vec::new();
    for insn in instructions {
        let mnemonic = insn.mnemonic.as_str();
        if !(is_load_mnemonic(mnemonic) || is_store_mnemonic(mnemonic)) {
            continue;
        }
        let Some(width) = memory_width(mnemonic) else {
            continue;
        };
        let Some(rs1) = insn.rs1 else {
            continue;
        };
        let Some(row_txns) = txns_by_step.get(&insn.step_idx) else {
            continue;
        };
        let effective_ptr =
            insn.regs_before[rs1 as usize].wrapping_add(insn.imm.unwrap_or(0) as u32);
        let aligned_ptr = effective_ptr & !0x3;
        let byte_offset = effective_ptr & 0x3;
        let addr_word = aligned_ptr / 4;
        let matching =
            row_txns.iter().copied().filter(|txn| txn.addr_word == addr_word).collect::<Vec<_>>();

        if is_load_mnemonic(mnemonic) {
            let Some(txn) = matching.iter().copied().filter(|txn| txn.is_load).last() else {
                continue;
            };
            let read_word = txn.prev_word;
            accesses.push(Risc0MemoryAccess {
                insn: insn.clone(),
                segment_idx: txn.segment_idx,
                row_idx: txn.row_idx,
                row_pc: txn.row_pc,
                txn_idx: txn.txn_idx,
                effective_ptr,
                aligned_ptr,
                byte_offset,
                width,
                is_load: true,
                is_store: false,
                timestamp: txn.txn_cycle,
                prev_timestamp: clean_prev_timestamp(txn),
                read_data: Some(read_word),
                prev_data: Some(read_word),
                write_data: None,
                loaded_value: Some(load_value(mnemonic, read_word, byte_offset)),
            });
        } else {
            let Some(store_txn) = matching.iter().copied().filter(|txn| txn.is_store).last() else {
                continue;
            };
            let prev_word = matching
                .iter()
                .copied()
                .filter(|txn| txn.is_load && txn.txn_cycle <= store_txn.txn_cycle)
                .last()
                .map(|txn| txn.prev_word)
                .unwrap_or(store_txn.prev_word);
            let rs2_val = insn.rs2.map(|rs2| insn.regs_before[rs2 as usize]).unwrap_or(0);
            let write_word = store_word(mnemonic, prev_word, rs2_val, byte_offset);
            accesses.push(Risc0MemoryAccess {
                insn: insn.clone(),
                segment_idx: store_txn.segment_idx,
                row_idx: store_txn.row_idx,
                row_pc: store_txn.row_pc,
                txn_idx: store_txn.txn_idx,
                effective_ptr,
                aligned_ptr,
                byte_offset,
                width,
                is_load: false,
                is_store: true,
                timestamp: store_txn.txn_cycle,
                prev_timestamp: clean_prev_timestamp(store_txn),
                read_data: None,
                prev_data: Some(prev_word),
                write_data: Some(write_word),
                loaded_value: None,
            });
        }
    }

    accesses
}

fn memory_access_details(
    access: &Risc0MemoryAccess,
    obligation_id: &str,
    cell_id: &str,
) -> HashMap<String, Value> {
    let mut details = base_details(&access.insn, obligation_id, cell_id);
    details.insert("trace_source".to_string(), json!("memory_access"));
    details.insert("segment_idx".to_string(), json!(access.segment_idx));
    details.insert("row_op_idx".to_string(), json!(access.row_idx));
    details.insert("preflight_row_pc".to_string(), json!(access.row_pc));
    details.insert("preflight_txn_idx".to_string(), json!(access.txn_idx));
    details.insert("address_space".to_string(), json!("risc0.main_memory"));
    details.insert("raw_ptr".to_string(), json!(access.effective_ptr));
    details.insert("effective_ptr".to_string(), json!(access.effective_ptr));
    details.insert("aligned_ptr".to_string(), json!(access.aligned_ptr));
    details.insert("byte_offset".to_string(), json!(access.byte_offset));
    details.insert("width".to_string(), json!(access.width));
    details.insert("is_load".to_string(), json!(access.is_load));
    details.insert("is_store".to_string(), json!(access.is_store));
    details.insert("timestamp".to_string(), json!(access.timestamp));
    if let Some(prev_timestamp) = access.prev_timestamp {
        details.insert("prev_timestamp".to_string(), json!(prev_timestamp));
    }
    if let Some(read_data) = access.read_data {
        details.insert("read_data".to_string(), json!(read_data));
    }
    if let Some(prev_data) = access.prev_data {
        details.insert("prev_data".to_string(), json!(prev_data));
    }
    if let Some(write_data) = access.write_data {
        details.insert("write_data".to_string(), json!(write_data));
    }
    if let Some(loaded_value) = access.loaded_value {
        details.insert("loaded_value".to_string(), json!(loaded_value));
    }
    if let Some(rs1) = access.insn.rs1 {
        details.insert("rs1_ptr".to_string(), json!(rs1));
    }
    if let Some(rd_rs2) = access.insn.rd.or(access.insn.rs2) {
        details.insert("rd_rs2_ptr".to_string(), json!(rd_rs2));
    }
    details
}

fn push_memory_hit(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    access: &Risc0MemoryAccess,
    obligation_id: &str,
    cell_id: &str,
) {
    hits.push(BucketHit::semantic(bucket, memory_access_details(access, obligation_id, cell_id)));
}

fn me1_cell(
    store: &Risc0MemoryAccess,
    load: &Risc0MemoryAccess,
    store_count: usize,
) -> &'static str {
    if store_count > 1 {
        return "me1.overwrite";
    }
    match (store.insn.mnemonic.as_str(), load.insn.mnemonic.as_str()) {
        ("sw", "lw") => "me1.sw_lw",
        ("sb", "lb") => "me1.sb_lb",
        ("sh", "lh") => "me1.sh_lh",
        ("sb", "lw") => "me1.sb_lw",
        ("sw", "lb" | "lbu") => "me1.sw_lb",
        ("sw", "lhu") => "me1.sw_lhu",
        _ => "me1.sw_lw",
    }
}

fn me2_cell(access: &Risc0MemoryAccess) -> Option<&'static str> {
    match access.width {
        1 => Some("me2.byte_any"),
        2 if access.byte_offset % 2 == 1 => Some("me2.half_off1"),
        4 if access.byte_offset == 1 => Some("me2.word_off1"),
        4 if access.byte_offset == 2 => Some("me2.word_off2"),
        4 if access.byte_offset == 3 => Some("me2.word_off3"),
        _ => None,
    }
}

fn me3_cell(access: &Risc0MemoryAccess) -> Option<&'static str> {
    let read_word = access.read_data?;
    let shift = 8 * access.byte_offset;
    match access.insn.mnemonic.as_str() {
        "lb" => Some(if ((read_word >> shift) & 0x80) == 0 { "me3.lb_pos" } else { "me3.lb_neg" }),
        "lh" => {
            Some(if ((read_word >> shift) & 0x8000) == 0 { "me3.lh_pos" } else { "me3.lh_neg" })
        }
        "lbu" => Some("me3.lbu"),
        "lhu" => Some("me3.lhu"),
        _ => None,
    }
}

fn me4_cell(access: &Risc0MemoryAccess) -> Option<&'static str> {
    match (access.insn.mnemonic.as_str(), access.byte_offset) {
        ("sb", 0) => Some("me4.sb_off0"),
        ("sb", 1) => Some("me4.sb_off1"),
        ("sb", 2) => Some("me4.sb_off2"),
        ("sb", 3) => Some("me4.sb_off3"),
        ("sh", 0) => Some("me4.sh_off0"),
        ("sh", 2) => Some("me4.sh_off2"),
        _ => None,
    }
}

fn me6_cell(access: &Risc0MemoryAccess) -> Option<&'static str> {
    let end_overflows = access.effective_ptr.checked_add(access.width as u32 - 1).is_none();
    if !end_overflows && access.effective_ptr < 0xbfff_f000 {
        return None;
    }
    match access.insn.mnemonic.as_str() {
        "lw" => Some("me6.near_max_lw"),
        "sw" => Some("me6.near_max_sw"),
        "lh" | "lhu" => Some("me6.near_max_lh"),
        "sb" => Some("me6.near_max_sb"),
        _ => Some("me6.heap_boundary"),
    }
}

fn me7_cell(access: &Risc0MemoryAccess) -> Option<&'static str> {
    let read_data = access.read_data?;
    Some(if read_data == 0 { "me7.bss_zero" } else { "me7.data_loaded" })
}

fn me9_offset_cell(access: &Risc0MemoryAccess) -> Option<&'static str> {
    if access.width >= 4 {
        return None;
    }
    Some(match access.byte_offset {
        0 => "me9.off0",
        1 => "me9.off1",
        2 => "me9.off2",
        _ => "me9.off3",
    })
}

fn ts2_cell(diff: u32) -> &'static str {
    if diff == 1 {
        "ts2.consecutive"
    } else if diff < 32 {
        "ts2.small_gap"
    } else {
        "ts2.large_gap"
    }
}

fn is_register_word_addr(addr_word: u32) -> bool {
    (RISC0_USER_REGS_WORD_ADDR..RISC0_USER_REGS_WORD_ADDR + RISC0_REG_COUNT).contains(&addr_word)
        || (RISC0_MACHINE_REGS_WORD_ADDR..RISC0_MACHINE_REGS_WORD_ADDR + RISC0_REG_COUNT)
            .contains(&addr_word)
}

fn emit_register_address_space_hits(
    instructions: &[Risc0Insn],
    txns: &[Risc0PreflightMemoryTxn],
) -> Vec<BucketHit> {
    let by_step =
        instructions.iter().map(|insn| ((insn.step_idx, insn.pc), insn)).collect::<HashMap<_, _>>();
    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    for txn in txns {
        if !is_register_word_addr(txn.addr_word) {
            continue;
        }
        if !seen.insert((txn.segment_idx, txn.txn_idx, txn.is_load)) {
            continue;
        }
        let Some(insn) = by_step.get(&(txn.row_step_idx, txn.row_pc)) else {
            continue;
        };
        let cell = if txn.is_load { "me5.reg_read" } else { "me5.reg_write" };
        let mut details = base_details(insn, "me5", cell);
        details.insert("trace_source".to_string(), json!("memory_access"));
        details.insert("segment_idx".to_string(), json!(txn.segment_idx));
        details.insert("row_op_idx".to_string(), json!(txn.row_idx));
        details.insert("preflight_row_pc".to_string(), json!(txn.row_pc));
        details.insert("preflight_txn_idx".to_string(), json!(txn.txn_idx));
        details.insert("address_space".to_string(), json!("risc0.register"));
        details.insert("effective_ptr".to_string(), json!(txn.addr_word * 4));
        details.insert("aligned_ptr".to_string(), json!(txn.addr_word * 4));
        details.insert("width".to_string(), json!(4));
        details.insert("is_load".to_string(), json!(txn.is_load));
        details.insert("is_store".to_string(), json!(txn.is_store));
        details.insert("timestamp".to_string(), json!(txn.txn_cycle));
        if let Some(prev_timestamp) = clean_prev_timestamp(txn) {
            details.insert("prev_timestamp".to_string(), json!(prev_timestamp));
        }
        if txn.is_load {
            details.insert("read_data".to_string(), json!(txn.prev_word));
        } else {
            details.insert("prev_data".to_string(), json!(txn.prev_word));
            details.insert("write_data".to_string(), json!(txn.word));
        }
        hits.push(BucketHit::semantic(semantic::memory::ADDRESS_SPACE_CONSISTENCY, details));
    }
    hits
}

fn emit_preflight_memory_obligation_hits(
    instructions: &[Risc0Insn],
    txns: &[Risc0PreflightMemoryTxn],
    summaries: &[Risc0PreflightSegmentSummary],
) -> Vec<BucketHit> {
    let mut hits = emit_register_address_space_hits(instructions, txns);
    let accesses = preflight_memory_accesses(instructions, txns);
    let mut last_store_by_ptr: HashMap<u32, Risc0MemoryAccess> = HashMap::new();
    let mut store_count_by_ptr: HashMap<u32, usize> = HashMap::new();
    let mut last_store_by_word: HashMap<u32, Risc0MemoryAccess> = HashMap::new();
    let mut store_count_by_word: HashMap<u32, usize> = HashMap::new();
    let mut last_access_by_ptr: HashMap<u32, Risc0MemoryAccess> = HashMap::new();
    let mut prior_store_words = HashSet::new();
    let mut last_subword: Option<Risc0MemoryAccess> = None;
    let mut final_by_word: HashMap<u32, (Risc0MemoryAccess, bool)> = HashMap::new();

    for access in &accesses {
        if let Some(prev) = last_access_by_ptr.get(&access.effective_ptr) {
            if access.timestamp > prev.timestamp {
                let diff = access.timestamp - prev.timestamp;
                let mut details = memory_access_details(access, "ts2", ts2_cell(diff));
                details.insert("previous_step_idx".to_string(), json!(prev.insn.step_idx));
                details.insert("previous_row_op_idx".to_string(), json!(prev.row_idx));
                details.insert("prev_timestamp".to_string(), json!(prev.timestamp));
                details.insert("ts_diff".to_string(), json!(diff));
                hits.push(BucketHit::semantic(semantic::time::MONOTONIC_ACCESS_ORDERING, details));
            }
        }
        last_access_by_ptr.insert(access.effective_ptr, access.clone());

        if let Some(cell) = me2_cell(access) {
            push_memory_hit(
                &mut hits,
                semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                access,
                "me2",
                cell,
            );
        }
        if let Some(cell) = me6_cell(access) {
            push_memory_hit(
                &mut hits,
                semantic::memory::ADDRESS_BOUNDARY_RANGE,
                access,
                "me6",
                cell,
            );
        }
        let me5_cell = if access.is_load { "me5.mem_read" } else { "me5.mem_write" };
        push_memory_hit(
            &mut hits,
            semantic::memory::ADDRESS_SPACE_CONSISTENCY,
            access,
            "me5",
            me5_cell,
        );

        if access.is_load {
            let exact_store = last_store_by_ptr.get(&access.effective_ptr);
            if let Some(store) = exact_store.or_else(|| last_store_by_word.get(&access.aligned_ptr))
            {
                let store_count = if exact_store.is_some() {
                    store_count_by_ptr.get(&access.effective_ptr).copied().unwrap_or(1)
                } else {
                    store_count_by_word.get(&access.aligned_ptr).copied().unwrap_or(1)
                };
                let cell = me1_cell(store, access, store_count);
                let mut details = memory_access_details(access, "me1", cell);
                details.insert("store_step_idx".to_string(), json!(store.insn.step_idx));
                details.insert("store_timestamp".to_string(), json!(store.timestamp));
                details.insert("store_width".to_string(), json!(store.width));
                if let Some(write_data) = store.write_data {
                    details.insert("write_data".to_string(), json!(write_data));
                }
                hits.push(BucketHit::semantic(semantic::memory::STORE_LOAD_PAYLOAD_FLOW, details));
            }
            if let Some(cell) = me3_cell(access) {
                push_memory_hit(
                    &mut hits,
                    semantic::memory::LOAD_VALUE_BINDING,
                    access,
                    "me3",
                    cell,
                );
            }
            if !prior_store_words.contains(&access.aligned_ptr) {
                if let Some(cell) = me7_cell(access) {
                    push_memory_hit(
                        &mut hits,
                        semantic::memory::INITIAL_VALUE_BINDING,
                        access,
                        "me7",
                        cell,
                    );
                }
            }
        }

        if access.is_store {
            *store_count_by_ptr.entry(access.effective_ptr).or_default() += 1;
            last_store_by_ptr.insert(access.effective_ptr, access.clone());
            *store_count_by_word.entry(access.aligned_ptr).or_default() += 1;
            last_store_by_word.insert(access.aligned_ptr, access.clone());
            prior_store_words.insert(access.aligned_ptr);
            if let Some(cell) = me4_cell(access) {
                push_memory_hit(
                    &mut hits,
                    semantic::memory::WRITE_PAYLOAD_CONSISTENCY,
                    access,
                    "me4",
                    cell,
                );
            }
        }

        if let Some(cell) = me9_offset_cell(access) {
            push_memory_hit(
                &mut hits,
                semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY,
                access,
                "me9",
                cell,
            );
            if let Some(prev) = &last_subword {
                let delta = access.effective_ptr.abs_diff(prev.effective_ptr);
                if delta == 1 {
                    let cell = if access.aligned_ptr == prev.aligned_ptr {
                        "me9.adjacent_same_word"
                    } else {
                        "me9.adjacent_diff_word"
                    };
                    let mut details = memory_access_details(access, "me9", cell);
                    details.insert("previous_effective_ptr".to_string(), json!(prev.effective_ptr));
                    details.insert("previous_step_idx".to_string(), json!(prev.insn.step_idx));
                    hits.push(BucketHit::semantic(
                        semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY,
                        details,
                    ));
                }
            }
            last_subword = Some(access.clone());
        }

        let entry =
            final_by_word.entry(access.aligned_ptr).or_insert_with(|| (access.clone(), false));
        entry.0 = access.clone();
        entry.1 |= access.is_store;
    }

    let final_step_idx = summaries.iter().map(|summary| summary.total_rows).max().unwrap_or(0);
    for (_aligned_ptr, (last, saw_store)) in final_by_word {
        let cell = if saw_store { "me11.written_cells" } else { "me11.read_only_cells" };
        let mut details = memory_access_details(&last, "me11", cell);
        details.insert("trace_source".to_string(), json!("preflight_memory_finalization"));
        details.insert("step_idx".to_string(), json!(final_step_idx));
        details.insert("last_access_step_idx".to_string(), json!(last.insn.step_idx));
        details.insert("last_access_timestamp".to_string(), json!(last.timestamp));
        details.insert("changed_from_initial".to_string(), json!(saw_store));
        details.insert("finalization_source".to_string(), json!("wrap_memory_txns"));
        hits.push(BucketHit::semantic(semantic::memory::FINALIZATION_CONSISTENCY, details));
    }

    for summary in summaries {
        if summary.padding_start_row >= summary.total_rows {
            continue;
        }
        let mut details = HashMap::new();
        details.insert("obligation_id".to_string(), json!("pd1"));
        details.insert("cell_id".to_string(), json!("pd1.exec_padding"));
        details.insert("backend".to_string(), json!(BACKEND));
        details.insert("commit".to_string(), json!(COMMIT));
        details.insert("trace_source".to_string(), json!("padding"));
        details.insert("segment_idx".to_string(), json!(summary.segment_idx));
        details.insert("step_idx".to_string(), json!(summary.padding_start_row));
        details.insert("table_name".to_string(), json!("risc0.preflight.main"));
        details.insert("is_padding".to_string(), json!(true));
        details.insert("interaction_kind".to_string(), json!("none"));
        details.insert("table_split_cycle".to_string(), json!(summary.table_split_cycle));
        details.insert("lookup_table_rows".to_string(), json!(summary.lookup_table_rows));
        details.insert("total_rows".to_string(), json!(summary.total_rows));
        hits.push(BucketHit::semantic(semantic::row::PADDING_INTERACTION_SEND, details));
    }

    hits
}

fn emit_instruction_obligation_hits(instructions: &[Risc0Insn]) -> Vec<BucketHit> {
    let mut hits = Vec::new();

    for (idx, insn) in instructions.iter().enumerate() {
        let mnemonic = insn.mnemonic.as_str();
        let class = mnemonic_class(mnemonic);
        let rd = insn.rd;
        let rs1 = insn.rs1;
        let rs2 = insn.rs2;

        if let Some(cell) = write_source_cell(mnemonic).filter(|_| rd == Some(0)) {
            push_write_hit(
                &mut hits,
                semantic::decode::ZERO_REGISTER_IMMUTABILITY,
                insn,
                "rf1",
                cell,
            );
        }

        if rs1.is_some() || rs2.is_some() {
            let cell = match (rs1, rs2, rd) {
                (Some(a), Some(b), Some(c)) if a == b && b == c => "rf2.all_same",
                (Some(a), Some(b), _) if a == b => "rf2.rs1_eq_rs2",
                (Some(a), _, Some(c)) if a == c => "rf2.rs1_eq_rd",
                (_, Some(b), Some(c)) if b == c => "rf2.rs2_eq_rd",
                (Some(0), _, _) => "rf2.rs1_x0",
                (_, Some(0), _) => "rf2.rs2_x0",
                _ => "rf2.no_alias",
            };
            push_obligation_hit(
                &mut hits,
                semantic::decode::OPERAND_INDEX_ROUTING,
                insn,
                "rf2",
                cell,
            );
        }

        if rd.filter(|rd| *rd != 0).is_some() {
            if let Some(cell) = dest_binding_cell(mnemonic) {
                push_write_hit(&mut hits, semantic::exec::DEST_BINDING, insn, "rf3", cell);
                push_obligation_hit(
                    &mut hits,
                    semantic::decode::RD_BIT_DECOMPOSITION,
                    insn,
                    "rc1",
                    "rc1.alu_result",
                );
            }
        }

        let funct3 = (insn.word >> 12) & 0x7;
        let funct7 = (insn.word >> 25) & 0x7f;
        let field_cell = if [rd, rs1, rs2].into_iter().flatten().any(|r| r == 31) {
            "id1.reg_max"
        } else if [rd, rs1, rs2].into_iter().flatten().any(|r| r == 0) {
            "id1.reg_zero"
        } else if funct3 == 7 || funct7 == 127 {
            "id1.funct_max"
        } else {
            "id1.reg_mid"
        };
        push_obligation_hit(&mut hits, semantic::decode::FIELD_RANGE, insn, "id1", field_cell);

        if let Some(imm) = insn.imm {
            let sign_cell = match mnemonic {
                "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai"
                | "lb" | "lh" | "lw" | "lbu" | "lhu" | "jalr" => {
                    Some(if imm < 0 { "id2.i_neg" } else { "id2.i_pos" })
                }
                "sb" | "sh" | "sw" => Some(if imm < 0 { "id2.s_neg" } else { "id2.s_pos" }),
                "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
                    Some(if imm < 0 { "id2.b_neg" } else { "id2.b_pos" })
                }
                "jal" => Some(if imm < 0 { "id2.j_neg" } else { "id2.j_pos" }),
                _ => None,
            };
            if let Some(cell) = sign_cell {
                push_obligation_hit(
                    &mut hits,
                    semantic::decode::IMMEDIATE_SIGN_EXTENSION,
                    insn,
                    "id2",
                    cell,
                );
            }
            if let Some(cell) = imm_format_cell(mnemonic, imm) {
                push_obligation_hit(
                    &mut hits,
                    semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY,
                    insn,
                    "id5",
                    cell,
                );
            }
        }

        match mnemonic {
            "lui" => {
                let imm = insn.imm.unwrap_or_default() as u32;
                let cell = if imm == 0 {
                    "id3.lui_zero"
                } else if imm == 0xfffff000 {
                    "id3.lui_max"
                } else {
                    "id3.lui_mid"
                };
                push_obligation_hit(
                    &mut hits,
                    semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION,
                    insn,
                    "id3",
                    cell,
                );
            }
            "auipc" => {
                let imm = insn.imm.unwrap_or_default() as u32;
                let cell = if insn.pc.checked_add(imm).is_some() {
                    "id3.auipc_no_wrap"
                } else {
                    "id3.auipc_wrap"
                };
                push_obligation_hit(
                    &mut hits,
                    semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION,
                    insn,
                    "id3",
                    cell,
                );
            }
            _ => {}
        }

        if let Some(class) = class {
            let cell = format!("id4.{class}");
            push_obligation_hit(&mut hits, semantic::exec::OP_SELECTOR_BINDING, insn, "id4", &cell);
        }

        if matches!(
            mnemonic,
            "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai"
        ) {
            if let Some(imm) = insn.imm {
                let cell = if matches!(imm, 255 | 256 | -1 | -2048 | 2047) {
                    "al1.boundary"
                } else if imm < 0 {
                    "al1.negative"
                } else if imm <= 255 {
                    "al1.single_limb"
                } else {
                    "al1.cross_01"
                };
                push_obligation_hit(
                    &mut hits,
                    semantic::alu::IMMEDIATE_LIMB_CONSISTENCY,
                    insn,
                    "al1",
                    cell,
                );
            }
        }

        if matches!(mnemonic, "sll" | "slli" | "srl" | "srli" | "sra" | "srai") {
            let (raw_shamt, effective_shamt) = shift_amount(insn);
            let mut details = base_details(insn, "al2", al2_cell(insn));
            details.insert("raw_shamt".to_string(), json!(raw_shamt));
            details.insert("effective_shamt".to_string(), json!(effective_shamt));
            details.insert("rs2_ge32".to_string(), json!(raw_shamt >= 32));
            hits.push(BucketHit::semantic(semantic::alu::SHIFT_MOD32, details));
        }

        if matches!(mnemonic, "slt" | "slti" | "sltu" | "sltiu") {
            push_obligation_hit(
                &mut hits,
                semantic::alu::COMPARISON_BOOLEANITY,
                insn,
                "al3",
                al3_cell(insn),
            );
            push_obligation_hit(
                &mut hits,
                semantic::alu::COMPARISON_AUXILIARY_CHAIN,
                insn,
                "al5",
                al5_cell(insn),
            );
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
            push_obligation_hit(
                &mut hits,
                semantic::alu::SUBTRACTION_BORROW_CHAIN,
                insn,
                "al4",
                al4_cell(insn),
            );
        }

        match mnemonic {
            "div" | "divu" | "rem" | "remu" => {
                if let Some((obligation_id, cell_id)) = div_special_cell(insn) {
                    push_obligation_hit(
                        &mut hits,
                        semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                        insn,
                        obligation_id,
                        cell_id,
                    );
                } else {
                    push_obligation_hit(
                        &mut hits,
                        semantic::arithmetic::DIVISION_REMAINDER_BOUND,
                        insn,
                        "md3",
                        md3_cell(insn),
                    );
                }
            }
            "mul" | "mulh" | "mulhu" | "mulhsu" => {
                push_obligation_hit(
                    &mut hits,
                    semantic::arithmetic::PRODUCT_DECOMPOSITION,
                    insn,
                    "md4",
                    md4_cell(insn),
                );
                if mnemonic == "mulhsu" {
                    push_obligation_hit(
                        &mut hits,
                        semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION,
                        insn,
                        "md5",
                        md5_cell(insn),
                    );
                }
            }
            _ => {}
        }

        if matches!(mnemonic, "lb" | "lh" | "lw" | "lbu" | "lhu" | "sb" | "sh" | "sw") {
            let is_load = matches!(mnemonic, "lb" | "lh" | "lw" | "lbu" | "lhu");
            let width = match mnemonic {
                "lb" | "lbu" | "sb" => 1,
                "lh" | "lhu" | "sh" => 2,
                _ => 4,
            };
            let cell = if is_load { "me10.load" } else { "me10.store" };
            let mut details = base_details(insn, "me10", cell);
            details.insert("is_load".to_string(), json!(is_load));
            details.insert("is_store".to_string(), json!(!is_load));
            details.insert("width".to_string(), json!(width));
            hits.push(BucketHit::semantic(semantic::memory::KIND_SELECTOR_CONSISTENCY, details));
        }

        match mnemonic {
            "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
                if let Some(cell) = cf1_cell(insn) {
                    push_control_flow_hit(&mut hits, insn, "cf1", cell);
                }
            }
            "jal" | "jalr" => {
                let cell = if mnemonic == "jal" {
                    if rd == Some(0) {
                        "cf2.jal_x0"
                    } else {
                        "cf2.jal_rd"
                    }
                } else if rd == Some(0) {
                    "cf2.jalr_x0"
                } else {
                    "cf2.jalr_rd"
                };
                push_control_flow_hit(&mut hits, insn, "cf2", cell);
                if mnemonic == "jalr" {
                    push_control_flow_hit(&mut hits, insn, "cf3", cf3_cell(insn));
                    if let Some(cell) = cf3_target_cell(insn) {
                        push_control_flow_hit(&mut hits, insn, "cf3", cell);
                    }
                }
            }
            "ecall" => {
                let ecall_cell = if insn.regs_before[17] == 0 {
                    "cf5.halt"
                } else if insn.regs_before[11] == 0 {
                    "cf5.arg_zero"
                } else {
                    "cf5.io_read"
                };
                push_obligation_hit(
                    &mut hits,
                    semantic::control::ECALL_ARGUMENT_DECOMPOSITION,
                    insn,
                    "cf5",
                    ecall_cell,
                );
                push_obligation_hit(
                    &mut hits,
                    semantic::control::ECALL_WORD_VALIDITY,
                    insn,
                    "cf7",
                    "cf7.standard",
                );
            }
            _ => {
                if idx > 0
                    && !matches!(
                        mnemonic,
                        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "jal" | "jalr" | "ecall"
                    )
                    && insn.next_pc == insn.pc.wrapping_add(4)
                {
                    let prev = &instructions[idx - 1];
                    let cell = if matches!(
                        prev.mnemonic.as_str(),
                        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu"
                    ) && prev.next_pc == prev.pc.wrapping_add(4)
                    {
                        "cf6.after_branch_not_taken"
                    } else {
                        "cf6.normal"
                    };
                    let mut details = control_flow_details(insn, "cf6", cell);
                    details.insert("previous_pc".to_string(), json!(prev.pc));
                    details.insert("previous_next_pc".to_string(), json!(prev.next_pc));
                    hits.push(BucketHit::semantic(semantic::exec::CONTROL_FLOW_BINDING, details));
                }
            }
        }
    }

    if let Some(first) = instructions.first() {
        push_obligation_hit(
            &mut hits,
            semantic::control::ENTRYPOINT_BINDING,
            first,
            "cf4",
            "cf4.default_entry",
        );
        push_obligation_hit(
            &mut hits,
            semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
            first,
            "ts1",
            "ts1.standard",
        );
        push_obligation_hit(
            &mut hits,
            semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
            first,
            "ts3",
            "ts3.standard",
        );
    }

    hits
}

impl Risc0Trace {
    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        Self::from_words_with_preflight(words, &[], &[])
    }

    pub fn from_words_with_preflight(
        words: &[u32],
        preflight_txns: &[Risc0PreflightMemoryTxn],
        preflight_summaries: &[Risc0PreflightSegmentSummary],
    ) -> Result<Self, String> {
        Self::from_words_with_preflight_and_executed(
            words,
            &[],
            preflight_txns,
            preflight_summaries,
        )
    }

    pub fn from_words_with_preflight_and_executed(
        words: &[u32],
        executed_records: &[Risc0ExecutedInsnRecord],
        preflight_txns: &[Risc0PreflightMemoryTxn],
        preflight_summaries: &[Risc0PreflightSegmentSummary],
    ) -> Result<Self, String> {
        let instructions = executed_instructions(words)?;
        let sequence = instructions
            .iter()
            .map(|insn| SequenceInsnObservation {
                step_idx: insn.step_idx,
                word: insn.word,
                mnemonic: insn.mnemonic.clone(),
                rs1: insn.rs1,
                imm: insn.imm,
            })
            .collect::<Vec<_>>();
        let trace_signals = semantic_matchers::sequence_trace_signals(&sequence);
        let mut bucket_hits = emit_instruction_obligation_hits(&instructions);
        let preflight_instructions = if executed_records.is_empty() {
            instructions.clone()
        } else {
            preflight_executed_instructions(executed_records, preflight_txns)?
        };
        bucket_hits.extend(emit_preflight_memory_obligation_hits(
            &preflight_instructions,
            preflight_txns,
            preflight_summaries,
        ));

        let instruction_count =
            if executed_records.is_empty() { instructions.len() } else { executed_records.len() };

        Ok(Self { bucket_hits, trace_signals, instruction_count })
    }

    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }
}

impl Trace for Risc0Trace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }

    fn trace_signals(&self) -> &[TraceSignal] {
        &self.trace_signals
    }
}

#[cfg(test)]
mod tests {
    use beak_core::trace::semantic;
    use beak_core::trace::Trace;

    use super::Risc0Trace;

    #[test]
    fn risc0_trace_emits_registered_semantics_with_contract_details() {
        let words = [0x0070_0113, 0x0050_0193, 0x0231_50b3, 0x0000_0073];
        let trace = Risc0Trace::from_words(&words).expect("trace");
        let sigs = trace.bucket_hits().iter().map(|hit| hit.bucket_id.as_str()).collect::<Vec<_>>();
        assert!(sigs.iter().all(|id| semantic::by_id(id).is_some()));
        assert!(sigs.contains(&semantic::decode::RD_BIT_DECOMPOSITION.id));
        assert!(sigs.contains(&semantic::decode::OPERAND_INDEX_ROUTING.id));
        assert!(sigs.contains(&semantic::arithmetic::DIVISION_REMAINDER_BOUND.id));
        assert!(sigs.contains(&semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id));
        assert!(sigs.contains(&semantic::exec::DEST_BINDING.id));
        assert!(trace.bucket_hits().iter().all(|hit| hit.details.contains_key("obligation_id")));
        assert!(trace.bucket_hits().iter().all(|hit| hit.details.contains_key("cell_id")));
        assert!(trace.bucket_hits().iter().all(|hit| hit.details.contains_key("backend")));
    }

    #[test]
    fn risc0_trace_skips_unexecuted_input_words() {
        let words = [0x0080_006f, 0x0010_0093, 0x0020_0113];
        let trace = Risc0Trace::from_words(&words).expect("trace");
        assert!(trace.bucket_hits().iter().all(|hit| hit
            .details
            .get("pc")
            .and_then(|v| v.as_u64())
            != Some(0x0001_0008)));
    }

    #[test]
    fn risc0_shift_cells_use_runtime_and_immediate_shamt() {
        let words = [0x0210_0093, 0x0010_9113, 0x0020_91b3];
        let trace = Risc0Trace::from_words(&words).expect("trace");
        let al2_cells = trace
            .bucket_hits()
            .iter()
            .filter(|hit| hit.bucket_id == semantic::alu::SHIFT_MOD32.id)
            .filter_map(|hit| hit.details.get("cell_id").and_then(|v| v.as_str()))
            .collect::<Vec<_>>();
        assert!(al2_cells.contains(&"al2.sll_lt32"));
        assert!(al2_cells.contains(&"al2.sll_ge32"));
    }

    #[test]
    fn risc0_cf1_skips_non_obligation_beq_bne_complements() {
        let words = [0x0010_0093, 0x0020_0113, 0x0020_8463, 0x0011_8463, 0x0030_0193];
        let trace = Risc0Trace::from_words(&words).expect("trace");
        let cf1_cells = trace
            .bucket_hits()
            .iter()
            .filter(|hit| hit.bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id)
            .filter(|hit| hit.details.get("obligation_id").and_then(|v| v.as_str()) == Some("cf1"))
            .filter_map(|hit| hit.details.get("cell_id").and_then(|v| v.as_str()))
            .collect::<Vec<_>>();
        assert!(!cf1_cells.contains(&"cf1.beq_not_equal"));
        assert!(!cf1_cells.contains(&"cf1.bne_equal"));
    }

    #[test]
    fn risc0_jalr_target_cells_use_executed_register_state() {
        let words = [0x0001_00b7, 0x0110_8093, 0x0000_8067, 0x0010_0113];
        let trace = Risc0Trace::from_words(&words).expect("trace");
        let cf3_cells = trace
            .bucket_hits()
            .iter()
            .filter(|hit| hit.bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id)
            .filter(|hit| hit.details.get("obligation_id").and_then(|v| v.as_str()) == Some("cf3"))
            .filter_map(|hit| hit.details.get("cell_id").and_then(|v| v.as_str()))
            .collect::<Vec<_>>();
        assert!(cf3_cells.contains(&"cf3.imm_zero"));
        assert!(cf3_cells.contains(&"cf3.clear_lsb"));
    }
}
