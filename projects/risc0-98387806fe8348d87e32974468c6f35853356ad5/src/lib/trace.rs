use std::collections::HashMap;

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
        let bucket_hits = emit_instruction_obligation_hits(&instructions);

        Ok(Self { bucket_hits, trace_signals, instruction_count: instructions.len() })
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
