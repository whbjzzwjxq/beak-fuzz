use std::collections::HashMap;

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel, RISCVOracle};
use beak_core::trace::observations::{SequenceInsnObservation, SequenceSemanticMatcherProfile};
use beak_core::trace::{semantic, semantic_matchers, BucketHit, Trace, TraceSignal};
use serde_json::{json, Value};
use sp1_core_executor::{Instruction as SP1Instruction, Opcode, Program};

use crate::chip_row::Sp1ChipRow;
use crate::insn::Sp1Insn;
use crate::interaction::Sp1Interaction;

const SP1_CODE_BASE: u32 = 0x1000;
const BACKEND: &str = "sp1";
const COMMIT: &str = "39ab52fce38172c9d23feed7248198dc14c164a9";
const ORACLE_MAX_TRACE_STEPS: u32 = 1000;

#[derive(Debug, Clone)]
pub struct Sp1Trace {
    instructions: Vec<Sp1Insn>,
    chip_rows: Vec<Sp1ChipRow>,
    interactions: Vec<Sp1Interaction>,
    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,

    insn_by_step: Vec<Option<usize>>,
    chip_rows_by_step: Vec<Vec<usize>>,
    interactions_by_step: Vec<Vec<usize>>,
    interactions_by_row_id: HashMap<String, Vec<usize>>,
}

fn imm_as_u64(imm: i32) -> u32 {
    imm as u32
}

fn op_u64_to_i32(v: u32) -> i32 {
    v as i32
}

fn sp1_trace_oracle_config() -> OracleConfig {
    OracleConfig {
        memory_model: OracleMemoryModel::SplitCodeData,
        code_base: SP1_CODE_BASE,
        data_size_bytes: 0,
    }
}

pub fn build_sp1_program(words: &[u32]) -> Result<Program, String> {
    let mut instructions = Vec::with_capacity(words.len());
    for (idx, &word) in words.iter().enumerate() {
        instructions.push(decode_word_to_sp1_instruction(word).map_err(|e| {
            format!("decode rv32 word to sp1 instruction failed at step {idx}: {e}")
        })?);
    }
    Ok(Program::new(instructions, SP1_CODE_BASE, SP1_CODE_BASE))
}

pub fn decode_word_to_sp1_instruction(word: u32) -> Result<SP1Instruction, String> {
    let dec = RV32IMInstruction::from_word(word).map_err(|e| format!("rv32 decode failed: {e}"))?;
    let m = dec.mnemonic.as_str();

    let req = |name: &str, v: Option<u32>| -> Result<u8, String> {
        v.map(|x| x as u8).ok_or_else(|| format!("missing {name} for {m}"))
    };
    let req_u64 = |name: &str, v: Option<u32>| -> Result<u32, String> {
        v.ok_or_else(|| format!("missing {name} for {m}"))
    };
    let req_imm =
        |v: Option<i32>| -> Result<i32, String> { v.ok_or_else(|| format!("missing imm for {m}")) };

    let insn = match m {
        "add" => SP1Instruction::new(
            Opcode::ADD,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "addi" => SP1Instruction::new(
            Opcode::ADD,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sub" => SP1Instruction::new(
            Opcode::SUB,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "xor" => SP1Instruction::new(
            Opcode::XOR,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "xori" => SP1Instruction::new(
            Opcode::XOR,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "or" => SP1Instruction::new(
            Opcode::OR,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "ori" => SP1Instruction::new(
            Opcode::OR,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "and" => SP1Instruction::new(
            Opcode::AND,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "andi" => SP1Instruction::new(
            Opcode::AND,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sll" => SP1Instruction::new(
            Opcode::SLL,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "slli" => SP1Instruction::new(
            Opcode::SLL,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "srl" => SP1Instruction::new(
            Opcode::SRL,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "srli" => SP1Instruction::new(
            Opcode::SRL,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sra" => SP1Instruction::new(
            Opcode::SRA,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "srai" => SP1Instruction::new(
            Opcode::SRA,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "slt" => SP1Instruction::new(
            Opcode::SLT,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "slti" => SP1Instruction::new(
            Opcode::SLT,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sltu" => SP1Instruction::new(
            Opcode::SLTU,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "sltiu" => SP1Instruction::new(
            Opcode::SLTU,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lb" => SP1Instruction::new(
            Opcode::LB,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lh" => SP1Instruction::new(
            Opcode::LH,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lw" => SP1Instruction::new(
            Opcode::LW,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lbu" => SP1Instruction::new(
            Opcode::LBU,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lhu" => SP1Instruction::new(
            Opcode::LHU,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sb" => SP1Instruction::new(
            Opcode::SB,
            req("rs2", dec.rs2)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sh" => SP1Instruction::new(
            Opcode::SH,
            req("rs2", dec.rs2)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sw" => SP1Instruction::new(
            Opcode::SW,
            req("rs2", dec.rs2)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "beq" => SP1Instruction::new(
            Opcode::BEQ,
            req("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "bne" => SP1Instruction::new(
            Opcode::BNE,
            req("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "blt" => SP1Instruction::new(
            Opcode::BLT,
            req("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "bge" => SP1Instruction::new(
            Opcode::BGE,
            req("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "bltu" => SP1Instruction::new(
            Opcode::BLTU,
            req("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "bgeu" => SP1Instruction::new(
            Opcode::BGEU,
            req("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "jal" => SP1Instruction::new(
            Opcode::JAL,
            req("rd", dec.rd)?,
            imm_as_u64(req_imm(dec.imm)?),
            0,
            true,
            true,
        ),
        "jalr" => SP1Instruction::new(
            Opcode::JALR,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            imm_as_u64(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lui" => SP1Instruction::new(
            Opcode::ADD,
            req("rd", dec.rd)?,
            0,
            imm_as_u64(req_imm(dec.imm)?),
            true,
            true,
        ),
        "auipc" => SP1Instruction::new(
            Opcode::AUIPC,
            req("rd", dec.rd)?,
            imm_as_u64(req_imm(dec.imm)?),
            0,
            true,
            true,
        ),
        "mul" => SP1Instruction::new(
            Opcode::MUL,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "mulh" => SP1Instruction::new(
            Opcode::MULH,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "mulhu" => SP1Instruction::new(
            Opcode::MULHU,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "mulhsu" => SP1Instruction::new(
            Opcode::MULHSU,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "div" => SP1Instruction::new(
            Opcode::DIV,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "divu" => SP1Instruction::new(
            Opcode::DIVU,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "rem" => SP1Instruction::new(
            Opcode::REM,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        "remu" => SP1Instruction::new(
            Opcode::REMU,
            req("rd", dec.rd)?,
            req_u64("rs1", dec.rs1)?,
            req_u64("rs2", dec.rs2)?,
            false,
            false,
        ),
        // SP1 models ECALL with fixed operand registers x5/x10/x11.
        "ecall" => SP1Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        "ebreak" => SP1Instruction::new(Opcode::EBREAK, 0, 0, 0, false, false),
        _ => return Err(format!("unsupported rv32 mnemonic for sp1 executor: {m}")),
    };
    Ok(insn)
}

fn decoded_ops_from_executor_instruction(
    insn: &SP1Instruction,
) -> (Option<u32>, Option<u32>, Option<u32>, Option<i32>) {
    use Opcode::*;

    match insn.opcode {
        ADD | SUB | XOR | OR | AND | SLL | SRL | SRA | SLT | SLTU | MUL | MULH | MULHU | MULHSU
        | DIV | DIVU | REM | REMU => {
            if insn.imm_c {
                (
                    Some(insn.op_a as u32),
                    Some(insn.op_b as u32),
                    None,
                    Some(op_u64_to_i32(insn.op_c)),
                )
            } else {
                (Some(insn.op_a as u32), Some(insn.op_b as u32), Some(insn.op_c as u32), None)
            }
        }
        LB | LH | LW | LBU | LHU => {
            (Some(insn.op_a as u32), Some(insn.op_b as u32), None, Some(op_u64_to_i32(insn.op_c)))
        }
        SB | SH | SW => {
            (None, Some(insn.op_b as u32), Some(insn.op_a as u32), Some(op_u64_to_i32(insn.op_c)))
        }
        BEQ | BNE | BLT | BGE | BLTU | BGEU => {
            (None, Some(insn.op_a as u32), Some(insn.op_b as u32), Some(op_u64_to_i32(insn.op_c)))
        }
        JAL => (Some(insn.op_a as u32), None, None, Some(op_u64_to_i32(insn.op_b))),
        JALR => {
            (Some(insn.op_a as u32), Some(insn.op_b as u32), None, Some(op_u64_to_i32(insn.op_c)))
        }
        AUIPC => (Some(insn.op_a as u32), None, None, Some(op_u64_to_i32(insn.op_b))),
        ECALL | EBREAK | UNIMP => (None, None, None, None),
    }
}

fn asm_from_parts(
    mnemonic: &str,
    rd: Option<u32>,
    rs1: Option<u32>,
    rs2: Option<u32>,
    imm: Option<i32>,
) -> String {
    let fmt_reg = |r: u32| format!("x{r}");
    match mnemonic {
        "sw" | "sh" | "sb" => match (rs2, rs1, imm) {
            (Some(v_rs2), Some(v_rs1), Some(v_imm)) => {
                format!("{mnemonic} {}, {}({})", fmt_reg(v_rs2), v_imm, fmt_reg(v_rs1))
            }
            _ => mnemonic.to_string(),
        },
        "lw" | "lh" | "lb" | "lhu" | "lbu" => match (rd, rs1, imm) {
            (Some(v_rd), Some(v_rs1), Some(v_imm)) => {
                format!("{mnemonic} {}, {}({})", fmt_reg(v_rd), v_imm, fmt_reg(v_rs1))
            }
            _ => mnemonic.to_string(),
        },
        _ => {
            let mut parts = Vec::new();
            if let Some(v) = rd {
                parts.push(fmt_reg(v));
            }
            if let Some(v) = rs1 {
                parts.push(fmt_reg(v));
            }
            if let Some(v) = rs2 {
                parts.push(fmt_reg(v));
            }
            if let Some(v) = imm {
                parts.push(v.to_string());
            }
            if parts.is_empty() {
                mnemonic.to_string()
            } else {
                format!("{mnemonic} {}", parts.join(", "))
            }
        }
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

fn base_details(insn: &Sp1Insn, obligation_id: &str, cell_id: &str) -> HashMap<String, Value> {
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
    details.insert("mnemonic".to_string(), json!(insn.mnemonic));
    if let Some(rd) = insn.rd {
        details.insert("rd".to_string(), json!(rd));
    }
    if let Some(rs1) = insn.rs1 {
        details.insert("rs1".to_string(), json!(rs1));
    }
    if let Some(rs2) = insn.rs2 {
        details.insert("rs2".to_string(), json!(rs2));
    }
    if let Some(imm) = insn.imm {
        details.insert("imm".to_string(), json!(imm));
    }
    details
}

fn push_obligation_hit(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    insn: &Sp1Insn,
    obligation_id: &str,
    cell_id: &str,
) {
    hits.push(BucketHit::semantic(bucket, base_details(insn, obligation_id, cell_id)));
}

fn emit_instruction_obligation_hits(instructions: &[Sp1Insn]) -> Vec<BucketHit> {
    let mut hits = Vec::new();

    for (idx, insn) in instructions.iter().enumerate() {
        let mnemonic = insn.mnemonic.as_str();
        let class = mnemonic_class(mnemonic);
        let rd = insn.rd;
        let rs1 = insn.rs1;
        let rs2 = insn.rs2;

        if let Some(cell) = write_source_cell(mnemonic).filter(|_| rd == Some(0)) {
            push_obligation_hit(
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
                push_obligation_hit(&mut hits, semantic::exec::DEST_BINDING, insn, "rf3", cell);
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
            let cell = match mnemonic {
                "sll" | "slli" => "al2.sll_lt32",
                "srl" | "srli" => "al2.srl_lt32",
                "sra" | "srai" => "al2.sra_lt32_pos",
                _ => "al2.shamt_zero",
            };
            push_obligation_hit(&mut hits, semantic::alu::SHIFT_MOD32, insn, "al2", cell);
        }

        if matches!(mnemonic, "slt" | "slti" | "sltu" | "sltiu") {
            let cell = if matches!(mnemonic, "sltu" | "sltiu") {
                "al3.sltu_false"
            } else {
                "al3.slt_false"
            };
            push_obligation_hit(&mut hits, semantic::alu::COMPARISON_BOOLEANITY, insn, "al3", cell);
            push_obligation_hit(
                &mut hits,
                semantic::alu::COMPARISON_AUXILIARY_CHAIN,
                insn,
                "al5",
                "al5.all_equal",
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
                "al4.no_borrow",
            );
        }

        match mnemonic {
            "div" | "divu" | "rem" | "remu" => {
                push_obligation_hit(
                    &mut hits,
                    semantic::arithmetic::DIVISION_REMAINDER_BOUND,
                    insn,
                    "md3",
                    if matches!(mnemonic, "divu" | "remu") { "md3.unsigned" } else { "md3.pp" },
                );
            }
            "mul" | "mulh" | "mulhu" | "mulhsu" => {
                let cell = match mnemonic {
                    "mul" => "md4.mul_small",
                    "mulh" => "md4.mulh_pp",
                    "mulhu" => "md4.mulhu",
                    "mulhsu" => "md4.mulh_pn",
                    _ => "md4.mul_small",
                };
                push_obligation_hit(
                    &mut hits,
                    semantic::arithmetic::PRODUCT_DECOMPOSITION,
                    insn,
                    "md4",
                    cell,
                );
                if mnemonic == "mulhsu" {
                    push_obligation_hit(
                        &mut hits,
                        semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION,
                        insn,
                        "md5",
                        "md5.pos_any",
                    );
                }
            }
            _ => {}
        }

        if matches!(mnemonic, "lb" | "lh" | "lw" | "lbu" | "lhu" | "sb" | "sh" | "sw") {
            let cell = if matches!(mnemonic, "lb" | "lh" | "lw" | "lbu" | "lhu") {
                "me10.load"
            } else {
                "me10.store"
            };
            push_obligation_hit(
                &mut hits,
                semantic::exec::MEMORY_EFFECT_BINDING,
                insn,
                "me10",
                cell,
            );
        }

        match mnemonic {
            "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
                let taken = insn.next_pc != insn.pc.wrapping_add(4);
                let cell = match mnemonic {
                    "blt" if taken => "cf1.blt_taken",
                    "blt" => "cf1.blt_not_taken",
                    "bge" if taken => "cf1.bge_taken",
                    "bge" => "cf1.bge_not_taken",
                    "bltu" if taken => "cf1.bltu_taken",
                    "bltu" => "cf1.bltu_not_taken",
                    "bgeu" if taken => "cf1.bgeu_taken",
                    "bgeu" => "cf1.bgeu_not_taken",
                    "beq" => "cf1.beq_equal",
                    "bne" => "cf1.bne_not_equal",
                    _ => "cf1.blt_not_taken",
                };
                push_obligation_hit(
                    &mut hits,
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    "cf1",
                    cell,
                );
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
                push_obligation_hit(
                    &mut hits,
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    "cf2",
                    cell,
                );
                if mnemonic == "jalr" {
                    let imm = insn.imm.unwrap_or_default();
                    let cell = if imm == 0 {
                        "cf3.imm_zero"
                    } else if imm < 0 {
                        "cf3.imm_neg"
                    } else {
                        "cf3.imm_pos"
                    };
                    push_obligation_hit(
                        &mut hits,
                        semantic::exec::CONTROL_FLOW_BINDING,
                        insn,
                        "cf3",
                        cell,
                    );
                }
            }
            "ecall" => {
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
                    push_obligation_hit(
                        &mut hits,
                        semantic::exec::CONTROL_FLOW_BINDING,
                        insn,
                        "cf6",
                        cell,
                    );
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

fn enrich_sequence_hit(hit: &mut BucketHit, insn: Option<&Sp1Insn>) {
    let details = &mut hit.details;
    details.entry("backend".to_string()).or_insert_with(|| json!(BACKEND));
    details.entry("commit".to_string()).or_insert_with(|| json!(COMMIT));
    details.entry("trace_source".to_string()).or_insert_with(|| json!("instruction"));
    if let Some(insn) = insn {
        details.entry("op_idx".to_string()).or_insert_with(|| json!(insn.step_idx));
        details.entry("step_idx".to_string()).or_insert_with(|| json!(insn.step_idx));
        details.entry("pc".to_string()).or_insert_with(|| json!(insn.pc));
        details
            .entry("opcode".to_string())
            .or_insert_with(|| json!(format!("0x{:08x}", insn.word)));
        details.entry("mnemonic".to_string()).or_insert_with(|| json!(insn.mnemonic));
    }

    let (obligation_id, cell_id) = match hit.bucket_id.as_str() {
        id if id == semantic::memory::TIMESTAMPED_LOAD_PATH.id => ("ts2", "ts2.small_gap"),
        id if id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id => ("me2", "me2.byte_any"),
        id if id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id => ("me9", "me9.off0"),
        id if id == semantic::memory::LOAD_VALUE_BINDING.id => ("me3", "me3.lbu"),
        id if id == semantic::exec::PARTIAL_WORD_WRITE_CONSISTENCY.id => ("me4", "me4.sb_off0"),
        id if id == semantic::lookup::BOOLEAN_MULTIPLICITY.id => ("bu1", "bu1.real_row"),
        _ => return,
    };
    details.entry("obligation_id".to_string()).or_insert_with(|| json!(obligation_id));
    details.entry("cell_id".to_string()).or_insert_with(|| json!(cell_id));
}

impl Sp1Trace {
    fn ensure_len<T: Default + Clone>(v: &mut Vec<T>, idx: usize) {
        if v.len() <= idx {
            v.resize(idx + 1, T::default());
        }
    }

    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        let executed_steps = RISCVOracle::executed_steps_with_config(
            words,
            sp1_trace_oracle_config(),
            ORACLE_MAX_TRACE_STEPS,
        );
        let mut instructions = Vec::with_capacity(executed_steps.len());
        for executed in executed_steps {
            let exec_insn = decode_word_to_sp1_instruction(executed.word)?;
            let (rd, rs1, rs2, imm) = decoded_ops_from_executor_instruction(&exec_insn);
            let mnemonic = RV32IMInstruction::from_word(executed.word)
                .map(|insn| insn.mnemonic)
                .unwrap_or_else(|_| exec_insn.opcode.mnemonic().to_string());
            let asm = asm_from_parts(&mnemonic, rd, rs1, rs2, imm);
            instructions.push(Sp1Insn {
                seq: executed.step_idx as u64,
                step_idx: executed.step_idx as u64,
                pc: executed.pc,
                timestamp: executed.step_idx,
                next_pc: executed.pc.wrapping_add(4),
                next_timestamp: executed.step_idx.saturating_add(1),
                word: executed.word,
                mnemonic,
                rd,
                rs1,
                rs2,
                imm,
                asm,
            });
        }
        let next_pcs: Vec<u32> =
            instructions.iter().skip(1).map(|insn| insn.pc).chain(std::iter::once(0)).collect();
        for (insn, next_pc) in instructions.iter_mut().zip(next_pcs) {
            if next_pc != 0 {
                insn.next_pc = next_pc;
            }
        }

        let mut insn_by_step = Vec::<Option<usize>>::new();
        let chip_rows_by_step = Vec::<Vec<usize>>::new();
        let interactions_by_step = Vec::<Vec<usize>>::new();
        let interactions_by_row_id = HashMap::<String, Vec<usize>>::new();

        for (i, insn) in instructions.iter().enumerate() {
            let step = insn.step_idx as usize;
            Self::ensure_len(&mut insn_by_step, step);
            insn_by_step[step] = Some(i);
        }

        let mut out = Self {
            instructions,
            chip_rows: Vec::new(),
            interactions: Vec::new(),
            bucket_hits: Vec::new(),
            trace_signals: Vec::new(),
            insn_by_step,
            chip_rows_by_step,
            interactions_by_step,
            interactions_by_row_id,
        };

        let insns = out
            .instructions()
            .iter()
            .map(|insn| SequenceInsnObservation {
                step_idx: insn.step_idx,
                word: insn.word,
                mnemonic: insn.mnemonic.clone(),
                rs1: insn.rs1,
                imm: insn.imm,
            })
            .collect::<Vec<_>>();
        out.trace_signals = semantic_matchers::sequence_trace_signals(&insns);
        out.bucket_hits = semantic_matchers::match_sequence_semantic_hits(
            SequenceSemanticMatcherProfile {
                emit_padding_interaction_send: false,
                emit_boolean_on_store: true,
                emit_boolean_on_load_after_store: false,
                emit_kind_selector: false,
                emit_digest_route: false,
                emit_control_flow_bindings: false,
                emit_memory_alignment: true,
                emit_memory_address_progression: true,
                emit_load_value_binding: true,
                emit_opcode_selector_bindings: false,
                emit_partial_word_write: true,
                emit_ecall_word_validity: false,
            },
            &insns,
        );
        for hit in &mut out.bucket_hits {
            let step = hit.details.get("step_idx").and_then(Value::as_u64);
            let insn = step.and_then(|step| out.instructions.iter().find(|i| i.step_idx == step));
            enrich_sequence_hit(hit, insn);
        }
        out.bucket_hits.extend(emit_instruction_obligation_hits(&out.instructions));
        Ok(out)
    }

    pub fn instructions(&self) -> &[Sp1Insn] {
        &self.instructions
    }

    pub fn chip_rows(&self) -> &[Sp1ChipRow] {
        &self.chip_rows
    }

    pub fn interactions(&self) -> &[Sp1Interaction] {
        &self.interactions
    }

    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    pub fn get_instruction_in_step(&self, step_idx: usize, op_idx: usize) -> &Sp1Insn {
        assert_eq!(op_idx, 0, "Sp1Insn is 1-per-step; op_idx must be 0");
        let i = self.insn_by_step[step_idx].expect("missing instruction for step");
        &self.instructions[i]
    }

    pub fn chip_row_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.chip_rows_by_step.get(step_idx).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn interaction_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.interactions_by_step.get(step_idx).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn interaction_indices_by_row_id(&self, row_id: &str) -> &[usize] {
        self.interactions_by_row_id.get(row_id).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

impl Trace for Sp1Trace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }

    fn trace_signals(&self) -> &[TraceSignal] {
        &self.trace_signals
    }
}
