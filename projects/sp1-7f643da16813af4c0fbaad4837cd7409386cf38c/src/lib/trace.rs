use std::collections::{BTreeMap, HashMap};

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::observations::{SequenceInsnObservation, SequenceSemanticMatcherProfile};
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic, semantic_matchers};
use serde_json::{Value, json};
use sp1_core_executor::{
    events::MemoryRecordEnum, ByteOpcode, ExecutionRecord, Executor, ExecutorMode,
    Instruction as SP1Instruction, Opcode, Program,
};
use sp1_stark::SP1CoreOpts;

use crate::chip_row::{Sp1ChipRow, Sp1ChipRowBase, Sp1ChipRowKind, Sp1ChipRowPayload};
use crate::insn::Sp1Insn;
use crate::interaction::{
    InteractionDirection, Sp1Interaction, Sp1InteractionBase, Sp1InteractionKind,
    Sp1InteractionPayload,
};

const BACKEND: &str = "sp1";
const COMMIT: &str = "7f643da16813af4c0fbaad4837cd7409386cf38c";

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

#[derive(Debug, Clone, Copy, Default)]
struct DecodedOps {
    rd: Option<u32>,
    rs1: Option<u32>,
    rs2: Option<u32>,
    imm: Option<i32>,
}

fn imm_as_u32(imm: i32) -> u32 {
    imm as u32
}

fn reg_as_u8(name: &str, v: Option<u32>, mnemonic: &str) -> Result<u8, String> {
    let raw = v.ok_or_else(|| format!("missing {name} for {mnemonic}"))?;
    u8::try_from(raw).map_err(|_| format!("register {name} out of range for {mnemonic}: {raw}"))
}

fn op_u32_to_i32(v: u32) -> i32 {
    v as i32
}

pub fn build_sp1_program(words: &[u32]) -> Result<Program, String> {
    let mut instructions = Vec::with_capacity(words.len());
    for (idx, &word) in words.iter().enumerate() {
        instructions.push(decode_word_to_sp1_instruction(word).map_err(|e| {
            format!("decode rv32 word to sp1 instruction failed at step {idx}: {e}")
        })?);
    }
    Ok(Program::new(instructions, 0, 0))
}

/// Reconstruct the four registers that determine an SP1 write ECALL from
/// executed CPU rows. x5/x10/x11 are also present on the ECALL row, while x12
/// must be carried forward from earlier executed register writes.
pub(crate) fn executed_ecall_register_states(
    records: &[ExecutionRecord],
) -> BTreeMap<u64, [u32; 4]> {
    let mut registers = [0u32; 32];
    if let Some(record) = records.first() {
        for (idx, register) in registers.iter_mut().enumerate() {
            if let Some(value) = record.program.memory_image.get(&(idx as u32)) {
                *register = *value;
            }
        }
    }

    let mut states = BTreeMap::new();
    let mut step_idx = 0u64;
    for record in records {
        for cpu in &record.cpu_events {
            let instruction = record.program.fetch(cpu.pc);
            if instruction.opcode == Opcode::ECALL {
                let x5 = match cpu.a_record {
                    Some(MemoryRecordEnum::Write(write)) => write.prev_value,
                    _ => registers[5],
                };
                states.insert(step_idx, [x5, cpu.b, cpu.c, registers[12]]);
            }
            if let Some(MemoryRecordEnum::Write(write)) = cpu.a_record {
                let register_idx = instruction.op_a as usize;
                if register_idx < registers.len() {
                    registers[register_idx] = if register_idx == 0 { 0 } else { write.value };
                }
            }
            step_idx = step_idx.saturating_add(1);
        }
    }
    states
}

pub fn decode_word_to_sp1_instruction(word: u32) -> Result<SP1Instruction, String> {
    let dec = RV32IMInstruction::from_word(word).map_err(|e| format!("rv32 decode failed: {e}"))?;
    let m = dec.mnemonic.as_str();

    let req_imm =
        |v: Option<i32>| -> Result<i32, String> { v.ok_or_else(|| format!("missing imm for {m}")) };

    let insn = match m {
        "add" => SP1Instruction::new(
            Opcode::ADD,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "addi" => SP1Instruction::new(
            Opcode::ADD,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sub" => SP1Instruction::new(
            Opcode::SUB,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "xor" => SP1Instruction::new(
            Opcode::XOR,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "xori" => SP1Instruction::new(
            Opcode::XOR,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "or" => SP1Instruction::new(
            Opcode::OR,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "ori" => SP1Instruction::new(
            Opcode::OR,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "and" => SP1Instruction::new(
            Opcode::AND,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "andi" => SP1Instruction::new(
            Opcode::AND,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sll" => SP1Instruction::new(
            Opcode::SLL,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "slli" => SP1Instruction::new(
            Opcode::SLL,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "srl" => SP1Instruction::new(
            Opcode::SRL,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "srli" => SP1Instruction::new(
            Opcode::SRL,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sra" => SP1Instruction::new(
            Opcode::SRA,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "srai" => SP1Instruction::new(
            Opcode::SRA,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "slt" => SP1Instruction::new(
            Opcode::SLT,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "slti" => SP1Instruction::new(
            Opcode::SLT,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sltu" => SP1Instruction::new(
            Opcode::SLTU,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "sltiu" => SP1Instruction::new(
            Opcode::SLTU,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lb" => SP1Instruction::new(
            Opcode::LB,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lh" => SP1Instruction::new(
            Opcode::LH,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lw" => SP1Instruction::new(
            Opcode::LW,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lbu" => SP1Instruction::new(
            Opcode::LBU,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lhu" => SP1Instruction::new(
            Opcode::LHU,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sb" => SP1Instruction::new(
            Opcode::SB,
            reg_as_u8("rs2", dec.rs2, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sh" => SP1Instruction::new(
            Opcode::SH,
            reg_as_u8("rs2", dec.rs2, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "sw" => SP1Instruction::new(
            Opcode::SW,
            reg_as_u8("rs2", dec.rs2, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "beq" => SP1Instruction::new(
            Opcode::BEQ,
            reg_as_u8("rs1", dec.rs1, m)?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "bne" => SP1Instruction::new(
            Opcode::BNE,
            reg_as_u8("rs1", dec.rs1, m)?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "blt" => SP1Instruction::new(
            Opcode::BLT,
            reg_as_u8("rs1", dec.rs1, m)?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "bge" => SP1Instruction::new(
            Opcode::BGE,
            reg_as_u8("rs1", dec.rs1, m)?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "bltu" => SP1Instruction::new(
            Opcode::BLTU,
            reg_as_u8("rs1", dec.rs1, m)?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "bgeu" => SP1Instruction::new(
            Opcode::BGEU,
            reg_as_u8("rs1", dec.rs1, m)?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "jal" => SP1Instruction::new(
            Opcode::JAL,
            reg_as_u8("rd", dec.rd, m)?,
            imm_as_u32(req_imm(dec.imm)?),
            0,
            true,
            true,
        ),
        "jalr" => SP1Instruction::new(
            Opcode::JALR,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            imm_as_u32(req_imm(dec.imm)?),
            false,
            true,
        ),
        "lui" => SP1Instruction::new(
            Opcode::ADD,
            reg_as_u8("rd", dec.rd, m)?,
            0,
            imm_as_u32(req_imm(dec.imm)?),
            true,
            true,
        ),
        "auipc" => SP1Instruction::new(
            Opcode::AUIPC,
            reg_as_u8("rd", dec.rd, m)?,
            imm_as_u32(req_imm(dec.imm)?),
            0,
            true,
            true,
        ),
        "mul" => SP1Instruction::new(
            Opcode::MUL,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "mulh" => SP1Instruction::new(
            Opcode::MULH,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "mulhu" => SP1Instruction::new(
            Opcode::MULHU,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "mulhsu" => SP1Instruction::new(
            Opcode::MULHSU,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "div" => SP1Instruction::new(
            Opcode::DIV,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "divu" => SP1Instruction::new(
            Opcode::DIVU,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "rem" => SP1Instruction::new(
            Opcode::REM,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
            false,
            false,
        ),
        "remu" => SP1Instruction::new(
            Opcode::REMU,
            reg_as_u8("rd", dec.rd, m)?,
            dec.rs1.ok_or_else(|| format!("missing rs1 for {m}"))?,
            dec.rs2.ok_or_else(|| format!("missing rs2 for {m}"))?,
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

fn decoded_ops_from_executor_instruction(insn: &SP1Instruction) -> DecodedOps {
    use Opcode::*;

    match insn.opcode {
        ADD | SUB | XOR | OR | AND | SLL | SRL | SRA | SLT | SLTU | MUL | MULH | MULHU | MULHSU
        | DIV | DIVU | REM | REMU => {
            if insn.imm_c {
                DecodedOps {
                    rd: Some(insn.op_a.into()),
                    rs1: Some(insn.op_b),
                    rs2: None,
                    imm: Some(op_u32_to_i32(insn.op_c)),
                }
            } else {
                DecodedOps {
                    rd: Some(insn.op_a.into()),
                    rs1: Some(insn.op_b),
                    rs2: Some(insn.op_c),
                    imm: None,
                }
            }
        }
        LB | LH | LW | LBU | LHU => DecodedOps {
            rd: Some(insn.op_a.into()),
            rs1: Some(insn.op_b),
            rs2: None,
            imm: Some(op_u32_to_i32(insn.op_c)),
        },
        SB | SH | SW => DecodedOps {
            rd: None,
            rs1: Some(insn.op_b),
            rs2: Some(insn.op_a.into()),
            imm: Some(op_u32_to_i32(insn.op_c)),
        },
        BEQ | BNE | BLT | BGE | BLTU | BGEU => DecodedOps {
            rd: None,
            rs1: Some(insn.op_a.into()),
            rs2: Some(insn.op_b),
            imm: Some(op_u32_to_i32(insn.op_c)),
        },
        JAL => DecodedOps {
            rd: Some(insn.op_a.into()),
            rs1: None,
            rs2: None,
            imm: Some(op_u32_to_i32(insn.op_b)),
        },
        JALR => DecodedOps {
            rd: Some(insn.op_a.into()),
            rs1: Some(insn.op_b),
            rs2: None,
            imm: Some(op_u32_to_i32(insn.op_c)),
        },
        AUIPC => DecodedOps {
            rd: Some(insn.op_a.into()),
            rs1: None,
            rs2: None,
            imm: Some(op_u32_to_i32(insn.op_b)),
        },
        ECALL | EBREAK | UNIMP => DecodedOps::default(),
    }
}

fn asm_from_parts(mnemonic: &str, ops: DecodedOps) -> String {
    let fmt_reg = |r: u32| format!("x{r}");
    match mnemonic {
        "sw" | "sh" | "sb" => match (ops.rs2, ops.rs1, ops.imm) {
            (Some(rs2), Some(rs1), Some(imm)) => {
                format!("{mnemonic} {}, {}({})", fmt_reg(rs2), imm, fmt_reg(rs1))
            }
            _ => mnemonic.to_string(),
        },
        "lw" | "lh" | "lb" | "lhu" | "lbu" => match (ops.rd, ops.rs1, ops.imm) {
            (Some(rd), Some(rs1), Some(imm)) => {
                format!("{mnemonic} {}, {}({})", fmt_reg(rd), imm, fmt_reg(rs1))
            }
            _ => mnemonic.to_string(),
        },
        _ => {
            let mut parts = Vec::new();
            if let Some(rd) = ops.rd {
                parts.push(fmt_reg(rd));
            }
            if let Some(rs1) = ops.rs1 {
                parts.push(fmt_reg(rs1));
            }
            if let Some(rs2) = ops.rs2 {
                parts.push(fmt_reg(rs2));
            }
            if let Some(imm) = ops.imm {
                parts.push(imm.to_string());
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
    details.insert("next_pc".to_string(), json!(insn.next_pc));
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
    if let Some(rd_val) = insn.rd_val {
        details.insert("rd_val".to_string(), json!(rd_val));
    }
    if let Some(rs1_val) = insn.rs1_val {
        details.insert("rs1_val".to_string(), json!(rs1_val));
    }
    if let Some(rs2_or_imm_val) = insn.rs2_or_imm_val {
        details.insert("rs2_or_imm_val".to_string(), json!(rs2_or_imm_val));
    }
    if let Some([x5, x10, x11, x12]) = insn.ecall_registers {
        details.insert("control_flow_family".to_string(), json!("ecall"));
        details.insert("expected_next_pc".to_string(), json!(insn.pc.wrapping_add(4)));
        details.insert("ecall_x5".to_string(), json!(x5));
        details.insert("ecall_x10".to_string(), json!(x10));
        details.insert("ecall_x11".to_string(), json!(x11));
        details.insert("ecall_x12".to_string(), json!(x12));
        details.insert(
            "ecall_registers".to_string(),
            json!({"x5": x5, "x10": x10, "x11": x11, "x12": x12}),
        );
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

#[derive(Debug, Clone)]
struct MemoryAccessObservation {
    insn_idx: usize,
    memory_hook_step: u64,
    effective_ptr: u32,
    aligned_ptr: u32,
    byte_offset: u32,
    width: u32,
    is_load: bool,
    is_store: bool,
    value: u32,
    prev_value: u32,
    shard: u32,
    prev_shard: u32,
    timestamp: u32,
    previous_timestamp: u32,
}

impl MemoryAccessObservation {
    fn start(&self) -> u64 {
        self.effective_ptr as u64
    }

    fn end(&self) -> u64 {
        self.start().saturating_add(self.width as u64)
    }
}

fn memory_width_for_opcode(opcode: Opcode) -> Option<u32> {
    match opcode {
        Opcode::LB | Opcode::LBU | Opcode::SB => Some(1),
        Opcode::LH | Opcode::LHU | Opcode::SH => Some(2),
        Opcode::LW | Opcode::SW => Some(4),
        _ => None,
    }
}

fn memory_access_details(
    insn: &Sp1Insn,
    obligation_id: &str,
    cell_id: &str,
    obs: &MemoryAccessObservation,
) -> HashMap<String, Value> {
    let mut details = base_details(insn, obligation_id, cell_id);
    details.insert("trace_source".to_string(), json!("memory_instr_event"));
    details.insert("memory_hook_step".to_string(), json!(obs.memory_hook_step));
    details.insert("memory_row_idx".to_string(), json!(obs.memory_hook_step));
    details.insert("effective_ptr".to_string(), json!(obs.effective_ptr));
    details.insert("aligned_ptr".to_string(), json!(obs.aligned_ptr));
    details.insert("byte_offset".to_string(), json!(obs.byte_offset));
    details.insert("width".to_string(), json!(obs.width));
    details.insert("is_load".to_string(), json!(obs.is_load));
    details.insert("is_store".to_string(), json!(obs.is_store));
    details.insert("address_space".to_string(), json!("memory"));
    details.insert("timestamp".to_string(), json!(obs.timestamp));
    details.insert("previous_timestamp".to_string(), json!(obs.previous_timestamp));
    details.insert("shard".to_string(), json!(obs.shard));
    details.insert("previous_shard".to_string(), json!(obs.prev_shard));
    if obs.is_load {
        details.insert("read_data".to_string(), json!(obs.value));
    }
    if obs.is_store {
        details.insert("write_data".to_string(), json!(obs.value));
        details.insert("prev_data".to_string(), json!(obs.prev_value));
    }
    details
}

fn push_memory_hit(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    insn: &Sp1Insn,
    obligation_id: &str,
    cell_id: &str,
    obs: &MemoryAccessObservation,
) {
    hits.push(BucketHit::semantic(
        bucket,
        memory_access_details(insn, obligation_id, cell_id, obs),
    ));
}

fn load_value_cell(mnemonic: &str, value: u32, byte_offset: u32) -> Option<&'static str> {
    match mnemonic {
        "lb" => {
            let byte = value.to_le_bytes()[byte_offset as usize];
            Some(if byte & 0x80 == 0 { "me3.lb_pos" } else { "me3.lb_neg" })
        }
        "lh" => {
            let half = if byte_offset < 2 { value & 0xffff } else { value >> 16 };
            Some(if half & 0x8000 == 0 { "me3.lh_pos" } else { "me3.lh_neg" })
        }
        "lbu" => Some("me3.lbu"),
        "lhu" => Some("me3.lhu"),
        _ => None,
    }
}

fn write_payload_cell(mnemonic: &str, byte_offset: u32) -> Option<&'static str> {
    match (mnemonic, byte_offset) {
        ("sb", 0) => Some("me4.sb_off0"),
        ("sb", 1) => Some("me4.sb_off1"),
        ("sb", 2) => Some("me4.sb_off2"),
        ("sb", 3) => Some("me4.sb_off3"),
        ("sh", 0) => Some("me4.sh_off0"),
        ("sh", 2) => Some("me4.sh_off2"),
        _ => None,
    }
}

fn alignment_cell(width: u32, byte_offset: u32) -> Option<&'static str> {
    match (width, byte_offset) {
        (1, _) => Some("me2.byte_any"),
        (2, 1) | (2, 3) => Some("me2.half_off1"),
        (4, 1) => Some("me2.word_off1"),
        (4, 2) => Some("me2.word_off2"),
        (4, 3) => Some("me2.word_off3"),
        _ => None,
    }
}

fn boundary_cell(mnemonic: &str, effective_ptr: u32) -> Option<&'static str> {
    match mnemonic {
        "lw" if effective_ptr >= 0xffff_fffc => Some("me6.near_max_lw"),
        "sw" if effective_ptr >= 0xffff_fffc => Some("me6.near_max_sw"),
        "lh" | "lhu" if effective_ptr >= 0xffff_fffe => Some("me6.near_max_lh"),
        "sb" if effective_ptr == u32::MAX => Some("me6.near_max_sb"),
        _ => None,
    }
}

fn ranges_overlap(a: &MemoryAccessObservation, b: &MemoryAccessObservation) -> bool {
    a.start() < b.end() && b.start() < a.end()
}

fn store_load_cell(
    store: &MemoryAccessObservation,
    load: &MemoryAccessObservation,
    store_mnemonic: &str,
    load_mnemonic: &str,
    overwrite: bool,
) -> Option<&'static str> {
    if overwrite {
        return Some("me1.overwrite");
    }
    match (store_mnemonic, load_mnemonic, store.width, load.width) {
        ("sw", "lw", 4, 4) if store.effective_ptr == load.effective_ptr => Some("me1.sw_lw"),
        ("sb", "lb" | "lbu", 1, 1) if store.effective_ptr == load.effective_ptr => {
            Some("me1.sb_lb")
        }
        ("sh", "lh" | "lhu", 2, 2) if store.effective_ptr == load.effective_ptr => {
            Some("me1.sh_lh")
        }
        ("sb", "lw", 1, 4) if ranges_overlap(store, load) => Some("me1.sb_lw"),
        ("sw", "lb" | "lbu", 4, 1) if ranges_overlap(store, load) => Some("me1.sw_lb"),
        ("sw", "lhu", 4, 2) if ranges_overlap(store, load) => Some("me1.sw_lhu"),
        _ => None,
    }
}

fn byte_lookup_step(row: usize, opcode_index: usize) -> u64 {
    (row as u64).saturating_mul(9).saturating_add(opcode_index as u64)
}

fn syscall_instr_padded_rows(real_rows: usize) -> usize {
    if real_rows == 0 { 0 } else { real_rows.next_power_of_two().max(16) }
}

fn emit_syscall_instr_padding_hits(records: &[ExecutionRecord]) -> Vec<BucketHit> {
    let mut hits = Vec::new();
    for (record_idx, record) in records.iter().enumerate() {
        let real_rows = record.syscall_events.len();
        let padded_rows = syscall_instr_padded_rows(real_rows);
        if padded_rows <= real_rows {
            continue;
        }
        let row_idx = real_rows as u64;
        let mut details = HashMap::new();
        details.insert("obligation_id".to_string(), json!("pd1"));
        details.insert("cell_id".to_string(), json!("pd1.lookup_padding"));
        details.insert("backend".to_string(), json!(BACKEND));
        details.insert("commit".to_string(), json!(COMMIT));
        details.insert("trace_source".to_string(), json!("syscall_instruction_padding"));
        details.insert("table_name".to_string(), json!("SyscallInstrs"));
        details.insert("interaction_kind".to_string(), json!("syscall_local"));
        details.insert("send_to_table_source".to_string(), json!("op_a_access.prev_value.byte1"));
        details.insert("step_idx".to_string(), json!(row_idx));
        details.insert("row_idx".to_string(), json!(row_idx));
        details.insert("record_idx".to_string(), json!(record_idx));
        details.insert("real_rows".to_string(), json!(real_rows));
        details.insert("padded_rows".to_string(), json!(padded_rows));
        details.insert("padding_rows".to_string(), json!(padded_rows - real_rows));
        details.insert("is_real".to_string(), json!(false));
        details.insert("is_padding".to_string(), json!(true));
        details.insert("strict_candidate".to_string(), json!(true));
        hits.push(BucketHit::semantic(semantic::row::PADDING_INTERACTION_SEND, details));
    }
    hits
}

fn emit_memory_event_obligation_hits(
    records: &[ExecutionRecord],
    instructions: &[Sp1Insn],
) -> Vec<BucketHit> {
    let mut hits = Vec::new();
    let insn_by_pc_clk = instructions
        .iter()
        .enumerate()
        .map(|(idx, insn)| ((insn.pc, insn.timestamp), idx))
        .collect::<HashMap<_, _>>();

    let mut observations = Vec::<MemoryAccessObservation>::new();
    let mut memory_hook_step = 0u64;
    for record in records {
        for event in &record.memory_instr_events {
            let Some(width) = memory_width_for_opcode(event.opcode) else {
                memory_hook_step = memory_hook_step.saturating_add(1);
                continue;
            };
            let Some(&insn_idx) = insn_by_pc_clk.get(&(event.pc, event.clk)) else {
                memory_hook_step = memory_hook_step.saturating_add(1);
                continue;
            };
            let current = event.mem_access.current_record();
            let previous = event.mem_access.previous_record();
            let effective_ptr = event.b.wrapping_add(event.c);
            observations.push(MemoryAccessObservation {
                insn_idx,
                memory_hook_step,
                effective_ptr,
                aligned_ptr: effective_ptr.wrapping_sub(effective_ptr % 4),
                byte_offset: effective_ptr % 4,
                width,
                is_load: matches!(
                    event.opcode,
                    Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW
                ),
                is_store: matches!(event.opcode, Opcode::SB | Opcode::SH | Opcode::SW),
                value: current.value,
                prev_value: previous.value,
                shard: current.shard,
                prev_shard: previous.shard,
                timestamp: current.timestamp,
                previous_timestamp: previous.timestamp,
            });
            memory_hook_step = memory_hook_step.saturating_add(1);
        }
    }

    let mut prior_stores = Vec::<MemoryAccessObservation>::new();
    let mut store_counts_by_word = HashMap::<u32, u64>::new();
    for obs in &observations {
        let insn = &instructions[obs.insn_idx];
        if let Some(cell) = alignment_cell(obs.width, obs.byte_offset) {
            push_memory_hit(
                &mut hits,
                semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                insn,
                "me2",
                cell,
                obs,
            );
        }
        let offset_cell = match obs.byte_offset {
            0 => "me9.off0",
            1 => "me9.off1",
            2 => "me9.off2",
            _ => "me9.off3",
        };
        push_memory_hit(
            &mut hits,
            semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY,
            insn,
            "me9",
            offset_cell,
            obs,
        );
        if let Some(cell) = boundary_cell(insn.mnemonic.as_str(), obs.effective_ptr) {
            push_memory_hit(
                &mut hits,
                semantic::memory::ADDRESS_BOUNDARY_RANGE,
                insn,
                "me6",
                cell,
                obs,
            );
        }
        let kind_cell = if obs.is_load { "me10.load" } else { "me10.store" };
        push_memory_hit(
            &mut hits,
            semantic::memory::KIND_SELECTOR_CONSISTENCY,
            insn,
            "me10",
            kind_cell,
            obs,
        );
        if obs.timestamp > obs.previous_timestamp {
            let ts_diff = obs.timestamp.saturating_sub(obs.previous_timestamp);
            let cell = if ts_diff == 1 {
                "ts2.consecutive"
            } else if ts_diff >= 1024 {
                "ts2.large_gap"
            } else {
                "ts2.small_gap"
            };
            let mut details = memory_access_details(insn, "ts2", cell, obs);
            details.insert("ts_diff".to_string(), json!(ts_diff));
            hits.push(BucketHit::semantic(semantic::time::MONOTONIC_ACCESS_ORDERING, details));
        }

        if obs.is_load {
            if let Some(cell) = load_value_cell(insn.mnemonic.as_str(), obs.value, obs.byte_offset)
            {
                push_memory_hit(
                    &mut hits,
                    semantic::memory::LOAD_VALUE_BINDING,
                    insn,
                    "me3",
                    cell,
                    obs,
                );
            }
            if obs.previous_timestamp <= 1
                && obs.prev_value == 0
                && !prior_stores.iter().any(|store| ranges_overlap(store, obs))
            {
                let mut details = memory_access_details(insn, "me7", "me7.bss_zero", obs);
                details.insert("no_prior_write".to_string(), json!(true));
                hits.push(BucketHit::semantic(semantic::memory::INITIAL_VALUE_BINDING, details));
            }
            if let Some(store) = prior_stores.iter().rev().find(|store| ranges_overlap(store, obs))
            {
                let store_insn = &instructions[store.insn_idx];
                let overwrite =
                    store_counts_by_word.get(&store.aligned_ptr).copied().unwrap_or(0) > 1;
                if let Some(cell) = store_load_cell(
                    store,
                    obs,
                    store_insn.mnemonic.as_str(),
                    insn.mnemonic.as_str(),
                    overwrite,
                ) {
                    let mut details = memory_access_details(insn, "me1", cell, obs);
                    details.insert("store_step_idx".to_string(), json!(store.memory_hook_step));
                    details.insert("store_pc".to_string(), json!(store_insn.pc));
                    details.insert("store_mnemonic".to_string(), json!(store_insn.mnemonic));
                    details.insert("write_data".to_string(), json!(store.value));
                    hits.push(BucketHit::semantic(
                        semantic::memory::STORE_LOAD_PAYLOAD_FLOW,
                        details,
                    ));
                }
            }
        }

        if obs.is_store {
            if let Some(cell) = write_payload_cell(insn.mnemonic.as_str(), obs.byte_offset) {
                push_memory_hit(
                    &mut hits,
                    semantic::memory::WRITE_PAYLOAD_CONSISTENCY,
                    insn,
                    "me4",
                    cell,
                    obs,
                );
            }
            *store_counts_by_word.entry(obs.aligned_ptr).or_default() += 1;
            prior_stores.push(obs.clone());
        }
    }

    for record in records {
        for (lookup, mult) in &record.byte_lookups {
            if *mult == 0 {
                continue;
            }
            let row = if lookup.opcode != ByteOpcode::U16Range {
                (((lookup.b as u16) << 8) + lookup.c as u16) as usize
            } else {
                lookup.a1 as usize
            };
            let opcode_index = lookup.opcode as usize;
            let cell = if *mult == 1 { "bu1.real_row" } else { "bu1.multi_send" };
            let mut details = HashMap::new();
            details.insert("obligation_id".to_string(), json!("bu1"));
            details.insert("cell_id".to_string(), json!(cell));
            details.insert("backend".to_string(), json!(BACKEND));
            details.insert("commit".to_string(), json!(COMMIT));
            details.insert("trace_source".to_string(), json!("byte_lookup"));
            details.insert("op_idx".to_string(), json!(byte_lookup_step(row, opcode_index)));
            details
                .insert("byte_lookup_step".to_string(), json!(byte_lookup_step(row, opcode_index)));
            details.insert("byte_lookup_row".to_string(), json!(row));
            details.insert("byte_lookup_opcode_index".to_string(), json!(opcode_index));
            details.insert("byte_opcode".to_string(), json!(format!("{:?}", lookup.opcode)));
            details.insert("multiplicity".to_string(), json!(*mult));
            hits.push(BucketHit::semantic(semantic::lookup::BOOLEAN_MULTIPLICITY, details));
        }
    }

    let mut initial_values = HashMap::<u32, u32>::new();
    let mut init_conflict = false;
    for record in records {
        for event in &record.global_memory_initialize_events {
            if event.used == 0 {
                continue;
            }
            if initial_values.insert(event.addr, event.value).is_some() {
                init_conflict = true;
            }
        }
    }
    if !initial_values.is_empty() && !init_conflict {
        let mut details = HashMap::new();
        details.insert("obligation_id".to_string(), json!("me8"));
        details.insert("cell_id".to_string(), json!("me8.no_conflict"));
        details.insert("backend".to_string(), json!(BACKEND));
        details.insert("commit".to_string(), json!(COMMIT));
        details.insert("trace_source".to_string(), json!("memory_initialization"));
        details.insert("op_idx".to_string(), json!(0));
        details.insert("memory_init_count".to_string(), json!(initial_values.len()));
        hits.push(BucketHit::semantic(semantic::memory::INITIAL_VALUE_BINDING, details));
    }

    for record in records {
        for event in &record.global_memory_finalize_events {
            if event.used == 0 {
                continue;
            }
            let initial = initial_values.get(&event.addr).copied().unwrap_or(0);
            let Some(cell) = (if event.value != initial || event.timestamp > 1 {
                Some("me11.written_cells")
            } else if initial_values.contains_key(&event.addr) {
                Some("me11.read_only_cells")
            } else {
                None
            }) else {
                continue;
            };
            let mut details = HashMap::new();
            details.insert("obligation_id".to_string(), json!("me11"));
            details.insert("cell_id".to_string(), json!(cell));
            details.insert("backend".to_string(), json!(BACKEND));
            details.insert("commit".to_string(), json!(COMMIT));
            details.insert("trace_source".to_string(), json!("memory_finalization"));
            details.insert("op_idx".to_string(), json!(event.timestamp));
            details.insert("pointer".to_string(), json!(event.addr));
            details.insert("effective_ptr".to_string(), json!(event.addr));
            details.insert("address_space".to_string(), json!("memory"));
            details.insert("timestamp".to_string(), json!(event.timestamp));
            details.insert("value".to_string(), json!(event.value));
            details.insert("initial_value".to_string(), json!(initial));
            details
                .insert("was_initial".to_string(), json!(initial_values.contains_key(&event.addr)));
            details.insert("changed_from_initial".to_string(), json!(event.value != initial));
            hits.push(BucketHit::semantic(semantic::memory::FINALIZATION_CONSISTENCY, details));
        }
    }

    hits
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
                let divisor = insn.rs2_or_imm_val;
                let signed_overflow = matches!(mnemonic, "div" | "rem")
                    && insn.rs1_val == Some(0x8000_0000)
                    && divisor == Some(u32::MAX);
                if divisor == Some(0) {
                    let cell = match mnemonic {
                        "div" => "md1.div_zero",
                        "divu" => "md1.divu_zero",
                        "rem" => "md1.rem_zero",
                        "remu" => "md1.remu_zero",
                        _ => "md1.zero",
                    };
                    push_obligation_hit(
                        &mut hits,
                        semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                        insn,
                        "md1",
                        cell,
                    );
                } else if signed_overflow {
                    push_obligation_hit(
                        &mut hits,
                        semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                        insn,
                        "md2",
                        if mnemonic == "div" { "md2.div_overflow" } else { "md2.rem_overflow" },
                    );
                } else {
                    push_obligation_hit(
                        &mut hits,
                        semantic::arithmetic::DIVISION_REMAINDER_BOUND,
                        insn,
                        "md3",
                        if matches!(mnemonic, "divu" | "remu") { "md3.unsigned" } else { "md3.pp" },
                    );
                }
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
                    if rd == Some(0) { "cf2.jal_x0" } else { "cf2.jal_rd" }
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
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    "cf6",
                    "cf6.normal",
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
        id if id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id => ("me10", "me10.load"),
        id if id == semantic::lookup::BOOLEAN_MULTIPLICITY.id => ("bu1", "bu1.real_row"),
        id if id == semantic::row::PADDING_INTERACTION_SEND.id => ("pd1", "pd1.short_trace"),
        id if id == semantic::interaction::DIGEST_KIND_ROUTE.id => ("bu6", "bu6.digest_route"),
        id if id == semantic::exec::CONTROL_FLOW_BINDING.id => ("cf6", "cf6.normal"),
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
        let program = build_sp1_program(words)?;
        let mut executor = Executor::new(program, SP1CoreOpts::default());
        executor.executor_mode = ExecutorMode::Trace;
        executor.run().map_err(|e| format!("sp1 executor run failed while building trace: {e}"))?;
        let records = std::mem::take(&mut executor.records);
        Self::from_execution_records(words, &records)
    }

    pub fn from_execution_records(
        words: &[u32],
        records: &[ExecutionRecord],
    ) -> Result<Self, String> {
        let ecall_register_states = executed_ecall_register_states(records);
        let mut instructions = Vec::new();
        let mut chip_rows = Vec::new();
        let mut interactions = Vec::new();

        let mut seq = 0u64;
        let mut step_idx = 0u64;

        for record in records {
            for cpu in &record.cpu_events {
                let fallback = if cpu.pc % 4 == 0 {
                    words.get((cpu.pc / 4) as usize).copied().unwrap_or_default()
                } else {
                    0
                };
                let executor_instruction = record.program.fetch(cpu.pc);
                let mnemonic = executor_instruction.opcode.mnemonic().to_string();

                let insn = if fallback != 0 {
                    if let Ok(dec) = RV32IMInstruction::from_word(fallback) {
                        Sp1Insn {
                            seq,
                            step_idx,
                            pc: cpu.pc,
                            timestamp: cpu.clk,
                            next_pc: cpu.next_pc,
                            next_timestamp: cpu.clk.saturating_add(1),
                            word: dec.word,
                            mnemonic: dec.mnemonic,
                            rd: dec.rd,
                            rs1: dec.rs1,
                            rs2: dec.rs2,
                            imm: dec.imm,
                            rd_val: Some(cpu.a),
                            rs1_val: Some(cpu.b),
                            rs2_or_imm_val: Some(cpu.c),
                            ecall_registers: ecall_register_states.get(&step_idx).copied(),
                            asm: dec.asm,
                        }
                    } else {
                        let ops = decoded_ops_from_executor_instruction(executor_instruction);
                        Sp1Insn {
                            seq,
                            step_idx,
                            pc: cpu.pc,
                            timestamp: cpu.clk,
                            next_pc: cpu.next_pc,
                            next_timestamp: cpu.clk.saturating_add(1),
                            word: fallback,
                            mnemonic: mnemonic.clone(),
                            rd: ops.rd,
                            rs1: ops.rs1,
                            rs2: ops.rs2,
                            imm: ops.imm,
                            rd_val: Some(cpu.a),
                            rs1_val: Some(cpu.b),
                            rs2_or_imm_val: Some(cpu.c),
                            ecall_registers: ecall_register_states.get(&step_idx).copied(),
                            asm: asm_from_parts(&mnemonic, ops),
                        }
                    }
                } else {
                    let ops = decoded_ops_from_executor_instruction(executor_instruction);
                    Sp1Insn {
                        seq,
                        step_idx,
                        pc: cpu.pc,
                        timestamp: cpu.clk,
                        next_pc: cpu.next_pc,
                        next_timestamp: cpu.clk.saturating_add(1),
                        word: 0,
                        mnemonic: mnemonic.clone(),
                        rd: ops.rd,
                        rs1: ops.rs1,
                        rs2: ops.rs2,
                        imm: ops.imm,
                        rd_val: Some(cpu.a),
                        rs1_val: Some(cpu.b),
                        rs2_or_imm_val: Some(cpu.c),
                        ecall_registers: ecall_register_states.get(&step_idx).copied(),
                        asm: asm_from_parts(&mnemonic, ops),
                    }
                };
                instructions.push(insn.clone());
                seq = seq.saturating_add(1);

                chip_rows.push(Sp1ChipRow {
                    base: Sp1ChipRowBase {
                        seq,
                        step_idx,
                        op_idx: 0,
                        is_valid: true,
                        timestamp: Some(cpu.clk),
                        chip_name: "sp1_cpu".to_string(),
                    },
                    kind: Sp1ChipRowKind::Cpu,
                    payload: Sp1ChipRowPayload::Cpu {
                        mnemonic: insn.mnemonic.clone(),
                        rd: insn.rd,
                        rs1: insn.rs1,
                        rs2: insn.rs2,
                        imm: insn.imm,
                    },
                });
                seq = seq.saturating_add(1);

                interactions.push(Sp1Interaction {
                    base: Sp1InteractionBase {
                        seq,
                        step_idx,
                        op_idx: 0,
                        row_id: format!("step{step_idx}_cpu0"),
                        direction: InteractionDirection::Send,
                        kind: Sp1InteractionKind::Execution,
                        timestamp: Some(cpu.clk),
                    },
                    payload: Sp1InteractionPayload::Execution { pc: cpu.pc },
                });
                seq = seq.saturating_add(1);

                let is_load = matches!(insn.mnemonic.as_str(), "lb" | "lh" | "lw" | "lbu" | "lhu");
                let is_store = matches!(insn.mnemonic.as_str(), "sb" | "sh" | "sw");
                if is_load || is_store {
                    chip_rows.push(Sp1ChipRow {
                        base: Sp1ChipRowBase {
                            seq,
                            step_idx,
                            op_idx: 1,
                            is_valid: true,
                            timestamp: Some(cpu.clk),
                            chip_name: "sp1_memory".to_string(),
                        },
                        kind: Sp1ChipRowKind::Memory,
                        payload: Sp1ChipRowPayload::Memory {
                            is_load,
                            is_store,
                            base_reg: insn.rs1,
                            offset: insn.imm,
                        },
                    });
                    seq = seq.saturating_add(1);

                    let effective_addr = match (insn.rs1, insn.imm) {
                        (Some(0), Some(imm)) => Some(imm as u32),
                        _ => None,
                    };
                    interactions.push(Sp1Interaction {
                        base: Sp1InteractionBase {
                            seq,
                            step_idx,
                            op_idx: 1,
                            row_id: format!("step{step_idx}_mem1"),
                            direction: InteractionDirection::Send,
                            kind: Sp1InteractionKind::Memory,
                            timestamp: Some(cpu.clk),
                        },
                        payload: Sp1InteractionPayload::Memory { effective_addr },
                    });
                    seq = seq.saturating_add(1);
                }

                step_idx = step_idx.saturating_add(1);
            }
        }

        let mut out = Self::new(instructions, chip_rows, interactions);
        out.bucket_hits.extend(emit_memory_event_obligation_hits(records, &out.instructions));
        out.bucket_hits.extend(emit_syscall_instr_padding_hits(records));
        Ok(out)
    }

    pub fn new(
        instructions: Vec<Sp1Insn>,
        chip_rows: Vec<Sp1ChipRow>,
        interactions: Vec<Sp1Interaction>,
    ) -> Self {
        let mut insn_by_step = Vec::<Option<usize>>::new();
        let mut chip_rows_by_step = Vec::<Vec<usize>>::new();
        let mut interactions_by_step = Vec::<Vec<usize>>::new();
        let mut interactions_by_row_id = HashMap::<String, Vec<usize>>::new();

        for (i, insn) in instructions.iter().enumerate() {
            let step = insn.step_idx as usize;
            Self::ensure_len(&mut insn_by_step, step);
            insn_by_step[step] = Some(i);
        }
        for (i, row) in chip_rows.iter().enumerate() {
            let step = row.base().step_idx as usize;
            Self::ensure_len(&mut chip_rows_by_step, step);
            chip_rows_by_step[step].push(i);
        }
        for (i, ia) in interactions.iter().enumerate() {
            let step = ia.base().step_idx as usize;
            Self::ensure_len(&mut interactions_by_step, step);
            interactions_by_step[step].push(i);
            interactions_by_row_id.entry(ia.base().row_id.clone()).or_default().push(i);
        }

        let mut out = Self {
            instructions,
            chip_rows,
            interactions,
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
                emit_padding_interaction_send: true,
                emit_boolean_on_store: false,
                emit_boolean_on_load_after_store: true,
                emit_kind_selector: true,
                emit_digest_route: true,
                // Native instruction hits below carry full executed identity for control flow.
                // Keeping the shared coarse hit would make exact receipt binding ambiguous.
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
        out
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

#[cfg(test)]
mod relation_hit_tests {
    use super::{Sp1Trace, BACKEND, COMMIT};
    use beak_core::trace::semantic;
    use serde_json::json;

    #[test]
    fn normal_ecall_has_exactly_one_rich_control_flow_hit() {
        let words = [0x0020_0293, 0x0030_0513, 0x0000_0593, 0x0000_0613, 0x0000_0073];
        let trace = Sp1Trace::from_words(&words).expect("canonical normal ECALL trace");
        let ecall = trace
            .instructions
            .iter()
            .find(|insn| insn.mnemonic == "ecall")
            .expect("executed ECALL instruction");
        let matching = trace
            .bucket_hits
            .iter()
            .filter(|hit| {
                let details = &hit.details;
                hit.bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id
                    && details.get("obligation_id") == Some(&json!("cf6"))
                    && details.get("cell_id") == Some(&json!("cf6.normal"))
                    && details.get("backend") == Some(&json!(BACKEND))
                    && details.get("commit") == Some(&json!(COMMIT))
                    && details.get("trace_source") == Some(&json!("instruction"))
                    && details.get("op_idx") == Some(&json!(ecall.step_idx))
                    && details.get("pc") == Some(&json!(ecall.pc))
                    && details.get("opcode")
                        == Some(&json!(format!("0x{:08x}", ecall.word)))
                    && details.get("mnemonic") == Some(&json!("ecall"))
            })
            .count();

        assert_eq!(matching, 1, "normal ECALL relation hit must be unique");
    }
}
