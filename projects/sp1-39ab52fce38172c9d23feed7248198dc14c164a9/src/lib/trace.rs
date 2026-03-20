use std::collections::HashMap;

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::observations::{SequenceInsnObservation, SequenceSemanticMatcherProfile};
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic_matchers};
use sp1_core_executor::{Instruction as SP1Instruction, Opcode, Program};

use crate::chip_row::Sp1ChipRow;
use crate::insn::Sp1Insn;
use crate::interaction::Sp1Interaction;

const SP1_CODE_BASE: u32 = 0x1000;

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
    let req_imm = |v: Option<i32>| -> Result<i32, String> {
        v.ok_or_else(|| format!("missing imm for {m}"))
    };

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

fn decoded_ops_from_executor_instruction(insn: &SP1Instruction) -> (Option<u32>, Option<u32>, Option<u32>, Option<i32>) {
    use Opcode::*;

    match insn.opcode {
        ADD | SUB | XOR | OR | AND | SLL | SRL | SRA | SLT | SLTU | MUL | MULH | MULHU
        | MULHSU | DIV | DIVU | REM | REMU => {
            if insn.imm_c {
                (
                    Some(insn.op_a as u32),
                    Some(insn.op_b as u32),
                    None,
                    Some(op_u64_to_i32(insn.op_c)),
                )
            } else {
                (
                    Some(insn.op_a as u32),
                    Some(insn.op_b as u32),
                    Some(insn.op_c as u32),
                    None,
                )
            }
        }
        LB | LH | LW | LBU | LHU => (
            Some(insn.op_a as u32),
            Some(insn.op_b as u32),
            None,
            Some(op_u64_to_i32(insn.op_c)),
        ),
        SB | SH | SW => (
            None,
            Some(insn.op_b as u32),
            Some(insn.op_a as u32),
            Some(op_u64_to_i32(insn.op_c)),
        ),
        BEQ | BNE | BLT | BGE | BLTU | BGEU => (
            None,
            Some(insn.op_a as u32),
            Some(insn.op_b as u32),
            Some(op_u64_to_i32(insn.op_c)),
        ),
        JAL => (
            Some(insn.op_a as u32),
            None,
            None,
            Some(op_u64_to_i32(insn.op_b)),
        ),
        JALR => (
            Some(insn.op_a as u32),
            Some(insn.op_b as u32),
            None,
            Some(op_u64_to_i32(insn.op_c)),
        ),
        AUIPC => (
            Some(insn.op_a as u32),
            None,
            None,
            Some(op_u64_to_i32(insn.op_b)),
        ),
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

impl Sp1Trace {
    fn ensure_len<T: Default + Clone>(v: &mut Vec<T>, idx: usize) {
        if v.len() <= idx {
            v.resize(idx + 1, T::default());
        }
    }

    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        let mut instructions = Vec::with_capacity(words.len());
        for (idx, &word) in words.iter().enumerate() {
            let exec_insn = decode_word_to_sp1_instruction(word)?;
            let (rd, rs1, rs2, imm) = decoded_ops_from_executor_instruction(&exec_insn);
            let mnemonic = RV32IMInstruction::from_word(word)
                .map(|insn| insn.mnemonic)
                .unwrap_or_else(|_| exec_insn.opcode.mnemonic().to_string());
            let pc = SP1_CODE_BASE as u32 + (idx as u32).saturating_mul(4);
            let asm = asm_from_parts(&mnemonic, rd, rs1, rs2, imm);
            instructions.push(Sp1Insn {
                seq: idx as u64,
                step_idx: idx as u64,
                pc,
                timestamp: idx as u32,
                next_pc: pc.wrapping_add(4),
                next_timestamp: (idx as u32).saturating_add(1),
                word,
                mnemonic,
                rd,
                rs1,
                rs2,
                imm,
                asm,
            });
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
                emit_ecall_next_pc: false,
            },
            &insns,
        );
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
        self.chip_rows_by_step
            .get(step_idx)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn interaction_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.interactions_by_step
            .get(step_idx)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn interaction_indices_by_row_id(&self, row_id: &str) -> &[usize] {
        self.interactions_by_row_id
            .get(row_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
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
