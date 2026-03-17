use std::collections::HashMap;

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::observations::{SequenceInsnObservation, SequenceSemanticMatcherProfile};
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic_matchers};
use sp1_core_executor::{
    ExecutionRecord, Executor, ExecutorMode, Instruction as SP1Instruction, Opcode, Program,
};
use sp1_stark::SP1CoreOpts;

use crate::chip_row::{Sp1ChipRow, Sp1ChipRowBase, Sp1ChipRowKind, Sp1ChipRowPayload};
use crate::insn::Sp1Insn;
use crate::interaction::{
    InteractionDirection, Sp1Interaction, Sp1InteractionBase, Sp1InteractionKind,
    Sp1InteractionPayload,
};

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

pub fn decode_word_to_sp1_instruction(word: u32) -> Result<SP1Instruction, String> {
    let dec = RV32IMInstruction::from_word(word).map_err(|e| format!("rv32 decode failed: {e}"))?;
    let m = dec.mnemonic.as_str();

    let req = |name: &str, v: Option<u32>| -> Result<u32, String> {
        v.ok_or_else(|| format!("missing {name} for {m}"))
    };
    let req_imm = |v: Option<i32>| -> Result<i32, String> {
        v.ok_or_else(|| format!("missing imm for {m}"))
    };

    let insn = match m {
        "add" => SP1Instruction::new(Opcode::ADD, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "addi" => SP1Instruction::new(Opcode::ADD, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "sub" => SP1Instruction::new(Opcode::SUB, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "xor" => SP1Instruction::new(Opcode::XOR, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "xori" => SP1Instruction::new(Opcode::XOR, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "or" => SP1Instruction::new(Opcode::OR, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "ori" => SP1Instruction::new(Opcode::OR, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "and" => SP1Instruction::new(Opcode::AND, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "andi" => SP1Instruction::new(Opcode::AND, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "sll" => SP1Instruction::new(Opcode::SLL, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "slli" => SP1Instruction::new(Opcode::SLL, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "srl" => SP1Instruction::new(Opcode::SRL, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "srli" => SP1Instruction::new(Opcode::SRL, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "sra" => SP1Instruction::new(Opcode::SRA, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "srai" => SP1Instruction::new(Opcode::SRA, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "slt" => SP1Instruction::new(Opcode::SLT, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "slti" => SP1Instruction::new(Opcode::SLT, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "sltu" => SP1Instruction::new(Opcode::SLTU, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "sltiu" => SP1Instruction::new(Opcode::SLTU, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "lb" => SP1Instruction::new(Opcode::LB, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "lh" => SP1Instruction::new(Opcode::LH, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "lw" => SP1Instruction::new(Opcode::LW, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "lbu" => SP1Instruction::new(Opcode::LBU, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "lhu" => SP1Instruction::new(Opcode::LHU, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "sb" => SP1Instruction::new(Opcode::SB, req("rs2", dec.rs2)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "sh" => SP1Instruction::new(Opcode::SH, req("rs2", dec.rs2)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "sw" => SP1Instruction::new(Opcode::SW, req("rs2", dec.rs2)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "beq" => SP1Instruction::new(Opcode::BEQ, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "bne" => SP1Instruction::new(Opcode::BNE, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "blt" => SP1Instruction::new(Opcode::BLT, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "bge" => SP1Instruction::new(Opcode::BGE, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "bltu" => SP1Instruction::new(Opcode::BLTU, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "bgeu" => SP1Instruction::new(Opcode::BGEU, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "jal" => SP1Instruction::new(Opcode::JAL, req("rd", dec.rd)?, imm_as_u32(req_imm(dec.imm)?), 0, true, true),
        "jalr" => SP1Instruction::new(Opcode::JALR, req("rd", dec.rd)?, req("rs1", dec.rs1)?, imm_as_u32(req_imm(dec.imm)?), false, true),
        "lui" => SP1Instruction::new(Opcode::ADD, req("rd", dec.rd)?, 0, imm_as_u32(req_imm(dec.imm)?), true, true),
        "auipc" => SP1Instruction::new(Opcode::AUIPC, req("rd", dec.rd)?, imm_as_u32(req_imm(dec.imm)?), 0, true, true),
        "mul" => SP1Instruction::new(Opcode::MUL, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "mulh" => SP1Instruction::new(Opcode::MULH, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "mulhu" => SP1Instruction::new(Opcode::MULHU, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "mulhsu" => SP1Instruction::new(Opcode::MULHSU, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "div" => SP1Instruction::new(Opcode::DIV, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "divu" => SP1Instruction::new(Opcode::DIVU, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "rem" => SP1Instruction::new(Opcode::REM, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "remu" => SP1Instruction::new(Opcode::REMU, req("rd", dec.rd)?, req("rs1", dec.rs1)?, req("rs2", dec.rs2)?, false, false),
        "ecall" => SP1Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
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
                    rd: Some(insn.op_a),
                    rs1: Some(insn.op_b),
                    rs2: None,
                    imm: Some(op_u32_to_i32(insn.op_c)),
                }
            } else {
                DecodedOps {
                    rd: Some(insn.op_a),
                    rs1: Some(insn.op_b),
                    rs2: Some(insn.op_c),
                    imm: None,
                }
            }
        }
        LB | LH | LW | LBU | LHU => DecodedOps {
            rd: Some(insn.op_a),
            rs1: Some(insn.op_b),
            rs2: None,
            imm: Some(op_u32_to_i32(insn.op_c)),
        },
        SB | SH | SW => DecodedOps {
            rd: None,
            rs1: Some(insn.op_b),
            rs2: Some(insn.op_a),
            imm: Some(op_u32_to_i32(insn.op_c)),
        },
        BEQ | BNE | BLT | BGE | BLTU | BGEU => DecodedOps {
            rd: None,
            rs1: Some(insn.op_a),
            rs2: Some(insn.op_b),
            imm: Some(op_u32_to_i32(insn.op_c)),
        },
        JAL => DecodedOps {
            rd: Some(insn.op_a),
            rs1: None,
            rs2: None,
            imm: Some(op_u32_to_i32(insn.op_b)),
        },
        JALR => DecodedOps {
            rd: Some(insn.op_a),
            rs1: Some(insn.op_b),
            rs2: None,
            imm: Some(op_u32_to_i32(insn.op_c)),
        },
        AUIPC => DecodedOps {
            rd: Some(insn.op_a),
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
        executor
            .run()
            .map_err(|e| format!("sp1 executor run failed while building trace: {e}"))?;
        let records = std::mem::take(&mut executor.records);
        Self::from_execution_records(words, &records)
    }

    pub fn from_execution_records(words: &[u32], records: &[ExecutionRecord]) -> Result<Self, String> {
        let mut instructions = Vec::new();
        let mut chip_rows = Vec::new();
        let mut interactions = Vec::new();

        let mut seq = 0u64;
        let mut step_idx = 0u64;

        for record in records {
            for cpu in &record.cpu_events {
                let fallback = words.get(step_idx as usize).copied().unwrap_or_default();
                let mnemonic = cpu.instruction.opcode.mnemonic().to_string();

                let insn = if fallback != 0 {
                    if let Ok(dec) = RV32IMInstruction::from_word(fallback) {
                        if dec.mnemonic == mnemonic {
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
                                asm: dec.asm,
                            }
                        } else {
                            let ops = decoded_ops_from_executor_instruction(&cpu.instruction);
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
                                asm: asm_from_parts(&mnemonic, ops),
                            }
                        }
                    } else {
                        let ops = decoded_ops_from_executor_instruction(&cpu.instruction);
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
                            asm: asm_from_parts(&mnemonic, ops),
                        }
                    }
                } else {
                    let ops = decoded_ops_from_executor_instruction(&cpu.instruction);
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

        Ok(Self::new(instructions, chip_rows, interactions))
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
            interactions_by_row_id
                .entry(ia.base().row_id.clone())
                .or_default()
                .push(i);
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
                emit_padding_interaction_send: false,
                emit_boolean_on_store: true,
                emit_boolean_on_load_after_store: false,
                emit_kind_selector: false,
                emit_digest_route: false,
                emit_ecall_next_pc: false,
            },
            &insns,
        );
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
