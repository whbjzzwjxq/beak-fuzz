use std::collections::HashMap;
use std::sync::Arc;

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::observations::{SequenceInsnObservation, SequenceSemanticMatcherProfile};
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic, semantic_matchers};
use serde_json::{Value, json};
use sp1_core_executor::{
    ByteOpcode, ExecutionRecord, Instruction as SP1Instruction, Opcode, Program, add_halt,
    events::{
        AluEvent, BranchEvent, JumpEvent, MemInstrEvent, MemoryInitializeFinalizeEvent,
        MemoryRecordEnum, PrecompileEvent, SyscallEvent, UTypeEvent,
    },
};
use sp1_core_machine::{io::SP1Stdin, utils::generate_records};
use sp1_primitives::SP1Field;

use crate::chip_row::Sp1ChipRow;
use crate::insn::Sp1Insn;
use crate::interaction::Sp1Interaction;

const SP1_CODE_BASE: u32 = 0x1000;
const BACKEND: &str = "sp1";
const COMMIT: &str = "98a376e87ec9dd5c3ae3495b98846bf921d6035b";
const SP1_WORD_WIDTH: u32 = 4;
const BABYBEAR_FIELD_MODULUS: u32 = 2_013_265_921;
const SP1_BYTE_OPS: u64 = 6;

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

fn imm_as_u64(imm: i32) -> u64 {
    imm as u32 as u64
}

fn op_u64_to_i32(v: u64) -> i32 {
    v as u32 as i32
}

fn word_for_pc(words: &[u32], program: &Program, pc: u64) -> Option<u32> {
    let offset = pc.checked_sub(program.pc_base)?;
    let idx = (offset / 4) as usize;
    words.get(idx).copied()
}

#[derive(Debug, Clone)]
pub struct Sp1ExecutedInsnEvent {
    pub seq: u64,
    pub pc: u64,
    pub clk: u64,
    pub next_pc: u64,
    pub opcode: Opcode,
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub op_a_0: bool,
}

impl Sp1ExecutedInsnEvent {
    fn from_alu(event: &AluEvent) -> Self {
        Self {
            seq: 0,
            pc: event.pc,
            clk: event.clk,
            next_pc: event.pc.saturating_add(4),
            opcode: event.opcode,
            a: event.a,
            b: event.b,
            c: event.c,
            op_a_0: event.op_a_0,
        }
    }

    fn from_mem(event: &MemInstrEvent) -> Self {
        Self {
            seq: 0,
            pc: event.pc,
            clk: event.clk,
            next_pc: event.pc.saturating_add(4),
            opcode: event.opcode,
            a: event.a,
            b: event.b,
            c: event.c,
            op_a_0: event.op_a_0,
        }
    }

    fn from_branch(event: &BranchEvent) -> Self {
        Self {
            seq: 0,
            pc: event.pc,
            clk: event.clk,
            next_pc: event.next_pc,
            opcode: event.opcode,
            a: event.a,
            b: event.b,
            c: event.c,
            op_a_0: event.op_a_0,
        }
    }

    fn from_jump(event: &JumpEvent) -> Self {
        Self {
            seq: 0,
            pc: event.pc,
            clk: event.clk,
            next_pc: event.next_pc,
            opcode: event.opcode,
            a: event.a,
            b: event.b,
            c: event.c,
            op_a_0: event.op_a_0,
        }
    }

    fn from_utype(event: &UTypeEvent) -> Self {
        Self {
            seq: 0,
            pc: event.pc,
            clk: event.clk,
            next_pc: event.pc.saturating_add(4),
            opcode: event.opcode,
            a: event.a,
            b: event.b,
            c: event.c,
            op_a_0: event.op_a_0,
        }
    }

    fn from_syscall(event: &SyscallEvent) -> Self {
        Self {
            seq: 0,
            pc: event.pc,
            clk: event.clk,
            next_pc: event.next_pc,
            opcode: Opcode::ECALL,
            a: 0,
            b: event.arg1,
            c: event.arg2,
            op_a_0: true,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Sp1MemoryInstrEvent {
    pub(crate) memory_hook_step: u64,
    pub(crate) pc: u64,
    pub(crate) clk: u64,
    pub(crate) opcode: Opcode,
    pub(crate) b: u64,
    pub(crate) c: u64,
    pub(crate) mem_access: MemoryRecordEnum,
}

fn push_alu_events(events: &mut Vec<Sp1ExecutedInsnEvent>, source: &[(AluEvent, impl Copy)]) {
    events.extend(source.iter().map(|(event, _)| Sp1ExecutedInsnEvent::from_alu(event)));
}

fn push_mem_events(events: &mut Vec<Sp1ExecutedInsnEvent>, source: &[(MemInstrEvent, impl Copy)]) {
    events.extend(source.iter().map(|(event, _)| Sp1ExecutedInsnEvent::from_mem(event)));
}

fn push_memory_instr_events(
    events: &mut Vec<Sp1MemoryInstrEvent>,
    source: &[(MemInstrEvent, impl Copy)],
) {
    events.extend(source.iter().map(|(event, _)| Sp1MemoryInstrEvent {
        memory_hook_step: 0,
        pc: event.pc,
        clk: event.clk,
        opcode: event.opcode,
        b: event.b,
        c: event.c,
        mem_access: event.mem_access,
    }));
}

pub fn executed_instruction_events(records: &[ExecutionRecord]) -> Vec<Sp1ExecutedInsnEvent> {
    let mut events = Vec::new();
    for record in records {
        push_alu_events(&mut events, &record.alu_x0_events);
        push_alu_events(&mut events, &record.add_events);
        push_alu_events(&mut events, &record.addi_events);
        push_alu_events(&mut events, &record.mul_events);
        push_alu_events(&mut events, &record.sub_events);
        push_alu_events(&mut events, &record.bitwise_events);
        push_alu_events(&mut events, &record.shift_left_events);
        push_alu_events(&mut events, &record.shift_right_events);
        push_alu_events(&mut events, &record.divrem_events);
        push_alu_events(&mut events, &record.lt_events);
        push_mem_events(&mut events, &record.memory_load_x0_events);
        push_mem_events(&mut events, &record.memory_load_byte_events);
        push_mem_events(&mut events, &record.memory_load_half_events);
        push_mem_events(&mut events, &record.memory_load_word_events);
        push_mem_events(&mut events, &record.memory_store_byte_events);
        push_mem_events(&mut events, &record.memory_store_half_events);
        push_mem_events(&mut events, &record.memory_store_word_events);
        events.extend(
            record.branch_events.iter().map(|(event, _)| Sp1ExecutedInsnEvent::from_branch(event)),
        );
        events.extend(
            record.jal_events.iter().map(|(event, _)| Sp1ExecutedInsnEvent::from_jump(event)),
        );
        events.extend(
            record.jalr_events.iter().map(|(event, _)| Sp1ExecutedInsnEvent::from_jump(event)),
        );
        events.extend(
            record.utype_events.iter().map(|(event, _)| Sp1ExecutedInsnEvent::from_utype(event)),
        );
        events.extend(
            record
                .syscall_events
                .iter()
                .map(|(event, _)| Sp1ExecutedInsnEvent::from_syscall(event)),
        );
    }
    events.sort_by_key(|event| (event.clk, event.pc, event.opcode as u8));
    for (idx, event) in events.iter_mut().enumerate() {
        event.seq = idx as u64;
    }
    events
}

pub(crate) fn memory_instruction_events(records: &[ExecutionRecord]) -> Vec<Sp1MemoryInstrEvent> {
    let mut events = Vec::new();
    for record in records {
        push_memory_instr_events(&mut events, &record.memory_load_x0_events);
        push_memory_instr_events(&mut events, &record.memory_load_byte_events);
        push_memory_instr_events(&mut events, &record.memory_load_half_events);
        push_memory_instr_events(&mut events, &record.memory_load_word_events);
        push_memory_instr_events(&mut events, &record.memory_store_byte_events);
        push_memory_instr_events(&mut events, &record.memory_store_half_events);
        push_memory_instr_events(&mut events, &record.memory_store_word_events);
    }
    events.sort_by_key(|event| (event.clk, event.pc, event.opcode as u8));
    for (idx, event) in events.iter_mut().enumerate() {
        event.memory_hook_step = idx as u64;
    }
    events
}

pub fn build_sp1_program(words: &[u32]) -> Result<Program, String> {
    let mut instructions = Vec::with_capacity(words.len().saturating_add(3));
    for (idx, &word) in words.iter().enumerate() {
        instructions.push(decode_word_to_sp1_instruction(word).map_err(|e| {
            format!("decode rv32 word to sp1 instruction failed at step {idx}: {e}")
        })?);
    }
    add_halt(&mut instructions);
    Ok(Program::new(instructions, u64::from(SP1_CODE_BASE), u64::from(SP1_CODE_BASE)))
}

pub fn decode_word_to_sp1_instruction(word: u32) -> Result<SP1Instruction, String> {
    let dec = RV32IMInstruction::from_word(word).map_err(|e| format!("rv32 decode failed: {e}"))?;
    let m = dec.mnemonic.as_str();

    let req = |name: &str, v: Option<u32>| -> Result<u8, String> {
        v.map(|x| x as u8).ok_or_else(|| format!("missing {name} for {m}"))
    };
    let req_u64 = |name: &str, v: Option<u32>| -> Result<u64, String> {
        v.map(u64::from).ok_or_else(|| format!("missing {name} for {m}"))
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
            Opcode::ADDI,
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
            Opcode::LUI,
            req("rd", dec.rd)?,
            imm_as_u64(req_imm(dec.imm)?),
            0,
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
        ADD | ADDI | SUB | XOR | OR | AND | SLL | SRL | SRA | SLT | SLTU | MUL | MULH | MULHU
        | MULHSU | DIV | DIVU | REM | REMU => {
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
        AUIPC | LUI => (Some(insn.op_a as u32), None, None, Some(op_u64_to_i32(insn.op_b))),
        ECALL | EBREAK | UNIMP => (None, None, None, None),
        _ => (None, None, None, None),
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
    if let Some(rd_val) = insn.rd_val {
        details.insert("rd_val".to_string(), json!(rd_val));
    }
    if let Some(rs1_val) = insn.rs1_val {
        details.insert("rs1_val".to_string(), json!(rs1_val));
    }
    if let Some(rs2_or_imm_val) = insn.rs2_or_imm_val {
        details.insert("rs2_or_imm_val".to_string(), json!(rs2_or_imm_val));
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

#[derive(Debug, Clone)]
struct PrecompileSliceObservation {
    phase: &'static str,
    effective_ptr: u64,
    len_words: usize,
    is_read: bool,
    is_write: bool,
}

impl PrecompileSliceObservation {
    fn width(&self) -> u32 {
        SP1_WORD_WIDTH
    }

    fn byte_offset(&self) -> u32 {
        (self.effective_ptr % u64::from(SP1_WORD_WIDTH)) as u32
    }

    fn aligned_ptr(&self) -> u64 {
        self.effective_ptr.wrapping_sub(u64::from(self.byte_offset()))
    }

    fn span_bytes(&self) -> u64 {
        (self.len_words as u64).saturating_mul(SP1_WORD_WIDTH as u64)
    }

    fn field_end_exclusive(&self) -> u64 {
        self.effective_ptr.saturating_add(self.span_bytes())
    }

    fn crosses_babybear_field_boundary(&self) -> bool {
        self.len_words > 0 && self.field_end_exclusive() > BABYBEAR_FIELD_MODULUS as u64
    }

    fn wrapped_field_ptr(&self) -> u64 {
        if self.len_words == 0 {
            self.effective_ptr
        } else {
            (self.field_end_exclusive() - 1) % BABYBEAR_FIELD_MODULUS as u64
        }
    }
}

fn push_precompile_slice(
    slices: &mut Vec<PrecompileSliceObservation>,
    phase: &'static str,
    effective_ptr: u64,
    len_words: usize,
    is_read: bool,
    is_write: bool,
) {
    if len_words > 0 {
        slices.push(PrecompileSliceObservation {
            phase,
            effective_ptr,
            len_words,
            is_read,
            is_write,
        });
    }
}

fn precompile_name(event: &PrecompileEvent) -> &'static str {
    match event {
        PrecompileEvent::ShaExtend(_) => "sha_extend",
        PrecompileEvent::ShaCompress(_) => "sha_compress",
        PrecompileEvent::KeccakPermute(_) => "keccak_permute",
        PrecompileEvent::EdAdd(_) => "ed_add",
        PrecompileEvent::EdDecompress(_) => "ed_decompress",
        PrecompileEvent::Secp256k1Add(_) => "secp256k1_add",
        PrecompileEvent::Secp256k1Double(_) => "secp256k1_double",
        PrecompileEvent::Secp256k1Decompress(_) => "secp256k1_decompress",
        PrecompileEvent::Secp256r1Add(_) => "secp256r1_add",
        PrecompileEvent::Secp256r1Double(_) => "secp256r1_double",
        PrecompileEvent::Secp256r1Decompress(_) => "secp256r1_decompress",
        PrecompileEvent::K256Decompress(_) => "k256_decompress",
        PrecompileEvent::Bn254Add(_) => "bn254_add",
        PrecompileEvent::Bn254Double(_) => "bn254_double",
        PrecompileEvent::Bn254Fp(_) => "bn254_fp",
        PrecompileEvent::Bn254Fp2AddSub(_) => "bn254_fp2_add_sub",
        PrecompileEvent::Bn254Fp2Mul(_) => "bn254_fp2_mul",
        PrecompileEvent::Bls12381Add(_) => "bls12381_add",
        PrecompileEvent::Bls12381Double(_) => "bls12381_double",
        PrecompileEvent::Bls12381Decompress(_) => "bls12381_decompress",
        PrecompileEvent::Bls12381Fp(_) => "bls12381_fp",
        PrecompileEvent::Bls12381Fp2AddSub(_) => "bls12381_fp2_add_sub",
        PrecompileEvent::Bls12381Fp2Mul(_) => "bls12381_fp2_mul",
        PrecompileEvent::Uint256Mul(_) => "uint256_mul",
        PrecompileEvent::Uint256Ops(_) => "uint256_ops",
        PrecompileEvent::U256xU2048Mul(_) => "u256x_u2048_mul",
        PrecompileEvent::Mprotect(_) => "mprotect",
        PrecompileEvent::POSEIDON2(_) => "poseidon2",
        PrecompileEvent::SigReturn(_) => "sig_return",
    }
}

fn precompile_slice_observations(event: &PrecompileEvent) -> Vec<PrecompileSliceObservation> {
    let mut slices = Vec::new();
    match event {
        PrecompileEvent::ShaExtend(e) => {
            let len_words = e.memory_records.len();
            push_precompile_slice(
                &mut slices,
                "sha_extend.w_i_minus_15_read",
                e.w_ptr.wrapping_add(u64::from(SP1_WORD_WIDTH)),
                len_words,
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "sha_extend.w_i_minus_2_read",
                e.w_ptr.wrapping_add(14 * u64::from(SP1_WORD_WIDTH)),
                len_words,
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "sha_extend.w_i_minus_16_read",
                e.w_ptr,
                len_words,
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "sha_extend.w_i_minus_7_read",
                e.w_ptr.wrapping_add(9 * u64::from(SP1_WORD_WIDTH)),
                len_words,
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "sha_extend.w_i_write",
                e.w_ptr.wrapping_add(16 * u64::from(SP1_WORD_WIDTH)),
                len_words,
                false,
                true,
            );
        }
        PrecompileEvent::ShaCompress(e) => {
            push_precompile_slice(
                &mut slices,
                "sha_compress.w_read",
                e.w_ptr,
                e.w_i_read_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "sha_compress.h_read",
                e.h_ptr,
                e.h_read_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "sha_compress.h_write",
                e.h_ptr,
                e.h_write_records.len(),
                false,
                true,
            );
        }
        PrecompileEvent::KeccakPermute(e) => {
            push_precompile_slice(
                &mut slices,
                "keccak_permute.state_read",
                e.state_addr,
                e.state_read_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "keccak_permute.state_write",
                e.state_addr,
                e.state_write_records.len(),
                false,
                true,
            );
        }
        PrecompileEvent::EdDecompress(e) => {
            push_precompile_slice(
                &mut slices,
                "ed_decompress.y_read",
                e.ptr,
                e.y_memory_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "ed_decompress.x_write",
                e.ptr,
                e.x_memory_records.len(),
                false,
                true,
            );
        }
        PrecompileEvent::Secp256k1Add(e)
        | PrecompileEvent::Secp256r1Add(e)
        | PrecompileEvent::EdAdd(e)
        | PrecompileEvent::Bn254Add(e)
        | PrecompileEvent::Bls12381Add(e) => {
            push_precompile_slice(
                &mut slices,
                "ec_add.q_read",
                e.q_ptr,
                e.q_memory_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "ec_add.p_write",
                e.p_ptr,
                e.p_memory_records.len(),
                false,
                true,
            );
        }
        PrecompileEvent::Secp256k1Double(e)
        | PrecompileEvent::Secp256r1Double(e)
        | PrecompileEvent::Bn254Double(e)
        | PrecompileEvent::Bls12381Double(e) => {
            push_precompile_slice(
                &mut slices,
                "ec_double.p_write",
                e.p_ptr,
                e.p_memory_records.len(),
                false,
                true,
            );
        }
        PrecompileEvent::Secp256k1Decompress(e)
        | PrecompileEvent::Secp256r1Decompress(e)
        | PrecompileEvent::K256Decompress(e)
        | PrecompileEvent::Bls12381Decompress(e) => {
            push_precompile_slice(
                &mut slices,
                "ec_decompress.x_read",
                e.ptr,
                e.x_memory_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "ec_decompress.y_write",
                e.ptr,
                e.y_memory_records.len(),
                false,
                true,
            );
        }
        PrecompileEvent::Bn254Fp(e) | PrecompileEvent::Bls12381Fp(e) => {
            push_precompile_slice(
                &mut slices,
                "fp_op.y_read",
                e.y_ptr,
                e.y_memory_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "fp_op.x_write",
                e.x_ptr,
                e.x_memory_records.len(),
                false,
                true,
            );
        }
        PrecompileEvent::Bn254Fp2AddSub(e) | PrecompileEvent::Bls12381Fp2AddSub(e) => {
            push_precompile_slice(
                &mut slices,
                "fp2_add_sub.y_read",
                e.y_ptr,
                e.y_memory_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "fp2_add_sub.x_write",
                e.x_ptr,
                e.x_memory_records.len(),
                false,
                true,
            );
        }
        PrecompileEvent::Bn254Fp2Mul(e) | PrecompileEvent::Bls12381Fp2Mul(e) => {
            push_precompile_slice(
                &mut slices,
                "fp2_mul.y_read",
                e.y_ptr,
                e.y_memory_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "fp2_mul.x_write",
                e.x_ptr,
                e.x_memory_records.len(),
                false,
                true,
            );
        }
        PrecompileEvent::Uint256Mul(e) => {
            push_precompile_slice(
                &mut slices,
                "uint256_mul.y_read",
                e.y_ptr,
                e.y_memory_records.len(),
                true,
                false,
            );
            let modulus_ptr = e.y_ptr.wrapping_add(
                (e.y_memory_records.len() as u64).saturating_mul(u64::from(SP1_WORD_WIDTH)),
            );
            push_precompile_slice(
                &mut slices,
                "uint256_mul.modulus_read",
                modulus_ptr,
                e.modulus_memory_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "uint256_mul.x_write",
                e.x_ptr,
                e.x_memory_records.len(),
                false,
                true,
            );
        }
        PrecompileEvent::U256xU2048Mul(e) => {
            push_precompile_slice(
                &mut slices,
                "u256x_u2048_mul.a_read",
                e.a_ptr,
                e.a_memory_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "u256x_u2048_mul.b_read",
                e.b_ptr,
                e.b_memory_records.len(),
                true,
                false,
            );
            push_precompile_slice(
                &mut slices,
                "u256x_u2048_mul.lo_write",
                e.lo_ptr,
                e.lo_memory_records.len(),
                false,
                true,
            );
            push_precompile_slice(
                &mut slices,
                "u256x_u2048_mul.hi_write",
                e.hi_ptr,
                e.hi_memory_records.len(),
                false,
                true,
            );
        }
        _ => {}
    }
    slices
}

fn precompile_slice_details(
    syscall_event: &SyscallEvent,
    precompile: &str,
    event_idx: u64,
    slice_idx: u64,
    obligation_id: &str,
    cell_id: &str,
    obs: &PrecompileSliceObservation,
) -> HashMap<String, Value> {
    let mut details = HashMap::new();
    details.insert("obligation_id".to_string(), json!(obligation_id));
    details.insert("cell_id".to_string(), json!(cell_id));
    details.insert("backend".to_string(), json!(BACKEND));
    details.insert("commit".to_string(), json!(COMMIT));
    details.insert("trace_source".to_string(), json!("precompile_events"));
    details.insert("trace_source_detail".to_string(), json!("precompile_slice"));
    details.insert("op_idx".to_string(), json!(syscall_event.clk));
    details.insert("step_idx".to_string(), json!(syscall_event.clk));
    details.insert("pc".to_string(), json!(syscall_event.pc));
    details.insert("next_pc".to_string(), json!(syscall_event.next_pc));
    details.insert("syscall_clk".to_string(), json!(syscall_event.clk));
    details.insert("syscall_code".to_string(), json!(format!("{:?}", syscall_event.syscall_code)));
    details.insert("syscall_id".to_string(), json!(syscall_event.syscall_id));
    details.insert("syscall_arg1".to_string(), json!(syscall_event.arg1));
    details.insert("syscall_arg2".to_string(), json!(syscall_event.arg2));
    details.insert("precompile".to_string(), json!(precompile));
    details.insert("precompile_event_idx".to_string(), json!(event_idx));
    details.insert("precompile_slice_idx".to_string(), json!(slice_idx));
    details.insert("precompile_phase".to_string(), json!(obs.phase));
    details.insert("effective_ptr".to_string(), json!(obs.effective_ptr));
    details.insert("aligned_ptr".to_string(), json!(obs.aligned_ptr()));
    details.insert("byte_offset".to_string(), json!(obs.byte_offset()));
    details.insert("width".to_string(), json!(obs.width()));
    details.insert("address_space".to_string(), json!("memory"));
    details.insert("slice_len_words".to_string(), json!(obs.len_words));
    details.insert("slice_span_bytes".to_string(), json!(obs.span_bytes()));
    details.insert("is_read".to_string(), json!(obs.is_read));
    details.insert("is_write".to_string(), json!(obs.is_write));
    details
}

fn emit_precompile_memory_obligation_hits(records: &[ExecutionRecord]) -> Vec<BucketHit> {
    let mut hits = Vec::new();
    let mut event_idx = 0u64;
    for record in records {
        for (syscall_event, event) in record.precompile_events.all_events() {
            let precompile = precompile_name(event);
            for (slice_idx, obs) in precompile_slice_observations(event).iter().enumerate() {
                if let Some(cell) = alignment_cell(obs.width(), obs.byte_offset()) {
                    hits.push(BucketHit::semantic(
                        semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                        precompile_slice_details(
                            syscall_event,
                            precompile,
                            event_idx,
                            slice_idx as u64,
                            "me2",
                            cell,
                            obs,
                        ),
                    ));
                }

                if obs.crosses_babybear_field_boundary() {
                    let mut details = precompile_slice_details(
                        syscall_event,
                        precompile,
                        event_idx,
                        slice_idx as u64,
                        "me6",
                        "me6.precompile_slice_field_wrap",
                        obs,
                    );
                    details.insert("field_modulus".to_string(), json!(BABYBEAR_FIELD_MODULUS));
                    details.insert(
                        "field_end_exclusive".to_string(),
                        json!(obs.field_end_exclusive()),
                    );
                    details.insert("wrapped_field_ptr".to_string(), json!(obs.wrapped_field_ptr()));
                    hits.push(BucketHit::semantic(
                        semantic::memory::ADDRESS_BOUNDARY_RANGE,
                        details,
                    ));
                }
            }
            event_idx = event_idx.saturating_add(1);
        }
    }
    hits
}

fn global_memory_alignment_details(
    event: &MemoryInitializeFinalizeEvent,
    event_idx: u64,
    trace_source: &'static str,
    phase: &'static str,
    cell_id: &str,
) -> HashMap<String, Value> {
    let byte_offset = (event.addr % u64::from(SP1_WORD_WIDTH)) as u32;
    let mut details = HashMap::new();
    details.insert("obligation_id".to_string(), json!("me2"));
    details.insert("cell_id".to_string(), json!(cell_id));
    details.insert("backend".to_string(), json!(BACKEND));
    details.insert("commit".to_string(), json!(COMMIT));
    details.insert("trace_source".to_string(), json!(trace_source));
    details.insert("phase".to_string(), json!(phase));
    details.insert("op_idx".to_string(), json!(event.timestamp));
    details.insert("global_memory_event_idx".to_string(), json!(event_idx));
    details.insert("effective_ptr".to_string(), json!(event.addr));
    details
        .insert("aligned_ptr".to_string(), json!(event.addr.wrapping_sub(u64::from(byte_offset))));
    details.insert("byte_offset".to_string(), json!(byte_offset));
    details.insert("width".to_string(), json!(SP1_WORD_WIDTH));
    details.insert("address_space".to_string(), json!("memory"));
    details.insert("timestamp".to_string(), json!(event.timestamp));
    details.insert("value".to_string(), json!(event.value));
    details
}

fn emit_global_memory_alignment_hits(records: &[ExecutionRecord]) -> Vec<BucketHit> {
    let mut hits = Vec::new();
    let mut event_idx = 0u64;
    for record in records {
        for event in &record.global_memory_initialize_events {
            if let Some(cell) =
                alignment_cell(SP1_WORD_WIDTH, (event.addr % u64::from(SP1_WORD_WIDTH)) as u32)
            {
                hits.push(BucketHit::semantic(
                    semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                    global_memory_alignment_details(
                        event,
                        event_idx,
                        "global_memory_initialize_event",
                        "initialize",
                        cell,
                    ),
                ));
            }
            event_idx = event_idx.saturating_add(1);
        }
    }

    event_idx = 0;
    for record in records {
        for event in &record.global_memory_finalize_events {
            if let Some(cell) =
                alignment_cell(SP1_WORD_WIDTH, (event.addr % u64::from(SP1_WORD_WIDTH)) as u32)
            {
                hits.push(BucketHit::semantic(
                    semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                    global_memory_alignment_details(
                        event,
                        event_idx,
                        "global_memory_finalize_event",
                        "finalize",
                        cell,
                    ),
                ));
            }
            event_idx = event_idx.saturating_add(1);
        }
    }
    hits
}

fn emit_syscall_padding_hits(records: &[ExecutionRecord]) -> Vec<BucketHit> {
    let mut hits = Vec::new();
    for (record_idx, record) in records.iter().enumerate() {
        let event_rows = record.syscall_events.len();
        if event_rows == 0 || event_rows % 32 == 0 {
            continue;
        }
        let mut details = HashMap::new();
        details.insert("obligation_id".to_string(), json!("pd1"));
        details.insert("cell_id".to_string(), json!("pd1.syscall_instr_padding"));
        details.insert("backend".to_string(), json!(BACKEND));
        details.insert("commit".to_string(), json!(COMMIT));
        details.insert("trace_source".to_string(), json!("syscall_instr_padding"));
        details.insert("record_idx".to_string(), json!(record_idx));
        details.insert("op_idx".to_string(), json!(event_rows));
        details.insert("step_idx".to_string(), json!(event_rows));
        details.insert("padding_hook_step".to_string(), json!(event_rows));
        details.insert("padding_row_idx".to_string(), json!(event_rows));
        details.insert("event_rows".to_string(), json!(event_rows));
        details.insert("padded_rows".to_string(), json!(((event_rows + 31) / 32) * 32));
        hits.push(BucketHit::semantic(semantic::row::PADDING_INTERACTION_SEND, details));
    }
    hits
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
    (row as u64).saturating_mul(SP1_BYTE_OPS).saturating_add(opcode_index as u64)
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
    for event in memory_instruction_events(records) {
        let Some(width) = memory_width_for_opcode(event.opcode) else {
            continue;
        };
        let Some(&insn_idx) = insn_by_pc_clk.get(&(event.pc as u32, event.clk as u32)) else {
            continue;
        };
        let current = event.mem_access.current_record();
        let previous = event.mem_access.previous_record();
        let effective_ptr = event.b.wrapping_add(event.c);
        observations.push(MemoryAccessObservation {
            insn_idx,
            memory_hook_step: event.memory_hook_step,
            effective_ptr: effective_ptr as u32,
            aligned_ptr: effective_ptr.wrapping_sub(effective_ptr % 4) as u32,
            byte_offset: (effective_ptr % 4) as u32,
            width,
            is_load: matches!(
                event.opcode,
                Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW
            ),
            is_store: matches!(event.opcode, Opcode::SB | Opcode::SH | Opcode::SW),
            value: current.value as u32,
            prev_value: previous.value as u32,
            shard: 0,
            prev_shard: 0,
            timestamp: current.timestamp as u32,
            previous_timestamp: previous.timestamp as u32,
        });
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
            let row = if lookup.opcode == ByteOpcode::Range {
                lookup.a as usize
            } else {
                (((lookup.b as u16) << 8) + lookup.c as u16) as usize
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

    hits.extend(emit_precompile_memory_obligation_hits(records));
    hits.extend(emit_global_memory_alignment_hits(records));
    hits.extend(emit_syscall_padding_hits(records));

    let mut initial_values = HashMap::<u32, u32>::new();
    let mut init_conflict = false;
    for record in records {
        for event in &record.global_memory_initialize_events {
            if initial_values.insert(event.addr as u32, event.value as u32).is_some() {
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
            let addr = event.addr as u32;
            let value = event.value as u32;
            let initial = initial_values.get(&addr).copied().unwrap_or(0);
            let Some(cell) = (if value != initial || event.timestamp > 1 {
                Some("me11.written_cells")
            } else if initial_values.contains_key(&addr) {
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
            details.insert("pointer".to_string(), json!(addr));
            details.insert("effective_ptr".to_string(), json!(addr));
            details.insert("address_space".to_string(), json!("memory"));
            details.insert("timestamp".to_string(), json!(event.timestamp));
            details.insert("value".to_string(), json!(value));
            details.insert("initial_value".to_string(), json!(initial));
            details.insert("was_initial".to_string(), json!(initial_values.contains_key(&addr)));
            details.insert("changed_from_initial".to_string(), json!(value != initial));
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
        let program = Arc::new(build_sp1_program(words)?);
        let (records, _) = generate_records::<SP1Field>(
            program,
            SP1Stdin::new(),
            sp1_core_executor::SP1CoreOpts::default(),
            [0; 4],
        )
        .map_err(|e| format!("sp1 generate_records failed while building trace: {e}"))?;
        Self::from_execution_records(words, &records)
    }

    pub fn from_execution_records(
        words: &[u32],
        records: &[ExecutionRecord],
    ) -> Result<Self, String> {
        let mut instructions = Vec::new();
        let mut seq = 0u64;
        let mut step_idx = 0u64;

        let program = records.first().map(|record| record.program.clone());
        for cpu in executed_instruction_events(records) {
            let exec_insn = program.as_ref().and_then(|program| program.fetch(cpu.pc));
            let fallback_word =
                program.as_ref().and_then(|program| word_for_pc(words, program, cpu.pc));
            let Some(fallback_word) = fallback_word else {
                continue;
            };

            let insn = if let Ok(dec) = RV32IMInstruction::from_word(fallback_word) {
                Sp1Insn {
                    seq,
                    step_idx,
                    pc: cpu.pc as u32,
                    timestamp: cpu.clk as u32,
                    next_pc: cpu.next_pc as u32,
                    next_timestamp: cpu.clk.saturating_add(1) as u32,
                    word: dec.word,
                    mnemonic: dec.mnemonic,
                    rd: dec.rd,
                    rs1: dec.rs1,
                    rs2: dec.rs2,
                    imm: dec.imm,
                    rd_val: Some(cpu.a as u32),
                    rs1_val: Some(cpu.b as u32),
                    rs2_or_imm_val: Some(cpu.c as u32),
                    asm: dec.asm,
                }
            } else {
                let mnemonic = exec_insn
                    .map(|insn| insn.opcode.mnemonic())
                    .unwrap_or_else(|| cpu.opcode.mnemonic())
                    .to_string();
                let (rd, rs1, rs2, imm) = exec_insn
                    .map(decoded_ops_from_executor_instruction)
                    .unwrap_or((None, None, None, None));
                Sp1Insn {
                    seq,
                    step_idx,
                    pc: cpu.pc as u32,
                    timestamp: cpu.clk as u32,
                    next_pc: cpu.next_pc as u32,
                    next_timestamp: cpu.clk.saturating_add(1) as u32,
                    word: fallback_word,
                    mnemonic: mnemonic.clone(),
                    rd,
                    rs1,
                    rs2,
                    imm,
                    rd_val: Some(cpu.a as u32),
                    rs1_val: Some(cpu.b as u32),
                    rs2_or_imm_val: Some(cpu.c as u32),
                    asm: asm_from_parts(&mnemonic, rd, rs1, rs2, imm),
                }
            };
            instructions.push(insn);
            seq = seq.saturating_add(1);
            step_idx = step_idx.saturating_add(1);
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
        out.bucket_hits.extend(emit_memory_event_obligation_hits(records, &out.instructions));
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sp1_core_executor::{
        SyscallCode,
        events::{MemoryReadRecord, ShaCompressEvent},
    };

    fn syscall_event(syscall_code: SyscallCode, arg1: u64, arg2: u64) -> SyscallEvent {
        SyscallEvent {
            pc: u64::from(SP1_CODE_BASE),
            next_pc: u64::from(SP1_CODE_BASE + 4),
            clk: 7,
            should_send: true,
            syscall_code,
            syscall_id: 3,
            arg1,
            arg2,
            exit_code: 0,
            sig_return_pc_record: None,
            trap_result: None,
            trap_error: None,
        }
    }

    #[test]
    fn precompile_slice_field_wrap_emits_me6_without_rv32_cell() {
        let mut event = ShaCompressEvent::default();
        event.w_ptr = u64::from(BABYBEAR_FIELD_MODULUS - 1);
        event.w_i_read_records = vec![MemoryReadRecord::default(); 2];

        let mut record = ExecutionRecord::default();
        record.precompile_events.add_event(
            SyscallCode::SHA_COMPRESS,
            syscall_event(SyscallCode::SHA_COMPRESS, event.w_ptr, 128),
            PrecompileEvent::ShaCompress(event),
        );

        let hits = emit_precompile_memory_obligation_hits(&[record]);
        let hit = hits
            .iter()
            .find(|hit| {
                hit.bucket_id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id
                    && hit.details.get("cell_id") == Some(&json!("me6.precompile_slice_field_wrap"))
            })
            .expect("missing precompile slice field-wrap bucket");

        assert_ne!(hit.details.get("cell_id"), Some(&json!("me6.near_max_lw")));
        assert_eq!(hit.details.get("trace_source"), Some(&json!("precompile_events")));
        assert_eq!(hit.details.get("precompile_phase"), Some(&json!("sha_compress.w_read")));
        assert_eq!(hit.details.get("effective_ptr"), Some(&json!(BABYBEAR_FIELD_MODULUS - 1)));
    }

    #[test]
    fn precompile_alignment_preserves_me2_address_fields() {
        let mut event = ShaCompressEvent::default();
        event.w_ptr = 65;
        event.w_i_read_records = vec![MemoryReadRecord::default(); 1];

        let mut record = ExecutionRecord::default();
        record.precompile_events.add_event(
            SyscallCode::SHA_COMPRESS,
            syscall_event(SyscallCode::SHA_COMPRESS, event.w_ptr, 128),
            PrecompileEvent::ShaCompress(event),
        );

        let hits = emit_precompile_memory_obligation_hits(&[record]);
        let hit = hits
            .iter()
            .find(|hit| {
                hit.bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id
                    && hit.details.get("cell_id") == Some(&json!("me2.word_off1"))
            })
            .expect("missing precompile alignment bucket");

        assert_eq!(hit.details.get("effective_ptr"), Some(&json!(65)));
        assert_eq!(hit.details.get("aligned_ptr"), Some(&json!(64)));
        assert_eq!(hit.details.get("byte_offset"), Some(&json!(1)));
        assert_eq!(hit.details.get("width"), Some(&json!(4)));
        assert_eq!(hit.details.get("trace_source"), Some(&json!("precompile_events")));
    }

    #[test]
    fn global_memory_alignment_preserves_provenance() {
        let mut record = ExecutionRecord::default();
        record.global_memory_initialize_events.push(MemoryInitializeFinalizeEvent {
            addr: 9,
            value: 42,
            timestamp: 5,
        });

        let hits = emit_global_memory_alignment_hits(&[record]);
        let hit = hits.first().expect("missing global alignment bucket");

        assert_eq!(hit.bucket_id, semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id);
        assert_eq!(hit.details.get("cell_id"), Some(&json!("me2.word_off1")));
        assert_eq!(hit.details.get("effective_ptr"), Some(&json!(9)));
        assert_eq!(hit.details.get("aligned_ptr"), Some(&json!(8)));
        assert_eq!(hit.details.get("byte_offset"), Some(&json!(1)));
        assert_eq!(hit.details.get("width"), Some(&json!(4)));
        assert_eq!(hit.details.get("trace_source"), Some(&json!("global_memory_initialize_event")));
        assert_eq!(hit.details.get("phase"), Some(&json!("initialize")));
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "the latest SP1 debug executor trips field inversion on this intentionally boundary precompile seed"
    )]
    fn exact_sha_extend_boundary_seed_emits_precompile_me6() {
        let words = [
            0x000102b7, // lui x5, 0x10
            0x12628293, // addi x5, x5, 0x126 (SHA_EXTEND)
            0x78000537, // lui x10, 0x78000
            0x00000073, // ecall
        ];
        let trace = Sp1Trace::from_words(&words).expect("trace exact SHA_EXTEND seed");

        assert!(trace.bucket_hits.iter().any(|hit| {
            hit.bucket_id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id
                && hit.details.get("cell_id") == Some(&json!("me6.precompile_slice_field_wrap"))
                && hit.details.get("trace_source") == Some(&json!("precompile_events"))
        }));
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "the legacy SP1 debug executor trips MemoryReadRecord::new debug_asserts on this intentionally unaligned precompile seed"
    )]
    fn exact_sha_compress_unaligned_seed_emits_precompile_me2() {
        let words = [
            0x000102b7, // lui x5, 0x10
            0x10628293, // addi x5, x5, 0x106 (SHA_COMPRESS)
            0x04100513, // addi x10, x0, 65
            0x08000593, // addi x11, x0, 128
            0x00000073, // ecall
        ];
        let trace = Sp1Trace::from_words(&words).expect("trace exact SHA_COMPRESS seed");

        assert!(trace.bucket_hits.iter().any(|hit| {
            hit.bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id
                && hit.details.get("cell_id") == Some(&json!("me2.word_off1"))
                && hit.details.get("trace_source") == Some(&json!("precompile_events"))
                && hit.details.get("effective_ptr") == Some(&json!(65))
                && hit.details.get("aligned_ptr") == Some(&json!(64))
                && hit.details.get("byte_offset") == Some(&json!(1))
                && hit.details.get("width") == Some(&json!(4))
        }));
    }
}
