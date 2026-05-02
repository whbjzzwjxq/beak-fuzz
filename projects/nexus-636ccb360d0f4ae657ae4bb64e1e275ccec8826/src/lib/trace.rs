use std::collections::HashMap;

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::observations::SequenceInsnObservation;
use beak_core::trace::{semantic, semantic_matchers, BucketHit, Trace, TraceSignal};
use nexus_common::cpu::Registers;
use nexus_common::memory::MemoryRecord;
use nexus_common::riscv::register::Register;
use nexus_vm::trace::UniformTrace;
use serde_json::{json, Value};

const BACKEND: &str = "nexus";
const COMMIT: &str = crate::NEXUS_COMMIT;

pub struct NexusTrace {
    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,
    step_count: usize,
}

#[derive(Debug, Clone)]
struct ExecutedMemoryAccess {
    op_idx: u64,
    timestamp: u32,
    pc: u32,
    raw_word: u32,
    mnemonic: String,
    size_bytes: u8,
    address: u32,
    value: u32,
}

#[derive(Debug, Clone)]
struct ExecutedInstruction {
    op_idx: u64,
    timestamp: u32,
    pc: u32,
    next_pc: u32,
    raw_word: u32,
    mnemonic: String,
    rd: Option<u32>,
    rs1: Option<u32>,
    rs2: Option<u32>,
    imm: Option<i32>,
    rs1_val: Option<u32>,
    rs2_val: Option<u32>,
    rd_val: Option<u32>,
}

fn base_details(
    obligation_id: &str,
    cell_id: &str,
    access: &ExecutedMemoryAccess,
) -> HashMap<String, Value> {
    let mut details = HashMap::new();
    details.insert("obligation_id".to_string(), json!(obligation_id));
    details.insert("cell_id".to_string(), json!(cell_id));
    details.insert("backend".to_string(), json!(BACKEND));
    details.insert("commit".to_string(), json!(COMMIT));
    details.insert("trace_source".to_string(), json!("memory"));
    details.insert("op_idx".to_string(), json!(access.op_idx));
    details.insert("step_idx".to_string(), json!(access.op_idx));
    details.insert("timestamp".to_string(), json!(access.timestamp));
    details.insert("pc".to_string(), json!(access.pc));
    details.insert("opcode".to_string(), json!(format!("0x{:08x}", access.raw_word)));
    details.insert("raw_word".to_string(), json!(access.raw_word));
    details.insert("mnemonic".to_string(), json!(access.mnemonic));
    details.insert("effective_ptr".to_string(), json!(access.address));
    details.insert("address".to_string(), json!(access.address));
    details.insert("width".to_string(), json!(access.size_bytes));
    details
}

fn me1_cell(store_mnemonic: &str, load_mnemonic: &str) -> Option<&'static str> {
    match (store_mnemonic, load_mnemonic) {
        ("sw", "lw") => Some("me1.sw_lw"),
        ("sb", "lb" | "lbu") => Some("me1.sb_lb"),
        ("sh", "lh" | "lhu") => Some("me1.sh_lh"),
        ("sb", "lw") => Some("me1.sb_lw"),
        ("sw", "lb" | "lbu") => Some("me1.sw_lb"),
        ("sw", "lhu") => Some("me1.sw_lhu"),
        _ => None,
    }
}

fn me4_cell(store_mnemonic: &str, address: u32) -> Option<&'static str> {
    match (store_mnemonic, address & 0x3) {
        ("sb", 0) => Some("me4.sb_off0"),
        ("sb", 1) => Some("me4.sb_off1"),
        ("sb", 2) => Some("me4.sb_off2"),
        ("sb", _) => Some("me4.sb_off3"),
        ("sh", 0 | 1) => Some("me4.sh_off0"),
        ("sh", _) => Some("me4.sh_off2"),
        _ => None,
    }
}

fn raw_opcode(word: u32) -> u32 {
    word & 0x7f
}

fn raw_funct3(word: u32) -> u32 {
    (word >> 12) & 0x7
}

fn raw_funct7(word: u32) -> u32 {
    (word >> 25) & 0x7f
}

fn i32_bits(value: i32) -> u32 {
    value as u32
}

fn signed_u32(value: u32) -> i32 {
    value as i32
}

fn branch_target(insn: &ExecutedInstruction) -> Option<u32> {
    Some(insn.pc.wrapping_add(i32_bits(insn.imm?)))
}

fn instr_details(
    obligation_id: &str,
    cell_id: &str,
    insn: &ExecutedInstruction,
) -> HashMap<String, Value> {
    let mut details = HashMap::new();
    details.insert("obligation_id".to_string(), json!(obligation_id));
    details.insert("cell_id".to_string(), json!(cell_id));
    details.insert("backend".to_string(), json!(BACKEND));
    details.insert("commit".to_string(), json!(COMMIT));
    details.insert("trace_source".to_string(), json!("instruction"));
    details.insert("op_idx".to_string(), json!(insn.op_idx));
    details.insert("step_idx".to_string(), json!(insn.op_idx));
    details.insert("timestamp".to_string(), json!(insn.timestamp));
    details.insert("pc".to_string(), json!(insn.pc));
    details.insert("next_pc".to_string(), json!(insn.next_pc));
    details.insert("opcode".to_string(), json!(format!("0x{:08x}", insn.raw_word)));
    details.insert("raw_word".to_string(), json!(insn.raw_word));
    details.insert("mnemonic".to_string(), json!(insn.mnemonic));
    details.insert("rv_opcode".to_string(), json!(raw_opcode(insn.raw_word)));
    details.insert("funct3".to_string(), json!(raw_funct3(insn.raw_word)));
    details.insert("funct7".to_string(), json!(raw_funct7(insn.raw_word)));
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
    if let Some(rs1_val) = insn.rs1_val {
        details.insert("rs1_val".to_string(), json!(rs1_val));
    }
    if let Some(rs2_val) = insn.rs2_val {
        details.insert("rs2_val".to_string(), json!(rs2_val));
    }
    if let Some(rd_val) = insn.rd_val {
        details.insert("rd_val".to_string(), json!(rd_val));
    }
    details
}

fn push_instr_hit(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    obligation_id: &str,
    cell_id: &str,
    insn: &ExecutedInstruction,
) {
    hits.push(BucketHit::semantic(bucket, instr_details(obligation_id, cell_id, insn)));
}

fn reads_rs1(mnemonic: &str) -> bool {
    !matches!(mnemonic, "lui" | "auipc" | "jal" | "ecall" | "ebreak")
}

fn reads_rs2(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "add"
            | "sub"
            | "sll"
            | "slt"
            | "sltu"
            | "xor"
            | "srl"
            | "sra"
            | "or"
            | "and"
            | "mul"
            | "mulh"
            | "mulhsu"
            | "mulhu"
            | "div"
            | "divu"
            | "rem"
            | "remu"
            | "sb"
            | "sh"
            | "sw"
            | "beq"
            | "bne"
            | "blt"
            | "bge"
            | "bltu"
            | "bgeu"
    )
}

fn writes_rd(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "add"
            | "sub"
            | "sll"
            | "slt"
            | "sltu"
            | "xor"
            | "srl"
            | "sra"
            | "or"
            | "and"
            | "mul"
            | "mulh"
            | "mulhsu"
            | "mulhu"
            | "div"
            | "divu"
            | "rem"
            | "remu"
            | "addi"
            | "slti"
            | "sltiu"
            | "xori"
            | "ori"
            | "andi"
            | "slli"
            | "srli"
            | "srai"
            | "lb"
            | "lh"
            | "lw"
            | "lbu"
            | "lhu"
            | "lui"
            | "auipc"
            | "jal"
            | "jalr"
    )
}

fn write_source(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        "add" | "sub" | "sll" | "slt" | "sltu" | "xor" | "srl" | "sra" | "or" | "and" => {
            Some("alu_r")
        }
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai" => {
            Some("alu_i")
        }
        "lb" | "lh" | "lw" | "lbu" | "lhu" => Some("load"),
        "lui" => Some("lui"),
        "auipc" => Some("auipc"),
        "jal" => Some("jal"),
        "jalr" => Some("jalr"),
        "mul" | "mulh" | "mulhsu" | "mulhu" => Some("mul"),
        "div" | "divu" | "rem" | "remu" => Some("div"),
        _ => None,
    }
}

fn rf3_source_cell(source: &str) -> Option<&'static str> {
    match source {
        "alu_r" | "alu_i" => Some("rf3.alu"),
        "load" => Some("rf3.load"),
        "jal" | "jalr" => Some("rf3.link"),
        "lui" | "auipc" => Some("rf3.upper"),
        "mul" | "div" => Some("rf3.muldiv"),
        _ => None,
    }
}

fn id4_cell(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        "add" | "sub" | "sll" | "slt" | "sltu" | "xor" | "srl" | "sra" | "or" | "and" => {
            Some("id4.alu_r")
        }
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai" => {
            Some("id4.alu_i")
        }
        "lb" | "lh" | "lw" | "lbu" | "lhu" => Some("id4.load"),
        "sb" | "sh" | "sw" => Some("id4.store"),
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => Some("id4.branch"),
        "jal" => Some("id4.jal"),
        "jalr" => Some("id4.jalr"),
        "lui" => Some("id4.lui"),
        "auipc" => Some("id4.auipc"),
        "ecall" => Some("id4.ecall"),
        "mul" | "mulh" | "mulhsu" | "mulhu" => Some("id4.mul"),
        "div" | "divu" | "rem" | "remu" => Some("id4.div"),
        _ => None,
    }
}

fn imm_format_cell(mnemonic: &str, imm: i32) -> Option<&'static str> {
    match mnemonic {
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

fn is_i_alu(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai"
    )
}

fn is_comparison(mnemonic: &str) -> bool {
    matches!(mnemonic, "slt" | "sltu" | "slti" | "sltiu" | "blt" | "bge" | "bltu" | "bgeu")
}

fn is_branch(mnemonic: &str) -> bool {
    matches!(mnemonic, "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu")
}

fn is_control(mnemonic: &str) -> bool {
    is_branch(mnemonic) || matches!(mnemonic, "jal" | "jalr" | "ecall" | "ebreak")
}

fn classify_limb_diff(a: u32, b: u32) -> &'static str {
    if a == b {
        return "al5.all_equal";
    }
    let a_bytes = a.to_be_bytes();
    let b_bytes = b.to_be_bytes();
    let first_diff = a_bytes.iter().zip(b_bytes).position(|(x, y)| *x != y).unwrap_or(0);
    if first_diff == 0 {
        "al5.first_limb_diff"
    } else if first_diff == 3 {
        "al5.last_limb_diff"
    } else {
        "al5.alternating_borrow"
    }
}

fn emit_instruction_buckets(
    bucket_hits: &mut Vec<BucketHit>,
    instructions: &[ExecutedInstruction],
) {
    for (idx, insn) in instructions.iter().enumerate() {
        if idx == 0 {
            let cell_id = if insn.pc == 0 { "cf4.default_entry" } else { "cf4.custom_entry" };
            push_instr_hit(
                bucket_hits,
                semantic::control::ENTRYPOINT_BINDING,
                "cf4",
                cell_id,
                insn,
            );
            push_instr_hit(
                bucket_hits,
                semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
                "ts1",
                "ts1.standard",
                insn,
            );
            push_instr_hit(
                bucket_hits,
                semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
                "ts3",
                "ts3.standard",
                insn,
            );
        }

        if let Some(cell_id) = id4_cell(&insn.mnemonic) {
            push_instr_hit(bucket_hits, semantic::exec::OP_SELECTOR_BINDING, "id4", cell_id, insn);
        }

        emit_register_decode_buckets(bucket_hits, insn);
        emit_alu_buckets(bucket_hits, insn);
        emit_muldiv_buckets(bucket_hits, insn);
        emit_control_buckets(bucket_hits, instructions, idx);
    }
}

fn emit_register_decode_buckets(bucket_hits: &mut Vec<BucketHit>, insn: &ExecutedInstruction) {
    if let Some(rd) = insn.rd {
        if rd == 0 && writes_rd(&insn.mnemonic) {
            if let Some(source) = write_source(&insn.mnemonic) {
                let cell_id = match source {
                    "alu_r" => "rf1.alu_r",
                    "alu_i" => "rf1.alu_i",
                    "lui" => "rf1.lui",
                    "auipc" => "rf1.auipc",
                    "load" => "rf1.load",
                    "jal" => "rf1.jal",
                    "jalr" => "rf1.jalr",
                    "mul" => "rf1.mul",
                    "div" => "rf1.div",
                    _ => "rf1.alu_r",
                };
                push_instr_hit(
                    bucket_hits,
                    semantic::decode::ZERO_REGISTER_IMMUTABILITY,
                    "rf1",
                    cell_id,
                    insn,
                );
            }
        } else if rd != 0 && writes_rd(&insn.mnemonic) {
            if let Some(cell_id) = write_source(&insn.mnemonic).and_then(rf3_source_cell) {
                push_instr_hit(bucket_hits, semantic::exec::DEST_BINDING, "rf3", cell_id, insn);
            }
        }
    }

    if reads_rs1(&insn.mnemonic) || reads_rs2(&insn.mnemonic) {
        if let (Some(rs1), Some(rs2), Some(rd)) = (insn.rs1, insn.rs2, insn.rd) {
            let cell_id = if rs1 == rs2 && rs2 == rd {
                "rf2.all_same"
            } else if rs1 == rs2 {
                "rf2.rs1_eq_rs2"
            } else if rs1 == rd {
                "rf2.rs1_eq_rd"
            } else if rs2 == rd {
                "rf2.rs2_eq_rd"
            } else {
                "rf2.no_alias"
            };
            push_instr_hit(
                bucket_hits,
                semantic::decode::OPERAND_INDEX_ROUTING,
                "rf2",
                cell_id,
                insn,
            );
        }
        if insn.rs1 == Some(0) {
            push_instr_hit(
                bucket_hits,
                semantic::decode::OPERAND_INDEX_ROUTING,
                "rf2",
                "rf2.rs1_x0",
                insn,
            );
        }
        if insn.rs2 == Some(0) {
            push_instr_hit(
                bucket_hits,
                semantic::decode::OPERAND_INDEX_ROUTING,
                "rf2",
                "rf2.rs2_x0",
                insn,
            );
        }
    }

    for reg in [insn.rd, insn.rs1, insn.rs2].into_iter().flatten() {
        let cell_id = if reg == 0 {
            "id1.reg_zero"
        } else if reg == 31 {
            "id1.reg_max"
        } else {
            "id1.reg_mid"
        };
        push_instr_hit(bucket_hits, semantic::decode::FIELD_RANGE, "id1", cell_id, insn);
    }
    if raw_funct3(insn.raw_word) == 7 || raw_funct7(insn.raw_word) == 127 {
        push_instr_hit(bucket_hits, semantic::decode::FIELD_RANGE, "id1", "id1.funct_max", insn);
    }

    if let Some(imm) = insn.imm {
        if let Some(cell_id) = imm_format_cell(&insn.mnemonic, imm) {
            push_instr_hit(
                bucket_hits,
                semantic::decode::IMMEDIATE_SIGN_EXTENSION,
                "id2",
                cell_id,
                insn,
            );
        }

        match insn.mnemonic.as_str() {
            "lui" => {
                let u_imm = insn.raw_word >> 12;
                let cell_id = if u_imm == 0 {
                    "id3.lui_zero"
                } else if u_imm == 0x000f_ffff {
                    "id3.lui_max"
                } else {
                    "id3.lui_mid"
                };
                push_instr_hit(
                    bucket_hits,
                    semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION,
                    "id3",
                    cell_id,
                    insn,
                );
            }
            "auipc" => {
                let addend = (insn.raw_word & 0xffff_f000) as u64;
                let cell_id = if u64::from(insn.pc) + addend >= (1u64 << 32) {
                    "id3.auipc_wrap"
                } else {
                    "id3.auipc_no_wrap"
                };
                push_instr_hit(
                    bucket_hits,
                    semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION,
                    "id3",
                    cell_id,
                    insn,
                );
            }
            "sb" | "sh" | "sw" => {
                push_instr_hit(
                    bucket_hits,
                    semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY,
                    "id5",
                    "id5.s_type",
                    insn,
                );
            }
            "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
                push_instr_hit(
                    bucket_hits,
                    semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY,
                    "id5",
                    "id5.b_type",
                    insn,
                );
            }
            "jal" => {
                push_instr_hit(
                    bucket_hits,
                    semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY,
                    "id5",
                    "id5.j_type",
                    insn,
                );
            }
            _ => {}
        }
        if matches!(
            insn.mnemonic.as_str(),
            "sb" | "sh" | "sw" | "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "jal"
        ) && imm.unsigned_abs() > 0xff
        {
            push_instr_hit(
                bucket_hits,
                semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY,
                "id5",
                "id5.cross_field",
                insn,
            );
        }
    }
}

fn emit_alu_buckets(bucket_hits: &mut Vec<BucketHit>, insn: &ExecutedInstruction) {
    if is_i_alu(&insn.mnemonic) {
        if let Some(imm) = insn.imm {
            let cell_id = if matches!(imm, 255 | 256 | -1 | -2048 | 2047) {
                "al1.boundary"
            } else if imm < 0 {
                "al1.negative"
            } else if imm <= 255 {
                "al1.single_limb"
            } else {
                "al1.cross_01"
            };
            push_instr_hit(
                bucket_hits,
                semantic::alu::IMMEDIATE_LIMB_CONSISTENCY,
                "al1",
                cell_id,
                insn,
            );
        }
    }

    if matches!(insn.mnemonic.as_str(), "sll" | "srl" | "sra" | "slli" | "srli" | "srai") {
        let shamt_input = insn.rs2_val.or_else(|| insn.imm.map(i32_bits)).unwrap_or(0);
        let shamt = shamt_input & 0x1f;
        let rs1_val = insn.rs1_val.unwrap_or(0);
        let cell_id = match insn.mnemonic.as_str() {
            "sll" | "slli" if shamt == 0 => "al2.shamt_zero",
            "sll" | "slli" if shamt_input >= 32 => "al2.sll_ge32",
            "sll" | "slli" => "al2.sll_lt32",
            "srl" | "srli" if shamt == 0 => "al2.shamt_zero",
            "srl" | "srli" if shamt_input >= 32 => "al2.srl_ge32",
            "srl" | "srli" => "al2.srl_lt32",
            "sra" | "srai" if shamt == 0 => "al2.shamt_zero",
            "sra" | "srai" if shamt_input >= 32 && (rs1_val as i32) < 0 => "al2.sra_ge32_neg",
            "sra" | "srai" if shamt_input >= 32 => "al2.sra_ge32_pos",
            "sra" | "srai" if (rs1_val as i32) < 0 => "al2.sra_lt32_neg",
            "sra" | "srai" => "al2.sra_lt32_pos",
            _ => "al2.shamt_zero",
        };
        let mut details = instr_details("al2", cell_id, insn);
        details.insert("effective_shamt".to_string(), json!(shamt));
        details.insert("shamt_input".to_string(), json!(shamt_input));
        bucket_hits.push(BucketHit::semantic(semantic::alu::SHIFT_MOD32, details));
    }

    if matches!(insn.mnemonic.as_str(), "slt" | "sltu" | "slti" | "sltiu") {
        let rhs = insn.rs2_val.or_else(|| insn.imm.map(i32_bits)).unwrap_or(0);
        let lhs = insn.rs1_val.unwrap_or(0);
        let rd_val = insn.rd_val.unwrap_or(0);
        let signed_less = signed_u32(lhs) < signed_u32(rhs);
        let unsigned_less = lhs < rhs;
        let cell_id = match insn.mnemonic.as_str() {
            "slt" | "slti" if lhs == rhs => "al3.equal",
            "slt" | "slti" if signed_less => "al3.slt_true",
            "slt" | "slti" => "al3.slt_false",
            "sltu" | "sltiu" if lhs == rhs => "al3.equal",
            "sltu" | "sltiu" if unsigned_less => "al3.sltu_true",
            "sltu" | "sltiu" => "al3.sltu_false",
            _ => "al3.equal",
        };
        let mut details = instr_details("al3", cell_id, insn);
        details.insert("result_boolean".to_string(), json!(rd_val));
        bucket_hits.push(BucketHit::semantic(semantic::alu::COMPARISON_BOOLEANITY, details));
        if signed_less != unsigned_less {
            push_instr_hit(
                bucket_hits,
                semantic::alu::COMPARISON_BOOLEANITY,
                "al3",
                "al3.sign_disagree",
                insn,
            );
        }
    }

    if insn.mnemonic == "sub" || is_comparison(&insn.mnemonic) {
        let rhs = insn.rs2_val.or_else(|| insn.imm.map(i32_bits)).unwrap_or(0);
        let lhs = insn.rs1_val.unwrap_or(0);
        let cell_id = if lhs == rhs {
            "al4.equal"
        } else if lhs < rhs {
            "al4.borrow"
        } else if (lhs & 0xff) < (rhs & 0xff) {
            "al4.cross_limb"
        } else {
            "al4.no_borrow"
        };
        push_instr_hit(bucket_hits, semantic::alu::SUBTRACTION_BORROW_CHAIN, "al4", cell_id, insn);
    }

    if is_comparison(&insn.mnemonic) {
        let rhs = insn.rs2_val.or_else(|| insn.imm.map(i32_bits)).unwrap_or(0);
        let lhs = insn.rs1_val.unwrap_or(0);
        push_instr_hit(
            bucket_hits,
            semantic::alu::COMPARISON_AUXILIARY_CHAIN,
            "al5",
            classify_limb_diff(lhs, rhs),
            insn,
        );
    }
}

fn emit_muldiv_buckets(bucket_hits: &mut Vec<BucketHit>, insn: &ExecutedInstruction) {
    let lhs = insn.rs1_val.unwrap_or(0);
    let rhs = insn.rs2_val.unwrap_or(0);
    match insn.mnemonic.as_str() {
        "div" | "divu" | "rem" | "remu" if rhs == 0 => {
            let cell_id = match insn.mnemonic.as_str() {
                "div" => "md1.div_zero",
                "divu" => "md1.divu_zero",
                "rem" => "md1.rem_zero",
                "remu" => "md1.remu_zero",
                _ => "md1.div_zero",
            };
            push_instr_hit(
                bucket_hits,
                semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                "md1",
                cell_id,
                insn,
            );
            let dividend_cell = if lhs == 0 {
                "md1.dividend_zero"
            } else if signed_u32(lhs) < 0 {
                "md1.dividend_neg"
            } else {
                "md1.dividend_pos"
            };
            push_instr_hit(
                bucket_hits,
                semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                "md1",
                dividend_cell,
                insn,
            );
        }
        "div" | "rem" if lhs == 0x8000_0000 && rhs == 0xffff_ffff => {
            let cell_id =
                if insn.mnemonic == "div" { "md2.div_overflow" } else { "md2.rem_overflow" };
            push_instr_hit(
                bucket_hits,
                semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                "md2",
                cell_id,
                insn,
            );
        }
        "div" | "divu" | "rem" | "remu" if rhs != 0 => {
            let cell_id = if matches!(insn.mnemonic.as_str(), "divu" | "remu") {
                "md3.unsigned"
            } else if lhs % rhs == 0 {
                "md3.exact"
            } else if rhs == 1 || rhs == 0xffff_ffff {
                "md3.one"
            } else if lhs / rhs > 0x4000_0000 {
                "md3.large_q"
            } else {
                match (signed_u32(lhs) >= 0, signed_u32(rhs) >= 0) {
                    (true, true) => "md3.pp",
                    (true, false) => "md3.pn",
                    (false, true) => "md3.np",
                    (false, false) => "md3.nn",
                }
            };
            push_instr_hit(
                bucket_hits,
                semantic::arithmetic::DIVISION_REMAINDER_BOUND,
                "md3",
                cell_id,
                insn,
            );
        }
        "mul" | "mulh" | "mulhsu" | "mulhu" => {
            let unsigned_product = u64::from(lhs) * u64::from(rhs);
            let signed_product =
                i64::from(signed_u32(lhs)) as i128 * i64::from(signed_u32(rhs)) as i128;
            let mixed_product = i64::from(signed_u32(lhs)) as i128 * u64::from(rhs) as i128;
            let product = match insn.mnemonic.as_str() {
                "mulh" => signed_product,
                "mulhsu" => mixed_product,
                _ => unsigned_product as i128,
            };
            let product_lo = product as u64 as u32;
            let product_hi = ((product as u128) >> 32) as u32;
            let cell_id = match insn.mnemonic.as_str() {
                "mul" if lhs == 0 || rhs == 0 => "md4.zero_op",
                "mul" if unsigned_product < (1u64 << 32) => "md4.mul_small",
                "mul" => "md4.mul_overflow",
                "mulh" if signed_u32(lhs) >= 0 && signed_u32(rhs) >= 0 => "md4.mulh_pp",
                "mulh" if signed_u32(lhs) < 0 && signed_u32(rhs) < 0 => "md4.mulh_nn",
                "mulh" => "md4.mulh_pn",
                "mulhu" => "md4.mulhu",
                "mulhsu" => "md4.mulh_pn",
                _ => "md4.mul_small",
            };
            let mut details = instr_details("md4", cell_id, insn);
            details.insert("product_lo".to_string(), json!(product_lo));
            details.insert("product_hi".to_string(), json!(product_hi));
            bucket_hits
                .push(BucketHit::semantic(semantic::arithmetic::PRODUCT_DECOMPOSITION, details));
            if lhs == u32::MAX || rhs == u32::MAX || lhs == 0x7fff_ffff || rhs == 0x7fff_ffff {
                push_instr_hit(
                    bucket_hits,
                    semantic::arithmetic::PRODUCT_DECOMPOSITION,
                    "md4",
                    "md4.max_product",
                    insn,
                );
            }

            if insn.mnemonic == "mulhsu" {
                let cell_id = if signed_u32(lhs) >= 0 {
                    "md5.pos_any"
                } else if lhs == u32::MAX && rhs == u32::MAX {
                    "md5.neg_max"
                } else if rhs == 1 {
                    "md5.neg_one"
                } else if rhs < 0x1_0000 {
                    "md5.neg_small"
                } else {
                    "md5.neg_large"
                };
                push_instr_hit(
                    bucket_hits,
                    semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION,
                    "md5",
                    cell_id,
                    insn,
                );
            }
        }
        _ => {}
    }
}

fn emit_control_buckets(
    bucket_hits: &mut Vec<BucketHit>,
    instructions: &[ExecutedInstruction],
    idx: usize,
) {
    let insn = &instructions[idx];
    if is_branch(&insn.mnemonic) {
        let taken = insn.next_pc != insn.pc.wrapping_add(4);
        let rs1 = insn.rs1_val.unwrap_or(0);
        let rs2 = insn.rs2_val.unwrap_or(0);
        let cell_id = match insn.mnemonic.as_str() {
            "beq" => {
                if rs1 == rs2 {
                    "cf1.beq_equal"
                } else {
                    "cf1.bne_not_equal"
                }
            }
            "bne" => {
                if rs1 != rs2 {
                    "cf1.bne_not_equal"
                } else {
                    "cf1.beq_equal"
                }
            }
            "blt" if taken => "cf1.blt_taken",
            "blt" => "cf1.blt_not_taken",
            "bge" if taken => "cf1.bge_taken",
            "bge" => "cf1.bge_not_taken",
            "bltu" if taken => "cf1.bltu_taken",
            "bltu" => "cf1.bltu_not_taken",
            "bgeu" if taken => "cf1.bgeu_taken",
            "bgeu" => "cf1.bgeu_not_taken",
            _ => "cf1.bne_not_equal",
        };
        let mut details = instr_details("cf1", cell_id, insn);
        details.insert("taken".to_string(), json!(taken));
        if let Some(target_pc) = branch_target(insn) {
            details.insert("target_pc".to_string(), json!(target_pc));
        }
        bucket_hits.push(BucketHit::semantic(semantic::exec::CONTROL_FLOW_BINDING, details));
        if (signed_u32(rs1) < 0) != (signed_u32(rs2) < 0) {
            push_instr_hit(
                bucket_hits,
                semantic::exec::CONTROL_FLOW_BINDING,
                "cf1",
                "cf1.sign_flip",
                insn,
            );
        }
    }

    match insn.mnemonic.as_str() {
        "jal" => {
            let cell_id = if insn.rd == Some(0) { "cf2.jal_x0" } else { "cf2.jal_rd" };
            let mut details = instr_details("cf2", cell_id, insn);
            details.insert("link_pc".to_string(), json!(insn.pc.wrapping_add(4)));
            bucket_hits.push(BucketHit::semantic(semantic::exec::CONTROL_FLOW_BINDING, details));
        }
        "jalr" => {
            let cell_id = if insn.rd == Some(0) { "cf2.jalr_x0" } else { "cf2.jalr_rd" };
            let mut details = instr_details("cf2", cell_id, insn);
            details.insert("link_pc".to_string(), json!(insn.pc.wrapping_add(4)));
            bucket_hits.push(BucketHit::semantic(semantic::exec::CONTROL_FLOW_BINDING, details));

            let imm = insn.imm.unwrap_or(0);
            let imm_cell = if imm == 0 {
                "cf3.imm_zero"
            } else if imm > 0 {
                "cf3.imm_pos"
            } else {
                "cf3.imm_neg"
            };
            push_instr_hit(
                bucket_hits,
                semantic::exec::CONTROL_FLOW_BINDING,
                "cf3",
                imm_cell,
                insn,
            );
            if let Some(rs1_val) = insn.rs1_val {
                let target_before = rs1_val.wrapping_add(i32_bits(imm));
                let target_after = target_before & !1;
                let cell_id = if u64::from(rs1_val) + u64::from(i32_bits(imm)) >= (1u64 << 32) {
                    "cf3.wrap"
                } else if target_before & 1 == 1 {
                    "cf3.clear_lsb"
                } else {
                    "cf3.even"
                };
                let mut details = instr_details("cf3", cell_id, insn);
                details.insert("target_before_lsb_clear".to_string(), json!(target_before));
                details.insert("target_after_lsb_clear".to_string(), json!(target_after));
                bucket_hits
                    .push(BucketHit::semantic(semantic::exec::CONTROL_FLOW_BINDING, details));
            }
        }
        "ecall" => {
            push_instr_hit(
                bucket_hits,
                semantic::control::ECALL_WORD_VALIDITY,
                "cf7",
                "cf7.standard",
                insn,
            );
        }
        _ => {}
    }

    if !is_control(&insn.mnemonic) && insn.next_pc == insn.pc.wrapping_add(4) {
        let previous_branch_not_taken = idx > 0
            && is_branch(&instructions[idx - 1].mnemonic)
            && instructions[idx - 1].next_pc == instructions[idx - 1].pc.wrapping_add(4);
        let cell_id =
            if previous_branch_not_taken { "cf6.after_branch_not_taken" } else { "cf6.normal" };
        push_instr_hit(bucket_hits, semantic::exec::CONTROL_FLOW_BINDING, "cf6", cell_id, insn);
    }
}

fn emit_memory_extension_buckets(
    bucket_hits: &mut Vec<BucketHit>,
    loads: &[ExecutedMemoryAccess],
    stores: &[(ExecutedMemoryAccess, u32)],
) {
    for load in loads {
        if let Some(cell_id) = match load.mnemonic.as_str() {
            "lb" if load.value & 0x80 == 0 => Some("me3.lb_pos"),
            "lb" => Some("me3.lb_neg"),
            "lh" if load.value & 0x8000 == 0 => Some("me3.lh_pos"),
            "lh" => Some("me3.lh_neg"),
            "lbu" => Some("me3.lbu"),
            "lhu" => Some("me3.lhu"),
            _ => None,
        } {
            let mut details = base_details("me3", cell_id, load);
            details.insert("read_data".to_string(), json!(load.value));
            details.insert("byte_offset".to_string(), json!(load.address & 0x3));
            bucket_hits.push(BucketHit::semantic(semantic::memory::LOAD_VALUE_BINDING, details));
        }

        let mut details = base_details("me5", "me5.mem_read", load);
        details.insert("address_space".to_string(), json!("main_memory"));
        details.insert("is_load".to_string(), json!(true));
        details.insert("is_store".to_string(), json!(false));
        bucket_hits.push(BucketHit::semantic(semantic::memory::ADDRESS_SPACE_CONSISTENCY, details));

        if !stores
            .iter()
            .any(|(store, _)| store.op_idx < load.op_idx && store.address == load.address)
        {
            let cell_id = if load.value == 0 { "me7.bss_zero" } else { "me7.data_loaded" };
            let mut details = base_details("me7", cell_id, load);
            details.insert("read_data".to_string(), json!(load.value));
            details.insert("no_prior_write".to_string(), json!(true));
            bucket_hits.push(BucketHit::semantic(semantic::memory::INITIAL_VALUE_BINDING, details));
        }
    }

    for (store, _) in stores {
        let mut details = base_details("me5", "me5.mem_write", store);
        details.insert("address_space".to_string(), json!("main_memory"));
        details.insert("is_load".to_string(), json!(false));
        details.insert("is_store".to_string(), json!(true));
        bucket_hits.push(BucketHit::semantic(semantic::memory::ADDRESS_SPACE_CONSISTENCY, details));
    }

    for access in loads.iter().chain(stores.iter().map(|(store, _)| store)) {
        if access.size_bytes > 1 && access.address % u32::from(access.size_bytes) != 0 {
            let cell_id = match (access.size_bytes, access.address & 0x3) {
                (2, _) => "me2.half_off1",
                (4, 1) => "me2.word_off1",
                (4, 2) => "me2.word_off2",
                (4, _) => "me2.word_off3",
                _ => "me2.byte_any",
            };
            let mut details = base_details("me2", cell_id, access);
            details.insert("byte_offset".to_string(), json!(access.address & 0x3));
            details.insert(
                "aligned_ptr".to_string(),
                json!(access.address & !(u32::from(access.size_bytes) - 1)),
            );
            bucket_hits.push(BucketHit::semantic(
                semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                details,
            ));
        } else if access.size_bytes == 1 {
            push_memory_hit(
                bucket_hits,
                semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                "me2",
                "me2.byte_any",
                access,
            );
        }

        if access.size_bytes < 4 {
            let cell_id = match access.address & 0x3 {
                0 => "me9.off0",
                1 => "me9.off1",
                2 => "me9.off2",
                _ => "me9.off3",
            };
            let mut details = base_details("me9", cell_id, access);
            details.insert("byte_offset".to_string(), json!(access.address & 0x3));
            details.insert("aligned_ptr".to_string(), json!(access.address & !3));
            bucket_hits.push(BucketHit::semantic(
                semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY,
                details,
            ));
        }

        if access.address >= u32::MAX.saturating_sub(u32::from(access.size_bytes)) {
            let cell_id = match (access.mnemonic.as_str(), access.size_bytes) {
                ("lw", 4) => "me6.near_max_lw",
                ("sw", 4) => "me6.near_max_sw",
                ("lh" | "lhu", 2) => "me6.near_max_lh",
                ("sb", 1) => "me6.near_max_sb",
                _ => "me6.heap_boundary",
            };
            push_memory_hit(
                bucket_hits,
                semantic::memory::ADDRESS_BOUNDARY_RANGE,
                "me6",
                cell_id,
                access,
            );
        }
    }

    let mut accesses = loads
        .iter()
        .map(|load| (load, true))
        .chain(stores.iter().map(|(store, _)| (store, false)))
        .collect::<Vec<_>>();
    accesses.sort_by_key(|(access, _)| access.op_idx);
    for pair in accesses.windows(2) {
        let (prev, _) = pair[0];
        let (next, _) = pair[1];
        if prev.address == next.address {
            let diff = next.timestamp.saturating_sub(prev.timestamp);
            let cell_id = if diff == 1 {
                "ts2.consecutive"
            } else if diff < 16 {
                "ts2.small_gap"
            } else {
                "ts2.large_gap"
            };
            let mut details = base_details("ts2", cell_id, next);
            details.insert("previous_timestamp".to_string(), json!(prev.timestamp));
            details.insert("ts_diff".to_string(), json!(diff));
            bucket_hits
                .push(BucketHit::semantic(semantic::time::MONOTONIC_ACCESS_ORDERING, details));
        }
        if prev.size_bytes < 4 && next.size_bytes < 4 && prev.address.abs_diff(next.address) == 1 {
            let cell_id = if (prev.address & !3) == (next.address & !3) {
                "me9.adjacent_same_word"
            } else {
                "me9.adjacent_diff_word"
            };
            let mut details = base_details("me9", cell_id, next);
            details.insert("previous_address".to_string(), json!(prev.address));
            bucket_hits.push(BucketHit::semantic(
                semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY,
                details,
            ));
        }
    }
}

fn push_memory_hit(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    obligation_id: &str,
    cell_id: &str,
    access: &ExecutedMemoryAccess,
) {
    hits.push(BucketHit::semantic(bucket, base_details(obligation_id, cell_id, access)));
}

impl NexusTrace {
    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        let program = nexus_vm::riscv::decode_instructions(words);
        let (_view, trace) = nexus_vm::trace::k_trace_direct(&program.blocks, 1)
            .map_err(|e| format!("nexus k_trace_direct failed: {e}"))?;
        Ok(Self::from_words_and_uniform_trace(words, &trace))
    }

    pub fn from_words_and_uniform_trace(_words: &[u32], trace: &UniformTrace) -> Self {
        let mut sequence = Vec::new();
        let mut instructions = Vec::new();
        let mut stores = Vec::new();
        let mut loads = Vec::new();
        let mut global_step = 0u64;

        for block in &trace.blocks {
            let mut regs = block.regs;
            for step in &block.steps {
                let Some(decoded) =
                    RV32IMInstruction::decode_with_pc(step.raw_instruction, step.pc)
                else {
                    global_step = global_step.saturating_add(1);
                    continue;
                };

                sequence.push(SequenceInsnObservation {
                    step_idx: global_step,
                    word: step.raw_instruction,
                    mnemonic: decoded.mnemonic.clone(),
                    rs1: decoded.rs1,
                    imm: decoded.imm,
                });

                let rs1_val = decoded.rs1.map(|rs1| regs.read(Register::from(rs1 as u8)));
                let rs2_val = decoded.rs2.map(|rs2| regs.read(Register::from(rs2 as u8)));
                instructions.push(ExecutedInstruction {
                    op_idx: global_step,
                    timestamp: step.timestamp,
                    pc: step.pc,
                    next_pc: step.next_pc,
                    raw_word: step.raw_instruction,
                    mnemonic: decoded.mnemonic.clone(),
                    rd: decoded.rd,
                    rs1: decoded.rs1,
                    rs2: decoded.rs2,
                    imm: decoded.imm,
                    rs1_val,
                    rs2_val,
                    rd_val: step.result,
                });

                for record in &step.memory_records {
                    match record {
                        MemoryRecord::StoreRecord((size, address, value, prev_value), _) => {
                            stores.push((
                                ExecutedMemoryAccess {
                                    op_idx: global_step,
                                    timestamp: step.timestamp,
                                    pc: step.pc,
                                    raw_word: step.raw_instruction,
                                    mnemonic: decoded.mnemonic.clone(),
                                    size_bytes: *size as u8,
                                    address: *address,
                                    value: *value,
                                },
                                *prev_value,
                            ));
                        }
                        MemoryRecord::LoadRecord((size, address, value), _) => {
                            loads.push(ExecutedMemoryAccess {
                                op_idx: global_step,
                                timestamp: step.timestamp,
                                pc: step.pc,
                                raw_word: step.raw_instruction,
                                mnemonic: decoded.mnemonic.clone(),
                                size_bytes: *size as u8,
                                address: *address,
                                value: *value,
                            });
                        }
                    }
                }
                if let (Some(rd), Some(value)) = (decoded.rd, step.result) {
                    regs.write(Register::from(rd as u8), value);
                }
                global_step = global_step.saturating_add(1);
            }
        }

        let trace_signals = semantic_matchers::sequence_trace_signals(&sequence);
        let mut bucket_hits = Vec::new();
        emit_instruction_buckets(&mut bucket_hits, &instructions);

        for load in &loads {
            let mut details = base_details("me10", "me10.load", load);
            details.insert("is_load".to_string(), json!(true));
            details.insert("is_store".to_string(), json!(false));
            details.insert("read_data".to_string(), json!(load.value));
            bucket_hits
                .push(BucketHit::semantic(semantic::memory::KIND_SELECTOR_CONSISTENCY, details));
        }

        for (store, prev_value) in &stores {
            let mut details = base_details("me10", "me10.store", store);
            details.insert("is_load".to_string(), json!(false));
            details.insert("is_store".to_string(), json!(true));
            details.insert("write_data".to_string(), json!(store.value));
            details.insert("prev_data".to_string(), json!(prev_value));
            bucket_hits
                .push(BucketHit::semantic(semantic::memory::KIND_SELECTOR_CONSISTENCY, details));

            if let Some(cell_id) = me4_cell(&store.mnemonic, store.address) {
                let mut details = base_details("me4", cell_id, store);
                details.insert("write_data".to_string(), json!(store.value));
                details.insert("prev_data".to_string(), json!(prev_value));
                details.insert("byte_offset".to_string(), json!(store.address & 0x3));
                bucket_hits.push(BucketHit::semantic(
                    semantic::memory::WRITE_PAYLOAD_CONSISTENCY,
                    details,
                ));
            }

            if let Some(load) = loads
                .iter()
                .find(|load| load.op_idx > store.op_idx && load.address == store.address)
            {
                if let Some(cell_id) = me1_cell(&store.mnemonic, &load.mnemonic) {
                    let mut details = base_details("me1", cell_id, store);
                    details.insert("write_data".to_string(), json!(store.value));
                    details.insert("prev_data".to_string(), json!(prev_value));
                    details.insert("load_step_idx".to_string(), json!(load.op_idx));
                    details.insert("load_pc".to_string(), json!(load.pc));
                    details.insert("load_mnemonic".to_string(), json!(load.mnemonic));
                    details.insert("read_data".to_string(), json!(load.value));
                    bucket_hits.push(BucketHit::semantic(
                        semantic::memory::STORE_LOAD_PAYLOAD_FLOW,
                        details,
                    ));
                }
            }

            if stores.iter().any(|(prev_store, _)| {
                prev_store.op_idx < store.op_idx && prev_store.address == store.address
            }) && loads
                .iter()
                .any(|load| load.op_idx > store.op_idx && load.address == store.address)
            {
                let mut details = base_details("me1", "me1.overwrite", store);
                details.insert("write_data".to_string(), json!(store.value));
                details.insert("prev_data".to_string(), json!(prev_value));
                bucket_hits
                    .push(BucketHit::semantic(semantic::memory::STORE_LOAD_PAYLOAD_FLOW, details));
            }
        }
        emit_memory_extension_buckets(&mut bucket_hits, &loads, &stores);

        Self {
            bucket_hits,
            trace_signals,
            step_count: trace.blocks.iter().map(|block| block.steps.len()).sum(),
        }
    }

    pub fn step_count(&self) -> usize {
        self.step_count
    }

    pub fn from_uniform_trace(trace: &UniformTrace) -> Self {
        Self::from_words_and_uniform_trace(&[], trace)
    }
}

impl Trace for NexusTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }

    fn trace_signals(&self) -> &[TraceSignal] {
        &self.trace_signals
    }
}
