use std::collections::HashMap;

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use common::constants::RAM_START_ADDRESS;
use serde_json::json;

use crate::JOLT_COMMIT;

const BACKEND: &str = "jolt";

pub struct JoltTrace {
    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,
}

#[derive(Debug, Clone)]
pub struct CycleObservation {
    pub step_idx: u64,
    pub pc: u64,
    pub rs1: Option<(u8, u64)>,
    pub rs2: Option<(u8, u64)>,
    pub rd: Option<(u8, u64, u64)>,
}

fn input_signals(words: &[u32]) -> Vec<TraceSignal> {
    let mut out = Vec::new();
    let mut has_load = false;
    let mut has_store = false;
    let mut has_auipc = false;
    let mut has_ecall = false;

    for word in words {
        let Some(decoded) = RV32IMInstruction::decode(*word) else {
            continue;
        };
        match decoded.mnemonic.as_str() {
            "lb" | "lh" | "lw" | "lbu" | "lhu" => has_load = true,
            "sb" | "sh" | "sw" => has_store = true,
            "auipc" => has_auipc = true,
            "ecall" => has_ecall = true,
            _ => {}
        }
    }

    if has_load {
        out.push(TraceSignal::HasLoad);
    }
    if has_store {
        out.push(TraceSignal::HasStore);
    }
    if has_load && has_store {
        out.push(TraceSignal::HasLoadStore);
    }
    if has_auipc {
        out.push(TraceSignal::HasAuipc);
    }
    if has_ecall {
        out.push(TraceSignal::HasEcall);
    }
    out
}

fn details_for(
    obligation_id: &str,
    cell_id: &str,
    op_idx: u64,
    program_op_idx: usize,
    pc: u64,
    raw_word: u32,
    decoded: &RV32IMInstruction,
) -> HashMap<String, serde_json::Value> {
    let mut details = HashMap::from([
        ("obligation_id".to_string(), json!(obligation_id)),
        ("cell_id".to_string(), json!(cell_id)),
        ("op_idx".to_string(), json!(op_idx)),
        ("step_idx".to_string(), json!(op_idx)),
        ("pc".to_string(), json!(pc)),
        ("program_op_idx".to_string(), json!(program_op_idx)),
        ("raw_word".to_string(), json!(format!("0x{raw_word:08x}"))),
        ("opcode".to_string(), json!(format!("0x{:02x}", raw_word & 0x7f))),
        ("mnemonic".to_string(), json!(decoded.mnemonic)),
        ("backend".to_string(), json!(BACKEND)),
        ("commit".to_string(), json!(JOLT_COMMIT)),
        ("trace_source".to_string(), json!("host.program.trace")),
    ]);
    if let Some(rd) = decoded.rd {
        details.insert("rd".to_string(), json!(rd));
    }
    if let Some(rs1) = decoded.rs1 {
        details.insert("rs1".to_string(), json!(rs1));
    }
    if let Some(rs2) = decoded.rs2 {
        details.insert("rs2".to_string(), json!(rs2));
    }
    if let Some(imm) = decoded.imm {
        details.insert("imm".to_string(), json!(imm));
    }
    details
}

fn push_hit(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    obligation_id: &str,
    cell_id: &str,
    op_idx: u64,
    program_op_idx: usize,
    pc: u64,
    raw_word: u32,
    decoded: &RV32IMInstruction,
) {
    hits.push(BucketHit::semantic(
        bucket,
        details_for(obligation_id, cell_id, op_idx, program_op_idx, pc, raw_word, decoded),
    ));
}

fn push_entrypoint_hit(hits: &mut Vec<BucketHit>, raw_word: u32, decoded: &RV32IMInstruction) {
    let details = HashMap::from([
        ("obligation_id".to_string(), json!("cf4")),
        ("cell_id".to_string(), json!("cf4.default_entry")),
        ("op_idx".to_string(), json!(0)),
        ("step_idx".to_string(), json!(0)),
        ("pc".to_string(), json!(RAM_START_ADDRESS)),
        ("program_op_idx".to_string(), json!(0)),
        ("opcode".to_string(), json!(format!("0x{raw_word:08x}"))),
        ("mnemonic".to_string(), json!(decoded.mnemonic)),
        ("backend".to_string(), json!(BACKEND)),
        ("commit".to_string(), json!(JOLT_COMMIT)),
        ("trace_source".to_string(), json!("host.program.trace")),
    ]);
    hits.push(BucketHit::semantic(semantic::control::ENTRYPOINT_BINDING, details));
}

fn is_immediate_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "addi"
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
            | "sb"
            | "sh"
            | "sw"
            | "beq"
            | "bne"
            | "blt"
            | "bge"
            | "bltu"
            | "bgeu"
            | "jal"
            | "jalr"
            | "lui"
            | "auipc"
    )
}

fn is_shift_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sll" | "slli" | "srl" | "srli" | "sra" | "srai")
}

fn is_comparison_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "slt" | "sltu" | "slti" | "sltiu" | "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu"
    )
}

fn is_branch_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu")
}

fn push_word_hits(
    hits: &mut Vec<BucketHit>,
    op_idx: u64,
    program_op_idx: usize,
    pc: u64,
    raw_word: u32,
    decoded: &RV32IMInstruction,
) {
    push_hit(
        hits,
        semantic::decode::FIELD_RANGE,
        "id1",
        "id1.rv32_field_bounds",
        op_idx,
        program_op_idx,
        pc,
        raw_word,
        decoded,
    );
    if is_immediate_mnemonic(decoded.mnemonic.as_str()) {
        push_hit(
            hits,
            semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY,
            "id5",
            "id5.format_immediate",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
        push_hit(
            hits,
            semantic::decode::IMMEDIATE_SIGN_EXTENSION,
            "id2",
            "id2.immediate_sign_extension",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
        push_hit(
            hits,
            semantic::alu::IMMEDIATE_LIMB_CONSISTENCY,
            "al1",
            "al1.immediate_limb",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
    }
    if matches!(decoded.mnemonic.as_str(), "lui" | "auipc") {
        push_hit(
            hits,
            semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION,
            "id3",
            "id3.upper_immediate",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
    }
    if is_shift_mnemonic(decoded.mnemonic.as_str()) {
        push_hit(
            hits,
            semantic::alu::SHIFT_MOD32,
            "al2",
            "al2.shift_mod32",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
    }
    if is_comparison_mnemonic(decoded.mnemonic.as_str()) {
        push_hit(
            hits,
            semantic::alu::COMPARISON_BOOLEANITY,
            "al3",
            "al3.comparison_boolean",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
        push_hit(
            hits,
            semantic::alu::COMPARISON_AUXILIARY_CHAIN,
            "al5",
            "al5.comparison_auxiliary",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
    }
    if decoded.mnemonic == "sub" {
        push_hit(
            hits,
            semantic::alu::SUBTRACTION_BORROW_CHAIN,
            "al4",
            "al4.subtraction_borrow",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
    }
    if is_branch_mnemonic(decoded.mnemonic.as_str()) {
        push_hit(
            hits,
            semantic::exec::CONTROL_FLOW_BINDING,
            "cf1",
            "cf1.branch_signedness",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
    }
    if matches!(decoded.mnemonic.as_str(), "jal" | "jalr") && decoded.rd.unwrap_or(0) != 0 {
        push_hit(
            hits,
            semantic::exec::CONTROL_FLOW_BINDING,
            "cf2",
            "cf2.link_register",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
    }
}

fn push_cycle_hits(
    hits: &mut Vec<BucketHit>,
    op_idx: u64,
    program_op_idx: usize,
    pc: u64,
    raw_word: u32,
    decoded: &RV32IMInstruction,
    cycle: &CycleObservation,
) {
    if cycle.rs1.is_some() || cycle.rs2.is_some() {
        push_hit(
            hits,
            semantic::exec::SOURCE_OPERAND_BINDING,
            "rf2",
            "rf2.operand_fetch",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
    }
    if let Some((rd, pre_value, post_value)) = cycle.rd {
        let mut details = details_for(
            "rf3",
            "rf3.writeback_binding",
            op_idx,
            program_op_idx,
            pc,
            raw_word,
            decoded,
        );
        details.insert("rd_observed".to_string(), json!(rd));
        details.insert("rd_pre_value".to_string(), json!(pre_value));
        details.insert("rd_post_value".to_string(), json!(post_value));
        hits.push(BucketHit::semantic(semantic::exec::DEST_BINDING, details));

        if rd == 0 {
            push_hit(
                hits,
                semantic::decode::ZERO_REGISTER_IMMUTABILITY,
                "rf1",
                "rf1.x0_immutable",
                op_idx,
                program_op_idx,
                pc,
                raw_word,
                decoded,
            );
        }
    }
}

impl JoltTrace {
    pub fn from_execution(words: &[u32], cycles: &[CycleObservation]) -> Result<Self, String> {
        let mut bucket_hits = Vec::new();
        if !cycles.is_empty() {
            if let Some(raw_word) = words.first().copied() {
                if let Some(decoded) =
                    RV32IMInstruction::decode_with_pc(raw_word, RAM_START_ADDRESS as u32)
                {
                    push_entrypoint_hit(&mut bucket_hits, raw_word, &decoded);
                }
            }
        }

        for cycle in cycles {
            if cycle.pc < RAM_START_ADDRESS || (cycle.pc - RAM_START_ADDRESS) % 4 != 0 {
                continue;
            }
            let program_op_idx = ((cycle.pc - RAM_START_ADDRESS) / 4) as usize;
            let Some(raw_word) = words.get(program_op_idx).copied() else {
                continue;
            };
            let Some(decoded) = RV32IMInstruction::decode_with_pc(raw_word, cycle.pc as u32) else {
                continue;
            };
            push_word_hits(
                &mut bucket_hits,
                cycle.step_idx,
                program_op_idx,
                cycle.pc,
                raw_word,
                &decoded,
            );
            push_cycle_hits(
                &mut bucket_hits,
                cycle.step_idx,
                program_op_idx,
                cycle.pc,
                raw_word,
                &decoded,
                cycle,
            );
        }

        Ok(Self { bucket_hits, trace_signals: input_signals(words) })
    }
}

impl Trace for JoltTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }

    fn trace_signals(&self) -> &[TraceSignal] {
        &self.trace_signals
    }
}
