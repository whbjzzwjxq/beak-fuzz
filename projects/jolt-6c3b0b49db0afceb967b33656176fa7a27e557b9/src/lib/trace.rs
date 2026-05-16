use std::collections::HashMap;

use beak_core::trace::{semantic, BucketHit, Trace};
use common::rv_trace::{ELFInstruction, RV32IM};
use serde_json::{json, Value};

const BACKEND: &str = "jolt";
const COMMIT: &str = "6c3b0b49db0afceb967b33656176fa7a27e557b9";

pub struct JoltTrace {
    bucket_hits: Vec<BucketHit>,
    instruction_count: usize,
}

fn push_table_hit_extra(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    obligation_id: &str,
    cell_id: &str,
    trace_source: &str,
    step_idx: u64,
    extras: &[(&str, Value)],
) {
    let mut details = HashMap::from([
        ("obligation_id".to_string(), json!(obligation_id)),
        ("cell_id".to_string(), json!(cell_id)),
        ("op_idx".to_string(), json!(step_idx)),
        ("step_idx".to_string(), json!(step_idx)),
        ("backend".to_string(), json!(BACKEND)),
        ("commit".to_string(), json!(COMMIT)),
        ("trace_source".to_string(), json!(trace_source)),
    ]);
    for (key, value) in extras {
        details.insert((*key).to_string(), value.clone());
    }
    hits.push(BucketHit::semantic(bucket, details));
}

fn expanded_bytecode_instruction_len(instruction: &ELFInstruction) -> usize {
    match instruction.opcode {
        RV32IM::MULH => 7,
        RV32IM::MULHSU => 4,
        RV32IM::DIV => 8,
        RV32IM::DIVU => 9,
        RV32IM::REM => 7,
        RV32IM::REMU => 8,
        RV32IM::SH => 12,
        RV32IM::SB => 11,
        RV32IM::LBU | RV32IM::LB => 7,
        RV32IM::LHU | RV32IM::LH => 8,
        _ => 1,
    }
}

fn virtualized_bytecode_len(bytecode: &[ELFInstruction]) -> usize {
    bytecode.iter().map(expanded_bytecode_instruction_len).sum::<usize>().max(1)
}

fn bytecode_boundary_cell(
    bytecode_len: usize,
    virtualized_len: usize,
    padded_len: usize,
) -> &'static str {
    if bytecode_len < 16 {
        return "pd4.small_program";
    }
    if bytecode_len > (1 << 14) {
        return "pd4.large_program";
    }

    let len = virtualized_len.max(1);
    let upper = len.next_power_of_two();
    let lower = if len.is_power_of_two() { len } else { upper / 2 };
    if len == lower.saturating_add(1) {
        "pd4.just_over"
    } else if len.saturating_add(1) == padded_len {
        "pd4.just_under"
    } else if len.saturating_sub(lower) <= padded_len.saturating_sub(len) {
        "pd4.just_over"
    } else {
        "pd4.just_under"
    }
}

fn emit_bytecode_table_boundary_hit(hits: &mut Vec<BucketHit>, bytecode: &[ELFInstruction]) {
    let bytecode_len = bytecode.len();
    let virtualized_len = virtualized_bytecode_len(bytecode);
    let preprocessed_len = virtualized_len.saturating_add(1);
    let padded_len = preprocessed_len.max(1).next_power_of_two();
    let crossed_k = padded_len.trailing_zeros();
    let min_address = bytecode.iter().map(|instruction| instruction.address).min();
    let max_address = bytecode.iter().map(|instruction| instruction.address).max();
    push_table_hit_extra(
        hits,
        semantic::row::BYTECODE_TABLE_BOUNDARY,
        "pd4",
        bytecode_boundary_cell(bytecode_len, virtualized_len, padded_len),
        "jolt_program.decode.bytecode",
        virtualized_len as u64,
        &[
            ("table_name", json!("bytecode")),
            ("bytecode_len", json!(bytecode_len)),
            ("virtualized_bytecode_len", json!(virtualized_len)),
            ("preprocessed_bytecode_len", json!(preprocessed_len)),
            ("padded_bytecode_len", json!(padded_len)),
            ("padding_rows", json!(padded_len.saturating_sub(preprocessed_len))),
            ("crossed_k", json!(crossed_k)),
            ("has_prepended_noop", json!(true)),
            ("bytecode_address_min", json!(min_address)),
            ("bytecode_address_max", json!(max_address)),
        ],
    );
}

impl JoltTrace {
    pub fn from_execution(bytecode: &[ELFInstruction]) -> Result<Self, String> {
        let mut bucket_hits = Vec::new();
        emit_bytecode_table_boundary_hit(&mut bucket_hits, bytecode);
        Ok(Self { bucket_hits, instruction_count: bytecode.len() })
    }

    #[allow(dead_code)]
    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }
}

impl Trace for JoltTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }
}
