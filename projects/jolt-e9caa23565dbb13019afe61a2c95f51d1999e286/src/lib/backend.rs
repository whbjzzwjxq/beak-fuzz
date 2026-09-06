use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, ExecutedExceptionEffect, ExecutedExceptionReceipt,
    InjectionSchedule, SemanticInjectionCandidate, SemanticMutationReceipt,
    SemanticMutationRelation,
};
use beak_core::fuzz::benchmark::SemanticMutationEffect;
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use common::constants::{RAM_START_ADDRESS, REGISTER_COUNT};
use common::rv_trace::{CircuitFlags, MemoryConfig, MemoryLayout, MemoryOp, RVTraceRow};
use jolt::jolt_core::jolt::vm::rv32i_vm::{C, M};
use jolt::jolt_core::jolt::vm::JoltTraceStep;
use jolt::{host, Jolt, ProofTranscript, RV32IJoltVM, F, PCS, RV32I};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::trace::JoltTrace;
use crate::JOLT_COMMIT;

const UPPER_IMMEDIATE_INJECT_KIND: &str = "jolt.semantic.decode.upper_immediate_materialization";
const ENTRYPOINT_INJECT_KIND: &str = "jolt.semantic.control.entrypoint_binding";
const CONTROL_FLOW_INJECT_KIND: &str = "jolt.semantic.exec.control_flow_binding";
const ZERO_REGISTER_INJECT_KIND: &str = "jolt.semantic.decode.zero_register_immutability";
const OPERAND_INDEX_INJECT_KIND: &str = "jolt.semantic.decode.operand_index_routing";
const DEST_BINDING_INJECT_KIND: &str = "jolt.semantic.exec.dest_binding";
const FIELD_RANGE_INJECT_KIND: &str = "jolt.semantic.decode.field_range";
const IMMEDIATE_SIGN_INJECT_KIND: &str = "jolt.semantic.decode.immediate_sign_extension";
const FORMAT_IMMEDIATE_INJECT_KIND: &str = "jolt.semantic.decode.format_immediate_reassembly";
const OP_SELECTOR_INJECT_KIND: &str = "jolt.semantic.exec.op_selector_binding";
const ALU_IMMEDIATE_INJECT_KIND: &str = "jolt.semantic.alu.immediate_limb_consistency";
const SHIFT_INJECT_KIND: &str = "jolt.semantic.alu.shift_mod32";
const COMPARISON_BOOL_INJECT_KIND: &str = "jolt.semantic.alu.comparison_booleanity";
const SUBTRACTION_INJECT_KIND: &str = "jolt.semantic.alu.subtraction_borrow_chain";
const COMPARISON_AUX_INJECT_KIND: &str = "jolt.semantic.alu.comparison_auxiliary_chain";
const ARITH_SPECIAL_INJECT_KIND: &str = "jolt.semantic.arithmetic.special_case_consistency";
const DIV_BOUND_INJECT_KIND: &str = "jolt.semantic.arithmetic.division_remainder_bound";
const PRODUCT_INJECT_KIND: &str = "jolt.semantic.arithmetic.product_decomposition";
const SIGNED_UNSIGNED_INJECT_KIND: &str =
    "jolt.semantic.arithmetic.signed_unsigned_product_correction";
const MEMORY_ADDRESS_SPACE_INJECT_KIND: &str = "jolt.semantic.memory.address_space_consistency";
const MEMORY_ADDRESS_INJECT_KIND: &str = "jolt.semantic.memory.address_pointer_consistency";
const MEMORY_KIND_SELECTOR_INJECT_KIND: &str = "jolt.semantic.memory.kind_selector_consistency";
const MEMORY_VALUE_INJECT_KIND: &str = "jolt.semantic.memory.value_payload_consistency";
const STORE_LOAD_INJECT_KIND: &str = "jolt.semantic.memory.store_load_payload_flow";
const MEMORY_INITIAL_INJECT_KIND: &str = "jolt.semantic.memory.initial_value_binding";
const MEMORY_FINALIZATION_INJECT_KIND: &str = "jolt.semantic.memory.finalization_consistency";
const TIME_BOUNDARY_INJECT_KIND: &str = "jolt.semantic.time.boundary_origin_consistency";
const TIME_MONOTONIC_INJECT_KIND: &str = "jolt.semantic.time.monotonic_access_ordering";
const LOOKUP_BOOLEAN_INJECT_KIND: &str = "jolt.semantic.lookup.boolean_multiplicity";
const PADDING_INJECT_KIND: &str = "jolt.semantic.row.padding_interaction_send";
const JOLT_INJECT_KIND_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_KIND";
const JOLT_INJECT_STEP_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_STEP";
const JOLT_INJECT_APPLIED_ENV: &str = "BEAK_JOLT_WITNESS_INJECTION_APPLIED";
const JOLT_MUTATION_RECEIPT_ENV: &str = "BEAK_JOLT_WITNESS_MUTATION_RECEIPT";
const JOLT_ENTRYPOINT_OPCODE_ENV: &str = "BEAK_JOLT_ENTRYPOINT_OPCODE";
const JOLT_ENTRYPOINT_MNEMONIC_ENV: &str = "BEAK_JOLT_ENTRYPOINT_MNEMONIC";
const JOLT_EXECUTED_EXCEPTION_RECEIPT_ENV: &str = "BEAK_JOLT_EXECUTED_EXCEPTION_RECEIPT";
const JOLT_R1CS_EXCEPTION_CANDIDATE_ENV: &str = "BEAK_JOLT_R1CS_EXCEPTION_CANDIDATE";
const JOLT_INSTRUCTION_LOOKUP_EXCEPTION_CANDIDATE_ENV: &str =
    "BEAK_JOLT_INSTRUCTION_LOOKUP_EXCEPTION_CANDIDATE";
const LOOP_FOREVER_WORD: u32 = 0x0000_006f;
const T0_REG: u32 = 5;
const T1_REG: u32 = 6;
const RAM_OP_INDEX: usize = 3;
static TEMP_ELF_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
struct WitnessInjectionPlan {
    kind: String,
    step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub backend_error: Option<String>,
    pub observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pub injection_applied: bool,
    pub semantic_mutation_receipt: Option<SemanticMutationReceipt>,
    pub executed_exception_receipt: Option<ExecutedExceptionReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub request_id: u64,
    pub words: Vec<u32>,
    pub iteration: u64,
    pub inject_kind: Option<String>,
    pub inject_step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub request_id: u64,
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub backend_error: Option<String>,
    pub observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pub injection_applied: bool,
    pub semantic_mutation_receipt: Option<SemanticMutationReceipt>,
    pub executed_exception_receipt: Option<ExecutedExceptionReceipt>,
}

impl WorkerResponse {
    pub fn from_run_response(request_id: u64, resp: RunResponse) -> Self {
        Self {
            request_id,
            final_regs: resp.final_regs,
            micro_op_count: resp.micro_op_count,
            bucket_hits: resp.bucket_hits,
            trace_signals: resp.trace_signals,
            backend_error: resp.backend_error,
            observed_injection_sites: resp.observed_injection_sites,
            injection_applied: resp.injection_applied,
            semantic_mutation_receipt: resp.semantic_mutation_receipt,
            executed_exception_receipt: resp.executed_exception_receipt,
        }
    }

    pub fn error(request_id: u64, error: String) -> Self {
        Self {
            request_id,
            final_regs: None,
            micro_op_count: 0,
            bucket_hits: Vec::new(),
            trace_signals: Vec::new(),
            backend_error: Some(error),
            observed_injection_sites: BTreeMap::new(),
            injection_applied: false,
            semantic_mutation_receipt: None,
            executed_exception_receipt: None,
        }
    }
}

const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";

struct JoltExecution {
    final_regs: [u32; 32],
    rows: Vec<RVTraceRow>,
    trace: Vec<JoltTraceStep<RV32I>>,
    io_device: common::rv_trace::JoltDevice,
    bytecode: Vec<common::rv_trace::ELFInstruction>,
    memory_init: Vec<(u64, u8)>,
    injection_applied: bool,
    semantic_mutation_receipt: Option<SemanticMutationReceipt>,
    inject_kind: Option<String>,
    inject_step: u64,
}

fn record_site(sites: &mut BTreeMap<String, Vec<u64>>, kind: &str, step: u64) {
    let steps = sites.entry(kind.to_string()).or_default();
    if steps.last().copied() != Some(step) {
        steps.push(step);
    }
}

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn build_program_words(words: &[u32]) -> Vec<u32> {
    let mut out = words.to_vec();
    let termination_addr =
        common::rv_trace::MemoryLayout::new(&MemoryConfig::default()).termination as u32;
    let (upper, lower) = split_u32_for_lui_addi(termination_addr);
    out.push(encode_lui(T0_REG, upper));
    out.push(encode_addi(T0_REG, T0_REG, lower));
    out.push(encode_addi(T1_REG, 0, 1));
    out.push(encode_sb(T1_REG, T0_REG, 0));
    out.push(encode_addi(T0_REG, 0, 0));
    out.push(encode_addi(T1_REG, 0, 0));
    out.push(LOOP_FOREVER_WORD);
    out
}

fn split_u32_for_lui_addi(value: u32) -> (u32, i32) {
    let upper = value.wrapping_add(0x800) >> 12;
    let lower = (value as i64) - ((upper as i64) << 12);
    (upper & 0x000f_ffff, lower as i32)
}

fn encode_lui(rd: u32, imm20: u32) -> u32 {
    ((imm20 & 0x000f_ffff) << 12) | ((rd & 0x1f) << 7) | 0x37
}

fn encode_addi(rd: u32, rs1: u32, imm12: i32) -> u32 {
    (((imm12 as u32) & 0x0fff) << 20) | ((rs1 & 0x1f) << 15) | ((rd & 0x1f) << 7) | 0x13
}

fn encode_sb(rs2: u32, rs1: u32, imm12: i32) -> u32 {
    let imm = (imm12 as u32) & 0x0fff;
    let imm_lo = imm & 0x1f;
    let imm_hi = (imm >> 5) & 0x7f;
    (imm_hi << 25) | ((rs2 & 0x1f) << 20) | ((rs1 & 0x1f) << 15) | (imm_lo << 7) | 0x23
}

fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 || value % align == 0 {
        value
    } else {
        value + (align - value % align)
    }
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn append_section_header(
    out: &mut Vec<u8>,
    name: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    addralign: u64,
) {
    push_u32(out, name);
    push_u32(out, kind);
    push_u64(out, flags);
    push_u64(out, address);
    push_u64(out, offset);
    push_u64(out, size);
    push_u32(out, 0);
    push_u32(out, 0);
    push_u64(out, addralign);
    push_u64(out, 0);
}

fn build_elf_bytes(words: &[u32]) -> Vec<u8> {
    let program_words = build_program_words(words);
    let mut text_bytes = Vec::with_capacity(program_words.len() * 4);
    for word in &program_words {
        text_bytes.extend_from_slice(&word.to_le_bytes());
    }
    let shstrtab = b"\0.text\0.shstrtab\0";
    let text_offset = 0x100u64;
    let shstrtab_offset = text_offset + text_bytes.len() as u64;
    let shoff = align_up(shstrtab_offset + shstrtab.len() as u64, 8);

    let mut elf = vec![0u8; 64];
    elf[0..4].copy_from_slice(b"\x7FELF");
    elf[4] = 2; // 64-bit
    elf[5] = 1; // little-endian
    elf[6] = 1; // ELF version
    write_u16(&mut elf, 16, 2); // executable
    write_u16(&mut elf, 18, 0x00f3); // RISC-V
    write_u32(&mut elf, 20, 1);
    write_u64(&mut elf, 24, RAM_START_ADDRESS);
    write_u64(&mut elf, 32, 0);
    write_u64(&mut elf, 40, shoff);
    write_u16(&mut elf, 52, 64);
    write_u16(&mut elf, 58, 64);
    write_u16(&mut elf, 60, 3);
    write_u16(&mut elf, 62, 2);

    elf.resize(text_offset as usize, 0);
    elf.extend_from_slice(&text_bytes);
    elf.extend_from_slice(shstrtab);
    elf.resize(shoff as usize, 0);

    elf.extend_from_slice(&[0u8; 64]);
    append_section_header(
        &mut elf,
        1,
        1,
        0x6,
        RAM_START_ADDRESS,
        text_offset,
        text_bytes.len() as u64,
        4,
    );
    append_section_header(&mut elf, 7, 3, 0, 0, shstrtab_offset, shstrtab.len() as u64, 1);
    elf
}

fn final_regs_from_rows(rows: &[RVTraceRow]) -> [u32; 32] {
    let mut final_regs = [0u32; 32];
    for row in rows {
        if let Some(rd) = row.instruction.rd {
            if rd != 0 {
                final_regs[rd as usize] = row.register_state.rd_post_val.unwrap_or(0) as u32;
            }
        }
    }
    final_regs
}

struct TempElfFile {
    path: PathBuf,
}

impl TempElfFile {
    fn new(bytes: &[u8]) -> Result<Self, String> {
        let nonce = TEMP_ELF_COUNTER.fetch_add(1, Ordering::Relaxed);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("jolt temp elf clock error: {e}"))?
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("beak-jolt-inline-{}-{ts}-{nonce}.elf", std::process::id()));
        fs::write(&path, bytes).map_err(|e| format!("write temp elf failed: {e}"))?;
        Ok(Self { path })
    }
}

impl Drop for TempElfFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn restore_env_var(key: &str, value: Option<std::ffi::OsString>) {
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}

fn parse_semantic_mutation_receipt(
    raw: Option<&str>,
) -> Result<Option<SemanticMutationReceipt>, String> {
    raw.map(serde_json::from_str)
        .transpose()
        .map_err(|e| format!("invalid semantic mutation receipt: {e}"))
}

fn parse_executed_exception_receipt(
    raw: Option<&str>,
) -> Result<Option<ExecutedExceptionReceipt>, String> {
    raw.map(serde_json::from_str)
        .transpose()
        .map_err(|e| format!("invalid executed exception receipt: {e}"))
}

#[derive(Debug, Default)]
struct ExecutedExceptionCandidates {
    instruction_lookup: Option<ExecutedExceptionReceipt>,
    r1cs: Option<ExecutedExceptionReceipt>,
}

fn detail_str<'a>(hit: &'a BucketHit, key: &str) -> Option<&'a str> {
    hit.details.get(key)?.as_str()
}

fn detail_bool(hit: &BucketHit, key: &str) -> Option<bool> {
    hit.details.get(key)?.as_bool()
}

fn detail_u64(hit: &BucketHit, key: &str) -> Option<u64> {
    hit.details.get(key)?.as_u64()
}

fn detail_i64(hit: &BucketHit, key: &str) -> Option<i64> {
    hit.details.get(key)?.as_i64()
}

fn exact_entrypoint_receipt_shape(receipt: &SemanticMutationReceipt) -> bool {
    let context = &receipt.effect.context;
    let (Some(declared), Some(before), Some(after)) = (
        context.get("declared_entry").and_then(serde_json::Value::as_u64),
        context.get("witnessed_pc_before").and_then(serde_json::Value::as_u64),
        context.get("witnessed_pc_after").and_then(serde_json::Value::as_u64),
    ) else {
        return false;
    };
    let opcode = context.get("opcode").and_then(serde_json::Value::as_str);
    let mnemonic = context.get("mnemonic").and_then(serde_json::Value::as_str);
    base_inject_kind(&receipt.inject_kind) == ENTRYPOINT_INJECT_KIND
        && receipt.site == "executor.trace_start"
        && receipt.field == "start_pc"
        && receipt.step == 0
        && context.get("bucket_id").and_then(serde_json::Value::as_str)
            == Some(semantic::control::ENTRYPOINT_BINDING.id)
        && context.get("obligation_id").and_then(serde_json::Value::as_str) == Some("cf4")
        && matches!(
            context.get("cell_id").and_then(serde_json::Value::as_str),
            Some("cf4.default_entry" | "cf4.custom_entry")
        )
        && context.get("backend").and_then(serde_json::Value::as_str) == Some("jolt")
        && context.get("trace_source").and_then(serde_json::Value::as_str) == Some("instruction")
        && context.get("op_idx").and_then(serde_json::Value::as_u64) == Some(receipt.step)
        && context.get("step_idx").and_then(serde_json::Value::as_u64) == Some(receipt.step)
        && context.get("boundary_row").and_then(serde_json::Value::as_u64) == Some(receipt.step)
        && context.get("pc").and_then(serde_json::Value::as_u64) == Some(declared)
        && declared == RAM_START_ADDRESS
        && before == declared
        && after != before
        && after <= u64::from(u32::MAX)
        && receipt.before.as_u64() == Some(before)
        && receipt.after.as_u64() == Some(after)
        && opcode.is_some_and(|value| !value.is_empty())
        && mnemonic.is_some_and(|value| !value.is_empty())
        && context.get("witnessed_pc_before").and_then(serde_json::Value::as_u64) == Some(before)
        && context.get("witnessed_pc_after").and_then(serde_json::Value::as_u64) == Some(after)
        && matches!(
            context.get("mutation_mode").and_then(serde_json::Value::as_str),
            Some("skip_one")
        )
        && context.get("executed_boundary_row").and_then(serde_json::Value::as_bool) == Some(true)
}

fn bind_semantic_mutation_receipt(
    mut receipt: SemanticMutationReceipt,
    hits: &[BucketHit],
) -> Option<SemanticMutationReceipt> {
    let context = &receipt.effect.context;
    let matching: Vec<&BucketHit> = match receipt.effect.relation {
        // Executor-level entrypoint mutation: the injected run's boundary-row
        // hit witnesses the diverged start (witnessed_pc != declared entry),
        // while the receipt keeps the declared-entry view (pc/witnessed_pc_before
        // == declared) so the core baseline binding stays exact.  Bind on the
        // declared entry + boundary row + divergence evidence only.
        SemanticMutationRelation::EntrypointPcEquation => hits
            .iter()
            .filter(|hit| {
                exact_entrypoint_receipt_shape(&receipt)
                    && hit.bucket_id == semantic::control::ENTRYPOINT_BINDING.id
                    && detail_str(hit, "obligation_id") == Some("cf4")
                    && matches!(
                        detail_str(hit, "cell_id"),
                        Some("cf4.default_entry" | "cf4.custom_entry")
                    )
                    && detail_u64(hit, "op_idx") == Some(receipt.step)
                    && detail_u64(hit, "declared_entry")
                        == context.get("declared_entry").and_then(serde_json::Value::as_u64)
                    && detail_u64(hit, "witnessed_pc_before")
                        != detail_u64(hit, "declared_entry")
            })
            .collect(),
        SemanticMutationRelation::UpperImmediateEquation => hits
            .iter()
            .filter(|hit| {
                hit.bucket_id == semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION.id
                    && detail_str(hit, "obligation_id") == Some("id3")
                    && detail_str(hit, "cell_id").is_some_and(|cell| cell.starts_with("id3.lui_"))
                    && detail_u64(hit, "op_idx") == Some(receipt.step)
                    && detail_u64(hit, "opcode")
                        == context.get("opcode").and_then(serde_json::Value::as_u64)
                    && detail_u64(hit, "imm20")
                        == context.get("imm20").and_then(serde_json::Value::as_u64)
                    && detail_u64(hit, "expected_result")
                        == context.get("expected_result").and_then(serde_json::Value::as_u64)
                    && receipt.before.as_u64() == detail_u64(hit, "witnessed_result_before")
                    && receipt.after.as_u64().is_some_and(|after| {
                        Some(after) != detail_u64(hit, "witnessed_result_before")
                    })
            })
            .collect(),
        _ => return Some(receipt),
    };
    let [hit] = matching.as_slice() else {
        return None;
    };
    let context = &mut receipt.effect.context;
    context.insert("bucket_id".to_string(), serde_json::json!(hit.bucket_id));
    if receipt.effect.relation == SemanticMutationRelation::EntrypointPcEquation {
        // Keep the receipt's declared-entry context (pc/cell_id/witnessed values);
        // only anchor the boundary row from the witnessed hit.
        context.insert("boundary_row".to_string(), hit.details.get("op_idx")?.clone());
        context.insert("op_idx".to_string(), hit.details.get("op_idx")?.clone());
        return Some(receipt);
    }
    for key in [
        "obligation_id",
        "cell_id",
        "backend",
        "commit",
        "trace_source",
        "pc",
        "opcode",
        "mnemonic",
    ] {
        context.insert(key.to_string(), hit.details.get(key)?.clone());
    }
    Some(receipt)
}

fn receipt_from_hit(
    hit: &BucketHit,
    effect: ExecutedExceptionEffect,
    stage: &str,
) -> Option<ExecutedExceptionReceipt> {
    let obligation_id = detail_str(hit, "obligation_id")?.to_string();
    let cell_id = detail_str(hit, "cell_id")?.to_string();
    let step = detail_u64(hit, "op_idx").or_else(|| detail_u64(hit, "step_idx"))?;
    let trace_source = detail_str(hit, "trace_source")?;
    if obligation_id.is_empty() || cell_id.is_empty() || trace_source.is_empty() {
        return None;
    }
    let context = hit.details.iter().map(|(key, value)| (key.clone(), value.clone())).collect();
    Some(ExecutedExceptionReceipt {
        effect,
        obligation_id,
        cell_id,
        stage: stage.to_string(),
        step,
        context,
    })
}

fn exact_signed_divrem_hit(hit: &BucketHit) -> bool {
    let (Some(dividend), Some(divisor), Some(quotient), Some(remainder), Some(recomposed)) = (
        detail_i64(hit, "dividend"),
        detail_i64(hit, "divisor"),
        detail_i64(hit, "quotient"),
        detail_i64(hit, "remainder"),
        detail_i64(hit, "recomposed"),
    ) else {
        return false;
    };
    let cell_id = detail_str(hit, "cell_id").unwrap_or_default();
    let mnemonic = detail_str(hit, "mnemonic").unwrap_or_default();
    let arithmetic = quotient.checked_mul(divisor).and_then(|value| value.checked_add(remainder));
    hit.bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id
        && detail_str(hit, "obligation_id") == Some("md3")
        && cell_id.starts_with("md3.")
        && cell_id != "md3.unsigned"
        && matches!(mnemonic, "div" | "rem")
        && detail_str(hit, "relation") == Some("quotient_times_divisor_plus_remainder")
        && detail_bool(hit, "relation_valid") == Some(true)
        && detail_bool(hit, "remainder_bound_holds") == Some(true)
        && detail_bool(hit, "remainder_sign_holds") == Some(true)
        && divisor != 0
        && arithmetic == Some(dividend)
        && recomposed == dividend
        && remainder.unsigned_abs() < divisor.unsigned_abs()
        && (remainder == 0 || remainder.signum() == dividend.signum())
}

fn exact_mulhsu_mismatch_hit(hit: &BucketHit) -> bool {
    let (
        Some(signed_lhs),
        Some(unsigned_rhs),
        Some(product_hi),
        Some(product_lo),
        Some(architectural_result),
        Some(observed_result),
    ) = (
        detail_i64(hit, "signed_lhs"),
        detail_u64(hit, "unsigned_rhs"),
        detail_u64(hit, "product_hi"),
        detail_u64(hit, "product_lo"),
        detail_u64(hit, "architectural_result"),
        detail_u64(hit, "observed_result"),
    )
    else {
        return false;
    };
    let product = i128::from(signed_lhs) * i128::from(unsigned_rhs);
    let expected_lo = product as u32 as u64;
    let expected_hi = ((product as u128 >> 32) as u32) as u64;
    let processed_provenance_valid = match (
        detail_u64(hit, "op_idx"),
        detail_u64(hit, "rd"),
        detail_u64(hit, "processed_row_idx"),
        detail_u64(hit, "processed_segment_start_step"),
        detail_u64(hit, "processed_segment_end_step"),
        detail_u64(hit, "processed_final_rd_write_step"),
        detail_u64(hit, "processed_final_rd_address"),
    ) {
        (
            Some(op_idx),
            Some(rd),
            Some(processed_row_idx),
            Some(segment_start),
            Some(segment_end),
            Some(final_write_step),
            Some(final_rd_address),
        ) => {
            processed_row_idx == op_idx
                && segment_start <= final_write_step
                && final_write_step <= segment_end
                && final_rd_address == rd
        }
        _ => false,
    };
    hit.bucket_id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id
        && detail_str(hit, "obligation_id") == Some("md5")
        && detail_str(hit, "cell_id").is_some_and(|cell| cell.starts_with("md5."))
        && detail_str(hit, "mnemonic") == Some("mulhsu")
        && detail_str(hit, "relation") == Some("high32_signed_lhs_times_unsigned_rhs")
        && detail_bool(hit, "relation_valid") == Some(true)
        && detail_bool(hit, "result_mismatch") == Some(true)
        && detail_bool(hit, "result_matches") == Some(false)
        && detail_str(hit, "observed_result_source")
            == Some("processed_virtual_sequence.final_rd_write")
        && processed_provenance_valid
        && detail_u64(hit, "expected_high32") == Some(product_hi)
        && product_hi == expected_hi
        && product_lo == expected_lo
        && observed_result != expected_hi
        // The architectural register state may itself diverge from the recomputed
        // product at this commit (executor-side mulhsu bug), so the exact gate is
        // the executed provenance plus the prover-claimed result disagreeing with
        // the spec recomputation.
}

fn executed_exception_candidates(
    hits: &[BucketHit],
    non_injected: bool,
) -> ExecutedExceptionCandidates {
    if !non_injected {
        return ExecutedExceptionCandidates::default();
    }
    ExecutedExceptionCandidates {
        instruction_lookup: hits.iter().find(|hit| exact_signed_divrem_hit(hit)).and_then(|hit| {
            receipt_from_hit(
                hit,
                ExecutedExceptionEffect::SignedDivisionRemainderVerification,
                "instruction_lookup.primary_sumcheck",
            )
        }),
        r1cs: hits.iter().find(|hit| exact_mulhsu_mismatch_hit(hit)).and_then(|hit| {
            receipt_from_hit(
                hit,
                ExecutedExceptionEffect::SignedUnsignedProductVerification,
                "r1cs.inner_sumcheck",
            )
        }),
    }
}

fn arm_exception_candidate_env(
    key: &str,
    receipt: Option<&ExecutedExceptionReceipt>,
) -> Result<(), String> {
    if let Some(receipt) = receipt {
        let encoded = serde_json::to_string(receipt)
            .map_err(|e| format!("serialize executed exception candidate failed: {e}"))?;
        std::env::set_var(key, encoded);
    } else {
        std::env::remove_var(key);
    }
    Ok(())
}

fn execute_trace(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<JoltExecution, String> {
    let memory_config = MemoryConfig::default();
    let is_entrypoint_injection =
        inject_kind.is_some_and(|kind| base_inject_kind(kind) == ENTRYPOINT_INJECT_KIND);
    // Executor-level entrypoint mutation: the bytecode/program view keeps the
    // declared entry (RAM_START_ADDRESS), while the tracer starts one instruction
    // later.  The multiset still covers the unchanged table; only the trace's
    // first executed row diverges from the declared entry.
    let elf = build_elf_bytes(words);
    let mut elf_exec = elf.clone();
    if is_entrypoint_injection {
        write_u64(&mut elf_exec, 24, RAM_START_ADDRESS + 4);
    }
    let (rows, _device) = tracer::trace(elf_exec.clone(), &[], &memory_config);
    let final_regs = final_regs_from_rows(&rows);
    // For the executor-level entrypoint mutation, also trace the undeclared
    // (unskipped) program so the register-file divergence caused by skipping
    // the first instruction can be exactly explained in the receipt.
    let entrypoint_explained_mismatches = if is_entrypoint_injection {
        let (rows_no_skip, _no_skip_device) = tracer::trace(elf.clone(), &[], &memory_config);
        let no_skip_regs = final_regs_from_rows(&rows_no_skip);
        let explained: Vec<serde_json::Value> = (0..final_regs.len())
            .filter(|&reg| final_regs[reg] != no_skip_regs[reg])
            .map(|reg| {
                serde_json::json!({
                    "reg": reg,
                    "oracle": no_skip_regs[reg],
                    "backend": final_regs[reg],
                })
            })
            .collect();
        Some(explained)
    } else {
        None
    };
    let temp_elf = TempElfFile::new(&elf)?;
    let mut program = host::Program::new("beak-inline");
    program.elf = Some(temp_elf.path.clone());
    let (bytecode, memory_init) = program.decode();
    let entrypoint_metadata =
        match inject_kind.filter(|kind| base_inject_kind(kind) == ENTRYPOINT_INJECT_KIND) {
            Some(_) => {
                let word = words.first().copied().ok_or_else(|| {
                    "entrypoint injection requires a nonempty program".to_string()
                })?;
                let decoded = RV32IMInstruction::decode(word).ok_or_else(|| {
                    "entrypoint injection requires a decodable first word".to_string()
                })?;
                Some((format!("0x{word:08x}"), decoded.mnemonic))
            }
            None => None,
        };
    let prev_kind = std::env::var_os(JOLT_INJECT_KIND_ENV);
    let prev_step = std::env::var_os(JOLT_INJECT_STEP_ENV);
    let prev_applied = std::env::var_os(JOLT_INJECT_APPLIED_ENV);
    let prev_receipt = std::env::var_os(JOLT_MUTATION_RECEIPT_ENV);
    let prev_entrypoint_opcode = std::env::var_os(JOLT_ENTRYPOINT_OPCODE_ENV);
    let prev_entrypoint_mnemonic = std::env::var_os(JOLT_ENTRYPOINT_MNEMONIC_ENV);
    std::env::remove_var(JOLT_INJECT_APPLIED_ENV);
    std::env::remove_var(JOLT_MUTATION_RECEIPT_ENV);
    if let Some(kind) = inject_kind.filter(|kind| {
        base_inject_kind(kind) != ENTRYPOINT_INJECT_KIND
    }) {
        std::env::set_var(JOLT_INJECT_KIND_ENV, kind);
        std::env::set_var(JOLT_INJECT_STEP_ENV, inject_step.to_string());
        if let Some((opcode, mnemonic)) = entrypoint_metadata.as_ref() {
            std::env::set_var(JOLT_ENTRYPOINT_OPCODE_ENV, opcode);
            std::env::set_var(JOLT_ENTRYPOINT_MNEMONIC_ENV, mnemonic);
        } else {
            std::env::remove_var(JOLT_ENTRYPOINT_OPCODE_ENV);
            std::env::remove_var(JOLT_ENTRYPOINT_MNEMONIC_ENV);
        }
    } else {
        std::env::remove_var(JOLT_INJECT_KIND_ENV);
        std::env::remove_var(JOLT_INJECT_STEP_ENV);
        std::env::remove_var(JOLT_ENTRYPOINT_OPCODE_ENV);
        std::env::remove_var(JOLT_ENTRYPOINT_MNEMONIC_ENV);
    }
    let (io_device, trace) = program.trace(&[]);
    let injection_applied = std::env::var(JOLT_INJECT_APPLIED_ENV).ok().as_deref() == Some("1");
    let raw_semantic_mutation_receipt = std::env::var(JOLT_MUTATION_RECEIPT_ENV).ok();
    restore_env_var(JOLT_INJECT_KIND_ENV, prev_kind);
    restore_env_var(JOLT_INJECT_STEP_ENV, prev_step);
    restore_env_var(JOLT_INJECT_APPLIED_ENV, prev_applied);
    restore_env_var(JOLT_MUTATION_RECEIPT_ENV, prev_receipt);
    restore_env_var(JOLT_ENTRYPOINT_OPCODE_ENV, prev_entrypoint_opcode);
    restore_env_var(JOLT_ENTRYPOINT_MNEMONIC_ENV, prev_entrypoint_mnemonic);
    let mut semantic_mutation_receipt =
        parse_semantic_mutation_receipt(raw_semantic_mutation_receipt.as_deref())?;
    if is_entrypoint_injection {
        if let Some((opcode, mnemonic)) = entrypoint_metadata.as_ref() {
            let declared = u64::from(RAM_START_ADDRESS);
            let mut context: serde_json::Map<String, serde_json::Value> = [
                ("bucket_id", json!(semantic::control::ENTRYPOINT_BINDING.id)),
                ("obligation_id", json!("cf4")),
                ("cell_id", json!("cf4.default_entry")),
                ("backend", json!("jolt")),
                ("commit", json!(JOLT_COMMIT)),
                ("trace_source", json!("instruction")),
                ("boundary_row", json!(0)),
                ("op_idx", json!(0)),
                ("step_idx", json!(0)),
                ("pc", json!(declared)),
                ("opcode", json!(opcode)),
                ("mnemonic", json!(mnemonic)),
                ("declared_entry", json!(declared)),
                ("witnessed_pc_before", json!(declared)),
                ("witnessed_pc_after", json!(declared + 4)),
                ("mutation_mode", json!("skip_one")),
                ("executed_boundary_row", json!(true)),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect();
            if let Some(explained) = entrypoint_explained_mismatches {
                context.insert("explained_mismatches".to_string(), json!(explained));
            }
            semantic_mutation_receipt = Some(SemanticMutationReceipt {
                inject_kind: inject_kind.expect("entrypoint injection kind").to_string(),
                site: "executor.trace_start".to_string(),
                field: "start_pc".to_string(),
                step: 0,
                before: json!(declared),
                after: json!(declared + 4),
                effect: SemanticMutationEffect {
                    relation: SemanticMutationRelation::EntrypointPcEquation,
                    preserved_before: None,
                    preserved_after: None,
                    context,
                },
            });
        }
    }
    let injection_applied = injection_applied || is_entrypoint_injection;
    Ok(JoltExecution {
        final_regs,
        rows,
        trace,
        io_device,
        bytecode,
        memory_init,
        injection_applied,
        semantic_mutation_receipt,
        inject_kind: inject_kind.map(ToOwned::to_owned),
        inject_step,
    })
}

fn is_real_lui_step(step: &JoltTraceStep<RV32I>) -> bool {
    matches!(step.instruction_lookup, Some(RV32I::VIRTUAL_ADVICE(_)))
        && !step.circuit_flags[CircuitFlags::Virtual as usize]
}

fn is_branch_step(step: &JoltTraceStep<RV32I>) -> bool {
    step.circuit_flags[CircuitFlags::Branch as usize]
        && !step.circuit_flags[CircuitFlags::Virtual as usize]
}

fn remap_memory_address(address: u64, memory_layout: &MemoryLayout) -> Option<u64> {
    if address >= memory_layout.input_start {
        Some(REGISTER_COUNT + (address - memory_layout.input_start) / 4)
    } else if address < REGISTER_COUNT {
        Some(address)
    } else {
        None
    }
}

fn ram_op_address(step: &JoltTraceStep<RV32I>) -> u64 {
    match step.memory_ops[RAM_OP_INDEX] {
        MemoryOp::Read(address) | MemoryOp::Write(address, _) => address,
    }
}

fn is_real_ram_op(step: &JoltTraceStep<RV32I>, memory_layout: &MemoryLayout) -> bool {
    ram_op_address(step) >= memory_layout.input_start
}

fn memory_init_witness_size(memory_init: &[(u64, u8)], memory_layout: &MemoryLayout) -> usize {
    memory_init
        .iter()
        .filter_map(|(address, _)| remap_memory_address(address & !3, memory_layout))
        .map(|idx| idx.saturating_add(1) as usize)
        .max()
        .unwrap_or(0)
}

fn trace_memory_witness_size(
    trace: &[JoltTraceStep<RV32I>],
    memory_init: &[(u64, u8)],
    memory_layout: &MemoryLayout,
) -> usize {
    let max_trace_address = trace
        .iter()
        .filter_map(|step| remap_memory_address(ram_op_address(step), memory_layout))
        .max()
        .map(|idx| idx.saturating_add(1) as usize)
        .unwrap_or(0);
    max_trace_address
        .max(memory_init_witness_size(memory_init, memory_layout))
        .max(8)
        .next_power_of_two()
}

fn collect_observed_injection_sites(
    trace: &[JoltTraceStep<RV32I>],
    memory_layout: &MemoryLayout,
) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    if !trace.is_empty() {
        record_site(&mut sites, ENTRYPOINT_INJECT_KIND, 0);
        record_site(&mut sites, TIME_BOUNDARY_INJECT_KIND, 0);
    }
    if trace.len().next_power_of_two() > trace.len() {
        record_site(&mut sites, PADDING_INJECT_KIND, trace.len() as u64);
    }
    for (idx, step) in trace.iter().enumerate() {
        let step_idx = idx as u64;
        record_site(&mut sites, MEMORY_ADDRESS_SPACE_INJECT_KIND, step_idx);
        record_site(&mut sites, FIELD_RANGE_INJECT_KIND, step_idx);
        record_site(&mut sites, OP_SELECTOR_INJECT_KIND, step_idx);
        record_site(&mut sites, OPERAND_INDEX_INJECT_KIND, step_idx);
        record_site(&mut sites, IMMEDIATE_SIGN_INJECT_KIND, step_idx);
        record_site(&mut sites, FORMAT_IMMEDIATE_INJECT_KIND, step_idx);
        record_site(&mut sites, ALU_IMMEDIATE_INJECT_KIND, step_idx);
        record_site(&mut sites, SHIFT_INJECT_KIND, step_idx);
        record_site(&mut sites, COMPARISON_BOOL_INJECT_KIND, step_idx);
        record_site(&mut sites, SUBTRACTION_INJECT_KIND, step_idx);
        record_site(&mut sites, COMPARISON_AUX_INJECT_KIND, step_idx);
        record_site(&mut sites, ARITH_SPECIAL_INJECT_KIND, step_idx);
        record_site(&mut sites, DIV_BOUND_INJECT_KIND, step_idx);
        record_site(&mut sites, PRODUCT_INJECT_KIND, step_idx);
        record_site(&mut sites, SIGNED_UNSIGNED_INJECT_KIND, step_idx);
        if is_branch_step(step) {
            record_site(&mut sites, CONTROL_FLOW_INJECT_KIND, step_idx);
        }
        if is_real_lui_step(step) {
            record_site(&mut sites, UPPER_IMMEDIATE_INJECT_KIND, step_idx);
        }
        if step.instruction_lookup.is_some() {
            record_site(&mut sites, LOOKUP_BOOLEAN_INJECT_KIND, step_idx);
        }
        match step.memory_ops[2] {
            MemoryOp::Write(0, _) => record_site(&mut sites, ZERO_REGISTER_INJECT_KIND, step_idx),
            MemoryOp::Write(_, _) => record_site(&mut sites, DEST_BINDING_INJECT_KIND, step_idx),
            MemoryOp::Read(_) => {}
        }
        if is_real_ram_op(step, memory_layout) {
            record_site(&mut sites, MEMORY_ADDRESS_INJECT_KIND, step_idx);
            record_site(&mut sites, MEMORY_KIND_SELECTOR_INJECT_KIND, step_idx);
            record_site(&mut sites, MEMORY_VALUE_INJECT_KIND, step_idx);
            record_site(&mut sites, STORE_LOAD_INJECT_KIND, step_idx);
            record_site(&mut sites, TIME_MONOTONIC_INJECT_KIND, step_idx);
        }
    }
    sites
}

fn proving_sizes(exec: &JoltExecution) -> (usize, usize, usize) {
    let bytecode_size = exec.bytecode.len().max(8).next_power_of_two();
    let memory_size =
        trace_memory_witness_size(&exec.trace, &exec.memory_init, &exec.io_device.memory_layout);
    let trace_size = exec.trace.len().max(8).next_power_of_two();
    (bytecode_size, memory_size, trace_size)
}

fn prove_and_verify(
    exec: JoltExecution,
    exception_candidates: &ExecutedExceptionCandidates,
) -> Result<(Option<String>, bool, Option<ExecutedExceptionReceipt>), String> {
    let (max_bytecode_size, max_memory_size, max_trace_length) = proving_sizes(&exec);
    let prev_kind = std::env::var_os(JOLT_INJECT_KIND_ENV);
    let prev_step = std::env::var_os(JOLT_INJECT_STEP_ENV);
    let prev_applied = std::env::var_os(JOLT_INJECT_APPLIED_ENV);
    let prev_r1cs_candidate = std::env::var_os(JOLT_R1CS_EXCEPTION_CANDIDATE_ENV);
    let prev_lookup_candidate = std::env::var_os(JOLT_INSTRUCTION_LOOKUP_EXCEPTION_CANDIDATE_ENV);
    let prev_exception_receipt = std::env::var_os(JOLT_EXECUTED_EXCEPTION_RECEIPT_ENV);
    std::env::remove_var(JOLT_INJECT_APPLIED_ENV);
    std::env::remove_var(JOLT_EXECUTED_EXCEPTION_RECEIPT_ENV);
    arm_exception_candidate_env(
        JOLT_R1CS_EXCEPTION_CANDIDATE_ENV,
        exception_candidates.r1cs.as_ref(),
    )?;
    arm_exception_candidate_env(
        JOLT_INSTRUCTION_LOOKUP_EXCEPTION_CANDIDATE_ENV,
        exception_candidates.instruction_lookup.as_ref(),
    )?;
    if let Some(kind) = exec.inject_kind.as_deref() {
        std::env::set_var(JOLT_INJECT_KIND_ENV, kind);
        std::env::set_var(JOLT_INJECT_STEP_ENV, exec.inject_step.to_string());
    } else {
        std::env::remove_var(JOLT_INJECT_KIND_ENV);
        std::env::remove_var(JOLT_INJECT_STEP_ENV);
    }
    let prove_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let preprocessing = RV32IJoltVM::prover_preprocess(
            exec.bytecode.clone(),
            exec.io_device.memory_layout.clone(),
            exec.memory_init.clone(),
            max_bytecode_size,
            max_memory_size,
            max_trace_length,
        );
        let (proof, commitments, verifier_io_device, debug_info) =
            <RV32IJoltVM as Jolt<F, PCS, C, M, ProofTranscript>>::prove(
                exec.io_device,
                exec.trace,
                preprocessing.clone(),
            );
        RV32IJoltVM::verify(
            preprocessing.shared,
            proof,
            commitments,
            verifier_io_device,
            debug_info,
        )
        .err()
        .map(|e| format!("jolt verify failed: {e}"))
    }));
    let injection_applied = std::env::var(JOLT_INJECT_APPLIED_ENV).ok().as_deref() == Some("1");
    let raw_executed_exception_receipt = std::env::var(JOLT_EXECUTED_EXCEPTION_RECEIPT_ENV).ok();
    restore_env_var(JOLT_INJECT_KIND_ENV, prev_kind);
    restore_env_var(JOLT_INJECT_STEP_ENV, prev_step);
    restore_env_var(JOLT_INJECT_APPLIED_ENV, prev_applied);
    restore_env_var(JOLT_R1CS_EXCEPTION_CANDIDATE_ENV, prev_r1cs_candidate);
    restore_env_var(JOLT_INSTRUCTION_LOOKUP_EXCEPTION_CANDIDATE_ENV, prev_lookup_candidate);
    restore_env_var(JOLT_EXECUTED_EXCEPTION_RECEIPT_ENV, prev_exception_receipt);
    let executed_exception_receipt =
        parse_executed_exception_receipt(raw_executed_exception_receipt.as_deref())?
            .map(|mut receipt| {
                // The receipt is only emitted from inside the failing sumcheck check,
                // so its presence already attests the failure; stamp the observation
                // and its manifestation for the exact-relation validators.
                let manifestation = match receipt.effect {
                    ExecutedExceptionEffect::SignedUnsignedProductVerification => {
                        Some("inner_sumcheck_mismatch")
                    }
                    ExecutedExceptionEffect::SignedDivisionRemainderVerification => {
                        Some("primary_sumcheck_mismatch")
                    }
                    _ => None,
                };
                if let Some(manifestation) = manifestation {
                    receipt.context.insert("failure_observed".to_string(), json!(true));
                    receipt
                        .context
                        .insert("failure_manifestation".to_string(), json!(manifestation));
                }
                receipt
            });

    match prove_result {
        Ok(verify_res) => Ok((verify_res, injection_applied, executed_exception_receipt)),
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic payload".to_string()
            };
            Ok((Some(format!("jolt panic: {msg}")), injection_applied, executed_exception_receipt))
        }
    }
}

pub fn run_backend_once(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RunResponse, String> {
    let exec = execute_trace(words, inject_kind, inject_step)?;
    let derived = JoltTrace::from_execution(
        words,
        &exec.rows,
        &exec.trace,
        &exec.bytecode,
        &exec.memory_init,
        &exec.io_device,
    )?;
    let final_regs = exec.final_regs;
    let micro_op_count = exec.trace.len();
    let observed_injection_sites =
        collect_observed_injection_sites(&exec.trace, &exec.io_device.memory_layout);
    let trace_injection_applied = exec.injection_applied;
    let semantic_mutation_receipt = exec
        .semantic_mutation_receipt
        .clone()
        .and_then(|receipt| bind_semantic_mutation_receipt(receipt, derived.bucket_hits()));
    let exception_candidates =
        executed_exception_candidates(derived.bucket_hits(), inject_kind.is_none());
    let (backend_error, proof_injection_applied, executed_exception_receipt) =
        prove_and_verify(exec, &exception_candidates)?;
    let injection_applied = trace_injection_applied || proof_injection_applied;

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count,
        bucket_hits: derived.bucket_hits().to_vec(),
        trace_signals: derived.trace_signals().to_vec(),
        backend_error,
        observed_injection_sites,
        injection_applied,
        semantic_mutation_receipt,
        executed_exception_receipt,
    })
}

struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    responses_rx: Receiver<Result<WorkerResponse, String>>,
    reader_thread: JoinHandle<()>,
}

pub struct JoltBackend {
    max_instructions: usize,
    eval: BackendEval,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    current_iteration: u64,
    next_request_id: u64,
    pending_injection: Option<WitnessInjectionPlan>,
    worker: Option<WorkerProcess>,
}

impl JoltBackend {
    pub fn new(max_instructions: usize) -> Self {
        Self {
            max_instructions,
            eval: BackendEval::default(),
            last_observed_injection_sites: BTreeMap::new(),
            current_iteration: 0,
            next_request_id: 1,
            pending_injection: None,
            worker: None,
        }
    }

    fn candidate_schedule(&self, inject_kind: &str, anchor: u64) -> InjectionSchedule {
        let base_kind = base_inject_kind(inject_kind);
        if let Some(steps) = self
            .last_observed_injection_sites
            .get(inject_kind)
            .or_else(|| self.last_observed_injection_sites.get(base_kind))
        {
            if !steps.is_empty() {
                return InjectionSchedule::Explicit(steps.clone());
            }
        }
        if base_kind == ENTRYPOINT_INJECT_KIND {
            InjectionSchedule::Exact(0)
        } else if matches!(
            base_kind,
            MEMORY_INITIAL_INJECT_KIND | MEMORY_FINALIZATION_INJECT_KIND | PADDING_INJECT_KIND
        ) {
            InjectionSchedule::Exact(anchor)
        } else {
            InjectionSchedule::AroundAnchor(anchor)
        }
    }

    fn start_worker(&mut self) -> Result<(), String> {
        if self.worker.is_some() {
            return Ok(());
        }
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("resolve current executable for worker failed: {e}"))?;
        let mut child = Command::new(exe_path)
            .arg("--worker-loop")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn backend worker failed: {e}"))?;

        let stdin =
            child.stdin.take().ok_or_else(|| "capture backend worker stdin failed".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "capture backend worker stdout failed".to_string())?;

        let (tx, rx) = mpsc::channel::<Result<WorkerResponse, String>>();
        let reader_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || !trimmed.starts_with(WORKER_RESPONSE_PREFIX) {
                            continue;
                        }
                        let payload = &trimmed[WORKER_RESPONSE_PREFIX.len()..];
                        let parsed = serde_json::from_str::<WorkerResponse>(payload).map_err(|e| {
                            let mut preview = payload.chars().take(200).collect::<String>();
                            if payload.chars().count() > 200 {
                                preview.push_str("...");
                            }
                            format!("parse worker response failed: {e}; raw={preview:?}")
                        });
                        if tx.send(parsed).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("read worker response failed: {e}")));
                        break;
                    }
                }
            }
        });

        self.worker = Some(WorkerProcess { child, stdin, responses_rx: rx, reader_thread });
        Ok(())
    }

    fn stop_worker(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            let _ = worker.child.kill();
            let _ = worker.child.wait();
            drop(worker.stdin);
            let _ = worker.reader_thread.join();
        }
    }

    fn candidate_for_hit(&self, hit: &BucketHit) -> Option<SemanticInjectionCandidate> {
        let obligation_id = hit.details.get("obligation_id")?.as_str()?;
        let step_anchor = hit
            .details
            .get("step_idx")
            .and_then(|v| v.as_u64())
            .or_else(|| hit.details.get("op_idx").and_then(|v| v.as_u64()));
        let witness_anchor = hit.details.get("witness_index").and_then(|v| v.as_u64());
        let anchor = if matches!(obligation_id, "me7" | "me11") {
            witness_anchor.or(step_anchor)?
        } else {
            step_anchor.or(witness_anchor)?
        };
        let (semantic_class, inject_kind) = match (hit.bucket_id.as_str(), obligation_id) {
            (id, "rf1") if id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id => (
                semantic::decode::ZERO_REGISTER_IMMUTABILITY.semantic_class,
                ZERO_REGISTER_INJECT_KIND,
            ),
            (id, "rf2") if id == semantic::decode::OPERAND_INDEX_ROUTING.id => {
                (semantic::decode::OPERAND_INDEX_ROUTING.semantic_class, OPERAND_INDEX_INJECT_KIND)
            }
            (id, "rf3") if id == semantic::exec::DEST_BINDING.id => {
                (semantic::exec::DEST_BINDING.semantic_class, DEST_BINDING_INJECT_KIND)
            }
            (id, "id1") if id == semantic::decode::FIELD_RANGE.id => {
                (semantic::decode::FIELD_RANGE.semantic_class, FIELD_RANGE_INJECT_KIND)
            }
            (id, "id2") if id == semantic::decode::IMMEDIATE_SIGN_EXTENSION.id => (
                semantic::decode::IMMEDIATE_SIGN_EXTENSION.semantic_class,
                IMMEDIATE_SIGN_INJECT_KIND,
            ),
            (id, "id3") if id == semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION.id => (
                semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION.semantic_class,
                UPPER_IMMEDIATE_INJECT_KIND,
            ),
            (id, "id4") if id == semantic::exec::OP_SELECTOR_BINDING.id => {
                (semantic::exec::OP_SELECTOR_BINDING.semantic_class, OP_SELECTOR_INJECT_KIND)
            }
            (id, "id5") if id == semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.id => (
                semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.semantic_class,
                FORMAT_IMMEDIATE_INJECT_KIND,
            ),
            (id, "al1") if id == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id => (
                semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.semantic_class,
                ALU_IMMEDIATE_INJECT_KIND,
            ),
            (id, "al2") if id == semantic::alu::SHIFT_MOD32.id => {
                (semantic::alu::SHIFT_MOD32.semantic_class, SHIFT_INJECT_KIND)
            }
            (id, "al3") if id == semantic::alu::COMPARISON_BOOLEANITY.id => {
                (semantic::alu::COMPARISON_BOOLEANITY.semantic_class, COMPARISON_BOOL_INJECT_KIND)
            }
            (id, "al4") if id == semantic::alu::SUBTRACTION_BORROW_CHAIN.id => {
                (semantic::alu::SUBTRACTION_BORROW_CHAIN.semantic_class, SUBTRACTION_INJECT_KIND)
            }
            (id, "al5") if id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id => (
                semantic::alu::COMPARISON_AUXILIARY_CHAIN.semantic_class,
                COMPARISON_AUX_INJECT_KIND,
            ),
            (id, "md1" | "md2") if id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id => (
                semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.semantic_class,
                ARITH_SPECIAL_INJECT_KIND,
            ),
            (id, "md3") if id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id => (
                semantic::arithmetic::DIVISION_REMAINDER_BOUND.semantic_class,
                DIV_BOUND_INJECT_KIND,
            ),
            (id, "md4") if id == semantic::arithmetic::PRODUCT_DECOMPOSITION.id => {
                (semantic::arithmetic::PRODUCT_DECOMPOSITION.semantic_class, PRODUCT_INJECT_KIND)
            }
            (id, "md5") if id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id => (
                semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.semantic_class,
                SIGNED_UNSIGNED_INJECT_KIND,
            ),
            (id, "me1") if id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id => {
                (semantic::memory::STORE_LOAD_PAYLOAD_FLOW.semantic_class, STORE_LOAD_INJECT_KIND)
            }
            (id, "me2") if id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id => (
                semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.semantic_class,
                MEMORY_ADDRESS_INJECT_KIND,
            ),
            (id, "me3") if id == semantic::memory::LOAD_VALUE_BINDING.id => {
                (semantic::memory::LOAD_VALUE_BINDING.semantic_class, MEMORY_VALUE_INJECT_KIND)
            }
            (id, "me4") if id == semantic::memory::WRITE_PAYLOAD_CONSISTENCY.id => (
                semantic::memory::WRITE_PAYLOAD_CONSISTENCY.semantic_class,
                MEMORY_VALUE_INJECT_KIND,
            ),
            (id, "me5") if id == semantic::memory::ADDRESS_SPACE_CONSISTENCY.id => (
                semantic::memory::ADDRESS_SPACE_CONSISTENCY.semantic_class,
                MEMORY_ADDRESS_SPACE_INJECT_KIND,
            ),
            (id, "me6") if id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id => (
                semantic::memory::ADDRESS_BOUNDARY_RANGE.semantic_class,
                MEMORY_ADDRESS_INJECT_KIND,
            ),
            (id, "me7") if id == semantic::memory::INITIAL_VALUE_BINDING.id => {
                (semantic::memory::INITIAL_VALUE_BINDING.semantic_class, MEMORY_INITIAL_INJECT_KIND)
            }
            (id, "me9") if id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id => (
                semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.semantic_class,
                MEMORY_ADDRESS_INJECT_KIND,
            ),
            (id, "me10") if id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id => (
                semantic::memory::KIND_SELECTOR_CONSISTENCY.semantic_class,
                MEMORY_KIND_SELECTOR_INJECT_KIND,
            ),
            (id, "me11") if id == semantic::memory::FINALIZATION_CONSISTENCY.id => (
                semantic::memory::FINALIZATION_CONSISTENCY.semantic_class,
                MEMORY_FINALIZATION_INJECT_KIND,
            ),
            (id, "ts1" | "ts3") if id == semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id => (
                semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.semantic_class,
                TIME_BOUNDARY_INJECT_KIND,
            ),
            (id, "ts2") if id == semantic::time::MONOTONIC_ACCESS_ORDERING.id => (
                semantic::time::MONOTONIC_ACCESS_ORDERING.semantic_class,
                TIME_MONOTONIC_INJECT_KIND,
            ),
            (id, "cf4") if id == semantic::control::ENTRYPOINT_BINDING.id => {
                (semantic::control::ENTRYPOINT_BINDING.semantic_class, ENTRYPOINT_INJECT_KIND)
            }
            (id, "cf1") if id == semantic::exec::CONTROL_FLOW_BINDING.id => {
                (semantic::exec::CONTROL_FLOW_BINDING.semantic_class, CONTROL_FLOW_INJECT_KIND)
            }
            (id, "bu1") if id == semantic::lookup::BOOLEAN_MULTIPLICITY.id => {
                (semantic::lookup::BOOLEAN_MULTIPLICITY.semantic_class, LOOKUP_BOOLEAN_INJECT_KIND)
            }
            (id, "pd1") if id == semantic::row::PADDING_INTERACTION_SEND.id => {
                (semantic::row::PADDING_INTERACTION_SEND.semantic_class, PADDING_INJECT_KIND)
            }
            (id, "pd4") if id == semantic::row::BYTECODE_TABLE_BOUNDARY.id => {
                // Bucket-only for now: PD4 needs a dedicated bytecode-boundary hook, not PD1 padding.
                return None;
            }
            _ => return None,
        };

        Some(SemanticInjectionCandidate {
            bucket_id: hit.bucket_id.clone(),
            trigger_signal_id: None,
            semantic_class: semantic_class.to_string(),
            inject_kind: inject_kind.to_string(),
            schedule: self.candidate_schedule(inject_kind, anchor),
        })
    }
}

impl BenchmarkBackend for JoltBackend {
    fn is_usable_seed(&self, words: &[u32]) -> bool {
        if words.is_empty() || words.len() > self.max_instructions {
            return false;
        }
        words.iter().all(|w| RV32IMInstruction::decode(*w).is_some())
    }

    fn prepare_for_run(&mut self, _rng_seed: u64) {
        self.eval = BackendEval::default();
        self.last_observed_injection_sites.clear();
        self.current_iteration = self.current_iteration.saturating_add(1);
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval = BackendEval::default();
        self.start_worker()?;
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        let req = WorkerRequest {
            request_id,
            words: words.to_vec(),
            iteration: self.current_iteration,
            inject_kind: self.pending_injection.as_ref().map(|p| p.kind.clone()),
            inject_step: self.pending_injection.as_ref().map(|p| p.step).unwrap_or(0),
        };
        {
            let worker =
                self.worker.as_mut().ok_or_else(|| "backend worker unavailable".to_string())?;
            let mut payload = serde_json::to_vec(&req)
                .map_err(|e| format!("serialize worker request failed: {e}"))?;
            payload.push(b'\n');
            worker
                .stdin
                .write_all(&payload)
                .map_err(|e| format!("write worker request failed: {e}"))?;
            worker.stdin.flush().map_err(|e| format!("flush worker request failed: {e}"))?;
        }

        let resp = loop {
            let recv = {
                let worker =
                    self.worker.as_ref().ok_or_else(|| "backend worker unavailable".to_string())?;
                worker.responses_rx.recv()
            };
            match recv {
                Ok(Ok(resp)) if resp.request_id == request_id => break resp,
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => {
                    self.stop_worker();
                    self.eval.backend_error = Some(e.clone());
                    return Err(e);
                }
                Err(_) => {
                    self.stop_worker();
                    let msg = "backend worker disconnected".to_string();
                    self.eval.backend_error = Some(msg.clone());
                    return Err(msg);
                }
            }
        };
        self.stop_worker();
        self.last_observed_injection_sites = resp.observed_injection_sites;
        self.eval.final_regs = resp.final_regs;
        self.eval.micro_op_count = resp.micro_op_count;
        self.eval.bucket_hits = resp.bucket_hits;
        self.eval.trace_signals = resp.trace_signals;
        self.eval.backend_error = resp.backend_error;
        self.eval.semantic_injection_applied = resp.injection_applied;
        self.eval.semantic_mutation_receipt = resp.semantic_mutation_receipt;
        self.eval.executed_exception_receipt = resp.executed_exception_receipt;
        resp.final_regs.ok_or_else(|| "jolt backend returned no final_regs".to_string())
    }

    fn collect_eval(&mut self) -> BackendEval {
        self.eval.clone()
    }

    fn clear_semantic_injection(&mut self) {
        self.pending_injection = None;
    }

    fn arm_semantic_injection(&mut self, kind: &str, step: u64) -> Result<(), String> {
        self.pending_injection = Some(WitnessInjectionPlan { kind: kind.to_string(), step });
        Ok(())
    }

    fn semantic_mutation_relation(
        &self,
        candidate: &SemanticInjectionCandidate,
    ) -> Option<SemanticMutationRelation> {
        match base_inject_kind(&candidate.inject_kind) {
            UPPER_IMMEDIATE_INJECT_KIND => Some(SemanticMutationRelation::UpperImmediateEquation),
            ENTRYPOINT_INJECT_KIND => Some(SemanticMutationRelation::EntrypointPcEquation),
            _ => None,
        }
    }

    fn semantic_injection_candidates(&self, hits: &[BucketHit]) -> Vec<SemanticInjectionCandidate> {
        let mut seen = BTreeSet::new();
        hits.iter()
            .filter_map(|hit| self.candidate_for_hit(hit))
            .filter(|candidate| {
                seen.insert((candidate.bucket_id.clone(), candidate.inject_kind.clone()))
            })
            .collect()
    }
}

impl Drop for JoltBackend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}

#[cfg(test)]
mod receipt_tests {
    use std::collections::HashMap;

    use beak_core::fuzz::benchmark::{
        BenchmarkBackend, ExecutedExceptionEffect, InjectionSchedule, SemanticInjectionCandidate,
        SemanticMutationRelation,
    };
    use beak_core::fuzz::bug_filter::has_exact_executed_exception_relation;
    use beak_core::trace::{semantic, BucketHit};
    use serde_json::json;

    use super::{
        bind_semantic_mutation_receipt, executed_exception_candidates,
        parse_executed_exception_receipt, parse_semantic_mutation_receipt, JoltBackend,
        ENTRYPOINT_INJECT_KIND, UPPER_IMMEDIATE_INJECT_KIND,
    };

    const VALID: &str = r#"{"inject_kind":"jolt.semantic.decode.upper_immediate_materialization","site":"host.trace.upper_immediate_lookup","field":"virtual_advice_value","step":3,"before":305418240,"after":305422336,"effect":{"relation":"upper_immediate_equation","context":{"obligation_id":"id3","cell_id":"id3.lui_mid","op_idx":3,"opcode":305418423,"mnemonic":"lui","imm20":74565,"expected_result":305418240,"witnessed_result_before":305418240,"witnessed_result_after":305422336,"executed_instruction":true}}}"#;
    const ENTRY_VALID: &str = r#"{"inject_kind":"jolt.semantic.control.entrypoint_binding","site":"executor.trace_start","field":"start_pc","step":0,"before":2147483648,"after":2147483652,"effect":{"relation":"entrypoint_pc_equation","context":{"bucket_id":"sem.control.entrypoint_binding","obligation_id":"cf4","cell_id":"cf4.default_entry","backend":"jolt","trace_source":"instruction","op_idx":0,"step_idx":0,"boundary_row":0,"pc":2147483648,"opcode":"0x00100093","mnemonic":"addi","declared_entry":2147483648,"witnessed_pc_before":2147483648,"witnessed_pc_after":2147483652,"mutation_mode":"skip_one","executed_boundary_row":true}}}"#;

    #[test]
    fn typed_receipt_parser_accepts_complete_receipt() {
        let receipt = parse_semantic_mutation_receipt(Some(VALID)).unwrap().unwrap();
        assert_eq!(receipt.step, 3);
        assert_eq!(receipt.before, 305418240);
        assert_eq!(receipt.after, 305422336);
        assert_eq!(receipt.effect.relation, SemanticMutationRelation::UpperImmediateEquation);
    }

    fn lui_hit() -> BucketHit {
        BucketHit::semantic(
            semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION,
            HashMap::from([
                ("obligation_id".to_string(), json!("id3")),
                ("cell_id".to_string(), json!("id3.lui_mid")),
                ("op_idx".to_string(), json!(3)),
                ("pc".to_string(), json!(0x8000_000cu64)),
                ("opcode".to_string(), json!(305418423u64)),
                ("mnemonic".to_string(), json!("lui")),
                ("backend".to_string(), json!("jolt")),
                ("commit".to_string(), json!("e9caa23565dbb13019afe61a2c95f51d1999e286")),
                ("trace_source".to_string(), json!("instruction")),
                ("imm20".to_string(), json!(74565)),
                ("expected_result".to_string(), json!(305418240u64)),
                ("witnessed_result_before".to_string(), json!(305418240u64)),
            ]),
        )
    }

    /// Boundary-row hit observed on the injected executor-level run: the
    /// witnessed start (0x80000004) diverges from the declared entry.  Its
    /// opcode/mnemonic describe the first *executed* row, which need not equal
    /// the declared first word.
    fn entry_hit() -> BucketHit {
        BucketHit::semantic(
            semantic::control::ENTRYPOINT_BINDING,
            HashMap::from([
                ("obligation_id".to_string(), json!("cf4")),
                ("cell_id".to_string(), json!("cf4.custom_entry")),
                ("op_idx".to_string(), json!(0)),
                ("pc".to_string(), json!(0x8000_0004u64)),
                ("opcode".to_string(), json!("0x00100093")),
                ("mnemonic".to_string(), json!("addi")),
                ("backend".to_string(), json!("jolt")),
                ("commit".to_string(), json!("e9caa23565dbb13019afe61a2c95f51d1999e286")),
                ("trace_source".to_string(), json!("instruction")),
                ("declared_entry".to_string(), json!(0x8000_0000u64)),
                ("witnessed_pc_before".to_string(), json!(0x8000_0004u64)),
            ]),
        )
    }

    #[test]
    fn equation_receipt_binding_requires_one_exact_executed_hit() {
        let receipt = parse_semantic_mutation_receipt(Some(VALID)).unwrap().unwrap();
        let bound = bind_semantic_mutation_receipt(receipt.clone(), &[lui_hit()]).unwrap();
        assert_eq!(
            bound.effect.context.get("bucket_id"),
            Some(&json!("sem.decode.upper_immediate_materialization"))
        );
        assert_eq!(
            bound.effect.context.get("commit"),
            Some(&json!("e9caa23565dbb13019afe61a2c95f51d1999e286"))
        );

        let mut wrong = lui_hit();
        wrong.details.insert("opcode".to_string(), json!(0x37));
        assert!(bind_semantic_mutation_receipt(receipt.clone(), &[wrong]).is_none());
        assert!(bind_semantic_mutation_receipt(receipt.clone(), &[]).is_none());
        assert!(bind_semantic_mutation_receipt(receipt, &[lui_hit(), lui_hit()]).is_none());
    }

    #[test]
    fn entrypoint_receipt_binding_rejects_stale_or_ambiguous_boundary_rows() {
        let receipt = parse_semantic_mutation_receipt(Some(ENTRY_VALID)).unwrap().unwrap();
        let bound = bind_semantic_mutation_receipt(receipt.clone(), &[entry_hit()]).unwrap();
        assert_eq!(bound.effect.relation, SemanticMutationRelation::EntrypointPcEquation);
        assert_eq!(bound.effect.context.get("opcode"), Some(&json!("0x00100093")));

        let mut stale = entry_hit();
        stale.details.insert("declared_entry".to_string(), json!(0x8000_0004u64));
        assert!(bind_semantic_mutation_receipt(receipt.clone(), &[stale]).is_none());

        let mut forged_declaration = receipt.clone();
        forged_declaration.before = json!(0x8000_0004u64);
        forged_declaration.effect.context.insert("pc".to_string(), json!(0x8000_0004u64));
        forged_declaration
            .effect
            .context
            .insert("declared_entry".to_string(), json!(0x8000_0004u64));
        forged_declaration
            .effect
            .context
            .insert("witnessed_pc_before".to_string(), json!(0x8000_0004u64));
        let mut forged_hit = entry_hit();
        forged_hit.details.insert("pc".to_string(), json!(0x8000_0004u64));
        forged_hit.details.insert("declared_entry".to_string(), json!(0x8000_0004u64));
        forged_hit
            .details
            .insert("witnessed_pc_before".to_string(), json!(0x8000_0004u64));
        assert!(bind_semantic_mutation_receipt(forged_declaration, &[forged_hit]).is_none());

        // A hit that does not witness divergence (witnessed == declared) is
        // the baseline shape and must not bind an executor-level receipt.
        let mut undiverged = entry_hit();
        undiverged.details.insert("pc".to_string(), json!(0x8000_0000u64));
        undiverged
            .details
            .insert("witnessed_pc_before".to_string(), json!(0x8000_0000u64));
        assert!(bind_semantic_mutation_receipt(receipt.clone(), &[undiverged]).is_none());

        assert!(bind_semantic_mutation_receipt(receipt.clone(), &[]).is_none());
        assert!(bind_semantic_mutation_receipt(receipt, &[entry_hit(), entry_hit()]).is_none());
    }

    #[test]
    fn entrypoint_receipt_binding_rejects_delete_noop_moved_and_non_boundary_effects() {
        let receipt = parse_semantic_mutation_receipt(Some(ENTRY_VALID)).unwrap().unwrap();

        let mut deleted = receipt.clone();
        deleted
            .effect
            .context
            .insert("executed_boundary_row".to_string(), json!(false));
        assert!(bind_semantic_mutation_receipt(deleted, &[entry_hit()]).is_none());

        let mut no_op = receipt.clone();
        no_op.after = json!(0x8000_0000u64);
        no_op.effect.context.insert("witnessed_pc_after".to_string(), json!(0x8000_0000u64));
        assert!(bind_semantic_mutation_receipt(no_op, &[entry_hit()]).is_none());

        let mut moved = receipt.clone();
        moved.site = "host.trace.row1.bytecode_row".to_string();
        assert!(bind_semantic_mutation_receipt(moved, &[entry_hit()]).is_none());

        let mut wrong_field = receipt.clone();
        wrong_field.field = "skipped_prefix_rows".to_string();
        assert!(bind_semantic_mutation_receipt(wrong_field, &[entry_hit()]).is_none());

        let mut non_boundary = receipt.clone();
        non_boundary.step = 1;
        non_boundary.effect.context.insert("op_idx".to_string(), json!(1));
        non_boundary.effect.context.insert("step_idx".to_string(), json!(1));
        non_boundary.effect.context.insert("boundary_row".to_string(), json!(1));
        assert!(bind_semantic_mutation_receipt(non_boundary, &[entry_hit()]).is_none());
    }

    #[test]
    fn entrypoint_receipt_binding_rejects_stale_or_mismatched_unchanged_row_context() {
        let receipt = parse_semantic_mutation_receipt(Some(ENTRY_VALID)).unwrap().unwrap();

        // Opcode/mnemonic of the receipt describe the declared first word and
        // are checked against the *baseline* hit by the core; the adapter bind
        // only anchors the witnessed divergence, so these still bind.
        let mut stale_opcode = receipt.clone();
        stale_opcode.effect.context.insert("opcode".to_string(), json!("0x00200113"));
        stale_opcode
            .effect
            .context
            .insert("first_row_opcode_before".to_string(), json!("0x00200113"));
        stale_opcode
            .effect
            .context
            .insert("first_row_opcode_after".to_string(), json!("0x00200113"));
        assert!(bind_semantic_mutation_receipt(stale_opcode, &[entry_hit()]).is_some());

        let mut changed_opcode = receipt.clone();
        changed_opcode
            .effect
            .context
            .insert("opcode".to_string(), json!("0x00200113"));
        assert!(bind_semantic_mutation_receipt(changed_opcode, &[entry_hit()]).is_some());

        let mut changed_mnemonic = receipt.clone();
        changed_mnemonic
            .effect
            .context
            .insert("mnemonic".to_string(), json!("sub"));
        assert!(bind_semantic_mutation_receipt(changed_mnemonic, &[entry_hit()]).is_some());

        let mut reordered = receipt;
        reordered
            .effect
            .context
            .insert("witnessed_pc_after".to_string(), json!(0x8000_0000u64));
        reordered.after = json!(0x8000_0000u64);
        assert!(bind_semantic_mutation_receipt(reordered, &[entry_hit()]).is_none());
    }

    #[test]
    fn backend_maps_jolt_scoped_buckets_to_equation_relations() {
        let backend = JoltBackend::new(8);
        let candidate = |bucket_id: &str, inject_kind: &str| SemanticInjectionCandidate {
            bucket_id: bucket_id.to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.test".to_string(),
            inject_kind: inject_kind.to_string(),
            schedule: InjectionSchedule::Exact(0),
        };
        assert_eq!(
            backend.semantic_mutation_relation(&candidate(
                semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION.id,
                UPPER_IMMEDIATE_INJECT_KIND,
            )),
            Some(SemanticMutationRelation::UpperImmediateEquation)
        );
        assert_eq!(
            backend.semantic_mutation_relation(&candidate(
                semantic::control::ENTRYPOINT_BINDING.id,
                ENTRYPOINT_INJECT_KIND,
            )),
            Some(SemanticMutationRelation::EntrypointPcEquation)
        );
    }

    #[test]
    fn ordinary_addi_and_lui_carriers_are_admitted_and_receive_bounded_schedules() {
        let backend = JoltBackend::new(256);
        assert!(backend.is_usable_seed(&[0x0010_0093]));
        assert!(backend.is_usable_seed(&[0x8000_00b7]));

        let candidates = backend.semantic_injection_candidates(&[entry_hit(), lui_hit()]);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].bucket_id, semantic::control::ENTRYPOINT_BINDING.id);
        assert_eq!(candidates[0].inject_kind, ENTRYPOINT_INJECT_KIND);
        assert!(matches!(candidates[0].schedule, InjectionSchedule::Exact(0)));
        assert_eq!(
            candidates[1].bucket_id,
            semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION.id
        );
        assert_eq!(candidates[1].inject_kind, UPPER_IMMEDIATE_INJECT_KIND);
        assert!(matches!(
            candidates[1].schedule,
            InjectionSchedule::AroundAnchor(3)
        ));
    }

    #[test]
    fn typed_receipt_parser_fails_closed_for_missing_or_incomplete_data() {
        assert!(parse_semantic_mutation_receipt(None).unwrap().is_none());
        assert!(parse_semantic_mutation_receipt(Some("not-json")).is_err());
        assert!(parse_semantic_mutation_receipt(Some(
            r#"{"inject_kind":"jolt.semantic.decode.upper_immediate_materialization","step":3}"#,
        ))
        .is_err());
    }

    fn executed_hit(
        bucket: semantic::SemanticBucket,
        obligation_id: &str,
        cell_id: &str,
        mnemonic: &str,
        extras: &[(&str, serde_json::Value)],
    ) -> BucketHit {
        let mut details = HashMap::from([
            ("obligation_id".to_string(), json!(obligation_id)),
            ("cell_id".to_string(), json!(cell_id)),
            ("op_idx".to_string(), json!(7)),
            ("step_idx".to_string(), json!(7)),
            ("pc".to_string(), json!(0x8000_0000u64)),
            ("opcode".to_string(), json!("0x02c5c733")),
            ("backend".to_string(), json!("jolt")),
            (
                "commit".to_string(),
                json!("e9caa23565dbb13019afe61a2c95f51d1999e286"),
            ),
            ("mnemonic".to_string(), json!(mnemonic)),
            ("trace_source".to_string(), json!("instruction")),
        ]);
        details.extend(extras.iter().map(|(key, value)| ((*key).to_string(), value.clone())));
        BucketHit::semantic(bucket, details)
    }

    #[test]
    fn exact_non_injected_divrem_and_mulhsu_hits_build_typed_candidates() {
        let divrem = executed_hit(
            semantic::arithmetic::DIVISION_REMAINDER_BOUND,
            "md3",
            "md3.np",
            "div",
            &[
                ("dividend", json!(-7)),
                ("divisor", json!(3)),
                ("quotient", json!(-2)),
                ("remainder", json!(-1)),
                ("recomposed", json!(-7)),
                ("remainder_bound_holds", json!(true)),
                ("remainder_sign_holds", json!(true)),
                ("relation", json!("quotient_times_divisor_plus_remainder")),
                ("relation_valid", json!(true)),
                ("failure_observed", json!(true)),
                ("failure_manifestation", json!("primary_sumcheck_mismatch")),
            ],
        );
        let mulhsu = executed_hit(
            semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION,
            "md5",
            "md5.neg_max",
            "mulhsu",
            &[
                ("signed_lhs", json!(-1)),
                ("unsigned_rhs", json!(u32::MAX)),
                ("product_hi", json!(u32::MAX)),
                ("product_lo", json!(1)),
                ("expected_high32", json!(u32::MAX)),
                ("architectural_result", json!(u32::MAX)),
                ("architectural_result_matches", json!(true)),
                ("observed_result", json!(0)),
                ("observed_result_source", json!("processed_virtual_sequence.final_rd_write")),
                ("rd", json!(5)),
                ("processed_row_idx", json!(7)),
                ("processed_segment_start_step", json!(19)),
                ("processed_segment_end_step", json!(23)),
                ("processed_final_rd_write_step", json!(22)),
                ("processed_final_rd_address", json!(5)),
                ("result_matches", json!(false)),
                ("result_mismatch", json!(true)),
                ("relation", json!("high32_signed_lhs_times_unsigned_rhs")),
                ("relation_valid", json!(true)),
                ("failure_observed", json!(true)),
                ("failure_manifestation", json!("inner_sumcheck_mismatch")),
            ],
        );

        let hits = vec![divrem, mulhsu];
        let candidates = executed_exception_candidates(&hits, true);
        let divrem_receipt = candidates.instruction_lookup.unwrap();
        assert_eq!(
            divrem_receipt.effect,
            ExecutedExceptionEffect::SignedDivisionRemainderVerification
        );
        assert_eq!(divrem_receipt.cell_id, "md3.np");
        assert_eq!(divrem_receipt.step, 7);
        assert!(has_exact_executed_exception_relation(&hits, Some(&divrem_receipt)));
        let mulhsu_receipt = candidates.r1cs.unwrap();
        assert_eq!(
            mulhsu_receipt.effect,
            ExecutedExceptionEffect::SignedUnsignedProductVerification
        );
        assert_eq!(mulhsu_receipt.cell_id, "md5.neg_max");
        assert!(has_exact_executed_exception_relation(&hits, Some(&mulhsu_receipt)));
    }

    #[test]
    fn processed_rd_receipt_chain_requires_exact_row_local_provenance() {
        let exact = executed_hit(
            semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION,
            "md5",
            "md5.neg_max",
            "mulhsu",
            &[
                ("signed_lhs", json!(-1)),
                ("unsigned_rhs", json!(u32::MAX)),
                ("product_hi", json!(u32::MAX)),
                ("product_lo", json!(1)),
                ("expected_high32", json!(u32::MAX)),
                ("architectural_result", json!(u32::MAX)),
                ("architectural_result_matches", json!(true)),
                ("observed_result", json!(0)),
                ("observed_result_source", json!("processed_virtual_sequence.final_rd_write")),
                ("rd", json!(5)),
                ("processed_row_idx", json!(7)),
                ("processed_segment_start_step", json!(19)),
                ("processed_segment_end_step", json!(23)),
                ("processed_final_rd_write_step", json!(22)),
                ("processed_final_rd_address", json!(5)),
                ("result_matches", json!(false)),
                ("result_mismatch", json!(true)),
                ("relation", json!("high32_signed_lhs_times_unsigned_rhs")),
                ("relation_valid", json!(true)),
            ],
        );
        assert!(executed_exception_candidates(&[exact.clone()], true).r1cs.is_some());

        let mut missing_marker = exact.clone();
        missing_marker.details.remove("processed_segment_end_step");
        assert!(executed_exception_candidates(&[missing_marker], true).r1cs.is_none());

        let mut outside_segment = exact;
        outside_segment.details.insert("processed_final_rd_write_step".to_string(), json!(24));
        assert!(executed_exception_candidates(&[outside_segment], true).r1cs.is_none());
    }

    #[test]
    fn exception_candidates_fail_closed_for_injected_controls_and_malformed_relations() {
        let malformed_divrem = executed_hit(
            semantic::arithmetic::DIVISION_REMAINDER_BOUND,
            "md3",
            "md3.np",
            "div",
            &[
                ("dividend", json!(-7)),
                ("divisor", json!(3)),
                ("quotient", json!(-2)),
                ("remainder", json!(1)),
                ("recomposed", json!(-5)),
                ("remainder_bound_holds", json!(true)),
                ("remainder_sign_holds", json!(false)),
                ("relation", json!("quotient_times_divisor_plus_remainder")),
                ("relation_valid", json!(true)),
            ],
        );
        let mulhu_control = executed_hit(
            semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION,
            "md5",
            "md5.neg_max",
            "mulhu",
            &[],
        );
        let candidates =
            executed_exception_candidates(&[malformed_divrem.clone(), mulhu_control], true);
        assert!(candidates.instruction_lookup.is_none());
        assert!(candidates.r1cs.is_none());
        let injected = executed_exception_candidates(&[malformed_divrem], false);
        assert!(injected.instruction_lookup.is_none());
        assert!(injected.r1cs.is_none());

        assert!(parse_executed_exception_receipt(None).unwrap().is_none());
        assert!(parse_executed_exception_receipt(Some("not-json")).is_err());
        assert!(parse_executed_exception_receipt(Some(
            r#"{"effect":"signed_division_remainder_verification","obligation_id":"md3"}"#,
        ))
        .is_err());
    }
}
