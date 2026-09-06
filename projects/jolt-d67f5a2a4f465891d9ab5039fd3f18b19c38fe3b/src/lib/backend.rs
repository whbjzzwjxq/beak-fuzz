use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use beak_core::fuzz::benchmark::{BackendEval, BenchmarkBackend, ExecutedExceptionReceipt};
use beak_core::fuzz::bug_filter::has_exact_executed_exception_relation;
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, TraceSignal};
use common::constants::RAM_START_ADDRESS;
use common::jolt_device::{MemoryConfig, MemoryLayout};
use jolt::{host, Jolt, JoltRV64IMAC, JoltVerifierPreprocessing};
use serde::{Deserialize, Serialize};
use tracer::instruction::Cycle;

const LOOP_FOREVER_WORD: u32 = 0x0000_006f;
const T0_REG: u32 = 5;
const T1_REG: u32 = 6;
const DORY_MATRIX_WIDTH_K: u64 = 1 << 8;
const DORY_RECEIPT_ARMED_ENV: &str = "BEAK_JOLT_DORY_RECEIPT_ARMED";
const DORY_INPUT_WORDS_LEN_ENV: &str = "BEAK_JOLT_DORY_INPUT_WORDS_LEN";
const DORY_UNPADDED_TRACE_LEN_ENV: &str = "BEAK_JOLT_DORY_UNPADDED_TRACE_LEN";
const EXECUTED_EXCEPTION_RECEIPT_ENV: &str = "BEAK_JOLT_EXECUTED_EXCEPTION_RECEIPT";
static TEMP_ELF_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub backend_error: Option<String>,
    pub injection_applied: bool,
    pub executed_exception_receipt: Option<ExecutedExceptionReceipt>,
}

struct JoltExecution {
    elf: Vec<u8>,
    bytecode: Vec<tracer::instruction::Instruction>,
    memory_init: Vec<(u64, u8)>,
    trace: Vec<Cycle>,
    io_device: common::jolt_device::JoltDevice,
    final_regs: [u32; 32],
}

fn build_program_words(words: &[u32]) -> Vec<u32> {
    let mut out = words.to_vec();
    let memory_config = MemoryConfig { program_size: Some(0), ..MemoryConfig::default() };
    let termination_addr = MemoryLayout::new(&memory_config).termination as u32;
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
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    write_u16(&mut elf, 16, 2);
    write_u16(&mut elf, 18, 0x00f3);
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

fn final_regs_from_trace(trace: &[Cycle]) -> [u32; 32] {
    let mut final_regs = [0u32; 32];
    for cycle in trace {
        let (rd, _pre, post) = cycle.rd_write();
        if rd != 0 && (rd as usize) < final_regs.len() {
            final_regs[rd as usize] = post as u32;
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
            .join(format!("beak-jolt-d67-inline-{}-{ts}-{nonce}.elf", std::process::id()));
        fs::write(&path, bytes).map_err(|e| format!("write temp elf failed: {e}"))?;
        Ok(Self { path })
    }
}

impl Drop for TempElfFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

fn restore_env_var(key: &str, value: Option<std::ffi::OsString>) {
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}

fn dory_short_trace_hit(input_words_len: usize, unpadded_trace_len: usize) -> Option<BucketHit> {
    let dory_domain_size = unpadded_trace_len.checked_next_power_of_two()? as u64;
    let matrix_size = u128::from(DORY_MATRIX_WIDTH_K).checked_mul(u128::from(dory_domain_size))?;
    let dory_dimension = matrix_size.isqrt().checked_next_power_of_two()? as u64;
    let boundary_k = dory_domain_size.trailing_zeros() as u64;
    let relation_valid = input_words_len > 0
        && input_words_len < 8
        && unpadded_trace_len >= input_words_len
        && unpadded_trace_len as u64 <= dory_domain_size
        && dory_domain_size == 32
        && dory_domain_size.is_power_of_two()
        && dory_dimension >= dory_domain_size;
    if !relation_valid {
        return None;
    }
    Some(BucketHit::semantic(
        semantic::row::TRACE_POWER2_BOUNDARY,
        std::collections::HashMap::from([
            ("obligation_id".to_string(), serde_json::json!("pd2")),
            ("cell_id".to_string(), serde_json::json!("pd2.very_short")),
            ("op_idx".to_string(), serde_json::json!(dory_domain_size)),
            ("step_idx".to_string(), serde_json::json!(dory_domain_size)),
            ("backend".to_string(), serde_json::json!("jolt")),
            ("commit".to_string(), serde_json::json!("d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b")),
            ("trace_source".to_string(), serde_json::json!("prover.dory")),
            ("input_words_len".to_string(), serde_json::json!(input_words_len)),
            ("unpadded_trace_len".to_string(), serde_json::json!(unpadded_trace_len)),
            ("dory_domain_size".to_string(), serde_json::json!(dory_domain_size)),
            ("matrix_width_k".to_string(), serde_json::json!(DORY_MATRIX_WIDTH_K)),
            ("dory_dimension".to_string(), serde_json::json!(dory_dimension)),
            ("boundary_k".to_string(), serde_json::json!(boundary_k)),
            (
                "relation".to_string(),
                serde_json::json!("dory_domain_not_greater_than_matrix_dimension"),
            ),
            ("relation_valid".to_string(), serde_json::json!(true)),
        ]),
    ))
}

fn validated_dory_receipt(
    hits: &[BucketHit],
    receipt: Option<ExecutedExceptionReceipt>,
    non_injected: bool,
) -> Option<ExecutedExceptionReceipt> {
    if !non_injected {
        return None;
    }
    receipt.filter(|receipt| has_exact_executed_exception_relation(hits, Some(receipt)))
}

fn execute_trace(words: &[u32]) -> Result<JoltExecution, String> {
    let elf = build_elf_bytes(words);
    let temp_elf = TempElfFile::new(&elf)?;
    let mut program = host::Program::new("beak-d67-inline");
    program.elf = Some(temp_elf.path.clone());
    let (bytecode, memory_init, _) = program.decode();
    let (trace, _, io_device) = program.trace(&[], &[], &[]);
    let final_regs = final_regs_from_trace(&trace);
    Ok(JoltExecution { elf, bytecode, memory_init, trace, io_device, final_regs })
}

fn prove_and_verify(
    exec: &JoltExecution,
    input_words_len: usize,
) -> Result<(Option<String>, Option<ExecutedExceptionReceipt>), String> {
    let max_trace_length = exec.trace.len().max(256).next_power_of_two();
    let prev_armed = std::env::var_os(DORY_RECEIPT_ARMED_ENV);
    let prev_input_words_len = std::env::var_os(DORY_INPUT_WORDS_LEN_ENV);
    let prev_unpadded_trace_len = std::env::var_os(DORY_UNPADDED_TRACE_LEN_ENV);
    let prev_receipt = std::env::var_os(EXECUTED_EXCEPTION_RECEIPT_ENV);
    std::env::set_var(DORY_RECEIPT_ARMED_ENV, "1");
    std::env::set_var(DORY_INPUT_WORDS_LEN_ENV, input_words_len.to_string());
    std::env::set_var(DORY_UNPADDED_TRACE_LEN_ENV, exec.trace.len().to_string());
    std::env::remove_var(EXECUTED_EXCEPTION_RECEIPT_ENV);
    let prove_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let preprocessing = JoltRV64IMAC::prover_preprocess(
            exec.bytecode.clone(),
            exec.io_device.memory_layout.clone(),
            exec.memory_init.clone(),
            max_trace_length,
        );
        let (proof, io_device, debug_info, _) =
            JoltRV64IMAC::prove(&preprocessing, &exec.elf, &[], &[], &[], None);
        let verifier_preprocessing = JoltVerifierPreprocessing::from(&preprocessing);
        JoltRV64IMAC::verify(&verifier_preprocessing, proof, io_device, None, debug_info)
            .err()
            .map(|e| format!("jolt verify failed: {e}"))
    }));
    let raw_receipt = std::env::var(EXECUTED_EXCEPTION_RECEIPT_ENV).ok();
    restore_env_var(DORY_RECEIPT_ARMED_ENV, prev_armed);
    restore_env_var(DORY_INPUT_WORDS_LEN_ENV, prev_input_words_len);
    restore_env_var(DORY_UNPADDED_TRACE_LEN_ENV, prev_unpadded_trace_len);
    restore_env_var(EXECUTED_EXCEPTION_RECEIPT_ENV, prev_receipt);
    let receipt = raw_receipt
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| format!("invalid Jolt Dory executed receipt: {error}"))?;
    let backend_error = match prove_result {
        Ok(verify_res) => verify_res,
        Err(payload) => Some(format!("jolt panic: {}", panic_payload_to_string(payload))),
    };
    Ok((backend_error, receipt))
}

pub fn run_backend_once(words: &[u32]) -> Result<RunResponse, String> {
    let exec = execute_trace(words)?;
    let mut bucket_hits: Vec<BucketHit> =
        dory_short_trace_hit(words.len(), exec.trace.len()).into_iter().collect();
    let (backend_error, receipt) = prove_and_verify(&exec, words.len())?;
    let executed_exception_receipt = if backend_error.is_some() {
        validated_dory_receipt(&bucket_hits, receipt, true)
    } else {
        None
    };

    Ok(RunResponse {
        final_regs: Some(exec.final_regs),
        micro_op_count: exec.trace.len(),
        bucket_hits: std::mem::take(&mut bucket_hits),
        trace_signals: Vec::new(),
        backend_error,
        injection_applied: false,
        executed_exception_receipt,
    })
}

pub struct JoltBackend {
    max_instructions: usize,
    eval: BackendEval,
}

impl JoltBackend {
    pub fn new(max_instructions: usize) -> Self {
        Self { max_instructions, eval: BackendEval::default() }
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
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval = BackendEval::default();
        let resp = run_backend_once(words)?;
        self.eval.final_regs = resp.final_regs;
        self.eval.micro_op_count = resp.micro_op_count;
        self.eval.bucket_hits = resp.bucket_hits;
        self.eval.trace_signals = resp.trace_signals;
        self.eval.backend_error = resp.backend_error;
        self.eval.semantic_injection_applied = resp.injection_applied;
        self.eval.executed_exception_receipt = resp.executed_exception_receipt;
        resp.final_regs.ok_or_else(|| "jolt d67 backend returned no final_regs".to_string())
    }

    fn collect_eval(&mut self) -> BackendEval {
        self.eval.clone()
    }
}

#[cfg(test)]
mod tests {
    use beak_core::fuzz::benchmark::{
        BenchmarkBackend, ExecutedExceptionEffect, ExecutedExceptionReceipt,
    };
    use beak_core::fuzz::bug_filter::has_exact_executed_exception_relation;
    use serde_json::json;

    use super::{dory_short_trace_hit, validated_dory_receipt};

    fn receipt() -> ExecutedExceptionReceipt {
        ExecutedExceptionReceipt {
            effect: ExecutedExceptionEffect::DoryShortTraceCapacity,
            obligation_id: "pd2".to_string(),
            cell_id: "pd2.very_short".to_string(),
            stage: "dory.commitment.domain_size".to_string(),
            step: 32,
            context: serde_json::Map::from_iter([
                ("backend".to_string(), json!("jolt")),
                ("commit".to_string(), json!("d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b")),
                ("trace_source".to_string(), json!("prover.dory")),
                ("input_words_len".to_string(), json!(1)),
                ("unpadded_trace_len".to_string(), json!(20)),
                ("dory_domain_size".to_string(), json!(32)),
                ("matrix_width_k".to_string(), json!(256)),
                ("dory_dimension".to_string(), json!(128)),
                ("boundary_k".to_string(), json!(5)),
                ("failing_domain_size".to_string(), json!(32)),
                ("relation".to_string(), json!("dory_domain_not_greater_than_matrix_dimension")),
            ]),
        }
    }

    #[test]
    fn dory_hit_is_derived_from_concrete_short_execution_shape() {
        let hit = dory_short_trace_hit(1, 20).unwrap();
        assert_eq!(hit.bucket_id, "sem.row.trace_power2_boundary");
        assert_eq!(hit.details.get("dory_domain_size"), Some(&json!(32)));
        assert_eq!(hit.details.get("dory_dimension"), Some(&json!(128)));
        assert!(has_exact_executed_exception_relation(&[hit], Some(&receipt())));

        assert!(dory_short_trace_hit(8, 20).is_none());
        assert!(dory_short_trace_hit(1, 33).is_none());
    }

    #[test]
    fn ordinary_short_program_family_is_admitted_for_the_dory_boundary_route() {
        let backend = super::JoltBackend::new(256);
        let one_addi = [0x0010_0093];
        let two_addi = [0x0010_0093, 0x0020_0113];

        assert!(backend.is_usable_seed(&one_addi));
        assert!(backend.is_usable_seed(&two_addi));
        assert!(dory_short_trace_hit(one_addi.len(), 20).is_some());
        assert!(dory_short_trace_hit(two_addi.len(), 21).is_some());
    }

    #[test]
    fn dory_receipt_fails_closed_for_wrong_identity_stage_step_context_hit_or_phase() {
        let hit = dory_short_trace_hit(1, 20).unwrap();
        assert!(validated_dory_receipt(&[hit.clone()], Some(receipt()), true).is_some());
        assert!(validated_dory_receipt(&[hit.clone()], Some(receipt()), false).is_none());
        assert!(validated_dory_receipt(&[], Some(receipt()), true).is_none());
        assert!(validated_dory_receipt(&[hit.clone()], None, true).is_none());
        assert!(
            validated_dory_receipt(&[hit.clone(), hit.clone()], Some(receipt()), true).is_none()
        );

        for (key, value) in [
            ("backend", json!("foreign")),
            ("commit", json!("stale")),
            ("trace_source", json!("caller_forged")),
        ] {
            let mut wrong_source_identity = receipt();
            wrong_source_identity.context.insert(key.to_string(), value);
            assert!(validated_dory_receipt(
                std::slice::from_ref(&hit),
                Some(wrong_source_identity),
                true,
            )
            .is_none());
        }

        let mut wrong_identity = receipt();
        wrong_identity.cell_id = "pd2.other".to_string();
        assert!(validated_dory_receipt(&[hit.clone()], Some(wrong_identity), true).is_none());

        let mut wrong_stage = receipt();
        wrong_stage.stage = "dory.other".to_string();
        assert!(validated_dory_receipt(&[hit.clone()], Some(wrong_stage), true).is_none());

        let mut wrong_step = receipt();
        wrong_step.step = 31;
        assert!(validated_dory_receipt(&[hit.clone()], Some(wrong_step), true).is_none());

        let mut wrong_context = receipt();
        wrong_context.context.insert("matrix_width_k".to_string(), json!(255));
        assert!(validated_dory_receipt(&[hit], Some(wrong_context), true).is_none());
    }
}
