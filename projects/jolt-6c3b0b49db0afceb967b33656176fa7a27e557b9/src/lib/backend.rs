use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ark_bn254::Fr;
use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, ExecutedExceptionReceipt, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::Trace;
use common::constants::{
    DEFAULT_MAX_INPUT_SIZE, DEFAULT_MAX_OUTPUT_SIZE, RAM_START_ADDRESS, REGISTER_COUNT,
};
use common::rv_trace::{JoltDevice, MemoryOp, RVTraceRow};
use jolt_core::host;
use jolt_core::jolt::vm::rv32i_vm::{RV32IJoltVM, C, M, PCS, RV32I};
use jolt_core::jolt::vm::{Jolt, JoltTraceStep};

use crate::trace::{bytecode_boundary_hit_from_receipt, JoltTrace};

const LOOP_FOREVER_WORD: u32 = 0x0000_006f;
const BYTECODE_BOUNDARY_RECEIPT_ENV: &str = "BEAK_JOLT_BYTECODE_BOUNDARY_RECEIPT";
const EXECUTED_EXCEPTION_RECEIPT_ENV: &str = "BEAK_JOLT_EXECUTED_EXCEPTION_RECEIPT";
const T0_REG: u32 = 5;
const T1_REG: u32 = 6;
static TEMP_ELF_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct RunResponse {
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<beak_core::trace::BucketHit>,
    pub backend_error: Option<String>,
    pub injection_applied: bool,
    pub executed_exception_receipt: Option<ExecutedExceptionReceipt>,
}

struct JoltExecution {
    final_regs: [u32; 32],
    bytecode: Vec<common::rv_trace::ELFInstruction>,
    memory_init: Vec<(u64, u8)>,
    io_device: JoltDevice,
    trace: Vec<JoltTraceStep<RV32I>>,
    circuit_flags: Vec<Fr>,
}

fn build_program_words(words: &[u32]) -> Vec<u32> {
    let mut out = words.to_vec();
    let layout =
        common::rv_trace::MemoryLayout::new(DEFAULT_MAX_INPUT_SIZE, DEFAULT_MAX_OUTPUT_SIZE);
    let termination_addr = layout.panic as u32;
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
            .join(format!("beak-jolt-6c-inline-{}-{ts}-{nonce}.elf", std::process::id()));
        fs::write(&path, bytes).map_err(|e| format!("write temp elf failed: {e}"))?;
        Ok(Self { path })
    }
}

impl Drop for TempElfFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn remap_memory_address(
    address: u64,
    memory_layout: &common::rv_trace::MemoryLayout,
) -> Option<u64> {
    if address >= memory_layout.input_start {
        Some(address + memory_layout.ram_witness_offset - RAM_START_ADDRESS)
    } else if address < REGISTER_COUNT {
        Some(address)
    } else {
        None
    }
}

fn trace_memory_witness_size(
    trace: &[JoltTraceStep<RV32I>],
    memory_layout: &common::rv_trace::MemoryLayout,
) -> usize {
    let max_index = trace
        .iter()
        .flat_map(|step| step.memory_ops.iter())
        .filter_map(|op| match op {
            MemoryOp::Read(address) | MemoryOp::Write(address, _) => {
                remap_memory_address(*address, memory_layout)
            }
        })
        .max();
    memory_witness_size_from_max_index(max_index)
}

fn memory_witness_size_from_max_index(max_index: Option<u64>) -> usize {
    max_index
        .map(|idx| idx.saturating_add(1).max(8) as usize)
        .unwrap_or(8)
        .next_power_of_two()
}

fn proving_sizes(exec: &JoltExecution) -> (usize, usize, usize) {
    let bytecode_size = exec.bytecode.len().max(8).next_power_of_two();
    let memory_size = trace_memory_witness_size(&exec.trace, &exec.io_device.memory_layout);
    let trace_size = exec.trace.len().max(8).next_power_of_two();
    (bytecode_size, memory_size, trace_size)
}

fn append_bytecode_boundary_receipt(
    hits: &mut Vec<beak_core::trace::BucketHit>,
    raw: Option<&str>,
) {
    if let Some(hit) = raw.and_then(bytecode_boundary_hit_from_receipt) {
        hits.push(hit);
    }
}

fn parse_executed_exception_receipt(
    raw: Option<&str>,
) -> Result<Option<ExecutedExceptionReceipt>, String> {
    raw.map(serde_json::from_str)
        .transpose()
        .map_err(|e| format!("invalid executed exception receipt: {e}"))
}

fn execute_trace(words: &[u32]) -> Result<JoltExecution, String> {
    let elf = build_elf_bytes(words);
    let temp_elf = TempElfFile::new(&elf)?;
    let (rows, _device) =
        tracer::trace(&temp_elf.path, &[], DEFAULT_MAX_INPUT_SIZE, DEFAULT_MAX_OUTPUT_SIZE);
    let final_regs = final_regs_from_rows(&rows);

    let mut program = host::Program::new("beak-inline");
    program.elf = Some(temp_elf.path.clone());
    let (bytecode, memory_init) = program.decode();
    let (io_device, trace, circuit_flags) = program.trace::<Fr>();

    Ok(JoltExecution { final_regs, bytecode, memory_init, io_device, trace, circuit_flags })
}

fn prove_and_verify(exec: JoltExecution) -> Result<Option<String>, String> {
    let (max_bytecode_size, max_memory_size, max_trace_length) = proving_sizes(&exec);
    let prove_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let preprocessing = <RV32IJoltVM as Jolt<Fr, PCS, C, M>>::preprocess(
            exec.bytecode.clone(),
            exec.memory_init.clone(),
            max_bytecode_size,
            max_memory_size,
            max_trace_length,
        );
        let (proof, commitments) = <RV32IJoltVM as Jolt<Fr, PCS, C, M>>::prove(
            exec.io_device,
            exec.trace,
            exec.circuit_flags,
            preprocessing.clone(),
        );
        <RV32IJoltVM as Jolt<Fr, PCS, C, M>>::verify(preprocessing, proof, commitments)
            .err()
            .map(|e| format!("jolt verify failed: {e}"))
    }));

    match prove_result {
        Ok(verify_res) => Ok(verify_res),
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic payload".to_string()
            };
            Ok(Some(format!("jolt panic: {msg}")))
        }
    }
}

#[cfg(test)]
mod memory_witness_sizing_tests {
    use common::constants::{DEFAULT_MAX_INPUT_SIZE, DEFAULT_MAX_OUTPUT_SIZE, RAM_START_ADDRESS};

    use super::{memory_witness_size_from_max_index, remap_memory_address};

    #[test]
    fn remapped_ram_index_is_sized_without_adding_the_offset_twice() {
        let layout = common::rv_trace::MemoryLayout::new(
            DEFAULT_MAX_INPUT_SIZE,
            DEFAULT_MAX_OUTPUT_SIZE,
        );
        let second_ram_byte = RAM_START_ADDRESS + 1;
        let max_index = remap_memory_address(second_ram_byte, &layout).unwrap();

        assert_eq!(max_index, layout.ram_witness_offset + 1);
        assert_eq!(
            memory_witness_size_from_max_index(Some(max_index)),
            (max_index.saturating_add(1).max(8) as usize).next_power_of_two()
        );
    }

    #[test]
    fn empty_and_small_witness_indices_preserve_the_minimum_size() {
        assert_eq!(memory_witness_size_from_max_index(None), 8);
        assert_eq!(memory_witness_size_from_max_index(Some(7)), 8);
        assert_eq!(memory_witness_size_from_max_index(Some(8)), 16);
    }
}

pub fn run_backend_once(
    words: &[u32],
    inject_kind: Option<&str>,
    _inject_step: u64,
) -> Result<RunResponse, String> {
    if inject_kind.is_some() {
        return Err(
            "semantic injection is intentionally unsupported for the vulnerable Jolt snapshot"
                .to_string(),
        );
    }

    let exec = execute_trace(words)?;
    let derived = JoltTrace::from_execution(&exec.bytecode)?;
    let final_regs = exec.final_regs;
    let micro_op_count = exec.trace.len();
    let previous_receipt = std::env::var_os(BYTECODE_BOUNDARY_RECEIPT_ENV);
    let previous_exception_receipt = std::env::var_os(EXECUTED_EXCEPTION_RECEIPT_ENV);
    std::env::remove_var(BYTECODE_BOUNDARY_RECEIPT_ENV);
    std::env::remove_var(EXECUTED_EXCEPTION_RECEIPT_ENV);
    let prove_result = prove_and_verify(exec);
    let boundary_receipt = std::env::var(BYTECODE_BOUNDARY_RECEIPT_ENV).ok();
    let raw_executed_exception_receipt = std::env::var(EXECUTED_EXCEPTION_RECEIPT_ENV).ok();
    if let Some(previous) = previous_receipt {
        std::env::set_var(BYTECODE_BOUNDARY_RECEIPT_ENV, previous);
    } else {
        std::env::remove_var(BYTECODE_BOUNDARY_RECEIPT_ENV);
    }
    if let Some(previous) = previous_exception_receipt {
        std::env::set_var(EXECUTED_EXCEPTION_RECEIPT_ENV, previous);
    } else {
        std::env::remove_var(EXECUTED_EXCEPTION_RECEIPT_ENV);
    }
    let backend_error = prove_result?;
    let executed_exception_receipt =
        parse_executed_exception_receipt(raw_executed_exception_receipt.as_deref())?;
    let mut bucket_hits = derived.bucket_hits().to_vec();
    append_bytecode_boundary_receipt(&mut bucket_hits, boundary_receipt.as_deref());

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count,
        bucket_hits,
        backend_error,
        injection_applied: false,
        executed_exception_receipt,
    })
}

#[cfg(test)]
mod baseline_receipt_routing_tests {
    use beak_core::fuzz::benchmark::BenchmarkBackend;

    use beak_core::fuzz::benchmark::ExecutedExceptionEffect;
    use beak_core::fuzz::bug_filter::has_exact_executed_exception_relation;

    use super::{append_bytecode_boundary_receipt, parse_executed_exception_receipt, JoltBackend};

    const VALID: &str = r#"{"schema_version":1,"relation":"preprocessed_bytecode_end_crosses_allocated_rows_by_one","table_name":"read_write_memory.v_init","population_start":12,"population_end":17,"population_rows":5,"allocated_rows":16,"boundary_k":4,"exact_crossing":true}"#;

    #[test]
    fn routes_only_valid_bytecode_boundary_receipts() {
        let mut hits = Vec::new();
        append_bytecode_boundary_receipt(&mut hits, Some(VALID));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].details["cell_id"], "pd4.just_over");

        let mut missing = Vec::new();
        append_bytecode_boundary_receipt(&mut missing, None);
        assert!(missing.is_empty());

        let mut malformed = Vec::new();
        append_bytecode_boundary_receipt(&mut malformed, Some("{}"));
        assert!(malformed.is_empty());
    }

    #[test]
    fn baseline_snapshot_exposes_no_semantic_injection_route() {
        let mut backend = JoltBackend::new(8);
        assert!(backend.arm_semantic_injection("jolt.semantic.unsupported", 0).is_err());
    }

    #[test]
    fn typed_capacity_exception_receipt_is_strict_and_non_injected() {
        const VALID_EXCEPTION: &str = r#"{"effect":"bytecode_table_capacity_write","obligation_id":"pd4","cell_id":"pd4.just_over","stage":"read_write_memory.v_init.write","step":16,"context":{"backend":"jolt","commit":"6c3b0b49db0afceb967b33656176fa7a27e557b9","trace_source":"jolt.read_write_memory.preprocessed_bytecode","relation":"preprocessed_bytecode_end_crosses_allocated_rows_by_one","relation_valid":true,"failure_observed":true,"failure_manifestation":"capacity_write_out_of_bounds","table_name":"read_write_memory.v_init","population_start":12,"population_end":17,"population_rows":5,"allocated_rows":16,"boundary_k":4,"failing_index":16,"exact_crossing":true}}"#;
        let receipt = parse_executed_exception_receipt(Some(VALID_EXCEPTION)).unwrap().unwrap();
        assert_eq!(receipt.effect, ExecutedExceptionEffect::BytecodeTableCapacityWrite);
        assert_eq!(receipt.step, 16);
        assert_eq!(receipt.context["table_name"], "read_write_memory.v_init");
        assert_eq!(receipt.context["failing_index"], 16);
        let mut hits = Vec::new();
        append_bytecode_boundary_receipt(&mut hits, Some(VALID));
        assert!(has_exact_executed_exception_relation(&hits, Some(&receipt)));

        let mut wrong_table = receipt.clone();
        wrong_table.context.insert(
            "table_name".to_string(),
            serde_json::Value::String("other.v_init".to_string()),
        );
        assert!(!has_exact_executed_exception_relation(&hits, Some(&wrong_table)));

        let mut missing_table = receipt.clone();
        missing_table.context.remove("table_name");
        assert!(!has_exact_executed_exception_relation(&hits, Some(&missing_table)));

        assert!(parse_executed_exception_receipt(None).unwrap().is_none());
        assert!(parse_executed_exception_receipt(Some("not-json")).is_err());
        assert!(parse_executed_exception_receipt(Some(
            r#"{"effect":"bytecode_table_capacity_write","obligation_id":"pd4"}"#,
        ))
        .is_err());
    }
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
        let resp = run_backend_once(words, None, 0)?;
        self.eval.final_regs = resp.final_regs;
        self.eval.micro_op_count = resp.micro_op_count;
        self.eval.bucket_hits = resp.bucket_hits;
        self.eval.backend_error = resp.backend_error;
        self.eval.semantic_injection_applied = resp.injection_applied;
        self.eval.executed_exception_receipt = resp.executed_exception_receipt;
        resp.final_regs.ok_or_else(|| "jolt backend returned no final_regs".to_string())
    }

    fn collect_eval(&mut self) -> BackendEval {
        self.eval.clone()
    }

    fn clear_semantic_injection(&mut self) {}

    fn arm_semantic_injection(&mut self, _kind: &str, _step: u64) -> Result<(), String> {
        Err("semantic injection is intentionally unsupported for the vulnerable Jolt snapshot"
            .to_string())
    }

    fn semantic_injection_candidates(
        &self,
        _hits: &[beak_core::trace::BucketHit],
    ) -> Vec<SemanticInjectionCandidate> {
        Vec::new()
    }
}
