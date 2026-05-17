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
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use common::constants::{RAM_START_ADDRESS, REGISTER_COUNT};
use common::rv_trace::{CircuitFlags, MemoryConfig, MemoryLayout, MemoryOp, RVTraceRow};
use jolt::jolt_core::jolt::vm::rv32i_vm::{C, M};
use jolt::jolt_core::jolt::vm::JoltTraceStep;
use jolt::{host, Jolt, ProofTranscript, RV32IJoltVM, F, PCS, RV32I};
use serde::{Deserialize, Serialize};

use crate::trace::JoltTrace;

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

fn execute_trace(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<JoltExecution, String> {
    let memory_config = MemoryConfig::default();
    let elf = build_elf_bytes(words);
    let (rows, _device) = tracer::trace(elf.clone(), &[], &memory_config);
    let final_regs = final_regs_from_rows(&rows);
    let temp_elf = TempElfFile::new(&elf)?;
    let mut program = host::Program::new("beak-inline");
    program.elf = Some(temp_elf.path.clone());
    let (bytecode, memory_init) = program.decode();
    let prev_kind = std::env::var_os(JOLT_INJECT_KIND_ENV);
    let prev_step = std::env::var_os(JOLT_INJECT_STEP_ENV);
    let prev_applied = std::env::var_os(JOLT_INJECT_APPLIED_ENV);
    std::env::remove_var(JOLT_INJECT_APPLIED_ENV);
    if let Some(kind) = inject_kind {
        std::env::set_var(JOLT_INJECT_KIND_ENV, kind);
        std::env::set_var(JOLT_INJECT_STEP_ENV, inject_step.to_string());
    } else {
        std::env::remove_var(JOLT_INJECT_KIND_ENV);
        std::env::remove_var(JOLT_INJECT_STEP_ENV);
    }
    let (io_device, trace) = program.trace(&[]);
    let injection_applied = std::env::var(JOLT_INJECT_APPLIED_ENV).ok().as_deref() == Some("1");
    restore_env_var(JOLT_INJECT_KIND_ENV, prev_kind);
    restore_env_var(JOLT_INJECT_STEP_ENV, prev_step);
    restore_env_var(JOLT_INJECT_APPLIED_ENV, prev_applied);
    Ok(JoltExecution {
        final_regs,
        rows,
        trace,
        io_device,
        bytecode,
        memory_init,
        injection_applied,
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

fn prove_and_verify(exec: JoltExecution) -> Result<(Option<String>, bool), String> {
    let (max_bytecode_size, max_memory_size, max_trace_length) = proving_sizes(&exec);
    let prev_kind = std::env::var_os(JOLT_INJECT_KIND_ENV);
    let prev_step = std::env::var_os(JOLT_INJECT_STEP_ENV);
    let prev_applied = std::env::var_os(JOLT_INJECT_APPLIED_ENV);
    std::env::remove_var(JOLT_INJECT_APPLIED_ENV);
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
    restore_env_var(JOLT_INJECT_KIND_ENV, prev_kind);
    restore_env_var(JOLT_INJECT_STEP_ENV, prev_step);
    restore_env_var(JOLT_INJECT_APPLIED_ENV, prev_applied);

    match prove_result {
        Ok(verify_res) => Ok((verify_res, injection_applied)),
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic payload".to_string()
            };
            Ok((Some(format!("jolt panic: {msg}")), injection_applied))
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
    let (backend_error, proof_injection_applied) = prove_and_verify(exec)?;
    let injection_applied = trace_injection_applied || proof_injection_applied;

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count,
        bucket_hits: derived.bucket_hits().to_vec(),
        trace_signals: derived.trace_signals().to_vec(),
        backend_error,
        observed_injection_sites,
        injection_applied,
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
