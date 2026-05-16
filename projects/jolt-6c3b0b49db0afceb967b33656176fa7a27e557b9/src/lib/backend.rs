use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ark_bn254::Fr;
use beak_core::fuzz::benchmark::{BackendEval, BenchmarkBackend, SemanticInjectionCandidate};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::Trace;
use common::constants::{
    DEFAULT_MAX_INPUT_SIZE, DEFAULT_MAX_OUTPUT_SIZE, RAM_START_ADDRESS, REGISTER_COUNT,
};
use common::rv_trace::{JoltDevice, MemoryOp, RVTraceRow};
use jolt_core::host;
use jolt_core::jolt::vm::rv32i_vm::{RV32IJoltVM, C, M, PCS, RV32I};
use jolt_core::jolt::vm::{Jolt, JoltTraceStep};

use crate::trace::JoltTrace;

const LOOP_FOREVER_WORD: u32 = 0x0000_006f;
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
    trace
        .iter()
        .flat_map(|step| step.memory_ops.iter())
        .filter_map(|op| match op {
            MemoryOp::Read(address) | MemoryOp::Write(address, _) => {
                remap_memory_address(*address, memory_layout)
            }
        })
        .max()
        .map(|idx| memory_layout.ram_witness_offset.saturating_add(idx).max(8) as usize)
        .unwrap_or(8)
        .next_power_of_two()
}

fn proving_sizes(exec: &JoltExecution) -> (usize, usize, usize) {
    let bytecode_size = exec.bytecode.len().max(8).next_power_of_two();
    let memory_size = trace_memory_witness_size(&exec.trace, &exec.io_device.memory_layout);
    let trace_size = exec.trace.len().max(8).next_power_of_two();
    (bytecode_size, memory_size, trace_size)
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
    let backend_error = prove_and_verify(exec)?;

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count,
        bucket_hits: derived.bucket_hits().to_vec(),
        backend_error,
        injection_applied: false,
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
        let resp = run_backend_once(words, None, 0)?;
        self.eval.final_regs = resp.final_regs;
        self.eval.micro_op_count = resp.micro_op_count;
        self.eval.bucket_hits = resp.bucket_hits;
        self.eval.backend_error = resp.backend_error;
        self.eval.semantic_injection_applied = resp.injection_applied;
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
