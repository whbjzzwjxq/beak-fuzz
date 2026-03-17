use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic};
use common::constants::RAM_START_ADDRESS;
use common::rv_trace::{CircuitFlags, MemoryConfig, RVTraceRow};
use jolt::jolt_core::jolt::instruction::virtual_advice::ADVICEInstruction;
use jolt::jolt_core::jolt::vm::JoltTraceStep;
use jolt::jolt_core::jolt::vm::rv32i_vm::{C, M};
use jolt::{F, Jolt, PCS, ProofTranscript, RV32I, RV32IJoltVM, host};
use serde::{Deserialize, Serialize};

use crate::trace::JoltTrace;

const UPPER_IMMEDIATE_INJECT_KIND: &str = "jolt.audit_decode.upper_immediate_materialization";
const LOOP_FOREVER_WORD: u32 = 0x0000_006f;
const T0_REG: u32 = 5;
const T1_REG: u32 = 6;
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

struct JoltExecution {
    final_regs: [u32; 32],
    trace: Vec<JoltTraceStep<RV32I>>,
    io_device: common::rv_trace::JoltDevice,
    bytecode: Vec<common::rv_trace::ELFInstruction>,
    memory_init: Vec<(u64, u8)>,
}

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn inject_kind_with_variant(kind: &str, variant: &str) -> String {
    if variant.is_empty() { kind.to_string() } else { format!("{kind}::{variant}") }
}

fn inject_variant_value<'a>(kind: &'a str, key: &str) -> Option<&'a str> {
    let (_, variant) = kind.split_once("::")?;
    for field in variant.split(',') {
        let (field_key, field_value) = field.split_once('=')?;
        if field_key == key {
            return Some(field_value);
        }
    }
    None
}

fn inject_variant_mode(kind: &str) -> Option<&str> {
    inject_variant_value(kind, "mode")
}

fn record_site(sites: &mut BTreeMap<String, Vec<u64>>, kind: &str, step: u64) {
    let steps = sites.entry(kind.to_string()).or_default();
    if steps.last().copied() != Some(step) {
        steps.push(step);
    }
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
    if align == 0 || value % align == 0 { value } else { value + (align - value % align) }
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

fn execute_trace(words: &[u32]) -> Result<JoltExecution, String> {
    let memory_config = MemoryConfig::default();
    let elf = build_elf_bytes(words);
    let (rows, _device) = tracer::trace(elf.clone(), &[], &memory_config);
    let final_regs = final_regs_from_rows(&rows);
    let temp_elf = TempElfFile::new(&elf)?;
    let mut program = host::Program::new("beak-inline");
    program.elf = Some(temp_elf.path.clone());
    let (bytecode, memory_init) = program.decode();
    let (io_device, trace) = program.trace(&[]);
    Ok(JoltExecution { final_regs, trace, io_device, bytecode, memory_init })
}

fn is_real_lui_step(step: &JoltTraceStep<RV32I>) -> bool {
    matches!(step.instruction_lookup, Some(RV32I::VIRTUAL_ADVICE(_)))
        && !step.circuit_flags[CircuitFlags::Virtual as usize]
}

fn collect_observed_injection_sites(trace: &[JoltTraceStep<RV32I>]) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    for (idx, step) in trace.iter().enumerate() {
        if is_real_lui_step(step) {
            record_site(&mut sites, UPPER_IMMEDIATE_INJECT_KIND, idx as u64);
        }
    }
    sites
}

fn apply_injection_to_trace(
    trace: &mut [JoltTraceStep<RV32I>],
    inject_kind: Option<&str>,
    inject_step: u64,
    observed_injection_sites: &BTreeMap<String, Vec<u64>>,
) -> bool {
    let Some(kind) = inject_kind else {
        return false;
    };
    let base_kind = base_inject_kind(kind);
    if base_kind != UPPER_IMMEDIATE_INJECT_KIND {
        return false;
    }

    if inject_step != u64::MAX
        && !observed_injection_sites
            .get(base_kind)
            .map(|steps| steps.contains(&inject_step))
            .unwrap_or(false)
    {
        return false;
    }

    let target_step = if inject_step == u64::MAX { None } else { Some(inject_step) };

    for (idx, step_row) in trace.iter_mut().enumerate() {
        if !is_real_lui_step(step_row) {
            continue;
        }
        let step = idx as u64;
        let step_match = target_step.map(|s| s == step).unwrap_or(true);
        if !step_match {
            continue;
        }

        if matches!(inject_variant_mode(kind), Some("noop_prefix")) {
            return false;
        }
        let current = match step_row.instruction_lookup.as_ref() {
            Some(RV32I::VIRTUAL_ADVICE(advice)) => advice.0 as u32,
            _ => continue,
        };
        let next = match inject_variant_mode(kind) {
            Some("imm_add_page") => current.wrapping_add(0x1000),
            Some("imm_flip_sign") => current ^ (1u32 << 31),
            _ => current ^ 0x1000,
        };
        step_row.instruction_lookup = Some(ADVICEInstruction::<32>(next as u64).into());
        return true;
    }

    false
}

fn proving_sizes(exec: &JoltExecution) -> (usize, usize, usize) {
    let bytecode_size = exec.bytecode.len().max(8).next_power_of_two();
    let memory_size = exec.memory_init.len().max(8).next_power_of_two();
    let trace_size = exec.trace.len().max(8).next_power_of_two();
    (bytecode_size, memory_size, trace_size)
}

fn prove_and_verify(exec: JoltExecution) -> Result<Option<String>, String> {
    let (max_bytecode_size, max_memory_size, max_trace_length) = proving_sizes(&exec);
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
    inject_step: u64,
) -> Result<RunResponse, String> {
    let derived = JoltTrace::from_words(words)?;
    let mut exec = execute_trace(words)?;
    let final_regs = exec.final_regs;
    let micro_op_count = exec.trace.len();
    let observed_injection_sites = collect_observed_injection_sites(&exec.trace);
    let injection_applied = apply_injection_to_trace(
        &mut exec.trace,
        inject_kind,
        inject_step,
        &observed_injection_sites,
    );
    let backend_error = prove_and_verify(exec)?;

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

pub struct JoltBackend {
    max_instructions: usize,
    eval: BackendEval,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pending_injection: Option<WitnessInjectionPlan>,
}

impl JoltBackend {
    pub fn new(max_instructions: usize, _timeout_ms: u64) -> Self {
        Self {
            max_instructions,
            eval: BackendEval::default(),
            last_observed_injection_sites: BTreeMap::new(),
            pending_injection: None,
        }
    }

    fn ordered_steps_around_anchor(steps: &[u64], anchor: u64) -> Vec<u64> {
        let mut ordered = steps.to_vec();
        ordered.sort_by_key(|step| {
            let dist = if *step >= anchor {
                step.saturating_sub(anchor)
            } else {
                anchor.saturating_sub(*step)
            };
            (dist, *step)
        });
        ordered.dedup();
        ordered
    }

    fn step_from_hit(hit: &BucketHit) -> u64 {
        hit.details.get("op_idx").and_then(|v| v.as_u64()).unwrap_or(0)
    }

    fn variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for rank in 0..512u32 {
            specs.push(format!("mode=noop_prefix,rank={rank}"));
        }
        specs.push("mode=imm_xor_mask".to_string());
        specs.push("mode=imm_add_page".to_string());
        specs.push("mode=imm_flip_sign".to_string());
        specs
    }

    fn inject_kinds_for_base(inject_kind: &str) -> Vec<String> {
        match inject_kind {
            UPPER_IMMEDIATE_INJECT_KIND => Self::variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            _ => vec![inject_kind.to_string()],
        }
    }

    fn semantic_candidate_from_hit(&self, hit: &BucketHit) -> Vec<SemanticInjectionCandidate> {
        let anchor = Self::step_from_hit(hit);
        let (semantic_class, inject_kind) =
            if hit.bucket_id == semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION.id {
                (
                    semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION.semantic_class,
                    UPPER_IMMEDIATE_INJECT_KIND,
                )
            } else {
                return Vec::new();
            };

        let schedule = self
            .last_observed_injection_sites
            .get(base_inject_kind(inject_kind))
            .map(|steps| {
                InjectionSchedule::Explicit(Self::ordered_steps_around_anchor(steps, anchor))
            })
            .unwrap_or(InjectionSchedule::AroundAnchor(anchor));

        Self::inject_kinds_for_base(inject_kind)
            .into_iter()
            .map(|kind| SemanticInjectionCandidate {
                bucket_id: hit.bucket_id.clone(),
                trigger_signal_id: None,
                semantic_class: semantic_class.to_string(),
                inject_kind: kind,
                schedule: schedule.clone(),
            })
            .collect()
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
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval = BackendEval::default();
        let resp = run_backend_once(
            words,
            self.pending_injection.as_ref().map(|p| p.kind.as_str()),
            self.pending_injection.as_ref().map(|p| p.step).unwrap_or(0),
        )?;
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
        hits.iter().flat_map(|hit| self.semantic_candidate_from_hit(hit)).collect()
    }
}
