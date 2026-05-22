use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use common::constants::RAM_START_ADDRESS;
use jolt::jolt_core::host::Program;
use serde::{Deserialize, Serialize};
use tracer::instruction::Cycle;

use crate::trace::{CycleObservation, JoltTrace};

const ALU_COMPARISON_AUX_INJECT_KIND: &str = "jolt.semantic.alu.comparison_auxiliary_chain";
const ALU_COMPARISON_BOOL_INJECT_KIND: &str = "jolt.semantic.alu.comparison_booleanity";
const ALU_IMM_INJECT_KIND: &str = "jolt.semantic.alu.immediate_limb_consistency";
const ALU_SHIFT_INJECT_KIND: &str = "jolt.semantic.alu.shift_mod32";
const ALU_SUB_INJECT_KIND: &str = "jolt.semantic.alu.subtraction_borrow_chain";
const BRANCH_INJECT_KIND: &str = "jolt.semantic.control.branch_signedness";
const DECODE_FIELD_INJECT_KIND: &str = "jolt.semantic.decode.field_range";
const DECODE_FORMAT_IMM_INJECT_KIND: &str = "jolt.semantic.decode.format_immediate_reassembly";
const DECODE_IMM_SIGN_INJECT_KIND: &str = "jolt.semantic.decode.immediate_sign_extension";
const DECODE_UPPER_IMM_INJECT_KIND: &str = "jolt.semantic.decode.upper_immediate_materialization";
const DEST_INJECT_KIND: &str = "jolt.semantic.exec.dest_binding";
const ENTRYPOINT_INJECT_KIND: &str = "jolt.semantic.control.entrypoint_binding";
const LINK_INJECT_KIND: &str = "jolt.semantic.control.link_register";
const SOURCE_INJECT_KIND: &str = "jolt.semantic.exec.source_operand_binding";
const ZERO_REGISTER_INJECT_KIND: &str = "jolt.semantic.decode.zero_register_immutability";
const JOLT_INJECT_KIND_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_KIND";
const JOLT_INJECT_STEP_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_STEP";
const JOLT_INJECT_APPLIED_ENV: &str = "BEAK_JOLT_WITNESS_INJECTION_APPLIED";
const LOOP_FOREVER_WORD: u32 = 0x0000_006f;
const SUPPORTED_INJECT_KINDS: &[&str] = &[
    ALU_COMPARISON_AUX_INJECT_KIND,
    ALU_COMPARISON_BOOL_INJECT_KIND,
    ALU_IMM_INJECT_KIND,
    ALU_SHIFT_INJECT_KIND,
    ALU_SUB_INJECT_KIND,
    BRANCH_INJECT_KIND,
    DECODE_FIELD_INJECT_KIND,
    DECODE_FORMAT_IMM_INJECT_KIND,
    DECODE_IMM_SIGN_INJECT_KIND,
    DECODE_UPPER_IMM_INJECT_KIND,
    DEST_INJECT_KIND,
    ENTRYPOINT_INJECT_KIND,
    LINK_INJECT_KIND,
    SOURCE_INJECT_KIND,
    ZERO_REGISTER_INJECT_KIND,
];
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
    micro_op_count: usize,
    cycle_observations: Vec<CycleObservation>,
    injection_applied: bool,
}

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn restore_env_var(key: &str, value: Option<std::ffi::OsString>) {
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
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

fn build_program_words(words: &[u32]) -> Vec<u32> {
    let mut out = words.to_vec();
    out.push(LOOP_FOREVER_WORD);
    out
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

fn final_regs_from_cycles(cycles: &[Cycle]) -> [u32; 32] {
    let mut final_regs = [0u32; 32];
    for cycle in cycles {
        let Some((rd, _pre_value, post_value)) = cycle.rd_write() else {
            continue;
        };
        if rd != 0 && usize::from(rd) < final_regs.len() {
            final_regs[usize::from(rd)] = post_value as u32;
        }
    }
    final_regs
}

fn cycle_observations(cycles: &[Cycle]) -> Vec<CycleObservation> {
    cycles
        .iter()
        .enumerate()
        .map(|(step_idx, cycle)| {
            let instruction = cycle.instruction();
            let pc = instruction.source_instruction().row().address as u64;
            CycleObservation {
                step_idx: step_idx as u64,
                pc,
                rs1: cycle.rs1_read(),
                rs2: cycle.rs2_read(),
                rd: cycle.rd_write(),
            }
        })
        .collect()
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
            .join(format!("beak-jolt-5fb4-inline-{}-{ts}-{nonce}.elf", std::process::id()));
        fs::write(&path, bytes).map_err(|e| format!("write temp elf failed: {e}"))?;
        Ok(Self { path })
    }
}

impl Drop for TempElfFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn execute_trace(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<JoltExecution, String> {
    let elf = build_elf_bytes(words);
    let temp_elf = TempElfFile::new(&elf)?;
    let mut program = Program::new("beak-inline");
    program.elf = Some(temp_elf.path.clone());

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

    let trace_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (_lazy_trace, trace, _memory, _jolt_device) = program.trace(&[], &[], &[]);
        let injection_applied = std::env::var(JOLT_INJECT_APPLIED_ENV).ok().as_deref() == Some("1");
        JoltExecution {
            final_regs: final_regs_from_cycles(&trace),
            micro_op_count: trace.len(),
            cycle_observations: cycle_observations(&trace),
            injection_applied,
        }
    }));

    restore_env_var(JOLT_INJECT_KIND_ENV, prev_kind);
    restore_env_var(JOLT_INJECT_STEP_ENV, prev_step);
    restore_env_var(JOLT_INJECT_APPLIED_ENV, prev_applied);

    match trace_result {
        Ok(exec) => Ok(exec),
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic payload".to_string()
            };
            Err(format!("jolt trace panic: {msg}"))
        }
    }
}

fn inject_kind_for_hit(hit: &BucketHit) -> Option<&'static str> {
    let obligation_id = hit.details.get("obligation_id")?.as_str()?;
    match (obligation_id, hit.bucket_id.as_str()) {
        ("rf1", id) if id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id => {
            Some(ZERO_REGISTER_INJECT_KIND)
        }
        ("rf2", id) if id == semantic::exec::SOURCE_OPERAND_BINDING.id => Some(SOURCE_INJECT_KIND),
        ("rf3", id) if id == semantic::exec::DEST_BINDING.id => Some(DEST_INJECT_KIND),
        ("id1", id) if id == semantic::decode::FIELD_RANGE.id => Some(DECODE_FIELD_INJECT_KIND),
        ("id2", id) if id == semantic::decode::IMMEDIATE_SIGN_EXTENSION.id => {
            Some(DECODE_IMM_SIGN_INJECT_KIND)
        }
        ("id3", id) if id == semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION.id => {
            Some(DECODE_UPPER_IMM_INJECT_KIND)
        }
        ("id5", id) if id == semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.id => {
            Some(DECODE_FORMAT_IMM_INJECT_KIND)
        }
        ("al1", id) if id == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id => {
            Some(ALU_IMM_INJECT_KIND)
        }
        ("al2", id) if id == semantic::alu::SHIFT_MOD32.id => Some(ALU_SHIFT_INJECT_KIND),
        ("al3", id) if id == semantic::alu::COMPARISON_BOOLEANITY.id => {
            Some(ALU_COMPARISON_BOOL_INJECT_KIND)
        }
        ("al4", id) if id == semantic::alu::SUBTRACTION_BORROW_CHAIN.id => {
            Some(ALU_SUB_INJECT_KIND)
        }
        ("al5", id) if id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id => {
            Some(ALU_COMPARISON_AUX_INJECT_KIND)
        }
        ("cf1", id) if id == semantic::exec::CONTROL_FLOW_BINDING.id => Some(BRANCH_INJECT_KIND),
        ("cf2", id) if id == semantic::exec::CONTROL_FLOW_BINDING.id => Some(LINK_INJECT_KIND),
        ("cf4", id) if id == semantic::control::ENTRYPOINT_BINDING.id => {
            Some(ENTRYPOINT_INJECT_KIND)
        }
        _ => None,
    }
}

fn semantic_class_for_hit(hit: &BucketHit) -> Option<&'static str> {
    semantic::by_id(&hit.bucket_id).map(|bucket| bucket.semantic_class)
}

fn anchor_for_hit(hit: &BucketHit) -> u64 {
    hit.details
        .get("step_idx")
        .and_then(|v| v.as_u64())
        .or_else(|| hit.details.get("op_idx").and_then(|v| v.as_u64()))
        .unwrap_or(0)
}

fn observed_injection_sites(hits: &[BucketHit]) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::new();
    for hit in hits {
        let Some(kind) = inject_kind_for_hit(hit) else {
            continue;
        };
        let anchor = anchor_for_hit(hit);
        sites.entry(kind.to_string()).or_insert_with(Vec::new).push(anchor);
    }
    sites
}

pub fn run_backend_once(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RunResponse, String> {
    let exec = execute_trace(words, inject_kind, inject_step)?;
    let derived = JoltTrace::from_execution(words, &exec.cycle_observations)?;
    let bucket_hits = derived.bucket_hits().to_vec();
    let trace_signals = derived.trace_signals().to_vec();
    let observed_injection_sites = observed_injection_sites(&bucket_hits);
    Ok(RunResponse {
        final_regs: Some(exec.final_regs),
        micro_op_count: exec.micro_op_count,
        bucket_hits,
        trace_signals,
        backend_error: None,
        observed_injection_sites,
        injection_applied: exec.injection_applied,
    })
}

pub struct JoltBackend {
    max_instructions: usize,
    eval: BackendEval,
    pending_injection: Option<WitnessInjectionPlan>,
}

impl JoltBackend {
    pub fn new(max_instructions: usize) -> Self {
        Self { max_instructions, eval: BackendEval::default(), pending_injection: None }
    }

    fn candidate_for_hit(&self, hit: &BucketHit) -> Option<SemanticInjectionCandidate> {
        let inject_kind = inject_kind_for_hit(hit)?;
        let semantic_class = semantic_class_for_hit(hit)?;
        let anchor = anchor_for_hit(hit);
        Some(SemanticInjectionCandidate {
            bucket_id: hit.bucket_id.clone(),
            trigger_signal_id: None,
            semantic_class: semantic_class.to_string(),
            inject_kind: inject_kind.to_string(),
            schedule: InjectionSchedule::Exact(anchor),
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
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval = BackendEval::default();
        let resp = run_backend_once(
            words,
            self.pending_injection.as_ref().map(|p| p.kind.as_str()),
            self.pending_injection.as_ref().map(|p| p.step).unwrap_or(0),
        )?;
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
        if !SUPPORTED_INJECT_KINDS.contains(&base_inject_kind(kind)) {
            return Err(format!("unsupported Jolt latest inject kind: {kind}"));
        }
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
