use std::collections::BTreeMap;

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic};
use nexus_common::cpu::Registers;
use nexus_common::memory::{MemoryRecord, MemoryRecords};
use nexus_common::riscv::register::Register;
use nexus_vm::emulator::{Emulator, HarvardEmulator};
use nexus_vm::error::VMError;
use nexus_vm::trace::UniformTrace;
use serde::{Deserialize, Serialize};

use crate::trace::NexusTrace;

const WRITE_PAYLOAD_INJECT_KIND: &str = "nexus.semantic.memory.write_payload_trace";
const FLOW_PAYLOAD_INJECT_KIND: &str = "nexus.semantic.memory.store_load_payload_flow_trace";
const FLOW_RANDOM_TRIALS_PER_MODE: u32 = 128;

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

fn inject_variant_trial(kind: &str) -> Option<u32> {
    inject_variant_value(kind, "trial").and_then(|trial| trial.parse().ok())
}

fn trial_word(trial: u32, salt: u32) -> u32 {
    let mut x = trial
        .wrapping_mul(0x9e37_79b9)
        .wrapping_add(salt.wrapping_mul(0x85eb_ca6b))
        .wrapping_add(0xc2b2_ae35);
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^= x >> 16;
    x
}

fn panic_payload_to_string(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        return format!("panic: {s}");
    }
    if let Some(s) = p.downcast_ref::<String>() {
        return format!("panic: {s}");
    }
    "panic: non-string payload".to_string()
}

fn catch_unwind_nonfatal<T, F>(f: F) -> std::thread::Result<T>
where
    F: FnOnce() -> T + std::panic::UnwindSafe,
{
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_panic_info| {}));
    let res = std::panic::catch_unwind(f);
    std::panic::set_hook(prev_hook);
    res
}

fn record_site(sites: &mut BTreeMap<String, Vec<u64>>, kind: &str, step: u64) {
    let steps = sites.entry(kind.to_string()).or_default();
    if steps.last().copied() != Some(step) {
        steps.push(step);
    }
}

fn raw_opcode(word: u32) -> u32 {
    word & 0x7f
}

fn raw_funct3(word: u32) -> u32 {
    (word >> 12) & 0x7
}

fn load_result_from_value(raw_instruction: u32, value: u32) -> Option<u32> {
    if raw_opcode(raw_instruction) != 0x03 {
        return None;
    }
    match raw_funct3(raw_instruction) {
        0x0 => Some(((value as u8) as i8) as i32 as u32),
        0x1 => Some(((value as u16) as i16) as i32 as u32),
        0x2 => Some(value),
        0x4 => Some(value & 0xff),
        0x5 => Some(value & 0xffff),
        _ => None,
    }
}

fn collect_observed_injection_sites(trace: &UniformTrace) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    let mut flat_step = 0u64;
    for block in &trace.blocks {
        for step in &block.steps {
            if step
                .memory_records
                .iter()
                .any(|record| matches!(record, MemoryRecord::StoreRecord(_, _)))
            {
                record_site(&mut sites, WRITE_PAYLOAD_INJECT_KIND, flat_step);
                record_site(&mut sites, FLOW_PAYLOAD_INJECT_KIND, flat_step);
            }
            flat_step = flat_step.saturating_add(1);
        }
    }
    sites
}

fn low_byte_bias(value: u32, delta: u8) -> u32 {
    (value & !0xff) | (((value & 0xff) as u8).wrapping_add(delta) as u32)
}

fn low_byte_xor(value: u32, mask: u8) -> u32 {
    (value & !0xff) | ((((value & 0xff) as u8) ^ mask) as u32)
}

fn low_byte_blend(value: u32, prev_value: u32, trial: u32) -> u32 {
    let mix_seed = trial_word(trial, 3) as u8;
    let mix = ((prev_value & 0xff) as u8).wrapping_add((mix_seed & 0x1f) << 1);
    (value & !0xff) | mix as u32
}

fn execute_final_regs(words: &[u32]) -> Result<[u32; 32], String> {
    let program = nexus_vm::riscv::decode_instructions(words);
    let mut emulator = HarvardEmulator::from_basic_blocks(&program.blocks);
    match emulator.execute(false) {
        Ok(_) => {}
        Err(VMError::VMExited(_) | VMError::VMOutOfInstructions) => {}
        Err(e) => return Err(format!("nexus execute failed: {e}")),
    }

    let mut out = [0u32; 32];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = emulator.get_executor().cpu.registers.read(Register::from(idx as u8));
    }
    Ok(out)
}

fn apply_injection_to_trace(
    trace: &mut UniformTrace,
    inject_kind: Option<&str>,
    inject_step: u64,
    observed_injection_sites: &BTreeMap<String, Vec<u64>>,
) -> bool {
    let Some(kind) = inject_kind else {
        return false;
    };
    let base_kind = base_inject_kind(kind);
    if base_kind != WRITE_PAYLOAD_INJECT_KIND && base_kind != FLOW_PAYLOAD_INJECT_KIND {
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
    let mut flat_step = 0u64;
    let mut applied_any = false;
    let mut propagated_load: Option<(u32, u8, u32)> = None;

    for block in &mut trace.blocks {
        for step in &mut block.steps {
            if let Some((target_addr, target_size, target_value)) = propagated_load {
                let records = std::mem::take(&mut step.memory_records);
                let mut rewritten = MemoryRecords::new();
                let mut propagated_here = false;
                for record in records {
                    let mut next_record = record;
                    if let MemoryRecord::LoadRecord((size, address, _), timestamp) = record {
                        if address == target_addr && (size as u8) == target_size {
                            next_record =
                                MemoryRecord::LoadRecord((size, address, target_value), timestamp);
                            propagated_here = true;
                        }
                    }
                    rewritten.insert(next_record);
                }
                step.memory_records = rewritten;
                if propagated_here {
                    if let Some(next_result) =
                        load_result_from_value(step.raw_instruction, target_value)
                    {
                        step.result = Some(next_result);
                    }
                }
            }

            let step_match = target_step.map(|s| s == flat_step).unwrap_or(true);
            if !step_match {
                flat_step = flat_step.saturating_add(1);
                continue;
            }

            let records = std::mem::take(&mut step.memory_records);
            let mut rewritten = MemoryRecords::new();
            let mut applied = false;
            for record in records {
                let mut next_record = record;
                if let MemoryRecord::StoreRecord((size, address, value, prev_value), timestamp) =
                    record
                {
                    let trial = inject_variant_trial(kind).unwrap_or(0);
                    let weak_delta = ((trial_word(trial, 0) % 251) + 1) as u8;
                    let weak_mask = 1u8 << (trial_word(trial, 1) % 8);
                    let strong_delta = ((trial_word(trial, 2) % 255) + 1) as u8;
                    let strong_bit = 1u32 << (trial_word(trial, 4) % 8);
                    let strong_prev = low_byte_bias(prev_value, strong_delta);
                    let strong_add = value.wrapping_add(strong_delta as u32);
                    let (next_value, next_prev_value, propagated_value, next_applied) =
                        match (base_kind, inject_variant_mode(kind)) {
                            (FLOW_PAYLOAD_INJECT_KIND, Some("weak_flow_load_bias")) => (
                                value,
                                low_byte_bias(prev_value, weak_delta),
                                low_byte_bias(value, weak_delta),
                                true,
                            ),
                            (FLOW_PAYLOAD_INJECT_KIND, Some("weak_flow_load_xor")) => (
                                value,
                                low_byte_xor(prev_value, weak_mask),
                                low_byte_xor(value, weak_mask),
                                true,
                            ),
                            (FLOW_PAYLOAD_INJECT_KIND, Some("weak_flow_prev_blend")) => (
                                value,
                                low_byte_blend(prev_value, value, trial),
                                low_byte_blend(value, prev_value, trial),
                                true,
                            ),
                            (_, Some("payload_add_delta")) => {
                                (strong_add, prev_value, strong_add, true)
                            }
                            (_, Some("payload_prev_bias")) => {
                                (strong_prev, strong_prev, strong_prev, true)
                            }
                            (_, Some("payload_flip_bit")) => {
                                (value ^ strong_bit, prev_value, value ^ strong_bit, true)
                            }
                            _ => (value, prev_value, value, false),
                        };
                    let next_store = MemoryRecord::StoreRecord(
                        (size, address, next_value, next_prev_value),
                        timestamp,
                    );
                    applied = next_applied;
                    if applied {
                        propagated_load = Some((address, size as u8, propagated_value));
                    }
                    next_record = next_store;
                }
                rewritten.insert(next_record);
            }
            step.memory_records = rewritten;

            if applied {
                applied_any = true;
            }
            flat_step = flat_step.saturating_add(1);
        }
    }

    applied_any
}

pub fn run_backend_once(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RunResponse, String> {
    let final_regs = execute_final_regs(words)?;

    let program = nexus_vm::riscv::decode_instructions(words);
    let (view, mut trace) = nexus_vm::trace::k_trace_direct(&program.blocks, 1)
        .map_err(|e| format!("nexus k_trace_direct failed: {e}"))?;

    let observed_injection_sites = collect_observed_injection_sites(&trace);
    let injection_applied =
        apply_injection_to_trace(&mut trace, inject_kind, inject_step, &observed_injection_sites);

    let derived = NexusTrace::from_words_and_uniform_trace(words, &trace);
    let backend_error = match catch_unwind_nonfatal(std::panic::AssertUnwindSafe(|| {
        match nexus_vm_prover::prove(&trace, &view) {
            Ok(proof) => nexus_vm_prover::verify(proof, &view)
                .err()
                .map(|e| format!("nexus verify failed: {e}")),
            Err(e) => Some(format!("nexus prove failed: {e}")),
        }
    })) {
        Ok(err) => err,
        Err(payload) => Some(panic_payload_to_string(&*payload)),
    };

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count: derived.step_count(),
        bucket_hits: derived.bucket_hits().to_vec(),
        trace_signals: derived.trace_signals().to_vec(),
        backend_error,
        observed_injection_sites,
        injection_applied,
    })
}

pub struct NexusBackend {
    max_instructions: usize,
    eval: BackendEval,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pending_injection: Option<WitnessInjectionPlan>,
}

impl NexusBackend {
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
        for trial in 0..FLOW_RANDOM_TRIALS_PER_MODE {
            specs.push(format!("mode=weak_flow_load_bias,trial={trial}"));
        }
        for trial in 0..FLOW_RANDOM_TRIALS_PER_MODE {
            specs.push(format!("mode=weak_flow_load_xor,trial={trial}"));
        }
        for trial in 0..FLOW_RANDOM_TRIALS_PER_MODE {
            specs.push(format!("mode=weak_flow_prev_blend,trial={trial}"));
        }
        for trial in 0..FLOW_RANDOM_TRIALS_PER_MODE {
            specs.push(format!("mode=payload_flip_bit,trial={trial}"));
        }
        for trial in 0..FLOW_RANDOM_TRIALS_PER_MODE {
            specs.push(format!("mode=payload_add_delta,trial={trial}"));
        }
        for trial in 0..FLOW_RANDOM_TRIALS_PER_MODE {
            specs.push(format!("mode=payload_prev_bias,trial={trial}"));
        }
        specs
    }

    fn inject_kinds_for_base(inject_kind: &str) -> Vec<String> {
        match inject_kind {
            FLOW_PAYLOAD_INJECT_KIND => Self::variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            _ => vec![inject_kind.to_string()],
        }
    }

    fn semantic_candidate_from_hit(&self, hit: &BucketHit) -> Vec<SemanticInjectionCandidate> {
        let anchor = Self::step_from_hit(hit);
        let bucket_id = hit.bucket_id.as_str();
        let (semantic_class, inject_kind) = if bucket_id
            == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id
        {
            (semantic::memory::STORE_LOAD_PAYLOAD_FLOW.semantic_class, FLOW_PAYLOAD_INJECT_KIND)
        } else if bucket_id == semantic::memory::WRITE_PAYLOAD_CONSISTENCY.id {
            (semantic::memory::WRITE_PAYLOAD_CONSISTENCY.semantic_class, WRITE_PAYLOAD_INJECT_KIND)
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

impl BenchmarkBackend for NexusBackend {
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
        resp.final_regs.ok_or_else(|| "nexus backend returned no final_regs".to_string())
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
