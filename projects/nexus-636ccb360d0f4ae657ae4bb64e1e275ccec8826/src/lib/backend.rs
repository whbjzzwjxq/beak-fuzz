use std::collections::BTreeMap;

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace, TraceSignal};
use nexus_common::cpu::Registers;
use nexus_common::memory::MemoryRecord;
use nexus_common::riscv::register::Register;
use nexus_vm::emulator::{Emulator, HarvardEmulator};
use nexus_vm::error::VMError;
use nexus_vm::trace::UniformTrace;
use serde::{Deserialize, Serialize};

use crate::trace::NexusTrace;

const FLOW_PAYLOAD_INJECT_KIND: &str = "nexus.semantic.memory.store_load_payload_flow";
const WRITE_PAYLOAD_INJECT_KIND: &str = "nexus.semantic.memory.write_payload_consistency";
const KIND_SELECTOR_INJECT_KIND: &str = "nexus.semantic.memory.kind_selector_consistency";
const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";

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
            if step.memory_records.iter().any(|record| {
                matches!(record, MemoryRecord::StoreRecord(_, _) | MemoryRecord::LoadRecord(_, _))
            }) {
                record_site(&mut sites, KIND_SELECTOR_INJECT_KIND, flat_step);
            }
            flat_step = flat_step.saturating_add(1);
        }
    }
    sites
}

fn read_prover_injection_applied() -> bool {
    std::env::var(BEAK_NEXUS_INJECTION_APPLIED_ENV).ok().as_deref() == Some("true")
}

fn arm_prover_injection_env(inject_kind: Option<&str>, inject_step: u64) -> EnvRestore {
    let previous_kind = std::env::var(BEAK_NEXUS_INJECT_KIND_ENV).ok();
    let previous_step = std::env::var(BEAK_NEXUS_INJECT_STEP_ENV).ok();
    let previous_applied = std::env::var(BEAK_NEXUS_INJECTION_APPLIED_ENV).ok();
    std::env::remove_var(BEAK_NEXUS_INJECTION_APPLIED_ENV);
    if let Some(kind) = inject_kind {
        std::env::set_var(BEAK_NEXUS_INJECT_KIND_ENV, kind);
        std::env::set_var(BEAK_NEXUS_INJECT_STEP_ENV, inject_step.to_string());
    } else {
        std::env::remove_var(BEAK_NEXUS_INJECT_KIND_ENV);
        std::env::remove_var(BEAK_NEXUS_INJECT_STEP_ENV);
    }
    EnvRestore { previous_kind, previous_step, previous_applied }
}

struct EnvRestore {
    previous_kind: Option<String>,
    previous_step: Option<String>,
    previous_applied: Option<String>,
}

impl EnvRestore {
    fn restore(self) {
        restore_env(BEAK_NEXUS_INJECT_KIND_ENV, self.previous_kind);
        restore_env(BEAK_NEXUS_INJECT_STEP_ENV, self.previous_step);
        restore_env(BEAK_NEXUS_INJECTION_APPLIED_ENV, self.previous_applied);
    }
}

fn restore_env(key: &str, value: Option<String>) {
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
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

pub fn run_backend_once(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RunResponse, String> {
    let final_regs = execute_final_regs(words)?;

    let program = nexus_vm::riscv::decode_instructions(words);
    let (view, trace) = nexus_vm::trace::k_trace_direct(&program.blocks, 1)
        .map_err(|e| format!("nexus k_trace_direct failed: {e}"))?;

    let observed_injection_sites = collect_observed_injection_sites(&trace);
    let derived = NexusTrace::from_words_and_uniform_trace(words, &trace);
    let env_restore = arm_prover_injection_env(inject_kind, inject_step);
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
    let injection_applied = read_prover_injection_applied();
    env_restore.restore();

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
    pub fn new(max_instructions: usize) -> Self {
        Self {
            max_instructions,
            eval: BackendEval::default(),
            last_observed_injection_sites: BTreeMap::new(),
            pending_injection: None,
        }
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
        hits.iter().filter_map(candidate_from_hit).collect()
    }
}

fn candidate_from_hit(hit: &BucketHit) -> Option<SemanticInjectionCandidate> {
    let (inject_kind, semantic_class) = match hit.bucket_id.as_str() {
        "sem.memory.store_load_payload_flow" => {
            (FLOW_PAYLOAD_INJECT_KIND, "semantic.memory.write_payload_flow_consistency")
        }
        "sem.memory.write_payload_consistency" => {
            (WRITE_PAYLOAD_INJECT_KIND, "semantic.memory.write_payload_flow_consistency")
        }
        "sem.memory.kind_selector_consistency" => {
            (KIND_SELECTOR_INJECT_KIND, "semantic.memory.kind_selector_consistency")
        }
        _ => return None,
    };
    let step = detail_u64(hit, "store_step_idx").or_else(|| detail_u64(hit, "step_idx"))?;
    Some(SemanticInjectionCandidate {
        bucket_id: hit.bucket_id.clone(),
        trigger_signal_id: None,
        semantic_class: semantic_class.to_string(),
        inject_kind: inject_kind.to_string(),
        schedule: InjectionSchedule::Exact(step),
    })
}

fn detail_u64(hit: &BucketHit, key: &str) -> Option<u64> {
    hit.details.get(key).and_then(|value| {
        value.as_u64().or_else(|| value.as_i64().and_then(|n| u64::try_from(n).ok()))
    })
}
