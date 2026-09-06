use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, ExecutedExceptionReceipt, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace, TraceSignal};
use nexus_common::cpu::Registers;
use nexus_common::riscv::register::Register;
use nexus_vm::emulator::{Emulator, HarvardEmulator};
use nexus_vm::error::VMError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::trace::{memory_table_boundary_hit_from_receipt, NexusTrace};

const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";
const MEMORY_TABLE_BOUNDARY_RECEIPT_ENV: &str = "BEAK_NEXUS_MEMORY_TABLE_BOUNDARY_RECEIPT";
const EXECUTED_EXCEPTION_RECEIPT_ENV: &str = "BEAK_NEXUS_EXECUTED_EXCEPTION_RECEIPT";
const MEMORY_TABLE_RELATION: &str =
    "last_access_population_crosses_allocated_rows_at_first_overflow";
const MEMORY_TABLE_NAME: &str = "rw_mem_check.last_access";
const MEMORY_TABLE_TRACE_SOURCE: &str = "prover.rw_mem_check.last_access";
const MEMORY_TABLE_FAILURE_MANIFESTATION: &str = "capacity_write_out_of_bounds";

pub const NEXUS_ORDINARY_MAX_INSTRUCTIONS: usize = 1 << 10;
pub const NEXUS_ORDINARY_MAX_INSTRUCTIONS_ARG: &str = "1024";
pub const NEXUS_ORDINARY_PRECHECK_MAX_STEPS_ARG: &str = "1024";
const CAPACITY_CONTROL_STORE_COUNT: usize = 1 << 7;
const CAPACITY_CROSSING_STORE_COUNT: usize = 1 << 9;
const ORDINARY_CAPACITY_CARRIER_COUNT: usize = 3;
const ORDINARY_CAPACITY_CARRIER_MAX_WORDS: usize = CAPACITY_CROSSING_STORE_COUNT + 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub backend_error: Option<String>,
    pub injection_applied: bool,
    pub executed_exception_receipt: Option<ExecutedExceptionReceipt>,
    pub production_resource: Option<Value>,
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

fn append_memory_table_boundary_receipt(
    hits: &mut Vec<BucketHit>,
    inject_kind: Option<&str>,
    raw_receipt: Option<&str>,
) {
    if inject_kind.is_some() {
        return;
    }
    if let Some(hit) = raw_receipt.and_then(memory_table_boundary_hit_from_receipt) {
        hits.push(hit);
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
    if inject_kind.is_some() {
        return Err(
            "semantic injection is intentionally unsupported for the vulnerable Nexus MemorySize snapshot"
                .to_string(),
        );
    }
    let final_regs = execute_final_regs(words)?;

    let program = nexus_vm::riscv::decode_instructions(words);
    let (view, trace) = nexus_vm::trace::k_trace_direct(&program.blocks, 1)
        .map_err(|e| format!("nexus k_trace_direct failed: {e}"))?;

    let derived = NexusTrace::from_words_and_uniform_trace(words, &trace);
    let env_restore = arm_prover_injection_env(inject_kind, inject_step);
    let previous_boundary_receipt = std::env::var_os(MEMORY_TABLE_BOUNDARY_RECEIPT_ENV);
    let previous_exception_receipt = std::env::var_os(EXECUTED_EXCEPTION_RECEIPT_ENV);
    std::env::remove_var(MEMORY_TABLE_BOUNDARY_RECEIPT_ENV);
    std::env::remove_var(EXECUTED_EXCEPTION_RECEIPT_ENV);
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
    let boundary_receipt = std::env::var(MEMORY_TABLE_BOUNDARY_RECEIPT_ENV).ok();
    let executed_exception_receipt = std::env::var(EXECUTED_EXCEPTION_RECEIPT_ENV)
        .ok()
        .and_then(|raw| serde_json::from_str::<ExecutedExceptionReceipt>(&raw).ok());
    if let Some(previous) = previous_boundary_receipt {
        std::env::set_var(MEMORY_TABLE_BOUNDARY_RECEIPT_ENV, previous);
    } else {
        std::env::remove_var(MEMORY_TABLE_BOUNDARY_RECEIPT_ENV);
    }
    if let Some(previous) = previous_exception_receipt {
        std::env::set_var(EXECUTED_EXCEPTION_RECEIPT_ENV, previous);
    } else {
        std::env::remove_var(EXECUTED_EXCEPTION_RECEIPT_ENV);
    }
    env_restore.restore();
    let mut bucket_hits = derived.bucket_hits().to_vec();
    append_memory_table_boundary_receipt(
        &mut bucket_hits,
        inject_kind,
        boundary_receipt.as_deref(),
    );

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count: derived.step_count(),
        bucket_hits,
        trace_signals: derived.trace_signals().to_vec(),
        backend_error,
        injection_applied,
        executed_exception_receipt,
        production_resource: None,
    })
}

#[cfg(test)]
mod baseline_receipt_routing_tests {
    use beak_core::fuzz::benchmark::BenchmarkBackend;

    use super::{append_memory_table_boundary_receipt, NexusBackend};

    const VALID: &str = r#"{"schema_version":1,"relation":"last_access_population_crosses_allocated_rows_at_first_overflow","table_name":"rw_mem_check.last_access","population_rows":23,"allocated_rows":16,"public_rows":8,"boundary_k":4,"crossing_row_idx":16,"overflow_rows":7,"exact_crossing":true,"failing_table_row_idx":16,"failing_address":64,"last_access_timestamp":16,"last_value":0}"#;

    #[test]
    fn routes_only_valid_non_injected_memory_boundary_receipts() {
        let mut hits = Vec::new();
        append_memory_table_boundary_receipt(&mut hits, None, Some(VALID));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].details["cell_id"], "pd3.mem_table");

        let mut injected = Vec::new();
        append_memory_table_boundary_receipt(
            &mut injected,
            Some("nexus.semantic.any"),
            Some(VALID),
        );
        assert!(injected.is_empty());

        let mut malformed = Vec::new();
        append_memory_table_boundary_receipt(&mut malformed, None, Some("{}"));
        assert!(malformed.is_empty());
    }

    #[test]
    fn baseline_snapshot_exposes_no_semantic_injection_route() {
        let mut backend = NexusBackend::new(8);
        assert!(backend.arm_semantic_injection("nexus.semantic.unsupported", 0).is_err());
    }
}

pub struct NexusBackend {
    max_instructions: usize,
    eval: BackendEval,
}

impl NexusBackend {
    pub fn new(max_instructions: usize) -> Self {
        Self { max_instructions, eval: BackendEval::default() }
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
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval = BackendEval::default();
        let resp = run_backend_once(words, None, 0)?;
        self.eval.final_regs = resp.final_regs;
        self.eval.micro_op_count = resp.micro_op_count;
        self.eval.bucket_hits = resp.bucket_hits;
        self.eval.trace_signals = resp.trace_signals;
        self.eval.backend_error = resp.backend_error;
        self.eval.semantic_injection_applied = resp.injection_applied;
        self.eval.executed_exception_receipt = resp.executed_exception_receipt;
        resp.final_regs.ok_or_else(|| "nexus backend returned no final_regs".to_string())
    }

    fn collect_eval(&mut self) -> BackendEval {
        self.eval.clone()
    }

    fn clear_semantic_injection(&mut self) {}

    fn arm_semantic_injection(&mut self, _kind: &str, _step: u64) -> Result<(), String> {
        Err(
            "semantic injection is intentionally unsupported for the vulnerable Nexus MemorySize snapshot"
                .to_string(),
        )
    }

    fn semantic_injection_candidates(
        &self,
        _hits: &[BucketHit],
    ) -> Vec<SemanticInjectionCandidate> {
        Vec::new()
    }
}

#[cfg(test)]
mod mem_bomb_probe {
    // Regression: a fuzzed non-terminating program (zero-offset taken branch) must fail
    // with a catchable step-budget panic instead of growing emulator trace buffers until
    // the process aborts on an uncatchable allocation failure.
    #[test]
    fn non_terminating_program_fails_at_step_budget() {
        let words: Vec<u32> = [
            0x00c00313u32, 0x00000393, 0x00002697, 0xd5568693, 0x00168703, 0x00070313,
            0xff000393, 0x00731063, 0x00138393, 0x00200293, 0x00539063,
        ]
        .to_vec();
        let prev = std::env::var_os("BEAK_NEXUS_EXECUTE_STEP_BUDGET");
        std::env::set_var("BEAK_NEXUS_EXECUTE_STEP_BUDGET", "10000");
        let result = std::panic::catch_unwind(|| super::execute_final_regs(&words));
        match &prev {
            Some(value) => std::env::set_var("BEAK_NEXUS_EXECUTE_STEP_BUDGET", value),
            None => std::env::remove_var("BEAK_NEXUS_EXECUTE_STEP_BUDGET"),
        }
        let err = result.expect_err("non-terminating program must not execute cleanly");
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(msg.contains("execute step budget"), "unexpected payload: {msg}");
    }
}
