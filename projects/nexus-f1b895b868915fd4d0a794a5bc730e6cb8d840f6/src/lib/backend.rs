use std::collections::BTreeMap;

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, ExecutedExceptionEffect, ExecutedExceptionReceipt,
    SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace, TraceSignal};
use nexus_common::cpu::Registers;
use nexus_common::memory::MemoryRecord;
use nexus_common::riscv::register::Register;
use nexus_vm::emulator::{Emulator, HarvardEmulator};
use nexus_vm::error::VMErrorKind;
use nexus_vm::trace::UniformTrace;
use serde::{Deserialize, Serialize};

use crate::trace::NexusTrace;

const ZERO_REG_INJECT_KIND: &str = "nexus.semantic.decode.zero_register_immutability";
const OPERAND_ROUTING_INJECT_KIND: &str = "nexus.semantic.decode.operand_index_routing";
const DEST_BINDING_INJECT_KIND: &str = "nexus.semantic.exec.dest_binding";
const FIELD_RANGE_INJECT_KIND: &str = "nexus.semantic.decode.field_range";
const IMM_SIGNEXT_INJECT_KIND: &str = "nexus.semantic.decode.immediate_sign_extension";
const UPPER_IMM_INJECT_KIND: &str = "nexus.semantic.decode.upper_immediate_materialization";
const FORMAT_IMM_INJECT_KIND: &str = "nexus.semantic.decode.format_immediate_reassembly";
const OP_SELECTOR_INJECT_KIND: &str = "nexus.semantic.exec.op_selector_binding";
const ALU_IMM_INJECT_KIND: &str = "nexus.semantic.alu.immediate_limb_consistency";
const SHIFT_INJECT_KIND: &str = "nexus.semantic.alu.shift_mod32";
const CMP_BOOL_INJECT_KIND: &str = "nexus.semantic.alu.comparison_booleanity";
const SUB_BORROW_INJECT_KIND: &str = "nexus.semantic.alu.subtraction_borrow_chain";
const CMP_AUX_INJECT_KIND: &str = "nexus.semantic.alu.comparison_auxiliary_chain";
const CONTROL_FLOW_INJECT_KIND: &str = "nexus.semantic.exec.control_flow_binding";
const ENTRYPOINT_INJECT_KIND: &str = "nexus.semantic.control.entrypoint_binding";
const ECALL_WORD_INJECT_KIND: &str = "nexus.semantic.control.ecall_word_validity";
const TIME_BOUNDARY_INJECT_KIND: &str = "nexus.semantic.time.boundary_origin_consistency";
const ADDRESS_ALIGNMENT_INJECT_KIND: &str = "nexus.semantic.memory.address_alignment_consistency";
const LOAD_VALUE_INJECT_KIND: &str = "nexus.semantic.memory.load_value_binding";
const ADDRESS_POINTER_INJECT_KIND: &str = "nexus.semantic.memory.address_pointer_consistency";
const ADDRESS_PROGRESSION_INJECT_KIND: &str =
    "nexus.semantic.memory.address_progression_consistency";
const TIME_MONOTONIC_INJECT_KIND: &str = "nexus.semantic.time.monotonic_access_ordering";
const FLOW_PAYLOAD_INJECT_KIND: &str = "nexus.semantic.memory.store_load_payload_flow";
const WRITE_PAYLOAD_INJECT_KIND: &str = "nexus.semantic.memory.write_payload_consistency";
const KIND_SELECTOR_INJECT_KIND: &str = "nexus.semantic.memory.kind_selector_consistency";
const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";
const EXECUTED_EXCEPTION_RECEIPT_ENV: &str = "BEAK_NEXUS_EXECUTED_EXCEPTION_RECEIPT";
const BEAK_NEXUS_STORE_LOAD_FLOW_ENV: [&str; 3] = [
    "BEAK_NEXUS_STORE_LOAD_FLOW_ADDR",
    "BEAK_NEXUS_STORE_LOAD_FLOW_CLK",
    "BEAK_NEXUS_STORE_LOAD_FLOW_BYTE",
];

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
    pub executed_exception_receipt: Option<ExecutedExceptionReceipt>,
}

fn receipt_context_u64(receipt: &ExecutedExceptionReceipt, key: &str) -> Option<u64> {
    receipt.context.get(key).and_then(serde_json::Value::as_u64)
}

fn nexus_mul_carry_1(lhs: u32, rhs: u32) -> u32 {
    let b = lhs.to_le_bytes().map(u32::from);
    let c = rhs.to_le_bytes().map(u32::from);
    let z = std::array::from_fn::<_, 4, _>(|idx| b[idx] * c[idx]);
    let p1 = (c[0] + c[1]) * (b[0] + b[1]) - z[0] - z[1];
    let p2_prime = (c[0] + c[2]) * (b[0] + b[2]) - z[0] - z[2];
    let p3_prime = (c[0] + c[3]) * (b[0] + b[3]) - z[0] - z[3];
    let p3_prime_prime = (c[1] + c[2]) * (b[1] + b[2]) - z[1] - z[2];
    let carry_0 = (z[0] + ((p1 & 0xff) << 8)) >> 16;
    let a23 = z[1]
        + ((p1 >> 8) & 0xff)
        + p2_prime
        + carry_0
        + (((p3_prime & 0xff) + (p3_prime_prime & 0xff) + (p1 >> 16)) << 8);
    a23 >> 16
}

fn validated_mul_carry_exception_receipt(
    raw: Option<&str>,
    hits: &[BucketHit],
    inject_kind: Option<&str>,
    backend_error: Option<&str>,
) -> Option<ExecutedExceptionReceipt> {
    if inject_kind.is_some() || backend_error.is_none() {
        return None;
    }
    let receipt = serde_json::from_str::<ExecutedExceptionReceipt>(raw?).ok()?;
    if receipt.effect != ExecutedExceptionEffect::MultiplicationCarryBound
        || receipt.obligation_id != "md4"
        || receipt.cell_id != "md4.mul_overflow"
        || receipt.stage != "mul.witness.carry_1_bound"
    {
        return None;
    }

    // Fill execution-identity fields the M-chip hook cannot see (pc/opcode/
    // mnemonic/rd values) from the exact executed hit, and stamp the observed
    // failure manifestation: the hook only runs at the carry bound assert.
    let mut receipt = receipt;
    if let Some(hit) = hits.iter().find(|hit| {
        hit.bucket_id == "sem.arithmetic.product_decomposition"
            && detail_str(hit, "cell_id") == Some("md4.mul_overflow")
            && detail_u64(hit, "op_idx") == Some(receipt.step)
    }) {
        for key in [
            "op_idx",
            "step_idx",
            "pc",
            "opcode",
            "mnemonic",
            "expected_rd_val",
            "observed_rd_val",
            "relation",
            "relation_valid",
        ] {
            if !receipt.context.contains_key(key) {
                if let Some(value) = hit.details.get(key) {
                    receipt.context.insert(key.to_string(), value.clone());
                }
            }
        }
    }
    receipt
        .context
        .insert("failure_observed".to_string(), serde_json::json!(true));
    receipt.context.insert(
        "failure_manifestation".to_string(),
        serde_json::json!("carry_bound_assertion"),
    );
    let lhs = receipt_context_u64(&receipt, "rs1_val")?;
    let rhs = receipt_context_u64(&receipt, "rs2_val")?;
    let product_hi = receipt_context_u64(&receipt, "product_hi")?;
    let product_lo = receipt_context_u64(&receipt, "product_lo")?;
    let carry_1 = receipt_context_u64(&receipt, "carry_1")?;
    let carry_bound_exclusive = receipt_context_u64(&receipt, "carry_bound_exclusive")?;
    let product = u128::from(lhs).checked_mul(u128::from(rhs))?;
    if lhs > u64::from(u32::MAX)
        || rhs > u64::from(u32::MAX)
        || product_hi != ((product >> 32) as u32 as u64)
        || product_lo != (product as u32 as u64)
        || product_hi == 0
        || carry_bound_exclusive != 4
        || carry_1 < carry_bound_exclusive
        || nexus_mul_carry_1(lhs as u32, rhs as u32) != carry_1 as u32
    {
        return None;
    }

    hits.iter()
        .any(|hit| {
            hit.bucket_id == "sem.arithmetic.product_decomposition"
                && detail_str(hit, "obligation_id") == Some("md4")
                && detail_str(hit, "cell_id") == Some("md4.mul_overflow")
                && detail_str(hit, "mnemonic") == Some("mul")
                && detail_str(hit, "relation") == Some("product_hi_lo_matches_operands")
                && hit.details.get("relation_valid").and_then(serde_json::Value::as_bool)
                    == Some(true)
                && detail_u64(hit, "op_idx") == Some(receipt.step)
                && detail_u64(hit, "rs1_val") == Some(lhs)
                && detail_u64(hit, "rs2_val") == Some(rhs)
                && detail_u64(hit, "product_hi") == Some(product_hi)
                && detail_u64(hit, "product_lo") == Some(product_lo)
                && detail_u64(hit, "expected_rd_val") == Some(product_lo)
                && detail_u64(hit, "observed_rd_val") == Some(product_lo)
        })
        .then_some(receipt)
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

fn is_i_alu_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai"
    )
}

fn is_shift_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sll" | "slli" | "srl" | "srli" | "sra" | "srai")
}

fn is_comparison_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "slt" | "slti" | "sltu" | "sltiu")
}

fn is_supported_sub_borrow_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sub" | "slt" | "slti" | "sltu" | "sltiu")
}

fn is_format_imm_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sb" | "sh" | "sw" | "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "jal")
}

fn collect_observed_injection_sites(trace: &UniformTrace) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    let mut flat_step = 0u64;
    for block in &trace.blocks {
        for step in &block.steps {
            if let Some(decoded) = RV32IMInstruction::decode_with_pc(step.raw_instruction, step.pc)
            {
                let mnemonic = decoded.mnemonic.as_str();
                record_site(&mut sites, FIELD_RANGE_INJECT_KIND, flat_step);
                record_site(&mut sites, OP_SELECTOR_INJECT_KIND, flat_step);
                record_site(&mut sites, OPERAND_ROUTING_INJECT_KIND, flat_step);
                if decoded.rd.is_some() {
                    record_site(&mut sites, ZERO_REG_INJECT_KIND, flat_step);
                    record_site(&mut sites, DEST_BINDING_INJECT_KIND, flat_step);
                }
                if decoded.imm.is_some() {
                    record_site(&mut sites, IMM_SIGNEXT_INJECT_KIND, flat_step);
                }
                if matches!(mnemonic, "lui" | "auipc") {
                    record_site(&mut sites, UPPER_IMM_INJECT_KIND, flat_step);
                }
                if is_format_imm_mnemonic(mnemonic) {
                    record_site(&mut sites, FORMAT_IMM_INJECT_KIND, flat_step);
                }
                if is_i_alu_mnemonic(mnemonic) {
                    record_site(&mut sites, ALU_IMM_INJECT_KIND, flat_step);
                }
                if is_shift_mnemonic(mnemonic) {
                    record_site(&mut sites, SHIFT_INJECT_KIND, flat_step);
                }
                if is_comparison_mnemonic(mnemonic) {
                    record_site(&mut sites, CMP_BOOL_INJECT_KIND, flat_step);
                    record_site(&mut sites, CMP_AUX_INJECT_KIND, flat_step);
                }
                if is_supported_sub_borrow_mnemonic(mnemonic) {
                    record_site(&mut sites, SUB_BORROW_INJECT_KIND, flat_step);
                }
                record_site(&mut sites, CONTROL_FLOW_INJECT_KIND, flat_step);
                if mnemonic == "ecall" {
                    record_site(&mut sites, ECALL_WORD_INJECT_KIND, flat_step);
                }
                if flat_step == 0 {
                    record_site(&mut sites, ENTRYPOINT_INJECT_KIND, flat_step);
                    record_site(&mut sites, TIME_BOUNDARY_INJECT_KIND, flat_step);
                }
            }
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
                record_site(&mut sites, ADDRESS_ALIGNMENT_INJECT_KIND, flat_step);
                record_site(&mut sites, ADDRESS_POINTER_INJECT_KIND, flat_step);
                record_site(&mut sites, ADDRESS_PROGRESSION_INJECT_KIND, flat_step);
                record_site(&mut sites, TIME_MONOTONIC_INJECT_KIND, flat_step);
            }
            if step
                .memory_records
                .iter()
                .any(|record| matches!(record, MemoryRecord::LoadRecord(_, _)))
            {
                record_site(&mut sites, LOAD_VALUE_INJECT_KIND, flat_step);
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
    let previous_flow = BEAK_NEXUS_STORE_LOAD_FLOW_ENV.map(|key| std::env::var(key).ok());
    std::env::remove_var(BEAK_NEXUS_INJECTION_APPLIED_ENV);
    for key in BEAK_NEXUS_STORE_LOAD_FLOW_ENV {
        std::env::remove_var(key);
    }
    if let Some(kind) = inject_kind {
        std::env::set_var(BEAK_NEXUS_INJECT_KIND_ENV, kind);
        std::env::set_var(BEAK_NEXUS_INJECT_STEP_ENV, inject_step.to_string());
    } else {
        std::env::remove_var(BEAK_NEXUS_INJECT_KIND_ENV);
        std::env::remove_var(BEAK_NEXUS_INJECT_STEP_ENV);
    }
    EnvRestore { previous_kind, previous_step, previous_applied, previous_flow }
}

struct EnvRestore {
    previous_kind: Option<String>,
    previous_step: Option<String>,
    previous_applied: Option<String>,
    previous_flow: [Option<String>; 3],
}

impl EnvRestore {
    fn restore(self) {
        restore_env(BEAK_NEXUS_INJECT_KIND_ENV, self.previous_kind);
        restore_env(BEAK_NEXUS_INJECT_STEP_ENV, self.previous_step);
        restore_env(BEAK_NEXUS_INJECTION_APPLIED_ENV, self.previous_applied);
        for (key, value) in BEAK_NEXUS_STORE_LOAD_FLOW_ENV.into_iter().zip(self.previous_flow) {
            restore_env(key, value);
        }
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
        Err(e)
            if matches!(e.source, VMErrorKind::VMExited(_) | VMErrorKind::VMOutOfInstructions) => {}
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
            "semantic injection is intentionally unsupported for the vulnerable Nexus MulCarry snapshot"
                .to_string(),
        );
    }
    let final_regs = execute_final_regs(words)?;

    let program = nexus_vm::riscv::decode_instructions(words);
    let (view, trace) = nexus_vm::trace::k_trace_direct(&program.blocks, 1)
        .map_err(|e| format!("nexus k_trace_direct failed: {e}"))?;

    let observed_injection_sites = collect_observed_injection_sites(&trace);
    let derived = NexusTrace::from_words_and_uniform_trace(words, &trace);
    let env_restore = arm_prover_injection_env(inject_kind, inject_step);
    let previous_exception_receipt = std::env::var_os(EXECUTED_EXCEPTION_RECEIPT_ENV);
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
    let raw_exception_receipt = std::env::var(EXECUTED_EXCEPTION_RECEIPT_ENV).ok();
    if let Some(previous) = previous_exception_receipt {
        std::env::set_var(EXECUTED_EXCEPTION_RECEIPT_ENV, previous);
    } else {
        std::env::remove_var(EXECUTED_EXCEPTION_RECEIPT_ENV);
    }
    env_restore.restore();
    let executed_exception_receipt = validated_mul_carry_exception_receipt(
        raw_exception_receipt.as_deref(),
        derived.bucket_hits(),
        inject_kind,
        backend_error.as_deref(),
    );

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count: derived.step_count(),
        bucket_hits: derived.bucket_hits().to_vec(),
        trace_signals: derived.trace_signals().to_vec(),
        backend_error,
        observed_injection_sites,
        injection_applied,
        executed_exception_receipt,
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
        self.eval.executed_exception_receipt = resp.executed_exception_receipt;
        resp.final_regs.ok_or_else(|| "nexus backend returned no final_regs".to_string())
    }

    fn collect_eval(&mut self) -> BackendEval {
        self.eval.clone()
    }

    fn clear_semantic_injection(&mut self) {
        self.pending_injection = None;
    }

    fn arm_semantic_injection(&mut self, _kind: &str, _step: u64) -> Result<(), String> {
        Err(
            "semantic injection is intentionally unsupported for the vulnerable Nexus MulCarry snapshot"
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
mod baseline_routing_tests {
    use std::collections::HashMap;

    use beak_core::fuzz::benchmark::BenchmarkBackend;
    use beak_core::fuzz::bug_filter::has_exact_executed_exception_relation;
    use beak_core::trace::BucketHit;
    use serde_json::{json, Value};

    use super::{nexus_mul_carry_1, validated_mul_carry_exception_receipt, NexusBackend};

    const FAIL_LHS: u32 = 0x55e4_fcfd;
    const FAIL_RHS: u32 = 0x2ff7_dde6;
    const STEP: u64 = 7;

    fn exact_hit(mnemonic: &str, cell_id: &str, lhs: u32, rhs: u32) -> BucketHit {
        let product = u64::from(lhs) * u64::from(rhs);
        let product_hi = (product >> 32) as u32;
        let product_lo = product as u32;
        let observed = if mnemonic == "mul" { product_lo } else { product_hi };
        let details: HashMap<String, Value> = [
            ("obligation_id", json!("md4")),
            ("cell_id", json!(cell_id)),
            ("mnemonic", json!(mnemonic)),
            ("op_idx", json!(STEP)),
            ("step_idx", json!(STEP)),
            ("rs1_val", json!(lhs)),
            ("rs2_val", json!(rhs)),
            ("product_hi", json!(product_hi)),
            ("product_lo", json!(product_lo)),
            ("expected_rd_val", json!(observed)),
            ("observed_rd_val", json!(observed)),
            ("relation", json!("product_hi_lo_matches_operands")),
            ("relation_valid", json!(true)),
            ("backend", json!("nexus")),
            ("commit", json!("f1b895b868915fd4d0a794a5bc730e6cb8d840f6")),
            ("trace_source", json!("instruction")),
            ("pc", json!(0x88 + STEP * 4)),
            ("opcode", json!("0x02c58533")),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect();
        BucketHit::semantic_id("sem.arithmetic.product_decomposition", details)
    }

    fn receipt(lhs: u32, rhs: u32, carry_1: u32) -> String {
        let product = u64::from(lhs) * u64::from(rhs);
        json!({
            "effect": "multiplication_carry_bound",
            "obligation_id": "md4",
            "cell_id": "md4.mul_overflow",
            "stage": "mul.witness.carry_1_bound",
            "step": STEP,
            "context": {
                "backend": "nexus",
                "commit": "f1b895b868915fd4d0a794a5bc730e6cb8d840f6",
                "trace_source": "instruction",
                "rs1_val": lhs,
                "rs2_val": rhs,
                "product_hi": (product >> 32) as u32,
                "product_lo": product as u32,
                "carry_1": carry_1,
                "carry_bound_exclusive": 4,
            }
        })
        .to_string()
    }

    #[test]
    fn baseline_snapshot_exposes_no_semantic_injection_route() {
        let mut backend = NexusBackend::new(8);
        assert!(backend.arm_semantic_injection("nexus.semantic.unsupported", 0).is_err());
    }

    #[test]
    fn accepts_exact_executed_mul_carry_failure() {
        let carry_1 = nexus_mul_carry_1(FAIL_LHS, FAIL_RHS);
        assert_eq!(carry_1, 4);
        let hit = exact_hit("mul", "md4.mul_overflow", FAIL_LHS, FAIL_RHS);
        let raw = receipt(FAIL_LHS, FAIL_RHS, carry_1);
        let parsed = validated_mul_carry_exception_receipt(
            Some(&raw),
            std::slice::from_ref(&hit),
            None,
            Some("prover failed"),
        )
        .expect("exact non-injected receipt must route");
        assert_eq!(parsed.step, STEP);
        assert!(has_exact_executed_exception_relation(&[hit], Some(&parsed)));
    }

    #[test]
    fn nearby_carry_bound_and_mulhu_nonoverflow_controls_stay_clean() {
        let nearby_lhs = 0xe453_7af9;
        let nearby_rhs = 0xb3ba_d9dd;
        assert_eq!(nexus_mul_carry_1(nearby_lhs, nearby_rhs), 3);
        let nearby_hit = exact_hit("mul", "md4.mul_overflow", nearby_lhs, nearby_rhs);
        let nearby_raw = receipt(nearby_lhs, nearby_rhs, 3);
        assert!(validated_mul_carry_exception_receipt(
            Some(&nearby_raw),
            &[nearby_hit],
            None,
            Some("prover failed"),
        )
        .is_none());

        let mulhu_hit = exact_hit("mulhu", "md4.mulhu", FAIL_LHS, FAIL_RHS);
        let target_raw = receipt(FAIL_LHS, FAIL_RHS, 4);
        assert!(validated_mul_carry_exception_receipt(
            Some(&target_raw),
            &[mulhu_hit],
            None,
            Some("prover failed"),
        )
        .is_none());

        let small_hit = exact_hit("mul", "md4.mul_small", 0xffff, 0x1_0000);
        let small_raw = receipt(0xffff, 0x1_0000, nexus_mul_carry_1(0xffff, 0x1_0000));
        assert!(validated_mul_carry_exception_receipt(
            Some(&small_raw),
            &[small_hit],
            None,
            Some("prover failed"),
        )
        .is_none());
    }

    #[test]
    fn malformed_injected_and_nonfailing_receipts_fail_closed() {
        let hit = exact_hit("mul", "md4.mul_overflow", FAIL_LHS, FAIL_RHS);
        let raw = receipt(FAIL_LHS, FAIL_RHS, 4);
        assert!(validated_mul_carry_exception_receipt(
            Some("{malformed"),
            std::slice::from_ref(&hit),
            None,
            Some("prover failed"),
        )
        .is_none());

        let wrong_product = raw.replace("\"product_lo\":", "\"product_lo\":1,\"ignored\":");
        assert!(validated_mul_carry_exception_receipt(
            Some(&wrong_product),
            std::slice::from_ref(&hit),
            None,
            Some("prover failed"),
        )
        .is_none());
        assert!(validated_mul_carry_exception_receipt(
            Some(&raw),
            std::slice::from_ref(&hit),
            Some("unsupported-injection"),
            Some("prover failed"),
        )
        .is_none());
        assert!(validated_mul_carry_exception_receipt(Some(&raw), &[hit], None, None).is_none());
    }
}

fn detail_str<'a>(hit: &'a BucketHit, key: &str) -> Option<&'a str> {
    hit.details.get(key).and_then(|value| value.as_str())
}

fn detail_u64(hit: &BucketHit, key: &str) -> Option<u64> {
    hit.details.get(key).and_then(|value| {
        value.as_u64().or_else(|| value.as_i64().and_then(|n| u64::try_from(n).ok()))
    })
}
