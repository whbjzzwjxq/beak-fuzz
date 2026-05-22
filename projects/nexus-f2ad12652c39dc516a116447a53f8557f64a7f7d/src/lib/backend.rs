use std::collections::BTreeMap;

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{BucketHit, Trace, TraceSignal};
use nexus_common::cpu::Registers;
use nexus_common::memory::MemoryRecord;
use nexus_common::riscv::register::Register;
use nexus_vm::emulator::{Emulator, HarvardEmulator, InternalView, LinearMemoryLayout, View};
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
const SHIFT_INJECT_KIND: &str = "nexus.semantic.alu.shift_mod32";
const CMP_BOOL_INJECT_KIND: &str = "nexus.semantic.alu.comparison_booleanity";
const SUB_BORROW_INJECT_KIND: &str = "nexus.semantic.alu.subtraction_borrow_chain";
const CMP_AUX_INJECT_KIND: &str = "nexus.semantic.alu.comparison_auxiliary_chain";
const CONTROL_FLOW_INJECT_KIND: &str = "nexus.semantic.exec.control_flow_binding";
const ENTRYPOINT_INJECT_KIND: &str = "nexus.semantic.control.entrypoint_binding";
const ECALL_ARGUMENT_INJECT_KIND: &str = "nexus.semantic.control.ecall_argument_decomposition";
const ECALL_WORD_INJECT_KIND: &str = "nexus.semantic.control.ecall_word_validity";
const TIME_BOUNDARY_INJECT_KIND: &str = "nexus.semantic.time.boundary_origin_consistency";
const ADDRESS_ALIGNMENT_INJECT_KIND: &str = "nexus.semantic.memory.address_alignment_consistency";
const LOAD_VALUE_INJECT_KIND: &str = "nexus.semantic.memory.load_value_binding";
const INITIAL_VALUE_INJECT_KIND: &str = "nexus.semantic.memory.initial_value_binding";
const ADDRESS_POINTER_INJECT_KIND: &str = "nexus.semantic.memory.address_pointer_consistency";
const ADDRESS_PROGRESSION_INJECT_KIND: &str =
    "nexus.semantic.memory.address_progression_consistency";
const TIME_MONOTONIC_INJECT_KIND: &str = "nexus.semantic.time.monotonic_access_ordering";
const FLOW_PAYLOAD_INJECT_KIND: &str = "nexus.semantic.memory.store_load_payload_flow";
const WRITE_PAYLOAD_INJECT_KIND: &str = "nexus.semantic.memory.write_payload_consistency";
const KIND_SELECTOR_INJECT_KIND: &str = "nexus.semantic.memory.kind_selector_consistency";
const FINALIZATION_INJECT_KIND: &str = "nexus.semantic.memory.finalization_consistency";
const PADDING_INTERACTION_INJECT_KIND: &str = "nexus.semantic.row.padding_interaction_send";
const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";
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

fn is_shift_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sll" | "slli" | "srl" | "srli" | "sra" | "srai")
}

fn is_comparison_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "slt" | "slti" | "sltu" | "sltiu")
}

fn is_supported_sub_borrow_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sub" | "slt" | "slti" | "sltu" | "sltiu")
}

fn is_control_flow_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "jal" | "jalr")
}

fn is_format_imm_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "sb" | "sh" | "sw" | "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "jal")
}

fn collect_observed_injection_sites(trace: &UniformTrace) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    let mut flat_step = 0u64;
    let mut ecall_row_idx = 0u64;
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
                if is_control_flow_mnemonic(mnemonic) {
                    record_site(&mut sites, CONTROL_FLOW_INJECT_KIND, flat_step);
                }
                if mnemonic == "ecall" {
                    record_site(&mut sites, ECALL_WORD_INJECT_KIND, flat_step);
                    record_site(&mut sites, ECALL_ARGUMENT_INJECT_KIND, ecall_row_idx);
                }
                if matches!(mnemonic, "ecall" | "ebreak") {
                    ecall_row_idx = ecall_row_idx.saturating_add(1);
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

fn direct_view_with_default_layout(view: &View) -> View {
    let layout = LinearMemoryLayout::default();
    let layout_opt = Some(layout);
    let debug_logs = view.view_debug_logs().unwrap_or_default();
    let ro_initial_memory = view.get_ro_initial_memory().to_vec();
    let rw_initial_memory = view.get_rw_initial_memory().to_vec();
    let public_input = view.get_public_input().to_vec();
    let exit_code = view.get_exit_code().to_vec();
    let public_output = view.get_public_output().to_vec();
    let associated_data = Vec::new();
    let tracked_ram_size = layout.tracked_ram_size(rw_initial_memory.len());
    View::new(
        &layout_opt,
        &debug_logs,
        view.get_program_memory(),
        &ro_initial_memory,
        &rw_initial_memory,
        &public_input,
        tracked_ram_size,
        &exit_code,
        &public_output,
        &associated_data,
    )
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
    let proving_view = direct_view_with_default_layout(&view);

    let observed_injection_sites = collect_observed_injection_sites(&trace);
    let derived = NexusTrace::from_words_and_uniform_trace(words, &trace);
    let env_restore = arm_prover_injection_env(inject_kind, inject_step);
    let backend_error =
        match catch_unwind_nonfatal(std::panic::AssertUnwindSafe(|| match nexus_vm_prover2::prove(
            &trace,
            &proving_view,
        ) {
            Ok(proof) => nexus_vm_prover2::verify(proof, &proving_view)
                .err()
                .map(|e| format!("nexus verify failed: {e}")),
            Err(e) => Some(format!("nexus prove failed: {e}")),
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
        "sem.decode.zero_register_immutability" => {
            (ZERO_REG_INJECT_KIND, "semantic.decode.zero_register_immutability")
        }
        "sem.decode.operand_index_routing" => {
            (OPERAND_ROUTING_INJECT_KIND, "semantic.decode.operand_index_routing")
        }
        "sem.exec.dest_binding" => (DEST_BINDING_INJECT_KIND, "semantic.exec.dest_binding"),
        "sem.decode.field_range" => (FIELD_RANGE_INJECT_KIND, "semantic.decode.field_range"),
        "sem.decode.immediate_sign_extension" => {
            (IMM_SIGNEXT_INJECT_KIND, "semantic.decode.immediate_sign_extension")
        }
        "sem.decode.upper_immediate_materialization" => {
            (UPPER_IMM_INJECT_KIND, "semantic.decode.upper_immediate_materialization")
        }
        "sem.decode.format_immediate_reassembly" => {
            (FORMAT_IMM_INJECT_KIND, "semantic.decode.format_immediate_reassembly")
        }
        "sem.exec.op_selector_binding" => {
            (OP_SELECTOR_INJECT_KIND, "semantic.exec.op_selector_binding")
        }
        "sem.alu.immediate_limb_consistency" => {
            // The f2ad hook named for this bucket mutates execution/add::AVal,
            // not the immediate/op_c decomposition source, so keep AL1 bucket-only.
            return None;
        }
        "sem.alu.shift_mod32" => (SHIFT_INJECT_KIND, "semantic.alu.shift_mod32"),
        "sem.alu.comparison_booleanity" => {
            (CMP_BOOL_INJECT_KIND, "semantic.alu.comparison_booleanity")
        }
        "sem.alu.subtraction_borrow_chain" => {
            if !detail_str(hit, "mnemonic").is_some_and(is_supported_sub_borrow_mnemonic) {
                return None;
            }
            (SUB_BORROW_INJECT_KIND, "semantic.alu.subtraction_borrow_chain")
        }
        "sem.alu.comparison_auxiliary_chain" => {
            if !detail_str(hit, "mnemonic").is_some_and(is_comparison_mnemonic) {
                return None;
            }
            (CMP_AUX_INJECT_KIND, "semantic.alu.comparison_auxiliary_chain")
        }
        "sem.exec.control_flow_binding" => {
            let obligation_id = detail_str(hit, "obligation_id")?;
            if !matches!(obligation_id, "cf1" | "cf2" | "cf3") {
                return None;
            }
            (CONTROL_FLOW_INJECT_KIND, "semantic.exec.control_flow_binding")
        }
        "sem.control.entrypoint_binding" => {
            (ENTRYPOINT_INJECT_KIND, "semantic.control.entrypoint_binding")
        }
        "sem.control.ecall_word_validity" => {
            (ECALL_WORD_INJECT_KIND, "semantic.control.ecall_word_validity")
        }
        "sem.control.ecall_argument_decomposition" => {
            let cell_id = detail_str(hit, "cell_id")?;
            if matches!(cell_id, "cf5.arg_zero" | "cf5.arg_max") {
                return None;
            }
            (ECALL_ARGUMENT_INJECT_KIND, "semantic.control.ecall_argument_decomposition")
        }
        "sem.time.boundary_origin_consistency" => {
            (TIME_BOUNDARY_INJECT_KIND, "semantic.time.boundary_origin_consistency")
        }
        "sem.memory.address_alignment_consistency" => {
            (ADDRESS_ALIGNMENT_INJECT_KIND, "semantic.memory.address_alignment_consistency")
        }
        "sem.memory.load_value_binding" => {
            (LOAD_VALUE_INJECT_KIND, "semantic.memory.load_value_binding")
        }
        "sem.memory.initial_value_binding" => {
            let cell_id = detail_str(hit, "cell_id")?;
            if !matches!(cell_id, "me7.bss_zero" | "me7.data_loaded") {
                return None;
            }
            (INITIAL_VALUE_INJECT_KIND, "semantic.memory.initial_value_binding")
        }
        "sem.memory.address_boundary_range" => {
            (ADDRESS_POINTER_INJECT_KIND, "semantic.memory.address_boundary_range")
        }
        "sem.memory.address_progression_consistency" => {
            (ADDRESS_PROGRESSION_INJECT_KIND, "semantic.memory.address_progression_consistency")
        }
        "sem.time.monotonic_access_ordering" => {
            (TIME_MONOTONIC_INJECT_KIND, "semantic.time.monotonic_access_ordering")
        }
        "sem.memory.store_load_payload_flow" => {
            (FLOW_PAYLOAD_INJECT_KIND, "semantic.memory.write_payload_flow_consistency")
        }
        "sem.memory.write_payload_consistency" => {
            (WRITE_PAYLOAD_INJECT_KIND, "semantic.memory.write_payload_flow_consistency")
        }
        "sem.memory.kind_selector_consistency" => {
            (KIND_SELECTOR_INJECT_KIND, "semantic.memory.kind_selector_consistency")
        }
        "sem.memory.finalization_consistency" => {
            let cell_id = detail_str(hit, "cell_id")?;
            if !matches!(cell_id, "me11.written_cells" | "me11.read_only_cells") {
                return None;
            }
            (FINALIZATION_INJECT_KIND, "semantic.memory.finalization_consistency")
        }
        "sem.row.padding_interaction_send" => {
            (PADDING_INTERACTION_INJECT_KIND, "semantic.row.padding_interaction_send")
        }
        "sem.row.table_power2_boundary" => {
            // Bucket-only for now: Nexus RamInitFinal table sizing has no safe witness hook yet.
            return None;
        }
        _ => return None,
    };
    let step = match hit.bucket_id.as_str() {
        "sem.row.padding_interaction_send" => {
            detail_u64(hit, "padding_row_idx").or_else(|| detail_u64(hit, "step_idx"))?
        }
        "sem.alu.shift_mod32"
        | "sem.alu.immediate_limb_consistency"
        | "sem.alu.comparison_booleanity"
        | "sem.alu.subtraction_borrow_chain"
        | "sem.alu.comparison_auxiliary_chain"
        | "sem.exec.control_flow_binding" => detail_u64(hit, "timestamp")?,
        "sem.memory.address_alignment_consistency"
        | "sem.memory.load_value_binding"
        | "sem.memory.initial_value_binding"
        | "sem.memory.address_boundary_range"
        | "sem.memory.address_progression_consistency"
        | "sem.time.monotonic_access_ordering"
        | "sem.memory.store_load_payload_flow"
        | "sem.memory.write_payload_consistency"
        | "sem.memory.kind_selector_consistency" => detail_u64(hit, "timestamp")?,
        "sem.memory.finalization_consistency" => detail_u64(hit, "private_boundary_row_idx")
            .or_else(|| detail_u64(hit, "boundary_row_idx"))
            .or_else(|| detail_u64(hit, "step_idx"))?,
        "sem.control.ecall_argument_decomposition" => detail_u64(hit, "ecall_row_idx")
            .or_else(|| detail_u64(hit, "op_idx"))
            .or_else(|| detail_u64(hit, "step_idx"))?,
        _ => detail_u64(hit, "op_idx").or_else(|| detail_u64(hit, "step_idx"))?,
    };
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

fn detail_str<'a>(hit: &'a BucketHit, key: &str) -> Option<&'a str> {
    hit.details.get(key).and_then(|value| value.as_str())
}
