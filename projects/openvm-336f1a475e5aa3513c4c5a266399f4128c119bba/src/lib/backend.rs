use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, Trace, TraceSignal};

use crate::trace::OpenVMTrace;
use openvm_circuit::arch::VmExecutor;
use openvm_instructions::exe::VmExe;
use openvm_instructions::instruction::Instruction;
use openvm_instructions::program::Program;
use openvm_instructions::riscv::RV32_REGISTER_AS;
use openvm_instructions::LocalOpcode;
use openvm_instructions::SystemOpcode;
use openvm_rv32im_transpiler::{Rv32ITranspilerExtension, Rv32MTranspilerExtension};
use openvm_sdk::config::{AppConfig, SdkVmConfig};
use openvm_sdk::prover::AppProver;
use openvm_sdk::{Sdk, StdIn, F};
use openvm_stark_backend::p3_field::{FieldAlgebra, PrimeField32};
use openvm_transpiler::transpiler::Transpiler;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::Instant;

fn build_vm_config() -> SdkVmConfig {
    let mut vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .build();
    let force_volatile = std::env::var("BEAK_OPENVM_FORCE_VOLATILE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut sys_cfg = vm_config.system.config.clone().with_max_segment_len(256);
    if !force_volatile {
        sys_cfg = sys_cfg.with_continuations();
    } else {
        sys_cfg = sys_cfg.without_continuations();
    }
    vm_config.system.config = sys_cfg;
    vm_config
}

fn parse_u32_literal(value: &str) -> Result<u32, String> {
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| format!("invalid hex u32 {value:?}: {e}"))
    } else {
        value.parse::<u32>().map_err(|e| format!("invalid u32 {value:?}: {e}"))
    }
}

fn parse_init_memory_env() -> Result<BTreeMap<(u32, u32), F>, String> {
    let Some(raw) = std::env::var("BEAK_OPENVM_INIT_MEMORY").ok().filter(|s| !s.trim().is_empty())
    else {
        return Ok(BTreeMap::new());
    };
    let mut init_memory = BTreeMap::new();
    for (idx, entry) in raw.split(',').enumerate() {
        let parts = entry.split(':').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(format!(
                "BEAK_OPENVM_INIT_MEMORY entry {idx} must be address_space:pointer:value"
            ));
        }
        let address_space = parse_u32_literal(parts[0].trim())?;
        let pointer = parse_u32_literal(parts[1].trim())?;
        let value = parse_u32_literal(parts[2].trim())?;
        init_memory.insert((address_space, pointer), F::from_canonical_u32(value));
    }
    Ok(init_memory)
}

fn build_exe(words: &[u32]) -> Result<std::sync::Arc<VmExe<F>>, String> {
    let transpiler = Transpiler::<F>::default()
        .with_extension(Rv32ITranspilerExtension)
        .with_extension(Rv32MTranspilerExtension);
    let transpiled = transpiler.transpile(words).map_err(|e| format!("transpile failed: {e:?}"))?;

    let mut instructions: Vec<Instruction<F>> = Vec::new();
    for opt in transpiled.into_iter().flatten() {
        instructions.push(opt);
    }
    instructions.push(Instruction::from_usize(SystemOpcode::TERMINATE.global_opcode(), [0, 0, 0]));

    let program = Program::from_instructions(&instructions);
    let mut exe = VmExe::new(program);
    let init_memory = parse_init_memory_env()?;
    if !init_memory.is_empty() {
        exe = exe.with_init_memory(init_memory);
    }
    Ok(std::sync::Arc::new(exe))
}

fn is_openvm_supported_rv32_word(_word: u32) -> bool {
    true
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
    pub bucket_hits: Vec<beak_core::trace::BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub backend_error: Option<String>,
    pub observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pub injection_applied: bool,
}

const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";
const OPENVM_RV32_POINTER_MAX_BITS: u64 = 29;

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn inject_kind_with_variant(kind: &str, variant: &str) -> String {
    if variant.is_empty() {
        kind.to_string()
    } else {
        format!("{kind}::{variant}")
    }
}

fn inject_variant_param_usize(kind: &str, key: &str) -> Option<usize> {
    kind.split_once("::").and_then(|(_, variant)| {
        variant.split(',').find_map(|part| {
            let (k, v) = part.split_once('=')?;
            (k == key).then(|| v.parse::<usize>().ok()).flatten()
        })
    })
}

pub fn run_backend_once(
    request_id: u64,
    words: &[u32],
    _current_iteration: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<WorkerResponse, String> {
    let mut eval = BackendEval::default();
    match inject_kind {
        Some(kind)
            if base_inject_kind(kind) == "openvm.semantic.memory.immediate_sign_consistency" =>
        {
            std::env::set_var("BEAK_OPENVM_ENABLE_O8", "1");
        }
        _ => {
            std::env::remove_var("BEAK_OPENVM_ENABLE_O8");
        }
    }
    match inject_kind {
        Some(kind) if !kind.is_empty() => {
            std::env::set_var("BEAK_OPENVM_WITNESS_INJECT_KIND", kind);
            std::env::set_var("BEAK_OPENVM_WITNESS_INJECT_STEP", inject_step.to_string());
        }
        _ => {
            std::env::remove_var("BEAK_OPENVM_WITNESS_INJECT_KIND");
            std::env::remove_var("BEAK_OPENVM_WITNESS_INJECT_STEP");
        }
    }
    fuzzer_utils::configure_witness_injection(inject_kind, inject_step);
    let _ = fuzzer_utils::take_json_logs();

    let t0 = Instant::now();
    let exe = build_exe(words).map_err(|e| {
        eval.backend_error = Some(e.clone());
        e
    })?;
    let _ms_build_exe = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let sdk = Sdk;
    let vm_config = build_vm_config();
    let continuation_enabled = vm_config.system.config.continuation_enabled;
    let app_config = AppConfig {
        app_fri_params: Default::default(),
        app_vm_config: vm_config,
        leaf_fri_params: Default::default(),
        compiler_options: Default::default(),
    };
    let app_pk = std::sync::Arc::new(sdk.app_keygen(app_config).map_err(|e| {
        let msg = format!("app_keygen failed: {e:?}");
        eval.backend_error = Some(msg.clone());
        msg
    })?);
    let app_committed_exe =
        sdk.commit_app_exe(app_pk.app_vm_pk.fri_params, exe.as_ref().clone()).map_err(|e| {
            let msg = format!("commit_app_exe failed: {e:?}");
            eval.backend_error = Some(msg.clone());
            msg
        })?;
    let app_vm = VmExecutor::new(app_pk.app_vm_pk.vm_config.clone());
    let _ms_instance = t1.elapsed().as_millis();

    let t2 = Instant::now();
    let input = StdIn::default();
    let vm_result = app_vm
        .execute_and_generate_with_cached_program(app_committed_exe.clone(), input)
        .map_err(|e| {
            let msg = format!("execute_and_generate_with_cached_program failed: {e:?}");
            eval.backend_error = Some(msg.clone());
            msg
        })?;
    let _ms_trace_only = t2.elapsed().as_millis();

    let t3 = Instant::now();
    let state = vm_result.final_memory.as_ref().ok_or_else(|| "no final state".to_string())?;
    let mut regs = [0u32; 32];
    for i in 0..32u32 {
        let limbs = state.get_range::<4>(&(RV32_REGISTER_AS, i * 4));
        let bytes: [u8; 4] = limbs.map(|x| x.as_canonical_u32() as u8);
        regs[i as usize] = u32::from_le_bytes(bytes);
    }
    eval.final_regs = Some(regs);
    let _ms_read_regs = t3.elapsed().as_millis();

    let t6 = Instant::now();
    let app_vk = app_pk.get_app_vk();
    if continuation_enabled {
        let proof = sdk
            .generate_app_proof(app_pk.clone(), app_committed_exe.clone(), StdIn::default())
            .map_err(|e| {
                let msg = format!("generate_app_proof failed: {e:?}");
                eval.backend_error = Some(msg.clone());
                msg
            });
        if let Ok(proof) = proof {
            if let Err(e) = sdk.verify_app_proof(&app_vk, &proof) {
                eval.backend_error = Some(format!("verify_app_proof failed: {e:?}"));
            }
        }
    } else {
        let app_prover = AppProver::new(app_pk.app_vm_pk.clone(), app_committed_exe.clone());
        let proof = app_prover.generate_app_proof_without_continuations(StdIn::default());
        if let Err(e) = sdk.verify_app_proof_without_continuations(&app_vk, &proof) {
            eval.backend_error =
                Some(format!("verify_app_proof_without_continuations failed: {e:?}"));
        }
    }
    let _ms_prove_verify = t6.elapsed().as_millis();

    let t4 = Instant::now();
    let observed_injection_sites = fuzzer_utils::take_observed_witness_sites();
    let mut applied_injection_sites = fuzzer_utils::take_applied_witness_sites();
    let logs = fuzzer_utils::take_json_logs();
    let _ms_take_logs = t4.elapsed().as_millis();
    let _logs_len = logs.len();

    let t5 = Instant::now();
    match OpenVMTrace::from_logs_with_words(logs, words) {
        Ok(trace) => {
            eval.micro_op_count = trace.instruction_count();
            eval.bucket_hits = trace.bucket_hits().to_vec();
            eval.trace_signals = trace.trace_signals().to_vec();
            let _ms_parse = t5.elapsed().as_millis();
        }
        Err(e) => {
            let _ms_parse = t5.elapsed().as_millis();
            eval.backend_error = Some(e.clone());
        }
    }
    for steps in applied_injection_sites.values_mut() {
        steps.sort_unstable();
        steps.dedup();
    }
    let injection_applied = inject_kind
        .and_then(|kind| applied_injection_sites.get(base_inject_kind(kind)))
        .map(
            |steps| {
                if inject_step == u64::MAX {
                    !steps.is_empty()
                } else {
                    steps.contains(&inject_step)
                }
            },
        )
        .or_else(|| {
            inject_kind.and_then(|kind| {
                (base_inject_kind(kind) == "openvm.semantic.lookup.xor_multiplicity_consistency")
                    .then(|| {
                        let rank = inject_variant_param_usize(kind, "rank").unwrap_or(0);
                        let xor_hits = eval
                            .bucket_hits
                            .iter()
                            .filter(|hit| {
                                hit.bucket_id == semantic::lookup::XOR_MULTIPLICITY_CONSISTENCY.id
                            })
                            .count();
                        rank < xor_hits
                    })
            })
        })
        .unwrap_or(false);

    Ok(WorkerResponse {
        request_id,
        final_regs: eval.final_regs,
        micro_op_count: eval.micro_op_count,
        bucket_hits: eval.bucket_hits,
        trace_signals: eval.trace_signals,
        backend_error: eval.backend_error,
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

#[derive(Debug, Clone)]
struct WitnessInjectionPlan {
    kind: String,
    step: u64,
}

pub struct OpenVmBackend {
    max_instructions: usize,
    eval: BackendEval,
    last_words: Vec<u32>,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    current_iteration: u64,
    next_request_id: u64,
    pending_injection: Option<WitnessInjectionPlan>,
    worker: Option<WorkerProcess>,
}

impl OpenVmBackend {
    pub fn new(max_instructions: usize) -> Self {
        Self {
            max_instructions,
            eval: BackendEval::default(),
            last_words: Vec::new(),
            last_observed_injection_sites: BTreeMap::new(),
            current_iteration: 0,
            next_request_id: 1,
            pending_injection: None,
            worker: None,
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

    fn step_from_hit(hit: &beak_core::trace::BucketHit) -> u64 {
        hit.details
            .get("op_idx")
            .and_then(|v| v.as_u64())
            .or_else(|| hit.details.get("step_idx").and_then(|v| v.as_u64()))
            .unwrap_or(0)
    }

    fn hit_detail_bool(hit: &beak_core::trace::BucketHit, key: &str) -> bool {
        hit.details.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
    }

    fn hit_detail_u64(hit: &beak_core::trace::BucketHit, key: &str) -> Option<u64> {
        hit.details.get(key).and_then(|v| v.as_u64())
    }

    fn o5_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for mode in ["byte_bias", "neighbor_copy", "sign_echo", "modulus_bias", "rotate_lane"] {
            for strength in 0..11u32 {
                for slot in 0..4u32 {
                    specs.push(format!("mode={mode},slot={slot},strength={strength}"));
                }
            }
        }
        for strength in 0..11u32 {
            for slot in [1u32, 2, 3] {
                specs.push(format!("mode=collapse_word,slot={slot},strength={strength}"));
            }
        }
        for strength in 0..11u32 {
            specs.push(format!("mode=collapse_word,slot=0,strength={strength}"));
        }
        specs
    }

    fn o1_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for mode in ["p_plus_mask", "double_modulus_mask", "p_plus_one"] {
            for rank in 0..30u32 {
                for strength in 0..8u32 {
                    specs.push(format!("mode={mode},rank={rank},strength={strength}"));
                }
            }
        }
        specs
    }

    fn o7_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for mode in [
            "from_pc_high_single_mod_p",
            "from_pc_high_stagger_mod_p",
            "from_pc_high_double_pair_mod_p",
            "from_pc_high_pair_mod_p",
            "from_pc_high_pair_mod_p_alt",
            "single_mod_p",
            "stagger_mod_p",
            "double_pair_mod_p",
            "pair_mod_p",
        ] {
            for mult in 1..=2u32 {
                for strength in 0..24u32 {
                    for slot in 1..3u32 {
                        specs.push(format!(
                            "mode={mode},slot={slot},strength={strength},mult={mult}"
                        ));
                    }
                }
            }
        }
        specs
    }

    fn o8_variant_specs_for_hit(hit: &beak_core::trace::BucketHit) -> Vec<String> {
        let is_store = Self::hit_detail_bool(hit, "is_store");
        let is_load = Self::hit_detail_bool(hit, "is_load");
        let alt_in_range = hit
            .details
            .get("alt_ptr_in_range_29")
            .and_then(|v| v.as_bool())
            .or_else(|| {
                Self::hit_detail_u64(hit, "alt_effective_ptr")
                    .map(|ptr| ptr < (1u64 << OPENVM_RV32_POINTER_MAX_BITS))
            })
            .unwrap_or(false);

        let mut domains = Vec::new();
        if is_store {
            domains.push("store");
        }
        if is_load {
            domains.push("load");
        }
        domains.push("any");

        let mut specs = Vec::new();
        for domain in domains {
            if alt_in_range {
                specs.push(format!("mode=flip_sign,domain={domain},guard=alt_in_range"));
            }
            specs.push(format!("mode=flip_sign,domain={domain},guard=none"));
        }

        if alt_in_range {
            specs.push("mode=flip_sign,domain=any,guard=alt_in_range,search=wildcard".to_string());
        }
        specs.push("mode=flip_sign,domain=any,guard=none,search=wildcard".to_string());
        specs.dedup();
        specs
    }

    fn o15_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        specs.push("mode=shadow_invalid_one,search=wildcard".to_string());
        specs.push("mode=lt_diff_bias,slot=0,strength=0,search=wildcard".to_string());
        // Try the overflow-special-case variants first; the standard o15 seed does not exercise
        // the zero-divisor-only path, so leading with those variants wastes semantic-search budget.
        for mode in ["lt_diff_bias", "marker_shift", "r_prime_alias", "flag_zero_divisor"] {
            for strength in 0..24u32 {
                for slot in 0..4u32 {
                    specs.push(format!("mode={mode},slot={slot},strength={strength}"));
                }
            }
        }
        for mode in [
            "zero_divisor_only_lt_diff_bias",
            "zero_divisor_only_marker_shift",
            "zero_divisor_only_r_prime_alias",
            "zero_divisor_only_flag_zero_divisor",
        ] {
            for strength in 0..20u32 {
                for slot in 0..4u32 {
                    specs.push(format!("mode={mode},slot={slot},strength={strength}"));
                }
            }
        }
        specs
    }

    fn inject_kinds_for_base(inject_kind: &str) -> Vec<String> {
        match inject_kind {
            "openvm.semantic.lookup.xor_multiplicity_consistency" => Self::o1_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            "openvm.semantic.alu.immediate_limb_consistency" => Self::o5_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            "openvm.semantic.control.auipc_pc_limb_consistency" => Self::o7_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            "openvm.semantic.arithmetic.special_case_consistency" => Self::o15_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            _ => vec![inject_kind.to_string()],
        }
    }

    fn semantic_candidate_from_hit(
        &self,
        hit: &beak_core::trace::BucketHit,
    ) -> Vec<SemanticInjectionCandidate> {
        let bucket_id = hit.bucket_id.as_str();
        let mut anchor = Self::step_from_hit(hit);
        if bucket_id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id {
            if let Some(store_step_idx) =
                hit.details.get("store_step_idx").and_then(|value| value.as_u64())
            {
                anchor = store_step_idx;
            }
        }
        let (semantic_class, inject_kind, fallback_schedule, wildcard_variant) =
            if bucket_id == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id {
                (
                    semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.semantic_class,
                    "openvm.semantic.alu.immediate_limb_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id {
                (
                    semantic::decode::ZERO_REGISTER_IMMUTABILITY.semantic_class,
                    "openvm.semantic.decode.zero_register_immutability",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::decode::OPERAND_INDEX_ROUTING.id {
                (
                    semantic::decode::OPERAND_INDEX_ROUTING.semantic_class,
                    "openvm.semantic.decode.operand_index_routing",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.id {
                (
                    semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.semantic_class,
                    "openvm.semantic.decode.format_immediate_reassembly",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::lookup::XOR_MULTIPLICITY_CONSISTENCY.id {
                (
                    semantic::lookup::XOR_MULTIPLICITY_CONSISTENCY.semantic_class,
                    "openvm.semantic.lookup.xor_multiplicity_consistency",
                    InjectionSchedule::Exact(0),
                    false,
                )
            } else if bucket_id == semantic::control::AUIPC_PC_LIMB_CONSISTENCY.id {
                (
                    semantic::control::AUIPC_PC_LIMB_CONSISTENCY.semantic_class,
                    "openvm.semantic.control.auipc_pc_limb_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::memory::IMMEDIATE_SIGN_CONSISTENCY.id {
                (
                    semantic::memory::IMMEDIATE_SIGN_CONSISTENCY.semantic_class,
                    "openvm.semantic.memory.immediate_sign_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::memory::ADDRESS_SPACE_CONSISTENCY.id {
                (
                    semantic::memory::ADDRESS_SPACE_CONSISTENCY.semantic_class,
                    "openvm.semantic.memory.address_space_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id
                || bucket_id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id
                || bucket_id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id
            {
                (
                    semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.semantic_class,
                    "openvm.semantic.memory.address_pointer_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::memory::LOAD_VALUE_BINDING.id
                || bucket_id == semantic::memory::WRITE_PAYLOAD_CONSISTENCY.id
            {
                (
                    semantic::memory::LOAD_VALUE_BINDING.semantic_class,
                    "openvm.semantic.memory.value_payload_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id {
                (
                    semantic::memory::STORE_LOAD_PAYLOAD_FLOW.semantic_class,
                    "openvm.semantic.memory.store_load_payload_flow",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::memory::FINALIZATION_CONSISTENCY.id {
                (
                    semantic::memory::FINALIZATION_CONSISTENCY.semantic_class,
                    "openvm.semantic.memory.finalization_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id {
                (
                    semantic::memory::KIND_SELECTOR_CONSISTENCY.semantic_class,
                    "openvm.semantic.memory.kind_selector_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id {
                (
                    semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.semantic_class,
                    "openvm.semantic.arithmetic.special_case_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::alu::SHIFT_MOD32.id {
                (
                    semantic::alu::SHIFT_MOD32.semantic_class,
                    "openvm.semantic.alu.shift_mod32",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::alu::COMPARISON_BOOLEANITY.id {
                (
                    semantic::alu::COMPARISON_BOOLEANITY.semantic_class,
                    "openvm.semantic.alu.comparison_booleanity",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::alu::SUBTRACTION_BORROW_CHAIN.id {
                (
                    semantic::alu::SUBTRACTION_BORROW_CHAIN.semantic_class,
                    "openvm.semantic.alu.subtraction_borrow_chain",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id {
                (
                    semantic::alu::COMPARISON_AUXILIARY_CHAIN.semantic_class,
                    "openvm.semantic.alu.comparison_auxiliary_chain",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id {
                (
                    semantic::arithmetic::DIVISION_REMAINDER_BOUND.semantic_class,
                    "openvm.semantic.arithmetic.division_remainder_bound",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::arithmetic::PRODUCT_DECOMPOSITION.id {
                (
                    semantic::arithmetic::PRODUCT_DECOMPOSITION.semantic_class,
                    "openvm.semantic.arithmetic.product_decomposition",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id {
                (
                    semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.semantic_class,
                    "openvm.semantic.arithmetic.signed_unsigned_product_correction",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id {
                (
                    semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.semantic_class,
                    "openvm.semantic.time.boundary_origin_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id {
                (
                    semantic::time::MONOTONIC_ACCESS_ORDERING.semantic_class,
                    "openvm.semantic.time.monotonic_access_ordering",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::control::ENTRYPOINT_BINDING.id {
                (
                    semantic::control::ENTRYPOINT_BINDING.semantic_class,
                    "openvm.semantic.control.entrypoint_binding",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id {
                (
                    semantic::exec::CONTROL_FLOW_BINDING.semantic_class,
                    "openvm.semantic.exec.control_flow_binding",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
                )
            } else if bucket_id == semantic::control::ECALL_WORD_VALIDITY.id {
                (
                    semantic::control::ECALL_WORD_VALIDITY.semantic_class,
                    "openvm.semantic.control.ecall_word_validity",
                    InjectionSchedule::AroundAnchor(anchor),
                    true,
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
            .unwrap_or(fallback_schedule);
        let inject_kinds = if inject_kind == "openvm.semantic.memory.immediate_sign_consistency" {
            Self::o8_variant_specs_for_hit(hit)
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect()
        } else {
            Self::inject_kinds_for_base(inject_kind)
        };
        let mut candidates: Vec<_> = inject_kinds
            .iter()
            .map(|kind| SemanticInjectionCandidate {
                bucket_id: hit.bucket_id.clone(),
                trigger_signal_id: None,
                semantic_class: semantic_class.to_string(),
                inject_kind: kind.clone(),
                schedule: if inject_kind == "openvm.semantic.arithmetic.special_case_consistency"
                    && kind.contains("search=wildcard")
                {
                    InjectionSchedule::Exact(u64::MAX)
                } else {
                    schedule.clone()
                },
            })
            .collect();
        if inject_kind == "openvm.semantic.memory.immediate_sign_consistency" {
            candidates.extend(
                inject_kinds
                    .iter()
                    .filter(|kind| {
                        kind.contains("mode=flip_sign")
                            && kind.contains("guard=alt_in_range")
                            && kind.contains("domain=")
                    })
                    .map(|kind| SemanticInjectionCandidate {
                        bucket_id: hit.bucket_id.clone(),
                        trigger_signal_id: None,
                        semantic_class: semantic_class.to_string(),
                        inject_kind: kind.clone(),
                        schedule: InjectionSchedule::Exact(u64::MAX),
                    }),
            );
        }
        if inject_kind == "openvm.semantic.arithmetic.special_case_consistency" {
            candidates.extend(
                inject_kinds.iter().filter(|kind| kind.contains("mode=flag_zero_divisor")).map(
                    |kind| SemanticInjectionCandidate {
                        bucket_id: hit.bucket_id.clone(),
                        trigger_signal_id: None,
                        semantic_class: semantic_class.to_string(),
                        inject_kind: kind.clone(),
                        schedule: InjectionSchedule::Exact(u64::MAX),
                    },
                ),
            );
        }
        if wildcard_variant && inject_kinds.len() == 1 {
            candidates.push(SemanticInjectionCandidate {
                bucket_id: hit.bucket_id.clone(),
                trigger_signal_id: None,
                semantic_class: semantic_class.to_string(),
                inject_kind: inject_kind.to_string(),
                schedule: InjectionSchedule::Exact(u64::MAX),
            });
        }
        candidates
    }

    fn semantic_candidate_priority(candidate: &SemanticInjectionCandidate) -> u8 {
        let bucket_id = candidate.bucket_id.as_str();
        if bucket_id == semantic::lookup::XOR_MULTIPLICITY_CONSISTENCY.id {
            0
        } else if bucket_id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id
            || bucket_id == semantic::decode::OPERAND_INDEX_ROUTING.id
            || bucket_id == semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.id
        {
            1
        } else if bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id
            || bucket_id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id
            || bucket_id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id
            || bucket_id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id
            || bucket_id == semantic::memory::LOAD_VALUE_BINDING.id
            || bucket_id == semantic::memory::WRITE_PAYLOAD_CONSISTENCY.id
            || bucket_id == semantic::memory::ADDRESS_SPACE_CONSISTENCY.id
            || bucket_id == semantic::memory::IMMEDIATE_SIGN_CONSISTENCY.id
            || bucket_id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id
            || bucket_id == semantic::memory::FINALIZATION_CONSISTENCY.id
        {
            2
        } else if bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id
            || bucket_id == semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id
            || bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id
        {
            3
        } else if bucket_id == semantic::alu::SHIFT_MOD32.id
            || bucket_id == semantic::alu::COMPARISON_BOOLEANITY.id
            || bucket_id == semantic::alu::SUBTRACTION_BORROW_CHAIN.id
            || bucket_id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id
            || bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id
            || bucket_id == semantic::arithmetic::PRODUCT_DECOMPOSITION.id
            || bucket_id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id
        {
            4
        } else if bucket_id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id {
            5
        } else if bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id
            || bucket_id == semantic::control::ECALL_WORD_VALIDITY.id
        {
            6
        } else if bucket_id == semantic::row::PADDING_INTERACTION_SEND.id {
            7
        } else if bucket_id == semantic::control::AUIPC_PC_LIMB_CONSISTENCY.id {
            8
        } else if bucket_id == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id {
            9
        } else {
            10
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
                        if trimmed.is_empty() {
                            continue;
                        }
                        if !trimmed.starts_with(WORKER_RESPONSE_PREFIX) {
                            // Ignore non-protocol stdout noise from dependencies.
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
}

impl BenchmarkBackend for OpenVmBackend {
    fn is_usable_seed(&self, words: &[u32]) -> bool {
        if words.is_empty() {
            return false;
        }
        if words.len() > self.max_instructions {
            return false;
        }
        words
            .iter()
            .all(|w| is_openvm_supported_rv32_word(*w) && RV32IMInstruction::from_word(*w).is_ok())
    }

    fn prepare_for_run(&mut self, _rng_seed: u64) {
        self.current_iteration = self.current_iteration.saturating_add(1);
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval.backend_error = None;
        self.eval.bucket_hits.clear();
        self.eval.micro_op_count = 0;
        self.eval.final_regs = None;
        self.eval.semantic_injection_applied = false;
        self.last_observed_injection_sites.clear();
        self.last_words = words.to_vec();
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

        let worker_resp = loop {
            let recv = {
                let worker =
                    self.worker.as_ref().ok_or_else(|| "backend worker unavailable".to_string())?;
                worker.responses_rx.recv()
            };
            match recv {
                Ok(Ok(resp)) => {
                    if resp.request_id == request_id {
                        break resp;
                    }
                }
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

        self.eval.micro_op_count = worker_resp.micro_op_count;
        self.eval.bucket_hits = worker_resp.bucket_hits;
        self.eval.trace_signals = worker_resp.trace_signals;
        self.eval.backend_error = worker_resp.backend_error.clone();
        self.eval.final_regs = worker_resp.final_regs;
        self.eval.semantic_injection_applied = worker_resp.injection_applied;
        self.last_observed_injection_sites = worker_resp.observed_injection_sites;

        match worker_resp.final_regs {
            Some(regs) => Ok(regs),
            None => Err(worker_resp
                .backend_error
                .unwrap_or_else(|| "backend worker returned no final regs".to_string())),
        }
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

    fn semantic_injection_candidates(
        &self,
        hits: &[beak_core::trace::BucketHit],
    ) -> Vec<SemanticInjectionCandidate> {
        let has_more_specific_semantic_target = hits.iter().any(|hit| {
            let bucket_id = hit.bucket_id.as_str();
            bucket_id == semantic::memory::IMMEDIATE_SIGN_CONSISTENCY.id
                || bucket_id == semantic::control::AUIPC_PC_LIMB_CONSISTENCY.id
                || bucket_id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id
        });
        let mut candidates: Vec<_> = hits
            .iter()
            .filter(|hit| {
                !(has_more_specific_semantic_target
                    && hit.bucket_id == semantic::lookup::XOR_MULTIPLICITY_CONSISTENCY.id)
            })
            .flat_map(|hit| self.semantic_candidate_from_hit(hit))
            .collect();
        candidates.sort_by_key(Self::semantic_candidate_priority);
        candidates
    }
}

impl Drop for OpenVmBackend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}
