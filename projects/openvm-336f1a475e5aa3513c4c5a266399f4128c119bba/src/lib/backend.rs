use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, ExecutedExceptionEffect, ExecutedExceptionReceipt,
    InjectionSchedule, SemanticInjectionCandidate, SemanticMutationReceipt,
    SemanticMutationRelation,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{Trace, TraceSignal, semantic};

use crate::trace::OpenVMTrace;
use openvm_circuit::arch::VmExecutor;
use openvm_instructions::{LocalOpcode, SystemOpcode};
use openvm_instructions::exe::VmExe;
use openvm_instructions::instruction::Instruction;
use openvm_instructions::program::Program;
use openvm_instructions::riscv::{RV32_REGISTER_AS};
use openvm_bigint_transpiler::Int256TranspilerExtension;
use openvm_rv32im_transpiler::{Rv32ITranspilerExtension, Rv32MTranspilerExtension};
use openvm_sdk::config::{AppConfig, SdkVmConfig};
use openvm_sdk::prover::AppProver;
use openvm_sdk::{F, Sdk, StdIn};
use openvm_stark_backend::p3_field::{FieldAlgebra, PrimeField32};
use openvm_transpiler::transpiler::Transpiler;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::Instant;

const INT256_CUSTOM_OPCODE: u32 = 0x0b;
const INT256_ALU_FUNCT3: u32 = 0b101;
const INT256_BEQ_FUNCT3: u32 = 0b110;
const INT256_BRANCH256_FUNCT3: u32 = 0b111;
const BIGINT_BRANCH_GLOBAL_OPCODE: u64 = 0x425;
const BIGINT_BRANCH_CHIP_OFFSET: u64 = 0x408;
const BIGINT_BRANCH_LOCAL_OPCODE: u64 =
    BIGINT_BRANCH_GLOBAL_OPCODE - BIGINT_BRANCH_CHIP_OFFSET;
const BIGINT_BRANCH_STAGE: &str = "openvm.bigint.branch_less_than_opcode_conversion";
const BIGINT_BRANCH_TRACE_SOURCE: &str =
    "extensions/rv32im/circuit/src/branch_lt/core.rs::execute_instruction";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenVmFrontend {
    Rv32,
    Int256,
}

impl OpenVmFrontend {
    fn detect(words: &[u32]) -> Self {
        if words.iter().copied().any(is_int256_frontend_word) {
            Self::Int256
        } else {
            Self::Rv32
        }
    }

    fn needs_bigint(self) -> bool {
        matches!(self, Self::Int256)
    }
}

fn is_branch256_family_word(word: u32) -> bool {
    word & 0x7f == INT256_CUSTOM_OPCODE
        && (word >> 12) & 0x7 == INT256_BRANCH256_FUNCT3
}

fn is_native_int256_word(word: u32) -> bool {
    word & 0x7f == INT256_CUSTOM_OPCODE
        && matches!((word >> 12) & 0x7, INT256_ALU_FUNCT3 | INT256_BEQ_FUNCT3)
}

fn is_int256_frontend_word(word: u32) -> bool {
    is_branch256_family_word(word) || is_native_int256_word(word)
}

fn build_vm_config(frontend: OpenVmFrontend) -> SdkVmConfig {
    let mut vm_config = if frontend.needs_bigint() {
        SdkVmConfig::builder()
            .system(Default::default())
            .rv32i(Default::default())
            .rv32m(Default::default())
            .io(Default::default())
            .bigint(Default::default())
            .build()
    } else {
        SdkVmConfig::builder()
            .system(Default::default())
            .rv32i(Default::default())
            .rv32m(Default::default())
            .io(Default::default())
            .build()
    };
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

fn build_exe(words: &[u32], frontend: OpenVmFrontend) -> Result<std::sync::Arc<VmExe<F>>, String> {
    let rv32_transpiler = Transpiler::<F>::default()
        .with_extension(Rv32ITranspilerExtension)
        .with_extension(Rv32MTranspilerExtension);
    let int256_transpiler = Transpiler::<F>::default().with_extension(Int256TranspilerExtension);

    let mut instructions: Vec<Instruction<F>> = Vec::new();
    for word in words.iter().copied() {
        let transpiled = if frontend.needs_bigint() && is_int256_frontend_word(word) {
            int256_transpiler.transpile(&[word])
        } else {
            rv32_transpiler.transpile(&[word])
        }
        .map_err(|e| format!("transpile failed for {word:08x}: {e:?}"))?;
        instructions.extend(transpiled.into_iter().flatten());
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
    pub semantic_mutation_receipt: Option<SemanticMutationReceipt>,
    pub executed_exception_receipt: Option<ExecutedExceptionReceipt>,
}

fn bigint_opcode_conversion_failure_response(
    request_id: u64,
    backend_error: String,
    attempts: Vec<serde_json::Value>,
) -> Option<WorkerResponse> {
    // Evidence is accepted only from the concrete installed conversion hook. Input words and
    // panic strings are deliberately not consulted, and duplicate/stale attempts fail closed.
    let [attempt] = attempts.as_slice() else {
        return None;
    };
    let attempt = attempt.as_object()?;
    let exact_str = |key: &str, expected: &str| {
        attempt.get(key).and_then(|value| value.as_str()) == Some(expected)
    };
    let global_opcode = attempt.get("global_opcode")?.as_u64()?;
    let chip_class_offset = attempt.get("chip_class_offset")?.as_u64()?;
    let local_opcode = attempt.get("local_opcode")?.as_u64()?;
    let step = attempt.get("step")?.as_u64()?;
    let from_pc = attempt.get("from_pc")?.as_u64()?;
    let supported = attempt.get("supported_local_opcodes")?;
    let exact_identity = exact_str("effect", "bigint_opcode_conversion")
        && exact_str("obligation_id", "id4")
        && exact_str("cell_id", "id4.branch")
        && exact_str("stage", BIGINT_BRANCH_STAGE)
        && exact_str("trace_source", BIGINT_BRANCH_TRACE_SOURCE)
        && exact_str("conversion_target", "BranchLessThanOpcode")
        && exact_str("relation", "local_opcode_not_in_branch_less_than_domain")
        && exact_str("backend", "openvm")
        && exact_str("commit", "336f1a475e5aa3513c4c5a266399f4128c119bba")
        && attempt.get("hook_fired").and_then(|value| value.as_bool()) == Some(true)
        && attempt.get("relation_valid").and_then(|value| value.as_bool()) == Some(true);
    let exact_domain = global_opcode == BIGINT_BRANCH_GLOBAL_OPCODE
        && chip_class_offset == BIGINT_BRANCH_CHIP_OFFSET
        && local_opcode == BIGINT_BRANCH_LOCAL_OPCODE
        && global_opcode.checked_sub(chip_class_offset) == Some(local_opcode)
        && supported == &serde_json::json!([0, 1, 2, 3])
        && !(0..=3).contains(&local_opcode)
        && from_pc <= u32::MAX as u64;
    if !exact_identity || !exact_domain {
        return None;
    }

    let mut details = std::collections::HashMap::new();
    for key in [
        "obligation_id",
        "cell_id",
        "local_opcode",
        "global_opcode",
        "chip_class_offset",
        "supported_local_opcodes",
        "conversion_target",
        "relation",
        "relation_valid",
        "backend",
        "commit",
        "trace_source",
        "from_pc",
    ] {
        details.insert(key.to_string(), attempt.get(key)?.clone());
    }
    details.insert("step_idx".to_string(), serde_json::json!(step));
    details.insert("op_idx".to_string(), serde_json::json!(step));

    let mut context = serde_json::Map::new();
    for key in [
        "local_opcode",
        "global_opcode",
        "chip_class_offset",
        "supported_local_opcodes",
        "conversion_target",
        "relation",
        "relation_valid",
        "hook_fired",
        "backend",
        "commit",
        "trace_source",
        "from_pc",
    ] {
        context.insert(key.to_string(), attempt.get(key)?.clone());
    }
    Some(WorkerResponse {
        request_id,
        final_regs: None,
        micro_op_count: 0,
        bucket_hits: vec![beak_core::trace::BucketHit::semantic(
            semantic::decode::FIELD_RANGE,
            details,
        )],
        trace_signals: Vec::new(),
        backend_error: Some(backend_error),
        observed_injection_sites: BTreeMap::new(),
        injection_applied: false,
        semantic_mutation_receipt: None,
        executed_exception_receipt: Some(ExecutedExceptionReceipt {
            effect: ExecutedExceptionEffect::BigIntOpcodeConversion,
            obligation_id: attempt.get("obligation_id")?.as_str()?.to_string(),
            cell_id: attempt.get("cell_id")?.as_str()?.to_string(),
            stage: attempt.get("stage")?.as_str()?.to_string(),
            step,
            context,
        }),
    })
}

const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";
const OPENVM_RV32_POINTER_MAX_BITS: u64 = 29;

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn inject_kind_with_variant(kind: &str, variant: &str) -> String {
    if variant.is_empty() { kind.to_string() } else { format!("{kind}::{variant}") }
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
    let _ = fuzzer_utils::take_executed_exception_attempts();

    let frontend = OpenVmFrontend::detect(words);
    let t0 = Instant::now();
    let exe = build_exe(words, frontend).map_err(|e| {
        eval.backend_error = Some(e.clone());
        e
    })?;
    let _ms_build_exe = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let sdk = Sdk;
    let vm_config = build_vm_config(frontend);
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
    let vm_result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        app_vm.execute_and_generate_with_cached_program(app_committed_exe.clone(), input)
    })) {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            let msg = format!("execute_and_generate_with_cached_program failed: {e:?}");
            eval.backend_error = Some(msg.clone());
            return Err(msg);
        }
        Err(payload) => {
            let attempts = fuzzer_utils::take_executed_exception_attempts();
            if let Some(response) = bigint_opcode_conversion_failure_response(
                request_id,
                "execute_and_generate_with_cached_program panicked".to_string(),
                attempts,
            ) {
                return Ok(response);
            }
            std::panic::resume_unwind(payload)
        }
    };
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
    // Successful execution cannot carry conversion-exception evidence into a later run.
    let _ = fuzzer_utils::take_executed_exception_attempts();
    let mut semantic_mutation_receipt: Option<SemanticMutationReceipt> =
        fuzzer_utils::take_semantic_mutation_receipt()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| format!("invalid semantic mutation receipt: {e}"))?;
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
    if let Some(receipt) = semantic_mutation_receipt.as_mut() {
        let bucket_id = receipt
            .effect
            .context
            .get("bucket_id")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let hit = match receipt.effect.relation {
            SemanticMutationRelation::FullLimbValueRepresentation => {
                let value = receipt.effect.context.get("value").and_then(|value| value.as_u64());
                eval.bucket_hits
                    .iter()
                    .filter(|hit| {
                        hit.bucket_id == bucket_id
                            && hit.details.get("imm").and_then(|value| value.as_u64()) == value
                    })
                    .last()
            }
            SemanticMutationRelation::DivisionRemainderSpecialCaseEquation => {
                let dividend =
                    receipt.effect.context.get("dividend_word").and_then(|value| value.as_u64());
                let divisor =
                    receipt.effect.context.get("divisor_word").and_then(|value| value.as_u64());
                eval.bucket_hits
                    .iter()
                    .filter(|hit| {
                        hit.bucket_id == bucket_id
                            && hit.details.get("rs1_val").and_then(|value| value.as_u64())
                                == dividend
                            && hit.details.get("rs2_val").and_then(|value| value.as_u64())
                                == divisor
                    })
                    .last()
            }
            _ => eval.bucket_hits.iter().find(|hit| {
                hit.bucket_id == bucket_id
                    && hit.details.get("op_idx").and_then(|value| value.as_u64())
                        == Some(receipt.step)
            }),
        };
        if let Some(hit) = hit {
            if matches!(
                receipt.effect.relation,
                SemanticMutationRelation::FullLimbValueRepresentation
                    | SemanticMutationRelation::DivisionRemainderSpecialCaseEquation
            ) {
                if let Some(op_idx) = hit.details.get("op_idx").and_then(|value| value.as_u64()) {
                    receipt.step = op_idx;
                    let key = if receipt.effect.relation
                        == SemanticMutationRelation::FullLimbValueRepresentation
                    {
                        "op_idx"
                    } else {
                        "step"
                    };
                    receipt.effect.context.insert(key.to_string(), serde_json::json!(op_idx));
                }
            }
            for key in [
                "obligation_id",
                "cell_id",
                "backend",
                "commit",
                "trace_source",
                "pc",
                "opcode",
                "mnemonic",
            ] {
                // Never let a matched hit overwrite a typed cell/obligation
                // identity the hook already bound: under a timestamp-origin
                // shift the ts1 hit legitimately disappears from the injected
                // trace, and the fallback op_idx match can land on a sibling
                // cell (e.g. ts3.standard) of the same bucket.
                if matches!(key, "obligation_id" | "cell_id")
                    && receipt
                        .effect
                        .context
                        .get(key)
                        .is_some_and(|existing| hit.details.get(key) != Some(existing))
                {
                    continue;
                }
                if let Some(value) = hit.details.get(key) {
                    receipt.effect.context.insert(key.to_string(), value.clone());
                }
            }
        }
    }
    for steps in applied_injection_sites.values_mut() {
        steps.sort_unstable();
        steps.dedup();
    }
    let injection_applied =
        inject_kind
            .and_then(|kind| applied_injection_sites.get(base_inject_kind(kind)))
            .map(|steps| {
                if inject_step == u64::MAX {
                    !steps.is_empty()
                } else {
                    steps.contains(&inject_step)
                }
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
        semantic_mutation_receipt,
        executed_exception_receipt: None,
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
        vec!["mode=adjacent_radix_carry,carry_slot=0,borrow_slot=1,radix=256,field_modulus=2013265921,limb_count=4".to_string()]
    }

    fn o1_variant_specs() -> Vec<String> {
        // The first nonzero XOR row with a p+1 shadow multiplicity is the exact
        // audit-o1 mechanism; sweeping ranks/strengths only floods the schedule.
        vec!["mode=p_plus_one,rank=0,strength=0".to_string()]
    }

    fn o7_variant_specs() -> Vec<String> {
        // The installed auipc hook only accepts the single-limb mod-p variant
        // at strength 0 and mult 1, and only slots 2|3: slot 1's pc_limbs[0]
        // is covered by the straddling range pair (imm_limbs[2], pc_limbs[0]),
        // so a +modulus mutation there is rejected by the range check.
        (2..=3u32)
            .map(|slot| format!("mode=from_pc_high_single_mod_p,slot={slot},strength=0,mult=1"))
            .collect()
    }

    fn timestamp_origin_wrap_variant_specs() -> Vec<String> {
        // The wrap_origin shape (origin -> modulus-1) is OOD-caught on this
        // snapshot whenever the carrier performs memory accesses (the ts1
        // connector observation requires saw_memory_access): re-basing the
        // OnlineMemory origin unbalances the lt-lookup table and hangs or
        // fails verify. The workable shape is a coherent +delta shift
        // propagated across online/offline memory and boundary rows, which
        // keeps every lookup balanced while breaking the declared-origin
        // binding (declared INITIAL_TIMESTAMP=0, actual origin=delta).
        vec!["mode=shift_origin,delta=1".to_string()]
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

        let mut specs = Vec::new();
        for domain in domains {
            if alt_in_range {
                specs.push(format!("mode=flip_sign,domain={domain},guard=alt_in_range"));
            }
            specs.push(format!("mode=flip_sign,domain={domain},guard=none"));
        }

        specs.dedup();
        specs
    }

    fn o15_variant_specs() -> Vec<String> {
        // Duplicate-row shadow flag variant: generate_trace appends an
        // is_valid=0 duplicate of the INT_MIN/-1 divrem row with r_zero=1,
        // satisfying every per-row constraint while breaking the row-vs-
        // execution correspondence (the md2.div_overflow special-case flag
        // lacks an is_valid implication).
        vec!["mode=duplicate_row_shadow_r_zero,search=wildcard".to_string()]
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
            "openvm.semantic.time.boundary_origin_consistency" => {
                Self::timestamp_origin_wrap_variant_specs()
                    .into_iter()
                    .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                    .collect()
            }
            "openvm.semantic.arithmetic.special_case_consistency" => Self::o15_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            _ => vec![inject_kind.to_string()],
        }
    }

    fn monotonic_timestamp_variant_for_hit(hit: &beak_core::trace::BucketHit) -> Option<String> {
        let cell_id = hit.details.get("cell_id")?.as_str()?;
        let previous_timestamp = hit.details.get("previous_timestamp")?.as_u64()?;
        let timestamp = hit.details.get("timestamp")?.as_u64()?;
        let ts_diff = hit.details.get("ts_diff")?.as_u64()?;
        if previous_timestamp >= timestamp || timestamp - previous_timestamp != ts_diff {
            return None;
        }
        let cell_matches = match cell_id {
            "ts2.consecutive" => ts_diff == 1,
            "ts2.small_gap" => ts_diff <= 16,
            "ts2.large_gap" => ts_diff >= 128,
            _ => false,
        };
        cell_matches.then(|| format!("cell_id={cell_id}"))
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
                    false,
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
            } else if bucket_id == semantic::row::PADDING_INTERACTION_SEND.id {
                (
                    semantic::row::PADDING_INTERACTION_SEND.semantic_class,
                    "openvm.semantic.row.padding_interaction_send",
                    InjectionSchedule::AroundAnchor(anchor),
                    false,
                )
            } else if bucket_id == semantic::lookup::BOOLEAN_MULTIPLICITY.id {
                (
                    semantic::lookup::BOOLEAN_MULTIPLICITY.semantic_class,
                    "openvm.semantic.lookup.boolean_multiplicity",
                    InjectionSchedule::AroundAnchor(anchor),
                    false,
                )
            } else if bucket_id == semantic::lookup::XOR_MULTIPLICITY_CONSISTENCY.id {
                (
                    semantic::lookup::XOR_MULTIPLICITY_CONSISTENCY.semantic_class,
                    "openvm.semantic.lookup.xor_multiplicity_consistency",
                    InjectionSchedule::AroundAnchor(anchor),
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
                    false,
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
                // Candidate routing is fail-closed: only the matcher’s typed
                // ts1.standard cell may reach the timestamp-origin hook.
                if hit.details.get("obligation_id").and_then(|value| value.as_str()) != Some("ts1")
                    || hit.details.get("cell_id").and_then(|value| value.as_str())
                        != Some("ts1.standard")
                {
                    return Vec::new();
                }
                (
                    semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.semantic_class,
                    "openvm.semantic.time.boundary_origin_consistency",
                    // The runtime hook observes the connector witness at the
                    // stage-local counter, which is not stable across adapter
                    // rows.  Use the explicit wildcard step so the typed
                    // ts1.standard candidate reaches the genuine hook while
                    // retaining fail-closed identity checks above.
                    InjectionSchedule::Exact(u64::MAX),
                    false,
                )
            } else if bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id {
                (
                    semantic::time::MONOTONIC_ACCESS_ORDERING.semantic_class,
                    "openvm.semantic.time.monotonic_access_ordering",
                    InjectionSchedule::AroundAnchor(anchor),
                    false,
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
        let observed_steps = self
            .last_observed_injection_sites
            .get(base_inject_kind(inject_kind))
            // An observed-site entry may legitimately be present but empty
            // when the baseline only exposed the semantic bucket.  Treat
            // that as "no scheduling hint" so a wildcard candidate keeps
            // its explicit fallback schedule instead of becoming an empty
            // schedule that silently skips semantic search.
            .filter(|steps| !steps.is_empty())
            .map(|steps| Self::ordered_steps_around_anchor(steps, anchor));
        let schedule = observed_steps
            .as_ref()
            .map(|steps| InjectionSchedule::Explicit(steps.clone()))
            .unwrap_or(fallback_schedule);
        let inject_kinds = if inject_kind == "openvm.semantic.memory.immediate_sign_consistency" {
            Self::o8_variant_specs_for_hit(hit)
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect()
        } else if inject_kind == "openvm.semantic.time.monotonic_access_ordering" {
            Self::monotonic_timestamp_variant_for_hit(hit)
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
                schedule: if matches!(
                    inject_kind,
                    "openvm.semantic.alu.immediate_limb_consistency"
                        | "openvm.semantic.arithmetic.special_case_consistency"
                        | "openvm.semantic.lookup.xor_multiplicity_consistency"
                ) {
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
        if bucket_id == semantic::row::PADDING_INTERACTION_SEND.id {
            0
        } else if bucket_id == semantic::lookup::BOOLEAN_MULTIPLICITY.id {
            1
        } else if bucket_id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id
            || bucket_id == semantic::decode::OPERAND_INDEX_ROUTING.id
            || bucket_id == semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.id
        {
            2
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
            3
        } else if bucket_id == semantic::memory::TIMESTAMPED_LOAD_PATH.id
            || bucket_id == semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id
            || bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id
        {
            4
        } else if bucket_id == semantic::alu::SHIFT_MOD32.id
            || bucket_id == semantic::alu::COMPARISON_BOOLEANITY.id
            || bucket_id == semantic::alu::SUBTRACTION_BORROW_CHAIN.id
            || bucket_id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id
            || bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id
            || bucket_id == semantic::arithmetic::PRODUCT_DECOMPOSITION.id
            || bucket_id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id
        {
            5
        } else if bucket_id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id {
            6
        } else if bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id
            || bucket_id == semantic::control::ECALL_WORD_VALIDITY.id
        {
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
        words.iter().all(|w| {
            is_int256_frontend_word(*w)
                || (is_openvm_supported_rv32_word(*w) && RV32IMInstruction::from_word(*w).is_ok())
        })
    }

    fn rv32_oracle_models_words(&self, words: &[u32]) -> bool {
        !words.iter().copied().any(is_int256_frontend_word)
    }

    fn admits_seed_word(&self, word: u32) -> bool {
        is_int256_frontend_word(word) || RV32IMInstruction::from_word(word).is_ok()
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
        self.eval.semantic_mutation_receipt = None;
        self.eval.executed_exception_receipt = None;
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
        self.eval.semantic_mutation_receipt = worker_resp.semantic_mutation_receipt;
        self.eval.executed_exception_receipt = worker_resp.executed_exception_receipt;
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

    fn semantic_mutation_relation(
        &self,
        candidate: &SemanticInjectionCandidate,
    ) -> Option<SemanticMutationRelation> {
        match base_inject_kind(&candidate.inject_kind) {
            "openvm.semantic.alu.immediate_limb_consistency" => {
                Some(SemanticMutationRelation::FullLimbValueRepresentation)
            }
            "openvm.semantic.row.padding_interaction_send" => {
                Some(SemanticMutationRelation::PaddingInteractionSend)
            }
            "openvm.semantic.lookup.xor_multiplicity_consistency" => {
                Some(SemanticMutationRelation::ShadowLookupMultiplicity)
            }
            "openvm.semantic.lookup.boolean_multiplicity" => {
                Some(SemanticMutationRelation::BooleanSourceSelector)
            }
            "openvm.semantic.control.auipc_pc_limb_consistency" => {
                Some(SemanticMutationRelation::AuipcPcLimbRepresentation)
            }
            "openvm.semantic.memory.immediate_sign_consistency" => {
                Some(SemanticMutationRelation::MemoryImmediateSignEquation)
            }
            "openvm.semantic.time.boundary_origin_consistency" => {
                Some(SemanticMutationRelation::TimestampOriginWrap)
            }
            "openvm.semantic.time.monotonic_access_ordering" => {
                Some(SemanticMutationRelation::WitnessValueChanged)
            }
            "openvm.semantic.arithmetic.special_case_consistency" => {
                Some(SemanticMutationRelation::DivisionRemainderSpecialCaseEquation)
            }
            _ => None,
        }
    }

    fn semantic_injection_candidates(
        &self,
        hits: &[beak_core::trace::BucketHit],
    ) -> Vec<SemanticInjectionCandidate> {
        let mut candidates: Vec<_> = hits
            .iter()
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use beak_core::fuzz::benchmark::{InjectionSchedule, SemanticMutationRelation};
    use beak_core::fuzz::bug_filter::has_exact_executed_exception_relation;
    use beak_core::trace::{BucketHit, semantic};
    use serde_json::json;

    use super::{
        BIGINT_BRANCH_GLOBAL_OPCODE, OpenVmBackend, OpenVmFrontend, build_exe,
        bigint_opcode_conversion_failure_response,
    };

    fn valid_bigint_conversion_attempt(step: u64, from_pc: u64) -> serde_json::Value {
        json!({
            "effect": "bigint_opcode_conversion",
            "obligation_id": "id4",
            "cell_id": "id4.branch",
            "stage": "openvm.bigint.branch_less_than_opcode_conversion",
            "trace_source": "extensions/rv32im/circuit/src/branch_lt/core.rs::execute_instruction",
            "conversion_target": "BranchLessThanOpcode",
            "global_opcode": 0x425,
            "chip_class_offset": 0x408,
            "local_opcode": 29,
            "supported_local_opcodes": [0, 1, 2, 3],
            "relation": "local_opcode_not_in_branch_less_than_domain",
            "relation_valid": true,
            "backend": "openvm",
            "commit": "336f1a475e5aa3513c4c5a266399f4128c119bba",
            "from_pc": from_pc,
            "step": step,
            "hook_fired": true,
        })
    }

    fn boundary_hit(cell_id: &str) -> BucketHit {
        BucketHit::semantic(
            semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
            HashMap::from([
                ("obligation_id".to_string(), json!("ts1")),
                ("cell_id".to_string(), json!(cell_id)),
                ("op_idx".to_string(), json!(9)),
            ]),
        )
    }

    fn monotonic_hit(cell_id: &str, previous: u64, timestamp: u64, diff: u64) -> BucketHit {
        BucketHit::semantic(
            semantic::time::MONOTONIC_ACCESS_ORDERING,
            HashMap::from([
                ("cell_id".to_string(), json!(cell_id)),
                ("op_idx".to_string(), json!(9)),
                ("previous_timestamp".to_string(), json!(previous)),
                ("timestamp".to_string(), json!(timestamp)),
                ("ts_diff".to_string(), json!(diff)),
            ]),
        )
    }

    #[test]
    fn timestamp_wrap_routes_only_exact_ts1_origin_hit() {
        let backend = OpenVmBackend::new(8);
        let candidates = backend.semantic_candidate_from_hit(&boundary_hit("ts1.standard"));

        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        match &candidate.schedule {
            InjectionSchedule::Exact(step) => assert_eq!(*step, u64::MAX),
            other => panic!("unexpected schedule: {other:?}"),
        }
        assert!(
            candidate
                .inject_kind
                .ends_with("::mode=shift_origin,delta=1")
        );
        assert!(matches!(
            beak_core::fuzz::benchmark::BenchmarkBackend::semantic_mutation_relation(
                &backend, candidate
            ),
            Some(SemanticMutationRelation::TimestampOriginWrap)
        ));

        assert!(backend.semantic_candidate_from_hit(&boundary_hit("ts3.standard")).is_empty());
        assert!(backend.semantic_candidate_from_hit(&boundary_hit("ts1.after_segment")).is_empty());
    }

    #[test]
    fn timestamp_wrap_keeps_fallback_when_observed_site_list_is_empty() {
        let mut backend = OpenVmBackend::new(8);
        backend
            .last_observed_injection_sites
            .insert("openvm.semantic.time.boundary_origin_consistency".to_string(), Vec::new());
        let candidates = backend.semantic_candidate_from_hit(&boundary_hit("ts1.standard"));
        assert_eq!(candidates.len(), 1);
        assert!(
            matches!(candidates[0].schedule, InjectionSchedule::Exact(step) if step == u64::MAX)
        );
    }

    #[test]
    fn monotonic_timestamp_routes_typed_cell_and_fails_closed_on_bad_geometry() {
        let backend = OpenVmBackend::new(8);
        let candidates =
            backend.semantic_candidate_from_hit(&monotonic_hit("ts2.consecutive", 10, 11, 1));

        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert!(candidate.inject_kind.ends_with("::cell_id=ts2.consecutive"));
        assert!(matches!(
            beak_core::fuzz::benchmark::BenchmarkBackend::semantic_mutation_relation(
                &backend, candidate
            ),
            Some(SemanticMutationRelation::WitnessValueChanged)
        ));

        assert!(
            backend
                .semantic_candidate_from_hit(&monotonic_hit("ts2.consecutive", 10, 12, 2))
                .is_empty()
        );
        assert!(
            backend
                .semantic_candidate_from_hit(&monotonic_hit("ts2.unknown", 10, 11, 1))
                .is_empty()
        );
        assert!(
            backend
                .semantic_candidate_from_hit(&monotonic_hit(
                    "ts2.small_gap",
                    11,
                    10,
                    u32::MAX as u64
                ))
                .is_empty()
        );
    }

    #[test]
    fn memory_sign_variants_route_only_executed_load_or_store_domains() {
        let load_hit = BucketHit::semantic(
            semantic::memory::IMMEDIATE_SIGN_CONSISTENCY,
            HashMap::from([
                ("op_idx".to_string(), json!(3)),
                ("is_load".to_string(), json!(true)),
                ("is_store".to_string(), json!(false)),
                ("alt_ptr_in_range_29".to_string(), json!(true)),
            ]),
        );
        let variants = OpenVmBackend::o8_variant_specs_for_hit(&load_hit);

        assert!(!variants.is_empty());
        assert!(variants.iter().all(|variant| variant.contains("domain=load")));
        assert!(variants.iter().all(|variant| !variant.contains("search=wildcard")));
        assert!(variants.iter().all(|variant| !variant.contains("domain=any")));

        let unsupported = BucketHit::semantic(
            semantic::memory::IMMEDIATE_SIGN_CONSISTENCY,
            HashMap::from([
                ("is_load".to_string(), json!(false)),
                ("is_store".to_string(), json!(false)),
            ]),
        );
        assert!(OpenVmBackend::o8_variant_specs_for_hit(&unsupported).is_empty());
    }

    #[test]
    fn bigint_exception_receipt_requires_exact_concrete_hook_attempt() {
        let response = bigint_opcode_conversion_failure_response(
            7,
            "opaque backend panic".to_string(),
            vec![valid_bigint_conversion_attempt(3, 1)],
        )
        .expect("exact installed-hook attempt must produce typed evidence");
        assert_eq!(response.request_id, 7);
        assert_eq!(response.bucket_hits.len(), 1);
        let hit = &response.bucket_hits[0];
        assert_eq!(hit.bucket_id, semantic::decode::FIELD_RANGE.id);
        assert_eq!(hit.details.get("local_opcode"), Some(&json!(29)));
        assert_eq!(hit.details.get("relation_valid"), Some(&json!(true)));
        assert_eq!(hit.details.get("global_opcode"), Some(&json!(0x425)));
        assert_eq!(hit.details.get("chip_class_offset"), Some(&json!(0x408)));
        assert!(has_exact_executed_exception_relation(
            &response.bucket_hits,
            response.executed_exception_receipt.as_ref(),
        ));
        let receipt =
            response.executed_exception_receipt.expect("typed executed exception receipt");
        assert_eq!(receipt.obligation_id, "id4");
        assert_eq!(receipt.cell_id, "id4.branch");
        assert_eq!(receipt.step, 3);
        assert_eq!(receipt.context.get("from_pc"), Some(&json!(1)));
        assert_eq!(receipt.context.get("local_opcode"), Some(&json!(29)));
        assert_eq!(receipt.context.get("hook_fired"), Some(&json!(true)));
        assert_eq!(
            receipt.context.get("trace_source"),
            Some(&json!(
                "extensions/rv32im/circuit/src/branch_lt/core.rs::execute_instruction"
            ))
        );
    }

    #[test]
    fn bigint_exception_receipt_fails_closed_on_missing_duplicate_or_mismatched_attempts() {
        let classify = |attempts| {
            bigint_opcode_conversion_failure_response(
                8,
                "unrelated or deliberately identical panic text".to_string(),
                attempts,
            )
        };
        assert!(classify(vec![]).is_none(), "non-fired hook must fail closed");
        let valid = valid_bigint_conversion_attempt(0, 7);
        assert!(
            classify(vec![valid.clone(), valid.clone()]).is_none(),
            "duplicate/stale attempts must fail closed"
        );

        for (field, wrong) in [
            ("hook_fired", json!(false)),
            ("global_opcode", json!(0x424)),
            ("chip_class_offset", json!(0x409)),
            ("local_opcode", json!(28)),
            ("supported_local_opcodes", json!([0, 1, 2, 4])),
            ("stage", json!("openvm.bigint.other_stage")),
            ("step", json!(null)),
            ("from_pc", json!(-1)),
            ("trace_source", json!("caller_supplied")),
            ("backend", json!("not-openvm")),
            ("commit", json!("stale")),
            ("obligation_id", json!("id3")),
            ("cell_id", json!("id4.not_branch")),
            ("effect", json!("other_effect")),
            ("relation_valid", json!(false)),
        ] {
            let mut attempt = valid.clone();
            attempt.as_object_mut().unwrap().insert(field.to_string(), wrong);
            assert!(classify(vec![attempt]).is_none(), "field {field} must fail closed");
        }
    }

    #[test]
    fn branch256_family_word_reaches_real_int256_transpiler_opcode() {
        // opcode=0x0b (int256 custom), funct3=0b111 (branch256 family), tag=0 (BLT)
        let words = [0x0000_0013, 0x0000_708b];
        assert_eq!(OpenVmFrontend::detect(&words), OpenVmFrontend::Int256);
        let exe = build_exe(&words, OpenVmFrontend::Int256).expect("generic transpilation");
        let instruction = &exe.program.instructions_and_debug_infos[1]
            .as_ref()
            .expect("branch256 word transpiles")
            .0;
        assert_eq!(instruction.opcode.as_usize() as u64, BIGINT_BRANCH_GLOBAL_OPCODE);

        assert_eq!(
            OpenVmFrontend::detect(&[0x0000_0013, 0x0000_4063]),
            OpenVmFrontend::Rv32,
            "ordinary RV32 signed BLT must remain on the ordinary RV32 frontend"
        );
    }

    #[test]
    fn scoped_o5_and_o15_routes_expose_only_complete_receipt_variants() {
        let backend = OpenVmBackend::new(8);
        assert_eq!(
            OpenVmBackend::o5_variant_specs(),
            [
                "mode=adjacent_radix_carry,carry_slot=0,borrow_slot=1,radix=256,field_modulus=2013265921,limb_count=4"
            ]
        );
        assert_eq!(
            OpenVmBackend::o15_variant_specs(),
            ["mode=duplicate_row_shadow_r_zero,search=wildcard"]
        );

        let o5 = beak_core::fuzz::benchmark::SemanticInjectionCandidate {
            bucket_id: semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id.to_string(),
            trigger_signal_id: None,
            semantic_class: semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.semantic_class.to_string(),
            inject_kind: format!(
                "openvm.semantic.alu.immediate_limb_consistency::{}",
                OpenVmBackend::o5_variant_specs()[0]
            ),
            schedule: InjectionSchedule::Exact(0),
        };
        let o15 = beak_core::fuzz::benchmark::SemanticInjectionCandidate {
            bucket_id: semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id.to_string(),
            trigger_signal_id: None,
            semantic_class: semantic::arithmetic::SPECIAL_CASE_CONSISTENCY
                .semantic_class
                .to_string(),
            inject_kind: format!(
                "openvm.semantic.arithmetic.special_case_consistency::{}",
                OpenVmBackend::o15_variant_specs()[0]
            ),
            schedule: InjectionSchedule::Exact(0),
        };
        assert_eq!(
            beak_core::fuzz::benchmark::BenchmarkBackend::semantic_mutation_relation(&backend, &o5),
            Some(SemanticMutationRelation::FullLimbValueRepresentation)
        );
        assert_eq!(
            beak_core::fuzz::benchmark::BenchmarkBackend::semantic_mutation_relation(
                &backend, &o15
            ),
            Some(SemanticMutationRelation::DivisionRemainderSpecialCaseEquation)
        );

        let o5_hits = backend.semantic_candidate_from_hit(&BucketHit::semantic(
            semantic::alu::IMMEDIATE_LIMB_CONSISTENCY,
            HashMap::from([("op_idx".to_string(), json!(2))]),
        ));
        assert_eq!(o5_hits.len(), 1);
        assert!(matches!(o5_hits[0].schedule, InjectionSchedule::Exact(step) if step == u64::MAX));

        let o15_hits = backend.semantic_candidate_from_hit(&BucketHit::semantic(
            semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
            HashMap::from([("op_idx".to_string(), json!(3))]),
        ));
        assert_eq!(o15_hits.len(), 1);
        assert!(matches!(o15_hits[0].schedule, InjectionSchedule::Exact(step) if step == u64::MAX));
    }

    fn xor_multiplicity_hit() -> BucketHit {
        BucketHit::semantic(
            semantic::lookup::XOR_MULTIPLICITY_CONSISTENCY,
            HashMap::from([
                ("op_idx".to_string(), json!(2)),
                ("step_idx".to_string(), json!(9)),
            ]),
        )
    }

    #[test]
    fn xor_shadow_multiplicity_hit_routes_to_p_plus_one_wildcard_candidate() {
        let backend = OpenVmBackend::new(8);
        let candidates = backend.semantic_candidate_from_hit(&xor_multiplicity_hit());

        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert!(candidate.inject_kind.ends_with("::mode=p_plus_one,rank=0,strength=0"));
        assert!(matches!(
            candidate.schedule,
            InjectionSchedule::Exact(step) if step == u64::MAX
        ));
        assert!(matches!(
            beak_core::fuzz::benchmark::BenchmarkBackend::semantic_mutation_relation(
                &backend, candidate
            ),
            Some(SemanticMutationRelation::ShadowLookupMultiplicity)
        ));
    }

    #[test]
    fn o7_variant_specs_converge_to_installed_hook_slots() {
        let backend = OpenVmBackend::new(8);
        assert_eq!(
            OpenVmBackend::o7_variant_specs(),
            [
                "mode=from_pc_high_single_mod_p,slot=2,strength=0,mult=1",
                "mode=from_pc_high_single_mod_p,slot=3,strength=0,mult=1",
            ]
        );

        let candidates = backend.semantic_candidate_from_hit(&BucketHit::semantic(
            semantic::control::AUIPC_PC_LIMB_CONSISTENCY,
            HashMap::from([("op_idx".to_string(), json!(4))]),
        ));
        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .all(|candidate| candidate.inject_kind.contains("mode=from_pc_high_single_mod_p")));
    }
}
