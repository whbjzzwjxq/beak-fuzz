use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
    SemanticMutationReceipt, SemanticMutationRelation,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{Trace, TraceSignal, semantic};

use crate::trace::OpenVMTrace;
use openvm_circuit::arch::VmExecutor;
use openvm_instructions::LocalOpcode;
use openvm_instructions::SystemOpcode;
use openvm_instructions::exe::VmExe;
use openvm_instructions::instruction::Instruction;
use openvm_instructions::program::Program;
use openvm_instructions::riscv::RV32_REGISTER_AS;
use openvm_rv32im_transpiler::{Rv32ITranspilerExtension, Rv32MTranspilerExtension};
use openvm_sdk::config::{AppConfig, SdkVmConfig};
use openvm_sdk::prover::AppProver;
use openvm_sdk::{F, Sdk, StdIn};
use openvm_transpiler::transpiler::Transpiler;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::Instant;

fn build_sdk() -> Sdk {
    Sdk
}

fn build_vm_config() -> SdkVmConfig {
    let mut vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .build();
    let force_continuations = std::env::var("BEAK_OPENVM_FORCE_CONTINUATIONS")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let force_volatile = std::env::var("BEAK_OPENVM_FORCE_VOLATILE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(!force_continuations);
    let mut sys_cfg = vm_config.system.config.clone().with_max_segment_len(256);
    if force_continuations && !force_volatile {
        sys_cfg = sys_cfg.with_continuations();
    } else {
        sys_cfg = sys_cfg.without_continuations();
    }
    vm_config.system.config = sys_cfg;
    vm_config
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
    Ok(std::sync::Arc::new(VmExe::new(program)))
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
}

const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";
const OPENVM_VOLATILE_POINTER_START: u32 = 0;
const OPENVM_VOLATILE_POINTER_END: u32 = 1 << 29;

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn inject_kind_with_variant(kind: &str, variant: &str) -> String {
    if variant.is_empty() { kind.to_string() } else { format!("{kind}::{variant}") }
}

fn exact_address_space_receipt_hit<'a>(
    hits: &'a [beak_core::trace::BucketHit],
    receipt: &SemanticMutationReceipt,
) -> Option<&'a beak_core::trace::BucketHit> {
    let context = &receipt.effect.context;
    let is_load = context.get("is_load").and_then(|value| value.as_bool())?;
    let is_store = context.get("is_store").and_then(|value| value.as_bool())?;
    if receipt.inject_kind
        != "openvm.semantic.memory.address_space_consistency::mode=bus_mem_as_reg"
        || receipt.effect.relation != SemanticMutationRelation::AddressSpaceConsistencyEquation
        || receipt.site != "rv32_loadstore_adapter.preprocess"
        || receipt.field != "memory_address_space"
        || receipt.before.as_u64() != Some(2)
        || receipt.after.as_u64() != Some(1)
        || context.get("bucket_id").and_then(|value| value.as_str())
            != Some("sem.memory.address_space_consistency")
        || context.get("row_idx").and_then(|value| value.as_u64()) != Some(receipt.step)
        || context.get("mode").and_then(|value| value.as_str()) != Some("bus_mem_as_reg")
        || context.get("is_memory").and_then(|value| value.as_bool()) != Some(true)
        || context.get("register_address_space").and_then(|value| value.as_u64()) != Some(1)
        || context.get("memory_address_space").and_then(|value| value.as_u64()) != Some(2)
        || context.get("address_space_before").and_then(|value| value.as_u64()) != Some(2)
        || context.get("address_space_after").and_then(|value| value.as_u64()) != Some(1)
        || context.get("executed_access").and_then(|value| value.as_bool()) != Some(true)
        || is_load == is_store
    {
        return None;
    }
    let mut matching = hits.iter().filter(|hit| {
        let direction_matches = match hit.details.get("cell_id").and_then(|value| value.as_str()) {
            Some("me5.mem_read") => {
                is_load
                    && !is_store
                    && hit.details.get("is_load").and_then(|value| value.as_bool()) == Some(true)
                    && hit.details.get("is_store").and_then(|value| value.as_bool()) == Some(false)
            }
            Some("me5.mem_write") => {
                !is_load
                    && is_store
                    && hit.details.get("is_load").and_then(|value| value.as_bool()) == Some(false)
                    && hit.details.get("is_store").and_then(|value| value.as_bool()) == Some(true)
            }
            _ => false,
        };
        hit.bucket_id == "sem.memory.address_space_consistency"
            && direction_matches
            && hit.details.get("op_idx").and_then(|value| value.as_u64()) == Some(receipt.step)
            && hit.details.get("trace_source").and_then(|value| value.as_str())
                == Some("memory_access")
            && hit.details.get("address_space").and_then(|value| value.as_u64())
                == Some(1)
    });
    let hit = matching.next()?;
    matching.next().is_none().then_some(hit)
}

pub fn run_backend_once(
    request_id: u64,
    words: &[u32],
    _current_iteration: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<WorkerResponse, String> {
    let mut eval = BackendEval::default();
    fuzzer_utils::configure_witness_injection(inject_kind, inject_step);
    let _ = fuzzer_utils::take_json_logs();

    let t0 = Instant::now();
    let exe = build_exe(words).map_err(|e| {
        eval.backend_error = Some(e.clone());
        e
    })?;
    let _ms_build_exe = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let sdk = build_sdk();
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
        let bytes: [u8; 4] = limbs.map(|x| x.to_string().parse::<u8>().expect("field byte limb"));
        regs[i as usize] = u32::from_le_bytes(bytes);
    }
    eval.final_regs = Some(regs);
    let _ms_read_regs = t3.elapsed().as_millis();

    // Proof-input generation emits connector rows and may apply prover-row mutations.
    // Drain trace logs, applied-site metadata, and typed receipts only after this phase.
    let t4 = Instant::now();
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
    let _ms_prove_verify = t4.elapsed().as_millis();

    let t5 = Instant::now();
    let observed_injection_sites = fuzzer_utils::take_observed_witness_sites();
    let applied_injection_sites = fuzzer_utils::take_applied_witness_sites();
    let mut semantic_mutation_receipt: Option<SemanticMutationReceipt> =
        fuzzer_utils::take_semantic_mutation_receipt()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| format!("invalid semantic mutation receipt: {e}"))?;
    let injection_is_noop_probe =
        inject_kind.map(|kind| kind.contains("mode=noop_probe")).unwrap_or(false);
    let injection_applied = !injection_is_noop_probe
        && inject_kind
            .and_then(|kind| applied_injection_sites.get(base_inject_kind(kind)))
            .map(|steps| {
                if inject_step == u64::MAX {
                    !steps.is_empty()
                } else {
                    steps.contains(&inject_step)
                }
            })
            .unwrap_or(false);
    let logs = fuzzer_utils::take_json_logs();
    let _ms_take_logs = t5.elapsed().as_millis();
    let _logs_len = logs.len();

    let t6 = Instant::now();
    match OpenVMTrace::from_logs(logs) {
        Ok(mut trace) => {
            trace.extend_instruction_local_obligation_hits(words);
            eval.micro_op_count = trace.instruction_count();
            eval.bucket_hits = trace.bucket_hits().to_vec();
            eval.trace_signals = trace.trace_signals().to_vec();
            let _ms_parse = t6.elapsed().as_millis();
        }
        Err(e) => {
            let _ms_parse = t6.elapsed().as_millis();
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
        let hit = if receipt.effect.relation
            == SemanticMutationRelation::AddressSpaceConsistencyEquation
        {
            exact_address_space_receipt_hit(&eval.bucket_hits, receipt)
        } else {
            eval.bucket_hits.iter().find(|hit| {
                hit.bucket_id == bucket_id
                    && hit.details.get("op_idx").and_then(|value| value.as_u64())
                        == Some(receipt.step)
            })
        };
        if let Some(hit) = hit {
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
                // Hook-supplied identity wins: the install hook knows which
                // executed surface it mutated; only fill what it left unset.
                if receipt.effect.context.contains_key(key) {
                    continue;
                }
                if let Some(value) = hit.details.get(key) {
                    receipt.effect.context.insert(key.to_string(), value.clone());
                }
            }
            if receipt.effect.relation
                == SemanticMutationRelation::AddressSpaceConsistencyEquation
            {
                let baseline_cell = if receipt
                    .effect
                    .context
                    .get("is_load")
                    .and_then(|value| value.as_bool())
                    == Some(true)
                {
                    "me5.mem_read"
                } else {
                    "me5.mem_write"
                };
                receipt
                    .effect
                    .context
                    .insert("cell_id".to_string(), serde_json::json!(baseline_cell));
            }
        }
    }

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

    fn detail_u64(hit: &beak_core::trace::BucketHit, key: &str) -> Option<u64> {
        hit.details.get(key).and_then(|v| v.as_u64())
    }

    fn o1_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for mode in ["p_plus_one", "p_plus_mask", "double_modulus_mask"] {
            for rank in 0..30u32 {
                for strength in 0..8u32 {
                    specs.push(format!("mode={mode},rank={rank},strength={strength}"));
                }
            }
        }
        specs
    }

    fn o5_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        let strengths = [0u32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15];
        for mode in ["byte_bias", "neighbor_copy", "sign_echo", "modulus_bias"] {
            for strength in strengths {
                for slot in 0..4u32 {
                    specs.push(format!("mode={mode},slot={slot},strength={strength}"));
                }
            }
        }
        for strength in strengths {
            for slot in [1u32, 2, 3] {
                specs.push(format!("mode=collapse_word,slot={slot},strength={strength}"));
            }
        }
        for strength in strengths {
            specs.push(format!("mode=collapse_word,slot=0,strength={strength}"));
        }
        for strength in strengths {
            specs.push(format!("mode=wide_limb,slot=0,strength={strength}"));
        }
        for strength in strengths {
            for slot in 0..4u32 {
                specs.push(format!("mode=rotate_lane,slot={slot},strength={strength}"));
            }
        }
        specs
    }

    fn o7_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        for mode in [
            "from_pc_high_legacy_pair_inc1",
            "from_pc_high_record_pair_inc1",
            "from_pc_high_single_mod_p",
            "from_pc_high_stagger_mod_p",
            "from_pc_high_double_pair_mod_p",
            "from_pc_high_pair_mod_p",
            "from_pc_high_pair_mod_p_alt",
            "legacy_pair_inc1",
            "record_pair_inc1",
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

    fn o26_variant_specs() -> Vec<String> {
        vec!["mode=wrap_origin,modulus=2013265921,origin=2013265920,increment=1".to_string()]
    }

    fn o25_variant_specs() -> Vec<String> {
        Vec::new()
    }

    fn o25_variant_specs_for_hit(hit: &beak_core::trace::BucketHit) -> Vec<String> {
        let Some(cell_id) = hit.details.get("cell_id").and_then(|value| value.as_str()) else {
            return Vec::new();
        };
        // The volatile-range mutation has a concrete pointer witness hook;
        // address-space-only hits are intentionally fail-closed until a
        // matching prover field is exposed.
        if cell_id != "rc3.volatile_pointer"
            || hit.details.get("is_valid").and_then(|value| value.as_bool()) != Some(true)
        {
            return Vec::new();
        }
        let Some(address_space) = Self::detail_u64(hit, "address_space")
            .or_else(|| Self::detail_u64(hit, "addr_space"))
            .and_then(|value| u32::try_from(value).ok())
        else {
            return Vec::new();
        };
        let Some(pointer) = Self::detail_u64(hit, "pointer")
            .and_then(|value| u32::try_from(value).ok())
            .filter(|pointer| {
                *pointer >= OPENVM_VOLATILE_POINTER_START && *pointer < OPENVM_VOLATILE_POINTER_END
            })
        else {
            return Vec::new();
        };
        let Some(width) = Self::detail_u64(hit, "width")
            .and_then(|value| u32::try_from(value).ok())
            .filter(|width| *width == 1)
        else {
            return Vec::new();
        };
        let Some(volatile_start) = Self::detail_u64(hit, "volatile_start")
            .and_then(|value| u32::try_from(value).ok())
            .filter(|start| *start == OPENVM_VOLATILE_POINTER_START)
        else {
            return Vec::new();
        };
        let Some(volatile_end) = Self::detail_u64(hit, "volatile_end")
            .and_then(|value| u32::try_from(value).ok())
            .filter(|end| *end == OPENVM_VOLATILE_POINTER_END)
        else {
            return Vec::new();
        };
        let Some(row_idx) = Self::detail_u64(hit, "row_idx") else {
            return Vec::new();
        };
        vec![format!(
            "mode=remap_boundary_cell,domain=volatile,guard=outside_range,cell_id={cell_id},row_idx={row_idx},address_space={address_space},pointer={pointer},width={width},forged_address_space={address_space},forged_pointer={OPENVM_VOLATILE_POINTER_END},volatile_start={volatile_start},volatile_end={volatile_end}"
        )]
    }

    fn o51_variant_specs() -> Vec<String> {
        // Keep strict o51 reporting on one deterministic, typed cross-space remap.
        vec!["mode=bus_mem_as_reg".to_string()]
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
            "openvm.semantic.time.boundary_origin_consistency" => Self::o26_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            "openvm.semantic.memory.volatile_boundary_range" => Self::o25_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            "openvm.semantic.memory.address_space_consistency" => Self::o51_variant_specs()
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
        let mut anchor = if bucket_id == semantic::memory::ADDRESS_SPACE_CONSISTENCY.id {
            hit.details
                .get("step_idx")
                .and_then(|v| v.as_u64())
                .or_else(|| hit.details.get("op_idx").and_then(|v| v.as_u64()))
                .unwrap_or(0)
        } else {
            Self::step_from_hit(hit)
        };
        if bucket_id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id {
            if let Some(store_step_idx) =
                hit.details.get("store_step_idx").and_then(|value| value.as_u64())
            {
                anchor = store_step_idx;
            }
        }
        if bucket_id == semantic::memory::VOLATILE_BOUNDARY_RANGE.id {
            let Some(row_idx) = Self::detail_u64(hit, "row_idx") else {
                return Vec::new();
            };
            return Self::o25_variant_specs_for_hit(hit)
                .into_iter()
                .map(|variant| SemanticInjectionCandidate {
                    bucket_id: hit.bucket_id.clone(),
                    trigger_signal_id: Some(
                        TraceSignal::ObservedVolatileBoundaryRange.id().to_string(),
                    ),
                    semantic_class: semantic::memory::VOLATILE_BOUNDARY_RANGE
                        .semantic_class
                        .to_string(),
                    inject_kind: inject_kind_with_variant(
                        "openvm.semantic.memory.volatile_boundary_range",
                        &variant,
                    ),
                    schedule: InjectionSchedule::Exact(row_idx),
                })
                .collect();
        }
        let (semantic_class, inject_kind, fallback_schedule, wildcard_variant) = if bucket_id
            == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id
        {
            (
                semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.semantic_class,
                "openvm.semantic.alu.immediate_limb_consistency",
                InjectionSchedule::AroundAnchor(anchor),
                true,
            )
        } else if bucket_id == semantic::memory::ADDRESS_SPACE_CONSISTENCY.id {
            let typed_memory_cell = match hit.details.get("cell_id").and_then(|value| value.as_str()) {
                Some("me5.mem_read") => {
                    hit.details.get("is_load").and_then(|value| value.as_bool()) == Some(true)
                        && hit.details.get("is_store").and_then(|value| value.as_bool())
                            == Some(false)
                }
                Some("me5.mem_write") => {
                    hit.details.get("is_load").and_then(|value| value.as_bool()) == Some(false)
                        && hit.details.get("is_store").and_then(|value| value.as_bool())
                            == Some(true)
                }
                _ => false,
            };
            let has_executed_identity =
                hit.details.get("trace_source").and_then(|value| value.as_str())
                    == Some("memory_access")
                    && hit.details.get("op_idx").and_then(|value| value.as_u64()).is_some()
                    && hit.details.get("pc").and_then(|value| value.as_u64()).is_some()
                    && hit.details.get("opcode").and_then(|value| value.as_u64()).is_some()
                    && hit.details.get("mnemonic").and_then(|value| value.as_str()).is_some()
                    && hit.details.get("address_space").and_then(|value| value.as_u64()) == Some(2)
                    && hit.details.get("backend").and_then(|value| value.as_str()) == Some("openvm")
                    && hit.details.get("commit").and_then(|value| value.as_str())
                        == Some("f038f61d21db3aecd3029e1a23ba1ba0bb314800");
            if !typed_memory_cell || !has_executed_identity {
                return Vec::new();
            }
            (
                semantic::memory::ADDRESS_SPACE_CONSISTENCY.semantic_class,
                "openvm.semantic.memory.address_space_consistency",
                InjectionSchedule::AroundAnchor(anchor),
                false,
            )
        } else if bucket_id == semantic::memory::IMMEDIATE_SIGN_CONSISTENCY.id {
            (
                semantic::memory::IMMEDIATE_SIGN_CONSISTENCY.semantic_class,
                "openvm.semantic.memory.immediate_sign_consistency",
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
        } else if bucket_id == semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id {
            if hit.details.get("obligation_id").and_then(|value| value.as_str()) != Some("ts1")
                || hit.details.get("cell_id").and_then(|value| value.as_str())
                    != Some("ts1.standard")
                || hit.details.get("trace_source").and_then(|value| value.as_str())
                    != Some("memory_initial_block")
                || Self::detail_u64(hit, "from_timestamp") != Some(0)
            {
                return Vec::new();
            }
            (
                semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.semantic_class,
                "openvm.semantic.time.boundary_origin_consistency",
                InjectionSchedule::Exact(0),
                false,
            )
        } else if bucket_id == semantic::memory::VOLATILE_BOUNDARY_RANGE.id {
            (
                semantic::memory::VOLATILE_BOUNDARY_RANGE.semantic_class,
                "openvm.semantic.memory.volatile_boundary_range",
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
        } else {
            return Vec::new();
        };
        if hit.bucket_id == semantic::control::AUIPC_PC_LIMB_CONSISTENCY.id
            && Self::detail_u64(hit, "from_pc").map(|from_pc| (from_pc >> 24) == 0).unwrap_or(false)
        {
            // For this snapshot family, low-PC AUIPC rows collapse to a unique base-256
            // decomposition, so witness-search variants consistently degrade into OODs
            // instead of real underconstraints. Skip the futile search path.
            return Vec::new();
        }
        let schedule = self
            .last_observed_injection_sites
            .get(base_inject_kind(inject_kind))
            .map(|steps| {
                InjectionSchedule::Explicit(Self::ordered_steps_around_anchor(steps, anchor))
            })
            .unwrap_or(fallback_schedule);
        let inject_kinds = Self::inject_kinds_for_base(inject_kind);
        let mut candidates: Vec<_> = inject_kinds
            .iter()
            .map(|kind| SemanticInjectionCandidate {
                bucket_id: hit.bucket_id.clone(),
                trigger_signal_id: None,
                semantic_class: semantic_class.to_string(),
                inject_kind: kind.clone(),
                schedule: schedule.clone(),
            })
            .collect();
        if inject_kind == "openvm.semantic.alu.immediate_limb_consistency" {
            candidates.extend(
                inject_kinds
                    .iter()
                    .filter(|kind| kind.contains("mode=wide_limb") && kind.contains("slot=0"))
                    .map(|kind| SemanticInjectionCandidate {
                        bucket_id: hit.bucket_id.clone(),
                        trigger_signal_id: None,
                        semantic_class: semantic_class.to_string(),
                        inject_kind: kind.clone(),
                        schedule: InjectionSchedule::Exact(u64::MAX),
                    }),
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
        if bucket_id == semantic::memory::ADDRESS_SPACE_CONSISTENCY.id
            || bucket_id == semantic::memory::VOLATILE_BOUNDARY_RANGE.id
            || bucket_id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id
            || bucket_id == semantic::memory::ADDRESS_BOUNDARY_RANGE.id
            || bucket_id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id
            || bucket_id == semantic::memory::KIND_SELECTOR_CONSISTENCY.id
            || bucket_id == semantic::memory::LOAD_VALUE_BINDING.id
            || bucket_id == semantic::memory::WRITE_PAYLOAD_CONSISTENCY.id
            || bucket_id == semantic::memory::IMMEDIATE_SIGN_CONSISTENCY.id
            || bucket_id == semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id
            || bucket_id == semantic::memory::FINALIZATION_CONSISTENCY.id
            || candidate.trigger_signal_id.as_deref()
                == Some(TraceSignal::ObservedVolatileBoundaryRange.id())
        {
            0
        } else if bucket_id == semantic::lookup::XOR_MULTIPLICITY_CONSISTENCY.id {
            // Prefer explicit bitwise-lookup semantics over generic connector fallback.
            1
        } else if bucket_id == semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id
            || bucket_id == semantic::time::MONOTONIC_ACCESS_ORDERING.id
        {
            2
        } else if bucket_id == semantic::control::AUIPC_PC_LIMB_CONSISTENCY.id {
            3
        } else if bucket_id == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id
            || bucket_id == semantic::alu::SHIFT_MOD32.id
            || bucket_id == semantic::alu::COMPARISON_BOOLEANITY.id
            || bucket_id == semantic::alu::SUBTRACTION_BORROW_CHAIN.id
            || bucket_id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id
            || bucket_id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id
            || bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id
            || bucket_id == semantic::arithmetic::PRODUCT_DECOMPOSITION.id
            || bucket_id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id
        {
            4
        } else {
            5
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
        self.eval.semantic_mutation_receipt = None;
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
            "openvm.semantic.time.boundary_origin_consistency" => {
                Some(SemanticMutationRelation::TimestampOriginWrap)
            }
            "openvm.semantic.memory.volatile_boundary_range" => {
                Some(SemanticMutationRelation::VolatileBoundaryRange)
            }
            "openvm.semantic.memory.address_space_consistency" => {
                Some(SemanticMutationRelation::AddressSpaceConsistencyEquation)
            }
            _ => None,
        }
    }

    fn semantic_injection_candidates(
        &self,
        hits: &[beak_core::trace::BucketHit],
    ) -> Vec<SemanticInjectionCandidate> {
        let mut candidates: Vec<_> =
            hits.iter().flat_map(|hit| self.semantic_candidate_from_hit(hit)).collect();
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
    use std::sync::Mutex;

    use beak_core::fuzz::benchmark::{
        BenchmarkBackend, InjectionSchedule, SemanticMutationReceipt, SemanticMutationRelation,
    };
    use beak_core::trace::{BucketHit, Trace, semantic};
    use serde_json::json;

    use super::{OpenVmBackend, exact_address_space_receipt_hit, run_backend_once};
    use crate::trace::OpenVMTrace;

    static FUZZER_UTILS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn volatile_hit() -> BucketHit {
        BucketHit::semantic(
            semantic::memory::VOLATILE_BOUNDARY_RANGE,
            HashMap::from([
                ("cell_id".to_string(), json!("rc3.volatile_pointer")),
                ("row_idx".to_string(), json!(7)),
                ("op_idx".to_string(), json!(91)),
                ("address_space".to_string(), json!(1)),
                ("pointer".to_string(), json!(16)),
                ("width".to_string(), json!(1)),
                ("volatile_start".to_string(), json!(0)),
                ("volatile_end".to_string(), json!(1u32 << 29)),
                ("is_valid".to_string(), json!(true)),
            ]),
        )
    }

    fn typed_address_space_hit() -> BucketHit {
        BucketHit::semantic(
            semantic::memory::ADDRESS_SPACE_CONSISTENCY,
            HashMap::from([
                ("obligation_id".to_string(), json!("me5")),
                ("cell_id".to_string(), json!("me5.mem_read")),
                ("op_idx".to_string(), json!(3)),
                ("step_idx".to_string(), json!(3)),
                ("pc".to_string(), json!(12)),
                ("opcode".to_string(), json!(0x0000_2083u64)),
                ("mnemonic".to_string(), json!("lw")),
                ("backend".to_string(), json!("openvm")),
                ("commit".to_string(), json!("f038f61d21db3aecd3029e1a23ba1ba0bb314800")),
                ("trace_source".to_string(), json!("memory_access")),
                ("address_space".to_string(), json!(2)),
                ("is_load".to_string(), json!(true)),
                ("is_store".to_string(), json!(false)),
            ]),
        )
    }

    fn typed_address_space_receipt() -> SemanticMutationReceipt {
        serde_json::from_value(json!({
            "inject_kind": concat!(
                "openvm.semantic.memory.address_space_consistency",
                "::mode=bus_mem_as_reg"
            ),
            "site": "rv32_loadstore_adapter.preprocess",
            "field": "memory_address_space",
            "step": 3,
            "before": 2,
            "after": 1,
            "effect": {
                "relation": "address_space_consistency_equation",
                "context": {
                    "bucket_id": "sem.memory.address_space_consistency",
                    "row_idx": 3,
                    "mode": "bus_mem_as_reg",
                    "is_memory": true,
                    "register_address_space": 1,
                    "memory_address_space": 2,
                    "address_space_before": 2,
                    "address_space_after": 1,
                    "is_load": true,
                    "is_store": false,
                    "executed_access": true
                }
            }
        }))
        .expect("typed address-space receipt fixture")
    }

    #[test]
    fn address_space_route_requires_exact_executed_memory_identity() {
        let backend = OpenVmBackend::new(8);
        let candidates = backend.semantic_candidate_from_hit(&typed_address_space_hit());
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].inject_kind.ends_with("::mode=bus_mem_as_reg"));
        assert_eq!(
            backend.semantic_mutation_relation(&candidates[0]),
            Some(SemanticMutationRelation::AddressSpaceConsistencyEquation)
        );

        let mut missing_pc = typed_address_space_hit();
        missing_pc.details.remove("pc");
        assert!(backend.semantic_candidate_from_hit(&missing_pc).is_empty());

        let mut caller_forged_space = typed_address_space_hit();
        caller_forged_space.details.insert("address_space".to_string(), json!(1));
        assert!(backend.semantic_candidate_from_hit(&caller_forged_space).is_empty());

        let mut register_proxy = typed_address_space_hit();
        register_proxy.details.insert("cell_id".to_string(), json!("me5.reg_write"));
        assert!(backend.semantic_candidate_from_hit(&register_proxy).is_empty());

        let mut stale_source = typed_address_space_hit();
        stale_source.details.insert("trace_source".to_string(), json!("decoded_instruction"));
        assert!(backend.semantic_candidate_from_hit(&stale_source).is_empty());

        let mut wrong_backend = typed_address_space_hit();
        wrong_backend.details.insert("backend".to_string(), json!("other"));
        assert!(backend.semantic_candidate_from_hit(&wrong_backend).is_empty());

        let mut wrong_commit = typed_address_space_hit();
        wrong_commit.details.insert("commit".to_string(), json!("stale"));
        assert!(backend.semantic_candidate_from_hit(&wrong_commit).is_empty());

        let mut wrong_direction = typed_address_space_hit();
        wrong_direction.details.insert("is_load".to_string(), json!(false));
        wrong_direction.details.insert("is_store".to_string(), json!(true));
        assert!(backend.semantic_candidate_from_hit(&wrong_direction).is_empty());

        let mut ambiguous_direction = typed_address_space_hit();
        ambiguous_direction.details.insert("is_store".to_string(), json!(true));
        assert!(backend.semantic_candidate_from_hit(&ambiguous_direction).is_empty());
    }

    #[test]
    fn address_space_receipt_enrichment_requires_one_exact_adapter_hit() {
        let receipt = typed_address_space_receipt();
        let mut mutated_memory_hit = typed_address_space_hit();
        mutated_memory_hit.details.insert("address_space".to_string(), json!(1));
        let mut register_proxy = typed_address_space_hit();
        register_proxy.details.insert("cell_id".to_string(), json!("me5.reg_write"));
        register_proxy.details.insert("address_space".to_string(), json!(1));
        let hits = vec![register_proxy, mutated_memory_hit.clone()];
        let matched = exact_address_space_receipt_hit(&hits, &receipt)
            .expect("one exact executed memory-side hit with the mutated bus address space");
        assert_eq!(
            matched.details.get("cell_id").and_then(|value| value.as_str()),
            Some("me5.mem_read")
        );

        assert!(exact_address_space_receipt_hit(&[typed_address_space_hit()], &receipt).is_none());

        let duplicate_hits = vec![mutated_memory_hit.clone(), mutated_memory_hit];
        assert!(exact_address_space_receipt_hit(&duplicate_hits, &receipt).is_none());

        let mut wrong_site = receipt.clone();
        wrong_site.site = "program_execution_trace.generate_trace".to_string();
        assert!(exact_address_space_receipt_hit(&hits, &wrong_site).is_none());

        let mut wrong_step = receipt.clone();
        wrong_step.step = 4;
        assert!(exact_address_space_receipt_hit(&hits, &wrong_step).is_none());

        let mut missing_direction = receipt.clone();
        missing_direction.effect.context.remove("is_load");
        assert!(exact_address_space_receipt_hit(&hits, &missing_direction).is_none());

        let mut forged_direction = receipt.clone();
        forged_direction.effect.context.insert("is_load".to_string(), json!(false));
        forged_direction.effect.context.insert("is_store".to_string(), json!(true));
        assert!(exact_address_space_receipt_hit(&hits, &forged_direction).is_none());

        let mut unchanged = receipt.clone();
        unchanged.after = unchanged.before.clone();
        assert!(exact_address_space_receipt_hit(&hits, &unchanged).is_none());

        let mut nonexecuted = receipt;
        nonexecuted.effect.context.insert("executed_access".to_string(), json!(false));
        assert!(exact_address_space_receipt_hit(&hits, &nonexecuted).is_none());
    }

    #[test]
    fn volatile_candidate_uses_exact_row_and_complete_variant() {
        let backend = OpenVmBackend::new(8);
        let candidates = backend.semantic_candidate_from_hit(&volatile_hit());

        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        match &candidate.schedule {
            InjectionSchedule::Exact(step) => assert_eq!(*step, 7),
            other => panic!("unexpected schedule: {other:?}"),
        }
        for parameter in [
            "mode=remap_boundary_cell",
            "domain=volatile",
            "guard=outside_range",
            "cell_id=rc3.volatile_pointer",
            "row_idx=7",
            "address_space=1",
            "pointer=16",
            "width=1",
            "forged_address_space=1",
            "forged_pointer=536870912",
            "volatile_start=0",
            "volatile_end=536870912",
        ] {
            assert!(candidate.inject_kind.contains(parameter), "missing {parameter}");
        }
        assert!(matches!(
            backend.semantic_mutation_relation(candidate),
            Some(beak_core::fuzz::benchmark::SemanticMutationRelation::VolatileBoundaryRange)
        ));
    }

    #[test]
    fn volatile_candidate_fails_closed_for_incomplete_or_invalid_hit() {
        let backend = OpenVmBackend::new(8);
        let mut missing_width = volatile_hit();
        missing_width.details.remove("width");
        assert!(backend.semantic_candidate_from_hit(&missing_width).is_empty());

        let mut invalid_range = volatile_hit();
        invalid_range.details.insert("volatile_end".to_string(), json!(1u32 << 28));
        assert!(backend.semantic_candidate_from_hit(&invalid_range).is_empty());

        let mut unsupported_cell = volatile_hit();
        unsupported_cell.details.insert("cell_id".to_string(), json!("rc3.near_max"));
        assert!(backend.semantic_candidate_from_hit(&unsupported_cell).is_empty());

        let mut address_space_cell = volatile_hit();
        address_space_cell.details.insert("cell_id".to_string(), json!("rc3.volatile_addr_space"));
        assert!(backend.semantic_candidate_from_hit(&address_space_cell).is_empty());
    }

    #[test]
    fn timestamp_wrap_routes_only_ts1_origin_cell() {
        let backend = OpenVmBackend::new(8);
        let hit = |cell_id: &str| {
            BucketHit::semantic(
                semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
                HashMap::from([
                    ("obligation_id".to_string(), json!("ts1")),
                    ("cell_id".to_string(), json!(cell_id)),
                    ("op_idx".to_string(), json!(0)),
                    ("trace_source".to_string(), json!("memory_initial_block")),
                    ("from_timestamp".to_string(), json!(0)),
                ]),
            )
        };

        let candidates = backend.semantic_candidate_from_hit(&hit("ts1.standard"));
        assert_eq!(candidates.len(), 1);
        match &candidates[0].schedule {
            InjectionSchedule::Exact(step) => assert_eq!(*step, 0),
            other => panic!("unexpected schedule: {other:?}"),
        }
        assert!(
            candidates[0]
                .inject_kind
                .ends_with("::mode=wrap_origin,modulus=2013265921,origin=2013265920,increment=1")
        );
        assert!(backend.semantic_candidate_from_hit(&hit("ts3.standard")).is_empty());

        let mut wrong_source = hit("ts1.standard");
        wrong_source.details.insert("trace_source".to_string(), json!("instruction"));
        assert!(backend.semantic_candidate_from_hit(&wrong_source).is_empty());

        let mut nonzero_origin = hit("ts1.standard");
        nonzero_origin.details.insert("from_timestamp".to_string(), json!(1));
        assert!(backend.semantic_candidate_from_hit(&nonzero_origin).is_empty());
    }

    #[test]
    fn timestamp_origin_emitter_to_backend_handoff_routes_only_zero_origin_ts1() {
        let _guard = FUZZER_UTILS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let backend = OpenVmBackend::new(8);
        let _ = fuzzer_utils::take_json_logs();
        fuzzer_utils::emit_timestamp_boundary_origin(0);
        let trace =
            OpenVMTrace::from_logs(fuzzer_utils::take_json_logs()).expect("zero-origin trace");
        let candidates = backend.semantic_injection_candidates(trace.bucket_hits());
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].bucket_id, semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id);
        assert!(matches!(candidates[0].schedule, InjectionSchedule::Exact(0)));

        fuzzer_utils::emit_timestamp_boundary_origin(1);
        let trace =
            OpenVMTrace::from_logs(fuzzer_utils::take_json_logs()).expect("nonzero-origin trace");
        assert!(backend.semantic_injection_candidates(trace.bucket_hits()).is_empty());
    }

    #[test]
    fn ordinary_worker_baseline_routes_exact_ts1_candidate() {
        let _guard = FUZZER_UTILS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let response = std::thread::Builder::new()
            .name("ordinary-ts1-worker-test".to_string())
            .stack_size(256 * 1024 * 1024)
            .spawn(|| run_backend_once(1, &[0x0010_0013], 0, None, 0))
            .expect("spawn large-stack worker test")
            .join()
            .expect("ordinary worker test thread panicked")
            .expect("ordinary worker baseline must complete");
        assert_eq!(response.backend_error, None);

        let ts1_hits: Vec<_> = response
            .bucket_hits
            .iter()
            .filter(|hit| {
                hit.bucket_id == semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id
                    && hit.details.get("cell_id").and_then(|value| value.as_str())
                        == Some("ts1.standard")
            })
            .collect();
        assert_eq!(
            ts1_hits.len(),
            1,
            "ordinary worker must expose one typed connector TS1 hit; all timestamp hits: {:#?}",
            response
                .bucket_hits
                .iter()
                .filter(|hit| { hit.bucket_id == semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id })
                .collect::<Vec<_>>()
        );

        let backend = OpenVmBackend::new(8);
        let candidates = backend.semantic_injection_candidates(&response.bucket_hits);
        let ts1_candidates: Vec<_> = candidates
            .iter()
            .filter(|candidate| {
                candidate.bucket_id == semantic::time::BOUNDARY_ORIGIN_CONSISTENCY.id
            })
            .collect();
        assert_eq!(ts1_candidates.len(), 1);
        assert!(matches!(ts1_candidates[0].schedule, InjectionSchedule::Exact(0)));
        assert!(
            ts1_candidates[0]
                .inject_kind
                .starts_with("openvm.semantic.time.boundary_origin_consistency::mode=wrap_origin")
        );
    }
}
