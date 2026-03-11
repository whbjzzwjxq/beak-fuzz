use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::Trace;

use crate::trace::OpenVMTrace;
use crate::bucket_id::OpenVMBucketId;
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
use p3_field::PrimeField32;
use openvm_transpiler::transpiler::Transpiler;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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
    eprintln!(
        "[beak-vm-config] force_volatile={} continuation_enabled={}",
        force_volatile,
        vm_config.system.config.continuation_enabled
    );
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

fn is_openvm_supported_rv32_word(word: u32) -> bool {
    let _ = word;
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
    pub backend_error: Option<String>,
    pub observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pub injection_applied: bool,
}

const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";

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

pub fn run_backend_once(
    request_id: u64,
    words: &[u32],
    current_iteration: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<WorkerResponse, String> {
    let t_total = Instant::now();
    let mut eval = BackendEval::default();
    fuzzer_utils::configure_witness_injection(inject_kind, inject_step);
    if let Some(kind) = inject_kind {
        eprintln!(
            "[beak-inject-arm] kind={} step={}",
            kind,
            inject_step
        );
    }
    let _ = fuzzer_utils::take_json_logs();

    let t0 = Instant::now();
    let exe = build_exe(words).map_err(|e| {
        eval.backend_error = Some(e.clone());
        e
    })?;
    let ms_build_exe = t0.elapsed().as_millis();

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
    let app_committed_exe = sdk
        .commit_app_exe(app_pk.app_vm_pk.fri_params, exe.as_ref().clone())
        .map_err(|e| {
            let msg = format!("commit_app_exe failed: {e:?}");
            eval.backend_error = Some(msg.clone());
            msg
        })?;
    let app_vm = VmExecutor::new(app_pk.app_vm_pk.vm_config.clone());
    let ms_instance = t1.elapsed().as_millis();

    let t2 = Instant::now();
    let input = StdIn::default();
    let vm_result = app_vm
        .execute_and_generate_with_cached_program(app_committed_exe.clone(), input)
        .map_err(|e| {
            let msg = format!("execute_and_generate_with_cached_program failed: {e:?}");
            eval.backend_error = Some(msg.clone());
            msg
        })?;
    let ms_trace_only = t2.elapsed().as_millis();

    let t3 = Instant::now();
    let state = vm_result
        .final_memory
        .as_ref()
        .ok_or_else(|| "no final state".to_string())?;
    let mut regs = [0u32; 32];
    for i in 0..32u32 {
        let limbs = state.get_range::<4>(&(RV32_REGISTER_AS, i * 4));
        let bytes: [u8; 4] = limbs.map(|x| x.as_canonical_u32() as u8);
        regs[i as usize] = u32::from_le_bytes(bytes);
    }
    eval.final_regs = Some(regs);
    let ms_read_regs = t3.elapsed().as_millis();

    let t4 = Instant::now();
    let observed_injection_sites = fuzzer_utils::take_observed_witness_sites();
    let applied_injection_sites = fuzzer_utils::take_applied_witness_sites();
    let injection_applied = inject_kind
        .and_then(|kind| applied_injection_sites.get(base_inject_kind(kind)))
        .map(|steps| {
            if inject_step == u64::MAX {
                !steps.is_empty()
            } else {
                steps.contains(&inject_step)
            }
        })
        .unwrap_or(false);
    if let Some(kind) = inject_kind {
        let observed = observed_injection_sites
            .get(base_inject_kind(kind))
            .cloned()
            .unwrap_or_default();
        let applied = applied_injection_sites
            .get(base_inject_kind(kind))
            .cloned()
            .unwrap_or_default();
        eprintln!(
            "[beak-inject-observed] kind={} requested_step={} observed_steps={:?} applied_steps={:?} applied={}",
            kind, inject_step, observed, applied, injection_applied
        );
    }
    let logs = fuzzer_utils::take_json_logs();
    let ms_take_logs = t4.elapsed().as_millis();
    let logs_len = logs.len();

    let t5 = Instant::now();
    match OpenVMTrace::from_logs(logs) {
        Ok(trace) => {
            let insn_count = trace.instructions().len();
            let row_count = trace.chip_rows().len();
            let hit_count = trace.bucket_hits().len();
            eval.micro_op_count = trace.instruction_count();
            eval.bucket_hits = trace.bucket_hits().to_vec();
            let ms_parse = t5.elapsed().as_millis();
            eprintln!(
                "[openvm-backend-worker] iter={} logs_len={logs_len} insn_count={insn_count} chip_rows={row_count} bucket_hits={hit_count} build_exe_ms={ms_build_exe} instance_ms={ms_instance} trace_only_ms={ms_trace_only} read_regs_ms={ms_read_regs} take_logs_ms={ms_take_logs} parse_ms={ms_parse} total_ms={}",
                current_iteration,
                t_total.elapsed().as_millis()
            );
        }
        Err(e) => {
            let ms_parse = t5.elapsed().as_millis();
            eval.backend_error = Some(e.clone());
            eprintln!(
                "[openvm-backend-worker] iter={} ERROR parse_logs ({e}); logs_len={logs_len} build_exe_ms={ms_build_exe} instance_ms={ms_instance} trace_only_ms={ms_trace_only} read_regs_ms={ms_read_regs} take_logs_ms={ms_take_logs} parse_ms={ms_parse} total_ms={}",
                current_iteration,
                t_total.elapsed().as_millis()
            );
        }
    }

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
            eval.backend_error = Some(format!(
                "verify_app_proof_without_continuations failed: {e:?}"
            ));
        }
    }
    let ms_prove_verify = t6.elapsed().as_millis();
    eprintln!(
        "[openvm-backend-worker] iter={} prove_verify_ms={ms_prove_verify}",
        current_iteration
    );

    Ok(WorkerResponse {
        request_id,
        final_regs: eval.final_regs,
        micro_op_count: eval.micro_op_count,
        bucket_hits: eval.bucket_hits,
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
    timeout_ms: u64,
    eval: BackendEval,
    last_words: Vec<u32>,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    current_iteration: u64,
    next_request_id: u64,
    pending_injection: Option<WitnessInjectionPlan>,
    worker: Option<WorkerProcess>,
}

impl OpenVmBackend {
    pub fn new(max_instructions: usize, timeout_ms: u64) -> Self {
        Self {
            max_instructions,
            timeout_ms,
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
        let mut specs = Vec::new();
        specs.push("mode=shift_origin,delta=1".to_string());
        for rank in 0..420u32 {
            specs.push(format!("mode=noop_probe,rank={rank}"));
        }
        specs
    }

    fn o25_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        specs.push("mode=aux_decomp,strength=29".to_string());
        for rank in 0..32u32 {
            specs.push(format!("mode=noop_probe,rank={rank}"));
        }
        specs
    }

    fn o51_variant_specs() -> Vec<String> {
        let mut specs = Vec::new();
        specs.push("mode=bus_mem_as_other".to_string());
        specs.push("mode=bus_mem_as_reg".to_string());
        for rank in 0..32u32 {
            specs.push(format!("mode=noop_probe,rank={rank}"));
        }
        specs.push("mode=bus_mem_as_zero".to_string());
        specs
    }

    fn inject_kinds_for_base(inject_kind: &str) -> Vec<String> {
        match inject_kind {
            "openvm.audit_o1.bitwise_mult_p_plus_1" => Self::o1_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            "openvm.audit_o5.rs2_imm_limbs" => Self::o5_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            "openvm.audit_o7.auipc_pc_limbs" => Self::o7_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            "openvm.audit_o26.connector_start_ts" => Self::o26_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            "openvm.audit_o25.volatile_addr_range" => Self::o25_variant_specs()
                .into_iter()
                .map(|variant| inject_kind_with_variant(inject_kind, &variant))
                .collect(),
            "openvm.audit_o51.loadstore_mem_as" => Self::o51_variant_specs()
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
        let anchor = Self::step_from_hit(hit);
        let (semantic_class, inject_kind, fallback_schedule, wildcard_variant) = match hit.bucket_id.as_str() {
            "openvm.sem.alu.immediate_limb_consistency" => (
                "openvm.semantic.alu.immediate_limb_consistency",
                "openvm.audit_o5.rs2_imm_limbs",
                InjectionSchedule::AroundAnchor(anchor),
                true,
            ),
            "openvm.sem.memory.address_space_consistency" => (
                "openvm.semantic.memory.address_space_consistency",
                "openvm.audit_o51.loadstore_mem_as",
                InjectionSchedule::AroundAnchor(anchor),
                true,
            ),
            "openvm.sem.time.boundary_origin_consistency" => (
                "openvm.semantic.time.boundary_origin_consistency",
                "openvm.audit_o26.connector_start_ts",
                InjectionSchedule::Exact(0),
                true,
            ),
            "openvm.sem.memory.volatile_boundary_range" => (
                "openvm.semantic.memory.volatile_boundary_range",
                "openvm.audit_o25.volatile_addr_range",
                InjectionSchedule::AroundAnchor(anchor),
                true,
            ),
            "openvm.interaction.bitwise.op_xor" => (
                "openvm.semantic.lookup.multiplicity_consistency",
                "openvm.audit_o1.bitwise_mult_p_plus_1",
                InjectionSchedule::Exact(0),
                false,
            ),
            "openvm.sem.control.auipc_pc_limb_consistency" => (
                "openvm.semantic.control.auipc_pc_limb_consistency",
                "openvm.audit_o7.auipc_pc_limbs",
                InjectionSchedule::AroundAnchor(anchor),
                true,
            ),
            _ => return Vec::new(),
        };
        if hit.bucket_id == "openvm.sem.control.auipc_pc_limb_consistency"
            && Self::detail_u64(hit, "from_pc")
                .map(|from_pc| (from_pc >> 24) == 0)
                .unwrap_or(false)
        {
            // For this snapshot family, low-PC AUIPC rows collapse to a unique base-256
            // decomposition, so witness-search variants consistently degrade into OODs
            // instead of real underconstraints. Skip the futile search path.
            return Vec::new();
        }
        let schedule = self
            .last_observed_injection_sites
            .get(base_inject_kind(inject_kind))
            .map(|steps| InjectionSchedule::Explicit(Self::ordered_steps_around_anchor(steps, anchor)))
            .unwrap_or(fallback_schedule);
        let inject_kinds = Self::inject_kinds_for_base(inject_kind);
        let mut candidates: Vec<_> = inject_kinds
            .iter()
            .map(|kind| SemanticInjectionCandidate {
                bucket_id: hit.bucket_id.clone(),
                semantic_class: semantic_class.to_string(),
                inject_kind: kind.clone(),
                schedule: schedule.clone(),
            })
            .collect();
        if inject_kind == "openvm.audit_o5.rs2_imm_limbs" {
            candidates.extend(inject_kinds.iter().filter(|kind| {
                kind.contains("mode=wide_limb") && kind.contains("slot=0")
            }).map(|kind| SemanticInjectionCandidate {
                bucket_id: hit.bucket_id.clone(),
                semantic_class: semantic_class.to_string(),
                inject_kind: kind.clone(),
                schedule: InjectionSchedule::Exact(u64::MAX),
            }));
        }
        if wildcard_variant && inject_kinds.len() == 1 {
            candidates.push(SemanticInjectionCandidate {
                bucket_id: hit.bucket_id.clone(),
                semantic_class: semantic_class.to_string(),
                inject_kind: inject_kind.to_string(),
                schedule: InjectionSchedule::Exact(u64::MAX),
            });
        }
        candidates
    }

    fn semantic_candidate_priority(candidate: &SemanticInjectionCandidate) -> u8 {
        match candidate.bucket_id.as_str() {
            "openvm.sem.memory.address_space_consistency" => 0,
            "openvm.sem.memory.volatile_boundary_range" => 0,
            "openvm.synthetic.observed.volatile_boundary_range" => 0,
            // Prefer explicit bitwise-lookup semantics over generic connector fallback.
            "openvm.interaction.bitwise.op_xor" => 1,
            "openvm.sem.time.boundary_origin_consistency" => 2,
            "openvm.sem.control.auipc_pc_limb_consistency" => 3,
            "openvm.sem.alu.immediate_limb_consistency" => 4,
            _ => 5,
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

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "capture backend worker stdin failed".to_string())?;
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

        self.worker = Some(WorkerProcess {
            child,
            stdin,
            responses_rx: rx,
            reader_thread,
        });
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
        let timeout = Duration::from_millis(self.timeout_ms);
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
            let worker = self
                .worker
                .as_mut()
                .ok_or_else(|| "backend worker unavailable".to_string())?;
            let mut payload =
                serde_json::to_vec(&req).map_err(|e| format!("serialize worker request failed: {e}"))?;
            payload.push(b'\n');
            worker
                .stdin
                .write_all(&payload)
                .map_err(|e| format!("write worker request failed: {e}"))?;
            worker
                .stdin
                .flush()
                .map_err(|e| format!("flush worker request failed: {e}"))?;
        }

        let started = Instant::now();
        let worker_resp = loop {
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                self.stop_worker();
                let msg = format!(
                    "backend trace build timed out after {} ms (worker killed)",
                    self.timeout_ms
                );
                self.eval.backend_error = Some(msg.clone());
                return Err(msg);
            }

            let remaining = timeout - elapsed;
            let recv = {
                let worker = self
                    .worker
                    .as_ref()
                    .ok_or_else(|| "backend worker unavailable".to_string())?;
                worker.responses_rx.recv_timeout(remaining)
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
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.stop_worker();
                    let msg = format!(
                        "backend trace build timed out after {} ms (worker killed)",
                        self.timeout_ms
                    );
                    self.eval.backend_error = Some(msg.clone());
                    return Err(msg);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.stop_worker();
                    let msg = "backend worker disconnected".to_string();
                    self.eval.backend_error = Some(msg.clone());
                    return Err(msg);
                }
            }
        };

        self.eval.micro_op_count = worker_resp.micro_op_count;
        self.eval.bucket_hits = worker_resp.bucket_hits;
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
        // Input-level buckets help guide seed evolution, even when the backend rejects or
        // does not fully model certain instruction classes.
        let details = HashMap::new();
        let mut saw_ecall = false;
        let mut saw_loadstore = false;
        for &w in &self.last_words {
            let opcode = w & 0x7f;
            if opcode == 0x03 || opcode == 0x23 {
                saw_loadstore = true;
            }
            if opcode != 0x73 {
                continue;
            }
            if let Ok(insn) = RV32IMInstruction::from_word(w) {
                match insn.mnemonic.as_str() {
                    "ecall" | "ebreak" => saw_ecall = true,
                    _ => {}
                }
            }
        }
        if saw_ecall {
            self.eval.bucket_hits.push(beak_core::trace::BucketHit::new(
                OpenVMBucketId::InputHasEcall.as_ref().to_string(),
                details.clone(),
            ));
        }
        if saw_loadstore {
            self.eval.bucket_hits.push(beak_core::trace::BucketHit::new(
                OpenVMBucketId::InputHasLoadStore.as_ref().to_string(),
                details.clone(),
            ));
        }

        self.eval.clone()
    }

    fn clear_semantic_injection(&mut self) {
        self.pending_injection = None;
    }

    fn arm_semantic_injection(&mut self, kind: &str, step: u64) -> Result<(), String> {
        self.pending_injection = Some(WitnessInjectionPlan {
            kind: kind.to_string(),
            step,
        });
        Ok(())
    }

    fn semantic_injection_candidates(
        &self,
        hits: &[beak_core::trace::BucketHit],
    ) -> Vec<SemanticInjectionCandidate> {
        let mut candidates: Vec<_> = hits
            .iter()
            .flat_map(|hit| self.semantic_candidate_from_hit(hit))
            .collect();
        let has_o25_candidate = candidates.iter().any(|candidate| {
            candidate.semantic_class == "openvm.semantic.memory.volatile_boundary_range"
        });
        if !has_o25_candidate {
            if let Some(steps) = self
                .last_observed_injection_sites
                .get("openvm.audit_o25.volatile_addr_range")
            {
                let schedule =
                    InjectionSchedule::Explicit(Self::ordered_steps_around_anchor(steps, 0));
                candidates.extend(
                    Self::inject_kinds_for_base("openvm.audit_o25.volatile_addr_range")
                        .into_iter()
                        .map(|inject_kind| SemanticInjectionCandidate {
                            bucket_id: "openvm.synthetic.observed.volatile_boundary_range"
                                .to_string(),
                            semantic_class:
                                "openvm.semantic.memory.volatile_boundary_range".to_string(),
                            inject_kind,
                            schedule: schedule.clone(),
                        }),
                );
            }
        }
        candidates.sort_by_key(Self::semantic_candidate_priority);
        candidates
    }
}

impl Drop for OpenVmBackend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}
