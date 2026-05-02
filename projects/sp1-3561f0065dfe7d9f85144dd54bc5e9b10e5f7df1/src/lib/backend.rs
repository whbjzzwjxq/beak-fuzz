use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};
use sp1_core::runtime::Runtime;
use sp1_core::utils::{run_test, SP1CoreOpts};
use sp1_sdk::{ProverClient, SP1Proof, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

use crate::insn::Sp1Insn;
use crate::trace::{build_sp1_program, Sp1Trace};

pub const DIV_REM_BOUND_INJECT_KIND: &str =
    "sp1.semantic.arithmetic.division_remainder_bound::mode=decrement_quotient_increment_remainder";
const DIV_REM_BOUND_BASE_KIND: &str = "sp1.semantic.arithmetic.division_remainder_bound";
const TIMESTAMPED_LOAD_INJECT_KIND: &str = "sp1.semantic.memory.timestamped_load_path";
const LOOKUP_BOOLEAN_INJECT_KIND: &str = "sp1.semantic.lookup.boolean_multiplicity";
const RF1_INJECT_KIND: &str = "sp1.semantic.decode.zero_register_immutability";
const RF2_INJECT_KIND: &str = "sp1.semantic.decode.operand_index_routing";
const RF3_INJECT_KIND: &str = "sp1.semantic.exec.dest_binding";
const ID1_INJECT_KIND: &str = "sp1.semantic.decode.field_range";
const ID2_INJECT_KIND: &str = "sp1.semantic.decode.immediate_sign_extension";
const ID4_INJECT_KIND: &str = "sp1.semantic.exec.op_selector_binding";
const ID5_INJECT_KIND: &str = "sp1.semantic.decode.format_immediate_reassembly";
const AL1_INJECT_KIND: &str = "sp1.semantic.alu.immediate_limb_consistency";
const AL2_INJECT_KIND: &str = "sp1.semantic.alu.shift_mod32";
const AL3_INJECT_KIND: &str = "sp1.semantic.alu.comparison_booleanity";
const AL4_INJECT_KIND: &str = "sp1.semantic.alu.subtraction_borrow_chain";
const AL5_INJECT_KIND: &str = "sp1.semantic.alu.comparison_auxiliary_chain";
const MD_SPECIAL_INJECT_KIND: &str = "sp1.semantic.arithmetic.special_case_consistency";
const MD4_INJECT_KIND: &str = "sp1.semantic.arithmetic.product_decomposition";
const MD5_INJECT_KIND: &str = "sp1.semantic.arithmetic.signed_unsigned_product_correction";
const PROGRAM_CARGO_TOML: &str = r#"[workspace]
[package]
name = "beak-uint256-div"
version = "0.1.0"
edition = "2021"

[dependencies]
sp1-zkvm = { path = "../../zkvm/entrypoint" }
sp1-derive = { path = "../../derive" }
"#;
const PROGRAM_MAIN_RS: &str = r#"#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::io;
use sp1_zkvm::precompiles::uint256_div::uint256_div;

fn main() {
    let mut dividend = io::read::<[u8; 32]>();
    let divisor = io::read::<[u8; 32]>();
    let quotient = uint256_div(&mut dividend, &divisor);
    io::commit(&quotient);
}
"#;

#[derive(Debug, Clone, Serialize)]
pub struct SupportedBucket {
    pub bucket_id: &'static str,
    pub semantic_class: &'static str,
    pub inject_kind: &'static str,
    pub default_step: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioRun {
    pub inject_kind: Option<String>,
    pub inject_step: u64,
    pub quotient_bytes: Vec<u8>,
    pub proof_verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioComparison {
    pub bucket: SupportedBucket,
    pub baseline: ScenarioRun,
    pub injected: ScenarioRun,
    pub diverged: bool,
    pub underconstrained_candidate: bool,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long, default_value_t = 7)]
    dividend: u64,
    #[arg(long, default_value_t = 3)]
    divisor: u64,
    #[arg(long)]
    inject_kind: Option<String>,
    #[arg(long, default_value_t = 0)]
    inject_step: u64,
    #[arg(long, action = ArgAction::SetTrue)]
    print_buckets: bool,
    #[arg(long)]
    search_steps_max: Option<u64>,
    #[arg(long, action = ArgAction::SetTrue)]
    json: bool,
}

struct EnvGuard {
    saved_kind: Option<String>,
    saved_step: Option<String>,
    saved_run_id: Option<String>,
    saved_prover: Option<String>,
}

#[derive(Debug, Clone)]
struct WitnessInjectionPlan {
    kind: String,
    step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub request_id: u64,
    pub words: Vec<u32>,
    pub iteration: u64,
    #[serde(default)]
    pub inject_kind: Option<String>,
    #[serde(default)]
    pub inject_step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub request_id: u64,
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

fn supports_old_runtime_unreportable_injection_kind(kind: &str) -> bool {
    matches!(base_inject_kind(kind), TIMESTAMPED_LOAD_INJECT_KIND | LOOKUP_BOOLEAN_INJECT_KIND)
}

fn supports_cpu_row_injection_kind(kind: &str) -> bool {
    matches!(
        base_inject_kind(kind),
        RF1_INJECT_KIND
            | RF2_INJECT_KIND
            | RF3_INJECT_KIND
            | ID1_INJECT_KIND
            | ID2_INJECT_KIND
            | ID4_INJECT_KIND
            | ID5_INJECT_KIND
            | AL1_INJECT_KIND
            | AL2_INJECT_KIND
            | AL3_INJECT_KIND
            | AL4_INJECT_KIND
            | AL5_INJECT_KIND
            | MD_SPECIAL_INJECT_KIND
            | DIV_REM_BOUND_BASE_KIND
            | MD4_INJECT_KIND
            | MD5_INJECT_KIND
    )
}

fn inject_kind_with_variant(kind: &str, variant: &str) -> String {
    if variant.is_empty() {
        kind.to_string()
    } else {
        format!("{kind}::{variant}")
    }
}

fn run_words_runtime(words: &[u32]) -> Result<(Sp1Trace, [u32; 32]), String> {
    let program = build_sp1_program(words)?;
    let mut runtime = Runtime::new(program, SP1CoreOpts::default());
    runtime.run().map_err(|e| format!("sp1 runtime run failed: {e}"))?;
    let mut records = vec![std::mem::take(&mut runtime.record)];
    let regs = runtime.registers();
    let trace = Sp1Trace::from_execution_records(words, &records)?;
    records.clear();
    Ok((trace, regs))
}

fn record_site(sites: &mut BTreeMap<String, Vec<u64>>, kind: &str, step: u64) {
    let steps = sites.entry(kind.to_string()).or_default();
    if steps.last().copied() != Some(step) {
        steps.push(step);
    }
}

fn collect_cpu_row_injection_sites(instructions: &[Sp1Insn]) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::new();
    for insn in instructions {
        let step = insn.step_idx;
        for kind in [
            RF1_INJECT_KIND,
            RF2_INJECT_KIND,
            RF3_INJECT_KIND,
            ID1_INJECT_KIND,
            ID2_INJECT_KIND,
            ID4_INJECT_KIND,
            ID5_INJECT_KIND,
        ] {
            record_site(&mut sites, kind, step);
        }
        match insn.mnemonic.as_str() {
            "addi" | "xori" | "ori" | "andi" => {
                record_site(&mut sites, AL1_INJECT_KIND, step);
            }
            "slli" | "srli" | "srai" => {
                record_site(&mut sites, AL1_INJECT_KIND, step);
                record_site(&mut sites, AL2_INJECT_KIND, step);
            }
            "sll" | "srl" | "sra" => {
                record_site(&mut sites, AL2_INJECT_KIND, step);
            }
            "slti" | "sltiu" => {
                record_site(&mut sites, AL1_INJECT_KIND, step);
                record_site(&mut sites, AL3_INJECT_KIND, step);
                record_site(&mut sites, AL4_INJECT_KIND, step);
                record_site(&mut sites, AL5_INJECT_KIND, step);
            }
            "slt" | "sltu" => {
                record_site(&mut sites, AL3_INJECT_KIND, step);
                record_site(&mut sites, AL4_INJECT_KIND, step);
                record_site(&mut sites, AL5_INJECT_KIND, step);
            }
            "sub" => {
                record_site(&mut sites, AL4_INJECT_KIND, step);
            }
            "div" | "divu" | "rem" | "remu" => {
                record_site(&mut sites, MD_SPECIAL_INJECT_KIND, step);
                record_site(&mut sites, DIV_REM_BOUND_BASE_KIND, step);
            }
            "mul" | "mulh" | "mulhu" => {
                record_site(&mut sites, MD4_INJECT_KIND, step);
            }
            "mulhsu" => {
                record_site(&mut sites, MD4_INJECT_KIND, step);
                record_site(&mut sites, MD5_INJECT_KIND, step);
            }
            _ => {}
        }
    }
    sites
}

fn resolve_cpu_row_injection_step(
    inject_kind: Option<&str>,
    inject_step: u64,
    observed_injection_sites: &BTreeMap<String, Vec<u64>>,
) -> Option<u64> {
    let kind = inject_kind?;
    if !supports_cpu_row_injection_kind(kind) {
        return None;
    }
    let steps = observed_injection_sites.get(base_inject_kind(kind))?;
    if inject_step == u64::MAX {
        steps.first().copied()
    } else if steps.contains(&inject_step) {
        Some(inject_step)
    } else {
        None
    }
}

fn panic_payload_to_string(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn run_cpu_row_prove_smoke(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: Option<u64>,
) -> (Option<String>, bool) {
    let Some(kind) = inject_kind.filter(|kind| supports_cpu_row_injection_kind(kind)) else {
        return (None, false);
    };
    let Some(step) = inject_step else {
        return (None, false);
    };
    let program = match build_sp1_program(words) {
        Ok(program) => program,
        Err(e) => return (Some(e), false),
    };
    let kind = kind.to_string();
    let worker = thread::Builder::new()
        .name("sp1-356-cpu-row-prove".to_string())
        .stack_size(128 * 1024 * 1024)
        .spawn(move || {
            let _guard = EnvGuard::arm(Some(kind.as_str()), step);
            fuzzer_utils::configure_witness_injection(Some(kind.as_str()), step);
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_test(program)));
            let applied = fuzzer_utils::injection_was_applied();
            fuzzer_utils::configure_witness_injection(None, 0);
            match result {
                Ok(Ok(_)) => (None, applied),
                Ok(Err(e)) => (Some(format!("sp1 run_test prove/verify failed: {e}")), applied),
                Err(p) => (
                    Some(format!(
                        "sp1 run_test prove/verify panicked: {}",
                        panic_payload_to_string(p.as_ref())
                    )),
                    applied,
                ),
            }
        });
    match worker {
        Ok(handle) => match handle.join() {
            Ok(result) => result,
            Err(_) => (Some("sp1 CPU-row proof worker panicked".to_string()), false),
        },
        Err(e) => (Some(format!("failed to spawn SP1 CPU-row proof worker: {e}")), false),
    }
}

pub fn run_backend_once(
    request_id: u64,
    words: &[u32],
    _current_iteration: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<WorkerResponse, String> {
    let (trace, regs) = run_words_runtime(words)?;
    let mut backend_error = None;
    let observed_injection_sites = collect_cpu_row_injection_sites(trace.instructions());
    let mut injection_applied = false;
    if let Some(kind) = inject_kind {
        if supports_cpu_row_injection_kind(kind) {
            let resolved_step =
                resolve_cpu_row_injection_step(Some(kind), inject_step, &observed_injection_sites);
            let (proof_error, applied) = run_cpu_row_prove_smoke(words, Some(kind), resolved_step);
            backend_error = proof_error;
            injection_applied = applied;
            if resolved_step.is_none() {
                backend_error = Some(format!(
                    "sp1-3561f006 did not observe CPU-row injection site for {kind} at requested step {inject_step}"
                ));
            }
        } else if supports_old_runtime_unreportable_injection_kind(kind) {
            backend_error = Some(format!(
                "sp1-3561f006 has installed hook {kind}, but this old fuzzer_utils path does not report applied-site metadata; backend candidates are disabled"
            ));
        }
    }

    Ok(WorkerResponse {
        request_id,
        final_regs: Some(regs),
        micro_op_count: trace.instruction_count(),
        bucket_hits: trace.bucket_hits().to_vec(),
        trace_signals: trace.trace_signals().to_vec(),
        backend_error,
        observed_injection_sites,
        injection_applied,
    })
}

pub struct Sp1Backend {
    max_instructions: usize,
    eval: BackendEval,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pending_injection: Option<WitnessInjectionPlan>,
    current_iteration: u64,
}

impl Sp1Backend {
    pub fn new(max_instructions: usize) -> Self {
        Self {
            max_instructions,
            eval: BackendEval::default(),
            last_observed_injection_sites: BTreeMap::new(),
            pending_injection: None,
            current_iteration: 0,
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
        hit.details
            .get("op_idx")
            .and_then(|v| v.as_u64())
            .or_else(|| hit.details.get("step_idx").and_then(|v| v.as_u64()))
            .unwrap_or(0)
    }

    fn mnemonic_from_hit(hit: &BucketHit) -> Option<&str> {
        hit.details.get("mnemonic").and_then(|value| value.as_str())
    }

    fn semantic_candidate_from_hit(&self, hit: &BucketHit) -> Vec<SemanticInjectionCandidate> {
        let anchor = Self::step_from_hit(hit);
        let bucket_id = hit.bucket_id.as_str();
        let (semantic_class, inject_kind, schedule_lookup_key) = if bucket_id
            == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id
        {
            (
                semantic::decode::ZERO_REGISTER_IMMUTABILITY.semantic_class.to_string(),
                inject_kind_with_variant(RF1_INJECT_KIND, "site=op_a_access"),
                RF1_INJECT_KIND,
            )
        } else if bucket_id == semantic::decode::OPERAND_INDEX_ROUTING.id {
            (
                semantic::decode::OPERAND_INDEX_ROUTING.semantic_class.to_string(),
                inject_kind_with_variant(RF2_INJECT_KIND, "site=op_b_access"),
                RF2_INJECT_KIND,
            )
        } else if bucket_id == semantic::exec::DEST_BINDING.id {
            (
                semantic::exec::DEST_BINDING.semantic_class.to_string(),
                inject_kind_with_variant(RF3_INJECT_KIND, "site=op_a_access"),
                RF3_INJECT_KIND,
            )
        } else if bucket_id == semantic::decode::FIELD_RANGE.id {
            (
                semantic::decode::FIELD_RANGE.semantic_class.to_string(),
                inject_kind_with_variant(ID1_INJECT_KIND, "site=instruction_op_a"),
                ID1_INJECT_KIND,
            )
        } else if bucket_id == semantic::decode::IMMEDIATE_SIGN_EXTENSION.id {
            (
                semantic::decode::IMMEDIATE_SIGN_EXTENSION.semantic_class.to_string(),
                inject_kind_with_variant(ID2_INJECT_KIND, "site=instruction_op_c"),
                ID2_INJECT_KIND,
            )
        } else if bucket_id == semantic::exec::OP_SELECTOR_BINDING.id {
            (
                semantic::exec::OP_SELECTOR_BINDING.semantic_class.to_string(),
                inject_kind_with_variant(ID4_INJECT_KIND, "site=opcode"),
                ID4_INJECT_KIND,
            )
        } else if bucket_id == semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.id {
            (
                semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY.semantic_class.to_string(),
                inject_kind_with_variant(ID5_INJECT_KIND, "site=instruction_op_c"),
                ID5_INJECT_KIND,
            )
        } else if bucket_id == semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.id {
            let Some(mnemonic) = Self::mnemonic_from_hit(hit) else {
                return Vec::new();
            };
            if !matches!(
                mnemonic,
                "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai"
            ) {
                return Vec::new();
            }
            (
                semantic::alu::IMMEDIATE_LIMB_CONSISTENCY.semantic_class.to_string(),
                AL1_INJECT_KIND.to_string(),
                AL1_INJECT_KIND,
            )
        } else if bucket_id == semantic::alu::SHIFT_MOD32.id {
            (
                semantic::alu::SHIFT_MOD32.semantic_class.to_string(),
                AL2_INJECT_KIND.to_string(),
                AL2_INJECT_KIND,
            )
        } else if bucket_id == semantic::alu::COMPARISON_BOOLEANITY.id {
            (
                semantic::alu::COMPARISON_BOOLEANITY.semantic_class.to_string(),
                AL3_INJECT_KIND.to_string(),
                AL3_INJECT_KIND,
            )
        } else if bucket_id == semantic::alu::SUBTRACTION_BORROW_CHAIN.id {
            let Some(mnemonic) = Self::mnemonic_from_hit(hit) else {
                return Vec::new();
            };
            if !matches!(mnemonic, "sub" | "slt" | "slti" | "sltu" | "sltiu") {
                return Vec::new();
            }
            (
                semantic::alu::SUBTRACTION_BORROW_CHAIN.semantic_class.to_string(),
                AL4_INJECT_KIND.to_string(),
                AL4_INJECT_KIND,
            )
        } else if bucket_id == semantic::alu::COMPARISON_AUXILIARY_CHAIN.id {
            (
                semantic::alu::COMPARISON_AUXILIARY_CHAIN.semantic_class.to_string(),
                AL5_INJECT_KIND.to_string(),
                AL5_INJECT_KIND,
            )
        } else if bucket_id == semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.id {
            (
                semantic::arithmetic::SPECIAL_CASE_CONSISTENCY.semantic_class.to_string(),
                MD_SPECIAL_INJECT_KIND.to_string(),
                MD_SPECIAL_INJECT_KIND,
            )
        } else if bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id {
            (
                semantic::arithmetic::DIVISION_REMAINDER_BOUND.semantic_class.to_string(),
                DIV_REM_BOUND_BASE_KIND.to_string(),
                DIV_REM_BOUND_BASE_KIND,
            )
        } else if bucket_id == semantic::arithmetic::PRODUCT_DECOMPOSITION.id {
            (
                semantic::arithmetic::PRODUCT_DECOMPOSITION.semantic_class.to_string(),
                MD4_INJECT_KIND.to_string(),
                MD4_INJECT_KIND,
            )
        } else if bucket_id == semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.id {
            (
                semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION.semantic_class.to_string(),
                MD5_INJECT_KIND.to_string(),
                MD5_INJECT_KIND,
            )
        } else {
            return Vec::new();
        };
        let schedule = self
            .last_observed_injection_sites
            .get(schedule_lookup_key)
            .map(|steps| {
                InjectionSchedule::Explicit(Self::ordered_steps_around_anchor(steps, anchor))
            })
            .unwrap_or(InjectionSchedule::AroundAnchor(anchor));
        vec![SemanticInjectionCandidate {
            bucket_id: hit.bucket_id.clone(),
            trigger_signal_id: None,
            semantic_class,
            inject_kind,
            schedule,
        }]
    }
}

impl BenchmarkBackend for Sp1Backend {
    fn is_usable_seed(&self, words: &[u32]) -> bool {
        !words.is_empty()
            && words.len() <= self.max_instructions
            && words.iter().all(|w| RV32IMInstruction::decode(*w).is_some())
    }

    fn prepare_for_run(&mut self, _rng_seed: u64) {
        self.eval = BackendEval::default();
        self.current_iteration = self.current_iteration.saturating_add(1);
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        let resp = run_backend_once(
            1,
            words,
            self.current_iteration,
            self.pending_injection.as_ref().map(|p| p.kind.as_str()),
            self.pending_injection.as_ref().map(|p| p.step).unwrap_or(0),
        )?;
        self.eval = BackendEval {
            micro_op_count: resp.micro_op_count,
            bucket_hits: resp.bucket_hits,
            trace_signals: resp.trace_signals,
            final_regs: resp.final_regs,
            backend_error: resp.backend_error.clone(),
            semantic_injection_applied: resp.injection_applied,
        };
        self.last_observed_injection_sites = resp.observed_injection_sites;
        if let Some(err) = resp.backend_error {
            return Err(err);
        }
        resp.final_regs.ok_or_else(|| "sp1 backend did not return final regs".to_string())
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

impl EnvGuard {
    fn arm(inject_kind: Option<&str>, inject_step: u64) -> Self {
        let saved_kind = env::var("BEAK_SP1_WITNESS_INJECT_KIND").ok();
        let saved_step = env::var("BEAK_SP1_WITNESS_INJECT_STEP").ok();
        let saved_run_id = env::var("BEAK_SP1_WITNESS_RUN_ID").ok();
        let saved_prover = env::var("SP1_PROVER").ok();
        env::set_var("SP1_PROVER", "local");
        match inject_kind {
            Some(kind) if !kind.is_empty() => {
                env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", kind);
                env::set_var("BEAK_SP1_WITNESS_INJECT_STEP", inject_step.to_string());
                env::set_var("BEAK_SP1_WITNESS_RUN_ID", format!("sp1-u256div-{inject_step}"));
            }
            _ => {
                env::remove_var("BEAK_SP1_WITNESS_INJECT_KIND");
                env::remove_var("BEAK_SP1_WITNESS_INJECT_STEP");
                env::remove_var("BEAK_SP1_WITNESS_RUN_ID");
            }
        }
        Self { saved_kind, saved_step, saved_run_id, saved_prover }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.saved_kind {
            Some(value) => env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", value),
            None => env::remove_var("BEAK_SP1_WITNESS_INJECT_KIND"),
        }
        match &self.saved_step {
            Some(value) => env::set_var("BEAK_SP1_WITNESS_INJECT_STEP", value),
            None => env::remove_var("BEAK_SP1_WITNESS_INJECT_STEP"),
        }
        match &self.saved_run_id {
            Some(value) => env::set_var("BEAK_SP1_WITNESS_RUN_ID", value),
            None => env::remove_var("BEAK_SP1_WITNESS_RUN_ID"),
        }
        match &self.saved_prover {
            Some(value) => env::set_var("SP1_PROVER", value),
            None => env::remove_var("SP1_PROVER"),
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn sp1_checkout_root() -> PathBuf {
    workspace_root()
        .join("beak-py")
        .join("out")
        .join(format!("sp1-{}", crate::SP1_COMMIT))
        .join("sp1-src")
}

fn program_dir() -> PathBuf {
    sp1_checkout_root().join("tests").join("beak-uint256-div")
}

fn built_elf_paths() -> [PathBuf; 5] {
    [
        program_dir().join("elf").join("riscv32im-succinct-zkvm-elf"),
        workspace_root()
            .join("projects")
            .join(format!("sp1-{}", crate::SP1_COMMIT))
            .join("target")
            .join("riscv32im-succinct-zkvm-elf")
            .join("release")
            .join("beak-uint256-div"),
        program_dir()
            .join("target")
            .join("riscv32im-succinct-zkvm-elf")
            .join("release")
            .join("beak-uint256-div"),
        sp1_checkout_root()
            .join("tests")
            .join("uint256-div")
            .join("elf")
            .join("riscv32im-succinct-zkvm-elf"),
        sp1_checkout_root()
            .join("tests")
            .join("uint256-div")
            .join("target")
            .join("riscv32im-succinct-zkvm-elf")
            .join("release")
            .join("uint256-div"),
    ]
}

fn ensure_program_source() -> Result<(), String> {
    let program = program_dir();
    let src = program.join("src");
    fs::create_dir_all(&src)
        .map_err(|e| format!("failed to create guest scaffold {}: {e}", src.display()))?;
    let cargo_toml = program.join("Cargo.toml");
    if !cargo_toml.exists() {
        fs::write(&cargo_toml, PROGRAM_CARGO_TOML)
            .map_err(|e| format!("failed to write {}: {e}", cargo_toml.display()))?;
    }
    let main_rs = src.join("main.rs");
    if !main_rs.exists() {
        fs::write(&main_rs, PROGRAM_MAIN_RS)
            .map_err(|e| format!("failed to write {}: {e}", main_rs.display()))?;
    }
    Ok(())
}

fn supported_bucket() -> SupportedBucket {
    SupportedBucket {
        bucket_id: semantic::arithmetic::DIVISION_REMAINDER_BOUND.id,
        semantic_class: semantic::arithmetic::DIVISION_REMAINDER_BOUND.semantic_class,
        inject_kind: DIV_REM_BOUND_BASE_KIND,
        default_step: 0,
    }
}

fn ensure_program_elf() -> Result<Vec<u8>, String> {
    ensure_program_source()?;

    let program = program_dir();
    let elf_paths = built_elf_paths();
    if !elf_paths.iter().any(|path| path.exists()) {
        let rustflags = "-C\x1flink-arg=-Ttext=0x00200800\x1f-C\x1fpanic=abort";
        let mut command = Command::new("cargo");
        command
            .current_dir(&program)
            .env("RUSTUP_TOOLCHAIN", "succinct")
            .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
            .args(["build", "--release", "--target", "riscv32im-succinct-zkvm-elf"]);
        if program.join("Cargo.lock").exists() {
            command.arg("--locked");
        }
        let status =
            command.status().map_err(|e| format!("failed to spawn guest cargo build: {e}"))?;
        if !status.success() {
            return Err(format!(
                "guest cargo build failed for {} with status {status}",
                program.display()
            ));
        }
    }

    let elf = elf_paths.into_iter().find(|path| path.exists()).ok_or_else(|| {
        let searched = built_elf_paths()
            .into_iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!("guest ELF was not produced under {} (searched: {})", program.display(), searched)
    })?;
    fs::read(&elf).map_err(|e| format!("failed to read ELF {}: {e}", elf.display()))
}

fn bytes32_from_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&value.to_le_bytes());
    out
}

fn prove_once(
    client: &ProverClient,
    pk: &SP1ProvingKey,
    vk: &SP1VerifyingKey,
    dividend: [u8; 32],
    divisor: [u8; 32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<ScenarioRun, String> {
    let _guard = EnvGuard::arm(inject_kind, inject_step);
    let mut stdin = SP1Stdin::new();
    stdin.write(&dividend);
    stdin.write(&divisor);

    let mut proof: SP1Proof = client.prove(pk, stdin).map_err(|e| format!("prove failed: {e}"))?;
    let quotient = proof.public_values.read::<[u8; 32]>();
    client.verify(&proof, vk).map_err(|e| format!("verify failed: {e}"))?;

    Ok(ScenarioRun {
        inject_kind: inject_kind.map(str::to_string),
        inject_step,
        quotient_bytes: quotient.to_vec(),
        proof_verified: true,
    })
}

fn execute_once(
    client: &ProverClient,
    elf: &[u8],
    dividend: [u8; 32],
    divisor: [u8; 32],
) -> Result<ScenarioRun, String> {
    execute_once_with_injection(client, elf, dividend, divisor, None, 0)
}

fn execute_once_with_injection(
    client: &ProverClient,
    elf: &[u8],
    dividend: [u8; 32],
    divisor: [u8; 32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<ScenarioRun, String> {
    let _guard = EnvGuard::arm(inject_kind, inject_step);
    let mut stdin = SP1Stdin::new();
    stdin.write(&dividend);
    stdin.write(&divisor);
    let (mut public_values, _) =
        client.execute(elf, stdin).map_err(|e| format!("execute failed: {e}"))?;
    let quotient = public_values.read::<[u8; 32]>();
    Ok(ScenarioRun {
        inject_kind: inject_kind.map(str::to_string),
        inject_step,
        quotient_bytes: quotient.to_vec(),
        proof_verified: false,
    })
}

pub fn run_comparison(
    dividend: u64,
    divisor: u64,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<ScenarioComparison, String> {
    let elf = ensure_program_elf()?;
    let client = ProverClient::local();
    let (pk, vk) = client.setup(&elf);

    let dividend = bytes32_from_u64(dividend);
    let divisor = bytes32_from_u64(divisor);

    let baseline = execute_once(&client, &elf, dividend, divisor)?;
    let configured_inject_kind = inject_kind.or(Some(DIV_REM_BOUND_INJECT_KIND));
    let injected =
        match prove_once(&client, &pk, &vk, dividend, divisor, configured_inject_kind, inject_step)
        {
            Ok(run) => run,
            Err(_) => execute_once_with_injection(
                &client,
                &elf,
                dividend,
                divisor,
                configured_inject_kind,
                inject_step,
            )?,
        };

    let diverged = baseline.quotient_bytes != injected.quotient_bytes;
    Ok(ScenarioComparison {
        bucket: supported_bucket(),
        baseline,
        injected,
        diverged,
        underconstrained_candidate: diverged,
    })
}

pub fn run_cli() -> Result<(), String> {
    let args = Args::parse();
    let bucket = supported_bucket();

    if args.print_buckets {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&vec![bucket]).map_err(|e| e.to_string())?);
        } else {
            println!(
                "{} {} {} step={}",
                bucket.bucket_id, bucket.semantic_class, bucket.inject_kind, bucket.default_step
            );
        }
        return Ok(());
    }

    if let Some(max_step) = args.search_steps_max {
        let dividend = args.dividend;
        let divisor = args.divisor;
        let inject_kind =
            args.inject_kind.clone().unwrap_or_else(|| DIV_REM_BOUND_INJECT_KIND.to_string());
        let hits = thread::Builder::new()
            .name("sp1-u256div-search".to_string())
            .stack_size(128 * 1024 * 1024)
            .spawn(move || {
                let elf = ensure_program_elf()?;
                let client = ProverClient::local();
                let dividend = bytes32_from_u64(dividend);
                let divisor = bytes32_from_u64(divisor);
                let baseline = execute_once(&client, &elf, dividend, divisor)?;
                let mut hits = Vec::new();
                for step in 0..=max_step {
                    let injected = execute_once_with_injection(
                        &client,
                        &elf,
                        dividend,
                        divisor,
                        Some(inject_kind.as_str()),
                        step,
                    )?;
                    if injected.quotient_bytes != baseline.quotient_bytes {
                        hits.push(injected);
                    }
                }
                Ok::<Vec<ScenarioRun>, String>(hits)
            })
            .map_err(|e| format!("failed to spawn search thread: {e}"))?
            .join()
            .map_err(|_| "search thread panicked".to_string())??;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&hits).map_err(|e| e.to_string())?);
        } else {
            for hit in hits {
                println!("step={} quotient={:02x?}", hit.inject_step, hit.quotient_bytes);
            }
        }
        return Ok(());
    }

    let dividend = args.dividend;
    let divisor = args.divisor;
    let inject_kind = args.inject_kind.clone();
    let inject_step = args.inject_step;
    let result = thread::Builder::new()
        .name("sp1-u256div-worker".to_string())
        .stack_size(128 * 1024 * 1024)
        .spawn(move || run_comparison(dividend, divisor, inject_kind.as_deref(), inject_step))
        .map_err(|e| format!("failed to spawn worker thread: {e}"))?
        .join()
        .map_err(|_| "worker thread panicked".to_string())??;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?);
    } else {
        println!(
            "baseline={:02x?} injected={:02x?} diverged={} underconstrained_candidate={}",
            result.baseline.quotient_bytes,
            result.injected.quotient_bytes,
            result.diverged,
            result.underconstrained_candidate
        );
    }
    Ok(())
}
