use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libafl::inputs::BytesInput;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::fuzz::bug_filter::{
    has_exact_executed_exception_relation, is_suppressed_exception, BugNoveltyFilter,
};
use crate::fuzz::jsonl::{BugRecord, CorpusRecord, JsonlWriter, RunRecord};
use crate::fuzz::merge_backend_errors;
use crate::fuzz::seed::FuzzingSeed;
use crate::fuzz::seed_mutation::SeedMutationEngine;
use crate::rv32im::instruction::RV32IMInstruction;
use crate::rv32im::oracle::{OracleConfig, RISCVOracle};
use crate::trace::{sorted_signatures_from_hits, sorted_signatures_from_signals, BucketHit, TraceSignal};

pub const DEFAULT_RNG_SEED: u64 = 2026;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticMutationRelation {
    WitnessValueChanged,
    ValuePreservingRepresentation,
    AuipcPcLimbRepresentation,
    MemoryImmediateSignEquation,
    TimestampOriginWrap,
    VolatileBoundaryRange,
    BooleanSourceSelector,
    PaddingInteractionSend,
    EntrypointBinding,
    UpperImmediateMaterialization,
    ArithmeticSpecialCase,
    FullLimbValueRepresentation,
    EntrypointPcEquation,
    UpperImmediateEquation,
    StoreLoadPayloadEquation,
    AddressSpaceConsistencyEquation,
    DivisionRemainderSpecialCaseEquation,
    OpcodeSelectorEquation,
    MemorySelectorEquation,
    ExecutedControlFlowEquation,
    ShadowLookupMultiplicity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticMutationEffect {
    pub relation: SemanticMutationRelation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preserved_before: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preserved_after: Option<serde_json::Value>,
    #[serde(default)]
    pub context: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticMutationReceipt {
    pub inject_kind: String,
    pub site: String,
    pub field: String,
    pub step: u64,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
    pub effect: SemanticMutationEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutedExceptionEffect {
    MemoryTableCapacityWrite,
    BytecodeTableCapacityWrite,
    MultiplicationCarryBound,
    SignedDivisionRemainderVerification,
    SignedUnsignedProductVerification,
    DoryShortTraceCapacity,
    BigIntOpcodeConversion,
    ControlDoneCapacity,
}

/// Typed evidence emitted at the concrete failing operation of a non-injected run.
///
/// This is deliberately separate from the executed obligation hit.  A valid exception needs
/// both: the arithmetic/table relation and an independently emitted receipt showing that the
/// matching prover/executor stage actually failed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutedExceptionReceipt {
    pub effect: ExecutedExceptionEffect,
    pub obligation_id: String,
    pub cell_id: String,
    pub stage: String,
    pub step: u64,
    #[serde(default)]
    pub context: serde_json::Map<String, serde_json::Value>,
}


#[derive(Debug, Clone, Default)]
pub struct BackendEval {
    /// Backend-defined trace size metric used for reporting.
    ///
    /// Note: this is not necessarily “total micro-ops”. Some backends may report instruction count
    /// as a proxy until full micro-op accounting is wired up.
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub final_regs: Option<[u32; 32]>,
    pub backend_error: Option<String>,
    pub semantic_injection_applied: bool,
    pub semantic_mutation_receipt: Option<SemanticMutationReceipt>,
    pub executed_exception_receipt: Option<ExecutedExceptionReceipt>,
    /// Backend-emitted production resource measurements.  The ordinary
    /// benchmark copies this value verbatim into run/bug metadata so a
    /// bounded route cannot be replaced by a mock-only resource claim.
    pub production_resource: Option<serde_json::Value>,
}


#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub zkvm_tag: String,
    pub zkvm_commit: String,
    pub rng_seed: u64,
    pub oracle: OracleConfig,

    pub seeds_jsonl: PathBuf,
    pub out_dir: PathBuf,
    pub output_prefix: Option<String>,

    pub initial_limit: usize,
    pub mutation_iterations: usize,
    pub max_instructions: usize,
    /// Absolute program-length ceiling for long-tail scheduling. 0 means "same as
    /// max_instructions" (legacy hard-cap behavior). When larger, seeds and mutants
    /// longer than max_instructions are admitted whole (never truncated) with a
    /// deterministic Pareto-style probability (max/len)^2, so long programs appear
    /// rarely instead of never while short programs still dominate.
    pub long_tail_max_instructions: usize,
    pub precheck_oracle_max_steps: u32,
    pub semantic_search_enabled: bool,
    pub semantic_window_before: u64,
    pub semantic_window_after: u64,
    pub semantic_step_stride: u64,
    pub semantic_max_trials_per_bucket: usize,
    pub stack_size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct BenchmarkOutputs {
    pub corpus_path: PathBuf,
    pub bugs_path: PathBuf,
    pub runs_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum InjectionSchedule {
    Exact(u64),
    AroundAnchor(u64),
    Explicit(Vec<u64>),
    Sweep { start: u64, end: u64 },
}

#[derive(Debug, Clone)]
pub struct SemanticInjectionCandidate {
    pub bucket_id: String,
    pub trigger_signal_id: Option<String>,
    pub semantic_class: String,
    pub inject_kind: String,
    pub schedule: InjectionSchedule,
}

pub trait BenchmarkBackend {
    fn is_usable_seed(&self, _words: &[u32]) -> bool {
        true
    }

    /// Whether the shared RV32 oracle models every word in this input. Backends with
    /// extension frontends (e.g. non-RV32 custom opcodes) return false for such words
    /// so the oracle precheck and register comparison are skipped instead of erroring.
    fn rv32_oracle_models_words(&self, _words: &[u32]) -> bool {
        true
    }

    /// Word-level admission for the initial seed loader: by default every word must
    /// decode as RV32IM. Backends with extension frontends override this to admit
    /// their custom opcode words as well.
    fn admits_seed_word(&self, word: u32) -> bool {
        RV32IMInstruction::from_word(word).is_ok()
    }

    fn prepare_for_run(&mut self, _rng_seed: u64) {}

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String>;

    fn collect_eval(&mut self) -> BackendEval;

    fn clear_semantic_injection(&mut self) {}

    fn arm_semantic_injection(&mut self, _kind: &str, _step: u64) -> Result<(), String> {
        Ok(())
    }

    fn supports_underconstrained_reporting(&self) -> bool {
        true
    }

    fn semantic_mutation_relation(
        &self,
        _candidate: &SemanticInjectionCandidate,
    ) -> Option<SemanticMutationRelation> {
        None
    }

    fn semantic_injection_candidates(
        &self,
        _hits: &[BucketHit],
    ) -> Vec<SemanticInjectionCandidate> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Default)]
struct EvalStats {
    bucket_hits_sig: String,
    signal_sig: String,
    micro_op_count: usize,
    bucket_hits: Vec<BucketHit>,
    mismatch_regs: Vec<(u32, u32, u32)>,
    backend_error: Option<String>,
    oracle_error: Option<String>,
    phase: String,
    semantic_class: Option<String>,
    inject_kind: Option<String>,
    inject_step: Option<u64>,
    trigger_bucket_id: Option<String>,
    trigger_signal_id: Option<String>,
    baseline_bucket_hits_sig: Option<String>,
    underconstrained_candidate: bool,
    semantic_injection_applied: bool,
    semantic_mutation_receipt: Option<SemanticMutationReceipt>,
    semantic_relation_validated: bool,
    executed_exception_receipt: Option<ExecutedExceptionReceipt>,
    production_resource: Option<serde_json::Value>,
    backend_run_succeeded: bool,
    eval_duration_ms: u64,
}

#[derive(Debug, Clone)]
struct CorpusEntry {
    words: Vec<u32>,
    metadata: serde_json::Value,
    seed_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrozenFindingReportIdentity {
    JoltDivRem,
    JoltDoryShortTrace,
    JoltEntryPcBinding,
    JoltHighBytecode,
    JoltImmediate,
    JoltMulhsu,
    JoltRamSize,
    NexusMemorySize,
    NexusMulCarry,
    NexusOperand,
    OpenVmAddressSpace,
    OpenVmAuipcPcO7,
    OpenVmBigIntMemory,
    OpenVmMultiple,
    OpenVmRangeCheck,
    OpenVmSignBitO8,
    OpenVmOverflowO1,
    OpenVmTimestampOriginO2,
    OpenVmTimestampOriginO26,
    OpenVmTimestampPaddingO3,
    PicoReadWriteOpcodeSelector,
    Risc0ControlDoneCycle,
    Sp1Memory,
    Sp1Pc,
}

impl FrozenFindingReportIdentity {
    /// Render the frozen reporting label compositionally. This label is output indexing only:
    /// it is attached after strict classification and novelty acceptance and is never evidence.
    fn case_id(self) -> String {
        let (vm, subject, revision) = match self {
            Self::JoltDivRem => ("Jolt", "DivRem", "01"),
            Self::JoltDoryShortTrace => ("Jolt", "Dory-ShortTrace", "01"),
            Self::JoltEntryPcBinding => ("Jolt", "EntryPc-Binding", "01"),
            Self::JoltHighBytecode => ("Jolt", "HighBytecode", "01"),
            Self::JoltImmediate => ("Jolt", "Immediate", "01"),
            Self::JoltMulhsu => ("Jolt", "Mulhsu", "01"),
            Self::JoltRamSize => ("Jolt", "RamSize", "01"),
            Self::NexusMemorySize => ("Nexus", "MemorySize", "01"),
            Self::NexusMulCarry => ("Nexus", "MulCarry", "01"),
            Self::NexusOperand => ("Nexus", "Operand", "01"),
            Self::OpenVmAddressSpace => ("OpenVM", "AddrSpace-Audit", "o51"),
            Self::OpenVmAuipcPcO7 => ("OpenVM", "RangeCheck-Audit", "o7"),
            Self::OpenVmBigIntMemory => ("OpenVM", "Memory-Audit", "o19"),
            Self::OpenVmMultiple => ("OpenVM", "Multiple-Audit", "o15"),
            Self::OpenVmRangeCheck => ("OpenVM", "RangeCheck-Audit", "o5"),
            Self::OpenVmSignBitO8 => ("OpenVM", "SignBit-Audit", "o8"),
            Self::OpenVmTimestampOriginO2 => ("OpenVM", "Timestamp-Audit", "o2"),
            Self::OpenVmTimestampOriginO26 => ("OpenVM", "Timestamp-Audit", "o26"),
            Self::OpenVmTimestampPaddingO3 => ("OpenVM", "Timestamp-Audit", "o3"),
            Self::OpenVmOverflowO1 => ("OpenVM", "Overflow-Audit", "o1"),
            Self::PicoReadWriteOpcodeSelector => ("Pico", "ReadWrite-OpcodeSelector", "01"),
            Self::Risc0ControlDoneCycle => ("Risc0", "ControlDone-Cycle", "01"),
            Self::Sp1Memory => ("Sp1", "Memory-Audit", "s27"),
            Self::Sp1Pc => ("Sp1", "Pc-Audit", "s28"),
        };
        format!("{vm}-{subject}-{revision}")
    }
}

fn scrub_caller_reporting_metadata(metadata: &mut serde_json::Map<String, serde_json::Value>) {
    metadata.remove("case_id");
}

fn exact_semantic_reporting_identity(
    cfg: &BenchmarkConfig,
    stats: &EvalStats,
) -> Option<FrozenFindingReportIdentity> {
    if stats.phase != "semantic_search"
        || !stats.underconstrained_candidate
        || !stats.semantic_relation_validated
        || !stats.semantic_injection_applied
    {
        return None;
    }
    let receipt = stats.semantic_mutation_receipt.as_ref()?;
    if receipt.before == receipt.after {
        return None;
    }
    let context = &receipt.effect.context;
    let bucket = stats.trigger_bucket_id.as_deref()?;
    if context_str(context, "bucket_id") != Some(bucket)
        || context_str(context, "backend") != Some(cfg.zkvm_tag.as_str())
        || context_str(context, "commit") != Some(cfg.zkvm_commit.as_str())
    {
        return None;
    }
    let obligation = context_str(context, "obligation_id")?;
    let cell = context_str(context, "cell_id")?;
    let source = context_str(context, "trace_source")?;
    let relation = receipt.effect.relation;

    match (cfg.zkvm_tag.as_str(), cfg.zkvm_commit.as_str(), bucket, relation) {
        (
            "jolt",
            "e9caa23565dbb13019afe61a2c95f51d1999e286",
            "sem.control.entrypoint_binding",
            SemanticMutationRelation::EntrypointPcEquation,
        ) if obligation == "cf4"
            && matches!(cell, "cf4.default_entry" | "cf4.custom_entry")
            && source == "instruction" =>
        {
            Some(FrozenFindingReportIdentity::JoltEntryPcBinding)
        }
        (
            "jolt",
            "e9caa23565dbb13019afe61a2c95f51d1999e286",
            "sem.decode.upper_immediate_materialization",
            SemanticMutationRelation::UpperImmediateEquation,
        ) if obligation == "id3"
            && matches!(cell, "id3.lui_zero" | "id3.lui_max" | "id3.lui_mid")
            && source == "instruction" =>
        {
            Some(FrozenFindingReportIdentity::JoltImmediate)
        }
        (
            "nexus",
            "636ccb360d0f4ae657ae4bb64e1e275ccec8826",
            "sem.memory.store_load_payload_flow",
            SemanticMutationRelation::StoreLoadPayloadEquation,
        ) if obligation == "me1" && cell == "me1.sw_lw" && source == "memory" => {
            Some(FrozenFindingReportIdentity::NexusOperand)
        }
        (
            "openvm",
            "f038f61d21db3aecd3029e1a23ba1ba0bb314800",
            "sem.memory.address_space_consistency",
            SemanticMutationRelation::AddressSpaceConsistencyEquation,
        ) if obligation == "me5"
            && matches!(cell, "me5.mem_read" | "me5.mem_write")
            && source == "memory_access" =>
        {
            Some(FrozenFindingReportIdentity::OpenVmAddressSpace)
        }
        (
            "openvm",
            "336f1a475e5aa3513c4c5a266399f4128c119bba",
            "sem.arithmetic.special_case_consistency",
            SemanticMutationRelation::DivisionRemainderSpecialCaseEquation,
        ) if obligation == "md2" && cell == "md2.div_overflow" && source == "chip_row" => {
            Some(FrozenFindingReportIdentity::OpenVmMultiple)
        }
        (
            "openvm",
            "336f1a475e5aa3513c4c5a266399f4128c119bba",
            "sem.alu.immediate_limb_consistency",
            SemanticMutationRelation::FullLimbValueRepresentation,
        ) if obligation == "al1" && cell.starts_with("al1.") && source == "decoded_instruction" => {
            Some(FrozenFindingReportIdentity::OpenVmRangeCheck)
        }
        (
            "openvm",
            "336f1a475e5aa3513c4c5a266399f4128c119bba",
            "sem.control.auipc_pc_limb_consistency",
            SemanticMutationRelation::AuipcPcLimbRepresentation,
        ) if obligation == "id3" && cell.starts_with("id3.auipc") && source == "instruction" => {
            Some(FrozenFindingReportIdentity::OpenVmAuipcPcO7)
        }
        (
            "openvm",
            "336f1a475e5aa3513c4c5a266399f4128c119bba",
            "sem.memory.immediate_sign_consistency",
            SemanticMutationRelation::MemoryImmediateSignEquation,
        ) if obligation == "id2" && cell.starts_with("id2.") && source == "instruction" => {
            Some(FrozenFindingReportIdentity::OpenVmSignBitO8)
        }
        (
            "openvm",
            "336f1a475e5aa3513c4c5a266399f4128c119bba",
            "sem.time.boundary_origin_consistency",
            SemanticMutationRelation::TimestampOriginWrap,
        ) if obligation == "ts1" && cell == "ts1.standard" && source == "instruction" => {
            Some(FrozenFindingReportIdentity::OpenVmTimestampOriginO2)
        }
        (
            "openvm",
            "f038f61d21db3aecd3029e1a23ba1ba0bb314800",
            "sem.time.boundary_origin_consistency",
            SemanticMutationRelation::TimestampOriginWrap,
        ) if obligation == "ts1" && cell == "ts1.standard" && source == "memory_initial_block" => {
            Some(FrozenFindingReportIdentity::OpenVmTimestampOriginO26)
        }
        (
            "openvm",
            "336f1a475e5aa3513c4c5a266399f4128c119bba",
            "sem.row.padding_interaction_send",
            SemanticMutationRelation::PaddingInteractionSend,
        ) if obligation == "pd1" && cell == "pd1.exec_padding" && source == "air_padding" => {
            Some(FrozenFindingReportIdentity::OpenVmTimestampPaddingO3)
        }
        (
            "openvm",
            "336f1a475e5aa3513c4c5a266399f4128c119bba",
            "sem.lookup.xor_multiplicity_consistency",
            SemanticMutationRelation::ShadowLookupMultiplicity,
        ) if obligation == "bu1" && cell == "bu1.xor_shadow_mult" && source == "lookup_multiplicity" => {
            Some(FrozenFindingReportIdentity::OpenVmOverflowO1)
        }
        (
            "pico",
            "45e74ccd62758c6d67239913956e749adaba261c",
            "sem.exec.op_selector_binding",
            SemanticMutationRelation::OpcodeSelectorEquation,
        ) if obligation == "id4"
            && matches!(cell, "id4.load" | "id4.store")
            && source == "instruction" =>
        {
            Some(FrozenFindingReportIdentity::PicoReadWriteOpcodeSelector)
        }
        (
            "sp1",
            "39ab52fce38172c9d23feed7248198dc14c164a9",
            "sem.exec.memory_effect_binding",
            SemanticMutationRelation::MemorySelectorEquation,
        ) if obligation == "me10"
            && matches!(cell, "me10.load" | "me10.store")
            && source == "instruction" =>
        {
            Some(FrozenFindingReportIdentity::Sp1Memory)
        }
        (
            "sp1",
            "7f643da16813af4c0fbaad4837cd7409386cf38c",
            "sem.exec.control_flow_binding",
            SemanticMutationRelation::ExecutedControlFlowEquation,
        ) if obligation == "cf6" && cell == "cf6.normal" && source == "instruction" => {
            Some(FrozenFindingReportIdentity::Sp1Pc)
        }
        _ => None,
    }
}

fn exact_exception_reporting_identity(
    cfg: &BenchmarkConfig,
    stats: &EvalStats,
) -> Option<FrozenFindingReportIdentity> {
    if stats.phase != "baseline"
        || stats.semantic_injection_applied
        || !has_exact_executed_exception_relation(
            &stats.bucket_hits,
            stats.executed_exception_receipt.as_ref(),
        )
    {
        return None;
    }
    let receipt = stats.executed_exception_receipt.as_ref()?;
    let context = &receipt.context;
    if context_str(context, "backend") != Some(cfg.zkvm_tag.as_str())
        || context_str(context, "commit") != Some(cfg.zkvm_commit.as_str())
    {
        return None;
    }
    let source = context_str(context, "trace_source")?;
    match (
        cfg.zkvm_tag.as_str(),
        cfg.zkvm_commit.as_str(),
        receipt.effect,
        receipt.obligation_id.as_str(),
        receipt.cell_id.as_str(),
        receipt.stage.as_str(),
        source,
    ) {
        (
            "jolt",
            "d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b",
            ExecutedExceptionEffect::DoryShortTraceCapacity,
            "pd2",
            "pd2.very_short",
            "dory.commitment.domain_size",
            "prover.dory",
        ) => Some(FrozenFindingReportIdentity::JoltDoryShortTrace),
        (
            "jolt",
            "e9caa23565dbb13019afe61a2c95f51d1999e286",
            ExecutedExceptionEffect::SignedUnsignedProductVerification,
            "md5",
            cell,
            "r1cs.inner_sumcheck",
            "instruction",
        ) if cell.starts_with("md5.") => Some(FrozenFindingReportIdentity::JoltMulhsu),
        (
            "jolt",
            "e9caa23565dbb13019afe61a2c95f51d1999e286",
            ExecutedExceptionEffect::SignedDivisionRemainderVerification,
            "md3",
            cell,
            "instruction_lookup.primary_sumcheck",
            "instruction",
        ) if cell.starts_with("md3.") && cell != "md3.unsigned" => {
            Some(FrozenFindingReportIdentity::JoltDivRem)
        }
        (
            "nexus",
            "f1b895b868915fd4d0a794a5bc730e6cb8d840f6",
            ExecutedExceptionEffect::MultiplicationCarryBound,
            "md4",
            "md4.mul_overflow",
            "mul.witness.carry_1_bound",
            "instruction",
        ) => Some(FrozenFindingReportIdentity::NexusMulCarry),
        (
            "nexus",
            "41c6c6080f46b97980053c47b078321225b4338a",
            ExecutedExceptionEffect::MemoryTableCapacityWrite,
            "pd3",
            "pd3.mem_table",
            "rw_mem_check.last_access.write",
            "prover.rw_mem_check.last_access",
        ) => Some(FrozenFindingReportIdentity::NexusMemorySize),
        (
            "jolt",
            "6c3b0b49db0afceb967b33656176fa7a27e557b9",
            ExecutedExceptionEffect::BytecodeTableCapacityWrite,
            "pd4",
            "pd4.just_over",
            "read_write_memory.v_init.write",
            "jolt.read_write_memory.preprocessed_bytecode",
        ) => {
            let population = context_u64(context, "population_rows")?;
            let allocated = context_u64(context, "allocated_rows")?;
            if population > allocated {
                Some(FrozenFindingReportIdentity::JoltHighBytecode)
            } else {
                Some(FrozenFindingReportIdentity::JoltRamSize)
            }
        }
        (
            "openvm",
            "336f1a475e5aa3513c4c5a266399f4128c119bba",
            ExecutedExceptionEffect::BigIntOpcodeConversion,
            "id4",
            "id4.branch",
            "openvm.bigint.branch_less_than_opcode_conversion",
            "extensions/rv32im/circuit/src/branch_lt/core.rs::execute_instruction",
        ) => Some(FrozenFindingReportIdentity::OpenVmBigIntMemory),
        (
            "risc0",
            "6f038bd11ed725d7025687d163977d93ac1f82f9",
            ExecutedExceptionEffect::ControlDoneCapacity,
            "pd2",
            "pd2.just_over",
            "risc0.segment.control_done_capacity",
            "segment_finalization",
        ) => Some(FrozenFindingReportIdentity::Risc0ControlDoneCycle),
        _ => None,
    }
}

pub(crate) fn injection_kind_is_noop_prefix(kind: Option<&str>) -> bool {
    let Some((_, variant)) = kind.and_then(|kind| kind.split_once("::")) else {
        return false;
    };
    variant.split(',').any(|field| field.trim() == "mode=noop_prefix")
}

fn clean_semantic_baseline(stats: &EvalStats) -> bool {
    stats.phase == "baseline"
        && stats.backend_run_succeeded
        && stats.backend_error.is_none()
        && stats.oracle_error.is_none()
        && stats.mismatch_regs.is_empty()
        && !stats.semantic_injection_applied
        && stats.semantic_mutation_receipt.is_none()
        && stats.executed_exception_receipt.is_none()
}

fn complete_semantic_source_identity(backend: &str, commit: &str, trace_source: &str) -> bool {
    !backend.trim().is_empty()
        && !commit.trim().is_empty()
        && !trace_source.trim().is_empty()
}

fn context_u64(context: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u64> {
    context.get(key)?.as_u64()
}

fn context_i64(context: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<i64> {
    context.get(key)?.as_i64()
}

fn context_str<'a>(
    context: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    context.get(key)?.as_str()
}

fn context_u64_array(
    context: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<Vec<u64>> {
    context.get(key)?.as_array()?.iter().map(serde_json::Value::as_u64).collect()
}

fn variant_parameters(kind: &str) -> Option<Vec<(&str, &str)>> {
    let (_, variant) = kind.split_once("::")?;
    let parameters: Option<Vec<_>> = variant
        .split(',')
        .map(|part| {
            let (key, value) = part.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            (!key.is_empty() && !value.is_empty()).then_some((key, value))
        })
        .collect();
    parameters.filter(|parameters| !parameters.is_empty())
}

fn context_value_matches_parameter(value: &serde_json::Value, parameter: &str) -> bool {
    value.as_str() == Some(parameter)
        || parameter.parse::<u64>().ok().is_some_and(|expected| value.as_u64() == Some(expected))
        || parameter.parse::<i64>().ok().is_some_and(|expected| value.as_i64() == Some(expected))
        || parameter.parse::<bool>().ok().is_some_and(|expected| value.as_bool() == Some(expected))
}

fn context_matches_all_variant_parameters(
    kind: &str,
    context: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    variant_parameters(kind).is_some_and(|parameters| {
        parameters.into_iter().all(|(key, expected)| {
            context.get(key).is_some_and(|value| context_value_matches_parameter(value, expected))
        })
    })
}

fn context_matches_variant_if_present(
    kind: &str,
    context: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    if kind.split_once("::").is_none() {
        true
    } else {
        context_matches_all_variant_parameters(kind, context)
    }
}

fn scalar_i128(value: &serde_json::Value) -> Option<i128> {
    if let Some(value) = value.as_u64() {
        return Some(i128::from(value));
    }
    if let Some(value) = value.as_i64() {
        return Some(i128::from(value));
    }
    let raw = value.as_str()?.trim();
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        i128::from_str_radix(hex, 16).ok()
    } else {
        raw.parse::<i128>().ok()
    }
}

fn detail_matches_context(
    details: &std::collections::HashMap<String, serde_json::Value>,
    detail_key: &str,
    context: &serde_json::Map<String, serde_json::Value>,
    context_key: &str,
) -> bool {
    let (Some(detail), Some(context)) = (details.get(detail_key), context.get(context_key)) else {
        return false;
    };
    detail == context
        || scalar_i128(detail).zip(scalar_i128(context)).is_some_and(|(left, right)| left == right)
}

/// Bind a relation receipt to one exact, richly typed hit from the clean baseline.
///
/// Equation recomputation alone is insufficient because a caller can construct a
/// self-consistent receipt for a different instruction or row.  The common identity
/// fields deliberately exclude the generic matcher-only OpenVM hits: accepted hits
/// must carry the implementation-contract backend/commit/source identity, then every
/// relation-specific raw input below must match the executed baseline observation.
fn exact_baseline_pairs(relation: SemanticMutationRelation) -> &'static [(&'static str, &'static str)] {
    match relation {
        SemanticMutationRelation::FullLimbValueRepresentation => {
            &[("op_idx", "op_idx"), ("imm", "value")]
        }
        SemanticMutationRelation::EntrypointPcEquation => &[
            ("op_idx", "boundary_row"),
            ("pc", "pc"),
            ("opcode", "opcode"),
            ("mnemonic", "mnemonic"),
            ("declared_entry", "declared_entry"),
        ],
        SemanticMutationRelation::UpperImmediateEquation => {
            &[("op_idx", "op_idx"), ("pc", "pc"), ("opcode", "opcode"), ("mnemonic", "mnemonic")]
        }
        SemanticMutationRelation::ShadowLookupMultiplicity => {
            &[("op_idx", "row_idx")]
        }
        SemanticMutationRelation::MemoryImmediateSignEquation => &[("step_idx", "step")],
        SemanticMutationRelation::AuipcPcLimbRepresentation => {
            &[("op_idx", "step"), ("step_idx", "step")]
        }
        SemanticMutationRelation::StoreLoadPayloadEquation => &[
            ("op_idx", "store_step"),
            ("load_step_idx", "load_step"),
            ("effective_ptr", "store_address"),
            ("effective_ptr", "load_address"),
            ("write_data", "store_value"),
            ("read_data", "load_value_before"),
            ("width", "width"),
        ],
        SemanticMutationRelation::AddressSpaceConsistencyEquation => &[
            ("op_idx", "row_idx"),
            ("pc", "pc"),
            ("opcode", "opcode"),
            ("mnemonic", "mnemonic"),
            ("address_space", "address_space_before"),
        ],
        SemanticMutationRelation::DivisionRemainderSpecialCaseEquation => &[
            ("op_idx", "step"),
            ("pc", "pc"),
            ("mnemonic", "mnemonic"),
            ("rs1_val", "dividend_word"),
            ("rs2_val", "claimed_divisor_word"),
        ],
        SemanticMutationRelation::OpcodeSelectorEquation => &[
            ("op_idx", "step"),
            ("pc", "pc"),
            ("opcode", "opcode"),
            ("mnemonic", "mnemonic"),
            ("rd", "rd"),
        ],
        SemanticMutationRelation::MemorySelectorEquation
        | SemanticMutationRelation::ExecutedControlFlowEquation => {
            &[("op_idx", "op_idx"), ("pc", "pc"), ("opcode", "opcode"), ("mnemonic", "mnemonic")]
        }
        // Relations without additional row-local equation fields still require
        // exactly one baseline hit with the complete common source identity.
        _ => &[],
    }
}

fn receipt_matches_exact_baseline_hit(
    relation: SemanticMutationRelation,
    baseline: &EvalStats,
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    let Some(backend) = context_str(context, "backend") else {
        return false;
    };
    let Some(commit) = context_str(context, "commit") else {
        return false;
    };
    let Some(trace_source) = context_str(context, "trace_source") else {
        return false;
    };
    if !complete_semantic_source_identity(backend, commit, trace_source) {
        return false;
    }
    let pairs = exact_baseline_pairs(relation);
    if context_str(context, "bucket_id") != Some(candidate.bucket_id.as_str()) {
        return false;
    }
    let identity_pairs = [
        ("obligation_id", "obligation_id"),
        ("cell_id", "cell_id"),
        ("backend", "backend"),
        ("commit", "commit"),
        ("trace_source", "trace_source"),
    ];
    let mut matches = baseline.bucket_hits.iter().filter(|hit| {
        let relation_inputs_match = match relation {
            SemanticMutationRelation::AddressSpaceConsistencyEquation => {
                match context_str(context, "cell_id") {
                    Some("me5.mem_read") => {
                        hit.details.get("is_load").and_then(serde_json::Value::as_bool)
                            == Some(true)
                            && hit.details.get("is_store").and_then(serde_json::Value::as_bool)
                                == Some(false)
                    }
                    Some("me5.mem_write") => {
                        hit.details.get("is_load").and_then(serde_json::Value::as_bool)
                            == Some(false)
                            && hit.details.get("is_store").and_then(serde_json::Value::as_bool)
                                == Some(true)
                    }
                    _ => false,
                }
            }
            _ => true,
        };
        hit.bucket_id == candidate.bucket_id
            && relation_inputs_match
            && identity_pairs.iter().all(|(detail, receipt)| {
                detail_matches_context(&hit.details, detail, context, receipt)
            })
            && pairs.iter().all(|(detail, receipt)| {
                detail_matches_context(&hit.details, detail, context, receipt)
            })
    });
    matches.next().is_some() && matches.next().is_none()
}

fn checked_recompose(limbs: &[u64], radix: u64) -> Option<u128> {
    if radix < 2 || limbs.is_empty() {
        return None;
    }
    let mut place = 1u128;
    let mut value = 0u128;
    for &limb in limbs {
        value = value.checked_add(u128::from(limb).checked_mul(place)?)?;
        place = place.checked_mul(u128::from(radix))?;
    }
    Some(value)
}

fn modular_recompose(limbs: &[u64], radix: u64, modulus: u64) -> Option<u64> {
    if limbs.is_empty() || radix < 2 || modulus < 2 {
        return None;
    }
    let modulus = u128::from(modulus);
    let mut place = 1u128;
    let mut value = 0u128;
    for &limb in limbs {
        value = (value + (u128::from(limb) % modulus) * place) % modulus;
        place = (place * u128::from(radix)) % modulus;
    }
    Some(value as u64)
}

fn valid_full_limb_value_representation_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    if candidate.bucket_id != "sem.alu.immediate_limb_consistency"
        || receipt.site != "rv32_base_alu_adapter.preprocess"
        || receipt.field != "rs2_data_limbs"
        || context_str(context, "obligation_id") != Some("al1")
        || context_str(context, "cell_id").is_none_or(|cell| !cell.starts_with("al1."))
        || context.get("executed_instruction").and_then(serde_json::Value::as_bool) != Some(true)
        || !context_matches_variant_if_present(&candidate.inject_kind, context)
    {
        return false;
    }
    const RADIX: u64 = 256;
    const BABY_BEAR_MODULUS: u64 = 2_013_265_921;
    const LIMB_COUNT: usize = 4;
    let (
        Some(op_idx),
        Some(carry_slot),
        Some(borrow_slot),
        Some(radix),
        Some(modulus),
        Some(value),
    ) = (
        context_u64(context, "op_idx"),
        context_u64(context, "carry_slot").and_then(|value| usize::try_from(value).ok()),
        context_u64(context, "borrow_slot").and_then(|value| usize::try_from(value).ok()),
        context_u64(context, "radix"),
        context_u64(context, "field_modulus"),
        context_u64(context, "value"),
    )
    else {
        return false;
    };
    let (Some(before_limbs), Some(after_limbs)) =
        (context_u64_array(context, "before_limbs"), context_u64_array(context, "after_limbs"))
    else {
        return false;
    };
    if radix != RADIX
        || modulus != BABY_BEAR_MODULUS
        || context_u64(context, "limb_count") != Some(LIMB_COUNT as u64)
        || context_str(context, "mode") != Some("adjacent_radix_carry")
        || before_limbs.len() != LIMB_COUNT
        || after_limbs.len() != LIMB_COUNT
        || carry_slot != 0
        || borrow_slot != carry_slot + 1
        || value > u32::MAX as u64
        || before_limbs.iter().any(|limb| *limb >= radix)
        || after_limbs.iter().any(|limb| *limb >= modulus)
    {
        return false;
    }
    let expected_before =
        (0..LIMB_COUNT).map(|idx| (value >> (idx * 8)) & 0xff).collect::<Vec<_>>();
    let mut expected_after = expected_before.clone();
    let Some(expected_carry) = expected_before[carry_slot].checked_add(radix) else {
        return false;
    };
    expected_after[carry_slot] = expected_carry;
    expected_after[borrow_slot] = if expected_before[borrow_slot] == 0 {
        modulus - 1
    } else {
        expected_before[borrow_slot] - 1
    };
    let before_value = modular_recompose(&before_limbs, radix, modulus);
    let after_value = modular_recompose(&after_limbs, radix, modulus);
    op_idx == receipt.step
        && before_limbs == expected_before
        && after_limbs == expected_after
        && receipt.before == json!(before_limbs)
        && receipt.after == json!(after_limbs)
        && before_limbs[carry_slot] != after_limbs[carry_slot]
        && before_limbs[borrow_slot] != after_limbs[borrow_slot]
        && before_value == Some(value % modulus)
        && after_value == before_value
        && context_u64(context, "recomposed_before") == before_value
        && context_u64(context, "recomposed_after") == after_value
}

fn valid_entrypoint_pc_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    if candidate.bucket_id != "sem.control.entrypoint_binding"
        || context_str(context, "obligation_id") != Some("cf4")
        || !matches!(
            context_str(context, "cell_id"),
            Some("cf4.default_entry" | "cf4.custom_entry")
        )
        || context.get("executed_boundary_row").and_then(serde_json::Value::as_bool) != Some(true)
        || !context_matches_variant_if_present(&candidate.inject_kind, context)
    {
        return false;
    }
    let (Some(row), Some(declared), Some(before), Some(after)) = (
        context_u64(context, "boundary_row"),
        context_u64(context, "declared_entry"),
        context_u64(context, "witnessed_pc_before"),
        context_u64(context, "witnessed_pc_after"),
    ) else {
        return false;
    };
    row == receipt.step
        && declared <= u32::MAX as u64
        && before == declared
        && after <= u32::MAX as u64
        && after != declared
        && receipt.before.as_u64() == Some(before)
        && receipt.after.as_u64() == Some(after)
}

fn valid_upper_immediate_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    if candidate.bucket_id != "sem.decode.upper_immediate_materialization"
        || context_str(context, "obligation_id") != Some("id3")
        || !matches!(
            context_str(context, "cell_id"),
            Some("id3.lui_zero" | "id3.lui_max" | "id3.lui_mid")
        )
        || context_str(context, "mnemonic") != Some("lui")
        || context.get("executed_instruction").and_then(serde_json::Value::as_bool) != Some(true)
        || !context_matches_variant_if_present(&candidate.inject_kind, context)
    {
        return false;
    }
    let (Some(step), Some(opcode), Some(imm20), Some(expected), Some(before), Some(after)) = (
        context_u64(context, "op_idx"),
        context_u64(context, "opcode"),
        context_u64(context, "imm20"),
        context_u64(context, "expected_result"),
        context_u64(context, "witnessed_result_before"),
        context_u64(context, "witnessed_result_after"),
    ) else {
        return false;
    };
    opcode <= u32::MAX as u64
        && opcode & 0x7f == 0x37
        && imm20 == (opcode >> 12) & 0x000f_ffff
        && expected == opcode & 0xffff_f000
        && before == expected
        && after != expected
        && step == receipt.step
        && receipt.before.as_u64() == Some(before)
        && receipt.after.as_u64() == Some(after)
}

fn valid_store_load_payload_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    if candidate.bucket_id != "sem.memory.store_load_payload_flow"
        || context_str(context, "obligation_id") != Some("me1")
        || context_str(context, "cell_id") != Some("me1.sw_lw")
        || context.get("executed_store").and_then(serde_json::Value::as_bool) != Some(true)
        || context.get("executed_load").and_then(serde_json::Value::as_bool) != Some(true)
        || context_str(context, "mutation_mode") != Some("replace_low_byte_5a_a5")
        || !context_matches_variant_if_present(&candidate.inject_kind, context)
    {
        return false;
    }
    let (
        Some(store_step),
        Some(load_step),
        Some(store_address),
        Some(load_address),
        Some(store_value),
        Some(store_before),
        Some(store_after),
        Some(load_before),
        Some(load_after),
        Some(width),
    ) = (
        context_u64(context, "store_step"),
        context_u64(context, "load_step"),
        context_u64(context, "store_address"),
        context_u64(context, "load_address"),
        context_u64(context, "store_value"),
        context_u64(context, "store_value_before"),
        context_u64(context, "store_value_after"),
        context_u64(context, "load_value_before"),
        context_u64(context, "load_value_after"),
        context_u64(context, "width"),
    )
    else {
        return false;
    };
    if [store_value, store_before, store_after, load_before, load_after]
        .iter()
        .any(|value| *value > u32::MAX as u64)
    {
        return false;
    }
    let expected_low = if store_before as u8 == 0x5a { 0xa5 } else { 0x5a };
    let expected_after = (store_before & 0xffff_ff00) | expected_low;
    store_step < load_step
        && store_step == receipt.step
        && store_address == load_address
        && width == 4
        && store_value == store_before
        && store_before == load_before
        && store_after == expected_after
        && store_after == load_after
        && store_after != store_before
        && receipt.before.as_u64() == Some(store_before)
        && receipt.after.as_u64() == Some(store_after)
}

fn valid_address_space_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    if candidate.bucket_id != "sem.memory.address_space_consistency"
        || receipt.site != "rv32_loadstore_adapter.preprocess"
        || receipt.field != "memory_address_space"
        || context_str(context, "obligation_id") != Some("me5")
        || !matches!(
            context_str(context, "cell_id"),
            Some("me5.reg_read" | "me5.reg_write" | "me5.mem_read" | "me5.mem_write")
        )
        || context.get("executed_access").and_then(serde_json::Value::as_bool) != Some(true)
        || !context_matches_variant_if_present(&candidate.inject_kind, context)
    {
        return false;
    }
    let (
        Some(row),
        Some(is_memory),
        Some(register_space),
        Some(memory_space),
        Some(before),
        Some(after),
    ) = (
        context_u64(context, "row_idx"),
        context.get("is_memory").and_then(serde_json::Value::as_bool),
        context_u64(context, "register_address_space"),
        context_u64(context, "memory_address_space"),
        context_u64(context, "address_space_before"),
        context_u64(context, "address_space_after"),
    )
    else {
        return false;
    };
    let exact_variant = candidate.inject_kind.rsplit_once("::").map(|(_, variant)| variant)
        == Some("mode=bus_mem_as_reg");
    matches!(context_str(context, "cell_id"), Some("me5.mem_read" | "me5.mem_write"))
        && exact_variant
        && is_memory
        && register_space == 1
        && memory_space == 2
        && row == receipt.step
        && before == memory_space
        && after == register_space
        && receipt.before.as_u64() == Some(before)
        && receipt.after.as_u64() == Some(after)
}

/// md2.div_overflow, generate_trace duplicate-row shadow shape
/// (mode=duplicate_row_shadow_r_zero).
///
/// The witness-row-level flag flip and the executor-level divisor reclass are
/// both unverifiable (the AIR pins b/c/q/r on the row and the adapter pins the
/// materialized divisor to the memory bus). The duplicate-row shadow instead
/// appends an is_valid = 0 row derived from the executed INT_MIN / -1 DIV row:
/// every interaction multiplicity collapses to zero so the proof verifies,
/// demonstrating that the special-case flag has no is_valid implication.
fn valid_divrem_duplicate_row_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    if receipt.site != "divrem_core.generate_trace"
        || receipt.field != "row_duplicate.is_valid"
        || context_str(context, "obligation_id") != Some("md2")
        || context_str(context, "cell_id") != Some("md2.div_overflow")
        || context_str(context, "mode") != Some("duplicate_row_shadow_r_zero")
        || context.get("executed_instruction").and_then(serde_json::Value::as_bool) != Some(true)
        || context.get("shadow_row").and_then(serde_json::Value::as_bool) != Some(true)
        || !context_matches_variant_if_present(&candidate.inject_kind, context)
    {
        return false;
    }
    let (
        Some(step),
        Some(dividend_word),
        Some(quotient),
        Some(remainder),
        Some(claimed_divisor_word),
        Some(is_valid),
        Some(zero_divisor),
        Some(r_zero),
        Some(duplicated_from_row_idx),
        Some(row_idx),
    ) = (
        context_u64(context, "step"),
        context_u64(context, "dividend_word"),
        context_i64(context, "quotient"),
        context_i64(context, "remainder"),
        context_u64(context, "claimed_divisor_word"),
        context_u64(context, "is_valid"),
        context_u64(context, "zero_divisor"),
        context_u64(context, "r_zero"),
        context_u64(context, "duplicated_from_row_idx"),
        context_u64(context, "row_idx"),
    )
    else {
        return false;
    };
    step == receipt.step
        && dividend_word == 0x8000_0000
        && quotient == i32::MIN as i64
        && remainder == 0
        && claimed_divisor_word == 0xffff_ffff
        && is_valid == 0
        && zero_divisor == 0
        && r_zero == 0
        && duplicated_from_row_idx < row_idx
        && context_str(context, "mnemonic") == Some("div")
        && context_u64(context, "pc") == Some(step * 4)
        && receipt.before.as_u64() == Some(1)
        && receipt.after.as_u64() == Some(0)
}

/// md2.div_overflow, executor-level divisor-reclass shape.
///
/// The witness-row-level flag flip (zero_divisor 0->1 on an INT_MIN/-1 row)
/// is provably unverifiable: the AIR pins b/c/q/r on such a row, so the
/// mutated row is always rejected.  The executor-level mutation instead
/// reclassifies the operand *before* record construction: the claimed
/// divisor is -1 (what the program computed and the oracle executed), while
/// the materialized divisor entering run_divrem is 0, so the chip naturally
/// derives the zero-divisor special case (q=-1, r=b).  The receipt binds
/// both views so the semantic relation (special-case class vs operands) is
/// checked against the originally executed instruction.
fn valid_divrem_special_case_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    if candidate.bucket_id != "sem.arithmetic.special_case_consistency" {
        return false;
    }
    if context_str(context, "mode") == Some("duplicate_row_shadow_r_zero") {
        return valid_divrem_duplicate_row_receipt(receipt, candidate);
    }
    if receipt.site != "divrem_core.execute_instruction"
        || receipt.field != "operand_divisor"
        || context_str(context, "obligation_id") != Some("md2")
        || context_str(context, "cell_id") != Some("md2.div_overflow")
        || context_str(context, "mutation_mode") != Some("executor_divisor_reclass")
        || context.get("executed_instruction").and_then(serde_json::Value::as_bool) != Some(true)
        || !context_matches_variant_if_present(&candidate.inject_kind, context)
    {
        return false;
    }
    let (
        Some(step),
        Some(dividend),
        Some(dividend_word),
        Some(quotient),
        Some(remainder),
        Some(claimed_divisor),
        Some(claimed_divisor_word),
        Some(materialized_divisor_word),
        Some(selector_before),
        Some(selector_after),
    ) = (
        context_u64(context, "step"),
        context_i64(context, "dividend"),
        context_u64(context, "dividend_word"),
        context_i64(context, "quotient"),
        context_i64(context, "remainder"),
        context_i64(context, "claimed_divisor"),
        context_u64(context, "claimed_divisor_word"),
        context_u64(context, "materialized_divisor_word"),
        context_u64(context, "special_selector_before"),
        context_u64(context, "special_selector_after"),
    )
    else {
        return false;
    };
    step == receipt.step
        && dividend == i32::MIN as i64
        && dividend_word == dividend as i32 as u32 as u64
        && quotient == i32::MIN as i64
        && remainder == 0
        && claimed_divisor == -1
        && claimed_divisor_word == claimed_divisor as i32 as u32 as u64
        && materialized_divisor_word == 0
        && selector_before == 0
        && selector_after == 1
        && receipt.before.as_u64() == Some(claimed_divisor_word)
        && receipt.after.as_u64() == Some(materialized_divisor_word)
}

fn valid_opcode_selector_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    if candidate.bucket_id != "sem.exec.op_selector_binding"
        || context_str(context, "obligation_id") != Some("id4")
        || !matches!(context_str(context, "cell_id"), Some("id4.load" | "id4.store"))
        || context.get("executed_read_write_row").and_then(serde_json::Value::as_bool) != Some(true)
        || !context_matches_variant_if_present(&candidate.inject_kind, context)
    {
        return false;
    }
    let (Some(step), Some(mutation_step), Some(opcode), Some(rd), Some(before), Some(after)) = (
        context_u64(context, "step"),
        context_u64(context, "mutation_step"),
        context_u64(context, "opcode"),
        context_u64(context, "rd"),
        context_u64(context, "selector_before"),
        context_u64(context, "selector_after"),
    ) else {
        return false;
    };
    let low_opcode = opcode & 0x7f;
    let cell_matches = match context_str(context, "cell_id") {
        Some("id4.load") => low_opcode == 0x03,
        Some("id4.store") => low_opcode == 0x23,
        _ => false,
    };
    let expected = u64::from(low_opcode == 0x03 && rd == 0);
    step == mutation_step
        && mutation_step == receipt.step
        && step <= u32::MAX as u64
        && opcode <= u32::MAX as u64
        && rd < 32
        && cell_matches
        && before == expected
        && after != expected
        && matches!(after, 0 | 1)
        && receipt.before.as_u64() == Some(before)
        && receipt.after.as_u64() == Some(after)
}

fn valid_memory_selector_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    if candidate.bucket_id != "sem.exec.memory_effect_binding"
        || context_str(context, "obligation_id") != Some("me10")
        || !matches!(context_str(context, "cell_id"), Some("me10.load" | "me10.store"))
        || context.get("executed_cpu_row").and_then(serde_json::Value::as_bool) != Some(true)
        || !context_matches_variant_if_present(&candidate.inject_kind, context)
    {
        return false;
    }
    let (Some(step), Some(op_idx), Some(opcode), Some(expected), Some(before), Some(after)) = (
        context_u64(context, "step"),
        context_u64(context, "op_idx"),
        context_u64(context, "opcode"),
        context_u64(context, "expected_is_memory"),
        context_u64(context, "selector_before"),
        context_u64(context, "selector_after"),
    ) else {
        return false;
    };
    let low_opcode = opcode & 0x7f;
    let derived = u64::from(matches!(low_opcode, 0x03 | 0x23));
    let cell_matches = match context_str(context, "cell_id") {
        Some("me10.load") => low_opcode == 0x03,
        Some("me10.store") => low_opcode == 0x23,
        _ => false,
    };
    op_idx == step
        && step == receipt.step
        && opcode <= u32::MAX as u64
        && expected == derived
        && expected == 1
        && cell_matches
        && before == expected
        && after != expected
        && matches!(after, 0 | 1)
        && receipt.before.as_u64() == Some(before)
        && receipt.after.as_u64() == Some(after)
}

fn valid_executed_control_flow_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    let context = &receipt.effect.context;
    if candidate.bucket_id != "sem.exec.control_flow_binding"
        || context_str(context, "obligation_id") != Some("cf6")
        || context_str(context, "cell_id") != Some("cf6.normal")
        || context_str(context, "control_flow_family") != Some("ecall")
        || context_str(context, "mnemonic") != Some("ecall")
        || context.get("executed_instruction").and_then(serde_json::Value::as_bool) != Some(true)
        || !context_matches_variant_if_present(&candidate.inject_kind, context)
    {
        return false;
    }
    let (
        Some(step),
        Some(op_idx),
        Some(pc),
        Some(opcode),
        Some(expected),
        Some(before),
        Some(after),
    ) = (
        context_u64(context, "step"),
        context_u64(context, "op_idx"),
        context_u64(context, "pc"),
        context_u64(context, "opcode"),
        context_u64(context, "expected_next_pc"),
        context_u64(context, "observed_next_pc_before"),
        context_u64(context, "observed_next_pc_after"),
    )
    else {
        return false;
    };
    let recomputed = (pc as u32).wrapping_add(4) as u64;
    let parameters = variant_parameters(&candidate.inject_kind);
    let family = parameters.as_ref().and_then(|parameters| {
        parameters.iter().find_map(|(key, value)| (*key == "family").then_some(*value))
    });
    let mode = parameters.as_ref().and_then(|parameters| {
        parameters.iter().find_map(|(key, value)| (*key == "mode").then_some(*value))
    });
    let expected_after = match (family, mode) {
        (Some("ecall"), Some("near_jump")) => {
            Some(if before == (pc as u32).wrapping_add(8) as u64 {
                (pc as u32).wrapping_add(12) as u64
            } else {
                (pc as u32).wrapping_add(8) as u64
            })
        }
        (Some("ecall"), Some("mid_jump")) => {
            Some(if before == (pc as u32).wrapping_add(0x40) as u64 {
                (pc as u32).wrapping_add(0x44) as u64
            } else {
                (pc as u32).wrapping_add(0x40) as u64
            })
        }
        (Some("ecall"), Some("legacy_far_jump")) => Some((pc as u32).wrapping_add(0x1_0000) as u64),
        _ => None,
    };
    op_idx == step
        && step == receipt.step
        && pc <= u32::MAX as u64
        && opcode == 0x0000_0073
        && expected == recomputed
        && before == expected
        && expected_after == Some(after)
        && after <= u32::MAX as u64
        && receipt.before.as_u64() == Some(before)
        && receipt.after.as_u64() == Some(after)
}

fn valid_auipc_pc_limb_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    if candidate.bucket_id != "sem.control.auipc_pc_limb_consistency"
        || !context_matches_all_variant_parameters(&candidate.inject_kind, &receipt.effect.context)
        || !matches!(
            context_str(&receipt.effect.context, "cell_id"),
            Some("id3.auipc_no_wrap" | "id3.auipc_wrap")
        )
    {
        return false;
    }
    let Some(slot) =
        context_u64(&receipt.effect.context, "slot").and_then(|v| usize::try_from(v).ok())
    else {
        return false;
    };
    let Some(mult) = context_u64(&receipt.effect.context, "mult") else {
        return false;
    };
    let Some(radix) = context_u64(&receipt.effect.context, "radix") else {
        return false;
    };
    let Some(limb_bound) = context_u64(&receipt.effect.context, "limb_bound") else {
        return false;
    };
    let Some(pc) = context_u64(&receipt.effect.context, "pc") else {
        return false;
    };
    let Some(before_limbs) = context_u64_array(&receipt.effect.context, "before_limbs") else {
        return false;
    };
    let Some(after_limbs) = context_u64_array(&receipt.effect.context, "after_limbs") else {
        return false;
    };
    if before_limbs.len() != after_limbs.len()
        || slot >= before_limbs.len()
        || limb_bound == 0
        || mult == 0
    {
        return false;
    }
    // Mod-p noncanonical representation: the selected pc limb is increased by
    // whole multiples of the field modulus.  Every AIR equation is evaluated in
    // the field, so the recomposed value is unchanged mod modulus while no
    // longer being the canonical byte decomposition of from_pc.  This is only
    // reachable when the AIR omits the byte range check on the pc limbs.
    let Some(modulus) = context_u64(&receipt.effect.context, "modulus") else {
        return false;
    };
    let selected_before = before_limbs[slot];
    let selected_after = after_limbs[slot];
    let expected_delta = modulus.checked_mul(mult);
    let only_selected_limb_changed = before_limbs
        .iter()
        .zip(&after_limbs)
        .enumerate()
        .all(|(idx, (before, after))| idx == slot || before == after);
    let Some(recomposed_before) = checked_recompose(&before_limbs, radix) else {
        return false;
    };
    let Some(recomposed_after) = checked_recompose(&after_limbs, radix) else {
        return false;
    };
    let congruent_mod_p = recomposed_after != recomposed_before
        && recomposed_after
            .checked_sub(recomposed_before)
            .is_some_and(|delta| delta % u128::from(modulus) == 0);
    receipt.before.as_u64() == Some(selected_before)
        && receipt.after.as_u64() == Some(selected_after)
        && context_u64(&receipt.effect.context, "selected_before") == Some(selected_before)
        && context_u64(&receipt.effect.context, "selected_after") == Some(selected_after)
        && expected_delta
            .is_some_and(|delta| selected_after.checked_sub(selected_before) == Some(delta))
        && u128::from(modulus) > u128::from(limb_bound)
        && selected_before < limb_bound
        && selected_after >= limb_bound
        && congruent_mod_p
        && only_selected_limb_changed
        && recomposed_before == u128::from(pc)
        && context_u64(&receipt.effect.context, "recomposed_before")
            .is_some_and(|value| u128::from(value) == recomposed_before)
        && context_u64(&receipt.effect.context, "recomposed_after")
            .is_some_and(|value| u128::from(value) == recomposed_after)
}

fn valid_memory_immediate_sign_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    if candidate.bucket_id != "sem.memory.immediate_sign_consistency"
        || !context_matches_all_variant_parameters(&candidate.inject_kind, &receipt.effect.context)
    {
        return false;
    }
    let cell_id = context_str(&receipt.effect.context, "cell_id");
    let mode = context_str(&receipt.effect.context, "mode");
    let domain = context_str(&receipt.effect.context, "domain");
    let guard = context_str(&receipt.effect.context, "guard");
    if cell_id.is_none_or(|cell| !cell.starts_with("id2."))
        || mode != Some("flip_sign")
        || !matches!(domain, Some("load" | "store"))
        || !matches!(guard, Some("none" | "alt_in_range"))
    {
        return false;
    }
    let Some(sign_before) = context_u64(&receipt.effect.context, "sign_before") else {
        return false;
    };
    let Some(sign_after) = context_u64(&receipt.effect.context, "sign_after") else {
        return false;
    };
    let Some(base) = context_u64(&receipt.effect.context, "base") else {
        return false;
    };
    let Some(immediate) = context_u64(&receipt.effect.context, "immediate") else {
        return false;
    };
    let Some(extended_before) = context_u64(&receipt.effect.context, "extended_before") else {
        return false;
    };
    let Some(extended_after) = context_u64(&receipt.effect.context, "extended_after") else {
        return false;
    };
    let Some(effective_before) = context_u64(&receipt.effect.context, "effective_before") else {
        return false;
    };
    let Some(effective_after) = context_u64(&receipt.effect.context, "effective_after") else {
        return false;
    };
    let expected_extended = |sign: u64| immediate.checked_add(sign.checked_mul(0xffff_0000)?);
    let expected_effective = |extended: u64| Some((base.checked_add(extended)?) & 0xffff_ffff);
    receipt.before.as_u64() == Some(sign_before)
        && receipt.after.as_u64() == Some(sign_after)
        && immediate <= 0xffff
        && matches!((sign_before, sign_after), (0, 1) | (1, 0))
        && expected_extended(sign_before) == Some(extended_before)
        && expected_extended(sign_after) == Some(extended_after)
        && expected_effective(extended_before) == Some(effective_before)
        && expected_effective(extended_after) == Some(effective_after)
        && effective_before != effective_after
}

fn valid_shadow_lookup_multiplicity_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    const BABY_BEAR_MODULUS: u64 = 2_013_265_921;
    let context = &receipt.effect.context;
    if candidate.bucket_id != "sem.lookup.xor_multiplicity_consistency"
        || receipt.site != "bitwise_op_lookup.generate_trace"
        || receipt.field != "mult_xor"
        || context_str(context, "obligation_id") != Some("bu1")
        || context_str(context, "cell_id") != Some("bu1.xor_shadow_mult")
        || context.get("executed_nonzero_row").and_then(serde_json::Value::as_bool)
            != Some(true)
        || !context_matches_all_variant_parameters(&candidate.inject_kind, context)
    {
        return false;
    }
    let Some(row_idx) = context_u64(context, "row_idx") else {
        return false;
    };
    let Some(mult_before) = context_u64(context, "mult_before") else {
        return false;
    };
    let Some(mult_after) = context_u64(context, "mult_after") else {
        return false;
    };
    let Some(modulus) = context_u64(context, "field_modulus") else {
        return false;
    };
    modulus == BABY_BEAR_MODULUS
        && mult_before != 0
        && mult_before < modulus
        && mult_after > modulus
        && mult_after <= 2 * modulus + 1
        && mult_after % modulus == mult_before
        && context.get("shadow_equivalent").and_then(serde_json::Value::as_bool) == Some(true)
        && row_idx == receipt.step
        && receipt.before.as_u64() == Some(mult_before)
        && receipt.after.as_u64() == Some(mult_after)
}

fn valid_timestamp_origin_shift_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    if candidate.bucket_id != "sem.time.boundary_origin_consistency"
        || !context_matches_all_variant_parameters(&candidate.inject_kind, &receipt.effect.context)
        || context_str(&receipt.effect.context, "cell_id") != Some("ts1.standard")
        || context_str(&receipt.effect.context, "mode") != Some("shift_origin")
    {
        return false;
    }
    let Some(delta) = context_u64(&receipt.effect.context, "delta") else {
        return false;
    };
    let Some(origin_before) = context_u64(&receipt.effect.context, "origin_before") else {
        return false;
    };
    let Some(origin_after) = context_u64(&receipt.effect.context, "origin_after") else {
        return false;
    };
    let Some(later_before) = context_u64(&receipt.effect.context, "later_before") else {
        return false;
    };
    let Some(later_after) = context_u64(&receipt.effect.context, "later_after") else {
        return false;
    };
    delta > 0
        && origin_before == 0
        && origin_after == delta
        && later_before == 1
        && later_after == 1 + delta
        && receipt.before.as_u64() == Some(origin_before)
        && receipt.after.as_u64() == Some(origin_after)
        && receipt.effect.context.get("wrapped") == Some(&json!(false))
}

fn valid_timestamp_origin_wrap_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    if candidate.bucket_id != "sem.time.boundary_origin_consistency"
        || !context_matches_all_variant_parameters(&candidate.inject_kind, &receipt.effect.context)
        || context_str(&receipt.effect.context, "cell_id") != Some("ts1.standard")
    {
        return false;
    }
    if context_str(&receipt.effect.context, "mode") == Some("shift_origin") {
        return valid_timestamp_origin_shift_receipt(receipt, candidate);
    }
    let Some(modulus) = context_u64(&receipt.effect.context, "modulus") else {
        return false;
    };
    let Some(origin_before) = context_u64(&receipt.effect.context, "origin_before") else {
        return false;
    };
    let Some(origin_after) = context_u64(&receipt.effect.context, "origin_after") else {
        return false;
    };
    let Some(increment) = context_u64(&receipt.effect.context, "increment") else {
        return false;
    };
    let Some(later_before) = context_u64(&receipt.effect.context, "later_before") else {
        return false;
    };
    let Some(later_after) = context_u64(&receipt.effect.context, "later_after") else {
        return false;
    };
    let expected_later = origin_after.checked_add(increment).map(|value| value % modulus);
    modulus > 2
        && increment > 0
        && origin_before == 0
        && origin_after < modulus
        && origin_after >= modulus.saturating_sub(increment)
        && later_before == origin_before.saturating_add(increment)
        && expected_later == Some(later_after)
        && later_after < origin_after
        && receipt.before.as_u64() == Some(origin_before)
        && receipt.after.as_u64() == Some(origin_after)
        && receipt.effect.context.get("near_modulus") == Some(&json!(true))
        && receipt.effect.context.get("wrapped") == Some(&json!(true))
}

fn valid_monotonic_timestamp_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    if candidate.bucket_id != "sem.time.monotonic_access_ordering"
        || candidate.inject_kind.split_once("::").map(|(base, _)| base)
            != Some("openvm.semantic.time.monotonic_access_ordering")
        || !context_matches_all_variant_parameters(&candidate.inject_kind, &receipt.effect.context)
        || receipt.site != "memory_controller.generate_base_aux"
        || receipt.field != "prev_timestamp"
        || context_str(&receipt.effect.context, "obligation_id") != Some("ts2")
    {
        return false;
    }

    let Some(previous_timestamp) = context_u64(&receipt.effect.context, "previous_timestamp")
    else {
        return false;
    };
    let Some(timestamp) = context_u64(&receipt.effect.context, "timestamp") else {
        return false;
    };
    let Some(ts_diff) = context_u64(&receipt.effect.context, "ts_diff") else {
        return false;
    };
    let Some(cell_id) = context_str(&receipt.effect.context, "cell_id") else {
        return false;
    };
    let cell_matches = match cell_id {
        "ts2.consecutive" => ts_diff == 1,
        "ts2.small_gap" => ts_diff <= 16,
        "ts2.large_gap" => ts_diff >= 128,
        _ => false,
    };

    previous_timestamp < timestamp
        && timestamp - previous_timestamp == ts_diff
        && cell_matches
        && receipt.before.as_u64() == Some(previous_timestamp)
        && receipt.after.as_u64() == Some(timestamp)
        && receipt.effect.context.get("before_strictly_ordered") == Some(&json!(true))
        && receipt.effect.context.get("after_strictly_ordered") == Some(&json!(false))
}

fn valid_volatile_boundary_range_receipt(
    receipt: &SemanticMutationReceipt,
    candidate: &SemanticInjectionCandidate,
) -> bool {
    if candidate.bucket_id != "sem.memory.volatile_boundary_range"
        || !context_matches_all_variant_parameters(&candidate.inject_kind, &receipt.effect.context)
        || !matches!(
            context_str(&receipt.effect.context, "cell_id"),
            Some("rc3.volatile_addr_space" | "rc3.volatile_pointer")
        )
    {
        return false;
    }
    let Some(row_anchor) = context_u64(&receipt.effect.context, "row_anchor") else {
        return false;
    };
    let Some(row_idx) = context_u64(&receipt.effect.context, "row_idx") else {
        return false;
    };
    let Some(address_space_before) = context_u64(&receipt.effect.context, "address_space_before")
    else {
        return false;
    };
    let Some(address_space_after) = context_u64(&receipt.effect.context, "address_space_after")
    else {
        return false;
    };
    let Some(pointer_before) = context_u64(&receipt.effect.context, "pointer_before") else {
        return false;
    };
    let Some(pointer_after) = context_u64(&receipt.effect.context, "pointer_after") else {
        return false;
    };
    let Some(width) = context_u64(&receipt.effect.context, "width") else {
        return false;
    };
    let Some(volatile_start) = context_u64(&receipt.effect.context, "volatile_start") else {
        return false;
    };
    let Some(volatile_end) = context_u64(&receipt.effect.context, "volatile_end") else {
        return false;
    };
    let Some(forged_address) = context_u64(&receipt.effect.context, "forged_address") else {
        return false;
    };
    let forged_end = forged_address.checked_add(width);
    row_anchor == row_idx
        && width > 0
        && volatile_start < volatile_end
        && pointer_before >= volatile_start
        && pointer_before.checked_add(width).is_some_and(|end| end <= volatile_end)
        && forged_address == pointer_after
        && forged_end.is_some_and(|end| forged_address < volatile_start || end > volatile_end)
        && receipt.effect.context.get("outside_volatile_range") == Some(&json!(true))
        && (address_space_before != address_space_after || pointer_before != pointer_after)
        && receipt.before
            == json!({"address_space": address_space_before, "pointer": pointer_before})
        && receipt.after == json!({"address_space": address_space_after, "pointer": pointer_after})
}

/// For relations whose exact receipt already recomputes the mutated architectural
/// result, a register divergence is the expected exploitation signal rather than
/// evidence of an unrelated executor bug.  Accept it only when every mismatched
/// register is exactly explained by the validated receipt: the mutated register
/// is the receipt's rd, the oracle side equals the pre-mutation architectural
/// result, and the backend side equals the receipt's witnessed post-mutation
/// result.
fn mismatch_explained_by_exact_receipt(
    relation: SemanticMutationRelation,
    injected: &EvalStats,
    receipt: &SemanticMutationReceipt,
) -> bool {
    let context = &receipt.effect.context;
    let (rd, before, after) = match relation {
        SemanticMutationRelation::UpperImmediateEquation => {
            let Some(opcode) = context_u64(context, "opcode") else {
                return false;
            };
            let rd = ((opcode >> 7) & 0x1f) as usize;
            let Some(before) = context_u64(context, "witnessed_result_before") else {
                return false;
            };
            let Some(after) = context_u64(context, "witnessed_result_after") else {
                return false;
            };
            (rd, before, after)
        }
        _ => return false,
    };
    !injected.mismatch_regs.is_empty()
        && injected
            .mismatch_regs
            .iter()
            .all(|&(reg, oracle, backend)| {
                reg as usize == rd && u64::from(oracle) == before && u64::from(backend) == after
            })
}

/// Executor-level entrypoint mutation: skipping the first instruction may
/// diverge the final register file.  Every mismatched register must be
/// exactly the divergence computed by the adapter between the skipped and
/// unskipped executions; no more, no less.
fn entrypoint_mismatch_explained(
    injected: &EvalStats,
    receipt: &SemanticMutationReceipt,
) -> bool {
    let context = &receipt.effect.context;
    if !matches!(
        context.get("mutation_mode").and_then(serde_json::Value::as_str),
        Some("skip_one" | "skip_two" | "far_page")
    ) {
        return false;
    }
    let Some(explained) = context.get("explained_mismatches").and_then(|value| value.as_array())
    else {
        return false;
    };
    let explained: std::collections::HashSet<(u64, u64, u64)> = explained
        .iter()
        .filter_map(|entry| {
            let reg = entry.get("reg")?.as_u64()?;
            let oracle = entry.get("oracle")?.as_u64()?;
            let backend = entry.get("backend")?.as_u64()?;
            Some((reg, oracle, backend))
        })
        .collect();
    !injected.mismatch_regs.is_empty()
        && explained.len() == injected.mismatch_regs.len()
        && injected
            .mismatch_regs
            .iter()
            .all(|&(reg, oracle, backend)| {
                explained.contains(&(u64::from(reg), u64::from(oracle), u64::from(backend)))
            })
}

fn semantic_underconstrained_candidate(
    backend_supports_reporting: bool,
    baseline: &EvalStats,
    injected: &EvalStats,
    candidate: &SemanticInjectionCandidate,
    expected_relation: Option<SemanticMutationRelation>,
) -> bool {
    let receipt_valid = expected_relation.is_some_and(|relation| {
        injected.semantic_mutation_receipt.as_ref().is_some_and(|receipt| {
            if std::env::var_os("BEAK_DEBUG_UC_GATES").is_some()
                && receipt.inject_kind == candidate.inject_kind
            {
                let step_ok = injected
                    .inject_step
                    .is_some_and(|configured| configured == u64::MAX || receipt.step == configured);
                let relation_ok = receipt.effect.relation == relation;
                eprintln!(
                    "BEAKDBG uc-receipt kind={} step_ok={} relation_ok={} relation={:?}",
                    receipt.inject_kind, step_ok, relation_ok, receipt.effect.relation,
                );
            }
            receipt.inject_kind == candidate.inject_kind
                && injected
                    .inject_step
                    .is_some_and(|configured| configured == u64::MAX || receipt.step == configured)
                && !receipt.site.trim().is_empty()
                && !receipt.field.trim().is_empty()
                && receipt.before != receipt.after
                && receipt.effect.relation == relation
                && {
                    let relation_specific = match relation {
                    // These legacy coarse relations do not carry enough structured data to
                    // recompute the claimed invariant.  A changed witness value (or two equal
                    // caller-supplied "preserved" JSON values) is not proof that the mutation
                    // targeted the candidate obligation, so keep them fail-closed until a
                    // relation-specific validator is added.
                    SemanticMutationRelation::ValuePreservingRepresentation
                    | SemanticMutationRelation::EntrypointBinding
                    | SemanticMutationRelation::UpperImmediateMaterialization
                    | SemanticMutationRelation::ArithmeticSpecialCase => false,
                    SemanticMutationRelation::WitnessValueChanged => {
                        valid_monotonic_timestamp_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::PaddingInteractionSend => {
                        receipt.effect.context.get("is_padding") == Some(&json!(true))
                            && receipt.effect.context.contains_key("interaction_kind")
                    }
                    SemanticMutationRelation::BooleanSourceSelector => {
                        receipt.before == json!(1)
                            && receipt.after == json!(2)
                            && receipt.effect.context.get("source_row") == Some(&json!(true))
                            && receipt.effect.context.get("cell_id") == Some(&json!("bu1.real_row"))
                            && receipt.effect.context.get("selector_before") == Some(&json!(1))
                            && receipt.effect.context.get("selector_after") == Some(&json!(2))
                    }
                    SemanticMutationRelation::ShadowLookupMultiplicity => {
                        valid_shadow_lookup_multiplicity_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::AuipcPcLimbRepresentation => {
                        valid_auipc_pc_limb_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::MemoryImmediateSignEquation => {
                        valid_memory_immediate_sign_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::TimestampOriginWrap => {
                        valid_timestamp_origin_wrap_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::VolatileBoundaryRange => {
                        valid_volatile_boundary_range_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::FullLimbValueRepresentation => {
                        valid_full_limb_value_representation_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::EntrypointPcEquation => {
                        valid_entrypoint_pc_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::UpperImmediateEquation => {
                        valid_upper_immediate_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::StoreLoadPayloadEquation => {
                        valid_store_load_payload_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::AddressSpaceConsistencyEquation => {
                        valid_address_space_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::DivisionRemainderSpecialCaseEquation => {
                        valid_divrem_special_case_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::OpcodeSelectorEquation => {
                        valid_opcode_selector_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::MemorySelectorEquation => {
                        valid_memory_selector_receipt(receipt, candidate)
                    }
                    SemanticMutationRelation::ExecutedControlFlowEquation => {
                        valid_executed_control_flow_receipt(receipt, candidate)
                    }
                };
                    let binding_ok = relation_specific
                        && receipt_matches_exact_baseline_hit(relation, baseline, receipt, candidate);
                    if std::env::var_os("BEAK_DEBUG_UC_GATES").is_some() {
                        eprintln!(
                            "BEAKDBG uc-validator kind={} specific={} binding={}",
                            receipt.inject_kind, relation_specific, binding_ok
                        );
                        if relation_specific && !binding_ok {
                            let identity = [("obligation_id", "obligation_id"), ("cell_id", "cell_id"), ("backend", "backend"), ("commit", "commit"), ("trace_source", "trace_source")];
                            let pairs_dbg = exact_baseline_pairs(relation);
                            let cand_hits = baseline.bucket_hits.iter().filter(|h| h.bucket_id == candidate.bucket_id).count();
                            eprintln!(
                                "BEAKDBG uc-validator-dbg candidate_bucket={} baseline_hits_for_bucket={} receipt_ctx={} pair_matched_hits={}",
                                candidate.bucket_id,
                                cand_hits,
                                serde_json::Value::Object(receipt.effect.context.clone()),
                                baseline.bucket_hits.iter().filter(|hit| {
                                    hit.bucket_id == candidate.bucket_id
                                        && identity.iter().all(|(d, r)| detail_matches_context(&hit.details, d, &receipt.effect.context, r))
                                        && pairs_dbg.iter().all(|(d, r)| detail_matches_context(&hit.details, d, &receipt.effect.context, r))
                                }).count()
                            );
                            for hit in baseline.bucket_hits.iter().filter(|h| h.bucket_id == candidate.bucket_id).take(4) {
                                eprintln!("BEAKDBG uc-validator-dbg hit details={}", serde_json::Value::Object(hit.details.iter().map(|(k,v)|(k.clone(),v.clone())).collect()));
                            }
                        }
                    }
                    binding_ok
                }
        })
    });
    let mismatch_ok = injected.mismatch_regs.is_empty()
        || (expected_relation.is_some() && injected.semantic_mutation_receipt.is_some() && {
            let relation = expected_relation.unwrap();
            let receipt = injected.semantic_mutation_receipt.as_ref().unwrap();
            receipt_valid
                && (match relation {
                    SemanticMutationRelation::EntrypointPcEquation => {
                        entrypoint_mismatch_explained(&injected, receipt)
                    }
                    _ => mismatch_explained_by_exact_receipt(relation, &injected, receipt),
                })
        });
    let result = backend_supports_reporting
        && clean_semantic_baseline(baseline)
        && injected.backend_error.is_none()
        && injected.oracle_error.is_none()
        && mismatch_ok
        && injected.semantic_injection_applied
        && receipt_valid
        && !injection_kind_is_noop_prefix(injected.inject_kind.as_deref());
    if std::env::var_os("BEAK_DEBUG_UC_GATES").is_some() && !result {
        eprintln!(
            "BEAKDBG uc-gates kind={} supports={} clean_base={} no_be={} no_oe={} no_mm={} applied={} receipt_valid={} no_noop={}",
            candidate.inject_kind,
            backend_supports_reporting,
            clean_semantic_baseline(baseline),
            injected.backend_error.is_none(),
            injected.oracle_error.is_none(),
            injected.mismatch_regs.is_empty(),
            injected.semantic_injection_applied,
            receipt_valid,
            !injection_kind_is_noop_prefix(injected.inject_kind.as_deref()),
        );
    }
    result
}

fn semantic_candidate_matches_target(
    candidate: &SemanticInjectionCandidate,
    bucket_prefix: Option<&str>,
    inject_kind_prefix: Option<&str>,
) -> bool {
    bucket_prefix.is_none_or(|prefix| candidate.bucket_id.starts_with(prefix))
        && inject_kind_prefix.is_none_or(|prefix| candidate.inject_kind.starts_with(prefix))
}

fn now_ts_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_millis()
        as u64
}

fn resolved_benchmark_out_dir(
    configured: &Path,
    override_dir: Option<std::ffi::OsString>,
) -> PathBuf {
    override_dir.map(PathBuf::from).unwrap_or_else(|| configured.to_path_buf())
}

fn decode_words_from_input(input: &BytesInput, max_instructions: usize) -> Vec<u32> {
    let bytes: &[u8] = input.as_ref();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= bytes.len() && out.len() < max_instructions {
        let w = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        out.push(w);
        i += 4;
    }
    out
}

/// Absolute program-length ceiling: legacy behavior keeps it equal to the nominal
/// `max_instructions`; a larger `long_tail_max_instructions` enables long-tail admission.
fn hard_max_instructions(cfg: &BenchmarkConfig) -> usize {
    cfg.long_tail_max_instructions.max(cfg.max_instructions)
}

fn encode_words(words: &[u32]) -> BytesInput {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for &w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    BytesInput::new(bytes)
}

/// Long seeds (nominal < len <= hard ceiling) occupy a small deterministic share of the
/// loaded corpus: they are ranked by a content hash and the top `long_tail_quota` are
/// admitted. This keeps long programs rare but reproducibly present instead of subject
/// to per-campaign coin flips.
fn long_tail_quota(short_count: usize) -> usize {
    (short_count / 50).max(1)
}

fn seed_content_hash(words: &[u32]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &word in words {
        hash ^= u64::from(word);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn load_initial_seeds(
    path: &Path,
    max_instructions: usize,
    long_tail_max_instructions: usize,
    is_usable: &dyn Fn(&[u32]) -> bool,
    admits_word: &dyn Fn(u32) -> bool,
) -> Vec<(BytesInput, serde_json::Value)> {
    let hard_max = long_tail_max_instructions.max(max_instructions);
    let f = File::open(path).expect("open initial seeds");
    let r = BufReader::new(f);
    let mut short = Vec::new();
    let mut long: Vec<(u64, Vec<u32>, serde_json::Value)> = Vec::new();
    for line in r.lines().flatten() {
        let s = line.trim();
        if s.is_empty() {
            continue;
        }
        let seed = FuzzingSeed::from_jsonl_str(s).expect("parse seed jsonl");
        let mut words = seed.instructions;
        words.truncate(hard_max);
        if words.len() > max_instructions && hard_max > max_instructions {
            long.push((seed_content_hash(&words), words, serde_json::Value::Object(seed.metadata)));
        } else {
            short.push((words, serde_json::Value::Object(seed.metadata)));
        }
    }
    let quota = long_tail_quota(short.len());
    long.sort_by_key(|(hash, _, _)| *hash);
    long.truncate(quota);
    let mut out = Vec::new();
    for (words, meta) in short.into_iter().chain(long.into_iter().map(|(_, words, meta)| (words, meta)))
    {
        if !is_usable(&words) {
            continue;
        }
        if words.iter().any(|w| !admits_word(*w)) {
            continue;
        }
        out.push((encode_words(&words), meta));
    }
    out
}

const INITIAL_SEED_LANE_COUNT: usize = 8;
/// Ordinary, backend-agnostic carriers occupy this bounded prefix of every benchmark schedule.
/// Keeping the prefix small makes their admission independent of the size or ordering of the
/// persistent JSONL corpus while leaving the remainder of the normal corpus untouched.
const ORDINARY_GENERATED_CARRIER_BUDGET: usize = 10;

fn ordinary_generated_carriers(
    max_instructions: usize,
    is_usable: &dyn Fn(&[u32]) -> bool,
) -> Vec<(BytesInput, serde_json::Value)> {
    // These are ISA families, not historical reproducer seeds.  In particular, ECALL is present
    // in several independently built short programs, signed DIV overflow is constructed twice
    // with disjoint register triples and a different setup order, and same-address store/load
    // flow is constructed twice with disjoint base/value/destination registers and offsets.
    let families = [
        ("ecall", "bare", vec![0x0000_0073]),
        ("ecall", "after_addi", vec![0x0010_0093, 0x0000_0073]),
        ("ecall", "after_two_addi", vec![0x0010_0093, 0x0020_0113, 0x0000_0073]),
        ("short_program", "one_addi", vec![0x0010_0093]),
        ("short_program", "two_addi", vec![0x0010_0093, 0x0020_0113]),
        ("signed_div_overflow", "x1_x2_to_x3", vec![0x8000_00b7, 0xfff0_0113, 0x0220_c1b3]),
        (
            "signed_div_overflow",
            "x5_x6_to_x7_reordered",
            vec![0xfff0_0313, 0x8000_02b7, 0x0262_c3b3],
        ),
        (
            "signed_branch",
            "min_vs_negative_one",
            vec![0x8000_02b7, 0xfff0_0313, 0x0062_c263, 0x0000_0073],
        ),
        (
            "paired_store_load",
            "x1_base_x2_value_x3_load_offset0",
            vec![0x4000_0093, 0x0070_0113, 0x0020_a023, 0x0000_a183],
        ),
        (
            "paired_store_load",
            "x5_base_x6_value_x7_load_offset4",
            vec![0x4040_0293, 0xfff0_0313, 0x0062_a223, 0x0042_a383],
        ),
    ];

    families
        .into_iter()
        .enumerate()
        .filter(|(_, (_, _, words))| {
            !words.is_empty()
                && words.len() <= max_instructions
                && words.iter().all(|word| RV32IMInstruction::from_word(*word).is_ok())
                && is_usable(words)
        })
        .take(ORDINARY_GENERATED_CARRIER_BUDGET)
        .map(|(rank, (family, variant, words))| {
            (
                encode_words(&words),
                json!({
                    "source": "ordinary_generator",
                    "generator": "bounded_rv32im_carriers_v1",
                    "carrier_family": family,
                    "carrier_variant": variant,
                    "ordinary_generator_rank": rank,
                    "ordinary_generator_budget": ORDINARY_GENERATED_CARRIER_BUDGET,
                }),
            )
        })
        .collect()
}

/// Deterministically interleave broad ISA-semantic carrier families before applying an initial
/// corpus cap. This is ordinary corpus scheduling: it neither names a backend/case nor injects an
/// exact replay row, and every usable input remains in the schedule after the first round.
fn initial_seed_lane(words: &[u32]) -> usize {
    let has = |predicate: &dyn Fn(u32) -> bool| words.iter().copied().any(predicate);
    let has_ecall = has(&|word| word == 0x0000_0073);
    let has_signed_blt = has(&|word| word & 0x7f == 0x63 && (word >> 12) & 0x7 == 0x4);
    let has_signed_div = has(&|word| {
        word & 0x7f == 0x33 && (word >> 12) & 0x7 == 0x4 && (word >> 25) & 0x7f == 0x01
    });
    let has_min_signed_lui = has(&|word| word & 0x7f == 0x37 && word & 0xffff_f000 == 0x8000_0000);
    let has_negative_one_addi =
        has(&|word| word & 0x7f == 0x13 && (word >> 12) & 0x7 == 0 && word >> 20 == 0xfff);
    let has_load = has(&|word| word & 0x7f == 0x03);
    let has_store = has(&|word| word & 0x7f == 0x23);
    let has_upper_immediate = has(&|word| word & 0x7f == 0x37);

    if words.len() <= 2 {
        0
    } else if has_signed_div && has_min_signed_lui && has_negative_one_addi {
        1
    } else if has_signed_blt {
        2
    } else if has_ecall {
        3
    } else if has_store && has_load {
        4
    } else if has_load {
        5
    } else if has_upper_immediate {
        6
    } else {
        7
    }
}

fn schedule_initial_seeds(
    seeds: Vec<(BytesInput, serde_json::Value)>,
    max_instructions: usize,
) -> Vec<(BytesInput, serde_json::Value)> {
    let mut lanes: Vec<VecDeque<(BytesInput, serde_json::Value)>> =
        (0..INITIAL_SEED_LANE_COUNT).map(|_| VecDeque::new()).collect();
    for seed in seeds {
        let lane = initial_seed_lane(&decode_words_from_input(&seed.0, max_instructions));
        lanes[lane].push_back(seed);
    }
    let mut scheduled = Vec::new();
    loop {
        let mut progressed = false;
        for lane in &mut lanes {
            if let Some(seed) = lane.pop_front() {
                scheduled.push(seed);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    scheduled
}

fn ordinary_seed_schedule(
    file_seeds: Vec<(BytesInput, serde_json::Value)>,
    max_instructions: usize,
    is_usable: &dyn Fn(&[u32]) -> bool,
) -> Vec<(BytesInput, serde_json::Value)> {
    let mut scheduled = ordinary_generated_carriers(max_instructions, is_usable);
    let generated_words: HashSet<Vec<u32>> = scheduled
        .iter()
        .map(|(input, _)| decode_words_from_input(input, max_instructions))
        .collect();
    scheduled.extend(schedule_initial_seeds(file_seeds, max_instructions).into_iter().filter(
        |(input, _)| !generated_words.contains(&decode_words_from_input(input, max_instructions)),
    ));
    scheduled
}

fn initial_schedule_take_count(
    requested_file_limit: usize,
    generated_count: usize,
    total_scheduled: usize,
) -> usize {
    if requested_file_limit == 0 {
        total_scheduled
    } else {
        generated_count.saturating_add(requested_file_limit).min(total_scheduled)
    }
}

fn mismatch_regs(oracle: &[u32; 32], prover: &[u32; 32]) -> Vec<(u32, u32, u32)> {
    let mut out = Vec::new();
    for i in 0..32u32 {
        let a = oracle[i as usize];
        let b = prover[i as usize];
        if a != b {
            out.push((i, a, b));
        }
    }
    out
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

fn canonical_bucket_sig(sigs: &[String]) -> String {
    let mut seen = HashSet::<&str>::new();
    let mut out: Vec<&str> = Vec::new();
    for sig in sigs {
        let t = sig.trim();
        if t.is_empty() {
            continue;
        }
        if seen.insert(t) {
            out.push(t);
        }
    }
    out.join(";")
}

fn novelty_signature(stats: &EvalStats) -> String {
    format!("buckets={}|signals={}", stats.bucket_hits_sig, stats.signal_sig)
}

fn record_novelty(
    stats: &EvalStats,
    seen_signatures: &mut HashSet<String>,
    seen_individual_buckets: &mut HashSet<String>,
) -> (bool, usize) {
    let is_new_signature = seen_signatures.insert(novelty_signature(stats));
    let mut new_individual = 0usize;
    for sig in sorted_signatures_from_hits(&stats.bucket_hits) {
        if seen_individual_buckets.insert(sig) {
            new_individual = new_individual.saturating_add(1);
        }
    }
    (is_new_signature, new_individual)
}

fn oracle_precheck_error(cfg: &BenchmarkConfig, words: &[u32]) -> Option<String> {
    if cfg.precheck_oracle_max_steps == 0 {
        return None;
    }
    let precheck = catch_unwind_nonfatal(std::panic::AssertUnwindSafe(|| {
        RISCVOracle::execute_with_step_limit(words, cfg.oracle, cfg.precheck_oracle_max_steps)
    }));
    match precheck {
        Ok(pre) if pre.hit_step_limit => Some("oracle_precheck_step_limit".to_string()),
        Ok(_) => None,
        Err(panic) => Some(format!("oracle_precheck_{}", panic_payload_to_string(panic.as_ref()))),
    }
}

fn eval_once<B: BenchmarkBackend>(
    cfg: &BenchmarkConfig,
    backend: &mut B,
    words: &[u32],
) -> EvalStats {
    let start = Instant::now();
    backend.prepare_for_run(cfg.rng_seed);

    let (oracle_regs, panic_oracle_error) = if backend.rv32_oracle_models_words(words) {
        match catch_unwind_nonfatal(std::panic::AssertUnwindSafe(|| {
            RISCVOracle::execute_with_config(words, cfg.oracle)
        })) {
            Ok(regs) => (Some(regs), None),
            Err(panic) => (None, Some(panic_payload_to_string(panic.as_ref()))),
        }
    } else {
        (None, None)
    };

    let backend_regs = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        backend.prove_and_read_final_regs(words)
    }));
    let panic_backend_error = match backend_regs.as_ref() {
        Err(p) => Some(panic_payload_to_string(p.as_ref())),
        _ => None,
    };
    let returned_backend_error = match backend_regs.as_ref() {
        Ok(Err(error)) => Some(error.clone()),
        _ => None,
    };
    let backend_run_succeeded = matches!(backend_regs.as_ref(), Ok(Ok(_)));

    let final_regs = match backend_regs {
        Ok(Ok(r)) => Some(r),
        Ok(Err(_)) => None,
        Err(_) => None,
    };
    let mismatches = match (oracle_regs.as_ref(), final_regs.as_ref()) {
        (Some(oracle), Some(regs)) => mismatch_regs(oracle, regs),
        _ => Vec::new(),
    };

    let eval = backend.collect_eval();
    let backend_error = merge_backend_errors(
        eval.backend_error.clone(),
        returned_backend_error,
        panic_backend_error,
    );
    let oracle_error = panic_oracle_error.map(|e| format!("oracle {e}"));
    let bucket_sigs = sorted_signatures_from_hits(&eval.bucket_hits);
    let signal_sigs = sorted_signatures_from_signals(&eval.trace_signals);
    let sig = canonical_bucket_sig(&bucket_sigs);
    let signal_sig = canonical_bucket_sig(&signal_sigs);
    let eval_duration = start.elapsed();

    EvalStats {
        bucket_hits_sig: sig,
        signal_sig,
        micro_op_count: eval.micro_op_count,
        bucket_hits: eval.bucket_hits,
        mismatch_regs: mismatches,
        backend_error,
        oracle_error,
        phase: "baseline".to_string(),
        semantic_class: None,
        inject_kind: None,
        inject_step: None,
        trigger_bucket_id: None,
        trigger_signal_id: None,
        baseline_bucket_hits_sig: None,
        underconstrained_candidate: false,
        semantic_injection_applied: eval.semantic_injection_applied,
        semantic_mutation_receipt: eval.semantic_mutation_receipt,
        semantic_relation_validated: false,
        executed_exception_receipt: eval.executed_exception_receipt,
        production_resource: eval.production_resource,
        backend_run_succeeded,
        eval_duration_ms: eval_duration.as_millis() as u64,
    }
}

fn metadata_object(seed_meta: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    match seed_meta.clone() {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    }
}

fn bug_kind(stats: &EvalStats) -> Option<&'static str> {
    let baseline_mismatch = is_baseline_mismatch(stats);
    if stats.phase == "semantic_search" {
        if !stats.semantic_injection_applied {
            return None;
        }
        if stats.underconstrained_candidate {
            return Some("underconstrained_candidate");
        }
        return None;
    }
    if stats.backend_error.is_some() || stats.oracle_error.is_some() {
        Some("exception")
    } else if baseline_mismatch {
        Some("mismatch")
    } else if stats.underconstrained_candidate {
        Some("underconstrained_candidate")
    } else {
        None
    }
}

fn is_reportable_exception(seed_meta: &serde_json::Value, stats: &EvalStats) -> bool {
    let result = (stats.backend_error.is_some() || stats.oracle_error.is_some())
        && has_exact_executed_exception_relation(
            &stats.bucket_hits,
            stats.executed_exception_receipt.as_ref(),
        )
        && !is_suppressed_exception(
            seed_meta,
            stats.backend_error.as_deref(),
            stats.oracle_error.as_deref(),
        );
    if std::env::var_os("BEAK_DEBUG_UC_GATES").is_some()
        && (stats.backend_error.is_some() || stats.oracle_error.is_some())
    {
        eprintln!(
            "BEAKDBG exc-report err={} relation={} suppressed={} hits={} receipt={}",
            stats.backend_error.is_some() || stats.oracle_error.is_some(),
            has_exact_executed_exception_relation(
                &stats.bucket_hits,
                stats.executed_exception_receipt.as_ref(),
            ),
            is_suppressed_exception(
                seed_meta,
                stats.backend_error.as_deref(),
                stats.oracle_error.as_deref(),
            ),
            stats.bucket_hits.len(),
            stats.executed_exception_receipt.is_some(),
        );
    }
    result
}

fn is_baseline_mismatch(stats: &EvalStats) -> bool {
    stats.phase == "baseline" && !stats.mismatch_regs.is_empty()
}

fn write_run_record(
    cfg: &BenchmarkConfig,
    writer: &JsonlWriter,
    run_started_at_ms: u64,
    elapsed_ms: u64,
    eval_id: u64,
    words: &[u32],
    seed_index: usize,
    seed_meta: &serde_json::Value,
    stats: &EvalStats,
    attempt_index: Option<usize>,
) -> Result<(), String> {
    let mut metadata = metadata_object(seed_meta);
    scrub_caller_reporting_metadata(&mut metadata);
    metadata.insert("mode".to_string(), json!("benchmark"));
    metadata.insert("phase".to_string(), json!(stats.phase));
    metadata.insert("seed_index".to_string(), json!(seed_index));
    metadata.insert("semantic_class".to_string(), json!(stats.semantic_class));
    metadata.insert("inject_kind".to_string(), json!(stats.inject_kind));
    metadata.insert("inject_step".to_string(), json!(stats.inject_step));
    metadata.insert("trigger_bucket_id".to_string(), json!(stats.trigger_bucket_id));
    metadata.insert("trigger_signal_id".to_string(), json!(stats.trigger_signal_id));
    metadata.insert("baseline_bucket_hits_sig".to_string(), json!(stats.baseline_bucket_hits_sig));
    metadata
        .insert("underconstrained_candidate".to_string(), json!(stats.underconstrained_candidate));
    metadata
        .insert("semantic_injection_applied".to_string(), json!(stats.semantic_injection_applied));
    metadata
        .insert("semantic_mutation_receipt".to_string(), json!(stats.semantic_mutation_receipt));
    metadata
        .insert("executed_exception_receipt".to_string(), json!(stats.executed_exception_receipt));
    metadata.insert(
        "semantic_relation_validated".to_string(),
        json!(stats.semantic_relation_validated),
    );
    metadata.insert("production_resource".to_string(), json!(stats.production_resource));
    metadata.insert("attempt_index".to_string(), json!(attempt_index));
    metadata.insert("kind".to_string(), json!("run"));
    let reportable_bug = match bug_kind(stats) {
        Some("exception") => is_reportable_exception(seed_meta, stats),
        Some(_) => true,
        None => false,
    };
    metadata.insert("is_bug".to_string(), json!(reportable_bug));

    let rec = RunRecord {
        zkvm_commit: cfg.zkvm_commit.clone(),
        rng_seed: cfg.rng_seed,
        run_started_at_ms,
        elapsed_ms,
        eval_duration_ms: stats.eval_duration_ms,
        eval_id,
        bucket_hits_sig: stats.bucket_hits_sig.clone(),
        signal_sig: stats.signal_sig.clone(),
        micro_op_count: stats.micro_op_count,
        backend_error: stats.backend_error.clone(),
        oracle_error: stats.oracle_error.clone(),
        mismatch_regs: stats.mismatch_regs.clone(),
        instructions: words.to_vec(),
        metadata: serde_json::Value::Object(metadata),
    };
    writer.append_json_line(&rec)
}

fn write_corpus_record(
    cfg: &BenchmarkConfig,
    writer: &JsonlWriter,
    run_started_at_ms: u64,
    elapsed_ms: u64,
    words: &[u32],
    seed_index: usize,
    seed_meta: &serde_json::Value,
    stats: &EvalStats,
    record_kind: &str,
    extra_metadata: Option<serde_json::Map<String, serde_json::Value>>,
) -> Result<(), String> {
    let mut metadata = metadata_object(seed_meta);
    scrub_caller_reporting_metadata(&mut metadata);
    metadata.insert("mode".to_string(), json!("benchmark"));
    metadata.insert("phase".to_string(), json!(stats.phase));
    metadata.insert("seed_index".to_string(), json!(seed_index));
    metadata.insert("kind".to_string(), json!(record_kind));
    if let Some(extra) = extra_metadata {
        for (k, v) in extra {
            metadata.insert(k, v);
        }
    }
    scrub_caller_reporting_metadata(&mut metadata);

    let rec = CorpusRecord {
        zkvm_commit: cfg.zkvm_commit.clone(),
        rng_seed: cfg.rng_seed,
        run_started_at_ms,
        elapsed_ms,
        eval_duration_ms: stats.eval_duration_ms,
        mismatch: is_baseline_mismatch(stats),
        bucket_hits_sig: stats.bucket_hits_sig.clone(),
        signal_sig: stats.signal_sig.clone(),
        instructions: words.to_vec(),
        metadata: serde_json::Value::Object(metadata),
    };
    writer.append_json_line(&rec)
}

fn write_bug_record(
    cfg: &BenchmarkConfig,
    writer: &JsonlWriter,
    bug_filter: &mut BugNoveltyFilter,
    run_started_at_ms: u64,
    elapsed_ms: u64,
    words: &[u32],
    seed_index: usize,
    seed_meta: &serde_json::Value,
    stats: &EvalStats,
    attempt_index: Option<usize>,
) -> Result<bool, String> {
    let Some(kind) = bug_kind(stats) else {
        return Ok(false);
    };
    if kind == "exception" && !is_reportable_exception(seed_meta, stats) {
        return Ok(false);
    }
    let mut metadata = metadata_object(seed_meta);
    scrub_caller_reporting_metadata(&mut metadata);
    metadata.insert("mode".to_string(), json!("benchmark"));
    metadata.insert("phase".to_string(), json!(stats.phase));
    metadata.insert("seed_index".to_string(), json!(seed_index));
    metadata.insert("kind".to_string(), json!(kind));
    metadata.insert("semantic_class".to_string(), json!(stats.semantic_class));
    metadata.insert("inject_kind".to_string(), json!(stats.inject_kind));
    metadata.insert("inject_step".to_string(), json!(stats.inject_step));
    metadata.insert("trigger_bucket_id".to_string(), json!(stats.trigger_bucket_id));
    metadata.insert("trigger_signal_id".to_string(), json!(stats.trigger_signal_id));
    metadata.insert("baseline_bucket_hits_sig".to_string(), json!(stats.baseline_bucket_hits_sig));
    metadata
        .insert("underconstrained_candidate".to_string(), json!(stats.underconstrained_candidate));
    metadata
        .insert("semantic_injection_applied".to_string(), json!(stats.semantic_injection_applied));
    metadata
        .insert("semantic_mutation_receipt".to_string(), json!(stats.semantic_mutation_receipt));
    metadata
        .insert("executed_exception_receipt".to_string(), json!(stats.executed_exception_receipt));
    metadata.insert(
        "semantic_relation_validated".to_string(),
        json!(stats.semantic_relation_validated),
    );
    metadata.insert("production_resource".to_string(), json!(stats.production_resource));
    metadata.insert("attempt_index".to_string(), json!(attempt_index));
    let metadata_for_novelty = serde_json::Value::Object(metadata.clone());

    if !bug_filter.should_record(
        kind,
        &metadata_for_novelty,
        &stats.bucket_hits_sig,
        &stats.signal_sig,
        stats.backend_error.as_deref(),
        stats.oracle_error.as_deref(),
        &stats.mismatch_regs,
    ) {
        return Ok(false);
    }

    // Reporting labels are attached only after strict bug classification and novelty acceptance.
    // They cannot influence input selection, candidate enumeration, classification, or deduping.
    let reporting_identity = match kind {
        "underconstrained_candidate" => exact_semantic_reporting_identity(cfg, stats),
        "exception" => exact_exception_reporting_identity(cfg, stats),
        _ => None,
    };
    if let Some(identity) = reporting_identity {
        metadata.insert("case_id".to_string(), json!(identity.case_id()));
    }
    let metadata_value = serde_json::Value::Object(metadata);

    let rec = BugRecord {
        zkvm_commit: cfg.zkvm_commit.clone(),
        rng_seed: cfg.rng_seed,
        run_started_at_ms,
        elapsed_ms,
        eval_duration_ms: stats.eval_duration_ms,
        bucket_hits_sig: stats.bucket_hits_sig.clone(),
        signal_sig: stats.signal_sig.clone(),
        micro_op_count: stats.micro_op_count,
        backend_error: stats.backend_error.clone(),
        oracle_error: stats.oracle_error.clone(),
        bucket_hits: stats.bucket_hits.clone(),
        mismatch_regs: stats.mismatch_regs.clone(),
        instructions: words.to_vec(),
        metadata: metadata_value,
    };
    writer.append_json_line(&rec)?;
    Ok(true)
}

fn centered_steps(
    anchor: u64,
    before: u64,
    after: u64,
    stride: u64,
    max_trials: usize,
) -> Vec<u64> {
    let step = stride.max(1);
    let start = anchor.saturating_sub(before);
    let end = anchor.saturating_add(after);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut dist = 0u64;

    while out.len() < max_trials {
        let mut emitted = false;
        if dist == 0 {
            if seen.insert(anchor) {
                out.push(anchor);
                emitted = true;
            }
        } else {
            if let Some(left) = anchor.checked_sub(dist) {
                if left >= start && seen.insert(left) {
                    out.push(left);
                    emitted = true;
                    if out.len() >= max_trials {
                        break;
                    }
                }
            }
            let right = anchor.saturating_add(dist);
            if right <= end && seen.insert(right) {
                out.push(right);
                emitted = true;
            }
        }
        if !emitted && anchor.saturating_add(dist) > end && dist > before {
            break;
        }
        dist = dist.saturating_add(step);
    }

    out
}

fn sweep_steps(start: u64, end: u64, stride: u64, max_trials: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let step = stride.max(1);
    let mut cur = start;
    while cur <= end && out.len() < max_trials {
        out.push(cur);
        if let Some(next) = cur.checked_add(step) {
            cur = next;
        } else {
            break;
        }
    }
    out
}

fn candidate_steps(cfg: &BenchmarkConfig, candidate: &SemanticInjectionCandidate) -> Vec<u64> {
    match candidate.schedule {
        InjectionSchedule::Exact(step) => vec![step],
        InjectionSchedule::Explicit(ref steps) => {
            steps.iter().copied().take(cfg.semantic_max_trials_per_bucket.max(1)).collect()
        }
        InjectionSchedule::AroundAnchor(anchor) => centered_steps(
            anchor,
            cfg.semantic_window_before,
            cfg.semantic_window_after,
            cfg.semantic_step_stride,
            cfg.semantic_max_trials_per_bucket.max(1),
        ),
        InjectionSchedule::Sweep { start, end } => sweep_steps(
            start,
            end,
            cfg.semantic_step_stride,
            cfg.semantic_max_trials_per_bucket.max(1),
        ),
    }
}

pub fn run_benchmark_threaded<B, F>(
    cfg: BenchmarkConfig,
    build_backend: F,
) -> Result<BenchmarkOutputs, String>
where
    B: BenchmarkBackend,
    F: FnOnce() -> B + Send + 'static,
{
    let stack = cfg.stack_size_bytes.max(16 * 1024 * 1024);
    let handle = std::thread::Builder::new()
        .name("beak-benchmark".into())
        .stack_size(stack)
        .spawn(move || {
            let backend = build_backend();
            run_benchmark(cfg, backend)
        })
        .map_err(|e| format!("spawn benchmark thread failed: {e}"))?;
    handle.join().map_err(|_| "benchmark thread panicked".to_string())?
}

pub fn run_benchmark<B: BenchmarkBackend>(
    mut cfg: BenchmarkConfig,
    mut backend: B,
) -> Result<BenchmarkOutputs, String> {
    cfg.out_dir =
        resolved_benchmark_out_dir(&cfg.out_dir, std::env::var_os("BEAK_BENCHMARK_OUT_DIR"));
    std::fs::create_dir_all(&cfg.out_dir)
        .map_err(|e| format!("create out_dir {} failed: {e}", cfg.out_dir.display()))?;

    let base_prefix = cfg.output_prefix.clone().unwrap_or_else(|| {
        format!(
            "benchmark-{}-{}-seed{}-{}-pid{}",
            cfg.zkvm_tag,
            &cfg.zkvm_commit[..cfg.zkvm_commit.len().min(8)],
            cfg.rng_seed,
            now_ts_millis(),
            std::process::id()
        )
    });
    let corpus_path = cfg.out_dir.join(format!("{base_prefix}-corpus.jsonl"));
    let bugs_path = cfg.out_dir.join(format!("{base_prefix}-bugs.jsonl"));
    let runs_path = cfg.out_dir.join(format!("{base_prefix}-runs.jsonl"));

    let corpus_writer = JsonlWriter::open_append(&corpus_path)?;
    let bug_writer = JsonlWriter::open_append(&bugs_path)?;
    let run_writer = JsonlWriter::open_append(&runs_path)?;
    let run_started_at_ms = now_ts_millis();
    let run_start = Instant::now();
    let mut bug_filter = BugNoveltyFilter::default();
    let target_bucket_prefix =
        std::env::var("BEAK_SEMANTIC_TARGET_BUCKET_PREFIX").ok().filter(|value| !value.is_empty());
    let target_inject_kind_prefix = std::env::var("BEAK_SEMANTIC_TARGET_INJECT_KIND_PREFIX")
        .ok()
        .filter(|value| !value.is_empty());

    let seeds = ordinary_seed_schedule(
        load_initial_seeds(
            &cfg.seeds_jsonl,
            cfg.max_instructions,
            cfg.long_tail_max_instructions,
            &|words| backend.is_usable_seed(words),
            &|word| backend.admits_seed_word(word),
        ),
        hard_max_instructions(&cfg),
        &|words| backend.is_usable_seed(words),
    );
    if seeds.is_empty() {
        return Err(format!("No usable initial seeds loaded from {}", cfg.seeds_jsonl.display()));
    }

    let generated_count = seeds
        .iter()
        .take_while(|(_, metadata)| metadata["source"] == json!("ordinary_generator"))
        .count();
    let take_n = initial_schedule_take_count(cfg.initial_limit, generated_count, seeds.len());
    let mut bug_count = 0usize;
    let mut eval_id: u64 = 0;
    let mut mutation_corpus = Vec::<CorpusEntry>::new();
    let mut seen_signatures = HashSet::<String>::new();
    let mut seen_individual_buckets = HashSet::<String>::new();

    for (seed_index, (input, seed_meta)) in seeds.into_iter().take(take_n).enumerate() {
        let words = decode_words_from_input(&input, hard_max_instructions(&cfg));
        if words.is_empty() || !backend.is_usable_seed(&words) {
            continue;
        }
        if std::env::var_os("BEAK_DEBUG_UC_GATES").is_some() {
            eprintln!(
                "BEAKDBG baseline-eval seed_index={} words={} label={:?} first={:08x?}",
                seed_index,
                words.len(),
                seed_meta.get("label").and_then(|v| v.as_str()).unwrap_or(""),
                &words[..words.len().min(3)],
            );
        }

        if backend.rv32_oracle_models_words(&words) {
            if let Some(error) = oracle_precheck_error(&cfg, &words) {
                let mut skipped = EvalStats::default();
                skipped.phase = "baseline".to_string();
                skipped.oracle_error = Some(error);
                eval_id = eval_id.saturating_add(1);
                let elapsed_ms = run_start.elapsed().as_millis() as u64;
                write_run_record(
                    &cfg,
                    &run_writer,
                    run_started_at_ms,
                    elapsed_ms,
                    eval_id,
                    &words,
                    seed_index,
                    &seed_meta,
                    &skipped,
                    None,
                )?;
                continue;
            }
        }

        backend.clear_semantic_injection();
        let baseline = eval_once(&cfg, &mut backend, &words);
        eval_id = eval_id.saturating_add(1);
        let elapsed_ms = run_start.elapsed().as_millis() as u64;
        write_corpus_record(
            &cfg,
            &corpus_writer,
            run_started_at_ms,
            elapsed_ms,
            &words,
            seed_index,
            &seed_meta,
            &baseline,
            "baseline_seed",
            None,
        )?;
        record_novelty(&baseline, &mut seen_signatures, &mut seen_individual_buckets);
        mutation_corpus.push(CorpusEntry {
            words: words.clone(),
            metadata: seed_meta.clone(),
            seed_index,
        });
        write_run_record(
            &cfg,
            &run_writer,
            run_started_at_ms,
            elapsed_ms,
            eval_id,
            &words,
            seed_index,
            &seed_meta,
            &baseline,
            None,
        )?;
        if write_bug_record(
            &cfg,
            &bug_writer,
            &mut bug_filter,
            run_started_at_ms,
            elapsed_ms,
            &words,
            seed_index,
            &seed_meta,
            &baseline,
            None,
        )? {
            bug_count = bug_count.saturating_add(1);
        }

        if !cfg.semantic_search_enabled {
            continue;
        }

        let candidates = backend
            .semantic_injection_candidates(&baseline.bucket_hits)
            .into_iter()
            .filter(|candidate| {
                semantic_candidate_matches_target(
                    candidate,
                    target_bucket_prefix.as_deref(),
                    target_inject_kind_prefix.as_deref(),
                )
            });
        let mut attempted = HashSet::<(String, u64)>::new();

        for candidate in candidates {
            let steps = candidate_steps(&cfg, &candidate);
            if steps.is_empty() {
                continue;
            }
            let mut consecutive_noops = 0usize;

            for (attempt_index, step) in steps.into_iter().enumerate() {
                let attempt_key = (candidate.inject_kind.clone(), step);
                if !attempted.insert(attempt_key) {
                    continue;
                }

                backend.clear_semantic_injection();
                backend.arm_semantic_injection(&candidate.inject_kind, step)?;

                let mut injected = eval_once(&cfg, &mut backend, &words);
                injected.phase = "semantic_search".to_string();
                injected.semantic_class = Some(candidate.semantic_class.clone());
                injected.inject_kind = Some(candidate.inject_kind.clone());
                injected.inject_step = Some(step);
                injected.trigger_bucket_id = Some(candidate.bucket_id.clone());
                injected.trigger_signal_id = candidate.trigger_signal_id.clone();
                injected.baseline_bucket_hits_sig = Some(baseline.bucket_hits_sig.clone());
                let expected_relation = backend.semantic_mutation_relation(&candidate);
                let relation_validated = semantic_underconstrained_candidate(
                    backend.supports_underconstrained_reporting(),
                    &baseline,
                    &injected,
                    &candidate,
                    expected_relation,
                );
                injected.semantic_relation_validated = relation_validated;
                injected.underconstrained_candidate = relation_validated;

                eval_id = eval_id.saturating_add(1);
                let elapsed_ms = run_start.elapsed().as_millis() as u64;
                write_run_record(
                    &cfg,
                    &run_writer,
                    run_started_at_ms,
                    elapsed_ms,
                    eval_id,
                    &words,
                    seed_index,
                    &seed_meta,
                    &injected,
                    Some(attempt_index),
                )?;
                if write_bug_record(
                    &cfg,
                    &bug_writer,
                    &mut bug_filter,
                    run_started_at_ms,
                    elapsed_ms,
                    &words,
                    seed_index,
                    &seed_meta,
                    &injected,
                    Some(attempt_index),
                )? {
                    bug_count = bug_count.saturating_add(1);
                }
                if injected.semantic_injection_applied {
                    consecutive_noops = 0;
                } else {
                    consecutive_noops = consecutive_noops.saturating_add(1);
                    if consecutive_noops >= 4 {
                        break;
                    }
                }
            }
        }

        backend.clear_semantic_injection();
    }

    if cfg.mutation_iterations > 0 && mutation_corpus.is_empty() {
        return Err("No usable corpus entries available for mutation".to_string());
    }

    let mut mutation_engine =
        SeedMutationEngine::new(
            cfg.max_instructions,
            hard_max_instructions(&cfg),
            cfg.rng_seed ^ 0xbea0_f00d_cafe_babe,
        );
    for iter in 0..cfg.mutation_iterations {
        let Some(parent_index) = mutation_engine.select_corpus_index(mutation_corpus.len()) else {
            break;
        };
        let parent = mutation_corpus[parent_index].clone();
        let corpus_words: Vec<Vec<u32>> =
            mutation_corpus.iter().map(|entry| entry.words.clone()).collect();
        let Some(mutation) = mutation_engine.mutate_from_corpus(&parent.words, &corpus_words)
        else {
            continue;
        };
        let words = mutation.words;
        if words.is_empty() || !backend.is_usable_seed(&words) {
            mutation_engine.record_reward(mutation.arm_index, 0.0);
            continue;
        }

        let mut mutation_meta = metadata_object(&parent.metadata);
        mutation_meta.insert("origin".to_string(), json!("mutation"));
        mutation_meta.insert("mutation_iteration".to_string(), json!(iter));
        mutation_meta.insert("parent_corpus_index".to_string(), json!(parent_index));
        mutation_meta.insert("parent_seed_index".to_string(), json!(parent.seed_index));
        mutation_meta.insert("mutation_arm".to_string(), json!(mutation.arm.as_str()));
        mutation_meta.insert("mutation_arm_index".to_string(), json!(mutation.arm_index));
        let seed_meta = serde_json::Value::Object(mutation_meta);

        if backend.rv32_oracle_models_words(&words) {
            if let Some(error) = oracle_precheck_error(&cfg, &words) {
                let mut skipped = EvalStats::default();
                skipped.phase = "baseline".to_string();
                skipped.oracle_error = Some(error);
                eval_id = eval_id.saturating_add(1);
                let elapsed_ms = run_start.elapsed().as_millis() as u64;
                write_run_record(
                    &cfg,
                    &run_writer,
                    run_started_at_ms,
                    elapsed_ms,
                    eval_id,
                    &words,
                    parent.seed_index,
                    &seed_meta,
                    &skipped,
                    None,
                )?;
                mutation_engine.record_reward(mutation.arm_index, 0.0);
                continue;
            }
        }

        backend.clear_semantic_injection();
        let baseline = eval_once(&cfg, &mut backend, &words);
        eval_id = eval_id.saturating_add(1);
        let elapsed_ms = run_start.elapsed().as_millis() as u64;
        write_run_record(
            &cfg,
            &run_writer,
            run_started_at_ms,
            elapsed_ms,
            eval_id,
            &words,
            parent.seed_index,
            &seed_meta,
            &baseline,
            None,
        )?;
        if write_bug_record(
            &cfg,
            &bug_writer,
            &mut bug_filter,
            run_started_at_ms,
            elapsed_ms,
            &words,
            parent.seed_index,
            &seed_meta,
            &baseline,
            None,
        )? {
            bug_count = bug_count.saturating_add(1);
        }

        let (is_new_signature, new_individual) =
            record_novelty(&baseline, &mut seen_signatures, &mut seen_individual_buckets);
        let mut reward = if is_new_signature { 1.0 } else { 0.0 };
        reward += 0.25 * new_individual as f64;

        if is_new_signature {
            let mut extra = serde_json::Map::new();
            extra.insert("mutation_iteration".to_string(), json!(iter));
            extra.insert("parent_corpus_index".to_string(), json!(parent_index));
            extra.insert("parent_seed_index".to_string(), json!(parent.seed_index));
            extra.insert("mutation_arm".to_string(), json!(mutation.arm.as_str()));
            extra.insert("mutation_arm_index".to_string(), json!(mutation.arm_index));
            write_corpus_record(
                &cfg,
                &corpus_writer,
                run_started_at_ms,
                elapsed_ms,
                &words,
                parent.seed_index,
                &seed_meta,
                &baseline,
                "mutated_seed",
                Some(extra),
            )?;
            mutation_corpus.push(CorpusEntry {
                words: words.clone(),
                metadata: seed_meta.clone(),
                seed_index: parent.seed_index,
            });
        }

        mutation_engine.record_reward(mutation.arm_index, reward);

        if !cfg.semantic_search_enabled {
            backend.clear_semantic_injection();
            continue;
        }

        let candidates = backend
            .semantic_injection_candidates(&baseline.bucket_hits)
            .into_iter()
            .filter(|candidate| {
                semantic_candidate_matches_target(
                    candidate,
                    target_bucket_prefix.as_deref(),
                    target_inject_kind_prefix.as_deref(),
                )
            });
        let mut attempted = HashSet::<(String, u64)>::new();

        for candidate in candidates {
            let steps = candidate_steps(&cfg, &candidate);
            if steps.is_empty() {
                continue;
            }
            let mut consecutive_noops = 0usize;

            for (attempt_index, step) in steps.into_iter().enumerate() {
                let attempt_key = (candidate.inject_kind.clone(), step);
                if !attempted.insert(attempt_key) {
                    continue;
                }

                backend.clear_semantic_injection();
                backend.arm_semantic_injection(&candidate.inject_kind, step)?;

                let mut injected = eval_once(&cfg, &mut backend, &words);
                injected.phase = "semantic_search".to_string();
                injected.semantic_class = Some(candidate.semantic_class.clone());
                injected.inject_kind = Some(candidate.inject_kind.clone());
                injected.inject_step = Some(step);
                injected.trigger_bucket_id = Some(candidate.bucket_id.clone());
                injected.trigger_signal_id = candidate.trigger_signal_id.clone();
                injected.baseline_bucket_hits_sig = Some(baseline.bucket_hits_sig.clone());
                let expected_relation = backend.semantic_mutation_relation(&candidate);
                let relation_validated = semantic_underconstrained_candidate(
                    backend.supports_underconstrained_reporting(),
                    &baseline,
                    &injected,
                    &candidate,
                    expected_relation,
                );
                injected.semantic_relation_validated = relation_validated;
                injected.underconstrained_candidate = relation_validated;

                eval_id = eval_id.saturating_add(1);
                let elapsed_ms = run_start.elapsed().as_millis() as u64;
                write_run_record(
                    &cfg,
                    &run_writer,
                    run_started_at_ms,
                    elapsed_ms,
                    eval_id,
                    &words,
                    parent.seed_index,
                    &seed_meta,
                    &injected,
                    Some(attempt_index),
                )?;
                if write_bug_record(
                    &cfg,
                    &bug_writer,
                    &mut bug_filter,
                    run_started_at_ms,
                    elapsed_ms,
                    &words,
                    parent.seed_index,
                    &seed_meta,
                    &injected,
                    Some(attempt_index),
                )? {
                    bug_count = bug_count.saturating_add(1);
                }
                if injected.semantic_injection_applied {
                    consecutive_noops = 0;
                } else {
                    consecutive_noops = consecutive_noops.saturating_add(1);
                    if consecutive_noops >= 4 {
                        break;
                    }
                }
            }
        }

        backend.clear_semantic_injection();
    }

    corpus_writer.flush()?;
    bug_writer.flush()?;
    run_writer.flush()?;

    if bug_count > 0 {
        eprintln!("[BENCHMARK][DONE] bug_records={bug_count}");
    } else {
        eprintln!("[BENCHMARK][DONE] bug_records=0");
    }

    Ok(BenchmarkOutputs { corpus_path, bugs_path, runs_path: Some(runs_path) })
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        bug_kind, centered_steps, entrypoint_mismatch_explained, eval_once, exact_exception_reporting_identity,
        load_initial_seeds, long_tail_quota, seed_content_hash,
        exact_semantic_reporting_identity, initial_schedule_take_count, initial_seed_lane,
        is_reportable_exception, ordinary_generated_carriers, ordinary_seed_schedule,
        receipt_matches_exact_baseline_hit, resolved_benchmark_out_dir, run_benchmark,
        schedule_initial_seeds, scrub_caller_reporting_metadata, semantic_candidate_matches_target,
        semantic_underconstrained_candidate, sweep_steps, valid_address_space_receipt,
        valid_auipc_pc_limb_receipt, valid_divrem_special_case_receipt,
        valid_entrypoint_pc_receipt, valid_executed_control_flow_receipt,
        valid_full_limb_value_representation_receipt, valid_memory_immediate_sign_receipt,
        valid_memory_selector_receipt, valid_monotonic_timestamp_receipt,
        valid_opcode_selector_receipt, valid_store_load_payload_receipt,
        valid_timestamp_origin_wrap_receipt, valid_upper_immediate_receipt,
        valid_volatile_boundary_range_receipt, write_bug_record, BackendEval, BenchmarkBackend,
        BenchmarkConfig, EvalStats, ExecutedExceptionEffect, ExecutedExceptionReceipt,
        FrozenFindingReportIdentity, InjectionSchedule, SemanticInjectionCandidate,
        SemanticMutationReceipt, SemanticMutationRelation, ORDINARY_GENERATED_CARRIER_BUDGET,
    };
    use crate::fuzz::bug_filter::BugNoveltyFilter;
    use crate::fuzz::jsonl::JsonlWriter;
    use super::SemanticMutationEffect;
    use crate::rv32im::oracle::{OracleConfig, RISCVOracle};
    use crate::trace::BucketHit;
    use serde_json::json;

    #[test]
    fn benchmark_output_directory_override_is_generic_and_optional() {
        let configured = std::path::Path::new("configured-output");
        assert_eq!(resolved_benchmark_out_dir(configured, None), configured);
        assert_eq!(
            resolved_benchmark_out_dir(configured, Some("campaign-output".into())),
            std::path::PathBuf::from("campaign-output")
        );
    }

    #[test]
    fn ordinary_initial_scheduler_round_robins_semantic_carrier_families() {
        let lane_words = [
            vec![0x0010_0093],
            vec![0x8000_00b7, 0xfff0_0113, 0x0220_c1b3],
            vec![0x0010_0093, 0x0020_c063, 0x0030_0193],
            vec![0x0010_0093, 0x0020_0113, 0x0000_0073],
            vec![0x0010_0093, 0x0020_a023, 0x0000_a183],
            vec![0x0010_0093, 0x0020_0113, 0x0000_a183],
            vec![0x1234_50b7, 0x0010_0113, 0x0020_0193],
            vec![0x0010_0093, 0x0020_0113, 0x0020_81b3],
        ];
        for (expected, words) in lane_words.iter().enumerate() {
            assert_eq!(initial_seed_lane(words), expected);
        }

        let seeds = lane_words
            .iter()
            .rev()
            .flat_map(|words| {
                (0..2).map(move |copy| {
                    (
                        super::encode_words(words),
                        json!({"lane": initial_seed_lane(words), "copy": copy}),
                    )
                })
            })
            .collect();
        let scheduled = schedule_initial_seeds(seeds, 256);
        let first_round = scheduled
            .iter()
            .take(8)
            .map(|(_, metadata)| metadata["lane"].as_u64().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(first_round, (0..8).collect::<Vec<_>>());
        assert_eq!(scheduled.len(), 16);
    }

    #[test]
    fn ordinary_generator_has_fixed_generic_ecall_short_div_and_memory_prefix() {
        let carriers = ordinary_generated_carriers(256, &|_| true);
        assert_eq!(carriers.len(), ORDINARY_GENERATED_CARRIER_BUDGET);

        let decoded = carriers
            .iter()
            .enumerate()
            .map(|(scheduled_rank, (input, metadata))| {
                assert_eq!(metadata["source"], json!("ordinary_generator"));
                assert_eq!(metadata["generator"], json!("bounded_rv32im_carriers_v1"));
                assert_eq!(metadata["ordinary_generator_rank"], json!(scheduled_rank));
                assert_eq!(
                    metadata["ordinary_generator_budget"],
                    json!(ORDINARY_GENERATED_CARRIER_BUDGET)
                );
                assert!(metadata.get("case_id").is_none());
                (
                    super::decode_words_from_input(input, 256),
                    metadata["carrier_family"].as_str().unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let ecall = decoded
            .iter()
            .enumerate()
            .filter(|(_, (_, family))| *family == "ecall")
            .collect::<Vec<_>>();
        assert_eq!(ecall.len(), 3);
        assert!(ecall.iter().all(|(rank, (words, _))| {
            *rank <= 2 && words.iter().any(|word| *word == 0x0000_0073)
        }));

        let div = decoded
            .iter()
            .enumerate()
            .filter(|(_, (_, family))| *family == "signed_div_overflow")
            .collect::<Vec<_>>();
        assert_eq!(div.len(), 2);
        assert_eq!(div.iter().map(|(rank, _)| *rank).collect::<Vec<_>>(), vec![5, 6]);
        let div_registers = div
            .iter()
            .map(|(_, (words, _))| {
                let word = words
                    .iter()
                    .copied()
                    .find(|word| {
                        word & 0x7f == 0x33
                            && (word >> 12) & 0x7 == 0x4
                            && (word >> 25) & 0x7f == 0x01
                    })
                    .unwrap();
                ((word >> 15) & 0x1f, (word >> 20) & 0x1f, (word >> 7) & 0x1f)
            })
            .collect::<Vec<_>>();
        assert_eq!(div_registers, vec![(1, 2, 3), (5, 6, 7)]);

        let paired_memory = decoded
            .iter()
            .enumerate()
            .filter(|(_, (_, family))| *family == "paired_store_load")
            .collect::<Vec<_>>();
        assert_eq!(paired_memory.len(), 2);
        assert_eq!(
            paired_memory.iter().map(|(rank, _)| *rank).collect::<Vec<_>>(),
            vec![8, 9]
        );
        let memory_registers = paired_memory
            .iter()
            .map(|(_, (words, _))| {
                let store = words.iter().copied().find(|word| word & 0x7f == 0x23).unwrap();
                let load = words.iter().copied().find(|word| word & 0x7f == 0x03).unwrap();
                let store_imm = (((store >> 25) << 5) | ((store >> 7) & 0x1f)) & 0xfff;
                let load_imm = (load >> 20) & 0xfff;
                (
                    (store >> 15) & 0x1f,
                    (store >> 20) & 0x1f,
                    (load >> 7) & 0x1f,
                    store_imm,
                    load_imm,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(memory_registers, vec![(1, 2, 3, 0, 0), (5, 6, 7, 4, 4)]);
        assert!(paired_memory.iter().all(|(_, (words, _))| initial_seed_lane(words) == 4));
    }

    #[test]
    fn ordinary_generated_prefix_is_independent_of_file_seed_order_and_deduplicates() {
        let file_seeds = vec![
            (super::encode_words(&[0x0000_0073]), json!({"source": "file-duplicate"})),
            (super::encode_words(&[0x1234_50b7]), json!({"source": "file-unique"})),
        ];
        let scheduled = ordinary_seed_schedule(file_seeds, 256, &|_| true);
        assert_eq!(scheduled.len(), ORDINARY_GENERATED_CARRIER_BUDGET + 1);
        assert!(scheduled
            .iter()
            .take(ORDINARY_GENERATED_CARRIER_BUDGET)
            .all(|(_, metadata)| metadata["source"] == json!("ordinary_generator")));
        assert_eq!(scheduled[ORDINARY_GENERATED_CARRIER_BUDGET].1["source"], json!("file-unique"));
    }

    #[test]
    fn initial_limit_counts_requested_file_rows_in_addition_to_generated_prefix() {
        assert_eq!(initial_schedule_take_count(0, 10, 15), 15);
        assert_eq!(initial_schedule_take_count(1, 10, 15), 11);
        assert_eq!(initial_schedule_take_count(3, 10, 15), 13);
        assert_eq!(initial_schedule_take_count(99, 10, 15), 15);
        assert_eq!(initial_schedule_take_count(1, 0, 5), 1);
    }

    #[derive(Default)]
    struct SleepyBackend {
        sleep_for: Duration,
    }

    impl BenchmarkBackend for SleepyBackend {
        fn prove_and_read_final_regs(&mut self, _words: &[u32]) -> Result<[u32; 32], String> {
            thread::sleep(self.sleep_for);
            Ok([0; 32])
        }

        fn collect_eval(&mut self) -> BackendEval {
            BackendEval::default()
        }
    }

    #[derive(Default)]
    struct MultiCandidateBackend {
        armed: Option<String>,
    }

    impl BenchmarkBackend for MultiCandidateBackend {
        fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
            Ok(RISCVOracle::execute_with_config(words, OracleConfig::default()))
        }

        fn collect_eval(&mut self) -> BackendEval {
            let semantic_mutation_receipt =
                self.armed.as_ref().map(|kind| SemanticMutationReceipt {
                    inject_kind: kind.clone(),
                    site: "generic-test-row:0".to_string(),
                    field: "witness_value".to_string(),
                    step: 0,
                    before: json!(1),
                    after: json!(2),
                    effect: SemanticMutationEffect {
                        relation: SemanticMutationRelation::WitnessValueChanged,
                        preserved_before: None,
                        preserved_after: None,
                        context: Default::default(),
                    },
                });
            BackendEval {
                semantic_injection_applied: self.armed.is_some(),
                semantic_mutation_receipt,
                ..BackendEval::default()
            }
        }

        fn clear_semantic_injection(&mut self) {
            self.armed = None;
        }

        fn arm_semantic_injection(&mut self, kind: &str, _step: u64) -> Result<(), String> {
            self.armed = Some(kind.to_string());
            Ok(())
        }

        fn semantic_mutation_relation(
            &self,
            _candidate: &SemanticInjectionCandidate,
        ) -> Option<SemanticMutationRelation> {
            Some(SemanticMutationRelation::WitnessValueChanged)
        }

        fn semantic_injection_candidates(
            &self,
            _hits: &[crate::trace::BucketHit],
        ) -> Vec<SemanticInjectionCandidate> {
            vec![
                SemanticInjectionCandidate {
                    bucket_id: "sem.exec.op_selector_binding".to_string(),
                    trigger_signal_id: None,
                    semantic_class: "semantic.exec.op_selector_binding".to_string(),
                    inject_kind: "test.semantic.first".to_string(),
                    schedule: InjectionSchedule::Exact(0),
                },
                SemanticInjectionCandidate {
                    bucket_id: "sem.time.boundary_origin_consistency".to_string(),
                    trigger_signal_id: None,
                    semantic_class: "semantic.time.boundary_origin_consistency".to_string(),
                    inject_kind: "test.semantic.second".to_string(),
                    schedule: InjectionSchedule::Exact(0),
                },
            ]
        }
    }

    #[derive(Default)]
    struct DirtyBaselineBackend {
        armed: Option<String>,
    }

    impl BenchmarkBackend for DirtyBaselineBackend {
        fn prove_and_read_final_regs(&mut self, _words: &[u32]) -> Result<[u32; 32], String> {
            let mut regs = [0; 32];
            regs[1] = 1;
            Ok(regs)
        }

        fn collect_eval(&mut self) -> BackendEval {
            BackendEval {
                semantic_injection_applied: self.armed.is_some(),
                ..BackendEval::default()
            }
        }

        fn clear_semantic_injection(&mut self) {
            self.armed = None;
        }

        fn arm_semantic_injection(&mut self, kind: &str, _step: u64) -> Result<(), String> {
            self.armed = Some(kind.to_string());
            Ok(())
        }

        fn semantic_injection_candidates(
            &self,
            _hits: &[crate::trace::BucketHit],
        ) -> Vec<SemanticInjectionCandidate> {
            vec![SemanticInjectionCandidate {
                bucket_id: "sem.memory.load_value_binding".to_string(),
                trigger_signal_id: None,
                semantic_class: "semantic.memory.load_value_binding".to_string(),
                inject_kind: "test.semantic.memory.load_value_binding".to_string(),
                schedule: InjectionSchedule::Exact(0),
            }]
        }
    }

    #[derive(Default)]
    struct UnsupportedUnderconstrainedBackend {
        inner: MultiCandidateBackend,
    }

    impl BenchmarkBackend for UnsupportedUnderconstrainedBackend {
        fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
            self.inner.prove_and_read_final_regs(words)
        }

        fn collect_eval(&mut self) -> BackendEval {
            self.inner.collect_eval()
        }

        fn clear_semantic_injection(&mut self) {
            self.inner.clear_semantic_injection();
        }

        fn arm_semantic_injection(&mut self, kind: &str, step: u64) -> Result<(), String> {
            self.inner.arm_semantic_injection(kind, step)
        }

        fn supports_underconstrained_reporting(&self) -> bool {
            false
        }

        fn semantic_injection_candidates(
            &self,
            hits: &[crate::trace::BucketHit],
        ) -> Vec<SemanticInjectionCandidate> {
            self.inner.semantic_injection_candidates(hits)
        }
    }

    fn test_config() -> BenchmarkConfig {
        BenchmarkConfig {
            zkvm_tag: "test".to_string(),
            zkvm_commit: "test".to_string(),
            rng_seed: 0,
            oracle: OracleConfig::default(),
            seeds_jsonl: Default::default(),
            out_dir: Default::default(),
            output_prefix: None,
            initial_limit: 0,
            mutation_iterations: 0,
            max_instructions: 0,
            long_tail_max_instructions: 0,
            precheck_oracle_max_steps: 0,
            semantic_search_enabled: false,
            semantic_window_before: 0,
            semantic_window_after: 0,
            semantic_step_stride: 0,
            semantic_max_trials_per_bucket: 0,
            stack_size_bytes: 0,
        }
    }

    fn receipt_candidate() -> SemanticInjectionCandidate {
        SemanticInjectionCandidate {
            bucket_id: "sem.memory.load_value_binding".to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.memory.load_value_binding".to_string(),
            inject_kind: "vm.semantic.memory.load_value_binding".to_string(),
            schedule: InjectionSchedule::Exact(0),
        }
    }

    fn changed_receipt(relation: SemanticMutationRelation) -> SemanticMutationReceipt {
        SemanticMutationReceipt {
            inject_kind: "vm.semantic.memory.load_value_binding".to_string(),
            site: "memory-row:0".to_string(),
            field: "value".to_string(),
            step: 0,
            before: json!(1),
            after: json!(2),
            effect: SemanticMutationEffect {
                relation,
                preserved_before: None,
                preserved_after: None,
                context: Default::default(),
            },
        }
    }

    fn monotonic_timestamp_candidate() -> SemanticInjectionCandidate {
        SemanticInjectionCandidate {
            bucket_id: "sem.time.monotonic_access_ordering".to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.time.monotonic_access_ordering".to_string(),
            inject_kind: concat!(
                "openvm.semantic.time.monotonic_access_ordering",
                "::cell_id=ts2.consecutive"
            )
            .to_string(),
            schedule: InjectionSchedule::Exact(7),
        }
    }

    fn monotonic_timestamp_receipt() -> SemanticMutationReceipt {
        SemanticMutationReceipt {
            inject_kind: monotonic_timestamp_candidate().inject_kind,
            site: "memory_controller.generate_base_aux".to_string(),
            field: "prev_timestamp".to_string(),
            step: 7,
            before: json!(10),
            after: json!(11),
            effect: SemanticMutationEffect {
                relation: SemanticMutationRelation::WitnessValueChanged,
                preserved_before: None,
                preserved_after: None,
                context: serde_json::Map::from_iter([
                    ("obligation_id".to_string(), json!("ts2")),
                    ("cell_id".to_string(), json!("ts2.consecutive")),
                    ("previous_timestamp".to_string(), json!(10)),
                    ("timestamp".to_string(), json!(11)),
                    ("ts_diff".to_string(), json!(1)),
                    ("before_strictly_ordered".to_string(), json!(true)),
                    ("after_strictly_ordered".to_string(), json!(false)),
                ]),
            },
        }
    }

    #[test]
    fn monotonic_timestamp_receipt_is_positive_control_and_fail_closed() {
        let candidate = monotonic_timestamp_candidate();
        let receipt = monotonic_timestamp_receipt();
        assert!(valid_monotonic_timestamp_receipt(&receipt, &candidate));

        let mut wrong_cell = receipt.clone();
        wrong_cell.effect.context.insert("cell_id".to_string(), json!("ts2.small_gap"));
        assert!(!valid_monotonic_timestamp_receipt(&wrong_cell, &candidate));

        let mut wrong_before = receipt.clone();
        wrong_before.before = json!(11);
        assert!(!valid_monotonic_timestamp_receipt(&wrong_before, &candidate));

        let mut still_ordered = receipt;
        still_ordered.after = json!(10);
        assert!(!valid_monotonic_timestamp_receipt(&still_ordered, &candidate));
    }

    #[test]
    fn centered_steps_expand_from_anchor() {
        assert_eq!(centered_steps(10, 2, 3, 1, 16), vec![10, 9, 11, 8, 12, 13]);
    }

    #[test]
    fn centered_steps_obey_stride_and_limit() {
        assert_eq!(centered_steps(10, 6, 6, 2, 3), vec![10, 8, 12]);
    }

    #[test]
    fn sweep_steps_respects_stride() {
        assert_eq!(sweep_steps(3, 10, 3, 8), vec![3, 6, 9]);
    }

    #[test]
    fn bug_kind_treats_only_baseline_mismatch_as_mismatch() {
        let mut baseline = EvalStats::default();
        baseline.phase = "baseline".to_string();
        baseline.mismatch_regs = vec![(1, 2, 3)];
        assert_eq!(bug_kind(&baseline), Some("mismatch"));

        let mut injected = EvalStats::default();
        injected.phase = "semantic_search".to_string();
        injected.semantic_injection_applied = true;
        injected.mismatch_regs = vec![(1, 2, 3)];
        injected.underconstrained_candidate = true;
        assert_eq!(bug_kind(&injected), Some("underconstrained_candidate"));
    }

    #[test]
    fn semantic_underconstrained_candidate_requires_clean_baseline() {
        let baseline = EvalStats::default();
        let candidate = receipt_candidate();
        let mut injected = EvalStats::default();
        injected.phase = "semantic_search".to_string();
        injected.semantic_injection_applied = true;
        injected.inject_kind = Some("vm.semantic.memory.load_value_binding".to_string());
        injected.inject_step = Some(0);
        injected.semantic_mutation_receipt =
            Some(changed_receipt(SemanticMutationRelation::WitnessValueChanged));
        assert!(!semantic_underconstrained_candidate(
            true,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));

        let mut dirty_baseline = baseline.clone();
        dirty_baseline.mismatch_regs = vec![(1, 2, 3)];
        assert!(!semantic_underconstrained_candidate(
            true,
            &dirty_baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));

        let mut rejected_baseline = baseline.clone();
        rejected_baseline.backend_error = Some("baseline backend failed".to_string());
        assert!(!semantic_underconstrained_candidate(
            true,
            &rejected_baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));

        let mut applied_baseline = baseline.clone();
        applied_baseline.semantic_injection_applied = true;
        assert!(!semantic_underconstrained_candidate(
            true,
            &applied_baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));

        let mut stale_semantic_baseline = baseline.clone();
        stale_semantic_baseline.semantic_mutation_receipt =
            Some(changed_receipt(SemanticMutationRelation::WitnessValueChanged));
        assert!(!semantic_underconstrained_candidate(
            true,
            &stale_semantic_baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));

        let mut stale_exception_baseline = baseline;
        stale_exception_baseline.executed_exception_receipt = Some(ExecutedExceptionReceipt {
            effect: ExecutedExceptionEffect::DoryShortTraceCapacity,
            obligation_id: "pd2".to_string(),
            cell_id: "pd2.very_short".to_string(),
            stage: "prover.dory".to_string(),
            step: 0,
            context: Default::default(),
        });
        assert!(!semantic_underconstrained_candidate(
            true,
            &stale_exception_baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));
    }

    #[test]
    fn semantic_underconstrained_candidate_requires_backend_support() {
        let baseline = EvalStats::default();
        let candidate = receipt_candidate();
        let mut injected = EvalStats::default();
        injected.phase = "semantic_search".to_string();
        injected.semantic_injection_applied = true;
        injected.inject_kind = Some("vm.semantic.memory.load_value_binding".to_string());
        injected.inject_step = Some(0);
        injected.semantic_mutation_receipt =
            Some(changed_receipt(SemanticMutationRelation::WitnessValueChanged));

        assert!(!semantic_underconstrained_candidate(
            false,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));
    }

    #[test]
    fn semantic_receipt_is_required_and_fail_closed() {
        let baseline = EvalStats::default();
        let candidate = receipt_candidate();
        let mut injected = EvalStats {
            phase: "semantic_search".to_string(),
            semantic_injection_applied: true,
            inject_kind: Some(candidate.inject_kind.clone()),
            inject_step: Some(0),
            ..EvalStats::default()
        };
        assert!(!semantic_underconstrained_candidate(
            true,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));
        injected.semantic_mutation_receipt =
            Some(changed_receipt(SemanticMutationRelation::WitnessValueChanged));
        assert!(
            !semantic_underconstrained_candidate(true, &baseline, &injected, &candidate, None,)
        );
    }

    #[test]
    fn semantic_receipt_requires_applied_signal_and_clean_injected_result() {
        let baseline = EvalStats::default();
        let candidate = receipt_candidate();
        let mut injected = EvalStats {
            inject_kind: Some(candidate.inject_kind.clone()),
            inject_step: Some(0),
            semantic_mutation_receipt: Some(changed_receipt(
                SemanticMutationRelation::WitnessValueChanged,
            )),
            ..EvalStats::default()
        };

        assert!(!semantic_underconstrained_candidate(
            true,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));

        injected.semantic_injection_applied = true;
        assert!(!semantic_underconstrained_candidate(
            true,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));

        injected.mismatch_regs = vec![(1, 2, 3)];
        assert!(!semantic_underconstrained_candidate(
            true,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::WitnessValueChanged),
        ));
    }

    #[test]
    fn coarse_value_preserving_relation_fails_closed_without_typed_recomposition() {
        let baseline = EvalStats::default();
        let candidate = receipt_candidate();
        let mut receipt = changed_receipt(SemanticMutationRelation::ValuePreservingRepresentation);
        receipt.effect.preserved_before = Some(json!(20));
        receipt.effect.preserved_after = Some(json!(276));
        let mut injected = EvalStats {
            inject_kind: Some(candidate.inject_kind.clone()),
            inject_step: Some(0),
            semantic_injection_applied: true,
            semantic_mutation_receipt: Some(receipt.clone()),
            ..EvalStats::default()
        };
        assert!(!semantic_underconstrained_candidate(
            true,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::ValuePreservingRepresentation),
        ));
        receipt.effect.preserved_after = Some(json!(20));
        injected.semantic_mutation_receipt = Some(receipt);
        assert!(!semantic_underconstrained_candidate(
            true,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::ValuePreservingRepresentation),
        ));
    }

    #[test]
    fn semantic_receipt_boolean_source_selector_rejects_unbound_or_wrong_receipts() {
        let baseline = EvalStats::default();
        let candidate = receipt_candidate();
        let mut receipt = changed_receipt(SemanticMutationRelation::BooleanSourceSelector);
        receipt.before = json!(1);
        receipt.after = json!(2);
        receipt.effect.context.insert("source_row".to_string(), json!(true));
        receipt.effect.context.insert("cell_id".to_string(), json!("bu1.real_row"));
        receipt.effect.context.insert("selector_before".to_string(), json!(1));
        receipt.effect.context.insert("selector_after".to_string(), json!(2));
        let mut injected = EvalStats {
            inject_kind: Some(candidate.inject_kind.clone()),
            inject_step: Some(0),
            semantic_injection_applied: true,
            semantic_mutation_receipt: Some(receipt.clone()),
            ..EvalStats::default()
        };
        assert!(!semantic_underconstrained_candidate(
            true,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::BooleanSourceSelector),
        ));

        receipt.effect.context.insert("source_row".to_string(), json!(false));
        injected.semantic_mutation_receipt = Some(receipt.clone());
        assert!(!semantic_underconstrained_candidate(
            true,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::BooleanSourceSelector),
        ));

        receipt.effect.context.insert("source_row".to_string(), json!(true));
        receipt.after = json!(3);
        injected.semantic_mutation_receipt = Some(receipt);
        assert!(!semantic_underconstrained_candidate(
            true,
            &baseline,
            &injected,
            &candidate,
            Some(SemanticMutationRelation::BooleanSourceSelector),
        ));
    }

    fn exact_receipt(
        candidate: &SemanticInjectionCandidate,
        relation: SemanticMutationRelation,
        before: serde_json::Value,
        after: serde_json::Value,
        context: serde_json::Map<String, serde_json::Value>,
    ) -> SemanticMutationReceipt {
        SemanticMutationReceipt {
            inject_kind: candidate.inject_kind.clone(),
            site: "exact-row:0".to_string(),
            field: "exact_field".to_string(),
            step: 0,
            before,
            after,
            effect: SemanticMutationEffect {
                relation,
                preserved_before: None,
                preserved_after: None,
                context,
            },
        }
    }

    #[test]
    fn auipc_pc_limb_relation_consumes_variant_and_rejects_unchanged_or_canonical_limb() {
        const BABYBEAR_MODULUS: u64 = 2013265921;
        let candidate = SemanticInjectionCandidate {
            bucket_id: "sem.control.auipc_pc_limb_consistency".to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.control.auipc_pc_limb_consistency".to_string(),
            inject_kind: "openvm.semantic.control.auipc_pc_limb_consistency::mode=from_pc_high_single_mod_p,slot=1,strength=0,mult=1".to_string(),
            schedule: InjectionSchedule::Exact(0),
        };
        let selected_after = 2 + BABYBEAR_MODULUS;
        let context = serde_json::Map::from_iter([
            ("cell_id".to_string(), json!("id3.auipc_no_wrap")),
            ("mode".to_string(), json!("from_pc_high_single_mod_p")),
            ("slot".to_string(), json!(1)),
            ("strength".to_string(), json!(0)),
            ("mult".to_string(), json!(1)),
            ("radix".to_string(), json!(256)),
            ("limb_bound".to_string(), json!(256)),
            ("modulus".to_string(), json!(BABYBEAR_MODULUS)),
            ("before_limbs".to_string(), json!([1, 2, 0, 0])),
            ("after_limbs".to_string(), json!([1, selected_after, 0, 0])),
            ("pc".to_string(), json!(513)),
            ("from_pc".to_string(), json!(513)),
            ("selected_before".to_string(), json!(2)),
            ("selected_after".to_string(), json!(selected_after)),
            ("recomposed_before".to_string(), json!(513)),
            ("recomposed_after".to_string(), json!(513u128 + u128::from(BABYBEAR_MODULUS) * 256)),
        ]);
        let mut receipt = exact_receipt(
            &candidate,
            SemanticMutationRelation::AuipcPcLimbRepresentation,
            json!(2),
            json!(selected_after),
            context,
        );
        assert!(valid_auipc_pc_limb_receipt(&receipt, &candidate));
        receipt.effect.context.insert("slot".to_string(), json!(2));
        assert!(!valid_auipc_pc_limb_receipt(&receipt, &candidate));
        receipt.effect.context.insert("slot".to_string(), json!(1));
        // A byte-range delta (no longer congruent mod p) must fail closed.
        receipt
            .effect
            .context
            .insert("after_limbs".to_string(), json!([1, 258, 0, 0]));
        receipt.effect.context.insert("selected_after".to_string(), json!(258));
        receipt.after = json!(258);
        assert!(!valid_auipc_pc_limb_receipt(&receipt, &candidate));
    }

    #[test]
    fn entrypoint_mismatch_requires_exact_explained_divergence_set() {
        let candidate = SemanticInjectionCandidate {
            bucket_id: "sem.control.entrypoint_binding".to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.control.entrypoint_binding".to_string(),
            inject_kind: "jolt.semantic.control.entrypoint_binding".to_string(),
            schedule: InjectionSchedule::Exact(0),
        };
        let context = serde_json::Map::from_iter([
            ("mutation_mode".to_string(), json!("skip_one")),
            (
                "explained_mismatches".to_string(),
                json!([{"reg": 6, "oracle": 7, "backend": 0}]),
            ),
        ]);
        let receipt = exact_receipt(
            &candidate,
            SemanticMutationRelation::EntrypointPcEquation,
            json!(0x8000_0000u64),
            json!(0x8000_0004u64),
            context,
        );
        let mut injected = EvalStats {
            mismatch_regs: vec![(6, 7, 0)],
            ..EvalStats::default()
        };
        assert!(entrypoint_mismatch_explained(&injected, &receipt));
        // An unexplained extra mismatch must fail closed.
        injected.mismatch_regs = vec![(6, 7, 0), (1, 2, 3)];
        assert!(!entrypoint_mismatch_explained(&injected, &receipt));
        // A wrong backend value must fail closed.
        injected.mismatch_regs = vec![(6, 7, 1)];
        assert!(!entrypoint_mismatch_explained(&injected, &receipt));
        // Empty divergence claims must not explain a real mismatch.
        injected.mismatch_regs = vec![(6, 7, 0)];
        let mut no_claims = receipt.clone();
        no_claims
            .effect
            .context
            .insert("explained_mismatches".to_string(), json!([]));
        assert!(!entrypoint_mismatch_explained(&injected, &no_claims));
    }

    #[test]
    fn memory_immediate_sign_relation_checks_both_effective_pointer_equations() {
        let candidate = SemanticInjectionCandidate {
            bucket_id: "sem.memory.immediate_sign_consistency".to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.memory.immediate_sign_consistency".to_string(),
            inject_kind: "openvm.semantic.memory.immediate_sign_consistency::mode=flip_sign,domain=load,guard=none".to_string(),
            schedule: InjectionSchedule::Exact(0),
        };
        let context = serde_json::Map::from_iter([
            ("cell_id".to_string(), json!("id2.i_neg")),
            ("mode".to_string(), json!("flip_sign")),
            ("domain".to_string(), json!("load")),
            ("guard".to_string(), json!("none")),
            ("sign_before".to_string(), json!(1)),
            ("sign_after".to_string(), json!(0)),
            ("base".to_string(), json!(4096)),
            ("immediate".to_string(), json!(65532)),
            ("extended_before".to_string(), json!(4_294_967_292u64)),
            ("extended_after".to_string(), json!(65532)),
            ("effective_before".to_string(), json!(4092)),
            ("effective_after".to_string(), json!(69628)),
        ]);
        let mut receipt = exact_receipt(
            &candidate,
            SemanticMutationRelation::MemoryImmediateSignEquation,
            json!(1),
            json!(0),
            context,
        );
        assert!(valid_memory_immediate_sign_receipt(&receipt, &candidate));
        receipt.effect.context.insert("effective_after".to_string(), json!(69629));
        assert!(!valid_memory_immediate_sign_receipt(&receipt, &candidate));
        receipt.effect.context.insert("effective_after".to_string(), json!(69628));
        receipt.effect.context.insert("guard".to_string(), json!("unsupported"));
        assert!(!valid_memory_immediate_sign_receipt(&receipt, &candidate));
    }

    #[test]
    fn timestamp_origin_relation_requires_near_modulus_wrap_and_ts1_cell() {
        let candidate = SemanticInjectionCandidate {
            bucket_id: "sem.time.boundary_origin_consistency".to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.time.boundary_origin_consistency".to_string(),
            inject_kind:
                "openvm.semantic.time.boundary_origin_consistency::mode=wrap_origin,increment=2"
                    .to_string(),
            schedule: InjectionSchedule::Exact(0),
        };
        let context = serde_json::Map::from_iter([
            ("cell_id".to_string(), json!("ts1.standard")),
            ("mode".to_string(), json!("wrap_origin")),
            ("modulus".to_string(), json!(17)),
            ("origin_before".to_string(), json!(0)),
            ("origin_after".to_string(), json!(16)),
            ("increment".to_string(), json!(2)),
            ("later_before".to_string(), json!(2)),
            ("later_after".to_string(), json!(1)),
            ("near_modulus".to_string(), json!(true)),
            ("wrapped".to_string(), json!(true)),
        ]);
        let mut receipt = exact_receipt(
            &candidate,
            SemanticMutationRelation::TimestampOriginWrap,
            json!(0),
            json!(16),
            context,
        );
        assert!(valid_timestamp_origin_wrap_receipt(&receipt, &candidate));
        receipt.effect.context.insert("cell_id".to_string(), json!("ts3.standard"));
        assert!(!valid_timestamp_origin_wrap_receipt(&receipt, &candidate));
        receipt.effect.context.insert("cell_id".to_string(), json!("ts1.standard"));
        receipt.effect.context.insert("later_after".to_string(), json!(2));
        assert!(!valid_timestamp_origin_wrap_receipt(&receipt, &candidate));
    }

    #[test]
    fn timestamp_origin_relation_accepts_shift_origin_delta_arm() {
        let candidate = SemanticInjectionCandidate {
            bucket_id: "sem.time.boundary_origin_consistency".to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.time.boundary_origin_consistency".to_string(),
            inject_kind:
                "openvm.semantic.time.boundary_origin_consistency::mode=shift_origin,delta=1"
                    .to_string(),
            schedule: InjectionSchedule::Exact(0),
        };
        let context = serde_json::Map::from_iter([
            ("cell_id".to_string(), json!("ts1.standard")),
            ("mode".to_string(), json!("shift_origin")),
            ("delta".to_string(), json!(1)),
            ("origin_before".to_string(), json!(0)),
            ("origin_after".to_string(), json!(1)),
            ("later_before".to_string(), json!(1)),
            ("later_after".to_string(), json!(2)),
            ("wrapped".to_string(), json!(false)),
        ]);
        let mut receipt = exact_receipt(
            &candidate,
            SemanticMutationRelation::TimestampOriginWrap,
            json!(0),
            json!(1),
            context,
        );
        assert!(valid_timestamp_origin_wrap_receipt(&receipt, &candidate));
        receipt.effect.context.insert("later_after".to_string(), json!(3));
        assert!(!valid_timestamp_origin_wrap_receipt(&receipt, &candidate));
        receipt.effect.context.insert("later_after".to_string(), json!(2));
        receipt.effect.context.insert("mode".to_string(), json!("wrap_origin"));
        assert!(!valid_timestamp_origin_wrap_receipt(&receipt, &candidate));
    }

    #[test]
    fn volatile_boundary_relation_checks_anchor_full_variant_and_out_of_range_forgery() {
        let candidate = SemanticInjectionCandidate {
            bucket_id: "sem.memory.volatile_boundary_range".to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.memory.volatile_boundary_range".to_string(),
            inject_kind: "openvm.semantic.memory.volatile_boundary_range::mode=remap_boundary_cell,row_idx=7,address_space=4,pointer=256,width=4,forged_address_space=4,forged_pointer=768".to_string(),
            schedule: InjectionSchedule::Exact(7),
        };
        let context = serde_json::Map::from_iter([
            ("cell_id".to_string(), json!("rc3.volatile_pointer")),
            ("mode".to_string(), json!("remap_boundary_cell")),
            ("row_idx".to_string(), json!(7)),
            ("row_anchor".to_string(), json!(7)),
            ("address_space".to_string(), json!(4)),
            ("pointer".to_string(), json!(256)),
            ("forged_address_space".to_string(), json!(4)),
            ("forged_pointer".to_string(), json!(768)),
            ("address_space_before".to_string(), json!(4)),
            ("address_space_after".to_string(), json!(4)),
            ("pointer_before".to_string(), json!(256)),
            ("pointer_after".to_string(), json!(768)),
            ("width".to_string(), json!(4)),
            ("volatile_start".to_string(), json!(256)),
            ("volatile_end".to_string(), json!(512)),
            ("forged_address".to_string(), json!(768)),
            ("outside_volatile_range".to_string(), json!(true)),
        ]);
        let mut receipt = exact_receipt(
            &candidate,
            SemanticMutationRelation::VolatileBoundaryRange,
            json!({"address_space": 4, "pointer": 256}),
            json!({"address_space": 4, "pointer": 768}),
            context,
        );
        assert!(valid_volatile_boundary_range_receipt(&receipt, &candidate));
        receipt.effect.context.insert("row_anchor".to_string(), json!(8));
        assert!(!valid_volatile_boundary_range_receipt(&receipt, &candidate));
        receipt.effect.context.insert("row_anchor".to_string(), json!(7));
        receipt.effect.context.insert("forged_address".to_string(), json!(300));
        assert!(!valid_volatile_boundary_range_receipt(&receipt, &candidate));
    }

    #[test]
    fn semantic_candidate_target_filter_matches_bucket_and_inject_kind_prefixes() {
        let candidate = SemanticInjectionCandidate {
            bucket_id: "sem.arithmetic.special_case_consistency".to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.arithmetic.special_case_consistency".to_string(),
            inject_kind:
                "openvm.semantic.arithmetic.special_case_consistency::mode=shadow_invalid_one"
                    .to_string(),
            schedule: InjectionSchedule::Exact(7),
        };

        assert!(semantic_candidate_matches_target(&candidate, None, None));
        assert!(semantic_candidate_matches_target(
            &candidate,
            Some("sem.arithmetic.special_case"),
            Some("openvm.semantic.arithmetic.special_case_consistency::mode=shadow_invalid_one"),
        ));
        assert!(!semantic_candidate_matches_target(&candidate, Some("sem.memory"), None,));
        assert!(!semantic_candidate_matches_target(
            &candidate,
            None,
            Some("openvm.semantic.arithmetic.division_remainder_bound"),
        ));
    }

    #[test]
    fn baseline_errors_are_exceptions() {
        let mut baseline = EvalStats::default();
        baseline.phase = "baseline".to_string();
        baseline.backend_error = Some("backend rejected input".to_string());
        assert_eq!(bug_kind(&baseline), Some("exception"));

        baseline.backend_error = None;
        baseline.oracle_error = Some("oracle rejected input".to_string());
        assert_eq!(bug_kind(&baseline), Some("exception"));
    }

    #[test]
    fn unsupported_baseline_exceptions_are_not_reportable() {
        let seed_meta = json!({"source": "storage/riscv-tests-artifacts/rv32ui-p-add.dump"});
        let mut baseline = EvalStats::default();
        baseline.phase = "baseline".to_string();
        baseline.backend_error = Some(
            "risc0 execute failed: Invalid trap address: 0x00000000, cause: IllegalInstruction(0x14002573, 1)"
                .to_string(),
        );

        assert_eq!(bug_kind(&baseline), Some("exception"));
        assert!(!is_reportable_exception(&seed_meta, &baseline));
    }

    #[test]
    fn baseline_prove_failures_require_an_exact_executed_relation() {
        let seed_meta = json!({"source": "storage/riscv-tests-artifacts/rv32ui-p-add.dump"});
        let mut baseline = EvalStats::default();
        baseline.phase = "baseline".to_string();
        baseline.backend_error =
            Some("sp1 prove/verify panicked: cumulative sums error".to_string());

        assert_eq!(bug_kind(&baseline), Some("exception"));
        assert!(!is_reportable_exception(&seed_meta, &baseline));
        baseline.bucket_hits.push(crate::trace::BucketHit::semantic_id(
            "sem.arithmetic.division_remainder_bound",
            std::collections::HashMap::from([
                ("step_idx".to_string(), json!(0)),
                ("trace_source".to_string(), json!("instruction")),
                ("obligation_id".to_string(), json!("md3")),
                ("cell_id".to_string(), json!("md3.np")),
                ("dividend".to_string(), json!(-7)),
                ("divisor".to_string(), json!(3)),
                ("quotient".to_string(), json!(-2)),
                ("remainder".to_string(), json!(-1)),
                ("recomposed".to_string(), json!(-7)),
                ("remainder_bound_holds".to_string(), json!(true)),
                ("remainder_sign_holds".to_string(), json!(true)),
                ("relation".to_string(), json!("quotient_times_divisor_plus_remainder")),
                ("relation_valid".to_string(), json!(true)),
            ]),
        ));
        assert!(!is_reportable_exception(&seed_meta, &baseline));
        baseline.executed_exception_receipt = Some(ExecutedExceptionReceipt {
            effect: ExecutedExceptionEffect::SignedDivisionRemainderVerification,
            obligation_id: "md3".to_string(),
            cell_id: "md3.np".to_string(),
            stage: "instruction_lookup.primary_sumcheck".to_string(),
            step: 0,
            context: Default::default(),
        });
        // A legacy stage-only receipt is intentionally insufficient: it lacks
        // source identity, row fields, and an observed failure manifestation.
        assert!(!is_reportable_exception(&seed_meta, &baseline));

        baseline.executed_exception_receipt.as_mut().unwrap().stage =
            "unrelated.prover.stage".to_string();
        assert!(!is_reportable_exception(&seed_meta, &baseline));
    }

    #[test]
    fn semantic_injection_rejections_are_not_bugs() {
        let mut injected = EvalStats::default();
        injected.phase = "semantic_search".to_string();
        injected.semantic_injection_applied = true;
        injected.backend_error = Some("constraints not satisfied".to_string());
        assert_eq!(bug_kind(&injected), None);

        injected.backend_error = None;
        injected.oracle_error = Some("oracle rejected injected witness".to_string());
        assert_eq!(bug_kind(&injected), None);
    }

    #[test]
    fn noop_prefix_variants_are_not_treated_as_mutations() {
        assert!(super::injection_kind_is_noop_prefix(Some(
            "sp1.semantic.memory.load_value_binding::mode=noop_prefix,rank=7"
        )));
        assert!(!super::injection_kind_is_noop_prefix(Some(
            "sp1.semantic.memory.load_value_binding::mode=xor_low_bit"
        )));
        assert!(!super::injection_kind_is_noop_prefix(Some(
            "sp1.semantic.memory.load_value_binding"
        )));
        assert!(!super::injection_kind_is_noop_prefix(None));
    }

    #[test]
    fn eval_once_records_eval_duration() {
        let cfg = test_config();
        let mut backend = SleepyBackend { sleep_for: Duration::from_millis(5) };

        let stats = eval_once(&cfg, &mut backend, &[]);
        assert!(stats.eval_duration_ms >= 1);
    }

    #[test]
    fn coarse_changed_value_candidates_do_not_create_underconstrained_bugs() {
        let root = std::env::temp_dir()
            .join(format!("beak-benchmark-all-candidates-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let seeds_jsonl = root.join("seeds.jsonl");
        std::fs::write(
            &seeds_jsonl,
            "{\"instructions\":[19],\"metadata\":{\"source\":\"unit\"}}\n",
        )
        .unwrap();

        let mut cfg = test_config();
        cfg.seeds_jsonl = seeds_jsonl;
        cfg.out_dir = root.clone();
        cfg.output_prefix = Some("all-candidates".to_string());
        cfg.initial_limit = 1;
        cfg.max_instructions = 1;
        cfg.semantic_search_enabled = true;
        cfg.semantic_max_trials_per_bucket = 1;

        let outputs = run_benchmark(cfg, MultiCandidateBackend::default()).unwrap();
        let bugs = std::fs::read_to_string(outputs.bugs_path).unwrap();
        assert!(bugs.trim().is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn semantic_search_does_not_report_underconstrained_from_dirty_baseline() {
        let root =
            std::env::temp_dir().join(format!("beak-benchmark-dirty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let seeds_jsonl = root.join("seeds.jsonl");
        std::fs::write(
            &seeds_jsonl,
            "{\"instructions\":[19],\"metadata\":{\"source\":\"unit\"}}\n",
        )
        .unwrap();

        let mut cfg = test_config();
        cfg.seeds_jsonl = seeds_jsonl;
        cfg.out_dir = root.clone();
        cfg.output_prefix = Some("dirty-baseline".to_string());
        cfg.initial_limit = 1;
        cfg.max_instructions = 1;
        cfg.semantic_search_enabled = true;
        cfg.semantic_max_trials_per_bucket = 1;

        let outputs = run_benchmark(cfg, DirtyBaselineBackend::default()).unwrap();
        let bugs = std::fs::read_to_string(outputs.bugs_path).unwrap();
        let records: Vec<serde_json::Value> =
            bugs.lines().map(|line| serde_json::from_str(line).unwrap()).collect();

        let kinds: Vec<_> = records
            .iter()
            .filter_map(|record| record.pointer("/metadata/kind").and_then(|value| value.as_str()))
            .collect();
        assert_eq!(kinds, vec!["mismatch"]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn semantic_search_does_not_report_when_backend_disables_underconstrained_reporting() {
        let root =
            std::env::temp_dir().join(format!("beak-benchmark-unsupported-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let seeds_jsonl = root.join("seeds.jsonl");
        std::fs::write(
            &seeds_jsonl,
            "{\"instructions\":[19],\"metadata\":{\"source\":\"unit\"}}\n",
        )
        .unwrap();

        let mut cfg = test_config();
        cfg.seeds_jsonl = seeds_jsonl;
        cfg.out_dir = root.clone();
        cfg.output_prefix = Some("unsupported-reporting".to_string());
        cfg.initial_limit = 1;
        cfg.max_instructions = 1;
        cfg.semantic_search_enabled = true;
        cfg.semantic_max_trials_per_bucket = 1;

        let outputs = run_benchmark(cfg, UnsupportedUnderconstrainedBackend::default()).unwrap();
        let bugs = std::fs::read_to_string(outputs.bugs_path).unwrap();
        assert!(bugs.trim().is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    fn scoped_candidate(bucket_id: &str, inject_kind: &str) -> SemanticInjectionCandidate {
        SemanticInjectionCandidate {
            bucket_id: bucket_id.to_string(),
            trigger_signal_id: None,
            semantic_class: bucket_id.replacen("sem.", "semantic.", 1),
            inject_kind: inject_kind.to_string(),
            schedule: InjectionSchedule::Exact(0),
        }
    }

    #[test]
    fn scoped_representation_entrypoint_and_lui_relations_recompute_and_reject_forgery() {
        let limb_candidate = scoped_candidate(
            "sem.alu.immediate_limb_consistency",
            concat!(
                "openvm.semantic.alu.immediate_limb_consistency",
                "::mode=adjacent_radix_carry,carry_slot=0,borrow_slot=1"
            ),
        );
        let limb_context = serde_json::Map::from_iter([
            ("obligation_id".to_string(), json!("al1")),
            ("cell_id".to_string(), json!("al1.single_limb")),
            ("op_idx".to_string(), json!(0)),
            ("mode".to_string(), json!("adjacent_radix_carry")),
            ("carry_slot".to_string(), json!(0)),
            ("borrow_slot".to_string(), json!(1)),
            ("radix".to_string(), json!(256)),
            ("field_modulus".to_string(), json!(2_013_265_921u64)),
            ("limb_count".to_string(), json!(4)),
            ("value".to_string(), json!(20)),
            ("before_limbs".to_string(), json!([20, 0, 0, 0])),
            ("after_limbs".to_string(), json!([276, 2_013_265_920u64, 0, 0])),
            ("recomposed_before".to_string(), json!(20)),
            ("recomposed_after".to_string(), json!(20)),
            ("executed_instruction".to_string(), json!(true)),
        ]);
        let mut limb_receipt = exact_receipt(
            &limb_candidate,
            SemanticMutationRelation::FullLimbValueRepresentation,
            json!([20, 0, 0, 0]),
            json!([276, 2_013_265_920u64, 0, 0]),
            limb_context,
        );
        limb_receipt.site = "rv32_base_alu_adapter.preprocess".to_string();
        limb_receipt.field = "rs2_data_limbs".to_string();
        assert!(valid_full_limb_value_representation_receipt(&limb_receipt, &limb_candidate,));
        let mut stale_limb_site = limb_receipt.clone();
        stale_limb_site.site = "caller-forged".to_string();
        assert!(!valid_full_limb_value_representation_receipt(&stale_limb_site, &limb_candidate,));
        limb_receipt.effect.context.insert("recomposed_after".to_string(), json!(12));
        assert!(!valid_full_limb_value_representation_receipt(&limb_receipt, &limb_candidate,));
        let mut wrong_modulus = limb_receipt.clone();
        wrong_modulus.effect.context.insert("recomposed_after".to_string(), json!(20));
        wrong_modulus.effect.context.insert("field_modulus".to_string(), json!(17));
        assert!(!valid_full_limb_value_representation_receipt(&wrong_modulus, &limb_candidate,));
        let mut wrong_step = limb_receipt.clone();
        wrong_step.effect.context.insert("recomposed_after".to_string(), json!(20));
        wrong_step.effect.context.insert("op_idx".to_string(), json!(1));
        assert!(!valid_full_limb_value_representation_receipt(&wrong_step, &limb_candidate));
        let forged_before = vec![2_013_265_409u64, 2, 0, 0];
        let forged_after = vec![2_013_265_665u64, 1, 0, 0];
        let mut forged_limbs = limb_receipt.clone();
        forged_limbs.effect.context.insert("recomposed_after".to_string(), json!(20));
        forged_limbs.effect.context.insert("value".to_string(), json!(0));
        forged_limbs.effect.context.insert("before_limbs".to_string(), json!(forged_before));
        forged_limbs.effect.context.insert("after_limbs".to_string(), json!(forged_after));
        forged_limbs.effect.context.insert("recomposed_before".to_string(), json!(0));
        forged_limbs.effect.context.insert("recomposed_after".to_string(), json!(0));
        forged_limbs.before = json!(forged_before);
        forged_limbs.after = json!(forged_after);
        assert!(!valid_full_limb_value_representation_receipt(&forged_limbs, &limb_candidate,));

        let entry_candidate = scoped_candidate(
            "sem.control.entrypoint_binding",
            "jolt.semantic.control.entrypoint_binding",
        );
        let entry_context = serde_json::Map::from_iter([
            ("obligation_id".to_string(), json!("cf4")),
            ("cell_id".to_string(), json!("cf4.default_entry")),
            ("boundary_row".to_string(), json!(0)),
            ("declared_entry".to_string(), json!(0x8000_0000u64)),
            ("witnessed_pc_before".to_string(), json!(0x8000_0000u64)),
            ("witnessed_pc_after".to_string(), json!(0x8000_0004u64)),
            ("executed_boundary_row".to_string(), json!(true)),
        ]);
        let mut entry_receipt = exact_receipt(
            &entry_candidate,
            SemanticMutationRelation::EntrypointPcEquation,
            json!(0x8000_0000u64),
            json!(0x8000_0004u64),
            entry_context,
        );
        assert!(valid_entrypoint_pc_receipt(&entry_receipt, &entry_candidate));
        entry_receipt.effect.context.insert("declared_entry".to_string(), json!(4));
        assert!(!valid_entrypoint_pc_receipt(&entry_receipt, &entry_candidate));

        let lui_candidate = scoped_candidate(
            "sem.decode.upper_immediate_materialization",
            "jolt.semantic.decode.upper_immediate_materialization",
        );
        let lui_context = serde_json::Map::from_iter([
            ("obligation_id".to_string(), json!("id3")),
            ("cell_id".to_string(), json!("id3.lui_mid")),
            ("op_idx".to_string(), json!(0)),
            ("pc".to_string(), json!(0x8000_0000u64)),
            ("opcode".to_string(), json!(0x1234_50b7u64)),
            ("mnemonic".to_string(), json!("lui")),
            ("imm20".to_string(), json!(0x12345)),
            ("expected_result".to_string(), json!(0x1234_5000u64)),
            ("witnessed_result_before".to_string(), json!(0x1234_5000u64)),
            ("witnessed_result_after".to_string(), json!(0x1234_5001u64)),
            ("executed_instruction".to_string(), json!(true)),
        ]);
        let mut lui_receipt = exact_receipt(
            &lui_candidate,
            SemanticMutationRelation::UpperImmediateEquation,
            json!(0x1234_5000u64),
            json!(0x1234_5001u64),
            lui_context,
        );
        assert!(valid_upper_immediate_receipt(&lui_receipt, &lui_candidate));
        lui_receipt.effect.context.insert("imm20".to_string(), json!(0x12344));
        assert!(!valid_upper_immediate_receipt(&lui_receipt, &lui_candidate));
    }

    #[test]
    fn scoped_memory_and_divrem_relations_recompute_and_reject_stale_context() {
        let store_load_candidate = scoped_candidate(
            "sem.memory.store_load_payload_flow",
            "nexus.semantic.memory.store_load_payload_flow",
        );
        let store_load_context = serde_json::Map::from_iter([
            ("obligation_id".to_string(), json!("me1")),
            ("cell_id".to_string(), json!("me1.sw_lw")),
            ("store_step".to_string(), json!(1)),
            ("load_step".to_string(), json!(3)),
            ("store_address".to_string(), json!(64)),
            ("load_address".to_string(), json!(64)),
            ("store_value".to_string(), json!(123)),
            ("store_value_before".to_string(), json!(123)),
            ("store_value_after".to_string(), json!(90)),
            ("load_value_before".to_string(), json!(123)),
            ("load_value_after".to_string(), json!(90)),
            ("width".to_string(), json!(4)),
            ("mutation_mode".to_string(), json!("replace_low_byte_5a_a5")),
            ("executed_store".to_string(), json!(true)),
            ("executed_load".to_string(), json!(true)),
        ]);
        let mut store_load_receipt = exact_receipt(
            &store_load_candidate,
            SemanticMutationRelation::StoreLoadPayloadEquation,
            json!(123),
            json!(90),
            store_load_context,
        );
        store_load_receipt.step = 1;
        assert!(valid_store_load_payload_receipt(&store_load_receipt, &store_load_candidate,));
        store_load_receipt.effect.context.insert("load_address".to_string(), json!(68));
        assert!(!valid_store_load_payload_receipt(&store_load_receipt, &store_load_candidate,));

        let mut address_candidate = scoped_candidate(
            "sem.memory.address_space_consistency",
            "openvm.semantic.memory.address_space_consistency",
        );
        address_candidate.inject_kind.push_str("::mode=bus_mem_as_reg");
        let address_context = serde_json::Map::from_iter([
            ("obligation_id".to_string(), json!("me5")),
            ("cell_id".to_string(), json!("me5.mem_read")),
            ("row_idx".to_string(), json!(0)),
            ("is_memory".to_string(), json!(true)),
            ("register_address_space".to_string(), json!(1)),
            ("memory_address_space".to_string(), json!(2)),
            ("address_space_before".to_string(), json!(2)),
            ("address_space_after".to_string(), json!(1)),
            ("mode".to_string(), json!("bus_mem_as_reg")),
            ("executed_access".to_string(), json!(true)),
        ]);
        let mut address_receipt = exact_receipt(
            &address_candidate,
            SemanticMutationRelation::AddressSpaceConsistencyEquation,
            json!(2),
            json!(1),
            address_context,
        );
        address_receipt.site = "rv32_loadstore_adapter.preprocess".to_string();
        address_receipt.field = "memory_address_space".to_string();
        assert!(valid_address_space_receipt(&address_receipt, &address_candidate));
        let mut stale_address_field = address_receipt.clone();
        stale_address_field.field = "caller_forged".to_string();
        assert!(!valid_address_space_receipt(&stale_address_field, &address_candidate));
        for (field, forged) in [
            ("is_memory", json!(false)),
            ("register_address_space", json!(2)),
            ("memory_address_space", json!(1)),
            ("address_space_after", json!(2)),
            ("cell_id", json!("me5.reg_read")),
        ] {
            let mut forged_receipt = address_receipt.clone();
            forged_receipt.effect.context.insert(field.to_string(), forged);
            assert!(
                !valid_address_space_receipt(&forged_receipt, &address_candidate),
                "caller-forged address-space field {field} must fail closed"
            );
        }

        let mut swapped_domain_receipt = address_receipt.clone();
        swapped_domain_receipt.effect.context.insert("is_memory".to_string(), json!(false));
        swapped_domain_receipt
            .effect
            .context
            .insert("register_address_space".to_string(), json!(2));
        swapped_domain_receipt.effect.context.insert("memory_address_space".to_string(), json!(1));
        assert!(
            !valid_address_space_receipt(&swapped_domain_receipt, &address_candidate),
            "the original swapped-domain false-accept must stay rejected"
        );

        let div_candidate = scoped_candidate(
            "sem.arithmetic.special_case_consistency",
            "openvm.semantic.arithmetic.special_case_consistency",
        );
        // Executor-level divisor-reclass shape: claimed divisor -1, materialized 0.
        let div_context = serde_json::Map::from_iter([
            ("obligation_id".to_string(), json!("md2")),
            ("cell_id".to_string(), json!("md2.div_overflow")),
            ("mutation_mode".to_string(), json!("executor_divisor_reclass")),
            ("step".to_string(), json!(0)),
            ("dividend".to_string(), json!(i32::MIN as i64)),
            ("dividend_word".to_string(), json!(0x8000_0000u64)),
            ("claimed_divisor".to_string(), json!(-1)),
            ("claimed_divisor_word".to_string(), json!(0xffff_ffffu64)),
            ("materialized_divisor_word".to_string(), json!(0)),
            ("quotient".to_string(), json!(i32::MIN as i64)),
            ("remainder".to_string(), json!(0)),
            ("special_selector_before".to_string(), json!(0)),
            ("special_selector_after".to_string(), json!(1)),
            ("executed_instruction".to_string(), json!(true)),
        ]);
        let mut div_receipt = exact_receipt(
            &div_candidate,
            SemanticMutationRelation::DivisionRemainderSpecialCaseEquation,
            json!(0xffff_ffffu64),
            json!(0),
            div_context,
        );
        div_receipt.site = "divrem_core.execute_instruction".to_string();
        div_receipt.field = "operand_divisor".to_string();
        assert!(valid_divrem_special_case_receipt(&div_receipt, &div_candidate));
        let mut stale_div_field = div_receipt.clone();
        stale_div_field.field = "caller_forged".to_string();
        assert!(!valid_divrem_special_case_receipt(&stale_div_field, &div_candidate));
        for (field, forged) in [
            ("dividend_word", json!(0)),
            ("claimed_divisor_word", json!(1)),
            ("materialized_divisor_word", json!(0xffff_ffffu64)),
        ] {
            let mut forged_words = div_receipt.clone();
            forged_words.effect.context.insert(field.to_string(), forged);
            assert!(
                !valid_divrem_special_case_receipt(&forged_words, &div_candidate),
                "forged two's-complement operand word {field} must fail closed"
            );
        }
        let mut wrong_step = div_receipt.clone();
        wrong_step.effect.context.insert("step".to_string(), json!(1));
        assert!(!valid_divrem_special_case_receipt(&wrong_step, &div_candidate));
        div_receipt.effect.context.insert("remainder".to_string(), json!(1));
        assert!(!valid_divrem_special_case_receipt(&div_receipt, &div_candidate));
    }

    #[test]
    fn duplicate_row_shadow_receipt_validates_generate_trace_is_valid_flip() {
        let div_candidate = scoped_candidate(
            "sem.arithmetic.special_case_consistency",
            concat!(
                "openvm.semantic.arithmetic.special_case_consistency",
                "::mode=duplicate_row_shadow_r_zero,search=wildcard"
            ),
        );
        // Generate-trace duplicate-row shadow: the receipt records the
        // is_valid 1 -> 0 flip on the appended shadow row of the executed
        // INT_MIN / -1 DIV instruction.
        let dup_context = serde_json::Map::from_iter([
            ("obligation_id".to_string(), json!("md2")),
            ("cell_id".to_string(), json!("md2.div_overflow")),
            ("mode".to_string(), json!("duplicate_row_shadow_r_zero")),
            ("search".to_string(), json!("wildcard")),
            ("executed_instruction".to_string(), json!(true)),
            ("shadow_row".to_string(), json!(true)),
            ("step".to_string(), json!(2)),
            ("pc".to_string(), json!(8)),
            ("opcode".to_string(), json!(0x0220_c1b3u64)),
            ("mnemonic".to_string(), json!("div")),
            ("is_valid".to_string(), json!(0)),
            ("zero_divisor".to_string(), json!(0)),
            ("r_zero".to_string(), json!(0)),
            ("dividend".to_string(), json!(i32::MIN as i64)),
            ("dividend_word".to_string(), json!(0x8000_0000u64)),
            ("claimed_divisor".to_string(), json!(-1)),
            ("claimed_divisor_word".to_string(), json!(0xffff_ffffu64)),
            ("quotient".to_string(), json!(i32::MIN as i64)),
            ("remainder".to_string(), json!(0)),
            ("duplicated_from_row_idx".to_string(), json!(0)),
            ("row_idx".to_string(), json!(1)),
        ]);
        let mut dup_receipt = exact_receipt(
            &div_candidate,
            SemanticMutationRelation::DivisionRemainderSpecialCaseEquation,
            json!(1),
            json!(0),
            dup_context,
        );
        dup_receipt.step = 2;
        dup_receipt.site = "divrem_core.generate_trace".to_string();
        dup_receipt.field = "row_duplicate.is_valid".to_string();
        assert!(valid_divrem_special_case_receipt(&dup_receipt, &div_candidate));

        // The disproven executor arm must not swallow the duplicate-row shape.
        let mut forged_site = dup_receipt.clone();
        forged_site.site = "divrem_core.execute_instruction".to_string();
        assert!(!valid_divrem_special_case_receipt(&forged_site, &div_candidate));
        // A live (is_valid = 1) duplicate would emit real interactions.
        let mut live_row = dup_receipt.clone();
        live_row.effect.context.insert("is_valid".to_string(), json!(1));
        assert!(!valid_divrem_special_case_receipt(&live_row, &div_candidate));
        // The shadow row must not claim the zero-divisor / r_zero special case.
        let mut flagged = dup_receipt.clone();
        flagged.effect.context.insert("zero_divisor".to_string(), json!(1));
        assert!(!valid_divrem_special_case_receipt(&flagged, &div_candidate));
        let mut r_zero_claim = dup_receipt.clone();
        r_zero_claim.effect.context.insert("r_zero".to_string(), json!(1));
        assert!(!valid_divrem_special_case_receipt(&r_zero_claim, &div_candidate));
        // The shadow row must come after the executed row it duplicates.
        let mut stale_anchor = dup_receipt.clone();
        stale_anchor
            .effect
            .context
            .insert("duplicated_from_row_idx".to_string(), json!(1));
        assert!(!valid_divrem_special_case_receipt(&stale_anchor, &div_candidate));
        // Two's-complement operand words are fail-closed.
        for (field, forged) in [
            ("dividend_word", json!(0)),
            ("claimed_divisor_word", json!(1)),
            ("quotient", json!(0)),
        ] {
            let mut forged_value = dup_receipt.clone();
            forged_value.effect.context.insert(field.to_string(), forged);
            assert!(
                !valid_divrem_special_case_receipt(&forged_value, &div_candidate),
                "forged duplicate-row operand {field} must fail closed"
            );
        }
        // Anchor and step must agree and the flip direction is 1 -> 0 only.
        let mut wrong_step = dup_receipt.clone();
        wrong_step.effect.context.insert("step".to_string(), json!(3));
        assert!(!valid_divrem_special_case_receipt(&wrong_step, &div_candidate));
        let mut swapped = dup_receipt.clone();
        swapped.before = json!(0);
        swapped.after = json!(1);
        assert!(!valid_divrem_special_case_receipt(&swapped, &div_candidate));
        let mut wrong_mnemonic = dup_receipt.clone();
        wrong_mnemonic
            .effect
            .context
            .insert("mnemonic".to_string(), json!("rem"));
        assert!(!valid_divrem_special_case_receipt(&wrong_mnemonic, &div_candidate));
    }

    #[test]
    fn scoped_selector_and_control_relations_recompute_from_executed_opcode() {
        let opcode_candidate = scoped_candidate(
            "sem.exec.op_selector_binding",
            "pico.semantic.exec.op_selector_binding.read_write",
        );
        let opcode_context = serde_json::Map::from_iter([
            ("obligation_id".to_string(), json!("id4")),
            ("cell_id".to_string(), json!("id4.load")),
            ("step".to_string(), json!(7)),
            ("mutation_step".to_string(), json!(7)),
            ("opcode".to_string(), json!(0x0001_2183u64)),
            ("rd".to_string(), json!(3)),
            ("selector_before".to_string(), json!(0)),
            ("selector_after".to_string(), json!(1)),
            ("executed_read_write_row".to_string(), json!(true)),
        ]);
        let mut opcode_receipt = exact_receipt(
            &opcode_candidate,
            SemanticMutationRelation::OpcodeSelectorEquation,
            json!(0),
            json!(1),
            opcode_context,
        );
        opcode_receipt.step = 7;
        assert!(valid_opcode_selector_receipt(&opcode_receipt, &opcode_candidate));
        let mut stale_opcode_step = opcode_receipt.clone();
        stale_opcode_step.effect.context.insert("step".to_string(), json!(6));
        assert!(!valid_opcode_selector_receipt(&stale_opcode_step, &opcode_candidate));
        opcode_receipt.effect.context.insert("opcode".to_string(), json!(0x23));
        assert!(!valid_opcode_selector_receipt(&opcode_receipt, &opcode_candidate));

        let memory_candidate = scoped_candidate(
            "sem.exec.memory_effect_binding",
            "sp1.semantic.exec.memory_effect_binding",
        );
        let memory_context = serde_json::Map::from_iter([
            ("obligation_id".to_string(), json!("me10")),
            ("cell_id".to_string(), json!("me10.load")),
            ("step".to_string(), json!(0)),
            ("op_idx".to_string(), json!(0)),
            ("opcode".to_string(), json!(0x0001_2183u64)),
            ("mnemonic".to_string(), json!("lw")),
            ("expected_is_memory".to_string(), json!(1)),
            ("selector_before".to_string(), json!(1)),
            ("selector_after".to_string(), json!(0)),
            ("executed_cpu_row".to_string(), json!(true)),
        ]);
        let mut memory_receipt = exact_receipt(
            &memory_candidate,
            SemanticMutationRelation::MemorySelectorEquation,
            json!(1),
            json!(0),
            memory_context,
        );
        assert!(valid_memory_selector_receipt(&memory_receipt, &memory_candidate));
        let mut stale_memory_anchor = memory_receipt.clone();
        stale_memory_anchor.effect.context.insert("op_idx".to_string(), json!(1));
        assert!(!valid_memory_selector_receipt(&stale_memory_anchor, &memory_candidate));
        memory_receipt.effect.context.insert("expected_is_memory".to_string(), json!(0));
        assert!(!valid_memory_selector_receipt(&memory_receipt, &memory_candidate));

        let control_candidate = scoped_candidate(
            "sem.exec.control_flow_binding",
            "sp1.semantic.exec.control_flow_binding::family=ecall,mode=near_jump",
        );
        let control_context = serde_json::Map::from_iter([
            ("obligation_id".to_string(), json!("cf6")),
            ("cell_id".to_string(), json!("cf6.normal")),
            ("step".to_string(), json!(0)),
            ("op_idx".to_string(), json!(0)),
            ("pc".to_string(), json!(16)),
            ("opcode".to_string(), json!(0x73)),
            ("mnemonic".to_string(), json!("ecall")),
            ("expected_next_pc".to_string(), json!(20)),
            ("observed_next_pc_before".to_string(), json!(20)),
            ("observed_next_pc_after".to_string(), json!(24)),
            ("executed_instruction".to_string(), json!(true)),
            ("control_flow_family".to_string(), json!("ecall")),
            ("family".to_string(), json!("ecall")),
            ("mode".to_string(), json!("near_jump")),
        ]);
        let mut control_receipt = exact_receipt(
            &control_candidate,
            SemanticMutationRelation::ExecutedControlFlowEquation,
            json!(20),
            json!(24),
            control_context,
        );
        assert!(valid_executed_control_flow_receipt(&control_receipt, &control_candidate,));
        let mut stale_control_anchor = control_receipt.clone();
        stale_control_anchor.effect.context.insert("op_idx".to_string(), json!(1));
        assert!(!valid_executed_control_flow_receipt(&stale_control_anchor, &control_candidate,));
        control_receipt.effect.context.insert("expected_next_pc".to_string(), json!(24));
        assert!(!valid_executed_control_flow_receipt(&control_receipt, &control_candidate,));
    }

    #[test]
    fn scoped_relations_require_one_exact_executed_baseline_hit() {
        let fixtures = vec![
            (
                SemanticMutationRelation::FullLimbValueRepresentation,
                "sem.alu.immediate_limb_consistency",
                "al1",
                "al1.single_limb",
                vec![("op_idx", "op_idx", json!(3)), ("imm", "value", json!(20))],
            ),
            (
                SemanticMutationRelation::EntrypointPcEquation,
                "sem.control.entrypoint_binding",
                "cf4",
                "cf4.default_entry",
                vec![
                    ("op_idx", "boundary_row", json!(0)),
                    ("pc", "pc", json!(0x8000_0000u64)),
                    ("opcode", "opcode", json!(0x13)),
                    ("mnemonic", "mnemonic", json!("addi")),
                    ("declared_entry", "declared_entry", json!(0x8000_0000u64)),
                ],
            ),
            (
                SemanticMutationRelation::UpperImmediateEquation,
                "sem.decode.upper_immediate_materialization",
                "id3",
                "id3.lui_mid",
                vec![
                    ("op_idx", "op_idx", json!(1)),
                    ("pc", "pc", json!(4)),
                    ("opcode", "opcode", json!(0x1234_50b7u64)),
                    ("mnemonic", "mnemonic", json!("lui")),
                ],
            ),
            (
                SemanticMutationRelation::StoreLoadPayloadEquation,
                "sem.memory.store_load_payload_flow",
                "me1",
                "me1.sw_lw",
                vec![
                    ("op_idx", "store_step", json!(1)),
                    ("load_step_idx", "load_step", json!(3)),
                    ("effective_ptr", "store_address", json!(64)),
                    ("effective_ptr", "load_address", json!(64)),
                    ("write_data", "store_value", json!(123)),
                    ("read_data", "load_value_before", json!(123)),
                    ("width", "width", json!(4)),
                ],
            ),
            (
                SemanticMutationRelation::AddressSpaceConsistencyEquation,
                "sem.memory.address_space_consistency",
                "me5",
                "me5.mem_read",
                vec![
                    ("op_idx", "row_idx", json!(2)),
                    ("pc", "pc", json!(8)),
                    ("opcode", "opcode", json!(0x0000_2083)),
                    ("mnemonic", "mnemonic", json!("lw")),
                    ("address_space", "address_space_before", json!(2)),
                ],
            ),
            (
                SemanticMutationRelation::DivisionRemainderSpecialCaseEquation,
                "sem.arithmetic.special_case_consistency",
                "md2",
                "md2.div_overflow",
                vec![
                    ("op_idx", "step", json!(4)),
                    ("pc", "pc", json!(16)),
                    ("opcode", "opcode", json!(0x0200_c0b3)),
                    ("mnemonic", "mnemonic", json!("div")),
                    ("rs1_val", "dividend_word", json!(0x8000_0000u64)),
                    ("rs2_val", "claimed_divisor_word", json!(0xffff_ffffu64)),
                ],
            ),
            (
                SemanticMutationRelation::OpcodeSelectorEquation,
                "sem.exec.op_selector_binding",
                "id4",
                "id4.load",
                vec![
                    ("op_idx", "step", json!(5)),
                    ("pc", "pc", json!(20)),
                    ("opcode", "opcode", json!(0x0001_2183)),
                    ("mnemonic", "mnemonic", json!("lw")),
                    ("rd", "rd", json!(3)),
                ],
            ),
            (
                SemanticMutationRelation::MemorySelectorEquation,
                "sem.exec.memory_effect_binding",
                "me10",
                "me10.load",
                vec![
                    ("op_idx", "op_idx", json!(6)),
                    ("pc", "pc", json!(24)),
                    ("opcode", "opcode", json!(0x0001_2183)),
                    ("mnemonic", "mnemonic", json!("lw")),
                ],
            ),
            (
                SemanticMutationRelation::ExecutedControlFlowEquation,
                "sem.exec.control_flow_binding",
                "cf6",
                "cf6.normal",
                vec![
                    ("op_idx", "op_idx", json!(7)),
                    ("pc", "pc", json!(28)),
                    ("opcode", "opcode", json!(0x73)),
                    ("mnemonic", "mnemonic", json!("ecall")),
                ],
            ),
        ];

        for (relation, bucket_id, obligation_id, cell_id, pairs) in fixtures {
            let candidate = scoped_candidate(bucket_id, "vm.semantic.typed_relation");
            let mut context = serde_json::Map::from_iter([
                ("bucket_id".to_string(), json!(bucket_id)),
                ("obligation_id".to_string(), json!(obligation_id)),
                ("cell_id".to_string(), json!(cell_id)),
                ("backend".to_string(), json!("vm")),
                ("commit".to_string(), json!("0123456789abcdef")),
                ("trace_source".to_string(), json!("executed_row")),
            ]);
            let mut details = std::collections::HashMap::from([
                ("obligation_id".to_string(), json!(obligation_id)),
                ("cell_id".to_string(), json!(cell_id)),
                ("backend".to_string(), json!("vm")),
                ("commit".to_string(), json!("0123456789abcdef")),
                ("trace_source".to_string(), json!("executed_row")),
            ]);
            for (detail_key, context_key, value) in &pairs {
                details.insert((*detail_key).to_string(), value.clone());
                context.insert((*context_key).to_string(), value.clone());
            }
            if relation == SemanticMutationRelation::AddressSpaceConsistencyEquation {
                details.insert("is_load".to_string(), json!(true));
                details.insert("is_store".to_string(), json!(false));
            }
            let receipt = exact_receipt(&candidate, relation, json!(1), json!(2), context);
            let hit = BucketHit { bucket_id: bucket_id.to_string(), details };
            let mut baseline = EvalStats::default();
            baseline.bucket_hits.push(hit.clone());
            assert!(
                receipt_matches_exact_baseline_hit(relation, &baseline, &receipt, &candidate,),
                "exact baseline binding failed for {relation:?}"
            );

            let mut mismatched = baseline.clone();
            mismatched.bucket_hits[0].details.insert("commit".to_string(), json!("stale-commit"));
            assert!(!receipt_matches_exact_baseline_hit(
                relation,
                &mismatched,
                &receipt,
                &candidate,
            ));

            let mut ambiguous = baseline.clone();
            ambiguous.bucket_hits.push(hit);
            assert!(!receipt_matches_exact_baseline_hit(
                relation, &ambiguous, &receipt, &candidate,
            ));

            if relation == SemanticMutationRelation::AddressSpaceConsistencyEquation {
                for (key, value) in [("is_load", json!(false)), ("is_store", json!(true))] {
                    let mut wrong_direction = baseline.clone();
                    wrong_direction.bucket_hits[0].details.insert(key.to_string(), value);
                    assert!(!receipt_matches_exact_baseline_hit(
                        relation,
                        &wrong_direction,
                        &receipt,
                        &candidate,
                    ));
                }
            }
        }
    }

    fn reporting_config(tag: &str, commit: &str) -> BenchmarkConfig {
        let mut cfg = test_config();
        cfg.zkvm_tag = tag.to_string();
        cfg.zkvm_commit = commit.to_string();
        cfg
    }

    fn reporting_semantic_stats(
        relation: SemanticMutationRelation,
        bucket: &str,
        obligation: &str,
        cell: &str,
        backend: &str,
        commit: &str,
        source: &str,
    ) -> EvalStats {
        EvalStats {
            phase: "semantic_search".to_string(),
            trigger_bucket_id: Some(bucket.to_string()),
            underconstrained_candidate: true,
            semantic_injection_applied: true,
            semantic_relation_validated: true,
            semantic_mutation_receipt: Some(SemanticMutationReceipt {
                inject_kind: format!("{backend}.semantic.reporting-test"),
                site: "executed.row".to_string(),
                field: "typed_field".to_string(),
                step: 1,
                before: json!(1),
                after: json!(2),
                effect: SemanticMutationEffect {
                    relation,
                    preserved_before: None,
                    preserved_after: None,
                    context: serde_json::Map::from_iter([
                        ("bucket_id".to_string(), json!(bucket)),
                        ("obligation_id".to_string(), json!(obligation)),
                        ("cell_id".to_string(), json!(cell)),
                        ("backend".to_string(), json!(backend)),
                        ("commit".to_string(), json!(commit)),
                        ("trace_source".to_string(), json!(source)),
                    ]),
                },
            }),
            ..EvalStats::default()
        }
    }

    fn assert_strict_stats_persist(
        cfg: &BenchmarkConfig,
        stats: &EvalStats,
        expected: FrozenFindingReportIdentity,
        expected_kind: &str,
    ) {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
        let dir = std::env::temp_dir()
            .join(format!("beak-r2-strict-persistence-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create strict persistence test directory");
        let path = dir.join("bugs.jsonl");
        let writer = JsonlWriter::open_append(&path).expect("open strict persistence JSONL");
        let mut filter = BugNoveltyFilter::default();
        assert!(write_bug_record(
            cfg,
            &writer,
            &mut filter,
            0,
            0,
            &[0x0000_0013],
            0,
            &json!({"source": "ordinary_corpus", "case_id": "caller-forged"}),
            stats,
            None,
        )
        .expect("persist strict route"));
        writer.flush().expect("flush strict persistence JSONL");
        let rows = std::fs::read_to_string(&path).expect("read strict persistence JSONL");
        let row: serde_json::Value = serde_json::from_str(rows.trim()).expect("parse bug row");
        assert_eq!(row["metadata"]["kind"], json!(expected_kind));
        assert_eq!(row["metadata"]["case_id"], json!(expected.case_id()));
        assert_ne!(row["metadata"]["case_id"], json!("caller-forged"));
        std::fs::remove_dir_all(dir).expect("remove strict persistence test directory");
    }

    #[test]
    fn post_classification_semantic_routes_persist_only_with_complete_frozen_identity() {
        let fixtures = [
            (
                "jolt",
                "e9caa23565dbb13019afe61a2c95f51d1999e286",
                "sem.control.entrypoint_binding",
                SemanticMutationRelation::EntrypointPcEquation,
                "cf4",
                "cf4.default_entry",
                "instruction",
                FrozenFindingReportIdentity::JoltEntryPcBinding,
            ),
            (
                "jolt",
                "e9caa23565dbb13019afe61a2c95f51d1999e286",
                "sem.decode.upper_immediate_materialization",
                SemanticMutationRelation::UpperImmediateEquation,
                "id3",
                "id3.lui_mid",
                "instruction",
                FrozenFindingReportIdentity::JoltImmediate,
            ),
            (
                "nexus",
                "636ccb360d0f4ae657ae4bb64e1e275ccec8826",
                "sem.memory.store_load_payload_flow",
                SemanticMutationRelation::StoreLoadPayloadEquation,
                "me1",
                "me1.sw_lw",
                "memory",
                FrozenFindingReportIdentity::NexusOperand,
            ),
            (
                "openvm",
                "f038f61d21db3aecd3029e1a23ba1ba0bb314800",
                "sem.memory.address_space_consistency",
                SemanticMutationRelation::AddressSpaceConsistencyEquation,
                "me5",
                "me5.mem_read",
                "memory_access",
                FrozenFindingReportIdentity::OpenVmAddressSpace,
            ),
            (
                "openvm",
                "336f1a475e5aa3513c4c5a266399f4128c119bba",
                "sem.arithmetic.special_case_consistency",
                SemanticMutationRelation::DivisionRemainderSpecialCaseEquation,
                "md2",
                "md2.div_overflow",
                "chip_row",
                FrozenFindingReportIdentity::OpenVmMultiple,
            ),
            (
                "openvm",
                "336f1a475e5aa3513c4c5a266399f4128c119bba",
                "sem.alu.immediate_limb_consistency",
                SemanticMutationRelation::FullLimbValueRepresentation,
                "al1",
                "al1.single_limb",
                "decoded_instruction",
                FrozenFindingReportIdentity::OpenVmRangeCheck,
            ),
            (
                "pico",
                "45e74ccd62758c6d67239913956e749adaba261c",
                "sem.exec.op_selector_binding",
                SemanticMutationRelation::OpcodeSelectorEquation,
                "id4",
                "id4.load",
                "instruction",
                FrozenFindingReportIdentity::PicoReadWriteOpcodeSelector,
            ),
            (
                "sp1",
                "39ab52fce38172c9d23feed7248198dc14c164a9",
                "sem.exec.memory_effect_binding",
                SemanticMutationRelation::MemorySelectorEquation,
                "me10",
                "me10.load",
                "instruction",
                FrozenFindingReportIdentity::Sp1Memory,
            ),
            (
                "sp1",
                "7f643da16813af4c0fbaad4837cd7409386cf38c",
                "sem.exec.control_flow_binding",
                SemanticMutationRelation::ExecutedControlFlowEquation,
                "cf6",
                "cf6.normal",
                "instruction",
                FrozenFindingReportIdentity::Sp1Pc,
            ),
        ];

        for (tag, commit, bucket, relation, obligation, cell, source, expected) in fixtures {
            let cfg = reporting_config(tag, commit);
            let stats =
                reporting_semantic_stats(relation, bucket, obligation, cell, tag, commit, source);
            assert_eq!(exact_semantic_reporting_identity(&cfg, &stats), Some(expected));
            assert_strict_stats_persist(&cfg, &stats, expected, "underconstrained_candidate");
            for key in
                ["backend", "commit", "bucket_id", "obligation_id", "cell_id", "trace_source"]
            {
                let mut wrong = stats.clone();
                wrong
                    .semantic_mutation_receipt
                    .as_mut()
                    .unwrap()
                    .effect
                    .context
                    .insert(key.to_string(), json!("forged"));
                assert_eq!(exact_semantic_reporting_identity(&cfg, &wrong), None);
            }
            let mut unchanged = stats.clone();
            unchanged.semantic_mutation_receipt.as_mut().unwrap().after = json!(1);
            assert_eq!(exact_semantic_reporting_identity(&cfg, &unchanged), None);
            let mut unvalidated = stats;
            unvalidated.semantic_relation_validated = false;
            assert_eq!(exact_semantic_reporting_identity(&cfg, &unvalidated), None);
        }
    }

    #[test]
    fn caller_case_labels_are_scrubbed_before_any_output_path_can_use_them() {
        let mut metadata = serde_json::Map::from_iter([
            ("case_id".to_string(), json!("caller-forged")),
            ("source".to_string(), json!("ordinary-corpus")),
        ]);
        scrub_caller_reporting_metadata(&mut metadata);
        assert!(!metadata.contains_key("case_id"));
        assert_eq!(metadata.get("source"), Some(&json!("ordinary-corpus")));
    }

    #[test]
    fn exception_reporting_label_requires_non_injected_unique_typed_evidence() {
        let commit = "d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b";
        let hit = BucketHit::semantic_id(
            "sem.row.trace_power2_boundary",
            std::collections::HashMap::from([
                ("backend".to_string(), json!("jolt")),
                ("commit".to_string(), json!(commit)),
                ("trace_source".to_string(), json!("prover.dory")),
                ("obligation_id".to_string(), json!("pd2")),
                ("cell_id".to_string(), json!("pd2.very_short")),
                ("step_idx".to_string(), json!(32)),
                ("input_words_len".to_string(), json!(1)),
                ("unpadded_trace_len".to_string(), json!(20)),
                ("dory_domain_size".to_string(), json!(32)),
                ("matrix_width_k".to_string(), json!(256)),
                ("dory_dimension".to_string(), json!(128)),
                ("boundary_k".to_string(), json!(5)),
                ("relation".to_string(), json!("dory_domain_not_greater_than_matrix_dimension")),
                ("relation_valid".to_string(), json!(true)),
            ]),
        );
        let receipt = ExecutedExceptionReceipt {
            effect: ExecutedExceptionEffect::DoryShortTraceCapacity,
            obligation_id: "pd2".to_string(),
            cell_id: "pd2.very_short".to_string(),
            stage: "dory.commitment.domain_size".to_string(),
            step: 32,
            context: serde_json::Map::from_iter([
                ("backend".to_string(), json!("jolt")),
                ("commit".to_string(), json!(commit)),
                ("trace_source".to_string(), json!("prover.dory")),
                ("input_words_len".to_string(), json!(1)),
                ("unpadded_trace_len".to_string(), json!(20)),
                ("dory_domain_size".to_string(), json!(32)),
                ("matrix_width_k".to_string(), json!(256)),
                ("dory_dimension".to_string(), json!(128)),
                ("boundary_k".to_string(), json!(5)),
                ("failing_domain_size".to_string(), json!(32)),
                ("relation".to_string(), json!("dory_domain_not_greater_than_matrix_dimension")),
            ]),
        };
        let cfg = reporting_config("jolt", commit);
        let mut stats = EvalStats {
            phase: "baseline".to_string(),
            bucket_hits: vec![hit.clone()],
            backend_error: Some("typed prover failure".to_string()),
            executed_exception_receipt: Some(receipt),
            ..EvalStats::default()
        };
        assert_eq!(
            exact_exception_reporting_identity(&cfg, &stats),
            Some(FrozenFindingReportIdentity::JoltDoryShortTrace)
        );
        assert_strict_stats_persist(
            &cfg,
            &stats,
            FrozenFindingReportIdentity::JoltDoryShortTrace,
            "exception",
        );

        stats.semantic_injection_applied = true;
        assert_eq!(exact_exception_reporting_identity(&cfg, &stats), None);
        stats.semantic_injection_applied = false;
        stats.bucket_hits.push(hit);
        assert_eq!(exact_exception_reporting_identity(&cfg, &stats), None);
        stats.bucket_hits.pop();
        stats
            .executed_exception_receipt
            .as_mut()
            .unwrap()
            .context
            .insert("trace_source".to_string(), json!("caller-forged"));
        assert_eq!(exact_exception_reporting_identity(&cfg, &stats), None);
    }

    #[test]
    fn bigint_and_control_done_exception_routes_persist_only_with_exact_executed_evidence() {
        let bigint_commit = "336f1a475e5aa3513c4c5a266399f4128c119bba";
        let bigint_source = "extensions/rv32im/circuit/src/branch_lt/core.rs::execute_instruction";
        let bigint_hit = BucketHit::semantic_id(
            "sem.decode.field_range",
            std::collections::HashMap::from([
                ("obligation_id".to_string(), json!("id4")),
                ("cell_id".to_string(), json!("id4.branch")),
                ("backend".to_string(), json!("openvm")),
                ("commit".to_string(), json!(bigint_commit)),
                ("trace_source".to_string(), json!(bigint_source)),
                ("step_idx".to_string(), json!(3)),
                ("op_idx".to_string(), json!(3)),
                ("from_pc".to_string(), json!(17)),
                ("global_opcode".to_string(), json!(0x425)),
                ("chip_class_offset".to_string(), json!(0x408)),
                ("local_opcode".to_string(), json!(29)),
                ("supported_local_opcodes".to_string(), json!([0, 1, 2, 3])),
                ("conversion_target".to_string(), json!("BranchLessThanOpcode")),
                ("relation".to_string(), json!("local_opcode_not_in_branch_less_than_domain")),
                ("relation_valid".to_string(), json!(true)),
            ]),
        );
        let bigint_receipt = ExecutedExceptionReceipt {
            effect: ExecutedExceptionEffect::BigIntOpcodeConversion,
            obligation_id: "id4".to_string(),
            cell_id: "id4.branch".to_string(),
            stage: "openvm.bigint.branch_less_than_opcode_conversion".to_string(),
            step: 3,
            context: serde_json::Map::from_iter([
                ("backend".to_string(), json!("openvm")),
                ("commit".to_string(), json!(bigint_commit)),
                ("trace_source".to_string(), json!(bigint_source)),
                ("from_pc".to_string(), json!(17)),
                ("global_opcode".to_string(), json!(0x425)),
                ("chip_class_offset".to_string(), json!(0x408)),
                ("local_opcode".to_string(), json!(29)),
                ("supported_local_opcodes".to_string(), json!([0, 1, 2, 3])),
                ("conversion_target".to_string(), json!("BranchLessThanOpcode")),
                ("relation".to_string(), json!("local_opcode_not_in_branch_less_than_domain")),
                ("relation_valid".to_string(), json!(true)),
                ("hook_fired".to_string(), json!(true)),
            ]),
        };
        let bigint_cfg = reporting_config("openvm", bigint_commit);
        let bigint_stats = EvalStats {
            phase: "baseline".to_string(),
            bucket_hits: vec![bigint_hit],
            backend_error: Some("typed conversion failure".to_string()),
            executed_exception_receipt: Some(bigint_receipt),
            ..EvalStats::default()
        };
        assert_eq!(
            exact_exception_reporting_identity(&bigint_cfg, &bigint_stats),
            Some(FrozenFindingReportIdentity::OpenVmBigIntMemory)
        );
        assert_strict_stats_persist(
            &bigint_cfg,
            &bigint_stats,
            FrozenFindingReportIdentity::OpenVmBigIntMemory,
            "exception",
        );
        let mut nonexecuted_bigint = bigint_stats.clone();
        nonexecuted_bigint
            .executed_exception_receipt
            .as_mut()
            .unwrap()
            .context
            .insert("hook_fired".to_string(), json!(false));
        assert_eq!(exact_exception_reporting_identity(&bigint_cfg, &nonexecuted_bigint), None);

        let control_commit = "6f038bd11ed725d7025687d163977d93ac1f82f9";
        let control_hit = BucketHit::semantic_id(
            "sem.row.trace_power2_boundary",
            std::collections::HashMap::from([
                ("obligation_id".to_string(), json!("pd2")),
                ("cell_id".to_string(), json!("pd2.just_over")),
                ("backend".to_string(), json!("risc0")),
                ("commit".to_string(), json!(control_commit)),
                ("trace_source".to_string(), json!("segment_finalization")),
                ("segment_idx".to_string(), json!(3)),
                ("step_idx".to_string(), json!(3)),
                ("segment_po2".to_string(), json!(4)),
                ("capacity_cycles".to_string(), json!(16)),
                ("user_cycles".to_string(), json!(9)),
                ("pager_cycles".to_string(), json!(2)),
                ("lookup_table_cycles".to_string(), json!(5)),
                ("accounted_cycles".to_string(), json!(16)),
                ("control_done_cycles_required".to_string(), json!(2)),
                ("required_cycles".to_string(), json!(18)),
                ("overflow_cycles".to_string(), json!(2)),
                ("actual_trace_cycles".to_string(), json!(17)),
                ("manifested_control_done_cycles".to_string(), json!(1)),
                ("relation".to_string(), json!("control_done_cycles_cross_segment_capacity")),
                ("relation_valid".to_string(), json!(true)),
                ("accounted_fits".to_string(), json!(true)),
                ("required_exceeds".to_string(), json!(true)),
            ]),
        );
        let control_receipt = ExecutedExceptionReceipt {
            effect: ExecutedExceptionEffect::ControlDoneCapacity,
            obligation_id: "pd2".to_string(),
            cell_id: "pd2.just_over".to_string(),
            stage: "risc0.segment.control_done_capacity".to_string(),
            step: 3,
            context: serde_json::Map::from_iter([
                ("segment_idx".to_string(), json!(3)),
                ("segment_po2".to_string(), json!(4)),
                ("capacity_cycles".to_string(), json!(16)),
                ("user_cycles".to_string(), json!(9)),
                ("pager_cycles".to_string(), json!(2)),
                ("lookup_table_cycles".to_string(), json!(5)),
                ("accounted_cycles".to_string(), json!(16)),
                ("control_done_cycles_required".to_string(), json!(2)),
                ("required_cycles".to_string(), json!(18)),
                ("overflow_cycles".to_string(), json!(2)),
                ("actual_trace_cycles".to_string(), json!(17)),
                ("manifested_control_done_cycles".to_string(), json!(1)),
                ("accounted_fits".to_string(), json!(true)),
                ("required_exceeds".to_string(), json!(true)),
                ("backend".to_string(), json!("risc0")),
                ("commit".to_string(), json!(control_commit)),
                ("trace_source".to_string(), json!("segment_finalization")),
            ]),
        };
        let control_cfg = reporting_config("risc0", control_commit);
        let control_stats = EvalStats {
            phase: "baseline".to_string(),
            bucket_hits: vec![control_hit],
            backend_error: Some("typed segment-capacity failure".to_string()),
            executed_exception_receipt: Some(control_receipt),
            ..EvalStats::default()
        };
        assert_eq!(
            exact_exception_reporting_identity(&control_cfg, &control_stats),
            Some(FrozenFindingReportIdentity::Risc0ControlDoneCycle)
        );
        assert_strict_stats_persist(
            &control_cfg,
            &control_stats,
            FrozenFindingReportIdentity::Risc0ControlDoneCycle,
            "exception",
        );
        let mut stale_control = control_stats.clone();
        stale_control
            .executed_exception_receipt
            .as_mut()
            .unwrap()
            .context
            .insert("commit".to_string(), json!("stale"));
        assert_eq!(exact_exception_reporting_identity(&control_cfg, &stale_control), None);
    }
    #[test]
    fn o8_flip_sign_receipt_validates() {
        let receipt: SemanticMutationReceipt = serde_json::from_str(r##"{"after": 0, "before": 1, "effect": {"context": {"backend": "openvm", "base": 4096, "bucket_id": "sem.memory.immediate_sign_consistency", "cell_id": "id2.i_neg", "commit": "336f1a475e5aa3513c4c5a266399f4128c119bba", "domain": "load", "effective_after": 69628, "effective_before": 4092, "equation_after_valid": true, "equation_before_valid": true, "extended_after": 65532, "extended_before": 4294967292, "guard": "alt_in_range", "immediate": 65532, "mode": "flip_sign", "obligation_id": "id2", "pointer_max_exclusive": 536870912, "sign_after": 0, "sign_before": 1, "step": 1, "trace_source": "decoded_instruction"}, "relation": "memory_immediate_sign_equation"}, "field": "imm_sign", "inject_kind": "openvm.semantic.memory.immediate_sign_consistency::mode=flip_sign,domain=load,guard=alt_in_range", "site": "rv32_loadstore_adapter.preprocess", "step": 1}"##).unwrap();
        let candidate = SemanticInjectionCandidate {
            bucket_id: "sem.memory.immediate_sign_consistency".to_string(),
            trigger_signal_id: None,
            semantic_class: "semantic.memory.immediate_sign_consistency".to_string(),
            inject_kind: "openvm.semantic.memory.immediate_sign_consistency::mode=flip_sign,domain=load,guard=alt_in_range".to_string(),
            schedule: InjectionSchedule::Exact(u64::MAX),
        };
        assert!(valid_memory_immediate_sign_receipt(&receipt, &candidate), "o8 r13 receipt must validate");
    }

    #[test]
    fn long_tail_quota_scales_with_corpus_and_hash_is_stable() {
        assert_eq!(long_tail_quota(0), 1);
        assert_eq!(long_tail_quota(49), 1);
        assert_eq!(long_tail_quota(2182), 43);
        let words = [0x13u32; 512];
        assert_eq!(seed_content_hash(&words), seed_content_hash(&words));
        assert_ne!(seed_content_hash(&words), seed_content_hash(&words[..256]));
    }

    #[test]
    fn long_tail_loader_admits_whole_long_seed_without_truncation() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "beak-long-tail-loader-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("seeds.jsonl");
        let long_seed: Vec<u32> = vec![0x13; 512];
        std::fs::write(
            &path,
            format!(
                "{{\"instructions\": {}, \"metadata\": {{\"source\": \"unit\"}}}}\n",
                serde_json::to_string(&long_seed).unwrap()
            ),
        )
        .expect("write seeds");

        // Long-tail mode (hard ceiling 8192): the 512-word seed lands in the long lane and
        // is admitted whole by the quota (single long seed, quota >= 1) — no truncation.
        let loaded = load_initial_seeds(&path, 256, 8192, &|_| true, &|_| true);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0.as_ref().len(), 512 * 4);

        // Legacy hard cap (long_tail == 0): unchanged old behavior — the seed is
        // truncated to the nominal length and the prefix is admitted.
        let legacy = load_initial_seeds(&path, 256, 0, &|_| true, &|_| true);
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].0.as_ref().len(), 256 * 4);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
