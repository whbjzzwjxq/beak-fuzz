use std::{env, fs};

use clap::{Arg, Command};
use p3_field::{AbstractField, PrimeField32};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp1_core::air::PublicValues as CorePublicValues;
use sp1_core::stark::{LocalProver, StarkGenericConfig};
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_core::air::Block;
use sp1_recursion_core::cpu::CpuEvent;
use sp1_recursion_core::runtime::{Instruction, MemoryEntry, Opcode, RecursionProgram, Runtime};
use sp1_recursion_core::stark::RecursionAirWideDeg3;

pub const LOAD_BINDING_INJECT_KIND: &str = "sp1.legacy_recursion.memory.load_binding";
pub const JUMP_BINDING_INJECT_KIND: &str =
    "sp1.legacy_recursion.exec.jump_binding::mode=jal_a_plus_one";
pub const BNEINC_UPPER_LIMBS_INJECT_KIND: &str = "sp1.legacy_recursion.exec.bneinc_upper_limbs";
pub const LOAD_WRITEBACK_BUCKET_ID: &str = "sem.recursion.load_writeback_binding";
pub const JUMP_STATE_BUCKET_ID: &str = "sem.recursion.jump_state_binding";
pub const BNEINC_INCREMENT_BUCKET_ID: &str = "sem.recursion.bneinc_increment_binding";

type SC = BabyBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;
const A0_SLOT: i32 = -8;

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyRecursionScenario {
    Load,
    Jump,
    Bneinc,
}

impl LegacyRecursionScenario {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "load" => Ok(Self::Load),
            "jump" => Ok(Self::Jump),
            "bneinc" => Ok(Self::Bneinc),
            _ => Err(format!("unknown scenario: {value}")),
        }
    }

    pub fn default_inject_kind(self) -> &'static str {
        match self {
            Self::Load => LOAD_BINDING_INJECT_KIND,
            Self::Jump => JUMP_BINDING_INJECT_KIND,
            Self::Bneinc => BNEINC_UPPER_LIMBS_INJECT_KIND,
        }
    }

    pub fn default_inject_step(self) -> u64 {
        match self {
            Self::Load => 0,
            Self::Jump => 1,
            Self::Bneinc => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioRun {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<LegacyRecursionScenario>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_path: Option<String>,
    pub inject_kind: Option<String>,
    pub inject_step: u64,
    pub semantic_injection_applied: bool,
    pub public_values: Vec<u32>,
    pub final_pc: u32,
    pub final_fp: u32,
    pub proof_verified: bool,
    pub projected_bucket_hits: Vec<ProjectedBucketHit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioComparison {
    pub baseline: ScenarioRun,
    pub injected: ScenarioRun,
    pub diverged: bool,
    pub semantic_injection_applied: bool,
    pub underconstrained_candidate: bool,
    pub strict_countable: bool,
    pub strict_blocker: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectedBucketHit {
    pub bucket_id: &'static str,
    pub semantic_class: &'static str,
    pub details: serde_json::Value,
    pub central_semantic_registered: bool,
    pub strict_countable: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RecursionSeedSpec {
    #[serde(default)]
    case_id: Option<String>,
    #[serde(default)]
    bucket: Option<String>,
    #[serde(default)]
    default_inject_kind: Option<String>,
    #[serde(default)]
    default_inject_step: Option<u64>,
    instructions: Vec<SeedInstruction>,
    #[serde(default)]
    initial_memory: Vec<SeedMemoryEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct SeedInstruction {
    opcode: Opcode,
    op_a: i32,
    op_b: [u32; 4],
    op_c: [u32; 4],
    #[serde(default)]
    offset_imm: u32,
    #[serde(default)]
    size_imm: u32,
    #[serde(default = "default_true")]
    imm_b: bool,
    #[serde(default = "default_true")]
    imm_c: bool,
    #[serde(default)]
    debug: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SeedMemoryEntry {
    addr: u32,
    value: [u32; 4],
}

struct EnvGuard {
    saved_kind: Option<String>,
    saved_step: Option<String>,
    saved_run_id: Option<String>,
}

impl EnvGuard {
    fn arm(inject_kind: Option<&str>, inject_step: u64) -> Self {
        let saved_kind = env::var("BEAK_SP1_WITNESS_INJECT_KIND").ok();
        let saved_step = env::var("BEAK_SP1_WITNESS_INJECT_STEP").ok();
        let saved_run_id = env::var("BEAK_SP1_WITNESS_RUN_ID").ok();
        match inject_kind {
            Some(kind) if !kind.is_empty() => {
                env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", kind);
                env::set_var("BEAK_SP1_WITNESS_INJECT_STEP", inject_step.to_string());
                env::set_var("BEAK_SP1_WITNESS_RUN_ID", format!("legacy-recursion-{inject_step}"));
            }
            _ => {
                env::remove_var("BEAK_SP1_WITNESS_INJECT_KIND");
                env::remove_var("BEAK_SP1_WITNESS_INJECT_STEP");
                env::remove_var("BEAK_SP1_WITNESS_RUN_ID");
            }
        }
        Self { saved_kind, saved_step, saved_run_id }
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
    }
}

fn felt(value: u32) -> F {
    F::from_canonical_u32(value)
}

fn signed_felt(value: i32) -> F {
    if value >= 0 {
        F::from_canonical_u32(value as u32)
    } else {
        -F::from_canonical_u32(value.unsigned_abs())
    }
}

fn block(values: [u32; 4]) -> Block<F> {
    Block::from(values.map(felt))
}

fn imm_instruction(
    opcode: Opcode,
    op_a: i32,
    op_b: [u32; 4],
    op_c: [u32; 4],
    offset_imm: u32,
    size_imm: u32,
    debug: &str,
) -> Instruction<F> {
    Instruction::new(
        opcode,
        signed_felt(op_a),
        op_b.map(felt),
        op_c.map(felt),
        felt(offset_imm),
        felt(size_imm),
        true,
        true,
        debug.to_string(),
    )
}

fn scenario_program(
    scenario: LegacyRecursionScenario,
) -> (RecursionProgram<F>, Vec<(u32, Block<F>)>) {
    let zero = [0u32; 4];
    match scenario {
        LegacyRecursionScenario::Load => (
            RecursionProgram {
                instructions: vec![
                    imm_instruction(Opcode::LOAD, 0, [128, 0, 0, 0], zero, 0, 1, "load"),
                    imm_instruction(Opcode::Commit, 0, zero, zero, 0, 0, "commit"),
                ],
                traces: vec![None, None],
            },
            vec![(128, block([7, 8, 9, 10]))],
        ),
        LegacyRecursionScenario::Jump => (
            RecursionProgram {
                instructions: vec![
                    imm_instruction(Opcode::ADD, A0_SLOT, zero, zero, 0, 0, "prefix_add"),
                    imm_instruction(Opcode::JAL, A0_SLOT, [1, 0, 0, 0], zero, 0, 0, "jal"),
                    imm_instruction(Opcode::Commit, A0_SLOT, zero, zero, 0, 0, "commit"),
                ],
                traces: vec![None, None, None],
            },
            vec![],
        ),
        LegacyRecursionScenario::Bneinc => (
            RecursionProgram {
                instructions: vec![
                    imm_instruction(Opcode::BNEINC, 0, [1, 0, 0, 0], [3, 0, 0, 0], 0, 0, "bneinc"),
                    imm_instruction(Opcode::Commit, 0, zero, zero, 0, 0, "commit"),
                ],
                traces: vec![None, None],
            },
            vec![(1 << 24, block([0, 0, 0, 0]))],
        ),
    }
}

impl SeedInstruction {
    fn to_instruction(&self) -> Instruction<F> {
        Instruction::new(
            self.opcode,
            signed_felt(self.op_a),
            self.op_b.map(felt),
            self.op_c.map(felt),
            felt(self.offset_imm),
            felt(self.size_imm),
            self.imm_b,
            self.imm_c,
            self.debug.clone(),
        )
    }
}

impl RecursionSeedSpec {
    fn to_program(&self) -> (RecursionProgram<F>, Vec<(u32, Block<F>)>) {
        let instructions =
            self.instructions.iter().map(SeedInstruction::to_instruction).collect::<Vec<_>>();
        let initial_memory = self
            .initial_memory
            .iter()
            .map(|entry| (entry.addr, block(entry.value)))
            .collect::<Vec<_>>();
        let traces = vec![None; instructions.len()];
        (RecursionProgram { instructions, traces }, initial_memory)
    }
}

fn init_memory<Diffusion>(runtime: &mut Runtime<F, EF, Diffusion>, entries: &[(u32, Block<F>)]) {
    for (addr, value) in entries {
        runtime.memory.insert(*addr as usize, MemoryEntry { value: *value, timestamp: F::zero() });
        runtime.uninitialized_memory.insert(*addr as usize, *value);
    }
}

fn proof_public_values<Felt: AbstractField>(start_pc: u32) -> Vec<Felt> {
    CorePublicValues::<u32, u32> {
        committed_value_digest: [0; 8],
        deferred_proofs_digest: [0; 8],
        start_pc,
        next_pc: 0,
        exit_code: 0,
        shard: 1,
    }
    .to_vec()
}

fn block_u32(value: Block<F>) -> [u32; 4] {
    value.0.map(|limb| limb.as_canonical_u32())
}

fn signed_slot_hint(value: F) -> i64 {
    const BABY_BEAR_ORDER_U32: i64 = 2_013_265_921;
    let raw = value.as_canonical_u32() as i64;
    if raw > BABY_BEAR_ORDER_U32 / 2 {
        raw - BABY_BEAR_ORDER_U32
    } else {
        raw
    }
}

fn projected_hit(
    bucket_id: &'static str,
    semantic_class: &'static str,
    details: serde_json::Value,
) -> ProjectedBucketHit {
    ProjectedBucketHit {
        bucket_id,
        semantic_class,
        details,
        central_semantic_registered: false,
        strict_countable: false,
    }
}

fn projected_bucket_hits(events: &[CpuEvent<F>], final_pc: u32) -> Vec<ProjectedBucketHit> {
    let mut hits = Vec::new();

    for (step_idx, event) in events.iter().enumerate() {
        let pc = event.pc.as_canonical_u32();
        let next_pc =
            events.get(step_idx + 1).map(|next| next.pc.as_canonical_u32()).unwrap_or(final_pc);
        let opcode = event.instruction.opcode;
        let base_details = || {
            json!({
                "backend": "sp1-fb38df2c",
                "commit": crate::SP1_COMMIT,
                "trace_source": "sp1_recursion_runtime_projected",
                "step_idx": step_idx,
                "pc": pc,
                "next_pc": next_pc,
                "opcode": format!("{:?}", opcode),
                "opcode_number": opcode as u32,
                "a_slot": signed_slot_hint(event.instruction.op_a),
                "a_slot_raw": event.instruction.op_a.as_canonical_u32(),
                "central_registry_status": "parent_pending"
            })
        };

        match opcode {
            Opcode::LOAD => {
                if let Some(memory_record) = event.memory_record.as_ref() {
                    let mut details = base_details();
                    details["obligation_id"] = json!("rec1");
                    details["cell_id"] = json!("rec1.load_init");
                    details["memory_addr"] = json!(memory_record.addr.as_canonical_u32());
                    details["memory_prev_value"] = json!(block_u32(memory_record.prev_value));
                    details["memory_value"] = json!(block_u32(memory_record.value));
                    details["a_after"] = json!(block_u32(event.a));
                    details["a_record_value"] = event
                        .a_record
                        .as_ref()
                        .map(|record| json!(block_u32(record.value)))
                        .unwrap_or(serde_json::Value::Null);
                    hits.push(projected_hit(
                        LOAD_WRITEBACK_BUCKET_ID,
                        "semantic.recursion.load_writeback_binding",
                        details,
                    ));
                }
            }
            Opcode::JAL | Opcode::JALR => {
                let expected_link = if opcode == Opcode::JAL { pc } else { pc.saturating_add(1) };
                let expected_fp = if opcode == Opcode::JAL {
                    (event.fp + event.c[0]).as_canonical_u32()
                } else {
                    event.c[0].as_canonical_u32()
                };
                let fp_after_observed = events
                    .get(step_idx + 1)
                    .map(|next| next.fp.as_canonical_u32())
                    .unwrap_or(expected_fp);
                let link_cell =
                    if opcode == Opcode::JAL { "rec2.jal_link" } else { "rec2.jalr_link" };
                let fp_cell = if opcode == Opcode::JAL { "rec2.jal_fp" } else { "rec2.jalr_fp" };

                for cell_id in [link_cell, fp_cell] {
                    let mut details = base_details();
                    details["obligation_id"] = json!("rec2");
                    details["cell_id"] = json!(cell_id);
                    details["a_after"] = json!(block_u32(event.a));
                    details["expected_link"] = json!(expected_link);
                    details["fp_before"] = json!(event.fp.as_canonical_u32());
                    details["fp_after_observed"] = json!(fp_after_observed);
                    details["expected_fp"] = json!(expected_fp);
                    details["b_value"] = json!(block_u32(event.b));
                    details["c_value"] = json!(block_u32(event.c));
                    hits.push(projected_hit(
                        JUMP_STATE_BUCKET_ID,
                        "semantic.recursion.jump_state_binding",
                        details,
                    ));
                }
            }
            Opcode::BNEINC => {
                let a_before = event
                    .a_record
                    .as_ref()
                    .map(|record| block_u32(record.prev_value))
                    .unwrap_or([0; 4]);
                let upper_cell = if a_before[1..].iter().any(|limb| *limb != 0) {
                    "rec3.upper_nonzero"
                } else {
                    "rec3.upper_zero"
                };
                let branch_cell = if next_pc == pc.saturating_add(1) {
                    "rec3.branch_not_taken"
                } else {
                    "rec3.branch_taken"
                };

                for cell_id in [upper_cell, branch_cell] {
                    let mut details = base_details();
                    details["obligation_id"] = json!("rec3");
                    details["cell_id"] = json!(cell_id);
                    details["a_before"] = json!(a_before);
                    details["a_after"] = json!(block_u32(event.a));
                    details["b_value"] = json!(block_u32(event.b));
                    details["c_offset"] = json!(block_u32(event.c));
                    details["branch_taken"] = json!(next_pc != pc.saturating_add(1));
                    hits.push(projected_hit(
                        BNEINC_INCREMENT_BUCKET_ID,
                        "semantic.recursion.bneinc_increment_binding",
                        details,
                    ));
                }
            }
            _ => {}
        }
    }

    hits
}

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn inject_kind_is_noop(kind: &str) -> bool {
    kind.split_once("::")
        .map(|(_, variant)| variant.split(',').any(|field| field.trim() == "mode=noop_prefix"))
        .unwrap_or(false)
}

fn legacy_injection_site_applied(
    events: &[CpuEvent<F>],
    inject_kind: Option<&str>,
    step: u64,
) -> bool {
    let Some(kind) = inject_kind else {
        return false;
    };
    if inject_kind_is_noop(kind) {
        return false;
    }
    let Some(event) = events.get(step as usize) else {
        return false;
    };
    match base_inject_kind(kind) {
        LOAD_BINDING_INJECT_KIND => event.instruction.opcode == Opcode::LOAD,
        "sp1.legacy_recursion.exec.jump_binding" => {
            matches!(event.instruction.opcode, Opcode::JAL | Opcode::JALR)
        }
        BNEINC_UPPER_LIMBS_INJECT_KIND => event.instruction.opcode == Opcode::BNEINC,
        _ => false,
    }
}

pub fn run_scenario_once(
    scenario: LegacyRecursionScenario,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<ScenarioRun, String> {
    let (program, init_mem) = scenario_program(scenario);
    run_program_once(Some(scenario), None, None, program, init_mem, inject_kind, inject_step)
}

fn run_program_once(
    scenario: Option<LegacyRecursionScenario>,
    case_id: Option<String>,
    seed_path: Option<String>,
    program: RecursionProgram<F>,
    init_mem: Vec<(u32, Block<F>)>,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<ScenarioRun, String> {
    let _guard = EnvGuard::arm(inject_kind, inject_step);
    fuzzer_utils::configure_witness_injection(inject_kind, inject_step);
    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    // The legacy recursion memory model requires strictly increasing timestamps even for the
    // first `Memory` access (position 0). Start at clk=1 so preinitialized memory at ts=0 is legal.
    runtime.clk = F::one();
    runtime.timestamp = 1;
    init_memory(&mut runtime, &init_mem);
    runtime.run();
    let semantic_injection_applied =
        legacy_injection_site_applied(&runtime.record.cpu_events, inject_kind, inject_step);
    let projected_bucket_hits =
        projected_bucket_hits(&runtime.record.cpu_events, runtime.pc.as_canonical_u32());
    let observed_public_values =
        runtime.record.public_values.iter().map(|v| v.as_canonical_u32()).collect::<Vec<_>>();
    runtime.record.public_values = proof_public_values(0);

    let machine = RecursionAirWideDeg3::machine(config);
    let (pk, vk) = machine.setup(&program);
    let debug_record = runtime.record.clone();
    let mut challenger = machine.config().challenger();
    let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record.clone(), &mut challenger);
    let mut challenger = machine.config().challenger();
    if let Err(err) = machine.verify(&vk, &proof, &mut challenger) {
        let mut challenger = machine.config().challenger();
        machine.debug_constraints(&pk, debug_record, &mut challenger);
        return Err(format!("verify failed: {err}"));
    }

    Ok(ScenarioRun {
        scenario,
        case_id,
        seed_path,
        inject_kind: inject_kind.map(str::to_string),
        inject_step,
        semantic_injection_applied,
        public_values: observed_public_values,
        final_pc: runtime.pc.as_canonical_u32(),
        final_fp: runtime.fp.as_canonical_u32(),
        proof_verified: true,
        projected_bucket_hits,
    })
}

pub fn compare_scenario(
    scenario: LegacyRecursionScenario,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<ScenarioComparison, String> {
    let baseline = run_scenario_once(scenario, None, 0)?;
    let injected = run_scenario_once(
        scenario,
        Some(inject_kind.unwrap_or(scenario.default_inject_kind())),
        inject_step,
    )?;
    let diverged = baseline.public_values != injected.public_values
        || baseline.final_fp != injected.final_fp
        || baseline.final_pc != injected.final_pc;
    Ok(ScenarioComparison {
        semantic_injection_applied: injected.semantic_injection_applied,
        underconstrained_candidate: false,
        strict_countable: false,
        strict_blocker: strict_blocker_message(),
        diverged,
        baseline,
        injected,
    })
}

pub fn compare_seed_file(
    seed_path: &str,
    inject_kind: Option<&str>,
    inject_step: Option<u64>,
) -> Result<ScenarioComparison, String> {
    let contents = fs::read_to_string(seed_path)
        .map_err(|err| format!("failed to read recursion seed {seed_path}: {err}"))?;
    let seed: RecursionSeedSpec = serde_json::from_str(&contents)
        .map_err(|err| format!("failed to parse recursion seed {seed_path}: {err}"))?;
    let default_kind = seed
        .default_inject_kind
        .as_deref()
        .ok_or_else(|| "recursion seed is missing default_inject_kind".to_string())?;
    let actual_inject_kind = inject_kind.unwrap_or(default_kind);
    let actual_inject_step = inject_step.or(seed.default_inject_step).unwrap_or(0);

    let (baseline_program, baseline_mem) = seed.to_program();
    let baseline = run_program_once(
        None,
        seed.case_id.clone(),
        Some(seed_path.to_string()),
        baseline_program,
        baseline_mem,
        None,
        0,
    )?;
    if let Some(expected_bucket) = seed.bucket.as_deref() {
        let emitted =
            baseline.projected_bucket_hits.iter().any(|hit| hit.bucket_id == expected_bucket);
        if !emitted {
            return Err(format!(
                "recursion seed {seed_path} did not project expected bucket {expected_bucket}"
            ));
        }
    }

    let (injected_program, injected_mem) = seed.to_program();
    let injected = run_program_once(
        None,
        seed.case_id.clone(),
        Some(seed_path.to_string()),
        injected_program,
        injected_mem,
        Some(actual_inject_kind),
        actual_inject_step,
    )?;
    let diverged = baseline.public_values != injected.public_values
        || baseline.final_fp != injected.final_fp
        || baseline.final_pc != injected.final_pc;

    Ok(ScenarioComparison {
        semantic_injection_applied: injected.semantic_injection_applied,
        underconstrained_candidate: false,
        strict_countable: false,
        strict_blocker: strict_blocker_message(),
        diverged,
        baseline,
        injected,
    })
}

fn strict_blocker_message() -> String {
    "project-local fb38 runner only: central REC obligations, sem.recursion bucket registry, non-RV32 seed frontend, and BenchmarkBackend semantic candidate mapping are parent-scope changes"
        .to_string()
}

pub fn run_cli() -> Result<(), String> {
    let matches = Command::new("beak-legacy-recursion")
        .about("Run historical SP1 recursion scenarios against the patched fb38 snapshot.")
        .arg(Arg::new("scenario").long("scenario").value_parser(["load", "jump", "bneinc"]))
        .arg(Arg::new("seed_json").long("seed-json"))
        .arg(Arg::new("inject_kind").long("inject-kind"))
        .arg(Arg::new("inject_step").long("inject-step"))
        .arg(Arg::new("json").long("json").action(clap::ArgAction::SetTrue))
        .get_matches();

    let inject_step_override = matches
        .get_one::<String>("inject_step")
        .map(|value| value.parse::<u64>().map_err(|e| format!("invalid inject-step: {e}")))
        .transpose()?;
    let inject_kind = matches.get_one::<String>("inject_kind").map(|s| s.as_str());
    let comparison = if let Some(seed_path) = matches.get_one::<String>("seed_json") {
        compare_seed_file(seed_path, inject_kind, inject_step_override)?
    } else {
        let scenario = LegacyRecursionScenario::parse(
            matches
                .get_one::<String>("scenario")
                .ok_or_else(|| "missing --scenario or --seed-json".to_string())?,
        )?;
        let inject_step = inject_step_override.unwrap_or_else(|| scenario.default_inject_step());
        compare_scenario(scenario, inject_kind, inject_step)?
    };

    if matches.get_flag("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&comparison)
                .map_err(|e| format!("json encode failed: {e}"))?
        );
        return Ok(());
    }

    println!("scenario: {:?}", comparison.baseline.scenario);
    println!("case_id: {:?}", comparison.baseline.case_id);
    println!("baseline public_values: {:?}", comparison.baseline.public_values);
    println!(
        "baseline final_pc/fp: {}/{}",
        comparison.baseline.final_pc, comparison.baseline.final_fp
    );
    println!("injected kind: {:?}", comparison.injected.inject_kind);
    println!("semantic_injection_applied: {}", comparison.semantic_injection_applied);
    println!("injected public_values: {:?}", comparison.injected.public_values);
    println!(
        "injected final_pc/fp: {}/{}",
        comparison.injected.final_pc, comparison.injected.final_fp
    );
    println!("diverged: {}", comparison.diverged);
    println!("underconstrained_candidate: {}", comparison.underconstrained_candidate);
    println!("strict_countable: {}", comparison.strict_countable);
    println!("strict_blocker: {}", comparison.strict_blocker);
    Ok(())
}
