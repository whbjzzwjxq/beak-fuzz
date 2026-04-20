use std::env;

use clap::{Arg, Command};
use p3_field::{AbstractField, PrimeField32};
use serde::Serialize;
use sp1_core::air::PublicValues as CorePublicValues;
use sp1_core::stark::{LocalProver, StarkGenericConfig};
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_core::air::Block;
use sp1_recursion_core::runtime::{Instruction, MemoryEntry, Opcode, RecursionProgram, Runtime};
use sp1_recursion_core::stark::RecursionAirWideDeg3;

pub const LOAD_BINDING_INJECT_KIND: &str = "sp1.legacy_recursion.memory.load_binding";
pub const JUMP_BINDING_INJECT_KIND: &str =
    "sp1.legacy_recursion.exec.jump_binding::mode=jal_a_plus_one";
pub const BNEINC_UPPER_LIMBS_INJECT_KIND: &str =
    "sp1.legacy_recursion.exec.bneinc_upper_limbs";

type SC = BabyBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;
const A0_SLOT: i32 = -8;

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
    pub scenario: LegacyRecursionScenario,
    pub inject_kind: Option<String>,
    pub inject_step: u64,
    pub public_values: Vec<u32>,
    pub final_pc: u32,
    pub final_fp: u32,
    pub proof_verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioComparison {
    pub baseline: ScenarioRun,
    pub injected: ScenarioRun,
    pub diverged: bool,
    pub underconstrained_candidate: bool,
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

fn scenario_program(scenario: LegacyRecursionScenario) -> (RecursionProgram<F>, Vec<(u32, Block<F>)>) {
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
                    imm_instruction(
                        Opcode::JAL,
                        A0_SLOT,
                        [1, 0, 0, 0],
                        zero,
                        0,
                        0,
                        "jal",
                    ),
                    imm_instruction(Opcode::Commit, A0_SLOT, zero, zero, 0, 0, "commit"),
                ],
                traces: vec![None, None, None],
            },
            vec![],
        ),
        LegacyRecursionScenario::Bneinc => (
            RecursionProgram {
                instructions: vec![
                    imm_instruction(
                        Opcode::BNEINC,
                        0,
                        [1, 0, 0, 0],
                        [3, 0, 0, 0],
                        0,
                        0,
                        "bneinc",
                    ),
                    imm_instruction(Opcode::Commit, 0, zero, zero, 0, 0, "commit"),
                ],
                traces: vec![None, None],
            },
            vec![(1 << 24, block([0, 0, 0, 0]))],
        ),
    }
}

fn init_memory<Diffusion>(runtime: &mut Runtime<F, EF, Diffusion>, entries: &[(u32, Block<F>)]) {
    for (addr, value) in entries {
        runtime.memory.insert(
            *addr as usize,
            MemoryEntry {
                value: *value,
                timestamp: F::zero(),
            },
        );
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

pub fn run_scenario_once(
    scenario: LegacyRecursionScenario,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<ScenarioRun, String> {
    let _guard = EnvGuard::arm(inject_kind, inject_step);
    let (program, init_mem) = scenario_program(scenario);
    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    // The legacy recursion memory model requires strictly increasing timestamps even for the
    // first `Memory` access (position 0). Start at clk=1 so preinitialized memory at ts=0 is legal.
    runtime.clk = F::one();
    runtime.timestamp = 1;
    init_memory(&mut runtime, &init_mem);
    runtime.run();
    let observed_public_values = runtime
        .record
        .public_values
        .iter()
        .map(|v| v.as_canonical_u32())
        .collect::<Vec<_>>();
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
        inject_kind: inject_kind.map(str::to_string),
        inject_step,
        public_values: observed_public_values,
        final_pc: runtime.pc.as_canonical_u32(),
        final_fp: runtime.fp.as_canonical_u32(),
        proof_verified: true,
    })
}

pub fn compare_scenario(
    scenario: LegacyRecursionScenario,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<ScenarioComparison, String> {
    let baseline = run_scenario_once(scenario, None, 0)?;
    let injected =
        run_scenario_once(scenario, Some(inject_kind.unwrap_or(scenario.default_inject_kind())), inject_step)?;
    let diverged = baseline.public_values != injected.public_values
        || baseline.final_fp != injected.final_fp
        || baseline.final_pc != injected.final_pc;
    Ok(ScenarioComparison {
        underconstrained_candidate: diverged && injected.proof_verified,
        diverged,
        baseline,
        injected,
    })
}

pub fn run_cli() -> Result<(), String> {
    let matches = Command::new("beak-legacy-recursion")
        .about("Run historical SP1 recursion scenarios against the patched fb38 snapshot.")
        .arg(
            Arg::new("scenario")
                .long("scenario")
                .required(true)
                .value_parser(["load", "jump", "bneinc"]),
        )
        .arg(Arg::new("inject_kind").long("inject-kind"))
        .arg(
            Arg::new("inject_step")
                .long("inject-step"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let scenario = LegacyRecursionScenario::parse(
        matches
            .get_one::<String>("scenario")
            .ok_or_else(|| "missing scenario".to_string())?,
    )?;
    let inject_step = matches
        .get_one::<String>("inject_step")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|e| format!("invalid inject-step: {e}"))
        })
        .transpose()?
        .unwrap_or_else(|| scenario.default_inject_step());
    let inject_kind = matches.get_one::<String>("inject_kind").map(|s| s.as_str());
    let comparison = compare_scenario(scenario, inject_kind, inject_step)?;

    if matches.get_flag("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&comparison).map_err(|e| format!("json encode failed: {e}"))?
        );
        return Ok(());
    }

    println!("scenario: {:?}", comparison.baseline.scenario);
    println!("baseline public_values: {:?}", comparison.baseline.public_values);
    println!(
        "baseline final_pc/fp: {}/{}",
        comparison.baseline.final_pc, comparison.baseline.final_fp
    );
    println!("injected kind: {:?}", comparison.injected.inject_kind);
    println!("injected public_values: {:?}", comparison.injected.public_values);
    println!(
        "injected final_pc/fp: {}/{}",
        comparison.injected.final_pc, comparison.injected.final_fp
    );
    println!("diverged: {}", comparison.diverged);
    println!(
        "underconstrained_candidate: {}",
        comparison.underconstrained_candidate
    );
    Ok(())
}
