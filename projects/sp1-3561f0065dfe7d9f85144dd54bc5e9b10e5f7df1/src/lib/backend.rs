use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use beak_core::trace::semantic;
use clap::{ArgAction, Parser};
use serde::Serialize;
use sp1_sdk::{ProverClient, SP1Proof, SP1Stdin, SP1VerifyingKey, SP1ProvingKey};

pub const DIV_REM_BOUND_INJECT_KIND: &str =
    "sp1.semantic.arithmetic.division_remainder_bound::mode=decrement_quotient_increment_remainder";
const DIV_REM_BOUND_BASE_KIND: &str = "sp1.semantic.arithmetic.division_remainder_bound";
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
        program_dir()
            .join("elf")
            .join("riscv32im-succinct-zkvm-elf"),
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
        let status = command
            .status()
            .map_err(|e| format!("failed to spawn guest cargo build: {e}"))?;
        if !status.success() {
            return Err(format!(
                "guest cargo build failed for {} with status {status}",
                program.display()
            ));
        }
    }

    let elf = elf_paths
        .into_iter()
        .find(|path| path.exists())
        .ok_or_else(|| {
            let searched = built_elf_paths()
                .into_iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "guest ELF was not produced under {} (searched: {})",
                program.display(),
                searched
            )
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

    let mut proof: SP1Proof = client
        .prove(pk, stdin)
        .map_err(|e| format!("prove failed: {e}"))?;
    let quotient = proof.public_values.read::<[u8; 32]>();
    client
        .verify(&proof, vk)
        .map_err(|e| format!("verify failed: {e}"))?;

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
    let (mut public_values, _) = client
        .execute(elf, stdin)
        .map_err(|e| format!("execute failed: {e}"))?;
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
    let injected = match prove_once(
        &client,
        &pk,
        &vk,
        dividend,
        divisor,
        configured_inject_kind,
        inject_step,
    ) {
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
            println!(
                "{}",
                serde_json::to_string_pretty(&vec![bucket]).map_err(|e| e.to_string())?
            );
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
        let inject_kind = args
            .inject_kind
            .clone()
            .unwrap_or_else(|| DIV_REM_BOUND_INJECT_KIND.to_string());
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
            println!(
                "{}",
                serde_json::to_string_pretty(&hits).map_err(|e| e.to_string())?
            );
        } else {
            for hit in hits {
                println!(
                    "step={} quotient={:02x?}",
                    hit.inject_step, hit.quotient_bytes
                );
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
        .spawn(move || {
            run_comparison(dividend, divisor, inject_kind.as_deref(), inject_step)
        })
        .map_err(|e| format!("failed to spawn worker thread: {e}"))?
        .join()
        .map_err(|_| "worker thread panicked".to_string())??;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
        );
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
