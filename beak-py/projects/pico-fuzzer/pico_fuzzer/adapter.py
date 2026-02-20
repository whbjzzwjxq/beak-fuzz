from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from beak_core.rv32im import FuzzingInstance
from pico_fuzzer.zkvm_project import InstructionProjectGenerator
from zkvm_fuzzer_utils.cmd import ExecStatus, invoke_command


@dataclass(frozen=True)
class PicoRunResult:
    baseline: ExecStatus
    injected: ExecStatus | None


def _ensure_sparse_registry(project_dir: Path) -> None:
    """
    Ensure Cargo uses the sparse crates.io index (https://index.crates.io) rather than
    the legacy git index (github.com/rust-lang/crates.io-index).

    Some environments block github.com DNS but still allow index.crates.io; without
    this override, `cargo` can fail while updating the registry index.
    """

    cargo_dir = project_dir / ".cargo"
    cargo_dir.mkdir(parents=True, exist_ok=True)
    cfg = cargo_dir / "config.toml"

    # Keep this minimal and local to the generated project.
    cfg.write_text(
        "\n".join(
            [
                "[registries.crates-io]",
                'protocol = "sparse"',
                "",
                "[source.crates-io]",
                'registry = "sparse+https://index.crates.io/"',
                "",
            ]
        )
    )


def build_pico_project(project_dir: Path) -> None:
    _ensure_sparse_registry(project_dir)

    pico_env = {
        "RUSTFLAGS": "--cap-lints allow",
        "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
    }

    guest = invoke_command(["cargo", "pico", "build"], cwd=project_dir / "app", env=pico_env)
    if guest.is_failure():
        # crates.io/git fetch can be flaky; if deps are cached, offline retry often works.
        if "gnutls_handshake" in guest.stderr or "failed to fetch" in guest.stderr:
            pico_env_offline = dict(pico_env)
            pico_env_offline["CARGO_NET_OFFLINE"] = "true"
            guest = invoke_command(
                ["cargo", "pico", "build"], cwd=project_dir / "app", env=pico_env_offline
            )
        if guest.is_failure():
            raise RuntimeError(f"failed to build guest: {guest.stderr}")

    prover = invoke_command(["cargo", "build", "--release"], cwd=project_dir / "prover", env=pico_env)
    if prover.is_failure():
        raise RuntimeError(f"failed to build prover: {prover.stderr}")


def run_pico_prover(project_dir: Path, *, env: dict[str, str] | None = None) -> ExecStatus:
    return invoke_command(["cargo", "run", "--release"], cwd=project_dir / "prover", env=env)


def build_and_run_pico(
    *,
    instance: FuzzingInstance,
    zkvm_dir: Path,
    out_dir: Path,
    injection_env: dict[str, str] | None = None,
    build: bool = True,
) -> PicoRunResult:
    """Generate Pico app/prover project for `instance`, then run baseline and (optional) injected."""

    out_dir.mkdir(parents=True, exist_ok=True)
    InstructionProjectGenerator(out_dir, zkvm_dir, instance).create()

    if build:
        build_pico_project(out_dir)

    baseline = run_pico_prover(out_dir)
    injected = None
    if injection_env is not None:
        injected = run_pico_prover(out_dir, env=injection_env)

    return PicoRunResult(baseline=baseline, injected=injected)
