from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any, Optional

from openvm_fuzzer.patches.snapshot import materialize_openvm_snapshot

from workflow_common import (
    RunResult,
    build_trace_from_records as build_trace_from_records_common,
    ensure_writable_cargo_home,
    extract_record_json,
    load_instructions,
    relpath,
    repo_root,
    write_run_artifacts as write_run_artifacts_common,
    write_text,
)


def _repo_root() -> Path:
    return repo_root()


def _out_dir() -> Path:
    return _repo_root() / "out"


def _extract_record_json(stdout: str) -> list[dict[str, Any]]:
    return extract_record_json(stdout)


def write_run_artifacts(
    *,
    project_root: Path,
    run: RunResult,
    records: list[dict[str, Any]],
    hits: Optional[list[dict[str, Any]]],
) -> None:
    write_run_artifacts_common(
        project_root=project_root,
        run=run,
        records=records,
        hits=hits,
        run_prefix="openvm",
    )


def _ensure_writable_cargo_home() -> Path:
    return ensure_writable_cargo_home()


def run_openvm_project(project_root: Path) -> RunResult:
    env = dict(os.environ)
    env.setdefault("CARGO_NET_OFFLINE", "true")
    env.setdefault("CARGO_HOME", str(_ensure_writable_cargo_home()))
    rustflags = env.get("RUSTFLAGS", "")
    custom_cfg = '--cfg getrandom_backend="custom"'
    if custom_cfg not in rustflags:
        env["RUSTFLAGS"] = (rustflags + " " + custom_cfg).strip()
    proc = subprocess.run(
        ["cargo", "run", "-q", "--release", "--", "--trace"],
        cwd=project_root / "host",
        text=True,
        capture_output=True,
        env=env,
    )
    return RunResult(stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode)


def build_trace_from_records(records: list[dict[str, Any]]):
    return build_trace_from_records_common(records)


def run_buckets(trace, *, openvm_commit: str):
    from beak_core.buckets import (
        GateBoolDomainBucket,
        InactiveRowEffectsBucket,
        NextPcUnderconstrainedBucket,
    )
    from openvm_fuzzer.settings import OPENVM_BENCHMARK_REGZERO_COMMIT

    # OpenVM control-flow candidates:
    # - audit-* snapshots emit adapter/core ChipRows, so we can match specific adapter chips.
    # - regzero snapshot now emits adapter ChipRows from rv32im `fill_trace_row` instrumentation,
    #   so we can match concrete adapter chips there as well.
    if openvm_commit == OPENVM_BENCHMARK_REGZERO_COMMIT:
        nextpc_buckets = [
            NextPcUnderconstrainedBucket(
                instruction_label="openvm.Rv32JalrAdapterAir",
                chip="Rv32JalrAdapterAir",
                min_following_instructions=2,
            ),
            NextPcUnderconstrainedBucket(
                instruction_label="openvm.Rv32BranchAdapterAir",
                chip="Rv32BranchAdapterAir",
                min_following_instructions=2,
            ),
        ]
    else:
        nextpc_buckets = [
            NextPcUnderconstrainedBucket(
                instruction_label="openvm.Rv32JalrAdapterAir",
                chip="Rv32JalrAdapterAir",
                min_following_instructions=2,
            ),
            NextPcUnderconstrainedBucket(
                instruction_label="openvm.Rv32BranchAdapterAir",
                chip="Rv32BranchAdapterAir",
                min_following_instructions=2,
            ),
        ]

    buckets = nextpc_buckets + [
        GateBoolDomainBucket(),
        InactiveRowEffectsBucket(activation_gate="is_real"),
    ]

    hits: list[dict[str, Any]] = []
    for op_idx in range(len(trace.op_spans or [])):
        op_micro_ops = trace.op_micro_ops(op_idx)
        for b in buckets:
            h = b.match_hits(trace, op_idx, op_micro_ops)
            if h is None:
                continue
            hits.append(
                {
                    "bucket": h.bucket_type,
                    "op_idx": op_idx,
                    "details": h.details,
                }
            )
    return hits


def _load_instructions(path: Path) -> list[str]:
    return load_instructions(path)


def _relpath(from_dir: Path, to_path: Path) -> str:
    return relpath(from_dir, to_path)


def _write_text(path: Path, content: str) -> None:
    write_text(path, content)


def install_and_inject_openvm(*, openvm_src: Path, out_dir: Path, commit_or_branch: str) -> Path:
    return materialize_openvm_snapshot(
        openvm_src=openvm_src,
        out_root=out_dir,
        commit_or_branch=commit_or_branch,
        inject=True,
    )


def _parse_used_registers(inst) -> tuple[set[int], set[int]]:
    """
    Returns (all_regs_used, mem_base_regs_used).
    x0 is not included in all_regs_used (it is treated as a constant register).
    """
    regs: set[int] = set()
    base_regs: set[int] = set()

    def _add(r: int | None):
        if r is None or r == 0:
            return
        regs.add(r)

    _add(getattr(inst, "rd", None))
    _add(getattr(inst, "rs1", None))
    _add(getattr(inst, "rs2", None))

    mnemonic = getattr(getattr(inst, "mnemonic", None), "literal", None)
    if mnemonic in {"lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"}:
        r1 = getattr(inst, "rs1", None)
        if isinstance(r1, int) and r1 != 0:
            base_regs.add(r1)
    return regs, base_regs


def generate_project_from_instructions(
    *, out_root: Path, openvm_path: Path, lines: list[str]
) -> Path:
    from beak_core.rv32im import DEFAULT_DATA_BASE, Instruction
    from openvm_fuzzer.settings import (
        OPENVM_BENCHMARK_336F_COMMIT,
        OPENVM_BENCHMARK_F038_COMMIT,
        OPENVM_BENCHMARK_REGZERO_COMMIT,
    )

    insts = [Instruction.from_asm(s) for s in lines]
    regs: set[int] = set()
    base_regs: set[int] = set()
    for inst in insts:
        used, base = _parse_used_registers(inst)
        regs |= used
        base_regs |= base

    # OpenVM guest inline asm constraints: keep to "normal" registers.
    # (x1..x4, x8, x9 are special; x0 is constant and not tracked as a variable.)
    disallowed = {1, 2, 3, 4, 8, 9}
    bad = sorted(r for r in regs if r in disallowed)
    if bad:
        bad_s = ", ".join(f"x{r}" for r in bad)
        raise RuntimeError(
            f"unsupported register(s) in instructions: {bad_s}. "
            "Please use x5..x7 or x10..x31 (avoid x1..x4, x8, x9)."
        )
    if any(getattr(inst, "rd", None) == 0 for inst in insts):
        raise RuntimeError("instructions write to x0 (rd=x0) which is invalid")

    out_root.mkdir(parents=True, exist_ok=True)
    host_dir = out_root / "host"
    guest_dir = out_root / "guest"
    (host_dir / "src").mkdir(parents=True, exist_ok=True)
    (guest_dir / "src").mkdir(parents=True, exist_ok=True)

    _write_text(
        out_root / "Cargo.toml",
        textwrap.dedent(
            """\
            [workspace]
            members = ["host", "guest"]
            default-members = ["host"]
            resolver = "2"
            """
        ),
    )

    fuzzer_utils_path = _relpath(host_dir, openvm_path / "crates" / "fuzzer_utils")
    sdk_path = _relpath(host_dir, openvm_path / "crates" / "sdk")
    build_path = _relpath(host_dir, openvm_path / "crates" / "toolchain" / "build")
    openvm_guest_path_host = _relpath(host_dir, openvm_path / "crates" / "toolchain" / "openvm")
    platform_path = _relpath(host_dir, openvm_path / "crates" / "toolchain" / "platform")
    transpiler_path = _relpath(host_dir, openvm_path / "crates" / "toolchain" / "transpiler")
    _write_text(
        host_dir / "Cargo.toml",
        textwrap.dedent(
            f"""\
            [package]
            name = "openvm-microops-host"
            version = "0.1.0"
            edition = "2021"

            [dependencies]
            fuzzer_utils = {{ path = "{fuzzer_utils_path}" }}
            openvm = {{ path = "{openvm_guest_path_host}", features = ["std"] }}
            openvm-sdk = {{ path = "{sdk_path}" }}
            openvm-build = {{ path = "{build_path}" }}
            openvm-platform = {{ path = "{platform_path}" }}
            openvm-transpiler = {{ path = "{transpiler_path}" }}
            """
        ),
    )

    regs_sorted = sorted(regs)
    init_regs: dict[int, int] = {0: 0}
    for r in regs_sorted:
        init_regs[r] = DEFAULT_DATA_BASE if r in base_regs else (0x10 + r)

    # Host program: prove+verify to ensure we go through the circuit tracegen path that emits micro-ops.
    if (openvm_path / ".openvm_commit").exists():
        commit = (openvm_path / ".openvm_commit").read_text().strip()
    else:
        commit = ""
    use_generic_sdk = commit == OPENVM_BENCHMARK_REGZERO_COMMIT
    use_legacy_sdk_unit = commit in {OPENVM_BENCHMARK_336F_COMMIT, OPENVM_BENCHMARK_F038_COMMIT}

    if use_generic_sdk:
        host_main = textwrap.dedent(
            """\
            use std::sync::Arc;

            use openvm_build::GuestOptions;
            use openvm_sdk::{
                config::{AppConfig, AppFriParams, SdkVmConfig, TranspilerConfig},
                prover::verify_app_proof,
                Sdk, StdIn,
            };

            use fuzzer_utils;

            fn main() {
                let trace = std::env::args().any(|arg| arg == "--trace");
                fuzzer_utils::set_trace_logging(trace);

                let vm_config = SdkVmConfig::builder()
                    .system(Default::default())
                    .rv32i(Default::default())
                    .rv32m(Default::default())
                    .io(Default::default())
                    .build();
                let app_fri_params = AppFriParams::default().fri_params;
                let app_config = AppConfig::new(app_fri_params.clone(), vm_config.clone());
                let sdk = Sdk::new(app_config).expect("sdk init");

                let guest_opts = GuestOptions::default();
                let elf = sdk
                    .build(guest_opts, "../guest", &Default::default(), None)
                    .expect("guest build");
                let exe = sdk.convert_to_exe(elf).expect("guest transpile");

                let mut stdin = StdIn::default();
            """
        )
    elif use_legacy_sdk_unit:
        host_main = textwrap.dedent(
            """\
            use std::sync::Arc;

            use openvm_build::GuestOptions;
            use openvm_sdk::{
                config::{AppConfig, AppFriParams, SdkVmConfig},
                Sdk, StdIn,
            };

            use fuzzer_utils;

            fn main() {
                let trace = std::env::args().any(|arg| arg == "--trace");
                fuzzer_utils::set_trace_logging(trace);

                let vm_config = SdkVmConfig::builder()
                    .system(Default::default())
                    .rv32i(Default::default())
                    .rv32m(Default::default())
                    .io(Default::default())
                    .build();
                let app_fri_params = AppFriParams::default().fri_params;
                let sdk = Sdk;
                let guest_opts = GuestOptions::default();

                let elf = sdk
                    .build(guest_opts, "../guest", &Default::default())
                    .expect("guest build");
                let exe = sdk.transpile(elf, vm_config.transpiler()).expect("guest transpile");

                let mut stdin = StdIn::default();
            """
        )
    else:
        # Default to the newer SDK API (Sdk::new + execute) used by ca36de+.
        host_main = textwrap.dedent(
            """\
            use openvm_build::GuestOptions;
            use openvm_sdk::config::SdkVmConfig;
            use openvm_sdk::{Sdk, StdIn};

            use fuzzer_utils;

            fn main() {
                let trace = std::env::args().any(|arg| arg == "--trace");
                fuzzer_utils::set_trace_logging(trace);

                let vm_config = SdkVmConfig::builder()
                    .system(Default::default())
                    .rv32i(Default::default())
                    .rv32m(Default::default())
                    .io(Default::default())
                    .build();

                let sdk = Sdk::new();
                let guest_opts = GuestOptions::default();

                let elf = sdk
                    .build(guest_opts, &vm_config, "../guest", &Default::default(), None)
                    .expect("guest build");
                let exe = sdk
                    .transpile(elf, vm_config.transpiler())
                    .expect("guest transpile");

                let stdin = StdIn::default();
                let _public_values = sdk.execute(exe, vm_config, stdin).expect("execute");
            }
            """
        )

    if use_generic_sdk or use_legacy_sdk_unit:
        for reg_idx in sorted(init_regs.keys()):
            if reg_idx == 0:
                continue
            host_main += f"    stdin.write(&{init_regs[reg_idx]}u32);\n"

        if use_generic_sdk:
            host_main += textwrap.dedent(
                """\

                let mut app_prover = sdk.app_prover(exe.clone()).expect("app prover");
                let app_commit = app_prover.app_commit();
                let (_app_pk, app_vk) = sdk.app_keygen();

                let proof = app_prover.prove(stdin.clone()).expect("prove");
                let verified = verify_app_proof(&app_vk, &proof).expect("verify");
                if verified.app_exe_commit != app_commit.app_exe_commit {
                    panic!("app exe commit mismatch");
                }
            """
            )
        else:
            host_main += textwrap.dedent(
                """\

                let app_config = AppConfig::new(app_fri_params.clone(), vm_config);
                let app_committed_exe = sdk
                    .commit_app_exe(app_fri_params, exe)
                    .expect("commit app exe");
                let app_pk = Arc::new(sdk.app_keygen(app_config).expect("app keygen"));

                let proof = sdk
                    .generate_app_proof(app_pk.clone(), app_committed_exe.clone(), stdin.clone())
                    .expect("prove");
                let app_vk = app_pk.get_app_vk();
                sdk.verify_app_proof(&app_vk, &proof).expect("verify");
            """
            )
        host_main += "}\n"

    _write_text(host_dir / "src" / "main.rs", host_main)

    openvm_guest_path = _relpath(guest_dir, openvm_path / "crates" / "toolchain" / "openvm")
    _write_text(
        guest_dir / "Cargo.toml",
        textwrap.dedent(
            f"""\
            [package]
            name = "openvm-microops-guest"
            version = "0.1.0"
            edition = "2021"

            [dependencies]
            openvm = {{ path = "{openvm_guest_path}", features = ["std"] }}
            """
        ),
    )

    asm_lines = "\n".join(f'            "{s}",' for s in lines)
    # Guest reads initial regs from stdin (excluding x0), runs asm, then reveals a sentinel.
    reveal_fn = "reveal_u32" if commit == OPENVM_BENCHMARK_REGZERO_COMMIT else "reveal"
    guest_main_lines: list[str] = [
        "#![allow(unused_unsafe)]",
        "#![allow(arithmetic_overflow)]",
        "#![no_main]",
        "",
        "use core::arch::asm;",
        f"use openvm::io::{{read, {reveal_fn}}};",
        "",
        "openvm::entry!(main);",
        "",
        "#[no_mangle]",
        "pub fn main() {",
    ]
    for r in sorted(init_regs.keys()):
        if r == 0:
            continue
        guest_main_lines.append(f"    let mut x{r}: u32 = read();")
    guest_main_lines += [
        "",
        "    unsafe {",
        "        asm!(",
        "            // instruction sequence",
        asm_lines,
    ]
    for r in sorted(init_regs.keys()):
        if r == 0:
            continue
        guest_main_lines.append(f'            inout("x{r}") x{r},')
    guest_main_lines += [
        "            options(nostack)",
        "        );",
        "    }",
        "",
        f"    {reveal_fn}(0xDEADBEEF, 0);",
        "}",
        "",
    ]
    guest_main = "\n".join(guest_main_lines)
    _write_text(guest_dir / "src" / "main.rs", guest_main)
    return out_root


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--openvm-path",
        type=Path,
        default=_repo_root() / "openvm-src",
        help="Path to an OpenVM git repo or checkout (used as the source for install+inject).",
    )
    ap.add_argument(
        "--openvm-commit",
        type=str,
        default="bmk-f038",
        help="OpenVM commit or alias (bmk-regzero/bmk-336f/bmk-f038).",
    )
    ap.add_argument(
        "--install-openvm",
        action="store_true",
        help="Local install+inject flow: copy --openvm-path into out/ and inject instrumentation there.",
    )
    ap.add_argument(
        "--project-root",
        type=Path,
        default=None,
        help="OpenVM project root containing `host/` and `guest/` (defaults under out/openvm-<commit>/).",
    )
    ap.add_argument(
        "--instructions-file",
        type=Path,
        default=None,
        help="Optional: file with one RV32IM asm instruction per line; generates a project and runs it.",
    )
    ap.add_argument(
        "--no-write-artifacts",
        action="store_true",
        help="Do not write run artifacts (stdout/stderr/records/hits) into the project root.",
    )
    ap.add_argument(
        "--trace-only",
        action="store_true",
        help=(
            "Trace mode: run and export micro_op_records.json only (skip bucket matching and do not write "
            "bucket_hits.json)."
        ),
    )
    args = ap.parse_args()
    from openvm_fuzzer.settings import resolve_openvm_commit

    commit = resolve_openvm_commit(args.openvm_commit)

    openvm_path = args.openvm_path
    if args.install_openvm:
        out_dir = _out_dir()
        openvm_path = install_and_inject_openvm(
            openvm_src=openvm_path, out_dir=out_dir, commit_or_branch=commit
        )
    elif args.instructions_file is not None:
        # Prefer an already-installed snapshot when generating an instruction-driven project.
        installed = _out_dir() / f"openvm-{commit}" / "openvm-src"
        if installed.exists():
            openvm_path = installed

    if args.project_root is None:
        project_root = _out_dir() / f"openvm-{commit}" / "microops-fixed-elf"
    else:
        project_root = args.project_root
    if args.instructions_file is not None:
        out_root = _out_dir() / f"openvm-{commit}" / "from-insts"
        project_root = generate_project_from_instructions(
            out_root=out_root,
            openvm_path=openvm_path,
            lines=_load_instructions(args.instructions_file),
        )

    run = run_openvm_project(project_root)
    if run.returncode != 0:
        if not args.no_write_artifacts:
            write_run_artifacts(
                project_root=project_root,
                run=run,
                records=[],
                hits=[] if not args.trace_only else None,
            )
        print(f"project_root={project_root}")
        print(f"exit={run.returncode}")
        print("stderr tail:")
        tail = "\n".join(run.stderr.strip().splitlines()[-40:])
        print(tail)
        return 1

    records = _extract_record_json(run.stdout)
    if not records:
        if not args.no_write_artifacts:
            write_run_artifacts(
                project_root=project_root,
                run=run,
                records=[],
                hits=[] if not args.trace_only else None,
            )
        raise RuntimeError(
            "no <record> json objects found in stdout. "
            f"project_root={project_root} (see openvm_run.stdout.txt / openvm_run.stderr.txt)"
        )
    micro_op_records = [r for r in records if r.get("context") == "micro_op"]
    if args.trace_only:
        if not args.no_write_artifacts:
            write_run_artifacts(project_root=project_root, run=run, records=records, hits=None)
        print(f"project_root={project_root}")
        print(f"exit={run.returncode}")
        print(f"trace_mode=on micro_op_records={len(micro_op_records)}")
        manifest = {
            "mode": "trace_only",
            "project_root": str(project_root),
            "micro_op_records_path": str(project_root / "micro_op_records.json"),
            "stdout_path": str(project_root / "openvm_run.stdout.txt"),
            "stderr_path": str(project_root / "openvm_run.stderr.txt"),
            "micro_op_record_count": len(micro_op_records),
        }
        print(json.dumps(manifest))
        return 0

    trace = build_trace_from_records(records)
    hits = run_buckets(trace, openvm_commit=commit)
    if not args.no_write_artifacts:
        write_run_artifacts(project_root=project_root, run=run, records=records, hits=hits)

    print(f"project_root={project_root}")
    print(f"exit={run.returncode}")
    print(f"micro_ops={len(trace.micro_ops)} ops={len(trace.op_spans or [])} hits={len(hits)}")
    for h in hits[:20]:
        print(json.dumps(h, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
