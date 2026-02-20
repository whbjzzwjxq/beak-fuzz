#!/usr/bin/env python3

import argparse
import re
import subprocess
from pathlib import Path

from openvm_fuzzer.settings import (
    OPNEVM_BENCHMARK_REGZERO_ALIAS,
    OPENVM_AVAILABLE_COMMITS_OR_BRANCHES,
    resolve_openvm_commit,
)
from openvm_fuzzer.utils_install import (
    clone_and_checkout_openvm,
)
from openvm_fuzzer.utils_trace import CircuitProjectGenerator

from openvm_fuzzer.patches import (
    rewrite_private_stark,
    create_fuzzer_utils_crate,
    add_fuzzer_utils_workspace,
    rv32im_overwrite_cores,
    transpiler_remove_protection,
    vm_replace_asserts,
    vm_add_serde_json,
    patch_integration_api_microops,
    patch_padding_samples,
    patch_segment_and_regzero_microops,
    rv32im_circuit_add_deps,
    rv32im_replace_asserts,
)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="openvm-fuzzer", description="OpenVM installer.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize a snapshot into out/.")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        default=OPNEVM_BENCHMARK_REGZERO_ALIAS,
        choices=OPENVM_AVAILABLE_COMMITS_OR_BRANCHES,
        help="OpenVM commit/alias to install.",
    )
    install.add_argument(
        "--out-root", type=Path, default=Path("out"), help="Output root (default: ./out)."
    )

    trace = sp.add_parser("trace", help="Trace a snapshot.")
    trace.add_argument(
        "--zkvm-src",
        type=Path,
        default=Path("openvm-src"),
        help="Path to a local OpenVM git repo (source). Default: ./openvm-src",
    )
    trace.add_argument(
        "--commit-or-branch",
        type=str,
        default=OPNEVM_BENCHMARK_REGZERO_ALIAS,
        choices=OPENVM_AVAILABLE_COMMITS_OR_BRANCHES,
        help="OpenVM commit/alias to trace.",
    )
    trace.add_argument(
        "--out-root", type=Path, default=Path("out"), help="Output root (default: ./out)."
    )
    trace.add_argument(
        "--project-root",
        type=Path,
        default=None,
        help="Where to generate the trace project (default: <out-root>/trace-<commit>).",
    )
    trace.add_argument(
        "--asm",
        type=str,
        nargs="+",
        action="extend",
        default=[],
        help=(
            "RISC-V assembly instructions (strings) to embed directly into guest inline asm. "
            "If omitted, uses a tiny default program."
        ),
    )
    trace.add_argument(
        "--reg",
        dest="reg",
        type=str,
        action="append",
        default=[],
        help="Initial register value as IDX=VALUE or xIDX=VALUE (decimal or 0x..). Repeatable.",
    )
    trace.add_argument(
        "--no-run",
        action="store_true",
        help="Only generate the trace project; do not run cargo.",
    )
    trace.add_argument(
        "--stdout",
        type=Path,
        default=None,
        help="Redirect host stdout (cargo run output) to this file.",
    )
    trace.add_argument(
        "--profile",
        type=str,
        choices=["release", "debug"],
        default="release",
        help="Cargo profile for running the host (default: release).",
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    # First, resolve the commit or branch to a concrete commit.
    resolved = resolve_openvm_commit(args.commit_or_branch)

    # Then, materialize the snapshot into out/openvm-<commit>/openvm-src.
    dest = (args.out_root / f"openvm-{resolved}" / "openvm-src").expanduser().resolve()

    dest = clone_and_checkout_openvm(dest=dest, commit_or_branch=resolved)

    # Now, we have the OpenVM snapshot in `dest`.
    # Then, we modify the OpenVM snapshot to make it suitable for fuzzing.

    applied_functions = [
        rewrite_private_stark.apply,
        create_fuzzer_utils_crate.apply,
        add_fuzzer_utils_workspace.apply,
        transpiler_remove_protection.apply,
        vm_replace_asserts.apply,
        vm_add_serde_json.apply,
        patch_integration_api_microops.apply,
        patch_padding_samples.apply,
        patch_segment_and_regzero_microops.apply,
        rv32im_circuit_add_deps.apply,
        rv32im_overwrite_cores.apply,
        rv32im_replace_asserts.apply,
    ]
    for apply_function in applied_functions:
        print("Applying %s..." % apply_function.__module__.split(".")[-1])
        apply_function(openvm_install_path=dest, commit_or_branch=resolved)

    # Finally, print the destination path.
    print(dest)
    return 0


def _trace(args: argparse.Namespace) -> int:
    resolved = resolve_openvm_commit(args.commit_or_branch)

    # If user didn't explicitly point to a repo, default to the installed snapshot path.
    zkvm_src = args.zkvm_src.expanduser().resolve()
    if args.zkvm_src == Path("openvm-src"):
        zkvm_src = (args.out_root / f"openvm-{resolved}" / "openvm-src").expanduser().resolve()

    if not zkvm_src.exists():
        raise SystemExit(f"zkvm source path does not exist: {zkvm_src}")

    if args.project_root is None:
        project_root = (args.out_root / f"trace-{resolved}").expanduser().resolve()
    else:
        project_root = args.project_root.expanduser().resolve()

    instructions_asm: list[str]
    if args.asm:
        instructions_asm = args.asm
    else:
        # Default: small illustrative program (assembly directly; avoids Instruction dependency)
        instructions_asm = [
            "add x0, x0, 0",
        ]

    initial_regs: dict[int, int] = {}
    for item in args.reg:
        if "=" not in item:
            raise SystemExit(f"invalid --reg (expected IDX=VALUE or xIDX=VALUE): {item}")
        k_str, v_str = item.split("=", 1)
        k_str = k_str.strip()
        if k_str.lower().startswith("x"):
            k_str = k_str[1:]
        k = int(k_str, 0)
        v = int(v_str, 0)
        initial_regs[k] = v & 0xFFFFFFFF

    # Reserve x30 as a scratch register to capture x0 inside inline asm.
    # This avoids introducing an extra Rust variable just to read x0.
    initial_regs.setdefault(30, 0)

    # Lightweight safety check: every register referenced as xN in --asm must be
    # present in --reg (plus x0 which is always allowed).
    allowed_regs = set(initial_regs.keys()) | {0}
    regs_in_asm: set[int] = set()
    # Also disallow ABI register names to avoid bypassing the check.
    abi_reg_re = re.compile(
        r"\b(ra|sp|gp|tp|fp|a[0-7]|t[0-6]|s(?:[0-9]|1[01]))\b", flags=re.IGNORECASE
    )
    x_reg_re = re.compile(r"\bx(\d+)\b", flags=re.IGNORECASE)
    for inst in instructions_asm:
        if abi_reg_re.search(inst):
            raise SystemExit(
                f"invalid --asm instruction (use xN names only): {inst!r}. "
                "Every register must be explicitly listed via --reg xN=VALUE (x0 is implicit)."
            )
        for m in x_reg_re.finditer(inst):
            idx = int(m.group(1), 10)
            if not (0 <= idx <= 31):
                raise SystemExit(f"invalid register in --asm (expected x0..x31): x{idx}")
            regs_in_asm.add(idx)
    missing = sorted(regs_in_asm - allowed_regs)
    if missing:
        missing_str = ", ".join(f"x{i}" for i in missing)
        raise SystemExit(
            f"--asm references registers not provided via --reg: {missing_str}. "
            "Every register used in --asm must be listed via --reg xN=VALUE (x0 is implicit)."
        )
    if 30 in regs_in_asm:
        raise SystemExit(
            "--asm must not reference x30: it is reserved as a scratch register for capturing x0."
        )
    forbidden = {2: "sp", 3: "gp", 4: "tp", 8: "fp", 9: "s1"}
    bad = [k for k in initial_regs.keys() if k in forbidden]
    if bad:
        bad_str = ", ".join(f"x{k}({forbidden[k]})" for k in sorted(bad))
        raise SystemExit(
            f"--reg contains forbidden inline-asm operand registers: {bad_str}. "
            "Avoid using x2/x3/x4/x8/x9 in seeds."
        )
    if not initial_regs:
        # Default initial regs (safe subset; can be overridden by passing --reg)
        initial_regs = {}
    gen = CircuitProjectGenerator(
        root=project_root,
        zkvm_path=zkvm_src,
        instructions_asm=instructions_asm,
        initial_regs=initial_regs,
        fault_injection=False,
        commit_or_branch=resolved,
    )
    gen.create()

    if args.no_run:
        print(project_root)
        return 0

    print(f"Running trace via cargo in {project_root}")
    cargo_cmd = [
        "cargo",
        "run",
        "-p",
        "openvm-host",
        "--manifest-path",
        str(project_root / "Cargo.toml"),
    ]
    if args.profile == "release":
        cargo_cmd.append("--release")
    cargo_cmd += [
        "--",
        "--trace",
    ]
    stdout_f = None
    try:
        if args.stdout is not None:
            stdout_path = args.stdout.expanduser().resolve()
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_f = open(stdout_path, "w", encoding="utf-8")
        subprocess.run(
            cargo_cmd,
            check=True,
            cwd=project_root,
            stdout=stdout_f,
        )
    finally:
        if stdout_f is not None:
            stdout_f.close()
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    if args.command == "trace":
        raise SystemExit(_trace(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
