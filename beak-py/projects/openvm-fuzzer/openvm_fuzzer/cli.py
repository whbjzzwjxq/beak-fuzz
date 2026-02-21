#!/usr/bin/env python3

import argparse
from pathlib import Path

from openvm_fuzzer.settings import (
    OPNEVM_BENCHMARK_REGZERO_ALIAS,
    OPENVM_AVAILABLE_COMMITS_OR_BRANCHES,
    resolve_openvm_commit,
)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="openvm-fuzzer", description="OpenVM installer/patcher.")
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
    return ap


def _install(args: argparse.Namespace) -> int:
    # Import heavy deps lazily so `--help` doesn't require optional runtime deps
    # (e.g. psutil in zkvm_fuzzer_utils).
    from openvm_fuzzer.utils_install import clone_and_checkout_openvm
    from openvm_fuzzer.passes import pass1_infrastructure, pass2_bypass_checks, pass3_collection

    # First, resolve the commit or branch to a concrete commit.
    resolved = resolve_openvm_commit(args.commit_or_branch)

    # Then, materialize the snapshot into out/openvm-<commit>/openvm-src.
    dest = (args.out_root / f"openvm-{resolved}" / "openvm-src").expanduser().resolve()

    dest = clone_and_checkout_openvm(dest=dest, commit_or_branch=resolved)

    # Now, we have the OpenVM snapshot in `dest`.
    # Then, we modify the OpenVM snapshot to make it suitable for fuzzing.

    print("Applying Pass 1/3 (infrastructure)...")
    pass1_infrastructure.apply(openvm_install_path=dest, commit_or_branch=resolved)

    print("Applying Pass 2/3 (bypass checks)...")
    pass2_bypass_checks.apply(openvm_install_path=dest, commit_or_branch=resolved)

    print("Applying Pass 3/3 (collection)...")
    pass3_collection.apply(openvm_install_path=dest, commit_or_branch=resolved)

    print("OpenVM snapshot patched for JSON trace collection.")

    # Finally, print the destination path.
    print(dest)
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
