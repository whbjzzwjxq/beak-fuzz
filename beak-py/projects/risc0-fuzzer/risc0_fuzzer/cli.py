#!/usr/bin/env python3

import argparse
from pathlib import Path

from risc0_fuzzer.settings import RISC0_BENCHMARK_COMMIT, resolve_risc0_commit
from risc0_fuzzer.utils_install import clone_and_checkout_risc0
from zkvm_fuzzer_utils.snapshot_install import (
    apply_pass_pipeline,
    default_snapshot_out_root,
    maybe_warn_on_nondefault_out_root,
    resolve_snapshot_out_root,
)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="risc0-fuzzer", description="RISC0 installer entrypoint.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser(
        "install",
        help="Materialize RISC0 snapshot into the repo-local beak-py/out/ by default.",
    )
    install.add_argument(
        "--commit-or-branch",
        type=str,
        default=RISC0_BENCHMARK_COMMIT,
        help="RISC0 commit/alias/branch to install.",
    )
    install.add_argument(
        "--out-root",
        type=Path,
        default=None,
        help=f"Output root (default: {default_snapshot_out_root()}).",
    )
    install.add_argument(
        "--zkvm-src",
        type=Path,
        default=None,
        help="Optional local RISC0 repository to clone from instead of GitHub.",
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    resolved = resolve_risc0_commit(args.commit_or_branch)
    out_root = resolve_snapshot_out_root(args.out_root)
    if args.out_root is not None:
        maybe_warn_on_nondefault_out_root(out_root)
    dest = (out_root / f"risc0-{resolved}" / "risc0-src").expanduser().resolve()
    clone_and_checkout_risc0(
        dest=dest,
        commit_or_branch=resolved,
        zkvm_src=args.zkvm_src,
    )
    apply_pass_pipeline(
        package_name="risc0_fuzzer",
        install_path_kw="risc0_install_path",
        install_path=dest,
        commit_or_branch=resolved,
    )
    print("RISC0 snapshot staged for beak.")
    print(dest)
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
