#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path

from risc0_fuzzer.settings import RISC0_AVAILABLE_COMMITS_OR_BRANCHES
from risc0_fuzzer.zkvm_repository.install import Risc0ManagerException, install_risc0
from zkvm_fuzzer_utils.worktree import materialize_worktree, reset_and_clean_repo

logger = logging.getLogger("fuzzer")


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="risc0-fuzzer", description="Risc0 installer (install-only).")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize a snapshot into out/.")
    install.add_argument("--zkvm-src", type=Path, required=True, help="Path to a local Risc0 git repo (source).")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        required=True,
        choices=RISC0_AVAILABLE_COMMITS_OR_BRANCHES,
        help="Risc0 commit/branch to install.",
    )
    install.add_argument("--out-root", type=Path, default=Path("out"), help="Output root (default: ./out).")
    install.add_argument(
        "--inject",
        action="store_true",
        help="Not supported for Risc0 in this repo (kept for flag parity).",
    )
    return ap


def _cmd_install(args: argparse.Namespace) -> int:
    if args.commit_or_branch == "all":
        raise Risc0ManagerException("'all' is not a valid install target; pick a concrete commit")
    if args.inject:
        raise Risc0ManagerException("inject is not supported for Risc0 in this repo")

    dest = materialize_worktree(
        zkvm_name="risc0",
        zkvm_src_repo=args.zkvm_src,
        out_root=args.out_root,
        resolved_commit=args.commit_or_branch,
    )
    reset_and_clean_repo(dest)
    # Reuse existing checks (e.g. Git LFS pointers) while staying local (checkout should succeed).
    install_risc0(dest, args.commit_or_branch)

    print(dest)
    return 0


def app():
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_cmd_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
