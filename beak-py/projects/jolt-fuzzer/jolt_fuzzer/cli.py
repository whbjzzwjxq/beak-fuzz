#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path

from jolt_fuzzer.settings import JOLT_AVAILABLE_COMMITS_OR_BRANCHES
from jolt_fuzzer.zkvm_repository.install import install_jolt
from zkvm_fuzzer_utils.worktree import materialize_worktree, reset_and_clean_repo

logger = logging.getLogger("fuzzer")


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="jolt-fuzzer", description="Jolt installer (install-only).")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize a snapshot into out/.")
    install.add_argument("--zkvm-src", type=Path, required=True, help="Path to a local Jolt git repo (source).")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        required=True,
        choices=JOLT_AVAILABLE_COMMITS_OR_BRANCHES,
        help="Jolt commit/branch to install.",
    )
    install.add_argument("--out-root", type=Path, default=Path("out"), help="Output root (default: ./out).")
    install.add_argument(
        "--inject",
        action="store_true",
        help="Not supported for Jolt in this repo (kept for flag parity).",
    )
    return ap


def _cmd_install(args: argparse.Namespace) -> int:
    if args.commit_or_branch == "all":
        raise RuntimeError("'all' is not a valid install target; pick a concrete commit")
    if args.inject:
        raise RuntimeError("inject is not supported for Jolt in this repo")

    dest = materialize_worktree(
        zkvm_name="jolt",
        zkvm_src_repo=args.zkvm_src,
        out_root=args.out_root,
        resolved_commit=args.commit_or_branch,
    )
    reset_and_clean_repo(dest)
    install_jolt(dest, args.commit_or_branch)

    print(dest)
    return 0


def app():
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_cmd_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()

