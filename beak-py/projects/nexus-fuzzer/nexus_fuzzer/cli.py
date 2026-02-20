#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path

from nexus_fuzzer.settings import (
    NEXUS_AVAILABLE_COMMITS_OR_BRANCHES,
    resolve_nexus_commit,
)
from nexus_fuzzer.zkvm_repository.install import install_nexus
from zkvm_fuzzer_utils.worktree import materialize_worktree, reset_and_clean_repo

logger = logging.getLogger("fuzzer")


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="nexus-fuzzer", description="Nexus installer (install-only).")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize a snapshot into out/.")
    install.add_argument("--zkvm-src", type=Path, required=True, help="Path to a local Nexus git repo (source).")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        required=True,
        choices=NEXUS_AVAILABLE_COMMITS_OR_BRANCHES,
        help="Nexus commit/alias to install.",
    )
    install.add_argument("--out-root", type=Path, default=Path("out"), help="Output root (default: ./out).")
    install.add_argument(
        "--inject",
        action="store_true",
        help="Not supported for Nexus in this repo (kept for flag parity).",
    )
    return ap


def _cmd_install(args: argparse.Namespace) -> int:
    if args.commit_or_branch == "all":
        raise RuntimeError("'all' is not a valid install target; pick a concrete commit")
    if args.inject:
        raise RuntimeError("inject is not supported for Nexus in this repo")

    resolved = resolve_nexus_commit(args.commit_or_branch)
    dest = materialize_worktree(
        zkvm_name="nexus",
        zkvm_src_repo=args.zkvm_src,
        out_root=args.out_root,
        resolved_commit=resolved,
    )
    reset_and_clean_repo(dest)
    install_nexus(dest, resolved)

    print(dest)
    return 0


def app():
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_cmd_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
