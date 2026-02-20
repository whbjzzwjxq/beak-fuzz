#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path

from pico_fuzzer.settings import PICO_AVAILABLE_COMMITS_OR_BRANCHES
from pico_fuzzer.zkvm_repository.install import install_pico
from zkvm_fuzzer_utils.worktree import materialize_worktree, reset_and_clean_repo

logger = logging.getLogger("fuzzer")


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pico-fuzzer", description="Pico installer (install+optional inject).")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize a snapshot into out/ and optionally inject.")
    install.add_argument("--zkvm-src", type=Path, required=True, help="Path to a local Pico git repo (source).")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        required=True,
        choices=PICO_AVAILABLE_COMMITS_OR_BRANCHES,
        help="Pico commit/branch to install.",
    )
    install.add_argument("--out-root", type=Path, default=Path("out"), help="Output root (default: ./out).")
    install.add_argument("--inject", action="store_true", help="Apply Pico zkVM modification hooks.")
    return ap


def _cmd_install(args: argparse.Namespace) -> int:
    if args.commit_or_branch == "all":
        raise RuntimeError("'all' is not a valid install target; pick a concrete commit")

    dest = materialize_worktree(
        zkvm_name="pico",
        zkvm_src_repo=args.zkvm_src,
        out_root=args.out_root,
        resolved_commit=args.commit_or_branch,
    )
    reset_and_clean_repo(dest)
    install_pico(dest, args.commit_or_branch, enable_zkvm_modification=bool(args.inject))

    print(dest)
    return 0


def app():
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_cmd_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
