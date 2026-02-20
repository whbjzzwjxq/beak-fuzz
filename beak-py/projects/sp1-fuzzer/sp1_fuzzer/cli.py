#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path

from sp1_fuzzer.settings import SP1_AVAILABLE_COMMITS_OR_BRANCHES
from sp1_fuzzer.zkvm_repository.snapshot import materialize_sp1_snapshot

logger = logging.getLogger("fuzzer")

def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="sp1-fuzzer", description="SP1 installer (install+optional inject).")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize a snapshot into out/ and optionally inject.")
    install.add_argument("--zkvm-src", type=Path, required=True, help="Path to a local SP1 git repo (source).")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        required=True,
        choices=SP1_AVAILABLE_COMMITS_OR_BRANCHES,
        help="SP1 commit/alias to install.",
    )
    install.add_argument("--out-root", type=Path, default=Path("out"), help="Output root (default: ./out).")
    install.add_argument("--inject", action="store_true", help="Apply SP1 fault-injection patches.")
    return ap


def _cmd_install(args: argparse.Namespace) -> int:
    dest = materialize_sp1_snapshot(
        sp1_src=args.zkvm_src,
        out_root=args.out_root,
        commit_or_branch=args.commit_or_branch,
        inject=bool(args.inject),
    )

    print(dest)
    return 0


def app():
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_cmd_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
