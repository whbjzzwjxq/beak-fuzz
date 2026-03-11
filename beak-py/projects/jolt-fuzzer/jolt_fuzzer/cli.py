#!/usr/bin/env python3

import argparse
from pathlib import Path

from jolt_fuzzer.settings import JOLT_BENCHMARK_COMMIT, resolve_jolt_commit


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="jolt-fuzzer", description="Jolt installer entrypoint.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize Jolt snapshot into out/.")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        default=JOLT_BENCHMARK_COMMIT,
        help="Jolt commit/alias/branch to install.",
    )
    install.add_argument(
        "--out-root",
        type=Path,
        default=Path("out"),
        help="Output root (default: ./out).",
    )
    install.add_argument(
        "--zkvm-src",
        type=Path,
        default=None,
        help="Optional local Jolt repository to clone from instead of GitHub.",
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    from jolt_fuzzer.utils_install import clone_and_checkout_jolt

    resolved = resolve_jolt_commit(args.commit_or_branch)
    dest = (args.out_root / f"jolt-{resolved}" / "jolt-src").expanduser().resolve()
    dest = clone_and_checkout_jolt(
        dest=dest,
        commit_or_branch=resolved,
        zkvm_src=args.zkvm_src,
    )
    print(dest)
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
