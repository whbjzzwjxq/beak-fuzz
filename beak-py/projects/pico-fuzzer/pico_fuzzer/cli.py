#!/usr/bin/env python3

import argparse
from pathlib import Path

from pico_fuzzer.settings import (
    PICO_AVAILABLE_COMMITS_OR_BRANCHES,
    PICO_BENCHMARK_45E74_COMMIT,
    resolve_pico_commit,
)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pico-fuzzer", description="Pico installer entrypoint.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize Pico snapshot into out/.")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        default=PICO_BENCHMARK_45E74_COMMIT,
        choices=PICO_AVAILABLE_COMMITS_OR_BRANCHES,
        help="Pico commit/alias to install.",
    )
    install.add_argument(
        "--out-root",
        type=Path,
        default=Path("out"),
        help="Output root (default: ./out).",
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    from pico_fuzzer.utils_install import clone_and_checkout_pico
    from pico_fuzzer.passes import pass1_infrastructure, pass2_bypass_checks, pass3_collection

    resolved = resolve_pico_commit(args.commit_or_branch)
    dest = (args.out_root / f"pico-{resolved}" / "pico-src").expanduser().resolve()
    dest = clone_and_checkout_pico(dest=dest, commit_or_branch=resolved)

    print("Applying Pass 1/3 (infrastructure)...")
    pass1_infrastructure.apply(pico_install_path=dest, commit_or_branch=resolved)

    print("Applying Pass 2/3 (bypass checks)...")
    pass2_bypass_checks.apply(pico_install_path=dest, commit_or_branch=resolved)

    print("Applying Pass 3/3 (collection)...")
    pass3_collection.apply(pico_install_path=dest, commit_or_branch=resolved)

    print("Pico snapshot patched for witness injection and collection.")
    print(dest)
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
