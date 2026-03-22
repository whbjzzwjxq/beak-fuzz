#!/usr/bin/env python3

import argparse
from pathlib import Path

from nexus_fuzzer.settings import NEXUS_BENCHMARK_COMMIT, resolve_nexus_commit


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="nexus-fuzzer", description="Nexus installer entrypoint.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize Nexus snapshot into out/.")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        default=NEXUS_BENCHMARK_COMMIT,
        help="Nexus commit/alias/branch to install.",
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
        help="Optional local Nexus repository to clone from instead of GitHub.",
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    from nexus_fuzzer.utils_install import clone_and_checkout_nexus
    from nexus_fuzzer.passes import pass1_infrastructure, pass2_bypass_checks, pass3_collection

    resolved = resolve_nexus_commit(args.commit_or_branch)
    dest = (args.out_root / f"nexus-{resolved}" / "nexus-src").expanduser().resolve()
    dest = clone_and_checkout_nexus(
        dest=dest,
        commit_or_branch=resolved,
        zkvm_src=args.zkvm_src,
    )

    print("Applying Pass 1/3 (infrastructure)...")
    pass1_infrastructure.apply(nexus_install_path=dest, commit_or_branch=resolved)

    print("Applying Pass 2/3 (bypass checks)...")
    pass2_bypass_checks.apply(nexus_install_path=dest, commit_or_branch=resolved)

    print("Applying Pass 3/3 (collection)...")
    pass3_collection.apply(nexus_install_path=dest, commit_or_branch=resolved)

    print("Nexus snapshot staged for beak.")
    print(dest)
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
