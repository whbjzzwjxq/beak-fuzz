#!/usr/bin/env python3

import argparse
from pathlib import Path

from sp1_fuzzer.settings import (
    SP1_AVAILABLE_COMMITS_OR_BRANCHES,
    SP1_AUDIT_V4_39AB_COMMIT,
    SP1_RECURSION_KALOS_FB38_COMMIT,
    SP1_UINT256_DIV_3561_COMMIT,
    resolve_sp1_commit,
)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="sp1-fuzzer", description="SP1 installer entrypoint.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize SP1 snapshot into out/.")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        default=SP1_AUDIT_V4_39AB_COMMIT,
        choices=SP1_AVAILABLE_COMMITS_OR_BRANCHES,
        help="SP1 commit/alias to install.",
    )
    install.add_argument(
        "--out-root",
        type=Path,
        default=Path("out"),
        help="Output root (default: ./out).",
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    from sp1_fuzzer.utils_install import clone_and_checkout_sp1
    from sp1_fuzzer.passes import (
        pass1_infrastructure,
        pass2_bypass_checks,
        pass3_collection,
        pass4_v4_is_memory,
        pass5_legacy_recursion,
        pass6_uint256_div,
    )

    resolved = resolve_sp1_commit(args.commit_or_branch)
    dest = (args.out_root / f"sp1-{resolved}" / "sp1-src").expanduser().resolve()
    dest = clone_and_checkout_sp1(dest=dest, commit_or_branch=resolved)

    print("Applying Pass 1/3 (infrastructure)...")
    pass1_infrastructure.apply(sp1_install_path=dest, commit_or_branch=resolved)

    print("Applying Pass 2/3 (bypass checks)...")
    pass2_bypass_checks.apply(sp1_install_path=dest, commit_or_branch=resolved)

    print("Applying Pass 3/3 (collection)...")
    pass3_collection.apply(sp1_install_path=dest, commit_or_branch=resolved)

    print("Applying Pass 4/4 (v4 is_memory hook)...")
    pass4_v4_is_memory.apply(sp1_install_path=dest, commit_or_branch=resolved)

    if resolved == SP1_RECURSION_KALOS_FB38_COMMIT:
        print("Applying Legacy Recursion pass...")
        pass5_legacy_recursion.apply(sp1_install_path=dest, commit_or_branch=resolved)
    if resolved == SP1_UINT256_DIV_3561_COMMIT:
        print("Applying uint256 div pass...")
        pass6_uint256_div.apply(sp1_install_path=dest, commit_or_branch=resolved)

    print("SP1 snapshot patched for witness injection and collection.")
    print(dest)
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
