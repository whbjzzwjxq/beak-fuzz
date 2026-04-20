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
from sp1_fuzzer.utils_install import clone_and_checkout_sp1
from zkvm_fuzzer_utils.snapshot_install import (
    apply_pass_pipeline,
    default_snapshot_out_root,
    maybe_warn_on_nondefault_out_root,
    resolve_snapshot_out_root,
)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="sp1-fuzzer", description="SP1 installer entrypoint.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser(
        "install",
        help="Materialize SP1 snapshot into the repo-local beak-py/out/ by default.",
    )
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
        default=None,
        help=f"Output root (default: {default_snapshot_out_root()}).",
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    resolved = resolve_sp1_commit(args.commit_or_branch)
    out_root = resolve_snapshot_out_root(args.out_root)
    if args.out_root is not None:
        maybe_warn_on_nondefault_out_root(out_root)
    dest = (out_root / f"sp1-{resolved}" / "sp1-src").expanduser().resolve()
    clone_and_checkout_sp1(dest=dest, commit_or_branch=resolved)
    apply_pass_pipeline(
        package_name="sp1_fuzzer",
        install_path_kw="sp1_install_path",
        install_path=dest,
        commit_or_branch=resolved,
    )
    print("SP1 snapshot staged for beak.")
    print(dest)
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
