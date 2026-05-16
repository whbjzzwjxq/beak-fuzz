#!/usr/bin/env python3

import argparse
from pathlib import Path

from jolt_fuzzer.settings import JOLT_BENCHMARK_COMMIT, resolve_jolt_commit
from jolt_fuzzer.utils_install import (
    clone_and_checkout_jolt,
    clone_and_checkout_jolt_auxiliary_sources,
)
from zkvm_fuzzer_utils.snapshot_install import (
    apply_pass_pipeline,
    default_snapshot_out_root,
    maybe_warn_on_nondefault_out_root,
    resolve_snapshot_out_root,
)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="jolt-fuzzer", description="Jolt installer entrypoint.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser(
        "install",
        help="Materialize Jolt snapshot into the repo-local beak-py/out/ by default.",
    )
    install.add_argument(
        "--commit-or-branch",
        type=str,
        default=JOLT_BENCHMARK_COMMIT,
        help="Jolt commit/alias/branch to install.",
    )
    install.add_argument(
        "--out-root",
        type=Path,
        default=None,
        help=f"Output root (default: {default_snapshot_out_root()}).",
    )
    install.add_argument(
        "--zkvm-src",
        type=Path,
        default=None,
        help="Optional local Jolt repository to clone from instead of GitHub.",
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    resolved = resolve_jolt_commit(args.commit_or_branch)
    out_root = resolve_snapshot_out_root(args.out_root)
    if args.out_root is not None:
        maybe_warn_on_nondefault_out_root(out_root)
    dest = (out_root / f"jolt-{resolved}" / "jolt-src").expanduser().resolve()
    clone_and_checkout_jolt(
        dest=dest,
        commit_or_branch=resolved,
        zkvm_src=args.zkvm_src,
    )
    clone_and_checkout_jolt_auxiliary_sources(
        jolt_install_path=dest,
        commit_or_branch=resolved,
    )
    apply_pass_pipeline(
        package_name="jolt_fuzzer",
        install_path_kw="jolt_install_path",
        install_path=dest,
        commit_or_branch=resolved,
    )
    print("Jolt snapshot staged for beak.")
    print(dest)
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
