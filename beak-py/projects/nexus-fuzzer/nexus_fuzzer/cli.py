#!/usr/bin/env python3

import argparse
from pathlib import Path

from nexus_fuzzer.settings import NEXUS_BENCHMARK_COMMIT, resolve_nexus_commit
from nexus_fuzzer.utils_install import (
    clone_and_checkout_nexus,
    clone_and_checkout_nexus_auxiliary_sources,
)
from zkvm_fuzzer_utils.snapshot_install import (
    apply_pass_pipeline,
    default_snapshot_out_root,
    maybe_warn_on_nondefault_out_root,
    resolve_snapshot_out_root,
)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="nexus-fuzzer", description="Nexus installer entrypoint.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser(
        "install",
        help="Materialize Nexus snapshot into the repo-local beak-py/out/ by default.",
    )
    install.add_argument(
        "--commit-or-branch",
        type=str,
        default=NEXUS_BENCHMARK_COMMIT,
        help="Nexus commit/alias/branch to install.",
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
        help="Optional local Nexus repository to clone from instead of GitHub.",
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    resolved = resolve_nexus_commit(args.commit_or_branch)
    out_root = resolve_snapshot_out_root(args.out_root)
    if args.out_root is not None:
        maybe_warn_on_nondefault_out_root(out_root)
    dest = (out_root / f"nexus-{resolved}" / "nexus-src").expanduser().resolve()
    clone_and_checkout_nexus(
        dest=dest,
        commit_or_branch=resolved,
        zkvm_src=args.zkvm_src,
    )
    clone_and_checkout_nexus_auxiliary_sources(
        nexus_install_path=dest,
        commit_or_branch=resolved,
    )
    apply_pass_pipeline(
        package_name="nexus_fuzzer",
        install_path_kw="nexus_install_path",
        install_path=dest,
        commit_or_branch=resolved,
    )
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
