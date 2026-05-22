#!/usr/bin/env python3

import argparse
from pathlib import Path

from pico_fuzzer.settings import (
    PICO_AVAILABLE_COMMITS_OR_BRANCHES,
    PICO_LATEST_22B0_COMMIT,
    resolve_pico_commit,
)
from pico_fuzzer.utils_install import clone_and_checkout_pico
from zkvm_fuzzer_utils.snapshot_install import (
    apply_pass_pipeline,
    default_snapshot_out_root,
    maybe_warn_on_nondefault_out_root,
    resolve_snapshot_out_root,
)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pico-fuzzer", description="Pico installer entrypoint.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser(
        "install",
        help="Materialize Pico snapshot into the repo-local beak-py/out/ by default.",
    )
    install.add_argument(
        "--commit-or-branch",
        type=str,
        default=PICO_LATEST_22B0_COMMIT,
        choices=PICO_AVAILABLE_COMMITS_OR_BRANCHES,
        help="Pico commit/alias to install.",
    )
    install.add_argument(
        "--out-root",
        type=Path,
        default=None,
        help=f"Output root (default: {default_snapshot_out_root()}).",
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    resolved = resolve_pico_commit(args.commit_or_branch)
    out_root = resolve_snapshot_out_root(args.out_root)
    if args.out_root is not None:
        maybe_warn_on_nondefault_out_root(out_root)
    dest = (out_root / f"pico-{resolved}" / "pico-src").expanduser().resolve()
    clone_and_checkout_pico(dest=dest, commit_or_branch=resolved)
    apply_pass_pipeline(
        package_name="pico_fuzzer",
        install_path_kw="pico_install_path",
        install_path=dest,
        commit_or_branch=resolved,
    )
    print("Pico snapshot staged for beak.")
    print(dest)
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
