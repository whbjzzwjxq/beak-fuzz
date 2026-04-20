from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path


def beak_py_root() -> Path:
    return Path(__file__).resolve().parents[3]


def default_snapshot_out_root() -> Path:
    return (beak_py_root() / "out").resolve()


def resolve_snapshot_out_root(out_root: Path | None) -> Path:
    if out_root is None:
        return default_snapshot_out_root()
    return out_root.expanduser().resolve()


def maybe_warn_on_nondefault_out_root(out_root: Path) -> None:
    default_root = default_snapshot_out_root()
    if out_root == default_root:
        return
    print(
        "warning: using non-default out root "
        f"{out_root}; commit-pinned Rust projects under beak-fuzz resolve snapshots from "
        f"{default_root}"
    )


def apply_pass_pipeline(
    *,
    package_name: str,
    install_path_kw: str,
    install_path: Path,
    commit_or_branch: str,
) -> None:
    passes_pkg = importlib.import_module(f"{package_name}.passes")
    pass_module_names = sorted(
        name
        for _, name, _ in pkgutil.iter_modules(
            passes_pkg.__path__,
            f"{package_name}.passes.",
        )
        if name.rsplit(".", 1)[-1].startswith("pass")
    )

    kwargs = {
        install_path_kw: install_path,
        "commit_or_branch": commit_or_branch,
    }
    for module_name in pass_module_names:
        module = importlib.import_module(module_name)
        apply = getattr(module, "apply", None)
        if apply is None:
            continue
        apply(**kwargs)
