"""
OpenVM zkVM patch pipeline.

This package contains:
- Step patches: `00_xxx.py`, `01_xxx.py`, ... applied in numeric order.
- Helper modules (non-numeric filenames) imported by step patches.

NOTE: Numeric module names are not importable via normal `import` syntax, so we
load them via importlib from file paths.
"""

from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType


_STEP_RE = re.compile(r"^(?P<idx>\d{2})_(?P<name>[A-Za-z0-9_]+)\.py$")


@dataclass(frozen=True)
class PatchStep:
    idx: int
    name: str
    path: Path


def _load_module_from_path(*, module_name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load patch module: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def iter_patch_steps() -> list[PatchStep]:
    here = Path(__file__).resolve().parent
    steps: list[PatchStep] = []
    for p in here.iterdir():
        if not p.is_file():
            continue
        m = _STEP_RE.match(p.name)
        if not m:
            continue
        steps.append(
            PatchStep(
                idx=int(m.group("idx")),
                name=m.group("name"),
                path=p,
            )
        )
    steps.sort(key=lambda s: s.idx)
    return steps


def apply_all(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    """
    Apply all `NN_xxx.py` patches in numeric order.

    Each step module must define:
      apply(*, openvm_install_path: Path, commit_or_branch: str) -> None
    """
    for step in iter_patch_steps():
        mod = _load_module_from_path(
            module_name=f"openvm_fuzzer.patches.step{step.idx:02d}_{step.name}",
            path=step.path,
        )
        fn = getattr(mod, "apply", None)
        if fn is None:
            raise RuntimeError(f"patch step missing apply(): {step.path}")
        fn(openvm_install_path=openvm_install_path, commit_or_branch=commit_or_branch)

