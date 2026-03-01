"""
Pass 1: Infrastructure / Dependencies

Purpose
-------
Keep parity with the OpenVM three-pass pipeline shape.
Pico currently has no extra infra patching in beak-py, so this is a no-op.
"""

from __future__ import annotations

from pathlib import Path


def apply(*, pico_install_path: Path, commit_or_branch: str) -> None:
    # Reserved for future Pico infra/dependency patches.
    _ = (pico_install_path, commit_or_branch)

