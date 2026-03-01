"""
Pass 2: Bypass / Replace Checks

Purpose
-------
Keep parity with the OpenVM three-pass pipeline shape.
Pico currently keeps bypass/check rewriting inside upstream snapshot behavior,
so this pass is intentionally a no-op for now.
"""

from __future__ import annotations

from pathlib import Path


def apply(*, pico_install_path: Path, commit_or_branch: str) -> None:
    # Reserved for future Pico bypass/check rewriting patches.
    _ = (pico_install_path, commit_or_branch)

