"""
Compatibility wrapper for legacy imports.

New code should import from `pico_fuzzer.passes.pass3_collection`.
"""

from __future__ import annotations

from pathlib import Path

from pico_fuzzer.passes import pass3_collection


def apply_beak_pico_injection_patches(zkvm_src: Path, resolved_commit: str) -> None:
    pass3_collection.apply(pico_install_path=zkvm_src, commit_or_branch=resolved_commit)
