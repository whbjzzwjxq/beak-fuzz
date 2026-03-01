"""
Three-pass Pico patch pipeline.

This package groups Pico modifications into three conceptual passes:
1) Infrastructure / dependencies
2) Bypass / assert rewriting for fuzzing
3) Trace + witness-collection instrumentation

Each pass module exposes:
  apply(*, pico_install_path: Path, commit_or_branch: str) -> None
"""

