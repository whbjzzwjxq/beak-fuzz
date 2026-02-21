"""
Three-pass OpenVM patch pipeline.

This package groups all OpenVM modifications into three conceptual passes:
1) Infrastructure / dependencies
2) Bypass / assert rewriting for fuzzing
3) Trace + micro-op collection instrumentation

Each pass module exposes:
  apply(*, openvm_install_path: Path, commit_or_branch: str) -> None
"""

