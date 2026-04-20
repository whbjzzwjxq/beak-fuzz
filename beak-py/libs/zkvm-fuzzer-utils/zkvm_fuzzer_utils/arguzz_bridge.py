from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def beak_fuzz_root() -> Path:
    return Path(__file__).resolve().parents[4]


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


def _default_arguzz_root() -> Path:
    return Path(__file__).resolve().parents[5] / "arguzz"


def find_arguzz_binary(binary_name: str) -> Path:
    if env_root := os.environ.get("ARGUZZ_ROOT"):
        arguzz_root = Path(env_root).expanduser().resolve()
    else:
        arguzz_root = _default_arguzz_root()

    candidates = [
        arguzz_root / ".conda" / "bin" / binary_name,
        arguzz_root / ".venv" / "bin" / binary_name,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    if path := shutil.which(binary_name):
        return Path(path)

    raise FileNotFoundError(
        f"Unable to find arguzz binary '{binary_name}'. Checked: "
        + ", ".join(str(path) for path in candidates)
    )


def run_arguzz_install(binary_name: str, *, dest: Path, commit_or_branch: str) -> None:
    binary = find_arguzz_binary(binary_name)
    command = [
        str(binary),
        "install",
        str(dest),
        "--commit-or-branch",
        commit_or_branch,
        "--zkvm-modification",
    ]
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.setdefault("ARGUZZ_REPO_CACHE", "/tmp/zkvm-repos")
    subprocess.run(command, check=True, env=env)
