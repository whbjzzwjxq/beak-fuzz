"""
Pass 1: Infrastructure / Dependencies

Purpose
-------
Set up the OpenVM workspace so later passes can compile and emit JSON traces.

Timing
------
- workspace_config: edits Cargo workspace manifests / adds local crates

Targets
-------
- <openvm>/Cargo.toml
- <openvm>/crates/vm/Cargo.toml
- <openvm>/extensions/rv32im/circuit/Cargo.toml
- <openvm>/crates/fuzzer_utils/{Cargo.toml,src/lib.rs}

Commit-dependent behavior
-------------------------
- `rewrite_private_stark` chooses a tag based on snapshot commit (regzero/336f/f038),
  or falls back to heuristics on the Plonky3 rev in Cargo.toml.
"""

from __future__ import annotations

import re
from pathlib import Path

from openvm_fuzzer.settings import (
    OPENVM_BENCHMARK_336F_COMMIT,
    OPENVM_BENCHMARK_F038_COMMIT,
    OPENVM_BENCHMARK_REGZERO_COMMIT,
    resolve_openvm_commit,
)
from zkvm_fuzzer_utils.file import create_file, replace_in_file

# --- rewrite_private_stark.py (merged) ---

_PLONKY3_TAG_BY_REV = {
    "539bbc84085efb609f4f62cb03cf49588388abdb": "v1.2.0-rc.0",
    "b0591e9": "v1.0.0-rc.0",
    "88d7f05": "v1.0.0-rc.2",
}

_STARK_BACKEND_TAG_BY_COMMIT = {
    OPENVM_BENCHMARK_REGZERO_COMMIT: "v1.2.0-rc.0",
    OPENVM_BENCHMARK_336F_COMMIT: "v1.0.0-rc.0",
    OPENVM_BENCHMARK_F038_COMMIT: "v1.0.0-rc.2",
}


def _resolve_stark_backend_tag(contents: str, commit_or_branch: str) -> str:
    resolved_commit = resolve_openvm_commit(commit_or_branch)
    if resolved_commit in _STARK_BACKEND_TAG_BY_COMMIT:
        return _STARK_BACKEND_TAG_BY_COMMIT[resolved_commit]

    match = re.search(r'Plonky3\\.git", rev = "([0-9a-f]+)"', contents)
    if match:
        plonky3_rev = match.group(1)
        if plonky3_rev in _PLONKY3_TAG_BY_REV:
            return _PLONKY3_TAG_BY_REV[plonky3_rev]

    return "v1.0.0-rc.2"


def _rewrite_private_stark_backend(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    cargo_toml = openvm_install_path / "Cargo.toml"
    if not cargo_toml.exists():
        return
    contents = cargo_toml.read_text()
    if "stark-backend-private" not in contents:
        return
    tag = _resolve_stark_backend_tag(contents, commit_or_branch)
    contents = contents.replace(
        "ssh://git@github.com/axiom-crypto/stark-backend-private.git",
        "https://github.com/openvm-org/stark-backend.git",
    )
    contents = re.sub(
        r"(openvm-stark-(?:backend|sdk) = \\{[^\\n]*?)(?:rev|tag) = \"[^\"]+\"",
        rf'\\1tag = "{tag}"',
        contents,
    )
    cargo_toml.write_text(contents)


# --- create_fuzzer_utils_crate.py (merged) ---

# NOTE: Templates live in-package so installs don't depend on external paths.
_FUZZER_UTILS_TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "fuzzer_utils_crate"


def _read_fuzzer_utils_template(filename: str) -> str:
    return (_FUZZER_UTILS_TEMPLATE_DIR / filename).read_text()


def _create_fuzzer_utils_crate(*, openvm_install_path: Path) -> None:
    create_file(
        openvm_install_path / "crates" / "fuzzer_utils" / "Cargo.toml",
        _read_fuzzer_utils_template("Cargo.toml"),
    )
    create_file(
        openvm_install_path / "crates" / "fuzzer_utils" / "src" / "lib.rs",
        _read_fuzzer_utils_template("lib.rs"),
    )


# --- add_fuzzer_utils_workspace.py (merged) ---


def _add_fuzzer_utils_to_workspace(*, openvm_install_path: Path) -> None:
    # Add fuzzer_utils to root Cargo.toml using RELATIVE paths.
    # This allows the project to be built both on host and inside Docker.
    root_cargo = openvm_install_path / "Cargo.toml"
    if not root_cargo.exists():
        return
    root_contents = root_cargo.read_text()
    if '"crates/fuzzer_utils"' not in root_contents:
        replace_in_file(
            root_cargo,
            [(r"members = \[", 'members = [\n    "crates/fuzzer_utils",')],
        )
    root_contents = root_cargo.read_text()
    if 'fuzzer_utils = { path = "crates/fuzzer_utils" }' not in root_contents:
        replace_in_file(
            root_cargo,
            [
                (
                    r"\[workspace\.dependencies\]",
                    '[workspace.dependencies]\nfuzzer_utils = { path = "crates/fuzzer_utils" }',
                )
            ],
        )


# --- vm_add_serde_json.py (merged) ---


def _vm_add_serde_json_dep(*, openvm_install_path: Path) -> None:
    # Ensure OpenVM circuit crate can serialize per-instruction records.
    # (serde_json is provided in the OpenVM workspace dependencies.)
    vm_cargo_toml = openvm_install_path / "crates" / "vm" / "Cargo.toml"
    if not vm_cargo_toml.exists():
        return
    vm_contents = vm_cargo_toml.read_text()
    if "serde_json.workspace = true" in vm_contents:
        return
    replace_in_file(
        vm_cargo_toml,
        [
            (
                r"\[dependencies\]",
                "[dependencies]\nserde_json.workspace = true",
            )
        ],
    )


# --- rv32im_circuit_add_deps.py (merged) ---


def _rv32im_circuit_add_deps(*, openvm_install_path: Path) -> None:
    rv32im_cargo = openvm_install_path / "extensions" / "rv32im" / "circuit" / "Cargo.toml"
    if not rv32im_cargo.exists():
        return
    rv32im_contents = rv32im_cargo.read_text()
    if "fuzzer_utils.workspace = true" not in rv32im_contents:
        replace_in_file(
            rv32im_cargo,
            [(r"\[dependencies\]", "[dependencies]\nfuzzer_utils.workspace = true")],
        )
    rv32im_contents = rv32im_cargo.read_text()
    if "serde_json.workspace = true" not in rv32im_contents:
        replace_in_file(
            rv32im_cargo,
            [(r"\[dependencies\]", "[dependencies]\nserde_json.workspace = true")],
        )


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _rewrite_private_stark_backend(
        openvm_install_path=openvm_install_path,
        commit_or_branch=commit_or_branch,
    )
    _create_fuzzer_utils_crate(openvm_install_path=openvm_install_path)
    _add_fuzzer_utils_to_workspace(openvm_install_path=openvm_install_path)
    _vm_add_serde_json_dep(openvm_install_path=openvm_install_path)
    _rv32im_circuit_add_deps(openvm_install_path=openvm_install_path)

