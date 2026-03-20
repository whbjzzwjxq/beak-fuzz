from __future__ import annotations

from pathlib import Path

from zkvm_fuzzer_utils.file import prepend_file

_PLONKY3_REV = "db3d45d4ec899efaf8f7234a8573f285fbdda5db"


def _cpu_trace_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [sp1_install_path / "crates" / "core" / "machine" / "src" / "cpu" / "trace.rs"]:
        if path.exists():
            out.append(path)
    return out


def _patch_cpu_trace(path: Path) -> None:
    contents = path.read_text()

    if "use fuzzer_utils;" not in contents:
        prepend_file(path, "#[allow(unused_imports)]\nuse fuzzer_utils;\n")
        contents = path.read_text()

    guard = "// BEAK-INSERT: sp1.v4.is_memory_underconstrained"
    if guard in contents:
        return

    anchor = """        cols.is_memory = F::from_bool(
            instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction(),
        );"""
    insert = """
        // BEAK-INSERT: sp1.v4.is_memory_underconstrained
        let beak_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness(
            "sp1.audit_v4.is_memory_instruction_interaction",
            beak_step,
        ) {
            cols.is_memory = F::zero();
        }
        // BEAK-INSERT-END
"""
    if anchor not in contents:
        return

    path.write_text(contents.replace(anchor, anchor + insert, 1))


def _patch_plonky3_pin(sp1_install_path: Path) -> None:
    cargo_toml = sp1_install_path / "Cargo.toml"
    if not cargo_toml.exists():
        return

    contents = cargo_toml.read_text()
    updated = contents.replace(
        'git = "https://github.com/Plonky3/Plonky3", branch = "sp1-v4"',
        f'git = "https://github.com/Plonky3/Plonky3", rev = "{_PLONKY3_REV}"',
    )
    if updated != contents:
        cargo_toml.write_text(updated)


def apply(*, sp1_install_path: Path, commit_or_branch: str) -> None:
    _ = commit_or_branch
    _patch_plonky3_pin(sp1_install_path)
    for path in _cpu_trace_candidates(sp1_install_path):
        _patch_cpu_trace(path)
