from __future__ import annotations

from pathlib import Path

from zkvm_fuzzer_utils.file import prepend_file, replace_in_file


def _runtime_files(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for p in [
        sp1_install_path / "core" / "src" / "runtime" / "mod.rs",
        sp1_install_path / "core" / "src" / "runtime" / "utils.rs",
        sp1_install_path / "crates" / "core" / "src" / "runtime" / "mod.rs",
        sp1_install_path / "crates" / "core" / "src" / "runtime" / "utils.rs",
    ]:
        if p.exists():
            out.append(p)
    return out


def _patch_runtime_asserts(*, sp1_install_path: Path) -> None:
    for path in _runtime_files(sp1_install_path):
        updated = replace_in_file(
            path,
            [
                (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                (r"\bassert_ne!", "fuzzer_utils::fuzzer_assert_ne!"),
                (r"\bdebug_assert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                (r"\bdebug_assert_ne!", "fuzzer_utils::fuzzer_assert_ne!"),
                (r"\bdebug_assert!", "fuzzer_utils::fuzzer_assert!"),
                (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
            ],
        )
        if updated:
            prefix = "#[allow(unused_imports)]\nuse fuzzer_utils;\n"
            if "use fuzzer_utils;" not in path.read_text():
                prepend_file(path, prefix)


def apply(*, sp1_install_path: Path, commit_or_branch: str) -> None:
    _ = commit_or_branch
    _patch_runtime_asserts(sp1_install_path=sp1_install_path)
