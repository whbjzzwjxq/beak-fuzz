"""
Pass 2: Bypass / Replace Checks (for fuzzing)

Purpose
-------
Make the snapshot fuzz-friendly by:
- rewriting assertions to fuzzer_utils macros so the run can continue and record context

Timing
------
- execute / tracegen_fill: affects runtime behavior and trace generation code paths

Targets
-------
- <openvm>/crates/vm/** (recursive)
- <openvm>/extensions/rv32im/circuit/src/** (recursive)

Commit-dependent behavior
-------------------------
None (these are structural patches applied uniformly when files exist).
"""

from __future__ import annotations

import re
from pathlib import Path

from zkvm_fuzzer_utils.file import prepend_file, replace_in_file


_FUZZER_UTILS_IMPORT = "#[allow(unused_imports)]\nuse fuzzer_utils;\n"


def _normalize_fuzzer_utils_import(path: Path) -> None:
    """Keep the pass idempotent even when an older install placed the import later."""
    contents = path.read_text()
    import_pattern = re.compile(
        r"(?:#\[allow\(unused_imports\)\]\n)?use fuzzer_utils;\n\n?"
    )
    if not import_pattern.search(contents):
        prepend_file(path, _FUZZER_UTILS_IMPORT)
        return
    normalized = import_pattern.sub("", contents).lstrip("\n")
    path.write_text(f"{_FUZZER_UTILS_IMPORT}\n{normalized}")


# --- vm_replace_asserts.py (merged) ---


def _vm_replace_asserts_and_add_fuzzer_utils_dep(*, openvm_install_path: Path) -> None:
    # Recursively remove asserts in the whole vm folder, and ensure fuzzer_utils dependency.
    working_dirs = [openvm_install_path / "crates" / "vm"]
    while len(working_dirs) > 0:
        working_dir = working_dirs.pop()
        if not working_dir.exists():
            continue
        for elem in working_dir.iterdir():
            if elem.is_dir():
                working_dirs.append(elem)
            if elem.is_file() and elem.name == "Cargo.toml":
                contents = elem.read_text()
                if "fuzzer_utils.workspace = true" not in contents:
                    replace_in_file(
                        elem,
                        [(r"\[dependencies\]", "[dependencies]\nfuzzer_utils.workspace = true")],
                    )
            if elem.is_file() and elem.suffix == ".rs":
                # NOTE: the order matters here because the replacement is done iteratively
                is_updated = replace_in_file(
                    elem,
                    [
                        (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                        (r"\bassert_ne!", "fuzzer_utils::fuzzer_assert_ne!"),
                        (r"\bdebug_assert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bdebug_assert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                    ],
                )
                if is_updated or "use fuzzer_utils;" in elem.read_text():
                    _normalize_fuzzer_utils_import(elem)


# --- rv32im_replace_asserts.py (merged) ---


def _rv32im_replace_asserts(*, openvm_install_path: Path) -> None:
    # Recursively remove asserts in the whole rv32im circuit folder
    working_dirs = [openvm_install_path / "extensions" / "rv32im" / "circuit" / "src"]
    while len(working_dirs) > 0:
        working_dir = working_dirs.pop()
        if not working_dir.exists():
            continue
        for elem in working_dir.iterdir():
            if elem.is_dir():
                working_dirs.append(elem)
            if elem.is_file() and elem.suffix == ".rs":
                # NOTE: the order matters here because the replacement is done iteratively
                is_updated = replace_in_file(
                    elem,
                    [
                        (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                        (r"\bdebug_assert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bdebug_assert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                    ],
                )
                if is_updated or "use fuzzer_utils;" in elem.read_text():
                    _normalize_fuzzer_utils_import(elem)


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _vm_replace_asserts_and_add_fuzzer_utils_dep(openvm_install_path=openvm_install_path)
    _rv32im_replace_asserts(openvm_install_path=openvm_install_path)
