from pathlib import Path

from zkvm_fuzzer_utils.file import prepend_file, replace_in_file


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _vm_replace_asserts_and_add_fuzzer_utils_dep(openvm_install_path=openvm_install_path)


def _vm_replace_asserts_and_add_fuzzer_utils_dep(*, openvm_install_path: Path) -> None:
    # recursively remove asserts in the whole vm folder, and ensure fuzzer_utils dependency.
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
                if is_updated:
                    prefix = "#[allow(unused_imports)]\nuse fuzzer_utils;\n"
                    if not elem.read_text().startswith(prefix):
                        prepend_file(elem, prefix)

