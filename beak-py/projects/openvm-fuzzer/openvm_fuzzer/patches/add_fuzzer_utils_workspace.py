from pathlib import Path

from zkvm_fuzzer_utils.file import replace_in_file


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _add_fuzzer_utils_to_workspace(openvm_install_path=openvm_install_path)


def _add_fuzzer_utils_to_workspace(*, openvm_install_path: Path) -> None:
    # add fuzzer utils to root Cargo.toml using RELATIVE paths
    # This allows the project to be built both on host and inside Docker
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
    if "fuzzer_utils = { path = \"crates/fuzzer_utils\" }" not in root_contents:
        replace_in_file(
            root_cargo,
            [
                (
                    r"\[workspace\.dependencies\]",
                    "[workspace.dependencies]\nfuzzer_utils = { path = \"crates/fuzzer_utils\" }",
                )
            ],
        )

