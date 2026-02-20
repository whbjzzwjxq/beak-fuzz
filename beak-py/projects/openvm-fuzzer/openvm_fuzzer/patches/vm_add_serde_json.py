from pathlib import Path

from zkvm_fuzzer_utils.file import replace_in_file


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _vm_add_serde_json_dep(openvm_install_path=openvm_install_path)


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

