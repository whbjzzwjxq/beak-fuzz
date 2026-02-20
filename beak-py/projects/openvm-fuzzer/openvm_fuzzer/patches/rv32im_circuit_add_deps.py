from pathlib import Path

from zkvm_fuzzer_utils.file import replace_in_file


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _rv32im_circuit_add_deps(openvm_install_path=openvm_install_path)


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

