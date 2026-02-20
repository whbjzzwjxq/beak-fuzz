from pathlib import Path

from zkvm_fuzzer_utils.file import create_file


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _create_fuzzer_utils_crate(openvm_install_path=openvm_install_path)


_TEMPLATE_DIR = Path(__file__).resolve().parent / "fuzzer_utils_crate"


def _read_template(filename: str) -> str:
    return (_TEMPLATE_DIR / filename).read_text()


def _create_fuzzer_utils_crate(*, openvm_install_path: Path) -> None:
    create_file(
        openvm_install_path / "crates" / "fuzzer_utils" / "Cargo.toml",
        _read_template("Cargo.toml"),
    )
    create_file(
        openvm_install_path / "crates" / "fuzzer_utils" / "src" / "lib.rs",
        _read_template("lib.rs"),
    )

