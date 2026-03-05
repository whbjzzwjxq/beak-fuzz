from __future__ import annotations

from pathlib import Path

from zkvm_fuzzer_utils.file import create_file

_FUZZER_UTILS_TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "fuzzer_utils_crate"


def _read_fuzzer_utils_template(filename: str) -> str:
    return (_FUZZER_UTILS_TEMPLATE_DIR / filename).read_text()


def _create_fuzzer_utils_crate(*, sp1_install_path: Path) -> None:
    create_file(
        sp1_install_path / "crates" / "fuzzer_utils" / "Cargo.toml",
        _read_fuzzer_utils_template("Cargo.toml"),
    )
    create_file(
        sp1_install_path / "crates" / "fuzzer_utils" / "src" / "lib.rs",
        _read_fuzzer_utils_template("lib.rs"),
    )


def _patch_workspace_manifest(*, sp1_install_path: Path) -> None:
    root_cargo = sp1_install_path / "Cargo.toml"
    if not root_cargo.exists():
        return

    contents = root_cargo.read_text()

    if '"crates/fuzzer_utils"' not in contents and "members = [" in contents:
        contents = contents.replace(
            "members = [",
            'members = [\n  "crates/fuzzer_utils",',
            1,
        )

    if 'fuzzer_utils = { path = "crates/fuzzer_utils" }' not in contents:
        marker = "[workspace.dependencies]"
        if marker in contents:
            contents = contents.replace(
                marker,
                marker + '\nfuzzer_utils = { path = "crates/fuzzer_utils" }',
                1,
            )
        else:
            contents = contents.rstrip() + '\n\n[workspace.dependencies]\nfuzzer_utils = { path = "crates/fuzzer_utils" }\n'

    root_cargo.write_text(contents)


def _patch_core_dependency(*, sp1_install_path: Path) -> None:
    core_candidates = [
        (sp1_install_path / "core" / "Cargo.toml", "../crates/fuzzer_utils"),
        (sp1_install_path / "crates" / "core" / "Cargo.toml", "../fuzzer_utils"),
    ]

    for core_cargo, rel_path in core_candidates:
        if not core_cargo.exists():
            continue
        contents = core_cargo.read_text()
        if "fuzzer_utils" in contents:
            continue
        marker = "[dependencies]"
        if marker not in contents:
            continue
        contents = contents.replace(
            marker,
            marker + f'\nfuzzer_utils = {{ path = "{rel_path}" }}',
            1,
        )
        core_cargo.write_text(contents)


def apply(*, sp1_install_path: Path, commit_or_branch: str) -> None:
    _ = commit_or_branch
    _create_fuzzer_utils_crate(sp1_install_path=sp1_install_path)
    _patch_workspace_manifest(sp1_install_path=sp1_install_path)
    _patch_core_dependency(sp1_install_path=sp1_install_path)
