from pathlib import Path

from openvm_fuzzer.passes.pass2_bypass_checks import apply


def test_pass2_is_idempotent_with_existing_late_fuzzer_utils_import(tmp_path: Path) -> None:
    vm = tmp_path / "crates" / "vm"
    vm_src = vm / "src"
    vm_src.mkdir(parents=True)
    (vm / "Cargo.toml").write_text("[dependencies]\n")
    source = vm_src / "lib.rs"
    source.write_text(
        "use core::fmt;\n"
        "#[allow(unused_imports)]\n"
        "use fuzzer_utils;\n\n"
        "fn check(value: bool) { assert!(value); }\n"
    )

    for _ in range(2):
        apply(openvm_install_path=tmp_path, commit_or_branch="ignored")

    contents = source.read_text()
    assert contents.count("use fuzzer_utils;") == 1
    assert contents.startswith("#[allow(unused_imports)]\nuse fuzzer_utils;\n")
    assert "fuzzer_utils::fuzzer_assert!(value)" in contents
    assert (vm / "Cargo.toml").read_text().count("fuzzer_utils.workspace = true") == 1
