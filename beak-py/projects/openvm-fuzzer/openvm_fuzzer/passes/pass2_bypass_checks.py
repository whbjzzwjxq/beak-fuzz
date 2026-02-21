"""
Pass 2: Bypass / Replace Checks (for fuzzing)

Purpose
-------
Make the snapshot fuzz-friendly by:
- removing transpiler protections that hide soundness issues (rd==x0 -> NOP)
- rewriting assertions to fuzzer_utils macros so the run can continue and record context

Timing
------
- transpiler: affects RISC-V -> OpenVM instruction translation
- execute / tracegen_fill: affects runtime behavior and trace generation code paths

Targets
-------
- <openvm>/crates/toolchain/transpiler/src/util.rs
- <openvm>/extensions/rv32im/transpiler/src/rrs.rs
- <openvm>/crates/vm/** (recursive)
- <openvm>/extensions/rv32im/circuit/src/** (recursive)

Commit-dependent behavior
-------------------------
None (these are structural patches applied uniformly when files exist).
"""

from __future__ import annotations

from pathlib import Path

from zkvm_fuzzer_utils.file import prepend_file, replace_in_file


# --- transpiler_remove_protection.py (merged) ---


def _patch_util_rs(openvm_install_path: Path) -> None:
    filepath = openvm_install_path / "crates" / "toolchain" / "transpiler" / "src" / "util.rs"
    content = filepath.read_text()

    # 1. from_r_type: remove the NOP guard block (including the comment)
    content = content.replace(
        "    // If `rd` is not allowed to be zero, we transpile to `NOP` to prevent a write\n"
        "    // to `x0`. In the cases where `allow_rd_zero` is true, it is the responsibility of\n"
        "    // the caller to guarantee that the resulting instruction does not write to `rd`.\n"
        "    if !allow_rd_zero && dec_insn.rd == 0 {\n"
        "        return nop();\n"
        "    }\n",
        "",
    )

    # 2. from_i_type: remove the NOP guard
    content = content.replace(
        "pub fn from_i_type<F: PrimeField32>(opcode: usize, dec_insn: &IType) -> Instruction<F> {\n"
        "    if dec_insn.rd == 0 {\n"
        "        return nop();\n"
        "    }\n",
        "pub fn from_i_type<F: PrimeField32>(opcode: usize, dec_insn: &IType) -> Instruction<F> {\n",
    )

    # 3. from_i_type_shamt: remove the NOP guard
    content = content.replace(
        "pub fn from_i_type_shamt<F: PrimeField32>(opcode: usize, dec_insn: &ITypeShamt) -> Instruction<F> {\n"
        "    if dec_insn.rd == 0 {\n"
        "        return nop();\n"
        "    }\n",
        "pub fn from_i_type_shamt<F: PrimeField32>(opcode: usize, dec_insn: &ITypeShamt) -> Instruction<F> {\n",
    )

    # 4. from_u_type: remove the NOP guard
    content = content.replace(
        "pub fn from_u_type<F: PrimeField32>(opcode: usize, dec_insn: &UType) -> Instruction<F> {\n"
        "    if dec_insn.rd == 0 {\n"
        "        return nop();\n"
        "    }\n",
        "pub fn from_u_type<F: PrimeField32>(opcode: usize, dec_insn: &UType) -> Instruction<F> {\n",
    )

    filepath.write_text(content)


def _patch_rrs_rs(openvm_install_path: Path) -> None:
    filepath = openvm_install_path / "extensions" / "rv32im" / "transpiler" / "src" / "rrs.rs"
    content = filepath.read_text()

    # 1. process_lui: remove the NOP guard
    content = content.replace(
        "    fn process_lui(&mut self, dec_insn: UType) -> Self::InstructionResult {\n"
        "        if dec_insn.rd == 0 {\n"
        "            return nop();\n"
        "        }\n",
        "    fn process_lui(&mut self, dec_insn: UType) -> Self::InstructionResult {\n",
    )

    # 2. process_auipc: remove the NOP guard
    content = content.replace(
        "    fn process_auipc(&mut self, dec_insn: UType) -> Self::InstructionResult {\n"
        "        if dec_insn.rd == 0 {\n"
        "            return nop();\n"
        "        }\n",
        "    fn process_auipc(&mut self, dec_insn: UType) -> Self::InstructionResult {\n",
    )

    filepath.write_text(content)


def _transpiler_remove_protection(openvm_install_path: Path) -> None:
    _patch_util_rs(openvm_install_path)
    _patch_rrs_rs(openvm_install_path)


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
                if is_updated:
                    prefix = "#[allow(unused_imports)]\nuse fuzzer_utils;\n"
                    if not elem.read_text().startswith(prefix):
                        prepend_file(elem, prefix)


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
                if is_updated:
                    prefix = "#[allow(unused_imports)]\nuse fuzzer_utils;\n"
                    if not elem.read_text().startswith(prefix):
                        prepend_file(elem, prefix)


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _transpiler_remove_protection(openvm_install_path)
    _vm_replace_asserts_and_add_fuzzer_utils_dep(openvm_install_path=openvm_install_path)
    _rv32im_replace_asserts(openvm_install_path=openvm_install_path)

