"""
Remove transpiler-level x0 NOP-guard protections.

The RISC-V transpiler in OpenVM silently replaces instructions with rd==x0 with NOPs.
This hides the fact that the *circuit* itself does not enforce x0 hardwired-zero in
several adapters (AUIPC, ALU, LUI, Shift).

This patch removes only the NOP-guard replacements (if rd==0 { return nop(); }) so that
rd=0 instructions are faithfully translated. Flag-based protections for JAL, JALR, and
LOAD are intentionally preserved because:
  - JAL: `j offset` = `jal x0, offset` is the standard unconditional jump used
    pervasively in compiler output.  Changing its flag corrupts x0 on every jump
    and causes the VM executor to diverge into an infinite loop.
  - JALR/LOAD: these circuits already have independent x0 protection at the
    constraint level, so the flag change is unnecessary.

Modified files
--------------
* crates/toolchain/transpiler/src/util.rs
    - from_r_type:       remove NOP guard on rd==0
    - from_i_type:       remove NOP guard on rd==0
    - from_i_type_shamt: remove NOP guard on rd==0
    - from_u_type:       remove NOP guard on rd==0

* extensions/rv32im/transpiler/src/rrs.rs
    - process_lui:   remove NOP guard on rd==0
    - process_auipc: remove NOP guard on rd==0
"""

from pathlib import Path


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _patch_util_rs(openvm_install_path)
    _patch_rrs_rs(openvm_install_path)


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
    filepath = (
        openvm_install_path / "extensions" / "rv32im" / "transpiler" / "src" / "rrs.rs"
    )
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
