from __future__ import annotations

from pathlib import Path

from sp1_fuzzer.settings import SP1_RECURSION_KALOS_FB38_COMMIT
from zkvm_fuzzer_utils.file import prepend_file

_RUNTIME_PATH = ("recursion", "core", "src", "runtime", "mod.rs")
_PLONKY3_REV = "aef4f8f03f960925f7088d757aeeb956a7f4b30c"


def _insert_after(contents: str, *, anchor: str, insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        return contents
    pos = idx + len(anchor)
    return contents[:pos] + insert + contents[pos:]


def _ensure_use_fuzzer_utils(path: Path) -> None:
    contents = path.read_text()
    if "use fuzzer_utils;" in contents:
        return
    prepend_file(path, "#[allow(unused_imports)]\nuse fuzzer_utils;\n")


def _patch_runtime(path: Path) -> None:
    _ensure_use_fuzzer_utils(path)
    contents = path.read_text()

    contents = _insert_after(
        contents,
        anchor="pub const NUM_BITS: usize = 31;\n",
        guard="// BEAK-INSERT: sp1.legacy_recursion.inject_helpers",
        insert="""

const BEAK_RECURSION_LOAD_BINDING_INJECT_KIND: &str = "sp1.legacy_recursion.memory.load_binding";
const BEAK_RECURSION_JUMP_BINDING_INJECT_KIND: &str = "sp1.legacy_recursion.exec.jump_binding";
const BEAK_RECURSION_BNEINC_UPPER_LIMBS_INJECT_KIND: &str =
    "sp1.legacy_recursion.exec.bneinc_upper_limbs";

// BEAK-INSERT: sp1.legacy_recursion.inject_helpers
fn beak_inject_variant_value<'a>(kind: &'a str, key: &str) -> Option<&'a str> {
    let (_, variant) = kind.split_once("::")?;
    for field in variant.split(',') {
        let (field_key, field_value) = field.split_once('=')?;
        if field_key == key {
            return Some(field_value);
        }
    }
    None
}

fn beak_mutate_load_value<F: PrimeField32>(kind: &str, mut value: Block<F>) -> Option<Block<F>> {
    match beak_inject_variant_value(kind, "mode") {
        Some("zero_all") => {
            value = Block::default();
            Some(value)
        }
        Some("flip_second_limb") => {
            value[1] += F::one();
            Some(value)
        }
        Some("noop_prefix") => None,
        _ => {
            value[0] += F::one();
            Some(value)
        }
    }
}

fn beak_mutate_jump_a<F: PrimeField32>(
    kind: &str,
    opcode: Opcode,
    mut value: Block<F>,
    c_value: Block<F>,
) -> Option<Block<F>> {
    match beak_inject_variant_value(kind, "mode") {
        Some("noop_prefix") => None,
        Some("jalr_a_matches_c") if opcode == Opcode::JALR => {
            value[0] = c_value[0];
            Some(value)
        }
        Some("jalr_a_plus_one") if opcode == Opcode::JALR => {
            value[0] += F::one();
            Some(value)
        }
        Some("jal_a_plus_one") if opcode == Opcode::JAL => {
            value[0] += F::one();
            Some(value)
        }
        _ => {
            value[0] += F::one();
            Some(value)
        }
    }
}

fn beak_mutate_jump_fp<F: PrimeField32>(
    kind: &str,
    opcode: Opcode,
    local_fp: F,
    a_value: Block<F>,
    c_value: Block<F>,
) -> Option<F> {
    match beak_inject_variant_value(kind, "mode") {
        Some("noop_prefix") => None,
        Some("jalr_fp_from_a") if opcode == Opcode::JALR => Some(a_value[0]),
        Some("jal_near_fp") if opcode == Opcode::JAL => Some(local_fp + c_value[0] + F::one()),
        Some("jalr_a_matches_c") if opcode == Opcode::JALR => None,
        _ if opcode == Opcode::JALR => Some(a_value[0]),
        _ => None,
    }
}

fn beak_mutate_bneinc_value<F: PrimeField32>(kind: &str, mut value: Block<F>) -> Option<Block<F>> {
    match beak_inject_variant_value(kind, "mode") {
        Some("noop_prefix") => None,
        Some("set_upper_ones") => {
            value[1] = F::one();
            value[2] = F::one();
            value[3] = F::one();
            Some(value)
        }
        _ => {
            value[1] += F::one();
            Some(value)
        }
    }
}
// BEAK-INSERT-END
""",
    )

    contents = _insert_after(
        contents,
        anchor="""            let mut next_clk = self.clk + F::from_canonical_u32(4);
            let mut next_pc = self.pc + F::one();
""",
        guard="// BEAK-INSERT: sp1.legacy_recursion.step_counter",
        insert="""
            // BEAK-INSERT: sp1.legacy_recursion.step_counter
            let beak_exec_step = fuzzer_utils::next_executor_step();
""",
    )

    contents = contents.replace(
        """        while self.pc < F::from_canonical_u32(self.program.instructions.len() as u32) {
            let idx = self.pc.as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();

            let mut next_clk = self.clk + F::from_canonical_u32(4);
""",
        """        while self.pc < F::from_canonical_u32(self.program.instructions.len() as u32) {
            let idx = self.pc.as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();
            let event_fp = self.fp;

            let mut next_clk = self.clk + F::from_canonical_u32(4);
""",
        1,
    )

    contents = contents.replace("                fp: self.fp,\n", "                fp: event_fp,\n", 1)

    contents = contents.replace(
        """                    let a_val = self.mr_cpu(addr, MemoryAccessPosition::Memory);
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
""",
        """                    let mut a_val = self.mr_cpu(addr, MemoryAccessPosition::Memory);
                    if let Some(kind) = fuzzer_utils::matching_injection_kind(
                        BEAK_RECURSION_LOAD_BINDING_INJECT_KIND,
                        beak_exec_step,
                    ) {
                        if let Some(mutated) = beak_mutate_load_value(kind.as_str(), a_val) {
                            a_val = mutated;
                        }
                    }
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
""",
        1,
    )

    contents = contents.replace(
        """                    let (_, b_val, c_offset) = self.alu_rr(&instruction);
                    let (a_ptr, mut a_val) = self.peek_a(&instruction);
                    a_val[0] += F::one();
                    if a_val != b_val {
                        next_pc = self.pc + c_offset[0];
                    }
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_offset);
""",
        """                    let (_, b_val, c_offset) = self.alu_rr(&instruction);
                    let (a_ptr, mut a_val) = self.peek_a(&instruction);
                    a_val[0] += F::one();
                    if let Some(kind) = fuzzer_utils::matching_injection_kind(
                        BEAK_RECURSION_BNEINC_UPPER_LIMBS_INJECT_KIND,
                        beak_exec_step,
                    ) {
                        if let Some(mutated) = beak_mutate_bneinc_value(kind.as_str(), a_val) {
                            a_val = mutated;
                        }
                    }
                    if a_val != b_val {
                        next_pc = self.pc + c_offset[0];
                    }
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_offset);
""",
        1,
    )

    contents = contents.replace(
        """                    let (a_ptr, b_val, c_offset) = self.alu_rr(&instruction);
                    let a_val = Block::from(self.pc);
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    next_pc = self.pc + b_val[0];
                    self.fp += c_offset[0];
                    (a, b, c) = (a_val, b_val, c_offset);
""",
        """                    let (a_ptr, b_val, c_offset) = self.alu_rr(&instruction);
                    let mut a_val = Block::from(self.pc);
                    if let Some(kind) = fuzzer_utils::matching_injection_kind(
                        BEAK_RECURSION_JUMP_BINDING_INJECT_KIND,
                        beak_exec_step,
                    ) {
                        if let Some(mutated) =
                            beak_mutate_jump_a(kind.as_str(), Opcode::JAL, a_val, c_offset)
                        {
                            a_val = mutated;
                        }
                    }
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    next_pc = self.pc + b_val[0];
                    self.fp += c_offset[0];
                    if let Some(kind) = fuzzer_utils::matching_injection_kind(
                        BEAK_RECURSION_JUMP_BINDING_INJECT_KIND,
                        beak_exec_step,
                    ) {
                        if let Some(mutated_fp) =
                            beak_mutate_jump_fp(kind.as_str(), Opcode::JAL, self.fp, a_val, c_offset)
                        {
                            self.fp = mutated_fp;
                        }
                    }
                    (a, b, c) = (a_val, b_val, c_offset);
""",
        1,
    )

    contents = contents.replace(
        """                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = Block::from(self.pc + F::one());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    next_pc = b_val[0];
                    self.fp = c_val[0];
                    (a, b, c) = (a_val, b_val, c_val);
""",
        """                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::from(self.pc + F::one());
                    if let Some(kind) = fuzzer_utils::matching_injection_kind(
                        BEAK_RECURSION_JUMP_BINDING_INJECT_KIND,
                        beak_exec_step,
                    ) {
                        if let Some(mutated) = beak_mutate_jump_a(
                            kind.as_str(),
                            Opcode::JALR,
                            a_val,
                            c_val,
                        )
                        {
                            a_val = mutated;
                        }
                    }
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    next_pc = b_val[0];
                    self.fp = c_val[0];
                    if let Some(kind) = fuzzer_utils::matching_injection_kind(
                        BEAK_RECURSION_JUMP_BINDING_INJECT_KIND,
                        beak_exec_step,
                    ) {
                        if let Some(mutated_fp) =
                            beak_mutate_jump_fp(kind.as_str(), Opcode::JALR, self.fp, a_val, c_val)
                        {
                            self.fp = mutated_fp;
                        }
                    }
                    (a, b, c) = (a_val, b_val, c_val);
""",
        1,
    )

    path.write_text(contents)


def _patch_plonky3_pin(sp1_install_path: Path) -> None:
    needle = 'git = "https://github.com/Plonky3/Plonky3.git", branch = "sp1"'
    replacement = f'git = "https://github.com/Plonky3/Plonky3.git", rev = "{_PLONKY3_REV}"'
    multiline_tail = '], branch = "sp1" }'
    multiline_replacement = f'], rev = "{_PLONKY3_REV}" }}'
    for cargo_toml in sp1_install_path.rglob("Cargo.toml"):
        contents = cargo_toml.read_text()
        updated = contents.replace(needle, replacement).replace(multiline_tail, multiline_replacement)
        if updated != contents:
            cargo_toml.write_text(updated)


def apply(*, sp1_install_path: Path, commit_or_branch: str) -> None:
    if commit_or_branch != SP1_RECURSION_KALOS_FB38_COMMIT:
        return
    _patch_plonky3_pin(sp1_install_path)
    path = sp1_install_path.joinpath(*_RUNTIME_PATH)
    if path.exists():
        _patch_runtime(path)
