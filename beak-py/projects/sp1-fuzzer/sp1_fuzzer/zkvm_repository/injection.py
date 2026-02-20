import logging
import re
from pathlib import Path

from sp1_fuzzer.zkvm_repository.fuzzer_utils_crate import create_fuzzer_utils_crate
from zkvm_fuzzer_utils.file import create_file, prepend_file, replace_in_file

logger = logging.getLogger("fuzzer")


class SP1ManagerException(Exception):
    pass


_FAULT_INJECTION_RS = """// Fault-injection + trace helpers for older SP1 snapshots.
//
// We intentionally keep this small and source-compatible across multiple historical commits.
// It is driven by `crates/fuzzer_utils` (also injected into the SP1 workspace).

use hashbrown::HashMap;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::Instruction;

use super::ExecutorMode;

#[allow(unused_imports)]
use fuzzer_utils;

/// Context used to manage fault injections.
#[derive(Debug)]
pub struct RV32IMFaultInjectionContext {
    trace_info_enabled: bool,
    injection_enabled: bool,
    instruction_override: bool,
    injection_step: u64,
    injection_type: String,
    current_step: u64,
    rng: StdRng,
    injection_history: HashMap<u32, Instruction>,
    pc_hint: u32,
    instruction_hint: Option<Instruction>,
}

impl RV32IMFaultInjectionContext {
    #[must_use]
    pub fn new(
        trace_info_enabled: bool,
        injection_enabled: bool,
        instruction_override: bool,
        injection_step: u64,
        injection_type: String,
        injection_seed: u64,
    ) -> Self {
        Self {
            trace_info_enabled,
            injection_enabled,
            instruction_override,
            injection_step,
            injection_type,
            current_step: 0,
            rng: StdRng::seed_from_u64(injection_seed),
            injection_history: HashMap::new(),
            pc_hint: 0,
            instruction_hint: None,
        }
    }

    /// Advance one instruction-step and update our best-effort PC hint.
    pub fn step(&mut self, next_pc: u32) {
        self.current_step += 1;
        self.pc_hint = next_pc;
    }

    #[must_use]
    pub fn get_pc_hint(&self) -> u32 {
        self.pc_hint
    }

    pub fn set_instruction_hint(&mut self, instruction: &Instruction) {
        self.instruction_hint = Some(*instruction);
    }

    #[must_use]
    pub fn get_instruction_hint(&self) -> Instruction {
        self.instruction_hint.unwrap()
    }

    #[must_use]
    pub fn is_injection_enabled(&self) -> bool {
        self.injection_enabled
    }

    /// Predicate indicating whether an injection should trigger at this point.
    #[must_use]
    pub fn is_injection(&self, injection_type: &str, pc: &u32, _executor_mode: ExecutorMode) -> bool {
        self.injection_enabled
            && self.injection_type == injection_type
            && ((self.instruction_override && self.injection_history.contains_key(pc))
                || (self.current_step == self.injection_step))
    }

    pub fn print_trace_info(
        &self,
        pc: &u32,
        instruction: &Instruction,
        executor_mode: ExecutorMode,
        clk: u32,
    ) {
        if self.trace_info_enabled {
            println!(
                "<trace>{{\\
                    \\"step\\":{}, \\
                    \\"pc\\":{}, \\
                    \\"instruction\\":\\"{:?}\\", \\
                    \\"assembly\\":\\"{:?}\\", \\
                    \\"executor_mode\\":\\"{:?}\\", \\
                    \\"clk\\": \\"{}\\"\\
                }}</trace>",
                self.current_step,
                pc,
                instruction,
                instruction,
                executor_mode,
                clk,
            );
        }
    }

    pub fn print_injection_info(
        &self,
        pc: &u32,
        instruction: &Instruction,
        injection_type: &str,
        executor_mode: ExecutorMode,
        clk: u32,
    ) {
        println!(
            "<injection>{{\\
                \\"step\\":{}, \\
                \\"pc\\":{}, \\
                \\"instruction\\":\\"{:?}\\", \\
                \\"assembly\\":\\"{:?}\\", \\
                \\"injection_type\\":\\"{}\\", \\
                \\"executor_mode\\":\\"{:?}\\", \\
                \\"clk\\":\\"{}\\"\\
            }}</injection>",
            self.current_step,
            pc,
            instruction,
            instruction,
            injection_type,
            executor_mode,
            clk,
        );
    }

    #[must_use]
    pub fn random_mod_of_u32(&mut self, value: u32) -> u32 {
        let choices = [
            0,
            value.wrapping_add(1),
            value.wrapping_sub(1),
            value.wrapping_add(0x100),
            value.wrapping_sub(0x100),
            self.rng.gen(),
        ];
        choices[self.rng.gen_range(0..choices.len())]
    }

    #[must_use]
    pub fn random_register(&mut self) -> u8 {
        self.rng.gen_range(0..32)
    }

    #[must_use]
    pub fn random_mod_ecall(&mut self, value: u32) -> u32 {
        match self.rng.gen_range(0..5) {
            0 => 0,
            1 => 1,
            2 => value.wrapping_add(1),
            3 => value.wrapping_sub(1),
            _ => value,
        }
    }

    #[must_use]
    pub fn maybe_inject_instruction(
        &mut self,
        pc: u32,
        instruction: Instruction,
        executor_mode: ExecutorMode,
    ) -> Instruction {
        if !self.is_injection("INSTR_WORD_MOD", &pc, executor_mode) {
            return instruction;
        }

        if self.instruction_override {
            if let Some(prev) = self.injection_history.get(&pc) {
                return *prev;
            }
        }

        let mut out = instruction;
        // Best-effort targeted mutations: tweak operands.
        //
        // NOTE: SP1 uses a custom encoding (`op_a`, `op_b`, `op_c` + immediate flags) instead of
        // raw RV32I instruction words. When an operand is not immediate, it typically encodes a
        // register index (0..31). Keep mutations conservative so the decoder keeps working.
        out.op_a = self.random_register();
        if !out.imm_b {
            out.op_b = u32::from(self.random_register());
        } else {
            out.op_b = self.random_mod_of_u32(out.op_b);
        }
        if !out.imm_c {
            out.op_c = u32::from(self.random_register());
        } else {
            out.op_c = self.random_mod_of_u32(out.op_c);
        }

        self.injection_history.insert(pc, out);
        self.print_injection_info(&pc, &instruction, "INSTR_WORD_MOD", executor_mode, 0);
        out
    }
}

impl Default for RV32IMFaultInjectionContext {
    fn default() -> Self {
        Self::new(
            fuzzer_utils::is_trace_logging(),
            fuzzer_utils::is_injection(),
            fuzzer_utils::is_instruction_override(),
            fuzzer_utils::get_injection_step(),
            fuzzer_utils::get_injection_kind(),
            fuzzer_utils::get_seed(),
        )
    }
}
"""


def sp1_fault_injection(sp1_install_path: Path, commit_or_branch: str):
    del commit_or_branch

    # add fuzzer utils crate
    create_fuzzer_utils_crate(sp1_install_path)

    cargo_toml_path = sp1_install_path / "Cargo.toml"
    cargo_toml = cargo_toml_path.read_text()

    # Add to workspace members (idempotent).
    if '"crates/fuzzer_utils"' not in cargo_toml:
        replace_in_file(
            cargo_toml_path,
            [
                (
                    r"""\[workspace\]
members = \[""",
                    """[workspace]
members = [
  "crates/fuzzer_utils",""",
                )
            ],
        )

    # Add to workspace deps (idempotent).
    cargo_toml = cargo_toml_path.read_text()
    if 'fuzzer_utils = { path = "crates/fuzzer_utils" }' not in cargo_toml:
        replace_in_file(
            cargo_toml_path,
            [
                (
                    r"\[workspace.dependencies\]",
                    '[workspace.dependencies]\nfuzzer_utils = { path = "crates/fuzzer_utils" }',
                )
            ],
        )

    # The executor crate references `fuzzer_utils::*`, so it must explicitly depend on it.
    executor_toml_path = sp1_install_path / "crates" / "core" / "executor" / "Cargo.toml"
    if executor_toml_path.exists():
        executor_toml = executor_toml_path.read_text()
        if "fuzzer_utils" not in executor_toml:
            replace_in_file(
                executor_toml_path,
                [
                    (
                        r"\[dependencies\]",
                        "[dependencies]\nfuzzer_utils = { workspace = true }",
                    )
                ],
            )

    # Core machine trace generators are where padding/inactive rows (is_real=0) naturally exist.
    # To support InactiveRowEffectsBucket, we sample a few padding rows and emit ChipRow +
    # Interaction anchored to those inactive rows.
    machine_toml_path = sp1_install_path / "crates" / "core" / "machine" / "Cargo.toml"
    if machine_toml_path.exists():
        machine_toml = machine_toml_path.read_text()
        if "fuzzer_utils" not in machine_toml:
            replace_in_file(
                machine_toml_path,
                [
                    (
                        r"\[dependencies\]",
                        "[dependencies]\nfuzzer_utils = { workspace = true }",
                    )
                ],
            )

    def _inject_padding_sampling(*, path: Path, guard: str, anchor: str, chip_expr: str, real_rows_expr: str, total_rows_expr: str):
        if not path.exists():
            return
        contents = path.read_text()
        if guard in contents:
            return
        # Ensure `use fuzzer_utils;` exists.
        if "use fuzzer_utils;" not in contents:
            # Insert after initial use block.
            header_end = contents.find("\n\n")
            if header_end > 0:
                contents = contents[:header_end] + "\n#[allow(unused_imports)]\nuse fuzzer_utils;\n" + contents[header_end:]
        insert = """

        // beak-fuzz: sample a few inactive (padding) rows for op-agnostic inactive-row analysis.
        if fuzzer_utils::is_trace_logging() {{
            // Group padding rows into their own op-span (not tied to any instruction).
            fuzzer_utils::update_hints(0, "PADDING", "PADDING");
            fuzzer_utils::inc_step();

            let chip = __CHIP_EXPR__;
            let real_rows: usize = (__REAL_ROWS_EXPR__) as usize;
            let total_rows: usize = (__TOTAL_ROWS_EXPR__) as usize;
            let max_samples: usize = 3;
            let mut emitted: usize = 0;
            let start = real_rows;
            while emitted < max_samples && (start + emitted) < total_rows {{
                let row_idx = start + emitted;
                let gates = "{\\\"is_real\\\":0}";
                let locals = format!(
                    r#"{{"chip":"{}","row_idx":{},"real_rows":{},"total_rows":{}}}"#,
                    chip, row_idx, real_rows, total_rows
                );
                fuzzer_utils::print_chip_row_json("sp1", &chip, gates, &locals);
                let anchor_row_id = fuzzer_utils::get_last_row_id();
                let payload = format!(r#"{{"chip":"{}","row_idx":{}}}"#, chip, row_idx);
                // Emit an effectful interaction anchored to an inactive row (this is what
                // InactiveRowEffectsBucket is designed to detect).
                fuzzer_utils::print_interaction_json(
                    "PaddingSample",
                    "send",
                    "inactive_row",
                    &anchor_row_id,
                    &payload,
                    1,
                    "const",
                );
                emitted += 1;
            }}
        }}
"""
        insert = (
            insert.replace("__CHIP_EXPR__", chip_expr)
            .replace("__REAL_ROWS_EXPR__", real_rows_expr)
            .replace("__TOTAL_ROWS_EXPR__", total_rows_expr)
        )
        idx = contents.find(anchor)
        if idx < 0:
            return
        contents = contents[:idx] + insert + contents[idx:]
        path.write_text(contents)

    # CPU padding rows.
    _inject_padding_sampling(
        path=sp1_install_path / "crates" / "core" / "machine" / "src" / "cpu" / "trace.rs",
        guard="PaddingSample",
        anchor="        // Convert the trace to a row major matrix.",
        chip_expr="\"Cpu\".to_string()",
        real_rows_expr="n_real_rows",
        total_rows_expr="padded_nb_rows",
    )

    # MemoryLocal padding rows.
    _inject_padding_sampling(
        path=sp1_install_path / "crates" / "core" / "machine" / "src" / "memory" / "local.rs",
        guard="PaddingSample",
        anchor="        // Convert the trace to a row major matrix.",
        chip_expr="\"MemoryLocal\".to_string()",
        real_rows_expr="nb_rows",
        total_rows_expr="padded_nb_rows",
    )

    # MemoryGlobal padding rows (Initialize/Finalize).
    _inject_padding_sampling(
        path=sp1_install_path / "crates" / "core" / "machine" / "src" / "memory" / "global.rs",
        guard="PaddingSample",
        # Insert right before returning the row-major matrix so `rows.len()` reflects padding.
        anchor="        RowMajorMatrix::new(",
        chip_expr="format!(\"MemoryGlobal({:?})\", self.kind)",
        real_rows_expr="memory_events.len()",
        total_rows_expr="rows.len()",
    )

    # Inject executor behavior.
    #
    # Older SP1 snapshots have incompatible `executor.rs` layouts, so we avoid overwriting the
    # whole file. Instead, we add a small submodule + patch a few stable anchors.
    executor_rs = sp1_install_path / "crates" / "core" / "executor" / "src" / "executor.rs"
    fault_rs = sp1_install_path / "crates" / "core" / "executor" / "src" / "fault_injection.rs"

    if not executor_rs.is_file():
        raise SP1ManagerException(f"missing executor.rs at {executor_rs}")

    create_file(fault_rs, _FAULT_INJECTION_RS)

    # Wire in the module and type import (idempotent).
    #
    # NOTE: `executor.rs` is at `src/executor.rs`, so a plain `mod fault_injection;` would look for
    # `src/executor/fault_injection.rs`. We intentionally create `src/fault_injection.rs` and use
    # `#[path = \"...\"]` to keep the patch stable across historical snapshots.
    executor_src = executor_rs.read_text()
    if "mod fault_injection;" not in executor_src and "fault_injection::RV32IMFaultInjectionContext" not in executor_src:
        replace_in_file(
            executor_rs,
            [
                (
                    r"(use crate::\{[\s\S]*?\};\s*)",
                    r'\1\n#[path = "fault_injection.rs"]\nmod fault_injection;\nuse fault_injection::RV32IMFaultInjectionContext;\n',
                )
            ],
            flags=re.MULTILINE,
        )

    # Add the context field to `Executor` (idempotent, line-based to preserve indentation).
    executor_src = executor_rs.read_text()
    if "fault_injection_context" not in executor_src:
        replace_in_file(
            executor_rs,
            [
                (
                    r"^(\s*)pub executor_mode: ExecutorMode,\s*$",
                    r"\1pub executor_mode: ExecutorMode,\n\n\1/// Fault injection context.\n\1pub fault_injection_context: RV32IMFaultInjectionContext,",
                )
            ],
            flags=re.MULTILINE,
        )

    # Initialize it in the constructor struct literal.
    executor_src = executor_rs.read_text()
    if "fault_injection_context: RV32IMFaultInjectionContext::default()" not in executor_src:
        replace_in_file(
            executor_rs,
            [
                (
                    r"^(\s*)executor_mode:\s*ExecutorMode::Trace,\s*$",
                    r"\1executor_mode: ExecutorMode::Trace,\n\1fault_injection_context: RV32IMFaultInjectionContext::default(),",
                )
            ],
            flags=re.MULTILINE,
        )

    # Patch the per-cycle execution loop:
    # - make the fetched instruction mutable,
    # - print trace info (when enabled),
    # - emit micro-op records (ChipRow + Interaction) when trace logging is enabled,
    # - apply `INSTR_WORD_MOD` at the fetch boundary,
    # - advance the injection context after the instruction is executed.
    executor_src = executor_rs.read_text()
    if "maybe_inject_instruction" not in executor_src:
        replace_in_file(
            executor_rs,
            [
                (
                    r"^(\s*)let instruction = self\.fetch\(\);\s*$",
                    r"""\1let mut instruction = self.fetch();

\1self.fault_injection_context.set_instruction_hint(&instruction);
\1self.fault_injection_context.print_trace_info(&self.state.pc, &instruction, self.executor_mode, self.state.clk);

\1// Micro-op emission (beak-core interface): ChipRow + InteractionBase
\1if fuzzer_utils::is_trace_logging() {
\1    let pc = self.state.pc;
\1    let asm = format!("{:?}", instruction);
\1    fuzzer_utils::update_hints(pc, &asm, &asm);
\1    let chip = format!("Exec({:?})", instruction.opcode);
\1    let gates = "{\"is_real\":1}";
\1    let locals = format!(
\1        "{{\"pc\":{},\"clk\":{},\"opcode\":\"{:?}\",\"op_a\":{},\"op_b\":{},\"op_c\":{},\"imm_b\":{},\"imm_c\":{}}}",
\1        pc,
\1        self.state.clk,
\1        instruction.opcode,
\1        instruction.op_a,
\1        instruction.op_b,
\1        instruction.op_c,
\1        instruction.imm_b,
\1        instruction.imm_c
\1    );
\1    fuzzer_utils::print_chip_row_json("sp1", &chip, gates, &locals);
\1
\1    // Program semantics (pc -> opcode/operands) as an anchored interaction.
\1    let anchor_row_id = fuzzer_utils::get_last_row_id();
\1    let payload = format!(
\1        "{{\"pc\":{},\"opcode\":\"{:?}\",\"op_a\":{},\"op_b\":{},\"op_c\":{},\"imm_b\":{},\"imm_c\":{}}}",
\1        pc, instruction.opcode, instruction.op_a, instruction.op_b, instruction.op_c, instruction.imm_b, instruction.imm_c
\1    );
\1    fuzzer_utils::print_interaction_json(
\1        "ProgramBus",
\1        "recv",
\1        "program",
\1        &anchor_row_id,
\1        &payload,
\1        1,
\1        "gates.is_real",
\1    );
\1}

\1instruction = self
\1    .fault_injection_context
\1    .maybe_inject_instruction(self.state.pc, instruction, self.executor_mode);""",
                ),
                (
                    r"^(\s*)self\.execute_instruction\(&instruction\)\?;\s*$",
                    r"""\1self.execute_instruction(&instruction)?;

\1if fuzzer_utils::is_trace_logging() {
\1    fuzzer_utils::inc_step();
\1}

\1self.fault_injection_context.step(self.state.pc);""",
                ),
            ],
            flags=re.MULTILINE,
        )

    # prepend the fuzzer util to registers.rs
    prepend_file(
        sp1_install_path / "crates" / "core" / "executor" / "src" / "register.rs",
        "#[allow(unused_imports)]\nuse fuzzer_utils;\n",
    )

    # manipulate register to avoid invalid register panics during injection
    replace_in_file(
        sp1_install_path / "crates" / "core" / "executor" / "src" / "register.rs",
        [
            (
                r"""pub fn from_u8\(value: u8\) -> Self \{
        match value \{""",
                """pub fn from_u8(value: u8) -> Self {
        let value = if value >= 32 && fuzzer_utils::is_injection() {
            println!("WARNING: Hotfix for register access out-of-bounds!");
            value % 32_u8
        } else {
            value
        };
        match value {""",
            )
        ],
    )

    # prepend the fuzzer util to memory.rs
    prepend_file(
        sp1_install_path / "crates" / "core" / "executor" / "src" / "memory.rs",
        "#[allow(unused_imports)]\nuse fuzzer_utils;\n",
    )

    # modify memory to fix addr out of bounds during injection
    replace_in_file(
        sp1_install_path / "crates" / "core" / "executor" / "src" / "memory.rs",
        [
            (
                r"""pub fn get\(&self, addr: u32\) -> Option<&V> \{
        let \(upper, lower\) = Self::indices\(addr\);
        let index = self.index\[upper\];
        if index == NO_PAGE \{
            None
        \} else \{
            self\.page_table\[index as usize\]\.0\[lower\]\.as_ref\(\)
        \}
    \}

    /// Get a mutable reference to the memory value at the given address, if it exists\.
    pub fn get_mut\(&mut self, addr: u32\) -> Option<&mut V> \{
        let \(upper, lower\) = Self::indices\(addr\);
        let index = self.index\[upper\];
        if index == NO_PAGE \{
            None
        \} else \{
            self\.page_table\[index as usize\]\.0\[lower\]\.as_mut\(\)
        \}
    \}""",
                """pub fn get(&self, addr: u32) -> Option<&V> {
        let (upper, lower) = Self::indices(addr);
        if upper >= self.index.len() && fuzzer_utils::is_injection() {
            println!("WARNING: Hotfix memory access out-of-bounds");
            return None;
        }
        let index = self.index[upper];
        if index == NO_PAGE {
            None
        } else {
            self.page_table[index as usize].0[lower].as_ref()
        }
    }

    /// Get a mutable reference to the memory value at the given address, if it exists.
    pub fn get_mut(&mut self, addr: u32) -> Option<&mut V> {
        let (upper, lower) = Self::indices(addr);
        if upper >= self.index.len() && fuzzer_utils::is_injection() {
            println!("WARNING: Hotfix memory access out-of-bounds");
            return None;
        }
        let index = self.index[upper];
        if index == NO_PAGE {
            None
        } else {
            self.page_table[index as usize].0[lower].as_mut()
        }
    }""",
            )
        ],
    )
