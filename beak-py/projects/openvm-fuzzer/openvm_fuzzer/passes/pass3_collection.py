'''
Pass 3: Trace + Micro-op Collection Instrumentation
'''
from __future__ import annotations
import logging
import re
from pathlib import Path
from openvm_fuzzer.settings import OPENVM_BENCHMARK_336F_COMMIT, OPENVM_BENCHMARK_BF11_COMMIT, OPENVM_BENCHMARK_F038_COMMIT, OPENVM_BENCHMARK_REGZERO_COMMIT, OPNEVM_BENCHMARK_REGZERO_ALIAS, resolve_openvm_commit
from zkvm_fuzzer_utils.file import replace_in_file
logger = logging.getLogger('fuzzer')

def _insert_after(contents = None, *, anchor, insert, guard):
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        raise RuntimeError(f'''anchor not found for injection: {anchor!r}''')
    pos = idx + len(anchor)
    return contents[:pos] + insert + contents[pos:]


def _insert_after_any(contents: str, *, anchors: tuple[str, ...], insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    missing = []
    for anchor in anchors:
        try:
            return _insert_after(contents, anchor=anchor, insert=insert, guard=guard)
        except RuntimeError:
            missing.append(anchor)
    raise RuntimeError(f"anchors not found for injection: {missing!r}")


def _insert_before(contents = None, *, anchor, insert, guard):
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        raise RuntimeError(f'''anchor not found for injection: {anchor!r}''')
    return contents[:idx] + insert + contents[idx:]


def _insert_before_fn_close(contents: str, *, fn_name: str, insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    needle = f"fn {fn_name}"
    start = contents.find(needle)
    if start < 0:
        raise RuntimeError(f"function not found for injection: {needle!r}")
    brace_open = contents.find("{", start)
    if brace_open < 0:
        raise RuntimeError(f"function body not found for injection: {needle!r}")
    depth = 0
    for i in range(brace_open, len(contents)):
        ch = contents[i]
        if ch == "{":
            depth += 1
            continue
        if ch == "}":
            depth -= 1
            if depth == 0:
                return contents[:i] + insert + contents[i:]
    raise RuntimeError(f"unterminated function body for injection: {needle!r}")


def _refresh_guarded_block(contents: str, *, template: str, guard: str) -> str:
    """Replace an already-installed guarded block with the current pass template."""

    def bounds(text: str) -> tuple[int, int] | None:
        marker = text.find(guard)
        if marker < 0:
            return None
        start = text.rfind("\n", 0, marker) + 1
        end_marker = text.find("// BEAK-INSERT-END", marker)
        if end_marker < 0:
            raise RuntimeError(f"unterminated guarded injection: {guard!r}")
        line_end = text.find("\n", end_marker)
        end = len(text) if line_end < 0 else line_end + 1
        return (start, end)

    current_bounds = bounds(contents)
    template_bounds = bounds(template)
    if current_bounds is None or template_bounds is None:
        return contents
    current_start, current_end = current_bounds
    (template_start, template_end) = template_bounds
    replacement = template[template_start:template_end]
    if contents[current_start:current_end] == replacement:
        return contents
    return contents[:current_start] + replacement + contents[current_end:]


def _ensure_use_fuzzer_utils(path = None):
    if not path.exists():
        return None
    c = path.read_text()
    if 'use fuzzer_utils;' in c:
        return None
    import_block = "#[allow(unused_imports)]\nuse fuzzer_utils;\n"
    header_end = c.find('\n\n')
    if header_end > 0:
        c = c[:header_end] + '\n' + import_block + c[header_end:]
    else:
        c = import_block + c
    path.write_text(c)


def _ensure_import_after_fuzzer_utils(path = None, import_line = None):
    if not path.exists():
        return None
    c = path.read_text()
    if import_line in c:
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    idx = c.find('use fuzzer_utils;')
    if idx < 0:
        return None
    line_end = c.find('\n', idx)
    pos = line_end + 1 if line_end >= 0 else len(c)
    c = c[:pos] + import_line + '\n' + c[pos:]
    path.write_text(c)


def _patch_regzero_record_arena_emit_chip_row(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'arch' / 'record_arena.rs'
    if not path.exists():
        return None
    contents = path.read_text()
    anchor = 'let height = next_power_of_two_or_zero(rows_used);'
    insert = '\n\n        // BEAK-INSERT: Emit padding rows.\n        if height > rows_used {\n            let max_samples: usize = std::cmp::min(height - rows_used, 3);\n            let mut emitted: usize = 0;\n            while emitted < max_samples {\n                // trace_buffer is row-major flat storage; sample by row start.\n                let row_start = (rows_used + emitted) * width;\n                let row_end = row_start + width;\n                let data = format!("{:?}", &self.trace_buffer[row_start..row_end]);\n                fuzzer_utils::emit_padding_chip_row(&data);\n                if fuzzer_utils::should_inject_witness(\n                    "openvm.semantic.row.padding_interaction_send",\n                    emitted as u64,\n                ) {\n                    eprintln!(\n                        "[beak-witness-inject] kind=openvm.semantic.row.padding_interaction_send step={} row_idx={} rows_used={} height={}",\n                        emitted,\n                        rows_used + emitted,\n                        rows_used,\n                        height\n                    );\n                    self.trace_buffer[row_start] += F::ONE;\n                }\n                emitted += 1;\n            }\n        }\n        // BEAK-INSERT-END\n'
    if anchor not in contents:
        return None
    contents = contents.replace(anchor, anchor + insert)
    path.write_text(contents)


def _patch_regzero_interpreter_preflight_emit_instruction(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "vm" / "src" / "arch" / "interpreter_preflight.rs"
    if not path.exists():
        return

    contents = path.read_text()

    if "use fuzzer_utils;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            contents = (
                contents[:header_end]
                + "\n#[allow(unused_imports)]\nuse fuzzer_utils;\n"
                + contents[header_end:]
            )

    contents = _insert_after(
        contents,
        anchor='tracing::trace!("pc: {pc:#x} | {:?}", pc_entry.insn);',
        guard="// BEAK-INSERT: guard.interpreter_preflight.preassign",
        insert=r"""

        // BEAK-INSERT: guard.interpreter_preflight.preassign
        // BEAK-INSERT: Emit instruction-level micro-op (pc/opcode/operands/timestamps) pre-assignment.
        let beak_from_pc = pc;
        let beak_from_timestamp = state.memory.timestamp();
        let beak_operands = [
            pc_entry.insn.a.as_canonical_u32(),
            pc_entry.insn.b.as_canonical_u32(),
            pc_entry.insn.c.as_canonical_u32(),
            pc_entry.insn.d.as_canonical_u32(),
            pc_entry.insn.e.as_canonical_u32(),
            pc_entry.insn.f.as_canonical_u32(),
            pc_entry.insn.g.as_canonical_u32(),
        ];
        let beak_opcode = pc_entry.insn.opcode.as_usize() as u32;
        // BEAK-INSERT-END
""",
    )

    contents = _insert_after(
        contents,
        anchor="state.exit_code = Ok(Some(c.as_canonical_u32()));",
        guard="// BEAK-INSERT: guard.interpreter_preflight.terminate_branch",
        insert=r"""
            // BEAK-INSERT: guard.interpreter_preflight.terminate_branch
            // BEAK-INSERT: Emit instruction-level micro-op (pc/opcode/operands/timestamps) termination branch.
            let beak_to_pc = state.pc();
            let beak_to_timestamp = state.memory.timestamp();
            fuzzer_utils::emit_instruction(
                beak_from_pc,
                beak_from_timestamp,
                beak_to_pc,
                beak_to_timestamp,
                beak_opcode,
                beak_operands,
            );
            // BEAK-TODO: Maybe we should use the row_id here?
            fuzzer_utils::emit_program_interaction(
                "receive",
                None,
                beak_from_pc,
                beak_opcode,
                beak_operands,
            );
            fuzzer_utils::emit_execution_interaction(
                "receive",
                None,
                beak_from_pc,
                beak_from_timestamp,
            );
            fuzzer_utils::emit_execution_interaction("send", None, beak_to_pc, beak_to_timestamp);
            // BEAK-INSERT-END
""",
    )

    contents = _insert_after(
        contents,
        anchor="executor.execute(vm_state_mut, &pc_entry.insn)?;",
        guard="// BEAK-INSERT: guard.interpreter_preflight.normal_branch",
        insert=r"""
        // BEAK-INSERT: guard.interpreter_preflight.normal_branch
        // BEAK-INSERT: Emit instruction-level micro-op (pc/opcode/operands/timestamps) normal branch.
        let beak_to_pc = state.pc();
        let beak_to_timestamp = state.memory.timestamp();

        fuzzer_utils::emit_instruction(
            beak_from_pc,
            beak_from_timestamp,
            beak_to_pc,
            beak_to_timestamp,
            beak_opcode,
            beak_operands,
        );

        // BEAK-TODO: Maybe we should use the row_id here?
        fuzzer_utils::emit_program_interaction(
            "receive",
            None,
            beak_from_pc,
            beak_opcode,
            beak_operands,
        );
        fuzzer_utils::emit_execution_interaction(
            "receive",
            None,
            beak_from_pc,
            beak_from_timestamp,
        );
        fuzzer_utils::emit_execution_interaction("send", None, beak_to_pc, beak_to_timestamp);
        // BEAK-INSERT-END
""",
    )

    path.write_text(contents)


def _patch_336f_segment_emit_instruction(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'arch' / 'segment.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '                if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {\n                    let next_state = InstructionExecutor::execute(\n                        executor,\n                        memory_controller,\n                        instruction,\n                        ExecutionState::new(pc, timestamp),\n                    )?;\n                    fuzzer_utils::fuzzer_assert!(next_state.timestamp > timestamp);\n                    pc = next_state.pc;\n                    timestamp = next_state.timestamp;\n                } else {\n'
    new = '                if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {\n                    // BEAK-INSERT: guard.336f.segment.emit_instruction\n                    let beak_from_pc = pc;\n                    let beak_from_timestamp = timestamp;\n                    let beak_operands = [\n                        instruction.a.as_canonical_u32(),\n                        instruction.b.as_canonical_u32(),\n                        instruction.c.as_canonical_u32(),\n                        instruction.d.as_canonical_u32(),\n                        instruction.e.as_canonical_u32(),\n                        instruction.f.as_canonical_u32(),\n                        instruction.g.as_canonical_u32(),\n                    ];\n                    let beak_opcode = opcode.as_usize() as u32;\n                    fuzzer_utils::begin_instruction_step();\n                    // BEAK-INSERT-END\n                    let next_state = InstructionExecutor::execute(\n                        executor,\n                        memory_controller,\n                        instruction,\n                        ExecutionState::new(pc, timestamp),\n                    )?;\n                    fuzzer_utils::fuzzer_assert!(next_state.timestamp > timestamp);\n                    // BEAK-INSERT: guard.336f.segment.emit_instruction.after\n                    fuzzer_utils::emit_instruction_current_step(\n                        beak_from_pc,\n                        beak_from_timestamp,\n                        next_state.pc,\n                        next_state.timestamp,\n                        beak_opcode,\n                        beak_operands,\n                    );\n                    // BEAK-INSERT-END\n                    pc = next_state.pc;\n                    timestamp = next_state.timestamp;\n                } else {\n'
    if '// BEAK-INSERT: guard.336f.segment.emit_instruction' not in c and old in c:
        c = c.replace(old, new, 1)
    old_f038 = '                if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {\n                    let next_state = InstructionExecutor::execute(\n                        executor,\n                        memory_controller,\n                        instruction,\n                        ExecutionState::new(pc, timestamp),\n                    )?;\n                    fuzzer_utils::fuzzer_assert!(next_state.timestamp > timestamp);\n                    pc = next_state.pc;\n                    timestamp = next_state.timestamp;\n                } else {\n'
    new_f038 = '                if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {\n                    // BEAK-INSERT: guard.336f.segment.emit_instruction\n                    let beak_from_pc = pc;\n                    let beak_from_timestamp = timestamp;\n                    let beak_operands = [\n                        instruction.a.as_canonical_u32(),\n                        instruction.b.as_canonical_u32(),\n                        instruction.c.as_canonical_u32(),\n                        instruction.d.as_canonical_u32(),\n                        instruction.e.as_canonical_u32(),\n                        instruction.f.as_canonical_u32(),\n                        instruction.g.as_canonical_u32(),\n                    ];\n                    let beak_opcode = opcode.as_usize() as u32;\n                    fuzzer_utils::begin_instruction_step();\n                    // BEAK-INSERT-END\n                    let next_state = InstructionExecutor::execute(\n                        executor,\n                        memory_controller,\n                        instruction,\n                        ExecutionState::new(pc, timestamp),\n                    )?;\n                    fuzzer_utils::fuzzer_assert!(next_state.timestamp > timestamp);\n                    // BEAK-INSERT: guard.336f.segment.emit_instruction.after\n                    fuzzer_utils::emit_instruction_current_step(\n                        beak_from_pc,\n                        beak_from_timestamp,\n                        next_state.pc,\n                        next_state.timestamp,\n                        beak_opcode,\n                        beak_operands,\n                    );\n                    // BEAK-INSERT-END\n                    pc = next_state.pc;\n                    timestamp = next_state.timestamp;\n                } else {\n'
    if '// BEAK-INSERT: guard.336f.segment.emit_instruction' not in c and old_f038 in c:
        c = c.replace(old_f038, new_f038, 1)
    path.write_text(c)


def _patch_regzero_rv32im_cores_emit_chip_row(openvm_install_path: Path) -> None:
    base = openvm_install_path / "extensions" / "rv32im" / "circuit" / "src"

    # (file, adapter-cols import, unique guard, insertion block)
    targets: list[tuple[Path, str, str, str]] = [
        (
            base / "base_alu" / "core.rs",
            "use crate::adapters::Rv32BaseAluAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.base_alu.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.base_alu.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BaseAluAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();

        // rs2_as: 1 if rs2 is a register read, 0 if an immediate.
        let is_rs2_imm = beak_cols.rs2_as.as_canonical_u32() == 0;
        let rs2_raw = beak_cols.rs2.as_canonical_u32();
        let rs2_i32 = rs2_raw as i32; // preserve bit-pattern for signed immediates

        fuzzer_utils::emit_base_alu_chip_row(local_opcode as u32, rd_ptr, rs1_ptr, rs2_i32, is_rs2_imm, a, beak_record_b, beak_record_c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "shift" / "core.rs",
            "use crate::adapters::Rv32BaseAluAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.shift.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.shift.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BaseAluAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();

        // rs2_as: 1 if rs2 is a register read, 0 if an immediate.
        let is_rs2_imm = beak_cols.rs2_as.as_canonical_u32() == 0;
        let rs2_raw = beak_cols.rs2.as_canonical_u32();
        let rs2_i32 = rs2_raw as i32; // preserve bit-pattern for signed immediates

        fuzzer_utils::emit_shift_chip_row(opcode as u32, rd_ptr, rs1_ptr, rs2_i32, is_rs2_imm, a, beak_record_b, beak_record_c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "less_than" / "core.rs",
            "use crate::adapters::Rv32BaseAluAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.less_than.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.less_than.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BaseAluAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();

        // rs2_as: 1 if rs2 is a register read, 0 if an immediate.
        let is_rs2_imm = beak_cols.rs2_as.as_canonical_u32() == 0;
        let rs2_raw = beak_cols.rs2.as_canonical_u32();
        let rs2_i32 = rs2_raw as i32; // preserve bit-pattern for signed immediates

        let opcode = LessThanOpcode::from_usize(beak_record_local_opcode as usize);
        let mut a = [0u8; NUM_LIMBS];
        a[0] = cmp_result as u8;

        fuzzer_utils::emit_less_than_chip_row(opcode as u32, rd_ptr, rs1_ptr, rs2_i32, is_rs2_imm, a, beak_record_b, beak_record_c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "mul" / "core.rs",
            "use crate::adapters::Rv32MultAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.mul.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.mul.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32MultAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rs2_ptr = beak_cols.rs2_ptr.as_canonical_u32();

        fuzzer_utils::emit_mul_chip_row(MulOpcode::MUL as u32, rd_ptr, rs1_ptr, rs2_ptr, a, beak_record_b, beak_record_c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "mulh" / "core.rs",
            "use crate::adapters::Rv32MultAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.mulh.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.mulh.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32MultAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rs2_ptr = beak_cols.rs2_ptr.as_canonical_u32();

        let a_u8 = a.map(|x| x as u8);
        fuzzer_utils::emit_mulh_chip_row(opcode as u32, rd_ptr, rs1_ptr, rs2_ptr, a_u8, beak_record_b, beak_record_c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "divrem" / "core.rs",
            "use crate::adapters::Rv32MultAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.divrem.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.divrem.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32MultAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rs2_ptr = beak_cols.rs2_ptr.as_canonical_u32();

        let is_div = matches!(opcode, DivRemOpcode::DIV | DivRemOpcode::DIVU);
        let a_u8 = if is_div { q.map(|x| x as u8) } else { r.map(|x| x as u8) };

        fuzzer_utils::emit_divrem_chip_row(opcode as u32, rd_ptr, rs1_ptr, rs2_ptr, a_u8, beak_record_b, beak_record_c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "branch_eq" / "core.rs",
            "use crate::adapters::Rv32BranchAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.branch_eq.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.branch_eq.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BranchAdapterCols<F> = adapter_slice.borrow();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rs2_ptr = beak_cols.rs2_ptr.as_canonical_u32();
        let from_pc = beak_cols.from_state.pc.as_canonical_u32();

        let opcode = BranchEqualOpcode::from_usize(beak_record_local_opcode as usize);
        let imm_i32 = beak_record_imm as i32; // preserve bit-pattern
        let is_beq = opcode == BranchEqualOpcode::BEQ;
        let is_taken = if is_beq { cmp_result } else { !cmp_result };
        let to_pc = if is_taken {
            from_pc.wrapping_add(beak_record_imm)
        } else {
            from_pc.wrapping_add(self.pc_step)
        };

        fuzzer_utils::emit_branch_equal_chip_row(
            opcode as u32,
            rs1_ptr,
            rs2_ptr,
            imm_i32,
            is_taken,
            from_pc,
            to_pc,
            beak_record_a,
            beak_record_b,
            cmp_result,
        );
        // BEAK-INSERT-END
""",
        ),
        (
            base / "branch_lt" / "core.rs",
            "use crate::adapters::Rv32BranchAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.branch_lt.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.branch_lt.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BranchAdapterCols<F> = adapter_slice.borrow();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rs2_ptr = beak_cols.rs2_ptr.as_canonical_u32();
        let from_pc = beak_cols.from_state.pc.as_canonical_u32();

        let opcode = BranchLessThanOpcode::from_usize(beak_record_local_opcode as usize);
        let imm_i32 = beak_record_imm as i32; // preserve bit-pattern
        let is_taken = cmp_result;
        let to_pc = if is_taken {
            from_pc.wrapping_add(beak_record_imm)
        } else {
            from_pc.wrapping_add(DEFAULT_PC_STEP)
        };

        fuzzer_utils::emit_branch_less_than_chip_row(
            opcode as u32,
            rs1_ptr,
            rs2_ptr,
            imm_i32,
            is_taken,
            from_pc,
            to_pc,
            beak_record_a,
            beak_record_b,
            cmp_result,
        );
        // BEAK-INSERT-END
""",
        ),
        (
            base / "jal_lui" / "core.rs",
            "use crate::adapters::Rv32CondRdWriteAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.jal_lui.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.jal_lui.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32CondRdWriteAdapterCols<F> = adapter_slice.borrow();
        let needs_write = beak_cols.needs_write.as_canonical_u32() == 1;
        let rd_ptr = beak_cols.inner.rd_ptr.as_canonical_u32();
        let from_pc = beak_cols.inner.from_state.pc.as_canonical_u32();
        let opcode = if beak_record_is_jal {
            Rv32JalLuiOpcode::JAL
        } else {
            Rv32JalLuiOpcode::LUI
        };
        let imm = beak_record_imm;

        let to_pc = if beak_record_is_jal {
            from_pc.wrapping_add(imm)
        } else {
            from_pc.wrapping_add(DEFAULT_PC_STEP)
        };

        fuzzer_utils::emit_jal_lui_chip_row(
            opcode as u32,
            rd_ptr,
            imm,
            needs_write,
            from_pc,
            to_pc,
            beak_record_rd_data,
            beak_record_is_jal,
        );
        // BEAK-INSERT-END
""",
        ),
        (
            base / "jalr" / "core.rs",
            "use crate::adapters::Rv32JalrAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.jalr.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.jalr.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32JalrAdapterCols<F> = adapter_slice.borrow();

        let needs_write = beak_cols.needs_write.as_canonical_u32() == 1;
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let from_pc = beak_cols.from_state.pc.as_canonical_u32();

        let imm_u16 = beak_record_imm;
        // Sign-extend 16-bit immediate into i32 using the explicit sign flag.
        let imm_i32: i32 = (imm_u16 as i32) - ((beak_record_imm_sign as i32) << 16);

        // Executor clears the least-significant bit of to_pc for control-flow.
        let target_before_lsb_clear = beak_record_rs1_val.wrapping_add(imm_i32 as u32);
        let to_pc_final = to_pc & !1;

        fuzzer_utils::emit_jalr_chip_row(
            Rv32JalrOpcode::JALR as u32,
            rd_ptr,
            rs1_ptr,
            imm_i32,
            beak_record_imm_sign,
            needs_write,
            from_pc,
            to_pc_final,
            beak_record_rs1_val,
            target_before_lsb_clear,
            rd_data,
        );
        // BEAK-INSERT-END
""",
        ),
        (
            base / "auipc" / "core.rs",
            "use crate::adapters::Rv32RdWriteAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.auipc.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.auipc.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32RdWriteAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        fuzzer_utils::emit_auipc_chip_row(0, rd_ptr, beak_record_imm, beak_record_from_pc, rd_data);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "loadstore" / "core.rs",
            "use crate::adapters::Rv32LoadStoreAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.loadstore.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.loadstore.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32LoadStoreAdapterCols<F> = adapter_slice.borrow();

        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rd_rs2_ptr = beak_cols.rd_rs2_ptr.as_canonical_u32();

        let imm_sign = beak_cols.imm_sign.as_canonical_u32() == 1;
        // Adapter stores imm split as (low 16 bits, sign flag).
        let imm_i32: i32 =
            (beak_cols.imm.as_canonical_u32() as i32) - ((imm_sign as i32) << 16);

        let mem_as = beak_cols.mem_as.as_canonical_u32();
        let mem_ptr_limbs = beak_cols.mem_ptr_limbs.map(|x| x.as_canonical_u32());
        let effective_ptr = mem_ptr_limbs[0] + (mem_ptr_limbs[1] << 16);

        let needs_write = beak_cols.needs_write.as_canonical_u32() == 1;
        let is_load = [LOADW, LOADHU, LOADBU].contains(&opcode);
        let is_store = matches!(opcode, STOREW | STOREH | STOREB);
        let flags_u32 = core_row.flags.map(|x| x.as_canonical_u32());

        fuzzer_utils::emit_load_store_chip_row(
            opcode as u32,
            rs1_ptr,
            rd_rs2_ptr,
            imm_i32,
            imm_sign,
            mem_as,
            effective_ptr,
            is_store,
            needs_write,
            is_load,
            flags_u32,
            beak_record_read_data,
            beak_record_prev_data,
            write_data,
        );
        // BEAK-INSERT-END
""",
        ),
        (
            base / "load_sign_extend" / "core.rs",
            "use crate::adapters::Rv32LoadStoreAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.load_sign_extend.emit",
            r"""

        // BEAK-INSERT: guard.rv32im.load_sign_extend.emit
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32LoadStoreAdapterCols<F> = adapter_slice.borrow();

        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        // LoadStore adapter uses a unified pointer: rd for loads, rs2 for stores.
        let rd_ptr = beak_cols.rd_rs2_ptr.as_canonical_u32();

        let imm_sign = beak_cols.imm_sign.as_canonical_u32() == 1;
        // Adapter stores imm split as (low 16 bits, sign flag).
        let imm_i32: i32 =
            (beak_cols.imm.as_canonical_u32() as i32) - ((imm_sign as i32) << 16);

        let mem_as = beak_cols.mem_as.as_canonical_u32();
        let mem_ptr_limbs = beak_cols.mem_ptr_limbs.map(|x| x.as_canonical_u32());
        let effective_ptr = mem_ptr_limbs[0] + (mem_ptr_limbs[1] << 16);

        let needs_write = beak_cols.needs_write.as_canonical_u32() == 1;

        let opcode = if beak_record_is_byte { Rv32LoadStoreOpcode::LOADB } else { Rv32LoadStoreOpcode::LOADH };

        let mut shifted_read_data = beak_record_read_data;
        shifted_read_data.rotate_left((shift & 2) as usize);

        fuzzer_utils::emit_load_sign_extend_chip_row(
            opcode as u32,
            rs1_ptr,
            rd_ptr,
            imm_i32,
            imm_sign,
            mem_as,
            effective_ptr,
            needs_write,
            beak_record_prev_data,
            shifted_read_data,
            most_sig_bit != 0,
            shift & 2 == 2,
            !beak_record_is_byte,
            beak_record_is_byte && ((shift & 1) == 1),
            beak_record_is_byte && ((shift & 1) == 0),
        );
        // BEAK-INSERT-END
""",
        ),
    ]

    record_copy_blocks: list[tuple[Path, str, str]] = [
        (
            base / "base_alu" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.base_alu.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.base_alu.record_copy
        let beak_record_b = record.b;
        let beak_record_c = record.c;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "shift" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.shift.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.shift.record_copy
        let beak_record_b = record.b;
        let beak_record_c = record.c;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "less_than" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.less_than.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.less_than.record_copy
        let beak_record_local_opcode = record.local_opcode;
        let beak_record_b = record.b;
        let beak_record_c = record.c;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "mul" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.mul.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.mul.record_copy
        let beak_record_b = record.b;
        let beak_record_c = record.c;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "mulh" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.mulh.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.mulh.record_copy
        let beak_record_b = record.b;
        let beak_record_c = record.c;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "divrem" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.divrem.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.divrem.record_copy
        let beak_record_b = record.b;
        let beak_record_c = record.c;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "branch_eq" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.branch_eq.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.branch_eq.record_copy
        let beak_record_local_opcode = record.local_opcode;
        let beak_record_imm = record.imm;
        let beak_record_a = record.a;
        let beak_record_b = record.b;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "branch_lt" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.branch_lt.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.branch_lt.record_copy
        let beak_record_local_opcode = record.local_opcode;
        let beak_record_imm = record.imm;
        let beak_record_a = record.a;
        let beak_record_b = record.b;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "jal_lui" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.jal_lui.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.jal_lui.record_copy
        let beak_record_is_jal = record.is_jal;
        let beak_record_imm = record.imm;
        let beak_record_rd_data = record.rd_data;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "jalr" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.jalr.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.jalr.record_copy
        let beak_record_imm = record.imm;
        let beak_record_imm_sign = record.imm_sign;
        let beak_record_rs1_val = record.rs1_val;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "auipc" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.auipc.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.auipc.record_copy
        let beak_record_imm = record.imm;
        let beak_record_from_pc = record.from_pc;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "loadstore" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.loadstore.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.loadstore.record_copy
        let beak_record_read_data = record.read_data;
        let beak_record_prev_data = record.prev_data;
        // BEAK-INSERT-END
""",
        ),
        (
            base / "load_sign_extend" / "core.rs",
            "// BEAK-INSERT: guard.rv32im.load_sign_extend.record_copy",
            r"""
        // BEAK-INSERT: guard.rv32im.load_sign_extend.record_copy
        let beak_record_is_byte = record.is_byte;
        let beak_record_read_data = record.read_data;
        let beak_record_prev_data = record.prev_data;
        // BEAK-INSERT-END
""",
        ),
    ]

    for p, guard, block in record_copy_blocks:
        if not p.exists():
            continue
        c = p.read_text()
        try:
            c = _insert_before(c, anchor="        let core_row: &mut", insert=block, guard=guard)
        except RuntimeError:
            continue
        p.write_text(c)

    for p, import_line, guard, block in targets:
        if not p.exists():
            continue
        _ensure_use_fuzzer_utils(p)
        _ensure_import_after_fuzzer_utils(p, import_line)
        c = p.read_text()
        try:
            c = _insert_before_fn_close(c, fn_name="fill_trace_row", insert=block, guard=guard)
        except RuntimeError:
            # Some snapshots (e.g., audit commits) changed filler function names/layout.
            # Keep install best-effort: skip this target instead of failing whole pass.
            continue
        p.write_text(c)


def _patch_regzero_system_connector_emit_chip_row(
    openvm_install_path: Path, *, program_row_slice_returns_option: bool = False
) -> None:
    # connector/mod.rs
    connector = openvm_install_path / "crates" / "vm" / "src" / "system" / "connector" / "mod.rs"
    if connector.exists():
        _ensure_use_fuzzer_utils(connector)
        c = connector.read_text()
        try:
            c = _insert_before(
                c,
                anchor="let [initial_state, final_state] =",
                guard="// BEAK-INSERT: guard.system.connector_chip_row",
                insert=r"""
        // BEAK-INSERT: guard.system.connector_chip_row
        // BEAK-INSERT: Emit chip-row micro-op.
        let [begin_u32, end_u32] = self.boundary_states.map(|state| state.unwrap());
        let is_terminate = end_u32.is_terminate == 1;
        let exit_code = if is_terminate { Some(end_u32.exit_code) } else { None };
        fuzzer_utils::emit_connector_chip_row(
            begin_u32.pc,
            end_u32.pc,
            Some(begin_u32.timestamp),
            Some(end_u32.timestamp),
            is_terminate,
            exit_code,
        );
        // BEAK-INSERT-END
""",
            )
        except RuntimeError:
            pass
        connector.write_text(c)

    # phantom/mod.rs
    phantom = openvm_install_path / "crates" / "vm" / "src" / "system" / "phantom" / "mod.rs"
    if phantom.exists():
        _ensure_use_fuzzer_utils(phantom)
        c = phantom.read_text()
        try:
            c = _insert_after(
                c,
                anchor="row.pc = F::from_canonical_u32(record.pc)",
                guard="// BEAK-INSERT: guard.system.phantom_chip_row",
                insert=r""";
        // BEAK-INSERT: guard.system.phantom_chip_row
        // BEAK-INSERT: Emit chip-row micro-op.
        fuzzer_utils::emit_phantom_chip_row();
        // BEAK-INSERT-END
""",
            )
        except RuntimeError:
            pass
        phantom.write_text(c)

    # program/trace.rs
    program = openvm_install_path / "crates" / "vm" / "src" / "system" / "program" / "trace.rs"
    if program.exists():
        _ensure_use_fuzzer_utils(program)
        c = program.read_text()
        row_slice_stmt = (
            "let Some(row) = cached.trace.row_slice(i) else { continue; };"
            if program_row_slice_returns_option
            else "let row = cached.trace.row_slice(i);"
        )
        try:
            c = _insert_after(
                c,
                anchor="assert!(self.filtered_exec_frequencies.len() <= cached.trace.height());",
                guard="// BEAK-INSERT: guard.system.program_chip_row",
                insert=r"""
        // BEAK-INSERT: guard.system.program_chip_row
        // BEAK-INSERT: Emit chip-row micro-op. Trace is BabyBear; reinterpret as &BabyBear and use as_canonical_u32().
        use p3_baby_bear::BabyBear;
        for (i, freq) in self.filtered_exec_frequencies.iter().copied().enumerate() {
            if freq == 0 {
                continue;
            }
            // ProgramExecutionCols: [pc, opcode, a, b, c, d, e, f, g]
            __BEAK_PROGRAM_ROW_SLICE_STMT__
            fuzzer_utils::fuzzer_assert_eq!(std::mem::size_of_val(&row[0]), std::mem::size_of::<BabyBear>());
            fuzzer_utils::fuzzer_assert_eq!(std::mem::align_of_val(&row[0]), std::mem::align_of::<BabyBear>());
            let as_babybear = |j: usize| -> &BabyBear { unsafe { &*(&row[j] as *const _ as *const BabyBear) } };
            let opcode_u32 = as_babybear(1).as_canonical_u32();
            let operands: [u32; 7] = [
                as_babybear(2).as_canonical_u32(),
                as_babybear(3).as_canonical_u32(),
                as_babybear(4).as_canonical_u32(),
                as_babybear(5).as_canonical_u32(),
                as_babybear(6).as_canonical_u32(),
                as_babybear(7).as_canonical_u32(),
                as_babybear(8).as_canonical_u32(),
            ];
            fuzzer_utils::emit_program_chip_row(opcode_u32, operands, freq);
        }
        // BEAK-INSERT-END
""".replace("__BEAK_PROGRAM_ROW_SLICE_STMT__", row_slice_stmt),
            )
        except RuntimeError:
            pass
        program.write_text(c)


def _patch_336f_program_trace_semantic_injection(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'program' / 'trace.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '    rows.par_chunks_mut(width)\n        .zip(instructions)\n        .for_each(|(row, (pc, instruction))| {\n            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();\n            *row = ProgramExecutionCols {\n                pc: F::from_canonical_u32(pc),\n                opcode: instruction.opcode.to_field(),\n                a: instruction.a,\n                b: instruction.b,\n                c: instruction.c,\n                d: instruction.d,\n                e: instruction.e,\n                f: instruction.f,\n                g: instruction.g,\n            };\n        });\n'
    new = '    rows.par_chunks_mut(width)\n        .zip(instructions.into_par_iter().enumerate())\n        .for_each(|(row, (i, (pc, instruction)))| {\n            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();\n            *row = ProgramExecutionCols {\n                pc: F::from_canonical_u32(pc),\n                opcode: instruction.opcode.to_field(),\n                a: instruction.a,\n                b: instruction.b,\n                c: instruction.c,\n                d: instruction.d,\n                e: instruction.e,\n                f: instruction.f,\n                g: instruction.g,\n            };\n\n            // BEAK-INSERT: guard.336f.program_trace.semantic_injection\n            let beak_program_step = i as u64;\n            if fuzzer_utils::witness_injection_enabled_at(\n                "openvm.semantic.decode.zero_register_immutability",\n                beak_program_step,\n            ) && fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.zero_register_immutability",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.zero_register_immutability step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.a += F::from_canonical_u32(1);\n            }\n            if fuzzer_utils::witness_injection_enabled_at(\n                "openvm.semantic.decode.operand_index_routing",\n                beak_program_step,\n            ) && fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.operand_index_routing",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.operand_index_routing step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.b += F::from_canonical_u32(1);\n            }\n            if fuzzer_utils::witness_injection_enabled_at(\n                "openvm.semantic.decode.format_immediate_reassembly",\n                beak_program_step,\n            ) && fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.format_immediate_reassembly",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.format_immediate_reassembly step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.c += F::from_canonical_u32(1);\n            }\n            let beak_terminate_opcode: F = SystemOpcode::TERMINATE.global_opcode().to_field();\n            if row.opcode == beak_terminate_opcode\n                && fuzzer_utils::witness_injection_enabled_at(\n                    "openvm.semantic.control.ecall_word_validity",\n                    beak_program_step,\n                )\n                && fuzzer_utils::should_inject_witness(\n                    "openvm.semantic.control.ecall_word_validity",\n                    beak_program_step,\n                )\n            {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.control.ecall_word_validity step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.opcode += F::from_canonical_u32(1);\n            }\n            // BEAK-INSERT-END\n        });\n'
    if '// BEAK-INSERT: guard.336f.program_trace.semantic_injection' not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_regzero_program_trace_zero_register_injection(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'program' / 'trace.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '    rows.par_chunks_mut(width)\n        .zip(instructions)\n        .for_each(|(row, (pc, instruction))| {\n            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();\n            *row = ProgramExecutionCols {\n                pc: F::from_canonical_u32(pc),\n                opcode: instruction.opcode.to_field(),\n                a: instruction.a,\n                b: instruction.b,\n                c: instruction.c,\n                d: instruction.d,\n                e: instruction.e,\n                f: instruction.f,\n                g: instruction.g,\n            };\n        });\n'
    new = '    rows.par_chunks_mut(width)\n        .zip(instructions.into_par_iter().enumerate())\n        .for_each(|(row, (i, (pc, instruction)))| {\n            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();\n            *row = ProgramExecutionCols {\n                pc: F::from_canonical_u32(pc),\n                opcode: instruction.opcode.to_field(),\n                a: instruction.a,\n                b: instruction.b,\n                c: instruction.c,\n                d: instruction.d,\n                e: instruction.e,\n                f: instruction.f,\n                g: instruction.g,\n            };\n\n            // BEAK-INSERT: guard.regzero.program_trace.zero_register_immutability\n            let beak_program_step = i as u64;\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.zero_register_immutability",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.zero_register_immutability step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.a += F::from_canonical_u32(1);\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.operand_index_routing",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.operand_index_routing step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.b += F::from_canonical_u32(1);\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.exec.dest_binding",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.exec.dest_binding step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.a += F::from_canonical_u32(1);\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.field_range",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.field_range step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.a += F::from_canonical_u32(32);\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.immediate_sign_extension",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.immediate_sign_extension step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.c += F::from_canonical_u32(1);\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.upper_immediate_materialization",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.upper_immediate_materialization step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.c += F::from_canonical_u32(1);\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.exec.op_selector_binding",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.exec.op_selector_binding step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.opcode += F::from_canonical_u32(1);\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.format_immediate_reassembly",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.format_immediate_reassembly step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.c += F::from_canonical_u32(1);\n            }\n            // BEAK-INSERT-END\n        });\n'
    if '// BEAK-INSERT: guard.regzero.program_trace.zero_register_immutability' not in c and old in c:
        c = c.replace(old, new, 1)
    old_bf11 = '    rows.par_chunks_mut(width)\n        .zip(instructions)\n        .for_each(|(row, (pc, instruction))| {\n            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();\n            *row = ProgramExecutionCols {\n                pc: F::from_u32(pc),\n                opcode: instruction.opcode.to_field(),\n                a: instruction.a,\n                b: instruction.b,\n                c: instruction.c,\n                d: instruction.d,\n                e: instruction.e,\n                f: instruction.f,\n                g: instruction.g,\n            };\n        });\n'
    new_bf11 = '    rows.par_chunks_mut(width)\n        .zip(instructions.into_par_iter().enumerate())\n        .for_each(|(row, (i, (pc, instruction)))| {\n            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();\n            *row = ProgramExecutionCols {\n                pc: F::from_u32(pc),\n                opcode: instruction.opcode.to_field(),\n                a: instruction.a,\n                b: instruction.b,\n                c: instruction.c,\n                d: instruction.d,\n                e: instruction.e,\n                f: instruction.f,\n                g: instruction.g,\n            };\n\n            // BEAK-INSERT: guard.regzero.program_trace.zero_register_immutability\n            let beak_program_step = i as u64;\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.zero_register_immutability",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.zero_register_immutability step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.a += F::ONE;\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.operand_index_routing",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.operand_index_routing step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.b += F::ONE;\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.exec.dest_binding",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.exec.dest_binding step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.a += F::ONE;\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.field_range",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.field_range step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.a += F::from_u32(32);\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.immediate_sign_extension",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.immediate_sign_extension step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.c += F::ONE;\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.upper_immediate_materialization",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.upper_immediate_materialization step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.c += F::ONE;\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.exec.op_selector_binding",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.exec.op_selector_binding step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.opcode += F::ONE;\n            }\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.decode.format_immediate_reassembly",\n                beak_program_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.decode.format_immediate_reassembly step={} pc={}",\n                    beak_program_step,\n                    pc\n                );\n                row.c += F::ONE;\n            }\n            // BEAK-INSERT-END\n        });\n'
    if '// BEAK-INSERT: guard.regzero.program_trace.zero_register_immutability' not in c and old_bf11 in c:
        c = c.replace(old_bf11, new_bf11, 1)
    path.write_text(c)


def _patch_336f_bitwise_lookup_serde_json_dep(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'circuits' / 'primitives' / 'Cargo.toml'
    if not path.exists():
        return None
    c = path.read_text()
    if 'serde_json.workspace = true' in c:
        return None
    anchor = '[dependencies]\nfuzzer_utils.workspace = true\n'
    if anchor not in c:
        raise RuntimeError('bitwise primitives Cargo.toml dependency anchor missing')
    c = c.replace(anchor, anchor + 'serde_json.workspace = true\n', 1)
    path.write_text(c)


def _patch_336f_base_alu_field_consistent_run_add(openvm_install_path = None):
    path = openvm_install_path / 'extensions' / 'rv32im' / 'circuit' / 'src' / 'base_alu' / 'core.rs'
    if not path.exists():
        return None
    c = path.read_text()
    guard = 'Compute the carry chain in the BabyBear field'
    if guard in c:
        return None
    old = 'fn run_add<const NUM_LIMBS: usize, const LIMB_BITS: usize>(\n    x: &[u32; NUM_LIMBS],\n    y: &[u32; NUM_LIMBS],\n) -> [u32; NUM_LIMBS] {\n    let mut z = [0u32; NUM_LIMBS];\n    let mut carry = [0u32; NUM_LIMBS];\n    for i in 0..NUM_LIMBS {\n        z[i] = x[i] + y[i] + if i > 0 { carry[i - 1] } else { 0 };\n        carry[i] = z[i] >> LIMB_BITS;\n        z[i] &= (1 << LIMB_BITS) - 1;\n    }\n    z\n}'
    new = "fn run_add<const NUM_LIMBS: usize, const LIMB_BITS: usize>(\n    x: &[u32; NUM_LIMBS],\n    y: &[u32; NUM_LIMBS],\n) -> [u32; NUM_LIMBS] {\n    // Compute the carry chain in the BabyBear field so non-canonical operand\n    // limbs (e.g. alternative immediate encodings the ALU chip does not\n    // range-check) reduce exactly the way the AIR's per-limb constraints see\n    // them. For canonical limbs the modulus never triggers, so honest traces\n    // are unchanged.\n    const MODULUS: u64 = 2_013_265_921;\n    let mut z = [0u32; NUM_LIMBS];\n    let mut carry = 0u64;\n    for i in 0..NUM_LIMBS {\n        let t = (x[i] as u64 + y[i] as u64 + carry) % MODULUS;\n        z[i] = (t % (1 << LIMB_BITS)) as u32;\n        carry = (t - z[i] as u64) >> LIMB_BITS;\n    }\n    z\n}"
    if old not in c:
        raise RuntimeError('run_add anchor missing in base_alu/core.rs')
    c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_witness_step_from_pc(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'arch' / 'integration_api.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    guard = 'deterministic witness step = executed instruction index'
    if guard in c:
        return None
    anchor = '        let (reads, read_record) = self.adapter.preprocess(memory, instruction)?;'
    insert = '        // BEAK-INSERT: deterministic witness step = executed instruction index so\n        // per-row hooks align exactly with backend candidate anchors.\n        fuzzer_utils::set_witness_step(u64::from(from_state.pc) / 4);\n'
    if anchor not in c:
        raise RuntimeError('witness-step-from-pc anchor missing in integration_api.rs')
    c = c.replace(anchor, insert + anchor, 1)
    path.write_text(c)


def _patch_336f_base_alu_padding_interaction_injection(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'arch' / 'integration_api.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    anchor = '        let mut trace = RowMajorMatrix::new(values, width);\n'
    insert = '        // BEAK-INSERT: guard.336f.base_alu.padding_interaction_send\n        let beak_adapter_name = get_air_name(self.adapter.air());\n        let beak_core_name = get_air_name(self.core.air());\n        if height > num_records\n            && beak_adapter_name.contains("Rv32BaseAluAdapterAir")\n            && beak_core_name.contains("BaseAluCoreAir")\n        {\n            let beak_padding_step = num_records as u64;\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.row.padding_interaction_send",\n                beak_padding_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.row.padding_interaction_send step={} site=base_alu_padding_row row_idx={} real_rows={} height={}",\n                    beak_padding_step,\n                    num_records,\n                    num_records,\n                    height\n                );\n                let beak_target = std::env::var("BEAK_OPENVM_PADDING_INTERACTION_TARGET")\n                    .ok()\n                    .and_then(|raw| {\n                        let parts = raw\n                            .split(\',\')\n                            .filter_map(|part| part.parse::<u32>().ok())\n                            .collect::<Vec<_>>();\n                        (parts.len() >= 7).then(|| {\n                            (\n                                parts[0],\n                                parts[1],\n                                parts[2],\n                                [parts[3], parts[4], parts[5], parts[6]],\n                            )\n                        })\n                    })\n                    .unwrap_or((1, 0, 0, [0, 0, 0, 0]));\n                let (\n                    beak_target_as,\n                    beak_target_pointer,\n                    beak_prev_timestamp,\n                    beak_target_data,\n                ) = beak_target;\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.row.padding_interaction_send site=base_alu_padding_target address_space={} pointer={} prev_timestamp={} data={:?}",\n                    beak_target_as,\n                    beak_target_pointer,\n                    beak_prev_timestamp,\n                    beak_target_data\n                );\n                let beak_row_start = num_records * width;\n                // Rv32BaseAluAdapterCols layout:\n                // from_state(pc,timestamp), rd_ptr, rs1_ptr, rs2, rs2_as, reads_aux...\n                let beak_from_timestamp_offset = 1usize;\n                let beak_rs2_offset = 4usize;\n                let beak_rs2_as_offset = 5usize;\n                let beak_rs2_prev_timestamp_offset = 9usize;\n                // BaseAluCoreCols layout: a[4], b[4], c[4], flags[5].\n                let beak_core_c_offset = adapter_width + 8usize;\n                if beak_row_start + beak_core_c_offset + 3 < values.len() {\n                    values[beak_row_start + beak_from_timestamp_offset] =\n                        Val::<SC>::from_canonical_u32(beak_prev_timestamp);\n                    values[beak_row_start + beak_rs2_offset] =\n                        Val::<SC>::from_canonical_u32(beak_target_pointer);\n                    values[beak_row_start + beak_rs2_as_offset] =\n                        Val::<SC>::from_canonical_u32(beak_target_as);\n                    values[beak_row_start + beak_rs2_prev_timestamp_offset] =\n                        Val::<SC>::from_canonical_u32(beak_prev_timestamp);\n                    for (i, limb) in beak_target_data.into_iter().enumerate() {\n                        values[beak_row_start + beak_core_c_offset + i] =\n                            Val::<SC>::from_canonical_u32(limb);\n                    }\n                    fuzzer_utils::record_semantic_mutation(\n                        "openvm.semantic.row.padding_interaction_send",\n                        "rv32_base_alu.padding_row",\n                        "memory_interaction_send",\n                        beak_padding_step,\n                        serde_json::json!({"is_padding": true, "send": null}),\n                        serde_json::json!({\n                            "is_padding": true,\n                            "address_space": beak_target_as,\n                            "pointer": beak_target_pointer,\n                            "timestamp": beak_prev_timestamp,\n                            "data": beak_target_data\n                        }),\n                        serde_json::json!({\n                            "relation": "padding_interaction_send",\n                            "context": {\n                                "cell_id": "pd1.exec_padding",\n                                "is_padding": true,\n                                "interaction_kind": "memory_read"\n                            }\n                        }),\n                    );\n                }\n            }\n        }\n        // BEAK-INSERT-END\n\n'
    if '// BEAK-INSERT: guard.336f.base_alu.padding_interaction_send' not in c and anchor in c:
        c = c.replace(anchor, insert + anchor, 1)
    path.write_text(c)


def _patch_336f_base_alu_adapter_emit_chip_row(openvm_install_path: Path) -> None:
    """
    Audit snapshots (336f/f038) use adapter-level `generate_trace_row` instead of many core-level
    `fill_trace_row` hooks. Inject a concrete chip-row emission for BaseALU at adapter layer.
    """
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "adapters"
        / "alu.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    try:
        c = _insert_after(
            c,
            anchor='let rs1 = memory.read::<RV32_REGISTER_NUM_LIMBS>(d, b);',
            guard='// BEAK-INSERT: guard.336f.adapter.base_alu.preprocess_step',
            insert='\n\n        // BEAK-INSERT: guard.336f.adapter.base_alu.preprocess_step\n        // BEAK-INSERT: deterministic per-row witness-step counter for targeted loop2 injection.\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        // BEAK-INSERT-END\n',
        )
    except RuntimeError:
        pass
    old_imm_block = '        let (rs2, rs2_data, rs2_imm) = if e.is_zero() {\n            let c_u32 = c.as_canonical_u32();\n            fuzzer_utils::fuzzer_assert_eq!(c_u32 >> 24, 0);\n            memory.increment_timestamp();\n            (\n                None,\n                [\n                    c_u32 as u8,\n                    (c_u32 >> 8) as u8,\n                    (c_u32 >> 16) as u8,\n                    (c_u32 >> 16) as u8,\n                ]\n                .map(F::from_canonical_u8),\n                c,\n            )\n        } else {\n'
    new_imm_block = '        let (rs2, rs2_data, rs2_imm) = if e.is_zero() {\n            let c_u32 = c.as_canonical_u32();\n            fuzzer_utils::fuzzer_assert_eq!(c_u32 >> 24, 0);\n            memory.increment_timestamp();\n            let mut beak_rs2_data = [\n                c_u32 as u8,\n                (c_u32 >> 8) as u8,\n                (c_u32 >> 16) as u8,\n                (c_u32 >> 16) as u8,\n            ]\n            .map(F::from_canonical_u8);\n\n            // BEAK-INSERT: guard.336f.adapter.base_alu.preprocess_o5\n            // BEAK-INSERT: witness-only injection for immediate limb decomposition.\n            // Move one radix-256 unit from limb[1] to limb[0] in BabyBear. The exact\n            // variant is parsed before should_inject_witness, so malformed or base-only\n            // caller input cannot be marked applied.\n            let beak_o5_variant = fuzzer_utils::active_witness_variant(\n                "openvm.semantic.alu.immediate_limb_consistency",\n            );\n            let beak_o5_variant_valid = beak_o5_variant.as_deref()\n                == Some("mode=adjacent_radix_carry,carry_slot=0,borrow_slot=1,radix=256,field_modulus=2013265921,limb_count=4");\n            if beak_o5_variant_valid\n                && fuzzer_utils::should_inject_witness("openvm.semantic.alu.immediate_limb_consistency", beak_witness_step)\n            {\n                let beak_before = beak_rs2_data.map(|limb| limb.as_canonical_u32());\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.alu.immediate_limb_consistency step={} c_u32={}",\n                    beak_witness_step,\n                    c_u32\n                );\n                // Move one radix-256 unit from limb[1] to limb[0] in BabyBear.\n                // The recomposition is preserved in the field (limb0 + 256,\n                // limb1 - 1), so the row stays architecturally consistent while\n                // limb0 leaves the byte range the chip forgot to constrain.\n                beak_rs2_data[0] += F::from_canonical_u32(1 << 8);\n                beak_rs2_data[1] -= F::ONE;\n                let beak_after = beak_rs2_data.map(|limb| limb.as_canonical_u32());\n                fuzzer_utils::record_semantic_mutation(\n                    "openvm.semantic.alu.immediate_limb_consistency",\n                    "rv32_base_alu_adapter.preprocess",\n                    "rs2_data_limbs",\n                    beak_witness_step,\n                    serde_json::json!(beak_before),\n                    serde_json::json!(beak_after),\n                    serde_json::json!({\n                        "relation": "full_limb_value_representation",\n                        "preserved_before": c_u32,\n                        "preserved_after": c_u32,\n                        "context": {\n                            "bucket_id": "sem.alu.immediate_limb_consistency",\n                            "cell_id": if matches!(c_u32 as i32, 255 | 256 | -1 | -2048 | 2047) { "al1.boundary" } else if (c_u32 as i32) < 0 { "al1.negative" } else if c_u32 <= 255 { "al1.single_limb" } else { "al1.cross_01" },\n                            "executed_instruction": true,\n                            "op_idx": beak_witness_step,\n                            "mode": "adjacent_radix_carry",\n                            "carry_slot": 0,\n                            "borrow_slot": 1,\n                            "radix": 256,\n                            "field_modulus": 2013265921u64,\n                            "limb_count": 4,\n                            "value": c_u32,\n                            "before_limbs": beak_before,\n                            "after_limbs": beak_after,\n                            "recomposed_before": c_u32,\n                            "recomposed_after": c_u32\n                        }\n                    }),\n                );\n            }\n            // BEAK-INSERT-END\n\n            (None, beak_rs2_data, c)\n        } else {\n'
    o5_guard = '// BEAK-INSERT: guard.336f.adapter.base_alu.preprocess_o5'
    c = _refresh_guarded_block(c, template=new_imm_block, guard=o5_guard)
    if o5_guard not in c and old_imm_block in c:
        c = c.replace(old_imm_block, new_imm_block, 1)
    try:
        c = _insert_before_fn_close(
            c,
            fn_name='generate_trace_row',
            guard='// BEAK-INSERT: guard.336f.adapter.base_alu.emit_chip_row',
            insert='\n\n        // BEAK-INSERT: guard.336f.adapter.base_alu.emit_chip_row\n        // BEAK-INSERT: Emit base_alu chip-row micro-op from adapter-layer row.\n        let rd_ptr = row_slice.rd_ptr.as_canonical_u32();\n        let rs1_ptr = row_slice.rs1_ptr.as_canonical_u32();\n        let is_rs2_imm = row_slice.rs2_as.as_canonical_u32() == 0;\n        let rs2_i32 = row_slice.rs2.as_canonical_u32() as i32;\n\n        // Adapter reads/writes are 4-limb values in this snapshot.\n        let a_u8: [u8; 4] = write_record.rd.1.map(|x| x.as_canonical_u32() as u8);\n        let b_u8: [u8; 4] = core::array::from_fn(|i| rs1.data_at(i).as_canonical_u32() as u8);\n        let c_u8: [u8; 4] = if read_record.rs2.is_none() {\n            let imm_u32 = read_record.rs2_imm.as_canonical_u32();\n            [\n                (imm_u32 & 0xff) as u8,\n                ((imm_u32 >> 8) & 0xff) as u8,\n                ((imm_u32 >> 16) & 0xff) as u8,\n                ((imm_u32 >> 24) & 0xff) as u8,\n            ]\n        } else {\n            let rs2 = rs2.expect("rs2 record must exist when rs2 is not immediate");\n            core::array::from_fn(|i| rs2.data_at(i).as_canonical_u32() as u8)\n        };\n\n        // Opcode-local value is not present in adapter record here; keep 0 as placeholder.\n        fuzzer_utils::emit_base_alu_chip_row(0, rd_ptr, rs1_ptr, rs2_i32, is_rs2_imm, a_u8, b_u8, c_u8);\n        // BEAK-INSERT-END\n',
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_auipc_core_emit_chip_row(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "auipc"
        / "core.rs"
    )
    if not path.exists():
        return
    c = path.read_text()
    try:
        c = _insert_before(
            c,
            anchor="        let output = AdapterRuntimeContext::without_pc([rd_data_field]);",
            guard="// BEAK-INSERT: guard.336f.auipc.core.emit_chip_row",
            insert=r"""
        // BEAK-INSERT: guard.336f.auipc.core.emit_chip_row
        // BEAK-INSERT: Emit AUIPC chip-row micro-op from core execution.
        let rd_ptr = instruction.a.as_canonical_u32();
        let rd_data_u8: [u8; RV32_REGISTER_NUM_LIMBS] = rd_data.map(|x| x as u8);
        fuzzer_utils::emit_auipc_chip_row(
            local_opcode as u32,
            rd_ptr,
            imm,
            from_pc,
            rd_data_u8,
        );
        // BEAK-INSERT-END
""",
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_loadstore_core_emit_chip_row(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "loadstore"
        / "core.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    try:
        c = _insert_before(
            c,
            anchor="        let output = AdapterRuntimeContext::without_pc([write_data]);",
            guard="// BEAK-INSERT: guard.336f.loadstore.core.emit_chip_row",
            insert=r"""
        // BEAK-INSERT: guard.336f.loadstore.core.emit_chip_row
        // BEAK-INSERT: Emit LoadStore chip-row micro-op from core execution.
        let rs1_ptr = instruction.b.as_canonical_u32();
        let rd_rs2_ptr = instruction.a.as_canonical_u32();
        let imm_u32 = instruction.c.as_canonical_u32();
        let imm_sign = ((imm_u32 & 0x8000) >> 15) == 1;
        let imm_i32: i32 = (imm_u32 as i32) - ((imm_sign as i32) << 16);
        let mem_as = instruction.e.as_canonical_u32();
        let opcode_u32 = local_opcode as u32;
        let is_load = matches!(local_opcode, LOADW | LOADH | LOADHU | LOADB | LOADBU);
        let is_store = matches!(local_opcode, STOREW | STOREH | STOREB);
        let needs_write = is_load;

        let mut flags_u32 = [0u32; 4];
        match (local_opcode, shift) {
            (LOADW, 0) => flags_u32[0] = 2,
            (LOADHU, 0) => flags_u32[1] = 2,
            (LOADHU, 2) => flags_u32[2] = 2,
            (LOADBU, 0) => flags_u32[3] = 2,
            (LOADBU, 1) => flags_u32[0] = 1,
            (LOADBU, 2) => flags_u32[1] = 1,
            (LOADBU, 3) => flags_u32[2] = 1,
            (STOREW, 0) => flags_u32[3] = 1,
            (STOREH, 0) => {
                flags_u32[0] = 1;
                flags_u32[1] = 1;
            }
            (STOREH, 2) => {
                flags_u32[0] = 1;
                flags_u32[2] = 1;
            }
            (STOREB, 0) => {
                flags_u32[0] = 1;
                flags_u32[3] = 1;
            }
            (STOREB, 1) => {
                flags_u32[1] = 1;
                flags_u32[2] = 1;
            }
            (STOREB, 2) => {
                flags_u32[1] = 1;
                flags_u32[3] = 1;
            }
            (STOREB, 3) => {
                flags_u32[2] = 1;
                flags_u32[3] = 1;
            }
            _ => {}
        }

        let read_data_u8: [u8; NUM_CELLS] = read_data.map(|x| x.as_canonical_u32() as u8);
        let prev_data_u32: [u32; NUM_CELLS] = prev_data.map(|x| x.as_canonical_u32());
        let write_data_u32: [u32; NUM_CELLS] = write_data.map(|x| x.as_canonical_u32());

        fuzzer_utils::emit_load_store_chip_row(
            opcode_u32,
            rs1_ptr,
            rd_rs2_ptr,
            imm_i32,
            imm_sign,
            mem_as,
            0u32,
            is_store,
            needs_write,
            is_load,
            flags_u32,
            read_data_u8,
            prev_data_u32,
            write_data_u32,
        );
        // BEAK-INSERT-END
""",
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_memory_access_emit_support(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'fuzzer_utils' / 'src' / 'lib.rs'
    if not path.exists():
        return None
    c = path.read_text()
    method_anchor = '    pub fn emit_memory_interaction(\n        &mut self,\n        direction: &str,\n        row_id: Option<&str>,\n        address_space: u32,\n        pointer: u32,\n        data: Vec<u32>,\n        timestamp: u32,\n    ) {\n        let payload_data = json!({\n            "address_space": address_space,\n            "pointer": pointer,\n            "data": data,\n            "timestamp": timestamp,\n        });\n        self.emit_interaction_envelope(\n            "memory",\n            direction,\n            row_id,\n            Some(timestamp),\n            "memory",\n            payload_data,\n        );\n    }\n'
    method_insert = method_anchor + '\n    pub fn emit_memory_access(\n        &mut self,\n        row_op_idx: u64,\n        opcode: u32,\n        rs1_ptr: u32,\n        rd_rs2_ptr: u32,\n        imm: i32,\n        imm_sign: bool,\n        address_space: u32,\n        raw_ptr: u32,\n        effective_ptr: u32,\n        aligned_ptr: u32,\n        byte_offset: u32,\n        width: u32,\n        is_load: bool,\n        is_store: bool,\n        needs_write: bool,\n        timestamp: u32,\n        read_data: Vec<u32>,\n        prev_data: Vec<u32>,\n        write_data: Vec<u32>,\n    ) {\n        let micro_op = json!({\n            "type": "memory_access",\n            "data": {\n                "seq": self.seq,\n                "step_idx": self.step_idx,\n                "op_idx": self.op_idx_in_step,\n                "row_op_idx": row_op_idx,\n                "opcode": opcode,\n                "rs1_ptr": rs1_ptr,\n                "rd_rs2_ptr": rd_rs2_ptr,\n                "imm": imm,\n                "imm_sign": imm_sign,\n                "address_space": address_space,\n                "raw_ptr": raw_ptr,\n                "effective_ptr": effective_ptr,\n                "aligned_ptr": aligned_ptr,\n                "byte_offset": byte_offset,\n                "width": width,\n                "is_load": is_load,\n                "is_store": is_store,\n                "needs_write": needs_write,\n                "timestamp": timestamp,\n                "read_data": read_data,\n                "prev_data": prev_data,\n                "write_data": write_data,\n            }\n        });\n        self.op_idx_in_step += 1;\n        self.emit_micro_op(micro_op);\n    }\n'
    if 'pub fn emit_memory_access(' not in c and method_anchor in c:
        c = c.replace(method_anchor, method_insert, 1)
    public_anchor = 'pub fn emit_memory_interaction(\n    direction: &str,\n    row_id: Option<&str>,\n    address_space: u32,\n    pointer: u32,\n    data: Vec<u32>,\n    timestamp: u32,\n) {\n    let mut state = GLOBAL_STATE.lock().unwrap();\n    state.emit_memory_interaction(direction, row_id, address_space, pointer, data, timestamp);\n}\n'
    public_insert = public_anchor + '\npub fn emit_memory_access(\n    row_op_idx: u64,\n    opcode: u32,\n    rs1_ptr: u32,\n    rd_rs2_ptr: u32,\n    imm: i32,\n    imm_sign: bool,\n    address_space: u32,\n    raw_ptr: u32,\n    effective_ptr: u32,\n    aligned_ptr: u32,\n    byte_offset: u32,\n    width: u32,\n    is_load: bool,\n    is_store: bool,\n    needs_write: bool,\n    timestamp: u32,\n    read_data: Vec<u32>,\n    prev_data: Vec<u32>,\n    write_data: Vec<u32>,\n) {\n    let mut state = GLOBAL_STATE.lock().unwrap();\n    state.emit_memory_access(\n        row_op_idx,\n        opcode,\n        rs1_ptr,\n        rd_rs2_ptr,\n        imm,\n        imm_sign,\n        address_space,\n        raw_ptr,\n        effective_ptr,\n        aligned_ptr,\n        byte_offset,\n        width,\n        is_load,\n        is_store,\n        needs_write,\n        timestamp,\n        read_data,\n        prev_data,\n        write_data,\n    );\n}\n'
    if 'pub fn emit_memory_access(\n    row_op_idx' not in c and public_anchor in c:
        c = c.replace(public_anchor, public_insert, 1)
    if '"write_data": write_data,' not in c and 'pub fn emit_memory_access(' in c:
        c = c.replace('        prev_data: Vec<u32>,\n    ) {\n', '        prev_data: Vec<u32>,\n        write_data: Vec<u32>,\n    ) {\n', 1)
        c = c.replace('                "prev_data": prev_data,\n', '                "prev_data": prev_data,\n                "write_data": write_data,\n', 1)
        c = c.replace('    prev_data: Vec<u32>,\n) {\n', '    prev_data: Vec<u32>,\n    write_data: Vec<u32>,\n) {\n', 1)
        c = c.replace('        prev_data,\n    );\n', '        prev_data,\n        write_data,\n    );\n', 1)
    path.write_text(c)


def _patch_336f_loadstore_core_witness_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "loadstore"
        / "core.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    try:
        c = _insert_after(
            c,
            anchor="        core_cols.write_data = record.write_data;",
            guard="// BEAK-INSERT: guard.336f.loadstore.core.witness_memory",
            insert='\n\n        // BEAK-INSERT: guard.336f.loadstore.core.witness_memory\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.value_payload_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.memory.value_payload_consistency step={}",\n                beak_witness_step\n            );\n            core_cols.write_data[0] += F::ONE;\n        }\n        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.store_load_payload_flow", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.memory.store_load_payload_flow step={}",\n                beak_witness_step\n            );\n            core_cols.write_data[0] += F::ONE;\n        }\n        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.kind_selector_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.memory.kind_selector_consistency step={}",\n                beak_witness_step\n            );\n            core_cols.is_load = F::ONE - core_cols.is_load;\n        }\n        // BEAK-INSERT-END\n',
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_memory_timestamp_aux_witness_injection(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'memory' / 'controller' / 'mod.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '    pub fn generate_base_aux(&self, record: &MemoryRecord<F>, buffer: &mut MemoryBaseAuxCols<F>) {\n        buffer.prev_timestamp = F::from_canonical_u32(record.prev_timestamp);\n        self.generate_timestamp_lt(\n            record.prev_timestamp,\n            record.timestamp,\n            &mut buffer.timestamp_lt_aux,\n        );\n    }\n'
    legacy = '    pub fn generate_base_aux(&self, record: &MemoryRecord<F>, buffer: &mut MemoryBaseAuxCols<F>) {\n        buffer.prev_timestamp = F::from_canonical_u32(record.prev_timestamp);\n        self.generate_timestamp_lt(\n            record.prev_timestamp,\n            record.timestamp,\n            &mut buffer.timestamp_lt_aux,\n        );\n\n        // BEAK-INSERT: guard.336f.memory.timestamp_aux\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.time.monotonic_access_ordering", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.time.monotonic_access_ordering step={} prev_timestamp={} timestamp={}",\n                beak_witness_step,\n                record.prev_timestamp,\n                record.timestamp\n            );\n            buffer.prev_timestamp = F::from_canonical_u32(record.timestamp);\n        }\n        // BEAK-INSERT-END\n    }\n'
    new = '    pub fn generate_base_aux(&self, record: &MemoryRecord<F>, buffer: &mut MemoryBaseAuxCols<F>) {\n        buffer.prev_timestamp = F::from_canonical_u32(record.prev_timestamp);\n        self.generate_timestamp_lt(\n            record.prev_timestamp,\n            record.timestamp,\n            &mut buffer.timestamp_lt_aux,\n        );\n\n        // BEAK-INSERT: guard.336f.memory.timestamp_aux\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::matching_injection_kind(\n            "openvm.semantic.time.monotonic_access_ordering",\n            beak_witness_step,\n        ).is_some() {\n            let beak_ts_diff = record.timestamp.wrapping_sub(record.prev_timestamp);\n            let beak_cell_id = fuzzer_utils::active_witness_variant(\n                "openvm.semantic.time.monotonic_access_ordering",\n            )\n            .and_then(|variant| variant.strip_prefix("cell_id=").map(str::to_owned));\n            let beak_cell_matches = match beak_cell_id.as_deref() {\n                Some("ts2.consecutive") => beak_ts_diff == 1,\n                Some("ts2.small_gap") => beak_ts_diff <= 16,\n                Some("ts2.large_gap") => beak_ts_diff >= 128,\n                _ => false,\n            };\n            if record.prev_timestamp < record.timestamp && beak_cell_matches {\n                let applied = fuzzer_utils::should_inject_witness(\n                    "openvm.semantic.time.monotonic_access_ordering",\n                    beak_witness_step,\n                );\n                debug_assert!(applied);\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.time.monotonic_access_ordering step={} prev_timestamp={} timestamp={} cell_id={}",\n                    beak_witness_step,\n                    record.prev_timestamp,\n                    record.timestamp,\n                    beak_cell_id.as_deref().unwrap()\n                );\n                buffer.prev_timestamp = F::from_canonical_u32(record.timestamp);\n                fuzzer_utils::record_semantic_mutation(\n                    "openvm.semantic.time.monotonic_access_ordering",\n                    "memory_controller.generate_base_aux",\n                    "prev_timestamp",\n                    beak_witness_step,\n                    serde_json::json!(record.prev_timestamp),\n                    serde_json::json!(record.timestamp),\n                    serde_json::json!({\n                        "relation": "witness_value_changed",\n                        "context": {\n                            "obligation_id": "ts2",\n                            "cell_id": beak_cell_id.unwrap(),\n                            "previous_timestamp": record.prev_timestamp,\n                            "timestamp": record.timestamp,\n                            "ts_diff": beak_ts_diff,\n                            "before_strictly_ordered": true,\n                            "after_strictly_ordered": false\n                        }\n                    }),\n                );\n            }\n        }\n        // BEAK-INSERT-END\n    }\n'
    if old in c:
        c = c.replace(old, new, 1)
    elif legacy in c:
        c = c.replace(legacy, new, 1)
    path.write_text(c)


def _patch_336f_memory_lifecycle_instrumentation(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'memory' / 'controller' / 'mod.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old_set = '    pub fn set_initial_memory(&mut self, memory: MemoryImage<F>) {\n        if self.timestamp() > INITIAL_TIMESTAMP + 1 {\n            panic!("Cannot set initial memory after first timestamp");\n        }\n        let mut offline_memory = self.offline_memory.lock().unwrap();\n        offline_memory.set_initial_memory(memory.clone(), self.mem_config);\n\n        self.memory = Memory::from_image(memory.clone(), self.mem_config.access_capacity);\n'
    new_set = '    pub fn set_initial_memory(&mut self, memory: MemoryImage<F>) {\n        if self.timestamp() > INITIAL_TIMESTAMP + 1 {\n            panic!("Cannot set initial memory after first timestamp");\n        }\n\n        // BEAK-INSERT: guard.336f.memory.lifecycle.initial\n        let beak_initial_cells: Vec<_> = memory\n            .items()\n            .filter_map(|((address_space, pointer), value)| {\n                let value = value.as_canonical_u32();\n                (value != 0).then_some(((address_space, pointer), value))\n            })\n            .collect();\n        for (beak_init_idx, ((address_space, pointer), value)) in\n            beak_initial_cells.into_iter().enumerate()\n        {\n            let beak_init_idx = beak_init_idx as u64;\n            fuzzer_utils::emit_memory_init(beak_init_idx, address_space, pointer, value);\n        }\n        // BEAK-INSERT-END\n\n        let mut offline_memory = self.offline_memory.lock().unwrap();\n        offline_memory.set_initial_memory(memory.clone(), self.mem_config);\n\n        self.memory = Memory::from_image(memory.clone(), self.mem_config.access_capacity);\n'
    if '// BEAK-INSERT: guard.336f.memory.lifecycle.initial' not in c and old_set in c:
        c = c.replace(old_set, new_set, 1)
    old_final = '                let (final_partition, records) = offline_memory.finalize::<CHUNK>();\n                self.access_adapters.extend_records(records);\n\n                boundary_chip.finalize(initial_memory, &final_partition, hasher);\n                let final_memory_values = final_partition\n'
    new_final = '                let (mut final_partition, mut records) = offline_memory.finalize::<CHUNK>();\n\n                // BEAK-INSERT: guard.336f.base_alu.padding_interaction_send.final_merge\n                if fuzzer_utils::witness_injection_enabled_for(\n                    "openvm.semantic.row.padding_interaction_send",\n                ) {\n                    for record in records.iter_mut() {\n                        let address_space = record.address_space.as_canonical_u32();\n                        let pointer = record.start_index.as_canonical_u32();\n                        if address_space != 1 || pointer % CHUNK as u32 != 0 || record.data.len() != CHUNK {\n                            continue;\n                        }\n                        if let crate::system::memory::adapter::AccessAdapterRecordKind::Merge {\n                            left_timestamp,\n                            right_timestamp,\n                        } = &mut record.kind\n                        {\n                            let old_left_timestamp = *left_timestamp;\n                            let new_left_timestamp = old_left_timestamp.saturating_add(1);\n                            *left_timestamp = new_left_timestamp;\n                            let new_parent_timestamp =\n                                std::cmp::max(new_left_timestamp, *right_timestamp);\n                            record.timestamp = new_parent_timestamp;\n                            if let Some(values) =\n                                final_partition.get_mut(&(address_space, pointer / CHUNK as u32))\n                            {\n                                values.timestamp = new_parent_timestamp;\n                            }\n                            let target_values = record\n                                .data\n                                .iter()\n                                .take(CHUNK / 2)\n                                .map(|value| value.as_canonical_u32().to_string())\n                                .collect::<Vec<_>>()\n                                .join(",");\n                            std::env::set_var(\n                                "BEAK_OPENVM_PADDING_INTERACTION_TARGET",\n                                format!(\n                                    "{address_space},{pointer},{old_left_timestamp},{target_values}"\n                                ),\n                            );\n                            eprintln!(\n                                "[beak-witness-inject] kind=openvm.semantic.row.padding_interaction_send site=memory_final_merge address_space={} pointer={} old_left_timestamp={} new_left_timestamp={} right_timestamp={} parent_timestamp={}",\n                                address_space,\n                                pointer,\n                                old_left_timestamp,\n                                new_left_timestamp,\n                                *right_timestamp,\n                                new_parent_timestamp\n                            );\n                            let mut beak_bits_remaining = self.mem_config.clk_max_bits;\n                            for _ in 0..AUX_LEN {\n                                let range_bits =\n                                    beak_bits_remaining.min(self.range_checker_bus.range_max_bits);\n                                self.range_checker.add_count(0, range_bits);\n                                beak_bits_remaining = beak_bits_remaining\n                                    .saturating_sub(self.range_checker_bus.range_max_bits);\n                            }\n                            break;\n                        }\n                    }\n                } else {\n                    std::env::remove_var("BEAK_OPENVM_PADDING_INTERACTION_TARGET");\n                }\n                // BEAK-INSERT-END\n\n                self.access_adapters.extend_records(records);\n\n                // BEAK-INSERT: guard.336f.memory.lifecycle.finalization\n                let beak_final_cells: Vec<_> = final_partition\n                    .iter()\n                    .map(|(&(address_space, chunk_label), values)| {\n                        let pointer = chunk_label * CHUNK as u32;\n                        let final_values = values\n                            .values\n                            .iter()\n                            .map(|value| value.as_canonical_u32())\n                            .collect::<Vec<_>>();\n                        let initial_values = (0..CHUNK as u32)\n                            .map(|offset| {\n                                initial_memory\n                                    .get(&(address_space, pointer + offset))\n                                    .copied()\n                                    .unwrap_or(F::ZERO)\n                                    .as_canonical_u32()\n                            })\n                            .collect::<Vec<_>>();\n                        let was_initial = initial_values.iter().any(|value| *value != 0);\n                        let changed_from_initial = final_values != initial_values;\n                        (\n                            (address_space, chunk_label),\n                            pointer,\n                            values.timestamp,\n                            final_values,\n                            was_initial,\n                            changed_from_initial,\n                        )\n                    })\n                    .collect();\n                for (\n                    beak_final_idx,\n                    (\n                        (address_space, chunk_label),\n                        pointer,\n                        timestamp,\n                        final_values,\n                        was_initial,\n                        changed_from_initial,\n                    ),\n                ) in beak_final_cells.into_iter().enumerate()\n                {\n                    let beak_final_idx = beak_final_idx as u64;\n                    fuzzer_utils::emit_memory_finalization(\n                        beak_final_idx,\n                        address_space,\n                        pointer,\n                        timestamp,\n                        final_values,\n                        was_initial,\n                        changed_from_initial,\n                    );\n                    if fuzzer_utils::should_inject_witness(\n                        "openvm.semantic.memory.finalization_consistency",\n                        beak_final_idx,\n                    ) {\n                        eprintln!(\n                            "[beak-witness-inject] kind=openvm.semantic.memory.finalization_consistency step={} address_space={} pointer={} timestamp={}",\n                            beak_final_idx,\n                            address_space,\n                            pointer,\n                            timestamp\n                        );\n                        if let Some(values) =\n                            final_partition.get_mut(&(address_space, chunk_label))\n                        {\n                            values.values[0] += F::from_canonical_u32(1);\n                        }\n                    }\n                }\n                // BEAK-INSERT-END\n\n                boundary_chip.finalize(initial_memory, &final_partition, hasher);\n                let final_memory_values = final_partition\n'
    if '// BEAK-INSERT: guard.336f.memory.lifecycle.finalization' not in c and old_final in c:
        c = c.replace(old_final, new_final, 1)
    path.write_text(c)


def _patch_336f_divrem_core_emit_chip_row(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "divrem"
        / "core.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    try:
        c = _insert_before(
            c,
            anchor="        let output = AdapterRuntimeContext::without_pc([",
            guard="// BEAK-INSERT: guard.336f.divrem.core.emit_chip_row",
            insert=r"""
        // BEAK-INSERT: guard.336f.divrem.core.emit_chip_row
        // BEAK-INSERT: Emit DivRem chip-row micro-op from core execution.
        let rd_ptr = instruction.a.as_canonical_u32();
        let rs1_ptr = instruction.b.as_canonical_u32();
        let rs2_ptr = instruction.c.as_canonical_u32();
        let a_u8: [u8; NUM_LIMBS] = if is_div {
            q.map(|x| x as u8)
        } else {
            r.map(|x| x as u8)
        };
        let b_u8: [u8; NUM_LIMBS] = b.map(|x| x as u8);
        let c_u8: [u8; NUM_LIMBS] = c.map(|x| x as u8);
        fuzzer_utils::emit_divrem_chip_row(
            divrem_opcode as u32,
            rd_ptr,
            rs1_ptr,
            rs2_ptr,
            a_u8,
            b_u8,
            c_u8,
        );
        // BEAK-INSERT-END
""",
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_auipc_core_witness_injection(openvm_install_path = None):
    path = openvm_install_path / 'extensions' / 'rv32im' / 'circuit' / 'src' / 'auipc' / 'core.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '        let imm_limbs = array::from_fn(|i| (imm >> (i * RV32_CELL_BITS)) & RV32_LIMB_MAX);\n        let pc_limbs = array::from_fn(|i| (from_pc >> ((i + 1) * RV32_CELL_BITS)) & RV32_LIMB_MAX);\n'
    new = '        let mut imm_limbs = array::from_fn(|i| (imm >> (i * RV32_CELL_BITS)) & RV32_LIMB_MAX);\n        let mut pc_limbs = array::from_fn(|i| (from_pc >> ((i + 1) * RV32_CELL_BITS)) & RV32_LIMB_MAX);\n\n        // BEAK-INSERT: guard.336f.auipc.core.preprocess_o7\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::matching_injection_kind(\n            "openvm.semantic.control.auipc_pc_limb_consistency",\n            beak_witness_step,\n        ).is_some() {\n            let beak_variant = fuzzer_utils::active_witness_variant(\n                "openvm.semantic.control.auipc_pc_limb_consistency",\n            );\n            let mut mode = None;\n            let mut slot = None;\n            let mut strength = None;\n            let mut mult = None;\n            let mut valid = beak_variant.is_some();\n            for part in beak_variant.as_deref().unwrap_or("").split(\',\') {\n                let Some((key, value)) = part.split_once(\'=\') else {\n                    valid = false;\n                    continue;\n                };\n                match key.trim() {\n                    "mode" if mode.is_none() => mode = Some(value.trim()),\n                    "slot" if slot.is_none() => slot = value.trim().parse::<usize>().ok(),\n                    "strength" if strength.is_none() => strength = value.trim().parse::<u32>().ok(),\n                    "mult" if mult.is_none() => mult = value.trim().parse::<u32>().ok(),\n                    _ => valid = false,\n                }\n            }\n            valid &= mode == Some("from_pc_high_single_mod_p")\n                && strength == Some(0)\n                && mult == Some(1)\n                // The AIR range loop sends (imm_limbs[2], pc_limbs[0]) as a byte\n                // pair, so pc_limbs[0] IS range-checked. Only the high pc limbs\n                // pc_limbs[1] and pc_limbs[2] lack any byte range check; they are\n                // the real id3 underconstraint surface.\n                && matches!(slot, Some(2 | 3));\n            if valid {\n                let applied = fuzzer_utils::should_inject_witness(\n                    "openvm.semantic.control.auipc_pc_limb_consistency",\n                    beak_witness_step,\n                );\n                fuzzer_utils::fuzzer_assert!(applied);\n                let slot = slot.unwrap();\n                let mult = mult.unwrap();\n                // BabyBear prime: 2^31 - 2^27 + 1 = 2013265921. The AIR computes\n                // rd_data[0] == from_pc - intermed_val in the field and never range\n                // checks the pc limbs, so adding a whole modulus multiple keeps every\n                // AIR equation satisfied while breaking canonical byte decomposition.\n                const BEAK_BABYBEAR_P: u32 = 2_013_265_921;\n                let before_limbs = [\n                    from_pc & RV32_LIMB_MAX,\n                    pc_limbs[0],\n                    pc_limbs[1],\n                    pc_limbs[2],\n                ];\n                let selected_before = before_limbs[slot];\n                pc_limbs[slot - 1] = selected_before + BEAK_BABYBEAR_P * mult;\n                let after_limbs = [\n                    before_limbs[0],\n                    pc_limbs[0],\n                    pc_limbs[1],\n                    pc_limbs[2],\n                ];\n                let recompose = |limbs: [u32; 4]| -> u64 {\n                    limbs.iter().enumerate().map(|(i, limb)| (*limb as u64) << (i * RV32_CELL_BITS)).sum()\n                };\n                fuzzer_utils::record_semantic_mutation(\n                    "openvm.semantic.control.auipc_pc_limb_consistency",\n                    "rv32_auipc_core.preprocess",\n                    "pc_limb",\n                    beak_witness_step,\n                    serde_json::json!(selected_before),\n                    serde_json::json!(after_limbs[slot]),\n                    serde_json::json!({\n                        "relation": "auipc_pc_limb_representation",\n                        "context": {\n                            "bucket_id": "sem.control.auipc_pc_limb_consistency",\n                            "obligation_id": "id3",\n                            "backend": "openvm",\n                            "commit": "336f1a475e5aa3513c4c5a266399f4128c119bba",\n                            "trace_source": "instruction",\n                            "cell_id": if from_pc.checked_add(imm).is_some() { "id3.auipc_no_wrap" } else { "id3.auipc_wrap" },\n                            "mode": mode.unwrap(),\n                            "slot": slot,\n                            "strength": strength.unwrap(),\n                            "mult": mult,\n                            "radix": RV32_LIMB_MAX + 1,\n                            "limb_bound": RV32_LIMB_MAX + 1,\n                            "modulus": BEAK_BABYBEAR_P as u64,\n                            "before_limbs": before_limbs,\n                            "after_limbs": after_limbs,\n                            "pc": from_pc,\n                            "from_pc": from_pc,\n                            "step": beak_witness_step,\n                            "selected_before": selected_before,\n                            "selected_after": after_limbs[slot],\n                            "recomposed_before": recompose(before_limbs),\n                            "recomposed_after": recompose(after_limbs)\n                        }\n                    }),\n                );\n            }\n        }\n        // BEAK-INSERT-END\n'
    if '// BEAK-INSERT: guard.336f.auipc.core.preprocess_o7' not in c and old in c:
        c = c.replace(old, new, 1)
    if '// BEAK-INSERT: guard.336f.auipc.core.preprocess_o7' in c:
        c = c.replace('pc_limbs: pc_limbs.map(F::from_canonical_u32),', 'pc_limbs: pc_limbs.map(F::from_wrapped_u32),', 1)
    path.write_text(c)


def _patch_336f_loadstore_adapter_witness_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "adapters"
        / "loadstore.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = r"""        let imm = c.as_canonical_u32();
        let imm_sign = (imm & 0x8000) >> 15;
        let imm_extended = imm + imm_sign * 0xffff0000;
"""
    new = '        let imm = c.as_canonical_u32();\n        let imm_sign = (imm & 0x8000) >> 15;\n\n        // BEAK-INSERT: guard.336f.loadstore.adapter.preprocess_o8\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        let beak_variant =\n            fuzzer_utils::active_witness_variant("openvm.semantic.memory.immediate_sign_consistency");\n        let spec = beak_variant.as_deref().unwrap_or("");\n        let mut mode = None;\n        let mut domain = None;\n        let mut guard = None;\n        let mut valid = beak_variant.is_some();\n        for part in spec.split(\',\') {\n            let Some((spec_key, spec_value)) = part.split_once(\'=\') else {\n                valid = false;\n                continue;\n            };\n            match spec_key.trim() {\n                "mode" if mode.is_none() => mode = Some(spec_value.trim()),\n                "domain" if domain.is_none() => domain = Some(spec_value.trim()),\n                "guard" if guard.is_none() => guard = Some(spec_value.trim()),\n                _ => valid = false,\n            }\n        }\n        let local_opcode = Rv32LoadStoreOpcode::from_usize(\n            opcode.local_opcode_idx(Rv32LoadStoreOpcode::CLASS_OFFSET),\n        );\n        let opcode_shift_ok = |ptr: u32| match (local_opcode, ptr & 0x3) {\n            (LOADW, 0) | (STOREW, 0) => true,\n            (LOADH, 0) | (LOADH, 2) | (LOADHU, 0) | (LOADHU, 2) | (STOREH, 0) | (STOREH, 2) => true,\n            (LOADB, _) | (LOADBU, _) | (STOREB, _) => true,\n            _ => false,\n        };\n        let is_load = matches!(local_opcode, LOADW | LOADB | LOADH | LOADBU | LOADHU);\n        let is_store = matches!(local_opcode, STOREW | STOREH | STOREB);\n        let base_imm_extended = imm + imm_sign * 0xffff0000;\n        let orig_ptr = rs1_val.wrapping_add(base_imm_extended);\n        let mut beak_imm_sign = imm_sign;\n        if fuzzer_utils::matching_injection_kind(\n            "openvm.semantic.memory.immediate_sign_consistency",\n            beak_witness_step,\n        ).is_some() {\n            let candidate_sign = if imm_sign == 1 { 0 } else { 1 };\n            let candidate_ext = imm + candidate_sign * 0xffff0000;\n            let flipped_ptr = rs1_val.wrapping_add(candidate_ext);\n            let ptr_in_range = flipped_ptr < (1 << self.air.pointer_max_bits);\n            let domain_ok = match domain.unwrap_or("") {\n                "load" => is_load,\n                "store" => is_store,\n                "any" => true,\n                _ => false,\n            };\n            let guard_ok = match guard.unwrap_or("") {\n                "alt_in_range" => ptr_in_range,\n                "none" => true,\n                _ => false,\n            };\n            if valid && mode == Some("flip_sign") && domain_ok && guard_ok && opcode_shift_ok(flipped_ptr) && ptr_in_range {\n                let applied = fuzzer_utils::should_inject_witness(\n                    "openvm.semantic.memory.immediate_sign_consistency",\n                    beak_witness_step,\n                );\n                fuzzer_utils::fuzzer_assert!(applied);\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.memory.immediate_sign_consistency step={} imm={} mode={} domain={} guard={} orig_ptr={} flipped_ptr={} flipped_sign={} variant={}",\n                    beak_witness_step,\n                    imm,\n                    mode.unwrap(),\n                    domain.unwrap(),\n                    guard.unwrap(),\n                    orig_ptr,\n                    flipped_ptr,\n                    candidate_sign,\n                    spec\n                );\n                beak_imm_sign = candidate_sign;\n                fuzzer_utils::record_semantic_mutation(\n                    "openvm.semantic.memory.immediate_sign_consistency",\n                    "rv32_loadstore_adapter.preprocess",\n                    "imm_sign",\n                    beak_witness_step,\n                    serde_json::json!(imm_sign),\n                    serde_json::json!(candidate_sign),\n                    serde_json::json!({\n                        "relation": "memory_immediate_sign_equation",\n                        "context": {\n                            "step": beak_witness_step,\n                            "cell_id": match (is_store, imm_sign) {\n                                (true, 0) => "id2.s_pos",\n                                (true, _) => "id2.s_neg",\n                                (false, 0) => "id2.i_pos",\n                                (false, _) => "id2.i_neg",\n                            },\n                            "mode": mode.unwrap(),\n                            "domain": domain.unwrap(),\n                            "guard": guard.unwrap(),\n                            "immediate": imm,\n                            "base": rs1_val,\n                            "sign_before": imm_sign,\n                            "sign_after": candidate_sign,\n                            "extended_before": base_imm_extended,\n                            "extended_after": candidate_ext,\n                            "effective_before": orig_ptr,\n                            "effective_after": flipped_ptr,\n                            "pointer_max_exclusive": 1u32 << self.air.pointer_max_bits,\n                            "equation_before_valid": orig_ptr == rs1_val.wrapping_add(base_imm_extended),\n                            "equation_after_valid": flipped_ptr == rs1_val.wrapping_add(candidate_ext)\n                        }\n                    }),\n                );\n            } else {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.memory.immediate_sign_consistency step={} imm={} mode=skip_context domain={} guard={} orig_ptr={} variant={}",\n                    beak_witness_step,\n                    imm,\n                    domain.unwrap_or("invalid"),\n                    guard.unwrap_or("invalid"),\n                    orig_ptr,\n                    spec\n                );\n            }\n        }\n        // BEAK-INSERT-END\n\n        let imm_extended = imm + beak_imm_sign * 0xffff0000;\n'
    if "// BEAK-INSERT: guard.336f.loadstore.adapter.preprocess_o8" not in c and old in c:
        c = c.replace(old, new, 1)
    old2 = r"""        Ok((
            (
                [prev_data, read_record.1],
                F::from_canonical_u32(shift_amount),
            ),
            Self::ReadRecord {
                rs1_record: rs1_record.0,
                rs1_ptr: b,
                read: read_record.0,
                imm: c,
                imm_sign: imm_sign == 1,
                shift_amount,
                mem_ptr_limbs,
                mem_as: e,
            },
        ))
"""
    new2 = r"""        // BEAK-INSERT: guard.336f.loadstore.adapter.emit_memory_access
        // BEAK-INSERT: Emit true memory access address metadata from the adapter. The core chip
        // does not have rs1_data, so its chip-row effective_ptr field is not the source of truth.
        let beak_width = match local_opcode {
            LOADW | STOREW => 4u32,
            LOADH | LOADHU | STOREH => 2u32,
            LOADB | LOADBU | STOREB => 1u32,
        };
        let beak_imm_i32: i32 = (imm as i32) - ((beak_imm_sign as i32) << 16);
        let beak_effective_ptr = ptr_val.wrapping_add(shift_amount);
        fuzzer_utils::emit_memory_access(
            0,
            local_opcode as u32,
            b.as_canonical_u32(),
            a.as_canonical_u32(),
            beak_imm_i32,
            beak_imm_sign == 1,
            e.as_canonical_u32(),
            beak_effective_ptr,
            beak_effective_ptr,
            ptr_val,
            shift_amount,
            beak_width,
            is_load,
            is_store,
            is_load,
            memory.timestamp(),
            read_record.1.iter().map(|x| x.as_canonical_u32()).collect(),
            prev_data.iter().map(|x| x.as_canonical_u32()).collect(),
            read_record.1.iter().map(|x| x.as_canonical_u32()).collect(),
        );
        // BEAK-INSERT-END

        // BEAK-INSERT: guard.336f.loadstore.adapter.mem_as_o5
        let mut beak_mem_as = e;
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.address_space_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} old_mem_as={}",
                beak_witness_step,
                e.as_canonical_u32()
            );
            // Force RAM address space as a forged witness value.
            beak_mem_as = F::ZERO;
        }
        // BEAK-INSERT-END

        Ok((
            (
                [prev_data, read_record.1],
                F::from_canonical_u32(shift_amount),
            ),
            Self::ReadRecord {
                rs1_record: rs1_record.0,
                rs1_ptr: b,
                read: read_record.0,
                imm: c,
                imm_sign: beak_imm_sign == 1,
                shift_amount,
                mem_ptr_limbs,
                mem_as: beak_mem_as,
            },
        ))
"""
    if "// BEAK-INSERT: guard.336f.loadstore.adapter.emit_memory_access" not in c and old2 in c:
        c = c.replace(old2, new2, 1)
    if "// BEAK-INSERT: guard.336f.loadstore.adapter.emit_memory_access" not in c:
        try:
            c = _insert_before(
                c,
                anchor="        Ok((\n            (\n                [prev_data, read_record.1],",
                guard="// BEAK-INSERT: guard.336f.loadstore.adapter.emit_memory_access",
                insert=r"""
        // BEAK-INSERT: guard.336f.loadstore.adapter.emit_memory_access
        // BEAK-INSERT: Emit true memory access address metadata from the adapter. The core chip
        // does not have rs1_data, so its chip-row effective_ptr field is not the source of truth.
        let beak_imm_sign = imm_sign;
        let is_load = matches!(local_opcode, LOADW | LOADB | LOADH | LOADBU | LOADHU);
        let is_store = matches!(local_opcode, STOREW | STOREH | STOREB);
        let beak_width = match local_opcode {
            LOADW | STOREW => 4u32,
            LOADH | LOADHU | STOREH => 2u32,
            LOADB | LOADBU | STOREB => 1u32,
        };
        let beak_imm_i32: i32 = (imm as i32) - ((beak_imm_sign as i32) << 16);
        let beak_effective_ptr = ptr_val.wrapping_add(shift_amount);
        fuzzer_utils::emit_memory_access(
            0,
            local_opcode as u32,
            b.as_canonical_u32(),
            a.as_canonical_u32(),
            beak_imm_i32,
            beak_imm_sign == 1,
            e.as_canonical_u32(),
            beak_effective_ptr,
            beak_effective_ptr,
            ptr_val,
            shift_amount,
            beak_width,
            is_load,
            is_store,
            is_load,
            memory.timestamp(),
            read_record.1.iter().map(|x| x.as_canonical_u32()).collect(),
            prev_data.iter().map(|x| x.as_canonical_u32()).collect(),
            read_record.1.iter().map(|x| x.as_canonical_u32()).collect(),
        );
        // BEAK-INSERT-END

""",
            )
        except RuntimeError:
            pass
    if (
        "// BEAK-INSERT: guard.336f.loadstore.adapter.emit_memory_access" in c
        and "let mut beak_imm_sign" not in c
        and "let beak_imm_sign = imm_sign;" not in c
    ):
        c = c.replace(
            "        let beak_width = match local_opcode {\n",
            "        let beak_imm_sign = imm_sign;\n"
            "        let is_load = matches!(local_opcode, LOADW | LOADB | LOADH | LOADBU | LOADHU);\n"
            "        let is_store = matches!(local_opcode, STOREW | STOREH | STOREB);\n"
            "        let beak_width = match local_opcode {\n",
            1,
        )
    if (
        "// BEAK-INSERT: guard.336f.loadstore.adapter.emit_memory_access" in c
        and "let beak_effective_ptr = ptr_val.wrapping_add(shift_amount);" not in c
    ):
        c = c.replace(
            "        fuzzer_utils::emit_memory_access(\n",
            "        let beak_effective_ptr = ptr_val.wrapping_add(shift_amount);\n"
            "        let beak_imm_i32: i32 = (imm as i32) - ((beak_imm_sign as i32) << 16);\n"
            "        fuzzer_utils::emit_memory_access(\n",
            1,
        )
        c = c.replace("            imm_i32,\n", "            beak_imm_i32,\n", 1)
        c = c.replace(
            "            e.as_canonical_u32(),\n"
            "            orig_ptr,\n"
            "            orig_ptr,\n"
            "            ptr_val,\n",
            "            e.as_canonical_u32(),\n"
            "            beak_effective_ptr,\n"
            "            beak_effective_ptr,\n"
            "            ptr_val,\n",
            1,
        )
    if (
        "// BEAK-INSERT: guard.336f.loadstore.adapter.emit_memory_access" in c
        and "let beak_imm_i32: i32 = (imm as i32) - ((beak_imm_sign as i32) << 16);" not in c
    ):
        c = c.replace(
            "        fuzzer_utils::emit_memory_access(\n",
            "        let beak_imm_i32: i32 = (imm as i32) - ((beak_imm_sign as i32) << 16);\n"
            "        fuzzer_utils::emit_memory_access(\n",
            1,
        )
        c = c.replace("            imm_i32,\n", "            beak_imm_i32,\n", 1)
    if (
        "// BEAK-INSERT: guard.336f.loadstore.adapter.emit_memory_access" in c
        and "read_record.1.iter().map(|x| x.as_canonical_u32()).collect(),\n        );"
        not in c
    ):
        c = c.replace(
            "            prev_data.iter().map(|x| x.as_canonical_u32()).collect(),\n"
            "        );\n",
            "            prev_data.iter().map(|x| x.as_canonical_u32()).collect(),\n"
            "            read_record.1.iter().map(|x| x.as_canonical_u32()).collect(),\n"
            "        );\n",
            1,
        )
    if (
        "// BEAK-INSERT: guard.336f.loadstore.adapter.mem_as_o5" not in c
        and "// BEAK-INSERT: guard.336f.loadstore.adapter.emit_memory_access" in c
        and "                mem_as: e,\n" in c
    ):
        c = c.replace(
            "        Ok((\n",
            """        // BEAK-INSERT: guard.336f.loadstore.adapter.mem_as_o5
        let mut beak_mem_as = e;
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.address_space_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} old_mem_as={}",
                beak_witness_step,
                e.as_canonical_u32()
            );
            // Force RAM address space as a forged witness value.
            beak_mem_as = F::ZERO;
        }
        // BEAK-INSERT-END

        Ok((
""",
            1,
        )
        c = c.replace("                mem_as: e,\n", "                mem_as: beak_mem_as,\n", 1)
    if (
        "// BEAK-INSERT: guard.336f.loadstore.adapter.ptr_limbs" not in c
        and "        let mem_ptr_limbs = array::from_fn(|i| ((ptr_val >> (i * (RV32_CELL_BITS * 2))) & 0xffff));\n"
        in c
    ):
        c = c.replace(
            "        let mem_ptr_limbs = array::from_fn(|i| ((ptr_val >> (i * (RV32_CELL_BITS * 2))) & 0xffff));\n",
            """        let mut mem_ptr_limbs = array::from_fn(|i| ((ptr_val >> (i * (RV32_CELL_BITS * 2))) & 0xffff));
        // BEAK-INSERT: guard.336f.loadstore.adapter.ptr_limbs
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.address_pointer_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.address_pointer_consistency step={} ptr_val={}",
                beak_witness_step,
                ptr_val
            );
            mem_ptr_limbs[0] = mem_ptr_limbs[0].wrapping_add(1) & 0xffff;
        }
        // BEAK-INSERT-END
""",
            1,
        )
    path.write_text(c)


def _remove_guarded_block(contents: str, guard: str) -> str:
    """Remove an installed guarded block (guard line through BEAK-INSERT-END)."""
    search_from = 0
    while True:
        marker = contents.find(guard, search_from)
        if marker < 0:
            return contents
        line_end = contents.find("\n", marker)
        if line_end >= 0 and contents[marker + len(guard):line_end].strip() == "":
            break
        search_from = marker + len(guard)
    start = contents.rfind("\n", 0, marker) + 1
    end_marker = contents.find('// BEAK-INSERT-END', marker)
    if end_marker < 0:
        raise RuntimeError(f'''unterminated guarded injection: {guard!r}''')
    end_line = contents.find('\n', end_marker)
    end = len(contents) if end_line < 0 else end_line + 1
    return contents[:start] + contents[end:]


def _patch_336f_divrem_core_witness_injection(openvm_install_path: Path) -> None:
    path = openvm_install_path / 'extensions' / 'rv32im' / 'circuit' / 'src' / 'divrem' / 'core.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    for legacy_guard in ('// BEAK-INSERT: guard.336f.divrem.core.o15', '// BEAK-INSERT: guard.336f.divrem.core.o15.apply', '// BEAK-INSERT: guard.336f.divrem.core.o15.executor'):
        c = _remove_guarded_block(c, legacy_guard)
    if '        let mut c = data[1].map(|y| y.as_canonical_u32());\n\n' in c:
        c = c.replace('        let mut c = data[1].map(|y| y.as_canonical_u32());\n\n', '        let c = data[1].map(|y| y.as_canonical_u32());\n', 1)
    else:
        c = c.replace('        let mut c = data[1].map(|y| y.as_canonical_u32());\n', '        let c = data[1].map(|y| y.as_canonical_u32());\n', 1)
    c = c.replace('            c: c.map(F::from_canonical_u32),\n', '            c: data[1],\n', 1)
    o15_dup_guard = '// BEAK-INSERT: guard.336f.divrem.core.o15.duplicate_row'
    o15_dup = '\n    fn finalize(\n        &self,\n        trace: &mut openvm_stark_backend::p3_matrix::dense::RowMajorMatrix<F>,\n        num_records: usize,\n    ) {\n        // BEAK-INSERT: guard.336f.divrem.core.o15.duplicate_row\n        // Generate-trace duplicate-row shadow for audit-o15 (md2.div_overflow).\n        // The records->matrix loop lives in the generic VmChipWrapper;\n        // finalize is the core-side entry that receives the finished matrix,\n        // so the duplicate row is appended here. The duplicate copies the value\n        // columns of the executed INT_MIN / -1 DIV row but carries is_valid = 0\n        // and zero_divisor = 0 with c = 0: every interaction multiplicity\n        // (execution bridge, memory reads/writes, range tuples, sign and lt\n        // lookups) collapses to zero, so logup stays balanced, while all local\n        // AIR constraints still hold (c = 0 makes the lt prefix constraint\n        // vanish and zero_divisor = 0 skips the zero-divisor clause). The\n        // special-case flag therefore has no is_valid implication: a shadow\n        // row whose divisor is 0 passes as an ordinary dead row.\n        use openvm_stark_backend::p3_matrix::Matrix as _;\n        let beak_o15_kind = "openvm.semantic.arithmetic.special_case_consistency";\n        let beak_o15_variant = fuzzer_utils::active_witness_variant(beak_o15_kind);\n        let mut beak_o15_mode = None;\n        for part in beak_o15_variant.as_deref().unwrap_or("").split(\',\') {\n            if let Some((key, value)) = part.split_once(\'=\') {\n                if key.trim() == "mode" && beak_o15_mode.is_none() {\n                    beak_o15_mode = Some(value.trim());\n                }\n            }\n        }\n        if beak_o15_mode.as_deref() == Some("duplicate_row_shadow_r_zero") {\n            let beak_core_width = DivRemCoreCols::<F, NUM_LIMBS, LIMB_BITS>::width();\n            let beak_width = trace.width();\n            if beak_width > beak_core_width && num_records <= trace.height() {\n                let beak_adapter_width = beak_width - beak_core_width;\n                // DivRemCoreCols layout: b, c, q, r, zero_divisor, r_zero,\n                // b_sign, c_sign, q_sign, sign_xor, r_prime, r_inv,\n                // lt_marker, lt_diff, opcode flags.\n                let beak_flag_base = beak_adapter_width + 4 * NUM_LIMBS + 6 + 3 * NUM_LIMBS + 1;\n                let beak_int_min: [u32; NUM_LIMBS] =\n                    array::from_fn(|i| if i == NUM_LIMBS - 1 { 1 << (LIMB_BITS - 1) } else { 0 });\n                let beak_minus_one: [u32; NUM_LIMBS] = [(1 << LIMB_BITS) - 1; NUM_LIMBS];\n                let mut beak_armed: Option<usize> = None;\n                for beak_row_idx in 0..num_records {\n                    let beak_base = beak_row_idx * beak_width;\n                    let beak_b_ok = (0..NUM_LIMBS)\n                        .all(|i| trace.values[beak_base + beak_adapter_width + i]\n                            .as_canonical_u32()\n                            == beak_int_min[i]);\n                    let beak_c_ok = (0..NUM_LIMBS)\n                        .all(|i| trace.values[beak_base + beak_adapter_width + NUM_LIMBS + i]\n                            .as_canonical_u32()\n                            == beak_minus_one[i]);\n                    let beak_q_ok = (0..NUM_LIMBS)\n                        .all(|i| trace.values[beak_base + beak_adapter_width + 2 * NUM_LIMBS + i]\n                            .as_canonical_u32()\n                            == beak_int_min[i]);\n                    let beak_div_ok = trace.values[beak_base + beak_flag_base] == F::ONE\n                        && (1..4)\n                            .all(|k| trace.values[beak_base + beak_flag_base + k] == F::ZERO);\n                    if beak_b_ok && beak_c_ok && beak_q_ok && beak_div_ok {\n                        beak_armed = Some(beak_row_idx);\n                        break;\n                    }\n                }\n                if let Some(beak_row_idx) = beak_armed {\n                    let beak_base = beak_row_idx * beak_width;\n                    let beak_pc = trace.values[beak_base].as_canonical_u32();\n                    let beak_step = u64::from(beak_pc) / 4;\n                    if fuzzer_utils::should_inject_witness(beak_o15_kind, beak_step) {\n                        if num_records == trace.height() {\n                            let beak_new_height = if trace.height() == 0 {\n                                1\n                            } else {\n                                trace.height() * 2\n                            };\n                            trace.values.resize(beak_new_height * beak_width, F::ZERO);\n                        }\n                        let beak_dup_base = num_records * beak_width;\n                        let beak_dup_core = beak_dup_base + beak_adapter_width;\n                        // Value columns: copy b (INT_MIN) and q (INT_MIN); set\n                        // c = 0 and r = 0. Every flag and auxiliary column\n                        // stays zero (is_valid = 0, zero_divisor = 0, r_zero =\n                        // 0), which every local AIR constraint accepts, and\n                        // every interaction multiplicity is zero.\n                        for beak_i in 0..NUM_LIMBS {\n                            trace.values[beak_dup_core + beak_i] =\n                                trace.values[beak_base + beak_adapter_width + beak_i];\n                            trace.values[beak_dup_core + 2 * NUM_LIMBS + beak_i] =\n                                trace.values[beak_base + beak_adapter_width + 2 * NUM_LIMBS + beak_i];\n                        }\n                        eprintln!(\n                            "[beak-witness-inject] kind={} mode=duplicate_row_shadow_r_zero step={} row={} dup_row={}",\n                            beak_o15_kind,\n                            beak_step,\n                            beak_row_idx,\n                            num_records\n                        );\n                        // Reconstruct the executed RISC-V word from the adapter\n                        // pointers: DIV is funct7=0000001, funct3=100,\n                        // opcode=0110011.\n                        let beak_rd_ptr = trace.values[beak_base + 2].as_canonical_u32();\n                        let beak_rs1_ptr = trace.values[beak_base + 3].as_canonical_u32();\n                        let beak_rs2_ptr = trace.values[beak_base + 4].as_canonical_u32();\n                        let beak_word = (1u32 << 25)\n                            | (beak_rs2_ptr << 20)\n                            | (beak_rs1_ptr << 15)\n                            | (4u32 << 12)\n                            | (beak_rd_ptr << 7)\n                            | 0x33;\n                        fuzzer_utils::record_semantic_mutation(\n                            beak_o15_kind,\n                            "divrem_core.generate_trace",\n                            "row_duplicate.is_valid",\n                            beak_step,\n                            serde_json::json!(1u64),\n                            serde_json::json!(0u64),\n                            serde_json::json!({\n                                "relation": "division_remainder_special_case_equation",\n                                "context": {\n                                    "bucket_id": "sem.arithmetic.special_case_consistency",\n                                    "obligation_id": "md2",\n                                    "cell_id": "md2.div_overflow",\n                                    "mode": "duplicate_row_shadow_r_zero",\n                                    "search": "wildcard",\n                                    "executed_instruction": true,\n                                    "step": beak_step,\n                                    "pc": beak_pc,\n                                    "opcode": beak_word,\n                                    "mnemonic": "div",\n                                    "is_valid": 0u64,\n                                    "zero_divisor": 0u64,\n                                    "r_zero": 0u64,\n                                    "dividend": -2147483648i64,\n                                    "dividend_word": 0x80000000u64,\n                                    "claimed_divisor": -1i64,\n                                    "claimed_divisor_word": 0xffffffffu64,\n                                    "quotient": -2147483648i64,\n                                    "remainder": 0i64,\n                                    "duplicated_from_row_idx": beak_row_idx as u64,\n                                    "row_idx": num_records as u64,\n                                    "shadow_row": true\n                                }\n                            }),\n                        );\n                    }\n                }\n            }\n        }\n        // BEAK-INSERT-END\n    }\n'
    c = _refresh_guarded_block(c, template=o15_dup, guard=o15_dup_guard)
    if o15_dup_guard not in c:
        try:
            c = _insert_before(
                c,
                anchor="    fn air(&self) -> &Self::Air {",
                guard=o15_dup_guard,
                insert=o15_dup,
            )
        except RuntimeError:
            return
    path.write_text(c)


def _patch_336f_shift_core_semantic_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "shift"
        / "core.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    try:
        c = _insert_before(
            c,
            anchor="        let output = AdapterRuntimeContext::without_pc([a.map(F::from_canonical_u32)]);",
            guard="// BEAK-INSERT: guard.336f.shift.core.emit_chip_row",
            insert=r"""
        // BEAK-INSERT: guard.336f.shift.core.emit_chip_row
        let rd_ptr = instruction.a.as_canonical_u32();
        let rs1_ptr = instruction.b.as_canonical_u32();
        let rs2_ptr = instruction.c.as_canonical_u32() as i32;
        let a_u8: [u8; NUM_LIMBS] = a.map(|x| x as u8);
        let b_u8: [u8; NUM_LIMBS] = b.map(|x| x as u8);
        let c_u8: [u8; NUM_LIMBS] = c.map(|x| x as u8);
        fuzzer_utils::emit_shift_chip_row(
            shift_opcode as u32,
            rd_ptr,
            rs1_ptr,
            rs2_ptr,
            false,
            a_u8,
            b_u8,
            c_u8,
        );
        // BEAK-INSERT-END
""",
        )
        c = _insert_before(
            c,
            anchor="    }\n\n    fn air(&self) -> &Self::Air {",
            guard="// BEAK-INSERT: guard.336f.shift.core.shift_mod32",
            insert='\n\n        // BEAK-INSERT: guard.336f.shift.core.shift_mod32\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.shift_mod32", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.alu.shift_mod32 step={}",\n                beak_witness_step\n            );\n            row_slice.a[0] += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_less_than_core_semantic_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "less_than"
        / "core.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    try:
        c = _insert_before(
            c,
            anchor="        let output = AdapterRuntimeContext::without_pc([writes.map(F::from_canonical_u32)]);",
            guard="// BEAK-INSERT: guard.336f.less_than.core.emit_chip_row",
            insert=r"""
        // BEAK-INSERT: guard.336f.less_than.core.emit_chip_row
        let rd_ptr = instruction.a.as_canonical_u32();
        let rs1_ptr = instruction.b.as_canonical_u32();
        let rs2_ptr = instruction.c.as_canonical_u32() as i32;
        let a_u8: [u8; NUM_LIMBS] = writes.map(|x| x as u8);
        let b_u8: [u8; NUM_LIMBS] = b.map(|x| x as u8);
        let c_u8: [u8; NUM_LIMBS] = c.map(|x| x as u8);
        fuzzer_utils::emit_less_than_chip_row(
            less_than_opcode as u32,
            rd_ptr,
            rs1_ptr,
            rs2_ptr,
            false,
            a_u8,
            b_u8,
            c_u8,
        );
        // BEAK-INSERT-END
""",
        )
        c = _insert_before(
            c,
            anchor="    }\n\n    fn air(&self) -> &Self::Air {",
            guard="// BEAK-INSERT: guard.336f.less_than.core.alu_semantics",
            insert='\n\n        // BEAK-INSERT: guard.336f.less_than.core.alu_semantics\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.comparison_booleanity", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.alu.comparison_booleanity step={}",\n                beak_witness_step\n            );\n            row_slice.cmp_result = F::ONE - row_slice.cmp_result;\n        }\n        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.comparison_auxiliary_chain", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.alu.comparison_auxiliary_chain step={}",\n                beak_witness_step\n            );\n            if record.diff_idx == NUM_LIMBS {\n                row_slice.diff_marker[0] = F::ONE;\n            } else {\n                row_slice.diff_val += F::ONE;\n            }\n        }\n        // BEAK-INSERT-END\n',
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_base_alu_core_semantic_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "base_alu"
        / "core.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    try:
        c = _insert_before(
            c,
            anchor="    }\n\n    fn air(&self) -> &Self::Air {",
            guard="// BEAK-INSERT: guard.336f.base_alu.core.sub_borrow",
            insert='\n\n        // BEAK-INSERT: guard.336f.base_alu.core.sub_borrow\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if record.opcode == BaseAluOpcode::XOR {\n            // This is the actual source interaction selector.  Keep receiver-table\n            // aggregate multiplicities out of BU1: four limb sends legitimately\n            // aggregate to a receiver multiplicity greater than one.\n            fuzzer_utils::emit_lookup_multiplicity(\n                "bitwise_source.base_alu.xor",\n                beak_witness_step,\n                1,\n                true,\n            );\n            if fuzzer_utils::should_inject_witness(\n                "openvm.semantic.lookup.boolean_multiplicity",\n                beak_witness_step,\n            ) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.lookup.boolean_multiplicity step={} site=base_alu_xor_source selector_before=1 selector_after=2",\n                    beak_witness_step\n                );\n                row_slice.opcode_xor_flag = F::from_canonical_u32(2);\n                fuzzer_utils::record_semantic_mutation(\n                    "openvm.semantic.lookup.boolean_multiplicity",\n                    "rv32_base_alu.xor_source",\n                    "interaction_selector",\n                    beak_witness_step,\n                    serde_json::json!(1),\n                    serde_json::json!(2),\n                    serde_json::json!({\n                        "relation": "boolean_source_selector",\n                        "context": {\n                            "obligation_id": "bu1",\n                            "cell_id": "bu1.real_row",\n                            "source_row": true,\n                            "table_name": "bitwise_source.base_alu.xor",\n                            "selector_before": 1,\n                            "selector_after": 2\n                        }\n                    }),\n                );\n            }\n        }\n        if record.opcode == BaseAluOpcode::SUB {\n            if fuzzer_utils::should_inject_witness("openvm.semantic.alu.subtraction_borrow_chain", beak_witness_step) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.alu.subtraction_borrow_chain step={}",\n                    beak_witness_step\n                );\n                row_slice.a[0] += F::ONE;\n            }\n        }\n        // BEAK-INSERT-END\n',
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_mul_core_semantic_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "mul"
        / "core.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    try:
        c = _insert_before(
            c,
            anchor="        let output = AdapterRuntimeContext::without_pc([a.map(F::from_canonical_u32)]);",
            guard="// BEAK-INSERT: guard.336f.mul.core.emit_chip_row",
            insert=r"""
        // BEAK-INSERT: guard.336f.mul.core.emit_chip_row
        let rd_ptr = instruction.a.as_canonical_u32();
        let rs1_ptr = instruction.b.as_canonical_u32();
        let rs2_ptr = instruction.c.as_canonical_u32();
        let a_u8: [u8; NUM_LIMBS] = a.map(|x| x as u8);
        let b_u8: [u8; NUM_LIMBS] = b.map(|x| x as u8);
        let c_u8: [u8; NUM_LIMBS] = c.map(|x| x as u8);
        fuzzer_utils::emit_mul_chip_row(
            MulOpcode::MUL as u32,
            rd_ptr,
            rs1_ptr,
            rs2_ptr,
            a_u8,
            b_u8,
            c_u8,
        );
        // BEAK-INSERT-END
""",
        )
        c = _insert_before(
            c,
            anchor="    }\n\n    fn air(&self) -> &Self::Air {",
            guard="// BEAK-INSERT: guard.336f.mul.core.product_decomposition",
            insert='\n\n        // BEAK-INSERT: guard.336f.mul.core.product_decomposition\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.product_decomposition", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.arithmetic.product_decomposition step={} site=mul",\n                beak_witness_step\n            );\n            row_slice.a[0] += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_mulh_core_semantic_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "mulh"
        / "core.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    try:
        c = _insert_before(
            c,
            anchor="        let output = AdapterRuntimeContext::without_pc([a.map(F::from_canonical_u32)]);",
            guard="// BEAK-INSERT: guard.336f.mulh.core.emit_chip_row",
            insert=r"""
        // BEAK-INSERT: guard.336f.mulh.core.emit_chip_row
        let rd_ptr = instruction.a.as_canonical_u32();
        let rs1_ptr = instruction.b.as_canonical_u32();
        let rs2_ptr = instruction.c.as_canonical_u32();
        let a_u8: [u8; NUM_LIMBS] = a.map(|x| x as u8);
        let b_u8: [u8; NUM_LIMBS] = b.map(|x| x as u8);
        let c_u8: [u8; NUM_LIMBS] = c.map(|x| x as u8);
        fuzzer_utils::emit_mulh_chip_row(
            mulh_opcode as u32,
            rd_ptr,
            rs1_ptr,
            rs2_ptr,
            a_u8,
            b_u8,
            c_u8,
        );
        // BEAK-INSERT-END
""",
        )
        c = _insert_before(
            c,
            anchor="    }\n\n    fn air(&self) -> &Self::Air {",
            guard="// BEAK-INSERT: guard.336f.mulh.core.product_semantics",
            insert='\n\n        // BEAK-INSERT: guard.336f.mulh.core.product_semantics\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.product_decomposition", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.arithmetic.product_decomposition step={} site=mulh",\n                beak_witness_step\n            );\n            row_slice.a[0] += F::ONE;\n        }\n        if record.opcode == MulHOpcode::MULHSU\n            && fuzzer_utils::should_inject_witness(\n                "openvm.semantic.arithmetic.signed_unsigned_product_correction",\n                beak_witness_step,\n            )\n        {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.arithmetic.signed_unsigned_product_correction step={}",\n                beak_witness_step\n            );\n            row_slice.b_ext += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_divrem_core_md3_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "divrem"
        / "core.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    try:
        c = _insert_after(
            c,
            anchor="        row_slice.lt_diff = record.lt_diff_val;",
            guard="// BEAK-INSERT: guard.336f.divrem.core.md3",
            insert='\n        // BEAK-INSERT: guard.336f.divrem.core.md3\n        if record.zero_divisor.as_canonical_u32() == 0 {\n            let beak_witness_step = fuzzer_utils::armed_inject_step();\n            if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.division_remainder_bound", beak_witness_step) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.arithmetic.division_remainder_bound step={}",\n                    beak_witness_step\n                );\n                row_slice.q[0] += F::ONE;\n            }\n        }\n        // BEAK-INSERT-END\n',
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_bitwise_lookup_shadow_multiplicity_injection(openvm_install_path: Path) -> None:
    """
    Add a witness-only (prove-side) shadow multiplicity mutation for audit-o1.
    This mutates lookup multiplicity in the bitwise lookup trace generation path
    without touching runtime instruction execution / interaction emission.
    """
    path = (
        openvm_install_path
        / "crates"
        / "circuits"
        / "primitives"
        / "src"
        / "bitwise_op_lookup"
        / "mod.rs"
    )
    if not path.exists():
        return
    c = path.read_text()
    c = c.replace('#[allow(unused_imports)]\nuse fuzzer_utils;\n\n', '')
    c = c.replace('#[allow(unused_imports)]\nuse fuzzer_utils;\n', '')
    o1_guard = '// BEAK-INSERT: guard.336f.bitwise.lookup.o1.shadow_mult'
    o1_insert = '\n        // BEAK-INSERT: guard.336f.bitwise.lookup.o1.shadow_mult\n        // Witness-only shadow multiplicity mutation for audit-o1.\n        // This intentionally mutates *prove-side* lookup multiplicity while keeping\n        // runtime behavior unchanged. Arm/apply decisions go through\n        // fuzzer_utils::should_inject_witness so applied sites are recorded.\n        // Logup balance is preserved by writing mult_before + P (BabyBear\n        // modulus): the cell is non-canonical as a u32 witness value but\n        // congruent to the real multiplicity in F, so the lookup table\n        // contribution is unchanged.\n        let beak_kind = "openvm.semantic.lookup.xor_multiplicity_consistency";\n        if fuzzer_utils::witness_injection_enabled_for(beak_kind) {\n            let beak_variant = fuzzer_utils::active_witness_variant(beak_kind).unwrap_or_default();\n            // BabyBear prime: 2^31 - 2^27 + 1 = 2013265921.\n            const BEAK_BABYBEAR_P: u32 = 2_013_265_921;\n            let mut mode = "p_plus_one";\n            let mut rank: usize = 0;\n            let mut strength: u32 = 0;\n            for part in beak_variant.split(\',\') {\n                if let Some((key, value)) = part.split_once(\'=\') {\n                    match key.trim() {\n                        "mode" => mode = value.trim(),\n                        "rank" => rank = value.trim().parse::<usize>().unwrap_or(0),\n                        "strength" => strength = value.trim().parse::<u32>().unwrap_or(0),\n                        _ => {}\n                    }\n                }\n            }\n            let mut injected = false;\n            let mut seen_nonzero = 0usize;\n            for (beak_row_idx, row) in rows.chunks_mut(NUM_BITWISE_OP_LOOKUP_COLS).enumerate() {\n                let cols: &mut BitwiseOperationLookupCols<F> = row.borrow_mut();\n                if cols.mult_xor != F::ZERO {\n                    if seen_nonzero != rank {\n                        seen_nonzero += 1;\n                        continue;\n                    }\n                    if !fuzzer_utils::should_inject_witness(beak_kind, beak_row_idx as u64) {\n                        eprintln!(\n                            "[beak-witness-inject] kind={} row={} skipped",\n                            beak_kind, beak_row_idx\n                        );\n                        break;\n                    }\n                    // Detect the actual canonical multiplicity. Real counts are\n                    // small nonnegative integers (bounded by the trace height,\n                    // observed values include 6), so scan canonical\n                    // representatives instead of assuming 0/1/2.\n                    let mut beak_detected_mult: Option<u32> = None;\n                    for beak_n in 0..=65537u32 {\n                        if cols.mult_xor == F::from_canonical_u32(beak_n) {\n                            beak_detected_mult = Some(beak_n);\n                            break;\n                        }\n                    }\n                    let beak_mult_before: u32 = match beak_detected_mult {\n                        Some(beak_n) => beak_n,\n                        None => {\n                            eprintln!(\n                                "[beak-witness-inject] kind={} row={} mult_above_scan_bound; skipped",\n                                beak_kind, beak_row_idx\n                            );\n                            break;\n                        }\n                    };\n                    // +modulus offset: congruent to the real multiplicity in F so\n                    // logup stays balanced, while the witness cell itself is a\n                    // non-canonical u32 (mult_before + P).\n                    let inject_mult = beak_mult_before.wrapping_add(BEAK_BABYBEAR_P);\n                    cols.mult_xor = F::from_wrapped_u32(inject_mult);\n                    injected = true;\n                    eprintln!(\n                        "[beak-witness-inject] kind={} mode=shadow_lookup_multiplicity row={} variant={}",\n                        beak_kind,\n                        beak_row_idx,\n                        beak_variant\n                    );\n                    fuzzer_utils::record_semantic_mutation(\n                        beak_kind,\n                        "bitwise_op_lookup.generate_trace",\n                        "mult_xor",\n                        beak_row_idx as u64,\n                        serde_json::json!(beak_mult_before),\n                        serde_json::json!(inject_mult),\n                        serde_json::json!({\n                            "relation": "shadow_lookup_multiplicity",\n                            "context": {\n                                "bucket_id": "sem.lookup.xor_multiplicity_consistency",\n                                "cell_id": "bu1.xor_shadow_mult",\n                                "mode": mode,\n                                "rank": rank,\n                                "strength": strength,\n                                "row_idx": beak_row_idx as u64,\n                                "mult_before": beak_mult_before,\n                                "mult_after": inject_mult,\n                                "field_modulus": BEAK_BABYBEAR_P as u64,\n                                "shadow_equivalent": inject_mult % BEAK_BABYBEAR_P == beak_mult_before,\n                                "executed_nonzero_row": true\n                            }\n                        }),\n                    );\n                    break;\n                }\n            }\n            if !injected {\n                eprintln!(\n                    "[beak-witness-inject] kind={} mode=shadow_lookup_multiplicity variant={} no_ranked_nonzero_xor_row",\n                    beak_kind,\n                    beak_variant\n                );\n            }\n        }\n        // BEAK-INSERT-END\n'
    c = _refresh_guarded_block(c, template=o1_insert, guard=o1_guard)
    try:
        c = _insert_before(
            c,
            anchor='        RowMajorMatrix::new(rows, NUM_BITWISE_OP_LOOKUP_COLS)',
            guard=o1_guard,
            insert=o1_insert,
        )
    except RuntimeError:
        return
    o1_obs_guard = '// BEAK-INSERT: trace.audit-o1.lookup_table.shadow_mult_observation'
    o1_obs_insert = '\n        // BEAK-INSERT: trace.audit-o1.lookup_table.shadow_mult_observation\n        // Emit one lookup_multiplicity observation per nonzero mult_xor table\n        // row so the frontend can bind xor_multiplicity_consistency receipts to\n        // the preprocessed lookup-table row index (not an execution step).\n        for (beak_obs_idx, beak_obs_row) in rows.chunks(NUM_BITWISE_OP_LOOKUP_COLS).enumerate() {\n            let beak_obs_cols: &BitwiseOperationLookupCols<F> = beak_obs_row.borrow();\n            if beak_obs_cols.mult_xor != F::ZERO {\n                let mut beak_obs_mult: u32 = 1;\n                for beak_obs_n in 0..=65537u32 {\n                    if beak_obs_cols.mult_xor == F::from_canonical_u32(beak_obs_n) {\n                        beak_obs_mult = beak_obs_n;\n                        break;\n                    }\n                }\n                fuzzer_utils::emit_lookup_multiplicity(\n                    "bitwise_op_lookup.xor_shadow_mult",\n                    beak_obs_idx as u64,\n                    beak_obs_mult,\n                    true,\n                );\n            }\n        }\n        // BEAK-INSERT-END\n'
    c = _refresh_guarded_block(c, template=o1_obs_insert, guard=o1_obs_guard)
    try:
        c = _insert_before(
            c,
            anchor='        RowMajorMatrix::new(rows, NUM_BITWISE_OP_LOOKUP_COLS)',
            guard=o1_obs_guard,
            insert=o1_obs_insert,
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_f038_volatile_boundary_collection_and_remap(openvm_install_path = None):
    kind = 'openvm.semantic.memory.volatile_boundary_range'
    program = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'program' / 'trace.rs'
    if program.exists():
        _ensure_use_fuzzer_utils(program)
        c = program.read_text()
        marker = '// BEAK-INSERT: guard.f038.program_trace.volatile_boundary_remap'
        anchor = '            // BEAK-INSERT: guard.f038.program_trace.mem_as_pre_access\n'
        insert = f'''            // BEAK-INSERT: guard.f038.program_trace.volatile_boundary_remap\n            if let Some(remap) = fuzzer_utils::active_volatile_boundary_remap(\n                "{kind}",\n            ) {{\n                let maybe_a = remap.map(\n                    instruction.d.as_canonical_u64() as u32,\n                    instruction.a.as_canonical_u64() as u32,\n                );\n                if let Some((new_as, new_ptr)) = maybe_a {{\n                    row.d = F::from_canonical_u32(new_as);\n                    row.a = F::from_canonical_u32(new_ptr);\n                }}\n                let maybe_b = remap.map(\n                    instruction.d.as_canonical_u64() as u32,\n                    instruction.b.as_canonical_u64() as u32,\n                );\n                if let Some((new_as, new_ptr)) = maybe_b {{\n                    row.d = F::from_canonical_u32(new_as);\n                    row.b = F::from_canonical_u32(new_ptr);\n                }}\n                let maybe_c = remap.map(\n                    instruction.e.as_canonical_u64() as u32,\n                    instruction.c.as_canonical_u64() as u32,\n                );\n                if let Some((new_as, new_ptr)) = maybe_c {{\n                    row.e = F::from_canonical_u32(new_as);\n                    row.c = F::from_canonical_u32(new_ptr);\n                }}\n            }}\n            // BEAK-INSERT-END\n\n'''
        if marker not in c and anchor in c:
            c = c.replace(anchor, insert + anchor, 1)
        program.write_text(c)
    volatile = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'memory' / 'volatile' / 'mod.rs'
    if volatile.exists():
        _ensure_use_fuzzer_utils(volatile)
        c = volatile.read_text()
        legacy_marker = '                // BEAK-INSERT: guard.f038.volatile.o25\n'
        if legacy_marker in c:
            legacy_start = c.index(legacy_marker)
            legacy_end_marker = '                // BEAK-INSERT-END\n'
            legacy_end = c.index(legacy_end_marker, legacy_start) + len(legacy_end_marker)
            c = c[:legacy_start] + c[legacy_end:]
        if 'emit_volatile_boundary(' not in c:
            c = c.replace('                row.final_data = data;\n                row.final_timestamp = Val::<SC>::from_canonical_u32(timestamped_values.timestamp);\n                row.is_valid = Val::<SC>::ONE;\n\n                // If next.is_valid == 1:\n', '                row.final_data = data;\n                row.final_timestamp = Val::<SC>::from_canonical_u32(timestamped_values.timestamp);\n                row.is_valid = Val::<SC>::ONE;\n                fuzzer_utils::emit_volatile_boundary(\n                    i as u64,\n                    row.addr_space.as_canonical_u32(),\n                    row.pointer.as_canonical_u32(),\n                    true,\n                );\n\n                // If next.is_valid == 1:\n', 1)
        row_marker = '// BEAK-INSERT: guard.f038.volatile.o25.row_witness'
        post_anchor = '        let trace = RowMajorMatrix::new(rows, width);\n'
        post_insert = '        // BEAK-INSERT: guard.f038.volatile.o25.row_witness\n        if let Some(remap) = fuzzer_utils::active_volatile_boundary_remap(\n            "openvm.semantic.memory.volatile_boundary_range",\n        ) {\n            for (i, row) in rows.chunks_mut(width).enumerate().take(memory_len) {\n                if remap.row_idx != i as u64 || i + 1 != memory_len {\n                    continue;\n                }\n                let row: &mut VolatileBoundaryCols<_> = row.borrow_mut();\n                let old_as = row.addr_space.as_canonical_u32();\n                let old_ptr = row.pointer.as_canonical_u32();\n                let Some((new_as, new_ptr)) = remap.map(old_as, old_ptr) else {\n                    continue;\n                };\n                if remap.cell_id != "rc3.volatile_pointer" {\n                    continue;\n                }\n                // Keep finalized-memory keys and address-space limbs intact;\n                // only the volatile boundary pointer witness is forged.\n                row.pointer = Val::<SC>::from_canonical_u32(new_ptr);\n                fuzzer_utils::mark_witness_mutation_applied(\n                    "openvm.semantic.memory.volatile_boundary_range",\n                    i as u64,\n                );\n                fuzzer_utils::record_semantic_mutation(\n                    "openvm.semantic.memory.volatile_boundary_range",\n                    "volatile_boundary.generate_air_proof_input",\n                    "pointer",\n                    i as u64,\n                    serde_json::json!({"address_space": old_as, "pointer": old_ptr}),\n                    serde_json::json!({"address_space": old_as, "pointer": new_ptr}),\n                    serde_json::json!({"relation": "volatile_boundary_range", "context": {\n                        "cell_id": remap.cell_id,\n                        "row_idx": i,\n                        "row_anchor": i,\n                        "address_space_before": old_as,\n                        "address_space_after": old_as,\n                        "pointer_before": old_ptr,\n                        "pointer_after": new_ptr,\n                        "width": remap.width,\n                        "volatile_start": remap.volatile_start,\n                        "volatile_end": remap.volatile_end,\n                        "forged_address": new_ptr,\n                        "outside_volatile_range": true,\n                        "final_row_transition_count": 0\n                    }}),\n                );\n                let _ = new_as;\n                break;\n            }\n        }\n        // BEAK-INSERT-END\n'
        if row_marker not in c and post_anchor in c:
            c = c.replace(post_anchor, post_insert + post_anchor, 1)
        volatile.write_text(c)
        return None


def _patch_f038_loadstore_immediate_sign_witness_injection(openvm_install_path = None):
    path = openvm_install_path / 'extensions' / 'rv32im' / 'circuit' / 'src' / 'adapters' / 'loadstore.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '        let rs1_val = compose(rs1_record.1);\n        let imm = c.as_canonical_u32();\n        let imm_sign = g.as_canonical_u32();\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        let imm_extended = imm + imm_sign * 0xffff0000;\n\n        let ptr_val = rs1_val.wrapping_add(imm_extended);\n'
    new = '        let rs1_val = compose(rs1_record.1);\n        let imm = c.as_canonical_u32();\n        let imm_sign = g.as_canonical_u32();\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n\n        // BEAK-INSERT: guard.f038.loadstore.adapter.immediate_sign\n        let mut beak_imm_sign = imm_sign;\n        let beak_sign_active = fuzzer_utils::matching_injection_kind(\n            "openvm.semantic.memory.immediate_sign_consistency",\n            beak_witness_step,\n        )\n        .is_some();\n        if beak_sign_active {\n            let candidate_sign = if imm_sign == 1 { 0 } else { 1 };\n            let candidate_ext = imm + candidate_sign * 0xffff0000;\n            let candidate_ptr = rs1_val.wrapping_add(candidate_ext);\n            if candidate_ptr < (1 << self.air.pointer_max_bits)\n                && fuzzer_utils::should_inject_witness(\n                    "openvm.semantic.memory.immediate_sign_consistency",\n                    beak_witness_step,\n                )\n            {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.memory.immediate_sign_consistency step={} imm={} orig_sign={} injected_sign={} orig_rs1={} injected_ptr={}",\n                    beak_witness_step,\n                    imm,\n                    imm_sign,\n                    candidate_sign,\n                    rs1_val,\n                    candidate_ptr\n                );\n                beak_imm_sign = candidate_sign;\n            } else {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.memory.immediate_sign_consistency step={} imm={} skip_out_of_range orig_sign={} candidate_sign={} orig_rs1={} candidate_ptr={}",\n                    beak_witness_step,\n                    imm,\n                    imm_sign,\n                    candidate_sign,\n                    rs1_val,\n                    candidate_ptr\n                );\n            }\n        }\n        // BEAK-INSERT-END\n        let imm_extended = imm + beak_imm_sign * 0xffff0000;\n\n        let ptr_val = rs1_val.wrapping_add(imm_extended);\n'
    if '// BEAK-INSERT: guard.f038.loadstore.adapter.immediate_sign' not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_f038_memory_finalization_instrumentation(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'memory' / 'controller' / 'mod.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '                let final_partition = offline_memory.finalize::<CHUNK>(&mut self.access_adapters);\n\n                boundary_chip.finalize(initial_memory, &final_partition, hasher);\n                let final_memory_values = final_partition\n'
    new = '                let mut final_partition = offline_memory.finalize::<CHUNK>(&mut self.access_adapters);\n\n                // BEAK-INSERT: guard.f038.memory.lifecycle.finalization\n                let beak_final_cells: Vec<_> = final_partition\n                    .iter()\n                    .map(|(&(address_space, chunk_label), values)| {\n                        let pointer = chunk_label * CHUNK as u32;\n                        let final_values = values\n                            .values\n                            .iter()\n                            .map(|value| value.as_canonical_u32())\n                            .collect::<Vec<_>>();\n                        let initial_values = (0..CHUNK as u32)\n                            .map(|offset| {\n                                initial_memory\n                                    .get(&(address_space, pointer + offset))\n                                    .copied()\n                                    .unwrap_or(F::ZERO)\n                                    .as_canonical_u32()\n                            })\n                            .collect::<Vec<_>>();\n                        let was_initial = initial_values.iter().any(|value| *value != 0);\n                        let changed_from_initial = final_values != initial_values;\n                        (\n                            (address_space, chunk_label),\n                            pointer,\n                            values.timestamp,\n                            final_values,\n                            was_initial,\n                            changed_from_initial,\n                        )\n                    })\n                    .collect();\n                for (\n                    beak_final_idx,\n                    (\n                        (address_space, chunk_label),\n                        pointer,\n                        timestamp,\n                        final_values,\n                        was_initial,\n                        changed_from_initial,\n                    ),\n                ) in beak_final_cells.into_iter().enumerate()\n                {\n                    let beak_final_idx = beak_final_idx as u64;\n                    fuzzer_utils::emit_memory_finalization(\n                        beak_final_idx,\n                        address_space,\n                        pointer,\n                        timestamp,\n                        final_values,\n                        was_initial,\n                        changed_from_initial,\n                    );\n                    if fuzzer_utils::should_inject_witness(\n                        "openvm.semantic.memory.finalization_consistency",\n                        beak_final_idx,\n                    ) {\n                        eprintln!(\n                            "[beak-witness-inject] kind=openvm.semantic.memory.finalization_consistency step={} address_space={} pointer={} timestamp={}",\n                            beak_final_idx,\n                            address_space,\n                            pointer,\n                            timestamp\n                        );\n                        if let Some(values) =\n                            final_partition.get_mut(&(address_space, chunk_label))\n                        {\n                            values.values[0] += F::from_canonical_u32(1);\n                        }\n                    }\n                }\n                // BEAK-INSERT-END\n\n                boundary_chip.finalize(initial_memory, &final_partition, hasher);\n                let final_memory_values = final_partition\n'
    if '// BEAK-INSERT: guard.f038.memory.lifecycle.finalization' not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_f038_connector_witness_injection(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'connector' / 'mod.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old_partial = '    pub fn begin(&mut self, state: ExecutionState<u32>) {\n        let mut beak_ts = state.timestamp;\n        let beak_step = fuzzer_utils::current_witness_step();\n        if let Some(beak_wrap) = fuzzer_utils::should_apply_time_origin_wrap_at(\n            "openvm.semantic.time.boundary_origin_consistency",\n            beak_step,\n        ) {\n            let beak_later_timestamp =\n                beak_wrap.origin.wrapping_add(beak_wrap.increment) % beak_wrap.modulus;\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.time.boundary_origin_consistency step={} from_ts={} origin={} later_ts={}",\n                beak_step,\n                state.timestamp,\n                beak_wrap.origin,\n                beak_later_timestamp\n            );\n            beak_ts = beak_wrap.origin;\n            fuzzer_utils::record_semantic_mutation(\n                "openvm.semantic.time.boundary_origin_consistency",\n                "system_connector.begin",\n                "boundary_timestamp",\n                beak_step,\n                serde_json::json!(state.timestamp),\n                serde_json::json!(beak_wrap.origin),\n                serde_json::json!({\n                    "relation": "timestamp_origin_wrap",\n                    "context": {\n                        "trace_source": "memory_initial_block",\n                        "cell_id": "ts1.standard",\n                        "mode": "wrap_origin",\n                        "modulus": beak_wrap.modulus,\n                        "origin": beak_wrap.origin,\n                        "increment": beak_wrap.increment,\n                        "later_timestamp": beak_later_timestamp,\n                        "wrapped": beak_later_timestamp < beak_wrap.origin\n                    }\n                }),\n            );\n        }\n        self.boundary_states[0] = Some(ConnectorCols {\n            pc: state.pc,\n            timestamp: beak_ts,\n            is_terminate: 0,\n            exit_code: 0,\n        });\n    }\n'
    clean = '    pub fn begin(&mut self, state: ExecutionState<u32>) {\n        self.boundary_states[0] = Some(ConnectorCols {\n            pc: state.pc,\n            timestamp: state.timestamp,\n            is_terminate: 0,\n            exit_code: 0,\n        });\n    }\n'
    if old_partial in c:
        c = c.replace(old_partial, clean, 1)
    stale_observed_begin = '    pub fn begin(&mut self, state: ExecutionState<u32>) {\n        // BEAK-INSERT: guard.f038.connector_boundary_origin\n        // Capture the concrete execution boundary before any instruction advances it.\n        fuzzer_utils::emit_connector_boundary_origin(state.pc, state.timestamp);\n        // BEAK-INSERT-END\n        self.boundary_states[0] = Some(ConnectorCols {\n            pc: state.pc,\n            timestamp: state.timestamp,\n            is_terminate: 0,\n            exit_code: 0,\n        });\n    }\n'
    if stale_observed_begin in c:
        c = c.replace(stale_observed_begin, clean, 1)
    clean_end = '    pub fn end(&mut self, state: ExecutionState<u32>, exit_code: Option<u32>) {\n        self.boundary_states[1] = Some(ConnectorCols {\n            pc: state.pc,\n            timestamp: state.timestamp,\n            is_terminate: exit_code.is_some() as u32,\n            exit_code: exit_code.unwrap_or(DEFAULT_SUSPEND_EXIT_CODE),\n        });\n    }\n'
    observed_end = '    pub fn end(&mut self, state: ExecutionState<u32>, exit_code: Option<u32>) {\n        self.boundary_states[1] = Some(ConnectorCols {\n            pc: state.pc,\n            timestamp: state.timestamp,\n            is_terminate: exit_code.is_some() as u32,\n            exit_code: exit_code.unwrap_or(DEFAULT_SUSPEND_EXIT_CODE),\n        });\n\n        // BEAK-INSERT: guard.f038.connector_boundary_observation\n        let begin = self.boundary_states[0].expect("connector begin state must be set");\n        fuzzer_utils::emit_connector_chip_row(\n            begin.pc,\n            state.pc,\n            Some(begin.timestamp),\n            Some(state.timestamp),\n            exit_code.is_some(),\n            exit_code,\n        );\n        // BEAK-INSERT-END\n    }\n'
    if observed_end in c:
        c = c.replace(observed_end, clean_end, 1)
    path.write_text(c)


def _patch_frozen_time_origin_wrap_witness_injection(openvm_install_path = None):
    kind = 'openvm.semantic.time.boundary_origin_consistency'
    online = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'memory' / 'online.rs'
    if online.exists():
        _ensure_use_fuzzer_utils(online)
        c = online.read_text()
        old_new = '    pub fn new(mem_config: &MemoryConfig) -> Self {\n        Self {\n            data: AddressMap::from_mem_config(mem_config),\n            timestamp: INITIAL_TIMESTAMP + 1,\n            log: Vec::with_capacity(mem_config.access_capacity),\n        }\n    }\n'
        stale_new_new = f'''    pub fn new(mem_config: &MemoryConfig) -> Self {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.online_new\n        let beak_later_timestamp = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0)\n            .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n            .unwrap_or(INITIAL_TIMESTAMP + 1);\n        Self {{\n            data: AddressMap::from_mem_config(mem_config),\n            timestamp: beak_later_timestamp,\n            log: Vec::with_capacity(mem_config.access_capacity),\n        }}\n    }}\n'''
        stale_shiftbase_new_new = f'''    pub fn new(mem_config: &MemoryConfig) -> Self {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.online_new\n        let beak_wrap = fuzzer_utils::should_apply_time_origin_wrap_at("{kind}", 0);\n        let beak_origin = beak_wrap.map(|wrap| wrap.origin).unwrap_or(INITIAL_TIMESTAMP);\n        let beak_later_timestamp = beak_wrap\n            .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n            .unwrap_or(INITIAL_TIMESTAMP + 1);\n        if let Some(beak_wrap) = beak_wrap {{\n            fuzzer_utils::record_semantic_mutation(\n                "{kind}",\n                "online_memory.new",\n                "initial_timestamp_origin",\n                0,\n                serde_json::json!(INITIAL_TIMESTAMP),\n                serde_json::json!(beak_origin),\n                serde_json::json!({{\n                    "relation": "timestamp_origin_wrap",\n                    "context": {{\n                        "cell_id": "ts1.standard",\n                        "mode": "wrap_origin",\n                        "modulus": beak_wrap.modulus,\n                        "origin": beak_wrap.origin,\n                        "origin_before": INITIAL_TIMESTAMP,\n                        "origin_after": beak_origin,\n                        "increment": beak_wrap.increment,\n                        "later_before": INITIAL_TIMESTAMP + beak_wrap.increment,\n                        "later_after": beak_later_timestamp,\n                        "near_modulus": beak_origin >= beak_wrap.modulus - beak_wrap.increment,\n                        "wrapped": beak_later_timestamp < beak_origin\n                    }}\n                }}),\n            );\n        }}\n        fuzzer_utils::emit_timestamp_boundary_origin(beak_origin);\n        Self {{\n            data: AddressMap::from_mem_config(mem_config),\n            timestamp: beak_later_timestamp,\n            log: Vec::with_capacity(mem_config.access_capacity),\n        }}\n    }}\n'''
        new_new = f'''    pub fn new(mem_config: &MemoryConfig) -> Self {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.online_new\n        let beak_shift = fuzzer_utils::active_time_origin_shift_delta_at("{kind}", 0);\n        let beak_wrap = fuzzer_utils::should_apply_time_origin_wrap_at("{kind}", 0);\n        let beak_origin = beak_wrap.map(|wrap| wrap.origin).unwrap_or(INITIAL_TIMESTAMP);\n        let beak_later_timestamp = if let Some(beak_shift) = beak_shift {{\n            INITIAL_TIMESTAMP + 1 + beak_shift\n        }} else {{\n            beak_wrap\n                .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n                .unwrap_or(INITIAL_TIMESTAMP + 1)\n        }};\n        if let Some(beak_shift) = beak_shift {{\n            fuzzer_utils::record_semantic_mutation(\n                "{kind}",\n                "online_memory.new",\n                "initial_timestamp_origin",\n                0,\n                serde_json::json!(INITIAL_TIMESTAMP),\n                serde_json::json!(INITIAL_TIMESTAMP + beak_shift),\n                serde_json::json!({{\n                    "relation": "timestamp_origin_wrap",\n                    "context": {{\n                        "cell_id": "ts1.standard",\n                        "mode": "shift_origin",\n                        "delta": beak_shift,\n                        "origin_before": INITIAL_TIMESTAMP,\n                        "origin_after": INITIAL_TIMESTAMP + beak_shift,\n                        "later_before": INITIAL_TIMESTAMP + 1,\n                        "later_after": beak_later_timestamp,\n                        "wrapped": false\n                    }}\n                }}),\n            );\n        }} else if let Some(beak_wrap) = beak_wrap {{\n            fuzzer_utils::record_semantic_mutation(\n                "{kind}",\n                "online_memory.new",\n                "initial_timestamp_origin",\n                0,\n                serde_json::json!(INITIAL_TIMESTAMP),\n                serde_json::json!(beak_origin),\n                serde_json::json!({{\n                    "relation": "timestamp_origin_wrap",\n                    "context": {{\n                        "cell_id": "ts1.standard",\n                        "mode": "wrap_origin",\n                        "modulus": beak_wrap.modulus,\n                        "origin": beak_wrap.origin,\n                        "origin_before": INITIAL_TIMESTAMP,\n                        "origin_after": beak_origin,\n                        "increment": beak_wrap.increment,\n                        "later_before": INITIAL_TIMESTAMP + beak_wrap.increment,\n                        "later_after": beak_later_timestamp,\n                        "near_modulus": beak_origin >= beak_wrap.modulus - beak_wrap.increment,\n                        "wrapped": beak_later_timestamp < beak_origin\n                    }}\n                }}),\n            );\n        }}\n        fuzzer_utils::emit_timestamp_boundary_origin(beak_origin);\n        Self {{\n            data: AddressMap::from_mem_config(mem_config),\n            timestamp: beak_later_timestamp,\n            log: Vec::with_capacity(mem_config.access_capacity),\n        }}\n    }}\n'''
        stale_guarded_new_new = new_new.replace('        fuzzer_utils::emit_timestamp_boundary_origin(beak_origin);\n', '')
        old_from_image = '    pub fn from_image(image: MemoryImage<F>, access_capacity: usize) -> Self {\n        Self {\n            data: image,\n            timestamp: INITIAL_TIMESTAMP + 1,\n            log: Vec::with_capacity(access_capacity),\n        }\n    }\n'
        stale_new_from_image = f'''    pub fn from_image(image: MemoryImage<F>, access_capacity: usize) -> Self {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.online_from_image\n        let beak_later_timestamp = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0)\n            .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n            .unwrap_or(INITIAL_TIMESTAMP + 1);\n        Self {{\n            data: image,\n            timestamp: beak_later_timestamp,\n            log: Vec::with_capacity(access_capacity),\n        }}\n    }}\n'''
        stale_shiftbase_from_image = f'''    pub fn from_image(image: MemoryImage<F>, access_capacity: usize) -> Self {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.online_from_image\n        let beak_wrap = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0);\n        let beak_origin = beak_wrap.map(|wrap| wrap.origin).unwrap_or(INITIAL_TIMESTAMP);\n        let beak_later_timestamp = beak_wrap\n            .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n            .unwrap_or(INITIAL_TIMESTAMP + 1);\n        fuzzer_utils::emit_timestamp_boundary_origin(beak_origin);\n        Self {{\n            data: image,\n            timestamp: beak_later_timestamp,\n            log: Vec::with_capacity(access_capacity),\n        }}\n    }}\n'''
        new_from_image = f'''    pub fn from_image(image: MemoryImage<F>, access_capacity: usize) -> Self {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.online_from_image\n        let beak_shift = fuzzer_utils::active_time_origin_shift_delta_at("{kind}", 0);\n        let beak_wrap = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0);\n        let beak_origin = beak_wrap.map(|wrap| wrap.origin).unwrap_or(INITIAL_TIMESTAMP);\n        let beak_later_timestamp = if let Some(beak_shift) = beak_shift {{\n            INITIAL_TIMESTAMP + 1 + beak_shift\n        }} else {{\n            beak_wrap\n                .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n                .unwrap_or(INITIAL_TIMESTAMP + 1)\n        }};\n        fuzzer_utils::emit_timestamp_boundary_origin(beak_origin);\n        Self {{\n            data: image,\n            timestamp: beak_later_timestamp,\n            log: Vec::with_capacity(access_capacity),\n        }}\n    }}\n'''
        if stale_shiftbase_new_new in c:
            c = c.replace(stale_shiftbase_new_new, new_new, 1)
        elif stale_guarded_new_new in c:
            c = c.replace(stale_guarded_new_new, new_new, 1)
        elif stale_new_new in c:
            c = c.replace(stale_new_new, new_new, 1)
        elif 'guard.frozen_openvm.time_origin_wrap.online_new' not in c and old_new in c:
            c = c.replace(old_new, new_new, 1)
        if stale_shiftbase_from_image in c:
            c = c.replace(stale_shiftbase_from_image, new_from_image, 1)
        elif stale_new_from_image in c:
            c = c.replace(stale_new_from_image, new_from_image, 1)
        elif 'guard.frozen_openvm.time_origin_wrap.online_from_image' not in c and old_from_image in c:
            c = c.replace(old_from_image, new_from_image, 1)
        online.write_text(c)
    offline = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'memory' / 'offline.rs'
    if offline.exists():
        _ensure_use_fuzzer_utils(offline)
        c = offline.read_text()
        old_block_ts = '        BlockData {\n            pointer: aligned_pointer,\n            size: initial_block_size,\n            timestamp: INITIAL_TIMESTAMP,\n        }\n'
        stale_applied_block_ts = f'''        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.initial_block\n        let mut block = BlockData {{\n            pointer: aligned_pointer,\n            size: initial_block_size,\n            timestamp: INITIAL_TIMESTAMP,\n        }};\n        if let Some(beak_wrap) =\n            fuzzer_utils::should_apply_time_origin_wrap_at("{kind}", 0)\n        {{\n            let beak_later_before = INITIAL_TIMESTAMP + beak_wrap.increment;\n            let beak_later_after =\n                beak_wrap.origin.wrapping_add(beak_wrap.increment) % beak_wrap.modulus;\n            block.timestamp = beak_wrap.origin;\n            fuzzer_utils::record_semantic_mutation(\n                "{kind}",\n                "offline_memory.initial_block_data",\n                "initial_timestamp_origin",\n                0,\n                serde_json::json!(INITIAL_TIMESTAMP),\n                serde_json::json!(block.timestamp),\n                serde_json::json!({{\n                    "relation": "timestamp_origin_wrap",\n                    "context": {{\n                        "cell_id": "ts1.standard",\n                        "mode": "wrap_origin",\n                        "modulus": beak_wrap.modulus,\n                        "origin": beak_wrap.origin,\n                        "origin_before": INITIAL_TIMESTAMP,\n                        "origin_after": block.timestamp,\n                        "increment": beak_wrap.increment,\n                        "later_before": beak_later_before,\n                        "later_after": beak_later_after,\n                        "near_modulus": block.timestamp >= beak_wrap.modulus - beak_wrap.increment,\n                        "wrapped": beak_later_after < block.timestamp\n                    }}\n                }}),\n            );\n        }}\n        fuzzer_utils::emit_timestamp_boundary_origin(block.timestamp);\n        block\n'''
        stale_guarded_block_ts = stale_applied_block_ts.replace('        fuzzer_utils::emit_timestamp_boundary_origin(block.timestamp);\n', '')
        new_block_ts = f'''        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.initial_block\n        let mut block = BlockData {{\n            pointer: aligned_pointer,\n            size: initial_block_size,\n            timestamp: INITIAL_TIMESTAMP,\n        }};\n        if let Some(beak_wrap) = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0) {{\n            block.timestamp = beak_wrap.origin;\n        }}\n        fuzzer_utils::emit_timestamp_boundary_origin(block.timestamp);\n        block\n'''
        stale_current_block_ts = new_block_ts.replace('        fuzzer_utils::emit_timestamp_boundary_origin(block.timestamp);\n', '')
        old_offline_new = '    pub fn new(\n        initial_memory: MemoryImage<F>,\n        initial_block_size: usize,\n        memory_bus: MemoryBus,\n        range_checker: SharedVariableRangeCheckerChip,\n        config: MemoryConfig,\n    ) -> Self {\n        Self {\n            block_data: BlockMap::from_mem_config(&config, initial_block_size),\n            data: Self::memory_image_to_paged_vec(initial_memory, config),\n            as_offset: config.as_offset,\n            timestamp: INITIAL_TIMESTAMP + 1,\n            timestamp_max_bits: config.clk_max_bits,\n            memory_bus,\n            range_checker,\n            log: vec![],\n        }\n    }\n'
        stale_offline_new = f'''    pub fn new(\n        initial_memory: MemoryImage<F>,\n        initial_block_size: usize,\n        memory_bus: MemoryBus,\n        range_checker: SharedVariableRangeCheckerChip,\n        config: MemoryConfig,\n    ) -> Self {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.offline_new\n        let beak_later_timestamp = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0)\n            .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n            .unwrap_or(INITIAL_TIMESTAMP + 1);\n        Self {{\n            block_data: BlockMap::from_mem_config(&config, initial_block_size),\n            data: Self::memory_image_to_paged_vec(initial_memory, config),\n            as_offset: config.as_offset,\n            timestamp: beak_later_timestamp,\n            timestamp_max_bits: config.clk_max_bits,\n            memory_bus,\n            range_checker,\n            log: vec![],\n        }}\n    }}\n'''
        new_offline_new = f'''    pub fn new(\n        initial_memory: MemoryImage<F>,\n        initial_block_size: usize,\n        memory_bus: MemoryBus,\n        range_checker: SharedVariableRangeCheckerChip,\n        config: MemoryConfig,\n    ) -> Self {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.offline_new\n        let beak_wrap = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0);\n        let beak_origin = beak_wrap.map(|wrap| wrap.origin).unwrap_or(INITIAL_TIMESTAMP);\n        let beak_later_timestamp = beak_wrap\n            .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n            .unwrap_or(INITIAL_TIMESTAMP + 1);\n        fuzzer_utils::emit_timestamp_boundary_origin(beak_origin);\n        Self {{\n            block_data: BlockMap::from_mem_config(&config, initial_block_size),\n            data: Self::memory_image_to_paged_vec(initial_memory, config),\n            as_offset: config.as_offset,\n            timestamp: beak_later_timestamp,\n            timestamp_max_bits: config.clk_max_bits,\n            memory_bus,\n            range_checker,\n            log: vec![],\n        }}\n    }}\n'''
        old_offline_new_336 = '    pub fn new(\n        initial_memory: MemoryImage<F>,\n        initial_block_size: usize,\n        memory_bus: MemoryBus,\n        range_checker: SharedVariableRangeCheckerChip,\n        config: MemoryConfig,\n    ) -> Self {\n        fuzzer_utils::fuzzer_assert!(initial_block_size.is_power_of_two());\n\n        Self {\n            block_data: AddressMap::from_mem_config(&config),\n            data: Self::memory_image_to_paged_vec(initial_memory, config),\n            as_offset: config.as_offset,\n            initial_block_size,\n            timestamp: INITIAL_TIMESTAMP + 1,\n            timestamp_max_bits: config.clk_max_bits,\n            memory_bus,\n            range_checker,\n            log: vec![],\n        }\n    }\n'
        stale_offline_new_336 = f'''    pub fn new(\n        initial_memory: MemoryImage<F>,\n        initial_block_size: usize,\n        memory_bus: MemoryBus,\n        range_checker: SharedVariableRangeCheckerChip,\n        config: MemoryConfig,\n    ) -> Self {{\n        fuzzer_utils::fuzzer_assert!(initial_block_size.is_power_of_two());\n\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.offline_new\n        let beak_later_timestamp = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0)\n            .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n            .unwrap_or(INITIAL_TIMESTAMP + 1);\n        Self {{\n            block_data: AddressMap::from_mem_config(&config),\n            data: Self::memory_image_to_paged_vec(initial_memory, config),\n            as_offset: config.as_offset,\n            initial_block_size,\n            timestamp: beak_later_timestamp,\n            timestamp_max_bits: config.clk_max_bits,\n            memory_bus,\n            range_checker,\n            log: vec![],\n        }}\n    }}\n'''
        stale_shiftbase_offline_new_336 = f'''    pub fn new(\n        initial_memory: MemoryImage<F>,\n        initial_block_size: usize,\n        memory_bus: MemoryBus,\n        range_checker: SharedVariableRangeCheckerChip,\n        config: MemoryConfig,\n    ) -> Self {{\n        fuzzer_utils::fuzzer_assert!(initial_block_size.is_power_of_two());\n\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.offline_new\n        let beak_wrap = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0);\n        let beak_origin = beak_wrap.map(|wrap| wrap.origin).unwrap_or(INITIAL_TIMESTAMP);\n        let beak_later_timestamp = beak_wrap\n            .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n            .unwrap_or(INITIAL_TIMESTAMP + 1);\n        fuzzer_utils::emit_timestamp_boundary_origin(beak_origin);\n        Self {{\n            block_data: AddressMap::from_mem_config(&config),\n            data: Self::memory_image_to_paged_vec(initial_memory, config),\n            as_offset: config.as_offset,\n            initial_block_size,\n            timestamp: beak_later_timestamp,\n            timestamp_max_bits: config.clk_max_bits,\n            memory_bus,\n            range_checker,\n            log: vec![],\n        }}\n    }}\n'''
        new_offline_new_336 = f'''    pub fn new(\n        initial_memory: MemoryImage<F>,\n        initial_block_size: usize,\n        memory_bus: MemoryBus,\n        range_checker: SharedVariableRangeCheckerChip,\n        config: MemoryConfig,\n    ) -> Self {{\n        fuzzer_utils::fuzzer_assert!(initial_block_size.is_power_of_two());\n\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.offline_new\n        let beak_shift = fuzzer_utils::active_time_origin_shift_delta_at("{kind}", 0);\n        let beak_wrap = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0);\n        let beak_origin = beak_wrap.map(|wrap| wrap.origin).unwrap_or(INITIAL_TIMESTAMP);\n        let beak_later_timestamp = if let Some(beak_shift) = beak_shift {{\n            INITIAL_TIMESTAMP + 1 + beak_shift\n        }} else {{\n            beak_wrap\n                .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n                .unwrap_or(INITIAL_TIMESTAMP + 1)\n        }};\n        fuzzer_utils::emit_timestamp_boundary_origin(beak_origin);\n        Self {{\n            block_data: AddressMap::from_mem_config(&config),\n            data: Self::memory_image_to_paged_vec(initial_memory, config),\n            as_offset: config.as_offset,\n            initial_block_size,\n            timestamp: beak_later_timestamp,\n            timestamp_max_bits: config.clk_max_bits,\n            memory_bus,\n            range_checker,\n            log: vec![],\n        }}\n    }}\n'''
        old_set_initial = '    pub fn set_initial_memory(&mut self, initial_memory: MemoryImage<F>, config: MemoryConfig) {\n        fuzzer_utils::fuzzer_assert_eq!(self.timestamp, INITIAL_TIMESTAMP + 1);\n        self.as_offset = config.as_offset;\n        self.data = Self::memory_image_to_paged_vec(initial_memory, config);\n    }\n'
        stale_shiftbase_set_initial = f'''    pub fn set_initial_memory(&mut self, initial_memory: MemoryImage<F>, config: MemoryConfig) {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.offline_set_initial\n        let beak_expected_timestamp = fuzzer_utils::active_time_origin_wrap_at("{kind}", 0)\n            .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n            .unwrap_or(INITIAL_TIMESTAMP + 1);\n        fuzzer_utils::fuzzer_assert_eq!(self.timestamp, beak_expected_timestamp);\n        self.as_offset = config.as_offset;\n        self.data = Self::memory_image_to_paged_vec(initial_memory, config);\n    }}\n'''
        new_set_initial = f'''    pub fn set_initial_memory(&mut self, initial_memory: MemoryImage<F>, config: MemoryConfig) {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.offline_set_initial\n        let beak_shift = fuzzer_utils::active_time_origin_shift_delta_at("{kind}", 0);\n        let beak_expected_timestamp = if let Some(beak_shift) = beak_shift {{\n            INITIAL_TIMESTAMP + 1 + beak_shift\n        }} else {{\n            fuzzer_utils::active_time_origin_wrap_at("{kind}", 0)\n                .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n                .unwrap_or(INITIAL_TIMESTAMP + 1)\n        }};\n        fuzzer_utils::fuzzer_assert_eq!(self.timestamp, beak_expected_timestamp);\n        self.as_offset = config.as_offset;\n        self.data = Self::memory_image_to_paged_vec(initial_memory, config);\n    }}\n'''
        if stale_current_block_ts in c:
            c = c.replace(stale_current_block_ts, new_block_ts, 1)
        elif stale_applied_block_ts in c:
            c = c.replace(stale_applied_block_ts, new_block_ts, 1)
        elif 'guard.frozen_openvm.time_origin_wrap.initial_block' in c and 'emit_timestamp_boundary_origin(block.timestamp)' not in c and stale_guarded_block_ts in c:
            c = c.replace(stale_guarded_block_ts, new_block_ts, 1)
        elif 'guard.frozen_openvm.time_origin_wrap.initial_block' not in c and old_block_ts in c:
            c = c.replace(old_block_ts, new_block_ts, 1)
        if stale_offline_new in c:
            c = c.replace(stale_offline_new, new_offline_new, 1)
        elif 'guard.frozen_openvm.time_origin_wrap.offline_new' not in c and old_offline_new in c:
            c = c.replace(old_offline_new, new_offline_new, 1)
        if stale_shiftbase_offline_new_336 in c:
            c = c.replace(stale_shiftbase_offline_new_336, new_offline_new_336, 1)
        elif stale_offline_new_336 in c:
            c = c.replace(stale_offline_new_336, new_offline_new_336, 1)
        elif 'guard.frozen_openvm.time_origin_wrap.offline_new' not in c and old_offline_new_336 in c:
            c = c.replace(old_offline_new_336, new_offline_new_336, 1)
        if stale_shiftbase_set_initial in c:
            c = c.replace(stale_shiftbase_set_initial, new_set_initial, 1)
        elif 'guard.frozen_openvm.time_origin_wrap.offline_set_initial' not in c and old_set_initial in c:
            c = c.replace(old_set_initial, new_set_initial, 1)
        offline.write_text(c)
    controller = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'memory' / 'controller' / 'mod.rs'
    if controller.exists():
        _ensure_use_fuzzer_utils(controller)
        c = controller.read_text()
        old = '    pub fn set_initial_memory(&mut self, memory: MemoryImage<F>) {\n        if self.timestamp() > INITIAL_TIMESTAMP + 1 {\n            panic!("Cannot set initial memory after first timestamp");\n        }\n'
        stale_shiftbase_controller = f'''    pub fn set_initial_memory(&mut self, memory: MemoryImage<F>) {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.controller_set_initial\n        let beak_expected_initial_memory_timestamp =\n            fuzzer_utils::active_time_origin_wrap_at("{kind}", 0)\n                .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n                .unwrap_or(INITIAL_TIMESTAMP + 1);\n        if self.timestamp() > beak_expected_initial_memory_timestamp {{\n            panic!("Cannot set initial memory after first timestamp");\n        }}\n'''
        new = f'''    pub fn set_initial_memory(&mut self, memory: MemoryImage<F>) {{\n        // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.controller_set_initial\n        let beak_shift = fuzzer_utils::active_time_origin_shift_delta_at("{kind}", 0);\n        let beak_expected_initial_memory_timestamp =\n            if let Some(beak_shift) = beak_shift {{\n                INITIAL_TIMESTAMP + 1 + beak_shift\n            }} else {{\n                fuzzer_utils::active_time_origin_wrap_at("{kind}", 0)\n                    .map(|wrap| wrap.origin.wrapping_add(wrap.increment) % wrap.modulus)\n                    .unwrap_or(INITIAL_TIMESTAMP + 1)\n            }};\n        if self.timestamp() > beak_expected_initial_memory_timestamp {{\n            panic!("Cannot set initial memory after first timestamp");\n        }}\n'''
        if stale_shiftbase_controller in c:
            c = c.replace(stale_shiftbase_controller, new, 1)
        elif 'guard.frozen_openvm.time_origin_wrap.controller_set_initial' not in c and old in c:
            c = c.replace(old, new, 1)
        controller.write_text(c)
    persistent = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'memory' / 'persistent.rs'
    if persistent.exists():
        _ensure_use_fuzzer_utils(persistent)
        c = persistent.read_text()
        old = '            rows.par_chunks_mut(2 * width)\n                .zip(touched_labels.into_par_iter())\n                .for_each(|(row, touched_label)| {\n'
        new = f'''            // BEAK-INSERT: guard.frozen_openvm.time_origin_wrap.persistent_rows\n            let beak_initial_timestamp =\n                fuzzer_utils::active_time_origin_wrap_at("{kind}", 0)\n                    .map(|wrap| wrap.origin)\n                    .unwrap_or(INITIAL_TIMESTAMP);\n\n            rows.par_chunks_mut(2 * width)\n                .zip(touched_labels.into_par_iter())\n                .for_each(|(row, touched_label)| {{\n'''
        if 'guard.frozen_openvm.time_origin_wrap.persistent_rows' not in c and old in c:
            c = c.replace(old, new, 1)
        c = c.replace('                        timestamp: Val::<SC>::from_canonical_u32(INITIAL_TIMESTAMP),', '                        timestamp: Val::<SC>::from_canonical_u32(beak_initial_timestamp),', 1)
        persistent.write_text(c)
    fuzzer_utils = openvm_install_path / 'crates' / 'fuzzer_utils' / 'src' / 'lib.rs'
    if fuzzer_utils.exists():
        c = fuzzer_utils.read_text()
        parser_anchor = 'fn injection_variant(kind: &str) -> Option<&str> {\n    kind.split_once("::").map(|(_, variant)| variant)\n}\n'
        parser_block = parser_anchor + '\nfn parse_time_origin_shift_delta(kind: &str) -> Option<u32> {\n    let mut mode = "shift_origin";\n    let mut delta = 1u32;\n\n    if let Some(variant) = injection_variant(kind) {\n        for part in variant.split(\',\') {\n            if let Some((key, value)) = part.split_once(\'=\') {\n                match key.trim() {\n                    "mode" => mode = value.trim(),\n                    "delta" => {\n                        if let Ok(parsed) = value.trim().parse::<u32>() {\n                            delta = parsed;\n                        }\n                    }\n                    _ => {}\n                }\n            }\n        }\n    }\n\n    (mode == "shift_origin").then_some(delta)\n}\n'
        if 'parse_time_origin_shift_delta' not in c and parser_anchor in c:
            c = c.replace(parser_anchor, parser_block, 1)
        method_anchor = '    pub fn take_observed_witness_sites(&mut self) -> BTreeMap<String, Vec<u64>> {\n'
        method_block = '    pub fn active_time_origin_shift_delta_at(&self, kind: &str, step: u64) -> Option<u32> {\n        self.should_inject_witness(kind, step)\n            .then(|| parse_time_origin_shift_delta(self.injection_kind.as_str()))\n            .flatten()\n    }\n\n' + method_anchor
        if 'active_time_origin_shift_delta_at(&self' not in c and method_anchor in c:
            c = c.replace(method_anchor, method_block, 1)
        free_anchor = 'pub fn active_time_origin_wrap_at(kind: &str, step: u64) -> Option<TimestampOriginWrap> {\n    let state = GLOBAL_STATE.lock().unwrap();\n    state.active_time_origin_wrap_at(kind, step)\n}\n'
        free_block = free_anchor + '\npub fn active_time_origin_shift_delta_at(kind: &str, step: u64) -> Option<u32> {\n    let mut state = GLOBAL_STATE.lock().unwrap();\n    state.note_witness_site(kind, step);\n    let delta = state.active_time_origin_shift_delta_at(kind, step)?;\n    state.note_applied_witness_site(kind, step);\n    Some(delta)\n}\n'
        stale_free_block = free_anchor + '\npub fn active_time_origin_shift_delta_at(kind: &str, step: u64) -> Option<u32> {\n    let state = GLOBAL_STATE.lock().unwrap();\n    state.active_time_origin_shift_delta_at(kind, step)\n}\n'
        if stale_free_block in c:
            c = c.replace(stale_free_block, free_block, 1)
        elif 'pub fn active_time_origin_shift_delta_at(kind' not in c and free_anchor in c:
            c = c.replace(free_anchor, free_block, 1)
        fuzzer_utils.write_text(c)
        return None


def _patch_f038_program_trace_row_anchor(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'program' / 'trace.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '    rows.par_chunks_mut(width)\n        .zip(instructions)\n        .for_each(|(row, (pc, instruction))| {\n            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();\n            *row = ProgramExecutionCols {\n                pc: F::from_canonical_u32(pc),\n                opcode: instruction.opcode.to_field(),\n                a: instruction.a,\n                b: instruction.b,\n                c: instruction.c,\n                d: instruction.d,\n                e: instruction.e,\n                f: instruction.f,\n                g: instruction.g,\n            };\n        });\n'
    new = '    rows.par_chunks_mut(width)\n        .zip(instructions.into_par_iter().enumerate())\n        .for_each(|(row, (i, (pc, instruction)))| {\n            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();\n            *row = ProgramExecutionCols {\n                pc: F::from_canonical_u32(pc),\n                opcode: instruction.opcode.to_field(),\n                a: instruction.a,\n                b: instruction.b,\n                c: instruction.c,\n                d: instruction.d,\n                e: instruction.e,\n                f: instruction.f,\n                g: instruction.g,\n            };\n\n            // BEAK-INSERT: guard.f038.program_trace.mem_as_pre_access\n            // Observation-only row anchor. The strict address-space candidate mutates only\n            // rv32_loadstore_adapter.preprocess, so one candidate cannot silently apply both\n            // a program-table mutation and an adapter mutation under the same base kind.\n            let beak_program_step = i as u64;\n            // BEAK-INSERT-END\n        });\n'
    mem_as_guard = '// BEAK-INSERT: guard.f038.program_trace.mem_as_pre_access'
    c = _refresh_guarded_block(c, template=new, guard=mem_as_guard)
    if mem_as_guard not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_336f_connector_witness_injection(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'vm' / 'src' / 'system' / 'connector' / 'mod.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '    pub fn begin(&mut self, state: ExecutionState<u32>) {\n        self.boundary_states[0] = Some(ConnectorCols {\n            pc: state.pc,\n            timestamp: state.timestamp,\n            is_terminate: 0,\n            exit_code: 0,\n        });\n    }\n'
    new = '    pub fn begin(&mut self, state: ExecutionState<u32>) {\n        let beak_step = fuzzer_utils::current_witness_step();\n        let mut beak_pc = state.pc;\n        if fuzzer_utils::should_inject_witness("openvm.semantic.control.entrypoint_binding", beak_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.control.entrypoint_binding step={} from_pc={}",\n                beak_step,\n                state.pc\n            );\n            beak_pc = state.pc.wrapping_add(1);\n        }\n        self.boundary_states[0] = Some(ConnectorCols {\n            pc: beak_pc,\n            timestamp: state.timestamp,\n            is_terminate: 0,\n            exit_code: 0,\n        });\n    }\n'
    if '// openvm.semantic.control.entrypoint_binding' not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_336f_control_flow_witness_injection(openvm_install_path: Path) -> None:
    branch_eq = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "branch_eq"
        / "core.rs"
    )
    if branch_eq.exists():
        _ensure_use_fuzzer_utils(branch_eq)
        c = branch_eq.read_text()
        try:
            c = _insert_before(
                c,
                anchor="    }\n\n    fn air(&self) -> &Self::Air {",
                guard="// BEAK-INSERT: guard.336f.branch_eq.control_flow",
                insert='\n\n        // BEAK-INSERT: guard.336f.branch_eq.control_flow\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.exec.control_flow_binding", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.exec.control_flow_binding step={} site=branch_eq",\n                beak_witness_step\n            );\n            row_slice.cmp_result = F::ONE - row_slice.cmp_result;\n        }\n        // BEAK-INSERT-END\n',
            )
            branch_eq.write_text(c)
        except RuntimeError:
            pass

    branch_lt = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "branch_lt"
        / "core.rs"
    )
    if branch_lt.exists():
        _ensure_use_fuzzer_utils(branch_lt)
        c = branch_lt.read_text()
        try:
            c = _insert_before(
                c,
                anchor="    }\n\n    fn air(&self) -> &Self::Air {",
                guard="// BEAK-INSERT: guard.336f.branch_lt.control_flow",
                insert='\n\n        // BEAK-INSERT: guard.336f.branch_lt.control_flow\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.exec.control_flow_binding", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.exec.control_flow_binding step={} site=branch_lt",\n                beak_witness_step\n            );\n            row_slice.cmp_result = F::ONE - row_slice.cmp_result;\n        }\n        // BEAK-INSERT-END\n',
            )
            branch_lt.write_text(c)
        except RuntimeError:
            pass

    jal_lui = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "jal_lui"
        / "core.rs"
    )
    if jal_lui.exists():
        _ensure_use_fuzzer_utils(jal_lui)
        c = jal_lui.read_text()
        try:
            c = _insert_after(
                c,
                anchor="        core_cols.is_lui = F::from_bool(record.is_lui);",
                guard="// BEAK-INSERT: guard.336f.jal_lui.control_flow",
                insert='\n\n        // BEAK-INSERT: guard.336f.jal_lui.control_flow\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if record.is_jal\n            && fuzzer_utils::should_inject_witness("openvm.semantic.exec.control_flow_binding", beak_witness_step)\n        {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.exec.control_flow_binding step={} site=jal",\n                beak_witness_step\n            );\n            core_cols.rd_data[0] += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
            )
            jal_lui.write_text(c)
        except RuntimeError:
            pass

    jalr = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "jalr"
        / "core.rs"
    )
    if jalr.exists():
        _ensure_use_fuzzer_utils(jalr)
        c = jalr.read_text()
        try:
            c = _insert_after(
                c,
                anchor="        core_cols.is_valid = F::ONE;",
                guard="// BEAK-INSERT: guard.336f.jalr.control_flow",
                insert='\n\n        // BEAK-INSERT: guard.336f.jalr.control_flow\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.exec.control_flow_binding", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.exec.control_flow_binding step={} site=jalr",\n                beak_witness_step\n            );\n            core_cols.rd_data[0] += F::ONE;\n            core_cols.to_pc_least_sig_bit = F::ONE - core_cols.to_pc_least_sig_bit;\n            core_cols.imm_sign = F::ONE - core_cols.imm_sign;\n        }\n        // BEAK-INSERT-END\n',
            )
            jalr.write_text(c)
        except RuntimeError:
            pass


def _patch_f038_loadstore_mem_as_witness_injection(openvm_install_path = None):
    path = openvm_install_path / 'extensions' / 'rv32im' / 'circuit' / 'src' / 'adapters' / 'loadstore.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '        let imm = c.as_canonical_u32();\n        let imm_sign = g.as_canonical_u32();\n        let imm_extended = imm + imm_sign * 0xffff0000;\n'
    new = '        let imm = c.as_canonical_u32();\n        let imm_sign = g.as_canonical_u32();\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        let imm_extended = imm + imm_sign * 0xffff0000;\n'
    if 'let beak_witness_step = fuzzer_utils::current_witness_step();' not in c and old in c:
        c = c.replace(old, new, 1)
    pre_marker = '// BEAK-INSERT: guard.f038.loadstore.adapter.mem_as_pre_access'
    if pre_marker not in c and '        let read_record = match local_opcode {\n' in c:
        c = c.replace('        let read_record = match local_opcode {\n', '        // BEAK-INSERT: guard.f038.loadstore.adapter.mem_as_pre_access\n        let beak_is_load = matches!(local_opcode, LOADW | LOADB | LOADH | LOADBU | LOADHU);\n        let beak_is_store = matches!(local_opcode, STOREW | STOREH | STOREB);\n        let mut beak_mem_as = e;\n        let beak_address_space_step = beak_witness_step.saturating_add(1);\n        let beak_variant =\n            fuzzer_utils::active_witness_variant("openvm.semantic.memory.address_space_consistency");\n        if e.as_canonical_u32() == 2\n            && beak_variant.as_deref() == Some("mode=bus_mem_as_reg")\n            && fuzzer_utils::should_inject_witness("openvm.semantic.memory.address_space_consistency", beak_address_space_step)\n        {\n            let spec = beak_variant.as_deref().expect("validated o51 variant");\n            let mut mode = "bus_mem_as_other";\n            for part in spec.split(\',\') {\n                if let Some((spec_key, spec_value)) = part.split_once(\'=\') {\n                    if spec_key.trim() == "mode" {\n                        mode = spec_value.trim();\n                    }\n                }\n            }\n            let old_mem_as = e.as_canonical_u32();\n            let selected_mem_as = match mode {\n                "bus_mem_as_reg" => RV32_REGISTER_AS,\n                "bus_mem_as_zero" => RV32_IMM_AS,\n                "bus_mem_as_other" => {\n                    if old_mem_as != 3 {\n                        3\n                    } else {\n                        4\n                    }\n                }\n                _ => old_mem_as,\n            };\n            if selected_mem_as != old_mem_as {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} site=loadstore_adapter mode={} old_mem_as={} new_mem_as={} is_load={} is_store={}",\n                    beak_address_space_step,\n                    mode,\n                    old_mem_as,\n                    selected_mem_as,\n                    beak_is_load,\n                    beak_is_store\n                );\n                beak_mem_as = F::from_canonical_u32(selected_mem_as);\n                fuzzer_utils::record_semantic_mutation(\n                    "openvm.semantic.memory.address_space_consistency",\n                    "rv32_loadstore_adapter.preprocess",\n                    "memory_address_space",\n                    beak_address_space_step,\n                    serde_json::json!(old_mem_as),\n                    serde_json::json!(selected_mem_as),\n                    serde_json::json!({\n                        "relation": "address_space_consistency_equation",\n                        "context": {\n                            "bucket_id": "sem.memory.address_space_consistency",\n                            "row_idx": beak_address_space_step,\n                            "mode": mode,\n                            "is_memory": true,\n                            "register_address_space": 1,\n                            "memory_address_space": 2,\n                            "address_space_before": old_mem_as,\n                            "address_space_after": selected_mem_as,\n                            "is_load": beak_is_load,\n                            "is_store": beak_is_store,\n                            "executed_access": beak_is_load || beak_is_store\n                        }\n                    }),\n                );\n            } else {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} site=loadstore_adapter mode={} skip_noop old_mem_as={} is_load={} is_store={}",\n                    beak_address_space_step,\n                    mode,\n                    old_mem_as,\n                    beak_is_load,\n                    beak_is_store\n                );\n            }\n        }\n        // BEAK-INSERT-END\n\n        let read_record = match local_opcode {\n', 1)
    if pre_marker in c:
        c = c.replace('                memory.read::<RV32_REGISTER_NUM_LIMBS>(e, F::from_canonical_u32(ptr_val))\n', '                memory.read::<RV32_REGISTER_NUM_LIMBS>(beak_mem_as, F::from_canonical_u32(ptr_val))\n', 1)
        c = c.replace('                memory.unsafe_read_cell(e, F::from_canonical_usize(ptr_val as usize + i))\n', '                memory.unsafe_read_cell(beak_mem_as, F::from_canonical_usize(ptr_val as usize + i))\n', 1)
        c = c.replace('            e.as_canonical_u32(),\n            beak_effective_ptr,\n            beak_effective_ptr,\n            ptr_val,\n', '            beak_mem_as.as_canonical_u32(),\n            beak_effective_ptr,\n            beak_effective_ptr,\n            ptr_val,\n', 1)
        c = c.replace('                    memory.write(e, F::from_canonical_u32(ptr & 0xfffffffc), output.writes[0])\n', '                    memory.write(read_record.mem_as, F::from_canonical_u32(ptr & 0xfffffffc), output.writes[0])\n', 1)
        c = c.replace('            d,\n            e,\n            f: enabled,\n', '            d,\n            f: enabled,\n', 1)
    old2 = '        Ok((\n            (\n                [prev_data, read_record.1],\n                F::from_canonical_u32(shift_amount),\n            ),\n            Self::ReadRecord {\n                rs1_record: rs1_record.0,\n                rs1_ptr: b,\n                read: read_record.0,\n                imm: c,\n                imm_sign: g,\n                shift_amount,\n                mem_ptr_limbs,\n                mem_as: e,\n            },\n        ))\n'
    new2 = '        Ok((\n            (\n                [prev_data, read_record.1],\n                F::from_canonical_u32(shift_amount),\n            ),\n            Self::ReadRecord {\n                rs1_record: rs1_record.0,\n                rs1_ptr: b,\n                read: read_record.0,\n                imm: c,\n                imm_sign: g,\n                shift_amount,\n                mem_ptr_limbs,\n                mem_as: beak_mem_as,\n            },\n        ))\n'
    if 'mem_as: beak_mem_as,' not in c and old2 in c:
        c = c.replace(old2, new2, 1)
    old_late = '        // BEAK-INSERT: guard.336f.loadstore.adapter.mem_as_o5\n        let mut beak_mem_as = e;\n        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.address_space_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} old_mem_as={}",\n                beak_witness_step,\n                e.as_canonical_u32()\n            );\n            // Force RAM address space as a forged witness value.\n            beak_mem_as = F::ZERO;\n        }\n        // BEAK-INSERT-END\n\n'
    if pre_marker in c and old_late in c:
        c = c.replace(old_late, '', 1)
    path.write_text(c)


def _patch_witness_step_wildcard_support(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'fuzzer_utils' / 'src' / 'lib.rs'
    if not path.exists():
        return None
    c = path.read_text()
    old = '        self.injection_enabled && self.injection_kind == kind && self.injection_step == step\n'
    new = '        self.injection_enabled\n            && self.injection_kind == kind\n            && (self.injection_step == step || self.injection_step == u64::MAX)\n'
    if old in c and 'self.injection_step == u64::MAX' not in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_witness_variant_support(openvm_install_path = None):
    path = openvm_install_path / 'crates' / 'fuzzer_utils' / 'src' / 'lib.rs'
    if not path.exists():
        return None
    c = path.read_text()
    constants_anchor = 'pub const LIMB_BITS: usize = 8;\n'
    helper_block = '\nfn base_injection_kind(kind: &str) -> &str {\n    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)\n}\n\nfn injection_variant(kind: &str) -> Option<&str> {\n    kind.split_once("::").map(|(_, variant)| variant)\n}\n'
    if helper_block.strip() not in c and constants_anchor in c:
        c = c.replace(constants_anchor, constants_anchor + helper_block, 1)
    if 'pub applied_witness_sites: BTreeMap<String, Vec<u64>>,' not in c:
        c = c.replace('    pub observed_witness_sites: BTreeMap<String, Vec<u64>>,\n', '    pub observed_witness_sites: BTreeMap<String, Vec<u64>>,\n    pub applied_witness_sites: BTreeMap<String, Vec<u64>>,\n', 1)
    if 'applied_witness_sites: BTreeMap::new(),' not in c:
        c = c.replace('            observed_witness_sites: BTreeMap::new(),\n', '            observed_witness_sites: BTreeMap::new(),\n            applied_witness_sites: BTreeMap::new(),\n', 1)
    if 'self.applied_witness_sites.clear();' not in c:
        c = c.replace('        self.observed_witness_sites.clear();\n', '        self.observed_witness_sites.clear();\n        self.applied_witness_sites.clear();\n', 1)
    if 'fn note_applied_witness_site(&mut self, kind: &str, step: u64)' not in c:
        c = c.replace('    fn note_witness_site(&mut self, kind: &str, step: u64) {\n        let sites = self.observed_witness_sites.entry(kind.to_string()).or_default();\n        if sites.last().copied() != Some(step) {\n            sites.push(step);\n        }\n    }\n', '    fn note_witness_site(&mut self, kind: &str, step: u64) {\n        let sites = self.observed_witness_sites.entry(kind.to_string()).or_default();\n        if sites.last().copied() != Some(step) {\n            sites.push(step);\n        }\n    }\n\n    fn note_applied_witness_site(&mut self, kind: &str, step: u64) {\n        let sites = self.applied_witness_sites.entry(kind.to_string()).or_default();\n        if sites.last().copied() != Some(step) {\n            sites.push(step);\n        }\n    }\n', 1)
    if 'pub fn matching_injection_kind(&self, kind: &str, step: u64) -> Option<String>' not in c:
        c = c.replace('    pub fn should_inject_witness(&self, kind: &str, step: u64) -> bool {\n        self.injection_enabled && self.injection_kind == kind && self.injection_step == step\n    }\n', '    pub fn should_inject_witness(&self, kind: &str, step: u64) -> bool {\n        self.injection_enabled\n            && base_injection_kind(self.injection_kind.as_str()) == kind\n            && (self.injection_step == step || self.injection_step == u64::MAX)\n    }\n\n    pub fn matching_injection_kind(&self, kind: &str, step: u64) -> Option<String> {\n        self.should_inject_witness(kind, step)\n            .then(|| self.injection_kind.clone())\n    }\n\n    pub fn active_witness_variant(&self, kind: &str) -> Option<String> {\n        self.injection_enabled\n            .then(|| base_injection_kind(self.injection_kind.as_str()) == kind)\n            .filter(|matched| *matched)\n            .and_then(|_| injection_variant(self.injection_kind.as_str()))\n            .map(str::to_string)\n    }\n', 1)
    elif 'pub fn take_applied_witness_sites(&mut self) -> BTreeMap<String, Vec<u64>>' not in c:
        c = c.replace('    pub fn take_observed_witness_sites(&mut self) -> BTreeMap<String, Vec<u64>> {\n        std::mem::take(&mut self.observed_witness_sites)\n    }\n', '    pub fn take_observed_witness_sites(&mut self) -> BTreeMap<String, Vec<u64>> {\n        std::mem::take(&mut self.observed_witness_sites)\n    }\n\n    pub fn take_applied_witness_sites(&mut self) -> BTreeMap<String, Vec<u64>> {\n        std::mem::take(&mut self.applied_witness_sites)\n    }\n', 1)
    if 'pub fn active_witness_variant(kind: &str) -> Option<String>' not in c:
        c = c.replace('pub fn should_inject_witness(kind: &str, step: u64) -> bool {\n    let mut state = GLOBAL_STATE.lock().unwrap();\n    state.note_witness_site(kind, step);\n    state.should_inject_witness(kind, step)\n}\n', 'pub fn should_inject_witness(kind: &str, step: u64) -> bool {\n    let mut state = GLOBAL_STATE.lock().unwrap();\n    state.note_witness_site(kind, step);\n    let should_inject = state.should_inject_witness(kind, step);\n    if should_inject {\n        state.note_applied_witness_site(kind, step);\n    }\n    should_inject\n}\n\npub fn matching_injection_kind(kind: &str, step: u64) -> Option<String> {\n    let mut state = GLOBAL_STATE.lock().unwrap();\n    state.note_witness_site(kind, step);\n    state.matching_injection_kind(kind, step)\n}\n\npub fn active_witness_variant(kind: &str) -> Option<String> {\n    let state = GLOBAL_STATE.lock().unwrap();\n    state.active_witness_variant(kind)\n}\n', 1)
    elif 'pub fn take_applied_witness_sites() -> BTreeMap<String, Vec<u64>>' not in c:
        c = c.replace('pub fn take_observed_witness_sites() -> BTreeMap<String, Vec<u64>> {\n    let mut state = GLOBAL_STATE.lock().unwrap();\n    state.take_observed_witness_sites()\n}\n', 'pub fn take_observed_witness_sites() -> BTreeMap<String, Vec<u64>> {\n    let mut state = GLOBAL_STATE.lock().unwrap();\n    state.take_observed_witness_sites()\n}\n\npub fn take_applied_witness_sites() -> BTreeMap<String, Vec<u64>> {\n    let mut state = GLOBAL_STATE.lock().unwrap();\n    state.take_applied_witness_sites()\n}\n', 1)
    path.write_text(c)


def _patch_regzero_semantic_witness_injection(openvm_install_path: Path) -> None:
    """Add d7/regzero witness mutation hooks at concrete prover row construction sites."""

    connector = openvm_install_path / "crates" / "vm" / "src" / "system" / "connector" / "mod.rs"
    if connector.exists():
        _ensure_use_fuzzer_utils(connector)
        c = connector.read_text()
        try:
            c = _insert_after(
                c,
                anchor="let [initial_state, final_state] = self.boundary_states.map(|state| {\n            let mut state = state.unwrap();",
                guard="// BEAK-INSERT: guard.regzero.connector.semantic_injection",
                insert='\n\n            // BEAK-INSERT: guard.regzero.connector.semantic_injection\n            let beak_witness_step = fuzzer_utils::current_witness_step();\n            if fuzzer_utils::should_inject_witness("openvm.semantic.time.boundary_origin_consistency", beak_witness_step) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.time.boundary_origin_consistency step={} from_ts={}",\n                    beak_witness_step,\n                    state.timestamp\n                );\n                state.timestamp = state.timestamp.wrapping_add(1 << 29);\n            }\n            if fuzzer_utils::should_inject_witness("openvm.semantic.control.entrypoint_binding", beak_witness_step) {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.control.entrypoint_binding step={} from_pc={}",\n                    beak_witness_step,\n                    state.pc\n                );\n                state.pc = state.pc.wrapping_add(1);\n            }\n            // BEAK-INSERT-END\n',
            )
        except RuntimeError:
            pass
        connector.write_text(c)

    core_hooks = [
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "base_alu" / "core.rs",
            (
                "        core_row.a = a.map(F::from_canonical_u8);\n",
                "        core_row.a = a.map(F::from_u8);\n",
            ),
            "// BEAK-INSERT: guard.regzero.base_alu.semantic_injection",
            '\n\n        // BEAK-INSERT: guard.regzero.base_alu.semantic_injection\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.immediate_limb_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.alu.immediate_limb_consistency step={}",\n                beak_witness_step\n            );\n            core_row.c[0] += F::ONE;\n        }\n        if local_opcode == BaseAluOpcode::SUB\n            && fuzzer_utils::should_inject_witness("openvm.semantic.alu.subtraction_borrow_chain", beak_witness_step)\n        {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.alu.subtraction_borrow_chain step={}",\n                beak_witness_step\n            );\n            core_row.a[0] += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "shift" / "core.rs",
            (
                "        core_row.a = a.map(F::from_canonical_u8);\n",
                "        core_row.a = a.map(F::from_u8);\n",
            ),
            "// BEAK-INSERT: guard.regzero.shift.semantic_injection",
            '\n\n        // BEAK-INSERT: guard.regzero.shift.semantic_injection\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.shift_mod32", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.alu.shift_mod32 step={}",\n                beak_witness_step\n            );\n            core_row.a[0] += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "less_than" / "core.rs",
            "        let mut a = [0u8; NUM_LIMBS];\n        a[0] = cmp_result as u8;\n",
            "// BEAK-INSERT: guard.regzero.less_than.semantic_injection",
            '\n\n        // BEAK-INSERT: guard.regzero.less_than.semantic_injection\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.comparison_booleanity", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.alu.comparison_booleanity step={}",\n                beak_witness_step\n            );\n            core_row.cmp_result = F::ONE - core_row.cmp_result;\n        }\n        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.comparison_auxiliary_chain", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.alu.comparison_auxiliary_chain step={}",\n                beak_witness_step\n            );\n            core_row.diff_marker[0] = F::ONE;\n        }\n        // BEAK-INSERT-END\n',
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "divrem" / "core.rs",
            (
                "        core_row.b = record.b.map(F::from_canonical_u8);\n",
                "        core_row.b = record.b.map(F::from_u8);\n",
            ),
            "// BEAK-INSERT: guard.regzero.divrem.semantic_injection",
            '\n\n        // BEAK-INSERT: guard.regzero.divrem.semantic_injection\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.special_case_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.arithmetic.special_case_consistency step={}",\n                beak_witness_step\n            );\n            core_row.q[0] += F::ONE;\n        }\n        if beak_record_c.iter().any(|limb| *limb != 0)\n            && fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.division_remainder_bound", beak_witness_step)\n        {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.arithmetic.division_remainder_bound step={}",\n                beak_witness_step\n            );\n            core_row.q[0] += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "mul" / "core.rs",
            (
                "        core_row.a = a.map(F::from_canonical_u8);\n",
                "        core_row.a = a.map(F::from_u8);\n",
            ),
            "// BEAK-INSERT: guard.regzero.mul.semantic_injection",
            '\n\n        // BEAK-INSERT: guard.regzero.mul.semantic_injection\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.product_decomposition", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.arithmetic.product_decomposition step={} site=mul",\n                beak_witness_step\n            );\n            core_row.a[0] += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "mulh" / "core.rs",
            (
                "        core_row.a = a.map(F::from_canonical_u32);\n",
                "        core_row.a = a.map(F::from_u32);\n",
            ),
            "// BEAK-INSERT: guard.regzero.mulh.semantic_injection",
            '\n\n        // BEAK-INSERT: guard.regzero.mulh.semantic_injection\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.product_decomposition", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.arithmetic.product_decomposition step={} site=mulh",\n                beak_witness_step\n            );\n            core_row.a[0] += F::ONE;\n        }\n        if opcode == MulHOpcode::MULHSU\n            && fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.signed_unsigned_product_correction", beak_witness_step)\n        {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.arithmetic.signed_unsigned_product_correction step={}",\n                beak_witness_step\n            );\n            core_row.b_ext += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "auipc" / "core.rs",
            (
                "        core_row.rd_data = rd_data.map(F::from_canonical_u8);\n",
                "        core_row.rd_data = rd_data.map(F::from_u8);\n",
            ),
            "// BEAK-INSERT: guard.regzero.auipc.semantic_injection",
            '\n\n        // BEAK-INSERT: guard.regzero.auipc.semantic_injection\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.control.auipc_pc_limb_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.control.auipc_pc_limb_consistency step={}",\n                beak_witness_step\n            );\n            core_row.pc_limbs[0] += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
        ),
    ]
    for path, anchor, guard, insert in core_hooks:
        if not path.exists():
            continue
        _ensure_use_fuzzer_utils(path)
        c = path.read_text()
        try:
            if isinstance(anchor, tuple):
                c = _insert_after_any(c, anchors=anchor, guard=guard, insert=insert)
            else:
                c = _insert_after(c, anchor=anchor, guard=guard, insert=insert)
        except RuntimeError:
            pass
        path.write_text(c)

    control_hooks = [
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "branch_eq" / "core.rs",
            (
                "        core_row.a = record.a.map(F::from_canonical_u8);\n",
                "        core_row.a = record.a.map(F::from_u8);\n",
            ),
            "// BEAK-INSERT: guard.regzero.branch_eq.semantic_injection",
            "branch_eq",
            "core_row.cmp_result = F::ONE - core_row.cmp_result;",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "branch_lt" / "core.rs",
            (
                "        core_row.a = record.a.map(F::from_canonical_u8);\n",
                "        core_row.a = record.a.map(F::from_u8);\n",
            ),
            "// BEAK-INSERT: guard.regzero.branch_lt.semantic_injection",
            "branch_lt",
            "core_row.cmp_result = F::ONE - core_row.cmp_result;",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "jal_lui" / "core.rs",
            (
                "        core_row.imm = F::from_canonical_u32(record.imm);\n",
                "        core_row.imm = F::from_u32(record.imm);\n",
            ),
            "// BEAK-INSERT: guard.regzero.jal_lui.semantic_injection",
            "jal",
            "if record.is_jal { core_row.rd_data[0] += F::ONE; }",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "jalr" / "core.rs",
            (
                "        core_row.imm = F::from_canonical_u16(record.imm);\n",
                "        core_row.imm = F::from_u16(record.imm);\n",
            ),
            "// BEAK-INSERT: guard.regzero.jalr.semantic_injection",
            "jalr",
            "core_row.rd_data[0] += F::ONE;\n            core_row.imm_sign = F::ONE - core_row.imm_sign;",
        ),
    ]
    for path, anchor, guard, site, mutation in control_hooks:
        if not path.exists():
            continue
        _ensure_use_fuzzer_utils(path)
        c = path.read_text()
        insert = f"""

        {guard}
        let beak_witness_step = fuzzer_utils::current_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.exec.control_flow_binding", beak_witness_step) {{
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.exec.control_flow_binding step={{}} site={site}",
                beak_witness_step
            );
            {mutation}
        }}
        // BEAK-INSERT-END
        """
        try:
            if isinstance(anchor, tuple):
                c = _insert_after_any(c, anchors=anchor, guard=guard, insert=insert)
            else:
                c = _insert_after(c, anchor=anchor, guard=guard, insert=insert)
        except RuntimeError:
            pass
        path.write_text(c)


def _patch_regzero_memory_deep_instrumentation(openvm_install_path: Path) -> None:
    """Add d7/regzero memory access, lifecycle, and timestamp witness instrumentation."""

    rv32im = openvm_install_path / "extensions" / "rv32im" / "circuit" / "src"

    loadstore_core = rv32im / "loadstore" / "core.rs"
    if loadstore_core.exists():
        _ensure_use_fuzzer_utils(loadstore_core)
        _ensure_import_after_fuzzer_utils(
            loadstore_core, "use crate::adapters::Rv32LoadStoreAdapterCols;"
        )
        c = loadstore_core.read_text()
        guard = "// BEAK-INSERT: guard.regzero.loadstore.memory_access"
        if guard not in c and "        fuzzer_utils::emit_load_store_chip_row(" in c:
            call_start = c.find("        fuzzer_utils::emit_load_store_chip_row(")
            call_end = c.find("        );", call_start)
            if call_end >= 0:
                pos = call_end + len("        );")
                insert = r"""

        // BEAK-INSERT: guard.regzero.loadstore.memory_access
        let beak_byte_offset = shift as u32;
        let beak_width = match opcode {
            LOADW | STOREW => 4u32,
            LOADHU | STOREH => 2u32,
            LOADBU | STOREB => 1u32,
            _ => 4u32,
        };
        let beak_aligned_ptr = effective_ptr.wrapping_sub(beak_byte_offset);
        let beak_access_timestamp = if is_store {
            beak_cols.from_state.timestamp.as_canonical_u32().saturating_add(2)
        } else {
            beak_cols.from_state.timestamp.as_canonical_u32().saturating_add(1)
        };
        fuzzer_utils::emit_memory_access_with_pc(
            beak_cols.from_state.pc.as_canonical_u32(),
            0,
            opcode as u32,
            rs1_ptr,
            rd_rs2_ptr,
            imm_i32,
            imm_sign,
            mem_as,
            effective_ptr,
            effective_ptr,
            beak_aligned_ptr,
            beak_byte_offset,
            beak_width,
            is_load,
            is_store,
            needs_write,
            beak_access_timestamp,
            beak_record_read_data.iter().map(|x| *x as u32).collect(),
            beak_record_prev_data.iter().copied().collect(),
            write_data.iter().copied().collect(),
        );
        // BEAK-INSERT-END
"""
                c = c[:pos] + insert + c[pos:]
        try:
            c = _insert_after(
                c,
                anchor="        core_row.is_load = F::from_bool([LOADW, LOADHU, LOADBU].contains(&opcode));\n",
                guard="// BEAK-INSERT: guard.regzero.loadstore.core.memory_injection",
                insert='\n        // BEAK-INSERT: guard.regzero.loadstore.core.memory_injection\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.value_payload_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.memory.value_payload_consistency step={} site=loadstore_core",\n                beak_witness_step\n            );\n            core_row.write_data[0] += F::ONE;\n        }\n        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.store_load_payload_flow", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.memory.store_load_payload_flow step={} site=loadstore_core",\n                beak_witness_step\n            );\n            core_row.write_data[0] += F::ONE;\n        }\n        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.kind_selector_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.memory.kind_selector_consistency step={} site=loadstore_core",\n                beak_witness_step\n            );\n            core_row.is_load = F::ONE - core_row.is_load;\n        }\n        // BEAK-INSERT-END\n',
            )
        except RuntimeError:
            pass
        loadstore_core.write_text(c)

    load_sign_extend_core = rv32im / "load_sign_extend" / "core.rs"
    if load_sign_extend_core.exists():
        _ensure_use_fuzzer_utils(load_sign_extend_core)
        _ensure_import_after_fuzzer_utils(
            load_sign_extend_core, "use crate::adapters::Rv32LoadStoreAdapterCols;"
        )
        c = load_sign_extend_core.read_text()
        guard = "// BEAK-INSERT: guard.regzero.load_sign_extend.memory_access"
        if guard not in c and "        fuzzer_utils::emit_load_sign_extend_chip_row(" in c:
            call_start = c.find("        fuzzer_utils::emit_load_sign_extend_chip_row(")
            call_end = c.find("        );", call_start)
            if call_end >= 0:
                pos = call_end + len("        );")
                insert = r"""

        // BEAK-INSERT: guard.regzero.load_sign_extend.memory_access
        let beak_byte_offset = shift as u32;
        let beak_width = if beak_record_is_byte { 1u32 } else { 2u32 };
        let beak_aligned_ptr = effective_ptr.wrapping_sub(beak_byte_offset);
        let beak_access_timestamp =
            beak_cols.from_state.timestamp.as_canonical_u32().saturating_add(1);
        fuzzer_utils::emit_memory_access_with_pc(
            beak_cols.from_state.pc.as_canonical_u32(),
            0,
            opcode as u32,
            rs1_ptr,
            rd_ptr,
            imm_i32,
            imm_sign,
            mem_as,
            effective_ptr,
            effective_ptr,
            beak_aligned_ptr,
            beak_byte_offset,
            beak_width,
            true,
            false,
            needs_write,
            beak_access_timestamp,
            beak_record_read_data.iter().map(|x| *x as u32).collect(),
            beak_record_prev_data.iter().map(|x| *x as u32).collect(),
            shifted_read_data.iter().map(|x| *x as u32).collect(),
        );
        // BEAK-INSERT-END
"""
                c = c[:pos] + insert + c[pos:]
        try:
            c = _insert_after(
                c,
                anchor="        core_row.opcode_loadb_flag0 = F::from_bool(record.is_byte && ((shift & 1) == 0));\n",
                guard="// BEAK-INSERT: guard.regzero.load_sign_extend.core.memory_injection",
                insert='\n        // BEAK-INSERT: guard.regzero.load_sign_extend.core.memory_injection\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.value_payload_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.memory.value_payload_consistency step={} site=load_sign_extend_core",\n                beak_witness_step\n            );\n            core_row.shifted_read_data[0] += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
            )
        except RuntimeError:
            pass
        load_sign_extend_core.write_text(c)

    loadstore_adapter = rv32im / "adapters" / "loadstore.rs"
    if loadstore_adapter.exists():
        _ensure_use_fuzzer_utils(loadstore_adapter)
        c = loadstore_adapter.read_text()
        try:
            c = _insert_after_any(
                c,
                anchors=(
                    "        adapter_row.mem_ptr_limbs = ptr_limbs.map(F::from_canonical_u32);\n",
                    "        adapter_row.mem_ptr_limbs = ptr_limbs.map(F::from_u32);\n",
                ),
                guard="// BEAK-INSERT: guard.regzero.loadstore.adapter.memory_injection",
                insert='\n        // BEAK-INSERT: guard.regzero.loadstore.adapter.memory_injection\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.address_pointer_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.memory.address_pointer_consistency step={} site=loadstore_adapter",\n                beak_witness_step\n            );\n            adapter_row.mem_ptr_limbs[0] += F::ONE;\n        }\n        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.address_space_consistency", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} site=loadstore_adapter",\n                beak_witness_step\n            );\n            adapter_row.mem_as += F::ONE;\n        }\n        // BEAK-INSERT-END\n',
            )
        except RuntimeError:
            pass
        loadstore_adapter.write_text(c)

    controller = openvm_install_path / "crates" / "vm" / "src" / "system" / "memory" / "controller" / "mod.rs"
    if controller.exists():
        _ensure_use_fuzzer_utils(controller)
        c = controller.read_text()
        old_fill = r"""    pub fn fill(&self, prev_timestamp: u32, timestamp: u32, buffer: &mut MemoryBaseAuxCols<F>) {
        self.generate_timestamp_lt(prev_timestamp, timestamp, &mut buffer.timestamp_lt_aux);
        // Safety: even if prev_timestamp were obtained by transmute_ref from
        // `buffer.prev_timestamp`, this should still work because it is a direct assignment
        buffer.prev_timestamp = F::from_canonical_u32(prev_timestamp);
    }
"""
        old_fill_bf11 = r"""    pub fn fill(&self, prev_timestamp: u32, timestamp: u32, buffer: &mut MemoryBaseAuxCols<F>) {
        self.generate_timestamp_lt(prev_timestamp, timestamp, &mut buffer.timestamp_lt_aux);
        // Safety: even if prev_timestamp were obtained by transmute_ref from
        // `buffer.prev_timestamp`, this should still work because it is a direct assignment
        buffer.prev_timestamp = F::from_u32(prev_timestamp);
    }
"""
        new_fill = '    pub fn fill(&self, prev_timestamp: u32, timestamp: u32, buffer: &mut MemoryBaseAuxCols<F>) {\n        self.generate_timestamp_lt(prev_timestamp, timestamp, &mut buffer.timestamp_lt_aux);\n        let beak_witness_step = fuzzer_utils::current_witness_step();\n        let mut beak_prev_timestamp = prev_timestamp;\n        if fuzzer_utils::should_inject_witness("openvm.semantic.time.monotonic_access_ordering", beak_witness_step) {\n            eprintln!(\n                "[beak-witness-inject] kind=openvm.semantic.time.monotonic_access_ordering step={} prev_timestamp={} timestamp={}",\n                beak_witness_step,\n                prev_timestamp,\n                timestamp\n            );\n            beak_prev_timestamp = timestamp;\n        }\n        // Safety: even if prev_timestamp were obtained by transmute_ref from\n        // `buffer.prev_timestamp`, this should still work because it is a direct assignment\n        buffer.prev_timestamp = F::from_canonical_u32(beak_prev_timestamp);\n    }\n'
        new_fill_bf11 = new_fill.replace(
            "F::from_canonical_u32(beak_prev_timestamp)",
            "F::from_u32(beak_prev_timestamp)",
        )
        if old_fill in c:
            c = c.replace(old_fill, new_fill, 1)
        if old_fill_bf11 in c:
            c = c.replace(old_fill_bf11, new_fill_bf11, 1)
        if "// BEAK-INSERT: guard.regzero.memory.lifecycle.finalization" not in c:
            c = c.replace(
                "                TouchedMemory::Persistent(final_memory),\n",
                "                TouchedMemory::Persistent(mut final_memory),\n",
                1,
            )
            try:
                c = _insert_before(
                    c,
                    anchor="                let hasher = self.hasher_chip.as_ref().unwrap();\n",
                    guard="// BEAK-INSERT: guard.regzero.memory.lifecycle.finalization",
                    insert=r"""                // BEAK-INSERT: guard.regzero.memory.lifecycle.finalization
                for (beak_final_idx, ((address_space, pointer), values)) in
                    final_memory.iter_mut().enumerate()
                {
                    let address_space = *address_space;
                    let pointer = *pointer;
                    let final_values = values
                        .values
                        .iter()
                        .map(|value| value.as_canonical_u32())
                        .collect::<Vec<_>>();
                    let initial_values = (0..CHUNK as u32)
                        .map(|offset| unsafe {
                            initial_memory
                                .get_f::<F>(address_space, pointer.wrapping_add(offset))
                                .as_canonical_u32()
                        })
                        .collect::<Vec<_>>();
                    let was_initial = initial_values.iter().any(|value| *value != 0);
                    let changed_from_initial = final_values != initial_values;
                    fuzzer_utils::emit_memory_finalization(
                        beak_final_idx as u64,
                        address_space,
                        pointer,
                        values.timestamp,
                        final_values,
                        was_initial,
                        changed_from_initial,
                    );
                    if fuzzer_utils::should_inject_witness(
                        "openvm.semantic.memory.finalization_consistency",
                        beak_final_idx as u64,
                    ) {
                        eprintln!(
                            "[beak-witness-inject] kind=openvm.semantic.memory.finalization_consistency step={} address_space={} pointer={}",
                            beak_final_idx,
                            address_space,
                            pointer
                        );
                        values.values[0] += F::ONE;
                    }
                }
                // BEAK-INSERT-END
""",
                )
            except RuntimeError:
                pass
        controller.write_text(c)

    vm = openvm_install_path / "crates" / "vm" / "src" / "arch" / "vm.rs"
    if vm.exists():
        _ensure_use_fuzzer_utils(vm)
        c = vm.read_text()
        try:
            c = _insert_after(
                c,
                anchor="    let mut inner = AddressMap::new(memory_config.addr_spaces.clone());\n",
                guard="// BEAK-INSERT: guard.regzero.memory.lifecycle.initial",
                insert=r"""    // BEAK-INSERT: guard.regzero.memory.lifecycle.initial
    for (beak_init_idx, (&(address_space, pointer), &value)) in init_memory
        .iter()
        .filter(|(_, value)| **value != 0)
        .enumerate()
    {
        fuzzer_utils::emit_memory_init(beak_init_idx as u64, address_space, pointer, value as u32);
    }
    // BEAK-INSERT-END
""",
            )
        except RuntimeError:
            pass
        vm.write_text(c)


def _patch_regzero_lookup_multiplicity_instrumentation(openvm_install_path = None):
    '''Emit and mutate d7/regzero bitwise lookup multiplicity rows.'''
    lookup = openvm_install_path / 'crates' / 'circuits' / 'primitives' / 'src' / 'bitwise_op_lookup' / 'mod.rs'
    if not lookup.exists():
        return None
    _ensure_use_fuzzer_utils(lookup)
    c = lookup.read_text()
    old = '    /// Generates trace and resets all internal counters to 0.\n    pub fn generate_trace<F: Field>(&self) -> RowMajorMatrix<F> {\n        let mut rows = F::zero_vec(self.count_range.len() * NUM_BITWISE_OP_LOOKUP_COLS);\n        for (n, row) in rows.chunks_mut(NUM_BITWISE_OP_LOOKUP_COLS).enumerate() {\n            let cols: &mut BitwiseOperationLookupCols<F> = row.borrow_mut();\n            cols.mult_range = F::from_canonical_u32(\n                self.count_range[n].swap(0, std::sync::atomic::Ordering::SeqCst),\n            );\n            cols.mult_xor = F::from_canonical_u32(\n                self.count_xor[n].swap(0, std::sync::atomic::Ordering::SeqCst),\n            );\n        }\n        RowMajorMatrix::new(rows, NUM_BITWISE_OP_LOOKUP_COLS)\n    }\n'
    old_bf11 = '    /// Generates trace and resets all internal counters to 0.\n    pub fn generate_trace<F: Field>(&self) -> RowMajorMatrix<F> {\n        let mut rows = F::zero_vec(self.count_range.len() * NUM_BITWISE_OP_LOOKUP_COLS);\n        for (n, row) in rows.chunks_mut(NUM_BITWISE_OP_LOOKUP_COLS).enumerate() {\n            let cols: &mut BitwiseOperationLookupCols<F> = row.borrow_mut();\n            cols.mult_range =\n                F::from_u32(self.count_range[n].swap(0, std::sync::atomic::Ordering::SeqCst));\n            cols.mult_xor =\n                F::from_u32(self.count_xor[n].swap(0, std::sync::atomic::Ordering::SeqCst));\n        }\n        RowMajorMatrix::new(rows, NUM_BITWISE_OP_LOOKUP_COLS)\n    }\n'
    new = '    /// Generates trace and resets all internal counters to 0.\n    pub fn generate_trace<F: Field>(&self) -> RowMajorMatrix<F> {\n        let mut rows = F::zero_vec(self.count_range.len() * NUM_BITWISE_OP_LOOKUP_COLS);\n        for (n, row) in rows.chunks_mut(NUM_BITWISE_OP_LOOKUP_COLS).enumerate() {\n            let cols: &mut BitwiseOperationLookupCols<F> = row.borrow_mut();\n            let range_mult = self.count_range[n].swap(0, std::sync::atomic::Ordering::SeqCst);\n            let xor_mult = self.count_xor[n].swap(0, std::sync::atomic::Ordering::SeqCst);\n            if range_mult != 0 {\n                fuzzer_utils::emit_lookup_multiplicity(\n                    "bitwise_op_lookup.range",\n                    n as u64,\n                    range_mult,\n                    true,\n                );\n            }\n            if xor_mult != 0 {\n                fuzzer_utils::emit_lookup_multiplicity(\n                    "bitwise_op_lookup.xor",\n                    n as u64,\n                    xor_mult,\n                    true,\n                );\n            }\n            cols.mult_range = F::from_canonical_u32(range_mult);\n            cols.mult_xor = F::from_canonical_u32(xor_mult);\n            if range_mult != 0\n                && fuzzer_utils::should_inject_witness(\n                    "openvm.semantic.lookup.boolean_multiplicity",\n                    n as u64,\n                )\n            {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.lookup.boolean_multiplicity step={} table=bitwise_op_lookup.range",\n                    n\n                );\n                cols.mult_range += F::ONE;\n            }\n            if xor_mult != 0\n                && fuzzer_utils::should_inject_witness(\n                    "openvm.semantic.lookup.boolean_multiplicity",\n                    n as u64,\n                )\n            {\n                eprintln!(\n                    "[beak-witness-inject] kind=openvm.semantic.lookup.boolean_multiplicity step={} table=bitwise_op_lookup.xor",\n                    n\n                );\n                cols.mult_xor += F::ONE;\n            }\n        }\n        RowMajorMatrix::new(rows, NUM_BITWISE_OP_LOOKUP_COLS)\n    }\n'
    new_bf11 = new.replace('F::from_canonical_u32', 'F::from_u32')
    if old in c:
        c = c.replace(old, new, 1)
    if old_bf11 in c:
        c = c.replace(old_bf11, new_bf11, 1)
    lookup.write_text(c)


def _patch_336f_branch_lt_conversion_receipt(openvm_install_path = None):
    '''Record the actual failing BranchLessThanOpcode conversion before it panics.'''
    path = openvm_install_path / 'extensions' / 'rv32im' / 'circuit' / 'src' / 'branch_lt' / 'core.rs'
    if not path.exists():
        return None
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = '        let Instruction { opcode, c: imm, .. } = *instruction;\n        let blt_opcode = BranchLessThanOpcode::from_usize(opcode.local_opcode_idx(self.air.offset));\n'
    new = '        let Instruction { opcode, c: imm, .. } = *instruction;\n        // BEAK-INSERT: guard.336f.branch_lt.conversion_receipt\n        let beak_local_opcode = opcode.local_opcode_idx(self.air.offset);\n        let beak_step = fuzzer_utils::current_instruction_step();\n        fuzzer_utils::record_executed_exception_attempt(serde_json::json!({\n            "effect": "bigint_opcode_conversion",\n            "obligation_id": "id4",\n            "cell_id": "id4.branch",\n            "stage": "openvm.bigint.branch_less_than_opcode_conversion",\n            "trace_source": "extensions/rv32im/circuit/src/branch_lt/core.rs::execute_instruction",\n            "conversion_target": "BranchLessThanOpcode",\n            "global_opcode": opcode.as_usize(),\n            "chip_class_offset": self.air.offset,\n            "local_opcode": beak_local_opcode,\n            "supported_local_opcodes": [0, 1, 2, 3],\n            "relation": "local_opcode_not_in_branch_less_than_domain",\n            "relation_valid": !matches!(beak_local_opcode, 0 | 1 | 2 | 3),\n            "backend": "openvm",\n            "commit": "336f1a475e5aa3513c4c5a266399f4128c119bba",\n            "from_pc": from_pc,\n            "step": beak_step,\n            "hook_fired": true,\n        }));\n        let blt_opcode = BranchLessThanOpcode::from_usize(beak_local_opcode);\n'
    if '// BEAK-INSERT: guard.336f.branch_lt.conversion_receipt' not in c:
        if old not in c:
            raise RuntimeError('336f branch-less-than conversion anchor not found')
        c = c.replace(old, new, 1)
        path.write_text(c)
        return None


def _patch_336f_int256_branch256_frontend(openvm_install_path = None):
    '''Generic Int256 branch-family decode in the custom opcode space.

    Upstream maps BEQ256_FUNCT3 only to BEQ256, leaving the registered
    BranchLessThan256 opcode class unreachable from word streams. Words in the
    int256 custom opcode space (0x0b) carrying the unallocated branch-family
    funct3 (0b111) select a BranchLessThan256 variant via an immediate tag
    (word bits [27:25]: 0=BLT, 1=BGE, 2=BLTU, 3=BGEU), mirroring the RV32
    branch taxonomy. Ordinary RV32 words are never rerouted.
    '''
    path = openvm_install_path / 'extensions' / 'bigint' / 'transpiler' / 'src' / 'lib.rs'
    if not path.exists():
        return None
    c = path.read_text()
    old = '        if opcode != OPCODE {\n            return None;\n        }\n        if funct3 != INT256_FUNCT3 && funct3 != BEQ256_FUNCT3 {\n            return None;\n        }\n\n        let dec_insn = RType::new(instruction_u32);\n        let instruction = match funct3 {\n'
    new = '        // BEAK-INSERT: guard.336f.int256.branch256_frontend\n        // Generic Int256 branch-family decode: upstream maps BEQ256_FUNCT3 only to\n        // BEQ256, leaving the registered BranchLessThan256 opcode class unreachable\n        // from word streams. The unallocated branch-family funct3 (0b111) in the\n        // int256 custom opcode space selects a BranchLessThan256 variant via an\n        // immediate tag (word bits [27:25]: 0=BLT, 1=BGE, 2=BLTU, 3=BGEU),\n        // mirroring the RV32 branch taxonomy. RV32 semantics are untouched.\n        let beak_branch256_family = opcode == OPCODE && funct3 == 0b111;\n        if !beak_branch256_family && opcode != OPCODE {\n            return None;\n        }\n        if !beak_branch256_family\n            && funct3 != INT256_FUNCT3\n            && funct3 != BEQ256_FUNCT3\n        {\n            return None;\n        }\n\n        if beak_branch256_family {\n            let dec_insn = BType::new(instruction_u32);\n            let beak_branch_op = match (instruction_u32 >> 25) & 0b111 {\n                0 => BranchLessThanOpcode::BLT,\n                1 => BranchLessThanOpcode::BGE,\n                2 => BranchLessThanOpcode::BLTU,\n                3 => BranchLessThanOpcode::BGEU,\n                _ => return None,\n            };\n            return Some(TranspilerOutput::one_to_one(Instruction::new(\n                VmOpcode::from_usize(\n                    beak_branch_op.local_usize()\n                        + Rv32BranchLessThan256Opcode::CLASS_OFFSET,\n                ),\n                F::from_canonical_usize(RV32_REGISTER_NUM_LIMBS * dec_insn.rs1),\n                F::from_canonical_usize(RV32_REGISTER_NUM_LIMBS * dec_insn.rs2),\n                isize_to_field(dec_insn.imm as isize),\n                F::ONE,\n                F::TWO,\n                F::ZERO,\n                F::ZERO,\n            )));\n        }\n\n        let dec_insn = RType::new(instruction_u32);\n        let instruction = match funct3 {\n'
    marker = '// BEAK-INSERT: guard.336f.int256.branch256_frontend'
    legacy_marker = '// BEAK-INSERT: guard.336f.int256.signed_blt_frontend'
    if marker not in c:
        if legacy_marker in c:
            legacy_start = c.rfind('\n', 0, c.find(legacy_marker)) + 1
            legacy_anchor = '        let dec_insn = RType::new(instruction_u32);\n        let instruction = match funct3 {\n'
            legacy_end = c.find(legacy_anchor, legacy_start)
            if legacy_end < 0:
                raise RuntimeError('unterminated legacy 336f signed-BLT frontend patch')
            legacy_end += len(legacy_anchor)
            c = c[:legacy_start] + new + c[legacy_end:]
        else:
            if old not in c:
                raise RuntimeError('336f Int256 transpiler frontend anchor not found')
            c = c.replace(old, new, 1)
        path.write_text(c)
        return None


def apply(*, openvm_install_path, commit_or_branch):
    commit = resolve_openvm_commit(commit_or_branch)
    if commit in {
        OPENVM_BENCHMARK_REGZERO_COMMIT,
        OPENVM_BENCHMARK_BF11_COMMIT}:
        _patch_regzero_record_arena_emit_chip_row(openvm_install_path)
        _patch_regzero_interpreter_preflight_emit_instruction(openvm_install_path)
        _patch_regzero_rv32im_cores_emit_chip_row(openvm_install_path)
        _patch_regzero_system_connector_emit_chip_row(
            openvm_install_path,
            program_row_slice_returns_option=(commit == OPENVM_BENCHMARK_BF11_COMMIT),
        )
        _patch_regzero_program_trace_zero_register_injection(openvm_install_path)
        _patch_regzero_semantic_witness_injection(openvm_install_path)
        _patch_memory_access_emit_support(openvm_install_path)
        _patch_regzero_memory_deep_instrumentation(openvm_install_path)
        _patch_regzero_lookup_multiplicity_instrumentation(openvm_install_path)
        _patch_witness_step_from_pc(openvm_install_path)
        _patch_336f_bitwise_lookup_serde_json_dep(openvm_install_path)
        _patch_336f_base_alu_field_consistent_run_add(openvm_install_path)
        _patch_witness_step_wildcard_support(openvm_install_path)
        _patch_witness_variant_support(openvm_install_path)
        return None
    if commit in {
        OPENVM_BENCHMARK_336F_COMMIT,
        OPENVM_BENCHMARK_F038_COMMIT}:
        _patch_regzero_system_connector_emit_chip_row(openvm_install_path)
        _patch_336f_segment_emit_instruction(openvm_install_path)
        _patch_336f_base_alu_adapter_emit_chip_row(openvm_install_path)
        _patch_336f_auipc_core_emit_chip_row(openvm_install_path)
        _patch_336f_loadstore_core_emit_chip_row(openvm_install_path)
        _patch_memory_access_emit_support(openvm_install_path)
        _patch_336f_divrem_core_emit_chip_row(openvm_install_path)
        _patch_336f_auipc_core_witness_injection(openvm_install_path)
        _patch_336f_loadstore_adapter_witness_injection(openvm_install_path)
        _patch_336f_loadstore_core_witness_injection(openvm_install_path)
        _patch_336f_memory_timestamp_aux_witness_injection(openvm_install_path)
        _patch_336f_memory_lifecycle_instrumentation(openvm_install_path)
        _patch_336f_divrem_core_witness_injection(openvm_install_path)
        _patch_336f_shift_core_semantic_injection(openvm_install_path)
        _patch_336f_less_than_core_semantic_injection(openvm_install_path)
        _patch_336f_base_alu_core_semantic_injection(openvm_install_path)
        _patch_336f_mul_core_semantic_injection(openvm_install_path)
        _patch_336f_mulh_core_semantic_injection(openvm_install_path)
        _patch_336f_divrem_core_md3_injection(openvm_install_path)
        _patch_336f_bitwise_lookup_shadow_multiplicity_injection(openvm_install_path)
        _patch_frozen_time_origin_wrap_witness_injection(openvm_install_path)
        if commit == OPENVM_BENCHMARK_336F_COMMIT:
            _patch_336f_int256_branch256_frontend(openvm_install_path)
            _patch_336f_branch_lt_conversion_receipt(openvm_install_path)
            _patch_336f_program_trace_semantic_injection(openvm_install_path)
            _patch_336f_base_alu_padding_interaction_injection(openvm_install_path)
            _patch_336f_connector_witness_injection(openvm_install_path)
            _patch_336f_control_flow_witness_injection(openvm_install_path)
        _patch_witness_step_wildcard_support(openvm_install_path)
        _patch_witness_variant_support(openvm_install_path)
        if commit == OPENVM_BENCHMARK_F038_COMMIT:
            _patch_f038_memory_finalization_instrumentation(openvm_install_path)
            _patch_f038_connector_witness_injection(openvm_install_path)
            _patch_f038_program_trace_row_anchor(openvm_install_path)
            _patch_f038_volatile_boundary_collection_and_remap(openvm_install_path)
            _patch_f038_loadstore_mem_as_witness_injection(openvm_install_path)
            _patch_f038_loadstore_immediate_sign_witness_injection(openvm_install_path)
            return None
        return None
    raise ValueError(f'''Unsupported commit or branch: {commit_or_branch}''')
