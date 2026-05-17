"""
Pass 3: Trace + Micro-op Collection Instrumentation
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from openvm_fuzzer.settings import (
    OPENVM_BENCHMARK_336F_COMMIT,
    OPENVM_BENCHMARK_F038_COMMIT,
    OPENVM_BENCHMARK_REGZERO_COMMIT,
    OPNEVM_BENCHMARK_REGZERO_ALIAS,
    resolve_openvm_commit,
)
from zkvm_fuzzer_utils.file import replace_in_file

logger = logging.getLogger("fuzzer")

# --- Utility functions ---


def _insert_after(contents: str, *, anchor: str, insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        raise RuntimeError(f"anchor not found for injection: {anchor!r}")
    pos = idx + len(anchor)
    return contents[:pos] + insert + contents[pos:]


def _insert_before(contents: str, *, anchor: str, insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        raise RuntimeError(f"anchor not found for injection: {anchor!r}")
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
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return contents[:i] + insert + contents[i:]
    raise RuntimeError(f"unterminated function body for injection: {needle!r}")


def _ensure_use_fuzzer_utils(path: Path) -> None:
    if not path.exists():
        return
    c = path.read_text()
    if "use fuzzer_utils;" in c:
        return
    header_end = c.find("\n\n")
    if header_end > 0:
        c = c[:header_end] + "\n#[allow(unused_imports)]\nuse fuzzer_utils;\n" + c[header_end:]
        path.write_text(c)


def _ensure_import_after_fuzzer_utils(path: Path, import_line: str) -> None:
    if not path.exists():
        return
    c = path.read_text()
    if import_line in c:
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    idx = c.find("use fuzzer_utils;")
    if idx < 0:
        return
    line_end = c.find("\n", idx)
    pos = line_end + 1 if line_end >= 0 else len(c)
    c = c[:pos] + import_line + "\n" + c[pos:]
    path.write_text(c)


# -------------------------------------------------------------------------------------------------
# regzero specific patches
# -------------------------------------------------------------------------------------------------


def _patch_regzero_record_arena_emit_chip_row(openvm_install_path: Path) -> None:

    path = openvm_install_path / "crates" / "vm" / "src" / "arch" / "record_arena.rs"
    if not path.exists():
        return

    contents = path.read_text()

    anchor = "let height = next_power_of_two_or_zero(rows_used);"
    insert = r"""

        // BEAK-INSERT: Emit padding rows.
        if height > rows_used {
            let max_samples: usize = std::cmp::min(height - rows_used, 3);
            let mut emitted: usize = 0;
            while emitted < max_samples {
                // trace_buffer is row-major flat storage; sample by row start.
                let row_start = (rows_used + emitted) * width;
                let row_end = row_start + width;
                let data = format!("{:?}", &self.trace_buffer[row_start..row_end]);
                fuzzer_utils::emit_padding_chip_row(&data);
                emitted += 1;
            }
        }
        // BEAK-INSERT-END
"""

    if anchor not in contents:
        return
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


def _patch_336f_segment_emit_instruction(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "vm" / "src" / "arch" / "segment.rs"
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = """                if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {
                    let next_state = InstructionExecutor::execute(
                        executor,
                        memory_controller,
                        instruction,
                        ExecutionState::new(pc, timestamp),
                    )?;
                    fuzzer_utils::fuzzer_assert!(next_state.timestamp > timestamp);
                    pc = next_state.pc;
                    timestamp = next_state.timestamp;
                } else {
"""
    new = """                if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {
                    // BEAK-INSERT: guard.336f.segment.emit_instruction
                    let beak_from_pc = pc;
                    let beak_from_timestamp = timestamp;
                    let beak_operands = [
                        instruction.a.as_canonical_u32(),
                        instruction.b.as_canonical_u32(),
                        instruction.c.as_canonical_u32(),
                        instruction.d.as_canonical_u32(),
                        instruction.e.as_canonical_u32(),
                        instruction.f.as_canonical_u32(),
                        instruction.g.as_canonical_u32(),
                    ];
                    let beak_opcode = opcode.as_usize() as u32;
                    fuzzer_utils::begin_instruction_step();
                    // BEAK-INSERT-END
                    let next_state = InstructionExecutor::execute(
                        executor,
                        memory_controller,
                        instruction,
                        ExecutionState::new(pc, timestamp),
                    )?;
                    fuzzer_utils::fuzzer_assert!(next_state.timestamp > timestamp);
                    // BEAK-INSERT: guard.336f.segment.emit_instruction.after
                    fuzzer_utils::emit_instruction_current_step(
                        beak_from_pc,
                        beak_from_timestamp,
                        next_state.pc,
                        next_state.timestamp,
                        beak_opcode,
                        beak_operands,
                    );
                    // BEAK-INSERT-END
                    pc = next_state.pc;
                    timestamp = next_state.timestamp;
                } else {
"""
    if "// BEAK-INSERT: guard.336f.segment.emit_instruction" not in c and old in c:
        c = c.replace(old, new, 1)
    old_f038 = """                if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {
                    let next_state = InstructionExecutor::execute(
                        executor,
                        memory_controller,
                        instruction,
                        ExecutionState::new(pc, timestamp),
                    )?;
                    fuzzer_utils::fuzzer_assert!(next_state.timestamp > timestamp);
                    pc = next_state.pc;
                    timestamp = next_state.timestamp;
                } else {
"""
    new_f038 = """                if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {
                    // BEAK-INSERT: guard.336f.segment.emit_instruction
                    let beak_from_pc = pc;
                    let beak_from_timestamp = timestamp;
                    let beak_operands = [
                        instruction.a.as_canonical_u32(),
                        instruction.b.as_canonical_u32(),
                        instruction.c.as_canonical_u32(),
                        instruction.d.as_canonical_u32(),
                        instruction.e.as_canonical_u32(),
                        instruction.f.as_canonical_u32(),
                        instruction.g.as_canonical_u32(),
                    ];
                    let beak_opcode = opcode.as_usize() as u32;
                    fuzzer_utils::begin_instruction_step();
                    // BEAK-INSERT-END
                    let next_state = InstructionExecutor::execute(
                        executor,
                        memory_controller,
                        instruction,
                        ExecutionState::new(pc, timestamp),
                    )?;
                    fuzzer_utils::fuzzer_assert!(next_state.timestamp > timestamp);
                    // BEAK-INSERT: guard.336f.segment.emit_instruction.after
                    fuzzer_utils::emit_instruction_current_step(
                        beak_from_pc,
                        beak_from_timestamp,
                        next_state.pc,
                        next_state.timestamp,
                        beak_opcode,
                        beak_operands,
                    );
                    // BEAK-INSERT-END
                    pc = next_state.pc;
                    timestamp = next_state.timestamp;
                } else {
"""
    if "// BEAK-INSERT: guard.336f.segment.emit_instruction" not in c and old_f038 in c:
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


def _patch_regzero_system_connector_emit_chip_row(openvm_install_path: Path) -> None:
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
            let row = cached.trace.row_slice(i);
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
""",
            )
        except RuntimeError:
            pass
        program.write_text(c)


def _patch_336f_program_trace_semantic_injection(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "vm" / "src" / "system" / "program" / "trace.rs"
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = r"""    rows.par_chunks_mut(width)
        .zip(instructions)
        .for_each(|(row, (pc, instruction))| {
            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();
            *row = ProgramExecutionCols {
                pc: F::from_canonical_u32(pc),
                opcode: instruction.opcode.to_field(),
                a: instruction.a,
                b: instruction.b,
                c: instruction.c,
                d: instruction.d,
                e: instruction.e,
                f: instruction.f,
                g: instruction.g,
            };
        });
"""
    new = r"""    rows.par_chunks_mut(width)
        .zip(instructions.into_par_iter().enumerate())
        .for_each(|(row, (i, (pc, instruction)))| {
            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();
            *row = ProgramExecutionCols {
                pc: F::from_canonical_u32(pc),
                opcode: instruction.opcode.to_field(),
                a: instruction.a,
                b: instruction.b,
                c: instruction.c,
                d: instruction.d,
                e: instruction.e,
                f: instruction.f,
                g: instruction.g,
            };

            // BEAK-INSERT: guard.336f.program_trace.semantic_injection
            let beak_program_step = i as u64;
            if fuzzer_utils::witness_injection_enabled_at(
                "openvm.semantic.decode.zero_register_immutability",
                beak_program_step,
            ) && fuzzer_utils::should_inject_witness(
                "openvm.semantic.decode.zero_register_immutability",
                beak_program_step,
            ) {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.decode.zero_register_immutability step={} pc={}",
                    beak_program_step,
                    pc
                );
                row.a += F::from_canonical_u32(1);
            }
            if fuzzer_utils::witness_injection_enabled_at(
                "openvm.semantic.decode.operand_index_routing",
                beak_program_step,
            ) && fuzzer_utils::should_inject_witness(
                "openvm.semantic.decode.operand_index_routing",
                beak_program_step,
            ) {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.decode.operand_index_routing step={} pc={}",
                    beak_program_step,
                    pc
                );
                row.b += F::from_canonical_u32(1);
            }
            if fuzzer_utils::witness_injection_enabled_at(
                "openvm.semantic.decode.format_immediate_reassembly",
                beak_program_step,
            ) && fuzzer_utils::should_inject_witness(
                "openvm.semantic.decode.format_immediate_reassembly",
                beak_program_step,
            ) {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.decode.format_immediate_reassembly step={} pc={}",
                    beak_program_step,
                    pc
                );
                row.c += F::from_canonical_u32(1);
            }
            let beak_terminate_opcode: F = SystemOpcode::TERMINATE.global_opcode().to_field();
            if row.opcode == beak_terminate_opcode
                && fuzzer_utils::witness_injection_enabled_at(
                    "openvm.semantic.control.ecall_word_validity",
                    beak_program_step,
                )
                && fuzzer_utils::should_inject_witness(
                    "openvm.semantic.control.ecall_word_validity",
                    beak_program_step,
                )
            {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.control.ecall_word_validity step={} pc={}",
                    beak_program_step,
                    pc
                );
                row.opcode += F::from_canonical_u32(1);
            }
            // BEAK-INSERT-END
        });
"""
    if "// BEAK-INSERT: guard.336f.program_trace.semantic_injection" not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_regzero_program_trace_zero_register_injection(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "vm" / "src" / "system" / "program" / "trace.rs"
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = r"""    rows.par_chunks_mut(width)
        .zip(instructions)
        .for_each(|(row, (pc, instruction))| {
            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();
            *row = ProgramExecutionCols {
                pc: F::from_canonical_u32(pc),
                opcode: instruction.opcode.to_field(),
                a: instruction.a,
                b: instruction.b,
                c: instruction.c,
                d: instruction.d,
                e: instruction.e,
                f: instruction.f,
                g: instruction.g,
            };
        });
"""
    new = r"""    rows.par_chunks_mut(width)
        .zip(instructions.into_par_iter().enumerate())
        .for_each(|(row, (i, (pc, instruction)))| {
            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();
            *row = ProgramExecutionCols {
                pc: F::from_canonical_u32(pc),
                opcode: instruction.opcode.to_field(),
                a: instruction.a,
                b: instruction.b,
                c: instruction.c,
                d: instruction.d,
                e: instruction.e,
                f: instruction.f,
                g: instruction.g,
            };

            // BEAK-INSERT: guard.regzero.program_trace.zero_register_immutability
            let beak_program_step = i as u64;
            if fuzzer_utils::should_inject_witness(
                "openvm.semantic.decode.zero_register_immutability",
                beak_program_step,
            ) {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.decode.zero_register_immutability step={} pc={}",
                    beak_program_step,
                    pc
                );
                row.a += F::from_canonical_u32(1);
            }
            // BEAK-INSERT-END
        });
"""
    if "// BEAK-INSERT: guard.regzero.program_trace.zero_register_immutability" not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_336f_base_alu_padding_interaction_injection(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "vm" / "src" / "arch" / "integration_api.rs"
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    anchor = "        let mut trace = RowMajorMatrix::new(values, width);\n"
    insert = r"""        // BEAK-INSERT: guard.336f.base_alu.padding_interaction_send
        let beak_adapter_name = get_air_name(self.adapter.air());
        let beak_core_name = get_air_name(self.core.air());
        if height > num_records
            && beak_adapter_name.contains("Rv32BaseAluAdapterAir")
            && beak_core_name.contains("BaseAluCoreAir")
        {
            let beak_padding_step = num_records as u64;
            if fuzzer_utils::should_inject_witness(
                "openvm.semantic.row.padding_interaction_send",
                beak_padding_step,
            ) {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.row.padding_interaction_send step={} site=base_alu_padding_row row_idx={} real_rows={} height={}",
                    beak_padding_step,
                    num_records,
                    num_records,
                    height
                );
                let beak_target = std::env::var("BEAK_OPENVM_PADDING_INTERACTION_TARGET")
                    .ok()
                    .and_then(|raw| {
                        let parts = raw
                            .split(',')
                            .filter_map(|part| part.parse::<u32>().ok())
                            .collect::<Vec<_>>();
                        (parts.len() >= 7).then(|| {
                            (
                                parts[0],
                                parts[1],
                                parts[2],
                                [parts[3], parts[4], parts[5], parts[6]],
                            )
                        })
                    })
                    .unwrap_or((1, 0, 0, [0, 0, 0, 0]));
                let (
                    beak_target_as,
                    beak_target_pointer,
                    beak_prev_timestamp,
                    beak_target_data,
                ) = beak_target;
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.row.padding_interaction_send site=base_alu_padding_target address_space={} pointer={} prev_timestamp={} data={:?}",
                    beak_target_as,
                    beak_target_pointer,
                    beak_prev_timestamp,
                    beak_target_data
                );
                let beak_row_start = num_records * width;
                // Rv32BaseAluAdapterCols layout:
                // from_state(pc,timestamp), rd_ptr, rs1_ptr, rs2, rs2_as, reads_aux...
                let beak_from_timestamp_offset = 1usize;
                let beak_rs2_offset = 4usize;
                let beak_rs2_as_offset = 5usize;
                let beak_rs2_prev_timestamp_offset = 9usize;
                // BaseAluCoreCols layout: a[4], b[4], c[4], flags[5].
                let beak_core_c_offset = adapter_width + 8usize;
                if beak_row_start + beak_core_c_offset + 3 < values.len() {
                    values[beak_row_start + beak_from_timestamp_offset] =
                        Val::<SC>::from_canonical_u32(beak_prev_timestamp);
                    values[beak_row_start + beak_rs2_offset] =
                        Val::<SC>::from_canonical_u32(beak_target_pointer);
                    values[beak_row_start + beak_rs2_as_offset] =
                        Val::<SC>::from_canonical_u32(beak_target_as);
                    values[beak_row_start + beak_rs2_prev_timestamp_offset] =
                        Val::<SC>::from_canonical_u32(beak_prev_timestamp);
                    for (i, limb) in beak_target_data.into_iter().enumerate() {
                        values[beak_row_start + beak_core_c_offset + i] =
                            Val::<SC>::from_canonical_u32(limb);
                    }
                }
            }
        }
        // BEAK-INSERT-END

"""
    if "// BEAK-INSERT: guard.336f.base_alu.padding_interaction_send" not in c and anchor in c:
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

    # Inject witness-level mutation hook in preprocess (audit-o5 / immediate-limb decomposition).
    try:
        c = _insert_after(
            c,
            anchor="let rs1 = memory.read::<RV32_REGISTER_NUM_LIMBS>(d, b);",
            guard="// BEAK-INSERT: guard.336f.adapter.base_alu.preprocess_step",
            insert=r"""

        // BEAK-INSERT: guard.336f.adapter.base_alu.preprocess_step
        // BEAK-INSERT: deterministic per-row witness-step counter for targeted loop2 injection.
        let beak_witness_step = fuzzer_utils::next_witness_step();
        // BEAK-INSERT-END
""",
        )
    except RuntimeError:
        pass

    old_imm_block = r"""        let (rs2, rs2_data, rs2_imm) = if e.is_zero() {
            let c_u32 = c.as_canonical_u32();
            fuzzer_utils::fuzzer_assert_eq!(c_u32 >> 24, 0);
            memory.increment_timestamp();
            (
                None,
                [
                    c_u32 as u8,
                    (c_u32 >> 8) as u8,
                    (c_u32 >> 16) as u8,
                    (c_u32 >> 16) as u8,
                ]
                .map(F::from_canonical_u8),
                c,
            )
        } else {
"""
    new_imm_block = r"""        let (rs2, rs2_data, rs2_imm) = if e.is_zero() {
            let c_u32 = c.as_canonical_u32();
            fuzzer_utils::fuzzer_assert_eq!(c_u32 >> 24, 0);
            memory.increment_timestamp();
            let mut beak_rs2_data = [
                c_u32 as u8,
                (c_u32 >> 8) as u8,
                (c_u32 >> 16) as u8,
                (c_u32 >> 16) as u8,
            ]
            .map(F::from_canonical_u8);

            // BEAK-INSERT: guard.336f.adapter.base_alu.preprocess_o5
            // BEAK-INSERT: witness-only injection for audit-o5 (immediate limb decomposition).
            // Keep rs2_imm unchanged while forging out-of-range limb[0].
            if fuzzer_utils::should_inject_witness("openvm.semantic.alu.immediate_limb_consistency", beak_witness_step)
            {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.alu.immediate_limb_consistency step={} c_u32={}",
                    beak_witness_step,
                    c_u32
                );
                beak_rs2_data = [F::from_canonical_u32(c_u32), F::ZERO, F::ZERO, F::ZERO];
            }
            // BEAK-INSERT-END

            (None, beak_rs2_data, c)
        } else {
"""
    if "// BEAK-INSERT: guard.336f.adapter.base_alu.preprocess_o5" not in c and old_imm_block in c:
        c = c.replace(old_imm_block, new_imm_block, 1)

    try:
        c = _insert_before_fn_close(
            c,
            fn_name="generate_trace_row",
            guard="// BEAK-INSERT: guard.336f.adapter.base_alu.emit_chip_row",
            insert=r"""

        // BEAK-INSERT: guard.336f.adapter.base_alu.emit_chip_row
        // BEAK-INSERT: Emit base_alu chip-row micro-op from adapter-layer row.
        let rd_ptr = row_slice.rd_ptr.as_canonical_u32();
        let rs1_ptr = row_slice.rs1_ptr.as_canonical_u32();
        let is_rs2_imm = row_slice.rs2_as.as_canonical_u32() == 0;
        let rs2_i32 = row_slice.rs2.as_canonical_u32() as i32;

        // Adapter reads/writes are 4-limb values in this snapshot.
        let a_u8: [u8; 4] = write_record.rd.1.map(|x| x.as_canonical_u32() as u8);
        let b_u8: [u8; 4] = core::array::from_fn(|i| rs1.data_at(i).as_canonical_u32() as u8);
        let c_u8: [u8; 4] = if read_record.rs2.is_none() {
            let imm_u32 = read_record.rs2_imm.as_canonical_u32();
            [
                (imm_u32 & 0xff) as u8,
                ((imm_u32 >> 8) & 0xff) as u8,
                ((imm_u32 >> 16) & 0xff) as u8,
                ((imm_u32 >> 24) & 0xff) as u8,
            ]
        } else {
            let rs2 = rs2.expect("rs2 record must exist when rs2 is not immediate");
            core::array::from_fn(|i| rs2.data_at(i).as_canonical_u32() as u8)
        };

        // Opcode-local value is not present in adapter record here; keep 0 as placeholder.
        fuzzer_utils::emit_base_alu_chip_row(0, rd_ptr, rs1_ptr, rs2_i32, is_rs2_imm, a_u8, b_u8, c_u8);
        // BEAK-INSERT-END
""",
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


def _patch_memory_access_emit_support(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "fuzzer_utils" / "src" / "lib.rs"
    if not path.exists():
        return
    c = path.read_text()

    method_anchor = """    pub fn emit_memory_interaction(
        &mut self,
        direction: &str,
        row_id: Option<&str>,
        address_space: u32,
        pointer: u32,
        data: Vec<u32>,
        timestamp: u32,
    ) {
        let payload_data = json!({
            "address_space": address_space,
            "pointer": pointer,
            "data": data,
            "timestamp": timestamp,
        });
        self.emit_interaction_envelope(
            "memory",
            direction,
            row_id,
            Some(timestamp),
            "memory",
            payload_data,
        );
    }
"""
    method_insert = method_anchor + r"""
    pub fn emit_memory_access(
        &mut self,
        row_op_idx: u64,
        opcode: u32,
        rs1_ptr: u32,
        rd_rs2_ptr: u32,
        imm: i32,
        imm_sign: bool,
        address_space: u32,
        raw_ptr: u32,
        effective_ptr: u32,
        aligned_ptr: u32,
        byte_offset: u32,
        width: u32,
        is_load: bool,
        is_store: bool,
        needs_write: bool,
        timestamp: u32,
        read_data: Vec<u32>,
        prev_data: Vec<u32>,
        write_data: Vec<u32>,
    ) {
        let micro_op = json!({
            "type": "memory_access",
            "data": {
                "seq": self.seq,
                "step_idx": self.step_idx,
                "op_idx": self.op_idx_in_step,
                "row_op_idx": row_op_idx,
                "opcode": opcode,
                "rs1_ptr": rs1_ptr,
                "rd_rs2_ptr": rd_rs2_ptr,
                "imm": imm,
                "imm_sign": imm_sign,
                "address_space": address_space,
                "raw_ptr": raw_ptr,
                "effective_ptr": effective_ptr,
                "aligned_ptr": aligned_ptr,
                "byte_offset": byte_offset,
                "width": width,
                "is_load": is_load,
                "is_store": is_store,
                "needs_write": needs_write,
                "timestamp": timestamp,
                "read_data": read_data,
                "prev_data": prev_data,
                "write_data": write_data,
            }
        });
        self.op_idx_in_step += 1;
        self.emit_micro_op(micro_op);
    }
"""
    if "pub fn emit_memory_access(" not in c and method_anchor in c:
        c = c.replace(method_anchor, method_insert, 1)

    public_anchor = """pub fn emit_memory_interaction(
    direction: &str,
    row_id: Option<&str>,
    address_space: u32,
    pointer: u32,
    data: Vec<u32>,
    timestamp: u32,
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_memory_interaction(direction, row_id, address_space, pointer, data, timestamp);
}
"""
    public_insert = public_anchor + r"""
pub fn emit_memory_access(
    row_op_idx: u64,
    opcode: u32,
    rs1_ptr: u32,
    rd_rs2_ptr: u32,
    imm: i32,
    imm_sign: bool,
    address_space: u32,
    raw_ptr: u32,
    effective_ptr: u32,
    aligned_ptr: u32,
    byte_offset: u32,
    width: u32,
    is_load: bool,
    is_store: bool,
    needs_write: bool,
    timestamp: u32,
    read_data: Vec<u32>,
    prev_data: Vec<u32>,
    write_data: Vec<u32>,
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_memory_access(
        row_op_idx,
        opcode,
        rs1_ptr,
        rd_rs2_ptr,
        imm,
        imm_sign,
        address_space,
        raw_ptr,
        effective_ptr,
        aligned_ptr,
        byte_offset,
        width,
        is_load,
        is_store,
        needs_write,
        timestamp,
        read_data,
        prev_data,
        write_data,
    );
}
"""
    if "pub fn emit_memory_access(\n    row_op_idx" not in c and public_anchor in c:
        c = c.replace(public_anchor, public_insert, 1)
    if '"write_data": write_data,' not in c and "pub fn emit_memory_access(" in c:
        c = c.replace(
            "        prev_data: Vec<u32>,\n    ) {\n",
            "        prev_data: Vec<u32>,\n        write_data: Vec<u32>,\n    ) {\n",
            1,
        )
        c = c.replace(
            "                \"prev_data\": prev_data,\n",
            "                \"prev_data\": prev_data,\n                \"write_data\": write_data,\n",
            1,
        )
        c = c.replace(
            "    prev_data: Vec<u32>,\n) {\n",
            "    prev_data: Vec<u32>,\n    write_data: Vec<u32>,\n) {\n",
            1,
        )
        c = c.replace(
            "        prev_data,\n    );\n",
            "        prev_data,\n        write_data,\n    );\n",
            1,
        )

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
            insert=r"""

        // BEAK-INSERT: guard.336f.loadstore.core.witness_memory
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.value_payload_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.value_payload_consistency step={}",
                beak_witness_step
            );
            core_cols.write_data[0] += F::ONE;
        }
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.store_load_payload_flow", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.store_load_payload_flow step={}",
                beak_witness_step
            );
            core_cols.write_data[0] += F::ONE;
        }
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.kind_selector_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.kind_selector_consistency step={}",
                beak_witness_step
            );
            core_cols.is_load = F::ONE - core_cols.is_load;
        }
        // BEAK-INSERT-END
""",
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_336f_memory_timestamp_aux_witness_injection(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "vm" / "src" / "system" / "memory" / "controller" / "mod.rs"
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = r"""    pub fn generate_base_aux(&self, record: &MemoryRecord<F>, buffer: &mut MemoryBaseAuxCols<F>) {
        buffer.prev_timestamp = F::from_canonical_u32(record.prev_timestamp);
        self.generate_timestamp_lt(
            record.prev_timestamp,
            record.timestamp,
            &mut buffer.timestamp_lt_aux,
        );
    }
"""
    new = r"""    pub fn generate_base_aux(&self, record: &MemoryRecord<F>, buffer: &mut MemoryBaseAuxCols<F>) {
        buffer.prev_timestamp = F::from_canonical_u32(record.prev_timestamp);
        self.generate_timestamp_lt(
            record.prev_timestamp,
            record.timestamp,
            &mut buffer.timestamp_lt_aux,
        );

        // BEAK-INSERT: guard.336f.memory.timestamp_aux
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.time.monotonic_access_ordering", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.time.monotonic_access_ordering step={} prev_timestamp={} timestamp={}",
                beak_witness_step,
                record.prev_timestamp,
                record.timestamp
            );
            buffer.prev_timestamp = F::from_canonical_u32(record.timestamp);
        }
        // BEAK-INSERT-END
    }
"""
    if "// BEAK-INSERT: guard.336f.memory.timestamp_aux" not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_336f_memory_lifecycle_instrumentation(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "vm" / "src" / "system" / "memory" / "controller" / "mod.rs"
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()

    old_set = r"""    pub fn set_initial_memory(&mut self, memory: MemoryImage<F>) {
        if self.timestamp() > INITIAL_TIMESTAMP + 1 {
            panic!("Cannot set initial memory after first timestamp");
        }
        let mut offline_memory = self.offline_memory.lock().unwrap();
        offline_memory.set_initial_memory(memory.clone(), self.mem_config);

        self.memory = Memory::from_image(memory.clone(), self.mem_config.access_capacity);
"""
    new_set = r"""    pub fn set_initial_memory(&mut self, memory: MemoryImage<F>) {
        if self.timestamp() > INITIAL_TIMESTAMP + 1 {
            panic!("Cannot set initial memory after first timestamp");
        }

        // BEAK-INSERT: guard.336f.memory.lifecycle.initial
        let beak_initial_cells: Vec<_> = memory
            .items()
            .filter_map(|((address_space, pointer), value)| {
                let value = value.as_canonical_u32();
                (value != 0).then_some(((address_space, pointer), value))
            })
            .collect();
        for (beak_init_idx, ((address_space, pointer), value)) in
            beak_initial_cells.into_iter().enumerate()
        {
            let beak_init_idx = beak_init_idx as u64;
            fuzzer_utils::emit_memory_init(beak_init_idx, address_space, pointer, value);
        }
        // BEAK-INSERT-END

        let mut offline_memory = self.offline_memory.lock().unwrap();
        offline_memory.set_initial_memory(memory.clone(), self.mem_config);

        self.memory = Memory::from_image(memory.clone(), self.mem_config.access_capacity);
"""
    if "// BEAK-INSERT: guard.336f.memory.lifecycle.initial" not in c and old_set in c:
        c = c.replace(old_set, new_set, 1)

    old_final = r"""                let (final_partition, records) = offline_memory.finalize::<CHUNK>();
                self.access_adapters.extend_records(records);

                boundary_chip.finalize(initial_memory, &final_partition, hasher);
                let final_memory_values = final_partition
"""
    new_final = r"""                let (mut final_partition, mut records) = offline_memory.finalize::<CHUNK>();

                // BEAK-INSERT: guard.336f.base_alu.padding_interaction_send.final_merge
                if fuzzer_utils::witness_injection_enabled_for(
                    "openvm.semantic.row.padding_interaction_send",
                ) {
                    for record in records.iter_mut() {
                        let address_space = record.address_space.as_canonical_u32();
                        let pointer = record.start_index.as_canonical_u32();
                        if address_space != 1 || pointer % CHUNK as u32 != 0 || record.data.len() != CHUNK {
                            continue;
                        }
                        if let crate::system::memory::adapter::AccessAdapterRecordKind::Merge {
                            left_timestamp,
                            right_timestamp,
                        } = &mut record.kind
                        {
                            let old_left_timestamp = *left_timestamp;
                            let new_left_timestamp = old_left_timestamp.saturating_add(1);
                            *left_timestamp = new_left_timestamp;
                            let new_parent_timestamp =
                                std::cmp::max(new_left_timestamp, *right_timestamp);
                            record.timestamp = new_parent_timestamp;
                            if let Some(values) =
                                final_partition.get_mut(&(address_space, pointer / CHUNK as u32))
                            {
                                values.timestamp = new_parent_timestamp;
                            }
                            let target_values = record
                                .data
                                .iter()
                                .take(CHUNK / 2)
                                .map(|value| value.as_canonical_u32().to_string())
                                .collect::<Vec<_>>()
                                .join(",");
                            std::env::set_var(
                                "BEAK_OPENVM_PADDING_INTERACTION_TARGET",
                                format!(
                                    "{address_space},{pointer},{old_left_timestamp},{target_values}"
                                ),
                            );
                            eprintln!(
                                "[beak-witness-inject] kind=openvm.semantic.row.padding_interaction_send site=memory_final_merge address_space={} pointer={} old_left_timestamp={} new_left_timestamp={} right_timestamp={} parent_timestamp={}",
                                address_space,
                                pointer,
                                old_left_timestamp,
                                new_left_timestamp,
                                *right_timestamp,
                                new_parent_timestamp
                            );
                            let mut beak_bits_remaining = self.mem_config.clk_max_bits;
                            for _ in 0..AUX_LEN {
                                let range_bits =
                                    beak_bits_remaining.min(self.range_checker_bus.range_max_bits);
                                self.range_checker.add_count(0, range_bits);
                                beak_bits_remaining = beak_bits_remaining
                                    .saturating_sub(self.range_checker_bus.range_max_bits);
                            }
                            break;
                        }
                    }
                } else {
                    std::env::remove_var("BEAK_OPENVM_PADDING_INTERACTION_TARGET");
                }
                // BEAK-INSERT-END

                self.access_adapters.extend_records(records);

                // BEAK-INSERT: guard.336f.memory.lifecycle.finalization
                let beak_final_cells: Vec<_> = final_partition
                    .iter()
                    .map(|(&(address_space, chunk_label), values)| {
                        let pointer = chunk_label * CHUNK as u32;
                        let final_values = values
                            .values
                            .iter()
                            .map(|value| value.as_canonical_u32())
                            .collect::<Vec<_>>();
                        let initial_values = (0..CHUNK as u32)
                            .map(|offset| {
                                initial_memory
                                    .get(&(address_space, pointer + offset))
                                    .copied()
                                    .unwrap_or(F::ZERO)
                                    .as_canonical_u32()
                            })
                            .collect::<Vec<_>>();
                        let was_initial = initial_values.iter().any(|value| *value != 0);
                        let changed_from_initial = final_values != initial_values;
                        (
                            (address_space, chunk_label),
                            pointer,
                            values.timestamp,
                            final_values,
                            was_initial,
                            changed_from_initial,
                        )
                    })
                    .collect();
                for (
                    beak_final_idx,
                    (
                        (address_space, chunk_label),
                        pointer,
                        timestamp,
                        final_values,
                        was_initial,
                        changed_from_initial,
                    ),
                ) in beak_final_cells.into_iter().enumerate()
                {
                    let beak_final_idx = beak_final_idx as u64;
                    fuzzer_utils::emit_memory_finalization(
                        beak_final_idx,
                        address_space,
                        pointer,
                        timestamp,
                        final_values,
                        was_initial,
                        changed_from_initial,
                    );
                    if fuzzer_utils::should_inject_witness(
                        "openvm.semantic.memory.finalization_consistency",
                        beak_final_idx,
                    ) {
                        eprintln!(
                            "[beak-witness-inject] kind=openvm.semantic.memory.finalization_consistency step={} address_space={} pointer={} timestamp={}",
                            beak_final_idx,
                            address_space,
                            pointer,
                            timestamp
                        );
                        if let Some(values) =
                            final_partition.get_mut(&(address_space, chunk_label))
                        {
                            values.values[0] += F::from_canonical_u32(1);
                        }
                    }
                }
                // BEAK-INSERT-END

                boundary_chip.finalize(initial_memory, &final_partition, hasher);
                let final_memory_values = final_partition
"""
    if "// BEAK-INSERT: guard.336f.memory.lifecycle.finalization" not in c and old_final in c:
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


def _patch_336f_auipc_core_witness_injection(openvm_install_path: Path) -> None:
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
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = r"""        let imm_limbs = array::from_fn(|i| (imm >> (i * RV32_CELL_BITS)) & RV32_LIMB_MAX);
        let pc_limbs = array::from_fn(|i| (from_pc >> ((i + 1) * RV32_CELL_BITS)) & RV32_LIMB_MAX);
"""
    new = r"""        let mut imm_limbs = array::from_fn(|i| (imm >> (i * RV32_CELL_BITS)) & RV32_LIMB_MAX);
        let mut pc_limbs = array::from_fn(|i| (from_pc >> ((i + 1) * RV32_CELL_BITS)) & RV32_LIMB_MAX);

        // BEAK-INSERT: guard.336f.auipc.core.preprocess_o7
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.control.auipc_pc_limb_consistency", beak_witness_step) {
            let can_inject_o7 = ((from_pc >> 24) != 0) || (((imm >> 16) & 0xff) != 0);
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.control.auipc_pc_limb_consistency step={} from_pc={} imm={}",
                beak_witness_step,
                from_pc,
                imm
            );
            if can_inject_o7 {
                let from_pc_hi = (from_pc >> RV32_CELL_BITS) & RV32_LIMB_MAX;
                let from_pc_top = (from_pc >> (RV32_CELL_BITS * 3)) & RV32_LIMB_MAX;
                pc_limbs[1] = from_pc_hi.wrapping_add(1) & RV32_LIMB_MAX;
                pc_limbs[2] = from_pc_top.wrapping_add(1) & RV32_LIMB_MAX;
            }
        }
        // BEAK-INSERT-END
"""
    if "// BEAK-INSERT: guard.336f.auipc.core.preprocess_o7" not in c and old in c:
        c = c.replace(old, new, 1)
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
    new = r"""        let imm = c.as_canonical_u32();
        let imm_sign = (imm & 0x8000) >> 15;

        // BEAK-INSERT: guard.336f.loadstore.adapter.preprocess_o8
        let beak_witness_step = fuzzer_utils::next_witness_step();
        let beak_variant =
            fuzzer_utils::active_witness_variant("openvm.semantic.memory.immediate_sign_consistency");
        let spec = beak_variant
            .as_deref()
            .unwrap_or("mode=flip_sign,domain=any,guard=none");
        let mut mode = "flip_sign";
        let mut domain = "any";
        let mut guard = "none";
        for part in spec.split(',') {
            if let Some((spec_key, spec_value)) = part.split_once('=') {
                match spec_key.trim() {
                    "mode" => mode = spec_value.trim(),
                    "domain" => domain = spec_value.trim(),
                    "guard" => guard = spec_value.trim(),
                    _ => {}
                }
            }
        }
        let local_opcode = Rv32LoadStoreOpcode::from_usize(
            opcode.local_opcode_idx(Rv32LoadStoreOpcode::CLASS_OFFSET),
        );
        let opcode_shift_ok = |ptr: u32| match (local_opcode, ptr & 0x3) {
            (LOADW, 0) | (STOREW, 0) => true,
            (LOADH, 0) | (LOADH, 2) | (LOADHU, 0) | (LOADHU, 2) | (STOREH, 0) | (STOREH, 2) => true,
            (LOADB, _) | (LOADBU, _) | (STOREB, _) => true,
            _ => false,
        };
        let is_load = matches!(local_opcode, LOADW | LOADB | LOADH | LOADBU | LOADHU);
        let is_store = matches!(local_opcode, STOREW | STOREH | STOREB);
        let base_imm_extended = imm + imm_sign * 0xffff0000;
        let orig_ptr = rs1_val.wrapping_add(base_imm_extended);
        let mut beak_imm_sign = imm_sign;
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.immediate_sign_consistency", beak_witness_step) {
            let candidate_sign = if imm_sign == 1 { 0 } else { 1 };
            let candidate_ext = imm + candidate_sign * 0xffff0000;
            let flipped_ptr = rs1_val.wrapping_add(candidate_ext);
            let ptr_in_range = flipped_ptr < (1 << self.air.pointer_max_bits);
            let domain_ok = match domain {
                "load" => is_load,
                "store" => is_store,
                _ => true,
            };
            let guard_ok = match guard {
                "alt_in_range" => ptr_in_range,
                _ => true,
            };
            if mode == "flip_sign" && domain_ok && guard_ok && opcode_shift_ok(flipped_ptr) && ptr_in_range {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.memory.immediate_sign_consistency step={} imm={} mode={} domain={} guard={} orig_ptr={} flipped_ptr={} flipped_sign={} variant={}",
                    beak_witness_step,
                    imm,
                    mode,
                    domain,
                    guard,
                    orig_ptr,
                    flipped_ptr,
                    candidate_sign,
                    spec
                );
                beak_imm_sign = candidate_sign;
            } else {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.memory.immediate_sign_consistency step={} imm={} mode=skip_context domain={} guard={} orig_ptr={} variant={}",
                    beak_witness_step,
                    imm,
                    domain,
                    guard,
                    orig_ptr,
                    spec
                );
            }
        }
        // BEAK-INSERT-END

        let imm_extended = imm + beak_imm_sign * 0xffff0000;
"""
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


def _patch_336f_divrem_core_witness_injection(openvm_install_path: Path) -> None:
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
            anchor="fn generate_trace_row(&self, row_slice: &mut [F], record: Self::Record) {",
            guard="// BEAK-INSERT: guard.336f.divrem.core.o15",
            insert=r"""
        // BEAK-INSERT: guard.336f.divrem.core.o15
        let beak_witness_step = fuzzer_utils::next_witness_step();
        let beak_inject_o15 = fuzzer_utils::should_inject_witness(
            "openvm.semantic.arithmetic.special_case_consistency",
            beak_witness_step,
        );
        // BEAK-INSERT-END
""",
        )
        c = _insert_after(
            c,
            anchor="        row_slice.opcode_remu_flag = F::from_bool(record.opcode == DivRemOpcode::REMU);",
            guard="// BEAK-INSERT: guard.336f.divrem.core.o15.apply",
            insert=r"""

        // BEAK-INSERT: guard.336f.divrem.core.o15.apply
        if beak_inject_o15 {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.arithmetic.special_case_consistency step={}",
                beak_witness_step
            );
            // Force invalid row while keeping special_case=true, so multiplicity becomes -1.
            row_slice.opcode_div_flag = F::ZERO;
            row_slice.opcode_divu_flag = F::ZERO;
            row_slice.opcode_rem_flag = F::ZERO;
            row_slice.opcode_remu_flag = F::ZERO;
            row_slice.zero_divisor = F::ONE;
            row_slice.r_zero = F::ZERO;
        }
        // BEAK-INSERT-END
""",
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
            insert=r"""

        // BEAK-INSERT: guard.336f.shift.core.shift_mod32
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.shift_mod32", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.alu.shift_mod32 step={}",
                beak_witness_step
            );
            row_slice.a[0] += F::ONE;
        }
        // BEAK-INSERT-END
""",
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
            insert=r"""

        // BEAK-INSERT: guard.336f.less_than.core.alu_semantics
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.comparison_booleanity", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.alu.comparison_booleanity step={}",
                beak_witness_step
            );
            row_slice.cmp_result = F::ONE - row_slice.cmp_result;
        }
        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.comparison_auxiliary_chain", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.alu.comparison_auxiliary_chain step={}",
                beak_witness_step
            );
            if record.diff_idx == NUM_LIMBS {
                row_slice.diff_marker[0] = F::ONE;
            } else {
                row_slice.diff_val += F::ONE;
            }
        }
        // BEAK-INSERT-END
""",
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
            insert=r"""

        // BEAK-INSERT: guard.336f.base_alu.core.sub_borrow
        if record.opcode == BaseAluOpcode::SUB {
            let beak_witness_step = fuzzer_utils::next_witness_step();
            if fuzzer_utils::should_inject_witness("openvm.semantic.alu.subtraction_borrow_chain", beak_witness_step) {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.alu.subtraction_borrow_chain step={}",
                    beak_witness_step
                );
                row_slice.a[0] += F::ONE;
            }
        }
        // BEAK-INSERT-END
""",
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
            insert=r"""

        // BEAK-INSERT: guard.336f.mul.core.product_decomposition
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.product_decomposition", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.arithmetic.product_decomposition step={} site=mul",
                beak_witness_step
            );
            row_slice.a[0] += F::ONE;
        }
        // BEAK-INSERT-END
""",
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
            insert=r"""

        // BEAK-INSERT: guard.336f.mulh.core.product_semantics
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.product_decomposition", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.arithmetic.product_decomposition step={} site=mulh",
                beak_witness_step
            );
            row_slice.a[0] += F::ONE;
        }
        if record.opcode == MulHOpcode::MULHSU
            && fuzzer_utils::should_inject_witness(
                "openvm.semantic.arithmetic.signed_unsigned_product_correction",
                beak_witness_step,
            )
        {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.arithmetic.signed_unsigned_product_correction step={}",
                beak_witness_step
            );
            row_slice.b_ext += F::ONE;
        }
        // BEAK-INSERT-END
""",
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
            insert=r"""
        // BEAK-INSERT: guard.336f.divrem.core.md3
        if record.zero_divisor.as_canonical_u32() == 0 {
            let beak_witness_step = fuzzer_utils::next_witness_step();
            if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.division_remainder_bound", beak_witness_step) {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.arithmetic.division_remainder_bound step={}",
                    beak_witness_step
                );
                row_slice.q[0] += F::ONE;
            }
        }
        // BEAK-INSERT-END
""",
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
    c = c.replace("#[allow(unused_imports)]\nuse fuzzer_utils;\n\n", "")
    c = c.replace("#[allow(unused_imports)]\nuse fuzzer_utils;\n", "")
    try:
        c = _insert_before(
            c,
            anchor="        RowMajorMatrix::new(rows, NUM_BITWISE_OP_LOOKUP_COLS)",
            guard="// BEAK-INSERT: guard.336f.bitwise.lookup.o1.shadow_mult",
            insert=r"""
        // BEAK-INSERT: guard.336f.bitwise.lookup.o1.shadow_mult
        // Witness-only shadow multiplicity mutation for audit-o1.
        // This intentionally mutates *prove-side* lookup multiplicity while keeping
        // runtime behavior unchanged.
        if let Some(beak_variant) = std::env::var("BEAK_OPENVM_WITNESS_INJECT_KIND")
            .ok()
            .and_then(|kind| {
                kind.strip_prefix("openvm.semantic.lookup.xor_multiplicity_consistency::")
                    .map(str::to_string)
                    .or_else(|| {
                        (kind == "openvm.semantic.lookup.xor_multiplicity_consistency")
                            .then(String::new)
                    })
            })
        {
            // BabyBear prime: 2^31 - 2^27 + 1 = 2013265921.
            const BEAK_BABYBEAR_P: u32 = 2_013_265_921;
            const BEAK_BABYBEAR_P_PLUS_1: u32 = BEAK_BABYBEAR_P + 1;
            const BEAK_BABYBEAR_2P_PLUS_1: u32 = 2 * BEAK_BABYBEAR_P + 1;
            let mut mode = "p_plus_one";
            let mut rank: usize = 0;
            for part in beak_variant.split(',') {
                if let Some((key, value)) = part.split_once('=') {
                    match key {
                        "mode" => mode = value,
                        "rank" => rank = value.parse::<usize>().unwrap_or(0),
                        _ => {}
                    }
                }
            }
            let inject_mult = match mode {
                "double_modulus_mask" => BEAK_BABYBEAR_2P_PLUS_1,
                "p_plus_mask" | "p_plus_one" => BEAK_BABYBEAR_P_PLUS_1,
                _ => BEAK_BABYBEAR_P_PLUS_1,
            };
            let mut injected = false;
            let mut seen_nonzero = 0usize;
            for row in rows.chunks_mut(NUM_BITWISE_OP_LOOKUP_COLS) {
                let cols: &mut BitwiseOperationLookupCols<F> = row.borrow_mut();
                if cols.mult_xor != F::ZERO {
                    if seen_nonzero != rank {
                        seen_nonzero += 1;
                        continue;
                    }
                    cols.mult_xor = F::from_canonical_u32(inject_mult);
                    injected = true;
                    eprintln!(
                        "[beak-witness-inject] kind=openvm.semantic.lookup.xor_multiplicity_consistency mode=shadow_lookup_multiplicity variant={}",
                        beak_variant
                    );
                    break;
                }
            }
            if !injected {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.lookup.xor_multiplicity_consistency mode=shadow_lookup_multiplicity variant={} no_ranked_nonzero_xor_row",
                    beak_variant
                );
            }
        }
        // BEAK-INSERT-END
""",
        )
    except RuntimeError:
        return
    path.write_text(c)


def _patch_f038_volatile_witness_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "crates"
        / "vm"
        / "src"
        / "system"
        / "memory"
        / "volatile"
        / "mod.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = r"""                row.addr_space = Val::<SC>::from_canonical_u32(*addr_space);
                row.pointer = Val::<SC>::from_canonical_u32(*ptr);
                row.initial_data = Val::<SC>::ZERO;
"""
    new = r"""                row.addr_space = Val::<SC>::from_canonical_u32(*addr_space);
                row.pointer = Val::<SC>::from_canonical_u32(*ptr);
                row.initial_data = Val::<SC>::ZERO;

                // BEAK-INSERT: guard.f038.volatile.o25
                if i == memory_len - 1
                    && fuzzer_utils::should_inject_witness("openvm.semantic.memory.volatile_boundary_range", i as u64)
                {
                    eprintln!(
                        "[beak-witness-inject] kind=openvm.semantic.memory.volatile_boundary_range step={} old_as={} old_ptr={}",
                        i,
                        *addr_space,
                        *ptr
                    );
                    // Forge a high canonical address tuple on the boundary row.
                    row.addr_space = Val::<SC>::from_canonical_u32(1 << 29);
                    row.pointer = Val::<SC>::from_canonical_u32(1 << 29);
                    // Emit explicit marker so injected-phase trace observes volatile boundary mutation.
                    fuzzer_utils::emit_memory_interaction(
                        "send",
                        Some("witness_inject_o25"),
                        1 << 29,
                        1 << 29,
                        vec![0],
                        0,
                    );
                }
                // BEAK-INSERT-END
"""
    if "// BEAK-INSERT: guard.f038.volatile.o25" not in c and old in c:
        c = c.replace(old, new, 1)
    if 'Some("witness_inject_o25")' not in c and "row.pointer = Val::<SC>::from_canonical_u32(1 << 29);" in c:
        c = c.replace(
            "                    row.pointer = Val::<SC>::from_canonical_u32(1 << 29);\n",
            """                    row.pointer = Val::<SC>::from_canonical_u32(1 << 29);
                    // Emit explicit marker so injected-phase trace observes volatile boundary mutation.
                    fuzzer_utils::emit_memory_interaction(
                        "send",
                        Some("witness_inject_o25"),
                        1 << 29,
                        1 << 29,
                        vec![0],
                        0,
                    );
""",
            1,
        )
    path.write_text(c)


def _patch_f038_volatile_boundary_collection_and_remap(openvm_install_path: Path) -> None:
    kind = "openvm.semantic.memory.volatile_boundary_range"

    adapter = openvm_install_path / "crates" / "vm" / "src" / "system" / "memory" / "adapter" / "mod.rs"
    if adapter.exists():
        _ensure_use_fuzzer_utils(adapter)
        c = adapter.read_text()
        if "pub fn beak_remap_volatile_boundary_records" not in c:
            c = c.replace(
                r"""    fn create_access_adapter_chip<const N: usize>(
        range_checker: SharedVariableRangeCheckerChip,
        memory_bus: MemoryBus,
        clk_max_bits: usize,
        max_access_adapter_n: usize,
    ) -> Option<GenericAccessAdapterChip<F>> {
        if N <= max_access_adapter_n {
            Some(GenericAccessAdapterChip::new::<N>(
                range_checker,
                memory_bus,
                clk_max_bits,
            ))
        } else {
            None
        }
    }
}
""",
                r"""    fn create_access_adapter_chip<const N: usize>(
        range_checker: SharedVariableRangeCheckerChip,
        memory_bus: MemoryBus,
        clk_max_bits: usize,
        max_access_adapter_n: usize,
    ) -> Option<GenericAccessAdapterChip<F>> {
        if N <= max_access_adapter_n {
            Some(GenericAccessAdapterChip::new::<N>(
                range_checker,
                memory_bus,
                clk_max_bits,
            ))
        } else {
            None
        }
    }
}

impl<F: PrimeField32> AccessAdapterInventory<F> {
    pub fn beak_remap_volatile_boundary_records(
        &mut self,
        remap: fuzzer_utils::VolatileBoundaryRemap,
    ) {
        for chip in &mut self.chips {
            chip.beak_remap_volatile_boundary_records(remap);
        }
    }
}
""",
                1,
            )
            c = c.replace(
                r"""    #[cfg(test)]
    fn records(&self) -> &[AccessAdapterRecord<F>] {
        match &self {
            GenericAccessAdapterChip::N2(chip) => &chip.records,
            GenericAccessAdapterChip::N4(chip) => &chip.records,
            GenericAccessAdapterChip::N8(chip) => &chip.records,
            GenericAccessAdapterChip::N16(chip) => &chip.records,
            GenericAccessAdapterChip::N32(chip) => &chip.records,
            GenericAccessAdapterChip::N64(chip) => &chip.records,
        }
    }
}
pub struct AccessAdapterChip<F, const N: usize> {
""",
                r"""    #[cfg(test)]
    fn records(&self) -> &[AccessAdapterRecord<F>] {
        match &self {
            GenericAccessAdapterChip::N2(chip) => &chip.records,
            GenericAccessAdapterChip::N4(chip) => &chip.records,
            GenericAccessAdapterChip::N8(chip) => &chip.records,
            GenericAccessAdapterChip::N16(chip) => &chip.records,
            GenericAccessAdapterChip::N32(chip) => &chip.records,
            GenericAccessAdapterChip::N64(chip) => &chip.records,
        }
    }
}

impl<F: PrimeField32> GenericAccessAdapterChip<F> {
    fn beak_remap_volatile_boundary_records(
        &mut self,
        remap: fuzzer_utils::VolatileBoundaryRemap,
    ) {
        match self {
            GenericAccessAdapterChip::N2(chip) => {
                chip.beak_remap_volatile_boundary_records(remap)
            }
            GenericAccessAdapterChip::N4(chip) => {
                chip.beak_remap_volatile_boundary_records(remap)
            }
            GenericAccessAdapterChip::N8(chip) => {
                chip.beak_remap_volatile_boundary_records(remap)
            }
            GenericAccessAdapterChip::N16(chip) => {
                chip.beak_remap_volatile_boundary_records(remap)
            }
            GenericAccessAdapterChip::N32(chip) => {
                chip.beak_remap_volatile_boundary_records(remap)
            }
            GenericAccessAdapterChip::N64(chip) => {
                chip.beak_remap_volatile_boundary_records(remap)
            }
        }
    }
}
pub struct AccessAdapterChip<F, const N: usize> {
""",
                1,
            )
            c = c.replace(
                r"""impl<F, const N: usize> AccessAdapterChip<F, N> {
    pub fn new(
        range_checker: SharedVariableRangeCheckerChip,
        memory_bus: MemoryBus,
        clk_max_bits: usize,
    ) -> Self {
        let lt_air = IsLtSubAir::new(range_checker.bus(), clk_max_bits);
        Self {
            air: AccessAdapterAir::<N> { memory_bus, lt_air },
            range_checker,
            records: vec![],
            overridden_height: None,
        }
    }
}
""",
                r"""impl<F, const N: usize> AccessAdapterChip<F, N> {
    pub fn new(
        range_checker: SharedVariableRangeCheckerChip,
        memory_bus: MemoryBus,
        clk_max_bits: usize,
    ) -> Self {
        let lt_air = IsLtSubAir::new(range_checker.bus(), clk_max_bits);
        Self {
            air: AccessAdapterAir::<N> { memory_bus, lt_air },
            range_checker,
            records: vec![],
            overridden_height: None,
        }
    }
}

impl<F: PrimeField32, const N: usize> AccessAdapterChip<F, N> {
    fn beak_remap_volatile_boundary_records(
        &mut self,
        remap: fuzzer_utils::VolatileBoundaryRemap,
    ) {
        for record in &mut self.records {
            let address_space = record.address_space.as_canonical_u32();
            let start_index = record.start_index.as_canonical_u32();
            if let Some((new_address_space, new_start_index)) =
                remap.map(address_space, start_index)
            {
                record.address_space = F::from_canonical_u32(new_address_space);
                record.start_index = F::from_canonical_u32(new_start_index);
            }
        }
    }
}
""",
                1,
            )
        adapter.write_text(c)

    offline = openvm_install_path / "crates" / "vm" / "src" / "system" / "memory" / "offline.rs"
    if offline.exists():
        _ensure_use_fuzzer_utils(offline)
        c = offline.read_text()
        if "beak_remap_volatile_boundary_records" not in c:
            c = c.replace(
                r"""    pub fn record_by_id(&self, id: RecordId) -> &MemoryRecord<F> {
        self.log[id.0].as_ref().unwrap()
    }

    pub fn finalize<const N: usize>(
""",
                r"""    pub fn record_by_id(&self, id: RecordId) -> &MemoryRecord<F> {
        self.log[id.0].as_ref().unwrap()
    }

    pub fn beak_remap_volatile_boundary_records(
        &mut self,
        remap: fuzzer_utils::VolatileBoundaryRemap,
    ) {
        for record in self.log.iter_mut().flatten() {
            let address_space = record.address_space.as_canonical_u32();
            let pointer = record.pointer.as_canonical_u32();
            if let Some((new_address_space, new_pointer)) = remap.map(address_space, pointer) {
                record.address_space = F::from_canonical_u32(new_address_space);
                record.pointer = F::from_canonical_u32(new_pointer);
            }
        }
    }

    pub fn finalize<const N: usize>(
""",
                1,
            )
        offline.write_text(c)

    controller = (
        openvm_install_path
        / "crates"
        / "vm"
        / "src"
        / "system"
        / "memory"
        / "controller"
        / "mod.rs"
    )
    if controller.exists():
        _ensure_use_fuzzer_utils(controller)
        c = controller.read_text()
        old = r"""            MemoryInterface::Volatile { boundary_chip } => {
                let final_memory = offline_memory.finalize::<1>(&mut self.access_adapters);
                boundary_chip.finalize(final_memory);
                self.final_state = Some(FinalState::Volatile(VolatileFinalState::default()));
            }
"""
        new = rf"""            MemoryInterface::Volatile {{ boundary_chip }} => {{
                let mut final_memory = offline_memory.finalize::<1>(&mut self.access_adapters);
                if let Some(remap) = fuzzer_utils::should_apply_volatile_boundary_remap(
                    "{kind}",
                ) {{
                    eprintln!(
                        "[beak-witness-inject] kind={kind} step={{}} site=volatile_memory_finalize mode=remap_boundary_cell old_as={{}} old_base={{}} width={{}} new_as={{}} new_base={{}}",
                        remap.row_idx,
                        remap.address_space,
                        remap.base_pointer,
                        remap.width,
                        remap.forged_address_space,
                        remap.forged_base_pointer
                    );
                    offline_memory.beak_remap_volatile_boundary_records(remap);
                    self.access_adapters.beak_remap_volatile_boundary_records(remap);
                    final_memory = final_memory
                        .into_iter()
                        .map(|((address_space, pointer), values)| {{
                            let key = remap
                                .map(address_space, pointer)
                                .unwrap_or((address_space, pointer));
                            (key, values)
                        }})
                        .collect();
                }}
                boundary_chip.finalize(final_memory);
                self.final_state = Some(FinalState::Volatile(VolatileFinalState::default()));
            }}
"""
        if "site=volatile_memory_finalize mode=remap_boundary_cell" not in c and old in c:
            c = c.replace(old, new, 1)
        controller.write_text(c)

    program = openvm_install_path / "crates" / "vm" / "src" / "system" / "program" / "trace.rs"
    if program.exists():
        _ensure_use_fuzzer_utils(program)
        c = program.read_text()
        marker = "// BEAK-INSERT: guard.f038.program_trace.volatile_boundary_remap"
        anchor = "            // BEAK-INSERT: guard.f038.program_trace.mem_as_pre_access\n"
        insert = rf"""            // BEAK-INSERT: guard.f038.program_trace.volatile_boundary_remap
            if let Some(remap) = fuzzer_utils::active_volatile_boundary_remap(
                "{kind}",
            ) {{
                let maybe_a = remap.map(
                    instruction.d.as_canonical_u64() as u32,
                    instruction.a.as_canonical_u64() as u32,
                );
                if let Some((new_as, new_ptr)) = maybe_a {{
                    row.d = F::from_canonical_u32(new_as);
                    row.a = F::from_canonical_u32(new_ptr);
                }}
                let maybe_b = remap.map(
                    instruction.d.as_canonical_u64() as u32,
                    instruction.b.as_canonical_u64() as u32,
                );
                if let Some((new_as, new_ptr)) = maybe_b {{
                    row.d = F::from_canonical_u32(new_as);
                    row.b = F::from_canonical_u32(new_ptr);
                }}
                let maybe_c = remap.map(
                    instruction.e.as_canonical_u64() as u32,
                    instruction.c.as_canonical_u64() as u32,
                );
                if let Some((new_as, new_ptr)) = maybe_c {{
                    row.e = F::from_canonical_u32(new_as);
                    row.c = F::from_canonical_u32(new_ptr);
                }}
            }}
            // BEAK-INSERT-END

"""
        if marker not in c and anchor in c:
            c = c.replace(anchor, insert + anchor, 1)
        program.write_text(c)

    volatile = openvm_install_path / "crates" / "vm" / "src" / "system" / "memory" / "volatile" / "mod.rs"
    if volatile.exists():
        _ensure_use_fuzzer_utils(volatile)
        c = volatile.read_text()
        if "active_volatile_boundary_remap" not in c:
            c = c.replace(
                f"""                    && fuzzer_utils::should_inject_witness("{kind}", i as u64)
                {{
""",
                f"""                    && fuzzer_utils::should_inject_witness("{kind}", i as u64)
                    && fuzzer_utils::active_volatile_boundary_remap("{kind}").is_none()
                {{
""",
                1,
            )
        if "emit_volatile_boundary(" not in c:
            c = c.replace(
                r"""                row.final_data = data;
                row.final_timestamp = Val::<SC>::from_canonical_u32(timestamped_values.timestamp);
                row.is_valid = Val::<SC>::ONE;

                // If next.is_valid == 1:
""",
                r"""                row.final_data = data;
                row.final_timestamp = Val::<SC>::from_canonical_u32(timestamped_values.timestamp);
                row.is_valid = Val::<SC>::ONE;
                fuzzer_utils::emit_volatile_boundary(
                    i as u64,
                    row.addr_space.as_canonical_u32(),
                    row.pointer.as_canonical_u32(),
                    true,
                );

                // If next.is_valid == 1:
""",
                1,
            )
        volatile.write_text(c)


def _patch_f038_loadstore_immediate_sign_witness_injection(openvm_install_path: Path) -> None:
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
    old = r"""        let rs1_val = compose(rs1_record.1);
        let imm = c.as_canonical_u32();
        let imm_sign = g.as_canonical_u32();
        let beak_witness_step = fuzzer_utils::next_witness_step();
        let imm_extended = imm + imm_sign * 0xffff0000;

        let ptr_val = rs1_val.wrapping_add(imm_extended);
"""
    new = r"""        let rs1_val = compose(rs1_record.1);
        let imm = c.as_canonical_u32();
        let imm_sign = g.as_canonical_u32();
        let beak_witness_step = fuzzer_utils::next_witness_step();

        // BEAK-INSERT: guard.f038.loadstore.adapter.immediate_sign
        let mut beak_imm_sign = imm_sign;
        let beak_sign_active = fuzzer_utils::matching_injection_kind(
            "openvm.semantic.memory.immediate_sign_consistency",
            beak_witness_step,
        )
        .is_some();
        if beak_sign_active {
            let candidate_sign = if imm_sign == 1 { 0 } else { 1 };
            let candidate_ext = imm + candidate_sign * 0xffff0000;
            let candidate_ptr = rs1_val.wrapping_add(candidate_ext);
            if candidate_ptr < (1 << self.air.pointer_max_bits)
                && fuzzer_utils::should_inject_witness(
                    "openvm.semantic.memory.immediate_sign_consistency",
                    beak_witness_step,
                )
            {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.memory.immediate_sign_consistency step={} imm={} orig_sign={} injected_sign={} orig_rs1={} injected_ptr={}",
                    beak_witness_step,
                    imm,
                    imm_sign,
                    candidate_sign,
                    rs1_val,
                    candidate_ptr
                );
                beak_imm_sign = candidate_sign;
            } else {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.memory.immediate_sign_consistency step={} imm={} skip_out_of_range orig_sign={} candidate_sign={} orig_rs1={} candidate_ptr={}",
                    beak_witness_step,
                    imm,
                    imm_sign,
                    candidate_sign,
                    rs1_val,
                    candidate_ptr
                );
            }
        }
        // BEAK-INSERT-END
        let imm_extended = imm + beak_imm_sign * 0xffff0000;

        let ptr_val = rs1_val.wrapping_add(imm_extended);
"""
    if "// BEAK-INSERT: guard.f038.loadstore.adapter.immediate_sign" not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_f038_memory_finalization_instrumentation(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "vm" / "src" / "system" / "memory" / "controller" / "mod.rs"
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = r"""                let final_partition = offline_memory.finalize::<CHUNK>(&mut self.access_adapters);

                boundary_chip.finalize(initial_memory, &final_partition, hasher);
                let final_memory_values = final_partition
"""
    new = r"""                let mut final_partition = offline_memory.finalize::<CHUNK>(&mut self.access_adapters);

                // BEAK-INSERT: guard.f038.memory.lifecycle.finalization
                let beak_final_cells: Vec<_> = final_partition
                    .iter()
                    .map(|(&(address_space, chunk_label), values)| {
                        let pointer = chunk_label * CHUNK as u32;
                        let final_values = values
                            .values
                            .iter()
                            .map(|value| value.as_canonical_u32())
                            .collect::<Vec<_>>();
                        let initial_values = (0..CHUNK as u32)
                            .map(|offset| {
                                initial_memory
                                    .get(&(address_space, pointer + offset))
                                    .copied()
                                    .unwrap_or(F::ZERO)
                                    .as_canonical_u32()
                            })
                            .collect::<Vec<_>>();
                        let was_initial = initial_values.iter().any(|value| *value != 0);
                        let changed_from_initial = final_values != initial_values;
                        (
                            (address_space, chunk_label),
                            pointer,
                            values.timestamp,
                            final_values,
                            was_initial,
                            changed_from_initial,
                        )
                    })
                    .collect();
                for (
                    beak_final_idx,
                    (
                        (address_space, chunk_label),
                        pointer,
                        timestamp,
                        final_values,
                        was_initial,
                        changed_from_initial,
                    ),
                ) in beak_final_cells.into_iter().enumerate()
                {
                    let beak_final_idx = beak_final_idx as u64;
                    fuzzer_utils::emit_memory_finalization(
                        beak_final_idx,
                        address_space,
                        pointer,
                        timestamp,
                        final_values,
                        was_initial,
                        changed_from_initial,
                    );
                    if fuzzer_utils::should_inject_witness(
                        "openvm.semantic.memory.finalization_consistency",
                        beak_final_idx,
                    ) {
                        eprintln!(
                            "[beak-witness-inject] kind=openvm.semantic.memory.finalization_consistency step={} address_space={} pointer={} timestamp={}",
                            beak_final_idx,
                            address_space,
                            pointer,
                            timestamp
                        );
                        if let Some(values) =
                            final_partition.get_mut(&(address_space, chunk_label))
                        {
                            values.values[0] += F::from_canonical_u32(1);
                        }
                    }
                }
                // BEAK-INSERT-END

                boundary_chip.finalize(initial_memory, &final_partition, hasher);
                let final_memory_values = final_partition
"""
    if "// BEAK-INSERT: guard.f038.memory.lifecycle.finalization" not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_f038_connector_witness_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "crates"
        / "vm"
        / "src"
        / "system"
        / "connector"
        / "mod.rs"
    )
    if not path.exists():
        return
    c = path.read_text()
    old_partial = r"""    pub fn begin(&mut self, state: ExecutionState<u32>) {
        let mut beak_ts = state.timestamp;
        let beak_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.time.boundary_origin_consistency", beak_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.time.boundary_origin_consistency step={} from_ts={}",
                beak_step,
                state.timestamp
            );
            // Shift initial timestamp away from zero (canonical BabyBear element).
            beak_ts = 1 << 29;
        }
        self.boundary_states[0] = Some(ConnectorCols {
            pc: state.pc,
            timestamp: beak_ts,
            is_terminate: 0,
            exit_code: 0,
        });
    }
"""
    clean = r"""    pub fn begin(&mut self, state: ExecutionState<u32>) {
        self.boundary_states[0] = Some(ConnectorCols {
            pc: state.pc,
            timestamp: state.timestamp,
            is_terminate: 0,
            exit_code: 0,
        });
    }
"""
    if old_partial in c:
        c = c.replace(old_partial, clean, 1)
    path.write_text(c)


def _patch_f038_time_origin_shift_witness_injection(openvm_install_path: Path) -> None:
    kind = "openvm.semantic.time.boundary_origin_consistency"

    online = openvm_install_path / "crates" / "vm" / "src" / "system" / "memory" / "online.rs"
    if online.exists():
        _ensure_use_fuzzer_utils(online)
        c = online.read_text()
        old_new = r"""    pub fn new(mem_config: &MemoryConfig) -> Self {
        Self {
            data: AddressMap::from_mem_config(mem_config),
            timestamp: INITIAL_TIMESTAMP + 1,
            log: Vec::with_capacity(mem_config.access_capacity),
        }
    }
"""
        new_new = rf"""    pub fn new(mem_config: &MemoryConfig) -> Self {{
        let beak_time_origin_delta =
            fuzzer_utils::should_shift_time_origin_at("{kind}", 0).unwrap_or(0);
        if beak_time_origin_delta != 0 {{
            eprintln!(
                "[beak-witness-inject] kind={kind} step=0 site=online_memory_new mode=shift_origin delta={{}}",
                beak_time_origin_delta
            );
        }}
        let beak_initial_timestamp = INITIAL_TIMESTAMP.wrapping_add(beak_time_origin_delta);
        Self {{
            data: AddressMap::from_mem_config(mem_config),
            timestamp: beak_initial_timestamp.wrapping_add(1),
            log: Vec::with_capacity(mem_config.access_capacity),
        }}
    }}
"""
        old_from_image = r"""    pub fn from_image(image: MemoryImage<F>, access_capacity: usize) -> Self {
        Self {
            data: image,
            timestamp: INITIAL_TIMESTAMP + 1,
            log: Vec::with_capacity(access_capacity),
        }
    }
"""
        new_from_image = rf"""    pub fn from_image(image: MemoryImage<F>, access_capacity: usize) -> Self {{
        let beak_time_origin_delta =
            fuzzer_utils::should_shift_time_origin_at("{kind}", 0).unwrap_or(0);
        if beak_time_origin_delta != 0 {{
            eprintln!(
                "[beak-witness-inject] kind={kind} step=0 site=online_memory_from_image mode=shift_origin delta={{}}",
                beak_time_origin_delta
            );
        }}
        let beak_initial_timestamp = INITIAL_TIMESTAMP.wrapping_add(beak_time_origin_delta);
        Self {{
            data: image,
            timestamp: beak_initial_timestamp.wrapping_add(1),
            log: Vec::with_capacity(access_capacity),
        }}
    }}
"""
        if "site=online_memory_new mode=shift_origin" not in c and old_new in c:
            c = c.replace(old_new, new_new, 1)
        if "site=online_memory_from_image mode=shift_origin" not in c and old_from_image in c:
            c = c.replace(old_from_image, new_from_image, 1)
        online.write_text(c)

    offline = openvm_install_path / "crates" / "vm" / "src" / "system" / "memory" / "offline.rs"
    if offline.exists():
        _ensure_use_fuzzer_utils(offline)
        c = offline.read_text()
        old_block_ts = r"""        BlockData {
            pointer: aligned_pointer,
            size: initial_block_size,
            timestamp: INITIAL_TIMESTAMP,
        }
"""
        new_block_ts = rf"""        let beak_initial_timestamp = INITIAL_TIMESTAMP.wrapping_add(
            fuzzer_utils::active_time_origin_shift_delta_at("{kind}", 0).unwrap_or(0),
        );
        BlockData {{
            pointer: aligned_pointer,
            size: initial_block_size,
            timestamp: beak_initial_timestamp,
        }}
"""
        old_offline_new = r"""    pub fn new(
        initial_memory: MemoryImage<F>,
        initial_block_size: usize,
        memory_bus: MemoryBus,
        range_checker: SharedVariableRangeCheckerChip,
        config: MemoryConfig,
    ) -> Self {
        Self {
            block_data: BlockMap::from_mem_config(&config, initial_block_size),
            data: Self::memory_image_to_paged_vec(initial_memory, config),
            as_offset: config.as_offset,
            timestamp: INITIAL_TIMESTAMP + 1,
            timestamp_max_bits: config.clk_max_bits,
            memory_bus,
            range_checker,
            log: vec![],
        }
    }
"""
        new_offline_new = rf"""    pub fn new(
        initial_memory: MemoryImage<F>,
        initial_block_size: usize,
        memory_bus: MemoryBus,
        range_checker: SharedVariableRangeCheckerChip,
        config: MemoryConfig,
    ) -> Self {{
        let beak_time_origin_delta =
            fuzzer_utils::should_shift_time_origin_at("{kind}", 0).unwrap_or(0);
        if beak_time_origin_delta != 0 {{
            eprintln!(
                "[beak-witness-inject] kind={kind} step=0 site=offline_memory_new mode=shift_origin delta={{}}",
                beak_time_origin_delta
            );
        }}
        let beak_initial_timestamp = INITIAL_TIMESTAMP.wrapping_add(beak_time_origin_delta);
        Self {{
            block_data: BlockMap::from_mem_config(&config, initial_block_size),
            data: Self::memory_image_to_paged_vec(initial_memory, config),
            as_offset: config.as_offset,
            timestamp: beak_initial_timestamp.wrapping_add(1),
            timestamp_max_bits: config.clk_max_bits,
            memory_bus,
            range_checker,
            log: vec![],
        }}
    }}
"""
        old_set_initial = r"""    pub fn set_initial_memory(&mut self, initial_memory: MemoryImage<F>, config: MemoryConfig) {
        fuzzer_utils::fuzzer_assert_eq!(self.timestamp, INITIAL_TIMESTAMP + 1);
        self.as_offset = config.as_offset;
        self.data = Self::memory_image_to_paged_vec(initial_memory, config);
    }
"""
        new_set_initial = rf"""    pub fn set_initial_memory(&mut self, initial_memory: MemoryImage<F>, config: MemoryConfig) {{
        let beak_expected_timestamp = INITIAL_TIMESTAMP
            .wrapping_add(fuzzer_utils::active_time_origin_shift_delta_at("{kind}", 0).unwrap_or(0))
            .wrapping_add(1);
        fuzzer_utils::fuzzer_assert_eq!(self.timestamp, beak_expected_timestamp);
        self.as_offset = config.as_offset;
        self.data = Self::memory_image_to_paged_vec(initial_memory, config);
    }}
"""
        if "active_time_origin_shift_delta_at" not in c and old_block_ts in c:
            c = c.replace(old_block_ts, new_block_ts, 1)
        if "site=offline_memory_new mode=shift_origin" not in c and old_offline_new in c:
            c = c.replace(old_offline_new, new_offline_new, 1)
        if "beak_expected_timestamp" not in c and old_set_initial in c:
            c = c.replace(old_set_initial, new_set_initial, 1)
        offline.write_text(c)

    controller = (
        openvm_install_path
        / "crates"
        / "vm"
        / "src"
        / "system"
        / "memory"
        / "controller"
        / "mod.rs"
    )
    if controller.exists():
        _ensure_use_fuzzer_utils(controller)
        c = controller.read_text()
        old = r"""    pub fn set_initial_memory(&mut self, memory: MemoryImage<F>) {
        if self.timestamp() > INITIAL_TIMESTAMP + 1 {
            panic!("Cannot set initial memory after first timestamp");
        }
"""
        new = rf"""    pub fn set_initial_memory(&mut self, memory: MemoryImage<F>) {{
        let beak_expected_initial_memory_timestamp = INITIAL_TIMESTAMP
            .wrapping_add(fuzzer_utils::active_time_origin_shift_delta_at("{kind}", 0).unwrap_or(0))
            .wrapping_add(1);
        if self.timestamp() > beak_expected_initial_memory_timestamp {{
            panic!("Cannot set initial memory after first timestamp");
        }}
"""
        if "beak_expected_initial_memory_timestamp" not in c and old in c:
            c = c.replace(old, new, 1)
        controller.write_text(c)

    persistent = (
        openvm_install_path
        / "crates"
        / "vm"
        / "src"
        / "system"
        / "memory"
        / "persistent.rs"
    )
    if persistent.exists():
        _ensure_use_fuzzer_utils(persistent)
        c = persistent.read_text()
        old = r"""            rows.par_chunks_mut(2 * width)
                .zip(touched_labels.into_par_iter())
                .for_each(|(row, touched_label)| {
"""
        new = rf"""            let beak_initial_timestamp = INITIAL_TIMESTAMP.wrapping_add(
                fuzzer_utils::active_time_origin_shift_delta_at("{kind}", 0).unwrap_or(0),
            );

            rows.par_chunks_mut(2 * width)
                .zip(touched_labels.into_par_iter())
                .for_each(|(row, touched_label)| {{
"""
        if "let beak_initial_timestamp = INITIAL_TIMESTAMP.wrapping_add" not in c and old in c:
            c = c.replace(old, new, 1)
        c = c.replace(
            "                        timestamp: Val::<SC>::from_canonical_u32(INITIAL_TIMESTAMP),",
            "                        timestamp: Val::<SC>::from_canonical_u32(beak_initial_timestamp),",
            1,
        )
        persistent.write_text(c)


def _patch_f038_program_trace_mem_as_witness_injection(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "vm" / "src" / "system" / "program" / "trace.rs"
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = r"""    rows.par_chunks_mut(width)
        .zip(instructions)
        .for_each(|(row, (pc, instruction))| {
            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();
            *row = ProgramExecutionCols {
                pc: F::from_canonical_u32(pc),
                opcode: instruction.opcode.to_field(),
                a: instruction.a,
                b: instruction.b,
                c: instruction.c,
                d: instruction.d,
                e: instruction.e,
                f: instruction.f,
                g: instruction.g,
            };
        });
"""
    new = r"""    rows.par_chunks_mut(width)
        .zip(instructions.into_par_iter().enumerate())
        .for_each(|(row, (i, (pc, instruction)))| {
            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();
            *row = ProgramExecutionCols {
                pc: F::from_canonical_u32(pc),
                opcode: instruction.opcode.to_field(),
                a: instruction.a,
                b: instruction.b,
                c: instruction.c,
                d: instruction.d,
                e: instruction.e,
                f: instruction.f,
                g: instruction.g,
            };

            // BEAK-INSERT: guard.f038.program_trace.mem_as_pre_access
            let beak_program_step = i as u64;
            let old_mem_as = instruction.e.as_canonical_u64();
            let beak_mem_as_enabled = old_mem_as != 0
                && fuzzer_utils::witness_injection_enabled_at(
                    "openvm.semantic.memory.address_space_consistency",
                    beak_program_step,
                );
            let beak_should_inject = beak_mem_as_enabled
                && fuzzer_utils::should_inject_witness(
                    "openvm.semantic.memory.address_space_consistency",
                    beak_program_step,
                );
            if beak_should_inject {
                let beak_variant =
                    fuzzer_utils::active_witness_variant("openvm.semantic.memory.address_space_consistency");
                let spec = beak_variant
                    .as_deref()
                    .unwrap_or("mode=bus_mem_as_other");
                let mut mode = "bus_mem_as_other";
                for part in spec.split(',') {
                    if let Some((spec_key, spec_value)) = part.split_once('=') {
                        if spec_key.trim() == "mode" {
                            mode = spec_value.trim();
                        }
                    }
                }
                let selected_mem_as = match mode {
                    "bus_mem_as_reg" => 1,
                    "bus_mem_as_zero" => 0,
                    "bus_mem_as_other" => {
                        if old_mem_as != 3 {
                            3
                        } else {
                            4
                        }
                    }
                    _ => old_mem_as as u32,
                };
                if u64::from(selected_mem_as) != old_mem_as {
                    eprintln!(
                        "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} site=program_trace mode={} old_mem_as={} new_mem_as={} pc={}",
                        beak_program_step,
                        mode,
                        old_mem_as,
                        selected_mem_as,
                        pc
                    );
                    row.e = F::from_canonical_u32(selected_mem_as);
                } else {
                    eprintln!(
                        "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} site=program_trace mode={} skip_noop old_mem_as={} pc={}",
                        beak_program_step,
                        mode,
                        old_mem_as,
                        pc
                    );
                }
            }
            // BEAK-INSERT-END
        });
"""
    if "// BEAK-INSERT: guard.f038.program_trace.mem_as_pre_access" not in c and old in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_336f_connector_witness_injection(openvm_install_path: Path) -> None:
    path = (
        openvm_install_path
        / "crates"
        / "vm"
        / "src"
        / "system"
        / "connector"
        / "mod.rs"
    )
    if not path.exists():
        return
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()
    old = r"""    pub fn begin(&mut self, state: ExecutionState<u32>) {
        self.boundary_states[0] = Some(ConnectorCols {
            pc: state.pc,
            timestamp: state.timestamp,
            is_terminate: 0,
            exit_code: 0,
        });
    }
"""
    new = r"""    pub fn begin(&mut self, state: ExecutionState<u32>) {
        let beak_step = fuzzer_utils::next_witness_step();
        let mut beak_pc = state.pc;
        let mut beak_ts = state.timestamp;
        if fuzzer_utils::should_inject_witness("openvm.semantic.time.boundary_origin_consistency", beak_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.time.boundary_origin_consistency step={} from_ts={}",
                beak_step,
                state.timestamp
            );
            // Shift initial timestamp away from zero (canonical BabyBear element).
            beak_ts = 1 << 29;
        }
        if fuzzer_utils::should_inject_witness("openvm.semantic.control.entrypoint_binding", beak_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.control.entrypoint_binding step={} from_pc={}",
                beak_step,
                state.pc
            );
            beak_pc = state.pc.wrapping_add(1);
        }
        self.boundary_states[0] = Some(ConnectorCols {
            pc: beak_pc,
            timestamp: beak_ts,
            is_terminate: 0,
            exit_code: 0,
        });
    }
"""
    if "// openvm.semantic.control.entrypoint_binding" not in c and old in c:
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
                insert=r"""

        // BEAK-INSERT: guard.336f.branch_eq.control_flow
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.exec.control_flow_binding", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.exec.control_flow_binding step={} site=branch_eq",
                beak_witness_step
            );
            row_slice.cmp_result = F::ONE - row_slice.cmp_result;
        }
        // BEAK-INSERT-END
""",
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
                insert=r"""

        // BEAK-INSERT: guard.336f.branch_lt.control_flow
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.exec.control_flow_binding", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.exec.control_flow_binding step={} site=branch_lt",
                beak_witness_step
            );
            row_slice.cmp_result = F::ONE - row_slice.cmp_result;
        }
        // BEAK-INSERT-END
""",
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
                insert=r"""

        // BEAK-INSERT: guard.336f.jal_lui.control_flow
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if record.is_jal
            && fuzzer_utils::should_inject_witness("openvm.semantic.exec.control_flow_binding", beak_witness_step)
        {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.exec.control_flow_binding step={} site=jal",
                beak_witness_step
            );
            core_cols.rd_data[0] += F::ONE;
        }
        // BEAK-INSERT-END
""",
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
                insert=r"""

        // BEAK-INSERT: guard.336f.jalr.control_flow
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.exec.control_flow_binding", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.exec.control_flow_binding step={} site=jalr",
                beak_witness_step
            );
            core_cols.rd_data[0] += F::ONE;
            core_cols.to_pc_least_sig_bit = F::ONE - core_cols.to_pc_least_sig_bit;
            core_cols.imm_sign = F::ONE - core_cols.imm_sign;
        }
        // BEAK-INSERT-END
""",
            )
            jalr.write_text(c)
        except RuntimeError:
            pass


def _patch_f038_loadstore_mem_as_witness_injection(openvm_install_path: Path) -> None:
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
        let imm_sign = g.as_canonical_u32();
        let imm_extended = imm + imm_sign * 0xffff0000;
"""
    new = r"""        let imm = c.as_canonical_u32();
        let imm_sign = g.as_canonical_u32();
        let beak_witness_step = fuzzer_utils::next_witness_step();
        let imm_extended = imm + imm_sign * 0xffff0000;
"""
    if "let beak_witness_step = fuzzer_utils::next_witness_step();" not in c and old in c:
        c = c.replace(old, new, 1)
    pre_marker = "// BEAK-INSERT: guard.f038.loadstore.adapter.mem_as_pre_access"
    if pre_marker not in c and "        let read_record = match local_opcode {\n" in c:
        c = c.replace(
            "        let read_record = match local_opcode {\n",
            r"""        // BEAK-INSERT: guard.f038.loadstore.adapter.mem_as_pre_access
        let beak_is_load = matches!(local_opcode, LOADW | LOADB | LOADH | LOADBU | LOADHU);
        let beak_is_store = matches!(local_opcode, STOREW | STOREH | STOREB);
        let mut beak_mem_as = e;
        let beak_address_space_step = beak_witness_step.saturating_add(1);
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.address_space_consistency", beak_address_space_step) {
            let beak_variant =
                fuzzer_utils::active_witness_variant("openvm.semantic.memory.address_space_consistency");
            let spec = beak_variant
                .as_deref()
                .unwrap_or("mode=bus_mem_as_other");
            let mut mode = "bus_mem_as_other";
            for part in spec.split(',') {
                if let Some((spec_key, spec_value)) = part.split_once('=') {
                    if spec_key.trim() == "mode" {
                        mode = spec_value.trim();
                    }
                }
            }
            let old_mem_as = e.as_canonical_u32();
            let selected_mem_as = match mode {
                "bus_mem_as_reg" => RV32_REGISTER_AS,
                "bus_mem_as_zero" => RV32_IMM_AS,
                "bus_mem_as_other" => {
                    if old_mem_as != 3 {
                        3
                    } else {
                        4
                    }
                }
                _ => old_mem_as,
            };
            if selected_mem_as != old_mem_as {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} site=loadstore_adapter mode={} old_mem_as={} new_mem_as={} is_load={} is_store={}",
                    beak_address_space_step,
                    mode,
                    old_mem_as,
                    selected_mem_as,
                    beak_is_load,
                    beak_is_store
                );
                beak_mem_as = F::from_canonical_u32(selected_mem_as);
            } else {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} site=loadstore_adapter mode={} skip_noop old_mem_as={} is_load={} is_store={}",
                    beak_address_space_step,
                    mode,
                    old_mem_as,
                    beak_is_load,
                    beak_is_store
                );
            }
        }
        // BEAK-INSERT-END

        let read_record = match local_opcode {
""",
            1,
        )
    if pre_marker in c:
        c = c.replace(
            "                memory.read::<RV32_REGISTER_NUM_LIMBS>(e, F::from_canonical_u32(ptr_val))\n",
            "                memory.read::<RV32_REGISTER_NUM_LIMBS>(beak_mem_as, F::from_canonical_u32(ptr_val))\n",
            1,
        )
        c = c.replace(
            "                memory.unsafe_read_cell(e, F::from_canonical_usize(ptr_val as usize + i))\n",
            "                memory.unsafe_read_cell(beak_mem_as, F::from_canonical_usize(ptr_val as usize + i))\n",
            1,
        )
        c = c.replace(
            "            e.as_canonical_u32(),\n"
            "            beak_effective_ptr,\n"
            "            beak_effective_ptr,\n"
            "            ptr_val,\n",
            "            beak_mem_as.as_canonical_u32(),\n"
            "            beak_effective_ptr,\n"
            "            beak_effective_ptr,\n"
            "            ptr_val,\n",
            1,
        )
        c = c.replace(
            "                    memory.write(e, F::from_canonical_u32(ptr & 0xfffffffc), output.writes[0])\n",
            "                    memory.write(read_record.mem_as, F::from_canonical_u32(ptr & 0xfffffffc), output.writes[0])\n",
            1,
        )
        c = c.replace(
            "            d,\n            e,\n            f: enabled,\n",
            "            d,\n            f: enabled,\n",
            1,
        )
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
                imm_sign: g,
                shift_amount,
                mem_ptr_limbs,
                mem_as: e,
            },
        ))
"""
    new2 = r"""        Ok((
            (
                [prev_data, read_record.1],
                F::from_canonical_u32(shift_amount),
            ),
            Self::ReadRecord {
                rs1_record: rs1_record.0,
                rs1_ptr: b,
                read: read_record.0,
                imm: c,
                imm_sign: g,
                shift_amount,
                mem_ptr_limbs,
                mem_as: beak_mem_as,
            },
        ))
"""
    if "mem_as: beak_mem_as," not in c and old2 in c:
        c = c.replace(old2, new2, 1)
    old_late = r"""        // BEAK-INSERT: guard.336f.loadstore.adapter.mem_as_o5
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

"""
    if pre_marker in c and old_late in c:
        c = c.replace(old_late, "", 1)
    path.write_text(c)


def _patch_witness_step_wildcard_support(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "fuzzer_utils" / "src" / "lib.rs"
    if not path.exists():
        return
    c = path.read_text()
    old = "        self.injection_enabled && self.injection_kind == kind && self.injection_step == step\n"
    new = (
        "        self.injection_enabled\n"
        "            && self.injection_kind == kind\n"
        "            && (self.injection_step == step || self.injection_step == u64::MAX)\n"
    )
    if old in c and "self.injection_step == u64::MAX" not in c:
        c = c.replace(old, new, 1)
    path.write_text(c)


def _patch_witness_variant_support(openvm_install_path: Path) -> None:
    path = openvm_install_path / "crates" / "fuzzer_utils" / "src" / "lib.rs"
    if not path.exists():
        return
    c = path.read_text()

    constants_anchor = "pub const LIMB_BITS: usize = 8;\n"
    helper_block = """
fn base_injection_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn injection_variant(kind: &str) -> Option<&str> {
    kind.split_once("::").map(|(_, variant)| variant)
}
"""
    if helper_block.strip() not in c and constants_anchor in c:
        c = c.replace(constants_anchor, constants_anchor + helper_block, 1)

    if "pub applied_witness_sites: BTreeMap<String, Vec<u64>>," not in c:
        c = c.replace(
            "    pub observed_witness_sites: BTreeMap<String, Vec<u64>>,\n",
            "    pub observed_witness_sites: BTreeMap<String, Vec<u64>>,\n"
            "    pub applied_witness_sites: BTreeMap<String, Vec<u64>>,\n",
            1,
        )

    if "applied_witness_sites: BTreeMap::new()," not in c:
        c = c.replace(
            "            observed_witness_sites: BTreeMap::new(),\n",
            "            observed_witness_sites: BTreeMap::new(),\n"
            "            applied_witness_sites: BTreeMap::new(),\n",
            1,
        )

    if "self.applied_witness_sites.clear();" not in c:
        c = c.replace(
            "        self.observed_witness_sites.clear();\n",
            "        self.observed_witness_sites.clear();\n"
            "        self.applied_witness_sites.clear();\n",
            1,
        )

    if "fn note_applied_witness_site(&mut self, kind: &str, step: u64)" not in c:
        c = c.replace(
            "    fn note_witness_site(&mut self, kind: &str, step: u64) {\n"
            "        let sites = self.observed_witness_sites.entry(kind.to_string()).or_default();\n"
            "        if sites.last().copied() != Some(step) {\n"
            "            sites.push(step);\n"
            "        }\n"
            "    }\n",
            "    fn note_witness_site(&mut self, kind: &str, step: u64) {\n"
            "        let sites = self.observed_witness_sites.entry(kind.to_string()).or_default();\n"
            "        if sites.last().copied() != Some(step) {\n"
            "            sites.push(step);\n"
            "        }\n"
            "    }\n"
            "\n"
            "    fn note_applied_witness_site(&mut self, kind: &str, step: u64) {\n"
            "        let sites = self.applied_witness_sites.entry(kind.to_string()).or_default();\n"
            "        if sites.last().copied() != Some(step) {\n"
            "            sites.push(step);\n"
            "        }\n"
            "    }\n",
            1,
        )

    if "pub fn matching_injection_kind(&self, kind: &str, step: u64) -> Option<String>" not in c:
        c = c.replace(
            "    pub fn should_inject_witness(&self, kind: &str, step: u64) -> bool {\n"
            "        self.injection_enabled && self.injection_kind == kind && self.injection_step == step\n"
            "    }\n",
            "    pub fn should_inject_witness(&self, kind: &str, step: u64) -> bool {\n"
            "        self.injection_enabled\n"
            "            && base_injection_kind(self.injection_kind.as_str()) == kind\n"
            "            && (self.injection_step == step || self.injection_step == u64::MAX)\n"
            "    }\n"
            "\n"
            "    pub fn matching_injection_kind(&self, kind: &str, step: u64) -> Option<String> {\n"
            "        self.should_inject_witness(kind, step)\n"
            "            .then(|| self.injection_kind.clone())\n"
            "    }\n"
            "\n"
            "    pub fn active_witness_variant(&self, kind: &str) -> Option<String> {\n"
            "        self.injection_enabled\n"
            "            .then(|| base_injection_kind(self.injection_kind.as_str()) == kind)\n"
            "            .filter(|matched| *matched)\n"
            "            .and_then(|_| injection_variant(self.injection_kind.as_str()))\n"
            "            .map(str::to_string)\n"
            "    }\n",
            1,
        )
    elif "pub fn take_applied_witness_sites(&mut self) -> BTreeMap<String, Vec<u64>>" not in c:
        c = c.replace(
            "    pub fn take_observed_witness_sites(&mut self) -> BTreeMap<String, Vec<u64>> {\n"
            "        std::mem::take(&mut self.observed_witness_sites)\n"
            "    }\n",
            "    pub fn take_observed_witness_sites(&mut self) -> BTreeMap<String, Vec<u64>> {\n"
            "        std::mem::take(&mut self.observed_witness_sites)\n"
            "    }\n"
            "\n"
            "    pub fn take_applied_witness_sites(&mut self) -> BTreeMap<String, Vec<u64>> {\n"
            "        std::mem::take(&mut self.applied_witness_sites)\n"
            "    }\n",
            1,
        )

    if "pub fn active_witness_variant(kind: &str) -> Option<String>" not in c:
        c = c.replace(
            "pub fn should_inject_witness(kind: &str, step: u64) -> bool {\n"
            "    let mut state = GLOBAL_STATE.lock().unwrap();\n"
            "    state.note_witness_site(kind, step);\n"
            "    state.should_inject_witness(kind, step)\n"
            "}\n",
            "pub fn should_inject_witness(kind: &str, step: u64) -> bool {\n"
            "    let mut state = GLOBAL_STATE.lock().unwrap();\n"
            "    state.note_witness_site(kind, step);\n"
            "    let should_inject = state.should_inject_witness(kind, step);\n"
            "    if should_inject {\n"
            "        state.note_applied_witness_site(kind, step);\n"
            "    }\n"
            "    should_inject\n"
            "}\n"
            "\n"
            "pub fn matching_injection_kind(kind: &str, step: u64) -> Option<String> {\n"
            "    let mut state = GLOBAL_STATE.lock().unwrap();\n"
            "    state.note_witness_site(kind, step);\n"
            "    state.matching_injection_kind(kind, step)\n"
            "}\n"
            "\n"
            "pub fn active_witness_variant(kind: &str) -> Option<String> {\n"
            "    let state = GLOBAL_STATE.lock().unwrap();\n"
            "    state.active_witness_variant(kind)\n"
            "}\n",
            1,
        )
    elif "pub fn take_applied_witness_sites() -> BTreeMap<String, Vec<u64>>" not in c:
        c = c.replace(
            "pub fn take_observed_witness_sites() -> BTreeMap<String, Vec<u64>> {\n"
            "    let mut state = GLOBAL_STATE.lock().unwrap();\n"
            "    state.take_observed_witness_sites()\n"
            "}\n",
            "pub fn take_observed_witness_sites() -> BTreeMap<String, Vec<u64>> {\n"
            "    let mut state = GLOBAL_STATE.lock().unwrap();\n"
            "    state.take_observed_witness_sites()\n"
            "}\n"
            "\n"
            "pub fn take_applied_witness_sites() -> BTreeMap<String, Vec<u64>> {\n"
            "    let mut state = GLOBAL_STATE.lock().unwrap();\n"
            "    state.take_applied_witness_sites()\n"
            "}\n",
            1,
        )

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
                insert=r"""

            // BEAK-INSERT: guard.regzero.connector.semantic_injection
            let beak_witness_step = fuzzer_utils::next_witness_step();
            if fuzzer_utils::should_inject_witness("openvm.semantic.time.boundary_origin_consistency", beak_witness_step) {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.time.boundary_origin_consistency step={} from_ts={}",
                    beak_witness_step,
                    state.timestamp
                );
                state.timestamp = state.timestamp.wrapping_add(1 << 29);
            }
            if fuzzer_utils::should_inject_witness("openvm.semantic.control.entrypoint_binding", beak_witness_step) {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.control.entrypoint_binding step={} from_pc={}",
                    beak_witness_step,
                    state.pc
                );
                state.pc = state.pc.wrapping_add(1);
            }
            // BEAK-INSERT-END
""",
            )
        except RuntimeError:
            pass
        connector.write_text(c)

    core_hooks = [
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "base_alu" / "core.rs",
            "        core_row.a = a.map(F::from_canonical_u8);\n",
            "// BEAK-INSERT: guard.regzero.base_alu.semantic_injection",
            r"""

        // BEAK-INSERT: guard.regzero.base_alu.semantic_injection
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.immediate_limb_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.alu.immediate_limb_consistency step={}",
                beak_witness_step
            );
            core_row.c[0] += F::ONE;
        }
        if local_opcode == BaseAluOpcode::SUB
            && fuzzer_utils::should_inject_witness("openvm.semantic.alu.subtraction_borrow_chain", beak_witness_step)
        {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.alu.subtraction_borrow_chain step={}",
                beak_witness_step
            );
            core_row.a[0] += F::ONE;
        }
        // BEAK-INSERT-END
""",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "shift" / "core.rs",
            "        core_row.a = a.map(F::from_canonical_u8);\n",
            "// BEAK-INSERT: guard.regzero.shift.semantic_injection",
            r"""

        // BEAK-INSERT: guard.regzero.shift.semantic_injection
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.shift_mod32", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.alu.shift_mod32 step={}",
                beak_witness_step
            );
            core_row.a[0] += F::ONE;
        }
        // BEAK-INSERT-END
""",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "less_than" / "core.rs",
            "        let mut a = [0u8; NUM_LIMBS];\n        a[0] = cmp_result as u8;\n",
            "// BEAK-INSERT: guard.regzero.less_than.semantic_injection",
            r"""

        // BEAK-INSERT: guard.regzero.less_than.semantic_injection
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.comparison_booleanity", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.alu.comparison_booleanity step={}",
                beak_witness_step
            );
            core_row.cmp_result = F::ONE - core_row.cmp_result;
        }
        if fuzzer_utils::should_inject_witness("openvm.semantic.alu.comparison_auxiliary_chain", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.alu.comparison_auxiliary_chain step={}",
                beak_witness_step
            );
            core_row.diff_marker[0] = F::ONE;
        }
        // BEAK-INSERT-END
""",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "divrem" / "core.rs",
            "        core_row.b = record.b.map(F::from_canonical_u8);\n",
            "// BEAK-INSERT: guard.regzero.divrem.semantic_injection",
            r"""

        // BEAK-INSERT: guard.regzero.divrem.semantic_injection
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.special_case_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.arithmetic.special_case_consistency step={}",
                beak_witness_step
            );
            core_row.q[0] += F::ONE;
        }
        if beak_record_c.iter().any(|limb| *limb != 0)
            && fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.division_remainder_bound", beak_witness_step)
        {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.arithmetic.division_remainder_bound step={}",
                beak_witness_step
            );
            core_row.q[0] += F::ONE;
        }
        // BEAK-INSERT-END
""",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "mul" / "core.rs",
            "        core_row.a = a.map(F::from_canonical_u8);\n",
            "// BEAK-INSERT: guard.regzero.mul.semantic_injection",
            r"""

        // BEAK-INSERT: guard.regzero.mul.semantic_injection
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.product_decomposition", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.arithmetic.product_decomposition step={} site=mul",
                beak_witness_step
            );
            core_row.a[0] += F::ONE;
        }
        // BEAK-INSERT-END
""",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "mulh" / "core.rs",
            "        core_row.a = a.map(F::from_canonical_u32);\n",
            "// BEAK-INSERT: guard.regzero.mulh.semantic_injection",
            r"""

        // BEAK-INSERT: guard.regzero.mulh.semantic_injection
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.product_decomposition", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.arithmetic.product_decomposition step={} site=mulh",
                beak_witness_step
            );
            core_row.a[0] += F::ONE;
        }
        if opcode == MulHOpcode::MULHSU
            && fuzzer_utils::should_inject_witness("openvm.semantic.arithmetic.signed_unsigned_product_correction", beak_witness_step)
        {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.arithmetic.signed_unsigned_product_correction step={}",
                beak_witness_step
            );
            core_row.b_ext += F::ONE;
        }
        // BEAK-INSERT-END
""",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "auipc" / "core.rs",
            "        core_row.rd_data = rd_data.map(F::from_canonical_u8);\n",
            "// BEAK-INSERT: guard.regzero.auipc.semantic_injection",
            r"""

        // BEAK-INSERT: guard.regzero.auipc.semantic_injection
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.control.auipc_pc_limb_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.control.auipc_pc_limb_consistency step={}",
                beak_witness_step
            );
            core_row.pc_limbs[0] += F::ONE;
        }
        // BEAK-INSERT-END
""",
        ),
    ]
    for path, anchor, guard, insert in core_hooks:
        if not path.exists():
            continue
        _ensure_use_fuzzer_utils(path)
        c = path.read_text()
        try:
            c = _insert_after(c, anchor=anchor, guard=guard, insert=insert)
        except RuntimeError:
            pass
        path.write_text(c)

    control_hooks = [
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "branch_eq" / "core.rs",
            "        core_row.a = record.a.map(F::from_canonical_u8);\n",
            "// BEAK-INSERT: guard.regzero.branch_eq.semantic_injection",
            "branch_eq",
            "core_row.cmp_result = F::ONE - core_row.cmp_result;",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "branch_lt" / "core.rs",
            "        core_row.a = record.a.map(F::from_canonical_u8);\n",
            "// BEAK-INSERT: guard.regzero.branch_lt.semantic_injection",
            "branch_lt",
            "core_row.cmp_result = F::ONE - core_row.cmp_result;",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "jal_lui" / "core.rs",
            "        core_row.imm = F::from_canonical_u32(record.imm);\n",
            "// BEAK-INSERT: guard.regzero.jal_lui.semantic_injection",
            "jal",
            "if record.is_jal { core_row.rd_data[0] += F::ONE; }",
        ),
        (
            openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "jalr" / "core.rs",
            "        core_row.imm = F::from_canonical_u16(record.imm);\n",
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
        let beak_witness_step = fuzzer_utils::next_witness_step();
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
                insert=r"""
        // BEAK-INSERT: guard.regzero.loadstore.core.memory_injection
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.value_payload_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.value_payload_consistency step={} site=loadstore_core",
                beak_witness_step
            );
            core_row.write_data[0] += F::ONE;
        }
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.store_load_payload_flow", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.store_load_payload_flow step={} site=loadstore_core",
                beak_witness_step
            );
            core_row.write_data[0] += F::ONE;
        }
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.kind_selector_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.kind_selector_consistency step={} site=loadstore_core",
                beak_witness_step
            );
            core_row.is_load = F::ONE - core_row.is_load;
        }
        // BEAK-INSERT-END
""",
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
                insert=r"""
        // BEAK-INSERT: guard.regzero.load_sign_extend.core.memory_injection
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.value_payload_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.value_payload_consistency step={} site=load_sign_extend_core",
                beak_witness_step
            );
            core_row.shifted_read_data[0] += F::ONE;
        }
        // BEAK-INSERT-END
""",
            )
        except RuntimeError:
            pass
        load_sign_extend_core.write_text(c)

    loadstore_adapter = rv32im / "adapters" / "loadstore.rs"
    if loadstore_adapter.exists():
        _ensure_use_fuzzer_utils(loadstore_adapter)
        c = loadstore_adapter.read_text()
        try:
            c = _insert_after(
                c,
                anchor="        adapter_row.mem_ptr_limbs = ptr_limbs.map(F::from_canonical_u32);\n",
                guard="// BEAK-INSERT: guard.regzero.loadstore.adapter.memory_injection",
                insert=r"""
        // BEAK-INSERT: guard.regzero.loadstore.adapter.memory_injection
        let beak_witness_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.address_pointer_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.address_pointer_consistency step={} site=loadstore_adapter",
                beak_witness_step
            );
            adapter_row.mem_ptr_limbs[0] += F::ONE;
        }
        if fuzzer_utils::should_inject_witness("openvm.semantic.memory.address_space_consistency", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.memory.address_space_consistency step={} site=loadstore_adapter",
                beak_witness_step
            );
            adapter_row.mem_as += F::ONE;
        }
        // BEAK-INSERT-END
""",
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
        new_fill = r"""    pub fn fill(&self, prev_timestamp: u32, timestamp: u32, buffer: &mut MemoryBaseAuxCols<F>) {
        self.generate_timestamp_lt(prev_timestamp, timestamp, &mut buffer.timestamp_lt_aux);
        let beak_witness_step = fuzzer_utils::next_witness_step();
        let mut beak_prev_timestamp = prev_timestamp;
        if fuzzer_utils::should_inject_witness("openvm.semantic.time.monotonic_access_ordering", beak_witness_step) {
            eprintln!(
                "[beak-witness-inject] kind=openvm.semantic.time.monotonic_access_ordering step={} prev_timestamp={} timestamp={}",
                beak_witness_step,
                prev_timestamp,
                timestamp
            );
            beak_prev_timestamp = timestamp;
        }
        // Safety: even if prev_timestamp were obtained by transmute_ref from
        // `buffer.prev_timestamp`, this should still work because it is a direct assignment
        buffer.prev_timestamp = F::from_canonical_u32(beak_prev_timestamp);
    }
"""
        if old_fill in c:
            c = c.replace(old_fill, new_fill, 1)
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


def _patch_regzero_lookup_multiplicity_instrumentation(openvm_install_path: Path) -> None:
    """Emit and mutate d7/regzero bitwise lookup multiplicity rows."""

    lookup = (
        openvm_install_path
        / "crates"
        / "circuits"
        / "primitives"
        / "src"
        / "bitwise_op_lookup"
        / "mod.rs"
    )
    if not lookup.exists():
        return
    _ensure_use_fuzzer_utils(lookup)
    c = lookup.read_text()
    old = r"""    /// Generates trace and resets all internal counters to 0.
    pub fn generate_trace<F: Field>(&self) -> RowMajorMatrix<F> {
        let mut rows = F::zero_vec(self.count_range.len() * NUM_BITWISE_OP_LOOKUP_COLS);
        for (n, row) in rows.chunks_mut(NUM_BITWISE_OP_LOOKUP_COLS).enumerate() {
            let cols: &mut BitwiseOperationLookupCols<F> = row.borrow_mut();
            cols.mult_range = F::from_canonical_u32(
                self.count_range[n].swap(0, std::sync::atomic::Ordering::SeqCst),
            );
            cols.mult_xor = F::from_canonical_u32(
                self.count_xor[n].swap(0, std::sync::atomic::Ordering::SeqCst),
            );
        }
        RowMajorMatrix::new(rows, NUM_BITWISE_OP_LOOKUP_COLS)
    }
"""
    new = r"""    /// Generates trace and resets all internal counters to 0.
    pub fn generate_trace<F: Field>(&self) -> RowMajorMatrix<F> {
        let mut rows = F::zero_vec(self.count_range.len() * NUM_BITWISE_OP_LOOKUP_COLS);
        for (n, row) in rows.chunks_mut(NUM_BITWISE_OP_LOOKUP_COLS).enumerate() {
            let cols: &mut BitwiseOperationLookupCols<F> = row.borrow_mut();
            let range_mult = self.count_range[n].swap(0, std::sync::atomic::Ordering::SeqCst);
            let xor_mult = self.count_xor[n].swap(0, std::sync::atomic::Ordering::SeqCst);
            if range_mult != 0 {
                fuzzer_utils::emit_lookup_multiplicity(
                    "bitwise_op_lookup.range",
                    n as u64,
                    range_mult,
                    true,
                );
            }
            if xor_mult != 0 {
                fuzzer_utils::emit_lookup_multiplicity(
                    "bitwise_op_lookup.xor",
                    n as u64,
                    xor_mult,
                    true,
                );
            }
            cols.mult_range = F::from_canonical_u32(range_mult);
            cols.mult_xor = F::from_canonical_u32(xor_mult);
            if range_mult != 0
                && fuzzer_utils::should_inject_witness(
                    "openvm.semantic.lookup.boolean_multiplicity",
                    n as u64,
                )
            {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.lookup.boolean_multiplicity step={} table=bitwise_op_lookup.range",
                    n
                );
                cols.mult_range += F::ONE;
            }
            if xor_mult != 0
                && fuzzer_utils::should_inject_witness(
                    "openvm.semantic.lookup.boolean_multiplicity",
                    n as u64,
                )
            {
                eprintln!(
                    "[beak-witness-inject] kind=openvm.semantic.lookup.boolean_multiplicity step={} table=bitwise_op_lookup.xor",
                    n
                );
                cols.mult_xor += F::ONE;
            }
        }
        RowMajorMatrix::new(rows, NUM_BITWISE_OP_LOOKUP_COLS)
    }
"""
    if old in c:
        c = c.replace(old, new, 1)
    lookup.write_text(c)


# def _patch_audit_integration_api_for_microops(openvm_install_path: Path) -> None:
#     """
#     Audit snapshots (336/f038) have a slightly different `integration_api.rs` layout (multi-line
#     `postprocess` assignment). Patch it in-place to emit adapter/core ChipRow micro-ops.
#     """

#     integration_api = openvm_install_path / "crates" / "vm" / "src" / "arch" / "integration_api.rs"
#     if not integration_api.exists():
#         return

#     contents = integration_api.read_text()
#     if 'fuzzer_utils::emit_chip_row_json("openvm"' in contents:
#         # Already injected.
#         return

#     # Ensure we can call fuzzer_utils even if assert-rewrite didn't touch this file.
#     if "use fuzzer_utils;" not in contents:
#         header_end = contents.find("\n\n")
#         if header_end > 0:
#             contents = contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]

#     # Ensure serde_json::json is available.
#     if "use serde_json::json;" not in contents:
#         # Accept both `use serde::{Deserialize, Serialize};` and
#         # `use serde::{de::DeserializeOwned, Deserialize, Serialize};` variants.
#         contents, n = re.subn(
#             r"^use serde::\{[^}]*\};\s*$",
#             lambda m: m.group(0) + "\nuse serde_json::json;",
#             contents,
#             count=1,
#             flags=re.MULTILINE,
#         )
#         if n == 0:
#             raise RuntimeError("unable to locate serde import to append serde_json::json")

#     # Insert after the multi-line postprocess assignment (ending at `?;`).
#     m = re.search(
#         r"(let\s+\(to_state,\s*write_record\)\s*=\s*\n\s*self\.adapter\s*\n\s*\.postprocess\([\s\S]*?\)\?\s*;)",
#         contents,
#         flags=re.MULTILINE,
#     )
#     if not m:
#         raise RuntimeError("unable to locate adapter postprocess assignment in integration_api.rs")

#     insert = r"""

#         if fuzzer_utils::is_trace_logging() {
#             // NOTE: We emit ChipRow-style records, i.e. per-chip payloads, using the
#             // `{"type":"chip_row","data":{...}}` JSON envelope emitted by fuzzer_utils.
#             let gates = json!({"is_real": 1}).to_string();

#             let adapter_chip = get_air_name(self.adapter.air());
#             let adapter_locals = json!({
#                 "from_pc": from_state.pc,
#                 "to_pc": to_state.pc,
#                 "from_timestamp": from_state.timestamp,
#                 "to_timestamp": to_state.timestamp,
#                 "payload_json": json!({
#                     "adapter_read": &read_record,
#                     "adapter_write": &write_record,
#                 })
#                 .to_string(),
#             })
#             .to_string();
#             // integration_api spans many extensions; default to explicit "custom" unless a given
#             // injection site can name a more specific kind without heuristics.
#             fuzzer_utils::emit_chip_row_json(
#                 "openvm",
#                 &adapter_chip,
#                 "custom",
#                 &gates,
#                 &adapter_locals,
#             );

#             let core_chip = get_air_name(self.core.air());
#             let core_locals = json!({
#                 "from_pc": from_state.pc,
#                 "payload_json": json!({ "core": &core_record }).to_string(),
#             })
#             .to_string();
#             fuzzer_utils::emit_chip_row_json("openvm", &core_chip, "custom", &gates, &core_locals);
#         }
# """
#     pos = m.end()
#     contents = contents[:pos] + insert + contents[pos:]
#     integration_api.write_text(contents)


# def _patch_integration_api_microops(*, openvm_install_path: Path, commit_or_branch: str) -> None:
#     resolved_commit = resolve_openvm_commit(commit_or_branch)

#     integration_api = openvm_install_path / "crates" / "vm" / "src" / "arch" / "integration_api.rs"
#     if not integration_api.exists():
#         return

#     # 87f006-style (typed micro-ops) does not instrument integration_api.rs.
#     if resolved_commit == OPENVM_BENCHMARK_REGZERO_COMMIT:
#         return

#     if resolved_commit in {OPENVM_BENCHMARK_336F_COMMIT, OPENVM_BENCHMARK_F038_COMMIT}:
#         _patch_audit_integration_api_for_microops(openvm_install_path)
#         return

#     contents = integration_api.read_text()

#     # Ensure we can call fuzzer_utils even if assert-rewrite didn't touch this file.
#     if "use fuzzer_utils;" not in contents:
#         header_end = contents.find("\n\n")
#         if header_end > 0:
#             integration_api.write_text(
#                 contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]
#             )
#             contents = integration_api.read_text()

#     # Ensure serde_json::json is available.
#     if "use serde_json::json;" not in contents:
#         replace_in_file(
#             integration_api,
#             [
#                 (
#                     r"use serde::\{de::DeserializeOwned, Deserialize, Serialize\};",
#                     "use serde::{de::DeserializeOwned, Deserialize, Serialize};\nuse serde_json::json;",
#                 )
#             ],
#         )
#         contents = integration_api.read_text()

#     # Repair a prior bad injection that left a literal `\1` line in the file.
#     if "\n\\1\n" in contents:
#         integration_api.write_text(contents.replace("\n\\1\n", "\n"))
#         contents = integration_api.read_text()

#     if 'fuzzer_utils::emit_chip_row_json("openvm"' in contents:
#         return

#     replace_in_file(
#         integration_api,
#         [
#             (
#                 r"^(\s*self\.adapter\s*\.postprocess\(\s*memory,\s*instruction,\s*from_state,\s*output,\s*&read_record\s*\)\?\s*;)\s*$",
#                 r"""\1

#         if fuzzer_utils::is_trace_logging() {
#             // NOTE: We emit ChipRow-style records, i.e. per-chip payloads, using the
#             // `{"type":"chip_row","data":{...}}` JSON envelope emitted by fuzzer_utils.
#             let gates = json!({"is_real": 1}).to_string();

#             let adapter_chip = get_air_name(self.adapter.air());
#             let adapter_locals = json!({
#                 "from_pc": from_state.pc,
#                 "to_pc": to_state.pc,
#                 "from_timestamp": from_state.timestamp,
#                 "to_timestamp": to_state.timestamp,
#                 "payload_json": json!({
#                     "adapter_read": &read_record,
#                     "adapter_write": &write_record,
#                 })
#                 .to_string(),
#             })
#             .to_string();
#             // integration_api spans many extensions; default to explicit "custom" unless a given
#             // injection site can name a more specific kind without heuristics.
#             fuzzer_utils::emit_chip_row_json(
#                 "openvm",
#                 &adapter_chip,
#                 "custom",
#                 &gates,
#                 &adapter_locals,
#             );

#             let core_chip = get_air_name(self.core.air());
#             let core_locals = json!({
#                 "from_pc": from_state.pc,
#                 "payload_json": json!({ "core": &core_record }).to_string(),
#             })
#             .to_string();
#             fuzzer_utils::emit_chip_row_json("openvm", &core_chip, "custom", &gates, &core_locals);
#         }""",
#             ),
#         ],
#         flags=re.MULTILINE,
#     )


# def _patch_audit_integration_api_for_padding_samples(openvm_install_path: Path) -> None:
#     """
#     Audit snapshots (336/f038) build padded traces in `VmChipWrapper::generate_air_proof_input`.

#     Sample a few padding rows (which are all-zero) as inactive ChipRows (is_real=0) and emit an
#     effectful Interaction anchored to them. This enables InactiveRowEffectsBucket without dumping
#     every padding row.
#     """

#     integration_api = openvm_install_path / "crates" / "vm" / "src" / "arch" / "integration_api.rs"
#     if not integration_api.exists():
#         return

#     contents = integration_api.read_text()
#     # Repair older insertion that passed `&str` to `update_hints` (signature expects `&String`).
#     if 'update_hints(0, "PADDING", "PADDING")' in contents:
#         contents = contents.replace(
#             'fuzzer_utils::update_hints(0, "PADDING", "PADDING");',
#             'let hint = "PADDING".to_string();\n            fuzzer_utils::update_hints(0, &hint, &hint);',
#         )
#         integration_api.write_text(contents)
#         contents = integration_api.read_text()

#     # Repair older insertion that borrowed `self` after `self.records` was moved.
#     if 'let chip = format!("VmChipWrapper{}", self.air_name());' in contents:
#         contents = contents.replace(
#             'let chip = format!("VmChipWrapper{}", self.air_name());',
#             'let chip = "VmChipWrapper".to_string();',
#         )
#         integration_api.write_text(contents)
#         contents = integration_api.read_text()

#     # Repair older insertion that references `beak_padding_chip` without declaration.
#     if "let chip = beak_padding_chip.clone();" in contents:
#         contents = contents.replace(
#             "let chip = beak_padding_chip.clone();",
#             'let chip = "VmChipWrapper".to_string();',
#         )
#         integration_api.write_text(contents)
#         contents = integration_api.read_text()

#     if "PaddingSample" in contents:
#         return

#     # Ensure we can call fuzzer_utils even if assert-rewrite didn't touch this file.
#     if "use fuzzer_utils;" not in contents:
#         header_end = contents.find("\n\n")
#         if header_end > 0:
#             contents = contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]

#     # Ensure serde_json::json is available (we emit small JSON payloads).
#     if "use serde_json::json;" not in contents:
#         contents, n = re.subn(
#             r"^use serde::\{[^}]*\};\s*$",
#             lambda m: m.group(0) + "\nuse serde_json::json;",
#             contents,
#             count=1,
#             flags=re.MULTILINE,
#         )
#         if n == 0:
#             # Best-effort: insert after the last `use` in the header.
#             header_end = contents.find("\n\n")
#             if header_end > 0:
#                 contents = (
#                     contents[:header_end] + "\nuse serde_json::json;\n" + contents[header_end:]
#                 )

#     # Insert after finalize, where `height/num_records/width` are in scope and padding rows exist.
#     anchor = "self.core.finalize(&mut trace, num_records);"
#     insert = r"""

#         // beak-fuzz: sample a few inactive (padding) rows for op-agnostic inactive-row analysis.
#         if fuzzer_utils::is_trace_logging() && height > num_records {
#             let hint = "PADDING".to_string();
#             fuzzer_utils::update_hints(0, &hint, &hint);
#             fuzzer_utils::inc_step();

#             let chip = "VmChipWrapper".to_string();
#             let max_samples: usize = 3;
#             let mut emitted: usize = 0;
#             while emitted < max_samples && (num_records + emitted) < height {
#                 let row_idx = num_records + emitted;
#                 let gates = json!({"is_real": 0}).to_string();
#                 let locals = json!({
#                     "chip": chip,
#                     "row_idx": row_idx,
#                     "real_rows": num_records,
#                     "total_rows": height,
#                     "width": width,
#                 })
#                 .to_string();
#                 fuzzer_utils::emit_chip_row_json("openvm", &chip, "memory", &gates, &locals);
#                 let anchor_row_id = fuzzer_utils::get_last_row_id();
#                 let payload = json!({"chip": chip, "row_idx": row_idx}).to_string();
#                 fuzzer_utils::emit_interaction_json(
#                     "PaddingSample",
#                     "send",
#                     "inactive_row",
#                     &anchor_row_id,
#                     &payload,
#                     1,
#                     "const",
#                 );
#                 emitted += 1;
#             }
#         }
# """

#     if anchor not in contents:
#         # Older/variant layouts: don't fail hard; just skip.
#         integration_api.write_text(contents)
#         return
#     contents = contents.replace(anchor, anchor + insert)
#     integration_api.write_text(contents)


# def _patch_padding_samples(*, openvm_install_path: Path, commit_or_branch: str) -> None:
#     resolved_commit = resolve_openvm_commit(commit_or_branch)

#     if resolved_commit in {OPENVM_BENCHMARK_336F_COMMIT, OPENVM_BENCHMARK_F038_COMMIT}:
#         _patch_audit_integration_api_for_padding_samples(openvm_install_path)

#     # 87f006-style: do not sample padding rows in regzero.


# def _patch_audit_segment_rs_for_microops(openvm_install_path: Path) -> None:
#     """
#     Audit snapshots (336/f038) predate our template overwrite approach.
#     Patch `crates/vm/src/arch/segment.rs` in-place to emit ChipRow + Interaction micro-ops.
#     """

#     segment_rs = openvm_install_path / "crates" / "vm" / "src" / "arch" / "segment.rs"
#     if not segment_rs.exists():
#         logger.info("segment.rs not found; skipping audit segment patch: %s", segment_rs)
#         return

#     contents = segment_rs.read_text()

#     # Ensure imports used by the injected blocks.
#     if "use serde_json::json;" not in contents:
#         # Prefer inserting after the top-level `use crate::{ ... };` block.
#         m = re.search(r"\nuse crate::\{[\s\S]*?\};\n", contents, flags=re.MULTILINE)
#         if m:
#             pos = m.end()
#             contents = contents[:pos] + "use serde_json::json;\n" + contents[pos:]
#         else:
#             # Best-effort: insert after the last `use` line in the header.
#             header_end = contents.find("\n\n")
#             if header_end > 0:
#                 header = contents[:header_end]
#                 if "use serde_json::json;" not in header:
#                     contents = (
#                         contents[:header_end] + "\nuse serde_json::json;\n" + contents[header_end:]
#                     )

#     if "use crate::system::memory::online::MemoryLogEntry;" not in contents:
#         # Insert after existing `use crate::{ ... system::memory::MemoryImage, ... };` block if present.
#         m = re.search(r"use crate::\{[\s\S]*?system::memory::MemoryImage,[\s\S]*?\};", contents)
#         if m:
#             insert_pos = m.end()
#             contents = (
#                 contents[:insert_pos]
#                 + "\nuse crate::system::memory::online::MemoryLogEntry;\n"
#                 + contents[insert_pos:]
#             )

#     # Ensure `use fuzzer_utils;` is present somewhere (assert-rewrite usually adds it, but be robust).
#     if "use fuzzer_utils;" not in contents:
#         header_end = contents.find("\n\n")
#         if header_end > 0:
#             contents = contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]

#     # ProgramChip + ProgramBus emission (pc -> opcode/operands).
#     contents = _insert_after(
#         contents,
#         anchor="let (instruction, debug_info) = program_chip.get_instruction(pc)?;",
#         guard='"ProgramBus"',
#         insert=r"""

#                 // Program-table semantics: the program bus constrains that (pc -> opcode/operands).
#                 // Emit a ChipRow so op-level analyses can include this "system" chip alongside
#                 // the instruction's adapter/core chips.
#                 if fuzzer_utils::is_trace_logging() {
#                     let gates = json!({"is_real": 1}).to_string();
#                     let locals = json!({
#                         "pc": pc,
#                         "opcode": instruction.opcode.as_usize(),
#                         "operands": [
#                             instruction.a.as_canonical_u32(),
#                             instruction.b.as_canonical_u32(),
#                             instruction.c.as_canonical_u32(),
#                             instruction.d.as_canonical_u32(),
#                             instruction.e.as_canonical_u32(),
#                             instruction.f.as_canonical_u32(),
#                             instruction.g.as_canonical_u32(),
#                         ],
#                     })
#                     .to_string();
#                     let chip = "ProgramChip".to_string();
#                     fuzzer_utils::emit_chip_row_json("openvm", &chip, "program", &gates, &locals);

#                     // Program-table interaction: lookup (pc -> opcode/operands).
#                     let anchor_row_id = fuzzer_utils::get_last_row_id();
#                     let payload = json!({
#                         "pc": pc,
#                         "opcode": instruction.opcode.as_usize(),
#                         "operands": [
#                             instruction.a.as_canonical_u32(),
#                             instruction.b.as_canonical_u32(),
#                             instruction.c.as_canonical_u32(),
#                             instruction.d.as_canonical_u32(),
#                             instruction.e.as_canonical_u32(),
#                             instruction.f.as_canonical_u32(),
#                             instruction.g.as_canonical_u32(),
#                         ],
#                     })
#                     .to_string();
#                     fuzzer_utils::emit_interaction_json(
#                         "ProgramBus",
#                         "recv",
#                         "program",
#                         &anchor_row_id,
#                         &payload,
#                         1,
#                         "gates.is_real",
#                     );
#                 }
# """,
#     )

#     # Memory log snapshot + prev state before execute.
#     contents = _insert_after(
#         contents,
#         anchor="if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {",
#         guard="let mem_log_start =",
#         insert=r"""

#                         // Snapshot memory logs to attribute memory chips per instruction.
#                         let mem_log_start = memory_controller.get_memory_logs().len();

#                         let prev_pc = pc;
#                         let prev_timestamp = timestamp;
# """,
#     )

#     # Post-exec memory chips + boundary + execution-bus + per-step increment.
#     contents = _insert_after(
#         contents,
#         anchor="timestamp = next_state.timestamp;",
#         guard="ExecutionBus",
#         insert=r"""

#                         // Emit memory-related chips as ChipRow markers.
#                         //
#                         // NOTE: During execution, OpenVM accumulates *memory logs* in online memory.
#                         // Those logs are later replayed in `finalize()` to populate memory trace
#                         // chips (Boundary, AccessAdapter<N>, ...). We attribute per-instruction
#                         // "memory chips involved" based on the newly-added memory-log entries here.
#                         if fuzzer_utils::is_trace_logging() {
#                             let gates = json!({"is_real": 1}).to_string();
#                             let logs = memory_controller.get_memory_logs();
#                             let new_logs = logs.iter().skip(mem_log_start);

#                             let mut boundary_spaces: Vec<u32> = Vec::new();
#                             let mut access_count: u32 = 0;

#                             for (i, entry) in new_logs.enumerate() {
#                                 let record_id = (mem_log_start + i) as u32;
#                                 match entry {
#                                     MemoryLogEntry::Read { address_space, pointer, len } => {
#                                         access_count += 1;
#                                         if *address_space != 0
#                                             && !boundary_spaces.contains(address_space)
#                                         {
#                                             boundary_spaces.push(*address_space);
#                                         }
#                                         let chip = format!("AccessAdapter<{}>", len);
#                                         let locals = json!({
#                                             "record_id": record_id,
#                                             "op": "read",
#                                             "address_space": address_space,
#                                             "pointer": pointer,
#                                             "len": len,
#                                         })
#                                         .to_string();
#                                         fuzzer_utils::emit_chip_row_json(
#                                             "openvm",
#                                             &chip,
#                                             "memory",
#                                             &gates,
#                                             &locals,
#                                         );

#                                         let anchor_row_id = fuzzer_utils::get_last_row_id();
#                                         let payload = json!({
#                                             "record_id": record_id,
#                                             "op": "read",
#                                             "address_space": address_space,
#                                             "pointer": pointer,
#                                             "len": len,
#                                         })
#                                         .to_string();
#                                         fuzzer_utils::emit_interaction_json(
#                                             "MemoryBus",
#                                             "send",
#                                             "memory",
#                                             &anchor_row_id,
#                                             &payload,
#                                             1,
#                                             "gates.is_real",
#                                         );
#                                     }
#                                     MemoryLogEntry::Write { address_space, pointer, data } => {
#                                         access_count += 1;
#                                         if *address_space != 0
#                                             && !boundary_spaces.contains(address_space)
#                                         {
#                                             boundary_spaces.push(*address_space);
#                                         }
#                                         let len = data.len() as u32;
#                                         let chip = format!("AccessAdapter<{}>", len);
#                                         let locals = json!({
#                                             "record_id": record_id,
#                                             "op": "write",
#                                             "address_space": address_space,
#                                             "pointer": pointer,
#                                             "len": len,
#                                         })
#                                         .to_string();
#                                         fuzzer_utils::emit_chip_row_json(
#                                             "openvm",
#                                             &chip,
#                                             "memory",
#                                             &gates,
#                                             &locals,
#                                         );

#                                         let anchor_row_id = fuzzer_utils::get_last_row_id();
#                                         let payload = json!({
#                                             "record_id": record_id,
#                                             "op": "write",
#                                             "address_space": address_space,
#                                             "pointer": pointer,
#                                             "len": len,
#                                         })
#                                         .to_string();
#                                         fuzzer_utils::emit_interaction_json(
#                                             "MemoryBus",
#                                             "send",
#                                             "memory",
#                                             &anchor_row_id,
#                                             &payload,
#                                             1,
#                                             "gates.is_real",
#                                         );
#                                     }
#                                     MemoryLogEntry::IncrementTimestampBy(_) => {}
#                                 }
#                             }

#                             // Boundary: constrain which address spaces are accessed.
#                             if access_count > 0 {
#                                 let chip = "Boundary".to_string();
#                                 let locals = json!({
#                                     "access_count": access_count,
#                                     "address_spaces": boundary_spaces,
#                                 })
#                                 .to_string();
#                                 fuzzer_utils::emit_chip_row_json("openvm", &chip, "memory", &gates, &locals);
#                                 let anchor_row_id = fuzzer_utils::get_last_row_id();
#                                 let payload = json!({
#                                     "access_count": access_count,
#                                     "address_spaces": boundary_spaces,
#                                 })
#                                 .to_string();
#                                 fuzzer_utils::emit_interaction_json(
#                                     "Boundary",
#                                     "send",
#                                     "memory",
#                                     &anchor_row_id,
#                                     &payload,
#                                     1,
#                                     "gates.is_real",
#                                 );
#                             }
#                         }

#                         // Execution-bus semantics: (pc,timestamp) transitions are constrained via
#                         // the execution bus (checked by the connector air). We record the edge as
#                         // a ChipRow so buckets can reason about next_pc / timestamp changes.
#                         if fuzzer_utils::is_trace_logging() {
#                             let gates = json!({"is_real": 1}).to_string();
#                             let locals = json!({
#                                 "from_pc": prev_pc,
#                                 "to_pc": pc,
#                                 "from_timestamp": prev_timestamp,
#                                 "to_timestamp": timestamp,
#                                 "opcode": opcode.as_usize(),
#                             })
#                             .to_string();
#                             let chip = "VmConnectorAir".to_string();
#                             fuzzer_utils::emit_chip_row_json("openvm", &chip, "connector", &gates, &locals);

#                             let anchor_row_id = fuzzer_utils::get_last_row_id();
#                             let recv_payload = json!({
#                                 "pc": prev_pc,
#                                 "timestamp": prev_timestamp,
#                             })
#                             .to_string();
#                             fuzzer_utils::emit_interaction_json(
#                                 "ExecutionBus",
#                                 "recv",
#                                 "global",
#                                 &anchor_row_id,
#                                 &recv_payload,
#                                 1,
#                                 "gates.is_real",
#                             );
#                             let send_payload = json!({
#                                 "pc": pc,
#                                 "timestamp": timestamp,
#                             })
#                             .to_string();
#                             fuzzer_utils::emit_interaction_json(
#                                 "ExecutionBus",
#                                 "send",
#                                 "global",
#                                 &anchor_row_id,
#                                 &send_payload,
#                                 1,
#                                 "gates.is_real",
#                             );
#                         }
# """,
#     )

#     # Per-op step increment (needed so bucket code gets `op_spans`).
#     contents = _insert_before(
#         contents,
#         anchor="(opcode, dsl_instr.cloned())",
#         guard="beak_fuzz_op_step_v1",
#         insert=r"""

#                 // beak_fuzz_op_step_v1
#                 // Advance "op index" for micro-op grouping.
#                 fuzzer_utils::print_trace_info();
#                 fuzzer_utils::inc_step();
# """,
#     )

#     segment_rs.write_text(contents)


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    commit = resolve_openvm_commit(commit_or_branch)
    if commit == OPENVM_BENCHMARK_REGZERO_COMMIT:
        _patch_regzero_record_arena_emit_chip_row(openvm_install_path)
        _patch_regzero_interpreter_preflight_emit_instruction(openvm_install_path)
        _patch_regzero_rv32im_cores_emit_chip_row(openvm_install_path)
        _patch_regzero_system_connector_emit_chip_row(openvm_install_path)
        _patch_regzero_program_trace_zero_register_injection(openvm_install_path)
        _patch_regzero_semantic_witness_injection(openvm_install_path)
        _patch_memory_access_emit_support(openvm_install_path)
        _patch_regzero_memory_deep_instrumentation(openvm_install_path)
        _patch_regzero_lookup_multiplicity_instrumentation(openvm_install_path)
        _patch_witness_step_wildcard_support(openvm_install_path)
        _patch_witness_variant_support(openvm_install_path)
    elif commit in {OPENVM_BENCHMARK_336F_COMMIT, OPENVM_BENCHMARK_F038_COMMIT}:
        # Keep audit snapshots on a lightweight, layout-compatible injection set.
        # Start with one concrete adapter-level injection used by loop2/audit-o5 workflow.
        # Also emit system connector chip-row as a first-class trace record, so connector-related
        # loop2 injections do not rely on coarse proxy buckets.
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
        if commit == OPENVM_BENCHMARK_336F_COMMIT:
            _patch_336f_program_trace_semantic_injection(openvm_install_path)
            _patch_336f_base_alu_padding_interaction_injection(openvm_install_path)
            _patch_336f_connector_witness_injection(openvm_install_path)
            _patch_336f_control_flow_witness_injection(openvm_install_path)
        _patch_witness_step_wildcard_support(openvm_install_path)
        _patch_witness_variant_support(openvm_install_path)
        if commit == OPENVM_BENCHMARK_F038_COMMIT:
            _patch_f038_memory_finalization_instrumentation(openvm_install_path)
            _patch_f038_volatile_witness_injection(openvm_install_path)
            _patch_f038_time_origin_shift_witness_injection(openvm_install_path)
            _patch_f038_connector_witness_injection(openvm_install_path)
            _patch_f038_program_trace_mem_as_witness_injection(openvm_install_path)
            _patch_f038_volatile_boundary_collection_and_remap(openvm_install_path)
            _patch_f038_loadstore_mem_as_witness_injection(openvm_install_path)
            _patch_f038_loadstore_immediate_sign_witness_injection(openvm_install_path)
    else:
        raise ValueError(f"Unsupported commit or branch: {commit_or_branch}")
