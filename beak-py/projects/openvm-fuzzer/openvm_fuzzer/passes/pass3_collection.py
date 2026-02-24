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
                let data = self.trace_buffer[rows_used + emitted].to_string();
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


def _patch_regzero_rv32im_cores_emit_chip_row(openvm_install_path: Path) -> None:
    base = openvm_install_path / "extensions" / "rv32im" / "circuit" / "src"

    # (file, adapter-cols import, unique guard, insertion block)
    targets: list[tuple[Path, str, str, str]] = [
        (
            base / "base_alu" / "core.rs",
            "use crate::adapters::Rv32BaseAluAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.base_alu",
            r"""

        // BEAK-INSERT: guard.rv32im.base_alu
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BaseAluAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();

        // rs2_as: 1 if rs2 is a register read, 0 if an immediate.
        let is_rs2_imm = beak_cols.rs2_as.as_canonical_u32() == 0;
        let rs2_raw = beak_cols.rs2.as_canonical_u32();
        let rs2_i32 = rs2_raw as i32; // preserve bit-pattern for signed immediates

        fuzzer_utils::emit_base_alu_chip_row(local_opcode as u32, rd_ptr, rs1_ptr, rs2_i32, is_rs2_imm, a, record.b, record.c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "shift" / "core.rs",
            "use crate::adapters::Rv32BaseAluAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.shift",
            r"""

        // BEAK-INSERT: guard.rv32im.shift
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BaseAluAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();

        // rs2_as: 1 if rs2 is a register read, 0 if an immediate.
        let is_rs2_imm = beak_cols.rs2_as.as_canonical_u32() == 0;
        let rs2_raw = beak_cols.rs2.as_canonical_u32();
        let rs2_i32 = rs2_raw as i32; // preserve bit-pattern for signed immediates

        fuzzer_utils::emit_shift_chip_row(opcode as u32, rd_ptr, rs1_ptr, rs2_i32, is_rs2_imm, a, record.b, record.c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "less_than" / "core.rs",
            "use crate::adapters::Rv32BaseAluAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.less_than",
            r"""

        // BEAK-INSERT: guard.rv32im.less_than
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BaseAluAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();

        // rs2_as: 1 if rs2 is a register read, 0 if an immediate.
        let is_rs2_imm = beak_cols.rs2_as.as_canonical_u32() == 0;
        let rs2_raw = beak_cols.rs2.as_canonical_u32();
        let rs2_i32 = rs2_raw as i32; // preserve bit-pattern for signed immediates

        let opcode = LessThanOpcode::from_usize(record.local_opcode as usize);
        let mut a = [0u8; NUM_LIMBS];
        a[0] = cmp_result as u8;

        fuzzer_utils::emit_less_than_chip_row(opcode as u32, rd_ptr, rs1_ptr, rs2_i32, is_rs2_imm, a, record.b, record.c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "mul" / "core.rs",
            "use crate::adapters::Rv32MultAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.mul",
            r"""

        // BEAK-INSERT: guard.rv32im.mul
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32MultAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rs2_ptr = beak_cols.rs2_ptr.as_canonical_u32();

        fuzzer_utils::emit_mul_chip_row(MulOpcode::MUL as u32, rd_ptr, rs1_ptr, rs2_ptr, a, record.b, record.c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "mulh" / "core.rs",
            "use crate::adapters::Rv32MultAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.mulh",
            r"""

        // BEAK-INSERT: guard.rv32im.mulh
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32MultAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rs2_ptr = beak_cols.rs2_ptr.as_canonical_u32();

        let a_u8 = a.map(|x| x as u8);
        fuzzer_utils::emit_mulh_chip_row(opcode as u32, rd_ptr, rs1_ptr, rs2_ptr, a_u8, record.b, record.c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "divrem" / "core.rs",
            "use crate::adapters::Rv32BaseAluAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.divrem",
            r"""

        // BEAK-INSERT: guard.rv32im.divrem
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BaseAluAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rs2_ptr = beak_cols.rs2.as_canonical_u32();

        let is_div = matches!(opcode, DivRemOpcode::DIV | DivRemOpcode::DIVU);
        let a_u8 = if is_div { q.map(|x| x as u8) } else { r.map(|x| x as u8) };

        fuzzer_utils::emit_divrem_chip_row(opcode as u32, rd_ptr, rs1_ptr, rs2_ptr, a_u8, record.b, record.c);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "branch_eq" / "core.rs",
            "use crate::adapters::Rv32BranchAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.branch_eq",
            r"""

        // BEAK-INSERT: guard.rv32im.branch_eq
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BranchAdapterCols<F> = adapter_slice.borrow();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rs2_ptr = beak_cols.rs2_ptr.as_canonical_u32();
        let from_pc = beak_cols.from_state.pc.as_canonical_u32();

        let opcode = BranchEqualOpcode::from_usize(record.local_opcode as usize);
        let imm_i32 = record.imm as i32; // preserve bit-pattern
        let is_beq = opcode == BranchEqualOpcode::BEQ;
        let is_taken = if is_beq { cmp_result } else { !cmp_result };
        let to_pc = if is_taken {
            from_pc.wrapping_add(record.imm)
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
            record.a,
            record.b,
            cmp_result,
        );
        // BEAK-INSERT-END
""",
        ),
        (
            base / "branch_lt" / "core.rs",
            "use crate::adapters::Rv32BranchAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.branch_lt",
            r"""

        // BEAK-INSERT: guard.rv32im.branch_lt
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32BranchAdapterCols<F> = adapter_slice.borrow();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let rs2_ptr = beak_cols.rs2_ptr.as_canonical_u32();
        let from_pc = beak_cols.from_state.pc.as_canonical_u32();

        let opcode = BranchLessThanOpcode::from_usize(record.local_opcode as usize);
        let imm_i32 = record.imm as i32; // preserve bit-pattern
        let is_taken = cmp_result;
        let to_pc = if is_taken {
            from_pc.wrapping_add(record.imm)
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
            record.a,
            record.b,
            cmp_result,
        );
        // BEAK-INSERT-END
""",
        ),
        (
            base / "jal_lui" / "core.rs",
            "use crate::adapters::Rv32CondRdWriteAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.jal_lui",
            r"""

        // BEAK-INSERT: guard.rv32im.jal_lui
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32CondRdWriteAdapterCols<F> = adapter_slice.borrow();
        let needs_write = beak_cols.needs_write.as_canonical_u32() == 1;
        let rd_ptr = beak_cols.inner.rd_ptr.as_canonical_u32();
        let from_pc = beak_cols.inner.from_state.pc.as_canonical_u32();
        let opcode = if record.is_jal {
            Rv32JalLuiOpcode::JAL
        } else {
            Rv32JalLuiOpcode::LUI
        };
        let imm = record.imm;

        let to_pc = if record.is_jal {
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
            record.rd_data,
            record.is_jal,
        );
        // BEAK-INSERT-END
""",
        ),
        (
            base / "jalr" / "core.rs",
            "use crate::adapters::Rv32JalrAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.jalr",
            r"""

        // BEAK-INSERT: guard.rv32im.jalr
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32JalrAdapterCols<F> = adapter_slice.borrow();

        let needs_write = beak_cols.needs_write.as_canonical_u32() == 1;
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        let rs1_ptr = beak_cols.rs1_ptr.as_canonical_u32();
        let from_pc = beak_cols.from_state.pc.as_canonical_u32();

        let imm_u16 = record.imm;
        // Sign-extend 16-bit immediate into i32 using the explicit sign flag.
        let imm_i32: i32 = (imm_u16 as i32) - ((record.imm_sign as i32) << 16);

        // Executor clears the least-significant bit of to_pc for control-flow.
        let to_pc_final = to_pc & !1;

        fuzzer_utils::emit_jalr_chip_row(
            Rv32JalrOpcode::JALR as u32,
            rd_ptr,
            rs1_ptr,
            imm_i32,
            record.imm_sign,
            needs_write,
            from_pc,
            to_pc_final,
            record.rs1_val,
            rd_data,
        );
        // BEAK-INSERT-END
""",
        ),
        (
            base / "auipc" / "core.rs",
            "use crate::adapters::Rv32RdWriteAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.auipc",
            r"""

        // BEAK-INSERT: guard.rv32im.auipc
        // BEAK-INSERT: Emit chip-row micro-op.
        let adapter_slice: &[F] = adapter_row;
        let beak_cols: &Rv32RdWriteAdapterCols<F> = adapter_slice.borrow();
        let rd_ptr = beak_cols.rd_ptr.as_canonical_u32();
        fuzzer_utils::emit_auipc_chip_row(0, rd_ptr, record.imm, record.from_pc, rd_data);
        // BEAK-INSERT-END
""",
        ),
        (
            base / "loadstore" / "core.rs",
            "use crate::adapters::Rv32LoadStoreAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.loadstore",
            r"""

        // BEAK-INSERT: guard.rv32im.loadstore
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
            record.read_data,
            record.prev_data,
            write_data,
        );
        // BEAK-INSERT-END
""",
        ),
        (
            base / "load_sign_extend" / "core.rs",
            "use crate::adapters::Rv32LoadStoreAdapterCols;",
            "// BEAK-INSERT: guard.rv32im.load_sign_extend",
            r"""

        // BEAK-INSERT: guard.rv32im.load_sign_extend
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

        let opcode = if record.is_byte { Rv32LoadStoreOpcode::LOADB } else { Rv32LoadStoreOpcode::LOADH };

        let mut shifted_read_data = record.read_data;
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
            record.prev_data,
            shifted_read_data,
            most_sig_bit != 0,
            shift & 2 == 2,
            !record.is_byte,
            record.is_byte && ((shift & 1) == 1),
            record.is_byte && ((shift & 1) == 0),
        );
        // BEAK-INSERT-END
""",
        ),
    ]

    for p, import_line, guard, block in targets:
        if not p.exists():
            continue
        _ensure_use_fuzzer_utils(p)
        _ensure_import_after_fuzzer_utils(p, import_line)
        c = p.read_text()
        c = _insert_before_fn_close(c, fn_name="fill_trace_row", insert=block, guard=guard)
        p.write_text(c)


def _patch_regzero_system_connector_emit_chip_row(openvm_install_path: Path) -> None:
    # connector/mod.rs
    connector = openvm_install_path / "crates" / "vm" / "src" / "system" / "connector" / "mod.rs"
    if connector.exists():
        _ensure_use_fuzzer_utils(connector)
        c = connector.read_text()
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
        connector.write_text(c)

    # phantom/mod.rs
    phantom = openvm_install_path / "crates" / "vm" / "src" / "system" / "phantom" / "mod.rs"
    if phantom.exists():
        _ensure_use_fuzzer_utils(phantom)
        c = phantom.read_text()
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
        phantom.write_text(c)

    # program/trace.rs
    program = openvm_install_path / "crates" / "vm" / "src" / "system" / "program" / "trace.rs"
    if program.exists():
        _ensure_use_fuzzer_utils(program)
        c = program.read_text()
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
        program.write_text(c)


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
    else:
        raise ValueError(f"Unsupported commit or branch: {commit_or_branch}")
