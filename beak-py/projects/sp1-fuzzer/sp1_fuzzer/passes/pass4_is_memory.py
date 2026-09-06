from __future__ import annotations

from pathlib import Path

from sp1_fuzzer.settings import SP1_UINT256_DIV_3561_COMMIT
from zkvm_fuzzer_utils.file import prepend_file

_PLONKY3_REV = "db3d45d4ec899efaf8f7234a8573f285fbdda5db"
_S27_MEMORY_SELECTOR_COMMIT = "39ab52fce38172c9d23feed7248198dc14c164a9"


def _cpu_trace_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [sp1_install_path / "crates" / "core" / "machine" / "src" / "cpu" / "trace.rs"]:
        if path.exists():
            out.append(path)
    return out


def _legacy_cpu_trace_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [sp1_install_path / "core" / "src" / "cpu" / "trace.rs"]:
        if path.exists():
            out.append(path)
    return out


def _memory_instruction_trace_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [
        sp1_install_path
        / "crates"
        / "core"
        / "machine"
        / "src"
        / "memory"
        / "instructions"
        / "trace.rs"
    ]:
        if path.exists():
            out.append(path)
    return out


def _syscall_instr_trace_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [
        sp1_install_path
        / "crates"
        / "core"
        / "machine"
        / "src"
        / "syscall"
        / "instructions"
        / "trace.rs"
    ]:
        if path.exists():
            out.append(path)
    return out


def _sha_extend_trace_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [
        sp1_install_path
        / "crates"
        / "core"
        / "machine"
        / "src"
        / "syscall"
        / "precompiles"
        / "sha256"
        / "extend"
        / "trace.rs"
    ]:
        if path.exists():
            out.append(path)
    return out


def _sha_compress_trace_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [
        sp1_install_path
        / "crates"
        / "core"
        / "machine"
        / "src"
        / "syscall"
        / "precompiles"
        / "sha256"
        / "compress"
        / "trace.rs"
    ]:
        if path.exists():
            out.append(path)
    return out


def _memory_global_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [
        sp1_install_path / "crates" / "core" / "machine" / "src" / "memory" / "global.rs"
    ]:
        if path.exists():
            out.append(path)
    return out


def _byte_trace_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [sp1_install_path / "crates" / "core" / "machine" / "src" / "bytes" / "trace.rs"]:
        if path.exists():
            out.append(path)
    return out


def _byte_event_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [sp1_install_path / "crates" / "core" / "executor" / "src" / "events" / "byte.rs"]:
        if path.exists():
            out.append(path)
    return out


def _execution_record_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [sp1_install_path / "crates" / "core" / "executor" / "src" / "record.rs"]:
        if path.exists():
            out.append(path)
    return out


def _executor_tracing_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [sp1_install_path / "crates" / "core" / "executor" / "src" / "tracing.rs"]:
        if path.exists():
            out.append(path)
    return out


def _syscall_context_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for path in [
        sp1_install_path
        / "crates"
        / "core"
        / "executor"
        / "src"
        / "syscalls"
        / "context.rs"
    ]:
        if path.exists():
            out.append(path)
    return out


def _ensure_fuzzer_utils_import(path: Path, contents: str) -> str:
    if "use fuzzer_utils;" not in contents:
        prepend_file(path, "#[allow(unused_imports)]\nuse fuzzer_utils;\n")
        return path.read_text()
    return contents


def _insert_after_once(contents: str, anchor: str, insert: str, guard: str) -> str:
    if guard in contents or anchor not in contents:
        return contents
    return contents.replace(anchor, anchor + insert, 1)


def _insert_before_once(contents: str, anchor: str, insert: str, guard: str) -> str:
    if guard in contents or anchor not in contents:
        return contents
    return contents.replace(anchor, insert + anchor, 1)


def _replace_guarded_block(contents: str, *, guard: str, replacement: str) -> str:
    guard_idx = contents.find(guard)
    if guard_idx < 0:
        return contents
    start = contents.rfind("\n", 0, guard_idx) + 1
    end_marker = "// BEAK-INSERT-END"
    end_idx = contents.find(end_marker, guard_idx)
    if end_idx < 0:
        return contents
    end = contents.find("\n", end_idx + len(end_marker))
    if end < 0:
        end = len(contents)
    else:
        end += 1
    return contents[:start] + replacement.lstrip("\n") + contents[end:]


def _patch_cpu_trace(path: Path, commit_or_branch: str) -> None:
    contents = path.read_text()
    instruction_cols = path.parent / "columns" / "instruction.rs"
    op_a_is_word = True
    if instruction_cols.exists():
        op_a_is_word = "pub op_a: Word<T>" in instruction_cols.read_text()
    op_a_mutation = (
        "(((event.a & 31).wrapping_add(1) & 31) as u32).into()"
        if op_a_is_word
        else "F::from_canonical_u32((event.a & 31).wrapping_add(1) & 31)"
    )
    memory_selector_step_fn = (
        "next_memory_selector_step"
        if commit_or_branch == _S27_MEMORY_SELECTOR_COMMIT
        else "next_witness_step"
    )
    memory_selector_op_idx = (
        "beak_step"
        if commit_or_branch == _S27_MEMORY_SELECTOR_COMMIT
        else "beak_step / 2"
    )

    contents = _ensure_fuzzer_utils_import(path, contents)

    helper_guard = "// BEAK-INSERT: sp1.v4.cpu_semantic_injection.helpers"
    if helper_guard not in contents:
        helper_anchor = "impl CpuChip {\n"
        helper_insert = """// BEAK-INSERT: sp1.v4.cpu_semantic_injection.helpers
    fn beak_cpu_semantic_injection_kind(step: u64) -> Option<String> {
        [
            "sp1.semantic.decode.zero_register_immutability",
            "sp1.semantic.decode.operand_index_routing",
            "sp1.semantic.exec.dest_binding",
            "sp1.semantic.decode.field_range",
            "sp1.semantic.decode.immediate_sign_extension",
            "sp1.semantic.decode.format_immediate_reassembly",
            "sp1.semantic.exec.op_selector_binding",
        ]
        .iter()
        .find_map(|kind| fuzzer_utils::matching_injection_kind(kind, step))
    }

    fn beak_mutate_cpu_semantic_row<F: PrimeField32>(
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        inject_kind: &str,
    ) {
        let site = fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("auto");
        match site {
            "opcode" => {
                cols.instruction.opcode = F::from_canonical_u32(0);
            }
            "instruction_op_a" => {
                cols.instruction.op_a = {OP_A_MUTATION};
                cols.instruction.op_a_0 = F::zero();
            }
            "instruction_op_b" => {
                cols.instruction.op_b = event.b.wrapping_add(1).into();
            }
            "instruction_op_c" => {
                cols.instruction.op_c = event.c.wrapping_add(1).into();
            }
            "op_a_access" => {
                *cols.op_a_access.value_mut() = event.a.wrapping_add(1).into();
            }
            "op_b_access" => {
                *cols.op_b_access.value_mut() = event.b.wrapping_add(1).into();
            }
            "op_c_access" => {
                *cols.op_c_access.value_mut() = event.c.wrapping_add(1).into();
            }
            _ => {
                *cols.op_a_access.value_mut() = event.a.wrapping_add(1).into();
            }
        }
    }
    // BEAK-INSERT-END

"""
        helper_insert = helper_insert.replace("{OP_A_MUTATION}", op_a_mutation)
        if helper_anchor in contents:
            contents = contents.replace(helper_anchor, helper_anchor + helper_insert, 1)

    anchor = """        cols.is_memory = F::from_bool(
            instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction(),
        );"""
    guard = "// BEAK-INSERT: sp1.v4.is_memory_underconstrained"
    insert = """
        // BEAK-INSERT: sp1.v4.is_memory_underconstrained
        let beak_step = fuzzer_utils::__BEAK_MEMORY_SELECTOR_STEP_FN__();
        let beak_expected_is_memory =
            instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction();
        if beak_expected_is_memory && fuzzer_utils::should_inject_witness(
            "sp1.semantic.exec.memory_effect_binding",
            beak_step,
        ) {
            let beak_funct3 = match instruction.opcode {
                sp1_core_executor::Opcode::LB | sp1_core_executor::Opcode::SB => 0,
                sp1_core_executor::Opcode::LH | sp1_core_executor::Opcode::SH => 1,
                sp1_core_executor::Opcode::LW | sp1_core_executor::Opcode::SW => 2,
                sp1_core_executor::Opcode::LBU => 4,
                sp1_core_executor::Opcode::LHU => 5,
                _ => unreachable!("memory selector hook is memory-only"),
            };
            let beak_imm = instruction.op_c & 0x0fff;
            let beak_rv_instruction = if instruction.is_memory_load_instruction() {
                (beak_imm << 20)
                    | ((instruction.op_b & 31) << 15)
                    | (beak_funct3 << 12)
                    | ((instruction.op_a as u32 & 31) << 7)
                    | 0x03
            } else {
                (((beak_imm >> 5) & 0x7f) << 25)
                    | ((instruction.op_a as u32 & 31) << 20)
                    | ((instruction.op_b & 31) << 15)
                    | (beak_funct3 << 12)
                    | ((beak_imm & 0x1f) << 7)
                    | 0x23
            };
            cols.is_memory = F::zero();
            let _ = fuzzer_utils::record_memory_selector_receipt(
                "sp1.semantic.exec.memory_effect_binding",
                beak_step,
                __BEAK_MEMORY_SELECTOR_OP_IDX__,
                event.pc,
                beak_rv_instruction,
                instruction.opcode as u32,
                instruction.opcode.mnemonic(),
                "__BEAK_SP1_COMMIT__",
                beak_expected_is_memory,
                1,
                0,
            );
        }
        // BEAK-INSERT-END
"""
    insert = insert.replace("__BEAK_SP1_COMMIT__", commit_or_branch)
    insert = insert.replace("__BEAK_MEMORY_SELECTOR_STEP_FN__", memory_selector_step_fn)
    insert = insert.replace("__BEAK_MEMORY_SELECTOR_OP_IDX__", memory_selector_op_idx)
    legacy_insert = """
        // BEAK-INSERT: sp1.v4.is_memory_underconstrained
        let beak_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness(
            "sp1.semantic.exec.memory_effect_binding",
            beak_step,
        ) {
            cols.is_memory = F::zero();
        }
        // BEAK-INSERT-END
"""
    if legacy_insert in contents:
        contents = contents.replace(legacy_insert, insert, 1)
    elif guard not in contents:
        if anchor in contents:
            contents = contents.replace(anchor, anchor + insert, 1)
    contents = _replace_guarded_block(contents, guard=guard, replacement=insert)

    cpu_anchor = """        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(record, blu_events);
        }"""
    cpu_guard = "// BEAK-INSERT: sp1.v4.cpu_semantic_injection.row"
    if cpu_guard not in contents:
        cpu_insert = """

        // BEAK-INSERT: sp1.v4.cpu_semantic_injection.row
        let beak_step = fuzzer_utils::next_witness_step();
        if let Some(beak_kind) = Self::beak_cpu_semantic_injection_kind(beak_step) {
            Self::beak_mutate_cpu_semantic_row(cols, event, beak_kind.as_str());
        }
        // BEAK-INSERT-END"""
        if cpu_anchor in contents:
            contents = contents.replace(cpu_anchor, cpu_anchor + cpu_insert, 1)

    path.write_text(contents)


def _patch_legacy_cpu_trace(path: Path) -> None:
    contents = path.read_text()

    contents = _ensure_fuzzer_utils_import(path, contents)

    helper_guard = "// BEAK-INSERT: sp1.356.cpu_semantic_injection.helpers"
    if helper_guard not in contents:
        helper_anchor = "impl CpuChip {\n"
        helper_insert = """// BEAK-INSERT: sp1.356.cpu_semantic_injection.helpers
    fn beak_cpu_semantic_injection_kind(step: u64) -> Option<String> {
        [
            "sp1.semantic.decode.zero_register_immutability",
            "sp1.semantic.decode.operand_index_routing",
            "sp1.semantic.exec.dest_binding",
            "sp1.semantic.decode.field_range",
            "sp1.semantic.decode.immediate_sign_extension",
            "sp1.semantic.decode.format_immediate_reassembly",
            "sp1.semantic.exec.op_selector_binding",
        ]
        .iter()
        .find_map(|kind| fuzzer_utils::matching_injection_kind(kind, step))
    }

    fn beak_mutate_cpu_semantic_row<F: PrimeField32>(
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        inject_kind: &str,
    ) {
        let site = fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("auto");
        match site {
            "opcode" => {
                cols.instruction.opcode = F::zero();
            }
            "instruction_op_a" => {
                cols.instruction.op_a = ((event.instruction.op_a & 31).wrapping_add(1) & 31).into();
                cols.instruction.op_a_0 = F::zero();
            }
            "instruction_op_b" => {
                cols.instruction.op_b = event.instruction.op_b.wrapping_add(1).into();
            }
            "instruction_op_c" => {
                cols.instruction.op_c = event.instruction.op_c.wrapping_add(1).into();
            }
            "op_a_access" => {
                *cols.op_a_access.value_mut() = event.a.wrapping_add(1).into();
            }
            "op_b_access" => {
                *cols.op_b_access.value_mut() = event.b.wrapping_add(1).into();
            }
            "op_c_access" => {
                *cols.op_c_access.value_mut() = event.c.wrapping_add(1).into();
            }
            _ => {
                *cols.op_a_access.value_mut() = event.a.wrapping_add(1).into();
            }
        }
    }
    // BEAK-INSERT-END

"""
        if helper_anchor in contents:
            contents = contents.replace(helper_anchor, helper_anchor + helper_insert, 1)

    row_anchor = """        // Assert that the instruction is not a no-op.
        cols.is_real = F::one();"""
    row_guard = "// BEAK-INSERT: sp1.356.cpu_semantic_injection.row"
    if row_guard not in contents:
        row_insert = """

        // BEAK-INSERT: sp1.356.cpu_semantic_injection.row
        let beak_step = fuzzer_utils::next_executor_step();
        if let Some(beak_kind) = Self::beak_cpu_semantic_injection_kind(beak_step) {
            Self::beak_mutate_cpu_semantic_row(cols, event, beak_kind.as_str());
        }
        // BEAK-INSERT-END"""
        if row_anchor in contents:
            contents = contents.replace(row_anchor, row_anchor + row_insert, 1)

    path.write_text(contents)


def _patch_v4_add_sub(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    anchor = "                        self.event_to_row(event, cols, &mut byte_lookup_events);"
    guard = "// BEAK-INSERT: sp1.v4.add_sub_chip_semantic_injection.row"
    insert = """

                        // BEAK-INSERT: sp1.v4.add_sub_chip_semantic_injection.row
                        let beak_step = (event.pc / 4) as u64;
                        if fuzzer_utils::should_inject_witness(
                            "sp1.semantic.alu.immediate_limb_consistency",
                            beak_step,
                        ) || fuzzer_utils::should_inject_witness(
                            "sp1.semantic.alu.subtraction_borrow_chain",
                            beak_step,
                        ) {
                            cols.add_operation.value[0] = cols.add_operation.value[0] + F::one();
                        }
                        // BEAK-INSERT-END"""
    path.write_text(_insert_after_once(contents, anchor, insert, guard))


def _patch_v4_bitwise(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    anchor = "                self.event_to_row(event, cols, &mut blu);"
    guard = "// BEAK-INSERT: sp1.v4.bitwise_chip_semantic_injection.row"
    insert = """

                // BEAK-INSERT: sp1.v4.bitwise_chip_semantic_injection.row
                let beak_step = (event.pc / 4) as u64;
                if fuzzer_utils::should_inject_witness(
                    "sp1.semantic.alu.immediate_limb_consistency",
                    beak_step,
                ) {
                    cols.c[0] = cols.c[0] + F::one();
                }
                // BEAK-INSERT-END"""
    path.write_text(_insert_after_once(contents, anchor, insert, guard))


def _patch_v4_lt(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    anchor = "                        self.event_to_row(event, cols, &mut byte_lookup_events);"
    guard = "// BEAK-INSERT: sp1.v4.lt_chip_semantic_injection.row"
    insert = """

                        // BEAK-INSERT: sp1.v4.lt_chip_semantic_injection.row
                        let beak_step = (event.pc / 4) as u64;
                        if fuzzer_utils::should_inject_witness(
                            "sp1.semantic.alu.immediate_limb_consistency",
                            beak_step,
                        ) {
                            cols.c[0] = cols.c[0] + F::one();
                        }
                        if fuzzer_utils::should_inject_witness(
                            "sp1.semantic.alu.comparison_booleanity",
                            beak_step,
                        ) {
                            cols.sltu = F::one() - cols.sltu;
                        }
                        if fuzzer_utils::should_inject_witness(
                            "sp1.semantic.alu.subtraction_borrow_chain",
                            beak_step,
                        ) || fuzzer_utils::should_inject_witness(
                            "sp1.semantic.alu.comparison_auxiliary_chain",
                            beak_step,
                        ) {
                            cols.byte_flags[0] = F::one() - cols.byte_flags[0];
                        }
                        // BEAK-INSERT-END"""
    path.write_text(_insert_after_once(contents, anchor, insert, guard))


def _patch_v4_shift(path: Path, guard_name: str, anchor: str, indent: str) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    guard = f"// BEAK-INSERT: {guard_name}"
    insert = (
        "\n\n"
        f"{indent}// BEAK-INSERT: {guard_name}\n"
        f"{indent}let beak_step = (event.pc / 4) as u64;\n"
        f"{indent}if fuzzer_utils::should_inject_witness(\n"
        f'{indent}    "sp1.semantic.alu.immediate_limb_consistency",\n'
        f"{indent}    beak_step,\n"
        f"{indent}) {{\n"
        f"{indent}    cols.c[0] = cols.c[0] + F::one();\n"
        f"{indent}}}\n"
        f"{indent}if fuzzer_utils::should_inject_witness(\n"
        f'{indent}    "sp1.semantic.alu.shift_mod32",\n'
        f"{indent}    beak_step,\n"
        f"{indent}) {{\n"
        f"{indent}    cols.bit_shift_result[0] = cols.bit_shift_result[0] + F::one();\n"
        f"{indent}}}\n"
        f"{indent}// BEAK-INSERT-END"
    )
    path.write_text(_insert_after_once(contents, anchor, insert, guard))


def _patch_v4_mul(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    anchor = "                        self.event_to_row(event, cols, &mut byte_lookup_events);"
    guard = "// BEAK-INSERT: sp1.v4.mul_chip_semantic_injection.row"
    insert = """

                        // BEAK-INSERT: sp1.v4.mul_chip_semantic_injection.row
                        let beak_step = (event.pc / 4) as u64;
                        if fuzzer_utils::should_inject_witness(
                            "sp1.semantic.arithmetic.product_decomposition",
                            beak_step,
                        ) {
                            cols.product[0] = cols.product[0] + F::one();
                        }
                        if event.opcode == Opcode::MULHSU
                            && fuzzer_utils::should_inject_witness(
                                "sp1.semantic.arithmetic.signed_unsigned_product_correction",
                                beak_step,
                            )
                        {
                            cols.b_sign_extend = F::one() - cols.b_sign_extend;
                        }
                        // BEAK-INSERT-END"""
    path.write_text(_insert_after_once(contents, anchor, insert, guard))


def _patch_v4_divrem(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    anchor = "            rows.push(row);"
    guard = "// BEAK-INSERT: sp1.v4.divrem_chip_semantic_injection.row"
    insert = """
            // BEAK-INSERT: sp1.v4.divrem_chip_semantic_injection.row
            let beak_step = (event.pc / 4) as u64;
            if fuzzer_utils::should_inject_witness(
                "sp1.semantic.arithmetic.special_case_consistency",
                beak_step,
            ) {
                cols.quotient[0] = cols.quotient[0] + F::one();
            }
            if fuzzer_utils::should_inject_witness(
                "sp1.semantic.arithmetic.division_remainder_bound",
                beak_step,
            ) {
                cols.remainder[0] = cols.remainder[0] + F::one();
            }
            // BEAK-INSERT-END

"""
    path.write_text(_insert_before_once(contents, anchor, insert, guard))


def _patch_v4_memory_instructions(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())

    helper_guard = "// BEAK-INSERT: sp1.v4.memory_instr_semantic_injection.helpers"
    if helper_guard not in contents:
        helper_anchor = "impl MemoryInstructionsChip {\n"
        helper_insert = """// BEAK-INSERT: sp1.v4.memory_instr_semantic_injection.helpers
    fn beak_memory_semantic_injection_kind(step: u64) -> Option<String> {
        [
            "sp1.semantic.memory.address_pointer_consistency",
            "sp1.semantic.memory.value_payload_consistency",
            "sp1.semantic.memory.store_load_payload_flow",
            "sp1.semantic.memory.kind_selector_consistency",
            "sp1.semantic.time.monotonic_access_ordering",
        ]
        .iter()
        .find_map(|kind| fuzzer_utils::matching_injection_kind(kind, step))
    }

    fn beak_mutate_memory_semantic_row<F: PrimeField32>(
        cols: &mut MemoryInstructionsColumns<F>,
        inject_kind: &str,
    ) {
        let site = fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("auto");
        match site {
            "addr_aligned" => {
                cols.addr_aligned = cols.addr_aligned + F::one();
            }
            "access_value" => {
                cols.memory_access.access.value[0] =
                    cols.memory_access.access.value[0] + F::one();
            }
            "prev_value" => {
                cols.memory_access.prev_value[0] = cols.memory_access.prev_value[0] + F::one();
            }
            "unsigned_mem_val" => {
                cols.unsigned_mem_val[0] = cols.unsigned_mem_val[0] + F::one();
            }
            "kind_selector" => {
                cols.is_lw = F::one() - cols.is_lw;
            }
            "prev_clk" => {
                cols.memory_access.access.prev_clk = cols.memory_access.access.prev_clk + F::one();
            }
            _ => {
                cols.addr_word[0] = cols.addr_word[0] + F::one();
            }
        }
    }
    // BEAK-INSERT-END

"""
        contents = _insert_after_once(contents, helper_anchor, helper_insert, helper_guard)

    guard = "// BEAK-INSERT: sp1.v4.memory_instr_semantic_injection.row"
    insert = """

                            // BEAK-INSERT: sp1.v4.memory_instr_semantic_injection.row
                            let beak_step = idx as u64;
                            if let Some(beak_kind) =
                                Self::beak_memory_semantic_injection_kind(beak_step)
                            {
                                Self::beak_mutate_memory_semantic_row(cols, beak_kind.as_str());
                            }
                            // BEAK-INSERT-END"""
    anchors = [
        "                            self.event_to_row(event, cols, &mut blu);",
        """                            self.event_to_row(
                                event,
                                cols,
                                &input.nonce_lookup,
                                &mut byte_lookup_events,
                            );""",
    ]
    for anchor in anchors:
        updated = _insert_after_once(contents, anchor, insert, guard)
        if updated != contents:
            contents = updated
            break

    path.write_text(contents)


def _patch_v4_syscall_instr_padding(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    latest_syscall_shape = "impl<M: TrustMode> SyscallInstrsChip<M> {\n" in contents

    helper_guard = "// BEAK-INSERT: sp1.v4.syscall_instr_padding_semantic_injection.helpers"
    if helper_guard not in contents:
        helper_anchor = (
            "impl<M: TrustMode> SyscallInstrsChip<M> {\n"
            if latest_syscall_shape
            else "impl SyscallInstrsChip {\n"
        )
        helper_insert = """// BEAK-INSERT: sp1.v4.syscall_instr_padding_semantic_injection.helpers
    fn beak_syscall_instr_padding_injection_kind(step: u64) -> Option<String> {
        fuzzer_utils::matching_injection_kind(
            "sp1.semantic.row.padding_interaction_send",
            step,
        )
    }

    fn beak_syscall_instr_padding_kind_matches(inject_kind: &str) -> bool {
        fuzzer_utils::injection_variant_value(inject_kind, "site")
            .map(|site| site == "syscall_instr_padding_send_table")
            .unwrap_or(true)
    }

    fn beak_mutate_syscall_instr_padding_row<F: PrimeField32>(
        cols: &mut {SYSCALL_COLS},
    ) {
        {MUTATE_PADDING_ROW}
    }
    // BEAK-INSERT-END

"""
        if latest_syscall_shape:
            helper_insert = helper_insert.replace("{SYSCALL_COLS}", "SyscallInstrColumns<F, M>")
            helper_insert = helper_insert.replace(
                "{MUTATE_PADDING_ROW}",
                "cols.is_real = F::one();\n        cols.next_pc[0] = F::one();",
            )
        else:
            helper_insert = helper_insert.replace("{SYSCALL_COLS}", "SyscallInstrColumns<F>")
            helper_insert = helper_insert.replace(
                "{MUTATE_PADDING_ROW}",
                "cols.op_a_access.prev_value[1] = F::one();",
            )
        contents = _insert_after_once(contents, helper_anchor, helper_insert, helper_guard)

    guard = "// BEAK-INSERT: sp1.v4.syscall_instr_padding_semantic_injection.row"
    if latest_syscall_shape:
        anchor = """        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width)
        };
"""
        insert = """        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width)
        };

        // BEAK-INSERT: sp1.v4.syscall_instr_padding_semantic_injection.row
        if padded_nb_rows > num_event_rows {
            let padding_row = unsafe {
                core::slice::from_raw_parts_mut(
                    buffer_ptr.add(num_event_rows * width),
                    width,
                )
            };
            let cols: &mut SyscallInstrColumns<F, M> = padding_row.borrow_mut();
            if let Some(beak_kind) =
                Self::beak_syscall_instr_padding_injection_kind(num_event_rows as u64)
            {
                if Self::beak_syscall_instr_padding_kind_matches(beak_kind.as_str()) {
                    Self::beak_mutate_syscall_instr_padding_row(cols);
                }
            }
        }
        // BEAK-INSERT-END
"""
        contents = _insert_after_once(contents, anchor, insert[len(anchor):], guard)
        one_line_anchor = (
            "        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, "
            "num_event_rows * width) };\n"
        )
        one_line_insert = """
        // BEAK-INSERT: sp1.v4.syscall_instr_padding_semantic_injection.row
        if padded_nb_rows > num_event_rows {
            let padding_row = unsafe {
                core::slice::from_raw_parts_mut(
                    buffer_ptr.add(num_event_rows * width),
                    width,
                )
            };
            let cols: &mut SyscallInstrColumns<F, M> = padding_row.borrow_mut();
            if let Some(beak_kind) =
                Self::beak_syscall_instr_padding_injection_kind(num_event_rows as u64)
            {
                if Self::beak_syscall_instr_padding_kind_matches(beak_kind.as_str()) {
                    Self::beak_mutate_syscall_instr_padding_row(cols);
                }
            }
        }
        // BEAK-INSERT-END
"""
        contents = _insert_after_once(contents, one_line_anchor, one_line_insert, guard)
    else:
        anchor = """                    if idx < input.syscall_events.len() {
                        let event = &input.syscall_events[idx];
                        self.event_to_row(event, cols, &mut blu);
                    }"""
        insert = """

                    // BEAK-INSERT: sp1.v4.syscall_instr_padding_semantic_injection.row
                    if idx >= input.syscall_events.len() {
                        if let Some(beak_kind) =
                            Self::beak_syscall_instr_padding_injection_kind(idx as u64)
                        {
                            if Self::beak_syscall_instr_padding_kind_matches(beak_kind.as_str()) {
                                Self::beak_mutate_syscall_instr_padding_row(cols);
                            }
                        }
                    }
                    // BEAK-INSERT-END"""
        contents = _insert_after_once(contents, anchor, insert, guard)

    path.write_text(contents)


def _patch_v4_sha_extend_precompile(path: Path) -> None:
    contents = path.read_text()
    if "cols.w_ptr = [" in contents or ".access_timestamp" in contents:
        return
    contents = _ensure_fuzzer_utils_import(path, contents)

    helper_guard = "// BEAK-INSERT: sp1.v4.sha_extend_precompile_address_injection.helpers"
    if helper_guard not in contents:
        helper_anchor = "impl ShaExtendChip {\n"
        helper_insert = """// BEAK-INSERT: sp1.v4.sha_extend_precompile_address_injection.helpers
    fn beak_precompile_address_injection_kind(step: u64) -> Option<String> {
        let inject_kind =
            std::env::var("BEAK_SP1_WITNESS_INJECT_KIND").unwrap_or_default();
        if fuzzer_utils::injection_variant_value(
            inject_kind.as_str(),
            "site",
        ) == Some("precompile_global_alignment")
        {
            return None;
        }
        fuzzer_utils::matching_injection_kind(
            "sp1.semantic.memory.address_pointer_consistency",
            step,
        )
    }

    fn beak_variant_u32(inject_kind: &str, key: &str) -> Option<u32> {
        fuzzer_utils::injection_variant_value(inject_kind, key)?.parse().ok()
    }

    fn beak_sha_extend_site(inject_kind: &str) -> &str {
        let site = fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("addr_word");
        if site == "precompile_slice" {
            if fuzzer_utils::injection_variant_value(inject_kind, "phase")
                .map(|phase| phase.starts_with("sha_extend."))
                .unwrap_or(false)
            {
                return "sha_extend_w_slice";
            }
        }
        site
    }

    fn beak_sha_extend_phase_ptr(w_ptr: u32, phase: &str) -> Option<u32> {
        match phase {
            "sha_extend.w_i_minus_15_read" => Some(w_ptr.wrapping_add(4)),
            "sha_extend.w_i_minus_2_read" => Some(w_ptr.wrapping_add(56)),
            "sha_extend.w_i_minus_16_read" => Some(w_ptr),
            "sha_extend.w_i_minus_7_read" => Some(w_ptr.wrapping_add(36)),
            "sha_extend.w_i_write" => Some(w_ptr.wrapping_add(64)),
            _ => None,
        }
    }

    fn beak_sha_extend_effective_ptr_matches(inject_kind: &str, w_ptr: u32) -> bool {
        let Some(target_ptr) = Self::beak_variant_u32(inject_kind, "effective_ptr") else {
            return true;
        };
        if let Some(phase) = fuzzer_utils::injection_variant_value(inject_kind, "phase") {
            return Self::beak_sha_extend_phase_ptr(w_ptr, phase)
                .map(|phase_ptr| phase_ptr == target_ptr)
                .unwrap_or(false);
        }
        [
            "sha_extend.w_i_minus_15_read",
            "sha_extend.w_i_minus_2_read",
            "sha_extend.w_i_minus_16_read",
            "sha_extend.w_i_minus_7_read",
            "sha_extend.w_i_write",
        ]
        .iter()
        .filter_map(|phase| Self::beak_sha_extend_phase_ptr(w_ptr, phase))
        .any(|phase_ptr| phase_ptr == target_ptr)
    }

    fn beak_mutate_sha_extend_address_row<F: PrimeField32>(
        cols: &mut ShaExtendCols<F>,
        inject_kind: &str,
        w_ptr: u32,
    ) {
        let site = Self::beak_sha_extend_site(inject_kind);
        match site {
            "precompile_global_alignment" => {}
            "sha_extend_w_slice" => {
                if Self::beak_sha_extend_effective_ptr_matches(inject_kind, w_ptr) {
                    cols.w_ptr = cols.w_ptr + F::one();
                }
            }
            "access_value" => {
                cols.w_i_minus_16.access.value[0] =
                    cols.w_i_minus_16.access.value[0] + F::one();
            }
            "prev_clk" => {
                cols.w_i_minus_16.access.prev_clk = cols.w_i_minus_16.access.prev_clk + F::one();
            }
            _ => {
                cols.w_ptr = cols.w_ptr + F::one();
            }
        }
    }
    // BEAK-INSERT-END

"""
        contents = _insert_after_once(contents, helper_anchor, helper_insert, helper_guard)

    guard = "// BEAK-INSERT: sp1.v4.sha_extend_precompile_address_injection.row"
    insert = """

            // BEAK-INSERT: sp1.v4.sha_extend_precompile_address_injection.row
            if let Some(beak_kind) =
                Self::beak_precompile_address_injection_kind(event.clk as u64)
            {
                Self::beak_mutate_sha_extend_address_row(cols, beak_kind.as_str(), event.w_ptr);
            }
            // BEAK-INSERT-END"""
    anchor = "            cols.w_i.populate(event.w_i_writes[j], blu);"
    contents = _insert_after_once(contents, anchor, insert, guard)

    path.write_text(contents)


def _patch_v4_sha_compress_precompile(path: Path) -> None:
    contents = path.read_text()
    if "cols.w_ptr = [" in contents or ".access_timestamp" in contents:
        return
    contents = _ensure_fuzzer_utils_import(path, contents)

    helper_guard = "// BEAK-INSERT: sp1.v4.sha_compress_precompile_address_injection.helpers"
    if helper_guard not in contents:
        helper_anchor = "impl ShaCompressChip {\n"
        helper_insert = """// BEAK-INSERT: sp1.v4.sha_compress_precompile_address_injection.helpers
    fn beak_precompile_address_injection_kind(step: u64) -> Option<String> {
        let inject_kind =
            std::env::var("BEAK_SP1_WITNESS_INJECT_KIND").unwrap_or_default();
        if fuzzer_utils::injection_variant_value(
            inject_kind.as_str(),
            "site",
        ) == Some("precompile_global_alignment")
        {
            return None;
        }
        fuzzer_utils::matching_injection_kind(
            "sp1.semantic.memory.address_pointer_consistency",
            step,
        )
    }

    fn beak_variant_u32(inject_kind: &str, key: &str) -> Option<u32> {
        fuzzer_utils::injection_variant_value(inject_kind, key)?.parse().ok()
    }

    fn beak_sha_compress_site(inject_kind: &str) -> &str {
        let site = fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("addr_word");
        if site != "precompile_slice" {
            return site;
        }
        match fuzzer_utils::injection_variant_value(inject_kind, "phase") {
            Some("sha_compress.w_read") => "sha_compress_w_slice",
            Some("sha_compress.h_read") | Some("sha_compress.h_write") => {
                "sha_compress_h_slice"
            }
            _ => site,
        }
    }

    fn beak_sha_compress_phase_matches(inject_kind: &str, phases: &[&str]) -> bool {
        fuzzer_utils::injection_variant_value(inject_kind, "phase")
            .map(|phase| phases.iter().any(|expected| phase == *expected))
            .unwrap_or(true)
    }

    fn beak_sha_compress_effective_ptr_matches(
        inject_kind: &str,
        effective_ptr: u32,
    ) -> bool {
        Self::beak_variant_u32(inject_kind, "effective_ptr")
            .map(|ptr| ptr == effective_ptr)
            .unwrap_or(true)
    }

    fn beak_mutate_sha_compress_address_row<F: PrimeField32>(
        cols: &mut ShaCompressCols<F>,
        inject_kind: &str,
        row_phase: &str,
        w_ptr: u32,
        h_ptr: u32,
    ) {
        let site = Self::beak_sha_compress_site(inject_kind);
        match site {
            "precompile_global_alignment" => {}
            "sha_compress_w_slice" => {
                if !Self::beak_sha_compress_phase_matches(inject_kind, &["sha_compress.w_read"]) {
                    return;
                }
                if !Self::beak_sha_compress_effective_ptr_matches(inject_kind, w_ptr) {
                    return;
                }
                cols.w_ptr = cols.w_ptr + F::one();
                if row_phase == "sha_compress.w_read" {
                    cols.mem_addr = cols.mem_addr + F::one();
                }
            }
            "sha_compress_h_slice" => {
                if !Self::beak_sha_compress_phase_matches(
                    inject_kind,
                    &["sha_compress.h_read", "sha_compress.h_write"],
                ) {
                    return;
                }
                if !Self::beak_sha_compress_effective_ptr_matches(inject_kind, h_ptr) {
                    return;
                }
                cols.h_ptr = cols.h_ptr + F::one();
                if row_phase == "sha_compress.h_read" || row_phase == "sha_compress.h_write" {
                    cols.mem_addr = cols.mem_addr + F::one();
                }
            }
            "w_ptr" => {
                cols.w_ptr = cols.w_ptr + F::one();
            }
            "h_ptr" => {
                cols.h_ptr = cols.h_ptr + F::one();
            }
            "access_value" => {
                cols.mem.access.value[0] = cols.mem.access.value[0] + F::one();
            }
            "prev_clk" => {
                cols.mem.access.prev_clk = cols.mem.access.prev_clk + F::one();
            }
            _ => {
                cols.mem_addr = cols.mem_addr + F::one();
            }
        }
    }
    // BEAK-INSERT-END

"""
        contents = _insert_after_once(contents, helper_anchor, helper_insert, helper_guard)

    inserts = [
        (
            "            cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];",
            """
            // BEAK-INSERT: sp1.v4.sha_compress_precompile_address_injection.init_row
            if let Some(beak_kind) =
                Self::beak_precompile_address_injection_kind(event.clk as u64)
            {
                Self::beak_mutate_sha_compress_address_row(
                    cols,
                    beak_kind.as_str(),
                    "sha_compress.h_read",
                    event.w_ptr,
                    event.h_ptr,
                );
            }
            // BEAK-INSERT-END
""",
            "// BEAK-INSERT: sp1.v4.sha_compress_precompile_address_injection.init_row",
        ),
        (
            "            if rows.as_ref().is_some() {\n                rows.as_mut().unwrap().push(row);\n            }\n        }\n\n        let mut v:",
            """            // BEAK-INSERT: sp1.v4.sha_compress_precompile_address_injection.compression_row
            if let Some(beak_kind) =
                Self::beak_precompile_address_injection_kind(event.clk as u64)
            {
                Self::beak_mutate_sha_compress_address_row(
                    cols,
                    beak_kind.as_str(),
                    "sha_compress.w_read",
                    event.w_ptr,
                    event.h_ptr,
                );
            }
            // BEAK-INSERT-END

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }

        let mut v:""",
            "// BEAK-INSERT: sp1.v4.sha_compress_precompile_address_injection.compression_row",
        ),
        (
            "            cols.is_last_row = cols.octet[7] * cols.octet_num[9];\n            cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];",
            """            cols.is_last_row = cols.octet[7] * cols.octet_num[9];
            cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];
            // BEAK-INSERT: sp1.v4.sha_compress_precompile_address_injection.finalize_row
            if let Some(beak_kind) =
                Self::beak_precompile_address_injection_kind(event.clk as u64)
            {
                Self::beak_mutate_sha_compress_address_row(
                    cols,
                    beak_kind.as_str(),
                    "sha_compress.h_write",
                    event.w_ptr,
                    event.h_ptr,
                );
            }
            // BEAK-INSERT-END""",
            "// BEAK-INSERT: sp1.v4.sha_compress_precompile_address_injection.finalize_row",
        ),
    ]
    for anchor, insert, guard in inserts:
        if guard in contents:
            continue
        if anchor in contents:
            if "let mut v:" in anchor:
                contents = contents.replace(anchor, insert, 1)
            else:
                contents = contents.replace(anchor, insert, 1)

    path.write_text(contents)


def _patch_v4_memory_global(path: Path) -> None:
    contents = path.read_text()
    contents = _ensure_fuzzer_utils_import(path, contents)
    contents = contents.replace(
        '            "sp1.semantic.memory.finalization_consistency" => {\n'
        "                if !matches!(self.kind, MemoryChipType::Finalize) {\n"
        "                    return false;\n"
        "                }\n"
        "            }\n"
        "            _ => return false,\n",
        '            "sp1.semantic.memory.finalization_consistency" => {\n'
        "                if !matches!(self.kind, MemoryChipType::Finalize) {\n"
        "                    return false;\n"
        "                }\n"
        "            }\n"
        '            "sp1.semantic.memory.initial_value_binding" => {\n'
        "                if !matches!(self.kind, MemoryChipType::Initialize) {\n"
        "                    return false;\n"
        "                }\n"
        "            }\n"
        "            _ => return false,\n",
    )
    contents = contents.replace(
        '            "sp1.semantic.memory.finalization_consistency",\n'
        "        ]\n",
        '            "sp1.semantic.memory.finalization_consistency",\n'
        '            "sp1.semantic.memory.initial_value_binding",\n'
        "        ]\n",
    )
    contents = contents.replace(
        '            "sp1.semantic.memory.finalization_consistency" => {\n'
        "                let site =\n"
        '                    fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("value");\n'
        "                match site {\n"
        '                    "timestamp" => {\n'
        "                        event.timestamp = event.timestamp.wrapping_add(1);\n"
        "                    }\n"
        "                    _ => {\n"
        "                        event.value = event.value.wrapping_add(1);\n"
        "                    }\n"
        "                }\n"
        "            }\n"
        "            _ => {\n",
        '            "sp1.semantic.memory.finalization_consistency" => {\n'
        "                let site =\n"
        '                    fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("value");\n'
        "                match site {\n"
        '                    "timestamp" => {\n'
        "                        event.timestamp = event.timestamp.wrapping_add(1);\n"
        "                    }\n"
        "                    _ => {\n"
        "                        event.value = event.value.wrapping_add(1);\n"
        "                    }\n"
        "                }\n"
        "            }\n"
        '            "sp1.semantic.memory.initial_value_binding" => {\n'
        "                event.value = event.value.wrapping_add(1);\n"
        "            }\n"
        "            _ => {\n",
    )

    helper_guard = "// BEAK-INSERT: sp1.v4.global_memory_address_injection.helpers"
    if helper_guard not in contents:
        helper_anchor = """impl MemoryGlobalChip {
    /// Creates a new memory chip with a certain type.
    pub const fn new(kind: MemoryChipType) -> Self {
        Self { kind }
    }
"""
        latest_limb_shape = "MemoryInitializeFinalizeEvent { addr, value, timestamp }" in contents
        if latest_limb_shape:
            helper_insert = """
    // BEAK-INSERT: sp1.v4.global_memory_address_injection.helpers
    fn beak_base_injection_kind(inject_kind: &str) -> &str {
        inject_kind
            .split_once("::")
            .map(|(base, _)| base)
            .unwrap_or(inject_kind)
    }

    fn beak_variant_u32(inject_kind: &str, key: &str) -> Option<u32> {
        fuzzer_utils::injection_variant_value(inject_kind, key)?.parse().ok()
    }

    fn beak_variant_u64(inject_kind: &str, key: &str) -> Option<u64> {
        fuzzer_utils::injection_variant_value(inject_kind, key)?.parse().ok()
    }

    fn beak_global_phase(&self) -> &'static str {
        match self.kind {
            MemoryChipType::Initialize => "initialize",
            MemoryChipType::Finalize => "finalize",
        }
    }

    fn beak_global_trace_source(&self) -> &'static str {
        match self.kind {
            MemoryChipType::Initialize => "global_memory_initialize_event",
            MemoryChipType::Finalize => "global_memory_finalize_event",
        }
    }

    fn beak_global_event_matches(
        &self,
        event: &MemoryInitializeFinalizeEvent,
        event_idx: u64,
        inject_kind: &str,
    ) -> bool {
        match Self::beak_base_injection_kind(inject_kind) {
            "sp1.semantic.memory.address_pointer_consistency" => {
                if fuzzer_utils::injection_variant_value(inject_kind, "site")
                    != Some("global_event")
                {
                    return false;
                }
            }
            "sp1.semantic.memory.finalization_consistency" => {
                if !matches!(self.kind, MemoryChipType::Finalize) {
                    return false;
                }
            }
            "sp1.semantic.memory.initial_value_binding" => {
                if !matches!(self.kind, MemoryChipType::Initialize) {
                    return false;
                }
            }
            _ => return false,
        }
        if let Some(phase) = fuzzer_utils::injection_variant_value(inject_kind, "phase") {
            if phase != self.beak_global_phase() {
                return false;
            }
        }
        if let Some(source) = fuzzer_utils::injection_variant_value(inject_kind, "trace_source") {
            if source != self.beak_global_trace_source() {
                return false;
            }
        }
        if let Some(ptr) = Self::beak_variant_u64(inject_kind, "effective_ptr") {
            if ptr != event.addr {
                return false;
            }
        }
        if let Some(target_event_idx) = Self::beak_variant_u64(inject_kind, "event_idx") {
            if target_event_idx != event_idx {
                return false;
            }
        }
        true
    }

    fn beak_global_injection_kind_for_event(event_timestamp: u64) -> Option<String> {
        [
            "sp1.semantic.memory.address_pointer_consistency",
            "sp1.semantic.memory.finalization_consistency",
            "sp1.semantic.memory.initial_value_binding",
        ]
        .iter()
        .find_map(|kind| fuzzer_utils::matching_injection_kind(kind, event_timestamp))
    }

    fn beak_mutate_global_event(
        event: &mut MemoryInitializeFinalizeEvent,
        inject_kind: &str,
    ) {
        match Self::beak_base_injection_kind(inject_kind) {
            "sp1.semantic.memory.finalization_consistency" => {
                let site =
                    fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("value");
                match site {
                    "timestamp" => {
                        event.timestamp = event.timestamp.wrapping_add(1);
                    }
                    _ => {
                        event.value = event.value.wrapping_add(1);
                    }
                }
            }
            "sp1.semantic.memory.initial_value_binding" => {
                event.value = event.value.wrapping_add(1);
            }
            _ => {
                event.addr = event.addr.wrapping_add(1);
            }
        }
    }

    fn beak_apply_global_injection(
        &self,
        memory_events: &mut [MemoryInitializeFinalizeEvent],
    ) {
        for (event_idx, event) in memory_events.iter_mut().enumerate() {
            if let Some(beak_kind) =
                Self::beak_global_injection_kind_for_event(event.timestamp)
            {
                if self.beak_global_event_matches(event, event_idx as u64, beak_kind.as_str()) {
                    Self::beak_mutate_global_event(event, beak_kind.as_str());
                }
            }
        }
    }
    // BEAK-INSERT-END
"""
        else:
            helper_insert = """
    // BEAK-INSERT: sp1.v4.global_memory_address_injection.helpers
    fn beak_global_address_injection_kind(step: u64) -> Option<String> {
        fuzzer_utils::matching_injection_kind(
            "sp1.semantic.memory.address_pointer_consistency",
            step,
        )
    }

    fn beak_base_injection_kind(inject_kind: &str) -> &str {
        inject_kind
            .split_once("::")
            .map(|(base, _)| base)
            .unwrap_or(inject_kind)
    }

    fn beak_env_global_address_injection_kind() -> Option<(String, u64)> {
        let inject_kind = std::env::var("BEAK_SP1_WITNESS_INJECT_KIND").ok()?;
        if inject_kind.is_empty()
            || Self::beak_base_injection_kind(inject_kind.as_str())
                != "sp1.semantic.memory.address_pointer_consistency"
        {
            return None;
        }
        let inject_step = std::env::var("BEAK_SP1_WITNESS_INJECT_STEP")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        Some((inject_kind, inject_step))
    }

    fn beak_global_address_injection_kind_for_event(event_timestamp: u32) -> Option<String> {
        if let Some(kind) = Self::beak_global_address_injection_kind(event_timestamp as u64) {
            return Some(kind);
        }
        let (kind, _inject_step) = Self::beak_env_global_address_injection_kind()?;
        if Self::beak_is_precompile_global_alignment(kind.as_str()) {
            return Some(kind);
        }
        None
    }

    fn beak_mark_global_address_injection(inject_kind: &str, event_timestamp: u32) {
        let step = if Self::beak_is_precompile_global_alignment(inject_kind) {
            Self::beak_env_global_address_injection_kind()
                .map(|(_, step)| step)
                .unwrap_or(event_timestamp as u64)
        } else {
            event_timestamp as u64
        };
        let _ = fuzzer_utils::matching_injection_kind(
            "sp1.semantic.memory.address_pointer_consistency",
            step,
        );
    }

    fn beak_variant_u32(inject_kind: &str, key: &str) -> Option<u32> {
        fuzzer_utils::injection_variant_value(inject_kind, key)?.parse().ok()
    }

    fn beak_variant_u64(inject_kind: &str, key: &str) -> Option<u64> {
        fuzzer_utils::injection_variant_value(inject_kind, key)?.parse().ok()
    }

    fn beak_is_precompile_global_alignment(inject_kind: &str) -> bool {
        fuzzer_utils::injection_variant_value(inject_kind, "site")
            == Some("precompile_global_alignment")
    }

    fn beak_precompile_slice_len_words(inject_kind: &str) -> Option<u32> {
        if let Some(len) = Self::beak_variant_u32(inject_kind, "slice_len_words") {
            if len > 0 {
                return Some(len);
            }
        }
        match fuzzer_utils::injection_variant_value(inject_kind, "phase") {
            Some("sha_compress.w_read") => Some(64),
            Some("sha_compress.h_read") | Some("sha_compress.h_write") => Some(8),
            _ => None,
        }
    }

    fn beak_precompile_global_alignment_addr(
        event_addr: u32,
        inject_kind: &str,
    ) -> Option<u32> {
        if !Self::beak_is_precompile_global_alignment(inject_kind) {
            return None;
        }
        if let Some(source) = fuzzer_utils::injection_variant_value(inject_kind, "trace_source") {
            if source != "precompile_events" {
                return None;
            }
        }
        let target_ptr = Self::beak_variant_u32(inject_kind, "effective_ptr")?;
        let len_words = Self::beak_precompile_slice_len_words(inject_kind)?;
        let aligned_start = target_ptr.wrapping_sub(target_ptr % 4);
        let span = (len_words as u64).saturating_mul(4);
        let event_addr_u64 = event_addr as u64;
        let aligned_start_u64 = aligned_start as u64;
        if event_addr_u64 < aligned_start_u64
            || event_addr_u64 >= aligned_start_u64.saturating_add(span)
        {
            return None;
        }
        let delta = event_addr_u64.saturating_sub(aligned_start_u64);
        if delta % 4 != 0 {
            return None;
        }
        Some(target_ptr.wrapping_add(delta as u32))
    }

    fn beak_global_phase(&self) -> &'static str {
        match self.kind {
            MemoryChipType::Initialize => "initialize",
            MemoryChipType::Finalize => "finalize",
        }
    }

    fn beak_global_trace_source(&self) -> &'static str {
        match self.kind {
            MemoryChipType::Initialize => "global_memory_initialize_event",
            MemoryChipType::Finalize => "global_memory_finalize_event",
        }
    }

    fn beak_global_event_matches(
        &self,
        event: &MemoryInitializeFinalizeEvent,
        event_idx: u64,
        inject_kind: &str,
    ) -> bool {
        if event.used == 0 {
            return false;
        }
        if Self::beak_is_precompile_global_alignment(inject_kind) {
            return Self::beak_precompile_global_alignment_addr(event.addr, inject_kind).is_some();
        }
        if fuzzer_utils::injection_variant_value(inject_kind, "site") != Some("global_event") {
            return false;
        }
        if let Some(phase) = fuzzer_utils::injection_variant_value(inject_kind, "phase") {
            if phase != self.beak_global_phase() {
                return false;
            }
        }
        if let Some(source) = fuzzer_utils::injection_variant_value(inject_kind, "trace_source") {
            if source != self.beak_global_trace_source() {
                return false;
            }
        }
        if let Some(ptr) = Self::beak_variant_u32(inject_kind, "effective_ptr") {
            if ptr != event.addr {
                return false;
            }
        }
        if let Some(target_event_idx) = Self::beak_variant_u64(inject_kind, "event_idx") {
            if target_event_idx != event_idx {
                return false;
            }
        }
        true
    }

    fn beak_mutate_global_address_event(
        event: &mut MemoryInitializeFinalizeEvent,
        inject_kind: &str,
    ) {
        if let Some(addr) = Self::beak_precompile_global_alignment_addr(event.addr, inject_kind) {
            event.addr = addr;
        } else {
            event.addr = event.addr.wrapping_add(1);
        }
    }

    fn beak_apply_global_address_injection(
        &self,
        memory_events: &mut [MemoryInitializeFinalizeEvent],
    ) {
        for (event_idx, event) in memory_events.iter_mut().enumerate() {
            if let Some(beak_kind) =
                Self::beak_global_address_injection_kind_for_event(event.timestamp)
            {
                if self.beak_global_event_matches(event, event_idx as u64, beak_kind.as_str()) {
                    Self::beak_mark_global_address_injection(beak_kind.as_str(), event.timestamp);
                    Self::beak_mutate_global_address_event(event, beak_kind.as_str());
                }
            }
        }
    }

    fn beak_mutate_global_address_row<F: PrimeField32>(
        cols: &mut MemoryInitCols<F>,
        inject_kind: &str,
    ) {
        let site = fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("addr_word");
        match site {
            "global_event" => {}
            "precompile_global_alignment" => {}
            "access_value" => {
                cols.value[0] = F::one() - cols.value[0];
            }
            "prev_clk" => {
                cols.timestamp = cols.timestamp + F::one();
            }
            _ => {
                cols.addr = cols.addr + F::one();
            }
        }
    }
    // BEAK-INSERT-END
"""
        contents = _insert_after_once(contents, helper_anchor, helper_insert, helper_guard)

    if "self.beak_apply_global_injection(&mut memory_events);" not in contents:
        anchor = """        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.global_memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_memory_finalize_events.clone(),
        };
"""
        if anchor in contents and "MemoryInitializeFinalizeEvent { addr, value, timestamp }" in contents:
            contents = contents.replace(
                anchor,
                anchor + "        self.beak_apply_global_injection(&mut memory_events);\n",
                2,
            )

    if "MemoryInitializeFinalizeEvent { addr, value, timestamp }" not in contents:
        guard = "// BEAK-INSERT: sp1.v4.global_memory_address_injection.row"
        insert = """

                // BEAK-INSERT: sp1.v4.global_memory_address_injection.row
                if used != 0 {
                    if let Some(beak_kind) =
                        Self::beak_global_address_injection_kind(timestamp as u64)
                    {
                        Self::beak_mutate_global_address_row(cols, beak_kind.as_str());
                    }
                }
                // BEAK-INSERT-END"""
        anchor = "                cols.is_real = F::from_canonical_u32(used);"
        contents = _insert_after_once(contents, anchor, insert, guard)

    apply_guard = "self.beak_apply_global_address_injection(&mut memory_events);"
    if apply_guard not in contents and "MemoryInitializeFinalizeEvent { addr, value, timestamp }" not in contents:
        anchor = """        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.global_memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_memory_finalize_events.clone(),
        };
"""
        contents = contents.replace(anchor, anchor + f"        {apply_guard}\n")

    path.write_text(contents)


def _patch_v4_byte_trace(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    if "NUM_BYTE_OPS" not in contents:
        contents = contents.replace("ByteChip,\n};", "ByteChip, NUM_BYTE_OPS,\n};", 1)

    anchor = "            cols.multiplicities[index] += F::from_canonical_usize(*mult);"
    guard = "// BEAK-INSERT: sp1.v4.byte_lookup_semantic_injection.row"
    insert = """

            // BEAK-INSERT: sp1.v4.byte_lookup_semantic_injection.row
            let beak_step = (row as u64)
                .saturating_mul(NUM_BYTE_OPS as u64)
                .saturating_add(index as u64);
            if fuzzer_utils::should_inject_witness(
                "sp1.semantic.lookup.boolean_multiplicity",
                beak_step,
            ) {
                cols.multiplicities[index] = cols.multiplicities[index] + F::one();
            }
            // BEAK-INSERT-END"""
    contents = _insert_after_once(contents, anchor, insert, guard)

    path.write_text(contents)


def _patch_v4_byte_record(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())

    helper_guard = "// BEAK-INSERT: sp1.v4.byte_record_semantic_injection.helpers"
    if helper_guard not in contents:
        legacy_event_shape = "pub fn new(opcode: ByteOpcode, a1: u16, a2: u8, b: u8, c: u8)" in contents
        helper_anchor = """impl ByteLookupEvent {
    /// Creates a new `ByteLookupEvent`.
    #[must_use]
"""
        if legacy_event_shape:
            helper_anchor += """    pub fn new(opcode: ByteOpcode, a1: u16, a2: u8, b: u8, c: u8) -> Self {
        Self { opcode, a1, a2, b, c }
    }
}
"""
            helper_insert = """
// BEAK-INSERT: sp1.v4.byte_record_semantic_injection.helpers
fn beak_byte_lookup_step(blu_event: ByteLookupEvent) -> u64 {
    let row = if blu_event.opcode != ByteOpcode::U16Range {
        (((blu_event.b as u16) << 8) + blu_event.c as u16) as u64
    } else {
        blu_event.a1 as u64
    };
    row.saturating_mul(NUM_BYTE_OPS as u64).saturating_add(blu_event.opcode as u64)
}
// BEAK-INSERT-END
"""
        else:
            helper_anchor += """    pub fn new(opcode: ByteOpcode, a: u16, b: u8, c: u8) -> Self {
        Self { opcode, a, b, c }
    }
}
"""
            helper_insert = """
// BEAK-INSERT: sp1.v4.byte_record_semantic_injection.helpers
fn beak_byte_lookup_step(blu_event: ByteLookupEvent) -> u64 {
    let row = if blu_event.opcode == ByteOpcode::Range {
        blu_event.a as u64
    } else {
        (((blu_event.b as u16) << 8) + blu_event.c as u16) as u64
    };
    row.saturating_mul(NUM_BYTE_OPS as u64).saturating_add(blu_event.opcode as u64)
}
// BEAK-INSERT-END
"""
        contents = _insert_after_once(contents, helper_anchor, helper_insert, helper_guard)

    anchor = "        self.entry(blu_event).and_modify(|e| *e += 1).or_insert(1);"
    guard = "// BEAK-INSERT: sp1.v4.byte_record_semantic_injection.row"
    insert = """        // BEAK-INSERT: sp1.v4.byte_record_semantic_injection.row
        let beak_step = beak_byte_lookup_step(blu_event);
        let beak_count = if fuzzer_utils::should_inject_witness(
            "sp1.semantic.lookup.boolean_multiplicity",
            beak_step,
        ) {
            2
        } else {
            1
        };
        self.entry(blu_event)
            .and_modify(|e| *e += beak_count)
            .or_insert(beak_count);"""
    if guard in contents:
        contents = contents.replace(anchor + "        // BEAK-INSERT", "        // BEAK-INSERT", 1)
        contents = contents.replace(anchor + "\n        // BEAK-INSERT", "        // BEAK-INSERT", 1)
    elif anchor in contents:
        contents = contents.replace(anchor, insert, 1)

    path.write_text(contents)


def _patch_v4_execution_record(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())

    helper_guard = "// BEAK-INSERT: sp1.v4.execution_record_byte_semantic_injection.helpers"
    helper_anchor = "impl ByteRecord for ExecutionRecord {\n"
    byte_event_path = path.parent / "events" / "byte.rs"
    legacy_event_shape = (
        byte_event_path.exists()
        and "pub a1: u16" in byte_event_path.read_text()
    )
    if legacy_event_shape:
        helper_insert = """// BEAK-INSERT: sp1.v4.execution_record_byte_semantic_injection.helpers
fn beak_execution_record_byte_lookup_step(blu_event: ByteLookupEvent) -> u64 {
    let row = if blu_event.opcode != crate::ByteOpcode::U16Range {
        (((blu_event.b as u16) << 8) + blu_event.c as u16) as u64
    } else {
        blu_event.a1 as u64
    };
    row.saturating_mul(9).saturating_add(blu_event.opcode as u64)
}

fn beak_execution_record_byte_lookup_count(blu_event: ByteLookupEvent, count: usize) -> usize {
    let beak_step = beak_execution_record_byte_lookup_step(blu_event);
    if fuzzer_utils::should_inject_witness(
        "sp1.semantic.lookup.boolean_multiplicity",
        beak_step,
    ) {
        count.saturating_add(1)
    } else {
        count
    }
}
// BEAK-INSERT-END

"""
    else:
        helper_insert = """// BEAK-INSERT: sp1.v4.execution_record_byte_semantic_injection.helpers
fn beak_execution_record_byte_lookup_step(blu_event: ByteLookupEvent) -> u64 {
    let row = if blu_event.opcode == crate::ByteOpcode::Range {
        blu_event.a as u64
    } else {
        (((blu_event.b as u16) << 8) + blu_event.c as u16) as u64
    };
    row.saturating_mul(crate::events::NUM_BYTE_OPS as u64)
        .saturating_add(blu_event.opcode as u64)
}

fn beak_execution_record_byte_lookup_count(blu_event: ByteLookupEvent, count: usize) -> usize {
    let beak_step = beak_execution_record_byte_lookup_step(blu_event);
    if fuzzer_utils::should_inject_witness(
        "sp1.semantic.lookup.boolean_multiplicity",
        beak_step,
    ) {
        count.saturating_add(1)
    } else {
        count
    }
}
// BEAK-INSERT-END

"""
    contents = _insert_before_once(contents, helper_anchor, helper_insert, helper_guard)

    direct_anchor = "        *self.byte_lookups.entry(blu_event).or_insert(0) += 1;"
    direct_guard = "// BEAK-INSERT: sp1.v4.execution_record_byte_semantic_injection.direct"
    direct_insert = """        // BEAK-INSERT: sp1.v4.execution_record_byte_semantic_injection.direct
        let beak_count = beak_execution_record_byte_lookup_count(blu_event, 1);
        *self.byte_lookups.entry(blu_event).or_insert(0) += beak_count;
        // BEAK-INSERT-END"""
    if direct_guard not in contents and direct_anchor in contents:
        contents = contents.replace(direct_anchor, direct_insert, 1)

    map_anchor = "                *self.byte_lookups.entry(*blu_event).or_insert(0) += count;"
    map_guard = "// BEAK-INSERT: sp1.v4.execution_record_byte_semantic_injection.map"
    map_insert = """                // BEAK-INSERT: sp1.v4.execution_record_byte_semantic_injection.map
                let beak_count = beak_execution_record_byte_lookup_count(*blu_event, *count);
                *self.byte_lookups.entry(*blu_event).or_insert(0) += beak_count;
                // BEAK-INSERT-END"""
    if map_guard not in contents and map_anchor in contents:
        contents = contents.replace(map_anchor, map_insert, 1)

    path.write_text(contents)


def _patch_v4_executor_tracing(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())

    helper_guard = "// BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.helpers"
    helper_anchor = "impl<M: ExecutionMode> TracingVM<'_, M> {\n"
    helper_insert = """    // BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.helpers
    fn beak_instruction_semantic_injection_kind(step: u64) -> Option<String> {
        [
            "sp1.semantic.decode.zero_register_immutability",
            "sp1.semantic.decode.operand_index_routing",
            "sp1.semantic.exec.dest_binding",
            "sp1.semantic.decode.field_range",
            "sp1.semantic.decode.immediate_sign_extension",
            "sp1.semantic.decode.upper_immediate_materialization",
            "sp1.semantic.decode.format_immediate_reassembly",
            "sp1.semantic.exec.op_selector_binding",
            "sp1.semantic.control.ecall_word_validity",
            "sp1.semantic.exec.memory_effect_binding",
        ]
        .iter()
        .find_map(|kind| fuzzer_utils::matching_injection_kind(kind, step))
    }

    fn beak_alu_semantic_injection_kind(opcode: Opcode, step: u64) -> Option<String> {
        let kinds: &[&str] = match opcode {
            Opcode::ADD | Opcode::ADDI | Opcode::XOR | Opcode::OR | Opcode::AND => {
                &["sp1.semantic.alu.immediate_limb_consistency"]
            }
            Opcode::SUB => &["sp1.semantic.alu.subtraction_borrow_chain"],
            Opcode::SLL | Opcode::SLLW | Opcode::SRL | Opcode::SRA | Opcode::SRLW | Opcode::SRAW => &[
                "sp1.semantic.alu.immediate_limb_consistency",
                "sp1.semantic.alu.shift_mod32",
            ],
            Opcode::SLT | Opcode::SLTU => &[
                "sp1.semantic.alu.immediate_limb_consistency",
                "sp1.semantic.alu.comparison_booleanity",
                "sp1.semantic.alu.subtraction_borrow_chain",
                "sp1.semantic.alu.comparison_auxiliary_chain",
            ],
            Opcode::DIV | Opcode::DIVU | Opcode::REM | Opcode::REMU | Opcode::DIVW | Opcode::DIVUW | Opcode::REMUW | Opcode::REMW => &[
                "sp1.semantic.arithmetic.special_case_consistency",
                "sp1.semantic.arithmetic.division_remainder_bound",
            ],
            Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU | Opcode::MULW => &[
                "sp1.semantic.arithmetic.product_decomposition",
                "sp1.semantic.arithmetic.signed_unsigned_product_correction",
            ],
            _ => &[],
        };
        kinds.iter().find_map(|kind| fuzzer_utils::matching_injection_kind(kind, step))
    }

    fn beak_memory_semantic_injection_kind(step: u64) -> Option<String> {
        [
            "sp1.semantic.memory.address_pointer_consistency",
            "sp1.semantic.memory.value_payload_consistency",
            "sp1.semantic.memory.store_load_payload_flow",
            "sp1.semantic.memory.kind_selector_consistency",
            "sp1.semantic.time.monotonic_access_ordering",
        ]
        .iter()
        .find_map(|kind| fuzzer_utils::matching_injection_kind(kind, step))
    }

    fn beak_control_semantic_injection_kind(step: u64) -> Option<String> {
        fuzzer_utils::matching_injection_kind(
            "sp1.semantic.exec.control_flow_binding",
            step,
        )
    }

    fn beak_boundary_origin_semantic_injection_kind(step: u64) -> Option<String> {
        fuzzer_utils::matching_injection_kind(
            "sp1.semantic.time.boundary_origin_consistency",
            step,
        )
    }

    fn beak_mutate_instruction_event(
        inject_kind: &str,
        opcode: &mut Opcode,
        a: &mut u64,
        b: &mut u64,
        c: &mut u64,
        op_a_0: &mut bool,
    ) {
        let site = fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("auto");
        match site {
            "opcode" => {
                *opcode = if *opcode == Opcode::ADD { Opcode::SUB } else { Opcode::ADD };
            }
            "instruction_op_b" | "op_b_access" => {
                *b = b.wrapping_add(1);
            }
            "instruction_op_c" | "op_c_access" => {
                *c = c.wrapping_add(1);
            }
            "instruction_op_a" | "op_a_access" | _ => {
                *a = a.wrapping_add(1);
                *op_a_0 = false;
            }
        }
    }

    fn beak_mutate_memory_event(inject_kind: &str, event: &mut MemInstrEvent) {
        let site = fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("auto");
        match site {
            "addr_word" | "kind_selector" => {
                event.b = event.b.wrapping_add(1);
            }
            "prev_clk" => match &mut event.mem_access {
                MemoryRecordEnum::Read(record) => {
                    record.prev_timestamp = record.prev_timestamp.wrapping_add(1);
                }
                MemoryRecordEnum::Write(record) => {
                    record.prev_timestamp = record.prev_timestamp.wrapping_add(1);
                }
            },
            "access_value" | _ => match &mut event.mem_access {
                MemoryRecordEnum::Read(record) => {
                    record.value = record.value.wrapping_add(1);
                }
                MemoryRecordEnum::Write(record) => {
                    record.value = record.value.wrapping_add(1);
                }
            },
        }
    }

    fn beak_mutate_boundary_origin_event(inject_kind: &str, clk: &mut u64, pc: &mut u64) {
        let site = fuzzer_utils::injection_variant_value(inject_kind, "site").unwrap_or("clk");
        match site {
            "pc" => {
                *pc = pc.wrapping_add(4);
            }
            _ => {
                *clk = clk.wrapping_add(1);
            }
        }
    }
    // BEAK-INSERT-END

"""
    if helper_guard not in contents and helper_anchor in contents:
        contents = contents.replace(helper_anchor, helper_anchor + helper_insert, 1)

    mem_guard = "// BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.mem"
    mem_anchor = """        let event = MemInstrEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            opcode,
            a,
            b,
            c,
            op_a_0,
            // SAFETY: We explicity populate the memory of the record on the following callsites:
            // - `execute_load`
            // - `execute_store`
            mem_access: unsafe { record.memory.unwrap_unchecked() },
        };
"""
    mem_insert = """        let mut event = MemInstrEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            opcode,
            a,
            b,
            c,
            op_a_0,
            // SAFETY: We explicity populate the memory of the record on the following callsites:
            // - `execute_load`
            // - `execute_store`
            mem_access: unsafe { record.memory.unwrap_unchecked() },
        };
        // BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.mem
        let beak_instruction_step = fuzzer_utils::next_executor_step();
        if let Some(beak_kind) =
            Self::beak_instruction_semantic_injection_kind(beak_instruction_step)
        {
            Self::beak_mutate_instruction_event(
                beak_kind.as_str(),
                &mut event.opcode,
                &mut event.a,
                &mut event.b,
                &mut event.c,
                &mut event.op_a_0,
            );
        }
        let beak_memory_step = fuzzer_utils::next_witness_step();
        if let Some(beak_kind) = Self::beak_memory_semantic_injection_kind(beak_memory_step) {
            Self::beak_mutate_memory_event(beak_kind.as_str(), &mut event);
        }
        if let Some(beak_kind) =
            Self::beak_boundary_origin_semantic_injection_kind(beak_instruction_step)
        {
            Self::beak_mutate_boundary_origin_event(
                beak_kind.as_str(),
                &mut event.clk,
                &mut event.pc,
            );
        }
        // BEAK-INSERT-END
"""
    if mem_guard not in contents and mem_anchor in contents:
        contents = contents.replace(mem_anchor, mem_insert, 1)

    alu_guard = "// BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.alu"
    alu_anchor = """        let opcode = instruction.opcode;
        let event = AluEvent { clk: self.core.clk(), pc: self.core.pc(), opcode, a, b, c, op_a_0 };
"""
    alu_insert = """        let opcode = instruction.opcode;
        let mut event = AluEvent { clk: self.core.clk(), pc: self.core.pc(), opcode, a, b, c, op_a_0 };
        // BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.alu
        let beak_instruction_step = fuzzer_utils::next_executor_step();
        if let Some(beak_kind) =
            Self::beak_instruction_semantic_injection_kind(beak_instruction_step)
        {
            Self::beak_mutate_instruction_event(
                beak_kind.as_str(),
                &mut event.opcode,
                &mut event.a,
                &mut event.b,
                &mut event.c,
                &mut event.op_a_0,
            );
        }
        let beak_chip_step = event.pc / 4;
        if let Some(beak_kind) =
            Self::beak_alu_semantic_injection_kind(event.opcode, beak_chip_step)
        {
            Self::beak_mutate_instruction_event(
                beak_kind.as_str(),
                &mut event.opcode,
                &mut event.a,
                &mut event.b,
                &mut event.c,
                &mut event.op_a_0,
            );
        }
        let opcode = event.opcode;
        let op_a_0 = event.op_a_0;
        if let Some(beak_kind) =
            Self::beak_boundary_origin_semantic_injection_kind(beak_instruction_step)
        {
            Self::beak_mutate_boundary_origin_event(
                beak_kind.as_str(),
                &mut event.clk,
                &mut event.pc,
            );
        }
        // BEAK-INSERT-END
"""
    if alu_guard not in contents and alu_anchor in contents:
        contents = contents.replace(alu_anchor, alu_insert, 1)

    jal_guard = "// BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.jal"
    jal_anchor = """        let event = JumpEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            next_pc,
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
"""
    jal_insert = """        let mut event = JumpEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            next_pc,
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
        // BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.jal
        let beak_instruction_step = fuzzer_utils::next_executor_step();
        if let Some(beak_kind) =
            Self::beak_instruction_semantic_injection_kind(beak_instruction_step)
        {
            Self::beak_mutate_instruction_event(
                beak_kind.as_str(),
                &mut event.opcode,
                &mut event.a,
                &mut event.b,
                &mut event.c,
                &mut event.op_a_0,
            );
        }
        if let Some(beak_kind) = Self::beak_control_semantic_injection_kind(beak_instruction_step) {
            event.next_pc = event.next_pc.wrapping_add(4);
            Self::beak_mutate_instruction_event(
                beak_kind.as_str(),
                &mut event.opcode,
                &mut event.a,
                &mut event.b,
                &mut event.c,
                &mut event.op_a_0,
            );
        }
        if let Some(beak_kind) =
            Self::beak_boundary_origin_semantic_injection_kind(beak_instruction_step)
        {
            Self::beak_mutate_boundary_origin_event(
                beak_kind.as_str(),
                &mut event.clk,
                &mut event.pc,
            );
        }
        // BEAK-INSERT-END
"""
    if jal_guard not in contents and jal_anchor in contents:
        contents = contents.replace(jal_anchor, jal_insert, 1)

    jalr_guard = "// BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.jalr"
    if jalr_guard not in contents and jal_anchor in contents:
        contents = contents.replace(
            jal_anchor,
            jal_insert.replace(jal_guard, jalr_guard),
            1,
        )

    branch_guard = "// BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.branch"
    branch_anchor = """        let event = BranchEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            next_pc,
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
"""
    branch_insert = jal_insert.replace("JumpEvent", "BranchEvent").replace(
        jal_guard,
        branch_guard,
    )
    if branch_guard not in contents and branch_anchor in contents:
        contents = contents.replace(branch_anchor, branch_insert, 1)

    utype_guard = "// BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.utype"
    utype_anchor = """        let event = UTypeEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
"""
    utype_insert = """        let mut event = UTypeEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
        // BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.utype
        let beak_instruction_step = fuzzer_utils::next_executor_step();
        if let Some(beak_kind) =
            Self::beak_instruction_semantic_injection_kind(beak_instruction_step)
        {
            Self::beak_mutate_instruction_event(
                beak_kind.as_str(),
                &mut event.opcode,
                &mut event.a,
                &mut event.b,
                &mut event.c,
                &mut event.op_a_0,
            );
        }
        if let Some(beak_kind) =
            Self::beak_boundary_origin_semantic_injection_kind(beak_instruction_step)
        {
            Self::beak_mutate_boundary_origin_event(
                beak_kind.as_str(),
                &mut event.clk,
                &mut event.pc,
            );
        }
        // BEAK-INSERT-END
"""
    if utype_guard not in contents and utype_anchor in contents:
        contents = contents.replace(utype_anchor, utype_insert, 1)

    syscall_guard = "// BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.syscall"
    syscall_anchor = """        let syscall_event = self.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            next_pc,
            exit_code,
            sig_return_pc_record,
            trap_result,
            trap_error,
        );
"""
    syscall_insert = """        let mut syscall_event = self.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            next_pc,
            exit_code,
            sig_return_pc_record,
            trap_result,
            trap_error,
        );
        // BEAK-INSERT: sp1.v4.executor_tracing_semantic_injection.syscall
        let beak_instruction_step = fuzzer_utils::next_executor_step();
        if let Some(_beak_kind) =
            Self::beak_instruction_semantic_injection_kind(beak_instruction_step)
        {
            syscall_event.arg1 = syscall_event.arg1.wrapping_add(1);
        }
        if let Some(_beak_kind) = Self::beak_control_semantic_injection_kind(beak_instruction_step) {
            syscall_event.next_pc = syscall_event.next_pc.wrapping_add(4);
        }
        if let Some(beak_kind) =
            Self::beak_boundary_origin_semantic_injection_kind(beak_instruction_step)
        {
            Self::beak_mutate_boundary_origin_event(
                beak_kind.as_str(),
                &mut syscall_event.clk,
                &mut syscall_event.pc,
            );
        }
        // BEAK-INSERT-END
"""
    if syscall_guard not in contents and syscall_anchor in contents:
        contents = contents.replace(syscall_anchor, syscall_insert, 1)

    path.write_text(contents)


def _patch_v4_syscall_context(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())

    helper_guard = "// BEAK-INSERT: sp1.v4.precompile_slice_executor_address_injection.helpers"
    helper_anchor = "impl<'a, 'b> SyscallContext<'a, 'b> {\n"
    helper_insert = """// BEAK-INSERT: sp1.v4.precompile_slice_executor_address_injection.helpers
    const BEAK_MEMORY_ADDRESS_INJECT_KIND: &'static str =
        "sp1.semantic.memory.address_pointer_consistency";
    const BEAK_BABYBEAR_FIELD_MODULUS: u64 = 2_013_265_921;

    fn beak_variant_u32(inject_kind: &str, key: &str) -> Option<u32> {
        fuzzer_utils::injection_variant_value(inject_kind, key)?.parse().ok()
    }

    fn beak_base_injection_kind(inject_kind: &str) -> &str {
        inject_kind
            .split_once("::")
            .map(|(base, _)| base)
            .unwrap_or(inject_kind)
    }

    fn beak_precompile_phase_matches_access(inject_kind: &str, access: &str) -> bool {
        let Some(phase) = fuzzer_utils::injection_variant_value(inject_kind, "phase") else {
            return true;
        };
        match access {
            "read" => phase.ends_with("_read"),
            "write" => phase.ends_with("_write"),
            _ => true,
        }
    }

    fn beak_precompile_slice_site_matches(inject_kind: &str, access: &str) -> bool {
        let site = fuzzer_utils::injection_variant_value(inject_kind, "site")
            .unwrap_or("precompile_slice");
        let phase = fuzzer_utils::injection_variant_value(inject_kind, "phase");
        match site {
            "precompile_slice" => true,
            "sha_compress_w_slice" => {
                access == "read" && phase.map(|p| p == "sha_compress.w_read").unwrap_or(true)
            }
            "sha_compress_h_slice" => phase
                .map(|p| {
                    (access == "read" && p == "sha_compress.h_read")
                        || (access == "write" && p == "sha_compress.h_write")
                })
                .unwrap_or(true),
            "sha_extend_w_slice" => phase
                .map(|p| p.starts_with("sha_extend.") && Self::beak_precompile_phase_matches_access(inject_kind, access))
                .unwrap_or(true),
            _ => false,
        }
    }

    fn beak_precompile_slice_crosses_field(addr: u32, len: usize) -> bool {
        len > 0
            && (addr as u64)
                .saturating_add((len as u64).saturating_mul(4))
                > Self::BEAK_BABYBEAR_FIELD_MODULUS
    }

    fn beak_precompile_slice_address_injection_kind(
        &self,
        addr: u32,
        len: usize,
        access: &str,
    ) -> Option<String> {
        let inject_kind =
            std::env::var("BEAK_SP1_WITNESS_INJECT_KIND").unwrap_or_default();
        let inject_step = std::env::var("BEAK_SP1_WITNESS_INJECT_STEP")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        if Self::beak_base_injection_kind(inject_kind.as_str())
            != Self::BEAK_MEMORY_ADDRESS_INJECT_KIND
            || inject_step != self.clk as u64
        {
            return None;
        }
        if !Self::beak_precompile_slice_site_matches(&inject_kind, access) {
            return None;
        }
        if let Some(expected_access) = fuzzer_utils::injection_variant_value(&inject_kind, "access")
        {
            if expected_access != access {
                return None;
            }
        }
        if !Self::beak_precompile_phase_matches_access(&inject_kind, access) {
            return None;
        }
        if let Some(target_ptr) = Self::beak_variant_u32(&inject_kind, "effective_ptr") {
            if target_ptr != addr {
                return None;
            }
        }
        if len == 0 {
            return None;
        }
        fuzzer_utils::matching_injection_kind(
            Self::BEAK_MEMORY_ADDRESS_INJECT_KIND,
            self.clk as u64,
        )
    }

    fn beak_precompile_slice_addr(addr: u32, lane: usize, inject_kind: Option<&str>) -> u32 {
        let raw = (addr as u64).saturating_add((lane as u64).saturating_mul(4));
        if let Some(kind) = inject_kind {
            if raw >= Self::BEAK_BABYBEAR_FIELD_MODULUS
                || Self::beak_precompile_slice_crosses_field(addr, lane.saturating_add(1))
            {
                return (raw % Self::BEAK_BABYBEAR_FIELD_MODULUS) as u32;
            }
            if Self::beak_precompile_slice_site_matches(kind, "read")
                || Self::beak_precompile_slice_site_matches(kind, "write")
            {
                return (raw as u32).wrapping_add(1);
            }
        }
        raw as u32
    }
    // BEAK-INSERT-END

"""
    contents = _insert_after_once(contents, helper_anchor, helper_insert, helper_guard)

    mr_anchor = """        let mut records = Vec::new();
        let mut values = Vec::new();
        for i in 0..len {
            let (record, value) = self.mr(addr + i as u32 * 4);"""
    mr_insert = """        let mut records = Vec::new();
        let mut values = Vec::new();
        let beak_kind =
            self.beak_precompile_slice_address_injection_kind(addr, len, "read");
        for i in 0..len {
            let (record, value) =
                self.mr(Self::beak_precompile_slice_addr(addr, i, beak_kind.as_deref()));"""
    if "self.beak_precompile_slice_address_injection_kind(addr, len, \"read\")" not in contents:
        contents = contents.replace(mr_anchor, mr_insert, 1)

    mw_anchor = """        let mut records = Vec::new();
        for i in 0..values.len() {
            let record = self.mw(addr + i as u32 * 4, values[i]);"""
    mw_insert = """        let mut records = Vec::new();
        let beak_kind =
            self.beak_precompile_slice_address_injection_kind(addr, values.len(), "write");
        for i in 0..values.len() {
            let record =
                self.mw(Self::beak_precompile_slice_addr(addr, i, beak_kind.as_deref()), values[i]);"""
    if (
        "self.beak_precompile_slice_address_injection_kind(addr, values.len(), \"write\")"
        not in contents
    ):
        contents = contents.replace(mw_anchor, mw_insert, 1)

    unsafe_anchor = """        let mut values = Vec::new();
        for i in 0..len {
            values.push(self.rt.word(addr + i as u32 * 4));"""
    unsafe_insert = """        let mut values = Vec::new();
        let beak_kind =
            self.beak_precompile_slice_address_injection_kind(addr, len, "write");
        for i in 0..len {
            values.push(self.rt.word(Self::beak_precompile_slice_addr(addr, i, beak_kind.as_deref())));"""
    if "values.push(self.rt.word(Self::beak_precompile_slice_addr" not in contents:
        contents = contents.replace(unsafe_anchor, unsafe_insert, 1)

    path.write_text(contents)


def _patch_legacy_add_sub(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    guard = "// BEAK-INSERT: sp1.356.add_sub_chip_semantic_injection.row"
    insert = """

                        // BEAK-INSERT: sp1.356.add_sub_chip_semantic_injection.row
                        let beak_step = (event.clk / 4) as u64;
                        if fuzzer_utils::should_inject_witness(
                            "sp1.semantic.alu.immediate_limb_consistency",
                            beak_step,
                        ) || fuzzer_utils::should_inject_witness(
                            "sp1.semantic.alu.subtraction_borrow_chain",
                            beak_step,
                        ) {
                            cols.add_operation.value[0] = cols.add_operation.value[0] + F::one();
                        }
                        // BEAK-INSERT-END"""
    path.write_text(
        _insert_after_once(
            contents,
            "                        cols.operand_2 = Word::from(operand_2);",
            insert,
            guard,
        )
    )


def _patch_legacy_bitwise(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    anchor = "                cols.is_and = F::from_bool(event.opcode == Opcode::AND);"
    guard = "// BEAK-INSERT: sp1.356.bitwise_chip_semantic_injection.row"
    insert = """

                // BEAK-INSERT: sp1.356.bitwise_chip_semantic_injection.row
                let beak_step = (event.clk / 4) as u64;
                if fuzzer_utils::should_inject_witness(
                    "sp1.semantic.alu.immediate_limb_consistency",
                    beak_step,
                ) {
                    cols.c[0] = cols.c[0] + F::one();
                }
                // BEAK-INSERT-END"""
    path.write_text(_insert_after_once(contents, anchor, insert, guard))


def _patch_legacy_lt(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    anchor = "                (row, new_byte_lookup_events)"
    guard = "// BEAK-INSERT: sp1.356.lt_chip_semantic_injection.row"
    insert = """
                // BEAK-INSERT: sp1.356.lt_chip_semantic_injection.row
                let beak_step = (event.clk / 4) as u64;
                if fuzzer_utils::should_inject_witness(
                    "sp1.semantic.alu.immediate_limb_consistency",
                    beak_step,
                ) {
                    cols.c[0] = cols.c[0] + F::one();
                }
                if fuzzer_utils::should_inject_witness(
                    "sp1.semantic.alu.comparison_booleanity",
                    beak_step,
                ) {
                    cols.sltu = F::one() - cols.sltu;
                }
                if fuzzer_utils::should_inject_witness(
                    "sp1.semantic.alu.subtraction_borrow_chain",
                    beak_step,
                ) || fuzzer_utils::should_inject_witness(
                    "sp1.semantic.alu.comparison_auxiliary_chain",
                    beak_step,
                ) {
                    cols.byte_flags[0] = F::one() - cols.byte_flags[0];
                }
                // BEAK-INSERT-END

"""
    path.write_text(_insert_before_once(contents, anchor, insert, guard))


def _patch_legacy_shift(path: Path, guard_name: str) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    anchor = "            rows.push(row);"
    guard = f"// BEAK-INSERT: {guard_name}"
    insert = f"""
            // BEAK-INSERT: {guard_name}
            let beak_step = (event.clk / 4) as u64;
            if fuzzer_utils::should_inject_witness(
                "sp1.semantic.alu.immediate_limb_consistency",
                beak_step,
            ) {{
                cols.c[0] = cols.c[0] + F::one();
            }}
            if fuzzer_utils::should_inject_witness(
                "sp1.semantic.alu.shift_mod32",
                beak_step,
            ) {{
                cols.bit_shift_result[0] = cols.bit_shift_result[0] + F::one();
            }}
            // BEAK-INSERT-END

"""
    path.write_text(_insert_before_once(contents, anchor, insert, guard))


def _patch_legacy_mul(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    anchor = "                        row"
    guard = "// BEAK-INSERT: sp1.356.mul_chip_semantic_injection.row"
    insert = """
                        // BEAK-INSERT: sp1.356.mul_chip_semantic_injection.row
                        let beak_step = (event.clk / 4) as u64;
                        if fuzzer_utils::should_inject_witness(
                            "sp1.semantic.arithmetic.product_decomposition",
                            beak_step,
                        ) {
                            cols.product[0] = cols.product[0] + F::one();
                        }
                        if event.opcode == Opcode::MULHSU
                            && fuzzer_utils::should_inject_witness(
                                "sp1.semantic.arithmetic.signed_unsigned_product_correction",
                                beak_step,
                            )
                        {
                            cols.b_sign_extend = F::one() - cols.b_sign_extend;
                        }
                        // BEAK-INSERT-END
"""
    path.write_text(_insert_before_once(contents, anchor, insert, guard))


def _patch_legacy_divrem(path: Path) -> None:
    contents = _ensure_fuzzer_utils_import(path, path.read_text())
    anchor = "            rows.push(row);"
    guard = "// BEAK-INSERT: sp1.356.divrem_chip_semantic_injection.row"
    insert = """
            // BEAK-INSERT: sp1.356.divrem_chip_semantic_injection.row
            let beak_step = (event.clk / 4) as u64;
            if fuzzer_utils::should_inject_witness(
                "sp1.semantic.arithmetic.special_case_consistency",
                beak_step,
            ) {
                cols.quotient[0] = cols.quotient[0] + F::one();
            }
            if fuzzer_utils::should_inject_witness(
                "sp1.semantic.arithmetic.division_remainder_bound",
                beak_step,
            ) {
                cols.remainder[0] = cols.remainder[0] + F::one();
            }
            // BEAK-INSERT-END

"""
    path.write_text(_insert_before_once(contents, anchor, insert, guard))


def _patch_v4_alu_chip_traces(sp1_install_path: Path) -> None:
    alu_dir = sp1_install_path / "crates" / "core" / "machine" / "src" / "alu"
    if not alu_dir.exists():
        return
    candidates = [
        (alu_dir / "add_sub" / "mod.rs", _patch_v4_add_sub),
        (alu_dir / "bitwise" / "mod.rs", _patch_v4_bitwise),
        (alu_dir / "lt" / "mod.rs", _patch_v4_lt),
        (
            alu_dir / "sll" / "mod.rs",
            lambda path: _patch_v4_shift(
                path,
                "sp1.v4.sll_chip_semantic_injection.row",
                "            self.event_to_row(event, cols, &mut blu);",
                "            ",
            ),
        ),
        (
            alu_dir / "sr" / "mod.rs",
            lambda path: _patch_v4_shift(
                path,
                "sp1.v4.sr_chip_semantic_injection.row",
                "                        self.event_to_row(event, cols, &mut byte_lookup_events);",
                "                        ",
            ),
        ),
        (alu_dir / "mul" / "mod.rs", _patch_v4_mul),
        (alu_dir / "divrem" / "mod.rs", _patch_v4_divrem),
    ]
    for path, patch in candidates:
        if path.exists():
            patch(path)


def _patch_legacy_alu_chip_traces(sp1_install_path: Path) -> None:
    alu_dir = sp1_install_path / "core" / "src" / "alu"
    if not alu_dir.exists():
        return
    candidates = [
        (alu_dir / "add_sub" / "mod.rs", _patch_legacy_add_sub),
        (alu_dir / "bitwise" / "mod.rs", _patch_legacy_bitwise),
        (alu_dir / "lt" / "mod.rs", _patch_legacy_lt),
        (
            alu_dir / "sll" / "mod.rs",
            lambda path: _patch_legacy_shift(path, "sp1.356.sll_chip_semantic_injection.row"),
        ),
        (
            alu_dir / "sr" / "mod.rs",
            lambda path: _patch_legacy_shift(path, "sp1.356.sr_chip_semantic_injection.row"),
        ),
        (alu_dir / "mul" / "mod.rs", _patch_legacy_mul),
        (alu_dir / "divrem" / "mod.rs", _patch_legacy_divrem),
    ]
    for path, patch in candidates:
        if path.exists():
            patch(path)


def _patch_plonky3_pin(sp1_install_path: Path) -> None:
    cargo_toml = sp1_install_path / "Cargo.toml"
    if not cargo_toml.exists():
        return

    contents = cargo_toml.read_text()
    updated = contents.replace(
        'git = "https://github.com/Plonky3/Plonky3", branch = "sp1-v4"',
        f'git = "https://github.com/Plonky3/Plonky3", rev = "{_PLONKY3_REV}"',
    )
    if updated != contents:
        cargo_toml.write_text(updated)


def apply(*, sp1_install_path: Path, commit_or_branch: str) -> None:
    _patch_plonky3_pin(sp1_install_path)
    _patch_v4_alu_chip_traces(sp1_install_path)
    for path in _memory_instruction_trace_candidates(sp1_install_path):
        _patch_v4_memory_instructions(path)
    for path in _syscall_instr_trace_candidates(sp1_install_path):
        _patch_v4_syscall_instr_padding(path)
    for path in _sha_extend_trace_candidates(sp1_install_path):
        _patch_v4_sha_extend_precompile(path)
    for path in _sha_compress_trace_candidates(sp1_install_path):
        _patch_v4_sha_compress_precompile(path)
    for path in _memory_global_candidates(sp1_install_path):
        _patch_v4_memory_global(path)
    for path in _byte_event_candidates(sp1_install_path):
        _patch_v4_byte_record(path)
    for path in _execution_record_candidates(sp1_install_path):
        _patch_v4_execution_record(path)
    for path in _executor_tracing_candidates(sp1_install_path):
        _patch_v4_executor_tracing(path)
    for path in _syscall_context_candidates(sp1_install_path):
        _patch_v4_syscall_context(path)
    for path in _byte_trace_candidates(sp1_install_path):
        _patch_v4_byte_trace(path)
    for path in _cpu_trace_candidates(sp1_install_path):
        _patch_cpu_trace(path, commit_or_branch)
    if commit_or_branch == SP1_UINT256_DIV_3561_COMMIT:
        _patch_legacy_alu_chip_traces(sp1_install_path)
        for path in _legacy_cpu_trace_candidates(sp1_install_path):
            _patch_legacy_cpu_trace(path)
