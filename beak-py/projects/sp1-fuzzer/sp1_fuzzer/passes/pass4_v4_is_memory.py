from __future__ import annotations

from pathlib import Path

from sp1_fuzzer.settings import SP1_UINT256_DIV_3561_COMMIT
from zkvm_fuzzer_utils.file import prepend_file

_PLONKY3_REV = "db3d45d4ec899efaf8f7234a8573f285fbdda5db"


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


def _patch_cpu_trace(path: Path) -> None:
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
    if guard not in contents:
        insert = """
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
        if anchor in contents:
            contents = contents.replace(anchor, anchor + insert, 1)

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
        helper_anchor = """impl ByteLookupEvent {
    /// Creates a new `ByteLookupEvent`.
    #[must_use]
    pub fn new(opcode: ByteOpcode, a1: u16, a2: u8, b: u8, c: u8) -> Self {
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
    for path in _byte_event_candidates(sp1_install_path):
        _patch_v4_byte_record(path)
    for path in _execution_record_candidates(sp1_install_path):
        _patch_v4_execution_record(path)
    for path in _byte_trace_candidates(sp1_install_path):
        _patch_v4_byte_trace(path)
    for path in _cpu_trace_candidates(sp1_install_path):
        _patch_cpu_trace(path)
    if commit_or_branch == SP1_UINT256_DIV_3561_COMMIT:
        _patch_legacy_alu_chip_traces(sp1_install_path)
        for path in _legacy_cpu_trace_candidates(sp1_install_path):
            _patch_legacy_cpu_trace(path)
