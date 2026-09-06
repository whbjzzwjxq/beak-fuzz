from pathlib import Path

from openvm_fuzzer.passes.pass3_collection import (
    _patch_336f_base_alu_adapter_emit_chip_row,
    _patch_336f_base_alu_core_semantic_injection,
    _patch_336f_branch_lt_conversion_receipt,
    _patch_336f_auipc_core_witness_injection,
    _patch_336f_divrem_core_witness_injection,
    _patch_336f_int256_branch256_frontend,
    _patch_336f_loadstore_adapter_witness_injection,
    _patch_336f_bitwise_lookup_shadow_multiplicity_injection,
    _patch_f038_connector_witness_injection,
    _patch_f038_loadstore_mem_as_witness_injection,
    _patch_f038_program_trace_row_anchor,
    _patch_f038_volatile_boundary_collection_and_remap,
    _patch_frozen_time_origin_wrap_witness_injection,
)


def _replace_guarded_block(text: str, guard: str, replacement: str) -> str:
    marker = text.index(guard)
    start = text.rfind("\n", 0, marker) + 1
    end_marker = text.index("// BEAK-INSERT-END", marker)
    line_end = text.find("\n", end_marker)
    end = len(text) if line_end < 0 else line_end + 1
    return text[:start] + replacement + text[end:]


def test_336_int256_branch256_uses_transpiler_and_concrete_conversion_hook(
    tmp_path: Path,
) -> None:
    transpiler = (
        tmp_path / "extensions" / "bigint" / "transpiler" / "src" / "lib.rs"
    )
    transpiler.parent.mkdir(parents=True)
    transpiler.write_text(
        "fn process(instruction_stream: &[u32]) {\n"
        "        let instruction_u32 = instruction_stream[0];\n"
        "        let opcode = (instruction_u32 & 0x7f) as u8;\n"
        "        let funct3 = ((instruction_u32 >> 12) & 0b111) as u8;\n"
        "        if opcode != OPCODE {\n"
        "            return None;\n"
        "        }\n"
        "        if funct3 != INT256_FUNCT3 && funct3 != BEQ256_FUNCT3 {\n"
        "            return None;\n"
        "        }\n\n"
        "        let dec_insn = RType::new(instruction_u32);\n"
        "        let instruction = match funct3 {\n"
        "        };\n"
        "}\n"
    )
    core = (
        tmp_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "branch_lt"
        / "core.rs"
    )
    core.parent.mkdir(parents=True)
    core.write_text(
        "fn execute_instruction(&self, instruction: &Instruction<F>, from_pc: u32) {\n"
        "        let Instruction { opcode, c: imm, .. } = *instruction;\n"
        "        let blt_opcode = BranchLessThanOpcode::from_usize(opcode.local_opcode_idx(self.air.offset));\n"
        "}\n"
    )

    _patch_336f_int256_branch256_frontend(tmp_path)
    _patch_336f_branch_lt_conversion_receipt(tmp_path)
    transpiled_once = transpiler.read_text()
    hooked_once = core.read_text()
    _patch_336f_int256_branch256_frontend(tmp_path)
    _patch_336f_branch_lt_conversion_receipt(tmp_path)

    assert transpiler.read_text() == transpiled_once
    assert core.read_text() == hooked_once
    assert "beak_branch256_family = opcode == OPCODE && funct3 == 0b111" in transpiled_once
    assert "Rv32BranchLessThan256Opcode::CLASS_OFFSET" in transpiled_once
    assert "0 => BranchLessThanOpcode::BLT," in transpiled_once
    assert "beak_branch_op.local_usize()" in transpiled_once
    assert "fuzzer_utils::current_instruction_step()" in hooked_once
    for field in [
        '"effect": "bigint_opcode_conversion"',
        '"obligation_id": "id4"',
        '"cell_id": "id4.branch"',
        '"global_opcode": opcode.as_usize()',
        '"chip_class_offset": self.air.offset',
        '"local_opcode": beak_local_opcode',
        '"supported_local_opcodes": [0, 1, 2, 3]',
        '"relation_valid": !matches!(beak_local_opcode, 0 | 1 | 2 | 3)',
        '"backend": "openvm"',
        '"commit": "336f1a475e5aa3513c4c5a266399f4128c119bba"',
        '"step": beak_step',
        '"hook_fired": true',
    ]:
        assert field in hooked_once
    assert hooked_once.index("record_executed_exception_attempt") < hooked_once.index(
        "BranchLessThanOpcode::from_usize(beak_local_opcode)"
    )

ORIGINAL_IMMEDIATE_BLOCK = r"""        let (rs2, rs2_data, rs2_imm) = if e.is_zero() {
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


def test_immediate_limb_hook_changes_zero_without_changing_recomposition(
    tmp_path: Path,
) -> None:
    adapter = tmp_path / "extensions" / "rv32im" / "circuit" / "src" / "adapters" / "alu.rs"
    adapter.parent.mkdir(parents=True)
    adapter.write_text(
        "use openvm_stark_backend::p3_field::Field;\n\n"
        "fn preprocess() {\n"
        "        let rs1 = memory.read::<RV32_REGISTER_NUM_LIMBS>(d, b);\n"
        f"{ORIGINAL_IMMEDIATE_BLOCK}"
        "            unreachable!()\n"
        "        };\n"
        "}\n\n"
        "fn generate_trace_row() {}\n"
    )

    _patch_336f_base_alu_adapter_emit_chip_row(tmp_path)

    patched = adapter.read_text()
    assert "beak_rs2_data[0] += F::from_canonical_u32(1 << 8);" in patched
    assert "beak_rs2_data[1] -= F::ONE;" in patched
    assert '== Some("mode=adjacent_radix_carry,carry_slot=0,borrow_slot=1,radix=256,field_modulus=2013265921,limb_count=4")' in patched
    assert patched.index("beak_o5_variant_valid") < patched.index(
        'should_inject_witness("openvm.semantic.alu.immediate_limb_consistency"'
    )
    assert '"relation": "full_limb_value_representation"' in patched
    assert '"bucket_id": "sem.alu.immediate_limb_consistency"' in patched
    for key in [
        '"carry_slot"',
        '"borrow_slot"',
        '"field_modulus"',
        '"before_limbs"',
        '"after_limbs"',
        '"recomposed_before"',
        '"recomposed_after"',
    ]:
        assert key in patched
    assert '"relation": "value_preserving_representation"' not in patched
    assert (
        "beak_rs2_data = [F::from_canonical_u32(c_u32), F::ZERO, F::ZERO, F::ZERO];" not in patched
    )

    legacy = _replace_guarded_block(
        patched,
        "// BEAK-INSERT: guard.336f.adapter.base_alu.preprocess_o5",
        """            // BEAK-INSERT: guard.336f.adapter.base_alu.preprocess_o5
            if fuzzer_utils::should_inject_witness(
                "openvm.semantic.alu.immediate_limb_consistency",
                beak_witness_step,
            ) {
                fuzzer_utils::record_semantic_mutation(
                    "openvm.semantic.alu.immediate_limb_consistency",
                    "legacy",
                    "legacy",
                    beak_witness_step,
                    serde_json::json!([]),
                    serde_json::json!([]),
                    serde_json::json!({"relation": "value_preserving_representation"}),
                );
            }
            // BEAK-INSERT-END
""",
    )
    adapter.write_text(legacy)
    _patch_336f_base_alu_adapter_emit_chip_row(tmp_path)
    assert adapter.read_text() == patched


def test_336_divrem_hook_emits_only_exact_overflow_equation_receipt(
    tmp_path: Path,
) -> None:
    core = tmp_path / "extensions" / "rv32im" / "circuit" / "src" / "divrem" / "core.rs"
    core.parent.mkdir(parents=True)
    core.write_text(
        "use fuzzer_utils;\n"
        "fn execute_instruction(&self, instruction: &Instruction<F>, _from_pc: u32, reads: I::Reads) -> Result<(AdapterRuntimeContext<F, I>, Self::Record)> {\n"
        "        let data: [[F; NUM_LIMBS]; 2] = reads.into();\n"
        "        let b = data[0].map(|x| x.as_canonical_u32());\n"
        "        let c = data[1].map(|y| y.as_canonical_u32());\n"
        "        let record = DivRemCoreRecord {\n"
        "            c: data[1],\n"
        "        };\n"
        "    }\n"
        "fn generate_trace_row(&self, row_slice: &mut [F], record: Self::Record) {\n"
        "        let row_slice: &mut DivRemCoreCols<F, 4, 8> = row_slice.borrow_mut();\n"
        "        row_slice.opcode_remu_flag = F::from_bool(record.opcode == DivRemOpcode::REMU);\n"
        "    }\n"
        "    fn air(&self) -> &Self::Air {\n"
        "        &self.air\n"
        "    }\n"
        "}\n"
    )

    _patch_336f_divrem_core_witness_injection(tmp_path)
    once = core.read_text()
    _patch_336f_divrem_core_witness_injection(tmp_path)

    assert core.read_text() == once
    # Generate-trace duplicate-row shadow: arm on the variant mode in the
    # finalize override, gate on should_inject_witness, and keep the executed
    # instruction/record construction untouched.
    assert once.count("guard.336f.divrem.core.o15.duplicate_row") == 1
    assert 'Some("duplicate_row_shadow_r_zero")' in once
    assert "fn finalize(" in once
    assert "duplicated_from_row_idx" in once
    assert "executor_divisor_reclass" not in once
    assert "let mut c = data[1].map(|y| y.as_canonical_u32());" not in once
    assert "c: c.map(F::from_canonical_u32)," not in once
    assert once.index("fn finalize(") < once.index("fn air(&self)")
    assert "fuzzer_utils::should_inject_witness(beak_o15_kind, beak_step)" in once
    assert once.index("should_inject_witness(beak_o15_kind, beak_step)") < once.index(
        "trace.values.resize(beak_new_height * beak_width, F::ZERO);"
    )
    assert '"divrem_core.generate_trace"' in once
    assert '"row_duplicate.is_valid"' in once
    assert '"relation": "division_remainder_special_case_equation"' in once
    assert '"bucket_id": "sem.arithmetic.special_case_consistency"' in once
    for key in [
        '"obligation_id"',
        '"cell_id"',
        '"mode"',
        '"search"',
        '"executed_instruction"',
        '"step"',
        '"pc"',
        '"opcode"',
        '"mnemonic"',
        '"is_valid"',
        '"zero_divisor"',
        '"r_zero"',
        '"dividend"',
        '"dividend_word"',
        '"claimed_divisor"',
        '"claimed_divisor_word"',
        '"quotient"',
        '"remainder"',
        '"duplicated_from_row_idx"',
        '"row_idx"',
        '"shadow_row"',
    ]:
        assert key in once
    # Legacy witness-row-level flag flip is gone.
    assert "shadow_invalid_one" not in once
    assert "guard.336f.divrem.core.o15.apply" not in once
    assert "row_slice.opcode_div_flag = F::ZERO;" not in once
    assert '"relation": "arithmetic_special_case"' not in once

    legacy = _replace_guarded_block(
        once,
        "// BEAK-INSERT: guard.336f.divrem.core.o15.duplicate_row",
        """        // BEAK-INSERT: guard.336f.divrem.core.o15.duplicate_row
        let beak_inject_o15 = fuzzer_utils::should_inject_witness(
            "openvm.semantic.arithmetic.special_case_consistency",
            0,
        );
        // BEAK-INSERT-END
""",
    )
    core.write_text(legacy)
    _patch_336f_divrem_core_witness_injection(tmp_path)
    assert core.read_text() == once

    # The legacy generate_trace_row blocks are removed on reinstall.
    with_legacy_row = (
        once.replace(
            "fn generate_trace_row(&self, row_slice: &mut [F], record: Self::Record) {\n",
            "fn generate_trace_row(&self, row_slice: &mut [F], record: Self::Record) {\n"
            "        // BEAK-INSERT: guard.336f.divrem.core.o15\n"
            "        let beak_inject_o15 = false;\n"
            "        // BEAK-INSERT-END\n"
            "        // BEAK-INSERT: guard.336f.divrem.core.o15.apply\n"
            "        if beak_inject_o15 {\n"
            "            row_slice.zero_divisor = F::ONE;\n"
            "        }\n"
            "        // BEAK-INSERT-END\n",
            1,
        )
    )
    core.write_text(with_legacy_row)
    _patch_336f_divrem_core_witness_injection(tmp_path)
    assert core.read_text() == once

    # The disproven executor-level block and its operand surgery are fully
    # reverted on reinstall.
    executor_block = (
        "        let data: [[F; NUM_LIMBS]; 2] = reads.into();\n"
        "        let b = data[0].map(|x| x.as_canonical_u32());\n"
        "        let mut c = data[1].map(|y| y.as_canonical_u32());\n"
        "\n"
        "        // BEAK-INSERT: guard.336f.divrem.core.o15.executor\n"
        "        {\n"
        "            let beak_o15_kind = \"openvm.semantic.arithmetic.special_case_consistency\";\n"
        "            let beak_inject_o15 = beak_o15_mode.as_deref() == Some(\"executor_divisor_reclass\");\n"
        "            if beak_inject_o15 {\n"
        "                c = [0u32; NUM_LIMBS];\n"
        "            }\n"
        "        }\n"
        "        // BEAK-INSERT-END\n"
    )
    with_executor = once.replace(
        "        let data: [[F; NUM_LIMBS]; 2] = reads.into();\n"
        "        let b = data[0].map(|x| x.as_canonical_u32());\n"
        "        let c = data[1].map(|y| y.as_canonical_u32());\n",
        executor_block,
        1,
    ).replace(
        "            c: data[1],\n",
        "            c: c.map(F::from_canonical_u32),\n",
        1,
    )
    assert "executor_divisor_reclass" in with_executor
    core.write_text(with_executor)
    _patch_336f_divrem_core_witness_injection(tmp_path)
    assert core.read_text() == once


def test_f038_program_trace_is_observation_only_for_address_space(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "crates" / "vm" / "src" / "system" / "program" / "trace.rs"
    trace.parent.mkdir(parents=True)
    trace.write_text(
        "use fuzzer_utils;\n"
        "fn generate() {\n"
        "    rows.par_chunks_mut(width)\n"
        "        .zip(instructions)\n"
        "        .for_each(|(row, (pc, instruction))| {\n"
        "            let row: &mut ProgramExecutionCols<F> = row.borrow_mut();\n"
        "            *row = ProgramExecutionCols {\n"
        "                pc: F::from_canonical_u32(pc),\n"
        "                opcode: instruction.opcode.to_field(),\n"
        "                a: instruction.a,\n"
        "                b: instruction.b,\n"
        "                c: instruction.c,\n"
        "                d: instruction.d,\n"
        "                e: instruction.e,\n"
        "                f: instruction.f,\n"
        "                g: instruction.g,\n"
        "            };\n"
        "        });\n"
        "}\n"
    )

    _patch_f038_program_trace_row_anchor(tmp_path)
    once = trace.read_text()
    _patch_f038_program_trace_row_anchor(tmp_path)

    assert trace.read_text() == once
    assert "let beak_program_step = i as u64;" in once
    assert "strict address-space candidate mutates only" in once
    assert "openvm.semantic.memory.address_space_consistency" not in once
    assert "record_semantic_mutation" not in once

    legacy = _replace_guarded_block(
        once,
        "// BEAK-INSERT: guard.f038.program_trace.mem_as_pre_access",
        """            // BEAK-INSERT: guard.f038.program_trace.mem_as_pre_access
            let old_mem_as = instruction.e.as_canonical_u64();
            if old_mem_as != 0 {
                row.e = F::ONE;
            }
            // BEAK-INSERT-END
""",
    )
    trace.write_text(legacy)
    _patch_f038_program_trace_row_anchor(tmp_path)
    assert trace.read_text() == once


def test_f038_adapter_is_the_only_typed_address_space_mutation(
    tmp_path: Path,
) -> None:
    adapter = tmp_path / "extensions" / "rv32im" / "circuit" / "src" / "adapters" / "loadstore.rs"
    adapter.parent.mkdir(parents=True)
    adapter.write_text(
        "use openvm_stark_backend::p3_field::Field;\n"
        "fn preprocess() {\n"
        "        let imm = c.as_canonical_u32();\n"
        "        let imm_sign = g.as_canonical_u32();\n"
        "        let imm_extended = imm + imm_sign * 0xffff0000;\n"
        "        let read_record = match local_opcode {\n"
        "            _ => unreachable!(),\n"
        "        };\n"
        "        Ok((\n"
        "            (\n"
        "                [prev_data, read_record.1],\n"
        "                F::from_canonical_u32(shift_amount),\n"
        "            ),\n"
        "            Self::ReadRecord {\n"
        "                rs1_record: rs1_record.0,\n"
        "                rs1_ptr: b,\n"
        "                read: read_record.0,\n"
        "                imm: c,\n"
        "                imm_sign: g,\n"
        "                shift_amount,\n"
        "                mem_ptr_limbs,\n"
        "                mem_as: e,\n"
        "            },\n"
        "        ))\n"
        "}\n"
    )

    _patch_f038_loadstore_mem_as_witness_injection(tmp_path)
    once = adapter.read_text()
    _patch_f038_loadstore_mem_as_witness_injection(tmp_path)

    assert adapter.read_text() == once
    assert once.count("use fuzzer_utils;") == 1
    assert once.count("#[allow(unused_imports)]") == 1
    assert 'beak_variant.as_deref() == Some("mode=bus_mem_as_reg")' in once
    assert once.index('beak_variant.as_deref() == Some("mode=bus_mem_as_reg")') < once.index(
        'should_inject_witness("openvm.semantic.memory.address_space_consistency"'
    )
    assert '"relation": "address_space_consistency_equation"' in once
    assert '"bucket_id": "sem.memory.address_space_consistency"' in once
    assert '"rv32_loadstore_adapter.preprocess"' in once
    assert "mem_as: beak_mem_as," in once
    for key in [
        '"row_idx"',
        '"is_memory"',
        '"register_address_space"',
        '"memory_address_space"',
        '"address_space_before"',
        '"address_space_after"',
        '"is_load"',
        '"is_store"',
        '"executed_access"',
    ]:
        assert key in once


def test_boolean_multiplicity_hook_targets_source_selector_and_is_idempotent(
    tmp_path: Path,
) -> None:
    core = tmp_path / "extensions" / "rv32im" / "circuit" / "src" / "base_alu" / "core.rs"
    core.parent.mkdir(parents=True)
    core.write_text(
        "use fuzzer_utils;\n\n"
        "fn generate_trace_row(&self, row_slice: &mut [F], record: Record) {\n"
        "        let row_slice: &mut BaseAluCoreCols<F> = row_slice.borrow_mut();\n"
        "        row_slice.opcode_xor_flag = F::from_bool(record.opcode == BaseAluOpcode::XOR);\n"
        "    }\n\n"
        "    fn air(&self) -> &Self::Air {\n"
        "        &self.air\n"
        "    }\n"
    )

    _patch_336f_base_alu_core_semantic_injection(tmp_path)
    once = core.read_text()
    _patch_336f_base_alu_core_semantic_injection(tmp_path)
    twice = core.read_text()

    assert twice == once
    assert once.count("guard.336f.base_alu.core.sub_borrow") == 1
    assert '"bitwise_source.base_alu.xor"' in once
    assert 'serde_json::json!(1)' in once
    assert 'serde_json::json!(2)' in once
    assert '"relation": "boolean_source_selector"' in once
    assert '"cell_id": "bu1.real_row"' in once
    assert "row_slice.opcode_xor_flag = F::from_canonical_u32(2);" in once
    assert "mult_xor" not in once
    assert once.index("emit_lookup_multiplicity") < once.index("should_inject_witness")


def test_336_bitwise_shadow_multiplicity_uses_central_injection_state(
    tmp_path: Path,
) -> None:
    lookup = (
        tmp_path
        / "crates"
        / "circuits"
        / "primitives"
        / "src"
        / "bitwise_op_lookup"
        / "mod.rs"
    )
    lookup.parent.mkdir(parents=True)
    lookup.write_text(
        "use fuzzer_utils;\n"
        "    pub fn generate_trace<F: Field>(&self) -> RowMajorMatrix<F> {\n"
        "        RowMajorMatrix::new(rows, NUM_BITWISE_OP_LOOKUP_COLS)\n"
        "    }\n"
    )

    _patch_336f_bitwise_lookup_shadow_multiplicity_injection(tmp_path)
    once = lookup.read_text()
    _patch_336f_bitwise_lookup_shadow_multiplicity_injection(tmp_path)

    assert lookup.read_text() == once
    # Arm/apply decisions go through fuzzer_utils, not raw env reads, so applied
    # injection sites are recorded and semantic_injection_applied can be set.
    assert "std::env::var" not in once
    assert "fuzzer_utils::witness_injection_enabled_for(beak_kind)" in once
    assert "fuzzer_utils::active_witness_variant(beak_kind)" in once
    assert "fuzzer_utils::should_inject_witness(beak_kind, beak_row_idx as u64)" in once
    assert once.index("should_inject_witness(beak_kind, beak_row_idx as u64)") < once.index(
        "cols.mult_xor = F::from_wrapped_u32(inject_mult);"
    )
    # Logup balance: the written cell is mult_before + P (non-canonical u32,
    # congruent in F), never a fixed p+1 constant that would desync the table.
    assert "let inject_mult = beak_mult_before.wrapping_add(BEAK_BABYBEAR_P);" in once
    assert "BEAK_BABYBEAR_P_PLUS_1" not in once
    assert '"strength": strength' in once
    assert "row={} skipped" in once
    assert once.count("guard.336f.bitwise.lookup.o1.shadow_mult") == 1

    legacy = _replace_guarded_block(
        once,
        "// BEAK-INSERT: guard.336f.bitwise.lookup.o1.shadow_mult",
        """        // BEAK-INSERT: guard.336f.bitwise.lookup.o1.shadow_mult
        if std::env::var("BEAK_OPENVM_WITNESS_INJECT_KIND").is_ok() {
            eprintln!("legacy");
        }
        // BEAK-INSERT-END
""",
    )
    lookup.write_text(legacy)
    _patch_336f_bitwise_lookup_shadow_multiplicity_injection(tmp_path)
    assert lookup.read_text() == once


def test_frozen_timestamp_wrap_hook_is_structural_typed_and_idempotent(tmp_path: Path) -> None:
    online = tmp_path / "crates" / "vm" / "src" / "system" / "memory" / "online.rs"
    offline = tmp_path / "crates" / "vm" / "src" / "system" / "memory" / "offline.rs"
    online.parent.mkdir(parents=True)
    online.write_text(
        "use fuzzer_utils;\n"
        "    pub fn new(mem_config: &MemoryConfig) -> Self {\n"
        "        Self {\n"
        "            data: AddressMap::from_mem_config(mem_config),\n"
        "            timestamp: INITIAL_TIMESTAMP + 1,\n"
        "            log: Vec::with_capacity(mem_config.access_capacity),\n"
        "        }\n"
        "    }\n"
    )
    offline.write_text(
        "use fuzzer_utils;\n"
        "        BlockData {\n"
        "            pointer: aligned_pointer,\n"
        "            size: initial_block_size,\n"
        "            timestamp: INITIAL_TIMESTAMP,\n"
        "        }\n"
        "    pub fn new(\n"
        "        initial_memory: MemoryImage<F>,\n"
        "        initial_block_size: usize,\n"
        "        memory_bus: MemoryBus,\n"
        "        range_checker: SharedVariableRangeCheckerChip,\n"
        "        config: MemoryConfig,\n"
        "    ) -> Self {\n"
        "        fuzzer_utils::fuzzer_assert!(initial_block_size.is_power_of_two());\n\n"
        "        Self {\n"
        "            block_data: AddressMap::from_mem_config(&config),\n"
        "            data: Self::memory_image_to_paged_vec(initial_memory, config),\n"
        "            as_offset: config.as_offset,\n"
        "            initial_block_size,\n"
        "            timestamp: INITIAL_TIMESTAMP + 1,\n"
        "            timestamp_max_bits: config.clk_max_bits,\n"
        "            memory_bus,\n"
        "            range_checker,\n"
        "            log: vec![],\n"
        "        }\n"
        "    }\n"
    )

    _patch_frozen_time_origin_wrap_witness_injection(tmp_path)
    online_once = online.read_text()
    offline_once = offline.read_text()
    _patch_frozen_time_origin_wrap_witness_injection(tmp_path)

    assert online.read_text() == online_once
    assert offline.read_text() == offline_once
    assert "should_apply_time_origin_wrap_at" in online_once
    assert "active_time_origin_wrap_at" in offline_once
    assert "should_shift_time_origin_at" not in online_once
    assert "block.timestamp = beak_wrap.origin;" in offline_once
    assert "later_after" in online_once
    assert '"near_modulus"' in online_once
    assert '"wrapped"' in online_once
    assert "emit_timestamp_boundary_origin(block.timestamp)" in offline_once
    assert "emit_timestamp_boundary_origin(beak_origin)" in offline_once
    assert online_once.index("should_apply_time_origin_wrap_at") < online_once.index(
        "record_semantic_mutation"
    )
    assert online_once.index("record_semantic_mutation") < online_once.index(
        "emit_timestamp_boundary_origin(beak_origin)"
    )
    assert offline_once.index("emit_timestamp_boundary_origin(block.timestamp)") < offline_once.index(
        "        block\n"
    )
    assert offline_once.index("emit_timestamp_boundary_origin(beak_origin)") < offline_once.index(
        "        Self {\n"
    )

    # Repair the guarded intermediate form left by an interrupted install: the
    # guard alone must not suppress the typed origin observation.
    offline.write_text(
        offline_once.replace(
            "        fuzzer_utils::emit_timestamp_boundary_origin(block.timestamp);\n", ""
        )
    )
    online.write_text(
        online_once.replace(
            "        fuzzer_utils::emit_timestamp_boundary_origin(beak_origin);\n", ""
        )
    )
    _patch_frozen_time_origin_wrap_witness_injection(tmp_path)
    assert offline.read_text() == offline_once
    assert online.read_text() == online_once


def test_f038_connector_observation_stays_on_prover_path_and_is_idempotent(
    tmp_path: Path,
) -> None:
    connector = tmp_path / "crates" / "vm" / "src" / "system" / "connector" / "mod.rs"
    connector.parent.mkdir(parents=True)
    connector.write_text(
        "use fuzzer_utils;\n"
        "    pub fn begin(&mut self, state: ExecutionState<u32>) {\n"
        "        self.boundary_states[0] = Some(ConnectorCols {\n"
        "            pc: state.pc,\n"
        "            timestamp: state.timestamp,\n"
        "            is_terminate: 0,\n"
        "            exit_code: 0,\n"
        "        });\n"
        "    }\n\n"
        "    pub fn end(&mut self, state: ExecutionState<u32>, exit_code: Option<u32>) {\n"
        "        self.boundary_states[1] = Some(ConnectorCols {\n"
        "            pc: state.pc,\n"
        "            timestamp: state.timestamp,\n"
        "            is_terminate: exit_code.is_some() as u32,\n"
        "            exit_code: exit_code.unwrap_or(DEFAULT_SUSPEND_EXIT_CODE),\n"
        "        });\n"
        "    }\n\n"
        "        // BEAK-INSERT: guard.system.connector_chip_row\n"
        "        // BEAK-INSERT: Emit chip-row micro-op.\n"
        "        let [begin_u32, end_u32] = self.boundary_states.map(|state| state.unwrap());\n"
        "        let is_terminate = end_u32.is_terminate == 1;\n"
        "        let exit_code = if is_terminate { Some(end_u32.exit_code) } else { None };\n"
        "        fuzzer_utils::emit_connector_chip_row(\n"
        "            begin_u32.pc,\n"
        "            end_u32.pc,\n"
        "            Some(begin_u32.timestamp),\n"
        "            Some(end_u32.timestamp),\n"
        "            is_terminate,\n"
        "            exit_code,\n"
        "        );\n"
        "        // BEAK-INSERT-END\n"
        "        let [initial_state, final_state] = self.boundary_states.map(|state| state.unwrap());\n"
    )

    _patch_f038_connector_witness_injection(tmp_path)
    once = connector.read_text()
    _patch_f038_connector_witness_injection(tmp_path)

    assert connector.read_text() == once
    assert once.count("guard.system.connector_chip_row") == 1
    assert "guard.f038.connector_boundary_origin" not in once
    assert "guard.f038.connector_boundary_observation" not in once
    assert once.index("guard.system.connector_chip_row") < once.index(
        "let [initial_state, final_state] ="
    )
    assert "Some(begin_u32.timestamp)" in once
    assert "Some(end_u32.timestamp)" in once


def test_f038_volatile_remap_receipt_follows_concrete_match_and_is_idempotent(
    tmp_path: Path,
) -> None:
    controller = (
        tmp_path
        / "crates"
        / "vm"
        / "src"
        / "system"
        / "memory"
        / "controller"
        / "mod.rs"
    )
    controller.parent.mkdir(parents=True)
    controller.write_text(
        "use fuzzer_utils;\n"
        "            MemoryInterface::Volatile { boundary_chip } => {\n"
        "                let final_memory = offline_memory.finalize::<1>(&mut self.access_adapters);\n"
        "                boundary_chip.finalize(final_memory);\n"
        "                self.final_state = Some(FinalState::Volatile(VolatileFinalState::default()));\n"
        "            }\n"
    )
    volatile = (
        tmp_path / "crates" / "vm" / "src" / "system" / "memory" / "volatile" / "mod.rs"
    )
    volatile.parent.mkdir(parents=True)
    volatile.write_text(
        "use fuzzer_utils;\n"
        "                row.final_data = data;\n"
        "                // BEAK-INSERT: guard.f038.volatile.o25\n"
        "                if fuzzer_utils::should_inject_witness(\"openvm.semantic.memory.volatile_boundary_range\", i as u64) {\n"
        "                    row.pointer = Val::<SC>::from_canonical_u32(1 << 29);\n"
        "                    fuzzer_utils::emit_memory_interaction(\"send\", Some(\"witness_inject_o25\"), 1 << 29, 1 << 29, vec![0], 0);\n"
        "                }\n"
        "                // BEAK-INSERT-END\n"
        "        let trace = RowMajorMatrix::new(rows, width);\n"
    )

    _patch_f038_volatile_boundary_collection_and_remap(tmp_path)
    once = controller.read_text()
    _patch_f038_volatile_boundary_collection_and_remap(tmp_path)

    assert controller.read_text() == once
    assert "guard.f038.volatile.o25\n" not in volatile.read_text()
    assert "witness_inject_o25" not in volatile.read_text()
    assert "let mut beak_mutated_tuple = None;" not in once
    volatile_once = volatile.read_text()
    assert "guard.f038.volatile.o25.row_witness" in volatile_once
    assert "i + 1 != memory_len" in volatile_once
    assert volatile_once.index("mark_witness_mutation_applied") < volatile_once.index(
        "record_semantic_mutation"
    )
    for key in [
        '"row_anchor"',
        '"row_idx"',
        '"volatile_start"',
        '"volatile_end"',
        '"forged_address"',
        '"outside_volatile_range"',
    ]:
        assert key in volatile_once


def test_336_auipc_receipt_consumes_variant_and_follows_mutation(tmp_path: Path) -> None:
    core = tmp_path / "extensions" / "rv32im" / "circuit" / "src" / "auipc" / "core.rs"
    core.parent.mkdir(parents=True)
    core.write_text(
        "use fuzzer_utils;\n"
        "        let imm_limbs = array::from_fn(|i| (imm >> (i * RV32_CELL_BITS)) & RV32_LIMB_MAX);\n"
        "        let pc_limbs = array::from_fn(|i| (from_pc >> ((i + 1) * RV32_CELL_BITS)) & RV32_LIMB_MAX);\n"
        "        let record = Rv32AuipcCoreRecord {\n"
        "            pc_limbs: pc_limbs.map(F::from_canonical_u32),\n"
        "        };\n"
    )

    _patch_336f_auipc_core_witness_injection(tmp_path)
    once = core.read_text()
    _patch_336f_auipc_core_witness_injection(tmp_path)

    assert core.read_text() == once
    assert 'mode == Some("from_pc_high_single_mod_p")' in once
    assert "strength == Some(0)" in once
    assert "mult == Some(1)" in once
    assert "matches!(slot, Some(2 | 3))" in once
    assert "_ => valid = false" in once
    assert once.index("matching_injection_kind") < once.index("should_inject_witness")
    assert once.index("pc_limbs[slot - 1] =") < once.index("record_semantic_mutation")
    # Mod-p noncanonical limb: delta is a whole field modulus multiple, and the
    # record conversion must wrap mod p because the raw limb exceeds the modulus.
    assert "BEAK_BABYBEAR_P * mult" in once
    assert "pc_limbs: pc_limbs.map(F::from_wrapped_u32)," in once
    assert "range_violated" not in once
    for key in [
        '"before_limbs"',
        '"after_limbs"',
        '"recomposed_before"',
        '"recomposed_after"',
        '"modulus"',
        '"from_pc"',
        '"step"',
    ]:
        assert key in once


def test_336_memory_sign_receipt_uses_exact_equation_schema_and_is_idempotent(
    tmp_path: Path,
) -> None:
    adapter = (
        tmp_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "adapters"
        / "loadstore.rs"
    )
    adapter.parent.mkdir(parents=True)
    adapter.write_text(
        "use fuzzer_utils;\n"
        "        let imm = c.as_canonical_u32();\n"
        "        let imm_sign = (imm & 0x8000) >> 15;\n"
        "        let imm_extended = imm + imm_sign * 0xffff0000;\n"
    )

    _patch_336f_loadstore_adapter_witness_injection(tmp_path)
    once = adapter.read_text()
    _patch_336f_loadstore_adapter_witness_injection(tmp_path)

    assert adapter.read_text() == once
    assert "_ => valid = false" in once
    assert once.index("matching_injection_kind") < once.index("should_inject_witness")
    assert once.index("beak_imm_sign = candidate_sign;") < once.index(
        "record_semantic_mutation"
    )
    assert '"immediate": imm' in once
    assert '"base": rs1_val' in once
    assert '"step": beak_witness_step' in once
    assert '"immediate_raw"' not in once
    assert '"base_pointer"' not in once
    assert '"id2.s_pos"' in once
    assert '"id2.i_neg"' in once
    for key in [
        '"sign_before"',
        '"sign_after"',
        '"extended_before"',
        '"extended_after"',
        '"effective_before"',
        '"effective_after"',
    ]:
        assert key in once
