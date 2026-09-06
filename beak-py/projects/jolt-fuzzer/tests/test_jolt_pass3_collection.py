import inspect
from pathlib import Path

from jolt_fuzzer.passes.pass3_collection import (
    _patch_bytecode_row_receipt_accessors,
    _patch_executed_exception_receipt_emission,
    _patch_host_trace_injection,
    _patch_read_write_memory_injection,
    apply,
)
from jolt_fuzzer.settings import JOLT_DORY_SHORT_TRACE_COMMIT, JOLT_READWRITE_SIZING_COMMIT


READ_WRITE_MARKERS = """
// BEAK-INSERT: jolt.read_write_memory.semantic_injection_helpers
        // BEAK-INSERT: jolt.read_write_memory.inclusive_memory_size
        stale sizing block
        // BEAK-INSERT-END
// BEAK-INSERT: jolt.read_write_memory.configure_semantic_injection
// BEAK-INSERT: jolt.read_write_memory.initial_value_binding
// BEAK-INSERT: jolt.read_write_memory.rs1_read_value
// BEAK-INSERT: jolt.read_write_memory.rs2_read_value
// BEAK-INSERT: jolt.read_write_memory.rd_write_value
// BEAK-INSERT: jolt.read_write_memory.ram_read_value
// BEAK-INSERT: jolt.read_write_memory.ram_write_value
// BEAK-INSERT: jolt.read_write_memory.finalization_consistency
"""

DORY_READ_WRITE_ANCHOR = """        let memory_size = (program_io.memory_layout.ram_witness_offset + max_trace_address)
            .next_power_of_two() as usize;
        let mut v_init: Vec<u64> = vec![0; memory_size];
        // Copy bytecode
        let mut v_init_index = memory_address_to_witness_index(
            preprocessing.min_bytecode_address,
            program_io.memory_layout.ram_witness_offset,
        );
        for byte in preprocessing.bytecode_bytes.iter() {
            v_init[v_init_index] = *byte as u64;
            v_init_index += 1;
        }
"""


def test_dory_bytecode_population_receipt_precedes_vulnerable_copy_and_is_idempotent(
    tmp_path: Path,
) -> None:
    target = (
        tmp_path
        / "jolt-core"
        / "src"
        / "jolt"
        / "vm"
        / "read_write_memory.rs"
    )
    target.parent.mkdir(parents=True)
    target.write_text(DORY_READ_WRITE_ANCHOR)

    apply(jolt_install_path=tmp_path, commit_or_branch=JOLT_READWRITE_SIZING_COMMIT)
    first = target.read_text()
    apply(jolt_install_path=tmp_path, commit_or_branch=JOLT_READWRITE_SIZING_COMMIT)
    second = target.read_text()

    assert first == second
    assert first.count("jolt.dory.bytecode_population_receipt") == 1
    assert first.count("jolt.dory.bytecode_capacity_exception_receipt") == 1
    assert "preprocessing.bytecode_bytes.len()" in first
    assert "beak_population_end > memory_size" in first
    assert '"exact_crossing":{}' in first
    assert first.index("BEAK_JOLT_BYTECODE_BOUNDARY_RECEIPT") < first.index(
        "let mut v_init: Vec<u64>"
    )
    assert first.index("let mut v_init: Vec<u64>") < first.index(
        "let mut v_init_index = beak_population_start"
    )
    assert first.index("if beak_exact_crossing && v_init_index == memory_size") < first.index(
        "v_init[v_init_index] = *byte as u64"
    )
    assert '"effect":"bytecode_table_capacity_write"' in first
    assert '"stage":"read_write_memory.v_init.write"' in first


def test_verifier_exception_receipts_emit_only_at_concrete_failed_relations_and_are_idempotent(
    tmp_path: Path,
) -> None:
    instruction_lookups = (
        tmp_path / "jolt-core" / "src" / "jolt" / "vm" / "instruction_lookups.rs"
    )
    instruction_lookups.parent.mkdir(parents=True)
    instruction_lookups.write_text(
        """        assert_eq!(
            eq_eval
                * (Self::combine_lookups(
                    preprocessing,
                    &proof.primary_sumcheck.openings.E_poly_openings,
                    &proof.primary_sumcheck.openings.flag_openings,
                ) - proof.primary_sumcheck.openings.lookup_outputs_opening),
            claim_last,
            "Primary sumcheck check failed."
        );
"""
    )
    spartan = tmp_path / "jolt-core" / "src" / "r1cs" / "spartan.rs"
    spartan.parent.mkdir(parents=True)
    spartan.write_text(
        """        if claim_inner_final != claim_inner_final_expected {
            return Err(SpartanError::InvalidInnerSumcheckClaim);
        }
"""
    )

    _patch_executed_exception_receipt_emission(tmp_path)
    instruction_first = instruction_lookups.read_text()
    spartan_first = spartan.read_text()
    _patch_executed_exception_receipt_emission(tmp_path)

    assert instruction_lookups.read_text() == instruction_first
    assert spartan.read_text() == spartan_first
    assert instruction_first.count("jolt.instruction_lookup.primary_exception_receipt") == 1
    assert spartan_first.count("jolt.r1cs.inner_exception_receipt") == 1
    assert instruction_first.index("if beak_primary_sumcheck_lhs != claim_last") < (
        instruction_first.index("BEAK_JOLT_EXECUTED_EXCEPTION_RECEIPT")
    )
    assert spartan_first.index("if claim_inner_final != claim_inner_final_expected") < (
        spartan_first.index("BEAK_JOLT_EXECUTED_EXCEPTION_RECEIPT")
    )
    assert "BEAK_JOLT_INSTRUCTION_LOOKUP_EXCEPTION_CANDIDATE" in instruction_first
    assert "BEAK_JOLT_R1CS_EXCEPTION_CANDIDATE" in spartan_first


def test_read_write_sizing_patch_is_inclusive_checked_and_idempotent(
    tmp_path: Path,
) -> None:
    target = tmp_path / "jolt-core" / "src" / "jolt" / "vm" / "read_write_memory.rs"
    target.parent.mkdir(parents=True)
    target.write_text(READ_WRITE_MARKERS)

    _patch_read_write_memory_injection(tmp_path)
    first = target.read_text()
    _patch_read_write_memory_injection(tmp_path)
    second = target.read_text()

    assert first == second
    assert "max_trace_address\n                .checked_add(1)" in first
    assert "bytecode_start_index\n            .checked_add(preprocessing.bytecode_words.len())" in first
    assert "input_start_index\n            .checked_add(input_word_len)" in first
    assert ".max()\n        .unwrap()\n        .next_power_of_two()" in first
    assert first.count("jolt.read_write_memory.inclusive_memory_size") == 1


def test_host_receipts_are_created_after_the_concrete_mutation() -> None:
    source = inspect.getsource(_patch_host_trace_injection)

    entrypoint = source.split(
        "if base_kind == BEAK_JOLT_ENTRYPOINT_INJECT_KIND", 1
    )[1].split("else if base_kind == BEAK_JOLT_CONTROL_FLOW_INJECT_KIND", 1)[0]
    assert "trace.drain" not in source
    assert "trace.remove" not in source
    assert "trace.clear" not in source
    assert "trace.rotate" not in source
    assert "trace.swap" not in source
    assert "trace.sort" not in source
    assert "trace.reverse" not in source
    assert "trace.truncate" not in source
    assert "trace.retain" not in source
    assert "trace.split_off" not in source
    assert "trace.splice" not in source
    assert "trace.first_mut()" in entrypoint
    assert "let declared_entry = common::constants::RAM_START_ADDRESS as usize" in entrypoint
    assert "witnessed_pc_before == declared_entry" in entrypoint
    declared_capture = entrypoint.index("let declared_entry =")
    witnessed_capture = entrypoint.index("let witnessed_pc_before =")
    mutation = entrypoint.index("beak_mutate_entrypoint_witness_address")
    receipt_emission = entrypoint.index("receipt = Some(format!(")
    assert max(declared_capture, witnessed_capture) < mutation < receipt_emission
    assert '"relation":"entrypoint_pc_equation"' in entrypoint
    for field in (
        '"site":"host.trace.row0.bytecode_row"',
        '"field":"bytecode_row.address"',
        '"bucket_id":"sem.control.entrypoint_binding"',
        '"obligation_id":"cf4"',
        '"cell_id":"cf4.default_entry"',
        '"op_idx":0',
        '"step_idx":0',
        '"pc":{}',
        '"opcode":"{}"',
        '"mnemonic":"{}"',
        '"declared_entry":{}',
        '"witnessed_pc_before":{}',
        '"witnessed_pc_after":{}',
        '"first_row_opcode_before":"{}"',
        '"first_row_opcode_after":"{}"',
        '"first_row_mnemonic_before":"{}"',
        '"first_row_mnemonic_after":"{}"',
        '"trace_len_before":{}',
        '"trace_len_after":{}',
        '"trace_rows_preserved":true',
        '"trace_order_preserved":true',
        '"executed_boundary_row":true',
    ):
        assert field in entrypoint
    upper_immediate = source.split(
        "else if base_kind == BEAK_JOLT_UPPER_IMMEDIATE_INJECT_KIND", 1
    )[1].split("\n    if applied {", 1)[0]
    assert upper_immediate.index("step_row.instruction_lookup = Some") < upper_immediate.index(
        "receipt = Some(format!("
    )
    assert '"relation":"upper_immediate_equation"' in upper_immediate
    for field in (
        '"bucket_id":"sem.decode.upper_immediate_materialization"',
        '"obligation_id":"id3"',
        '"opcode":{}',
        '"imm20":{}',
        '"expected_result":{}',
        '"witnessed_result_before":{}',
        '"witnessed_result_after":{}',
        '"executed_instruction":true',
    ):
        assert field in upper_immediate

    applied = source.split("\n    if applied {", 1)[1]
    assert applied.index("if let Some(receipt) = receipt") < applied.index(
        "std::env::set_var(BEAK_JOLT_MUTATION_RECEIPT_ENV, receipt)"
    )


def test_host_entrypoint_legacy_delete_hook_is_replaced_and_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "jolt-core" / "src" / "host" / "mod.rs"
    target.parent.mkdir(parents=True)
    target.write_text(
        '''const BEAK_JOLT_MUTATION_RECEIPT_ENV: &str = "BEAK_JOLT_WITNESS_MUTATION_RECEIPT";
// BEAK-INSERT: jolt.host.semantic_injection_helpers
fn beak_apply_semantic_injection(trace: &mut Vec<JoltTraceStep<RV32I>>) {
    if base_kind == BEAK_JOLT_ENTRYPOINT_INJECT_KIND {
        let prefix_len = 2usize;
        trace.drain(0..prefix_len);
    } else if base_kind == BEAK_JOLT_CONTROL_FLOW_INJECT_KIND {
        untouched_control_flow_hook();
    }
}
// BEAK-INSERT-END
// BEAK-INSERT: jolt.host.apply_semantic_injection
'''
    )

    _patch_host_trace_injection(tmp_path)
    first = target.read_text()
    _patch_host_trace_injection(tmp_path)

    assert target.read_text() == first
    assert "trace.drain" not in first
    assert "prefix_len" not in first
    assert first.count("beak_mutate_entrypoint_witness_address") == 1
    assert first.count('"site":"host.trace.row0.bytecode_row"') == 1
    assert "untouched_control_flow_hook();" in first


def test_bytecode_row_receipt_accessors_are_narrow_and_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "jolt-core" / "src" / "jolt" / "vm" / "bytecode.rs"
    target.parent.mkdir(parents=True)
    target.write_text("impl BytecodeRow {\n    existing\n}\n")

    _patch_bytecode_row_receipt_accessors(tmp_path)
    first = target.read_text()
    _patch_bytecode_row_receipt_accessors(tmp_path)

    assert target.read_text() == first
    assert first.count("jolt.bytecode_row.receipt_accessors") == 1
    assert "pub fn beak_receipt_address" in first
    assert "pub fn beak_receipt_rd" in first
    assert first.count("pub fn beak_mutate_entrypoint_witness_address") == 1
    mutator = first.split("pub fn beak_mutate_entrypoint_witness_address", 1)[1].split(
        "// BEAK-INSERT-END", 1
    )[0]
    assert "self.address != expected_before" in mutator
    assert "after == expected_before" in mutator
    assert "self.address = after" in mutator
    assert "self.address = after" not in first.split(
        "pub fn beak_mutate_entrypoint_witness_address", 1
    )[0]


def test_dory_short_trace_receipt_is_at_concrete_domain_assertion_and_idempotent(
    tmp_path: Path,
) -> None:
    dory = tmp_path / "jolt-core" / "src" / "poly" / "commitment" / "dory.rs"
    dory.parent.mkdir(parents=True)
    dory.write_text(
        '''/// The (padded) length of the execution trace currently being proven
static mut GLOBAL_T: OnceCell<usize> = OnceCell::new();
/// Dory works by viewing the coefficients of a polynomial as a square matrix.
static mut DIMENSION: OnceCell<usize> = OnceCell::new();

impl DoryGlobals {
    pub fn initialize(K: usize, T: usize) -> Self {
        let matrix_size = K as u128 * T as u128;
        let dimension = matrix_size.isqrt().next_power_of_two();
        unsafe {
            GLOBAL_T.set(T).expect("GLOBAL_T is already initialized");
            DIMENSION
                .set(dimension as usize)
                .expect("DIMENSION is already initialized");
        }
        DoryGlobals()
    }

    pub fn get_T() -> usize {
        unsafe { GLOBAL_T.get().cloned().expect("GLOBAL_T is uninitialized") }
    }
}

impl Drop for DoryGlobals {
    fn drop(&mut self) {
        unsafe {
            GLOBAL_T
                .take()
                .expect("reset_globals: GLOBAL_T is uninitialized");
            DIMENSION
                .take()
                .expect("reset_globals: DIMENSION is uninitialized");
        }
    }
}

// NewType wrappers for Jolt + arkworks types to interop with Dory traits

        let T = DoryGlobals::get_T();
        assert!(
            T > DoryGlobals::get_dimension(),
            "T = {T}, why are you doing this",
        );
'''
    )
    for name in ("one_hot_polynomial.rs", "rlc_polynomial.rs"):
        path = dory.parent.parent / name
        path.write_text('        assert!(T > num_rows, "T = {T}, why are you doing this");\n')

    apply(jolt_install_path=tmp_path, commit_or_branch=JOLT_DORY_SHORT_TRACE_COMMIT)
    first = dory.read_text()
    apply(jolt_install_path=tmp_path, commit_or_branch=JOLT_DORY_SHORT_TRACE_COMMIT)

    assert dory.read_text() == first
    typed_context = (
        r'"context":{{"backend":"jolt",'
        r'"commit":"d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b",'
        r'"trace_source":"prover.dory","input_words_len":{}'
    )
    legacy_context = r'"context":{{"input_words_len":{}'
    assert typed_context in first
    dory.write_text(first.replace(typed_context, legacy_context, 1))
    apply(jolt_install_path=tmp_path, commit_or_branch=JOLT_DORY_SHORT_TRACE_COMMIT)
    assert dory.read_text() == first
    assert first.count("jolt.dory.short_trace_globals") == 1
    assert first.count("jolt.dory.short_trace_receipt") == 1
    assert first.count("jolt.dory.commit_rows.short_trace_receipt") == 1
    assert '"effect":"dory_short_trace_capacity"' in first
    assert '"stage":"dory.commitment.domain_size"' in first
    assert '"relation":"dory_domain_not_greater_than_matrix_dimension"' in first
    assert first.index("beak_record_short_trace_capacity_failure();") < first.index(
        '"T = {T}, why are you doing this"'
    )
    for name in ("one_hot_polynomial.rs", "rlc_polynomial.rs"):
        patched = (dory.parent.parent / name).read_text()
        assert patched.count("jolt.dory.polynomial.short_trace_receipt") == 1
        assert patched.index("beak_record_short_trace_capacity_failure();") < patched.index(
            '"T = {T}, why are you doing this"'
        )
