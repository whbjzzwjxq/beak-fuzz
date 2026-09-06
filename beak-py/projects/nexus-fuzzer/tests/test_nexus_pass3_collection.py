from pathlib import Path

import inspect

from nexus_fuzzer.passes.pass3_collection import _patch_load_store_semantic_injection, apply
from nexus_fuzzer.settings import (
    NEXUS_AVAILABLE_COMMITS_OR_BRANCHES,
    NEXUS_MEMORY_SIZE_COMMIT,
    NEXUS_MUL_CARRY_COMMIT,
)


SIDENOTE_ANCHOR = """    /// Public output with the exit code.
    pub(crate) public_output: BTreeMap<u32, u8>,
}

        ret.public_output = public_output;
        ret
"""

LOAD_STORE_ANCHOR = """        assert_eq!(row_idx + 1, traces.num_rows());

        // side_note.rw_mem_check.last_access contains the last access time and value for every address under RW memory checking
        for (row_idx, (address, (last_access, last_value))) in
            side_note.rw_mem_check.last_access.iter().enumerate()
        {
            traces.fill_columns(row_idx, *address, Column::RamInitFinalAddr);
"""

MUL_NEXANI_ANCHORS = """pub(super) fn mull_limb(b: u32, c: u32) -> MulResult {
    // Convert inputs to limbs (4 bytes each)

    // Verify our calculations match the built-in multiplication
    assert!(carry_1 < 4, "Carry_1 exceeds expected bounds {}", carry_1);
"""

MUL_CHIP_ANCHORS = """use super::{gadget::constrain_mul_partial_product, nexani::mull_limb};

        let mul_result = mull_limb(u32::from_le_bytes(value_b), u32::from_le_bytes(value_c));
"""


def test_memory_table_receipt_follows_population_and_precedes_finalize(
    tmp_path: Path,
) -> None:
    sidenote = tmp_path / "prover" / "src" / "trace" / "sidenote.rs"
    load_store = (
        tmp_path / "prover" / "src" / "chips" / "instructions" / "load_store.rs"
    )
    sidenote.parent.mkdir(parents=True)
    load_store.parent.mkdir(parents=True)
    sidenote.write_text(SIDENOTE_ANCHOR)
    load_store.write_text(LOAD_STORE_ANCHOR)

    apply(nexus_install_path=tmp_path, commit_or_branch=NEXUS_MEMORY_SIZE_COMMIT)
    first_sidenote = sidenote.read_text()
    first_load_store = load_store.read_text()
    apply(nexus_install_path=tmp_path, commit_or_branch=NEXUS_MEMORY_SIZE_COMMIT)
    second_sidenote = sidenote.read_text()
    second_load_store = load_store.read_text()

    assert first_sidenote == second_sidenote
    assert first_load_store == second_load_store
    assert first_load_store.count("nexus.41c6.memory_table_population_receipt") == 1
    assert "side_note.rw_mem_check.last_access.len()" in first_load_store
    assert "let beak_allocated_rows = traces.num_rows()" in first_load_store
    assert "side_note.rw_mem_check.beak_public_rows" in first_load_store
    assert "beak_population_rows > beak_allocated_rows" in first_load_store
    assert "beak_public_rows <= beak_allocated_rows" in first_load_store
    assert "let beak_crossing_row_idx = beak_allocated_rows" in first_load_store
    assert "beak_population_rows.saturating_sub(beak_allocated_rows)" in first_load_store
    assert '"crossing_row_idx":{}' in first_load_store
    assert '"overflow_rows":{}' in first_load_store
    assert "row_idx == beak_crossing_row_idx" in first_load_store
    assert first_load_store.index("BEAK_NEXUS_MEMORY_TABLE_BOUNDARY_RECEIPT") < (
        first_load_store.index("for (row_idx, (address")
    )
    assert first_load_store.index("BEAK_NEXUS_EXECUTED_EXCEPTION_RECEIPT") < (
        first_load_store.index("traces.fill_columns(row_idx, *address")
    )
    assert "ret.beak_public_rows = init_memory" in first_sidenote


def test_mul_carry_receipt_is_emitted_only_at_executed_mul_failure(tmp_path: Path) -> None:
    assert NEXUS_MUL_CARRY_COMMIT in NEXUS_AVAILABLE_COMMITS_OR_BRANCHES
    nexani = (
        tmp_path
        / "prover"
        / "src"
        / "chips"
        / "instructions"
        / "m"
        / "nexani.rs"
    )
    mul_chip = nexani.with_name("mul.rs")
    nexani.parent.mkdir(parents=True)
    nexani.write_text(MUL_NEXANI_ANCHORS)
    mul_chip.write_text(MUL_CHIP_ANCHORS)

    apply(nexus_install_path=tmp_path, commit_or_branch=NEXUS_MUL_CARRY_COMMIT)
    first_nexani = nexani.read_text()
    first_mul_chip = mul_chip.read_text()
    apply(nexus_install_path=tmp_path, commit_or_branch=NEXUS_MUL_CARRY_COMMIT)
    second_nexani = nexani.read_text()
    second_mul_chip = mul_chip.read_text()

    assert first_nexani == second_nexani
    assert first_mul_chip == second_mul_chip
    assert first_nexani.count("BEAK_NEXUS_EXECUTED_EXCEPTION_RECEIPT") == 1
    assert "if carry_1 >= 4" in first_nexani
    assert "if let Some(step) = executed_mul_step" in first_nexani
    assert '"effect":"multiplication_carry_bound"' in first_nexani
    assert '"cell_id":"md4.mul_overflow"' in first_nexani
    assert '"rs1_val":{}' in first_nexani
    assert '"product_hi":{}' in first_nexani
    assert first_nexani.index("BEAK_NEXUS_EXECUTED_EXCEPTION_RECEIPT") < (
        first_nexani.index('assert!(carry_1 < 4')
    )
    assert "mull_limb_for_executed_mul(" in first_mul_chip
    assert "row_idx," in first_mul_chip


def test_store_load_relation_receipt_has_complete_typed_binding() -> None:
    source = inspect.getsource(_patch_load_store_semantic_injection)
    assert (
        '"beak_nexus_store_load_flow_raw_load_value(memory_record, side_note, row_idx)"'
        in source
    )
    for required in (
        "BEAK_NEXUS_SEMANTIC_MUTATION_RECEIPT",
        '"relation":"store_load_payload_equation"',
        '"bucket_id":"sem.memory.store_load_payload_flow"',
        '"obligation_id":"me1"',
        '"cell_id":"me1.sw_lw"',
        '"backend":"nexus"',
        '"commit":"636ccb360d0f4ae657ae4bb64e1e275ccec8826"',
        '"trace_source":"memory"',
        '"store_step":{}',
        '"load_step":{}',
        '"store_address":{}',
        '"load_address":{}',
        '"store_value":{}',
        '"store_value_before":{}',
        '"store_value_after":{}',
        '"load_value_before":{}',
        '"load_value_after":{}',
        '"width":4',
    ):
        assert required in source
    assert "store_before == load_before" in source
    assert "store_after == expected_store_after" in source
    assert "store_after == load_after" in source
    assert "store_before & 0xffff_ff00" in source
    assert "beak_nexus_mutated_payload_byte(store_before as u8)" in source
    assert "store_step < load_step" in source
