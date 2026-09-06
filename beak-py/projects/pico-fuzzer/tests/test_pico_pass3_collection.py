from pathlib import Path
from tempfile import TemporaryDirectory
import inspect
import unittest

from pico_fuzzer.passes.pass3_collection import (
    _patch_init_final_traces,
    _patch_local_cf5_bridge_text,
    _patch_rw_traces,
)


class Pico45eTimestampTypeTests(unittest.TestCase):
    def test_opcode_selector_hook_emits_changed_mutation_local_receipt_fields(self) -> None:
        source = inspect.getsource(_patch_rw_traces)
        self.assertIn("BEAK_PICO_OPCODE_SELECTOR_MUTATION_STEP", source)
        self.assertIn("BEAK_PICO_OPCODE_SELECTOR_BEFORE", source)
        self.assertIn("BEAK_PICO_OPCODE_SELECTOR_AFTER", source)
        self.assertIn('event.clk as u64 / 4', source)
        self.assertIn("BEAK_PICO_OPCODE_SELECTOR_MEMORY_EVENT_INDEX", source)
        self.assertIn('event_idx.to_string()', source)
        self.assertIn('BEAK_PICO_OPCODE_SELECTOR_BEFORE", "0', source)
        self.assertIn('BEAK_PICO_OPCODE_SELECTOR_AFTER", "1', source)

    def test_local_helper_uses_45e_u32_word_size(self) -> None:
        source = """use crate::{
    chips::{
        chips::riscv_global::event::GlobalInteractionEvent,
        utils::{next_power_of_two, zeroed_f_vec},
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    primitives::consts::LOCAL_MEMORY_DATAPAR,
};
impl<F: PrimeField32> ChipBehavior<F> for MemoryLocalChip<F> {}
"""

        patched = _patch_local_cf5_bridge_text(source)

        self.assertIn("primitives::consts::{LOCAL_MEMORY_DATAPAR, WORD_SIZE}", patched)
        self.assertIn("memory_addr - memory_addr % WORD_SIZE as u32", patched)
        self.assertNotIn("WORD_BYTE_SIZE", patched)

    def test_read_write_helper_uses_45e_u32_event_types(self) -> None:
        source = """use crate::primitives::consts::{MEMORY_RW_DATAPAR, WORD_SIZE};
impl<F: PrimeField32> ChipBehavior<F> for MemoryReadWriteChip<F> {
    fn generate_main(&self) {
        for event in events {
        }

        RowMajorMatrix::new(values, NUM_MEMORY_CHIP_COLS)
    }
}
"""
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "traces.rs"
            path.write_text(source)
            _patch_rw_traces(path, narrow_45e_types=True)
            patched = path.read_text()

        self.assertIn("memory_addr - memory_addr % WORD_SIZE as u32", patched)
        self.assertIn("event.clk = plan.high_timestamp;", patched)
        self.assertNotIn("WORD_BYTE_SIZE", patched)
        self.assertNotIn("event.clk = plan.high_timestamp as u64;", patched)
        self.assertIn("inject_step == (event.clk as u64 / 4)", patched)
        self.assertIn("BEAK_PICO_OPCODE_SELECTOR_MEMORY_EVENT_INDEX", patched)
        self.assertIn("event_idx.to_string()", patched)
        self.assertEqual(
            patched.count('Some("pico.semantic.exec.op_selector_binding.read_write")'),
            1,
        )

    def test_legacy_selector_branch_is_upgraded_to_changed_typed_receipt_metadata(self) -> None:
        source = '''impl<F: PrimeField32> ChipBehavior<F> for MemoryReadWriteChip<F> {
                    Some("pico.semantic.exec.op_selector_binding.read_write") => {
                        beak_applied = flip_read_write_selector_pair(cols);
                    }
}
'''
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "traces.rs"
            path.write_text(source)
            _patch_rw_traces(path, narrow_45e_types=True)
            patched = path.read_text()

        self.assertNotIn("beak_applied = flip_read_write_selector_pair(cols);", patched)
        self.assertIn("beak_applied = disable_non_x0_load_value_binding(cols);", patched)
        self.assertIn("(event.clk as u64 / 4).to_string()", patched)
        self.assertIn("BEAK_PICO_OPCODE_SELECTOR_MEMORY_EVENT_INDEX", patched)
        self.assertIn('BEAK_PICO_OPCODE_SELECTOR_BEFORE", "0', patched)
        self.assertIn('BEAK_PICO_OPCODE_SELECTOR_AFTER", "1', patched)

    def test_finalize_helper_uses_45e_u32_addresses(self) -> None:
        source = """impl<F: PrimeField32> ChipBehavior<F> for MemoryInitializeFinalizeChip<F> {}
"""
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "traces.rs"
            path.write_text(source)
            _patch_init_final_traces(path, narrow_45e_types=True)
            patched = path.read_text()

        self.assertIn("const WORD_SIZE_U32: u32 = 4;", patched)
        self.assertIn("addr: u32", patched)
        self.assertIn("HashMap::<u32, usize>", patched)
        self.assertNotIn("WORD_SIZE_U64", patched)
        self.assertNotIn("addr: u64", patched)


if __name__ == "__main__":
    unittest.main()
