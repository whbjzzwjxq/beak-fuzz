from pathlib import Path

from sp1_fuzzer.passes.pass3_collection import _patch_executor
from sp1_fuzzer.passes.pass4_is_memory import _patch_cpu_trace


def test_s27_cpu_hook_records_typed_executed_selector_context_idempotently(
    tmp_path: Path,
) -> None:
    cpu_trace = tmp_path / "crates" / "core" / "machine" / "src" / "cpu" / "trace.rs"
    cpu_trace.parent.mkdir(parents=True)
    cpu_trace.write_text(
        "impl CpuChip {\n"
        "    fn event_to_row<F: PrimeField32>(\n"
        "        &self, event: &CpuEvent, cols: &mut CpuCols<F>, instruction: &Instruction,\n"
        "    ) {\n"
        "        cols.is_memory = F::from_bool(\n"
        "            instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction(),\n"
        "        );\n"
        "    }\n"
        "}\n"
    )

    commit = "39ab52fce38172c9d23feed7248198dc14c164a9"
    _patch_cpu_trace(cpu_trace, commit)
    once = cpu_trace.read_text()
    _patch_cpu_trace(cpu_trace, commit)
    twice = cpu_trace.read_text()

    assert twice == once
    assert once.count("sp1.v4.is_memory_underconstrained") == 1
    assert "fuzzer_utils::next_memory_selector_step()" in once
    assert "fuzzer_utils::next_witness_step()" not in once.split(
        "// BEAK-INSERT: sp1.v4.is_memory_underconstrained", 1
    )[1].split("// BEAK-INSERT-END", 1)[0]
    assert "beak_step,\n                event.pc," in once
    assert "let beak_expected_is_memory" in once
    assert "if beak_expected_is_memory && fuzzer_utils::should_inject_witness(" in once
    assert "fuzzer_utils::record_memory_selector_receipt(" in once
    assert "event.pc" in once
    assert "instruction.opcode as u32" in once
    assert "instruction.opcode.mnemonic()" in once
    assert "beak_rv_instruction" in once
    assert commit in once


def test_s28_executor_hook_records_typed_executed_ecall_operands_idempotently(
    tmp_path: Path,
) -> None:
    executor = tmp_path / "crates" / "core" / "executor" / "src" / "executor.rs"
    executor.parent.mkdir(parents=True)
    executor.write_text(
        "pub const UNUSED_PC: u32 = 1;\n"
        "impl Executor {\n"
        "    fn execute_instruction(&mut self, instruction: Instruction) {\n"
        "        let mut next_pc = self.state.pc.wrapping_add(4);\n"
        "        // If the destination register is x0, then we need to make sure that a's value is 0.\n"
        "    }\n"
        "}\n"
    )

    commit = "7f643da16813af4c0fbaad4837cd7409386cf38c"
    _patch_executor(executor, commit)
    once = executor.read_text()
    _patch_executor(executor, commit)
    twice = executor.read_text()

    assert twice == once
    assert once.count("sp1.execute_instruction.control_flow_injection") == 1
    assert "Option<(String, u32)>" in once
    assert "let beak_pc = self.state.pc;" in once
    assert "let beak_observed_before = next_pc;" in once
    assert "fuzzer_utils::record_executed_control_flow_receipt(" in once
    assert "beak_pc.wrapping_add(4)" in once
    assert "instruction.opcode as u32" in once
    assert "instruction.opcode.mnemonic()" in once
    assert commit in once


def test_s27_selector_counter_is_scoped_to_the_audited_snapshot(tmp_path: Path) -> None:
    cpu_trace = tmp_path / "crates" / "core" / "machine" / "src" / "cpu" / "trace.rs"
    cpu_trace.parent.mkdir(parents=True)
    cpu_trace.write_text(
        "impl CpuChip {\n"
        "    fn event_to_row<F: PrimeField32>(\n"
        "        &self, event: &CpuEvent, cols: &mut CpuCols<F>, instruction: &Instruction,\n"
        "    ) {\n"
        "        cols.is_memory = F::from_bool(\n"
        "            instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction(),\n"
        "        );\n"
        "    }\n"
        "}\n"
    )

    _patch_cpu_trace(cpu_trace, "7f643da16813af4c0fbaad4837cd7409386cf38c")
    patched = cpu_trace.read_text()

    assert "fuzzer_utils::next_witness_step()" in patched
    assert "beak_step / 2,\n                event.pc," in patched
    assert "fuzzer_utils::next_memory_selector_step()" not in patched
