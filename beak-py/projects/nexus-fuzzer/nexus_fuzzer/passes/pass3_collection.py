from __future__ import annotations

from pathlib import Path

NEXUS_BENCHMARK_COMMIT = "636ccb360d0f4ae657ae4bb64e1e275ccec8826"
NEXUS_MEMORY_SIZE_COMMIT = "41c6c6080f46b97980053c47b078321225b4338a"
NEXUS_MUL_CARRY_COMMIT = "f1b895b868915fd4d0a794a5bc730e6cb8d840f6"
NEXUS_F2AD_COMMIT = "f2ad12652c39dc516a116447a53f8557f64a7f7d"


def _replace_once(path: Path, old: str, new: str) -> None:
    contents = path.read_text()
    if new in contents:
        return
    if old not in contents:
        raise RuntimeError(f"anchor not found in {path}: {old[:80]!r}")
    path.write_text(contents.replace(old, new, 1))


def _patch_f1_mul_carry_exception_receipt(nexus_install_path: Path) -> None:
    nexani_path = (
        nexus_install_path
        / "prover"
        / "src"
        / "chips"
        / "instructions"
        / "m"
        / "nexani.rs"
    )
    _replace_once(
        nexani_path,
        """pub(super) fn mull_limb(b: u32, c: u32) -> MulResult {
    // Convert inputs to limbs (4 bytes each)
""",
        """pub(super) fn mull_limb(b: u32, c: u32) -> MulResult {
    mull_limb_inner(b, c, None)
}

// BEAK-INSERT: nexus.f1b895b.mul_carry.executed_exception_receipt.entry
pub(super) fn mull_limb_for_executed_mul(b: u32, c: u32, step: usize) -> MulResult {
    mull_limb_inner(b, c, Some(step))
}

fn mull_limb_inner(b: u32, c: u32, executed_mul_step: Option<usize>) -> MulResult {
    // Convert inputs to limbs (4 bytes each)
""",
    )
    _replace_once(
        nexani_path,
        """    // Verify our calculations match the built-in multiplication
    assert!(carry_1 < 4, "Carry_1 exceeds expected bounds {}", carry_1);
""",
        """    // Verify our calculations match the built-in multiplication.
    // BEAK-INSERT: nexus.f1b895b.mul_carry.executed_exception_receipt.failure
    if carry_1 >= 4 {
        if let Some(step) = executed_mul_step {
            std::env::set_var(
                "BEAK_NEXUS_EXECUTED_EXCEPTION_RECEIPT",
                format!(
                    r#"{{"effect":"multiplication_carry_bound","obligation_id":"md4","cell_id":"md4.mul_overflow","stage":"mul.witness.carry_1_bound","step":{},"context":{{"backend":"nexus","commit":"f1b895b868915fd4d0a794a5bc730e6cb8d840f6","trace_source":"instruction","rs1_val":{},"rs2_val":{},"product_hi":{},"product_lo":{},"carry_1":{},"carry_bound_exclusive":4}}}}"#,
                    step,
                    b,
                    c,
                    product >> 32,
                    product as u32,
                    carry_1,
                ),
            );
        }
    }
    assert!(carry_1 < 4, "Carry_1 exceeds expected bounds {}", carry_1);
""",
    )

    mul_path = (
        nexus_install_path
        / "prover"
        / "src"
        / "chips"
        / "instructions"
        / "m"
        / "mul.rs"
    )
    _replace_once(
        mul_path,
        """use super::{gadget::constrain_mul_partial_product, nexani::mull_limb};
""",
        """// BEAK-INSERT: nexus.f1b895b.mul_carry.executed_exception_receipt.import
use super::{
    gadget::constrain_mul_partial_product,
    nexani::mull_limb_for_executed_mul,
};
""",
    )
    _replace_once(
        mul_path,
        """        let mul_result = mull_limb(u32::from_le_bytes(value_b), u32::from_le_bytes(value_c));
""",
        """        // BEAK-INSERT: nexus.f1b895b.mul_carry.executed_exception_receipt.call
        let mul_result = mull_limb_for_executed_mul(
            u32::from_le_bytes(value_b),
            u32::from_le_bytes(value_c),
            row_idx,
        );
""",
    )


def _patch_41_memory_table_population_receipt(nexus_install_path: Path) -> None:
    machine_path = nexus_install_path / "prover" / "src" / "machine.rs"
    if machine_path.exists():
        contents = machine_path.read_text()
        legacy_start = contents.find(
            "        // BEAK-INSERT: nexus.41c6.memory_table_population_receipt\n"
        )
        if legacy_start >= 0:
            legacy_end_marker = "        // BEAK-INSERT-END\n"
            legacy_end = contents.find(legacy_end_marker, legacy_start)
            if legacy_end < 0:
                raise RuntimeError("unterminated legacy Nexus-41 receipt patch")
            legacy_end += len(legacy_end_marker)
            machine_path.write_text(contents[:legacy_start] + contents[legacy_end:])

    sidenote_path = nexus_install_path / "prover" / "src" / "trace" / "sidenote.rs"
    _replace_once(
        sidenote_path,
        """    /// Public output with the exit code.
    pub(crate) public_output: BTreeMap<u32, u8>,
}
""",
        """    /// Public output with the exit code.
    pub(crate) public_output: BTreeMap<u32, u8>,
    // BEAK-INSERT: nexus.41c6.memory_table_public_rows
    pub(crate) beak_public_rows: usize,
}
""",
    )
    _replace_once(
        sidenote_path,
        """        ret.public_output = public_output;
        ret
""",
        """        // BEAK-INSERT: nexus.41c6.memory_table_public_rows.value
        ret.beak_public_rows = init_memory
            .len()
            .saturating_add(public_output.len())
            .saturating_add(exit_code.len());
        ret.public_output = public_output;
        ret
""",
    )

    load_store_path = (
        nexus_install_path
        / "prover"
        / "src"
        / "chips"
        / "instructions"
        / "load_store.rs"
    )
    legacy_population_patch = r'''        assert_eq!(row_idx + 1, traces.num_rows());

        // BEAK-INSERT: nexus.41c6.memory_table_population_receipt
        let beak_population_rows = side_note.rw_mem_check.last_access.len();
        let beak_allocated_rows = traces.num_rows();
        let beak_public_rows = side_note.rw_mem_check.beak_public_rows;
        let beak_boundary_k = beak_allocated_rows.trailing_zeros();
        let beak_exact_crossing = beak_allocated_rows.is_power_of_two()
            && beak_population_rows == beak_allocated_rows.saturating_add(1)
            && beak_public_rows <= beak_allocated_rows;
        std::env::set_var(
            "BEAK_NEXUS_MEMORY_TABLE_BOUNDARY_RECEIPT",
            format!(
                r#"{{"schema_version":1,"relation":"last_access_population_crosses_allocated_rows_by_one","table_name":"rw_mem_check.last_access","population_rows":{},"allocated_rows":{},"public_rows":{},"boundary_k":{},"exact_crossing":{}}}"#,
                beak_population_rows,
                beak_allocated_rows,
                beak_public_rows,
                beak_boundary_k,
                beak_exact_crossing,
            ),
        );
        // BEAK-INSERT-END

        // side_note.rw_mem_check.last_access contains the last access time and value for every address under RW memory checking
        for (row_idx, (address, (last_access, last_value))) in
            side_note.rw_mem_check.last_access.iter().enumerate()
        {
            if beak_exact_crossing && row_idx == beak_allocated_rows {
                std::env::set_var(
                    "BEAK_NEXUS_EXECUTED_EXCEPTION_RECEIPT",
                    format!(
                        r#"{{"effect":"memory_table_capacity_write","obligation_id":"pd3","cell_id":"pd3.mem_table","stage":"rw_mem_check.last_access.write","step":{},"context":{{"backend":"nexus","commit":"41c6c6080f46b97980053c47b078321225b4338a","trace_source":"prover.rw_mem_check.last_access","table_name":"rw_mem_check.last_access","relation":"last_access_population_crosses_allocated_rows_at_first_overflow","relation_valid":true,"exact_crossing":true,"failure_observed":true,"failure_manifestation":"capacity_write_out_of_bounds","failing_row_idx":{},"population_rows":{},"allocated_rows":{},"public_rows":{},"boundary_k":{}}}}}"#,
                        beak_population_rows,
                        row_idx,
                        beak_population_rows,
                        beak_allocated_rows,
                        beak_public_rows,
                        beak_boundary_k,
                    ),
                );
            }
            traces.fill_columns(row_idx, *address, Column::RamInitFinalAddr);
'''
    original_population_anchor = '''        assert_eq!(row_idx + 1, traces.num_rows());

        // side_note.rw_mem_check.last_access contains the last access time and value for every address under RW memory checking
        for (row_idx, (address, (last_access, last_value))) in
            side_note.rw_mem_check.last_access.iter().enumerate()
        {
            traces.fill_columns(row_idx, *address, Column::RamInitFinalAddr);
'''
    contents = load_store_path.read_text()
    if legacy_population_patch in contents:
        load_store_path.write_text(
            contents.replace(legacy_population_patch, original_population_anchor, 1)
        )
    _replace_once(
        load_store_path,
        original_population_anchor,
        """        assert_eq!(row_idx + 1, traces.num_rows());

        // BEAK-INSERT: nexus.41c6.memory_table_population_receipt
        let beak_population_rows = side_note.rw_mem_check.last_access.len();
        let beak_allocated_rows = traces.num_rows();
        let beak_public_rows = side_note.rw_mem_check.beak_public_rows;
        let beak_boundary_k = beak_allocated_rows.trailing_zeros();
        let beak_crossing_row_idx = beak_allocated_rows;
        let beak_overflow_rows = beak_population_rows.saturating_sub(beak_allocated_rows);
        let beak_exact_crossing = beak_allocated_rows.is_power_of_two()
            && beak_population_rows > beak_allocated_rows
            && beak_public_rows <= beak_allocated_rows;
        let (beak_failing_address, beak_last_access_timestamp, beak_last_value) =
            if beak_exact_crossing {
                side_note
                    .rw_mem_check
                    .last_access
                    .iter()
                    .nth(beak_crossing_row_idx)
                    .map(|(address, (last_access, last_value))| {
                        (*address, *last_access, *last_value)
                    })
                    .unwrap_or((0, 0, 0))
            } else {
                (0, 0, 0)
            };
        std::env::set_var(
            "BEAK_NEXUS_MEMORY_TABLE_BOUNDARY_RECEIPT",
            format!(
                r#"{{"schema_version":1,"relation":"last_access_population_crosses_allocated_rows_at_first_overflow","table_name":"rw_mem_check.last_access","population_rows":{},"allocated_rows":{},"public_rows":{},"boundary_k":{},"crossing_row_idx":{},"overflow_rows":{},"exact_crossing":{},"failing_table_row_idx":{},"failing_address":{},"last_access_timestamp":{},"last_value":{}}}"#,
                beak_population_rows,
                beak_allocated_rows,
                beak_public_rows,
                beak_boundary_k,
                beak_crossing_row_idx,
                beak_overflow_rows,
                beak_exact_crossing,
                beak_crossing_row_idx,
                beak_failing_address,
                beak_last_access_timestamp,
                beak_last_value,
            ),
        );
        // BEAK-INSERT-END

        // side_note.rw_mem_check.last_access contains the last access time and value for every address under RW memory checking
        for (row_idx, (address, (last_access, last_value))) in
            side_note.rw_mem_check.last_access.iter().enumerate()
        {
            if beak_exact_crossing && row_idx == beak_crossing_row_idx {
                std::env::set_var(
                    "BEAK_NEXUS_EXECUTED_EXCEPTION_RECEIPT",
                    format!(
                        r#"{{"effect":"memory_table_capacity_write","obligation_id":"pd3","cell_id":"pd3.mem_table","stage":"rw_mem_check.last_access.write","step":{},"context":{{"backend":"nexus","commit":"41c6c6080f46b97980053c47b078321225b4338a","trace_source":"prover.rw_mem_check.last_access","table_name":"rw_mem_check.last_access","relation":"last_access_population_crosses_allocated_rows_at_first_overflow","relation_valid":true,"exact_crossing":true,"failure_observed":true,"failure_manifestation":"capacity_write_out_of_bounds","failing_row_idx":{},"population_rows":{},"allocated_rows":{},"public_rows":{},"boundary_k":{},"crossing_row_idx":{},"overflow_rows":{}}}}}"#,
                        beak_crossing_row_idx,
                        row_idx,
                        beak_population_rows,
                        beak_allocated_rows,
                        beak_public_rows,
                        beak_boundary_k,
                        beak_crossing_row_idx,
                        beak_overflow_rows,
                    ),
                );
            }
            traces.fill_columns(row_idx, *address, Column::RamInitFinalAddr);
""",
    )


def _patch_f2ad_prover2_resource_guard(nexus_install_path: Path) -> None:
    path = nexus_install_path / "prover2" / "trace" / "src" / "builder.rs"
    contents = path.read_text()
    helper_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.trace_builder.resource_guard"
    helper_anchor = """use super::utils::{self, IntoBaseFields};
"""
    helper = """use super::utils::{self, IntoBaseFields};

// BEAK-INSERT: nexus.f2ad126.prover2.trace_builder.resource_guard
const BEAK_NEXUS_MAX_PROVER_LOG_SIZE_ENV: &str = "BEAK_NEXUS_MAX_PROVER_LOG_SIZE";
const BEAK_NEXUS_MAX_TRACE_CELLS_ENV: &str = "BEAK_NEXUS_MAX_TRACE_CELLS";
const BEAK_NEXUS_DEFAULT_MAX_PROVER_LOG_SIZE: u32 = 22;
const BEAK_NEXUS_DEFAULT_MAX_TRACE_CELLS: usize = 134_217_728;

fn beak_nexus_env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(default)
}

fn beak_nexus_env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

fn beak_nexus_guard_trace_allocation(log_size: u32, columns_num: usize) {
    if log_size >= usize::BITS {
        panic!(
            "beak nexus resource guard: prover trace log_size {log_size} cannot \
             fit in usize-backed vectors"
        );
    }

    let max_log_size = beak_nexus_env_u32(
        BEAK_NEXUS_MAX_PROVER_LOG_SIZE_ENV,
        BEAK_NEXUS_DEFAULT_MAX_PROVER_LOG_SIZE,
    );
    if log_size > max_log_size {
        panic!(
            "beak nexus resource guard: prover trace log_size {log_size} exceeds \
             {max_log_size}; set {BEAK_NEXUS_MAX_PROVER_LOG_SIZE_ENV} to override"
        );
    }

    let rows = 1usize.checked_shl(log_size).unwrap_or(usize::MAX);
    let cells = rows.checked_mul(columns_num).unwrap_or(usize::MAX);
    let max_cells = beak_nexus_env_usize(
        BEAK_NEXUS_MAX_TRACE_CELLS_ENV,
        BEAK_NEXUS_DEFAULT_MAX_TRACE_CELLS,
    );
    if cells > max_cells {
        panic!(
            "beak nexus resource guard: prover trace allocation would create \
             {cells} cells ({columns_num} columns * 2^{log_size} rows), exceeding \
             {max_cells}; set {BEAK_NEXUS_MAX_TRACE_CELLS_ENV} to override"
        );
    }
}
"""
    if helper_guard not in contents:
        _replace_once(path, helper_anchor, helper)

    contents = path.read_text()
    call_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.trace_builder.resource_guard.call"
    call_anchor = """    pub fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self {
            cols: vec![vec![BaseField::zero(); 1 << log_size]; C::COLUMNS_NUM],
            log_size,
            phantom_data: PhantomData,
        }
    }
"""
    call = """    pub fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        // BEAK-INSERT: nexus.f2ad126.prover2.trace_builder.resource_guard.call
        beak_nexus_guard_trace_allocation(log_size, C::COLUMNS_NUM);
        Self {
            cols: vec![vec![BaseField::zero(); 1 << log_size]; C::COLUMNS_NUM],
            log_size,
            phantom_data: PhantomData,
        }
    }
"""
    if call_guard not in contents:
        _replace_once(path, call_anchor, call)


def _patch_f2ad_vm_resource_guards(nexus_install_path: Path) -> None:
    executor_path = nexus_install_path / "vm" / "src" / "emulator" / "executor.rs"
    contents = executor_path.read_text()
    helper_guard = "// BEAK-INSERT: nexus.f2ad126.vm.execution_resource_guard"
    helper_anchor = """use std::{
    cmp::max,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    rc::Rc,
};
"""
    helper = """use std::{
    cmp::max,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    rc::Rc,
};

// BEAK-INSERT: nexus.f2ad126.vm.execution_resource_guard
const BEAK_NEXUS_MAX_EXEC_STEPS_ENV: &str = "BEAK_NEXUS_MAX_EXEC_STEPS";
const BEAK_NEXUS_DEFAULT_MAX_EXEC_STEPS: usize = 262_144;

fn beak_nexus_max_exec_steps() -> usize {
    std::env::var(BEAK_NEXUS_MAX_EXEC_STEPS_ENV)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(BEAK_NEXUS_DEFAULT_MAX_EXEC_STEPS)
}
"""
    if helper_guard not in contents:
        _replace_once(executor_path, helper_anchor, helper)

    contents = executor_path.read_text()
    call_guard = "// BEAK-INSERT: nexus.f2ad126.vm.execution_resource_guard.call"
    call_anchor = """    ) -> Result<(Vec<InstructionResult>, MemoryTranscript)> {
        let mut results: Vec<InstructionResult> = Vec::new();
        let mut transcript: MemoryTranscript = Vec::new();

        loop {
            let basic_block_entry = self.fetch_block(self.get_executor().cpu.pc.value)?;
            let (res, mem) =
                self.execute_basic_block(&basic_block_entry, force_provable_transcript)?;

            results.extend(res);
            transcript.extend(mem);
        }
    }
"""
    call = """    ) -> Result<(Vec<InstructionResult>, MemoryTranscript)> {
        let mut results: Vec<InstructionResult> = Vec::new();
        let mut transcript: MemoryTranscript = Vec::new();
        // BEAK-INSERT: nexus.f2ad126.vm.execution_resource_guard.call
        let max_exec_steps = beak_nexus_max_exec_steps();

        loop {
            let basic_block_entry = self.fetch_block(self.get_executor().cpu.pc.value)?;
            let (res, mem) =
                self.execute_basic_block(&basic_block_entry, force_provable_transcript)?;

            results.extend(res);
            transcript.extend(mem);
            if results.len() > max_exec_steps {
                Err(VMErrorKind::VMOutOfInstructions)?;
            }
        }
    }
"""
    if call_guard not in contents:
        _replace_once(executor_path, call_anchor, call)

    trace_path = nexus_install_path / "vm" / "src" / "trace.rs"
    contents = trace_path.read_text()
    trace_helper_guard = "// BEAK-INSERT: nexus.f2ad126.vm.trace_resource_guard"
    trace_helper_anchor = """use crate::{
    cpu::{instructions::InstructionResult, RegisterFile},
    elf::ElfFile,
    emulator::{Emulator, HarvardEmulator, InternalView, LinearEmulator, LinearMemoryLayout, View},
    error::{Result, VMError, VMErrorKind},
    memory::MemoryRecords,
    riscv::{BasicBlock, Instruction},
    WORD_SIZE,
};
"""
    trace_helper = """use crate::{
    cpu::{instructions::InstructionResult, RegisterFile},
    elf::ElfFile,
    emulator::{Emulator, HarvardEmulator, InternalView, LinearEmulator, LinearMemoryLayout, View},
    error::{Result, VMError, VMErrorKind},
    memory::MemoryRecords,
    riscv::{BasicBlock, Instruction},
    WORD_SIZE,
};

// BEAK-INSERT: nexus.f2ad126.vm.trace_resource_guard
const BEAK_NEXUS_MAX_TRACE_STEPS_ENV: &str = "BEAK_NEXUS_MAX_TRACE_STEPS";
const BEAK_NEXUS_MAX_EXEC_STEPS_ENV: &str = "BEAK_NEXUS_MAX_EXEC_STEPS";
const BEAK_NEXUS_DEFAULT_MAX_TRACE_STEPS: usize = 262_144;

fn beak_nexus_env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok().and_then(|s| s.parse::<usize>().ok())
}

fn beak_nexus_max_trace_steps() -> usize {
    beak_nexus_env_usize(BEAK_NEXUS_MAX_TRACE_STEPS_ENV)
        .or_else(|| beak_nexus_env_usize(BEAK_NEXUS_MAX_EXEC_STEPS_ENV))
        .unwrap_or(BEAK_NEXUS_DEFAULT_MAX_TRACE_STEPS)
}
"""
    if trace_helper_guard not in contents:
        _replace_once(trace_path, trace_helper_anchor, trace_helper)

    contents = trace_path.read_text()
    trace_call_guard = "// BEAK-INSERT: nexus.f2ad126.vm.trace_resource_guard.call"
    trace_call_anchor = """    let mut trace = UniformTrace {
        memory_layout: LinearMemoryLayout::default(), // dummy
        k,
        start: 0,
        blocks: Vec::new(),
    };

    loop {
        match k_step(&mut harvard, k, true) {
            (Some(block), Ok(())) => trace.blocks.push(block),
            (Some(block), Err(e)) => {
                if !block.steps.is_empty() {
                    trace.blocks.push(block);
                }

                match e.source {
                    VMErrorKind::VMExited(_) | VMErrorKind::VMOutOfInstructions => {
                        return Ok((harvard.finalize(), trace))
                    }
                    _ => return Err(e),
                }
            }
            (None, Err(e)) => return Err(e),
            (None, Ok(())) => unreachable!(),
        }
    }
}
"""
    trace_call = """    let mut trace = UniformTrace {
        memory_layout: LinearMemoryLayout::default(), // dummy
        k,
        start: 0,
        blocks: Vec::new(),
    };
    // BEAK-INSERT: nexus.f2ad126.vm.trace_resource_guard.call
    let max_trace_steps = beak_nexus_max_trace_steps();
    let mut observed_trace_steps = 0usize;

    loop {
        match k_step(&mut harvard, k, true) {
            (Some(block), Ok(())) => {
                observed_trace_steps = observed_trace_steps.saturating_add(block.steps.len());
                if observed_trace_steps > max_trace_steps {
                    return Err(VMErrorKind::VMOutOfInstructions.into());
                }
                trace.blocks.push(block);
            }
            (Some(block), Err(e)) => {
                observed_trace_steps = observed_trace_steps.saturating_add(block.steps.len());
                if observed_trace_steps > max_trace_steps {
                    return Err(VMErrorKind::VMOutOfInstructions.into());
                }
                if !block.steps.is_empty() {
                    trace.blocks.push(block);
                }

                match e.source {
                    VMErrorKind::VMExited(_) | VMErrorKind::VMOutOfInstructions => {
                        return Ok((harvard.finalize(), trace))
                    }
                    _ => return Err(e),
                }
            }
            (None, Err(e)) => return Err(e),
            (None, Ok(())) => unreachable!(),
        }
    }
}
"""
    if trace_call_guard not in contents:
        _replace_once(trace_path, trace_call_anchor, trace_call)


def _patch_load_store_semantic_injection(nexus_install_path: Path) -> None:
    path = nexus_install_path / "prover" / "src" / "chips" / "instructions" / "load_store.rs"
    contents = path.read_text()
    helper_guard = "// BEAK-INSERT: nexus.636ccb36.load_store.semantic_injection.helpers"
    helper_anchor = """const LOOKUP_TUPLE_SIZE: usize = 2 * WORD_SIZE_HALVED + 1;
stwo_prover::relation!(LoadStoreLookupElements, LOOKUP_TUPLE_SIZE);
"""
    helper = """const LOOKUP_TUPLE_SIZE: usize = 2 * WORD_SIZE_HALVED + 1;
stwo_prover::relation!(LoadStoreLookupElements, LOOKUP_TUPLE_SIZE);

// BEAK-INSERT: nexus.636ccb36.load_store.semantic_injection.helpers
const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";
const BEAK_NEXUS_FLOW_ADDR_ENV: &str = "BEAK_NEXUS_STORE_LOAD_FLOW_ADDR";
const BEAK_NEXUS_FLOW_CLK_ENV: &str = "BEAK_NEXUS_STORE_LOAD_FLOW_CLK";
const BEAK_NEXUS_FLOW_BYTE_ENV: &str = "BEAK_NEXUS_STORE_LOAD_FLOW_BYTE";
const BEAK_NEXUS_FLOW_STORE_STEP_ENV: &str = "BEAK_NEXUS_STORE_LOAD_FLOW_STORE_STEP";
const BEAK_NEXUS_FLOW_BEFORE_ENV: &str = "BEAK_NEXUS_STORE_LOAD_FLOW_BEFORE";
const BEAK_NEXUS_FLOW_AFTER_ENV: &str = "BEAK_NEXUS_STORE_LOAD_FLOW_AFTER";
const BEAK_NEXUS_FLOW_PC_ENV: &str = "BEAK_NEXUS_STORE_LOAD_FLOW_PC";
const BEAK_NEXUS_FLOW_RAW_ENV: &str = "BEAK_NEXUS_STORE_LOAD_FLOW_RAW";
const BEAK_NEXUS_FLOW_WIDTH_ENV: &str = "BEAK_NEXUS_STORE_LOAD_FLOW_WIDTH";
const BEAK_NEXUS_SEMANTIC_RECEIPT_ENV: &str = "BEAK_NEXUS_SEMANTIC_MUTATION_RECEIPT";

fn beak_nexus_base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn beak_nexus_should_inject(kind: &str, row_idx: usize) -> bool {
    let Ok(active_kind) = std::env::var(BEAK_NEXUS_INJECT_KIND_ENV) else {
        return false;
    };
    if beak_nexus_base_inject_kind(&active_kind) != kind {
        return false;
    }
    let target_step = std::env::var(BEAK_NEXUS_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    target_step == u64::MAX || target_step == row_idx as u64
}

fn beak_nexus_note_injection(kind: &str, row_idx: usize, site: &str) {
    std::env::set_var(BEAK_NEXUS_INJECTION_APPLIED_ENV, "true");
    println!(
        "BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED kind={kind} step={row_idx} site={site}"
    );
}

fn beak_nexus_mutate_byte_column(traces: &mut TracesBuilder, row_idx: usize, col: Column) {
    let [old] = traces.column::<1>(row_idx, col);
    let next = if old == BaseField::from(0x5au32) {
        BaseField::from(0xa5u32)
    } else {
        BaseField::from(0x5au32)
    };
    let [slot] = traces.column_mut::<1>(row_idx, col);
    *slot = next;
}

fn beak_nexus_flip_selector(traces: &mut TracesBuilder, row_idx: usize, col: Column) {
    let [old] = traces.column::<1>(row_idx, col);
    let next = if old == BaseField::from(0u32) {
        BaseField::from(1u32)
    } else {
        BaseField::from(0u32)
    };
    let [slot] = traces.column_mut::<1>(row_idx, col);
    *slot = next;
}

fn beak_nexus_mutated_payload_byte(old: u8) -> u8 {
    if old == 0x5a {
        0xa5
    } else {
        0x5a
    }
}

fn beak_nexus_arm_store_load_flow(
    address: u32,
    clk: u32,
    store_step: usize,
    before: u32,
    after: u32,
    pc: u32,
    raw_word: u32,
    width: usize,
) {
    std::env::set_var(BEAK_NEXUS_FLOW_ADDR_ENV, address.to_string());
    std::env::set_var(BEAK_NEXUS_FLOW_CLK_ENV, clk.to_string());
    std::env::set_var(BEAK_NEXUS_FLOW_BYTE_ENV, (after as u8).to_string());
    std::env::set_var(BEAK_NEXUS_FLOW_STORE_STEP_ENV, store_step.to_string());
    std::env::set_var(BEAK_NEXUS_FLOW_BEFORE_ENV, before.to_string());
    std::env::set_var(BEAK_NEXUS_FLOW_AFTER_ENV, after.to_string());
    std::env::set_var(BEAK_NEXUS_FLOW_PC_ENV, pc.to_string());
    std::env::set_var(BEAK_NEXUS_FLOW_RAW_ENV, raw_word.to_string());
    std::env::set_var(BEAK_NEXUS_FLOW_WIDTH_ENV, width.to_string());
}

fn beak_nexus_store_load_flow_context() -> Option<(u32, u32, u8, usize, u32, u32, u32, u32, usize)> {
    let active_kind = std::env::var(BEAK_NEXUS_INJECT_KIND_ENV).ok()?;
    if beak_nexus_base_inject_kind(&active_kind)
        != "nexus.semantic.memory.store_load_payload_flow"
    {
        return None;
    }
    let address = std::env::var(BEAK_NEXUS_FLOW_ADDR_ENV).ok()?.parse::<u32>().ok()?;
    let clk = std::env::var(BEAK_NEXUS_FLOW_CLK_ENV).ok()?.parse::<u32>().ok()?;
    let byte = std::env::var(BEAK_NEXUS_FLOW_BYTE_ENV).ok()?.parse::<u8>().ok()?;
    let store_step = std::env::var(BEAK_NEXUS_FLOW_STORE_STEP_ENV).ok()?.parse::<usize>().ok()?;
    let before = std::env::var(BEAK_NEXUS_FLOW_BEFORE_ENV).ok()?.parse::<u32>().ok()?;
    let after = std::env::var(BEAK_NEXUS_FLOW_AFTER_ENV).ok()?.parse::<u32>().ok()?;
    let pc = std::env::var(BEAK_NEXUS_FLOW_PC_ENV).ok()?.parse::<u32>().ok()?;
    let raw_word = std::env::var(BEAK_NEXUS_FLOW_RAW_ENV).ok()?.parse::<u32>().ok()?;
    let width = std::env::var(BEAK_NEXUS_FLOW_WIDTH_ENV).ok()?.parse::<usize>().ok()?;
    Some((address, clk, byte, store_step, before, after, pc, raw_word, width))
}

fn beak_nexus_mem_mnemonic(raw_word: u32) -> &'static str {
    match (raw_word & 0x7f, (raw_word >> 12) & 0x7) {
        (0x23, 0) => "sb",
        (0x23, 1) => "sh",
        (0x23, 2) => "sw",
        (0x03, 0) => "lb",
        (0x03, 1) => "lh",
        (0x03, 2) => "lw",
        (0x03, 4) => "lbu",
        (0x03, 5) => "lhu",
        _ => "unknown",
    }
}

#[allow(clippy::type_complexity)]

#[allow(clippy::type_complexity)]

fn beak_nexus_store_load_flow_raw_load_value(
    memory_record: &nexus_common::memory::MemoryRecord,
    side_note: &SideNote,
    load_step: usize,
    load_pc: u32,
    load_raw_word: u32,
    load_timestamp: u32,
) -> Option<u32> {
    let (address, clk, byte, store_step, store_before, store_after, store_pc, store_raw_word, store_width) =
        beak_nexus_store_load_flow_context()?;
    if memory_record.get_address() != address {
        return None;
    }
    let Some((last_clk, last_value)) = side_note.rw_mem_check.last_access.get(&address) else {
        return None;
    };
    if *last_clk != clk || *last_value != byte {
        return None;
    }
    let mut raw = memory_record.get_value().to_le_bytes();
    raw[0] = byte;
    let load_before = memory_record.get_value();
    let load_after = u32::from_le_bytes(raw);
    let expected_store_after = (store_before & 0xffff_ff00)
        | u32::from(beak_nexus_mutated_payload_byte(store_before as u8));
    let load_width = memory_record.get_size() as usize;
    if memory_record.get_size() == MemAccessSize::Word
        && store_before == load_before
        && store_after == expected_store_after
        && store_after == load_after
        && store_step < load_step
    {
        let store_mnemonic = beak_nexus_mem_mnemonic(store_raw_word);
        let load_mnemonic = beak_nexus_mem_mnemonic(load_raw_word);
        std::env::set_var(
            BEAK_NEXUS_SEMANTIC_RECEIPT_ENV,
            format!(
                r#"{{"inject_kind":"nexus.semantic.memory.store_load_payload_flow","site":"load_store.store_value_lower_byte","field":"load_store.payload","step":{},"before":{},"after":{},"effect":{{"relation":"store_load_payload_equation","context":{{"bucket_id":"sem.memory.store_load_payload_flow","obligation_id":"me1","cell_id":"me1.sw_lw","backend":"nexus","commit":"636ccb360d0f4ae657ae4bb64e1e275ccec8826","trace_source":"memory","executed_store":true,"executed_load":true,"mutation_mode":"replace_low_byte_5a_a5","manifestation":"store_and_load_payload_changed","store_step":{},"store_step_idx":{},"load_step":{},"load_step_idx":{},"store_timestamp":{},"load_timestamp":{},"store_pc":{},"load_pc":{},"store_raw_word":{},"load_raw_word":{},"store_opcode":"0x{:08x}","load_opcode":"0x{:08x}","store_mnemonic":"{}","load_mnemonic":"{}","store_address":{},"load_address":{},"store_width":{},"load_width":{},"store_value":{},"store_value_before":{},"store_value_after":{},"load_value_before":{},"load_value_after":{},"width":4}}}}}}"#,
                store_step,
                store_before,
                store_after,
                store_step,
                store_step,
                load_step,
                load_step,
                clk,
                load_timestamp,
                store_pc,
                load_pc,
                store_raw_word,
                load_raw_word,
                store_raw_word,
                load_raw_word,
                store_mnemonic,
                load_mnemonic,
                address,
                address,
                store_width,
                load_width,
                store_before,
                store_before,
                store_after,
                load_before,
                load_after,
            ),
        );
    }
    Some(load_after)
}

fn beak_nexus_extend_load_value(raw_value: u32, opcode: Option<BuiltinOpcode>) -> u32 {
    match opcode {
        Some(BuiltinOpcode::LB) => ((raw_value as u8 as i8) as i32) as u32,
        Some(BuiltinOpcode::LH) => ((raw_value as u16 as i16) as i32) as u32,
        _ => raw_value,
    }
}

fn beak_nexus_mutate_load_store_trace(
    traces: &mut TracesBuilder,
    row_idx: usize,
    is_load: bool,
) {
    if !is_load
        && beak_nexus_should_inject(
            "nexus.semantic.memory.write_payload_consistency",
            row_idx,
        )
    {
        beak_nexus_mutate_byte_column(traces, row_idx, Ram1ValPrev);
        beak_nexus_note_injection(
            "nexus.semantic.memory.write_payload_consistency",
            row_idx,
            "load_store.ram1_val_prev",
        );
    }

    if beak_nexus_should_inject(
        "nexus.semantic.memory.kind_selector_consistency",
        row_idx,
    ) {
        let selector = if is_load { IsLw } else { IsSw };
        beak_nexus_flip_selector(traces, row_idx, selector);
        beak_nexus_note_injection(
            "nexus.semantic.memory.kind_selector_consistency",
            row_idx,
            "load_store.kind_selector",
        );
    }
}
"""
    if helper_guard in contents:
        helper_start = contents.index(helper_guard)
        helper_end = contents.index("impl MachineChip for LoadStoreChip", helper_start)
        helper_payload = helper[helper.index(helper_guard) :]
        if contents[helper_start:helper_end].strip() != helper_payload.strip():
            contents = contents[:helper_start] + helper_payload + "\n" + contents[helper_end:]
            path.write_text(contents)
    if helper_guard not in contents:
        _replace_once(path, helper_anchor, helper)

    contents = path.read_text()
    call_guard = "// BEAK-INSERT: nexus.636ccb36.load_store.semantic_injection.call"
    call_anchor = """            }
        }
    }

    fn fill_interaction_trace(
"""
    call = """            }
        }
        // BEAK-INSERT: nexus.636ccb36.load_store.semantic_injection.call
        beak_nexus_mutate_load_store_trace(traces, row_idx, is_load);
    }

    fn fill_interaction_trace(
"""
    if call_guard not in contents:
        _replace_once(path, call_anchor, call)

    contents = path.read_text()
    flow_value_guard = (
        "beak_nexus_store_load_flow_raw_load_value(memory_record, side_note, row_idx)"
    )
    flow_value_anchor = """            if is_load {
                let cur_value_extended =
                    vm_step.step.result.expect("load operation should have a result");
                match memory_record.get_size() {
                    MemAccessSize::Byte => {
                        assert_eq!(cur_value_extended & 0xff, memory_record.get_value() & 0xff);
                        traces.fill_columns(
                            row_idx,
                            (cur_value_extended & 0x7f) as u8,
                            Column::QtAux,
                        );
                    }
                    MemAccessSize::HalfWord => {
                        assert_eq!(cur_value_extended & 0xffff, memory_record.get_value() & 0xffff);
                        traces.fill_columns(
                            row_idx,
                            ((cur_value_extended >> 8) & 0x7f) as u8,
                            Column::QtAux,
                        );
                    }
                    MemAccessSize::Word => {
                        assert_eq!(cur_value_extended, memory_record.get_value());
                    }
                }
                traces.fill_columns(row_idx, cur_value_extended, Column::ValueA);
            }
            let cur_value: Word = memory_record.get_value().to_le_bytes();
"""
    flow_value_anchor_pretty = """            if is_load {
                let cur_value_extended = vm_step
                    .step
                    .result
                    .expect("load operation should have a result");
                match memory_record.get_size() {
                    MemAccessSize::Byte => {
                        assert_eq!(cur_value_extended & 0xff, memory_record.get_value() & 0xff);
                        traces.fill_columns(
                            row_idx,
                            (cur_value_extended & 0x7f) as u8,
                            Column::QtAux,
                        );
                    }
                    MemAccessSize::HalfWord => {
                        assert_eq!(
                            cur_value_extended & 0xffff,
                            memory_record.get_value() & 0xffff
                        );
                        traces.fill_columns(
                            row_idx,
                            ((cur_value_extended >> 8) & 0x7f) as u8,
                            Column::QtAux,
                        );
                    }
                    MemAccessSize::Word => {
                        assert_eq!(cur_value_extended, memory_record.get_value());
                    }
                }
                traces.fill_columns(row_idx, cur_value_extended, Column::ValueA);
            }
            let cur_value: Word = memory_record.get_value().to_le_bytes();
"""
    flow_value_patch = """            let injected_load_raw_value = beak_nexus_store_load_flow_raw_load_value(
                memory_record,
                side_note,
                row_idx,
                vm_step.step.pc,
                vm_step.step.raw_instruction,
                clk,
            );
            if is_load {
                let raw_value_for_assert =
                    injected_load_raw_value.unwrap_or_else(|| memory_record.get_value());
                let cur_value_extended = injected_load_raw_value
                    .map(|raw| {
                        beak_nexus_extend_load_value(
                            raw,
                            vm_step.step.instruction.opcode.builtin(),
                        )
                    })
                    .unwrap_or_else(|| {
                        vm_step.step.result.expect("load operation should have a result")
                    });
                match memory_record.get_size() {
                    MemAccessSize::Byte => {
                        assert_eq!(cur_value_extended & 0xff, raw_value_for_assert & 0xff);
                        traces.fill_columns(
                            row_idx,
                            (cur_value_extended & 0x7f) as u8,
                            Column::QtAux,
                        );
                    }
                    MemAccessSize::HalfWord => {
                        assert_eq!(cur_value_extended & 0xffff, raw_value_for_assert & 0xffff);
                        traces.fill_columns(
                            row_idx,
                            ((cur_value_extended >> 8) & 0x7f) as u8,
                            Column::QtAux,
                        );
                    }
                    MemAccessSize::Word => {
                        assert_eq!(cur_value_extended, raw_value_for_assert);
                    }
                }
                traces.fill_columns(row_idx, cur_value_extended, Column::ValueA);
            }
            let mut cur_value: Word =
                injected_load_raw_value.unwrap_or_else(|| memory_record.get_value()).to_le_bytes();
            if !is_load
                && beak_nexus_should_inject(
                    "nexus.semantic.memory.store_load_payload_flow",
                    row_idx,
                )
            {
                cur_value[0] = beak_nexus_mutated_payload_byte(cur_value[0]);
                beak_nexus_arm_store_load_flow(
                    byte_address,
                    clk,
                    row_idx,
                    memory_record.get_value(),
                    u32::from_le_bytes(cur_value),
                    vm_step.step.pc,
                    vm_step.step.raw_instruction,
                    memory_record.get_size() as usize,
                );
                beak_nexus_note_injection(
                    "nexus.semantic.memory.store_load_payload_flow",
                    row_idx,
                    "load_store.store_value_lower_byte",
                );
            }
"""
    contents = path.read_text()
    if "BEAK_NEXUS_FLOW_STORE_STEP_ENV" in contents:
        contents = contents.replace(
            "beak_nexus_store_load_flow_raw_load_value(memory_record, side_note);",
            """beak_nexus_store_load_flow_raw_load_value(
                memory_record,
                side_note,
                row_idx,
                vm_step.step.pc,
                vm_step.step.raw_instruction,
                clk,
            );""",
        )
        contents = contents.replace(
            "beak_nexus_store_load_flow_raw_load_value(memory_record, side_note, row_idx);",
            """beak_nexus_store_load_flow_raw_load_value(
                memory_record,
                side_note,
                row_idx,
                vm_step.step.pc,
                vm_step.step.raw_instruction,
                clk,
            );""",
        )
        contents = contents.replace(
            "beak_nexus_arm_store_load_flow(byte_address, clk, cur_value[0]);",
            """beak_nexus_arm_store_load_flow(
                    byte_address,
                    clk,
                    row_idx,
                    memory_record.get_value(),
                    u32::from_le_bytes(cur_value),
                    vm_step.step.pc,
                    vm_step.step.raw_instruction,
                    memory_record.get_size() as usize,
                );""",
        )
        contents = contents.replace(
            """beak_nexus_arm_store_load_flow(
                    byte_address,
                    clk,
                    row_idx,
                    memory_record.get_value(),
                    u32::from_le_bytes(cur_value),
                );""",
            """beak_nexus_arm_store_load_flow(
                    byte_address,
                    clk,
                    row_idx,
                    memory_record.get_value(),
                    u32::from_le_bytes(cur_value),
                    vm_step.step.pc,
                    vm_step.step.raw_instruction,
                    memory_record.get_size() as usize,
                );""",
        )
        path.write_text(contents)
    if flow_value_guard not in contents:
        if flow_value_anchor in contents:
            _replace_once(path, flow_value_anchor, flow_value_patch)
        else:
            _replace_once(path, flow_value_anchor_pretty, flow_value_patch)


def _patch_load_store_extended_semantic_injection(nexus_install_path: Path) -> None:
    path = nexus_install_path / "prover" / "src" / "chips" / "instructions" / "load_store.rs"
    helper_guard = "// BEAK-INSERT: nexus.636ccb36.load_store.extended_semantic_injection.helpers"
    helper_anchor = """fn beak_nexus_flip_selector(traces: &mut TracesBuilder, row_idx: usize, col: Column) {
    let [old] = traces.column::<1>(row_idx, col);
    let next = if old == BaseField::from(0u32) {
        BaseField::from(1u32)
    } else {
        BaseField::from(0u32)
    };
    let [slot] = traces.column_mut::<1>(row_idx, col);
    *slot = next;
}
"""
    helper = helper_anchor + """
// BEAK-INSERT: nexus.636ccb36.load_store.extended_semantic_injection.helpers
fn beak_nexus_mutate_word_column(traces: &mut TracesBuilder, row_idx: usize, col: Column) {
    let [old, _, _, _] = traces.column::<4>(row_idx, col);
    let next = if old == BaseField::from(0x5au32) {
        BaseField::from(0xa5u32)
    } else {
        BaseField::from(0x5au32)
    };
    for (idx, slot) in traces.column_mut::<4>(row_idx, col).into_iter().enumerate() {
        if idx == 0 {
            *slot = next;
        }
    }
}

fn beak_nexus_mutate_load_store_extended_trace(
    traces: &mut TracesBuilder,
    row_idx: usize,
    is_load: bool,
) {
    if beak_nexus_should_inject(
        "nexus.semantic.memory.address_pointer_consistency",
        row_idx,
    ) {
        beak_nexus_mutate_word_column(traces, row_idx, Column::RamBaseAddr);
        beak_nexus_note_injection(
            "nexus.semantic.memory.address_pointer_consistency",
            row_idx,
            "load_store.ram_base_addr",
        );
    }

    if beak_nexus_should_inject(
        "nexus.semantic.memory.address_alignment_consistency",
        row_idx,
    ) {
        beak_nexus_mutate_word_column(traces, row_idx, Column::RamBaseAddr);
        beak_nexus_note_injection(
            "nexus.semantic.memory.address_alignment_consistency",
            row_idx,
            "load_store.ram_base_addr",
        );
    }

    if beak_nexus_should_inject(
        "nexus.semantic.memory.address_progression_consistency",
        row_idx,
    ) {
        beak_nexus_mutate_word_column(traces, row_idx, Column::RamBaseAddr);
        beak_nexus_note_injection(
            "nexus.semantic.memory.address_progression_consistency",
            row_idx,
            "load_store.ram_base_addr",
        );
    }

    if is_load
        && beak_nexus_should_inject(
            "nexus.semantic.memory.load_value_binding",
            row_idx,
        )
    {
        beak_nexus_mutate_word_column(traces, row_idx, Column::ValueA);
        beak_nexus_note_injection(
            "nexus.semantic.memory.load_value_binding",
            row_idx,
            "load_store.value_a",
        );
    }

    if beak_nexus_should_inject(
        "nexus.semantic.time.monotonic_access_ordering",
        row_idx,
    ) {
        beak_nexus_mutate_word_column(traces, row_idx, Ram1TsPrev);
        beak_nexus_note_injection(
            "nexus.semantic.time.monotonic_access_ordering",
            row_idx,
            "load_store.ram1_ts_prev",
        );
    }
}
"""
    if helper_guard not in path.read_text():
        _replace_once(path, helper_anchor, helper)

    call_guard = "// BEAK-INSERT: nexus.636ccb36.load_store.extended_semantic_injection.call"
    call_anchor = """        // BEAK-INSERT: nexus.636ccb36.load_store.semantic_injection.call
        beak_nexus_mutate_load_store_trace(traces, row_idx, is_load);
    }
"""
    call = """        // BEAK-INSERT: nexus.636ccb36.load_store.semantic_injection.call
        beak_nexus_mutate_load_store_trace(traces, row_idx, is_load);
        // BEAK-INSERT: nexus.636ccb36.load_store.extended_semantic_injection.call
        beak_nexus_mutate_load_store_extended_trace(traces, row_idx, is_load);
    }
"""
    if call_guard not in path.read_text():
        _replace_once(path, call_anchor, call)


def _common_injection_helpers(function_name: str, body: str) -> str:
    return f"""// BEAK-INSERT: nexus.636ccb36.{function_name}.semantic_injection.helpers
const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";

fn beak_nexus_base_inject_kind(kind: &str) -> &str {{
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}}

fn beak_nexus_should_inject(kind: &str, row_idx: usize) -> bool {{
    let Ok(active_kind) = std::env::var(BEAK_NEXUS_INJECT_KIND_ENV) else {{
        return false;
    }};
    if beak_nexus_base_inject_kind(&active_kind) != kind {{
        return false;
    }}
    let target_step = std::env::var(BEAK_NEXUS_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    target_step == u64::MAX || target_step == row_idx as u64
}}

fn beak_nexus_note_injection(kind: &str, row_idx: usize, site: &str) {{
    std::env::set_var(BEAK_NEXUS_INJECTION_APPLIED_ENV, "true");
    println!(
        "BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED kind={{kind}} step={{row_idx}} site={{site}}"
    );
}}

{body}
"""


def _word_mutator_source() -> str:
    return """fn beak_nexus_mutate_word_column(traces: &mut TracesBuilder, row_idx: usize, col: Column) {
    let [old, _, _, _] = traces.column::<4>(row_idx, col);
    let next = if old == stwo_prover::core::fields::m31::BaseField::from(0x5au32) {
        stwo_prover::core::fields::m31::BaseField::from(0xa5u32)
    } else {
        stwo_prover::core::fields::m31::BaseField::from(0x5au32)
    };
    for (idx, slot) in traces.column_mut::<4>(row_idx, col).into_iter().enumerate() {
        if idx == 0 {
            *slot = next;
        }
    }
}
"""


def _scalar_mutator_source() -> str:
    return """fn beak_nexus_mutate_scalar_column(traces: &mut TracesBuilder, row_idx: usize, col: Column) {
    let [old] = traces.column::<1>(row_idx, col);
    let next = if old == stwo_prover::core::fields::m31::BaseField::from(0u32) {
        stwo_prover::core::fields::m31::BaseField::from(1u32)
    } else {
        stwo_prover::core::fields::m31::BaseField::from(0u32)
    };
    let [slot] = traces.column_mut::<1>(row_idx, col);
    *slot = next;
}
"""


def _pair_mutator_source() -> str:
    return """fn beak_nexus_mutate_pair_column(traces: &mut TracesBuilder, row_idx: usize, col: Column) {
    let [old, _] = traces.column::<2>(row_idx, col);
    let next = if old == stwo_prover::core::fields::m31::BaseField::from(0u32) {
        stwo_prover::core::fields::m31::BaseField::from(1u32)
    } else {
        stwo_prover::core::fields::m31::BaseField::from(0u32)
    };
    for (idx, slot) in traces.column_mut::<2>(row_idx, col).into_iter().enumerate() {
        if idx == 0 {
            *slot = next;
        }
    }
}
"""


def _patch_cpu_semantic_injection(nexus_install_path: Path) -> None:
    path = nexus_install_path / "prover" / "src" / "chips" / "cpu.rs"
    ecall_word_block = """    if beak_nexus_should_inject("nexus.semantic.control.ecall_word_validity", row_idx) {
        beak_nexus_mutate_word_column(traces, row_idx, InstrVal);
        beak_nexus_note_injection(
            "nexus.semantic.control.ecall_word_validity",
            row_idx,
            "cpu.instr_val",
        );
    }

"""
    body = (
        _word_mutator_source()
        + _scalar_mutator_source()
        + """
fn beak_nexus_mutate_reg_index_column(traces: &mut TracesBuilder, row_idx: usize, col: Column) {
    let [old] = traces.column::<1>(row_idx, col);
    let next = if old == BaseField::from(0u32) {
        BaseField::from(31u32)
    } else {
        BaseField::from(0u32)
    };
    let [slot] = traces.column_mut::<1>(row_idx, col);
    *slot = next;
}

fn beak_nexus_mutate_cpu_trace(traces: &mut TracesBuilder, row_idx: usize) {
    if beak_nexus_should_inject("nexus.semantic.decode.field_range", row_idx) {
        beak_nexus_mutate_reg_index_column(traces, row_idx, OpA);
        beak_nexus_note_injection(
            "nexus.semantic.decode.field_range",
            row_idx,
            "cpu.op_a",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.decode.immediate_sign_extension", row_idx) {
        beak_nexus_mutate_word_column(traces, row_idx, ValueC);
        beak_nexus_note_injection(
            "nexus.semantic.decode.immediate_sign_extension",
            row_idx,
            "cpu.value_c",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.decode.upper_immediate_materialization", row_idx) {
        beak_nexus_mutate_word_column(traces, row_idx, ValueC);
        beak_nexus_note_injection(
            "nexus.semantic.decode.upper_immediate_materialization",
            row_idx,
            "cpu.value_c",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.decode.format_immediate_reassembly", row_idx) {
        beak_nexus_mutate_scalar_column(traces, row_idx, OpC);
        beak_nexus_note_injection(
            "nexus.semantic.decode.format_immediate_reassembly",
            row_idx,
            "cpu.op_c",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.exec.op_selector_binding", row_idx) {
        beak_nexus_mutate_scalar_column(traces, row_idx, IsAdd);
        beak_nexus_note_injection(
            "nexus.semantic.exec.op_selector_binding",
            row_idx,
            "cpu.is_add",
        );
    }

"""
        + ecall_word_block
        + """
    if beak_nexus_should_inject("nexus.semantic.alu.immediate_limb_consistency", row_idx) {
        beak_nexus_mutate_word_column(traces, row_idx, ValueC);
        beak_nexus_note_injection(
            "nexus.semantic.alu.immediate_limb_consistency",
            row_idx,
            "cpu.value_c",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.control.entrypoint_binding", row_idx) {
        beak_nexus_mutate_word_column(traces, row_idx, Pc);
        beak_nexus_note_injection(
            "nexus.semantic.control.entrypoint_binding",
            row_idx,
            "cpu.pc",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.time.boundary_origin_consistency", row_idx) {
        beak_nexus_mutate_word_column(traces, row_idx, Pc);
        beak_nexus_note_injection(
            "nexus.semantic.time.boundary_origin_consistency",
            row_idx,
            "cpu.pc",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.exec.control_flow_binding", row_idx) {
        beak_nexus_mutate_word_column(traces, row_idx, PcNext);
        beak_nexus_note_injection(
            "nexus.semantic.exec.control_flow_binding",
            row_idx,
            "cpu.pc_next",
        );
    }
}
"""
    )
    helper_anchor = "use nexus_common::constants::KECCAKF_OPCODE;\n"
    helper = helper_anchor + "\n" + _common_injection_helpers("cpu", body)
    helper_guard = "// BEAK-INSERT: nexus.636ccb36.cpu.semantic_injection.helpers"
    contents = path.read_text()
    if helper_guard not in contents:
        _replace_once(path, helper_anchor, helper)
    elif "nexus.semantic.control.ecall_word_validity" not in contents:
        ecall_anchor = """    if beak_nexus_should_inject("nexus.semantic.alu.immediate_limb_consistency", row_idx) {
"""
        _replace_once(path, ecall_anchor, ecall_word_block + ecall_anchor)

    call_anchor = """            Unimpl => {
                panic!(
                    "Unsupported instruction type: {:?}",
                    vm_step.step.instruction.ins_type
                );
            }
        }
    }

    fn add_constraints"""
    call = """            Unimpl => {
                panic!(
                    "Unsupported instruction type: {:?}",
                    vm_step.step.instruction.ins_type
                );
            }
        }
        // BEAK-INSERT: nexus.636ccb36.cpu.semantic_injection.call
        beak_nexus_mutate_cpu_trace(traces, row_idx);
    }

    fn add_constraints"""
    _replace_once(path, call_anchor, call)


def _patch_register_semantic_injection(nexus_install_path: Path) -> None:
    path = nexus_install_path / "prover" / "src" / "chips" / "memory_check" / "register_mem_check.rs"
    body = (
        _word_mutator_source()
        + """
fn beak_nexus_mutate_register_trace(traces: &mut TracesBuilder, row_idx: usize) {
    if beak_nexus_should_inject("nexus.semantic.decode.zero_register_immutability", row_idx) {
        beak_nexus_mutate_word_column(traces, row_idx, ValueAEffective);
        beak_nexus_note_injection(
            "nexus.semantic.decode.zero_register_immutability",
            row_idx,
            "register.value_a_effective",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.exec.dest_binding", row_idx) {
        beak_nexus_mutate_word_column(traces, row_idx, ValueAEffective);
        beak_nexus_note_injection(
            "nexus.semantic.exec.dest_binding",
            row_idx,
            "register.value_a_effective",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.decode.operand_index_routing", row_idx) {
        beak_nexus_mutate_word_column(traces, row_idx, Reg1ValPrev);
        beak_nexus_note_injection(
            "nexus.semantic.decode.operand_index_routing",
            row_idx,
            "register.reg1_val_prev",
        );
    }
}
"""
    )
    helper_anchor = "stwo_prover::relation!(RegisterCheckLookupElements, LOOKUP_TUPLE_SIZE);\n"
    helper = helper_anchor + "\n" + _common_injection_helpers("register", body)
    _replace_once(path, helper_anchor, helper)

    call_anchor = """        if !reg3_accessed[0].is_zero() {
            fill_prev_values(
                reg3_address,
                reg3_value,
                side_note,
                reg3_cur_ts,
                Reg3TsPrev,
                Reg3ValPrev,
                traces,
                row_idx,
            );
        }
    }

    fn add_constraints"""
    call = """        if !reg3_accessed[0].is_zero() {
            fill_prev_values(
                reg3_address,
                reg3_value,
                side_note,
                reg3_cur_ts,
                Reg3TsPrev,
                Reg3ValPrev,
                traces,
                row_idx,
            );
        }
        // BEAK-INSERT: nexus.636ccb36.register.semantic_injection.call
        beak_nexus_mutate_register_trace(traces, row_idx);
    }

    fn add_constraints"""
    _replace_once(path, call_anchor, call)


def _patch_shift_semantic_injection(nexus_install_path: Path) -> None:
    for stem in ("sll", "srl", "sra"):
        path = nexus_install_path / "prover" / "src" / "chips" / "instructions" / f"{stem}.rs"
        body = (
            _scalar_mutator_source()
            + f"""
fn beak_nexus_mutate_shift_trace(traces: &mut TracesBuilder, row_idx: usize) {{
    if beak_nexus_should_inject("nexus.semantic.alu.shift_mod32", row_idx) {{
        beak_nexus_mutate_scalar_column(traces, row_idx, Column::ShiftBit5);
        beak_nexus_note_injection(
            "nexus.semantic.alu.shift_mod32",
            row_idx,
            "{stem}.shift_bit5",
        );
    }}
}}
"""
        )
        helper_anchor = f"pub struct {stem.capitalize()}Chip;\n"
        if stem == "srl":
            helper_anchor = "pub struct SrlChip;\n"
        elif stem == "sra":
            helper_anchor = "pub struct SraChip;\n"
        elif stem == "sll":
            helper_anchor = "pub struct SllChip;\n"
        helper = _common_injection_helpers(f"{stem}_shift", body) + helper_anchor
        _replace_once(path, helper_anchor, helper)

        call_anchor = """        traces.fill_columns(row_idx, exp1_3, Column::Exp1_3);
    }

    fn add_constraints"""
        if stem == "sra":
            call_anchor = """        traces.fill_columns(row_idx, sra_degree_aux, Column::SraDegreeAux);
    }

    fn add_constraints"""
            call = """        traces.fill_columns(row_idx, sra_degree_aux, Column::SraDegreeAux);
        // BEAK-INSERT: nexus.636ccb36.shift.semantic_injection.call
        beak_nexus_mutate_shift_trace(traces, row_idx);
    }

    fn add_constraints"""
        else:
            call = """        traces.fill_columns(row_idx, exp1_3, Column::Exp1_3);
        // BEAK-INSERT: nexus.636ccb36.shift.semantic_injection.call
        beak_nexus_mutate_shift_trace(traces, row_idx);
    }

    fn add_constraints"""
        _replace_once(path, call_anchor, call)


def _patch_comparison_semantic_injection(nexus_install_path: Path) -> None:
    for stem, struct_name in (("slt", "SltChip"), ("sltu", "SltuChip")):
        path = nexus_install_path / "prover" / "src" / "chips" / "instructions" / f"{stem}.rs"
        body = (
            _word_mutator_source()
            + _pair_mutator_source()
            + f"""
fn beak_nexus_mutate_comparison_trace(traces: &mut TracesBuilder, row_idx: usize) {{
    if beak_nexus_should_inject("nexus.semantic.alu.comparison_booleanity", row_idx) {{
        beak_nexus_mutate_word_column(traces, row_idx, ValueA);
        beak_nexus_note_injection(
            "nexus.semantic.alu.comparison_booleanity",
            row_idx,
            "{stem}.value_a",
        );
    }}

    if beak_nexus_should_inject("nexus.semantic.alu.subtraction_borrow_chain", row_idx) {{
        beak_nexus_mutate_pair_column(traces, row_idx, CarryFlag);
        beak_nexus_note_injection(
            "nexus.semantic.alu.subtraction_borrow_chain",
            row_idx,
            "{stem}.carry_flag",
        );
    }}

    if beak_nexus_should_inject("nexus.semantic.alu.comparison_auxiliary_chain", row_idx) {{
        beak_nexus_mutate_word_column(traces, row_idx, Helper1);
        beak_nexus_note_injection(
            "nexus.semantic.alu.comparison_auxiliary_chain",
            row_idx,
            "{stem}.helper1",
        );
    }}
}}
"""
        )
        helper_anchor = f"pub struct {struct_name};\n"
        helper = _common_injection_helpers(f"{stem}_comparison", body) + helper_anchor
        _replace_once(path, helper_anchor, helper)

        if stem == "slt":
            call_anchor = """        traces.fill_columns(row_idx, result, ValueA);
    }

    fn add_constraints"""
            call = """        traces.fill_columns(row_idx, result, ValueA);
        // BEAK-INSERT: nexus.636ccb36.comparison.semantic_injection.call
        beak_nexus_mutate_comparison_trace(traces, row_idx);
    }

    fn add_constraints"""
        else:
            call_anchor = """        traces.fill_columns_bytes(row_idx, &result, ValueA);
    }

    fn add_constraints"""
            call = """        traces.fill_columns_bytes(row_idx, &result, ValueA);
        // BEAK-INSERT: nexus.636ccb36.comparison.semantic_injection.call
        beak_nexus_mutate_comparison_trace(traces, row_idx);
    }

    fn add_constraints"""
        _replace_once(path, call_anchor, call)


def _patch_sub_semantic_injection(nexus_install_path: Path) -> None:
    path = nexus_install_path / "prover" / "src" / "chips" / "instructions" / "sub.rs"
    body = (
        _pair_mutator_source()
        + """
fn beak_nexus_mutate_sub_trace(traces: &mut TracesBuilder, row_idx: usize) {
    if beak_nexus_should_inject("nexus.semantic.alu.subtraction_borrow_chain", row_idx) {
        beak_nexus_mutate_pair_column(traces, row_idx, CarryFlag);
        beak_nexus_note_injection(
            "nexus.semantic.alu.subtraction_borrow_chain",
            row_idx,
            "sub.carry_flag",
        );
    }
}
"""
    )
    helper_anchor = "pub struct SubChip;\n"
    helper = _common_injection_helpers("sub", body) + helper_anchor
    _replace_once(path, helper_anchor, helper)

    call_anchor = """        traces.fill_columns_bytes(row_idx, &diff_bytes, ValueA);
        traces.fill_columns(row_idx, borrow_bits, CarryFlag);
    }

    fn add_constraints"""
    call = """        traces.fill_columns_bytes(row_idx, &diff_bytes, ValueA);
        traces.fill_columns(row_idx, borrow_bits, CarryFlag);
        // BEAK-INSERT: nexus.636ccb36.sub.semantic_injection.call
        beak_nexus_mutate_sub_trace(traces, row_idx);
    }

    fn add_constraints"""
    _replace_once(path, call_anchor, call)


def _patch_control_semantic_injection(nexus_install_path: Path) -> None:
    for stem, struct_name in (
        ("beq", "BeqChip"),
        ("bne", "BneChip"),
        ("blt", "BltChip"),
        ("bltu", "BltuChip"),
        ("bge", "BgeChip"),
        ("bgeu", "BgeuChip"),
        ("jal", "JalChip"),
        ("jalr", "JalrChip"),
    ):
        path = nexus_install_path / "prover" / "src" / "chips" / "instructions" / f"{stem}.rs"
        body = (
            _word_mutator_source()
            + f"""
fn beak_nexus_mutate_control_trace(traces: &mut TracesBuilder, row_idx: usize) {{
    if beak_nexus_should_inject("nexus.semantic.exec.control_flow_binding", row_idx) {{
        beak_nexus_mutate_word_column(traces, row_idx, Column::PcNext);
        beak_nexus_note_injection(
            "nexus.semantic.exec.control_flow_binding",
            row_idx,
            "{stem}.pc_next",
        );
    }}
}}
"""
        )
        helper_anchor = f"pub struct {struct_name};\n"
        helper = _common_injection_helpers(f"{stem}_control", body) + helper_anchor
        _replace_once(path, helper_anchor, helper)

        if stem in ("jal", "jalr"):
            call_anchor = """        traces.fill_columns(row_idx, value_a, Column::ValueA);
        traces.fill_columns(row_idx, carry_bits, Column::CarryFlag);
    }

    fn add_constraints"""
            call = """        traces.fill_columns(row_idx, value_a, Column::ValueA);
        traces.fill_columns(row_idx, carry_bits, Column::CarryFlag);
        // BEAK-INSERT: nexus.636ccb36.control.semantic_injection.call
        beak_nexus_mutate_control_trace(traces, row_idx);
    }

    fn add_constraints"""
        else:
            call_anchor = """        traces.fill_columns(row_idx, pc_next, Column::PcNext);
        traces.fill_columns(row_idx, carry_bits, Column::CarryFlag);
    }

    fn add_constraints"""
            call = """        traces.fill_columns(row_idx, pc_next, Column::PcNext);
        traces.fill_columns(row_idx, carry_bits, Column::CarryFlag);
        // BEAK-INSERT: nexus.636ccb36.control.semantic_injection.call
        beak_nexus_mutate_control_trace(traces, row_idx);
    }

    fn add_constraints"""
        _replace_once(path, call_anchor, call)


def _f2ad_common_injection_helpers(function_name: str, body: str) -> str:
    return f"""// BEAK-INSERT: nexus.f2ad126.prover2.{function_name}.semantic_injection.helpers
const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";

fn beak_nexus_base_inject_kind(kind: &str) -> &str {{
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}}

fn beak_nexus_should_inject(kind: &str, step_idx: u64) -> bool {{
    let Ok(active_kind) = std::env::var(BEAK_NEXUS_INJECT_KIND_ENV) else {{
        return false;
    }};
    if beak_nexus_base_inject_kind(&active_kind) != kind {{
        return false;
    }}
    let target_step = std::env::var(BEAK_NEXUS_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    target_step == u64::MAX || target_step == step_idx
}}

fn beak_nexus_note_injection(kind: &str, step_idx: u64, site: &str) {{
    std::env::set_var(BEAK_NEXUS_INJECTION_APPLIED_ENV, "true");
    println!(
        "BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED kind={{kind}} step={{step_idx}} site={{site}}"
    );
}}

{body}
"""


def _patch_f2ad_program_memory_semantic_injection(nexus_install_path: Path) -> None:
    path = (
        nexus_install_path
        / "prover2"
        / "machine"
        / "src"
        / "components"
        / "program_memory"
        / "trace.rs"
    )
    body = """fn beak_nexus_mutate_instr_word(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    kind: &str,
    site: &str,
) {
    let step_idx = row_idx as u64;
    if !beak_nexus_should_inject(kind, step_idx) {
        return;
    }
    trace.fill_columns(row_idx, [0x5a5au16, 0xa5a5u16], Column::InstrVal);
    beak_nexus_note_injection(kind, step_idx, site);
}

fn beak_nexus_mutate_program_memory_trace(trace: &mut TraceBuilder<Column>, row_idx: usize) {
    beak_nexus_mutate_instr_word(
        trace,
        row_idx,
        "nexus.semantic.decode.field_range",
        "program_memory.instr_val",
    );
    beak_nexus_mutate_instr_word(
        trace,
        row_idx,
        "nexus.semantic.decode.immediate_sign_extension",
        "program_memory.instr_val",
    );
    beak_nexus_mutate_instr_word(
        trace,
        row_idx,
        "nexus.semantic.decode.upper_immediate_materialization",
        "program_memory.instr_val",
    );
    beak_nexus_mutate_instr_word(
        trace,
        row_idx,
        "nexus.semantic.decode.format_immediate_reassembly",
        "program_memory.instr_val",
    );
    beak_nexus_mutate_instr_word(
        trace,
        row_idx,
        "nexus.semantic.exec.op_selector_binding",
        "program_memory.instr_val",
    );
    beak_nexus_mutate_instr_word(
        trace,
        row_idx,
        "nexus.semantic.control.ecall_word_validity",
        "program_memory.instr_val",
    );
}
"""
    helper_anchor = "use super::columns::Column;\n"
    helper = helper_anchor + "\n" + _f2ad_common_injection_helpers("program_memory", body)
    helper_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.program_memory.semantic_injection.helpers"
    if helper_guard not in path.read_text():
        _replace_once(path, helper_anchor, helper)

    call_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.program_memory.semantic_injection.call"
    call_anchor = """    range_check_mults.add_values(&prev_access_bytes);
    range_check_mults.add_values(&next_access_bytes);
}
"""
    call = """    range_check_mults.add_values(&prev_access_bytes);
    range_check_mults.add_values(&next_access_bytes);
    // BEAK-INSERT: nexus.f2ad126.prover2.program_memory.semantic_injection.call
    beak_nexus_mutate_program_memory_trace(trace, row_idx);
}
"""
    if call_guard not in path.read_text():
        _replace_once(path, call_anchor, call)


def _patch_f2ad_register_memory_semantic_injection(nexus_install_path: Path) -> None:
    path = (
        nexus_install_path
        / "prover2"
        / "machine"
        / "src"
        / "components"
        / "register_memory"
        / "trace.rs"
    )
    body = """fn beak_nexus_mutate_word_column(trace: &mut TraceBuilder<Column>, row_idx: usize, col: Column) {
    let [old, _, _, _] = trace.column::<4>(row_idx, col);
    let next = if old == BaseField::from(0x5au32) {
        BaseField::from(0xa5u32)
    } else {
        BaseField::from(0x5au32)
    };
    for (idx, slot) in trace.column_mut::<4>(row_idx, col).into_iter().enumerate() {
        if idx == 0 {
            *slot = next;
        }
    }
}

fn beak_nexus_mutate_register_memory_trace(trace: &mut TraceBuilder<Column>, row_idx: usize) {
    let step_idx = row_idx as u64;
    if beak_nexus_should_inject("nexus.semantic.decode.zero_register_immutability", step_idx) {
        beak_nexus_mutate_word_column(trace, row_idx, Column::Reg3ValCur);
        beak_nexus_note_injection(
            "nexus.semantic.decode.zero_register_immutability",
            step_idx,
            "register_memory.reg3_val_cur",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.exec.dest_binding", step_idx) {
        beak_nexus_mutate_word_column(trace, row_idx, Column::Reg3ValCur);
        beak_nexus_note_injection(
            "nexus.semantic.exec.dest_binding",
            step_idx,
            "register_memory.reg3_val_cur",
        );
    }

    if beak_nexus_should_inject("nexus.semantic.decode.operand_index_routing", step_idx) {
        beak_nexus_mutate_word_column(trace, row_idx, Column::Reg1Val);
        beak_nexus_note_injection(
            "nexus.semantic.decode.operand_index_routing",
            step_idx,
            "register_memory.reg1_val",
        );
    }
}
"""
    helper_anchor = "use super::columns::Column;\n"
    helper = helper_anchor + "\n" + _f2ad_common_injection_helpers("register_memory", body)
    helper_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.register_memory.semantic_injection.helpers"
    if helper_guard not in path.read_text():
        _replace_once(path, helper_anchor, helper)

    call_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.register_memory.semantic_injection.call"
    call_anchor = """    range_check_accum
        .range256
        .add_values(range_checked_reg3_val);
}
"""
    call = """    range_check_accum
        .range256
        .add_values(range_checked_reg3_val);
    // BEAK-INSERT: nexus.f2ad126.prover2.register_memory.semantic_injection.call
    beak_nexus_mutate_register_memory_trace(trace, row_idx);
}
"""
    if call_guard not in path.read_text():
        _replace_once(path, call_anchor, call)


def _patch_f2ad_cpu_boundary_semantic_injection(nexus_install_path: Path) -> None:
    path = (
        nexus_install_path
        / "prover2"
        / "machine"
        / "src"
        / "components"
        / "cpu_boundary"
        / "mod.rs"
    )
    body = """fn beak_nexus_mutate_cpu_boundary_preprocessed_trace(
    trace: &mut TraceBuilder<PreprocessedColumn>,
) {
    if beak_nexus_should_inject("nexus.semantic.control.entrypoint_binding", 0) {
        trace.fill_columns(0, [0x5a5au16, 0u16], PreprocessedColumn::InitPc);
        beak_nexus_note_injection(
            "nexus.semantic.control.entrypoint_binding",
            0,
            "cpu_boundary.init_pc",
        );
    }
}

fn beak_nexus_mutate_cpu_boundary_main_trace(trace: &mut TraceBuilder<Column>) {
    if beak_nexus_should_inject("nexus.semantic.time.boundary_origin_consistency", 0) {
        trace.fill_columns(0, [0x5a5au16, 0u16], Column::Clk);
        beak_nexus_note_injection(
            "nexus.semantic.time.boundary_origin_consistency",
            0,
            "cpu_boundary.init_clk",
        );
    }
}
"""
    helper_anchor = "use columns::{Column, PreprocessedColumn};\n"
    helper = helper_anchor + "\n" + _f2ad_common_injection_helpers("cpu_boundary", body)
    helper_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.cpu_boundary.semantic_injection.helpers"
    if helper_guard not in path.read_text():
        _replace_once(path, helper_anchor, helper)

    pre_call_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.cpu_boundary.preprocessed_semantic_injection.call"
    pre_call_anchor = """        trace.fill_columns_base_field(
            1,
            &[-BaseField::one()],
            PreprocessedColumn::FinalMultiplicity,
        );

        trace.finalize()
"""
    pre_call = """        trace.fill_columns_base_field(
            1,
            &[-BaseField::one()],
            PreprocessedColumn::FinalMultiplicity,
        );
        // BEAK-INSERT: nexus.f2ad126.prover2.cpu_boundary.preprocessed_semantic_injection.call
        beak_nexus_mutate_cpu_boundary_preprocessed_trace(&mut trace);

        trace.finalize()
"""
    if pre_call_guard not in path.read_text():
        _replace_once(path, pre_call_anchor, pre_call)

    main_call_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.cpu_boundary.main_semantic_injection.call"
    main_call_anchor = """        trace.fill_columns(1, final_pc_parts, Column::FinalPc);
        trace.fill_columns(1, final_clk_parts, Column::Clk);

        trace.finalize()
"""
    main_call = """        trace.fill_columns(1, final_pc_parts, Column::FinalPc);
        trace.fill_columns(1, final_clk_parts, Column::Clk);
        // BEAK-INSERT: nexus.f2ad126.prover2.cpu_boundary.main_semantic_injection.call
        beak_nexus_mutate_cpu_boundary_main_trace(&mut trace);

        trace.finalize()
"""
    if main_call_guard not in path.read_text():
        _replace_once(path, main_call_anchor, main_call)


def _patch_f2ad_ecall_semantic_injection(nexus_install_path: Path) -> None:
    path = (
        nexus_install_path
        / "prover2"
        / "machine"
        / "src"
        / "components"
        / "execution"
        / "ecall"
        / "mod.rs"
    )
    c = path.read_text()
    c = c.replace(
        "        trace.column_mut::<2>(row_idx, Column::BVal)[0] = next_lo;\n"
        "        trace.column_mut::<2>(row_idx, Column::BVal)[1] = old_hi;\n",
        "        *trace.column_mut::<2>(row_idx, Column::BVal)[0] = next_lo;\n"
        "        *trace.column_mut::<2>(row_idx, Column::BVal)[1] = old_hi;\n",
    )
    path.write_text(c)
    body = """fn beak_nexus_mutate_ecall_argument_trace(trace: &mut TraceBuilder<Column>, row_idx: usize) {
    let step_idx = row_idx as u64;
    if beak_nexus_should_inject(
        "nexus.semantic.control.ecall_argument_decomposition",
        step_idx,
    ) {
        let [old_lo, old_hi] = trace.column::<2>(row_idx, Column::BVal);
        let next_lo = if old_lo == BaseField::from(0x5au32) {
            BaseField::from(0xa5u32)
        } else {
            BaseField::from(0x5au32)
        };
        *trace.column_mut::<2>(row_idx, Column::BVal)[0] = next_lo;
        *trace.column_mut::<2>(row_idx, Column::BVal)[1] = old_hi;
        beak_nexus_note_injection(
            "nexus.semantic.control.ecall_argument_decomposition",
            step_idx,
            "ecall.b_val_syscall_code",
        );
    }
}
"""
    helper_anchor = "mod columns;\nuse columns::{Column, PreprocessedColumn};\n"
    helper = helper_anchor + "\n" + _f2ad_common_injection_helpers("ecall", body)
    helper_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.ecall.semantic_injection.helpers"
    if helper_guard not in path.read_text():
        _replace_once(path, helper_anchor, helper)

    call_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.ecall.semantic_injection.call"
    call_anchor = """        trace.fill_columns(row_idx, reg3_accessed, Column::Reg3Accessed);
        trace.fill_columns(row_idx, a_val, Column::AVal);
        trace.fill_columns(row_idx, true, syscall_flag);
    }
}
"""
    call = """        trace.fill_columns(row_idx, reg3_accessed, Column::Reg3Accessed);
        trace.fill_columns(row_idx, a_val, Column::AVal);
        trace.fill_columns(row_idx, true, syscall_flag);
        // BEAK-INSERT: nexus.f2ad126.prover2.ecall.semantic_injection.call
        beak_nexus_mutate_ecall_argument_trace(trace, row_idx);
    }
}
"""
    if call_guard not in path.read_text():
        _replace_once(path, call_anchor, call)


def _patch_f2ad_prover2_read_write_memory_injection(nexus_install_path: Path) -> None:
    path = (
        nexus_install_path
        / "prover2"
        / "machine"
        / "src"
        / "components"
        / "read_write_memory"
        / "trace.rs"
    )
    contents = path.read_text()
    contents = contents.replace(
        "use stwo::{core::fields::m31::BaseField, prover::backend::simd::m31::LOG_N_LANES};\n",
        "use stwo::prover::backend::simd::m31::LOG_N_LANES;\n",
    )
    path.write_text(contents)
    contents = path.read_text()
    old_finalization_guard = """    if base != "nexus.semantic.row.padding_interaction_send"
        && base != "nexus.semantic.memory.finalization_consistency"
    {
        return None;
    }
"""
    new_padding_guard = """    if base != "nexus.semantic.row.padding_interaction_send" {
        return None;
    }
"""
    if old_finalization_guard in contents:
        path.write_text(contents.replace(old_finalization_guard, new_padding_guard, 1))

    helper_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.semantic_injection.helpers"
    helper_anchor = """fn iter_program_steps<'a>(side_note: &SideNote<'a>) -> impl Iterator<Item = ProgramStep<'a>> {
"""
    helper = """// BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.semantic_injection.helpers
const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";

fn beak_nexus_base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn beak_nexus_should_inject(row_idx: usize) -> Option<String> {
    let active_kind = std::env::var(BEAK_NEXUS_INJECT_KIND_ENV).ok()?;
    let base = beak_nexus_base_inject_kind(&active_kind);
    if base != "nexus.semantic.row.padding_interaction_send" {
        return None;
    }
    let target_step = std::env::var(BEAK_NEXUS_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    if target_step != u64::MAX && target_step != row_idx as u64 {
        return None;
    }
    Some(base.to_string())
}

fn beak_nexus_note_injection(kind: &str, row_idx: usize, site: &str) {
    std::env::set_var(BEAK_NEXUS_INJECTION_APPLIED_ENV, "true");
    println!(
        "BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED kind={kind} step={row_idx} site={site}"
    );
}

fn beak_nexus_forged_byte(old: u8) -> u8 {
    if old == 0x5a { 0xa5 } else { 0x5a }
}

fn beak_nexus_apply_padding_row_injection(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    log_size: u32,
    rw_memory_side_note: &mut ReadWriteMemorySideNote,
) {
    if row_idx >= (1usize << log_size) {
        return;
    }
    let Some(kind) = beak_nexus_should_inject(row_idx) else {
        return;
    };
    let Some((&address, &(prev_timestamp, prev_value))) = rw_memory_side_note
        .last_access
        .iter()
        .rev()
        .find(|(_, (timestamp, _))| *timestamp > 0)
    else {
        return;
    };

    let forged_timestamp = prev_timestamp.saturating_add(1);
    let forged_value = beak_nexus_forged_byte(prev_value);
    trace.fill_columns(row_idx, address.to_le_bytes(), Column::RamBaseAddr);
    trace.fill_columns(row_idx, u32_to_16bit_parts_le(forged_timestamp), Column::Clk);
    trace.fill_columns(row_idx, true, Column::IsLocalPad);
    trace.fill_columns(row_idx, true, Column::RamWrite);
    trace.fill_columns(row_idx, true, Column::Ram1Accessed);
    trace.fill_columns(row_idx, prev_value, Column::Ram1ValPrev);
    trace.fill_columns(row_idx, forged_value, Column::Ram1ValCur);
    trace.fill_columns(row_idx, prev_timestamp, Column::Ram1TsPrev);
    rw_memory_side_note
        .last_access
        .insert(address, (forged_timestamp, forged_value));
    beak_nexus_note_injection(&kind, row_idx, "prover2.read_write_memory.padding_row");
}

fn iter_program_steps<'a>(side_note: &SideNote<'a>) -> impl Iterator<Item = ProgramStep<'a>> {
"""
    contents = path.read_text()
    if helper_guard not in contents:
        _replace_once(path, helper_anchor, helper)

    call_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.semantic_injection.call"
    call_anchor = """    for (row_idx, program_step) in iter_program_steps(side_note).enumerate() {
        generate_trace_row(
            &mut trace,
            row_idx,
            program_step,
            &mut rw_memory_side_note,
            &mut read_access,
            &mut write_access,
            &mut range_check_mults,
        );
    }
    side_note.range_check.range256.append(range_check_mults);
    // store final ram state into side note
"""
    call = """    for (row_idx, program_step) in iter_program_steps(side_note).enumerate() {
        generate_trace_row(
            &mut trace,
            row_idx,
            program_step,
            &mut rw_memory_side_note,
            &mut read_access,
            &mut write_access,
            &mut range_check_mults,
        );
    }
    // BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.semantic_injection.call
    beak_nexus_apply_padding_row_injection(
        &mut trace,
        num_memory_steps,
        log_size,
        &mut rw_memory_side_note,
    );
    side_note.range_check.range256.append(range_check_mults);
    // store final ram state into side note
"""
    if call_guard not in path.read_text():
        _replace_once(path, call_anchor, call)

    normal_guard = (
        "// BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.normal_semantic_injection.helpers"
    )
    normal_anchor = """fn beak_nexus_apply_padding_row_injection(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    log_size: u32,
    rw_memory_side_note: &mut ReadWriteMemorySideNote,
) {
"""
    normal_helpers = """// BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.normal_semantic_injection.helpers
fn beak_nexus_should_inject_memory_row(kind: &str, step_idx: u64) -> bool {
    let Ok(active_kind) = std::env::var(BEAK_NEXUS_INJECT_KIND_ENV) else {
        return false;
    };
    if beak_nexus_base_inject_kind(&active_kind) != kind {
        return false;
    }
    let target_step = std::env::var(BEAK_NEXUS_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    target_step == u64::MAX || target_step == step_idx
}

fn beak_nexus_apply_memory_row_injection(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    timestamp: u32,
    is_load: bool,
    initial_load_prev_value: Option<u8>,
) {
    let step_idx = u64::from(timestamp);
    if beak_nexus_should_inject_memory_row(
        "nexus.semantic.memory.address_alignment_consistency",
        step_idx,
    ) {
        trace.fill_columns(row_idx, [0xfeu8, 0xff, 0xff, 0xff], Column::RamBaseAddr);
        beak_nexus_note_injection(
            "nexus.semantic.memory.address_alignment_consistency",
            step_idx as usize,
            "read_write_memory.ram_base_addr",
        );
    }

    if beak_nexus_should_inject_memory_row(
        "nexus.semantic.memory.address_pointer_consistency",
        step_idx,
    ) {
        trace.fill_columns(row_idx, [0xfeu8, 0xff, 0xff, 0xff], Column::RamBaseAddr);
        beak_nexus_note_injection(
            "nexus.semantic.memory.address_pointer_consistency",
            step_idx as usize,
            "read_write_memory.ram_base_addr",
        );
    }

    if beak_nexus_should_inject_memory_row(
        "nexus.semantic.memory.address_progression_consistency",
        step_idx,
    ) {
        trace.fill_columns(row_idx, [0xfeu8, 0xff, 0xff, 0xff], Column::RamBaseAddr);
        beak_nexus_note_injection(
            "nexus.semantic.memory.address_progression_consistency",
            step_idx as usize,
            "read_write_memory.ram_base_addr",
        );
    }

    if is_load
        && beak_nexus_should_inject_memory_row(
            "nexus.semantic.memory.load_value_binding",
            step_idx,
        )
    {
        trace.fill_columns(row_idx, 0x5au8, Column::Ram1ValCur);
        beak_nexus_note_injection(
            "nexus.semantic.memory.load_value_binding",
            step_idx as usize,
            "read_write_memory.ram1_val_cur",
        );
    }

    if let Some(prev_value) = initial_load_prev_value {
        if beak_nexus_should_inject_memory_row(
            "nexus.semantic.memory.initial_value_binding",
            step_idx,
        ) {
            trace.fill_columns(
                row_idx,
                beak_nexus_forged_byte(prev_value),
                Column::Ram1ValPrev,
            );
            beak_nexus_note_injection(
                "nexus.semantic.memory.initial_value_binding",
                step_idx as usize,
                "read_write_memory.ram1_val_prev_initial",
            );
        }
    }

    if !is_load
        && beak_nexus_should_inject_memory_row(
            "nexus.semantic.memory.store_load_payload_flow",
            step_idx,
        )
    {
        trace.fill_columns(row_idx, 0x5au8, Column::Ram1ValCur);
        beak_nexus_note_injection(
            "nexus.semantic.memory.store_load_payload_flow",
            step_idx as usize,
            "read_write_memory.ram1_val_cur",
        );
    }

    if !is_load
        && beak_nexus_should_inject_memory_row(
            "nexus.semantic.memory.write_payload_consistency",
            step_idx,
        )
    {
        trace.fill_columns(row_idx, 0x5au8, Column::Ram1ValCur);
        beak_nexus_note_injection(
            "nexus.semantic.memory.write_payload_consistency",
            step_idx as usize,
            "read_write_memory.ram1_val_cur",
        );
    }

    if beak_nexus_should_inject_memory_row(
        "nexus.semantic.memory.kind_selector_consistency",
        step_idx,
    ) {
        trace.fill_columns(row_idx, is_load, Column::RamWrite);
        beak_nexus_note_injection(
            "nexus.semantic.memory.kind_selector_consistency",
            step_idx as usize,
            "read_write_memory.ram_write",
        );
    }

    if beak_nexus_should_inject_memory_row(
        "nexus.semantic.time.monotonic_access_ordering",
        step_idx,
    ) {
        trace.fill_columns(row_idx, 0x5a5a5a5au32, Column::Ram1TsPrev);
        beak_nexus_note_injection(
            "nexus.semantic.time.monotonic_access_ordering",
            step_idx as usize,
            "read_write_memory.ram1_ts_prev",
        );
    }
}

fn beak_nexus_apply_padding_row_injection(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    log_size: u32,
    rw_memory_side_note: &mut ReadWriteMemorySideNote,
) {
"""
    if normal_guard not in path.read_text():
        _replace_once(path, normal_anchor, normal_helpers)

    normal_call_guard = (
        "// BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.normal_semantic_injection.call"
    )
    normal_call_anchor = """        let range_checked_prev_vals: Vec<u8> = prev_value[..access_size]
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0, WORD_SIZE - access_size))
            .collect();
        range_check_mults.add_values(&range_checked_prev_vals);
    }
}
"""
    normal_call = """        let range_checked_prev_vals: Vec<u8> = prev_value[..access_size]
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0, WORD_SIZE - access_size))
            .collect();
        range_check_mults.add_values(&range_checked_prev_vals);
    }
    // BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.normal_semantic_injection.call
    beak_nexus_apply_memory_row_injection(
        trace,
        row_idx,
        clk,
        is_load,
        beak_initial_load_prev_value,
    );
}
"""
    if normal_call_guard not in path.read_text():
        _replace_once(path, normal_call_anchor, normal_call)

    contents = path.read_text()
    if "let mut beak_initial_load_prev_value: Option<u8> = None;" not in contents:
        contents = contents.replace(
            "    for memory_record in &program_step.step.memory_records {\n",
            "    let mut beak_initial_load_prev_value: Option<u8> = None;\n\n    for memory_record in &program_step.step.memory_records {\n",
            1,
        )
        path.write_text(contents)

    contents = path.read_text()
    contents = contents.replace(
        "use stwo::{core::fields::m31::BaseField, prover::backend::simd::m31::LOG_N_LANES};\n",
        "use stwo::prover::backend::simd::m31::LOG_N_LANES;\n",
    )
    contents = contents.replace(
        """    let beak_initial_load_prev_value = if is_load {
        let [ts0, ts1, ts2, ts3] = trace.column::<4>(row_idx, Column::Ram1TsPrev);
        if ts0 == BaseField::from(0u32)
            && ts1 == BaseField::from(0u32)
            && ts2 == BaseField::from(0u32)
            && ts3 == BaseField::from(0u32)
        {
            Some(prev_value[0])
        } else {
            None
        }
    } else {
        None
    };
""",
        "",
    )
    if "beak_initial_load_prev_value = Some(prev_value[0]);" not in contents:
        contents = contents.replace(
            """            let (prev_timestamp, prev_val) = prev_access.unwrap_or((0, 0));
            if is_load && i == 0 && prev_timestamp == 0 {
                beak_initial_load_prev_value = Some(prev_value[0]);
            }
            if is_load {
""",
            """            let (prev_timestamp, prev_val) = prev_access.unwrap_or((0, 0));
            if is_load && i == 0 && prev_timestamp == 0 {
                beak_initial_load_prev_value = Some(prev_value[0]);
            }
            if is_load {
""",
            1,
        )
    contents = contents.replace(
        """        range_check_mults.add_values(&range_checked_prev_vals);
        if is_load && prev_timestamp == 0 && beak_initial_load_prev_value.is_none() {
            beak_initial_load_prev_value = Some(prev_value[0]);
        }
""",
        """        range_check_mults.add_values(&range_checked_prev_vals);
""",
    )
    if "i == 0 && prev_timestamp == 0" not in contents:
        contents = contents.replace(
            """            let (prev_timestamp, prev_val) = prev_access.unwrap_or((0, 0));
            if is_load {
""",
            """            let (prev_timestamp, prev_val) = prev_access.unwrap_or((0, 0));
            if is_load && i == 0 && prev_timestamp == 0 {
                beak_initial_load_prev_value = Some(prev_value[0]);
            }
            if is_load {
""",
            1,
        )
    path.write_text(contents)

    contents = path.read_text()
    if "initial_load_prev_value: Option<u8>" not in contents:
        contents = contents.replace(
            """fn beak_nexus_apply_memory_row_injection(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    timestamp: u32,
    is_load: bool,
) {
""",
            """fn beak_nexus_apply_memory_row_injection(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    timestamp: u32,
    is_load: bool,
    initial_load_prev_value: Option<u8>,
) {
""",
            1,
        )
        contents = contents.replace(
            """    if !is_load
        && beak_nexus_should_inject_memory_row(
            "nexus.semantic.memory.store_load_payload_flow",
            step_idx,
        )
""",
            """    if let Some(prev_value) = initial_load_prev_value {
        if beak_nexus_should_inject_memory_row(
            "nexus.semantic.memory.initial_value_binding",
            step_idx,
        ) {
            trace.fill_columns(
                row_idx,
                beak_nexus_forged_byte(prev_value),
                Column::Ram1ValPrev,
            );
            beak_nexus_note_injection(
                "nexus.semantic.memory.initial_value_binding",
                step_idx as usize,
                "read_write_memory.ram1_val_prev_initial",
            );
        }
    }

    if !is_load
        && beak_nexus_should_inject_memory_row(
            "nexus.semantic.memory.store_load_payload_flow",
            step_idx,
        )
""",
            1,
        )
        contents = contents.replace(
            """        range_check_mults.add_values(&range_checked_prev_vals);
    }
    // BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.normal_semantic_injection.call
""",
            """        range_check_mults.add_values(&range_checked_prev_vals);
        if is_load && prev_timestamp == 0 && beak_initial_load_prev_value.is_none() {
            beak_initial_load_prev_value = Some(prev_value[0]);
        }
    }
    // BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.normal_semantic_injection.call
""",
            1,
        )
        contents = contents.replace(
            """    // BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.normal_semantic_injection.call
    beak_nexus_apply_memory_row_injection(trace, row_idx, clk, is_load);
}
""",
            """    // BEAK-INSERT: nexus.f2ad126.prover2.read_write_memory.normal_semantic_injection.call
    beak_nexus_apply_memory_row_injection(
        trace,
        row_idx,
        clk,
        is_load,
        beak_initial_load_prev_value,
    );
}
""",
            1,
        )
        path.write_text(contents)


def _patch_f2ad_prover2_private_memory_boundary_injection(nexus_install_path: Path) -> None:
    path = (
        nexus_install_path
        / "prover2"
        / "machine"
        / "src"
        / "components"
        / "read_write_memory_boundary"
        / "private_memory"
        / "mod.rs"
    )
    helper_guard = (
        "// BEAK-INSERT: nexus.f2ad126.prover2.private_memory_boundary.semantic_injection.helpers"
    )
    helper_anchor = """mod columns;
use columns::{Column, PreprocessedColumn};
"""
    helper = """mod columns;
use columns::{Column, PreprocessedColumn};

// BEAK-INSERT: nexus.f2ad126.prover2.private_memory_boundary.semantic_injection.helpers
const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";

fn beak_nexus_private_boundary_base_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn beak_nexus_should_inject_private_boundary(row_idx: usize) -> bool {
    let Ok(active_kind) = std::env::var(BEAK_NEXUS_INJECT_KIND_ENV) else {
        return false;
    };
    if beak_nexus_private_boundary_base_kind(&active_kind)
        != "nexus.semantic.memory.finalization_consistency"
    {
        return false;
    }
    let target_step = std::env::var(BEAK_NEXUS_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    target_step == u64::MAX || target_step == row_idx as u64
}

fn beak_nexus_note_private_boundary_injection(row_idx: usize, site: &str) {
    std::env::set_var(BEAK_NEXUS_INJECTION_APPLIED_ENV, "true");
    println!(
        "BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED kind=nexus.semantic.memory.finalization_consistency step={row_idx} site={site}"
    );
}

fn beak_nexus_private_boundary_forged_byte(old: u8) -> u8 {
    if old == 0x5a { 0xa5 } else { 0x5a }
}

fn beak_nexus_mutate_private_boundary_row(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    final_value: u8,
) {
    if !beak_nexus_should_inject_private_boundary(row_idx) {
        return;
    }
    trace.fill_columns(
        row_idx,
        beak_nexus_private_boundary_forged_byte(final_value),
        Column::RamValFinal,
    );
    beak_nexus_note_private_boundary_injection(
        row_idx,
        "private_memory_boundary.ram_val_final",
    );
}
"""
    if helper_guard not in path.read_text():
        _replace_once(path, helper_anchor, helper)

    call_guard = (
        "// BEAK-INSERT: nexus.f2ad126.prover2.private_memory_boundary.semantic_injection.call"
    )
    call_anchor = """            trace.fill_columns(row_idx, final_ts, Column::RamTsFinal);
            trace.fill_columns(row_idx, *final_val, Column::RamValFinal);

            let read_mult = read_mults.get(curr_addr.0).copied().unwrap_or_default();
"""
    call = """            trace.fill_columns(row_idx, final_ts, Column::RamTsFinal);
            trace.fill_columns(row_idx, *final_val, Column::RamValFinal);
            // BEAK-INSERT: nexus.f2ad126.prover2.private_memory_boundary.semantic_injection.call
            beak_nexus_mutate_private_boundary_row(&mut trace, row_idx, *final_val);

            let read_mult = read_mults.get(curr_addr.0).copied().unwrap_or_default();
"""
    if call_guard not in path.read_text():
        _replace_once(path, call_anchor, call)


def _f2ad_execution_mutators_source() -> str:
    return """#[allow(dead_code)]
fn beak_nexus_flip_first_column_value<const N: usize>(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    col: Column,
) {
    let old = trace.column::<N>(row_idx, col)[0];
    let next = if old == BaseField::from(0u32) {
        BaseField::from(1u32)
    } else {
        BaseField::from(0u32)
    };
    *trace.column_mut::<N>(row_idx, col)[0] = next;
}

#[allow(dead_code)]
fn beak_nexus_mutate_pc_next(trace: &mut TraceBuilder<Column>, row_idx: usize, col: Column) {
    trace.fill_columns(row_idx, [0x5a5au16, 0xa5a5u16], col);
}
"""


def _patch_f2ad_shift_semantic_injection(nexus_install_path: Path) -> None:
    for stem in ("sll", "srl", "sra"):
        path = (
            nexus_install_path
            / "prover2"
            / "machine"
            / "src"
            / "components"
            / "execution"
            / stem
            / "mod.rs"
        )
        body = _f2ad_execution_mutators_source() + f"""
fn beak_nexus_mutate_shift_trace(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    program_step: ProgramStep,
) {{
    let step_idx = u64::from(program_step.step.timestamp);
    if beak_nexus_should_inject("nexus.semantic.alu.shift_mod32", step_idx) {{
        beak_nexus_flip_first_column_value::<5>(trace, row_idx, Column::Sh);
        beak_nexus_note_injection(
            "nexus.semantic.alu.shift_mod32",
            step_idx,
            "{stem}.sh",
        );
    }}
}}
"""
        helper_anchor = "use columns::{Column, PreprocessedColumn};\n"
        helper = helper_anchor + "\n" + _f2ad_common_injection_helpers(f"{stem}_shift", body)
        helper_guard = f"// BEAK-INSERT: nexus.f2ad126.prover2.{stem}_shift.semantic_injection.helpers"
        if helper_guard not in path.read_text():
            _replace_once(path, helper_anchor, helper)

        call_guard = f"// BEAK-INSERT: nexus.f2ad126.prover2.{stem}_shift.semantic_injection.call"
        if stem == "sll":
            call_anchor = """        range_check_accum.range256.add_values(&rem);
        range_check_accum.range256.add_values(&qt);
        range_check_accum.range8.add_value(h1);
    }
"""
            call = """        range_check_accum.range256.add_values(&rem);
        range_check_accum.range256.add_values(&qt);
        range_check_accum.range8.add_value(h1);
        // BEAK-INSERT: nexus.f2ad126.prover2.sll_shift.semantic_injection.call
        beak_nexus_mutate_shift_trace(trace, row_idx, program_step);
    }
"""
        elif stem == "srl":
            call_anchor = """        range_check_accum.range256.add_values(&rem);
        range_check_accum.range256.add_values(&rem_diff);
        range_check_accum.range256.add_values(&qt);
        range_check_accum.range8.add_value(h1);
    }
"""
            call = """        range_check_accum.range256.add_values(&rem);
        range_check_accum.range256.add_values(&rem_diff);
        range_check_accum.range256.add_values(&qt);
        range_check_accum.range8.add_value(h1);
        // BEAK-INSERT: nexus.f2ad126.prover2.srl_shift.semantic_injection.call
        beak_nexus_mutate_shift_trace(trace, row_idx, program_step);
    }
"""
        else:
            call_anchor = """        range_check_accum.range256.add_values(&rem);
        range_check_accum.range256.add_values(&rem_diff);
        range_check_accum.range256.add_values(&qt);
        range_check_accum.range8.add_value(h1);
        range_check_accum.range128.add_value(h2);
    }
"""
            call = """        range_check_accum.range256.add_values(&rem);
        range_check_accum.range256.add_values(&rem_diff);
        range_check_accum.range256.add_values(&qt);
        range_check_accum.range8.add_value(h1);
        range_check_accum.range128.add_value(h2);
        // BEAK-INSERT: nexus.f2ad126.prover2.sra_shift.semantic_injection.call
        beak_nexus_mutate_shift_trace(trace, row_idx, program_step);
    }
"""
        if call_guard not in path.read_text():
            _replace_once(path, call_anchor, call)


def _patch_f2ad_add_semantic_injection(nexus_install_path: Path) -> None:
    path = (
        nexus_install_path
        / "prover2"
        / "machine"
        / "src"
        / "components"
        / "execution"
        / "add"
        / "mod.rs"
    )
    body = _f2ad_execution_mutators_source() + """
fn beak_nexus_mutate_add_trace(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    program_step: ProgramStep,
) {
    let step_idx = u64::from(program_step.step.timestamp);
    if beak_nexus_should_inject("nexus.semantic.alu.immediate_limb_consistency", step_idx) {
        beak_nexus_flip_first_column_value::<4>(trace, row_idx, Column::AVal);
        beak_nexus_note_injection(
            "nexus.semantic.alu.immediate_limb_consistency",
            step_idx,
            "add.a_val",
        );
    }
}
"""
    helper_anchor = "use columns::{Column, PreprocessedColumn};\n"
    helper = helper_anchor + "\n" + _f2ad_common_injection_helpers("add", body)
    helper_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.add.semantic_injection.helpers"
    if helper_guard not in path.read_text():
        _replace_once(path, helper_anchor, helper)

    call_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.add.semantic_injection.call"
    call_anchor = """        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &sum_bytes, Column::AVal);
        trace.fill_columns(row_idx, carry_bits, Column::HCarry);
    }
"""
    call = """        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &sum_bytes, Column::AVal);
        trace.fill_columns(row_idx, carry_bits, Column::HCarry);
        // BEAK-INSERT: nexus.f2ad126.prover2.add.semantic_injection.call
        beak_nexus_mutate_add_trace(trace, row_idx, program_step);
    }
"""
    if call_guard not in path.read_text():
        _replace_once(path, call_anchor, call)


def _patch_f2ad_comparison_semantic_injection(nexus_install_path: Path) -> None:
    for stem in ("slt", "sltu"):
        path = (
            nexus_install_path
            / "prover2"
            / "machine"
            / "src"
            / "components"
            / "execution"
            / stem
            / "mod.rs"
        )
        body = _f2ad_execution_mutators_source() + f"""
fn beak_nexus_mutate_comparison_trace(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    program_step: ProgramStep,
) {{
    let step_idx = u64::from(program_step.step.timestamp);
    if beak_nexus_should_inject("nexus.semantic.alu.comparison_booleanity", step_idx) {{
        beak_nexus_flip_first_column_value::<{1 if stem == "slt" else 2}>(
            trace,
            row_idx,
            Column::{'AVal' if stem == 'slt' else 'HBorrow'},
        );
        beak_nexus_note_injection(
            "nexus.semantic.alu.comparison_booleanity",
            step_idx,
            "{stem}.{'a_val' if stem == 'slt' else 'h_borrow'}",
        );
    }}

    if beak_nexus_should_inject("nexus.semantic.alu.subtraction_borrow_chain", step_idx) {{
        beak_nexus_flip_first_column_value::<2>(trace, row_idx, Column::HBorrow);
        beak_nexus_note_injection(
            "nexus.semantic.alu.subtraction_borrow_chain",
            step_idx,
            "{stem}.h_borrow",
        );
    }}

    if beak_nexus_should_inject("nexus.semantic.alu.comparison_auxiliary_chain", step_idx) {{
        beak_nexus_flip_first_column_value::<4>(trace, row_idx, Column::HRem);
        beak_nexus_note_injection(
            "nexus.semantic.alu.comparison_auxiliary_chain",
            step_idx,
            "{stem}.h_rem",
        );
    }}
}}
"""
        helper_anchor = "use columns::{Column, PreprocessedColumn};\n"
        helper = helper_anchor + "\n" + _f2ad_common_injection_helpers(f"{stem}_comparison", body)
        helper_guard = f"// BEAK-INSERT: nexus.f2ad126.prover2.{stem}_comparison.semantic_injection.helpers"
        if helper_guard not in path.read_text():
            _replace_once(path, helper_anchor, helper)

        call_guard = f"// BEAK-INSERT: nexus.f2ad126.prover2.{stem}_comparison.semantic_injection.call"
        if stem == "slt":
            call_anchor = """        range_check_accum.range256.add_values(&diff_bytes);
        range_check_accum.range256.add_values(&[h_rem_b, h_rem_c]);
    }
"""
            call = """        range_check_accum.range256.add_values(&diff_bytes);
        range_check_accum.range256.add_values(&[h_rem_b, h_rem_c]);
        // BEAK-INSERT: nexus.f2ad126.prover2.slt_comparison.semantic_injection.call
        beak_nexus_mutate_comparison_trace(trace, row_idx, program_step);
    }
"""
        else:
            call_anchor = """        range_check_accum.range256.add_values(&diff_bytes);
    }
"""
            call = """        range_check_accum.range256.add_values(&diff_bytes);
        // BEAK-INSERT: nexus.f2ad126.prover2.sltu_comparison.semantic_injection.call
        beak_nexus_mutate_comparison_trace(trace, row_idx, program_step);
    }
"""
        if call_guard not in path.read_text():
            _replace_once(path, call_anchor, call)


def _patch_f2ad_sub_semantic_injection(nexus_install_path: Path) -> None:
    path = (
        nexus_install_path
        / "prover2"
        / "machine"
        / "src"
        / "components"
        / "execution"
        / "sub"
        / "mod.rs"
    )
    body = _f2ad_execution_mutators_source() + """
fn beak_nexus_mutate_sub_trace(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    program_step: ProgramStep,
) {
    let step_idx = u64::from(program_step.step.timestamp);
    if beak_nexus_should_inject("nexus.semantic.alu.subtraction_borrow_chain", step_idx) {
        beak_nexus_flip_first_column_value::<2>(trace, row_idx, Column::HBorrow);
        beak_nexus_note_injection(
            "nexus.semantic.alu.subtraction_borrow_chain",
            step_idx,
            "sub.h_borrow",
        );
    }
}
"""
    helper_anchor = "use columns::{Column, PreprocessedColumn};\n"
    helper = helper_anchor + "\n" + _f2ad_common_injection_helpers("sub", body)
    helper_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.sub.semantic_injection.helpers"
    if helper_guard not in path.read_text():
        _replace_once(path, helper_anchor, helper)

    call_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.sub.semantic_injection.call"
    call_anchor = """        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &diff_bytes, Column::AVal);
        trace.fill_columns(row_idx, borrow_bits, Column::HBorrow);
    }
"""
    call = """        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &diff_bytes, Column::AVal);
        trace.fill_columns(row_idx, borrow_bits, Column::HBorrow);
        // BEAK-INSERT: nexus.f2ad126.prover2.sub.semantic_injection.call
        beak_nexus_mutate_sub_trace(trace, row_idx, program_step);
    }
"""
    if call_guard not in path.read_text():
        _replace_once(path, call_anchor, call)


def _patch_f2ad_control_semantic_injection(nexus_install_path: Path) -> None:
    control_modules = {
        "branch_eq": ("branch_eq", "Column::PcNext", "branch_eq.pc_next"),
        "branch_cmp_signed": ("branch_cmp_signed", "Column::PcNext", "branch_cmp_signed.pc_next"),
        "branch_cmp_unsigned": ("branch_cmp_unsigned", "Column::PcNext", "branch_cmp_unsigned.pc_next"),
        "jal": ("jal", "Column::PcNext", "jal.pc_next"),
    }
    for directory, (name, pc_col, site) in control_modules.items():
        path = (
            nexus_install_path
            / "prover2"
            / "machine"
            / "src"
            / "components"
            / "execution"
            / directory
            / "mod.rs"
        )
        body = _f2ad_execution_mutators_source() + f"""
fn beak_nexus_mutate_control_trace(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    program_step: ProgramStep,
) {{
    let step_idx = u64::from(program_step.step.timestamp);
    if beak_nexus_should_inject("nexus.semantic.exec.control_flow_binding", step_idx) {{
        beak_nexus_mutate_pc_next(trace, row_idx, {pc_col});
        beak_nexus_note_injection(
            "nexus.semantic.exec.control_flow_binding",
            step_idx,
            "{site}",
        );
    }}
}}
"""
        helper_anchor = "use columns::{Column, PreprocessedColumn};\n"
        if directory == "jal":
            helper_anchor = "use columns::{CVal, Column, InstrVal, PreprocessedColumn, OP_A};\n"
        helper = helper_anchor + "\n" + _f2ad_common_injection_helpers(f"{name}_control", body)
        helper_guard = f"// BEAK-INSERT: nexus.f2ad126.prover2.{name}_control.semantic_injection.helpers"
        if helper_guard not in path.read_text():
            _replace_once(path, helper_anchor, helper)

        call_guard = f"// BEAK-INSERT: nexus.f2ad126.prover2.{name}_control.semantic_injection.call"
        if directory == "branch_eq":
            call_anchor = """        trace.fill_columns_base_field(
            row_idx,
            [neq_aux_inv[1]].as_slice(),
            Column::HNeq34FlagAuxInv,
        );

        trace.fill_columns(row_idx, carry_bits, Column::HCarry);
    }
"""
            call = """        trace.fill_columns_base_field(
            row_idx,
            [neq_aux_inv[1]].as_slice(),
            Column::HNeq34FlagAuxInv,
        );

        trace.fill_columns(row_idx, carry_bits, Column::HCarry);
        // BEAK-INSERT: nexus.f2ad126.prover2.branch_eq_control.semantic_injection.call
        beak_nexus_mutate_control_trace(trace, row_idx, program_step);
    }
"""
        elif directory == "branch_cmp_signed":
            call_anchor = """        range_check_accum.range256.add_values(&diff_bytes);
        range_check_accum
            .range128
            .add_values_from_slice(&[h_rem_a, h_rem_b]);
    }
"""
            call = """        range_check_accum.range256.add_values(&diff_bytes);
        range_check_accum
            .range128
            .add_values_from_slice(&[h_rem_a, h_rem_b]);
        // BEAK-INSERT: nexus.f2ad126.prover2.branch_cmp_signed_control.semantic_injection.call
        beak_nexus_mutate_control_trace(trace, row_idx, program_step);
    }
"""
        elif directory == "branch_cmp_unsigned":
            call_anchor = """        range_check_accum.range256.add_values(&diff_bytes);
    }
"""
            call = """        range_check_accum.range256.add_values(&diff_bytes);
        // BEAK-INSERT: nexus.f2ad126.prover2.branch_cmp_unsigned_control.semantic_injection.call
        beak_nexus_mutate_control_trace(trace, row_idx, program_step);
    }
"""
        else:
            call_anchor = """        trace.fill_columns(row_idx, a_val, Column::AVal);
        trace.fill_columns(row_idx, carry_bits, Column::HCarry);

        Decoding::generate_decoding_trace_row(trace, row_idx, program_step, range_check_accum);
    }
"""
            call = """        trace.fill_columns(row_idx, a_val, Column::AVal);
        trace.fill_columns(row_idx, carry_bits, Column::HCarry);

        Decoding::generate_decoding_trace_row(trace, row_idx, program_step, range_check_accum);
        // BEAK-INSERT: nexus.f2ad126.prover2.jal_control.semantic_injection.call
        beak_nexus_mutate_control_trace(trace, row_idx, program_step);
    }
"""
        if call_guard not in path.read_text():
            _replace_once(path, call_anchor, call)

    path = (
        nexus_install_path
        / "prover2"
        / "machine"
        / "src"
        / "components"
        / "execution"
        / "jalr"
        / "mod.rs"
    )
    body = _f2ad_execution_mutators_source() + """
fn beak_nexus_mutate_jalr_control_trace(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    program_step: ProgramStep,
) {
    let step_idx = u64::from(program_step.step.timestamp);
    if beak_nexus_should_inject("nexus.semantic.exec.control_flow_binding", step_idx) {
        trace.fill_columns(row_idx, 0x5au8, Column::PcNext8_15);
        beak_nexus_note_injection(
            "nexus.semantic.exec.control_flow_binding",
            step_idx,
            "jalr.pc_next8_15",
        );
    }
}
"""
    helper_anchor = "use columns::{Column, PreprocessedColumn};\n"
    helper = helper_anchor + "\n" + _f2ad_common_injection_helpers("jalr_control", body)
    helper_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.jalr_control.semantic_injection.helpers"
    if helper_guard not in path.read_text():
        _replace_once(path, helper_anchor, helper)

    call_guard = "// BEAK-INSERT: nexus.f2ad126.prover2.jalr_control.semantic_injection.call"
    call_anchor = """        range_check_accum.range128.add_value(qt_aux);
        range_check_accum
            .range256
            .add_values(&[pc_next_bytes[1], 0]);
    }
"""
    call = """        range_check_accum.range128.add_value(qt_aux);
        range_check_accum
            .range256
            .add_values(&[pc_next_bytes[1], 0]);
        // BEAK-INSERT: nexus.f2ad126.prover2.jalr_control.semantic_injection.call
        beak_nexus_mutate_jalr_control_trace(trace, row_idx, program_step);
    }
"""
    if call_guard not in path.read_text():
        _replace_once(path, call_anchor, call)



def _patch_execute_step_budget(nexus_install_path: Path) -> None:
    """Bound the Harvard emulator execute loop.

    Fuzzed programs can be non-terminating (e.g. a zero-offset taken branch).
    The upstream loop appends trace records without any step bound, growing
    memory until the process aborts on allocation failure (uncatchable). Failing
    with a panic instead makes it catchable by the benchmark harness.
    """
    path = nexus_install_path / "vm" / "src" / "emulator" / "executor.rs"
    if not path.exists():
        return
    c = path.read_text()
    old = """        let mut results: Vec<InstructionResult> = Vec::new();
        let mut transcript: MemoryTranscript = Vec::new();

        loop {
"""
    new = """        let mut results: Vec<InstructionResult> = Vec::new();
        let mut transcript: MemoryTranscript = Vec::new();

        // BEAK-INSERT: nexus.execute_step_budget
        let beak_step_budget: u64 = std::env::var("BEAK_NEXUS_EXECUTE_STEP_BUDGET")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1_000_000);
        let mut beak_steps: u64 = 0;

        loop {
            beak_steps += 1;
            if beak_steps > beak_step_budget {
                panic!(
                    "beak nexus execute step budget ({beak_step_budget}) exceeded: non-terminating program"
                );
            }
"""
    marker = "// BEAK-INSERT: nexus.execute_step_budget"
    if marker not in c:
        if old not in c:
            raise RuntimeError("nexus execute step budget anchor not found")
        c = c.replace(old, new, 1)
        path.write_text(c)


def apply(*, nexus_install_path: Path, commit_or_branch: str) -> None:
    _patch_execute_step_budget(nexus_install_path)
    if commit_or_branch == NEXUS_MEMORY_SIZE_COMMIT:
        _patch_41_memory_table_population_receipt(nexus_install_path)
        return
    if commit_or_branch == NEXUS_MUL_CARRY_COMMIT:
        _patch_f1_mul_carry_exception_receipt(nexus_install_path)
        return
    if commit_or_branch == NEXUS_F2AD_COMMIT:
        _patch_f2ad_vm_resource_guards(nexus_install_path)
        _patch_f2ad_prover2_resource_guard(nexus_install_path)
        _patch_f2ad_program_memory_semantic_injection(nexus_install_path)
        _patch_f2ad_register_memory_semantic_injection(nexus_install_path)
        _patch_f2ad_cpu_boundary_semantic_injection(nexus_install_path)
        _patch_f2ad_ecall_semantic_injection(nexus_install_path)
        _patch_f2ad_prover2_read_write_memory_injection(nexus_install_path)
        _patch_f2ad_prover2_private_memory_boundary_injection(nexus_install_path)
        _patch_f2ad_add_semantic_injection(nexus_install_path)
        _patch_f2ad_shift_semantic_injection(nexus_install_path)
        _patch_f2ad_comparison_semantic_injection(nexus_install_path)
        _patch_f2ad_sub_semantic_injection(nexus_install_path)
        _patch_f2ad_control_semantic_injection(nexus_install_path)
        return
    if commit_or_branch != NEXUS_BENCHMARK_COMMIT:
        return
    _patch_load_store_semantic_injection(nexus_install_path)
    _patch_load_store_extended_semantic_injection(nexus_install_path)
    _patch_cpu_semantic_injection(nexus_install_path)
    _patch_register_semantic_injection(nexus_install_path)
    _patch_shift_semantic_injection(nexus_install_path)
    _patch_comparison_semantic_injection(nexus_install_path)
    _patch_sub_semantic_injection(nexus_install_path)
    _patch_control_semantic_injection(nexus_install_path)
