from __future__ import annotations

from pathlib import Path

from jolt_fuzzer.settings import (
    JOLT_DORY_SHORT_TRACE_COMMIT,
    JOLT_LATEST_OBLIGATIONS_COMMIT,
    JOLT_READWRITE_SIZING_COMMIT,
)


def apply(*, jolt_install_path: Path, commit_or_branch: str) -> None:
    if commit_or_branch == JOLT_READWRITE_SIZING_COMMIT:
        # Preserve the vulnerable sizing behavior while recording the concrete
        # preprocessing population/capacity relation immediately before the copy.
        _patch_dory_bytecode_population_receipt(jolt_install_path)
        return

    if commit_or_branch == JOLT_DORY_SHORT_TRACE_COMMIT:
        # This vulnerable snapshot is verified through a baseline prover exception.
        # Record the concrete Dory domain/dimension state at the assertion that fails;
        # the e9caa witness-mutation anchors do not exist in this older tree.
        _patch_dory_short_trace_receipt(jolt_install_path)
        return

    _patch_resource_guards(jolt_install_path)

    if commit_or_branch == JOLT_LATEST_OBLIGATIONS_COMMIT:
        _patch_latest_host_program_trace_injection(jolt_install_path)
        return

    _ = commit_or_branch
    _patch_executed_exception_receipt_emission(jolt_install_path)
    _patch_bytecode_row_receipt_accessors(jolt_install_path)
    _patch_host_trace_injection(jolt_install_path)
    _patch_read_write_memory_injection(jolt_install_path)
    _patch_bytecode_injection(jolt_install_path)
    _patch_instruction_lookup_injection(jolt_install_path)
    _patch_vm_padding_injection(jolt_install_path)


def _patch_dory_short_trace_receipt(jolt_install_path: Path) -> None:
    dory = jolt_install_path / "jolt-core" / "src" / "poly" / "commitment" / "dory.rs"
    c = dory.read_text()
    globals_guard = "// BEAK-INSERT: jolt.dory.short_trace_globals"
    if globals_guard not in c:
        old = """/// The (padded) length of the execution trace currently being proven
static mut GLOBAL_T: OnceCell<usize> = OnceCell::new();
/// Dory works by viewing the coefficients of a polynomial as a square matrix.
"""
        new = """/// The (padded) length of the execution trace currently being proven
static mut GLOBAL_T: OnceCell<usize> = OnceCell::new();
// BEAK-INSERT: jolt.dory.short_trace_globals
/// The concrete matrix-width parameter supplied to Dory for this proof.
static mut GLOBAL_K: OnceCell<usize> = OnceCell::new();
// BEAK-INSERT-END
/// Dory works by viewing the coefficients of a polynomial as a square matrix.
"""
        if old not in c:
            raise RuntimeError("Jolt Dory globals anchor not found")
        c = c.replace(old, new, 1)

        old = """        unsafe {
            GLOBAL_T.set(T).expect("GLOBAL_T is already initialized");
            DIMENSION
"""
        new = """        unsafe {
            GLOBAL_T.set(T).expect("GLOBAL_T is already initialized");
            GLOBAL_K.set(K).expect("GLOBAL_K is already initialized");
            DIMENSION
"""
        if old not in c:
            raise RuntimeError("Jolt Dory initialize anchor not found")
        c = c.replace(old, new, 1)

        old = """    pub fn get_T() -> usize {
        unsafe { GLOBAL_T.get().cloned().expect("GLOBAL_T is uninitialized") }
    }
}
"""
        new = """    pub fn get_T() -> usize {
        unsafe { GLOBAL_T.get().cloned().expect("GLOBAL_T is uninitialized") }
    }

    pub fn get_K() -> usize {
        unsafe { GLOBAL_K.get().cloned().expect("GLOBAL_K is uninitialized") }
    }
}
"""
        if old not in c:
            raise RuntimeError("Jolt Dory get_T anchor not found")
        c = c.replace(old, new, 1)

        old = """            GLOBAL_T
                .take()
                .expect("reset_globals: GLOBAL_T is uninitialized");
            DIMENSION
"""
        new = """            GLOBAL_T
                .take()
                .expect("reset_globals: GLOBAL_T is uninitialized");
            GLOBAL_K
                .take()
                .expect("reset_globals: GLOBAL_K is uninitialized");
            DIMENSION
"""
        if old not in c:
            raise RuntimeError("Jolt Dory globals teardown anchor not found")
        c = c.replace(old, new, 1)

        helper_anchor = "// NewType wrappers for Jolt + arkworks types to interop with Dory traits\n"
        helper = r'''
// BEAK-INSERT: jolt.dory.short_trace_receipt
pub(crate) fn beak_record_short_trace_capacity_failure() {
    if std::env::var("BEAK_JOLT_DORY_RECEIPT_ARMED").ok().as_deref() != Some("1") {
        return;
    }
    let Some(input_words_len) = std::env::var("BEAK_JOLT_DORY_INPUT_WORDS_LEN")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return;
    };
    let Some(unpadded_trace_len) = std::env::var("BEAK_JOLT_DORY_UNPADDED_TRACE_LEN")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return;
    };
    let dory_domain_size = DoryGlobals::get_T();
    let matrix_width_k = DoryGlobals::get_K();
    let dory_dimension = DoryGlobals::get_dimension();
    if dory_domain_size > dory_dimension || !dory_domain_size.is_power_of_two() {
        return;
    }
    let boundary_k = dory_domain_size.trailing_zeros();
    std::env::set_var(
        "BEAK_JOLT_EXECUTED_EXCEPTION_RECEIPT",
        format!(
            r#"{{"effect":"dory_short_trace_capacity","obligation_id":"pd2","cell_id":"pd2.very_short","stage":"dory.commitment.domain_size","step":{},"context":{{"backend":"jolt","commit":"d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b","trace_source":"prover.dory","input_words_len":{},"unpadded_trace_len":{},"dory_domain_size":{},"matrix_width_k":{},"dory_dimension":{},"boundary_k":{},"failing_domain_size":{},"relation":"dory_domain_not_greater_than_matrix_dimension"}}}}"#,
            dory_domain_size,
            input_words_len,
            unpadded_trace_len,
            dory_domain_size,
            matrix_width_k,
            dory_dimension,
            boundary_k,
            dory_domain_size,
        ),
    );
}
// BEAK-INSERT-END

'''
        if helper_anchor not in c:
            raise RuntimeError("Jolt Dory receipt helper anchor not found")
        c = c.replace(helper_anchor, helper + helper_anchor, 1)

    # Upgrade already-patched snapshots whose legacy receipt predates the
    # source-identity fields required by exact typed exception binding.
    legacy_context = (
        r'"context":{{"input_words_len":{}'
    )
    typed_context = (
        r'"context":{{"backend":"jolt",'
        r'"commit":"d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b",'
        r'"trace_source":"prover.dory","input_words_len":{}'
    )
    if "// BEAK-INSERT: jolt.dory.short_trace_receipt" in c and typed_context not in c:
        if c.count(legacy_context) != 1:
            raise RuntimeError("Jolt Dory legacy receipt identity anchor not found exactly once")
        c = c.replace(legacy_context, typed_context, 1)

    assertion_guard = "// BEAK-INSERT: jolt.dory.commit_rows.short_trace_receipt"
    if assertion_guard not in c:
        old = """        let T = DoryGlobals::get_T();
        assert!(
            T > DoryGlobals::get_dimension(),
            "T = {T}, why are you doing this",
        );
"""
        new = """        let T = DoryGlobals::get_T();
        // BEAK-INSERT: jolt.dory.commit_rows.short_trace_receipt
        if T <= DoryGlobals::get_dimension() {
            beak_record_short_trace_capacity_failure();
        }
        // BEAK-INSERT-END
        assert!(
            T > DoryGlobals::get_dimension(),
            "T = {T}, why are you doing this",
        );
"""
        if old not in c:
            raise RuntimeError("Jolt Dory commit_rows assertion anchor not found")
        c = c.replace(old, new, 1)
    dory.write_text(c)

    assertion_files = [
        jolt_install_path / "jolt-core" / "src" / "poly" / "one_hot_polynomial.rs",
        jolt_install_path / "jolt-core" / "src" / "poly" / "rlc_polynomial.rs",
    ]
    for path in assertion_files:
        c = path.read_text()
        guard = "// BEAK-INSERT: jolt.dory.polynomial.short_trace_receipt"
        if guard not in c:
            simple = '        assert!(T > num_rows, "T = {T}, why are you doing this");\n'
            simple_with_trailing_comma = (
                '        assert!(T > num_rows, "T = {T}, why are you doing this",);\n'
            )
            simple_new = """        // BEAK-INSERT: jolt.dory.polynomial.short_trace_receipt
        if T <= num_rows {
            crate::poly::commitment::dory::beak_record_short_trace_capacity_failure();
        }
        // BEAK-INSERT-END
        assert!(T > num_rows, "T = {T}, why are you doing this");
"""
            multiline = """        assert!(
            T > DoryGlobals::get_dimension(),
            "T = {T}, why are you doing this",
        );
"""
            multiline_new = """        // BEAK-INSERT: jolt.dory.polynomial.short_trace_receipt
        if T <= DoryGlobals::get_dimension() {
            crate::poly::commitment::dory::beak_record_short_trace_capacity_failure();
        }
        // BEAK-INSERT-END
        assert!(
            T > DoryGlobals::get_dimension(),
            "T = {T}, why are you doing this",
        );
"""
            if simple in c:
                c = c.replace(simple, simple_new, 1)
            elif simple_with_trailing_comma in c:
                c = c.replace(simple_with_trailing_comma, simple_new, 1)
            elif multiline in c:
                c = c.replace(multiline, multiline_new, 1)
            else:
                raise RuntimeError(f"Jolt Dory polynomial assertion anchor not found: {path}")
            path.write_text(c)


def _patch_bytecode_row_receipt_accessors(jolt_install_path: Path) -> None:
    path = jolt_install_path / "jolt-core" / "src" / "jolt" / "vm" / "bytecode.rs"
    c = path.read_text()
    guard = "// BEAK-INSERT: jolt.bytecode_row.receipt_accessors"
    if guard in c:
        mutator = """    pub fn beak_mutate_entrypoint_witness_address(
        &mut self,
        expected_before: usize,
        after: usize,
    ) -> bool {
        if self.address != expected_before || after == expected_before {
            return false;
        }
        self.address = after;
        true
    }

"""
        if "pub fn beak_mutate_entrypoint_witness_address" not in c:
            end = "    // BEAK-INSERT-END\n"
            if end not in c:
                raise RuntimeError("Jolt bytecode row accessor end guard not found")
            c = c.replace(end, mutator + end, 1)
            path.write_text(c)
        return
    anchor = "impl BytecodeRow {\n"
    accessors = """impl BytecodeRow {
    // BEAK-INSERT: jolt.bytecode_row.receipt_accessors
    pub fn beak_receipt_address(&self) -> usize {
        self.address
    }

    pub fn beak_receipt_rd(&self) -> u8 {
        self.rd
    }

    pub fn beak_mutate_entrypoint_witness_address(
        &mut self,
        expected_before: usize,
        after: usize,
    ) -> bool {
        if self.address != expected_before || after == expected_before {
            return false;
        }
        self.address = after;
        true
    }
    // BEAK-INSERT-END
"""
    if anchor not in c:
        raise RuntimeError("Jolt bytecode row accessor anchor not found")
    c = c.replace(anchor, accessors, 1)
    path.write_text(c)


def _patch_dory_bytecode_population_receipt(jolt_install_path: Path) -> None:
    path = (
        jolt_install_path
        / "jolt-core"
        / "src"
        / "jolt"
        / "vm"
        / "read_write_memory.rs"
    )
    c = path.read_text()
    sizing_guard = "// BEAK-INSERT: jolt.dory.offset_once_memory_size"
    sizing_old = """        let memory_size = (program_io.memory_layout.ram_witness_offset + max_trace_address)
            .next_power_of_two() as usize;
"""
    sizing_new = """        // BEAK-INSERT: jolt.dory.offset_once_memory_size
        let memory_size = max_trace_address
            .checked_add(1)
            .expect("read/write memory witness address overflow")
            .max(8)
            .next_power_of_two() as usize;
        // BEAK-INSERT-END
"""
    if sizing_guard not in c:
        if sizing_old not in c:
            raise RuntimeError("Jolt Dory read/write memory sizing anchor not found")
        c = c.replace(sizing_old, sizing_new, 1)

    population_guard = "// BEAK-INSERT: jolt.dory.bytecode_population_receipt"
    if population_guard not in c:
        old = sizing_new + """        let mut v_init: Vec<u64> = vec![0; memory_size];
        // Copy bytecode
        let mut v_init_index = memory_address_to_witness_index(
            preprocessing.min_bytecode_address,
            program_io.memory_layout.ram_witness_offset,
        );
"""
        new = sizing_new + """        // BEAK-INSERT: jolt.dory.bytecode_population_receipt
        let beak_population_start = memory_address_to_witness_index(
            preprocessing.min_bytecode_address,
            program_io.memory_layout.ram_witness_offset,
        );
        let beak_population_end = beak_population_start
            .checked_add(preprocessing.bytecode_bytes.len())
            .expect("bytecode preprocessing population end overflow");
        let beak_boundary_k = memory_size.trailing_zeros();
        let beak_exact_crossing = memory_size.is_power_of_two()
            && beak_population_end > memory_size;
        std::env::set_var(
            "BEAK_JOLT_BYTECODE_BOUNDARY_RECEIPT",
            format!(
                r#"{{"schema_version":1,"relation":"preprocessed_bytecode_end_crosses_allocated_rows_by_one","table_name":"read_write_memory.v_init","population_start":{},"population_end":{},"population_rows":{},"allocated_rows":{},"boundary_k":{},"exact_crossing":{}}}"#,
                beak_population_start,
                beak_population_end,
                preprocessing.bytecode_bytes.len(),
                memory_size,
                beak_boundary_k,
                beak_exact_crossing,
            ),
        );
        // BEAK-INSERT-END
        let mut v_init: Vec<u64> = vec![0; memory_size];
        // Copy bytecode
        let mut v_init_index = beak_population_start;
"""
        if old not in c:
            raise RuntimeError("Jolt Dory bytecode population anchor not found")
        c = c.replace(old, new, 1)

    exception_guard = "// BEAK-INSERT: jolt.dory.bytecode_capacity_exception_receipt"
    if exception_guard not in c:
        old = """        for byte in preprocessing.bytecode_bytes.iter() {
            v_init[v_init_index] = *byte as u64;
            v_init_index += 1;
        }
"""
        new = """        for byte in preprocessing.bytecode_bytes.iter() {
            // BEAK-INSERT: jolt.dory.bytecode_capacity_exception_receipt
            if beak_exact_crossing && v_init_index == memory_size {
                std::env::set_var(
                    "BEAK_JOLT_EXECUTED_EXCEPTION_RECEIPT",
                    format!(
                        r#"{{"effect":"bytecode_table_capacity_write","obligation_id":"pd4","cell_id":"pd4.just_over","stage":"read_write_memory.v_init.write","step":{},"context":{{"backend":"jolt","commit":"6c3b0b49db0afceb967b33656176fa7a27e557b9","trace_source":"jolt.read_write_memory.preprocessed_bytecode","relation":"preprocessed_bytecode_end_crosses_allocated_rows_by_one","relation_valid":true,"failure_observed":true,"failure_manifestation":"capacity_write_out_of_bounds","table_name":"read_write_memory.v_init","population_start":{},"population_end":{},"population_rows":{},"allocated_rows":{},"boundary_k":{},"failing_index":{},"exact_crossing":true}}}}"#,
                        v_init_index,
                        beak_population_start,
                        beak_population_end,
                        preprocessing.bytecode_bytes.len(),
                        memory_size,
                        beak_boundary_k,
                        v_init_index,
                    ),
                );
            }
            // BEAK-INSERT-END
            v_init[v_init_index] = *byte as u64;
            v_init_index += 1;
        }
"""
        if old not in c:
            raise RuntimeError("Jolt Dory bytecode capacity-write anchor not found")
        c = c.replace(old, new, 1)

    path.write_text(c)


def _patch_executed_exception_receipt_emission(jolt_install_path: Path) -> None:
    instruction_lookups = (
        jolt_install_path / "jolt-core" / "src" / "jolt" / "vm" / "instruction_lookups.rs"
    )
    c = instruction_lookups.read_text()
    guard = "// BEAK-INSERT: jolt.instruction_lookup.primary_exception_receipt"
    if guard not in c:
        old = """        assert_eq!(
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
        new = """        let beak_primary_sumcheck_lhs = eq_eval
            * (Self::combine_lookups(
                preprocessing,
                &proof.primary_sumcheck.openings.E_poly_openings,
                &proof.primary_sumcheck.openings.flag_openings,
            ) - proof.primary_sumcheck.openings.lookup_outputs_opening);
        if beak_primary_sumcheck_lhs != claim_last {
            // BEAK-INSERT: jolt.instruction_lookup.primary_exception_receipt
            if let Ok(receipt) =
                std::env::var("BEAK_JOLT_INSTRUCTION_LOOKUP_EXCEPTION_CANDIDATE")
            {
                std::env::set_var("BEAK_JOLT_EXECUTED_EXCEPTION_RECEIPT", receipt);
            }
            // BEAK-INSERT-END
        }
        assert_eq!(
            beak_primary_sumcheck_lhs,
            claim_last,
            "Primary sumcheck check failed."
        );
"""
        if old not in c:
            raise RuntimeError("Jolt instruction-lookup primary-sumcheck anchor not found")
        c = c.replace(old, new, 1)
        instruction_lookups.write_text(c)

    spartan = jolt_install_path / "jolt-core" / "src" / "r1cs" / "spartan.rs"
    c = spartan.read_text()
    guard = "// BEAK-INSERT: jolt.r1cs.inner_exception_receipt"
    if guard not in c:
        old = """        if claim_inner_final != claim_inner_final_expected {
            return Err(SpartanError::InvalidInnerSumcheckClaim);
        }
"""
        new = """        if claim_inner_final != claim_inner_final_expected {
            // BEAK-INSERT: jolt.r1cs.inner_exception_receipt
            if let Ok(receipt) = std::env::var("BEAK_JOLT_R1CS_EXCEPTION_CANDIDATE") {
                std::env::set_var("BEAK_JOLT_EXECUTED_EXCEPTION_RECEIPT", receipt);
            }
            // BEAK-INSERT-END
            return Err(SpartanError::InvalidInnerSumcheckClaim);
        }
"""
        if old not in c:
            raise RuntimeError("Jolt R1CS inner-sumcheck anchor not found")
        c = c.replace(old, new, 1)
        spartan.write_text(c)


def _patch_resource_guards(jolt_install_path: Path) -> None:
    tracer_lib = jolt_install_path / "tracer" / "src" / "lib.rs"
    c = tracer_lib.read_text()
    if "// BEAK-INSERT: jolt.tracer.resource_guard_helpers" not in c:
        anchor = "use tracing::{error, info};\n"
        helpers = r'''
// BEAK-INSERT: jolt.tracer.resource_guard_helpers
fn beak_jolt_env_limit(name: &str, default_value: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default_value)
}

fn beak_jolt_max_trace_cycles() -> usize {
    beak_jolt_env_limit("BEAK_JOLT_MAX_TRACE_CYCLES", 262_144)
}

// BEAK-INSERT-END
'''
        if anchor not in c:
            # Older pinned layouts use a direct emulator loop and do not contain the
            # lazy-trace collection path guarded below. Their resource handling is
            # supplied by the backend worker boundary instead.
            return
        c = c.replace(anchor, anchor + helpers + "\n", 1)
    if "// BEAK-INSERT: jolt.tracer.trace_cycle_guard" not in c:
        old = "    let trace: Vec<Cycle> = lazy_trace_iter.by_ref().collect();\n"
        new = """    let max_trace_cycles = beak_jolt_max_trace_cycles();
    let mut trace: Vec<Cycle> = Vec::new();
    for (cycle_idx, cycle) in lazy_trace_iter.by_ref().enumerate() {
        if cycle_idx >= max_trace_cycles {
            panic!(
                "BEAK_JOLT_MAX_TRACE_CYCLES exceeded: cycle={} max={}",
                cycle_idx, max_trace_cycles
            );
        }
        trace.push(cycle);
    }
    // BEAK-INSERT: jolt.tracer.trace_cycle_guard
    // BEAK-INSERT-END
"""
        if old not in c:
            raise RuntimeError("Jolt tracer trace collect anchor not found")
        c = c.replace(old, new, 1)
    tracer_lib.write_text(c)

    cpu = jolt_install_path / "tracer" / "src" / "emulator" / "cpu.rs"
    c = cpu.read_text()
    if "// BEAK-INSERT: jolt.cpu.host_io_byte_guard_helpers" not in c:
        anchor = "use crate::utils::virtual_registers::VirtualRegisterAllocator;\n"
        helpers = r'''
// BEAK-INSERT: jolt.cpu.host_io_byte_guard_helpers
fn beak_jolt_env_u64_limit(name: &str, default_value: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_value)
}

fn beak_jolt_check_host_io_len(context: &str, len: u64) {
    let max_len = beak_jolt_env_u64_limit("BEAK_JOLT_MAX_HOST_IO_BYTES", 1_048_576);
    if len > max_len {
        panic!(
            "BEAK_JOLT_MAX_HOST_IO_BYTES exceeded in {}: len={} max={}",
            context, len, max_len
        );
    }
}

// BEAK-INSERT-END
'''
        if anchor not in c:
            raise RuntimeError("Jolt CPU host-IO helper anchor not found")
        c = c.replace(anchor, anchor + helpers + "\n", 1)
    replacements = {
        "        // Read bytes from guest memory and write to advice tape\n        let mut bytes = Vec::with_capacity(len as usize);\n": """        // Read bytes from guest memory and write to advice tape
        beak_jolt_check_host_io_len("handle_advice_write", len);
        let mut bytes = Vec::with_capacity(len as usize);
""",
        "        let mut bytes = Vec::with_capacity(len as usize);\n        for _ in 0..len {\n": """        beak_jolt_check_host_io_len("read_string", u64::from(len));
        let mut bytes = Vec::with_capacity(len as usize);
        for _ in 0..len {
""",
    }
    for old, new in replacements.items():
        if new not in c:
            if old not in c:
                raise RuntimeError("Jolt CPU host-IO byte guard anchor not found")
            c = c.replace(old, new, 1)
    cpu.write_text(c)

    instruction = jolt_install_path / "tracer" / "src" / "instruction" / "mod.rs"
    c = instruction.read_text()
    if "// BEAK-INSERT: jolt.instruction.deserialize_byte_guard_helpers" not in c:
        anchor = "use crate::emulator::cpu::Cpu;\n"
        helpers = r'''
// BEAK-INSERT: jolt.instruction.deserialize_byte_guard_helpers
fn beak_jolt_env_u64_limit(name: &str, default_value: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_value)
}

fn beak_jolt_check_deserialize_len(context: &str, len: u64) {
    let max_len = beak_jolt_env_u64_limit("BEAK_JOLT_MAX_DESERIALIZE_BYTES", 1_048_576);
    if len > max_len {
        panic!(
            "BEAK_JOLT_MAX_DESERIALIZE_BYTES exceeded in {}: len={} max={}",
            context, len, max_len
        );
    }
}

// BEAK-INSERT-END
'''
        if anchor not in c:
            raise RuntimeError("Jolt instruction deserialize helper anchor not found")
        c = c.replace(anchor, anchor + helpers + "\n", 1)
    old = """        let len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut bytes = vec![0u8; len as usize];
"""
    new = """        let len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        beak_jolt_check_deserialize_len("Instruction::deserialize_with_mode", len);
        let mut bytes = vec![0u8; len as usize];
"""
    if new not in c:
        if old not in c:
            raise RuntimeError("Jolt instruction deserialize byte guard anchor not found")
        c = c.replace(old, new, 1)
    instruction.write_text(c)


def _patch_latest_host_program_trace_injection(jolt_install_path: Path) -> None:
    host_program = jolt_install_path / "jolt-core" / "src" / "host" / "program.rs"
    c = host_program.read_text()

    if "// BEAK-INSERT: jolt.latest.host_program.trace_injection_helpers" not in c:
        helper_anchor = "use tracing::info;\n"
        helpers = r'''
const BEAK_JOLT_LATEST_INJECT_KIND_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_KIND";
const BEAK_JOLT_LATEST_INJECT_STEP_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_STEP";
const BEAK_JOLT_LATEST_INJECT_APPLIED_ENV: &str = "BEAK_JOLT_WITNESS_INJECTION_APPLIED";
const BEAK_JOLT_LATEST_ALU_COMPARISON_AUX_KIND: &str = "jolt.semantic.alu.comparison_auxiliary_chain";
const BEAK_JOLT_LATEST_ALU_COMPARISON_BOOL_KIND: &str = "jolt.semantic.alu.comparison_booleanity";
const BEAK_JOLT_LATEST_ALU_IMM_KIND: &str = "jolt.semantic.alu.immediate_limb_consistency";
const BEAK_JOLT_LATEST_ALU_SHIFT_KIND: &str = "jolt.semantic.alu.shift_mod32";
const BEAK_JOLT_LATEST_ALU_SUB_KIND: &str = "jolt.semantic.alu.subtraction_borrow_chain";
const BEAK_JOLT_LATEST_BRANCH_KIND: &str = "jolt.semantic.control.branch_signedness";
const BEAK_JOLT_LATEST_DECODE_FIELD_KIND: &str = "jolt.semantic.decode.field_range";
const BEAK_JOLT_LATEST_DECODE_FORMAT_IMM_KIND: &str = "jolt.semantic.decode.format_immediate_reassembly";
const BEAK_JOLT_LATEST_DECODE_IMM_SIGN_KIND: &str = "jolt.semantic.decode.immediate_sign_extension";
const BEAK_JOLT_LATEST_DECODE_UPPER_IMM_KIND: &str = "jolt.semantic.decode.upper_immediate_materialization";
const BEAK_JOLT_LATEST_DEST_KIND: &str = "jolt.semantic.exec.dest_binding";
const BEAK_JOLT_LATEST_ENTRYPOINT_KIND: &str = "jolt.semantic.control.entrypoint_binding";
const BEAK_JOLT_LATEST_LINK_KIND: &str = "jolt.semantic.control.link_register";
const BEAK_JOLT_LATEST_SOURCE_KIND: &str = "jolt.semantic.exec.source_operand_binding";
const BEAK_JOLT_LATEST_ZERO_REGISTER_KIND: &str = "jolt.semantic.decode.zero_register_immutability";

// BEAK-INSERT: jolt.latest.host_program.trace_injection_helpers
fn beak_latest_base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn beak_latest_inject_step_matches(configured_step: u64, candidate_step: u64) -> bool {
    configured_step == u64::MAX || configured_step == candidate_step
}

fn beak_latest_cycle_matches_kind(base_kind: &str, cycle: &Cycle) -> bool {
    match base_kind {
        BEAK_JOLT_LATEST_ZERO_REGISTER_KIND => cycle
            .rd_write()
            .map(|(rd, _, _)| rd == 0)
            .unwrap_or(false),
        BEAK_JOLT_LATEST_SOURCE_KIND => cycle.rs1_read().is_some() || cycle.rs2_read().is_some(),
        BEAK_JOLT_LATEST_DEST_KIND => cycle.rd_write().is_some(),
        BEAK_JOLT_LATEST_ENTRYPOINT_KIND
        | BEAK_JOLT_LATEST_DECODE_FIELD_KIND
        | BEAK_JOLT_LATEST_DECODE_IMM_SIGN_KIND
        | BEAK_JOLT_LATEST_DECODE_UPPER_IMM_KIND
        | BEAK_JOLT_LATEST_DECODE_FORMAT_IMM_KIND
        | BEAK_JOLT_LATEST_ALU_IMM_KIND
        | BEAK_JOLT_LATEST_ALU_SHIFT_KIND
        | BEAK_JOLT_LATEST_ALU_COMPARISON_BOOL_KIND
        | BEAK_JOLT_LATEST_ALU_SUB_KIND
        | BEAK_JOLT_LATEST_ALU_COMPARISON_AUX_KIND
        | BEAK_JOLT_LATEST_BRANCH_KIND
        | BEAK_JOLT_LATEST_LINK_KIND => true,
        _ => false,
    }
}

fn beak_latest_apply_trace_injection(trace: &mut Vec<Cycle>) {
    let Ok(kind) = std::env::var(BEAK_JOLT_LATEST_INJECT_KIND_ENV) else {
        return;
    };
    let base_kind = beak_latest_base_inject_kind(&kind);
    let inject_step = std::env::var(BEAK_JOLT_LATEST_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    for candidate_step in 0..trace.len() {
        if !beak_latest_inject_step_matches(inject_step, candidate_step as u64) {
            continue;
        }
        if !beak_latest_cycle_matches_kind(base_kind, &trace[candidate_step]) {
            continue;
        }
        trace.remove(candidate_step);
        std::env::set_var(BEAK_JOLT_LATEST_INJECT_APPLIED_ENV, "1");
        return;
    }
}
// BEAK-INSERT-END
'''
        if helper_anchor not in c:
            raise RuntimeError("Jolt latest host/program helper anchor not found")
        c = c.replace(helper_anchor, helper_anchor + helpers + "\n", 1)

    if "// BEAK-INSERT: jolt.latest.host_program.apply_trace_injection" not in c:
        old_trace = """        let (lazy_trace, trace, memory, jolt_device, _advice_tape) = guest::program::trace(
            &elf_contents,
            self.elf.as_ref(),
            inputs,
            untrusted_advice,
            trusted_advice,
            &memory_config,
            None,
        );
        (lazy_trace, trace, memory, jolt_device)
"""
        new_trace = """        let (lazy_trace, mut trace, memory, jolt_device, _advice_tape) = guest::program::trace(
            &elf_contents,
            self.elf.as_ref(),
            inputs,
            untrusted_advice,
            trusted_advice,
            &memory_config,
            None,
        );
        // BEAK-INSERT: jolt.latest.host_program.apply_trace_injection
        beak_latest_apply_trace_injection(&mut trace);
        // BEAK-INSERT-END
        (lazy_trace, trace, memory, jolt_device)
"""
        if old_trace not in c:
            raise RuntimeError("Jolt latest host/program trace return anchor not found")
        c = c.replace(old_trace, new_trace, 1)

    host_program.write_text(c)


def _patch_read_write_memory_injection(jolt_install_path: Path) -> None:
    read_write_memory = (
        jolt_install_path / "jolt-core" / "src" / "jolt" / "vm" / "read_write_memory.rs"
    )
    c = read_write_memory.read_text()

    if "// BEAK-INSERT: jolt.read_write_memory.semantic_injection_helpers" not in c:
        anchor = "const RAM: usize = 3;\n"
        helpers = r'''
const BEAK_JOLT_INJECT_KIND_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_KIND";
const BEAK_JOLT_INJECT_STEP_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_STEP";
const BEAK_JOLT_INJECT_APPLIED_ENV: &str = "BEAK_JOLT_WITNESS_INJECTION_APPLIED";
const BEAK_JOLT_MUTATION_RECEIPT_ENV: &str = "BEAK_JOLT_WITNESS_MUTATION_RECEIPT";
const BEAK_JOLT_ZERO_REGISTER_KIND: &str = "jolt.semantic.decode.zero_register_immutability";
const BEAK_JOLT_OPERAND_INDEX_KIND: &str = "jolt.semantic.decode.operand_index_routing";
const BEAK_JOLT_DEST_BINDING_KIND: &str = "jolt.semantic.exec.dest_binding";
const BEAK_JOLT_MEMORY_ADDRESS_KIND: &str = "jolt.semantic.memory.address_pointer_consistency";
const BEAK_JOLT_MEMORY_VALUE_KIND: &str = "jolt.semantic.memory.value_payload_consistency";
const BEAK_JOLT_STORE_LOAD_KIND: &str = "jolt.semantic.memory.store_load_payload_flow";
const BEAK_JOLT_MEMORY_INITIAL_KIND: &str = "jolt.semantic.memory.initial_value_binding";
const BEAK_JOLT_MEMORY_FINALIZATION_KIND: &str = "jolt.semantic.memory.finalization_consistency";
const BEAK_JOLT_TIME_BOUNDARY_KIND: &str = "jolt.semantic.time.boundary_origin_consistency";
const BEAK_JOLT_TIME_MONOTONIC_KIND: &str = "jolt.semantic.time.monotonic_access_ordering";

// BEAK-INSERT: jolt.read_write_memory.semantic_injection_helpers
fn beak_rw_base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn beak_rw_step_matches(configured_step: u64, candidate_step: u64) -> bool {
    configured_step == u64::MAX || configured_step == candidate_step
}

fn beak_rw_should_inject(kind: Option<&str>, target: &str, configured_step: u64, step: u64) -> bool {
    kind.map(|kind| beak_rw_base_inject_kind(kind) == target)
        .unwrap_or(false)
        && beak_rw_step_matches(configured_step, step)
}

fn beak_rw_mark_applied() {
    std::env::set_var(BEAK_JOLT_INJECT_APPLIED_ENV, "1");
}

fn beak_rw_mutate_u32(value: u32) -> u32 {
    value.wrapping_add(1)
}
// BEAK-INSERT-END
'''
        if anchor not in c:
            raise RuntimeError("Jolt read_write_memory helper anchor not found")
        c = c.replace(anchor, anchor + helpers + "\n")

    new_size = """        // BEAK-INSERT: jolt.read_write_memory.inclusive_memory_size
        let bytecode_start_index = memory_address_to_witness_index(
            preprocessing.min_bytecode_address,
            &program_io.memory_layout,
        );
        let bytecode_end_index = bytecode_start_index
            .checked_add(preprocessing.bytecode_words.len())
            .expect("read/write memory bytecode index overflow");
        let input_start_index = memory_address_to_witness_index(
            program_io.memory_layout.input_start,
            &program_io.memory_layout,
        );
        let input_word_len = (program_io.inputs.len() + 3) / 4;
        let input_end_index = input_start_index
            .checked_add(input_word_len)
            .expect("read/write memory input index overflow");
        let memory_size = [
            max_trace_address
                .checked_add(1)
                .expect("read/write memory witness address overflow") as usize,
            bytecode_end_index,
            input_end_index,
            8,
        ]
        .into_iter()
        .max()
        .unwrap()
        .next_power_of_two();
        // BEAK-INSERT-END
"""
    if "// BEAK-INSERT: jolt.read_write_memory.inclusive_memory_size" not in c:
        old_size = "        let memory_size = max_trace_address.next_power_of_two() as usize;\n"
        if old_size not in c:
            raise RuntimeError("Jolt read_write_memory memory_size anchor not found")
        c = c.replace(old_size, new_size, 1)
    else:
        start = c.index("        // BEAK-INSERT: jolt.read_write_memory.inclusive_memory_size\n")
        end_marker = "        // BEAK-INSERT-END\n"
        end = c.index(end_marker, start) + len(end_marker)
        c = c[:start] + new_size + c[end:]

    if "// BEAK-INSERT: jolt.read_write_memory.configure_semantic_injection" not in c:
        old_config = """        let mut t_final = vec![0; memory_size];
        let mut v_final = v_init.clone();

        let span = tracing::span!(tracing::Level::DEBUG, "memory_trace_processing");
"""
        new_config = """        let mut t_final = vec![0; memory_size];
        let mut v_final = v_init.clone();

        // BEAK-INSERT: jolt.read_write_memory.configure_semantic_injection
        let beak_inject_kind = std::env::var(BEAK_JOLT_INJECT_KIND_ENV).ok();
        let beak_inject_step = std::env::var(BEAK_JOLT_INJECT_STEP_ENV)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        // BEAK-INSERT-END

        let span = tracing::span!(tracing::Level::DEBUG, "memory_trace_processing");
"""
        if old_config not in c:
            raise RuntimeError("Jolt read_write_memory injection config anchor not found")
        c = c.replace(old_config, new_config, 1)

    if "// BEAK-INSERT: jolt.read_write_memory.initial_value_binding" not in c:
        old_initial = """        // BEAK-INSERT-END

        let span = tracing::span!(tracing::Level::DEBUG, "memory_trace_processing");
"""
        new_initial = """        // BEAK-INSERT-END

        // BEAK-INSERT: jolt.read_write_memory.initial_value_binding
        if let Some(kind) = beak_inject_kind.as_deref() {
            if beak_rw_base_inject_kind(kind) == BEAK_JOLT_MEMORY_INITIAL_KIND && !v_init.is_empty() {
                let target = if beak_inject_step == u64::MAX {
                    v_init.iter().position(|v| *v != 0).unwrap_or(0)
                } else {
                    beak_inject_step as usize
                };
                if target < v_init.len() {
                    v_init[target] = beak_rw_mutate_u32(v_init[target]);
                    beak_rw_mark_applied();
                }
            }
        }
        // BEAK-INSERT-END

        let span = tracing::span!(tracing::Level::DEBUG, "memory_trace_processing");
"""
        if old_initial not in c:
            raise RuntimeError("Jolt read_write_memory initial binding anchor not found")
        c = c.replace(old_initial, new_initial, 1)

    if "// BEAK-INSERT: jolt.read_write_memory.rs1_read_value" not in c:
        old_rs1 = """                    v_read_rs1.push(v);
                    t_read_rs1.push(t_final[a]);
                    t_final[a] = timestamp;
"""
        new_rs1 = """                    let mut beak_v_read_rs1 = v;
                    // BEAK-INSERT: jolt.read_write_memory.rs1_read_value
                    if beak_rw_should_inject(
                        beak_inject_kind.as_deref(),
                        BEAK_JOLT_OPERAND_INDEX_KIND,
                        beak_inject_step,
                        timestamp as u64,
                    ) {
                        beak_v_read_rs1 = beak_rw_mutate_u32(beak_v_read_rs1);
                        beak_rw_mark_applied();
                    }
                    // BEAK-INSERT-END

                    v_read_rs1.push(beak_v_read_rs1);
                    t_read_rs1.push(t_final[a]);
                    t_final[a] = timestamp;
"""
        if old_rs1 not in c:
            raise RuntimeError("Jolt read_write_memory rs1 read anchor not found")
        c = c.replace(old_rs1, new_rs1, 1)

    if "// BEAK-INSERT: jolt.read_write_memory.rs2_read_value" not in c:
        old_rs2 = """                    v_read_rs2.push(v);
                    t_read_rs2.push(t_final[a]);
                    t_final[a] = timestamp;
"""
        new_rs2 = """                    let mut beak_v_read_rs2 = v;
                    // BEAK-INSERT: jolt.read_write_memory.rs2_read_value
                    if beak_rw_should_inject(
                        beak_inject_kind.as_deref(),
                        BEAK_JOLT_OPERAND_INDEX_KIND,
                        beak_inject_step,
                        timestamp as u64,
                    ) {
                        beak_v_read_rs2 = beak_rw_mutate_u32(beak_v_read_rs2);
                        beak_rw_mark_applied();
                    }
                    // BEAK-INSERT-END

                    v_read_rs2.push(beak_v_read_rs2);
                    t_read_rs2.push(t_final[a]);
                    t_final[a] = timestamp;
"""
        if old_rs2 not in c:
            raise RuntimeError("Jolt read_write_memory rs2 read anchor not found")
        c = c.replace(old_rs2, new_rs2, 1)

    if "// BEAK-INSERT: jolt.read_write_memory.rd_write_value" not in c:
        old_rd = """                    v_read_rd.push(v_old);
                    t_read_rd.push(t_final[a]);
                    v_write_rd.push(v_new as u32);
                    v_final[a] = v_new as u32;
                    t_final[a] = timestamp;
"""
        new_rd = """                    let mut beak_v_write_rd = v_new as u32;
                    // BEAK-INSERT: jolt.read_write_memory.rd_write_value
                    if (a == 0
                        && beak_rw_should_inject(
                            beak_inject_kind.as_deref(),
                            BEAK_JOLT_ZERO_REGISTER_KIND,
                            beak_inject_step,
                            timestamp as u64,
                        ))
                        || (a != 0
                            && beak_rw_should_inject(
                                beak_inject_kind.as_deref(),
                                BEAK_JOLT_DEST_BINDING_KIND,
                                beak_inject_step,
                                timestamp as u64,
                            ))
                    {
                        beak_v_write_rd = beak_rw_mutate_u32(beak_v_write_rd);
                        beak_rw_mark_applied();
                    }
                    // BEAK-INSERT-END

                    v_read_rd.push(v_old);
                    t_read_rd.push(t_final[a]);
                    v_write_rd.push(beak_v_write_rd);
                    v_final[a] = v_new as u32;
                    t_final[a] = timestamp;
"""
        if old_rd not in c:
            raise RuntimeError("Jolt read_write_memory rd write anchor not found")
        c = c.replace(old_rd, new_rd, 1)

    if "// BEAK-INSERT: jolt.read_write_memory.ram_read_value" not in c:
        old_ram_read = """                    a_ram.push(remapped_a as u32);
                    v_read_ram.push(v);
                    t_read_ram.push(t_final[remapped_a]);
                    v_write_ram.push(v);
                    t_final[remapped_a] = timestamp;
"""
        new_ram_read = """                    let beak_is_real_ram = a >= program_io.memory_layout.input_start;
                    let mut beak_a_ram = remapped_a as u32;
                    let mut beak_v_read_ram = v;
                    let mut beak_t_read_ram = t_final[remapped_a];
                    // BEAK-INSERT: jolt.read_write_memory.ram_read_value
                    if beak_is_real_ram
                        && beak_rw_should_inject(
                            beak_inject_kind.as_deref(),
                            BEAK_JOLT_MEMORY_ADDRESS_KIND,
                            beak_inject_step,
                            timestamp as u64,
                        )
                    {
                        beak_a_ram = beak_rw_mutate_u32(beak_a_ram);
                        beak_rw_mark_applied();
                    }
                    if beak_is_real_ram
                        && (beak_rw_should_inject(
                            beak_inject_kind.as_deref(),
                            BEAK_JOLT_MEMORY_VALUE_KIND,
                            beak_inject_step,
                            timestamp as u64,
                        ) || beak_rw_should_inject(
                            beak_inject_kind.as_deref(),
                            BEAK_JOLT_STORE_LOAD_KIND,
                            beak_inject_step,
                            timestamp as u64,
                        ))
                    {
                        beak_v_read_ram = beak_rw_mutate_u32(beak_v_read_ram);
                        beak_rw_mark_applied();
                    }
                    if beak_rw_should_inject(
                        beak_inject_kind.as_deref(),
                        BEAK_JOLT_TIME_BOUNDARY_KIND,
                        beak_inject_step,
                        timestamp as u64,
                    ) || beak_rw_should_inject(
                        beak_inject_kind.as_deref(),
                        BEAK_JOLT_TIME_MONOTONIC_KIND,
                        beak_inject_step,
                        timestamp as u64,
                    ) {
                        beak_t_read_ram = beak_rw_mutate_u32(beak_t_read_ram);
                        beak_rw_mark_applied();
                    }
                    // BEAK-INSERT-END

                    a_ram.push(beak_a_ram);
                    v_read_ram.push(beak_v_read_ram);
                    t_read_ram.push(beak_t_read_ram);
                    v_write_ram.push(v);
                    t_final[remapped_a] = timestamp;
"""
        if old_ram_read not in c:
            raise RuntimeError("Jolt read_write_memory ram read anchor not found")
        c = c.replace(old_ram_read, new_ram_read, 1)

    if "// BEAK-INSERT: jolt.read_write_memory.ram_write_value" not in c:
        old_ram_write = """                    a_ram.push(remapped_a as u32);
                    v_read_ram.push(v_old);
                    t_read_ram.push(t_final[remapped_a]);
                    v_write_ram.push(v_new as u32);
                    v_final[remapped_a] = v_new as u32;
                    t_final[remapped_a] = timestamp;
"""
        new_ram_write = """                    let beak_is_real_ram = a >= program_io.memory_layout.input_start;
                    let mut beak_a_ram = remapped_a as u32;
                    let mut beak_v_write_ram = v_new as u32;
                    let mut beak_t_read_ram = t_final[remapped_a];
                    // BEAK-INSERT: jolt.read_write_memory.ram_write_value
                    if beak_is_real_ram
                        && beak_rw_should_inject(
                            beak_inject_kind.as_deref(),
                            BEAK_JOLT_MEMORY_ADDRESS_KIND,
                            beak_inject_step,
                            timestamp as u64,
                        )
                    {
                        beak_a_ram = beak_rw_mutate_u32(beak_a_ram);
                        beak_rw_mark_applied();
                    }
                    if beak_is_real_ram
                        && (beak_rw_should_inject(
                            beak_inject_kind.as_deref(),
                            BEAK_JOLT_MEMORY_VALUE_KIND,
                            beak_inject_step,
                            timestamp as u64,
                        ) || beak_rw_should_inject(
                            beak_inject_kind.as_deref(),
                            BEAK_JOLT_STORE_LOAD_KIND,
                            beak_inject_step,
                            timestamp as u64,
                        ))
                    {
                        beak_v_write_ram = beak_rw_mutate_u32(beak_v_write_ram);
                        beak_rw_mark_applied();
                    }
                    if beak_rw_should_inject(
                        beak_inject_kind.as_deref(),
                        BEAK_JOLT_TIME_BOUNDARY_KIND,
                        beak_inject_step,
                        timestamp as u64,
                    ) || beak_rw_should_inject(
                        beak_inject_kind.as_deref(),
                        BEAK_JOLT_TIME_MONOTONIC_KIND,
                        beak_inject_step,
                        timestamp as u64,
                    ) {
                        beak_t_read_ram = beak_rw_mutate_u32(beak_t_read_ram);
                        beak_rw_mark_applied();
                    }
                    // BEAK-INSERT-END

                    a_ram.push(beak_a_ram);
                    v_read_ram.push(v_old);
                    t_read_ram.push(beak_t_read_ram);
                    v_write_ram.push(beak_v_write_ram);
                    v_final[remapped_a] = v_new as u32;
                    t_final[remapped_a] = timestamp;
"""
        if old_ram_write not in c:
            raise RuntimeError("Jolt read_write_memory ram write anchor not found")
        c = c.replace(old_ram_write, new_ram_write, 1)

    if "// BEAK-INSERT: jolt.read_write_memory.finalization_consistency" not in c:
        old_final = """        let [a_ram, v_read_rd, v_read_rs1, v_read_rs2, v_read_ram, v_write_rd, v_write_ram, v_final, t_read_rd_poly, t_read_rs1_poly, t_read_rs2_poly, t_read_ram_poly, t_final, v_init] =
            map_to_polys([
"""
        new_final = """        // BEAK-INSERT: jolt.read_write_memory.finalization_consistency
        if let Some(kind) = beak_inject_kind.as_deref() {
            if beak_rw_base_inject_kind(kind) == BEAK_JOLT_MEMORY_FINALIZATION_KIND && !v_final.is_empty() {
                let target = if beak_inject_step == u64::MAX {
                    t_final
                        .iter()
                        .enumerate()
                        .find(|(_, t)| **t != 0)
                        .map(|(idx, _)| idx)
                        .unwrap_or(0)
                } else {
                    beak_inject_step as usize
                };
                if target < v_final.len() {
                    v_final[target] = beak_rw_mutate_u32(v_final[target]);
                    beak_rw_mark_applied();
                }
            }
        }
        // BEAK-INSERT-END

        let [a_ram, v_read_rd, v_read_rs1, v_read_rs2, v_read_ram, v_write_rd, v_write_ram, v_final, t_read_rd_poly, t_read_rs1_poly, t_read_rs2_poly, t_read_ram_poly, t_final, v_init] =
            map_to_polys([
"""
        if old_final not in c:
            raise RuntimeError("Jolt read_write_memory finalization anchor not found")
        c = c.replace(old_final, new_final, 1)

    read_write_memory.write_text(c)


def _patch_bytecode_injection(jolt_install_path: Path) -> None:
    bytecode = jolt_install_path / "jolt-core" / "src" / "jolt" / "vm" / "bytecode.rs"
    c = bytecode.read_text()

    if "// BEAK-INSERT: jolt.bytecode.semantic_injection_helpers" not in c:
        anchor = "use crate::utils::transcript::Transcript;\n"
        helpers = r'''
const BEAK_JOLT_INJECT_KIND_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_KIND";
const BEAK_JOLT_INJECT_STEP_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_STEP";
const BEAK_JOLT_INJECT_APPLIED_ENV: &str = "BEAK_JOLT_WITNESS_INJECTION_APPLIED";
const BEAK_JOLT_FIELD_RANGE_KIND: &str = "jolt.semantic.decode.field_range";
const BEAK_JOLT_IMMEDIATE_SIGN_KIND: &str = "jolt.semantic.decode.immediate_sign_extension";
const BEAK_JOLT_FORMAT_IMMEDIATE_KIND: &str = "jolt.semantic.decode.format_immediate_reassembly";
const BEAK_JOLT_OP_SELECTOR_KIND: &str = "jolt.semantic.exec.op_selector_binding";
const BEAK_JOLT_ALU_IMMEDIATE_KIND: &str = "jolt.semantic.alu.immediate_limb_consistency";

// BEAK-INSERT: jolt.bytecode.semantic_injection_helpers
fn beak_bytecode_base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn beak_bytecode_target_index(len: usize) -> Option<(String, usize)> {
    let kind = std::env::var(BEAK_JOLT_INJECT_KIND_ENV).ok()?;
    let step = std::env::var(BEAK_JOLT_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    if len == 0 {
        return None;
    }
    let idx = if step == u64::MAX { 0 } else { step as usize };
    (idx < len).then_some((kind, idx))
}

fn beak_bytecode_mark_applied() {
    std::env::set_var(BEAK_JOLT_INJECT_APPLIED_ENV, "1");
}

fn beak_bytecode_apply_semantic_injection(
    bitflags: &mut [u64],
    rd: &mut [u8],
    rs1: &mut [u8],
    rs2: &mut [u8],
    imm: &mut [i64],
) {
    let Some((kind, idx)) = beak_bytecode_target_index(bitflags.len()) else {
        return;
    };
    match beak_bytecode_base_inject_kind(&kind) {
        BEAK_JOLT_FIELD_RANGE_KIND => {
            rd[idx] = 32;
            beak_bytecode_mark_applied();
        }
        BEAK_JOLT_IMMEDIATE_SIGN_KIND | BEAK_JOLT_FORMAT_IMMEDIATE_KIND | BEAK_JOLT_ALU_IMMEDIATE_KIND => {
            imm[idx] ^= 0x1000;
            beak_bytecode_mark_applied();
        }
        BEAK_JOLT_OP_SELECTOR_KIND => {
            bitflags[idx] ^= 1;
            beak_bytecode_mark_applied();
        }
        _ => {
            let _ = (rs1, rs2);
        }
    }
}
// BEAK-INSERT-END
'''
        if anchor not in c:
            raise RuntimeError("Jolt bytecode helper anchor not found")
        c = c.replace(anchor, anchor + helpers + "\n")

    if "// BEAK-INSERT: jolt.bytecode.apply_semantic_injection" not in c:
        anchor = """        for step in trace {
            address.push(step.bytecode_row.address as u64);
            bitflags.push(step.bytecode_row.bitflags);
            rd.push(step.bytecode_row.rd);
            rs1.push(step.bytecode_row.rs1);
            rs2.push(step.bytecode_row.rs2);
            imm.push(step.bytecode_row.imm);
        }

        let v_read_write = [
"""
        replacement = """        for step in trace {
            address.push(step.bytecode_row.address as u64);
            bitflags.push(step.bytecode_row.bitflags);
            rd.push(step.bytecode_row.rd);
            rs1.push(step.bytecode_row.rs1);
            rs2.push(step.bytecode_row.rs2);
            imm.push(step.bytecode_row.imm);
        }

        // BEAK-INSERT: jolt.bytecode.apply_semantic_injection
        beak_bytecode_apply_semantic_injection(
            &mut bitflags,
            &mut rd,
            &mut rs1,
            &mut rs2,
            &mut imm,
        );
        // BEAK-INSERT-END

        let v_read_write = [
"""
        if anchor not in c:
            raise RuntimeError("Jolt bytecode injection anchor not found")
        c = c.replace(anchor, replacement, 1)

    bytecode.write_text(c)


def _patch_instruction_lookup_injection(jolt_install_path: Path) -> None:
    instruction_lookups = (
        jolt_install_path / "jolt-core" / "src" / "jolt" / "vm" / "instruction_lookups.rs"
    )
    c = instruction_lookups.read_text()

    if "// BEAK-INSERT: jolt.instruction_lookups.semantic_injection_helpers" not in c:
        anchor = "use tracing::trace_span;\n"
        helpers = r'''
const BEAK_JOLT_INJECT_KIND_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_KIND";
const BEAK_JOLT_INJECT_STEP_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_STEP";
const BEAK_JOLT_INJECT_APPLIED_ENV: &str = "BEAK_JOLT_WITNESS_INJECTION_APPLIED";
const BEAK_JOLT_SHIFT_KIND: &str = "jolt.semantic.alu.shift_mod32";
const BEAK_JOLT_COMPARISON_BOOL_KIND: &str = "jolt.semantic.alu.comparison_booleanity";
const BEAK_JOLT_SUBTRACTION_KIND: &str = "jolt.semantic.alu.subtraction_borrow_chain";
const BEAK_JOLT_COMPARISON_AUX_KIND: &str = "jolt.semantic.alu.comparison_auxiliary_chain";
const BEAK_JOLT_ARITH_SPECIAL_KIND: &str = "jolt.semantic.arithmetic.special_case_consistency";
const BEAK_JOLT_DIV_BOUND_KIND: &str = "jolt.semantic.arithmetic.division_remainder_bound";
const BEAK_JOLT_PRODUCT_KIND: &str = "jolt.semantic.arithmetic.product_decomposition";
const BEAK_JOLT_SIGNED_UNSIGNED_KIND: &str =
    "jolt.semantic.arithmetic.signed_unsigned_product_correction";
const BEAK_JOLT_LOOKUP_BOOLEAN_KIND: &str = "jolt.semantic.lookup.boolean_multiplicity";

// BEAK-INSERT: jolt.instruction_lookups.semantic_injection_helpers
fn beak_lookup_base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn beak_lookup_kind_is_supported(kind: &str) -> bool {
    matches!(
        beak_lookup_base_inject_kind(kind),
        BEAK_JOLT_SHIFT_KIND
            | BEAK_JOLT_COMPARISON_BOOL_KIND
            | BEAK_JOLT_SUBTRACTION_KIND
            | BEAK_JOLT_COMPARISON_AUX_KIND
            | BEAK_JOLT_ARITH_SPECIAL_KIND
            | BEAK_JOLT_DIV_BOUND_KIND
            | BEAK_JOLT_PRODUCT_KIND
            | BEAK_JOLT_SIGNED_UNSIGNED_KIND
    )
}

fn beak_lookup_apply_semantic_injection(lookup_outputs: &mut [u32]) {
    let Ok(kind) = std::env::var(BEAK_JOLT_INJECT_KIND_ENV) else {
        return;
    };
    if !beak_lookup_kind_is_supported(&kind) || lookup_outputs.is_empty() {
        return;
    }
    let step = std::env::var(BEAK_JOLT_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let idx = if step == u64::MAX { 0 } else { step as usize };
    if idx < lookup_outputs.len() {
        lookup_outputs[idx] = lookup_outputs[idx].wrapping_add(1);
        std::env::set_var(BEAK_JOLT_INJECT_APPLIED_ENV, "1");
    }
}

fn beak_lookup_apply_boolean_multiplicity(instruction_flag_bitvectors: &mut [Vec<u8>]) {
    let Ok(kind) = std::env::var(BEAK_JOLT_INJECT_KIND_ENV) else {
        return;
    };
    if beak_lookup_base_inject_kind(&kind) != BEAK_JOLT_LOOKUP_BOOLEAN_KIND
        || instruction_flag_bitvectors.is_empty()
    {
        return;
    }
    let step = std::env::var(BEAK_JOLT_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let trace_len = instruction_flag_bitvectors[0].len();
    if trace_len == 0 {
        return;
    }
    let idx = if step == u64::MAX {
        (0..trace_len)
            .find(|idx| instruction_flag_bitvectors.iter().any(|flags| flags[*idx] == 1))
            .unwrap_or(0)
    } else {
        step as usize
    };
    if idx >= trace_len {
        return;
    }
    for flags in instruction_flag_bitvectors.iter_mut() {
        if flags[idx] == 1 {
            flags[idx] = 2;
            std::env::set_var(BEAK_JOLT_INJECT_APPLIED_ENV, "1");
            return;
        }
    }
    if let Some(first_flags) = instruction_flag_bitvectors.first_mut() {
        first_flags[idx] = 1;
        std::env::set_var(BEAK_JOLT_INJECT_APPLIED_ENV, "1");
    }
}
// BEAK-INSERT-END
'''
        if anchor not in c:
            raise RuntimeError("Jolt instruction_lookups helper anchor not found")
        c = c.replace(anchor, anchor + helpers + "\n")

    if "// BEAK-INSERT: jolt.instruction_lookups.apply_boolean_multiplicity" not in c:
        anchor = """        let instruction_flag_polys: Vec<MultilinearPolynomial<F>> = instruction_flag_bitvectors
            .into_par_iter()
            .map(MultilinearPolynomial::from)
            .collect();
"""
        replacement = """        // BEAK-INSERT: jolt.instruction_lookups.apply_boolean_multiplicity
        beak_lookup_apply_boolean_multiplicity(&mut instruction_flag_bitvectors);
        // BEAK-INSERT-END
        let instruction_flag_polys: Vec<MultilinearPolynomial<F>> = instruction_flag_bitvectors
            .into_par_iter()
            .map(MultilinearPolynomial::from)
            .collect();
"""
        if anchor not in c:
            raise RuntimeError("Jolt instruction_lookups booleanity anchor not found")
        c = c.replace(anchor, replacement, 1)

    if "// BEAK-INSERT: jolt.instruction_lookups.apply_semantic_injection" not in c:
        anchor = """        let mut lookup_outputs = Self::compute_lookup_outputs(ops);
        lookup_outputs.resize(m, 0);
        let lookup_outputs = MultilinearPolynomial::from(lookup_outputs);
"""
        replacement = """        let mut lookup_outputs = Self::compute_lookup_outputs(ops);
        lookup_outputs.resize(m, 0);
        // BEAK-INSERT: jolt.instruction_lookups.apply_semantic_injection
        beak_lookup_apply_semantic_injection(&mut lookup_outputs);
        // BEAK-INSERT-END
        let lookup_outputs = MultilinearPolynomial::from(lookup_outputs);
"""
        if anchor not in c:
            raise RuntimeError("Jolt instruction_lookups injection anchor not found")
        c = c.replace(anchor, replacement, 1)

    instruction_lookups.write_text(c)


def _entrypoint_boundary_witness_hook() -> str:
    """Return the canonical row-0 address-only mutation used for installs and upgrades."""
    return r'''    if base_kind == BEAK_JOLT_ENTRYPOINT_INJECT_KIND {
        let (delta, mode_name) = match mode {
            None | Some("skip_two") => (8usize, "skip_two"),
            Some("skip_one") => (4usize, "skip_one"),
            Some("far_page") => (0x1000usize, "far_page"),
            _ => (0usize, "rejected"),
        };
        let opcode = std::env::var(BEAK_JOLT_ENTRYPOINT_OPCODE_ENV).ok();
        let mnemonic = std::env::var(BEAK_JOLT_ENTRYPOINT_MNEMONIC_ENV).ok();
        let metadata_is_typed = opcode.as_deref().is_some_and(|value| {
            value.len() == 10
                && value.starts_with("0x")
                && value[2..].chars().all(|character| character.is_ascii_hexdigit())
        }) && mnemonic.as_deref().is_some_and(|value| {
            !value.is_empty()
                && value
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        });
        if beak_inject_step_matches(inject_step, 0) && delta != 0 && metadata_is_typed {
            let trace_len_before = trace.len();
            if let Some(boundary_row) = trace.first_mut() {
                let declared_entry = common::constants::RAM_START_ADDRESS as usize;
                let witnessed_pc_before = boundary_row.bytecode_row.beak_receipt_address();
                if witnessed_pc_before == declared_entry {
                    let witnessed_pc_after = witnessed_pc_before.checked_add(delta);
                if let Some(witnessed_pc_after) = witnessed_pc_after {
                    if boundary_row
                        .bytecode_row
                        .beak_mutate_entrypoint_witness_address(
                            witnessed_pc_before,
                            witnessed_pc_after,
                        )
                    {
                        let trace_len_after = trace_len_before;
                        let opcode = opcode.unwrap();
                        let mnemonic = mnemonic.unwrap();
                        applied = true;
                        receipt = Some(format!(
                            r#"{{"inject_kind":"{}","site":"host.trace.row0.bytecode_row","field":"bytecode_row.address","step":0,"before":{},"after":{},"effect":{{"relation":"entrypoint_pc_equation","context":{{"bucket_id":"sem.control.entrypoint_binding","obligation_id":"cf4","cell_id":"cf4.default_entry","backend":"jolt","trace_source":"instruction","op_idx":0,"step_idx":0,"boundary_row":0,"pc":{},"opcode":"{}","mnemonic":"{}","declared_entry":{},"witnessed_pc_before":{},"witnessed_pc_after":{},"first_row_opcode_before":"{}","first_row_opcode_after":"{}","first_row_mnemonic_before":"{}","first_row_mnemonic_after":"{}","mutation_mode":"{}","trace_len_before":{},"trace_len_after":{},"trace_rows_preserved":true,"trace_order_preserved":true,"executed_boundary_row":true}}}}}}"#,
                            kind,
                            witnessed_pc_before,
                            witnessed_pc_after,
                            witnessed_pc_before,
                            opcode,
                            mnemonic,
                            declared_entry,
                            witnessed_pc_before,
                            witnessed_pc_after,
                            opcode,
                            opcode,
                            mnemonic,
                            mnemonic,
                            mode_name,
                            trace_len_before,
                            trace_len_after,
                        ));
                    }
                }
                }
            }
        }
    }'''


def _patch_host_trace_injection(jolt_install_path: Path) -> None:
    host_mod = jolt_install_path / "jolt-core" / "src" / "host" / "mod.rs"
    c = host_mod.read_text()
    if (
        "// BEAK-INSERT: jolt.host.semantic_injection_helpers" in c
        and "const BEAK_JOLT_ENTRYPOINT_OPCODE_ENV" not in c
    ):
        env_anchor = '''const BEAK_JOLT_MUTATION_RECEIPT_ENV: &str = "BEAK_JOLT_WITNESS_MUTATION_RECEIPT";
'''
        env_constants = '''const BEAK_JOLT_MUTATION_RECEIPT_ENV: &str = "BEAK_JOLT_WITNESS_MUTATION_RECEIPT";
const BEAK_JOLT_ENTRYPOINT_OPCODE_ENV: &str = "BEAK_JOLT_ENTRYPOINT_OPCODE";
const BEAK_JOLT_ENTRYPOINT_MNEMONIC_ENV: &str = "BEAK_JOLT_ENTRYPOINT_MNEMONIC";
'''
        if env_anchor not in c:
            raise RuntimeError("Jolt entrypoint receipt metadata env anchor not found")
        c = c.replace(env_anchor, env_constants, 1)
    if (
        "// BEAK-INSERT: jolt.host.semantic_injection_helpers" in c
        and '"relation":"upper_immediate_materialization"' in c
    ):
        legacy = '''            step_row.instruction_lookup = Some(ADVICEInstruction::<32>(next as u64).into());
            applied = true;
            receipt = Some(format!(
                r#"{{"inject_kind":"{}","site":"host.trace.upper_immediate_lookup","field":"virtual_advice_value","step":{},"before":{},"after":{},"effect":{{"relation":"upper_immediate_materialization"}}}}"#,
                kind, step, current, next
            ));
'''
        upgraded = '''            let imm20 = (current >> 12) & 0x000f_ffff;
            let rd = step_row.bytecode_row.beak_receipt_rd() as u32;
            let pc = step_row.bytecode_row.beak_receipt_address() as u64;
            let opcode = (imm20 << 12) | (rd << 7) | 0x37;
            let cell_id = if imm20 == 0 {
                "id3.lui_zero"
            } else if imm20 == 0x000f_ffff {
                "id3.lui_max"
            } else {
                "id3.lui_mid"
            };
            step_row.instruction_lookup = Some(ADVICEInstruction::<32>(next as u64).into());
            applied = true;
            receipt = Some(format!(
                r#"{{"inject_kind":"{}","site":"host.trace.upper_immediate_lookup","field":"virtual_advice_value","step":{},"before":{},"after":{},"effect":{{"relation":"upper_immediate_equation","context":{{"bucket_id":"sem.decode.upper_immediate_materialization","obligation_id":"id3","cell_id":"{}","backend":"jolt","trace_source":"instruction","op_idx":{},"pc":{},"opcode":{},"mnemonic":"lui","imm20":{},"expected_result":{},"witnessed_result_before":{},"witnessed_result_after":{},"executed_instruction":true}}}}}}"#,
                kind,
                step,
                current,
                next,
                cell_id,
                step,
                pc,
                opcode,
                imm20,
                current,
                current,
                next,
            ));
'''
        if legacy not in c:
            raise RuntimeError("Jolt legacy upper-immediate receipt migration anchor not found")
        c = c.replace(legacy, upgraded, 1)
    if (
        "// BEAK-INSERT: jolt.host.apply_semantic_injection" in c
        and "        let trace: Vec<_> = raw_trace" in c
    ):
        c = c.replace(
            "        let trace: Vec<_> = raw_trace",
            "        let mut trace: Vec<_> = raw_trace",
            1,
        )

    if "// BEAK-INSERT: jolt.host.semantic_injection_helpers" not in c:
        old_imports = """            div::DIVInstruction, divu::DIVUInstruction, lb::LBInstruction, lbu::LBUInstruction,
            lh::LHInstruction, lhu::LHUInstruction, mulh::MULHInstruction,
            mulhsu::MULHSUInstruction, rem::REMInstruction, remu::REMUInstruction,
            sb::SBInstruction, sh::SHInstruction, VirtualInstructionSequence,
"""
        new_imports = """            beq::BEQInstruction, bge::BGEInstruction, bgeu::BGEUInstruction,
            bne::BNEInstruction, div::DIVInstruction, divu::DIVUInstruction, lb::LBInstruction,
            lbu::LBUInstruction, lh::LHInstruction, lhu::LHUInstruction, mulh::MULHInstruction,
            mulhsu::MULHSUInstruction, rem::REMInstruction, remu::REMUInstruction,
            sb::SBInstruction, sh::SHInstruction, slt::SLTInstruction, sltu::SLTUInstruction,
            virtual_advice::ADVICEInstruction, VirtualInstructionSequence,
"""
        if old_imports not in c:
            raise RuntimeError("Jolt host instruction import anchor not found")
        c = c.replace(old_imports, new_imports)

        helper_anchor = 'pub const DEFAULT_TARGET_DIR: &str = "/tmp/jolt-guest-targets";\n'
        helpers = r'''
const BEAK_JOLT_INJECT_KIND_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_KIND";
const BEAK_JOLT_INJECT_STEP_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_STEP";
const BEAK_JOLT_INJECT_APPLIED_ENV: &str = "BEAK_JOLT_WITNESS_INJECTION_APPLIED";
const BEAK_JOLT_MUTATION_RECEIPT_ENV: &str = "BEAK_JOLT_WITNESS_MUTATION_RECEIPT";
const BEAK_JOLT_ENTRYPOINT_OPCODE_ENV: &str = "BEAK_JOLT_ENTRYPOINT_OPCODE";
const BEAK_JOLT_ENTRYPOINT_MNEMONIC_ENV: &str = "BEAK_JOLT_ENTRYPOINT_MNEMONIC";
const BEAK_JOLT_UPPER_IMMEDIATE_INJECT_KIND: &str =
    "jolt.semantic.decode.upper_immediate_materialization";
const BEAK_JOLT_ENTRYPOINT_INJECT_KIND: &str = "jolt.semantic.control.entrypoint_binding";
const BEAK_JOLT_CONTROL_FLOW_INJECT_KIND: &str = "jolt.semantic.exec.control_flow_binding";
const BEAK_JOLT_ADDRESS_SPACE_INJECT_KIND: &str =
    "jolt.semantic.memory.address_space_consistency";
const BEAK_JOLT_KIND_SELECTOR_INJECT_KIND: &str =
    "jolt.semantic.memory.kind_selector_consistency";

// BEAK-INSERT: jolt.host.semantic_injection_helpers
fn beak_base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn beak_inject_variant_value<'a>(kind: &'a str, key: &str) -> Option<&'a str> {
    let (_, variant) = kind.split_once("::")?;
    for field in variant.split(',') {
        let (field_key, field_value) = field.split_once('=')?;
        if field_key == key {
            return Some(field_value);
        }
    }
    None
}

fn beak_inject_variant_mode(kind: &str) -> Option<&str> {
    beak_inject_variant_value(kind, "mode")
}

fn beak_inject_step_matches(configured_step: u64, candidate_step: u64) -> bool {
    configured_step == u64::MAX || configured_step == candidate_step
}

fn beak_is_real_lui_step(step: &JoltTraceStep<RV32I>) -> bool {
    matches!(step.instruction_lookup, Some(RV32I::VIRTUAL_ADVICE(_)))
        && !step.circuit_flags[common::rv_trace::CircuitFlags::Virtual as usize]
}

fn beak_is_branch_step(step: &JoltTraceStep<RV32I>) -> bool {
    step.circuit_flags[common::rv_trace::CircuitFlags::Branch as usize]
        && !step.circuit_flags[common::rv_trace::CircuitFlags::Virtual as usize]
}

fn beak_branch_mode_matches(mode: Option<&str>, family: &str) -> bool {
    match mode {
        None | Some("paired_flip") => true,
        Some("eq_flip") => family == "eq",
        Some("signed_cmp_flip") => family == "signed",
        Some("unsigned_cmp_flip") => family == "unsigned",
        _ => false,
    }
}

fn beak_mutate_branch_lookup(step_row: &mut JoltTraceStep<RV32I>, mode: Option<&str>) -> bool {
    let next_lookup = match step_row.instruction_lookup {
        Some(RV32I::BEQ(insn)) if beak_branch_mode_matches(mode, "eq") => {
            Some(RV32I::BNE(BNEInstruction::<32>(insn.0, insn.1)))
        }
        Some(RV32I::BNE(insn)) if beak_branch_mode_matches(mode, "eq") => {
            Some(RV32I::BEQ(BEQInstruction::<32>(insn.0, insn.1)))
        }
        Some(RV32I::SLT(insn)) if beak_branch_mode_matches(mode, "signed") => {
            Some(RV32I::BGE(BGEInstruction::<32>(insn.0, insn.1)))
        }
        Some(RV32I::BGE(insn)) if beak_branch_mode_matches(mode, "signed") => {
            Some(RV32I::SLT(SLTInstruction::<32>(insn.0, insn.1)))
        }
        Some(RV32I::SLTU(insn)) if beak_branch_mode_matches(mode, "unsigned") => {
            Some(RV32I::BGEU(BGEUInstruction::<32>(insn.0, insn.1)))
        }
        Some(RV32I::BGEU(insn)) if beak_branch_mode_matches(mode, "unsigned") => {
            Some(RV32I::SLTU(SLTUInstruction::<32>(insn.0, insn.1)))
        }
        _ => None,
    };

    if let Some(next_lookup) = next_lookup {
        step_row.instruction_lookup = Some(next_lookup);
        true
    } else {
        false
    }
}

fn beak_mutate_address_space_slot(step_row: &mut JoltTraceStep<RV32I>, slot: usize) -> bool {
    let Some(memory_op) = step_row.memory_ops.get_mut(slot) else {
        return false;
    };
    match memory_op {
        common::rv_trace::MemoryOp::Read(address)
            if slot == 3 && *address >= common::constants::REGISTER_COUNT =>
        {
            *address = 0;
            true
        }
        common::rv_trace::MemoryOp::Write(address, _)
            if slot == 3 && *address >= common::constants::REGISTER_COUNT =>
        {
            *address = 0;
            true
        }
        common::rv_trace::MemoryOp::Read(address)
            if slot != 3 && *address < common::constants::REGISTER_COUNT =>
        {
            *address = common::constants::RAM_START_ADDRESS;
            true
        }
        common::rv_trace::MemoryOp::Write(address, _)
            if slot != 3 && *address < common::constants::REGISTER_COUNT =>
        {
            *address = common::constants::RAM_START_ADDRESS;
            true
        }
        _ => false,
    }
}

fn beak_mutate_address_space(step_row: &mut JoltTraceStep<RV32I>, slot: Option<&str>) -> bool {
    let slots: &[usize] = match slot {
        Some("rs1") => &[0],
        Some("rs2") => &[1],
        Some("rd") => &[2],
        Some("ram") => &[3],
        _ => &[3, 0, 1, 2],
    };
    slots
        .iter()
        .copied()
        .any(|slot| beak_mutate_address_space_slot(step_row, slot))
}

fn beak_mutate_kind_selector(step_row: &mut JoltTraceStep<RV32I>) -> bool {
    let memory_op = &mut step_row.memory_ops[3];
    match *memory_op {
        common::rv_trace::MemoryOp::Read(address)
            if address >= common::constants::REGISTER_COUNT =>
        {
            *memory_op = common::rv_trace::MemoryOp::Write(address, 0);
            true
        }
        common::rv_trace::MemoryOp::Write(address, _)
            if address >= common::constants::REGISTER_COUNT =>
        {
            *memory_op = common::rv_trace::MemoryOp::Read(address);
            true
        }
        _ => false,
    }
}

fn beak_apply_semantic_injection(trace: &mut Vec<JoltTraceStep<RV32I>>) {
    let Ok(kind) = std::env::var(BEAK_JOLT_INJECT_KIND_ENV) else {
        return;
    };
    let inject_step = std::env::var(BEAK_JOLT_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let base_kind = beak_base_inject_kind(&kind);
    let mode = beak_inject_variant_mode(&kind);
    let slot = beak_inject_variant_value(&kind, "slot");
    let mut applied = false;
    let mut receipt = None;

    if base_kind == BEAK_JOLT_ENTRYPOINT_INJECT_KIND {
        let (delta, mode_name) = match mode {
            None | Some("skip_two") => (8usize, "skip_two"),
            Some("skip_one") => (4usize, "skip_one"),
            Some("far_page") => (0x1000usize, "far_page"),
            _ => (0usize, "rejected"),
        };
        let opcode = std::env::var(BEAK_JOLT_ENTRYPOINT_OPCODE_ENV).ok();
        let mnemonic = std::env::var(BEAK_JOLT_ENTRYPOINT_MNEMONIC_ENV).ok();
        let metadata_is_typed = opcode.as_deref().is_some_and(|value| {
            value.len() == 10
                && value.starts_with("0x")
                && value[2..].chars().all(|character| character.is_ascii_hexdigit())
        }) && mnemonic.as_deref().is_some_and(|value| {
            !value.is_empty()
                && value
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        });
        if beak_inject_step_matches(inject_step, 0) && delta != 0 && metadata_is_typed {
            let trace_len_before = trace.len();
            if let Some(boundary_row) = trace.first_mut() {
                let declared_entry = common::constants::RAM_START_ADDRESS as usize;
                let witnessed_pc_before = boundary_row.bytecode_row.beak_receipt_address();
                if witnessed_pc_before == declared_entry {
                    let witnessed_pc_after = witnessed_pc_before.checked_add(delta);
                if let Some(witnessed_pc_after) = witnessed_pc_after {
                    if boundary_row
                        .bytecode_row
                        .beak_mutate_entrypoint_witness_address(
                            witnessed_pc_before,
                            witnessed_pc_after,
                        )
                    {
                        let trace_len_after = trace_len_before;
                        let opcode = opcode.unwrap();
                        let mnemonic = mnemonic.unwrap();
                        applied = true;
                        receipt = Some(format!(
                            r#"{{"inject_kind":"{}","site":"host.trace.row0.bytecode_row","field":"bytecode_row.address","step":0,"before":{},"after":{},"effect":{{"relation":"entrypoint_pc_equation","context":{{"bucket_id":"sem.control.entrypoint_binding","obligation_id":"cf4","cell_id":"cf4.default_entry","backend":"jolt","trace_source":"instruction","op_idx":0,"step_idx":0,"boundary_row":0,"pc":{},"opcode":"{}","mnemonic":"{}","declared_entry":{},"witnessed_pc_before":{},"witnessed_pc_after":{},"first_row_opcode_before":"{}","first_row_opcode_after":"{}","first_row_mnemonic_before":"{}","first_row_mnemonic_after":"{}","mutation_mode":"{}","trace_len_before":{},"trace_len_after":{},"trace_rows_preserved":true,"trace_order_preserved":true,"executed_boundary_row":true}}}}}}"#,
                            kind,
                            witnessed_pc_before,
                            witnessed_pc_after,
                            witnessed_pc_before,
                            opcode,
                            mnemonic,
                            declared_entry,
                            witnessed_pc_before,
                            witnessed_pc_after,
                            opcode,
                            opcode,
                            mnemonic,
                            mnemonic,
                            mode_name,
                            trace_len_before,
                            trace_len_after,
                        ));
                    }
                }
                }
            }
        }
    } else if base_kind == BEAK_JOLT_CONTROL_FLOW_INJECT_KIND {
        for (idx, step_row) in trace.iter_mut().enumerate() {
            let step = idx as u64;
            if beak_is_branch_step(step_row)
                && beak_inject_step_matches(inject_step, step)
                && beak_mutate_branch_lookup(step_row, mode)
            {
                applied = true;
                break;
            }
        }
    } else if base_kind == BEAK_JOLT_ADDRESS_SPACE_INJECT_KIND {
        for (idx, step_row) in trace.iter_mut().enumerate() {
            let step = idx as u64;
            if beak_inject_step_matches(inject_step, step)
                && beak_mutate_address_space(step_row, slot)
            {
                applied = true;
                break;
            }
        }
    } else if base_kind == BEAK_JOLT_KIND_SELECTOR_INJECT_KIND {
        for (idx, step_row) in trace.iter_mut().enumerate() {
            let step = idx as u64;
            if beak_inject_step_matches(inject_step, step)
                && beak_mutate_kind_selector(step_row)
            {
                applied = true;
                break;
            }
        }
    } else if base_kind == BEAK_JOLT_UPPER_IMMEDIATE_INJECT_KIND
        && !matches!(mode, Some("noop_prefix"))
    {
        for (idx, step_row) in trace.iter_mut().enumerate() {
            let step = idx as u64;
            if !beak_is_real_lui_step(step_row) || !beak_inject_step_matches(inject_step, step) {
                continue;
            }
            let current = match step_row.instruction_lookup.as_ref() {
                Some(RV32I::VIRTUAL_ADVICE(advice)) => advice.0 as u32,
                _ => continue,
            };
            let next = match mode {
                Some("imm_add_page") => current.wrapping_add(0x1000),
                Some("imm_flip_sign") => current ^ (1u32 << 31),
                _ => current ^ 0x1000,
            };
            let imm20 = (current >> 12) & 0x000f_ffff;
            let rd = step_row.bytecode_row.beak_receipt_rd() as u32;
            let pc = step_row.bytecode_row.beak_receipt_address() as u64;
            let opcode = (imm20 << 12) | (rd << 7) | 0x37;
            let cell_id = if imm20 == 0 {
                "id3.lui_zero"
            } else if imm20 == 0x000f_ffff {
                "id3.lui_max"
            } else {
                "id3.lui_mid"
            };
            step_row.instruction_lookup = Some(ADVICEInstruction::<32>(next as u64).into());
            applied = true;
            receipt = Some(format!(
                r#"{{"inject_kind":"{}","site":"host.trace.upper_immediate_lookup","field":"virtual_advice_value","step":{},"before":{},"after":{},"effect":{{"relation":"upper_immediate_equation","context":{{"bucket_id":"sem.decode.upper_immediate_materialization","obligation_id":"id3","cell_id":"{}","backend":"jolt","trace_source":"instruction","op_idx":{},"pc":{},"opcode":{},"mnemonic":"lui","imm20":{},"expected_result":{},"witnessed_result_before":{},"witnessed_result_after":{},"executed_instruction":true}}}}}}"#,
                kind,
                step,
                current,
                next,
                cell_id,
                step,
                pc,
                opcode,
                imm20,
                current,
                current,
                next,
            ));
            break;
        }
    }

    if applied {
        std::env::set_var(BEAK_JOLT_INJECT_APPLIED_ENV, "1");
        if let Some(receipt) = receipt {
            std::env::set_var(BEAK_JOLT_MUTATION_RECEIPT_ENV, receipt);
        }
    }
}
// BEAK-INSERT-END
'''
        if helper_anchor not in c:
            raise RuntimeError("Jolt host helper anchor not found")
        c = c.replace(helper_anchor, helper_anchor + helpers + "\n")

    if "// BEAK-INSERT: jolt.host.semantic_injection_helpers" in c:
        entry_start = "    if base_kind == BEAK_JOLT_ENTRYPOINT_INJECT_KIND {"
        next_branch = "    } else if base_kind == BEAK_JOLT_CONTROL_FLOW_INJECT_KIND {"
        start_idx = c.find(entry_start)
        end_idx = c.find(next_branch, start_idx + len(entry_start))
        if start_idx < 0 or end_idx < 0:
            raise RuntimeError("Jolt entrypoint witness hook boundary not found")
        c = (
            c[:start_idx]
            + _entrypoint_boundary_witness_hook()
            + c[end_idx + len("    }") :]
        )

    if "// BEAK-INSERT: jolt.host.apply_semantic_injection" not in c:
        old_collect = """            .map(|row| {
                let instruction_lookup = RV32I::try_from(&row).ok();

                JoltTraceStep {
                    instruction_lookup,
                    bytecode_row: BytecodeRow::from_instruction::<RV32I>(&row.instruction),
                    memory_ops: (&row).into(),
                    circuit_flags: row.instruction.to_circuit_flags(),
                }
            })
            .collect();

        (io_device, trace)
"""
        new_collect = """            .map(|row| {
                let instruction_lookup = RV32I::try_from(&row).ok();

                JoltTraceStep {
                    instruction_lookup,
                    bytecode_row: BytecodeRow::from_instruction::<RV32I>(&row.instruction),
                    memory_ops: (&row).into(),
                    circuit_flags: row.instruction.to_circuit_flags(),
                }
            })
            .collect();

        // BEAK-INSERT: jolt.host.apply_semantic_injection
        beak_apply_semantic_injection(&mut trace);
        // BEAK-INSERT-END

        (io_device, trace)
"""
        if "        let trace: Vec<_> = raw_trace" in c:
            c = c.replace(
                "        let trace: Vec<_> = raw_trace",
                "        let mut trace: Vec<_> = raw_trace",
                1,
            )
        if old_collect not in c:
            raise RuntimeError("Jolt host trace collect anchor not found")
        c = c.replace(old_collect, new_collect)

    host_mod.write_text(c)


def _patch_vm_padding_injection(jolt_install_path: Path) -> None:
    vm_mod = jolt_install_path / "jolt-core" / "src" / "jolt" / "vm" / "mod.rs"
    c = vm_mod.read_text()

    if "// BEAK-INSERT: jolt.vm.padding_injection_helpers" not in c:
        anchor = "impl<InstructionSet: JoltInstructionSet> JoltTraceStep<InstructionSet> {\n"
        helpers = r'''
const BEAK_JOLT_PADDING_INJECT_KIND: &str = "jolt.semantic.row.padding_interaction_send";
const BEAK_JOLT_PADDING_INJECT_KIND_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_KIND";
const BEAK_JOLT_PADDING_INJECT_STEP_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_STEP";
const BEAK_JOLT_PADDING_INJECT_APPLIED_ENV: &str = "BEAK_JOLT_WITNESS_INJECTION_APPLIED";

// BEAK-INSERT: jolt.vm.padding_injection_helpers
fn beak_pad_base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn beak_apply_padding_injection<InstructionSet: JoltInstructionSet>(
    trace: &mut [JoltTraceStep<InstructionSet>],
    unpadded_length: usize,
    padded_length: usize,
) {
    if padded_length <= unpadded_length {
        return;
    }
    let Ok(kind) = std::env::var(BEAK_JOLT_PADDING_INJECT_KIND_ENV) else {
        return;
    };
    if beak_pad_base_inject_kind(&kind) != BEAK_JOLT_PADDING_INJECT_KIND {
        return;
    }
    let step = std::env::var(BEAK_JOLT_PADDING_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    let target = if step == u64::MAX {
        unpadded_length
    } else {
        step as usize
    };
    if target >= unpadded_length && target < padded_length && target < trace.len() {
        trace[target].memory_ops[3] = MemoryOp::Write(0, 1);
        std::env::set_var(BEAK_JOLT_PADDING_INJECT_APPLIED_ENV, "1");
    }
}
// BEAK-INSERT-END

'''
        if anchor not in c:
            raise RuntimeError("Jolt vm padding helper anchor not found")
        c = c.replace(anchor, helpers + anchor, 1)

    if "// BEAK-INSERT: jolt.vm.apply_padding_injection" not in c:
        old_pad = """    fn pad(trace: &mut Vec<Self>) {
        let unpadded_length = trace.len();
        let padded_length = unpadded_length.next_power_of_two();
        trace.resize(padded_length, Self::no_op());
    }
"""
        new_pad = """    fn pad(trace: &mut Vec<Self>) {
        let unpadded_length = trace.len();
        let padded_length = unpadded_length.next_power_of_two();
        trace.resize(padded_length, Self::no_op());
        // BEAK-INSERT: jolt.vm.apply_padding_injection
        beak_apply_padding_injection(trace, unpadded_length, padded_length);
        // BEAK-INSERT-END
    }
"""
        if old_pad not in c:
            raise RuntimeError("Jolt vm padding anchor not found")
        c = c.replace(old_pad, new_pad, 1)

    vm_mod.write_text(c)
