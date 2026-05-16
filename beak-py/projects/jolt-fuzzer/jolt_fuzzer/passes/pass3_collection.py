from __future__ import annotations

from pathlib import Path

from jolt_fuzzer.settings import JOLT_DORY_SHORT_TRACE_COMMIT, JOLT_READWRITE_SIZING_COMMIT


def apply(*, jolt_install_path: Path, commit_or_branch: str) -> None:
    if commit_or_branch in {JOLT_READWRITE_SIZING_COMMIT, JOLT_DORY_SHORT_TRACE_COMMIT}:
        # These vulnerable snapshots are verified through baseline prover
        # exceptions. Keep upstream source shape intact instead of applying the
        # e9caa witness-mutation hooks, whose host/tracer anchors do not exist
        # uniformly across the older Dory-era tree.
        return

    _ = commit_or_branch
    _patch_host_trace_injection(jolt_install_path)
    _patch_read_write_memory_injection(jolt_install_path)
    _patch_bytecode_injection(jolt_install_path)
    _patch_instruction_lookup_injection(jolt_install_path)
    _patch_vm_padding_injection(jolt_install_path)


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


def _patch_host_trace_injection(jolt_install_path: Path) -> None:
    host_mod = jolt_install_path / "jolt-core" / "src" / "host" / "mod.rs"
    c = host_mod.read_text()
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

    if base_kind == BEAK_JOLT_ENTRYPOINT_INJECT_KIND {
        if beak_inject_step_matches(inject_step, 0) && !matches!(mode, Some("noop_prefix")) {
            let prefix_len = match mode {
                Some("skip_one") => 1usize,
                Some("skip_two") | Some("far_page") => 2usize,
                _ => 2usize,
            };
            if trace.len() > prefix_len {
                trace.drain(0..prefix_len);
                applied = true;
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
            step_row.instruction_lookup = Some(ADVICEInstruction::<32>(next as u64).into());
            applied = true;
            break;
        }
    }

    if applied {
        std::env::set_var(BEAK_JOLT_INJECT_APPLIED_ENV, "1");
    }
}
// BEAK-INSERT-END
'''
        if helper_anchor not in c:
            raise RuntimeError("Jolt host helper anchor not found")
        c = c.replace(helper_anchor, helper_anchor + helpers + "\n")

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
