from __future__ import annotations

from pathlib import Path

NEXUS_BENCHMARK_COMMIT = "636ccb360d0f4ae657ae4bb64e1e275ccec8826"
NEXUS_F2AD_COMMIT = "f2ad12652c39dc516a116447a53f8557f64a7f7d"


def _replace_once(path: Path, old: str, new: str) -> None:
    contents = path.read_text()
    if new in contents:
        return
    if old not in contents:
        raise RuntimeError(f"anchor not found in {path}: {old[:80]!r}")
    path.write_text(contents.replace(old, new, 1))


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

fn beak_nexus_arm_store_load_flow(address: u32, clk: u32, byte: u8) {
    std::env::set_var(BEAK_NEXUS_FLOW_ADDR_ENV, address.to_string());
    std::env::set_var(BEAK_NEXUS_FLOW_CLK_ENV, clk.to_string());
    std::env::set_var(BEAK_NEXUS_FLOW_BYTE_ENV, byte.to_string());
}

fn beak_nexus_store_load_flow_context() -> Option<(u32, u32, u8)> {
    let active_kind = std::env::var(BEAK_NEXUS_INJECT_KIND_ENV).ok()?;
    if beak_nexus_base_inject_kind(&active_kind)
        != "nexus.semantic.memory.store_load_payload_flow"
    {
        return None;
    }
    let address = std::env::var(BEAK_NEXUS_FLOW_ADDR_ENV).ok()?.parse::<u32>().ok()?;
    let clk = std::env::var(BEAK_NEXUS_FLOW_CLK_ENV).ok()?.parse::<u32>().ok()?;
    let byte = std::env::var(BEAK_NEXUS_FLOW_BYTE_ENV).ok()?.parse::<u8>().ok()?;
    Some((address, clk, byte))
}

fn beak_nexus_store_load_flow_raw_load_value(
    memory_record: &nexus_common::memory::MemoryRecord,
    side_note: &SideNote,
) -> Option<u32> {
    let (address, clk, byte) = beak_nexus_store_load_flow_context()?;
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
    Some(u32::from_le_bytes(raw))
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
    flow_value_guard = "beak_nexus_store_load_flow_raw_load_value(memory_record, side_note)"
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
    flow_value_patch = """            let injected_load_raw_value =
                beak_nexus_store_load_flow_raw_load_value(memory_record, side_note);
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
                beak_nexus_arm_store_load_flow(byte_address, clk, cur_value[0]);
                beak_nexus_note_injection(
                    "nexus.semantic.memory.store_load_payload_flow",
                    row_idx,
                    "load_store.store_value_lower_byte",
                );
            }
"""
    if flow_value_guard not in contents:
        _replace_once(path, flow_value_anchor, flow_value_patch)


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
    if base != "nexus.semantic.row.padding_interaction_send"
        && base != "nexus.semantic.memory.finalization_consistency"
    {
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


def apply(*, nexus_install_path: Path, commit_or_branch: str) -> None:
    if commit_or_branch == NEXUS_F2AD_COMMIT:
        _patch_f2ad_prover2_read_write_memory_injection(nexus_install_path)
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
