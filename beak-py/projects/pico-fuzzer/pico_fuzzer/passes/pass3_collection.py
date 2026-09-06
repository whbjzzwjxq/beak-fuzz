"""
Pass 3: Trace + Witness Collection Instrumentation
"""

from __future__ import annotations

from pathlib import Path

from pico_fuzzer.settings import PICO_BENCHMARK_45E74_COMMIT, PICO_LATEST_22B0_COMMIT


def _replace_once(text: str, old: str, new: str) -> str:
    if old not in text:
        return text
    return text.replace(old, new, 1)


def _inject_before(text: str, marker: str, insertion: str) -> str:
    if insertion.strip() in text:
        return text
    if marker not in text:
        return text
    return text.replace(marker, insertion + marker, 1)


def _patch_columns(path: Path) -> None:
    c = path.read_text()
    if "is_real_shadow" in c:
        return
    c = _replace_once(
        c,
        "    /// Whether the memory access is a real access.\n    pub is_real: T,\n}",
        "    /// Whether the memory access is a real access.\n    pub is_real: T,\n\n    /// Shadow multiplicity used by lookup interactions.\n    pub is_real_shadow: T,\n}",
    )
    path.write_text(c)


def _patch_local_cf5_bridge_text(c: str) -> str:
    local_helper = """
const BEAK_CF5_INJECT_KIND: &str = "pico.semantic.control.ecall_argument_decomposition";

#[derive(Clone, Copy)]
struct BeakCf5MemoryBridge<F: PrimeField32> {
    addr: u32,
    initial_chunk: u32,
    final_chunk: u32,
    initial_clk: u32,
    final_clk: u32,
    alias_word: Word<F>,
    alias_limbs: [u32; 4],
}

fn beak_ecall_syscall_id(event: &CpuEvent) -> u32 {
    match event.a_record {
        Some(MemoryRecordEnum::Write(record)) => record.prev_value,
        Some(MemoryRecordEnum::Read(record)) => record.value,
        None => event.a,
    }
}

fn beak_cf5_alias_limbs<F: PrimeField32>(value: u32) -> Option<[u32; 4]> {
    if (value >> 24) >= 0x78 {
        return None;
    }
    let bytes = value.to_le_bytes();
    Some([
        bytes[0] as u32 + 256,
        if bytes[1] == 0 { F::ORDER_U32 - 1 } else { bytes[1] as u32 - 1 },
        bytes[2] as u32,
        bytes[3] as u32,
    ])
}

fn beak_cf5_alias_word<F: PrimeField32>(value: u32) -> Option<(Word<F>, [u32; 4])> {
    let alias_limbs = beak_cf5_alias_limbs::<F>(value)?;
    Some((Word(alias_limbs.map(F::from_canonical_u32)), alias_limbs))
}

fn beak_cf5_memory_bridge<F: PrimeField32>(
    input: &EmulationRecord,
    inject_step: u64,
) -> Option<BeakCf5MemoryBridge<F>> {
    for (idx, event) in input.cpu_events.iter().enumerate() {
        if event.instruction.opcode != Opcode::ECALL {
            continue;
        }
        if !(inject_step == u64::MAX
            || inject_step == idx as u64
            || inject_step == event.clk as u64
            || inject_step == 0)
        {
            continue;
        }
        if beak_ecall_syscall_id(event) != SyscallCode::HALT.syscall_id() {
            continue;
        }
        let Some(MemoryRecordEnum::Read(record)) = event.b_record else {
            continue;
        };
        let (alias_word, alias_limbs) = beak_cf5_alias_word::<F>(event.b)?;
        return Some(BeakCf5MemoryBridge {
            addr: event.instruction.op_b,
            initial_chunk: record.prev_chunk,
            final_chunk: record.chunk,
            initial_clk: record.prev_timestamp,
            final_clk: record.timestamp,
            alias_word,
            alias_limbs,
        });
    }
    None
}

fn beak_cf5_event_matches<F: PrimeField32>(
    event: &MemoryLocalEvent,
    bridge: &BeakCf5MemoryBridge<F>,
) -> bool {
    event.addr == bridge.addr
        && event.initial_mem_access.chunk == bridge.initial_chunk
        && event.initial_mem_access.timestamp == bridge.initial_clk
        && event.final_mem_access.chunk == bridge.final_chunk
        && event.final_mem_access.timestamp == bridge.final_clk
}

"""
    ts2_local_helper = """
const BEAK_TS2_INJECT_KIND: &str = "pico.semantic.memory.timestamped_load_path";

#[derive(Clone, Copy)]
struct BeakTs2MemoryPlan {
    addr: u32,
    initial_chunk: u32,
    initial_timestamp: u32,
    final_chunk: u32,
    final_timestamp: u32,
}

fn beak_ts2_aligned_addr(event: &CpuEvent) -> u32 {
    let memory_addr = event.b.wrapping_add(event.c);
    memory_addr - memory_addr % WORD_SIZE as u32
}

fn beak_ts2_memory_plan(input: &EmulationRecord, inject_step: u64) -> Option<BeakTs2MemoryPlan> {
    let events = input
        .cpu_events
        .iter()
        .filter(|event| event.instruction.is_memory_instruction())
        .collect::<Vec<_>>();
    let mut first_store_by_addr = hashbrown::HashMap::<u32, usize>::new();
    let mut fallback = None;

    for (event_idx, event) in events.iter().enumerate() {
        let Some(memory_record) = event.memory_record else {
            continue;
        };
        let addr = beak_ts2_aligned_addr(event);
        match memory_record {
            MemoryRecordEnum::Write(write_record) => {
                if write_record.prev_chunk == 0 && write_record.prev_timestamp == 0 {
                    first_store_by_addr.entry(addr).or_insert(event_idx);
                }
            }
            MemoryRecordEnum::Read(read_record) => {
                let Some(&producer_event_idx) = first_store_by_addr.get(&addr) else {
                    continue;
                };
                let Some(MemoryRecordEnum::Write(write_record)) =
                    events[producer_event_idx].memory_record
                else {
                    continue;
                };
                if read_record.chunk != write_record.chunk
                    || read_record.prev_chunk != write_record.chunk
                    || read_record.prev_timestamp != write_record.timestamp
                    || read_record.timestamp >= (1 << 24) - 16
                {
                    continue;
                }
                let plan = BeakTs2MemoryPlan {
                    addr,
                    initial_chunk: write_record.prev_chunk,
                    initial_timestamp: write_record.prev_timestamp,
                    final_chunk: if write_record.chunk == 0 { 1 } else { write_record.chunk },
                    final_timestamp: read_record.timestamp,
                };
                let producer = events[producer_event_idx];
                if inject_step == u64::MAX
                    || inject_step == 0
                    || inject_step == event_idx as u64
                    || inject_step == producer_event_idx as u64
                    || inject_step == event.clk as u64
                    || inject_step == producer.clk as u64
                {
                    return Some(plan);
                }
                fallback.get_or_insert(plan);
            }
        }
    }

    fallback
}

fn beak_ts2_patched_local_event(
    event: &MemoryLocalEvent,
    plan: Option<BeakTs2MemoryPlan>,
) -> MemoryLocalEvent {
    let mut patched = event.clone();
    if let Some(plan) = plan {
        if patched.addr == plan.addr
            && patched.initial_mem_access.chunk == plan.initial_chunk
            && patched.initial_mem_access.timestamp == plan.initial_timestamp
        {
            patched.final_mem_access.chunk = plan.final_chunk;
            patched.final_mem_access.timestamp = plan.final_timestamp;
        }
    }
    patched
}

fn beak_ts2_local_event_matches(event: &MemoryLocalEvent, plan: Option<BeakTs2MemoryPlan>) -> bool {
    plan.is_some_and(|plan| {
        event.addr == plan.addr
            && event.initial_mem_access.chunk == plan.initial_chunk
            && event.initial_mem_access.timestamp == plan.initial_timestamp
    })
}

"""
    c = c.replace(
        "    chips::{\n        chips::riscv_global::event::GlobalInteractionEvent,\n        utils::{next_power_of_two, zeroed_f_vec},\n    },\n    compiler::riscv::program::Program,\n    emulator::riscv::record::EmulationRecord,\n",
        "    chips::{\n        chips::{\n            riscv_cpu::event::CpuEvent,\n            riscv_global::event::GlobalInteractionEvent,\n            riscv_memory::event::{MemoryLocalEvent, MemoryRecordEnum},\n        },\n        utils::{next_power_of_two, zeroed_f_vec},\n    },\n    compiler::{\n        riscv::{opcode::Opcode, program::Program},\n        word::Word,\n    },\n    emulator::riscv::{record::EmulationRecord, syscalls::SyscallCode},\n",
    )
    c = c.replace(
        "    primitives::consts::LOCAL_MEMORY_DATAPAR,\n",
        "    primitives::consts::{LOCAL_MEMORY_DATAPAR, WORD_SIZE},\n",
    )
    if "const BEAK_CF5_INJECT_KIND" not in c:
        c = _inject_before(
            c,
            "impl<F: PrimeField32> ChipBehavior<F> for MemoryLocalChip<F> {",
            local_helper,
        )
    if "const BEAK_TS2_INJECT_KIND" not in c:
        c = _inject_before(
            c,
            "impl<F: PrimeField32> ChipBehavior<F> for MemoryLocalChip<F> {",
            ts2_local_helper,
        )
    if "let beak_cf5_bridge = if inject_kind.as_deref() == Some(BEAK_CF5_INJECT_KIND)" not in c:
        c = c.replace(
            "        let mut injected_once = false;\n        let events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            "        let mut injected_once = false;\n        let beak_cf5_bridge = if inject_kind.as_deref() == Some(BEAK_CF5_INJECT_KIND) {\n            beak_cf5_memory_bridge::<F>(input, inject_step)\n        } else {\n            None\n        };\n        let events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            1,
        )
    if "let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND)" not in c:
        c = c.replace(
            "        let beak_cf5_bridge = if inject_kind.as_deref() == Some(BEAK_CF5_INJECT_KIND) {\n            beak_cf5_memory_bridge::<F>(input, inject_step)\n        } else {\n            None\n        };\n        let events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            "        let beak_cf5_bridge = if inject_kind.as_deref() == Some(BEAK_CF5_INJECT_KIND) {\n            beak_cf5_memory_bridge::<F>(input, inject_step)\n        } else {\n            None\n        };\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_memory_plan(input, inject_step)\n        } else {\n            None\n        };\n        let events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            1,
        )
    if "beak_ts2_patched_local_event(raw_event, beak_ts2_plan)" not in c:
        c = c.replace(
            "                    let event = &events[base_event_idx + k];\n",
            "                    let raw_event = &events[base_event_idx + k];\n                    if beak_ts2_local_event_matches(raw_event, beak_ts2_plan) {\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                        injected_once = true;\n                    }\n                    let patched_event = beak_ts2_patched_local_event(raw_event, beak_ts2_plan);\n                    let event = &patched_event;\n",
            1,
        )
    if "beak_cf5_event_matches(event, bridge)" not in c:
        c = c.replace(
            "                    cols.addr = F::from_canonical_u32(event.addr);\n",
            "                    if let Some(bridge) = beak_cf5_bridge\n                        .as_ref()\n                        .filter(|bridge| beak_cf5_event_matches(event, bridge))\n                    {\n                        cols.addr = F::from_canonical_u32(bridge.addr);\n                        cols.initial_chunk = F::from_canonical_u32(bridge.initial_chunk);\n                        cols.final_chunk = F::from_canonical_u32(bridge.final_chunk);\n                        cols.initial_clk = F::from_canonical_u32(bridge.initial_clk);\n                        cols.final_clk = F::from_canonical_u32(bridge.final_clk);\n                        cols.initial_value = bridge.alias_word.clone();\n                        cols.final_value = bridge.alias_word.clone();\n                        cols.is_real = F::ONE;\n                        cols.is_real_shadow = F::ONE;\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                        injected_once = true;\n                        continue;\n                    }\n                    cols.addr = F::from_canonical_u32(event.addr);\n",
            1,
        )
    if "fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {\n        let inject_kind = std::env::var" not in c:
        c = c.replace(
            "    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {\n        let local_mem_events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            "    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let beak_cf5_bridge = if inject_kind.as_deref() == Some(BEAK_CF5_INJECT_KIND) {\n            beak_cf5_memory_bridge::<F>(input, inject_step)\n        } else {\n            None\n        };\n        let local_mem_events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            1,
        )
    if "beak_ts2_memory_plan(input, inject_step)\n        } else {\n            None\n        };\n        let local_mem_events" not in c:
        c = c.replace(
            "        let beak_cf5_bridge = if inject_kind.as_deref() == Some(BEAK_CF5_INJECT_KIND) {\n            beak_cf5_memory_bridge::<F>(input, inject_step)\n        } else {\n            None\n        };\n        let local_mem_events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            "        let beak_cf5_bridge = if inject_kind.as_deref() == Some(BEAK_CF5_INJECT_KIND) {\n            beak_cf5_memory_bridge::<F>(input, inject_step)\n        } else {\n            None\n        };\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_memory_plan(input, inject_step)\n        } else {\n            None\n        };\n        let local_mem_events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            1,
        )
    c = c.replace("        let global_events: Vec<_> = local_mem_events\n", "        let mut global_events: Vec<_> = local_mem_events\n", 1)
    if "let alias_bridge = beak_cf5_bridge" not in c:
        c = c.replace(
            "                            let event = events[k];\n",
            "                            let event = events[k];\n                            let alias_bridge = beak_cf5_bridge\n                                .as_ref()\n                                .filter(|bridge| beak_cf5_event_matches(event, bridge));\n                            let initial_value = event.initial_mem_access.value;\n                            let final_value = event.final_mem_access.value;\n                            let initial_limbs = alias_bridge.map_or(\n                                [\n                                    initial_value & 255,\n                                    (initial_value >> 8) & 255,\n                                    (initial_value >> 16) & 255,\n                                    (initial_value >> 24) & 255,\n                                ],\n                                |bridge| bridge.alias_limbs,\n                            );\n                            let final_limbs = alias_bridge.map_or(\n                                [\n                                    final_value & 255,\n                                    (final_value >> 8) & 255,\n                                    (final_value >> 16) & 255,\n                                    (final_value >> 24) & 255,\n                                ],\n                                |bridge| bridge.alias_limbs,\n                            );\n",
            1,
        )
        c = c.replace(
            "                                    event.initial_mem_access.value & 255,\n                                    (event.initial_mem_access.value >> 8) & 255,\n                                    (event.initial_mem_access.value >> 16) & 255,\n                                    (event.initial_mem_access.value >> 24) & 255,\n",
            "                                    initial_limbs[0],\n                                    initial_limbs[1],\n                                    initial_limbs[2],\n                                    initial_limbs[3],\n",
            1,
        )
        c = c.replace(
            "                                    event.final_mem_access.value & 255,\n                                    (event.final_mem_access.value >> 8) & 255,\n                                    (event.final_mem_access.value >> 16) & 255,\n                                    (event.final_mem_access.value >> 24) & 255,\n",
            "                                    final_limbs[0],\n                                    final_limbs[1],\n                                    final_limbs[2],\n                                    final_limbs[3],\n",
            1,
        )
    if "for raw_event in local_mem_events" in c and "let patched_event = beak_ts2_patched_local_event(raw_event, beak_ts2_plan);" not in c:
        c = c.replace(
            "        for raw_event in local_mem_events {\n",
            "        for raw_event in local_mem_events {\n            if beak_ts2_local_event_matches(raw_event, beak_ts2_plan) {\n                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n            }\n            let patched_event = beak_ts2_patched_local_event(raw_event, beak_ts2_plan);\n            let event = &patched_event;\n",
            1,
        )
    if "for raw_event in local_mem_events" in c:
        c = c.replace("            let event = &raw_event;\n", "", 1)
    if "extra.cpu_local_memory_access.push(beak_cf5_marker_event(bridge));" in c:
        c = c.replace(
            "        if let Some(bridge) = beak_cf5_bridge {\n            extra.cpu_local_memory_access.push(beak_cf5_marker_event(bridge));\n            global_events.push(beak_cf5_global_event(bridge, true));\n            global_events.push(beak_cf5_global_event(bridge, false));\n        }\n\n        extra.global_lookup_events.extend(global_events);\n",
            "        extra.global_lookup_events.extend(global_events);\n",
            1,
        )
    return c


def _patch_local_traces(path: Path) -> None:
    c = path.read_text()
    if "BEAK_PICO_WITNESS_INJECT_KIND" in c:
        c = c.replace(
            "cols.is_real = F::from_canonical_u32(2);",
            "cols.is_real_shadow = F::from_canonical_u32(2);",
        )
        if "BEAK_PICO_WITNESS_INJECTION_APPLIED" not in c:
            c = c.replace(
                "cols.is_real_shadow = F::from_canonical_u32(2);\n                        injected_once = true;",
                "cols.is_real_shadow = F::from_canonical_u32(2);\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                        injected_once = true;",
            )
        c = _patch_local_cf5_bridge_text(c)
        path.write_text(c)
        return
    c = _replace_once(
        c,
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        _output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let events = input.get_local_mem_events().collect::<Vec<_>>();\n",
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        _output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let events = input.get_local_mem_events().collect::<Vec<_>>();\n",
    )
    c = _replace_once(
        c,
        "        // Parallelize the main computation using par_chunks_mut\n        values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]\n            .par_chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS)\n            .enumerate()\n            .for_each(|(row_idx, row)| {\n                let base_event_idx = row_idx * LOCAL_MEMORY_DATAPAR;\n                let cols: &mut MemoryLocalCols<F> = row.borrow_mut();\n\n                for k in 0..LOCAL_MEMORY_DATAPAR {\n                    let cols = &mut cols.memory_local_entries[k];\n                    if base_event_idx + k < events.len() {\n                        let event = &events[base_event_idx + k];\n                        cols.addr = F::from_canonical_u32(event.addr);\n                        cols.initial_chunk = F::from_canonical_u32(event.initial_mem_access.chunk);\n                        cols.final_chunk = F::from_canonical_u32(event.final_mem_access.chunk);\n                        cols.initial_clk =\n                            F::from_canonical_u32(event.initial_mem_access.timestamp);\n                        cols.final_clk = F::from_canonical_u32(event.final_mem_access.timestamp);\n                        cols.initial_value = event.initial_mem_access.value.into();\n                        cols.final_value = event.final_mem_access.value.into();\n                        cols.is_real = F::ONE;\n                    }\n                }\n            });\n",
        "        for (row_idx, row) in values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]\n            .chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS)\n            .enumerate()\n        {\n            let base_event_idx = row_idx * LOCAL_MEMORY_DATAPAR;\n            let cols: &mut MemoryLocalCols<F> = row.borrow_mut();\n\n            for k in 0..LOCAL_MEMORY_DATAPAR {\n                let cols = &mut cols.memory_local_entries[k];\n                if base_event_idx + k < events.len() {\n                    let event_idx = (base_event_idx + k) as u64;\n                    let event = &events[base_event_idx + k];\n                    cols.addr = F::from_canonical_u32(event.addr);\n                    cols.initial_chunk = F::from_canonical_u32(event.initial_mem_access.chunk);\n                    cols.final_chunk = F::from_canonical_u32(event.final_mem_access.chunk);\n                    cols.initial_clk = F::from_canonical_u32(event.initial_mem_access.timestamp);\n                    cols.final_clk = F::from_canonical_u32(event.final_mem_access.timestamp);\n                    cols.initial_value = event.initial_mem_access.value.into();\n                    cols.final_value = event.final_mem_access.value.into();\n                    cols.is_real = F::ONE;\n                    cols.is_real_shadow = F::ONE;\n\n                    if inject_kind.as_deref() == Some(\"pico.semantic.lookup.boolean_multiplicity\")\n                        && (inject_step == u64::MAX\n                            || inject_step == event_idx\n                            || (inject_step == 0 && !injected_once))\n                    {\n                        cols.is_real_shadow = F::from_canonical_u32(2);\n                        injected_once = true;\n                    }\n                }\n            }\n        }\n",
    )
    c = c.replace(
        "cols.is_real_shadow = F::from_canonical_u32(2);\n                        injected_once = true;",
        "cols.is_real_shadow = F::from_canonical_u32(2);\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                        injected_once = true;",
    )
    c = _patch_local_cf5_bridge_text(c)
    path.write_text(c)


def _patch_local_constraints(path: Path) -> None:
    c = path.read_text()
    if "beak_shadow_mult" in c:
        return
    c = _replace_once(
        c,
        "        for local in local.memory_local_entries.iter() {\n            builder.assert_eq(\n                local.is_real * local.is_real * local.is_real,\n                local.is_real * local.is_real * local.is_real,\n            );\n",
        "        for local in local.memory_local_entries.iter() {\n            let beak_shadow_mult: CB::Expr = local.is_real_shadow.into();\n\n            builder.assert_eq(\n                local.is_real * local.is_real * local.is_real,\n                local.is_real * local.is_real * local.is_real,\n            );\n            builder.assert_bool(local.is_real_shadow);\n",
    )
    c = _replace_once(c, "                local.is_real.into(),", "                beak_shadow_mult.clone(),")
    c = _replace_once(c, "                local.is_real.into(),", "                beak_shadow_mult.clone(),")
    c = _replace_once(c, "                local.is_real.into(),", "                beak_shadow_mult.clone(),")
    c = _replace_once(c, "                local.is_real.into(),", "                beak_shadow_mult,")
    path.write_text(c)


def _patch_rw_traces(path: Path, *, narrow_45e_types: bool = False) -> None:
    c = path.read_text()
    if narrow_45e_types:
        # Pico 45e stores CpuEvent operands/clocks and memory event addresses as
        # u32.  The newer 22b0 snapshot widened these fields to u64 and uses the
        # WORD_BYTE_SIZE name, so keep the generated helper commit-aware.
        c = c.replace(
            "    (memory_addr - memory_addr % WORD_BYTE_SIZE as u64) as u32\n",
            "    memory_addr - memory_addr % WORD_SIZE as u32\n",
        )
        c = c.replace(
            "        event.clk = plan.high_timestamp as u64;\n",
            "        event.clk = plan.high_timestamp;\n",
        )
    else:
        c = c.replace(
            "    memory_addr - memory_addr % WORD_SIZE as u32\n",
            "    (memory_addr - memory_addr % WORD_BYTE_SIZE as u64) as u32\n",
        )
        c = c.replace(
            "        event.clk = plan.high_timestamp;\n",
            "        event.clk = plan.high_timestamp as u64;\n",
        )
    c = c.replace(
        "    iter::{IndexedPicoIterator, IntoPicoRefIterator, PicoIterator, PicoSlice, PicoSliceMut},\n",
        "    iter::{IntoPicoRefIterator, PicoIterator, PicoSlice},\n",
    )
    rw_helper = """
fn flip_read_write_selector_pair<F: Field>(cols: &mut MemoryChipValueCols<F>) -> bool {
    if cols.instruction.is_lw == F::ONE {
        cols.instruction.is_lw = F::ZERO;
        cols.instruction.is_sw = F::ONE;
        true
    } else if cols.instruction.is_sw == F::ONE {
        cols.instruction.is_sw = F::ZERO;
        cols.instruction.is_lw = F::ONE;
        true
    } else if cols.instruction.is_lb == F::ONE {
        cols.instruction.is_lb = F::ZERO;
        cols.instruction.is_sb = F::ONE;
        true
    } else if cols.instruction.is_lbu == F::ONE {
        cols.instruction.is_lbu = F::ZERO;
        cols.instruction.is_sb = F::ONE;
        true
    } else if cols.instruction.is_lh == F::ONE {
        cols.instruction.is_lh = F::ZERO;
        cols.instruction.is_sh = F::ONE;
        true
    } else if cols.instruction.is_lhu == F::ONE {
        cols.instruction.is_lhu = F::ZERO;
        cols.instruction.is_sh = F::ONE;
        true
    } else if cols.instruction.is_sb == F::ONE {
        cols.instruction.is_sb = F::ZERO;
        cols.instruction.is_lb = F::ONE;
        true
    } else if cols.instruction.is_sh == F::ONE {
        cols.instruction.is_sh = F::ZERO;
        cols.instruction.is_lh = F::ONE;
        true
    } else {
        false
    }
}

fn disable_non_x0_load_value_binding<F: Field>(cols: &mut MemoryChipValueCols<F>) -> bool {
    let is_load = cols.instruction.is_lb == F::ONE
        || cols.instruction.is_lbu == F::ONE
        || cols.instruction.is_lh == F::ONE
        || cols.instruction.is_lhu == F::ONE
        || cols.instruction.is_lw == F::ONE;

    if !is_load || cols.instruction.op_a_0 == F::ONE {
        return false;
    }

    cols.instruction.op_a_0 = F::ONE;
    cols.mem_value_is_pos_not_x0 = F::ZERO;
    cols.mem_value_is_neg_not_x0 = F::ZERO;
    true
}

"""
    ts2_helper = """
const BEAK_TS2_INJECT_KIND: &str = "pico.semantic.memory.timestamped_load_path";
const BEAK_TS2_HIGH_TIMESTAMP: u32 = 2_013_265_921 - 16;

#[derive(Clone, Copy)]
struct BeakTs2ChainPlan {
    producer_event_idx: usize,
    consumer_event_idx: usize,
    chain_chunk: u32,
    final_timestamp: u32,
    high_timestamp: u32,
}

impl BeakTs2ChainPlan {
    fn involves(self, event_idx: usize) -> bool {
        event_idx == self.producer_event_idx || event_idx == self.consumer_event_idx
    }

    fn is_consumer(self, event_idx: usize) -> bool {
        event_idx == self.consumer_event_idx
    }

    fn final_timestamp(self) -> u32 {
        self.final_timestamp
    }
}

fn beak_ts2_aligned_addr(event: &CpuEvent) -> u32 {
    let memory_addr = event.b.wrapping_add(event.c);
    (memory_addr - memory_addr % WORD_BYTE_SIZE as u64) as u32
}

fn beak_ts2_chain_plan(events: &[&CpuEvent], inject_step: u64) -> Option<BeakTs2ChainPlan> {
    let mut first_store_by_addr = HashMap::<u32, usize>::new();
    let mut fallback = None;

    for (event_idx, event) in events.iter().enumerate() {
        let Some(memory_record) = event.memory_record else {
            continue;
        };
        let addr = beak_ts2_aligned_addr(event);
        match memory_record {
            MemoryRecordEnum::Write(write_record) => {
                if write_record.prev_chunk == 0 && write_record.prev_timestamp == 0 {
                    first_store_by_addr.entry(addr).or_insert(event_idx);
                }
            }
            MemoryRecordEnum::Read(read_record) => {
                let Some(&producer_event_idx) = first_store_by_addr.get(&addr) else {
                    continue;
                };
                let Some(MemoryRecordEnum::Write(write_record)) =
                    events[producer_event_idx].memory_record
                else {
                    continue;
                };
                if read_record.chunk != write_record.chunk
                    || read_record.prev_chunk != write_record.chunk
                    || read_record.prev_timestamp != write_record.timestamp
                    || read_record.timestamp >= (1 << 24) - 16
                {
                    continue;
                }
                let plan = BeakTs2ChainPlan {
                    producer_event_idx,
                    consumer_event_idx: event_idx,
                    chain_chunk: if write_record.chunk == 0 { 1 } else { write_record.chunk },
                    final_timestamp: read_record.timestamp,
                    high_timestamp: BEAK_TS2_HIGH_TIMESTAMP,
                };
                let producer = events[producer_event_idx];
                if inject_step == u64::MAX
                    || inject_step == 0
                    || inject_step == event_idx as u64
                    || inject_step == producer_event_idx as u64
                    || inject_step == event.clk as u64
                    || inject_step == producer.clk as u64
                {
                    return Some(plan);
                }
                fallback.get_or_insert(plan);
            }
        }
    }

    fallback
}

fn beak_ts2_patched_event(
    mut event: CpuEvent,
    event_idx: usize,
    plan: Option<BeakTs2ChainPlan>,
) -> CpuEvent {
    let Some(plan) = plan else {
        return event;
    };
    if event_idx == plan.producer_event_idx {
        event.chunk = plan.chain_chunk;
        event.clk = plan.high_timestamp as u64;
        if let Some(MemoryRecordEnum::Write(mut record)) = event.memory_record {
            record.chunk = plan.chain_chunk;
            record.timestamp = plan.high_timestamp;
            record.prev_chunk = 0;
            record.prev_timestamp = 0;
            event.memory_record = Some(MemoryRecordEnum::Write(record));
        }
    } else if event_idx == plan.consumer_event_idx {
        event.chunk = plan.chain_chunk;
        if let Some(MemoryRecordEnum::Read(mut record)) = event.memory_record {
            record.chunk = plan.chain_chunk;
            record.prev_chunk = plan.chain_chunk;
            record.prev_timestamp = plan.high_timestamp;
            event.memory_record = Some(MemoryRecordEnum::Read(record));
        }
    }
    event
}

fn beak_ts2_field_diff_minus_one(current_timestamp: u32, high_timestamp: u32) -> u32 {
    let p = 2_013_265_921u64;
    ((p + current_timestamp as u64 - high_timestamp as u64 - 1) % p) as u32
}

fn beak_ts2_fix_consumer_diff_cols<F: PrimeField32>(
    cols: &mut MemoryChipValueCols<F>,
    event_idx: usize,
    plan: Option<BeakTs2ChainPlan>,
) {
    let Some(plan) = plan else {
        return;
    };
    if !plan.is_consumer(event_idx) {
        return;
    }
    let diff_minus_one =
        beak_ts2_field_diff_minus_one(plan.final_timestamp(), plan.high_timestamp);
    cols.memory_access.access.diff_16bit_limb =
        F::from_canonical_u16((diff_minus_one & 0xffff) as u16);
    cols.memory_access.access.diff_8bit_limb =
        F::from_canonical_u32((diff_minus_one >> 16) & 0xff);
}

fn beak_ts2_u16_range_event(value: u16) -> ByteLookupEvent {
    ByteLookupEvent::new(
        ByteOpcode::U16Range,
        0,
        0,
        (value >> 8) as u8,
        (value & u8::MAX as u16) as u8,
    )
}

fn beak_ts2_u8_range_event(value: u8) -> ByteLookupEvent {
    ByteLookupEvent::new(ByteOpcode::U8Range, 0, 0, value, 0)
}

fn beak_ts2_remove_one_event(events: &mut Vec<ByteLookupEvent>, target: ByteLookupEvent) {
    if let Some(pos) = events.iter().position(|event| *event == target) {
        events.remove(pos);
    }
}

fn beak_ts2_add_consumer_range_events(
    output: &mut impl ByteRecordBehavior,
    mut row_events: Vec<ByteLookupEvent>,
    event_idx: usize,
    plan: Option<BeakTs2ChainPlan>,
) {
    let Some(plan) = plan else {
        output.add_byte_lookup_events(row_events);
        return;
    };
    if !plan.is_consumer(event_idx) {
        output.add_byte_lookup_events(row_events);
        return;
    }
    let old_diff_minus_one = plan
        .final_timestamp()
        .wrapping_sub(plan.high_timestamp)
        .wrapping_sub(1);
    beak_ts2_remove_one_event(
        &mut row_events,
        beak_ts2_u16_range_event((old_diff_minus_one & 0xffff) as u16),
    );
    beak_ts2_remove_one_event(
        &mut row_events,
        beak_ts2_u8_range_event(((old_diff_minus_one >> 16) & 0xff) as u8),
    );
    output.add_byte_lookup_events(row_events);
    let diff_minus_one =
        beak_ts2_field_diff_minus_one(plan.final_timestamp(), plan.high_timestamp);
    output.add_u16_range_check((diff_minus_one & 0xffff) as u16);
    output.add_u8_range_check(((diff_minus_one >> 16) & 0xff) as u8, 0);
}

"""
    if narrow_45e_types:
        ts2_helper = ts2_helper.replace(
            "    (memory_addr - memory_addr % WORD_BYTE_SIZE as u64) as u32\n",
            "    memory_addr - memory_addr % WORD_SIZE as u32\n",
        ).replace(
            "        event.clk = plan.high_timestamp as u64;\n",
            "        event.clk = plan.high_timestamp;\n",
        )
    memory_hook = """
            // BEAK-INSERT pico semantic memory rw hooks
            if !injected_once
                && (inject_step == u64::MAX
                    || inject_step == (event.clk as u64 / 4)
                    || (inject_step == 0 && !injected_once))
            {
                let mut beak_applied = false;
                match inject_kind.as_deref() {
                    Some("pico.semantic.memory.address_alignment_consistency")
                    | Some("pico.semantic.memory.address_progression_consistency")
                    | Some("pico.semantic.memory.address_boundary_range") => {
                        cols.addr_word[0] = cols.addr_word[0] + F::ONE;
                        beak_applied = true;
                    }
                    Some("pico.semantic.memory.load_value_binding")
                    | Some("pico.semantic.memory.write_payload_consistency")
                    | Some("pico.semantic.memory.store_load_payload_flow") => {
                        cols.memory_access.access.value[0] =
                            cols.memory_access.access.value[0] + F::ONE;
                        beak_applied = true;
                    }
                    Some("pico.semantic.memory.kind_selector_consistency") => {
                        beak_applied = flip_read_write_selector_pair(cols);
                    }
                    Some("pico.semantic.exec.op_selector_binding.read_write") => {
                        beak_applied = disable_non_x0_load_value_binding(cols);
                        if beak_applied {
                            std::env::set_var(
                                "BEAK_PICO_OPCODE_SELECTOR_MUTATION_STEP",
                                (event.clk as u64 / 4).to_string(),
                            );
                            std::env::set_var(
                                "BEAK_PICO_OPCODE_SELECTOR_MEMORY_EVENT_INDEX",
                                event_idx.to_string(),
                            );
                            std::env::set_var("BEAK_PICO_OPCODE_SELECTOR_BEFORE", "0");
                            std::env::set_var("BEAK_PICO_OPCODE_SELECTOR_AFTER", "1");
                        }
                    }
                    _ => {}
                }
                if beak_applied {
                    std::env::set_var("BEAK_PICO_WITNESS_INJECTION_APPLIED", "1");
                    injected_once = true;
                }
            }
"""
    c = c.replace(
        "    IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator, ParallelSlice,\n",
        "    IntoParallelRefIterator, ParallelIterator,\n",
    )
    c = c.replace(
        "use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator, ParallelSlice};\n",
        "use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator};\n",
    )
    c = c.replace("use rayon::slice::ParallelSliceMut;\n", "")
    c = _inject_before(
        c,
        "impl<F: PrimeField32> ChipBehavior<F> for MemoryReadWriteChip<F> {",
        rw_helper,
    )
    if "const BEAK_TS2_INJECT_KIND" not in c:
        c = _inject_before(
            c,
            "impl<F: PrimeField32> ChipBehavior<F> for MemoryReadWriteChip<F> {",
            ts2_helper,
        )
    c = c.replace(
        'Some("pico.semantic.exec.op_selector_binding.read_write") => {\n'
        "                        beak_applied = flip_read_write_selector_pair(cols);\n"
        "                    }",
        'Some("pico.semantic.exec.op_selector_binding.read_write") => {\n'
        "                        beak_applied = disable_non_x0_load_value_binding(cols);\n"
        "                        if beak_applied {\n"
        "                            std::env::set_var(\n"
        '                                "BEAK_PICO_OPCODE_SELECTOR_MUTATION_STEP",\n'
        "                                (event.clk as u64 / 4).to_string(),\n"
        "                            );\n"
        "                            std::env::set_var(\n"
        '                                "BEAK_PICO_OPCODE_SELECTOR_MEMORY_EVENT_INDEX",\n'
        "                                event_idx.to_string(),\n"
        "                            );\n"
        '                            std::env::set_var("BEAK_PICO_OPCODE_SELECTOR_BEFORE", "0");\n'
        '                            std::env::set_var("BEAK_PICO_OPCODE_SELECTOR_AFTER", "1");\n'
        "                        }\n"
        "                    }",
    )
    c = _replace_once(
        c,
        "    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {\n        // We only care about the CPU events of memory instructions.\n        let mem_events = input\n            .cpu_events\n            .iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect_vec();\n        // Generate the trace rows for each event.\n        let chunk_size = std::cmp::max(mem_events.len() / num_cpus::get(), 1);\n        let (alu_events, blu_events): (Vec<_>, Vec<_>) = mem_events\n            .par_chunks(chunk_size)\n            .map(|ops: &[&CpuEvent]| {\n                let mut alu = HashMap::new();\n                // The range map stores range (u8) lookup event -> multiplicity.\n                let mut blu = vec![];\n                ops.iter().for_each(|op| {\n                    let mut row = [F::ZERO; NUM_MEMORY_CHIP_VALUE_COLS];\n                    let cols: &mut MemoryChipValueCols<F> = row.as_mut_slice().borrow_mut();\n                    let alu_events = self.event_to_row(op, cols, &mut blu);\n                    alu_events.into_iter().for_each(|(key, value)| {\n                        alu.entry(key).or_insert(Vec::default()).extend(value);\n                    });\n                });\n                (alu, blu)\n            })\n            .unzip();\n        for alu_events_chunk in alu_events {\n            extra.add_alu_events(alu_events_chunk);\n        }\n        for blu_events_chunk in blu_events {\n            extra.add_byte_lookup_events(blu_events_chunk);\n        }\n    }\n",
        "    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n\n        // We only care about the CPU events of memory instructions.\n        let mem_events = input\n            .cpu_events\n            .iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect_vec();\n        // Generate the trace rows for each event.\n        let mut alu_events = HashMap::new();\n        // The range map stores range (u8) lookup event -> multiplicity.\n        let mut blu_events = vec![];\n        for (event_idx, op) in mem_events.iter().enumerate() {\n            let mut row = [F::ZERO; NUM_MEMORY_CHIP_VALUE_COLS];\n            let cols: &mut MemoryChipValueCols<F> = row.as_mut_slice().borrow_mut();\n            let mut row_alu_events = self.event_to_row(op, cols, &mut blu_events);\n\n            if !injected_once\n                && inject_kind.as_deref()\n                    == Some(\"pico.semantic.exec.op_selector_binding.read_write\")\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || inject_step == op.clk as u64\n                    || (inject_step == 0 && !injected_once))\n                && disable_non_x0_load_value_binding(cols)\n            {\n                row_alu_events.remove(&Opcode::SUB);\n                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                injected_once = true;\n            }\n\n            row_alu_events.into_iter().for_each(|(key, value)| {\n                alu_events.entry(key).or_insert(Vec::default()).extend(value);\n            });\n        }\n        extra.add_alu_events(alu_events);\n        extra.add_byte_lookup_events(blu_events);\n    }\n",
    )
    if "beak_ts2_chain_plan(&mem_events" not in c:
        c = _replace_once(
            c,
            "        let mem_events = input\n            .cpu_events\n            .iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect_vec();\n        // Generate the trace rows for each event.\n",
            "        let mem_events = input\n            .cpu_events\n            .iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect_vec();\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_chain_plan(&mem_events, inject_step)\n        } else {\n            None\n        };\n        // Generate the trace rows for each event.\n",
        )
        c = _replace_once(
            c,
            "            let mut row_alu_events = self.event_to_row(op, cols, &mut blu_events);\n",
            "            let patched = beak_ts2_patched_event(**op, event_idx, beak_ts2_plan);\n            if beak_ts2_plan.is_some_and(|plan| plan.involves(event_idx)) {\n                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                injected_once = true;\n            }\n            let mut row_blu_events = vec![];\n            let mut row_alu_events = self.event_to_row(&patched, cols, &mut row_blu_events);\n            beak_ts2_fix_consumer_diff_cols(cols, event_idx, beak_ts2_plan);\n            beak_ts2_add_consumer_range_events(\n                &mut blu_events,\n                row_blu_events,\n                event_idx,\n                beak_ts2_plan,\n            );\n",
        )
    if "let mut patched = **event;" in c or "beak_ts2_chain_plan(&events" in c:
        if "beak_ts2_chain_plan(&events" not in c:
            c = _replace_once(
                c,
                "        let events: Vec<_> = input\n            .cpu_events\n            .par_iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect();\n",
                "        let events: Vec<_> = input\n            .cpu_events\n            .par_iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect();\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_chain_plan(&events, inject_step)\n        } else {\n            None\n        };\n",
            )
            c = c.replace(
                "            let mut patched = **event;\n            if inject_kind.as_deref() == Some(\"pico.semantic.memory.timestamped_load_path\")\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                if let Some(mut mr) = patched.memory_record {\n                    match &mut mr {\n                        MemoryRecordEnum::Read(r) => {\n                            r.prev_chunk = r.chunk;\n                            r.prev_timestamp = BABYBEAR_P - 16;\n                        }\n                        MemoryRecordEnum::Write(w) => {\n                            w.prev_chunk = w.chunk;\n                            w.prev_timestamp = BABYBEAR_P - 16;\n                        }\n                    }\n                    patched.memory_record = Some(mr);\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;\n                }\n            }\n",
                "            let patched = beak_ts2_patched_event(**event, event_idx, beak_ts2_plan);\n            if beak_ts2_plan.is_some_and(|plan| plan.involves(event_idx)) {\n                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                injected_once = true;\n            }\n",
            )
            c = c.replace(
                "            self.event_to_row(&patched, cols, &mut vec![]);\n",
                "            self.event_to_row(&patched, cols, &mut vec![]);\n            beak_ts2_fix_consumer_diff_cols(cols, event_idx, beak_ts2_plan);\n",
                1,
            )
        if "beak_ts2_chain_plan(&mem_events" not in c:
            c = _replace_once(
                c,
                "        let mem_events = input\n            .cpu_events\n            .iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect_vec();\n        // Generate the trace rows for each event.\n",
                "        let mem_events = input\n            .cpu_events\n            .iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect_vec();\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_chain_plan(&mem_events, inject_step)\n        } else {\n            None\n        };\n        // Generate the trace rows for each event.\n",
            )
            c = _replace_once(
                c,
                "            let mut row_alu_events = self.event_to_row(op, cols, &mut blu_events);\n",
                "            let patched = beak_ts2_patched_event(**op, event_idx, beak_ts2_plan);\n            if beak_ts2_plan.is_some_and(|plan| plan.involves(event_idx)) {\n                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                injected_once = true;\n            }\n            let mut row_blu_events = vec![];\n            let mut row_alu_events = self.event_to_row(&patched, cols, &mut row_blu_events);\n            beak_ts2_fix_consumer_diff_cols(cols, event_idx, beak_ts2_plan);\n            beak_ts2_add_consumer_range_events(\n                &mut blu_events,\n                row_blu_events,\n                event_idx,\n                beak_ts2_plan,\n            );\n",
            )
        if "BEAK_PICO_WITNESS_INJECTION_APPLIED" not in c:
            c = c.replace(
                "patched.memory_record = Some(mr);\n                    injected_once = true;",
                "patched.memory_record = Some(mr);\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;",
            )
        c = _inject_before(c, "        }\n\n        RowMajorMatrix::new(values, NUM_MEMORY_CHIP_COLS)", memory_hook)
        path.write_text(c)
        return
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        // Parallelize the initial filtering and collection\n",
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        // Parallelize the initial filtering and collection\n",
    )
    c = _replace_once(
        c,
        "        let events: Vec<_> = input\n            .cpu_events\n            .par_iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect();\n",
        "        let events: Vec<_> = input\n            .cpu_events\n            .par_iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect();\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_chain_plan(&events, inject_step)\n        } else {\n            None\n        };\n",
    )
    c = _replace_once(
        c,
        "        let events: Vec<_> = input\n            .cpu_events\n            .pico_iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect();\n",
        "        let events: Vec<_> = input\n            .cpu_events\n            .pico_iter()\n            .filter(|e| e.instruction.is_memory_instruction())\n            .collect();\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_chain_plan(&events, inject_step)\n        } else {\n            None\n        };\n",
    )
    c = _replace_once(
        c,
        "        // Use rayon's parallel slice operations for better chunk handling\n        values[..populate_len]\n            .par_chunks_mut(NUM_MEMORY_CHIP_VALUE_COLS)\n            .zip_eq(events.par_iter())\n            .for_each(|(row, event)| {\n                let cols: &mut MemoryChipValueCols<_> = row.borrow_mut();\n                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "        for (event_idx, (row, event)) in values[..populate_len]\n            .chunks_mut(NUM_MEMORY_CHIP_VALUE_COLS)\n            .zip(events.iter())\n            .enumerate()\n        {\n            let patched = beak_ts2_patched_event(**event, event_idx, beak_ts2_plan);\n            if beak_ts2_plan.is_some_and(|plan| plan.involves(event_idx)) {\n                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                injected_once = true;\n            }\n            let cols: &mut MemoryChipValueCols<_> = row.borrow_mut();\n            self.event_to_row(&patched, cols, &mut vec![]);\n            beak_ts2_fix_consumer_diff_cols(cols, event_idx, beak_ts2_plan);\n        }\n",
    )
    c = _replace_once(
        c,
        "        // Use rayon's parallel slice operations for better chunk handling\n        values[..populate_len]\n            .pico_chunks_mut(NUM_MEMORY_CHIP_VALUE_COLS)\n            .zip_eq(events.pico_iter())\n            .for_each(|(row, event)| {\n                let cols: &mut MemoryChipValueCols<_> = row.borrow_mut();\n                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "        for (event_idx, (row, event)) in values[..populate_len]\n            .chunks_mut(NUM_MEMORY_CHIP_VALUE_COLS)\n            .zip(events.iter())\n            .enumerate()\n        {\n            let patched = beak_ts2_patched_event(**event, event_idx, beak_ts2_plan);\n            if beak_ts2_plan.is_some_and(|plan| plan.involves(event_idx)) {\n                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                injected_once = true;\n            }\n            let cols: &mut MemoryChipValueCols<_> = row.borrow_mut();\n            self.event_to_row(&patched, cols, &mut vec![]);\n            beak_ts2_fix_consumer_diff_cols(cols, event_idx, beak_ts2_plan);\n        }\n",
    )
    c = c.replace(
        "patched.memory_record = Some(mr);\n                    injected_once = true;",
        "patched.memory_record = Some(mr);\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;",
    )
    c = _inject_before(c, "        }\n\n        RowMajorMatrix::new(values, NUM_MEMORY_CHIP_COLS)", memory_hook)
    path.write_text(c)


def _patch_init_final_traces(path: Path, *, narrow_45e_types: bool = False) -> None:
    c = path.read_text()
    ts2_helper = """
const BEAK_TS2_INJECT_KIND: &str = "pico.semantic.memory.timestamped_load_path";
const WORD_SIZE_U64: u64 = 4;

#[derive(Clone, Copy)]
struct BeakTs2FinalizePlan {
    addr: u64,
    final_chunk: u32,
    final_timestamp: u32,
}

fn beak_ts2_aligned_addr(event: &CpuEvent) -> u64 {
    let memory_addr = event.b.wrapping_add(event.c);
    memory_addr - memory_addr % WORD_SIZE_U64
}

fn beak_ts2_finalize_plan(
    input: &EmulationRecord,
    inject_step: u64,
) -> Option<BeakTs2FinalizePlan> {
    let events = input
        .cpu_events
        .iter()
        .filter(|event| event.instruction.is_memory_instruction())
        .collect::<Vec<_>>();
    let mut first_store_by_addr = hashbrown::HashMap::<u64, usize>::new();
    let mut fallback = None;

    for (event_idx, event) in events.iter().enumerate() {
        let Some(memory_record) = event.memory_record else {
            continue;
        };
        let addr = beak_ts2_aligned_addr(event);
        match memory_record {
            MemoryRecordEnum::Write(write_record) => {
                if write_record.prev_chunk == 0 && write_record.prev_timestamp == 0 {
                    first_store_by_addr.entry(addr).or_insert(event_idx);
                }
            }
            MemoryRecordEnum::Read(read_record) => {
                let Some(&producer_event_idx) = first_store_by_addr.get(&addr) else {
                    continue;
                };
                let Some(MemoryRecordEnum::Write(write_record)) =
                    events[producer_event_idx].memory_record
                else {
                    continue;
                };
                if read_record.chunk != write_record.chunk
                    || read_record.prev_chunk != write_record.chunk
                    || read_record.prev_timestamp != write_record.timestamp
                    || read_record.timestamp >= (1 << 24) - 16
                {
                    continue;
                }
                let plan = BeakTs2FinalizePlan {
                    addr,
                    final_chunk: if write_record.chunk == 0 { 1 } else { write_record.chunk },
                    final_timestamp: read_record.timestamp,
                };
                let producer = events[producer_event_idx];
                if inject_step == u64::MAX
                    || inject_step == 0
                    || inject_step == event_idx as u64
                    || inject_step == producer_event_idx as u64
                    || inject_step == event.clk as u64
                    || inject_step == producer.clk as u64
                {
                    return Some(plan);
                }
                fallback.get_or_insert(plan);
            }
        }
    }

    fallback
}

fn beak_ts2_patched_finalize_event(
    mut event: MemoryInitializeFinalizeEvent,
    kind: MemoryChipType,
    plan: Option<BeakTs2FinalizePlan>,
) -> MemoryInitializeFinalizeEvent {
    if kind == MemoryChipType::Finalize {
        if let Some(plan) = plan {
            if event.addr == plan.addr {
                event.chunk = plan.final_chunk;
                event.timestamp = plan.final_timestamp;
            }
        }
    }
    event
}

fn beak_ts2_finalize_event_matches(
    event: &MemoryInitializeFinalizeEvent,
    kind: MemoryChipType,
    plan: Option<BeakTs2FinalizePlan>,
) -> bool {
    kind == MemoryChipType::Finalize && plan.is_some_and(|plan| event.addr == plan.addr)
}

"""
    if narrow_45e_types:
        narrow_replacements = {
            "const WORD_SIZE_U64: u64 = 4;": "const WORD_SIZE_U32: u32 = 4;",
            "    addr: u64,": "    addr: u32,",
            "fn beak_ts2_aligned_addr(event: &CpuEvent) -> u64 {":
                "fn beak_ts2_aligned_addr(event: &CpuEvent) -> u32 {",
            "    memory_addr - memory_addr % WORD_SIZE_U64":
                "    memory_addr - memory_addr % WORD_SIZE_U32",
            "hashbrown::HashMap::<u64, usize>": "hashbrown::HashMap::<u32, usize>",
        }
        for old, new in narrow_replacements.items():
            c = c.replace(old, new)
            ts2_helper = ts2_helper.replace(old, new)
    c = _remove_init_final_ts2_hook(c)
    c = c.replace(
        "    chips::chips::{\n        riscv_global::event::GlobalInteractionEvent,\n        riscv_memory::event::MemoryInitializeFinalizeEvent,\n    },\n",
        "    chips::chips::{\n        riscv_cpu::event::CpuEvent,\n        riscv_global::event::GlobalInteractionEvent,\n        riscv_memory::event::{MemoryInitializeFinalizeEvent, MemoryRecordEnum},\n    },\n",
    )
    c = c.replace(
        "    chips::chips::{\n        byte::event::{ByteLookupEvent, ByteRecordBehavior},\n        riscv_global::event::GlobalInteractionEvent,\n        riscv_memory::event::MemoryInitializeFinalizeEvent,\n    },\n",
        "    chips::chips::{\n        byte::event::{ByteLookupEvent, ByteRecordBehavior},\n        riscv_cpu::event::CpuEvent,\n        riscv_global::event::GlobalInteractionEvent,\n        riscv_memory::event::{MemoryInitializeFinalizeEvent, MemoryRecordEnum},\n    },\n",
    )
    if "const BEAK_TS2_INJECT_KIND" not in c:
        c = _inject_before(
            c,
            "impl<F: PrimeField32> ChipBehavior<F> for MemoryInitializeFinalizeChip<F> {",
            ts2_helper,
        )
    if "let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND)" not in c:
        c = c.replace(
            "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let mut memory_events = match self.kind {\n",
            "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_finalize_plan(input, inject_step)\n        } else {\n            None\n        };\n        let mut memory_events = match self.kind {\n",
            1,
        )
        c = c.replace(
            "    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {\n        let mut memory_events = match self.kind {\n",
            "    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_finalize_plan(input, inject_step)\n        } else {\n            None\n        };\n        let mut memory_events = match self.kind {\n",
            1,
        )
    c = _replace_once(
        c,
        "        let rows: Vec<[F; NUM_MEMORY_INITIALIZE_FINALIZE_COLS]> = (0..memory_events.len())\n            .into_par_iter()\n            .map(|i| {\n",
        "        let rows: Vec<[F; NUM_MEMORY_INITIALIZE_FINALIZE_COLS]> = (0..memory_events.len())\n            .map(|i| {\n",
    )
    if "beak_ts2_patched_finalize_event(memory_events[i].clone()" not in c:
        c = c.replace(
            "                let MemoryInitializeFinalizeEvent {\n                    addr,\n                    value,\n                    chunk,\n                    timestamp,\n                    used,\n                } = memory_events[i].clone();\n",
            "                if beak_ts2_finalize_event_matches(&memory_events[i], self.kind, beak_ts2_plan) {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                }\n                let event =\n                    beak_ts2_patched_finalize_event(memory_events[i].clone(), self.kind, beak_ts2_plan);\n                let MemoryInitializeFinalizeEvent {\n                    addr,\n                    value,\n                    chunk,\n                    timestamp,\n                    used,\n                } = event;\n",
            1,
        )
        c = c.replace(
            "                let MemoryInitializeFinalizeEvent {\n                    addr,\n                    value,\n                    chunk,\n                    timestamp,\n                    used,\n                } = memory_events[i];\n",
            "                if beak_ts2_finalize_event_matches(&memory_events[i], self.kind, beak_ts2_plan) {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                }\n                let event =\n                    beak_ts2_patched_finalize_event(memory_events[i].clone(), self.kind, beak_ts2_plan);\n                let MemoryInitializeFinalizeEvent {\n                    addr,\n                    value,\n                    chunk,\n                    timestamp,\n                    used,\n                } = event;\n",
            1,
        )
    if "beak_ts2_patched_finalize_event(event, self.kind, beak_ts2_plan)" not in c:
        c = c.replace(
            "            .map(|event| {\n                let interaction_chunk = if is_receive { event.chunk } else { 0 };\n",
            "            .map(|event| {\n                if beak_ts2_finalize_event_matches(&event, self.kind, beak_ts2_plan) {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                }\n                let event = beak_ts2_patched_finalize_event(event, self.kind, beak_ts2_plan);\n                let interaction_chunk = if is_receive { event.chunk } else { 0 };\n",
            1,
        )
        c = c.replace(
            "        for (i, event) in memory_events.iter().enumerate() {\n            let addr = event.addr;\n            let value = event.value;\n",
            "        for (i, event) in memory_events.iter().enumerate() {\n            if beak_ts2_finalize_event_matches(event, self.kind, beak_ts2_plan) {\n                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n            }\n            let event = beak_ts2_patched_finalize_event(event.clone(), self.kind, beak_ts2_plan);\n            let addr = event.addr;\n            let value = event.value;\n",
            1,
        )
    path.write_text(c)


def _patch_local_traces_22b0(path: Path) -> None:
    c = path.read_text()
    ts2_helper = """
const BEAK_TS2_INJECT_KIND: &str = "pico.semantic.memory.timestamped_load_path";
const WORD_SIZE_U64: u64 = 4;

#[derive(Clone, Copy)]
struct BeakTs2MemoryPlan {
    addr: u64,
    initial_chunk: u32,
    initial_timestamp: u32,
    final_chunk: u32,
    final_timestamp: u32,
}

fn beak_ts2_aligned_addr(event: &CpuEvent) -> u64 {
    let memory_addr = event.b.wrapping_add(event.c);
    memory_addr - memory_addr % WORD_SIZE_U64
}

fn beak_ts2_memory_plan(input: &EmulationRecord, inject_step: u64) -> Option<BeakTs2MemoryPlan> {
    let events = input
        .cpu_events
        .iter()
        .filter(|event| event.instruction.is_memory_instruction())
        .collect::<Vec<_>>();
    let mut first_store_by_addr = hashbrown::HashMap::<u64, usize>::new();
    let mut fallback = None;

    for (event_idx, event) in events.iter().enumerate() {
        let Some(memory_record) = event.memory_record else {
            continue;
        };
        let addr = beak_ts2_aligned_addr(event);
        match memory_record {
            MemoryRecordEnum::Write(write_record) => {
                if write_record.prev_chunk == 0 && write_record.prev_timestamp == 0 {
                    first_store_by_addr.entry(addr).or_insert(event_idx);
                }
            }
            MemoryRecordEnum::Read(read_record) => {
                let Some(&producer_event_idx) = first_store_by_addr.get(&addr) else {
                    continue;
                };
                let Some(MemoryRecordEnum::Write(write_record)) =
                    events[producer_event_idx].memory_record
                else {
                    continue;
                };
                if read_record.chunk != write_record.chunk
                    || read_record.prev_chunk != write_record.chunk
                    || read_record.prev_timestamp != write_record.timestamp
                    || read_record.timestamp >= (1 << 24) - 16
                {
                    continue;
                }
                let plan = BeakTs2MemoryPlan {
                    addr,
                    initial_chunk: write_record.prev_chunk,
                    initial_timestamp: write_record.prev_timestamp,
                    final_chunk: if write_record.chunk == 0 { 1 } else { write_record.chunk },
                    final_timestamp: read_record.timestamp,
                };
                let producer = events[producer_event_idx];
                if inject_step == u64::MAX
                    || inject_step == 0
                    || inject_step == event_idx as u64
                    || inject_step == producer_event_idx as u64
                    || inject_step == event.clk as u64
                    || inject_step == producer.clk as u64
                {
                    return Some(plan);
                }
                fallback.get_or_insert(plan);
            }
        }
    }

    fallback
}

fn beak_ts2_patched_local_event(
    event: &MemoryLocalEvent,
    plan: Option<BeakTs2MemoryPlan>,
) -> MemoryLocalEvent {
    let mut patched = event.clone();
    if let Some(plan) = plan {
        if patched.addr == plan.addr
            && patched.initial_mem_access.chunk == plan.initial_chunk
            && patched.initial_mem_access.timestamp == plan.initial_timestamp
        {
            patched.final_mem_access.chunk = plan.final_chunk;
            patched.final_mem_access.timestamp = plan.final_timestamp;
        }
    }
    patched
}

fn beak_ts2_local_event_matches(event: &MemoryLocalEvent, plan: Option<BeakTs2MemoryPlan>) -> bool {
    plan.is_some_and(|plan| {
        event.addr == plan.addr
            && event.initial_mem_access.chunk == plan.initial_chunk
            && event.initial_mem_access.timestamp == plan.initial_timestamp
    })
}

"""
    c = c.replace(
        "        chips::{byte::event::ByteRecordBehavior, riscv_global::event::GlobalInteractionEvent},\n",
        "        chips::{\n            byte::event::ByteRecordBehavior,\n            riscv_cpu::event::CpuEvent,\n            riscv_global::event::GlobalInteractionEvent,\n            riscv_memory::event::{MemoryLocalEvent, MemoryRecordEnum},\n        },\n",
    )
    if "const BEAK_TS2_INJECT_KIND" not in c:
        c = _inject_before(
            c,
            "impl<F: PrimeField32> ChipBehavior<F> for MemoryLocalChip<F> {",
            ts2_helper,
        )
    if "let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND)" not in c:
        c = c.replace(
            "        let events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            "        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_memory_plan(input, inject_step)\n        } else {\n            None\n        };\n        let events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            1,
        )
        c = c.replace(
            "                        let event = &events[base_event_idx + k];\n",
            "                        let raw_event = &events[base_event_idx + k];\n                        if beak_ts2_local_event_matches(raw_event, beak_ts2_plan) {\n                            std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                        }\n                        let patched_event = beak_ts2_patched_local_event(raw_event, beak_ts2_plan);\n                        let event = &patched_event;\n",
            1,
        )
        c = c.replace(
            "    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {\n        let local_mem_events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            "    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {\n            beak_ts2_memory_plan(input, inject_step)\n        } else {\n            None\n        };\n        let local_mem_events = input.get_local_mem_events().collect::<Vec<_>>();\n",
            1,
        )
        c = c.replace(
            "                            let event = events[k];\n",
            "                            let raw_event = events[k];\n                            if beak_ts2_local_event_matches(raw_event, beak_ts2_plan) {\n                                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                            }\n                            let patched_event = beak_ts2_patched_local_event(raw_event, beak_ts2_plan);\n                            let event = &patched_event;\n",
            1,
        )
    path.write_text(c)


def _patch_rw_extra_record_22b0(path: Path) -> None:
    c = path.read_text()
    if "let mut row_blu_events = vec![];" in c:
        return
    old = """    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        // We only care about the CPU events of memory instructions.
        let mem_events = input
            .cpu_events
            .iter()
            .filter(|e| e.instruction.is_memory_instruction())
            .collect::<Box<[_]>>();
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(mem_events.len() / num_cpus::get(), 1);
        let (alu_events, blu_events): (Vec<_>, Vec<_>) = mem_events
            .pico_chunks(chunk_size)
            .map(|ops: &[&CpuEvent]| {
                let mut alu = HashMap::new();
                // The range map stores range (u8) lookup event -> multiplicity.
                let mut blu = vec![];
                ops.iter().for_each(|op| {
                    let mut row = [F::ZERO; NUM_MEMORY_CHIP_VALUE_COLS];
                    let cols: &mut MemoryChipValueCols<F> = row.as_mut_slice().borrow_mut();
                    let alu_events = self.event_to_row(op, cols, &mut blu);
                    alu_events.into_iter().for_each(|(key, value)| {
                        alu.entry(key).or_insert(Vec::default()).extend(value);
                    });
                });
                (alu, blu)
            })
            .unzip();
        for alu_events_chunk in alu_events {
            extra.add_alu_events(alu_events_chunk);
        }
        for blu_events_chunk in blu_events {
            extra.add_byte_lookup_events(blu_events_chunk);
        }
    }
"""
    new = """    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let inject_kind = std::env::var("BEAK_PICO_WITNESS_INJECT_KIND").ok();
        let inject_step = std::env::var("BEAK_PICO_WITNESS_INJECT_STEP")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // We only care about the CPU events of memory instructions.
        let mem_events = input
            .cpu_events
            .iter()
            .filter(|e| e.instruction.is_memory_instruction())
            .collect::<Box<[_]>>();
        let beak_ts2_plan = if inject_kind.as_deref() == Some(BEAK_TS2_INJECT_KIND) {
            beak_ts2_chain_plan(&mem_events, inject_step)
        } else {
            None
        };

        let mut alu_events = HashMap::new();
        let mut blu_events = vec![];
        for (event_idx, op) in mem_events.iter().enumerate() {
            let mut row = [F::ZERO; NUM_MEMORY_CHIP_VALUE_COLS];
            let cols: &mut MemoryChipValueCols<F> = row.as_mut_slice().borrow_mut();
            let patched = beak_ts2_patched_event(**op, event_idx, beak_ts2_plan);
            if beak_ts2_plan.is_some_and(|plan| plan.involves(event_idx)) {
                std::env::set_var("BEAK_PICO_WITNESS_INJECTION_APPLIED", "1");
            }
            let mut row_blu_events = vec![];
            let row_alu_events = self.event_to_row(&patched, cols, &mut row_blu_events);
            beak_ts2_fix_consumer_diff_cols(cols, event_idx, beak_ts2_plan);
            beak_ts2_add_consumer_range_events(
                &mut blu_events,
                row_blu_events,
                event_idx,
                beak_ts2_plan,
            );
            row_alu_events.into_iter().for_each(|(key, value)| {
                alu_events.entry(key).or_insert(Vec::default()).extend(value);
            });
        }
        extra.add_alu_events(alu_events);
        extra.add_byte_lookup_events(blu_events);
    }
"""
    c = _replace_once(c, old, new)
    path.write_text(c)


def _remove_init_final_ts2_hook(c: str) -> str:
    c = c.replace(
        "        const BABYBEAR_P: u32 = 2_013_265_921;\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n",
        "",
    )
    c = c.replace("                    mut timestamp,\n", "                    timestamp,\n")
    c = c.replace(
        "                if inject_kind.as_deref() == Some(\"pico.semantic.memory.timestamped_load_path\")\n                    && (inject_step == u64::MAX\n                        || inject_step == i as u64\n                        || (inject_step == 0 && !injected_once))\n                {\n                    timestamp = BABYBEAR_P - 8;\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;\n                }\n\n",
        "",
    )
    c = c.replace(
        "                if inject_kind.as_deref() == Some(\"pico.semantic.memory.timestamped_load_path\")\n                    && (inject_step == u64::MAX\n                        || inject_step == i as u64\n                        || (inject_step == 0 && !injected_once))\n                {\n                    timestamp = BABYBEAR_P - 8;\n                    injected_once = true;\n                }\n\n",
        "",
    )
    return c


def _patch_cpu_traces(path: Path) -> None:
    c = path.read_text()
    cpu_helper = """
fn beak_cf5_alias_word<F: Field>(value: u32) -> Option<Word<F>> {
    if (value >> 24) >= 0x78 {
        return None;
    }
    let mut word = Word::<F>::from(value);
    word[0] = word[0] + F::from_canonical_u32(256);
    word[1] = word[1] - F::ONE;
    Some(word)
}

"""
    cpu_hook = """\n            // BEAK-INSERT pico semantic cpu-row hooks\n            if !injected_once\n                && (inject_step == u64::MAX\n                    || inject_step == idx as u64\n                    || inject_step == event.clk as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                let mut beak_applied = false;\n                match inject_kind.as_deref() {\n                    Some(\"pico.semantic.decode.zero_register_immutability\")\n                        if event.instruction.op_a == 0 =>\n                    {\n                        cols.op_a_access.access.value[0] = cols.op_a_access.access.value[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.decode.operand_index_routing\") => {\n                        cols.instruction.op_b[0] = cols.instruction.op_b[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.exec.dest_binding\")\n                        if event.instruction.op_a != 0 =>\n                    {\n                        cols.op_a_access.access.value[0] = cols.op_a_access.access.value[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.decode.field_range\") => {\n                        cols.instruction.op_a[0] = cols.instruction.op_a[0] + F::from_canonical_u32(32);\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.decode.immediate_sign_extension\")\n                    | Some(\"pico.semantic.decode.format_immediate_reassembly\")\n                    | Some(\"pico.semantic.decode.upper_immediate_materialization\") => {\n                        if event.instruction.imm_c {\n                            cols.instruction.op_c[0] = cols.instruction.op_c[0] + F::ONE;\n                            beak_applied = true;\n                        } else if event.instruction.imm_b {\n                            cols.instruction.op_b[0] = cols.instruction.op_b[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                    }\n                    Some(\"pico.semantic.control.entrypoint_binding\") if idx == 0 => {\n                        cols.pc = cols.pc + F::from_canonical_u32(4);\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.exec.control_flow_binding\") => {\n                        cols.next_pc = cols.next_pc + F::from_canonical_u32(4);\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.control.ecall_argument_decomposition\")\n                        if event.instruction.opcode == Opcode::ECALL =>\n                    {\n                        if cols.ecall_range_check_operand == F::ONE {\n                            if let Some(alias_word) = beak_cf5_alias_word::<F>(event.b) {\n                                cols.op_b_access.access.value = alias_word;\n                                let ecall_cols = cols.opcode_specific.ecall_mut();\n                                ecall_cols.operand_to_check = alias_word;\n                                ecall_cols.operand_range_check_cols.populate(event.b);\n                                beak_applied = true;\n                            }\n                        }\n                    }\n                    Some(\"pico.semantic.time.boundary_origin_consistency\") if idx == 0 => {\n                        cols.clk = cols.clk + F::ONE;\n                        beak_applied = true;\n                    }\n                    _ => {}\n                }\n                if beak_applied {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;\n                }\n            }\n"""
    c = c.replace(
        "    compiler::riscv::{\n        opcode::{ByteOpcode, Opcode},\n        program::Program,\n    },\n",
        "    compiler::{\n        riscv::{\n            opcode::{ByteOpcode, Opcode},\n            program::Program,\n        },\n        word::Word,\n    },\n",
    )
    c = _inject_before(
        c,
        "impl<F: PrimeField32> ChipBehavior<F> for CpuChip<F> {",
        cpu_helper,
    )
    old_cf5 = """                    Some(\"pico.semantic.control.ecall_argument_decomposition\")
                        if event.instruction.opcode == Opcode::ECALL =>
                    {
                        if cols.ecall_range_check_operand == F::ONE {
                            let ecall_cols = cols.opcode_specific.ecall_mut();
                            ecall_cols.operand_to_check[0] =
                                ecall_cols.operand_to_check[0] + F::ONE;
                            beak_applied = true;
                        } else {
                            cols.op_b_access.access.value[0] =
                                cols.op_b_access.access.value[0] + F::ONE;
                            beak_applied = true;
                        }
                    }
"""
    new_cf5 = """                    Some(\"pico.semantic.control.ecall_argument_decomposition\")
                        if event.instruction.opcode == Opcode::ECALL =>
                    {
                        if cols.ecall_range_check_operand == F::ONE {
                            if let Some(alias_word) = beak_cf5_alias_word::<F>(event.b) {
                                cols.op_b_access.access.value = alias_word;
                                let ecall_cols = cols.opcode_specific.ecall_mut();
                                ecall_cols.operand_to_check = alias_word;
                                ecall_cols.operand_range_check_cols.populate(event.b);
                                beak_applied = true;
                            }
                        }
                    }
"""
    c = c.replace(old_cf5, new_cf5)
    if "pico.semantic.exec.op_selector_binding" in c:
        c = _inject_before(c, "        }\n\n        // Convert the trace", cpu_hook)
        path.write_text(c)
        return
    c = c.replace(
        "use rayon::prelude::{IntoParallelRefMutIterator, ParallelBridge, ParallelIterator};\n",
        "use rayon::prelude::{IntoParallelRefMutIterator, ParallelIterator};\n",
    )
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let mut values = vec![F::ZERO; input.cpu_events.len() * NUM_CPU_COLS];\n\n        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);\n        values\n            .chunks_mut(chunk_size * NUM_CPU_COLS)\n            .enumerate()\n            .par_bridge()\n            .for_each(|(i, rows)| {\n                rows.chunks_mut(NUM_CPU_COLS)\n                    .enumerate()\n                    .for_each(|(j, row)| {\n                        let idx = i * chunk_size + j;\n                        let cols: &mut CpuCols<F> = row.borrow_mut();\n                        let mut byte_lookup_events = Vec::new();\n                        self.event_to_row(&input.cpu_events[idx], cols, &mut byte_lookup_events);\n                    });\n            });\n",
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let mut values = vec![F::ZERO; input.cpu_events.len() * NUM_CPU_COLS];\n\n        for (idx, event) in input.cpu_events.iter().enumerate() {\n            let row = &mut values[idx * NUM_CPU_COLS..(idx + 1) * NUM_CPU_COLS];\n            let cols: &mut CpuCols<F> = row.borrow_mut();\n            let mut byte_lookup_events = Vec::new();\n            self.event_to_row(event, cols, &mut byte_lookup_events);\n\n            if inject_kind.as_deref() == Some(\"pico.semantic.exec.op_selector_binding\")\n                && (inject_step == u64::MAX\n                    || inject_step == idx as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                if cols.opcode_selector.is_alu == F::ONE {\n                    cols.opcode_selector.is_alu = F::ZERO;\n                } else {\n                    cols.opcode_selector.is_alu = F::ONE;\n                }\n                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                injected_once = true;\n            }\n        }\n",
    )
    c = _inject_before(c, "        }\n\n        // Convert the trace", cpu_hook)
    path.write_text(c)


def _patch_add_sub_traces(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico semantic addsub hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let events = input\n",
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let events = input\n",
    )
    c = _replace_once(
        c,
        "        values[..populate_len]\n            .par_chunks_mut(NUM_ADD_SUB_VALUE_COLS)\n            .zip_eq(events)\n            .for_each(|(row, event)| {\n                let cols: &mut AddSubValueCols<_> = row.borrow_mut();\n                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "        for (event_idx, (row, event)) in values[..populate_len]\n            .chunks_mut(NUM_ADD_SUB_VALUE_COLS)\n            .zip(events.iter())\n            .enumerate()\n        {\n            let cols: &mut AddSubValueCols<_> = row.borrow_mut();\n            self.event_to_row(event, cols, &mut vec![]);\n\n            // BEAK-INSERT pico semantic addsub hooks\n            if !injected_once\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || inject_step == event.clk as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                let mut beak_applied = false;\n                match inject_kind.as_deref() {\n                    Some(\"pico.semantic.alu.immediate_limb_consistency\") => {\n                        cols.operand_2[0] = cols.operand_2[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.alu.subtraction_borrow_chain\")\n                        if event.opcode == Opcode::SUB =>\n                    {\n                        cols.add_operation.carry[0] = F::ONE - cols.add_operation.carry[0];\n                        beak_applied = true;\n                    }\n                    _ => {}\n                }\n                if beak_applied {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;\n                }\n            }\n        }\n",
    )
    path.write_text(c)


def _patch_sll_traces(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico semantic sll hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {\n        let events = input.shift_left_events.iter().collect::<Vec<_>>();\n",
        "    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let events = input.shift_left_events.iter().collect::<Vec<_>>();\n",
    )
    c = _replace_once(
        c,
        "        values[..populate_len]\n            .par_chunks_mut(NUM_SLL_VALUE_COLS)\n            .zip_eq(events)\n            .for_each(|(row, event)| {\n                let cols: &mut ShiftLeftValueCols<_> = row.borrow_mut();\n                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "        for (event_idx, (row, event)) in values[..populate_len]\n            .chunks_mut(NUM_SLL_VALUE_COLS)\n            .zip(events.iter())\n            .enumerate()\n        {\n            let cols: &mut ShiftLeftValueCols<_> = row.borrow_mut();\n            self.event_to_row(event, cols, &mut vec![]);\n\n            // BEAK-INSERT pico semantic sll hooks\n            if !injected_once\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || inject_step == event.clk as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                let mut beak_applied = false;\n                match inject_kind.as_deref() {\n                    Some(\"pico.semantic.alu.immediate_limb_consistency\") => {\n                        cols.c[0] = cols.c[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.alu.shift_mod32\") => {\n                        cols.shift_by_n_bits[0] = F::ONE - cols.shift_by_n_bits[0];\n                        beak_applied = true;\n                    }\n                    _ => {}\n                }\n                if beak_applied {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;\n                }\n            }\n        }\n",
    )
    path.write_text(c)


def _patch_sr_traces(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico semantic sr hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {\n        let events = input.shift_right_events.iter().collect::<Vec<_>>();\n",
        "    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let events = input.shift_right_events.iter().collect::<Vec<_>>();\n",
    )
    c = _replace_once(
        c,
        "        values[..populate_len]\n            .par_chunks_mut(NUM_SLR_VALUE_COLS)\n            .zip_eq(events)\n            .for_each(|(row, event)| {\n                let cols: &mut ShiftRightValueCols<_> = row.borrow_mut();\n                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "        for (event_idx, (row, event)) in values[..populate_len]\n            .chunks_mut(NUM_SLR_VALUE_COLS)\n            .zip(events.iter())\n            .enumerate()\n        {\n            let cols: &mut ShiftRightValueCols<_> = row.borrow_mut();\n            self.event_to_row(event, cols, &mut vec![]);\n\n            // BEAK-INSERT pico semantic sr hooks\n            if !injected_once\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || inject_step == event.clk as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                let mut beak_applied = false;\n                match inject_kind.as_deref() {\n                    Some(\"pico.semantic.alu.immediate_limb_consistency\") => {\n                        cols.c[0] = cols.c[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.alu.shift_mod32\") => {\n                        cols.shift_by_n_bits[0] = F::ONE - cols.shift_by_n_bits[0];\n                        beak_applied = true;\n                    }\n                    _ => {}\n                }\n                if beak_applied {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;\n                }\n            }\n        }\n",
    )
    path.write_text(c)


def _patch_lt_traces(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico semantic lt hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let events = input.lt_events.iter().collect::<Vec<_>>();\n",
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let events = input.lt_events.iter().collect::<Vec<_>>();\n",
    )
    c = _replace_once(
        c,
        "        values[..populate_len]\n            .par_chunks_mut(NUM_LT_VALUE_COLS)\n            .zip_eq(events)\n            .for_each(|(row, event)| {\n                let cols: &mut LtValueCols<_> = row.borrow_mut();\n                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "        for (event_idx, (row, event)) in values[..populate_len]\n            .chunks_mut(NUM_LT_VALUE_COLS)\n            .zip(events.iter())\n            .enumerate()\n        {\n            let cols: &mut LtValueCols<_> = row.borrow_mut();\n            self.event_to_row(event, cols, &mut vec![]);\n\n            // BEAK-INSERT pico semantic lt hooks\n            if !injected_once\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || inject_step == event.clk as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                let mut beak_applied = false;\n                match inject_kind.as_deref() {\n                    Some(\"pico.semantic.alu.immediate_limb_consistency\") => {\n                        cols.c[0] = cols.c[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.alu.comparison_booleanity\") => {\n                        cols.a[0] = cols.a[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.alu.comparison_auxiliary_chain\") => {\n                        cols.byte_flags[0] = F::ONE - cols.byte_flags[0];\n                        beak_applied = true;\n                    }\n                    _ => {}\n                }\n                if beak_applied {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;\n                }\n            }\n        }\n",
    )
    path.write_text(c)


def _patch_mul_traces(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico semantic mul hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let events = input.mul_events.iter().collect::<Vec<_>>();\n",
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let events = input.mul_events.iter().collect::<Vec<_>>();\n",
    )
    c = _inject_before(
        c,
        "                // Range check.\n",
        "                // BEAK-INSERT pico semantic mul hooks\n                if !injected_once\n                    && (inject_step == u64::MAX\n                        || inject_step == event.clk as u64\n                        || (inject_step == 0 && !injected_once))\n                {\n                    let mut beak_applied = false;\n                    match inject_kind.as_deref() {\n                        Some(\"pico.semantic.arithmetic.product_decomposition\") => {\n                            cols.product[0] = cols.product[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                        Some(\"pico.semantic.arithmetic.signed_unsigned_product_correction\")\n                            if event.opcode == Opcode::MULHSU =>\n                        {\n                            cols.b_sign_extend = F::ONE - cols.b_sign_extend;\n                            beak_applied = true;\n                        }\n                        _ => {}\n                    }\n                    if beak_applied {\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                        injected_once = true;\n                    }\n                }\n\n",
    )
    path.write_text(c)


def _patch_divrem_traces(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico semantic divrem hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let events = input.divrem_events.iter().collect::<Vec<_>>();\n",
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let events = input.divrem_events.iter().collect::<Vec<_>>();\n",
    )
    c = _inject_before(
        c,
        "                // Calculate flags for sign detection.\n",
        "                // BEAK-INSERT pico semantic divrem hooks\n                if !injected_once\n                    && (inject_step == u64::MAX\n                        || inject_step == event.clk as u64\n                        || (inject_step == 0 && !injected_once))\n                {\n                    let mut beak_applied = false;\n                    match inject_kind.as_deref() {\n                        Some(\"pico.semantic.arithmetic.special_case_consistency\") => {\n                            cols.quotient[0] = cols.quotient[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                        Some(\"pico.semantic.arithmetic.division_remainder_bound\") => {\n                            cols.remainder[0] = cols.remainder[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                        _ => {}\n                    }\n                    if beak_applied {\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                        injected_once = true;\n                    }\n                }\n\n",
    )
    path.write_text(c)


def _patch_cpu_traces_22b0(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico 22b0 semantic cpu-row hooks" in c:
        return
    c = c.replace(
        "    iter::{IntoPicoRefMutIterator, PicoBridge, PicoIterator, PicoSlice},\n",
        "    iter::{IntoPicoRefMutIterator, PicoIterator, PicoSlice},\n",
    )
    cpu_helper = """
fn beak_cf5_alias_word<F: Field>(value: u64) -> Option<Word<F>> {
    if (value >> 56) >= 0x78 {
        return None;
    }
    let mut word = Word::<F>::from(value);
    word[0] = word[0] + F::from_canonical_u32(256);
    word[1] = word[1] - F::ONE;
    Some(word)
}

"""
    c = _inject_before(
        c,
        "impl<F: PrimeField32> ChipBehavior<F> for CpuChip<F> {",
        cpu_helper,
    )
    old = """    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut values = vec![F::ZERO; input.cpu_events.len() * NUM_CPU_COLS];

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values
            .chunks_mut(chunk_size * NUM_CPU_COLS)
            .enumerate()
            .pico_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut CpuCols<F> = row.borrow_mut();
                        let mut byte_lookup_events = Vec::new();
                        self.event_to_row(&input.cpu_events[idx], cols, &mut byte_lookup_events);
                    });
            });
"""
    new = """    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let inject_kind = std::env::var("BEAK_PICO_WITNESS_INJECT_KIND").ok();
        let inject_step = std::env::var("BEAK_PICO_WITNESS_INJECT_STEP")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let mut injected_once = false;
        let mut values = vec![F::ZERO; input.cpu_events.len() * NUM_CPU_COLS];

        for (idx, event) in input.cpu_events.iter().enumerate() {
            let row = &mut values[idx * NUM_CPU_COLS..(idx + 1) * NUM_CPU_COLS];
            let cols: &mut CpuCols<F> = row.borrow_mut();
            let mut byte_lookup_events = Vec::new();
            self.event_to_row(event, cols, &mut byte_lookup_events);

            // BEAK-INSERT pico 22b0 semantic cpu-row hooks
            if !injected_once
                && (inject_step == u64::MAX
                    || inject_step == idx as u64
                    || inject_step == event.clk
                    || (inject_step == 0 && !injected_once))
            {
                let mut beak_applied = false;
                match inject_kind.as_deref() {
                    Some("pico.semantic.exec.op_selector_binding") => {
                        cols.opcode_selector.is_alu = F::ONE - cols.opcode_selector.is_alu;
                        beak_applied = true;
                    }
                    Some("pico.semantic.decode.zero_register_immutability")
                        if event.instruction.op_a == 0 =>
                    {
                        cols.op_a_access.access.value[0] =
                            cols.op_a_access.access.value[0] + F::ONE;
                        beak_applied = true;
                    }
                    Some("pico.semantic.decode.operand_index_routing") => {
                        cols.instruction.op_b[0] = cols.instruction.op_b[0] + F::ONE;
                        beak_applied = true;
                    }
                    Some("pico.semantic.exec.dest_binding")
                        if event.instruction.op_a != 0 =>
                    {
                        cols.op_a_access.access.value[0] =
                            cols.op_a_access.access.value[0] + F::ONE;
                        beak_applied = true;
                    }
                    Some("pico.semantic.decode.field_range") => {
                        cols.instruction.op_a[0] =
                            cols.instruction.op_a[0] + F::from_canonical_u32(32);
                        beak_applied = true;
                    }
                    Some("pico.semantic.decode.immediate_sign_extension")
                    | Some("pico.semantic.decode.format_immediate_reassembly")
                    | Some("pico.semantic.decode.upper_immediate_materialization") => {
                        if event.instruction.imm_c {
                            cols.instruction.op_c[0] = cols.instruction.op_c[0] + F::ONE;
                            beak_applied = true;
                        } else if event.instruction.imm_b {
                            cols.instruction.op_b[0] = cols.instruction.op_b[0] + F::ONE;
                            beak_applied = true;
                        }
                    }
                    Some("pico.semantic.control.entrypoint_binding") if idx == 0 => {
                        cols.pc[0] = cols.pc[0] + F::from_canonical_u32(4);
                        beak_applied = true;
                    }
                    Some("pico.semantic.exec.control_flow_binding") => {
                        cols.next_pc[0] = cols.next_pc[0] + F::from_canonical_u32(4);
                        beak_applied = true;
                    }
                    Some("pico.semantic.control.ecall_argument_decomposition")
                        if event.instruction.opcode == Opcode::ECALL =>
                    {
                        if cols.ecall_range_check_operand == F::ONE {
                            if let Some(alias_word) = beak_cf5_alias_word::<F>(event.b) {
                                cols.op_b_access.access.value = alias_word;
                                let ecall_cols = cols.opcode_specific.ecall_mut();
                                ecall_cols.operand_to_check = alias_word;
                                ecall_cols.operand_range_check_cols.populate(event.b as u32);
                                beak_applied = true;
                            }
                        }
                    }
                    Some("pico.semantic.time.boundary_origin_consistency") if idx == 0 => {
                        cols.clk = cols.clk + F::ONE;
                        beak_applied = true;
                    }
                    _ => {}
                }
                if beak_applied {
                    std::env::set_var("BEAK_PICO_WITNESS_INJECTION_APPLIED", "1");
                    injected_once = true;
                }
            }
        }
"""
    c = _replace_once(c, old, new)
    path.write_text(c)


def _patch_add_traces_22b0(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico 22b0 semantic add hooks" in c:
        return
    c = c.replace(
        "    iter::{IndexedPicoIterator, PicoBridge, PicoIterator, PicoSliceMut},\n",
        "    iter::{PicoBridge, PicoIterator},\n",
    )
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let events: Vec<&AluEvent> = input\n",
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let events: Vec<&AluEvent> = input\n",
    )
    c = _replace_once(
        c,
        "        values[..populate_len]\n            .pico_chunks_mut(NUM_ADD_VALUE_COLS)\n            .zip_eq(events)\n            .for_each(|(row, event)| {\n                let cols: &mut AddValueCols<_> = row.borrow_mut();\n                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "        for (event_idx, (row, event)) in values[..populate_len]\n            .chunks_mut(NUM_ADD_VALUE_COLS)\n            .zip(events.iter())\n            .enumerate()\n        {\n            let cols: &mut AddValueCols<_> = row.borrow_mut();\n            self.event_to_row(event, cols, &mut vec![]);\n\n            // BEAK-INSERT pico 22b0 semantic add hooks\n            if !injected_once\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || inject_step == event.clk\n                    || (inject_step == 0 && !injected_once))\n                && inject_kind.as_deref()\n                    == Some(\"pico.semantic.alu.immediate_limb_consistency\")\n            {\n                cols.operand_2[0] = cols.operand_2[0] + F::ONE;\n                std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                injected_once = true;\n            }\n        }\n",
    )
    path.write_text(c)


def _patch_sub_traces_22b0(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico 22b0 semantic sub hooks" in c:
        return
    c = c.replace(
        "    iter::{IndexedPicoIterator, PicoBridge, PicoIterator, PicoSliceMut},\n",
        "    iter::{PicoBridge, PicoIterator},\n",
    )
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let events: Vec<&AluEvent> = input\n",
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let events: Vec<&AluEvent> = input\n",
    )
    c = _replace_once(
        c,
        "        values[..populate_len]\n            .pico_chunks_mut(NUM_SUB_VALUE_COLS)\n            .zip_eq(events)\n            .for_each(|(row, event)| {\n                let cols: &mut SubValueCols<_> = row.borrow_mut();\n                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "        for (event_idx, (row, event)) in values[..populate_len]\n            .chunks_mut(NUM_SUB_VALUE_COLS)\n            .zip(events.iter())\n            .enumerate()\n        {\n            let cols: &mut SubValueCols<_> = row.borrow_mut();\n            self.event_to_row(event, cols, &mut vec![]);\n\n            // BEAK-INSERT pico 22b0 semantic sub hooks\n            if !injected_once\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || inject_step == event.clk\n                    || (inject_step == 0 && !injected_once))\n            {\n                let mut beak_applied = false;\n                match inject_kind.as_deref() {\n                    Some(\"pico.semantic.alu.immediate_limb_consistency\") => {\n                        cols.operand_2[0] = cols.operand_2[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.alu.subtraction_borrow_chain\") => {\n                        cols.sub_operation.value[0] = cols.sub_operation.value[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    _ => {}\n                }\n                if beak_applied {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;\n                }\n            }\n        }\n",
    )
    path.write_text(c)


def _patch_sll_traces_22b0(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico 22b0 semantic sll hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {\n        let events = input.shift_left_events.iter().collect::<Vec<_>>();\n",
        "    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let events = input.shift_left_events.iter().collect::<Vec<_>>();\n",
    )
    c = _replace_once(
        c,
        "                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "                self.event_to_row(event, cols, &mut vec![]);\n\n                // BEAK-INSERT pico 22b0 semantic sll hooks\n                if inject_step == u64::MAX || inject_step == event.clk || inject_step == 0 {\n                    let mut beak_applied = false;\n                    match inject_kind.as_deref() {\n                        Some(\"pico.semantic.alu.immediate_limb_consistency\") => {\n                            cols.c[0] = cols.c[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                        Some(\"pico.semantic.alu.shift_mod32\") => {\n                            cols.c_bits[5] = F::ONE - cols.c_bits[5];\n                            beak_applied = true;\n                        }\n                        _ => {}\n                    }\n                    if beak_applied {\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    }\n                }\n            });\n",
    )
    path.write_text(c)


def _patch_sr_traces_22b0(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico 22b0 semantic sr hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {\n        let events = input.shift_right_events.iter().collect::<Vec<_>>();\n",
        "    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let events = input.shift_right_events.iter().collect::<Vec<_>>();\n",
    )
    c = _replace_once(
        c,
        "                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "                self.event_to_row(event, cols, &mut vec![]);\n\n                // BEAK-INSERT pico 22b0 semantic sr hooks\n                if inject_step == u64::MAX || inject_step == event.clk || inject_step == 0 {\n                    let mut beak_applied = false;\n                    match inject_kind.as_deref() {\n                        Some(\"pico.semantic.alu.immediate_limb_consistency\") => {\n                            cols.c_for_lookup[0] = cols.c_for_lookup[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                        Some(\"pico.semantic.alu.shift_mod32\") => {\n                            cols.c_bits[5] = F::ONE - cols.c_bits[5];\n                            beak_applied = true;\n                        }\n                        _ => {}\n                    }\n                    if beak_applied {\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    }\n                }\n            });\n",
    )
    path.write_text(c)


def _patch_lt_traces_22b0(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico 22b0 semantic lt hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let events = input.lt_events.iter().collect::<Vec<_>>();\n",
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let events = input.lt_events.iter().collect::<Vec<_>>();\n",
    )
    c = _replace_once(
        c,
        "                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "                self.event_to_row(event, cols, &mut vec![]);\n\n                // BEAK-INSERT pico 22b0 semantic lt hooks\n                if inject_step == u64::MAX || inject_step == event.clk || inject_step == 0 {\n                    let mut beak_applied = false;\n                    match inject_kind.as_deref() {\n                        Some(\"pico.semantic.alu.immediate_limb_consistency\") => {\n                            cols.c[0] = cols.c[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                        Some(\"pico.semantic.alu.comparison_booleanity\") => {\n                            cols.a[0] = cols.a[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                        Some(\"pico.semantic.alu.comparison_auxiliary_chain\") => {\n                            cols.lt_signed.result.u16_flags[0] =\n                                F::ONE - cols.lt_signed.result.u16_flags[0];\n                            beak_applied = true;\n                        }\n                        _ => {}\n                    }\n                    if beak_applied {\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    }\n                }\n            });\n",
    )
    path.write_text(c)


def _patch_mul_traces_22b0(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico 22b0 semantic mul hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let events = input.mul_events.iter().collect::<Vec<_>>();\n",
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let events = input.mul_events.iter().collect::<Vec<_>>();\n",
    )
    c = _inject_before(
        c,
        "                // Set the input operands b and c\n",
        "                // BEAK-INSERT pico 22b0 semantic mul hooks\n                if inject_step == u64::MAX || inject_step == event.clk || inject_step == 0 {\n                    let mut beak_applied = false;\n                    match inject_kind.as_deref() {\n                        Some(\"pico.semantic.arithmetic.product_decomposition\") => {\n                            cols.mul_gadget.product[0] = cols.mul_gadget.product[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                        Some(\"pico.semantic.arithmetic.signed_unsigned_product_correction\")\n                            if event.opcode == Opcode::MULHSU =>\n                        {\n                            cols.mul_gadget.b_sign_extend =\n                                F::ONE - cols.mul_gadget.b_sign_extend;\n                            beak_applied = true;\n                        }\n                        _ => {}\n                    }\n                    if beak_applied {\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    }\n                }\n\n",
    )
    path.write_text(c)


def _patch_divrem_traces_22b0(path: Path) -> None:
    c = path.read_text()
    if "BEAK-INSERT pico 22b0 semantic divrem hooks" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let events = input.divrem_events.iter().collect::<Vec<_>>();\n",
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let events = input.divrem_events.iter().collect::<Vec<_>>();\n",
    )
    c = _inject_before(
        c,
        "                // Calculate flags for sign detection.\n",
        "                // BEAK-INSERT pico 22b0 semantic divrem hooks\n                if inject_step == u64::MAX || inject_step == event.clk || inject_step == 0 {\n                    let mut beak_applied = false;\n                    match inject_kind.as_deref() {\n                        Some(\"pico.semantic.arithmetic.special_case_consistency\") => {\n                            cols.quotient[0] = cols.quotient[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                        Some(\"pico.semantic.arithmetic.division_remainder_bound\") => {\n                            cols.remainder[0] = cols.remainder[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                        _ => {}\n                    }\n                    if beak_applied {\n                        std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    }\n                }\n\n",
    )
    path.write_text(c)


def apply(*, pico_install_path: Path, commit_or_branch: str) -> None:
    if commit_or_branch == PICO_LATEST_22B0_COMMIT:
        cpu = pico_install_path / "vm" / "src" / "chips" / "chips" / "riscv_cpu"
        _patch_cpu_traces_22b0(cpu / "traces.rs")
        alu = pico_install_path / "vm" / "src" / "chips" / "chips" / "alu"
        _patch_add_traces_22b0(alu / "add" / "traces.rs")
        _patch_sub_traces_22b0(alu / "sub" / "traces.rs")
        _patch_sll_traces_22b0(alu / "sll" / "traces.rs")
        _patch_sr_traces_22b0(alu / "sr" / "traces.rs")
        _patch_lt_traces_22b0(alu / "lt" / "traces.rs")
        _patch_mul_traces_22b0(alu / "mul" / "traces.rs")
        _patch_divrem_traces_22b0(alu / "divrem" / "traces.rs")
        vm = pico_install_path / "vm" / "src" / "chips" / "chips" / "riscv_memory"
        _patch_local_traces_22b0(vm / "local" / "traces.rs")
        _patch_rw_traces(vm / "read_write" / "traces.rs")
        _patch_rw_extra_record_22b0(vm / "read_write" / "traces.rs")
        _patch_init_final_traces(vm / "initialize_finalize" / "traces.rs")
        return
    # Keep patch surface minimal and deterministic for the benchmark snapshot only.
    if commit_or_branch != PICO_BENCHMARK_45E74_COMMIT:
        return
    cpu = pico_install_path / "vm" / "src" / "chips" / "chips" / "riscv_cpu"
    _patch_cpu_traces(cpu / "traces.rs")
    alu = pico_install_path / "vm" / "src" / "chips" / "chips" / "alu"
    _patch_add_sub_traces(alu / "add_sub" / "traces.rs")
    _patch_sll_traces(alu / "sll" / "traces.rs")
    _patch_sr_traces(alu / "sr" / "traces.rs")
    _patch_lt_traces(alu / "lt" / "traces.rs")
    _patch_mul_traces(alu / "mul" / "traces.rs")
    _patch_divrem_traces(alu / "divrem" / "traces.rs")
    vm = pico_install_path / "vm" / "src" / "chips" / "chips" / "riscv_memory"
    _patch_columns(vm / "local" / "columns.rs")
    _patch_local_traces(vm / "local" / "traces.rs")
    _patch_local_constraints(vm / "local" / "constraints.rs")
    _patch_rw_traces(vm / "read_write" / "traces.rs", narrow_45e_types=True)
    _patch_init_final_traces(
        vm / "initialize_finalize" / "traces.rs", narrow_45e_types=True
    )
