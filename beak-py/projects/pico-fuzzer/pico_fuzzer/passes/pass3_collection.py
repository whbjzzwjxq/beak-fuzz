"""
Pass 3: Trace + Witness Collection Instrumentation
"""

from __future__ import annotations

from pathlib import Path

from pico_fuzzer.settings import PICO_BENCHMARK_45E74_COMMIT


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


def _patch_rw_traces(path: Path) -> None:
    c = path.read_text()
    memory_hook = """\n            // BEAK-INSERT pico semantic memory rw hooks\n            if !injected_once\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || inject_step == event.clk as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                let mut beak_applied = false;\n                match inject_kind.as_deref() {\n                    Some(\"pico.semantic.memory.address_alignment_consistency\")\n                    | Some(\"pico.semantic.memory.address_progression_consistency\")\n                    | Some(\"pico.semantic.memory.address_boundary_range\") => {\n                        cols.addr_word[0] = cols.addr_word[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.memory.load_value_binding\")\n                    | Some(\"pico.semantic.memory.write_payload_consistency\")\n                    | Some(\"pico.semantic.memory.store_load_payload_flow\") => {\n                        cols.memory_access.access.value[0] = cols.memory_access.access.value[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.memory.kind_selector_consistency\") => {\n                        cols.instruction.is_lw = F::ONE - cols.instruction.is_lw;\n                        beak_applied = true;\n                    }\n                    _ => {}\n                }\n                if beak_applied {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;\n                }\n            }\n"""
    c = c.replace(
        "    IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator, ParallelSlice,\n",
        "    IntoParallelRefIterator, ParallelIterator, ParallelSlice,\n",
    )
    c = c.replace("use rayon::slice::ParallelSliceMut;\n", "")
    if "pico.semantic.memory.timestamped_load_path" in c:
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
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        const BABYBEAR_P: u32 = 2_013_265_921;\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        // Parallelize the initial filtering and collection\n",
    )
    c = _replace_once(
        c,
        "        // Use rayon's parallel slice operations for better chunk handling\n        values[..populate_len]\n            .par_chunks_mut(NUM_MEMORY_CHIP_VALUE_COLS)\n            .zip_eq(events.par_iter())\n            .for_each(|(row, event)| {\n                let cols: &mut MemoryChipValueCols<_> = row.borrow_mut();\n                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "        for (event_idx, (row, event)) in values[..populate_len]\n            .chunks_mut(NUM_MEMORY_CHIP_VALUE_COLS)\n            .zip(events.iter())\n            .enumerate()\n        {\n            let mut patched = **event;\n            if inject_kind.as_deref() == Some(\"pico.semantic.memory.timestamped_load_path\")\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                if let Some(mut mr) = patched.memory_record {\n                    match &mut mr {\n                        MemoryRecordEnum::Read(r) => {\n                            r.prev_chunk = r.chunk;\n                            r.prev_timestamp = BABYBEAR_P - 16;\n                        }\n                        MemoryRecordEnum::Write(w) => {\n                            w.prev_chunk = w.chunk;\n                            w.prev_timestamp = BABYBEAR_P - 16;\n                        }\n                    }\n                    patched.memory_record = Some(mr);\n                    injected_once = true;\n                }\n            }\n            let cols: &mut MemoryChipValueCols<_> = row.borrow_mut();\n            self.event_to_row(&patched, cols, &mut vec![]);\n        }\n",
    )
    c = c.replace(
        "patched.memory_record = Some(mr);\n                    injected_once = true;",
        "patched.memory_record = Some(mr);\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;",
    )
    c = _inject_before(c, "        }\n\n        RowMajorMatrix::new(values, NUM_MEMORY_CHIP_COLS)", memory_hook)
    path.write_text(c)


def _patch_init_final_traces(path: Path) -> None:
    c = path.read_text()
    if "pico.semantic.memory.timestamped_load_path" in c:
        if "BEAK_PICO_WITNESS_INJECTION_APPLIED" not in c:
            c = c.replace(
                "timestamp = BABYBEAR_P - 8;\n                    injected_once = true;",
                "timestamp = BABYBEAR_P - 8;\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;",
            )
            path.write_text(c)
        return
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        let mut memory_events = match self.kind {\n",
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        const BABYBEAR_P: u32 = 2_013_265_921;\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let mut memory_events = match self.kind {\n",
    )
    c = _replace_once(
        c,
        "                    timestamp,\n",
        "                    mut timestamp,\n",
    )
    c = _replace_once(
        c,
        "                } = memory_events[i];\n\n                let mut row = [F::ZERO; NUM_MEMORY_INITIALIZE_FINALIZE_COLS];\n",
        "                } = memory_events[i];\n                if inject_kind.as_deref() == Some(\"pico.semantic.memory.timestamped_load_path\")\n                    && (inject_step == u64::MAX\n                        || inject_step == i as u64\n                        || (inject_step == 0 && !injected_once))\n                {\n                    timestamp = BABYBEAR_P - 8;\n                    injected_once = true;\n                }\n\n                let mut row = [F::ZERO; NUM_MEMORY_INITIALIZE_FINALIZE_COLS];\n",
    )
    c = c.replace(
        "timestamp = BABYBEAR_P - 8;\n                    injected_once = true;",
        "timestamp = BABYBEAR_P - 8;\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;",
    )
    c = _replace_once(
        c,
        "        let rows: Vec<[F; NUM_MEMORY_INITIALIZE_FINALIZE_COLS]> = (0..memory_events.len())\n            .into_par_iter()\n            .map(|i| {\n",
        "        let rows: Vec<[F; NUM_MEMORY_INITIALIZE_FINALIZE_COLS]> = (0..memory_events.len())\n            .map(|i| {\n",
    )
    path.write_text(c)


def _patch_cpu_traces(path: Path) -> None:
    c = path.read_text()
    cpu_hook = """\n            // BEAK-INSERT pico semantic cpu-row hooks\n            if !injected_once\n                && (inject_step == u64::MAX\n                    || inject_step == idx as u64\n                    || inject_step == event.clk as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                let mut beak_applied = false;\n                match inject_kind.as_deref() {\n                    Some(\"pico.semantic.decode.zero_register_immutability\")\n                        if event.instruction.op_a == 0 =>\n                    {\n                        cols.op_a_access.access.value[0] = cols.op_a_access.access.value[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.decode.operand_index_routing\") => {\n                        cols.instruction.op_b[0] = cols.instruction.op_b[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.exec.dest_binding\")\n                        if event.instruction.op_a != 0 =>\n                    {\n                        cols.op_a_access.access.value[0] = cols.op_a_access.access.value[0] + F::ONE;\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.decode.field_range\") => {\n                        cols.instruction.op_a[0] = cols.instruction.op_a[0] + F::from_canonical_u32(32);\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.decode.immediate_sign_extension\")\n                    | Some(\"pico.semantic.decode.format_immediate_reassembly\")\n                    | Some(\"pico.semantic.decode.upper_immediate_materialization\") => {\n                        if event.instruction.imm_c {\n                            cols.instruction.op_c[0] = cols.instruction.op_c[0] + F::ONE;\n                            beak_applied = true;\n                        } else if event.instruction.imm_b {\n                            cols.instruction.op_b[0] = cols.instruction.op_b[0] + F::ONE;\n                            beak_applied = true;\n                        }\n                    }\n                    Some(\"pico.semantic.control.entrypoint_binding\") if idx == 0 => {\n                        cols.pc = cols.pc + F::from_canonical_u32(4);\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.exec.control_flow_binding\") => {\n                        cols.next_pc = cols.next_pc + F::from_canonical_u32(4);\n                        beak_applied = true;\n                    }\n                    Some(\"pico.semantic.time.boundary_origin_consistency\") if idx == 0 => {\n                        cols.clk = cols.clk + F::ONE;\n                        beak_applied = true;\n                    }\n                    _ => {}\n                }\n                if beak_applied {\n                    std::env::set_var(\"BEAK_PICO_WITNESS_INJECTION_APPLIED\", \"1\");\n                    injected_once = true;\n                }\n            }\n"""
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


def apply(*, pico_install_path: Path, commit_or_branch: str) -> None:
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
    _patch_rw_traces(vm / "read_write" / "traces.rs")
    _patch_init_final_traces(vm / "initialize_finalize" / "traces.rs")
