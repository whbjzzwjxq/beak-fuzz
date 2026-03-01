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
        return
    c = _replace_once(
        c,
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        _output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let events = input.get_local_mem_events().collect::<Vec<_>>();\n",
        "    fn generate_main(\n        &self,\n        input: &EmulationRecord,\n        _output: &mut EmulationRecord,\n    ) -> RowMajorMatrix<F> {\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        let events = input.get_local_mem_events().collect::<Vec<_>>();\n",
    )
    c = _replace_once(
        c,
        "        // Parallelize the main computation using par_chunks_mut\n        values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]\n            .par_chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS)\n            .enumerate()\n            .for_each(|(row_idx, row)| {\n                let base_event_idx = row_idx * LOCAL_MEMORY_DATAPAR;\n                let cols: &mut MemoryLocalCols<F> = row.borrow_mut();\n\n                for k in 0..LOCAL_MEMORY_DATAPAR {\n                    let cols = &mut cols.memory_local_entries[k];\n                    if base_event_idx + k < events.len() {\n                        let event = &events[base_event_idx + k];\n                        cols.addr = F::from_canonical_u32(event.addr);\n                        cols.initial_chunk = F::from_canonical_u32(event.initial_mem_access.chunk);\n                        cols.final_chunk = F::from_canonical_u32(event.final_mem_access.chunk);\n                        cols.initial_clk =\n                            F::from_canonical_u32(event.initial_mem_access.timestamp);\n                        cols.final_clk = F::from_canonical_u32(event.final_mem_access.timestamp);\n                        cols.initial_value = event.initial_mem_access.value.into();\n                        cols.final_value = event.final_mem_access.value.into();\n                        cols.is_real = F::ONE;\n                    }\n                }\n            });\n",
        "        for (row_idx, row) in values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]\n            .chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS)\n            .enumerate()\n        {\n            let base_event_idx = row_idx * LOCAL_MEMORY_DATAPAR;\n            let cols: &mut MemoryLocalCols<F> = row.borrow_mut();\n\n            for k in 0..LOCAL_MEMORY_DATAPAR {\n                let cols = &mut cols.memory_local_entries[k];\n                if base_event_idx + k < events.len() {\n                    let event_idx = (base_event_idx + k) as u64;\n                    let event = &events[base_event_idx + k];\n                    cols.addr = F::from_canonical_u32(event.addr);\n                    cols.initial_chunk = F::from_canonical_u32(event.initial_mem_access.chunk);\n                    cols.final_chunk = F::from_canonical_u32(event.final_mem_access.chunk);\n                    cols.initial_clk = F::from_canonical_u32(event.initial_mem_access.timestamp);\n                    cols.final_clk = F::from_canonical_u32(event.final_mem_access.timestamp);\n                    cols.initial_value = event.initial_mem_access.value.into();\n                    cols.final_value = event.final_mem_access.value.into();\n                    cols.is_real = F::ONE;\n                    cols.is_real_shadow = F::ONE;\n\n                    if inject_kind.as_deref() == Some(\"pico.audit_multiplicity_bool_constraint.local_event_row\")\n                        && (inject_step == u64::MAX\n                            || inject_step == event_idx\n                            || (inject_step == 0 && !injected_once))\n                    {\n                        cols.is_real = F::from_canonical_u32(2);\n                        injected_once = true;\n                    }\n                }\n            }\n        }\n",
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
    if "pico.audit_timestamp.mem_row_wraparound" in c:
        return
    c = _replace_once(
        c,
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        // Parallelize the initial filtering and collection\n",
        "    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {\n        const BABYBEAR_P: u32 = 2_013_265_921;\n        let inject_kind = std::env::var(\"BEAK_PICO_WITNESS_INJECT_KIND\").ok();\n        let inject_step = std::env::var(\"BEAK_PICO_WITNESS_INJECT_STEP\")\n            .ok()\n            .and_then(|s| s.parse::<u64>().ok())\n            .unwrap_or(0);\n        let mut injected_once = false;\n        // Parallelize the initial filtering and collection\n",
    )
    c = _replace_once(
        c,
        "        // Use rayon's parallel slice operations for better chunk handling\n        values[..populate_len]\n            .par_chunks_mut(NUM_MEMORY_CHIP_VALUE_COLS)\n            .zip_eq(events.par_iter())\n            .for_each(|(row, event)| {\n                let cols: &mut MemoryChipValueCols<_> = row.borrow_mut();\n                self.event_to_row(event, cols, &mut vec![]);\n            });\n",
        "        for (event_idx, (row, event)) in values[..populate_len]\n            .chunks_mut(NUM_MEMORY_CHIP_VALUE_COLS)\n            .zip(events.iter())\n            .enumerate()\n        {\n            let mut patched = **event;\n            if inject_kind.as_deref() == Some(\"pico.audit_timestamp.mem_row_wraparound\")\n                && (inject_step == u64::MAX\n                    || inject_step == event_idx as u64\n                    || (inject_step == 0 && !injected_once))\n            {\n                if let Some(mut mr) = patched.memory_record {\n                    match &mut mr {\n                        MemoryRecordEnum::Read(r) => {\n                            r.prev_chunk = r.chunk;\n                            r.prev_timestamp = BABYBEAR_P - 16;\n                        }\n                        MemoryRecordEnum::Write(w) => {\n                            w.prev_chunk = w.chunk;\n                            w.prev_timestamp = BABYBEAR_P - 16;\n                        }\n                    }\n                    patched.memory_record = Some(mr);\n                    injected_once = true;\n                }\n            }\n            let cols: &mut MemoryChipValueCols<_> = row.borrow_mut();\n            self.event_to_row(&patched, cols, &mut vec![]);\n        }\n",
    )
    path.write_text(c)


def _patch_init_final_traces(path: Path) -> None:
    c = path.read_text()
    if "pico.audit_timestamp.mem_row_wraparound" in c:
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
        "                } = memory_events[i];\n                if inject_kind.as_deref() == Some(\"pico.audit_timestamp.mem_row_wraparound\")\n                    && (inject_step == u64::MAX\n                        || inject_step == i as u64\n                        || (inject_step == 0 && !injected_once))\n                {\n                    timestamp = BABYBEAR_P - 8;\n                    injected_once = true;\n                }\n\n                let mut row = [F::ZERO; NUM_MEMORY_INITIALIZE_FINALIZE_COLS];\n",
    )
    c = _replace_once(
        c,
        "        let rows: Vec<[F; NUM_MEMORY_INITIALIZE_FINALIZE_COLS]> = (0..memory_events.len())\n            .into_par_iter()\n            .map(|i| {\n",
        "        let rows: Vec<[F; NUM_MEMORY_INITIALIZE_FINALIZE_COLS]> = (0..memory_events.len())\n            .map(|i| {\n",
    )
    path.write_text(c)


def apply(*, pico_install_path: Path, commit_or_branch: str) -> None:
    # Keep patch surface minimal and deterministic for the benchmark snapshot only.
    if commit_or_branch != PICO_BENCHMARK_45E74_COMMIT:
        return
    vm = pico_install_path / "vm" / "src" / "chips" / "chips" / "riscv_memory"
    _patch_columns(vm / "local" / "columns.rs")
    _patch_local_traces(vm / "local" / "traces.rs")
    _patch_local_constraints(vm / "local" / "constraints.rs")
    _patch_rw_traces(vm / "read_write" / "traces.rs")
    _patch_init_final_traces(vm / "initialize_finalize" / "traces.rs")

