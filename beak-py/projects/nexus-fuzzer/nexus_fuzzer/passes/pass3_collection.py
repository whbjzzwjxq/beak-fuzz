from __future__ import annotations

from pathlib import Path

NEXUS_BENCHMARK_COMMIT = "636ccb360d0f4ae657ae4bb64e1e275ccec8826"


def _replace_once(path: Path, old: str, new: str) -> None:
    contents = path.read_text()
    if new in contents:
        return
    if old not in contents:
        raise RuntimeError(f"anchor not found in {path}: {old[:80]!r}")
    path.write_text(contents.replace(old, new, 1))


def _patch_load_store_semantic_injection(nexus_install_path: Path) -> None:
    path = nexus_install_path / "prover" / "src" / "chips" / "instructions" / "load_store.rs"
    helper_anchor = """const LOOKUP_TUPLE_SIZE: usize = 2 * WORD_SIZE_HALVED + 1;
stwo_prover::relation!(LoadStoreLookupElements, LOOKUP_TUPLE_SIZE);
"""
    helper = """const LOOKUP_TUPLE_SIZE: usize = 2 * WORD_SIZE_HALVED + 1;
stwo_prover::relation!(LoadStoreLookupElements, LOOKUP_TUPLE_SIZE);

// BEAK-INSERT: nexus.636ccb36.load_store.semantic_injection.helpers
const BEAK_NEXUS_INJECT_KIND_ENV: &str = "BEAK_NEXUS_INJECT_KIND";
const BEAK_NEXUS_INJECT_STEP_ENV: &str = "BEAK_NEXUS_INJECT_STEP";
const BEAK_NEXUS_INJECTION_APPLIED_ENV: &str = "BEAK_NEXUS_INJECTION_APPLIED";

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

fn beak_nexus_mutate_load_store_trace(
    traces: &mut TracesBuilder,
    row_idx: usize,
    is_load: bool,
) {
    if !is_load
        && beak_nexus_should_inject(
            "nexus.semantic.memory.store_load_payload_flow",
            row_idx,
        )
    {
        beak_nexus_mutate_byte_column(traces, row_idx, Ram1ValCur);
        beak_nexus_note_injection(
            "nexus.semantic.memory.store_load_payload_flow",
            row_idx,
            "load_store.ram1_val_cur",
        );
    }

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
    _replace_once(path, helper_anchor, helper)

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
    _replace_once(path, call_anchor, call)


def apply(*, nexus_install_path: Path, commit_or_branch: str) -> None:
    if commit_or_branch != NEXUS_BENCHMARK_COMMIT:
        return
    _patch_load_store_semantic_injection(nexus_install_path)
