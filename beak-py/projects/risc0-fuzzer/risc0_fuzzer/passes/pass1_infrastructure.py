from __future__ import annotations

import shutil
from pathlib import Path


_CONTROL_DONE_RECEIPT_COMMIT = "6f038bd11ed725d7025687d163977d93ac1f82f9"


def _patch_control_done_receipt(*, risc0_install_path: Path, commit_or_branch: str) -> None:
    if commit_or_branch != _CONTROL_DONE_RECEIPT_COMMIT:
        return

    witgen_mod = (
        risc0_install_path
        / "risc0"
        / "circuit"
        / "rv32im"
        / "src"
        / "prove"
        / "witgen"
        / "mod.rs"
    )
    contents = witgen_mod.read_text(encoding="utf-8")
    marker = "// BEAK-INSERT: risc0-control-done-executed-receipt"
    if marker in contents:
        required_fragments = (
            "fn beak_record_control_done_capacity_receipt(segment: &Segment, actual_cycles: u64)",
            "beak_record_control_done_capacity_receipt(segment, cycles as u64);",
            'const ARMED_ENV: &str = "BEAK_RISC0_CONTROL_DONE_RECEIPT_ARMED";',
            'const RECEIPT_ENV: &str = "BEAK_RISC0_EXECUTED_EXCEPTION_RECEIPT";',
            "if cycles > 1 << segment.po2 {",
        )
        if contents.count(marker) != 1 or any(
            contents.count(fragment) != 1 for fragment in required_fragments
        ):
            raise RuntimeError(
                "Risc0 6f038bd ControlDone receipt marker is stale or patch is incomplete"
            )
        return

    anchor = """        assert!(cycles <= 1 << segment.po2, "cycles <= 1 << segment.po2");
"""
    replacement = """        // BEAK-INSERT: risc0-control-done-executed-receipt
        if cycles > 1 << segment.po2 {
            beak_record_control_done_capacity_receipt(segment, cycles as u64);
        }
        assert!(cycles <= 1 << segment.po2, "cycles <= 1 << segment.po2");
"""
    if anchor not in contents:
        raise RuntimeError(
            "Risc0 6f038bd ControlDone receipt anchor missing from prove/witgen/mod.rs"
        )

    helper_anchor = """pub(crate) struct WitnessGenerator<H: Hal> {
"""
    helper = """fn beak_record_control_done_capacity_receipt(segment: &Segment, actual_cycles: u64) {
    const ARMED_ENV: &str = "BEAK_RISC0_CONTROL_DONE_RECEIPT_ARMED";
    const RECEIPT_ENV: &str = "BEAK_RISC0_EXECUTED_EXCEPTION_RECEIPT";
    const CONTROL_DONE_CYCLES: u64 = 2;
    const BACKEND: &str = "risc0";
    const COMMIT: &str = "6f038bd11ed725d7025687d163977d93ac1f82f9";
    const TRACE_SOURCE: &str = "segment_finalization";

    let armed_segment = std::env::var(ARMED_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok());
    if armed_segment != Some(segment.index) {
        return;
    }

    let capacity_cycles = 1u64.checked_shl(segment.po2).unwrap_or(u64::MAX);
    let user_cycles = segment.suspend_cycle as u64;
    let pager_cycles = segment.paging_cycles as u64;
    let lookup_table_cycles = crate::execute::platform::LOOKUP_TABLE_CYCLES as u64;
    let Some(accounted_cycles) = user_cycles
        .checked_add(pager_cycles)
        .and_then(|value| value.checked_add(lookup_table_cycles))
    else {
        return;
    };
    let Some(required_cycles) = accounted_cycles.checked_add(CONTROL_DONE_CYCLES) else {
        return;
    };
    let Some(manifested_cycles) = accounted_cycles.checked_add(1) else {
        return;
    };
    if accounted_cycles > capacity_cycles
        || required_cycles <= capacity_cycles
        || manifested_cycles != actual_cycles
    {
        return;
    }
    let overflow_cycles = required_cycles - capacity_cycles;
    let receipt = format!(
        concat!(
            "{{\\\"effect\\\":\\\"control_done_capacity\\\",",
            "\\\"obligation_id\\\":\\\"pd2\\\",",
            "\\\"cell_id\\\":\\\"pd2.just_over\\\",",
            "\\\"stage\\\":\\\"risc0.segment.control_done_capacity\\\",",
            "\\\"step\\\":{},\\\"context\\\":{{",
            "\\\"backend\\\":\\\"{}\\\",\\\"commit\\\":\\\"{}\\\",",
            "\\\"trace_source\\\":\\\"{}\\\",",
            "\\\"segment_idx\\\":{},\\\"segment_po2\\\":{},",
            "\\\"capacity_cycles\\\":{},\\\"user_cycles\\\":{},",
            "\\\"pager_cycles\\\":{},\\\"lookup_table_cycles\\\":{},",
            "\\\"accounted_cycles\\\":{},\\\"control_done_cycles_required\\\":{},",
            "\\\"required_cycles\\\":{},\\\"overflow_cycles\\\":{},",
            "\\\"actual_trace_cycles\\\":{},\\\"manifested_control_done_cycles\\\":1,",
            "\\\"accounted_fits\\\":true,\\\"required_exceeds\\\":true}}}}"
        ),
        segment.index,
        BACKEND,
        COMMIT,
        TRACE_SOURCE,
        segment.index,
        segment.po2,
        capacity_cycles,
        user_cycles,
        pager_cycles,
        lookup_table_cycles,
        accounted_cycles,
        CONTROL_DONE_CYCLES,
        required_cycles,
        overflow_cycles,
        actual_cycles,
    );
    std::env::set_var(RECEIPT_ENV, receipt);
}

"""
    if helper_anchor not in contents:
        raise RuntimeError(
            "Risc0 6f038bd ControlDone helper anchor missing from prove/witgen/mod.rs"
        )
    contents = contents.replace(helper_anchor, helper + helper_anchor, 1)
    contents = contents.replace(anchor, replacement, 1)
    witgen_mod.write_text(contents, encoding="utf-8")


def _assets_root() -> Path:
    return Path(__file__).resolve().parents[1] / "assets"


def apply(*, risc0_install_path: Path, commit_or_branch: str) -> None:
    asset_root = _assets_root()
    prove_dir = risc0_install_path / "risc0" / "circuit" / "rv32im" / "src" / "prove"
    prove_dir.mkdir(parents=True, exist_ok=True)

    witgen_mod = prove_dir / "witgen" / "mod.rs"
    flat_prove_rs = risc0_install_path / "risc0" / "circuit" / "rv32im" / "src" / "prove.rs"
    beak_src = asset_root / "risc0" / "circuit" / "rv32im" / "src" / "prove" / "beak.rs"
    if flat_prove_rs.exists():
        beak_src = (
            asset_root / "risc0" / "circuit" / "rv32im" / "src" / "prove" / "beak_m3.rs"
        )
    elif not commit_or_branch.startswith("98387806") and witgen_mod.exists():
        witgen_mod_contents = witgen_mod.read_text(encoding="utf-8")
        if "pub struct PreflightResults" not in witgen_mod_contents:
            beak_src = (
                asset_root / "risc0" / "circuit" / "rv32im" / "src" / "prove" / "beak_legacy.rs"
            )

    shutil.copyfile(beak_src, prove_dir / "beak.rs")
    _patch_control_done_receipt(
        risc0_install_path=risc0_install_path,
        commit_or_branch=commit_or_branch,
    )

    mod_rs = flat_prove_rs if flat_prove_rs.exists() else prove_dir / "mod.rs"
    contents = mod_rs.read_text(encoding="utf-8")
    marker = "pub mod beak;\n"
    if marker in contents:
        return

    anchor = "mod preflight;\n"
    if anchor in contents:
        contents = contents.replace(anchor, anchor + marker, 1)
        mod_rs.write_text(contents, encoding="utf-8")
        return

    anchor = "#[cfg(test)]\nmod tests;\n"
    if anchor in contents:
        contents = contents.replace(anchor, anchor + marker, 1)
    else:
        contents = marker + contents
    mod_rs.write_text(contents, encoding="utf-8")
