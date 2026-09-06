from pathlib import Path

import pytest

from risc0_fuzzer.passes.pass1_infrastructure import (
    _CONTROL_DONE_RECEIPT_COMMIT,
    _patch_control_done_receipt,
)


WITGEN_SOURCE = """use crate::execute::segment::Segment;

pub(crate) struct WitnessGenerator<H: Hal> {
    marker: H,
}

fn build(segment: &Segment, cycles: usize) {
        assert!(cycles <= 1 << segment.po2, "cycles <= 1 << segment.po2");
}
"""


def _witgen_path(root: Path) -> Path:
    return root / "risc0/circuit/rv32im/src/prove/witgen/mod.rs"


def test_control_done_receipt_patch_is_scoped_and_idempotent(tmp_path: Path) -> None:
    witgen = _witgen_path(tmp_path)
    witgen.parent.mkdir(parents=True)
    witgen.write_text(WITGEN_SOURCE, encoding="utf-8")

    _patch_control_done_receipt(
        risc0_install_path=tmp_path,
        commit_or_branch=_CONTROL_DONE_RECEIPT_COMMIT,
    )
    once = witgen.read_text(encoding="utf-8")
    _patch_control_done_receipt(
        risc0_install_path=tmp_path,
        commit_or_branch=_CONTROL_DONE_RECEIPT_COMMIT,
    )

    assert witgen.read_text(encoding="utf-8") == once
    assert once.count("BEAK-INSERT: risc0-control-done-executed-receipt") == 1
    assert "manifested_cycles != actual_cycles" in once
    assert "BEAK_RISC0_CONTROL_DONE_RECEIPT_ARMED" in once
    assert "BEAK_RISC0_EXECUTED_EXCEPTION_RECEIPT" in once
    assert 'const BACKEND: &str = "risc0"' in once
    assert _CONTROL_DONE_RECEIPT_COMMIT in once
    assert 'const TRACE_SOURCE: &str = "segment_finalization"' in once


def test_control_done_receipt_patch_requires_the_exact_snapshot(tmp_path: Path) -> None:
    witgen = _witgen_path(tmp_path)
    witgen.parent.mkdir(parents=True)
    witgen.write_text(WITGEN_SOURCE, encoding="utf-8")

    _patch_control_done_receipt(
        risc0_install_path=tmp_path,
        commit_or_branch=f"{_CONTROL_DONE_RECEIPT_COMMIT}-unrelated",
    )

    assert witgen.read_text(encoding="utf-8") == WITGEN_SOURCE


def test_control_done_receipt_patch_rejects_a_stale_partial_marker(tmp_path: Path) -> None:
    witgen = _witgen_path(tmp_path)
    witgen.parent.mkdir(parents=True)
    witgen.write_text(
        WITGEN_SOURCE.replace(
            "pub(crate) struct WitnessGenerator",
            "// BEAK-INSERT: risc0-control-done-executed-receipt\n"
            "pub(crate) struct WitnessGenerator",
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="marker is stale or patch is incomplete"):
        _patch_control_done_receipt(
            risc0_install_path=tmp_path,
            commit_or_branch=_CONTROL_DONE_RECEIPT_COMMIT,
        )


def test_control_done_receipt_patch_fails_closed_when_assertion_moves(tmp_path: Path) -> None:
    witgen = _witgen_path(tmp_path)
    witgen.parent.mkdir(parents=True)
    witgen.write_text(
        WITGEN_SOURCE.replace("cycles <= 1 << segment.po2", "cycles < 1 << segment.po2"),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="receipt anchor missing"):
        _patch_control_done_receipt(
            risc0_install_path=tmp_path,
            commit_or_branch=_CONTROL_DONE_RECEIPT_COMMIT,
        )
