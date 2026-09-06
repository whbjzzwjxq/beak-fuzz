from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest import mock


RUNNER = Path(__file__).resolve().parents[1] / "run_serial_install_injection.py"
SPEC = importlib.util.spec_from_file_location("run_serial_install_injection", RUNNER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_campaign_runner_rejects_corpus_overlay_argument() -> None:
    with mock.patch.object(sys, "argv", [str(RUNNER), "--corpus-overlay", "carrier.jsonl"]):
        try:
            MODULE.parse_args()
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError("campaign-chosen corpus overlays must fail closed")


def test_campaign_runner_has_no_overlay_merge_surface() -> None:
    assert not hasattr(MODULE, "prepare_ordinary_corpus")
    assert "corpus_overlay" not in MODULE.parse_args.__code__.co_names


def test_ordinary_child_env_scrubs_adversarial_semantic_target_filters() -> None:
    hostile = {
        "PATH": os.environ.get("PATH", ""),
        "CPU_SET": "0-3",
        "BEAK_SEMANTIC_TARGET_BUCKET_PREFIX": "sem.only.this.case",
        "BEAK_SEMANTIC_TARGET_INJECT_KIND_PREFIX": "backend.only_this_hook",
        "BEAK_BENCHMARK_OUT_DIR": "/tmp/ordinary-output",
    }
    with mock.patch.dict(os.environ, hostile, clear=True):
        config = MODULE.Config()
        child_env = config.command_env()
        _, _, run_env = MODULE.build_run_cmd("openvm-336f1a47", config)

    for name in MODULE.ORDINARY_FORBIDDEN_CHILD_ENV:
        assert name not in child_env
        assert name not in run_env
    assert child_env["BEAK_BENCHMARK_OUT_DIR"] == "/tmp/ordinary-output"
    assert "BEAK_SEMANTIC_TARGET_BUCKET_PREFIX" not in " ".join(
        MODULE.build_run_cmd("openvm-336f1a47", config)[0]
    )


def test_documented_defaults_track_the_cpu_pool_and_remain_explicitly_overridable() -> None:
    minimal = {"PATH": os.environ.get("PATH", ""), "CPU_SET": "0-7"}
    with mock.patch.dict(os.environ, minimal, clear=True):
        defaults = MODULE.Config()
    assert defaults.parallel_vms == 1
    assert defaults.vm_cores == 32
    assert defaults.threads == 8
    assert defaults.memory_limit_bytes == 40 * 1024 * 1024 * 1024
    assert defaults.command_env()["CARGO_BUILD_JOBS"] == "8"
    assert defaults.command_env()["RAYON_NUM_THREADS"] == "8"
    assert defaults.command_env()["TOKIO_WORKER_THREADS"] == "8"
    assert defaults.command_env()["OMP_NUM_THREADS"] == "8"

    wide = {"PATH": os.environ.get("PATH", ""), "CPU_SET": "0-127"}
    with mock.patch.dict(os.environ, wide, clear=True):
        pooled = MODULE.Config()
    assert pooled.parallel_vms == 4
    assert pooled.vm_cores == 32
    assert pooled.threads == 32

    explicit = {
        **minimal,
        "VM_CORES": "4",
        "PARALLEL_VMS": "2",
        "MEMORY_LIMIT_GB": "15",
    }
    with mock.patch.dict(os.environ, explicit, clear=True):
        overridden = MODULE.Config()
    assert overridden.parallel_vms == 2
    assert overridden.vm_cores == 4
    assert overridden.memory_limit_bytes == 15 * 1024 * 1024 * 1024
