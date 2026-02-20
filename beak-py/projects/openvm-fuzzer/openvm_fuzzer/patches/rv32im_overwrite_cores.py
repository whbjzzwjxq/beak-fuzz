from pathlib import Path

from openvm_fuzzer.patches.injection_sources import (
    openvm_extensions_rv32im_circuit_src_auipc_core_rs,
    openvm_extensions_rv32im_circuit_src_base_alu_core_rs,
    openvm_extensions_rv32im_circuit_src_divrem_core_rs,
    openvm_extensions_rv32im_circuit_src_load_sign_extend_core_rs,
    openvm_extensions_rv32im_circuit_src_loadstore_core_rs,
)
from openvm_fuzzer.settings import (
    OPENVM_BENCHMARK_336F_COMMIT,
    OPENVM_BENCHMARK_F038_COMMIT,
    OPENVM_BENCHMARK_REGZERO_COMMIT,
    resolve_openvm_commit,
)
from zkvm_fuzzer_utils.file import overwrite_file


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _overwrite_rv32im_cores(openvm_install_path=openvm_install_path, commit_or_branch=commit_or_branch)


def _overwrite_rv32im_cores(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    resolved_commit = resolve_openvm_commit(commit_or_branch)
    snapshot_commits = {OPENVM_BENCHMARK_REGZERO_COMMIT, OPENVM_BENCHMARK_336F_COMMIT, OPENVM_BENCHMARK_F038_COMMIT}

    # NOTE: this is done before all assertions are replaced! This is intentional!
    if resolved_commit in snapshot_commits:
        return

    overwrite_file(
        openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "base_alu" / "core.rs",
        openvm_extensions_rv32im_circuit_src_base_alu_core_rs(resolved_commit),
    )
    overwrite_file(
        openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "auipc" / "core.rs",
        openvm_extensions_rv32im_circuit_src_auipc_core_rs(resolved_commit),
    )
    overwrite_file(
        openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "loadstore" / "core.rs",
        openvm_extensions_rv32im_circuit_src_loadstore_core_rs(resolved_commit),
    )
    overwrite_file(
        openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "divrem" / "core.rs",
        openvm_extensions_rv32im_circuit_src_divrem_core_rs(resolved_commit),
    )
    overwrite_file(
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "load_sign_extend"
        / "core.rs",
        openvm_extensions_rv32im_circuit_src_load_sign_extend_core_rs(resolved_commit),
    )

