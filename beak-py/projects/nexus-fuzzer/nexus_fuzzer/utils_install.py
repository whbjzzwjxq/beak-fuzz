import logging
import shutil
from pathlib import Path

from nexus_fuzzer.settings import (
    NEXUS_MEMORY_SIZE_COMMIT,
    NEXUS_STWO_COMMIT,
    NEXUS_STWO_GIT_REPOSITORY,
    NEXUS_ZKVM_GIT_REPOSITORY,
    resolve_nexus_commit,
)
from zkvm_fuzzer_utils.git import (
    GitException,
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


def clone_and_checkout_nexus(
    *, dest: Path, commit_or_branch: str, zkvm_src: Path | None = None
) -> Path:
    resolved = resolve_nexus_commit(commit_or_branch)
    dest = dest.expanduser().resolve()
    repo = str(zkvm_src.expanduser().resolve()) if zkvm_src else NEXUS_ZKVM_GIT_REPOSITORY

    if dest.exists() and not is_git_repository(dest):
        shutil.rmtree(dest)

    if not is_git_repository(dest):
        logger.info("cloning nexus repo to %s", dest)
        git_clone_and_switch(dest, repo, resolved)
    else:
        logger.info("resetting and switching nexus repo @ %s", dest)
        try:
            git_reset_and_switch(dest, resolved)
        except GitException:
            logger.warning("nexus repo at %s is invalid; recloning", dest)
            shutil.rmtree(dest, ignore_errors=True)
            git_clone_and_switch(dest, repo, resolved)

    return dest


def clone_and_checkout_nexus_auxiliary_sources(*, nexus_install_path: Path, commit_or_branch: str) -> None:
    """Materialize snapshot-specific auxiliary repos beside nexus-src.

    Nexus 41c6 depends on a pinned stwo git revision. Keep that checkout in
    beak-py/out rather than vendoring it under projects/.
    """

    resolved = resolve_nexus_commit(commit_or_branch)
    if resolved != NEXUS_MEMORY_SIZE_COMMIT:
        return

    out_dir = nexus_install_path.parent
    stwo_dest = (out_dir / "stwo-src").expanduser().resolve()
    if stwo_dest.exists() and not is_git_repository(stwo_dest):
        shutil.rmtree(stwo_dest)

    if not is_git_repository(stwo_dest):
        logger.info("cloning stwo repo to %s", stwo_dest)
        git_clone_and_switch(stwo_dest, NEXUS_STWO_GIT_REPOSITORY, NEXUS_STWO_COMMIT)
    else:
        logger.info("resetting and switching stwo repo @ %s", stwo_dest)
        try:
            git_reset_and_switch(stwo_dest, NEXUS_STWO_COMMIT)
        except GitException:
            logger.warning("stwo repo at %s is invalid; recloning", stwo_dest)
            shutil.rmtree(stwo_dest, ignore_errors=True)
            git_clone_and_switch(stwo_dest, NEXUS_STWO_GIT_REPOSITORY, NEXUS_STWO_COMMIT)

    _patch_stwo_a194fad_for_current_rust(stwo_dest)


def _patch_stwo_a194fad_for_current_rust(stwo_dest: Path) -> None:
    lib_rs = stwo_dest / "crates" / "prover" / "src" / "lib.rs"
    c = lib_rs.read_text()
    c = c.replace("    get_many_mut,\n", "")
    c = c.replace("    trait_upcasting\n", "")
    c = c.replace("    slice_ptr_get,\n)", "    slice_ptr_get\n)")
    lib_rs.write_text(c)

    for path in [
        stwo_dest / "crates" / "prover" / "src" / "core" / "air" / "accumulation.rs",
        stwo_dest / "crates" / "prover" / "src" / "core" / "backend" / "simd" / "column.rs",
        stwo_dest / "crates" / "prover" / "src" / "examples" / "blake" / "round" / "constraints.rs",
        stwo_dest / "crates" / "prover" / "src" / "examples" / "blake" / "round" / "gen.rs",
    ]:
        path.write_text(path.read_text().replace(".get_many_mut(", ".get_disjoint_mut("))
