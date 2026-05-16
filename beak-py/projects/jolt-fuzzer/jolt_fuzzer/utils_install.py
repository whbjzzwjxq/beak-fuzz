import logging
import shutil
from pathlib import Path

from jolt_fuzzer.settings import (
    JOLT_BINIUS_COMMIT,
    JOLT_BINIUS_GIT_REPOSITORY,
    JOLT_READWRITE_SIZING_COMMIT,
    JOLT_ZKVM_GIT_REPOSITORY,
    resolve_jolt_commit,
)
from zkvm_fuzzer_utils.git import (
    GitException,
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


def clone_and_checkout_jolt(
    *, dest: Path, commit_or_branch: str, zkvm_src: Path | None = None
) -> Path:
    resolved = resolve_jolt_commit(commit_or_branch)
    dest = dest.expanduser().resolve()
    repo = str(zkvm_src.expanduser().resolve()) if zkvm_src else JOLT_ZKVM_GIT_REPOSITORY

    if dest.exists() and not is_git_repository(dest):
        shutil.rmtree(dest)

    if not is_git_repository(dest):
        logger.info("cloning jolt repo to %s", dest)
        git_clone_and_switch(dest, repo, resolved)
    else:
        logger.info("resetting and switching jolt repo @ %s", dest)
        try:
            git_reset_and_switch(dest, resolved)
        except GitException:
            logger.warning("jolt repo at %s is invalid; recloning", dest)
            shutil.rmtree(dest, ignore_errors=True)
            git_clone_and_switch(dest, repo, resolved)

    _patch_jolt_6c_for_current_rust(dest, resolved)
    return dest


def clone_and_checkout_jolt_auxiliary_sources(*, jolt_install_path: Path, commit_or_branch: str) -> None:
    """Materialize snapshot-specific auxiliary repos beside jolt-src.

    Jolt 6c depends on the moving Binius Git repository without a pinned rev in
    its Cargo.toml. Keep that checkout in beak-py/out rather than vendoring it
    under projects/.
    """

    resolved = resolve_jolt_commit(commit_or_branch)
    if resolved != JOLT_READWRITE_SIZING_COMMIT:
        return

    out_dir = jolt_install_path.parent
    binius_dest = (out_dir / "binius-src").expanduser().resolve()
    if binius_dest.exists() and not is_git_repository(binius_dest):
        shutil.rmtree(binius_dest)

    if not is_git_repository(binius_dest):
        logger.info("cloning binius repo to %s", binius_dest)
        git_clone_and_switch(binius_dest, JOLT_BINIUS_GIT_REPOSITORY, JOLT_BINIUS_COMMIT)
    else:
        logger.info("resetting and switching binius repo @ %s", binius_dest)
        try:
            git_reset_and_switch(binius_dest, JOLT_BINIUS_COMMIT)
        except GitException:
            logger.warning("binius repo at %s is invalid; recloning", binius_dest)
            shutil.rmtree(binius_dest, ignore_errors=True)
            git_clone_and_switch(binius_dest, JOLT_BINIUS_GIT_REPOSITORY, JOLT_BINIUS_COMMIT)

    _patch_binius_e587_for_current_rust(binius_dest)


def _patch_jolt_6c_for_current_rust(jolt_dest: Path, resolved_commit: str) -> None:
    if resolved_commit != JOLT_READWRITE_SIZING_COMMIT:
        return

    rv32i_vm = jolt_dest / "jolt-core" / "src" / "jolt" / "vm" / "rv32i_vm.rs"
    c = rv32i_vm.read_text()
    old = "impl<F, CS> Jolt<F, CS, C, M> for RV32IJoltVM"
    new = "impl<F, CS> Jolt<F, CS, 4, 65536> for RV32IJoltVM"
    if new in c:
        return
    if old not in c:
        raise RuntimeError(f"Jolt 6c RV32I VM compatibility anchor not found: {rv32i_vm}")
    rv32i_vm.write_text(c.replace(old, new, 1))


def _patch_binius_e587_for_current_rust(binius_dest: Path) -> None:
    binary_field = binius_dest / "crates" / "field" / "src" / "binary_field.rs"
    c = binary_field.read_text()
    old = """\t\timpl Step for $name {
\t\t\tfn steps_between(start: &Self, end: &Self) -> Option<usize> {
\t\t\t\tlet diff = end.val().checked_sub(start.val())?;
\t\t\t\tusize::try_from(diff).ok()
\t\t\t}
"""
    new = """\t\timpl Step for $name {
\t\t\tfn steps_between(start: &Self, end: &Self) -> (usize, Option<usize>) {
\t\t\t\tlet Some(diff) = end.val().checked_sub(start.val()) else {
\t\t\t\t\treturn (0, None);
\t\t\t\t};
\t\t\t\tlet Some(diff) = usize::try_from(diff).ok() else {
\t\t\t\t\treturn (usize::MAX, None);
\t\t\t\t};
\t\t\t\t(diff, Some(diff))
\t\t\t}
"""
    if new in c:
        return
    if old not in c:
        raise RuntimeError(f"Binius Step compatibility anchor not found: {binary_field}")
    binary_field.write_text(c.replace(old, new, 1))
