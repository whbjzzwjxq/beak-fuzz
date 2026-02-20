import logging
from pathlib import Path

from risc0_fuzzer.settings import RISC0_ZKVM_GIT_REPOSITORY
from zkvm_fuzzer_utils.git import (
    GitException,
    git_checkout,
    git_clean,
    git_clone_and_switch,
    git_fetch,
    git_reset_hard,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


class Risc0ManagerException(Exception):
    pass


def _find_git_lfs_pointers(root: Path) -> list[Path]:
    """
    Return a list of known-large RISC0 artifacts that are still Git LFS pointer files.

    Without Git LFS, these files will look like:
      version https://git-lfs.github.com/spec/v1
    and downstream build scripts may fail with confusing "InvalidData/Format" errors.
    """
    lfs_header = b"version https://git-lfs.github.com/spec/v1"
    candidates = list((root / "risc0" / "circuit" / "recursion-zkrs" / "src").glob("*.xz"))
    pointers: list[Path] = []
    for path in candidates:
        try:
            with path.open("rb") as f:
                prefix = f.read(len(lfs_header))
            if prefix == lfs_header:
                pointers.append(path)
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return pointers


def install_risc0(
    risc0_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,  # reserved for future parity
):
    logger.info(f"installing risc0 zkvm @ {risc0_install_path}")

    if commit_or_branch == "all":
        raise Risc0ManagerException("'all' is not a valid install target; pick a concrete commit")

    if not is_git_repository(risc0_install_path):
        logger.info(f"cloning risc0 repo to {risc0_install_path}")
        git_clone_and_switch(risc0_install_path, RISC0_ZKVM_GIT_REPOSITORY, commit_or_branch)
        return

    logger.info(f"resetting and switching risc0 repo @ {risc0_install_path}")
    git_reset_hard(risc0_install_path)
    git_clean(risc0_install_path)
    try:
        git_checkout(risc0_install_path, commit_or_branch)
    except GitException:
        git_fetch(risc0_install_path)
        git_checkout(risc0_install_path, commit_or_branch)

    pointers = _find_git_lfs_pointers(risc0_install_path)
    if pointers:
        example = pointers[0]
        raise Risc0ManagerException(
            "RISC0 repo contains Git LFS pointer files (git-lfs not pulled). "
            f"Example: {example}. "
            "Install git-lfs, then run `git lfs pull` in the risc0 repo checkout."
        )
