import logging
from pathlib import Path

from sp1_fuzzer.settings import SP1_ZKVM_GIT_REPOSITORY, resolve_sp1_commit
from zkvm_fuzzer_utils.git import (
    GitException,
    git_checkout,
    git_clone_and_switch,
    git_clean,
    git_fetch,
    git_reset_hard,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


class SP1ManagerException(Exception):
    pass


def install_sp1(
    sp1_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,  # reserved for future parity
):
    logger.info(f"installing sp1 zkvm @ {sp1_install_path}")

    if commit_or_branch == "all":
        raise SP1ManagerException("'all' is not a valid install target; pick a concrete commit")

    commit_or_branch = resolve_sp1_commit(commit_or_branch)

    if not is_git_repository(sp1_install_path):
        logger.info(f"cloning sp1 repo to {sp1_install_path}")
        git_clone_and_switch(sp1_install_path, SP1_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        logger.info(f"resetting and switching sp1 repo @ {sp1_install_path}")
        git_reset_hard(sp1_install_path)
        git_clean(sp1_install_path)
        try:
            git_checkout(sp1_install_path, commit_or_branch)
        except GitException:
            # Fallback: fetch (network) in case the commit is not available locally yet.
            git_fetch(sp1_install_path)
            git_checkout(sp1_install_path, commit_or_branch)
