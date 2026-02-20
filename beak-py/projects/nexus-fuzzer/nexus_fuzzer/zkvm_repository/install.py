import logging
from pathlib import Path

from nexus_fuzzer.settings import NEXUS_ZKVM_GIT_REPOSITORY, resolve_nexus_commit
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


def install_nexus(
    nexus_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,  # reserved for future parity
):
    logger.info(f"installing nexus zkvm @ {nexus_install_path}")

    if commit_or_branch == "all":
        raise RuntimeError("'all' is not a valid install target; pick a concrete commit")

    commit_or_branch = resolve_nexus_commit(commit_or_branch)

    if not is_git_repository(nexus_install_path):
        logger.info(f"cloning nexus repo to {nexus_install_path}")
        git_clone_and_switch(nexus_install_path, NEXUS_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        logger.info(f"resetting and switching nexus repo @ {nexus_install_path}")
        git_reset_hard(nexus_install_path)
        git_clean(nexus_install_path)
        try:
            git_checkout(nexus_install_path, commit_or_branch)
        except GitException:
            git_fetch(nexus_install_path)
            git_checkout(nexus_install_path, commit_or_branch)

    if enable_zkvm_modification:
        raise RuntimeError("zkvm modification not wired for nexus in beak-fuzz yet")
