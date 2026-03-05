import logging
import shutil
from pathlib import Path

from sp1_fuzzer.settings import SP1_ZKVM_GIT_REPOSITORY, resolve_sp1_commit
from zkvm_fuzzer_utils.git import (
    GitException,
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


def clone_and_checkout_sp1(*, dest: Path, commit_or_branch: str) -> Path:
    resolved = resolve_sp1_commit(commit_or_branch)
    dest = dest.expanduser().resolve()

    if dest.exists() and not is_git_repository(dest):
        shutil.rmtree(dest)

    if not is_git_repository(dest):
        logger.info("cloning sp1 repo to %s", dest)
        git_clone_and_switch(dest, SP1_ZKVM_GIT_REPOSITORY, resolved)
    else:
        logger.info("resetting and switching sp1 repo @ %s", dest)
        try:
            git_reset_and_switch(dest, resolved)
        except GitException:
            logger.warning("sp1 repo at %s is invalid; recloning", dest)
            shutil.rmtree(dest, ignore_errors=True)
            git_clone_and_switch(dest, SP1_ZKVM_GIT_REPOSITORY, resolved)

    return dest
