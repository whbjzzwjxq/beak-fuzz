import logging
import re
import shutil
from pathlib import Path

from openvm_fuzzer.settings import (
    OPENVM_ZKVM_GIT_REPOSITORY,
    resolve_openvm_commit,
)
from zkvm_fuzzer_utils.git import git_clone_and_switch, git_reset_and_switch, is_git_repository

logger = logging.getLogger("fuzzer")


def clone_and_checkout_openvm(*, dest: Path, commit_or_branch: str) -> Path:
    """
    Clone OpenVM from the canonical repository into `dest`, then checkout the resolved commit.
    If `dest` already exists as a git repo, reset local modifications and switch commits.
    """
    resolved = resolve_openvm_commit(commit_or_branch)
    dest = dest.expanduser().resolve()

    if dest.exists() and not is_git_repository(dest):
        shutil.rmtree(dest)

    if not is_git_repository(dest):
        logger.info("cloning openvm repo to %s", dest)
        git_clone_and_switch(dest, OPENVM_ZKVM_GIT_REPOSITORY, resolved)
    else:
        logger.info("resetting and switching openvm repo @ %s", dest)
        git_reset_and_switch(dest, resolved)

    return dest
