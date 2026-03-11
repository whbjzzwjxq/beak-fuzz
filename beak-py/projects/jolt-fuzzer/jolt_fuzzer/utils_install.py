import logging
import shutil
from pathlib import Path

from jolt_fuzzer.settings import JOLT_ZKVM_GIT_REPOSITORY, resolve_jolt_commit
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

    return dest
