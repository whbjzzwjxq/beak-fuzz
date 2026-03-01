import logging
import shutil
from pathlib import Path

from pico_fuzzer.settings import PICO_ZKVM_GIT_REPOSITORY, resolve_pico_commit
from zkvm_fuzzer_utils.git import (
    GitException,
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


def clone_and_checkout_pico(*, dest: Path, commit_or_branch: str) -> Path:
    resolved = resolve_pico_commit(commit_or_branch)
    dest = dest.expanduser().resolve()

    if dest.exists() and not is_git_repository(dest):
        shutil.rmtree(dest)

    if not is_git_repository(dest):
        logger.info("cloning pico repo to %s", dest)
        git_clone_and_switch(dest, PICO_ZKVM_GIT_REPOSITORY, resolved)
    else:
        logger.info("resetting and switching pico repo @ %s", dest)
        try:
            git_reset_and_switch(dest, resolved)
        except GitException:
            # Interrupted/partial clones may not have a valid HEAD; recover by recloning.
            logger.warning("pico repo at %s is invalid; recloning", dest)
            shutil.rmtree(dest, ignore_errors=True)
            git_clone_and_switch(dest, PICO_ZKVM_GIT_REPOSITORY, resolved)

    return dest
