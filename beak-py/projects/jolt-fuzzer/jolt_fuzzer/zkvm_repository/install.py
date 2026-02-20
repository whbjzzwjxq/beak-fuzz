import logging
from pathlib import Path

from jolt_fuzzer.settings import JOLT_ZKVM_GIT_REPOSITORY
from zkvm_fuzzer_utils.file import replace_in_file
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


def install_jolt(
    jolt_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,  # reserved for future parity
):
    logger.info(f"installing jolt zkvm @ {jolt_install_path}")

    if commit_or_branch == "all":
        raise RuntimeError("'all' is not a valid install target; pick a concrete commit")

    if not is_git_repository(jolt_install_path):
        logger.info(f"cloning jolt repo to {jolt_install_path}")
        git_clone_and_switch(jolt_install_path, JOLT_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        logger.info(f"resetting and switching jolt repo @ {jolt_install_path}")
        git_reset_hard(jolt_install_path)
        git_clean(jolt_install_path)
        try:
            git_checkout(jolt_install_path, commit_or_branch)
        except GitException:
            git_fetch(jolt_install_path)
            git_checkout(jolt_install_path, commit_or_branch)

    if enable_zkvm_modification:
        raise RuntimeError("zkvm modification not wired for jolt in beak-fuzz yet")

    # Required hotfix for a few snapshots: pin the twist-shout dependency to a commit.
    if commit_or_branch in [
        "0582b2aa4a33944506d75ce891db7cf090814ff6",
        "57ea518d6d9872fb221bf6ac97df1456a5494cf2",
        "20ac6eb526af383e7b597273990b5e4b783cc2a6",
        "70c77337426615b67191b301e9175e2bb093830d",
    ] and (jolt_install_path / "Cargo.lock").is_file():
        logger.info("Pin 'dev/twist-shout' to commit efc56e0d2f1129257a35c078b13dd017aeceff91")
        replace_in_file(
            jolt_install_path / "Cargo.lock",
            [
                (
                    r"\?branch=dev%2Ftwist-shout\)",
                    "?branch=dev%2Ftwist-shout#efc56e0d2f1129257a35c078b13dd017aeceff91)",
                ),
            ],
        )
