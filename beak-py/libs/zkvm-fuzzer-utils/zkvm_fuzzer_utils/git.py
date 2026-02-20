import logging
from pathlib import Path

from zkvm_fuzzer_utils.cmd import ExecStatus, invoke_command
from zkvm_fuzzer_utils.file import path_to_binary

GIT = path_to_binary("git")

logger = logging.getLogger("fuzzer")


# ---------------------------------------------------------------------------- #
#                                 Git Exception                                #
# ---------------------------------------------------------------------------- #


class GitException(Exception):
    pass


# ---------------------------------------------------------------------------- #
#                           Git Private Local Helper                           #
# ---------------------------------------------------------------------------- #


def __git_check_for_failure(status: ExecStatus, error_msg: str, exception_msg: str):
    if status.is_failure():
        logger.critical(error_msg)
        logger.info("=== STDOUT ===")
        logger.info(status.stdout)
        logger.info("=== STDERR ===")
        logger.info(status.stderr)
        logger.info("==============")
        # Include full command output in the exception so it is visible even when
        # logger output is not surfaced to the caller (common in CLI wrappers).
        raise GitException(f"{exception_msg}\n{status}")


# ---------------------------------------------------------------------------- #
#                             Git Helper Functions                             #
# ---------------------------------------------------------------------------- #


def is_git_repository(path: Path) -> bool:
    # Worktrees use a `.git` *file* that points to the main repo's gitdir.
    # Treat both as a git repository.
    return (path / ".git").exists()


# ---------------------------------------------------------------------------- #


def git_clone(repo_url: str, target: Path, branch: str | None = None):
    cmd = ["git", "clone"]
    if branch:
        cmd += ["-b", branch]
    cmd += [repo_url, str(target)]
    __git_check_for_failure(
        invoke_command(cmd),
        f"Unable to clone git repository {repo_url} to {target}",
        f"Unable to clone git repository {repo_url}",
    )


# ---------------------------------------------------------------------------- #


def git_pull(repo_dir: Path):
    __git_check_for_failure(
        invoke_command(["git", "pull"], cwd=repo_dir),
        f"Unable to pull git repository {repo_dir}",
        f"Unable to pull git repository {repo_dir}",
    )


# ---------------------------------------------------------------------------- #


def git_fetch(repo_dir: Path):
    __git_check_for_failure(
        invoke_command(["git", "fetch", "origin"], cwd=repo_dir),
        f"Unable to fetch git origin for repository {repo_dir}",
        f"Unable to fetch git origin for repository {repo_dir}",
    )


# ---------------------------------------------------------------------------- #


def git_reset_hard(repo_dir: Path):
    __git_check_for_failure(
        invoke_command(["git", "reset", "--hard", "HEAD"], cwd=repo_dir),
        f"Unable to hard reset git repository {repo_dir}",
        f"Unable to hard reset git repository {repo_dir}",
    )


# ---------------------------------------------------------------------------- #


def git_clean(repo_dir: Path):
    # `git clean` refuses to delete nested git repositories unless `-f` is passed twice.
    # This can happen after running tooling that vendors/clones repos inside the tree.
    #
    # IMPORTANT: We do NOT pass `-x` here, so entries ignored by `.gitignore`
    # are preserved.
    status = invoke_command(["git", "clean", "-fd"], cwd=repo_dir)
    if status.is_failure():
        status_retry = invoke_command(["git", "clean", "-ffd"], cwd=repo_dir)
        __git_check_for_failure(
            status_retry,
            f"Unable to clean files of git repository {repo_dir}",
            f"Unable to clean files of git repository {repo_dir}",
        )


# ---------------------------------------------------------------------------- #


def git_checkout(repo_dir: Path, commit: str):
    __git_check_for_failure(
        invoke_command(["git", "checkout", f"{commit}"], cwd=repo_dir),
        f"Unable to checkout git commit / branch {commit} for {repo_dir}",
        f"Unable to checkout git commit / branch {commit} for {repo_dir.name}",
    )


# ---------------------------------------------------------------------------- #
#                               Combined Actions                               #
# ---------------------------------------------------------------------------- #


def git_clone_and_switch(repo_dir: Path, repo_url: str, commit: str = "main"):
    git_clone(repo_url, repo_dir)
    git_checkout(repo_dir, commit)


# ---------------------------------------------------------------------------- #


def git_reset_and_switch(repo_dir: Path, commit: str = "main"):
    git_reset_hard(repo_dir)
    git_clean(repo_dir)
    git_fetch(repo_dir)
    git_checkout(repo_dir, commit)


# ---------------------------------------------------------------------------- #
