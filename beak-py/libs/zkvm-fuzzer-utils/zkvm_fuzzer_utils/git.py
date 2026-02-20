import logging
import subprocess
from pathlib import Path

logger = logging.getLogger("fuzzer")


class GitException(Exception):
    pass


def _run_git(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    cmd = ["git", *args]
    logger.info("run: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def _check_ok(proc: subprocess.CompletedProcess[str], *, msg: str) -> None:
    if proc.returncode == 0:
        return
    raise GitException(
        "\n".join(
            [
                msg,
                f"cmd: {proc.args}",
                f"exit: {proc.returncode}",
                "=== STDOUT ===",
                proc.stdout or "",
                "=== STDERR ===",
                proc.stderr or "",
            ]
        )
    )


def is_git_repository(path: Path) -> bool:
    # Worktrees use a `.git` *file* that points to the main repo's gitdir.
    return (path / ".git").exists()


def git_clone(repo_url: str, target: Path, branch: str | None = None) -> None:
    args = ["clone"]
    if branch:
        args += ["-b", branch]
    args += [repo_url, str(target)]
    proc = _run_git(args)
    _check_ok(proc, msg=f"Unable to clone {repo_url} to {target}")


def git_pull(repo_dir: Path) -> None:
    proc = _run_git(["pull"], cwd=repo_dir)
    _check_ok(proc, msg=f"Unable to pull {repo_dir}")


def git_fetch(repo_dir: Path) -> None:
    proc = _run_git(["fetch", "origin"], cwd=repo_dir)
    _check_ok(proc, msg=f"Unable to fetch origin for {repo_dir}")


def git_reset_hard(repo_dir: Path) -> None:
    proc = _run_git(["reset", "--hard", "HEAD"], cwd=repo_dir)
    _check_ok(proc, msg=f"Unable to hard reset {repo_dir}")


def git_clean(repo_dir: Path) -> None:
    # `git clean` refuses to delete nested git repos unless `-f` is passed twice.
    # We intentionally do NOT pass `-x` (keeps .gitignore'd files).
    proc = _run_git(["clean", "-fd"], cwd=repo_dir)
    if proc.returncode == 0:
        return

    proc2 = _run_git(["clean", "-ffd"], cwd=repo_dir)
    _check_ok(proc2, msg=f"Unable to clean {repo_dir}")


def git_checkout(repo_dir: Path, commit: str) -> None:
    proc = _run_git(["checkout", commit], cwd=repo_dir)
    _check_ok(proc, msg=f"Unable to checkout {commit} for {repo_dir}")


def git_clone_and_switch(repo_dir: Path, repo_url: str, commit: str = "main") -> None:
    git_clone(repo_url, repo_dir)
    git_checkout(repo_dir, commit)


def git_reset_and_switch(repo_dir: Path, commit: str = "main") -> None:
    git_reset_hard(repo_dir)
    git_clean(repo_dir)
    git_fetch(repo_dir)
    git_checkout(repo_dir, commit)
