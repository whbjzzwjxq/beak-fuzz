import logging
import os
import re
import resource
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import psutil

logger = logging.getLogger("fuzzer")

# ---------------------------------------------------------------------------- #
#                               Helper Functions                               #
# ---------------------------------------------------------------------------- #


# build a table mapping all non-printable characters to None
LINE_BREAK_CHARACTERS = set(["\n", "\r"])
NO_PRINT_TRANS_TABLE = {
    i: None
    for i in range(0, sys.maxunicode + 1)
    if not chr(i).isprintable() and not chr(i) in LINE_BREAK_CHARACTERS
}


# ---------------------------------------------------------------------------- #


def make_printable(data: str) -> str:
    """Replace non-printable characters in a string."""
    return data.translate(NO_PRINT_TRANS_TABLE)


# ---------------------------------------------------------------------------- #


def make_utf8(data: bytes | None) -> str:
    return "" if data is None else data.decode("utf-8", errors="ignore")


# ---------------------------------------------------------------------------- #


def stdout_and_stderr_to_printable(
    stdout_bytes: bytes | None, stderr_bytes: bytes | None
) -> tuple[str, str]:
    stdout, stdin = [make_printable(make_utf8(x)) for x in [stdout_bytes, stderr_bytes]]
    return (stdout, stdin)


# ---------------------------------------------------------------------------- #


def generate_preexec_fn_memory_limit(limit_memory: int | None) -> Callable[[], Any] | None:
    if limit_memory is None:
        return None
    max_virtual_memory = limit_memory * 1024 * 1024  # limit_memory in MB
    return lambda: resource.setrlimit(
        resource.RLIMIT_AS, (max_virtual_memory, resource.RLIM_INFINITY)
    )


# ---------------------------------------------------------------------------- #


def remove_ansi_escape_sequences(string: str) -> str:
    ansi_escape_pattern = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]")
    return ansi_escape_pattern.sub("", string)


# ---------------------------------------------------------------------------- #
#                            Execution Status Class                            #
# ---------------------------------------------------------------------------- #


@dataclass
class ExecStatus:
    command: str
    stdout: str
    stderr: str
    stdout_raw: bytes | None
    stderr_raw: bytes | None
    returncode: int
    delta_time: float
    is_timeout: bool = False
    env: dict[str, str] | None = None
    cwd: Path | None = None

    def is_failure(self):
        return not self.returncode == 0

    def is_failure_strict(self):
        return self.is_failure() or len(self.stderr) > 0

    def __str__(self):
        return f"""
command   : {self.command}
returncode: {self.returncode}
stdout:
{self.stdout}
stderr:
{self.stderr}
time: {self.delta_time}s
"""

    def to_script(self, ignore_cwd: bool = False) -> str:
        script_lines = ["#!/usr/bin/env bash", ""]
        if self.cwd and ignore_cwd is False:
            script_lines.append(f"cd {self.cwd.absolute()}")
        env_prefix = ""
        if self.env:
            env_prefix = (" ".join(f"{key}='{val}'" for key, val in self.env.items())) + " "
        script_lines.append(f"{env_prefix}{self.command}")
        script_lines.append("")
        return "\n".join(script_lines)


# ---------------------------------------------------------------------------- #
#                       Core Command Invocation Function                       #
# ---------------------------------------------------------------------------- #


def invoke_command(
    command: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
    memory: int | None = None,
    is_log_debug: bool = True,
    explicit_clean_zombies=False,
) -> ExecStatus:

    # ------------------------- debug initial information ------------------------ #

    logger.info("run command: " + " ".join(command))
    logger.debug(f"  - cwd     : {cwd}")
    logger.debug(f"  - env     : {env}")
    logger.debug(f"  - timeout : {timeout}")
    logger.debug(f"  - memory  : {memory}")

    # ------------ combine current environment with passed environment ----------- #

    combined_env = None
    if env is not None:
        combined_env = os.environ.copy()
        for key in env:
            combined_env[key] = env[key]

    # ----------------- preprocessing for zombie process cleanup ----------------- #

    pre_call_active_children = None
    if explicit_clean_zombies:
        pre_call_active_children = set(p.pid for p in psutil.Process().children(recursive=True))

    # ------------------------------ call subprocess ----------------------------- #

    start_time = time.time()
    is_timeout = False
    try:
        complete_proc = subprocess.run(
            command,
            close_fds=True,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=-1,
            cwd=cwd,
            preexec_fn=generate_preexec_fn_memory_limit(memory),
            timeout=timeout,
            env=combined_env,
        )
        stdout_bytes, stderr_bytes = complete_proc.stdout, complete_proc.stderr
        returncode = complete_proc.returncode
    except subprocess.TimeoutExpired as timeErr:
        stdout_bytes, stderr_bytes = timeErr.stdout, timeErr.stderr
        returncode = 124  # timeout return status
        is_timeout = True

    end_time = time.time()
    delta_time = end_time - start_time

    # ------------------------------ process output ------------------------------ #

    stdout, stderr = stdout_and_stderr_to_printable(stdout_bytes, stderr_bytes)
    command_as_str = " ".join(command)

    # --------------------------- debug process output --------------------------- #

    logger.info(f"  => exit {returncode}")
    if is_log_debug:
        logger.debug("========== START STDOUT ==========")
        logger.debug(stdout)
        logger.debug("=========== END STDOUT ===========")

        logger.debug("========== START STDERR ==========")
        logger.debug(stderr)
        logger.debug("=========== END STDERR ===========")

    # ---------------------- build execute status and return --------------------- #

    status = ExecStatus(
        command_as_str,
        stdout,
        stderr,
        stdout_bytes,
        stderr_bytes,
        returncode,
        delta_time,
        is_timeout,
        env,
        cwd,
    )

    # ----------------- postprocessing for zombie process cleanup ---------------- #

    if explicit_clean_zombies:
        assert pre_call_active_children is not None, "unexpected value of child process list"

        post_call_active_children = psutil.Process().children(recursive=True)
        possible_zombies = [
            p for p in post_call_active_children if p.pid not in pre_call_active_children
        ]

        for possible_zombie in possible_zombies:
            z_pid = possible_zombie.pid
            logger.debug(f"possible zombie detected, waiting for {z_pid} ...")
            try:
                if possible_zombie.status() == psutil.STATUS_ZOMBIE:
                    possible_zombie.wait()
                elif possible_zombie.is_running():
                    possible_zombie.terminate()
                    possible_zombie.wait(timeout=5)
            except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                logger.error(f"unable to clean up possible zombie {z_pid}")

    return status
