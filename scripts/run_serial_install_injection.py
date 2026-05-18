#!/usr/bin/env python3
"""Install + injection campaign runner for Beak."""

from __future__ import annotations

import argparse
import atexit
import copy
import csv
import json
import os
import queue
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
BEAK_ROOT = SCRIPT_DIR.parent
STORAGE_DIR = BEAK_ROOT / "storage" / "fuzzing_seeds"
IO_LOCK = threading.Lock()
INSTALL_LOCK = threading.Lock()


class ProcessReaper:
    def __init__(self) -> None:
        self.children: dict[int, subprocess.Popen[str]] = {}
        self.shutting_down = False

    def register(self, proc: subprocess.Popen[str]) -> None:
        self.children[proc.pid] = proc

    def unregister(self, proc: subprocess.Popen[str]) -> None:
        self.children.pop(proc.pid, None)

    def terminate_proc_group(
        self,
        proc: subprocess.Popen[str],
        *,
        grace_seconds: int,
        log: Any | None = None,
        reason: str,
    ) -> None:
        if proc.poll() is not None:
            return
        msg = f"[reaper] {reason}, sending SIGTERM to process group {proc.pid}\n"
        print(msg, end="")
        if log is not None:
            log.write(msg)
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

        deadline = time.monotonic() + grace_seconds
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.2)
        if proc.poll() is None:
            msg = f"[reaper] grace period expired, sending SIGKILL to process group {proc.pid}\n"
            print(msg, end="")
            if log is not None:
                log.write(msg)
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    def cleanup_all(self, *, grace_seconds: int = 5, reason: str = "runner exiting") -> None:
        if self.shutting_down:
            return
        self.shutting_down = True
        for proc in list(self.children.values()):
            self.terminate_proc_group(proc, grace_seconds=grace_seconds, reason=reason)
            self.unregister(proc)
        self.shutting_down = False


REAPER = ProcessReaper()


def install_signal_handlers(default_grace_seconds: int) -> None:
    def handle_signal(signum: int, _frame: Any) -> None:
        name = signal.Signals(signum).name
        REAPER.cleanup_all(grace_seconds=default_grace_seconds, reason=f"received {name}")
        raise SystemExit(128 + signum)

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, handle_signal)


atexit.register(lambda: REAPER.cleanup_all(reason="atexit cleanup"))

TARGETS: list[tuple[str, str]] = [
    ("openvm-336f1a47", "336f1a475e5aa3513c4c5a266399f4128c119bba"),
    ("openvm-d7eab708", "d7eab708f43487b2e7c00524ffd611f835e8e6b5"),
    ("openvm-f038f61d", "f038f61d21db3aecd3029e1a23ba1ba0bb314800"),
    ("pico-45e74ccd", "45e74ccd62758c6d67239913956e749adaba261c"),
    ("risc0-6f038bd", "6f038bd11ed725d7025687d163977d93ac1f82f9"),
    ("risc0-98387806", "98387806fe8348d87e32974468c6f35853356ad5"),
    ("risc0-c0db0713", "c0db0713671c8ec467b3efc26b22a0b0591897ff"),
    ("jolt-6c3b0b49", "6c3b0b49db0afceb967b33656176fa7a27e557b9"),
    ("jolt-d67f5a2a", "d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b"),
    ("jolt-e9caa235", "e9caa23565dbb13019afe61a2c95f51d1999e286"),
    ("nexus-41c6c608", "41c6c6080f46b97980053c47b078321225b4338a"),
    ("nexus-636ccb36", "636ccb360d0f4ae657ae4bb64e1e275ccec8826"),
    ("nexus-f1b895b8", "f1b895b868915fd4d0a794a5bc730e6cb8d840f6"),
    ("nexus-f2ad1265", "f2ad12652c39dc516a116447a53f8557f64a7f7d"),
    ("sp1-3561f006", "3561f0065dfe7d9f85144dd54bc5e9b10e5f7df1"),
    ("sp1-39ab52fc", "39ab52fce38172c9d23feed7248198dc14c164a9"),
    ("sp1-7f643da1", "7f643da16813af4c0fbaad4837cd7409386cf38c"),
    ("sp1-811a3f2c", "811a3f2c03914088c7c9e1774266934a3f9f5359"),
    ("sp1-fb38df2c", "fb38df2c4e963ef1d3a6f3be0ff62ea92bb3df13"),
]
TARGET_COMMITS = dict(TARGETS)

INSTALL_TARGETS = {
    "openvm": ("openvm-install", "COMMIT"),
    "pico": ("pico-install", "PICO_COMMIT"),
    "sp1": ("sp1-install", "SP1_COMMIT"),
    "jolt": ("jolt-install", "JOLT_COMMIT"),
    "nexus": ("nexus-install", "NEXUS_COMMIT"),
    "risc0": ("risc0-install", "RISC0_COMMIT"),
}

TARGET_CLASS = {
    "openvm-d7eab708": "generic_rv32_trace_only",
    "sp1-3561f006": "bespoke_sp1_uint256_div",
    "sp1-fb38df2c": "bespoke_sp1_recursion",
}


def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


def env_path(name: str, default: Path) -> Path:
    return Path(os.environ.get(name, str(default))).expanduser().resolve()


def parse_cpu_set(spec: str) -> list[int]:
    cpus: list[int] = []
    seen: set[int] = set()
    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if end < start:
                raise ValueError(f"invalid CPU range: {part}")
            values = range(start, end + 1)
        else:
            values = [int(part)]
        for cpu in values:
            if cpu < 0:
                raise ValueError(f"invalid negative CPU id: {cpu}")
            if cpu not in seen:
                cpus.append(cpu)
                seen.add(cpu)
    if not cpus:
        raise ValueError("CPU_SET resolved to an empty CPU pool")
    return cpus


def format_cpu_set(cpus: list[int]) -> str:
    if not cpus:
        raise ValueError("cannot format empty CPU set")
    ordered = sorted(cpus)
    ranges: list[str] = []
    start = prev = ordered[0]
    for cpu in ordered[1:]:
        if cpu == prev + 1:
            prev = cpu
            continue
        ranges.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = cpu
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(ranges)


def default_cpu_set() -> str:
    count = os.cpu_count() or 1
    return format_cpu_set(list(range(count)))


def default_parallel_vms(cpu_count: int, vm_cores: int) -> int:
    return max(1, cpu_count // max(1, vm_cores))


def build_worker_cpu_sets(cpu_pool: list[int], vm_cores: int, parallel_vms: int) -> list[list[int]]:
    if vm_cores <= 0:
        raise ValueError("VM_CORES must be positive")
    if parallel_vms <= 0:
        raise ValueError("PARALLEL_VMS must be positive")
    if len(cpu_pool) < vm_cores:
        if parallel_vms != 1:
            raise ValueError(
                f"CPU_SET has {len(cpu_pool)} CPUs, which is smaller than VM_CORES={vm_cores}; "
                "set PARALLEL_VMS=1 or reduce VM_CORES"
            )
        return [cpu_pool]
    required = parallel_vms * vm_cores
    if required > len(cpu_pool):
        raise ValueError(
            f"PARALLEL_VMS={parallel_vms} with VM_CORES={vm_cores} requires {required} CPUs, "
            f"but CPU_SET only contains {len(cpu_pool)} CPUs"
        )
    return [cpu_pool[i * vm_cores : (i + 1) * vm_cores] for i in range(parallel_vms)]


class Config:
    def __init__(self) -> None:
        self.cpu_set = os.environ.get("CPU_SET", default_cpu_set())
        self.cpu_pool = parse_cpu_set(self.cpu_set)
        legacy_threads = env_int("THREADS", 32)
        self.vm_cores = env_int("VM_CORES", legacy_threads)
        self.parallel_vms = env_int(
            "PARALLEL_VMS", default_parallel_vms(len(self.cpu_pool), self.vm_cores)
        )
        self.worker_cpu_sets = build_worker_cpu_sets(
            self.cpu_pool,
            self.vm_cores,
            self.parallel_vms,
        )
        self.threads = min(self.vm_cores, len(self.worker_cpu_sets[0]))
        self.soft_timeout_seconds = env_int("SOFT_TIMEOUT_SECONDS", 14400)
        self.kill_grace_seconds = env_int("KILL_GRACE_SECONDS", 30)
        self.uv_cache_dir = os.environ.get("UV_CACHE_DIR", "/tmp/uv-cache")
        self.arguzz_repo_cache = os.environ.get("ARGUZZ_REPO_CACHE", "/tmp/zkvm-repos")
        self.seeds_jsonl = env_path("SEEDS_JSONL", STORAGE_DIR / "initial.jsonl")
        self.memory_limit_gb = env_int("MEMORY_LIMIT_GB", 40)
        self.memory_limit_bytes = int(
            os.environ.get(
                "MEMORY_LIMIT_BYTES",
                str(self.memory_limit_gb * 1024 * 1024 * 1024),
            )
        )
        self.initial_limit = env_int("INITIAL_LIMIT", 0)
        self.mutation_iters = env_int("MUTATION_ITERS", env_int("ITERS", 0))
        self.max_instructions = env_int("MAX_INSTRUCTIONS", 256)
        self.oracle_precheck_max_steps = env_int("ORACLE_PRECHECK_MAX_STEPS", 32)
        self.semantic_window_before = env_int("SEMANTIC_WINDOW_BEFORE", 16)
        self.semantic_window_after = env_int("SEMANTIC_WINDOW_AFTER", 64)
        self.semantic_step_stride = env_int("SEMANTIC_STEP_STRIDE", 1)
        self.semantic_max_trials = env_int("SEMANTIC_MAX_TRIALS", 64)
        self.fast_test = os.environ.get("FAST_TEST", "0")
        self.run_root = env_path("RUN_ROOT", BEAK_ROOT / "out" / "serial-install-injection")
        self.log_root = env_path("LOG_ROOT", self.run_root / "logs")
        self.summary_path = env_path("SUMMARY_PATH", self.run_root / "summary.tsv")
        self.artifacts_path = env_path("ARTIFACTS_PATH", self.run_root / "artifacts.tsv")
        self.summary_json_path = env_path("SUMMARY_JSON_PATH", self.run_root / "summary.json")

    def for_worker_slot(self, slot_index: int) -> "Config":
        worker = copy.copy(self)
        cpus = self.worker_cpu_sets[slot_index]
        worker.cpu_set = format_cpu_set(cpus)
        worker.cpu_pool = cpus
        worker.worker_cpu_sets = [cpus]
        worker.parallel_vms = 1
        worker.threads = min(self.vm_cores, len(cpus))
        return worker

    def command_env(self) -> dict[str, str]:
        env = dict(os.environ)
        home_local_bin = Path.home() / ".local" / "bin"
        if home_local_bin.is_dir():
            env["PATH"] = f"{home_local_bin}:{env.get('PATH', '')}"
        env.update(
            {
                "UV_CACHE_DIR": self.uv_cache_dir,
                "ARGUZZ_REPO_CACHE": self.arguzz_repo_cache,
                "CARGO_BUILD_JOBS": str(self.threads),
                "RAYON_NUM_THREADS": str(self.threads),
                "OMP_NUM_THREADS": str(self.threads),
                "TOKIO_WORKER_THREADS": str(self.threads),
                "NUM_JOBS": str(self.threads),
                "CMAKE_BUILD_PARALLEL_LEVEL": str(self.threads),
                "FAST_TEST": self.fast_test,
            }
        )
        return env


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run_serial_install_injection.py",
        description="Run the Beak install + injection campaign.",
    )
    parser.add_argument("--print-commands", action="store_true")
    parser.add_argument("--skip-install", action="store_true")
    parser.add_argument("--only-commit", action="append", default=[])
    parser.add_argument("--exclude-commit", action="append", default=[])
    return parser.parse_args()


def require_cmd(cmd: str) -> None:
    if shutil.which(cmd) is None:
        raise SystemExit(f"missing required command: {cmd}")


def vm_name(target_id: str) -> str:
    return target_id.split("-", 1)[0]


def target_project_dir(target_id: str) -> Path:
    commit = TARGET_COMMITS[target_id]
    return BEAK_ROOT / "projects" / f"{vm_name(target_id)}-{commit}"


def target_artifact_prefix(target_id: str) -> str | None:
    if target_id in {"sp1-fb38df2c"}:
        return None
    return f"benchmark-{vm_name(target_id)}-{target_id.split('-', 1)[1]}"


def experiment_class(target_id: str) -> str:
    return TARGET_CLASS.get(target_id, "generic_rv32_benchmark")


def matches_filters(
    target_id: str,
    commit: str,
    only_commits: list[str],
    exclude_commits: list[str],
) -> bool:
    def matches(needle: str) -> bool:
        return (
            commit.startswith(needle)
            or needle.startswith(commit)
            or target_id.startswith(needle)
            or needle.startswith(target_id)
        )

    if only_commits and not any(matches(needle) for needle in only_commits):
        return False
    return not any(matches(needle) for needle in exclude_commits)


def command_prefix(config: Config) -> list[str]:
    prefix: list[str] = []
    if shutil.which("taskset"):
        prefix.extend(["taskset", "-c", config.cpu_set])
    if config.memory_limit_bytes > 0:
        prefix.extend(["prlimit", f"--as={config.memory_limit_bytes}"])
    return prefix


def build_install_cmd(target_id: str, config: Config) -> tuple[list[str], Path]:
    commit = TARGET_COMMITS[target_id]
    make_target, commit_var = INSTALL_TARGETS[vm_name(target_id)]
    cmd = command_prefix(config) + [
        "make",
        "-C",
        str(BEAK_ROOT),
        make_target,
        f"{commit_var}={commit}",
    ]
    return cmd, BEAK_ROOT


def build_run_cmd(target_id: str, config: Config) -> tuple[list[str], Path, dict[str, str]]:
    project_dir = target_project_dir(target_id)
    env = config.command_env()
    env["CARGO_TARGET_DIR"] = str(project_dir / "target")

    if target_id == "sp1-fb38df2c":
        script = (
            "set -euo pipefail; "
            "for scenario in load jump bneinc; do "
            "cargo run --release -q --bin beak-trace -- --scenario \"$scenario\" --json; "
            "done"
        )
        return command_prefix(config) + ["bash", "-lc", script], project_dir, env

    run_args = [
        "cargo",
        "run",
        "--release",
        "-q",
        "--bin",
        "beak-fuzz",
        "--",
        "--seeds-jsonl",
        str(config.seeds_jsonl),
        "--initial-limit",
        str(config.initial_limit),
        "--mutation-iters",
        str(config.mutation_iters),
        "--max-instructions",
        str(config.max_instructions),
    ]
    if target_id != "openvm-d7eab708":
        run_args.extend(
            [
                "--oracle-precheck-max-steps",
                str(config.oracle_precheck_max_steps),
            ]
        )
    run_args.extend(
        [
            "--semantic-window-before",
            str(config.semantic_window_before),
            "--semantic-window-after",
            str(config.semantic_window_after),
            "--semantic-step-stride",
            str(config.semantic_step_stride),
            "--semantic-max-trials-per-bucket",
            str(config.semantic_max_trials),
        ],
    )

    return (
        command_prefix(config) + run_args,
        project_dir,
        env,
    )


def quote_cmd(cmd: list[str]) -> str:
    return " ".join(shlex_quote(arg) for arg in cmd)


def shlex_quote(s: str) -> str:
    import shlex

    return shlex.quote(s)


def run_and_log(
    cmd: list[str],
    log_file: Path,
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int | None = None,
    grace_seconds: int = 30,
) -> int:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("w", encoding="utf-8", buffering=1) as log:
        cmd_line = f"[cmd] {quote_cmd(cmd)}\n"
        print(cmd_line, end="")
        log.write(cmd_line)
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            bufsize=1,
        )
        REAPER.register(proc)
        start = time.monotonic()
        assert proc.stdout is not None
        try:
            while True:
                ready, _, _ = select.select([proc.stdout], [], [], 1.0)
                if ready:
                    line = proc.stdout.readline()
                    if line:
                        print(line, end="")
                        log.write(line)
                if proc.poll() is not None:
                    rest = proc.stdout.read()
                    if rest:
                        print(rest, end="")
                        log.write(rest)
                    return proc.returncode
                if timeout_seconds is not None and time.monotonic() - start >= timeout_seconds:
                    REAPER.terminate_proc_group(
                        proc,
                        grace_seconds=grace_seconds,
                        log=log,
                        reason=f"{timeout_seconds}s reached",
                    )
                    rest = proc.stdout.read()
                    if rest:
                        print(rest, end="")
                        log.write(rest)
                    return 124
        except BaseException:
            REAPER.terminate_proc_group(
                proc,
                grace_seconds=grace_seconds,
                log=log,
                reason="runner exception",
            )
            raise
        finally:
            REAPER.unregister(proc)


def snapshot_target_artifacts(target_id: str) -> set[Path]:
    prefix = target_artifact_prefix(target_id)
    if prefix is None:
        return set()
    return set(STORAGE_DIR.glob(f"{prefix}-*.jsonl"))


def artifact_kind(path: Path) -> str:
    name = path.name
    if name.endswith("-corpus.jsonl"):
        return "corpus"
    if name.endswith("-runs.jsonl"):
        return "runs"
    if name.endswith("-bugs.jsonl"):
        return "bugs"
    return "unknown"


def append_artifacts(
    artifacts_path: Path,
    target_id: str,
    commit: str,
    before: set[Path],
    after: set[Path],
) -> None:
    new_paths = sorted(after - before)
    if not new_paths:
        return
    with IO_LOCK:
        with artifacts_path.open("a", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            for path in new_paths:
                writer.writerow([target_id, commit, artifact_kind(path), str(path)])


def append_summary(summary_path: Path, target_id: str, commit: str, status: str, detail: Path) -> None:
    with IO_LOCK:
        with summary_path.open("a", encoding="utf-8", newline="") as f:
            csv.writer(f, delimiter="\t").writerow([target_id, commit, status, str(detail)])


def run_target(target_id: str, config: Config, skip_install: bool) -> bool:
    commit = TARGET_COMMITS[target_id]
    project_dir = target_project_dir(target_id)
    install_log = config.log_root / f"install-{target_id}.log"
    run_log = config.log_root / f"run-{target_id}.log"
    env = config.command_env()

    print(f"== [{target_id}] start ==")
    print(f"   commit       : {commit}")
    print(f"   project_dir  : {project_dir}")
    print(f"   install_log  : {install_log}")
    print(f"   run_log      : {run_log}")

    if not skip_install:
        install_cmd, install_cwd = build_install_cmd(target_id, config)
        with INSTALL_LOCK:
            rc = run_and_log(install_cmd, install_log, cwd=install_cwd, env=env)
        if rc != 0:
            append_summary(config.summary_path, target_id, commit, "install_failed", install_log)
            print(f"== [{target_id}] install failed ==")
            return False
    else:
        print("   skip install : true")

    before = snapshot_target_artifacts(target_id)
    run_cmd, run_cwd, run_env = build_run_cmd(target_id, config)
    rc = run_and_log(
        run_cmd,
        run_log,
        cwd=run_cwd,
        env=run_env,
        timeout_seconds=config.soft_timeout_seconds,
        grace_seconds=config.kill_grace_seconds,
    )
    after = snapshot_target_artifacts(target_id)
    append_artifacts(config.artifacts_path, target_id, commit, before, after)

    if rc == 0:
        append_summary(config.summary_path, target_id, commit, "ok", run_log)
        print(f"== [{target_id}] completed before budget ==")
        return True
    if rc == 124:
        append_summary(config.summary_path, target_id, commit, "budget_reached", run_log)
        print(f"== [{target_id}] {config.soft_timeout_seconds}s budget reached ==")
        return True

    append_summary(config.summary_path, target_id, commit, "run_failed", run_log)
    print(f"== [{target_id}] run failed with exit code {rc} ==")
    return False


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                records.append({"__parse_error__": f"{path}:{line_no}: {exc}"})
                continue
            if isinstance(value, dict):
                records.append(value)
    return records


def inc(counter: dict[str, int], key: str) -> None:
    counter[key] = counter.get(key, 0) + 1


def empty_target_summary(row: dict[str, str]) -> dict[str, Any]:
    target = row.get("target") or ""
    return {
        "target": target,
        "commit": row.get("commit") or "",
        "status": row.get("status") or "",
        "detail": row.get("detail") or "",
        "experiment_class": experiment_class(target),
        "artifacts": {"corpus": [], "runs": [], "bugs": []},
        "run_counts": {
            "baseline": 0,
            "semantic_total": 0,
            "semantic_applied": 0,
            "semantic_noop": 0,
            "total": 0,
        },
        "bug_counts_by_class": {},
        "bug_counts_by_kind": {},
        "underconstrained_counts_by_class": {},
        "first_bug_overall": None,
        "first_bug_by_class": {},
        "first_underconstrained_overall": None,
        "first_underconstrained_by_class": {},
        "bespoke": None,
        "warnings": [],
    }


def concise_bug(rec: dict[str, Any]) -> dict[str, Any]:
    md = rec.get("metadata") or {}
    return {
        "elapsed_ms": rec.get("elapsed_ms"),
        "eval_duration_ms": rec.get("eval_duration_ms"),
        "phase": md.get("phase"),
        "kind": md.get("kind"),
        "semantic_class": md.get("semantic_class"),
        "trigger_bucket_id": md.get("trigger_bucket_id"),
        "inject_kind": md.get("inject_kind"),
        "inject_step": md.get("inject_step"),
        "attempt_index": md.get("attempt_index"),
        "semantic_injection_applied": md.get("semantic_injection_applied"),
        "seed_index": md.get("seed_index"),
        "label": md.get("label"),
        "source": md.get("source"),
        "backend_error": rec.get("backend_error"),
        "oracle_error": rec.get("oracle_error"),
        "bucket_hits_sig": rec.get("bucket_hits_sig"),
    }


def json_objects_from_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    decoder = json.JSONDecoder()
    out: list[dict[str, Any]] = []
    idx = 0
    while True:
        start = text.find("{", idx)
        if start < 0:
            break
        try:
            value, end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            idx = start + 1
            continue
        if isinstance(value, dict):
            out.append(value)
        idx = start + end
    return out


def summarize_jsonl_artifacts(item: dict[str, Any]) -> None:
    for path_s in item["artifacts"].get("runs", []):
        for rec in read_jsonl(Path(path_s)):
            if "__parse_error__" in rec:
                item["warnings"].append(rec["__parse_error__"])
                continue
            md = rec.get("metadata") or {}
            phase = md.get("phase")
            item["run_counts"]["total"] += 1
            if phase == "baseline":
                item["run_counts"]["baseline"] += 1
            elif phase == "semantic_search":
                item["run_counts"]["semantic_total"] += 1
                if md.get("semantic_injection_applied"):
                    item["run_counts"]["semantic_applied"] += 1
                else:
                    item["run_counts"]["semantic_noop"] += 1

    for path_s in item["artifacts"].get("bugs", []):
        for rec in read_jsonl(Path(path_s)):
            if "__parse_error__" in rec:
                item["warnings"].append(rec["__parse_error__"])
                continue
            md = rec.get("metadata") or {}
            semantic_class = md.get("semantic_class") or "__non_semantic__"
            kind = md.get("kind") or "unknown"
            inc(item["bug_counts_by_class"], semantic_class)
            inc(item["bug_counts_by_kind"], kind)
            bug = concise_bug(rec)
            if item["first_bug_overall"] is None:
                item["first_bug_overall"] = bug
            item["first_bug_by_class"].setdefault(semantic_class, bug)
            if kind == "underconstrained_candidate":
                inc(item["underconstrained_counts_by_class"], semantic_class)
                if item["first_underconstrained_overall"] is None:
                    item["first_underconstrained_overall"] = bug
                item["first_underconstrained_by_class"].setdefault(semantic_class, bug)


def summarize_bespoke(item: dict[str, Any]) -> None:
    log_path = Path(item["detail"])
    objects = [
        obj
        for obj in json_objects_from_log(log_path)
        if "underconstrained_candidate" in obj and "baseline" in obj and "injected" in obj
    ]
    scenarios: list[dict[str, Any]] = []
    underconstrained = 0
    diverged = 0
    for obj in objects:
        underconstrained += int(bool(obj.get("underconstrained_candidate")))
        diverged += int(bool(obj.get("diverged")))
        baseline = obj.get("baseline") or {}
        injected = obj.get("injected") or {}
        scenarios.append(
            {
                "scenario": baseline.get("scenario") or injected.get("scenario"),
                "diverged": obj.get("diverged"),
                "underconstrained_candidate": obj.get("underconstrained_candidate"),
                "inject_kind": injected.get("inject_kind"),
                "inject_step": injected.get("inject_step"),
                "proof_verified": injected.get("proof_verified"),
            }
        )
    item["bespoke"] = {
        "log_path": str(log_path),
        "scenario_count": len(scenarios),
        "diverged_count": diverged,
        "underconstrained_count": underconstrained,
        "scenarios": scenarios,
    }
    if not objects and log_path.exists():
        item["warnings"].append("no bespoke JSON scenario object found in run log")


def load_artifacts(config: Config, targets: list[dict[str, Any]]) -> None:
    by_target = {item["target"]: item for item in targets}
    if config.artifacts_path.exists():
        with config.artifacts_path.open("r", encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f, delimiter="\t"):
                item = by_target.get(row.get("target") or "")
                kind = row.get("kind") or ""
                path = row.get("path") or ""
                if item is not None and kind in item["artifacts"] and path:
                    item["artifacts"][kind].append(path)

    for item in targets:
        if any(item["artifacts"].values()):
            continue
        prefix = target_artifact_prefix(item["target"])
        if prefix is None:
            continue
        for kind in ("corpus", "runs", "bugs"):
            paths = sorted(
                STORAGE_DIR.glob(f"{prefix}-*-{kind}.jsonl"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            if paths:
                item["artifacts"][kind].append(str(paths[0]))
                item["warnings"].append(f"used latest {kind} artifact fallback")


def aggregate(items: list[dict[str, Any]]) -> dict[str, Any]:
    by_class: dict[str, dict[str, int]] = {}
    status_counts: dict[str, int] = {}
    for item in items:
        inc(status_counts, item["status"])
        cls = item["experiment_class"]
        acc = by_class.setdefault(
            cls,
            {
                "targets": 0,
                "baseline_runs": 0,
                "semantic_runs": 0,
                "semantic_applied": 0,
                "bugs": 0,
                "underconstrained": 0,
            },
        )
        acc["targets"] += 1
        acc["baseline_runs"] += item["run_counts"]["baseline"]
        acc["semantic_runs"] += item["run_counts"]["semantic_total"]
        acc["semantic_applied"] += item["run_counts"]["semantic_applied"]
        acc["bugs"] += sum(item["bug_counts_by_kind"].values())
        acc["underconstrained"] += sum(item["underconstrained_counts_by_class"].values())
        if item["bespoke"]:
            acc["underconstrained"] += int(item["bespoke"].get("underconstrained_count") or 0)
    return {
        "status_counts": dict(sorted(status_counts.items())),
        "by_experiment_class": {key: by_class[key] for key in sorted(by_class)},
    }


def write_structured_summary(config: Config) -> None:
    if not config.summary_path.exists():
        raise SystemExit(f"summary TSV not found: {config.summary_path}")
    with config.summary_path.open("r", encoding="utf-8", newline="") as f:
        targets = [empty_target_summary(row) for row in csv.DictReader(f, delimiter="\t")]

    load_artifacts(config, targets)
    for item in targets:
        if item["experiment_class"].startswith("bespoke_"):
            summarize_bespoke(item)
        else:
            summarize_jsonl_artifacts(item)

    result = {
        "run_root": str(config.run_root),
        "summary_tsv": str(config.summary_path),
        "artifacts_tsv": str(config.artifacts_path) if config.artifacts_path.exists() else None,
        "aggregate": aggregate(targets),
        "targets": targets,
    }
    config.summary_json_path.parent.mkdir(parents=True, exist_ok=True)
    config.summary_json_path.write_text(
        json.dumps(result, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def print_header(config: Config, targets: list[str]) -> None:
    print("Beak install+injection campaign")
    print(f"  targets         : {len(targets)}")
    print(f"  cpu_pool        : {config.cpu_set}")
    print(f"  vm_cores        : {config.vm_cores}")
    print(f"  parallel_vms    : {config.parallel_vms}")
    print(
        "  worker_cpu_sets : "
        + ", ".join(format_cpu_set(cpus) for cpus in config.worker_cpu_sets)
    )
    print(f"  timeout_s       : {config.soft_timeout_seconds}")
    print(f"  grace_s         : {config.kill_grace_seconds}")
    print(f"  initial_limit   : {config.initial_limit}")
    print(f"  mutation_iters  : {config.mutation_iters}")
    print(f"  max_instructions: {config.max_instructions}")
    print(f"  oracle_precheck : {config.oracle_precheck_max_steps}")
    print(f"  sem_before      : {config.semantic_window_before}")
    print(f"  sem_after       : {config.semantic_window_after}")
    print(f"  sem_stride      : {config.semantic_step_stride}")
    print(f"  sem_max_trials  : {config.semantic_max_trials}")
    print(f"  fast_test       : {config.fast_test}")
    print(f"  seeds_jsonl     : {config.seeds_jsonl}")
    print(f"  mem_limit       : {config.memory_limit_gb}G ({config.memory_limit_bytes} bytes)")
    print(f"  run_root        : {config.run_root}")


def print_target_commands(target_id: str, config: Config) -> None:
    worker_config = config.for_worker_slot(0)
    install_cmd, _ = build_install_cmd(target_id, worker_config)
    run_cmd, _, _ = build_run_cmd(target_id, worker_config)
    print(f"[{target_id}] install")
    print(quote_cmd(install_cmd))
    print(f"[{target_id}] run")
    print(quote_cmd(run_cmd))


def run_filtered_targets(filtered: list[str], config: Config, skip_install: bool) -> bool:
    if not filtered:
        return True

    worker_count = min(config.parallel_vms, len(filtered))
    if worker_count <= 1:
        worker_config = config.for_worker_slot(0)
        overall_ok = True
        for target_id in filtered:
            if not run_target(target_id, worker_config, skip_install):
                overall_ok = False
        return overall_ok

    tasks: queue.Queue[tuple[int, str] | None] = queue.Queue()
    for index, target_id in enumerate(filtered):
        tasks.put((index, target_id))
    for _ in range(worker_count):
        tasks.put(None)

    results = [False] * len(filtered)
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def worker(slot_index: int) -> None:
        worker_config = config.for_worker_slot(slot_index)
        print(
            f"[worker {slot_index}] cpu_set={worker_config.cpu_set} "
            f"threads={worker_config.threads}"
        )
        while True:
            item = tasks.get()
            try:
                if item is None:
                    return
                index, target_id = item
                results[index] = run_target(target_id, worker_config, skip_install)
            except BaseException as exc:
                with errors_lock:
                    errors.append(exc)
                return
            finally:
                tasks.task_done()

    threads = [
        threading.Thread(target=worker, args=(slot_index,), name=f"beak-campaign-{slot_index}")
        for slot_index in range(worker_count)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    if errors:
        raise errors[0]
    return all(results)


def main() -> int:
    args = parse_args()
    try:
        config = Config()
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    install_signal_handlers(config.kill_grace_seconds)

    for cmd in ("bash", "cargo", "make", "prlimit"):
        require_cmd(cmd)
    if not args.skip_install:
        require_cmd("uv")
    if not config.seeds_jsonl.exists():
        print(f"seed file not found: {config.seeds_jsonl}", file=sys.stderr)
        return 1

    filtered = [
        target_id
        for target_id, commit in TARGETS
        if matches_filters(target_id, commit, args.only_commit, args.exclude_commit)
    ]
    print_header(config, filtered)

    if args.print_commands:
        for target_id in filtered:
            print_target_commands(target_id, config)
        return 0

    config.summary_path.parent.mkdir(parents=True, exist_ok=True)
    config.artifacts_path.parent.mkdir(parents=True, exist_ok=True)
    config.summary_json_path.parent.mkdir(parents=True, exist_ok=True)
    with config.summary_path.open("w", encoding="utf-8", newline="") as f:
        csv.writer(f, delimiter="\t").writerow(["target", "commit", "status", "detail"])
    with config.artifacts_path.open("w", encoding="utf-8", newline="") as f:
        csv.writer(f, delimiter="\t").writerow(["target", "commit", "kind", "path"])

    overall_ok = run_filtered_targets(filtered, config, args.skip_install)

    print(f"Summary written to {config.summary_path}")
    try:
        write_structured_summary(config)
        print(f"Structured summary written to {config.summary_json_path}")
    except Exception as exc:
        print(f"structured summary failed: {exc}", file=sys.stderr)
        overall_ok = False
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
