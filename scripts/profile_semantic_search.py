#!/usr/bin/env python3
"""
Profile benchmark-driven semantic search for curated beak cases.

The script:
1. Builds `beak-fuzz --release` for a project if needed.
2. Runs one or more inline-seed cases.
3. Tails the generated benchmark `runs.jsonl` / `bugs.jsonl` in real time.
4. Reports:
   - wall-clock runtime
   - baseline bucket signature
   - number of semantic-search attempts completed
   - first semantic bug timing / attempt / step (if any)
   - first underconstrained timing / attempt / step (if any)
   - whether the run hit a wall timeout

Typical usage:

  python scripts/profile_semantic_search.py --list-cases
  python scripts/profile_semantic_search.py --case openvm-336.o5
  python scripts/profile_semantic_search.py --case openvm-336.o5 --wall-timeout-sec 900
  python scripts/profile_semantic_search.py --case openvm-336.o5 --case openvm-336.o7
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
STORAGE_DIR = REPO_ROOT / "storage" / "fuzzing_seeds"
DEFAULT_POLL_SEC = 0.25


@dataclass(frozen=True)
class Case:
    name: str
    project_dir: str
    words: tuple[str, ...]
    timeout_ms: int
    semantic_window_before: int
    semantic_window_after: int
    semantic_step_stride: int
    semantic_max_trials: int
    oracle_precheck_max_steps: int | None = None


CASES: dict[str, Case] = {
    "openvm-336.o5": Case(
        name="openvm-336.o5",
        project_dir="projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba",
        words=("01400313", "14001073", "14002573", "00000393", "00754533"),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=400,
    ),
    "openvm-336.o7": Case(
        name="openvm-336.o7",
        project_dir="projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba",
        words=("0badc297", "00000293"),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=400,
    ),
    "openvm-336.o8": Case(
        name="openvm-336.o8",
        project_dir="projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba",
        words=(
            "00200313",
            "0ff00793",
            "00002297",
            "e6c28293",
            "0002c703",
            "0ff00393",
            "00774533",
        ),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=400,
    ),
    "openvm-336.o15": Case(
        name="openvm-336.o15",
        project_dir="projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba",
        words=("00700313", "800005b7", "fff00613", "02c5c733", "800003b7", "00774533"),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=400,
    ),
    "openvm-f038.o1": Case(
        name="openvm-f038.o1",
        project_dir="projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800",
        words=("14001073", "01400313", "14002573", "00000393", "00754533"),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=400,
    ),
    "openvm-f038.o5": Case(
        name="openvm-f038.o5",
        project_dir="projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800",
        words=(
            "00200313",
            "0ff00793",
            "00002297",
            "e6c28293",
            "0002c703",
            "0ff00393",
            "00774533",
        ),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=400,
    ),
    "openvm-f038.o7": Case(
        name="openvm-f038.o7",
        project_dir="projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800",
        words=(
            "00200313",
            "0ff00793",
            "00002297",
            "e6c28293",
            "0002c703",
            "0ff00393",
            "0ff00393",
        ),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=400,
    ),
    "openvm-f038.o25": Case(
        name="openvm-f038.o25",
        project_dir="projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800",
        words=("01400313", "14001073", "00000393", "14002573", "00754533"),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=400,
    ),
    "openvm-f038.o26": Case(
        name="openvm-f038.o26",
        project_dir="projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800",
        words=("01400313", "14001073", "14002573", "00000393", "00754533"),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=400,
    ),
    "openvm-f038.o51": Case(
        name="openvm-f038.o51",
        project_dir="projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800",
        words=(
            "00200313",
            "0ff00793",
            "00002297",
            "e6c28293",
            "0002c703",
            "0ff00393",
            "00774533",
        ),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=400,
    ),
    "sp1-811.timestamp": Case(
        name="sp1-811.timestamp",
        project_dir="projects/sp1-811a3f2c03914088c7c9e1774266934a3f9f5359",
        words=("00012183",),
        timeout_ms=30000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=0,
    ),
    "sp1-811.bool": Case(
        name="sp1-811.bool",
        project_dir="projects/sp1-811a3f2c03914088c7c9e1774266934a3f9f5359",
        words=("27654137", "00100193", "32312023"),
        timeout_ms=30000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=0,
    ),
    "sp1-7f64.s27": Case(
        name="sp1-7f64.s27",
        project_dir="projects/sp1-7f643da16813af4c0fbaad4837cd7409386cf38c",
        words=("00012183",),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=0,
    ),
    "sp1-7f64.s28": Case(
        name="sp1-7f64.s28",
        project_dir="projects/sp1-7f643da16813af4c0fbaad4837cd7409386cf38c",
        words=("00000073",),
        timeout_ms=15000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=0,
    ),
    "pico-45.timestamp": Case(
        name="pico-45.timestamp",
        project_dir="projects/pico-45e74ccd62758c6d67239913956e749adaba261c",
        words=("00012083",),
        timeout_ms=60000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=0,
    ),
    "pico-45.bool": Case(
        name="pico-45.bool",
        project_dir="projects/pico-45e74ccd62758c6d67239913956e749adaba261c",
        words=("00112023", "00012083"),
        timeout_ms=60000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=64,
        oracle_precheck_max_steps=0,
    ),
}


def project_prefix(project_dir: Path) -> tuple[str, str]:
    m = re.search(r"(openvm|sp1|pico)-([0-9a-f]{8,40})$", project_dir.name)
    if not m:
        raise SystemExit(f"cannot derive benchmark prefix from {project_dir}")
    return m.group(1), m.group(2)[:8]


def benchmark_glob(project_dir: Path) -> str:
    tag, short_commit = project_prefix(project_dir)
    return f"benchmark-{tag}-{short_commit}-seed2026-*.jsonl"


def build_release(project_dir: Path) -> None:
    cmd = ["cargo", "build", "--release", "--bin", "beak-fuzz"]
    subprocess.run(cmd, cwd=project_dir, check=True)


def kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.1)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def find_new_artifacts(pattern: str, before: set[Path]) -> tuple[Path | None, Path | None, Path | None]:
    new_paths = sorted(p for p in STORAGE_DIR.glob(pattern) if p not in before)
    corpus = next((p for p in new_paths if p.name.endswith("-corpus.jsonl")), None)
    bugs = next((p for p in new_paths if p.name.endswith("-bugs.jsonl")), None)
    runs = next((p for p in new_paths if p.name.endswith("-runs.jsonl")), None)
    return corpus, bugs, runs


def read_new_jsonl(path: Path, offset: int) -> tuple[int, list[dict[str, Any]]]:
    if not path.exists():
        return offset, []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        f.seek(offset)
        for line in f:
            s = line.strip()
            if not s:
                continue
            out.append(json.loads(s))
        offset = f.tell()
    return offset, out


def make_cmd(case: Case) -> list[str]:
    project_dir = REPO_ROOT / case.project_dir
    binary = project_dir / "target" / "release" / "beak-fuzz"
    cmd = [
        str(binary),
        "--bin",
        " ".join(case.words),
        "--timeout-ms",
        str(case.timeout_ms),
        "--semantic-window-before",
        str(case.semantic_window_before),
        "--semantic-window-after",
        str(case.semantic_window_after),
        "--semantic-step-stride",
        str(case.semantic_step_stride),
        "--semantic-max-trials-per-bucket",
        str(case.semantic_max_trials),
    ]
    if case.oracle_precheck_max_steps is not None:
        cmd.extend(["--oracle-precheck-max-steps", str(case.oracle_precheck_max_steps)])
    return cmd


def summarize_case(
    case: Case,
    wall_timeout_sec: float,
    stop_on_first_underconstrained: bool,
    build: bool,
    keep_artifacts: bool,
) -> dict[str, Any]:
    project_dir = REPO_ROOT / case.project_dir
    if build:
        build_release(project_dir)

    pattern = benchmark_glob(project_dir)
    before = set(STORAGE_DIR.glob(pattern))
    log_path = STORAGE_DIR / f".profile-{case.name}-{int(time.time())}.log"
    cmd = make_cmd(case)

    start = time.time()
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            cmd,
            cwd=project_dir,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    corpus_path: Path | None = None
    bugs_path: Path | None = None
    runs_path: Path | None = None
    runs_offset = 0
    bugs_offset = 0
    semantic_attempts = 0
    semantic_applied_attempts = 0
    semantic_noop_attempts = 0
    baseline: dict[str, Any] | None = None
    first_semantic_run: dict[str, Any] | None = None
    last_semantic_run: dict[str, Any] | None = None
    first_semantic_bug: dict[str, Any] | None = None
    first_semantic_bug_elapsed: float | None = None
    first_underconstrained: dict[str, Any] | None = None
    first_underconstrained_elapsed: float | None = None
    semantic_bug_counts_by_kind: dict[str, int] = {}
    wall_timed_out = False
    terminated_on_underconstrained = False

    try:
        while True:
            if corpus_path is None or bugs_path is None or runs_path is None:
                c, b, r = find_new_artifacts(pattern, before)
                corpus_path = corpus_path or c
                bugs_path = bugs_path or b
                runs_path = runs_path or r

            if runs_path is not None:
                runs_offset, records = read_new_jsonl(runs_path, runs_offset)
                for rec in records:
                    phase = ((rec.get("metadata") or {}).get("phase") or "")
                    if phase == "baseline" and baseline is None:
                        baseline = rec
                    if phase == "semantic_search":
                        semantic_attempts += 1
                        applied = bool(((rec.get("metadata") or {}).get("semantic_injection_applied")))
                        if applied:
                            semantic_applied_attempts += 1
                        else:
                            semantic_noop_attempts += 1
                        if first_semantic_run is None:
                            first_semantic_run = rec
                        last_semantic_run = rec

            if bugs_path is not None:
                bugs_offset, records = read_new_jsonl(bugs_path, bugs_offset)
                for rec in records:
                    md = rec.get("metadata") or {}
                    phase = md.get("phase") or ""
                    if phase != "semantic_search":
                        continue
                    kind = md.get("kind") or "unknown"
                    semantic_bug_counts_by_kind[kind] = semantic_bug_counts_by_kind.get(kind, 0) + 1
                    if first_semantic_bug is None:
                        first_semantic_bug = rec
                        first_semantic_bug_elapsed = time.time() - start
                    if kind == "underconstrained_candidate" and first_underconstrained is None:
                        first_underconstrained = rec
                        first_underconstrained_elapsed = time.time() - start
                        if stop_on_first_underconstrained:
                            terminated_on_underconstrained = True
                            kill_process_group(proc)
                            break

            if proc.poll() is not None:
                break
            if time.time() - start >= wall_timeout_sec:
                wall_timed_out = True
                kill_process_group(proc)
                break
            time.sleep(DEFAULT_POLL_SEC)
    finally:
        if proc.poll() is None:
            kill_process_group(proc)

    # Final drain after process exit/kill.
    if runs_path is not None:
        runs_offset, records = read_new_jsonl(runs_path, runs_offset)
        for rec in records:
            phase = ((rec.get("metadata") or {}).get("phase") or "")
            if phase == "baseline" and baseline is None:
                baseline = rec
            if phase == "semantic_search":
                semantic_attempts += 1
                applied = bool(((rec.get("metadata") or {}).get("semantic_injection_applied")))
                if applied:
                    semantic_applied_attempts += 1
                else:
                    semantic_noop_attempts += 1
                if first_semantic_run is None:
                    first_semantic_run = rec
                last_semantic_run = rec
    if bugs_path is not None:
        bugs_offset, records = read_new_jsonl(bugs_path, bugs_offset)
        for rec in records:
            md = rec.get("metadata") or {}
            phase = md.get("phase") or ""
            if phase == "semantic_search":
                kind = md.get("kind") or "unknown"
                semantic_bug_counts_by_kind[kind] = semantic_bug_counts_by_kind.get(kind, 0) + 1
                if first_semantic_bug is None:
                    first_semantic_bug = rec
                    first_semantic_bug_elapsed = time.time() - start
                if kind == "underconstrained_candidate" and first_underconstrained is None:
                    first_underconstrained = rec
                    first_underconstrained_elapsed = time.time() - start

    runtime_sec = time.time() - start
    log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""

    effective_steps = sorted(
        {
            int(m.group(1))
            for m in re.finditer(r"\[beak-witness-inject\].* step=(\d+)", log_text)
        }
    )
    prove_verify_ms = [
        int(m.group(1))
        for m in re.finditer(r"prove_verify_ms=(\d+)", log_text)
    ]

    summary = {
        "case": case.name,
        "project_dir": str(project_dir),
        "command": cmd,
        "runtime_sec": round(runtime_sec, 3),
        "wall_timeout_sec": wall_timeout_sec,
        "wall_timed_out": wall_timed_out,
        "terminated_on_underconstrained": terminated_on_underconstrained,
        "exit_code": proc.poll(),
        "artifacts": {
            "corpus": str(corpus_path) if corpus_path else None,
            "bugs": str(bugs_path) if bugs_path else None,
            "runs": str(runs_path) if runs_path else None,
        },
        "baseline": {
            "bucket_hits_sig": baseline.get("bucket_hits_sig") if baseline else None,
            "backend_error": baseline.get("backend_error") if baseline else None,
            "timed_out": baseline.get("timed_out") if baseline else None,
        },
        "semantic_attempts_completed": semantic_attempts,
        "semantic_applied_attempts": semantic_applied_attempts,
        "semantic_noop_attempts": semantic_noop_attempts,
        "first_semantic_run": {
            "attempt_index": ((first_semantic_run or {}).get("metadata") or {}).get("attempt_index"),
            "inject_step": ((first_semantic_run or {}).get("metadata") or {}).get("inject_step"),
            "semantic_class": ((first_semantic_run or {}).get("metadata") or {}).get("semantic_class"),
            "trigger_bucket_id": ((first_semantic_run or {}).get("metadata") or {}).get("trigger_bucket_id"),
            "semantic_injection_applied": ((first_semantic_run or {}).get("metadata") or {}).get("semantic_injection_applied"),
        }
        if first_semantic_run
        else None,
        "last_semantic_run": {
            "attempt_index": ((last_semantic_run or {}).get("metadata") or {}).get("attempt_index"),
            "inject_step": ((last_semantic_run or {}).get("metadata") or {}).get("inject_step"),
            "semantic_class": ((last_semantic_run or {}).get("metadata") or {}).get("semantic_class"),
            "trigger_bucket_id": ((last_semantic_run or {}).get("metadata") or {}).get("trigger_bucket_id"),
            "kind": ((last_semantic_run or {}).get("metadata") or {}).get("kind"),
            "semantic_injection_applied": ((last_semantic_run or {}).get("metadata") or {}).get("semantic_injection_applied"),
        }
        if last_semantic_run
        else None,
        "first_semantic_bug": {
            "elapsed_sec": round(first_semantic_bug_elapsed or 0.0, 3),
            "attempt_index": ((first_semantic_bug or {}).get("metadata") or {}).get("attempt_index"),
            "inject_step": ((first_semantic_bug or {}).get("metadata") or {}).get("inject_step"),
            "semantic_class": ((first_semantic_bug or {}).get("metadata") or {}).get("semantic_class"),
            "trigger_bucket_id": ((first_semantic_bug or {}).get("metadata") or {}).get("trigger_bucket_id"),
            "kind": ((first_semantic_bug or {}).get("metadata") or {}).get("kind"),
            "semantic_injection_applied": ((first_semantic_bug or {}).get("metadata") or {}).get("semantic_injection_applied"),
            "bucket_hits_sig": (first_semantic_bug or {}).get("bucket_hits_sig"),
            "backend_error": (first_semantic_bug or {}).get("backend_error"),
            "timed_out": (first_semantic_bug or {}).get("timed_out"),
        }
        if first_semantic_bug
        else None,
        "first_underconstrained": {
            "elapsed_sec": round(first_underconstrained_elapsed or 0.0, 3),
            "attempt_index": ((first_underconstrained or {}).get("metadata") or {}).get("attempt_index"),
            "inject_step": ((first_underconstrained or {}).get("metadata") or {}).get("inject_step"),
            "semantic_class": ((first_underconstrained or {}).get("metadata") or {}).get("semantic_class"),
            "trigger_bucket_id": ((first_underconstrained or {}).get("metadata") or {}).get("trigger_bucket_id"),
            "kind": ((first_underconstrained or {}).get("metadata") or {}).get("kind"),
            "semantic_injection_applied": ((first_underconstrained or {}).get("metadata") or {}).get("semantic_injection_applied"),
            "bucket_hits_sig": (first_underconstrained or {}).get("bucket_hits_sig"),
            "backend_error": (first_underconstrained or {}).get("backend_error"),
            "timed_out": (first_underconstrained or {}).get("timed_out"),
        }
        if first_underconstrained
        else None,
        "semantic_bug_counts_by_kind": dict(sorted(semantic_bug_counts_by_kind.items())),
        "effective_injection_steps": effective_steps,
        "prove_verify_ms": {
            "count": len(prove_verify_ms),
            "min": min(prove_verify_ms) if prove_verify_ms else None,
            "max": max(prove_verify_ms) if prove_verify_ms else None,
            "avg": round(sum(prove_verify_ms) / len(prove_verify_ms), 3) if prove_verify_ms else None,
        },
        "log_path": str(log_path),
    }

    if not keep_artifacts:
        for path in (corpus_path, bugs_path, runs_path, log_path):
            if path and path.exists():
                path.unlink()

    return summary


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Profile semantic-search benchmark cases.")
    ap.add_argument("--list-cases", action="store_true", help="List built-in case names and exit.")
    ap.add_argument("--case", action="append", default=[], help="Built-in case name. Can be repeated.")
    ap.add_argument(
        "--wall-timeout-sec",
        type=float,
        default=600.0,
        help="Maximum wall-clock time per case before killing the process.",
    )
    ap.add_argument(
        "--no-stop-on-first-underconstrained",
        action="store_true",
        help="Do not terminate the run when the first semantic underconstrained candidate appears.",
    )
    ap.add_argument(
        "--no-stop-on-first-semantic-bug",
        dest="no_stop_on_first_underconstrained",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    ap.add_argument(
        "--no-build",
        action="store_true",
        help="Skip `cargo build --release --bin beak-fuzz` before running cases.",
    )
    ap.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep generated benchmark JSONL and log files.",
    )
    ap.add_argument(
        "--output-json",
        type=Path,
        help="Write the full summary JSON array to this path.",
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    if args.list_cases:
        for name in sorted(CASES):
            case = CASES[name]
            print(
                f"{name}: {case.project_dir} words={' '.join(case.words)} "
                f"timeout_ms={case.timeout_ms} search={case.semantic_window_before}/{case.semantic_window_after}/{case.semantic_max_trials}"
            )
        return

    if not args.case:
        raise SystemExit("pass at least one --case, or use --list-cases")

    unknown = [name for name in args.case if name not in CASES]
    if unknown:
        raise SystemExit(f"unknown cases: {', '.join(unknown)}")

    summaries = []
    stop_on_underconstrained = not args.no_stop_on_first_underconstrained
    build = not args.no_build
    built_projects: set[str] = set()
    for name in args.case:
        case = CASES[name]
        project_key = case.project_dir
        case_build = build and project_key not in built_projects
        summaries.append(
            summarize_case(
                case,
                wall_timeout_sec=args.wall_timeout_sec,
                stop_on_first_underconstrained=stop_on_underconstrained,
                build=case_build,
                keep_artifacts=args.keep_artifacts,
            )
        )
        if case_build:
            built_projects.add(project_key)

    text = json.dumps(summaries, indent=2, sort_keys=True)
    if args.output_json:
        args.output_json.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
