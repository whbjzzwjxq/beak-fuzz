#!/usr/bin/env python3
"""
Run a project-level benchmark campaign and summarize first-hit timing per semantic class.

Example:

  python scripts/profile_benchmark_campaign.py \
    --project-dir projects/sp1-811a3f2c03914088c7c9e1774266934a3f9f5359 \
    --timeout-ms 3000 \
    --initial-limit 1000 \
    --wall-timeout-sec 3600 \
    --output-json /tmp/sp1-811-campaign.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
STORAGE_DIR = REPO_ROOT / "storage" / "fuzzing_seeds"
DEFAULT_POLL_SEC = 0.5


@dataclass(frozen=True)
class CampaignConfig:
    project_dir: Path
    seeds_jsonl: Path
    timeout_ms: int
    initial_limit: int
    max_instructions: int
    semantic_window_before: int
    semantic_window_after: int
    semantic_step_stride: int
    semantic_max_trials_per_bucket: int
    oracle_precheck_max_steps: int | None


def project_prefix(project_dir: Path) -> tuple[str, str]:
    m = re.search(r"(openvm|sp1|pico)-([0-9a-f]{8,40})$", project_dir.name)
    if not m:
        raise SystemExit(f"cannot derive benchmark prefix from {project_dir}")
    return m.group(1), m.group(2)[:8]


def benchmark_glob(project_dir: Path) -> str:
    tag, short_commit = project_prefix(project_dir)
    return f"benchmark-{tag}-{short_commit}-seed2026-*.jsonl"


def build_release(project_dir: Path) -> None:
    subprocess.run(
        ["cargo", "build", "--release", "--bin", "beak-fuzz"],
        cwd=project_dir,
        check=True,
    )


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


def make_cmd(cfg: CampaignConfig) -> list[str]:
    binary = cfg.project_dir / "target" / "release" / "beak-fuzz"
    cmd = [
        str(binary),
        "--seeds-jsonl",
        str(cfg.seeds_jsonl),
        "--timeout-ms",
        str(cfg.timeout_ms),
        "--initial-limit",
        str(cfg.initial_limit),
        "--max-instructions",
        str(cfg.max_instructions),
        "--semantic-window-before",
        str(cfg.semantic_window_before),
        "--semantic-window-after",
        str(cfg.semantic_window_after),
        "--semantic-step-stride",
        str(cfg.semantic_step_stride),
        "--semantic-max-trials-per-bucket",
        str(cfg.semantic_max_trials_per_bucket),
    ]
    if cfg.oracle_precheck_max_steps is not None:
        cmd.extend(["--oracle-precheck-max-steps", str(cfg.oracle_precheck_max_steps)])
    return cmd


def summarize_bug(rec: dict[str, Any], elapsed_sec: float) -> dict[str, Any]:
    md = rec.get("metadata") or {}
    return {
        "elapsed_sec": round(elapsed_sec, 3),
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
        "timed_out": rec.get("timed_out"),
        "bucket_hits_sig": rec.get("bucket_hits_sig"),
    }


def record_bug(
    rec: dict[str, Any],
    elapsed_sec: float,
    first_bug_overall: dict[str, Any] | None,
    first_bug_by_class: dict[str, dict[str, Any]],
    first_underconstrained_overall: dict[str, Any] | None,
    first_underconstrained_by_class: dict[str, dict[str, Any]],
    bug_counts_by_class: dict[str, int],
    bug_counts_by_kind: dict[str, int],
    underconstrained_counts_by_class: dict[str, int],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    md = rec.get("metadata") or {}
    semantic_class = md.get("semantic_class") or "__non_semantic__"
    kind = md.get("kind") or "unknown"
    bug_counts_by_class[semantic_class] = bug_counts_by_class.get(semantic_class, 0) + 1
    bug_counts_by_kind[kind] = bug_counts_by_kind.get(kind, 0) + 1
    bug_summary = summarize_bug(rec, elapsed_sec)
    if first_bug_overall is None:
        first_bug_overall = bug_summary
    if semantic_class not in first_bug_by_class:
        first_bug_by_class[semantic_class] = bug_summary
    if kind == "underconstrained_candidate":
        underconstrained_counts_by_class[semantic_class] = (
            underconstrained_counts_by_class.get(semantic_class, 0) + 1
        )
        if first_underconstrained_overall is None:
            first_underconstrained_overall = bug_summary
        if semantic_class not in first_underconstrained_by_class:
            first_underconstrained_by_class[semantic_class] = bug_summary
    return first_bug_overall, first_underconstrained_overall


def run_campaign(
    cfg: CampaignConfig,
    wall_timeout_sec: float,
    build: bool,
    keep_artifacts: bool,
    stop_on_first_underconstrained: bool,
) -> dict[str, Any]:
    if build:
        build_release(cfg.project_dir)

    pattern = benchmark_glob(cfg.project_dir)
    before = set(STORAGE_DIR.glob(pattern))
    log_path = STORAGE_DIR / f".campaign-{cfg.project_dir.name}-{int(time.time())}.log"
    cmd = make_cmd(cfg)

    start = time.time()
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            cmd,
            cwd=cfg.project_dir,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    corpus_path: Path | None = None
    bugs_path: Path | None = None
    runs_path: Path | None = None
    runs_offset = 0
    bugs_offset = 0
    wall_timed_out = False
    terminated_on_underconstrained = False

    baseline_runs = 0
    semantic_runs = 0
    semantic_applied_runs = 0
    semantic_noop_runs = 0
    first_bug_overall: dict[str, Any] | None = None
    first_bug_by_class: dict[str, dict[str, Any]] = {}
    first_underconstrained_overall: dict[str, Any] | None = None
    first_underconstrained_by_class: dict[str, dict[str, Any]] = {}
    bug_counts_by_class: dict[str, int] = {}
    bug_counts_by_kind: dict[str, int] = {}
    underconstrained_counts_by_class: dict[str, int] = {}

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
                    md = rec.get("metadata") or {}
                    phase = md.get("phase")
                    if phase == "baseline":
                        baseline_runs += 1
                    elif phase == "semantic_search":
                        semantic_runs += 1
                        if md.get("semantic_injection_applied"):
                            semantic_applied_runs += 1
                        else:
                            semantic_noop_runs += 1

            if bugs_path is not None:
                bugs_offset, records = read_new_jsonl(bugs_path, bugs_offset)
                for rec in records:
                    first_bug_overall, first_underconstrained_overall = record_bug(
                        rec,
                        time.time() - start,
                        first_bug_overall,
                        first_bug_by_class,
                        first_underconstrained_overall,
                        first_underconstrained_by_class,
                        bug_counts_by_class,
                        bug_counts_by_kind,
                        underconstrained_counts_by_class,
                    )
                    kind = ((rec.get("metadata") or {}).get("kind")) or "unknown"
                    if kind == "underconstrained_candidate" and stop_on_first_underconstrained:
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

    if runs_path is not None:
        runs_offset, records = read_new_jsonl(runs_path, runs_offset)
        for rec in records:
            md = rec.get("metadata") or {}
            phase = md.get("phase")
            if phase == "baseline":
                baseline_runs += 1
            elif phase == "semantic_search":
                semantic_runs += 1
                if md.get("semantic_injection_applied"):
                    semantic_applied_runs += 1
                else:
                    semantic_noop_runs += 1

    if bugs_path is not None:
        bugs_offset, records = read_new_jsonl(bugs_path, bugs_offset)
        for rec in records:
            first_bug_overall, first_underconstrained_overall = record_bug(
                rec,
                time.time() - start,
                first_bug_overall,
                first_bug_by_class,
                first_underconstrained_overall,
                first_underconstrained_by_class,
                bug_counts_by_class,
                bug_counts_by_kind,
                underconstrained_counts_by_class,
            )

    runtime_sec = time.time() - start
    summary = {
        "project_dir": str(cfg.project_dir),
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
        "run_counts": {
            "baseline": baseline_runs,
            "semantic_total": semantic_runs,
            "semantic_applied": semantic_applied_runs,
            "semantic_noop": semantic_noop_runs,
        },
        "first_bug_overall": first_bug_overall,
        "first_bug_by_class": dict(sorted(first_bug_by_class.items())),
        "first_underconstrained_overall": first_underconstrained_overall,
        "first_underconstrained_by_class": dict(sorted(first_underconstrained_by_class.items())),
        "bug_counts_by_class": dict(sorted(bug_counts_by_class.items())),
        "bug_counts_by_kind": dict(sorted(bug_counts_by_kind.items())),
        "underconstrained_counts_by_class": dict(sorted(underconstrained_counts_by_class.items())),
        "log_path": str(log_path),
    }

    if not keep_artifacts:
        for path in (corpus_path, bugs_path, runs_path, log_path):
            if path and path.exists():
                path.unlink()

    return summary


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Profile a full benchmark campaign for one project.")
    ap.add_argument("--project-dir", type=Path, required=True, help="Project directory under beak/projects.")
    ap.add_argument(
        "--seeds-jsonl",
        type=Path,
        default=REPO_ROOT / "storage" / "fuzzing_seeds" / "initial.jsonl",
        help="Seed corpus JSONL.",
    )
    ap.add_argument("--timeout-ms", type=int, required=True, help="Per-run timeout in milliseconds.")
    ap.add_argument("--initial-limit", type=int, default=1000, help="Initial seed limit.")
    ap.add_argument("--max-instructions", type=int, default=32, help="Max instructions per seed.")
    ap.add_argument("--semantic-window-before", type=int, default=16, help="Semantic search window before anchor.")
    ap.add_argument("--semantic-window-after", type=int, default=64, help="Semantic search window after anchor.")
    ap.add_argument("--semantic-step-stride", type=int, default=1, help="Semantic search step stride.")
    ap.add_argument(
        "--semantic-max-trials-per-bucket",
        type=int,
        default=64,
        help="Semantic search max trials per bucket.",
    )
    ap.add_argument(
        "--oracle-precheck-max-steps",
        type=int,
        default=None,
        help="Optional oracle precheck max steps.",
    )
    ap.add_argument(
        "--wall-timeout-sec",
        type=float,
        default=3600.0,
        help="Maximum wall-clock time for the whole campaign.",
    )
    ap.add_argument(
        "--stop-on-first-underconstrained",
        action="store_true",
        help="Terminate the campaign once the first semantic underconstrained candidate appears.",
    )
    ap.add_argument("--no-build", action="store_true", help="Skip cargo build --release.")
    ap.add_argument("--keep-artifacts", action="store_true", help="Keep generated JSONL and logs.")
    ap.add_argument("--output-json", type=Path, help="Write summary JSON to this path.")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    cfg = CampaignConfig(
        project_dir=(REPO_ROOT / args.project_dir).resolve()
        if not args.project_dir.is_absolute()
        else args.project_dir.resolve(),
        seeds_jsonl=args.seeds_jsonl.resolve(),
        timeout_ms=args.timeout_ms,
        initial_limit=args.initial_limit,
        max_instructions=args.max_instructions,
        semantic_window_before=args.semantic_window_before,
        semantic_window_after=args.semantic_window_after,
        semantic_step_stride=args.semantic_step_stride,
        semantic_max_trials_per_bucket=args.semantic_max_trials_per_bucket,
        oracle_precheck_max_steps=args.oracle_precheck_max_steps,
    )
    summary = run_campaign(
        cfg,
        wall_timeout_sec=args.wall_timeout_sec,
        build=not args.no_build,
        keep_artifacts=args.keep_artifacts,
        stop_on_first_underconstrained=args.stop_on_first_underconstrained,
    )
    if args.output_json:
        args.output_json.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
