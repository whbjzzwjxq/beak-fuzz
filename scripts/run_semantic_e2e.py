#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
STORAGE_DIR = REPO_ROOT / "storage" / "fuzzing_seeds"


@dataclass(frozen=True)
class Case:
    name: str
    project_dir: str
    words: tuple[str, ...]
    timeout_ms: int = 5000
    semantic_window_before: int = 16
    semantic_window_after: int = 64
    semantic_step_stride: int = 1
    semantic_max_trials: int = 12
    oracle_precheck_max_steps: int | None = None


CASES: dict[str, Case] = {
    "nexus.store_load_flow": Case(
        name="nexus.store_load_flow",
        project_dir="projects/nexus-636ccb360d0f4ae657ae4bb64e1e275ccec8826",
        words=("00100093", "00112023", "00012183"),
        timeout_ms=5000,
        semantic_window_before=16,
        semantic_window_after=64,
        semantic_step_stride=1,
        semantic_max_trials=12,
        oracle_precheck_max_steps=0,
    ),
}


@dataclass(frozen=True)
class Config:
    name: str
    project_dir: Path
    words: tuple[str, ...]
    timeout_ms: int
    semantic_window_before: int
    semantic_window_after: int
    semantic_step_stride: int
    semantic_max_trials: int
    oracle_precheck_max_steps: int | None


def project_prefix(project_dir: Path) -> tuple[str, str]:
    m = re.search(r"(openvm|sp1|pico|nexus|jolt)-([0-9a-f]{8,40})$", project_dir.name)
    if not m:
        raise SystemExit(f"cannot derive benchmark prefix from {project_dir}")
    return m.group(1), m.group(2)[:8]


def benchmark_glob(project_dir: Path) -> str:
    tag, short_commit = project_prefix(project_dir)
    return f"benchmark-{tag}-{short_commit}-seed2026-*.jsonl"


def build_release(project_dir: Path) -> None:
    subprocess.run(["cargo", "build", "--release", "--bin", "beak-fuzz"], cwd=project_dir, check=True)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s:
                records.append(json.loads(s))
    return records


def newest_artifacts(project_dir: Path, before: set[Path]) -> tuple[Path, Path, Path]:
    pattern = benchmark_glob(project_dir)
    new_paths = sorted(p for p in STORAGE_DIR.glob(pattern) if p not in before)
    corpus = next((p for p in new_paths if p.name.endswith("-corpus.jsonl")), None)
    bugs = next((p for p in new_paths if p.name.endswith("-bugs.jsonl")), None)
    runs = next((p for p in new_paths if p.name.endswith("-runs.jsonl")), None)
    if corpus is None or bugs is None or runs is None:
        raise SystemExit(f"missing benchmark artifacts for pattern {pattern}")
    return corpus, bugs, runs


def mode_from_inject_kind(kind: str | None) -> str | None:
    if not kind:
        return None
    m = re.search(r"mode=([^,:]+)", kind)
    return m.group(1) if m else None


def summarize_records(cfg: Config, cmd: list[str], corpus: Path, bugs: Path, runs: Path, runtime_sec: float) -> dict[str, Any]:
    run_records = read_jsonl(runs)
    bug_records = read_jsonl(bugs)

    baseline = next((r for r in run_records if ((r.get("metadata") or {}).get("phase") == "baseline")), None)
    semantic_runs = [r for r in run_records if ((r.get("metadata") or {}).get("phase") == "semantic_search")]
    applied_runs = [r for r in semantic_runs if bool((r.get("metadata") or {}).get("semantic_injection_applied"))]
    under_runs = [r for r in semantic_runs if bool((r.get("metadata") or {}).get("underconstrained_candidate"))]
    semantic_bug_records = [r for r in bug_records if ((r.get("metadata") or {}).get("phase") == "semantic_search")]

    bug_counts_by_kind: dict[str, int] = {}
    bug_counts_by_mode: dict[str, int] = {}
    for rec in bug_records:
        md = rec.get("metadata") or {}
        kind = str(md.get("kind") or "unknown")
        bug_counts_by_kind[kind] = bug_counts_by_kind.get(kind, 0) + 1
        mode = mode_from_inject_kind(md.get("inject_kind"))
        if mode:
            bug_counts_by_mode[mode] = bug_counts_by_mode.get(mode, 0) + 1

    first_applied = applied_runs[0] if applied_runs else None
    first_bug_record = semantic_bug_records[0] if semantic_bug_records else None
    first_bug = None
    if first_bug_record is not None:
        first_bug_kind = (first_bug_record.get("metadata") or {}).get("inject_kind")
        first_bug_step = (first_bug_record.get("metadata") or {}).get("inject_step")
        first_bug = next(
            (
                r
                for r in semantic_runs
                if ((r.get("metadata") or {}).get("inject_kind") == first_bug_kind)
                and ((r.get("metadata") or {}).get("inject_step") == first_bug_step)
            ),
            None,
        )
    first_under = under_runs[0] if under_runs else None
    last_semantic = semantic_runs[-1] if semantic_runs else None

    early_semantic = []
    for rec in semantic_runs[:12]:
        md = rec.get("metadata") or {}
        early_semantic.append(
            {
                "eval_id": rec.get("eval_id"),
                "inject_kind": md.get("inject_kind"),
                "mode": mode_from_inject_kind(md.get("inject_kind")),
                "inject_step": md.get("inject_step"),
                "semantic_injection_applied": md.get("semantic_injection_applied"),
                "underconstrained_candidate": md.get("underconstrained_candidate"),
                "is_bug": md.get("is_bug"),
                "backend_error": rec.get("backend_error"),
            }
        )

    summary = {
        "case": cfg.name,
        "project_dir": str(cfg.project_dir),
        "words": list(cfg.words),
        "command": cmd,
        "runtime_sec": round(runtime_sec, 3),
        "artifacts": {
            "corpus": str(corpus),
            "bugs": str(bugs),
            "runs": str(runs),
        },
        "baseline": {
            "bucket_hits_sig": baseline.get("bucket_hits_sig") if baseline else None,
            "backend_error": baseline.get("backend_error") if baseline else None,
            "timed_out": baseline.get("timed_out") if baseline else None,
        },
        "semantic_attempts": len(semantic_runs),
        "semantic_applied_attempts": len(applied_runs),
        "semantic_bug_records": len(bug_records),
        "bug_counts_by_kind": bug_counts_by_kind,
        "bug_counts_by_mode": bug_counts_by_mode,
        "first_applied": {
            "eval_id": first_applied.get("eval_id") if first_applied else None,
            "inject_kind": (first_applied.get("metadata") or {}).get("inject_kind") if first_applied else None,
            "inject_step": (first_applied.get("metadata") or {}).get("inject_step") if first_applied else None,
            "mode": mode_from_inject_kind((first_applied.get("metadata") or {}).get("inject_kind")) if first_applied else None,
        },
        "first_bug": {
            "eval_id": first_bug.get("eval_id") if first_bug else None,
            "kind": (first_bug_record.get("metadata") or {}).get("kind") if first_bug_record else None,
            "inject_kind": (first_bug_record.get("metadata") or {}).get("inject_kind") if first_bug_record else None,
            "inject_step": (first_bug_record.get("metadata") or {}).get("inject_step") if first_bug_record else None,
            "mode": mode_from_inject_kind((first_bug_record.get("metadata") or {}).get("inject_kind")) if first_bug_record else None,
        },
        "first_underconstrained": {
            "eval_id": first_under.get("eval_id") if first_under else None,
            "inject_kind": (first_under.get("metadata") or {}).get("inject_kind") if first_under else None,
            "inject_step": (first_under.get("metadata") or {}).get("inject_step") if first_under else None,
            "mode": mode_from_inject_kind((first_under.get("metadata") or {}).get("inject_kind")) if first_under else None,
        },
        "last_semantic": {
            "eval_id": last_semantic.get("eval_id") if last_semantic else None,
            "inject_kind": (last_semantic.get("metadata") or {}).get("inject_kind") if last_semantic else None,
            "mode": mode_from_inject_kind((last_semantic.get("metadata") or {}).get("inject_kind")) if last_semantic else None,
        },
        "early_semantic_runs": early_semantic,
    }
    return summary


def make_cmd(cfg: Config) -> list[str]:
    binary = cfg.project_dir / "target" / "release" / "beak-fuzz"
    cmd = [
        str(binary),
        "--bin",
        " ".join(cfg.words),
        "--timeout-ms",
        str(cfg.timeout_ms),
        "--semantic-window-before",
        str(cfg.semantic_window_before),
        "--semantic-window-after",
        str(cfg.semantic_window_after),
        "--semantic-step-stride",
        str(cfg.semantic_step_stride),
        "--semantic-max-trials-per-bucket",
        str(cfg.semantic_max_trials),
    ]
    if cfg.oracle_precheck_max_steps is not None:
        cmd.extend(["--oracle-precheck-max-steps", str(cfg.oracle_precheck_max_steps)])
    return cmd


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run one end-to-end semantic benchmark case and emit a compact summary JSON.")
    ap.add_argument("--list-cases", action="store_true", help="List preset cases and exit.")
    ap.add_argument("--case", choices=sorted(CASES), help="Preset case to run.")
    ap.add_argument("--project-dir", help="Project directory relative to repo root or absolute path.")
    ap.add_argument("--bin-words", help="Space or comma separated hex words for an inline seed.")
    ap.add_argument("--word", action="append", default=[], help="Add one hex instruction word. Can be repeated.")
    ap.add_argument("--name", help="Case name for manual mode.")
    ap.add_argument("--timeout-ms", type=int, default=5000)
    ap.add_argument("--semantic-window-before", type=int, default=16)
    ap.add_argument("--semantic-window-after", type=int, default=64)
    ap.add_argument("--semantic-step-stride", type=int, default=1)
    ap.add_argument("--semantic-max-trials-per-bucket", type=int, default=12)
    ap.add_argument("--oracle-precheck-max-steps", type=int, default=None)
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--summary-json", help="Optional output path for summary JSON.")
    return ap.parse_args()


def make_config(args: argparse.Namespace) -> Config:
    if args.case:
        case = CASES[args.case]
        return Config(
            name=case.name,
            project_dir=(REPO_ROOT / case.project_dir).resolve(),
            words=case.words,
            timeout_ms=case.timeout_ms,
            semantic_window_before=case.semantic_window_before,
            semantic_window_after=case.semantic_window_after,
            semantic_step_stride=case.semantic_step_stride,
            semantic_max_trials=case.semantic_max_trials,
            oracle_precheck_max_steps=case.oracle_precheck_max_steps,
        )

    if not args.project_dir:
        raise SystemExit("manual mode requires --project-dir")

    project_dir = Path(args.project_dir)
    if not project_dir.is_absolute():
        project_dir = (REPO_ROOT / project_dir).resolve()

    raw_words: list[str] = []
    if args.bin_words:
        raw_words.extend(w for w in re.split(r"[\s,]+", args.bin_words.strip()) if w)
    raw_words.extend(args.word)
    if not raw_words:
        raise SystemExit("manual mode requires --bin-words or --word")

    words = tuple(w.lower().removeprefix("0x") for w in raw_words)
    for w in words:
        if not re.fullmatch(r"[0-9a-fA-F]{8}", w):
            raise SystemExit(f"invalid instruction word: {w}")

    return Config(
        name=args.name or f"manual.{project_dir.name}",
        project_dir=project_dir,
        words=words,
        timeout_ms=args.timeout_ms,
        semantic_window_before=args.semantic_window_before,
        semantic_window_after=args.semantic_window_after,
        semantic_step_stride=args.semantic_step_stride,
        semantic_max_trials=args.semantic_max_trials_per_bucket,
        oracle_precheck_max_steps=args.oracle_precheck_max_steps,
    )


def main() -> int:
    args = parse_args()
    if args.list_cases:
        for name in sorted(CASES):
            case = CASES[name]
            print(f"{name}\t{case.project_dir}\t{' '.join(case.words)}")
        return 0

    cfg = make_config(args)
    if not args.skip_build:
        build_release(cfg.project_dir)

    before = set(STORAGE_DIR.glob(benchmark_glob(cfg.project_dir)))
    cmd = make_cmd(cfg)
    start = time.time()
    completed = subprocess.run(cmd, cwd=cfg.project_dir, check=True)
    runtime_sec = time.time() - start
    corpus, bugs, runs = newest_artifacts(cfg.project_dir, before)
    summary = summarize_records(cfg, cmd, corpus, bugs, runs, runtime_sec)
    summary["exit_code"] = completed.returncode

    summary_path = Path(args.summary_json).resolve() if args.summary_json else (
        STORAGE_DIR / f"e2e-{cfg.name.replace('/', '_')}-{int(time.time())}-summary.json"
    )
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"CASE {cfg.name}")
    print(f"PROJECT {cfg.project_dir}")
    print(f"WORDS {' '.join(cfg.words)}")
    print(f"RUNTIME_SEC {summary['runtime_sec']}")
    print(f"BASELINE_SIG {summary['baseline']['bucket_hits_sig']}")
    print(f"SEMANTIC_ATTEMPTS {summary['semantic_attempts']}")
    print(f"SEMANTIC_APPLIED {summary['semantic_applied_attempts']}")
    print(f"BUG_RECORDS {summary['semantic_bug_records']}")
    print(f"FIRST_APPLIED_EVAL {summary['first_applied']['eval_id']}")
    print(f"FIRST_APPLIED_MODE {summary['first_applied']['mode']}")
    print(f"FIRST_BUG_EVAL {summary['first_bug']['eval_id']}")
    print(f"FIRST_BUG_KIND {summary['first_bug']['kind']}")
    print(f"FIRST_BUG_MODE {summary['first_bug']['mode']}")
    print(f"FIRST_UNDER_EVAL {summary['first_underconstrained']['eval_id']}")
    print(f"FIRST_UNDER_MODE {summary['first_underconstrained']['mode']}")
    print(f"RUNS_JSONL {runs}")
    print(f"BUGS_JSONL {bugs}")
    print(f"SUMMARY_JSON {summary_path}")
    print("BUG_COUNTS_BY_KIND " + json.dumps(summary["bug_counts_by_kind"], sort_keys=True))
    print("BUG_COUNTS_BY_MODE " + json.dumps(summary["bug_counts_by_mode"], sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
