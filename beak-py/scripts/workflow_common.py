from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class RunResult:
    stdout: str
    stderr: str
    returncode: int


def repo_root() -> Path:
    # This repo has historically been nested under a larger mono-repo layout.
    # Resolve the real repo root by walking up until we find a marker file.
    here = Path(__file__).resolve()
    for p in (here.parent, *here.parents):
        if (p / "pyproject.toml").exists() or (p / ".git").exists():
            return p
    # Fallback: scripts/ is directly under the repo root.
    return here.parents[1]


def extract_record_json(stdout: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    start = 0
    while True:
        i = stdout.find("<record>", start)
        if i < 0:
            break
        j = stdout.find("</record>", i)
        if j < 0:
            break
        payload = stdout[i + len("<record>") : j]
        start = j + len("</record>")
        try:
            records.append(json.loads(payload))
        except Exception:
            continue
    return records


def write_run_artifacts(
    *,
    project_root: Path,
    run: RunResult,
    records: list[dict[str, Any]],
    hits: Optional[list[dict[str, Any]]],
    run_prefix: str,
) -> None:
    project_root.mkdir(parents=True, exist_ok=True)
    (project_root / f"{run_prefix}_run.stdout.txt").write_text(run.stdout)
    (project_root / f"{run_prefix}_run.stderr.txt").write_text(run.stderr)
    micro_op_records = [r for r in records if r.get("context") == "micro_op"]
    (project_root / "micro_op_records.json").write_text(json.dumps(micro_op_records, indent=2, sort_keys=True))
    bucket_hits_path = project_root / "bucket_hits.json"
    if hits is not None:
        bucket_hits_path.write_text(json.dumps(hits, indent=2, sort_keys=True, default=str))
    elif bucket_hits_path.exists():
        bucket_hits_path.unlink()


def ensure_writable_cargo_home() -> Path:
    dest = repo_root() / "beak-fuzz" / "out" / ".cargo-home"
    if (dest / "registry").exists():
        return dest

    src = Path("/home/work/.cargo")
    dest.mkdir(parents=True, exist_ok=True)
    for sub in ("registry", "git", "bin", "config.toml", "config"):
        sp = src / sub
        dp = dest / sub
        if not sp.exists() or dp.exists():
            continue
        if sp.is_dir():
            shutil.copytree(sp, dp, symlinks=True)
        else:
            shutil.copy2(sp, dp)
    return dest


def build_trace_from_records(records: list[dict[str, Any]]):
    from chip_row_records import chip_row_from_record
    from beak_core.micro_ops import (  # type: ignore
        InteractionBase,
        InteractionKind,
        InteractionMultiplicity,
        InteractionScope,
        InteractionType,
        ZKVMTrace,
    )

    micro_ops: list[Any] = []
    op_spans: dict[int, list[int]] = {}

    def _add(step: int, item: Any):
        idx = len(micro_ops)
        micro_ops.append(item)
        op_spans.setdefault(step, []).append(idx)

    for rec in records:
        if rec.get("context") != "micro_op":
            continue
        step = rec.get("step")
        if not isinstance(step, int):
            continue
        typ = rec.get("micro_op_type")
        if typ == "chip_row":
            row = chip_row_from_record(rec)
            if row is None:
                continue
            _add(step, row)
        elif typ == "interaction":
            table_id = rec.get("table_id")
            io = rec.get("io")
            kind = rec.get("kind")
            scope = rec.get("scope")
            anchor_row_id = rec.get("anchor_row_id")
            multiplicity = rec.get("multiplicity")
            if not isinstance(table_id, str) or not isinstance(io, str) or not isinstance(kind, str):
                continue
            if scope is None or not isinstance(scope, str):
                scope = "global"
            if anchor_row_id is not None and not isinstance(anchor_row_id, str):
                anchor_row_id = None
            mult_obj = None
            if isinstance(multiplicity, dict):
                mv = multiplicity.get("value")
                mr = multiplicity.get("ref")
                if isinstance(mv, int) and isinstance(mr, str):
                    mult_obj = InteractionMultiplicity(value=mv, ref=mr)
            try:
                io_t = InteractionType(io)
            except Exception:
                continue
            try:
                scope_t = InteractionScope(scope)
            except Exception:
                scope_t = InteractionScope.GLOBAL
            try:
                kind_t = InteractionKind(kind)
            except Exception:
                kind_t = InteractionKind.CUSTOM

            _add(
                step,
                InteractionBase(
                    table_id=table_id,
                    io=io_t,
                    scope=scope_t,
                    anchor_row_id=anchor_row_id,
                    event_id=None,
                    kind=kind_t,
                    multiplicity=mult_obj,
                ),
            )

    if not micro_ops:
        raise RuntimeError("no micro_op records found")

    spans = [op_spans[k] for k in sorted(op_spans.keys())]
    trace = ZKVMTrace(micro_ops, op_spans=spans)
    errors = trace.validate()
    if errors:
        raise RuntimeError(f"trace validation errors: {errors}")
    return trace


def load_instructions(path: Path) -> list[str]:
    lines: list[str] = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines


def relpath(from_dir: Path, to_path: Path) -> str:
    return os.path.relpath(to_path, start=from_dir).replace(os.sep, "/")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
