#!/usr/bin/env python3
"""
Filter bugs.jsonl by pattern: exclude lines matching "uninteresting" patterns,
output the remaining lines (by line number and/or full JSONL).

Uninteresting (see docs/BUG_REPORTS.md) includes:
  - timeout
  - CSR semantics (failed_exit2 with only openvm.input.has_csr)
  - read/write regzero (bucket hits openvm.reg.read_rs1_x0 / read_rs2_x0, or mismatch on x0)
  - Known doc bugs: Invalid LoadStoreOp, opcode 225 conversion, index-out-of-bounds (DivRem), code-as-data mismatch

Usage:
  # Show pattern summary
  python scripts/filter_bugs_by_pattern.py --summary storage/.../bugs.jsonl

  # Exclude default uninteresting patterns (timeout, csr, regzero, doc-known), output remaining
  python scripts/filter_bugs_by_pattern.py --default-exclude -o filtered.jsonl storage/.../bugs.jsonl

  # Exclude custom patterns
  python scripts/filter_bugs_by_pattern.py --exclude timeout,failed_exit2_csr storage/.../bugs.jsonl

  # Only output line numbers
  python scripts/filter_bugs_by_pattern.py --default-exclude --lines-only storage/.../bugs.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# Default uninteresting: timeout, CSR semantics, read/write regzero, and known bugs from docs/BUG_REPORTS.md
DEFAULT_UNINTERESTING = [
    "timeout",
    "failed_exit2_csr",  # CSR 不一致语义
    "regzero",           # read/write regzero
    "index_out_of_bounds",  # DivRem trace fill / index len 0 (BUG_REPORTS)
    "invalid_loadstore_op",  # Invalid LoadStoreOp (BUG_REPORTS)
    "opcode_225",        # Failed to convert usize 225 to opcode (BUG_REPORTS)
    "memory_out_of_bounds",
    "unaligned_memory",
    "code_as_data_mismatch",  # Code-as-data read mismatch (BUG_REPORTS)
    "pc_out_of_bounds",       # PcOutOfBounds
    "load_sign_extend_shift", # LoadSignExtend invalid shift amount
]


def classify_backend_error(be: str | None) -> str:
    if be is None:
        return "null"
    s = str(be)
    if "timed out" in s.lower() or "worker killed" in s.lower():
        return "timeout"
    if "FailedWithExitCode(2)" in s:
        return "failed_exit2"
    if "Memory access out of bounds" in s:
        return "memory_out_of_bounds"
    if "unaligned memory" in s.lower() or "STOREW" in s or ("LOAD" in s and "unaligned" in s.lower()):
        return "unaligned_memory"
    if "index out of bounds" in s.lower() or "the len is 0" in s.lower():
        return "index_out_of_bounds"
    if "Invalid LoadStoreOp" in s:
        return "invalid_loadstore_op"
    if "PcOutOfBounds" in s:
        return "pc_out_of_bounds"
    if "LoadSignExtend invalid shift amount" in s or "invalid shift amount" in s:
        return "load_sign_extend_shift"
    if "Failed to convert usize 225" in s or "opcode LessThanOpcode" in s or "opcode BranchEq" in s or "opcode BranchLe" in s:
        return "opcode_225"
    if "worker panic" in s.lower() or "run_backend_once" in s:
        return "other_worker_panic"
    return "other"


def bucket_category(sig: str) -> str:
    if not sig:
        return "empty"
    if sig.strip() == "openvm.input.has_csr":
        return "only_has_csr"
    return "has_more"


def has_regzero_hit(obj: dict) -> bool:
    """True if bucket_hits indicate read-rs1/rs2-from-x0 (read regzero)."""
    for h in obj.get("bucket_hits") or []:
        bid = (h.get("bucket_id") or "").lower()
        if "read_rs1_x0" in bid or "read_rs2_x0" in bid:
            return True
    return False


def mismatch_includes_x0(obj: dict) -> bool:
    """True if mismatch_regs includes register 0 (x0) — write-regzero semantics."""
    for triple in obj.get("mismatch_regs") or []:
        if len(triple) >= 1 and triple[0] == 0:
            return True
    return False


def is_code_as_data_mismatch(obj: dict) -> bool:
    """Code-as-data read mismatch: mismatch + mem/auipc/effective_ptr_zero etc. (BUG_REPORTS)."""
    if obj.get("metadata", {}).get("kind") != "mismatch":
        return False
    sig = (obj.get("bucket_hits_sig") or "")
    return (
        "openvm.auipc.seen" in sig
        or "openvm.mem.effective_ptr_zero" in sig
        or "openvm.mem.access_seen" in sig
        or "openvm.mem.addr_space.is_other" in sig
    )


def pattern_id(kind: str, timed_out: bool, be_cat: str, bucket: str) -> str:
    return f"{kind}|{timed_out}|{be_cat}|{bucket}"


def classify_line(obj: dict) -> tuple[str, str]:
    """
    Returns (pattern_id, human_label).
    human_label is a short name for summary; extra labels (regzero, code_as_data_mismatch) are applied when applicable.
    """
    kind = obj.get("metadata", {}).get("kind", "?")
    timed_out = obj.get("timed_out", False)
    be = obj.get("backend_error")
    be_cat = classify_backend_error(be)
    bucket = bucket_category(obj.get("bucket_hits_sig", "") or "")

    pid = pattern_id(kind, timed_out, be_cat, bucket)

    if kind == "exception" and timed_out and be_cat == "timeout":
        label = "timeout"
    elif kind == "exception" and not timed_out and be_cat == "failed_exit2" and bucket == "only_has_csr":
        label = "failed_exit2_csr"
    elif kind == "mismatch" and be_cat == "null":
        if is_code_as_data_mismatch(obj):
            label = "code_as_data_mismatch"
        else:
            label = "mismatch"
    elif kind == "exception" and be_cat == "memory_out_of_bounds":
        label = "memory_out_of_bounds"
    elif kind == "exception" and be_cat == "unaligned_memory":
        label = "unaligned_memory"
    elif kind == "exception" and be_cat == "index_out_of_bounds":
        label = "index_out_of_bounds"
    elif kind == "exception" and be_cat == "invalid_loadstore_op":
        label = "invalid_loadstore_op"
    elif kind == "exception" and be_cat == "opcode_225":
        label = "opcode_225"
    elif kind == "exception" and be_cat == "pc_out_of_bounds":
        label = "pc_out_of_bounds"
    elif kind == "exception" and be_cat == "load_sign_extend_shift":
        label = "load_sign_extend_shift"
    else:
        label = pid.replace("|", "_")

    # Override: read/write regzero takes precedence for labeling
    if has_regzero_hit(obj) or mismatch_includes_x0(obj):
        label = "regzero"

    return pid, label


def run_summary(path: Path) -> dict[str, list[tuple[int, str]]]:
    """Return pattern_label -> [(line_no, pattern_id), ...]."""
    by_label: dict[str, list[tuple[int, str]]] = defaultdict(list)
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                pid, label = classify_line(obj)
                by_label[label].append((i, pid))
            except json.JSONDecodeError:
                by_label["_parse_error"].append((i, "parse_error"))
    return dict(by_label)


def main() -> None:
    ap = argparse.ArgumentParser(description="Filter bugs JSONL by pattern.")
    ap.add_argument("input", type=Path, help="bugs.jsonl file")
    ap.add_argument(
        "--summary",
        action="store_true",
        help="Print pattern summary and exit (no filtering).",
    )
    ap.add_argument(
        "--default-exclude",
        action="store_true",
        help="Exclude default uninteresting patterns (timeout, csr, regzero, doc-known). Same as docs/BUG_REPORTS.md + timeout + read/write regzero + CSR semantics.",
    )
    ap.add_argument(
        "--exclude",
        type=str,
        metavar="PATTERNS",
        help="Comma-separated pattern labels or IDs to exclude (e.g. timeout,failed_exit2_csr). Ignored if --default-exclude is set.",
    )
    ap.add_argument(
        "-o", "--output",
        type=Path,
        help="Write filtered JSONL here (default: stdout).",
    )
    ap.add_argument(
        "--lines-only",
        action="store_true",
        help="Output only line numbers of remaining lines (one per line).",
    )
    args = ap.parse_args()

    if not args.input.exists():
        print(f"Error: file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    by_label = run_summary(args.input)

    if args.summary:
        print("Pattern summary (use these names with --exclude):\n")
        for label in sorted(by_label.keys(), key=lambda L: (-len(by_label[L]), L)):
            count = len(by_label[label])
            print(f"  {count:6d}  {label}")
        print("\nDefault uninteresting (--default-exclude):", ", ".join(DEFAULT_UNINTERESTING))
        return

    if args.default_exclude:
        exclude_set = set(DEFAULT_UNINTERESTING)
    elif args.exclude:
        exclude_set = {s.strip() for s in args.exclude.split(",") if s.strip()}
    else:
        print("Error: use --default-exclude, --exclude PATTERNS, or --summary", file=sys.stderr)
        sys.exit(1)
    # Also exclude by pattern_id if user passes id-like strings
    lines_to_skip: set[int] = set()
    for label, entries in by_label.items():
        if label in exclude_set:
            for (ln, _) in entries:
                lines_to_skip.add(ln)
        else:
            for (ln, pid) in entries:
                if pid in exclude_set:
                    lines_to_skip.add(ln)

    out = open(args.output, "w") if args.output else sys.stdout
    try:
        with open(args.input) as f:
            for i, line in enumerate(f, 1):
                line_stripped = line.strip()
                if not line_stripped:
                    if not args.lines_only:
                        out.write(line)
                    continue
                if i in lines_to_skip:
                    continue
                if args.lines_only:
                    out.write(f"{i}\n")
                else:
                    out.write(line)
    finally:
        if args.output:
            out.close()

    if args.output and not args.lines_only:
        with open(args.output) as o:
            kept = sum(1 for _ in o)
        print(f"Wrote {kept} lines to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
