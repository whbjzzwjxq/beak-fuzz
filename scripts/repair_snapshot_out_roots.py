#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


SNAPSHOT_DIR_RE = re.compile(r"^(openvm|pico|sp1|jolt|nexus|risc0)-[0-9a-f]{8,40}$")


def beak_root() -> Path:
    return Path(__file__).resolve().parents[1]


def canonical_out_root() -> Path:
    return beak_root() / "beak-py" / "out"


def default_scan_roots() -> list[Path]:
    roots = [beak_root() / "out", beak_root().parent / "out"]
    deduped: list[Path] = []
    for root in roots:
        resolved = root.resolve()
        if resolved not in deduped:
            deduped.append(resolved)
    return deduped


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Move misinstalled zkVM snapshots from legacy out/ roots into beak-py/out/."
    )
    ap.add_argument(
        "--scan-root",
        action="append",
        type=Path,
        default=None,
        help="Extra out/ root to scan. May be provided multiple times.",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned moves without modifying the filesystem.",
    )
    return ap.parse_args()


def find_candidate_dirs(scan_root: Path) -> list[Path]:
    if not scan_root.is_dir():
        return []
    return [
        child
        for child in sorted(scan_root.iterdir())
        if child.is_dir() and SNAPSHOT_DIR_RE.fullmatch(child.name)
    ]


def main() -> int:
    args = parse_args()
    target_root = canonical_out_root().resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    scan_roots = default_scan_roots()
    if args.scan_root:
        for root in args.scan_root:
            resolved = root.expanduser().resolve()
            if resolved not in scan_roots:
                scan_roots.append(resolved)

    moved = 0
    skipped = 0
    scanned_any = False

    for scan_root in scan_roots:
        if scan_root == target_root:
            continue
        candidates = find_candidate_dirs(scan_root)
        if not candidates:
            continue
        scanned_any = True
        print(f"scan root: {scan_root}")
        for candidate in candidates:
            dest = target_root / candidate.name
            if dest.exists():
                print(f"skip: {candidate} -> {dest} (destination already exists)")
                skipped += 1
                continue
            print(f"move: {candidate} -> {dest}")
            if not args.dry_run:
                shutil.move(str(candidate), str(dest))
            moved += 1

    if moved == 0 and skipped == 0:
        if scanned_any:
            print("no movable misinstalled snapshot directories found")
        else:
            print("no misinstalled snapshot directories found")
        return 0

    summary = f"moved={moved}"
    if skipped:
        summary += f" skipped={skipped}"
    if args.dry_run:
        summary = "dry-run " + summary
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
