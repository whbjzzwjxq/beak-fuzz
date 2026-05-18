#!/usr/bin/env python3
"""Build the mixed replay corpus used for all-target regression campaigns."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def parse_seed_hex(seed_hex: str) -> list[int]:
    words: list[int] = []
    for raw in seed_hex.replace(",", " ").split():
        word = raw.strip()
        if not word:
            continue
        words.append(int(word, 16) & 0xFFFF_FFFF)
    return words


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open() as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
    return rows


def instruction_features(instructions: list[int]) -> set[str]:
    features: set[str] = set()
    if len(instructions) <= 2:
        features.add("short")
    if len(instructions) >= 16:
        features.add("long")
    if len(instructions) >= 128:
        features.add("very_long")

    opcodes: set[int] = set()
    for word in instructions:
        opcode = word & 0x7F
        funct3 = (word >> 12) & 0x7
        funct7 = (word >> 25) & 0x7F
        imm_i = (word >> 20) & 0xFFF
        opcodes.add(opcode)
        if opcode in (0x03, 0x23):
            features.add("memory")
            if funct3 in (0, 4):
                features.add("byte_memory")
            if funct3 in (1, 5):
                features.add("half_memory")
            if funct3 == 2:
                features.add("word_memory")
        if opcode in (0x63, 0x6F, 0x67):
            features.add("control_flow")
        if opcode == 0x73:
            features.add("system")
        if opcode == 0x33 and funct7 == 0x01:
            features.add("muldiv")
            if funct3 in (4, 5, 6, 7):
                features.add("division")
            if funct3 in (0, 1, 2, 3):
                features.add("multiply")
        if opcode in (0x17, 0x37):
            features.add("upper_imm")
        if imm_i & 0x800:
            features.add("negative_imm")
    if len(opcodes) >= 4:
        features.add("opcode_diverse")
    return features


def score_initial(row: dict[str, Any], index: int) -> tuple[int, str]:
    instructions = [int(x) & 0xFFFF_FFFF for x in row.get("instructions", [])]
    metadata = row.get("metadata", {})
    features = instruction_features(instructions)
    score = 0
    weights = {
        "memory": 30,
        "control_flow": 26,
        "system": 24,
        "muldiv": 24,
        "division": 12,
        "multiply": 10,
        "upper_imm": 12,
        "byte_memory": 8,
        "half_memory": 8,
        "word_memory": 8,
        "negative_imm": 8,
        "opcode_diverse": 10,
        "long": 8,
        "short": 4,
        "very_long": 4,
    }
    for feature in features:
        score += weights.get(feature, 0)
    source = str(metadata.get("source", ""))
    label = str(metadata.get("label", ""))
    if "rv32um" in source:
        score += 18
    if "rv32ui" in source:
        score += 8
    if "rv32si" in source:
        score += 10
    if label.startswith("test_"):
        try:
            score += int(label.split("_", 1)[1]) % 11
        except ValueError:
            pass
    return score, ";".join(sorted(features)) or f"line_{index + 1}"


def build_corpus(
    manifest_path: Path,
    initial_path: Path,
    out_path: Path,
    initial_extra_count: int,
) -> tuple[int, int, int]:
    manifest_rows = load_jsonl(manifest_path)
    initial_rows = load_jsonl(initial_path)

    out_rows: list[dict[str, Any]] = []
    seen: set[tuple[int, ...]] = set()
    gt_row_by_key: dict[tuple[int, ...], dict[str, Any]] = {}
    gt_count = 0

    for manifest_index, row in enumerate(manifest_rows):
        instructions = parse_seed_hex(row["seed_hex"])
        key = tuple(instructions)
        if key in seen:
            existing = gt_row_by_key.get(key)
            if existing is not None:
                metadata = existing["metadata"]
                metadata.setdefault("case_ids", [metadata["case_id"]])
                metadata.setdefault("target_projects", [metadata.get("target_project")])
                metadata.setdefault("expected_buckets", [metadata.get("expected_bucket")])
                metadata.setdefault(
                    "expected_inject_kinds", [metadata.get("expected_inject_kind")]
                )
                metadata["case_ids"].append(row["case_id"])
                metadata["target_projects"].append(row.get("project"))
                metadata["expected_buckets"].append(row.get("expected", {}).get("trigger_bucket_id"))
                metadata["expected_inject_kinds"].append(
                    row.get("expected", {}).get("inject_kind")
                    or row.get("expected", {}).get("inject_kind_prefix")
                )
            continue
        seen.add(key)
        gt_count += 1
        out_row = {
            "instructions": instructions,
            "metadata": {
                "source": "replay_seed.jsonl",
                "label": row["case_id"],
                "case_id": row["case_id"],
                "ground_truth": True,
                "manifest_index": manifest_index,
                "target_project": row.get("project"),
                "target_frontend": row.get("frontend", "bin"),
                "expected_kind": row.get("expected", {}).get("kind"),
                "expected_bucket": row.get("expected", {}).get("trigger_bucket_id"),
                "expected_inject_kind": row.get("expected", {}).get("inject_kind")
                or row.get("expected", {}).get("inject_kind_prefix"),
            },
        }
        out_rows.append(out_row)
        gt_row_by_key[key] = out_row

    scored: list[tuple[int, int, str, dict[str, Any]]] = []
    for index, row in enumerate(initial_rows):
        instructions = [int(x) & 0xFFFF_FFFF for x in row.get("instructions", [])]
        if not instructions:
            continue
        key = tuple(instructions)
        if key in seen:
            continue
        score, feature_sig = score_initial(row, index)
        scored.append((score, index, feature_sig, row))

    scored.sort(key=lambda item: (-item[0], item[1]))
    extras = 0
    feature_counts: dict[str, int] = {}

    def add_extra(row: dict[str, Any], index: int, feature_sig: str, score: int) -> None:
        nonlocal extras
        instructions = [int(x) & 0xFFFF_FFFF for x in row.get("instructions", [])]
        key = tuple(instructions)
        if key in seen:
            return
        seen.add(key)
        extras += 1
        metadata = dict(row.get("metadata", {}))
        metadata.update(
            {
                "source": metadata.get("source", "storage/fuzzing_seeds/initial.jsonl"),
                "label": metadata.get("label", f"initial_line_{index + 1}"),
                "ground_truth": False,
                "replay_extra": True,
                "initial_jsonl_line": index + 1,
                "selection_score": score,
                "selection_features": feature_sig,
            }
        )
        out_rows.append({"instructions": instructions, "metadata": metadata})

    for score, index, feature_sig, row in scored:
        if extras >= initial_extra_count:
            break
        primary = feature_sig.split(";", 1)[0]
        if feature_counts.get(primary, 0) >= 32:
            continue
        add_extra(row, index, feature_sig, score)
        feature_counts[primary] = feature_counts.get(primary, 0) + 1

    if extras < initial_extra_count:
        for score, index, feature_sig, row in scored:
            if extras >= initial_extra_count:
                break
            add_extra(row, index, feature_sig, score)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        for row in out_rows:
            f.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    return len(manifest_rows), gt_count, extras


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path("replay_seed.jsonl"))
    parser.add_argument(
        "--initial", type=Path, default=Path("storage/fuzzing_seeds/initial.jsonl")
    )
    parser.add_argument(
        "--out", type=Path, default=Path("storage/fuzzing_seeds/replay_mixed.jsonl")
    )
    parser.add_argument("--initial-extra-count", type=int, default=256)
    args = parser.parse_args()

    manifest_count, gt_count, extra_count = build_corpus(
        args.manifest, args.initial, args.out, args.initial_extra_count
    )
    print(
        f"wrote {args.out}: manifest_rows={manifest_count} "
        f"ground_truth_rows={gt_count} initial_extra_rows={extra_count}"
    )


if __name__ == "__main__":
    main()
