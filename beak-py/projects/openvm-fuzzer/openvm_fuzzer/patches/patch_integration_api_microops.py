from pathlib import Path

import re

from openvm_fuzzer.settings import (
    OPENVM_BENCHMARK_336F_COMMIT,
    OPENVM_BENCHMARK_F038_COMMIT,
    resolve_openvm_commit,
)
from zkvm_fuzzer_utils.file import replace_in_file


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _patch_integration_api_microops(openvm_install_path=openvm_install_path, commit_or_branch=commit_or_branch)


def _patch_audit_integration_api_for_microops(openvm_install_path: Path) -> None:
    """
    Audit snapshots (336/f038) have a slightly different `integration_api.rs` layout (multi-line
    `postprocess` assignment). Patch it in-place to emit adapter/core ChipRow micro-ops.
    """
    integration_api = openvm_install_path / "crates" / "vm" / "src" / "arch" / "integration_api.rs"
    if not integration_api.exists():
        return

    contents = integration_api.read_text()
    if "fuzzer_utils::print_chip_row_json(\"openvm\"" in contents:
        # Already injected.
        return

    # Ensure we can call fuzzer_utils even if assert-rewrite didn't touch this file.
    if "use fuzzer_utils;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            contents = contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]

    # Ensure serde_json::json is available.
    if "use serde_json::json;" not in contents:
        # Accept both `use serde::{Deserialize, Serialize};` and
        # `use serde::{de::DeserializeOwned, Deserialize, Serialize};` variants.
        contents, n = re.subn(
            r"^use serde::\{[^}]*\};\s*$",
            lambda m: m.group(0) + "\nuse serde_json::json;",
            contents,
            count=1,
            flags=re.MULTILINE,
        )
        if n == 0:
            raise RuntimeError("unable to locate serde import to append serde_json::json")

    # Insert after the multi-line postprocess assignment (ending at `?;`).
    m = re.search(
        r"(let\s+\(to_state,\s*write_record\)\s*=\s*\n\s*self\.adapter\s*\n\s*\.postprocess\([\s\S]*?\)\?\s*;)",
        contents,
        flags=re.MULTILINE,
    )
    if not m:
        raise RuntimeError("unable to locate adapter postprocess assignment in integration_api.rs")

    insert = r"""

        if fuzzer_utils::is_trace_logging() {
            // NOTE: We emit ChipRow-style micro-ops, i.e. per-chip payloads. This matches
            // the beak-core interface (MicroOp = ChipRow | InteractionBase).
            let gates = json!({"is_real": 1}).to_string();

            let adapter_chip = get_air_name(self.adapter.air());
            let adapter_locals = json!({
                "from_pc": from_state.pc,
                "to_pc": to_state.pc,
                "from_timestamp": from_state.timestamp,
                "to_timestamp": to_state.timestamp,
                "payload_json": json!({
                    "adapter_read": &read_record,
                    "adapter_write": &write_record,
                })
                .to_string(),
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &adapter_chip, &gates, &adapter_locals);

            let core_chip = get_air_name(self.core.air());
            let core_locals = json!({
                "from_pc": from_state.pc,
                "payload_json": json!({ "core": &core_record }).to_string(),
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &core_chip, &gates, &core_locals);
        }
"""
    pos = m.end()
    contents = contents[:pos] + insert + contents[pos:]
    integration_api.write_text(contents)


def _patch_integration_api_microops(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    resolved_commit = resolve_openvm_commit(commit_or_branch)

    integration_api = openvm_install_path / "crates" / "vm" / "src" / "arch" / "integration_api.rs"
    if not integration_api.exists():
        return

    if resolved_commit in {OPENVM_BENCHMARK_336F_COMMIT, OPENVM_BENCHMARK_F038_COMMIT}:
        _patch_audit_integration_api_for_microops(openvm_install_path)
        return

    contents = integration_api.read_text()

    # Ensure we can call fuzzer_utils even if assert-rewrite didn't touch this file.
    if "use fuzzer_utils;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            integration_api.write_text(contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:])
            contents = integration_api.read_text()

    # Ensure serde_json::json is available.
    if "use serde_json::json;" not in contents:
        replace_in_file(
            integration_api,
            [
                (
                    r"use serde::\{de::DeserializeOwned, Deserialize, Serialize\};",
                    "use serde::{de::DeserializeOwned, Deserialize, Serialize};\nuse serde_json::json;",
                )
            ],
        )
        contents = integration_api.read_text()

    # Repair a prior bad injection that left a literal `\1` line in the file.
    if "\n\\1\n" in contents:
        integration_api.write_text(contents.replace("\n\\1\n", "\n"))
        contents = integration_api.read_text()

    if "fuzzer_utils::print_chip_row_json(\"openvm\"" in contents:
        return

    replace_in_file(
        integration_api,
        [
            (
                r"^(\s*self\.adapter\s*\.postprocess\(\s*memory,\s*instruction,\s*from_state,\s*output,\s*&read_record\s*\)\?\s*;)\s*$",
                r"""\1

        if fuzzer_utils::is_trace_logging() {
            // NOTE: We emit ChipRow-style micro-ops, i.e. per-chip payloads. This matches
            // the beak-core interface (MicroOp = ChipRow | InteractionBase).
            let gates = json!({"is_real": 1}).to_string();

            let adapter_chip = get_air_name(self.adapter.air());
            let adapter_locals = json!({
                "from_pc": from_state.pc,
                "to_pc": to_state.pc,
                "from_timestamp": from_state.timestamp,
                "to_timestamp": to_state.timestamp,
                "payload_json": json!({
                    "adapter_read": &read_record,
                    "adapter_write": &write_record,
                })
                .to_string(),
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &adapter_chip, &gates, &adapter_locals);

            let core_chip = get_air_name(self.core.air());
            let core_locals = json!({
                "from_pc": from_state.pc,
                "payload_json": json!({ "core": &core_record }).to_string(),
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &core_chip, &gates, &core_locals);
        }""",
            ),
        ],
        flags=re.MULTILINE,
    )

