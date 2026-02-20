from pathlib import Path

import re

from openvm_fuzzer.settings import (
    OPENVM_BENCHMARK_336F_COMMIT,
    OPENVM_BENCHMARK_F038_COMMIT,
    OPENVM_BENCHMARK_REGZERO_COMMIT,
    resolve_openvm_commit,
)


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _patch_padding_samples(openvm_install_path=openvm_install_path, commit_or_branch=commit_or_branch)


def _patch_audit_integration_api_for_padding_samples(openvm_install_path: Path) -> None:
    """
    Audit snapshots (336/f038) build padded traces in `VmChipWrapper::generate_air_proof_input`.

    Sample a few padding rows (which are all-zero) as inactive ChipRows (is_real=0) and emit an
    effectful Interaction anchored to them. This enables InactiveRowEffectsBucket without dumping
    every padding row.
    """
    integration_api = openvm_install_path / "crates" / "vm" / "src" / "arch" / "integration_api.rs"
    if not integration_api.exists():
        return

    contents = integration_api.read_text()
    # Repair older insertion that passed `&str` to `update_hints` (signature expects `&String`).
    if 'update_hints(0, "PADDING", "PADDING")' in contents:
        contents = contents.replace(
            'fuzzer_utils::update_hints(0, "PADDING", "PADDING");',
            'let hint = "PADDING".to_string();\n            fuzzer_utils::update_hints(0, &hint, &hint);',
        )
        integration_api.write_text(contents)
        contents = integration_api.read_text()

    # Repair older insertion that borrowed `self` after `self.records` was moved.
    if 'let chip = format!("VmChipWrapper{}", self.air_name());' in contents:
        contents = contents.replace(
            'let chip = format!("VmChipWrapper{}", self.air_name());',
            'let chip = "VmChipWrapper".to_string();',
        )
        integration_api.write_text(contents)
        contents = integration_api.read_text()

    # Repair older insertion that references `beak_padding_chip` without declaration.
    if "let chip = beak_padding_chip.clone();" in contents:
        contents = contents.replace(
            "let chip = beak_padding_chip.clone();",
            'let chip = "VmChipWrapper".to_string();',
        )
        integration_api.write_text(contents)
        contents = integration_api.read_text()

    if "PaddingSample" in contents:
        return

    # Ensure we can call fuzzer_utils even if assert-rewrite didn't touch this file.
    if "use fuzzer_utils;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            contents = contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]

    # Ensure serde_json::json is available (we emit small JSON payloads).
    if "use serde_json::json;" not in contents:
        contents, n = re.subn(
            r"^use serde::\{[^}]*\};\s*$",
            lambda m: m.group(0) + "\nuse serde_json::json;",
            contents,
            count=1,
            flags=re.MULTILINE,
        )
        if n == 0:
            # Best-effort: insert after the last `use` in the header.
            header_end = contents.find("\n\n")
            if header_end > 0:
                contents = contents[:header_end] + "\nuse serde_json::json;\n" + contents[header_end:]

    # Insert after finalize, where `height/num_records/width` are in scope and padding rows exist.
    anchor = "self.core.finalize(&mut trace, num_records);"
    insert = r"""

        // beak-fuzz: sample a few inactive (padding) rows for op-agnostic inactive-row analysis.
        if fuzzer_utils::is_trace_logging() && height > num_records {
            let hint = "PADDING".to_string();
            fuzzer_utils::update_hints(0, &hint, &hint);
            fuzzer_utils::inc_step();

            let chip = "VmChipWrapper".to_string();
            let max_samples: usize = 3;
            let mut emitted: usize = 0;
            while emitted < max_samples && (num_records + emitted) < height {
                let row_idx = num_records + emitted;
                let gates = json!({"is_real": 0}).to_string();
                let locals = json!({
                    "chip": chip,
                    "row_idx": row_idx,
                    "real_rows": num_records,
                    "total_rows": height,
                    "width": width,
                })
                .to_string();
                fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
                let anchor_row_id = fuzzer_utils::get_last_row_id();
                let payload = json!({"chip": chip, "row_idx": row_idx}).to_string();
                fuzzer_utils::print_interaction_json(
                    "PaddingSample",
                    "send",
                    "inactive_row",
                    &anchor_row_id,
                    &payload,
                    1,
                    "const",
                );
                emitted += 1;
            }
        }
"""

    if anchor not in contents:
        # Older/variant layouts: don't fail hard; just skip.
        integration_api.write_text(contents)
        return
    contents = contents.replace(anchor, anchor + insert)
    integration_api.write_text(contents)


def _patch_regzero_record_arena_for_padding_samples(openvm_install_path: Path) -> None:
    """
    regzero snapshot pads traces via `MatrixRecordArena::into_matrix`, truncating to the next power
    of two and leaving unused rows as all-zeros. Sample a few padding rows there.
    """
    path = openvm_install_path / "crates" / "vm" / "src" / "arch" / "record_arena.rs"
    if not path.exists():
        return

    contents = path.read_text()
    # Repair older insertion that passed `&str` to `update_hints` (signature expects `&String`).
    if 'update_hints(0, "PADDING", "PADDING")' in contents:
        contents = contents.replace(
            'fuzzer_utils::update_hints(0, "PADDING", "PADDING");',
            'let hint = "PADDING".to_string();\n            fuzzer_utils::update_hints(0, &hint, &hint);',
        )
        path.write_text(contents)

    if "PaddingSample" in contents:
        return

    anchor = "let height = next_power_of_two_or_zero(rows_used);"
    insert = r"""

        // beak-fuzz: sample a few inactive (padding) rows for op-agnostic inactive-row analysis.
        if fuzzer_utils::is_trace_logging() && height > rows_used {
            let hint = "PADDING".to_string();
            fuzzer_utils::update_hints(0, &hint, &hint);
            fuzzer_utils::inc_step();

            let chip = format!("MatrixRecordArena(width={})", width);
            let max_samples: usize = 3;
            let mut emitted: usize = 0;
            while emitted < max_samples && (rows_used + emitted) < height {
                let row_idx = rows_used + emitted;
                let gates = "{\"is_real\":0}".to_string();
                let locals = format!(
                    "{{\"chip\":\"{}\",\"row_idx\":{},\"real_rows\":{},\"total_rows\":{},\"width\":{}}}",
                    chip, row_idx, rows_used, height, width
                );
                fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
                let anchor_row_id = fuzzer_utils::get_last_row_id();
                let payload = format!("{{\"chip\":\"{}\",\"row_idx\":{}}}", chip, row_idx);
                fuzzer_utils::print_interaction_json(
                    "PaddingSample",
                    "send",
                    "inactive_row",
                    &anchor_row_id,
                    &payload,
                    1,
                    "const",
                );
                emitted += 1;
            }
        }
"""

    if anchor not in contents:
        return
    contents = contents.replace(anchor, anchor + insert)
    path.write_text(contents)


def _patch_padding_samples(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    resolved_commit = resolve_openvm_commit(commit_or_branch)

    if resolved_commit in {OPENVM_BENCHMARK_336F_COMMIT, OPENVM_BENCHMARK_F038_COMMIT}:
        _patch_audit_integration_api_for_padding_samples(openvm_install_path)

    if resolved_commit == OPENVM_BENCHMARK_REGZERO_COMMIT:
        _patch_regzero_record_arena_for_padding_samples(openvm_install_path)

