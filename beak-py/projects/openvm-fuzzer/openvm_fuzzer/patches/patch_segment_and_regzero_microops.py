import logging
import re
from pathlib import Path

from openvm_fuzzer.patches.injection_sources import openvm_crates_vm_src_arch_segment_rs
from openvm_fuzzer.settings import (
    OPENVM_BENCHMARK_336F_COMMIT,
    OPENVM_BENCHMARK_F038_COMMIT,
    OPENVM_BENCHMARK_REGZERO_COMMIT,
    resolve_openvm_commit,
)
from zkvm_fuzzer_utils.file import overwrite_file

logger = logging.getLogger("fuzzer")

_OPENVM_SNAPSHOT_COMMITS = {
    OPENVM_BENCHMARK_REGZERO_COMMIT,
    OPENVM_BENCHMARK_336F_COMMIT,
    OPENVM_BENCHMARK_F038_COMMIT,
}


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _patch_segment_and_regzero_microops(
        openvm_install_path=openvm_install_path,
        commit_or_branch=commit_or_branch,
    )


def _insert_after(contents: str, *, anchor: str, insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        raise RuntimeError(f"anchor not found for injection: {anchor!r}")
    pos = idx + len(anchor)
    return contents[:pos] + insert + contents[pos:]


def _insert_before(contents: str, *, anchor: str, insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        raise RuntimeError(f"anchor not found for injection: {anchor!r}")
    return contents[:idx] + insert + contents[idx:]


def _patch_audit_segment_rs_for_microops(openvm_install_path: Path) -> None:
    """
    Audit snapshots (336/f038) predate our template overwrite approach.
    Patch `crates/vm/src/arch/segment.rs` in-place to emit ChipRow + Interaction micro-ops.
    """
    segment_rs = openvm_install_path / "crates" / "vm" / "src" / "arch" / "segment.rs"
    if not segment_rs.exists():
        logger.info("segment.rs not found; skipping audit segment patch: %s", segment_rs)
        return

    contents = segment_rs.read_text()

    # Repair a prior bad patch that inserted `inc_step()` *after* the `(opcode, dsl_instr)` tuple,
    # breaking the block's return type.
    bad_block = (
        "(opcode, dsl_instr.cloned())\n\n"
        "                // Advance \"op index\" for micro-op grouping.\n"
        "                fuzzer_utils::print_trace_info();\n"
        "                fuzzer_utils::inc_step();\n\n"
    )
    if bad_block in contents:
        good_block = (
            "\n                // Advance \"op index\" for micro-op grouping.\n"
            "                fuzzer_utils::print_trace_info();\n"
            "                fuzzer_utils::inc_step();\n\n"
            "                (opcode, dsl_instr.cloned())\n"
        )
        contents = contents.replace(bad_block, good_block)

    # Ensure imports used by the injected blocks.
    if "use serde_json::json;" not in contents:
        # Prefer inserting after the top-level `use crate::{ ... };` block.
        m = re.search(r"\nuse crate::\{[\s\S]*?\};\n", contents, flags=re.MULTILINE)
        if m:
            pos = m.end()
            contents = contents[:pos] + "use serde_json::json;\n" + contents[pos:]
        else:
            # Best-effort: insert after the last `use` line in the header.
            header_end = contents.find("\n\n")
            if header_end > 0:
                header = contents[:header_end]
                if "use serde_json::json;" not in header:
                    contents = (
                        contents[:header_end]
                        + "\nuse serde_json::json;\n"
                        + contents[header_end:]
                    )

    if "use crate::system::memory::online::MemoryLogEntry;" not in contents:
        # Insert after existing `use crate::{ ... system::memory::MemoryImage, ... };` block if present.
        m = re.search(r"use crate::\{[\s\S]*?system::memory::MemoryImage,[\s\S]*?\};", contents)
        if m:
            insert_pos = m.end()
            contents = (
                contents[:insert_pos]
                + "\nuse crate::system::memory::online::MemoryLogEntry;\n"
                + contents[insert_pos:]
            )

    # Ensure `use fuzzer_utils;` is present somewhere (assert-rewrite usually adds it, but be robust).
    if "use fuzzer_utils;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            contents = contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]

    # ProgramChip + ProgramBus emission (pc -> opcode/operands).
    contents = _insert_after(
        contents,
        anchor="let (instruction, debug_info) = program_chip.get_instruction(pc)?;",
        guard="\"ProgramBus\"",
        insert=r"""

                // Program-table semantics: the program bus constrains that (pc -> opcode/operands).
                // Emit a ChipRow so op-level analyses can include this "system" chip alongside
                // the instruction's adapter/core chips.
                if fuzzer_utils::is_trace_logging() {
                    let gates = json!({"is_real": 1}).to_string();
                    let locals = json!({
                        "pc": pc,
                        "opcode": instruction.opcode.as_usize(),
                        "operands": [
                            instruction.a.as_canonical_u32(),
                            instruction.b.as_canonical_u32(),
                            instruction.c.as_canonical_u32(),
                            instruction.d.as_canonical_u32(),
                            instruction.e.as_canonical_u32(),
                            instruction.f.as_canonical_u32(),
                            instruction.g.as_canonical_u32(),
                        ],
                    })
                    .to_string();
                    let chip = "ProgramChip".to_string();
                    fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);

                    // Program-table interaction: lookup (pc -> opcode/operands).
                    let anchor_row_id = fuzzer_utils::get_last_row_id();
                    let payload = json!({
                        "pc": pc,
                        "opcode": instruction.opcode.as_usize(),
                        "operands": [
                            instruction.a.as_canonical_u32(),
                            instruction.b.as_canonical_u32(),
                            instruction.c.as_canonical_u32(),
                            instruction.d.as_canonical_u32(),
                            instruction.e.as_canonical_u32(),
                            instruction.f.as_canonical_u32(),
                            instruction.g.as_canonical_u32(),
                        ],
                    })
                    .to_string();
                    fuzzer_utils::print_interaction_json(
                        "ProgramBus",
                        "recv",
                        "program",
                        &anchor_row_id,
                        &payload,
                        1,
                        "gates.is_real",
                    );
                }
""",
    )

    # Memory log snapshot + prev state before execute.
    contents = _insert_after(
        contents,
        anchor="if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {",
        guard="let mem_log_start =",
        insert=r"""

                        // Snapshot memory logs to attribute memory chips per instruction.
                        let mem_log_start = memory_controller.get_memory_logs().len();

                        let prev_pc = pc;
                        let prev_timestamp = timestamp;
""",
    )

    # Post-exec memory chips + boundary + execution-bus + per-step increment.
    contents = _insert_after(
        contents,
        anchor="timestamp = next_state.timestamp;",
        guard="ExecutionBus",
        insert=r"""

                        // Emit memory-related chips as ChipRow markers.
                        //
                        // NOTE: During execution, OpenVM accumulates *memory logs* in online memory.
                        // Those logs are later replayed in `finalize()` to populate memory trace
                        // chips (Boundary, AccessAdapter<N>, ...). We attribute per-instruction
                        // "memory chips involved" based on the newly-added memory-log entries here.
                        if fuzzer_utils::is_trace_logging() {
                            let gates = json!({"is_real": 1}).to_string();
                            let logs = memory_controller.get_memory_logs();
                            let new_logs = logs.iter().skip(mem_log_start);

                            let mut boundary_spaces: Vec<u32> = Vec::new();
                            let mut access_count: u32 = 0;

                            for (i, entry) in new_logs.enumerate() {
                                let record_id = (mem_log_start + i) as u32;
                                match entry {
                                    MemoryLogEntry::Read { address_space, pointer, len } => {
                                        access_count += 1;
                                        if *address_space != 0
                                            && !boundary_spaces.contains(address_space)
                                        {
                                            boundary_spaces.push(*address_space);
                                        }
                                        let chip = format!("AccessAdapter<{}>", len);
                                        let locals = json!({
                                            "record_id": record_id,
                                            "op": "read",
                                            "address_space": address_space,
                                            "pointer": pointer,
                                            "len": len,
                                        })
                                        .to_string();
                                        fuzzer_utils::print_chip_row_json(
                                            "openvm",
                                            &chip,
                                            &gates,
                                            &locals,
                                        );

                                        let anchor_row_id = fuzzer_utils::get_last_row_id();
                                        let payload = json!({
                                            "record_id": record_id,
                                            "op": "read",
                                            "address_space": address_space,
                                            "pointer": pointer,
                                            "len": len,
                                        })
                                        .to_string();
                                        fuzzer_utils::print_interaction_json(
                                            "MemoryBus",
                                            "send",
                                            "memory",
                                            &anchor_row_id,
                                            &payload,
                                            1,
                                            "gates.is_real",
                                        );
                                    }
                                    MemoryLogEntry::Write { address_space, pointer, data } => {
                                        access_count += 1;
                                        if *address_space != 0
                                            && !boundary_spaces.contains(address_space)
                                        {
                                            boundary_spaces.push(*address_space);
                                        }
                                        let len = data.len() as u32;
                                        let chip = format!("AccessAdapter<{}>", len);
                                        let locals = json!({
                                            "record_id": record_id,
                                            "op": "write",
                                            "address_space": address_space,
                                            "pointer": pointer,
                                            "len": len,
                                        })
                                        .to_string();
                                        fuzzer_utils::print_chip_row_json(
                                            "openvm",
                                            &chip,
                                            &gates,
                                            &locals,
                                        );

                                        let anchor_row_id = fuzzer_utils::get_last_row_id();
                                        let payload = json!({
                                            "record_id": record_id,
                                            "op": "write",
                                            "address_space": address_space,
                                            "pointer": pointer,
                                            "len": len,
                                        })
                                        .to_string();
                                        fuzzer_utils::print_interaction_json(
                                            "MemoryBus",
                                            "send",
                                            "memory",
                                            &anchor_row_id,
                                            &payload,
                                            1,
                                            "gates.is_real",
                                        );
                                    }
                                    MemoryLogEntry::IncrementTimestampBy(_) => {}
                                }
                            }

                            // Boundary: constrain which address spaces are accessed.
                            if access_count > 0 {
                                let chip = "Boundary".to_string();
                                let locals = json!({
                                    "access_count": access_count,
                                    "address_spaces": boundary_spaces,
                                })
                                .to_string();
                                fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
                                let anchor_row_id = fuzzer_utils::get_last_row_id();
                                let payload = json!({
                                    "access_count": access_count,
                                    "address_spaces": boundary_spaces,
                                })
                                .to_string();
                                fuzzer_utils::print_interaction_json(
                                    "Boundary",
                                    "send",
                                    "memory",
                                    &anchor_row_id,
                                    &payload,
                                    1,
                                    "gates.is_real",
                                );
                            }
                        }

                        // Execution-bus semantics: (pc,timestamp) transitions are constrained via
                        // the execution bus (checked by the connector air). We record the edge as
                        // a ChipRow so buckets can reason about next_pc / timestamp changes.
                        if fuzzer_utils::is_trace_logging() {
                            let gates = json!({"is_real": 1}).to_string();
                            let locals = json!({
                                "from_pc": prev_pc,
                                "to_pc": pc,
                                "from_timestamp": prev_timestamp,
                                "to_timestamp": timestamp,
                                "opcode": opcode.as_usize(),
                            })
                            .to_string();
                            let chip = "VmConnectorAir".to_string();
                            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);

                            let anchor_row_id = fuzzer_utils::get_last_row_id();
                            let recv_payload = json!({
                                "pc": prev_pc,
                                "timestamp": prev_timestamp,
                            })
                            .to_string();
                            fuzzer_utils::print_interaction_json(
                                "ExecutionBus",
                                "recv",
                                "global",
                                &anchor_row_id,
                                &recv_payload,
                                1,
                                "gates.is_real",
                            );
                            let send_payload = json!({
                                "pc": pc,
                                "timestamp": timestamp,
                            })
                            .to_string();
                            fuzzer_utils::print_interaction_json(
                                "ExecutionBus",
                                "send",
                                "global",
                                &anchor_row_id,
                                &send_payload,
                                1,
                                "gates.is_real",
                            );
                        }
""",
    )

    # Per-op step increment (needed so bucket code gets `op_spans`).
    contents = _insert_before(
        contents,
        anchor="(opcode, dsl_instr.cloned())",
        guard="fuzzer_utils::inc_step()",
        insert=r"""

                // Advance "op index" for micro-op grouping.
                fuzzer_utils::print_trace_info();
                fuzzer_utils::inc_step();
""",
    )

    segment_rs.write_text(contents)


def _patch_regzero_interpreter_preflight_for_microops(openvm_install_path: Path) -> None:
    """
    regzero snapshot uses the preflight interpreter loop for trace-generation. Patch it to emit
    ProgramChip + ProgramBus and a lightweight ExecutionBus edge per instruction.
    """
    path = (
        openvm_install_path
        / "crates"
        / "vm"
        / "src"
        / "arch"
        / "interpreter_preflight.rs"
    )
    if not path.exists():
        return

    contents = path.read_text()
    # Idempotence: allow incremental additions (e.g. later adding Exec(...) chip markers).
    if (
        "ProgramChip" in contents
        and "ProgramBus" in contents
        and "ExecutionBus" in contents
        and "fuzzer_utils::inc_step();" in contents
        and "Exec(" in contents
        and "fuzzer_utils::update_hints" in contents
        and "fuzzer_utils::record_pc_step" in contents
        and "fuzzer_utils::record_pc_hints" in contents
    ):
        return

    # Ensure serde_json::json import.
    if "use serde_json::json;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            contents = contents[:header_end] + "\nuse serde_json::json;\n" + contents[header_end:]

    # Ensure we can call fuzzer_utils even if assert-rewrite didn't touch this file.
    if "use fuzzer_utils;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            contents = contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]

    # Pre-exec: ProgramChip + ProgramBus.
    contents = _insert_after(
        contents,
        anchor='tracing::trace!("pc: {pc:#x} | {:?}", pc_entry.insn);',
        guard="record_pc_hints",
        insert=r"""

        // Populate human-readable hints and record pc -> step mapping for tracegen (fill_trace_row).
        // NOTE: regzero tracegen reconstructs step indices from per-AIR records; those records include
        // `from_pc`, so this mapping lets tracegen-emitted micro-ops align with per-instruction buckets.
        fuzzer_utils::update_hints(pc, &format!("{:?}", pc_entry.insn), &format!("{:?}", pc_entry.insn));
        fuzzer_utils::record_pc_step(pc);
        fuzzer_utils::record_pc_hints(pc);

        let beak_from_timestamp = state.memory.timestamp();
        if fuzzer_utils::is_trace_logging() {
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "pc": pc,
                "opcode": pc_entry.insn.opcode.as_usize(),
                "operands": [
                    pc_entry.insn.a.as_canonical_u32(),
                    pc_entry.insn.b.as_canonical_u32(),
                    pc_entry.insn.c.as_canonical_u32(),
                    pc_entry.insn.d.as_canonical_u32(),
                    pc_entry.insn.e.as_canonical_u32(),
                    pc_entry.insn.f.as_canonical_u32(),
                    pc_entry.insn.g.as_canonical_u32(),
                ],
            })
            .to_string();
            let chip = "ProgramChip".to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);

            let anchor_row_id = fuzzer_utils::get_last_row_id();
            let payload = json!({
                "pc": pc,
                "opcode": pc_entry.insn.opcode.as_usize(),
                "operands": [
                    pc_entry.insn.a.as_canonical_u32(),
                    pc_entry.insn.b.as_canonical_u32(),
                    pc_entry.insn.c.as_canonical_u32(),
                    pc_entry.insn.d.as_canonical_u32(),
                    pc_entry.insn.e.as_canonical_u32(),
                    pc_entry.insn.f.as_canonical_u32(),
                    pc_entry.insn.g.as_canonical_u32(),
                ],
            })
            .to_string();
            fuzzer_utils::print_interaction_json(
                "ProgramBus",
                "recv",
                "program",
                &anchor_row_id,
                &payload,
                1,
                "gates.is_real",
            );
        }
""",
    )

    # Per-instruction executor chip marker (may be added later than ProgramChip patch).
    contents = _insert_after(
        contents,
        anchor="if fuzzer_utils::is_trace_logging() {",
        guard="Exec(",
        insert=r"""
            // Per-instruction "main chip" marker at the executor granularity.
            // regzero-era preflight execution does not expose adapter/core splits here.
            // TODO(beak-fuzz): If we want ChipRow outputs for concrete AIRs like
            // `Rv32JalrAdapterAir` / `Rv32BranchAdapterAir` (with their real column/locals
            // payloads), we must instrument the trace build/filler stage that materializes those
            // AIR rows (e.g. the rv32im adapter fillers / tracegen). The preflight interpreter
            // only sees decoded `Instruction` and executor dispatch, so it cannot access the
            // per-AIR row objects needed to print accurate ChipRow locals.
            let opcode_name = executor.get_opcode_name(pc_entry.insn.opcode.as_usize());
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "pc": pc,
                "opcode": pc_entry.insn.opcode.as_usize(),
                "opcode_name": opcode_name,
                "operands": [
                    pc_entry.insn.a.as_canonical_u32(),
                    pc_entry.insn.b.as_canonical_u32(),
                    pc_entry.insn.c.as_canonical_u32(),
                    pc_entry.insn.d.as_canonical_u32(),
                    pc_entry.insn.e.as_canonical_u32(),
                    pc_entry.insn.f.as_canonical_u32(),
                    pc_entry.insn.g.as_canonical_u32(),
                ],
            })
            .to_string();
            let chip = format!("Exec({})", opcode_name);
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);

""",
    )

    # Post-exec: ExecutionBus edge + per-op increment.
    contents = _insert_after(
        contents,
        anchor="executor.execute(vm_state_mut, &pc_entry.insn)?;",
        guard="ExecutionBus",
        insert=r"""

        if fuzzer_utils::is_trace_logging() {
            let to_pc = state.pc();
            let to_timestamp = state.memory.timestamp();
            let from_timestamp = beak_from_timestamp;
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "from_pc": pc,
                "to_pc": to_pc,
                "from_timestamp": from_timestamp,
                "to_timestamp": to_timestamp,
                "opcode": pc_entry.insn.opcode.as_usize(),
            })
            .to_string();
            let chip = "VmConnectorAir".to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);

            let anchor_row_id = fuzzer_utils::get_last_row_id();
            let recv_payload = json!({
                "pc": pc,
                "timestamp": from_timestamp,
            })
            .to_string();
            fuzzer_utils::print_interaction_json(
                "ExecutionBus",
                "recv",
                "global",
                &anchor_row_id,
                &recv_payload,
                1,
                "gates.is_real",
            );
            let send_payload = json!({
                "pc": to_pc,
                "timestamp": to_timestamp,
            })
            .to_string();
            fuzzer_utils::print_interaction_json(
                "ExecutionBus",
                "send",
                "global",
                &anchor_row_id,
                &send_payload,
                1,
                "gates.is_real",
            );
        }

        fuzzer_utils::print_trace_info();
        fuzzer_utils::inc_step();
""",
    )

    path.write_text(contents)


def _patch_regzero_tracegen_extensions_for_microops(openvm_install_path: Path) -> None:
    """
    regzero snapshot: tracegen entry point has access to per-AIR (chip) names, which we expose via
    `fuzzer_utils::set_current_air_name(...)` so deeper fillers can label micro-ops consistently.
    """
    path = openvm_install_path / "crates" / "vm" / "src" / "arch" / "extensions.rs"
    if not path.exists():
        return

    contents = path.read_text()
    # Repair: earlier injection used `set_current_air_name(air_name)` but the API expects `&str`.
    if "fuzzer_utils::set_current_air_name(air_name);" in contents:
        contents = contents.replace(
            "fuzzer_utils::set_current_air_name(air_name);",
            "fuzzer_utils::set_current_air_name(&air_name);",
        )
        path.write_text(contents)
        return
    if "fuzzer_utils::set_current_air_name(&air_name);" in contents:
        return

    if "use fuzzer_utils;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            contents = contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]

    contents = _insert_after(
        contents,
        anchor="let air_name = self.inventory.airs.ext_airs[insertion_idx].name();",
        guard="set_current_air_name",
        insert=r"""
                            fuzzer_utils::set_current_air_name(&air_name);
""",
    )
    path.write_text(contents)


def _patch_regzero_rv32im_adapters_for_microops(openvm_install_path: Path) -> None:
    """
    regzero snapshot: emit ChipRow micro-ops for key RV32IM adapter AIRs from their
    AdapterTraceFiller::fill_trace_row implementations.
    """
    branch_path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "adapters"
        / "branch.rs"
    )
    jalr_path = (
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "adapters"
        / "jalr.rs"
    )

    for p in (branch_path, jalr_path):
        if not p.exists():
            continue
        c = p.read_text()
        if "use serde_json::json;" not in c:
            header_end = c.find("\n\n")
            if header_end > 0:
                c = c[:header_end] + "\nuse serde_json::json;\n" + c[header_end:]
        p.write_text(c)

    if branch_path.exists():
        c = branch_path.read_text()
        # Drop any prior beak-fuzz capture/emit blocks (keep the rest intact).
        c = re.sub(
            r"\n\s*// beak_fuzz_emit_chip_row_v2.*?\n\s*let beak_from_pc = .*?;\n\s*let beak_from_timestamp = .*?;\n\s*let beak_rs1_ptr = .*?;\n\s*let beak_rs2_ptr = .*?;\n",
            "\n",
            c,
            flags=re.DOTALL,
        )
        c = re.sub(
            r"\n\s*// beak-fuzz: emit adapter ChipRow at tracegen time \(regzero snapshot\)\.\n\s*if fuzzer_utils::is_trace_logging\(\) \{\n.*?\n\s*fuzzer_utils::print_chip_row_json\(\"openvm\", &chip, &gates, &locals\);\n\s*\}\n",
            "\n",
            c,
            flags=re.DOTALL,
        )
        branch_path.write_text(c)

        c = branch_path.read_text()
        # Ensure v3 capture block is present and up-to-date (older injections captured too few fields).
        # Rewrite any existing v3 capture region (marker -> adapter_row borrow) to keep it stable.
        if "beak_fuzz_emit_chip_row_v3_capture" in c:
            c = re.sub(
                r"\n(?P<indent>\s*)// beak_fuzz_emit_chip_row_v3_capture[\s\S]*?\n(?P=indent)let adapter_row:",
                r"""

\g<indent>// beak_fuzz_emit_chip_row_v3_capture
\g<indent>// beak-fuzz (regzero): capture record fields before the row is overwritten.
\g<indent>let beak_from_pc = record.from_pc;
\g<indent>let beak_from_timestamp = record.from_timestamp;
\g<indent>let beak_rs1_ptr = record.rs1_ptr;
\g<indent>let beak_rs2_ptr = record.rs2_ptr;
\g<indent>let beak_reads_prev_timestamp_0 = record.reads_aux[0].prev_timestamp;
\g<indent>let beak_reads_prev_timestamp_1 = record.reads_aux[1].prev_timestamp;

\g<indent>let adapter_row:""",
                c,
                count=1,
                flags=re.DOTALL,
            )
        else:
            # Capture record fields early (before overwriting the row) so we can print them later.
            c = _insert_after(
                c,
                anchor="unsafe { get_record_from_slice(&mut adapter_row, ()) };",
                guard="beak_fuzz_emit_chip_row_v3_capture",
                insert=r"""

        // beak_fuzz_emit_chip_row_v3_capture
        // beak-fuzz (regzero): capture record fields before the row is overwritten.
        let beak_from_pc = record.from_pc;
        let beak_from_timestamp = record.from_timestamp;
        let beak_rs1_ptr = record.rs1_ptr;
        let beak_rs2_ptr = record.rs2_ptr;
        let beak_reads_prev_timestamp_0 = record.reads_aux[0].prev_timestamp;
        let beak_reads_prev_timestamp_1 = record.reads_aux[1].prev_timestamp;
""",
            )

        # Ensure v3 emit block is present. Older injections sometimes left only the marker comment.
        if 'let chip = "Rv32BranchAdapterAir"' not in c:
            if "beak_fuzz_emit_chip_row_v3_emit" in c:
                c = re.sub(
                    r"(?P<indent>\s*)// beak_fuzz_emit_chip_row_v3_emit\s*\n",
                    r"""\g<indent>// beak_fuzz_emit_chip_row_v3_emit
\g<indent>// beak-fuzz: emit adapter ChipRow at tracegen time (regzero snapshot).
\g<indent>if fuzzer_utils::is_trace_logging() {
\g<indent>    fuzzer_utils::set_step_from_pc(beak_from_pc);
\g<indent>    let chip = "Rv32BranchAdapterAir".to_string();
\g<indent>    let gates = json!({"is_real": 1}).to_string();
\g<indent>    let locals = json!({
\g<indent>        "from_state": {"pc": beak_from_pc, "timestamp": beak_from_timestamp},
\g<indent>        "rs1_ptr": beak_rs1_ptr,
\g<indent>        "rs2_ptr": beak_rs2_ptr,
\g<indent>        "reads_aux": [
\g<indent>            {"prev_timestamp": beak_reads_prev_timestamp_0},
\g<indent>            {"prev_timestamp": beak_reads_prev_timestamp_1},
\g<indent>        ],
\g<indent>    })
\g<indent>    .to_string();
\g<indent>    fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
\g<indent>}
""",
                    c,
                    count=1,
                    flags=re.MULTILINE,
                )
            else:
                # Emit after the last assignment.
                c = _insert_after(
                    c,
                    anchor="adapter_row.rs2_ptr = F::from_canonical_u32(record.rs2_ptr);",
                    guard="beak_fuzz_emit_chip_row_v3_emit",
                    insert=r"""

        // beak_fuzz_emit_chip_row_v3_emit
        // beak-fuzz: emit adapter ChipRow at tracegen time (regzero snapshot).
        if fuzzer_utils::is_trace_logging() {
            fuzzer_utils::set_step_from_pc(beak_from_pc);
            let chip = "Rv32BranchAdapterAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "from_state": {"pc": beak_from_pc, "timestamp": beak_from_timestamp},
                "rs1_ptr": beak_rs1_ptr,
                "rs2_ptr": beak_rs2_ptr,
                "reads_aux": [
                    {"prev_timestamp": beak_reads_prev_timestamp_0},
                    {"prev_timestamp": beak_reads_prev_timestamp_1},
                ],
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
""",
                )

        branch_path.write_text(c)

    if jalr_path.exists():
        c = jalr_path.read_text()
        c = re.sub(
            r"\n\s*// beak_fuzz_emit_chip_row_v2.*?\n\s*let beak_from_pc = .*?;\n\s*let beak_from_timestamp = .*?;\n\s*let beak_rs1_ptr = .*?;\n\s*let beak_rd_ptr = .*?;\n",
            "\n",
            c,
            flags=re.DOTALL,
        )
        c = re.sub(
            r"\n\s*// beak-fuzz: emit adapter ChipRow at tracegen time \(regzero snapshot\)\.\n\s*if fuzzer_utils::is_trace_logging\(\) \{\n.*?\n\s*fuzzer_utils::print_chip_row_json\(\"openvm\", &chip, &gates, &locals\);\n\s*\}\n",
            "\n",
            c,
            flags=re.DOTALL,
        )
        jalr_path.write_text(c)


def _insert_before_fn_close(contents: str, *, fn_name: str, insert: str, guard: str) -> str:
    """
    Insert `insert` right before the closing `}` of `fn <fn_name>(...) { ... }`.
    Uses a small brace-matching scan to avoid brittle regexes across OpenVM snapshots.
    """
    if guard in contents:
        return contents
    needle = f"fn {fn_name}"
    start = contents.find(needle)
    if start < 0:
        raise RuntimeError(f"function not found for injection: {needle!r}")
    brace_open = contents.find("{", start)
    if brace_open < 0:
        raise RuntimeError(f"function body not found for injection: {needle!r}")
    depth = 0
    for i in range(brace_open, len(contents)):
        ch = contents[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                # Insert right before this `}`.
                return contents[:i] + insert + contents[i:]
    raise RuntimeError(f"unterminated function body for injection: {needle!r}")


def _ensure_serde_json_import(path: Path) -> None:
    if not path.exists():
        return
    c = path.read_text()
    if "use serde_json::json;" in c:
        return
    header_end = c.find("\n\n")
    if header_end > 0:
        c = c[:header_end] + "\nuse serde_json::json;\n" + c[header_end:]
        path.write_text(c)


def _patch_regzero_rv32im_more_adapters_for_microops(openvm_install_path: Path) -> None:
    """
    regzero snapshot: emit ChipRow micro-ops for additional RV32IM adapter AIRs from their
    AdapterTraceFiller::fill_trace_row implementations.
    """
    adapters_dir = (
        openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "adapters"
    )
    targets = {
        "alu.rs": ("Rv32BaseAluAdapterAir", "fill_trace_row"),
        "mul.rs": ("Rv32MultAdapterAir", "fill_trace_row"),
        "rdwrite.rs": ("Rv32RdWriteAdapterAir", "fill_trace_row"),
        "loadstore.rs": ("Rv32LoadStoreAdapterAir", "fill_trace_row"),
    }
    for filename in targets.keys():
        _ensure_serde_json_import(adapters_dir / filename)

    # --- alu.rs (Rv32BaseAluAdapterFiller) ---
    alu_rs = adapters_dir / "alu.rs"
    if alu_rs.exists():
        c = alu_rs.read_text()
        if "beak_fuzz_emit_chip_row_v3_alu_emit" not in c:
            # Capture record fields right after get_record_from_slice.
            c = _insert_after(
                c,
                anchor="unsafe { get_record_from_slice(&mut adapter_row, ()) };",
                guard="beak_fuzz_emit_chip_row_v3_alu_capture",
                insert=r"""

        // beak_fuzz_emit_chip_row_v3_alu_capture
        let beak_from_pc = record.from_pc;
        let beak_from_timestamp = record.from_timestamp;
        let beak_rs1_ptr = record.rs1_ptr;
        let beak_rs2_as = record.rs2_as;
        let beak_rs2 = record.rs2;
        let beak_rd_ptr = record.rd_ptr;
        let beak_reads_prev_timestamp_0 = record.reads_aux[0].prev_timestamp;
        let beak_reads_prev_timestamp_1 = record.reads_aux[1].prev_timestamp;
        let beak_writes_prev_timestamp = record.writes_aux.prev_timestamp;
        let beak_writes_prev_data = record.writes_aux.prev_data;
""",
            )
            # Emit right before the end of the function.
            c = _insert_before_fn_close(
                c,
                fn_name="fill_trace_row",
                guard="beak_fuzz_emit_chip_row_v3_alu_emit",
                insert=r"""

        // beak_fuzz_emit_chip_row_v3_alu_emit
        if fuzzer_utils::is_trace_logging() {
            fuzzer_utils::set_step_from_pc(beak_from_pc);
            let chip = "Rv32BaseAluAdapterAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "from_state": {"pc": beak_from_pc, "timestamp": beak_from_timestamp},
                "rs1_ptr": beak_rs1_ptr,
                "rs2_as": beak_rs2_as,
                "rs2": beak_rs2,
                "rd_ptr": beak_rd_ptr,
                "reads_aux": [
                    {"prev_timestamp": beak_reads_prev_timestamp_0},
                    {"prev_timestamp": beak_reads_prev_timestamp_1},
                ],
                "writes_aux": {"prev_timestamp": beak_writes_prev_timestamp, "prev_data": beak_writes_prev_data},
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
""",
            )
            alu_rs.write_text(c)

    # --- mul.rs (Rv32MultAdapterFiller) ---
    mul_rs = adapters_dir / "mul.rs"
    if mul_rs.exists():
        c = mul_rs.read_text()
        if "beak_fuzz_emit_chip_row_v3_mul_emit" not in c:
            c = _insert_after(
                c,
                anchor="unsafe { get_record_from_slice(&mut adapter_row, ()) };",
                guard="beak_fuzz_emit_chip_row_v3_mul_capture",
                insert=r"""

        // beak_fuzz_emit_chip_row_v3_mul_capture
        let beak_from_pc = record.from_pc;
        let beak_from_timestamp = record.from_timestamp;
        let beak_rs1_ptr = record.rs1_ptr;
        let beak_rs2_ptr = record.rs2_ptr;
        let beak_rd_ptr = record.rd_ptr;
        let beak_reads_prev_timestamp_0 = record.reads_aux[0].prev_timestamp;
        let beak_reads_prev_timestamp_1 = record.reads_aux[1].prev_timestamp;
        let beak_writes_prev_timestamp = record.writes_aux.prev_timestamp;
        let beak_writes_prev_data = record.writes_aux.prev_data;
""",
            )
            c = _insert_before_fn_close(
                c,
                fn_name="fill_trace_row",
                guard="beak_fuzz_emit_chip_row_v3_mul_emit",
                insert=r"""

        // beak_fuzz_emit_chip_row_v3_mul_emit
        if fuzzer_utils::is_trace_logging() {
            fuzzer_utils::set_step_from_pc(beak_from_pc);
            let chip = "Rv32MultAdapterAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "from_state": {"pc": beak_from_pc, "timestamp": beak_from_timestamp},
                "rs1_ptr": beak_rs1_ptr,
                "rs2_ptr": beak_rs2_ptr,
                "rd_ptr": beak_rd_ptr,
                "reads_aux": [
                    {"prev_timestamp": beak_reads_prev_timestamp_0},
                    {"prev_timestamp": beak_reads_prev_timestamp_1},
                ],
                "writes_aux": {"prev_timestamp": beak_writes_prev_timestamp, "prev_data": beak_writes_prev_data},
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
""",
            )
            mul_rs.write_text(c)

    # --- rdwrite.rs (Rv32RdWriteAdapterFiller + Rv32CondRdWriteAdapterFiller) ---
    rdwrite_rs = adapters_dir / "rdwrite.rs"
    if rdwrite_rs.exists():
        c = rdwrite_rs.read_text()
        if "beak_fuzz_emit_chip_row_v3_rdwrite_emit" not in c:
            c = _insert_after(
                c,
                anchor="unsafe { get_record_from_slice(&mut adapter_row, ()) };",
                guard="beak_fuzz_emit_chip_row_v3_rdwrite_capture",
                insert=r"""

        // beak_fuzz_emit_chip_row_v3_rdwrite_capture
        let beak_from_pc = record.from_pc;
        let beak_from_timestamp = record.from_timestamp;
        let beak_rd_ptr = record.rd_ptr;
        let beak_rd_prev_timestamp = record.rd_aux_record.prev_timestamp;
        let beak_rd_prev_data = record.rd_aux_record.prev_data;
""",
            )
            # Emit twice in the file (first fill_trace_row belongs to Rv32RdWriteAdapterFiller).
            c = _insert_before_fn_close(
                c,
                fn_name="fill_trace_row",
                guard="beak_fuzz_emit_chip_row_v3_rdwrite_emit",
                insert=r"""

        // beak_fuzz_emit_chip_row_v3_rdwrite_emit
        if fuzzer_utils::is_trace_logging() {
            fuzzer_utils::set_step_from_pc(beak_from_pc);
            let chip = "Rv32RdWriteAdapterAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "from_state": {"pc": beak_from_pc, "timestamp": beak_from_timestamp},
                "rd_ptr": beak_rd_ptr,
                "rd_aux": {"prev_timestamp": beak_rd_prev_timestamp, "prev_data": beak_rd_prev_data},
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
""",
            )
            rdwrite_rs.write_text(c)

        # Cond adapter: best-effort emit (it shares the same record layout).
        c = rdwrite_rs.read_text()
        if "beak_fuzz_emit_chip_row_v3_cond_rdwrite_emit" not in c:
            # Insert into the *second* fill_trace_row by starting search after the first marker.
            first_idx = c.find("beak_fuzz_emit_chip_row_v3_rdwrite_emit")
            if first_idx < 0:
                first_idx = 0
            tail = c[first_idx:]
            try:
                patched_tail = _insert_before_fn_close(
                    tail,
                    fn_name="fill_trace_row",
                    guard="beak_fuzz_emit_chip_row_v3_cond_rdwrite_emit",
                    insert=r"""

        // beak_fuzz_emit_chip_row_v3_cond_rdwrite_emit
        if fuzzer_utils::is_trace_logging() {
            fuzzer_utils::set_step_from_pc(record.from_pc);
            let chip = "Rv32CondRdWriteAdapterAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "from_state": {"pc": record.from_pc, "timestamp": record.from_timestamp},
                "needs_write": (record.rd_ptr != u32::MAX),
                "rd_ptr": record.rd_ptr,
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
""",
                )
                c = c[:first_idx] + patched_tail
                rdwrite_rs.write_text(c)
            except Exception:
                # If brace matching fails, skip silently for snapshot drift.
                pass

    # --- loadstore.rs (Rv32LoadStoreAdapterFiller) ---
    loadstore_rs = adapters_dir / "loadstore.rs"
    if loadstore_rs.exists():
        c = loadstore_rs.read_text()
        if "beak_fuzz_emit_chip_row_v3_loadstore_emit" not in c:
            c = _insert_after(
                c,
                anchor="unsafe { get_record_from_slice(&mut adapter_row, ()) };",
                guard="beak_fuzz_emit_chip_row_v3_loadstore_capture",
                insert=r"""

        // beak_fuzz_emit_chip_row_v3_loadstore_capture
        let beak_from_pc = record.from_pc;
        let beak_from_timestamp = record.from_timestamp;
        let beak_mem_as = record.mem_as;
        let beak_rs1_ptr = record.rs1_ptr;
        let beak_rs1_val = record.rs1_val;
        let beak_imm = record.imm;
        let beak_imm_sign = record.imm_sign;
        let beak_rd_rs2_ptr = record.rd_rs2_ptr;
        let beak_rs1_prev_timestamp = record.rs1_aux_record.prev_timestamp;
        let beak_read_prev_timestamp = record.read_data_aux.prev_timestamp;
        let beak_write_prev_timestamp = record.write_prev_timestamp;
""",
            )
            c = _insert_before_fn_close(
                c,
                fn_name="fill_trace_row",
                guard="beak_fuzz_emit_chip_row_v3_loadstore_emit",
                insert=r"""

        // beak_fuzz_emit_chip_row_v3_loadstore_emit
        if fuzzer_utils::is_trace_logging() {
            fuzzer_utils::set_step_from_pc(beak_from_pc);
            let chip = "Rv32LoadStoreAdapterAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "from_state": {"pc": beak_from_pc, "timestamp": beak_from_timestamp},
                "mem_as": beak_mem_as,
                "rs1_ptr": beak_rs1_ptr,
                "rs1_val": beak_rs1_val,
                "imm": beak_imm,
                "imm_sign": beak_imm_sign,
                "rd_rs2_ptr": beak_rd_rs2_ptr,
                "rs1_aux": {"prev_timestamp": beak_rs1_prev_timestamp},
                "read_data_aux": {"prev_timestamp": beak_read_prev_timestamp},
                "write_base_aux": {"prev_timestamp": beak_write_prev_timestamp},
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
""",
            )
            loadstore_rs.write_text(c)


def _patch_regzero_rv32im_cores_for_microops(openvm_install_path: Path) -> None:
    """
    regzero snapshot: emit ChipRow micro-ops for key RV32IM *core* AIRs from their
    TraceFiller::fill_trace_row implementations. These run after adapter.fill_trace_row, so
    they inherit `pc/step` hints set by the adapter instrumentation.
    """
    base = openvm_install_path / "extensions" / "rv32im" / "circuit" / "src"
    core_files = [
        base / "auipc" / "core.rs",
        base / "base_alu" / "core.rs",
        base / "divrem" / "core.rs",
        base / "load_sign_extend" / "core.rs",
        base / "loadstore" / "core.rs",
    ]
    for p in core_files:
        _ensure_serde_json_import(p)

    # auipc/core.rs
    auipc = base / "auipc" / "core.rs"
    if auipc.exists():
        c = auipc.read_text()
        if "beak_fuzz_emit_chip_row_v3_auipc_core" not in c:
            c = _insert_before_fn_close(
                c,
                fn_name="fill_trace_row",
                guard="beak_fuzz_emit_chip_row_v3_auipc_core",
                insert=r"""

        // beak_fuzz_emit_chip_row_v3_auipc_core
        if fuzzer_utils::is_trace_logging() {
            let chip = "Rv32AuipcCoreAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "from_pc": record.from_pc,
                "imm": record.imm,
                "rd_data": rd_data,
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
""",
            )
            auipc.write_text(c)

    # base_alu/core.rs
    base_alu = base / "base_alu" / "core.rs"
    if base_alu.exists():
        c = base_alu.read_text()
        block = r"""

        // beak_fuzz_emit_chip_row_v3_base_alu_core
        if fuzzer_utils::is_trace_logging() {
            let chip = "BaseAluCoreAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let b = record.b.iter().copied().collect::<Vec<u8>>();
            let c_ = record.c.iter().copied().collect::<Vec<u8>>();
            let a_ = a.iter().copied().collect::<Vec<u8>>();
            let locals = json!({
                "local_opcode": (record.local_opcode as u64),
                "b": b,
                "c": c_,
                "a": a_,
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
"""
        if "beak_fuzz_emit_chip_row_v3_base_alu_core" in c:
            c2 = re.sub(
                r"\n\s*// beak_fuzz_emit_chip_row_v3_base_alu_core[\s\S]*?fuzzer_utils::print_chip_row_json\(\"openvm\", &chip, &gates, &locals\);\n\s*}\n",
                block + "\n",
                c,
                count=1,
                flags=re.DOTALL,
            )
            if c2 != c:
                base_alu.write_text(c2)
        else:
            c = _insert_before_fn_close(
                c,
                fn_name="fill_trace_row",
                guard="beak_fuzz_emit_chip_row_v3_base_alu_core",
                insert=block,
            )
            base_alu.write_text(c)

    # divrem/core.rs
    divrem = base / "divrem" / "core.rs"
    if divrem.exists():
        c = divrem.read_text()
        block = r"""

        // beak_fuzz_emit_chip_row_v3_divrem_core
        if fuzzer_utils::is_trace_logging() {
            let chip = "DivRemCoreAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let b = record.b.iter().copied().collect::<Vec<u8>>();
            let c_ = record.c.iter().copied().collect::<Vec<u8>>();
            let q_ = q.iter().copied().collect::<Vec<u32>>();
            let r_ = r.iter().copied().collect::<Vec<u32>>();
            let locals = json!({
                "local_opcode": (record.local_opcode as u64),
                "is_signed": is_signed,
                "b": b,
                "c": c_,
                "q": q_,
                "r": r_,
                "case": format!("{:?}", case),
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
"""
        if "beak_fuzz_emit_chip_row_v3_divrem_core" in c:
            c2 = re.sub(
                r"\n\s*// beak_fuzz_emit_chip_row_v3_divrem_core[\s\S]*?fuzzer_utils::print_chip_row_json\(\"openvm\", &chip, &gates, &locals\);\n\s*}\n",
                block + "\n",
                c,
                count=1,
                flags=re.DOTALL,
            )
            if c2 != c:
                divrem.write_text(c2)
        else:
            c = _insert_before_fn_close(
                c,
                fn_name="fill_trace_row",
                guard="beak_fuzz_emit_chip_row_v3_divrem_core",
                insert=block,
            )
            divrem.write_text(c)

    # load_sign_extend/core.rs
    lse = base / "load_sign_extend" / "core.rs"
    if lse.exists():
        c = lse.read_text()
        block = r"""

        // beak_fuzz_emit_chip_row_v3_load_sign_extend_core
        if fuzzer_utils::is_trace_logging() {
            let chip = "LoadSignExtendCoreAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let prev_data = record.prev_data.iter().copied().collect::<Vec<u8>>();
            let read_data = record.read_data.iter().copied().collect::<Vec<u8>>();
            let locals = json!({
                "is_byte": record.is_byte,
                "shift_amount": record.shift_amount,
                "prev_data": prev_data,
                "read_data": read_data,
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
"""
        if "beak_fuzz_emit_chip_row_v3_load_sign_extend_core" in c:
            c2 = re.sub(
                r"\n\s*// beak_fuzz_emit_chip_row_v3_load_sign_extend_core[\s\S]*?fuzzer_utils::print_chip_row_json\(\"openvm\", &chip, &gates, &locals\);\n\s*}\n",
                block + "\n",
                c,
                count=1,
                flags=re.DOTALL,
            )
            if c2 != c:
                lse.write_text(c2)
        else:
            c = _insert_before_fn_close(
                c,
                fn_name="fill_trace_row",
                guard="beak_fuzz_emit_chip_row_v3_load_sign_extend_core",
                insert=block,
            )
            lse.write_text(c)

    # loadstore/core.rs
    ls = base / "loadstore" / "core.rs"
    if ls.exists():
        c = ls.read_text()
        block = r"""

        // beak_fuzz_emit_chip_row_v3_loadstore_core
        if fuzzer_utils::is_trace_logging() {
            let chip = "LoadStoreCoreAir".to_string();
            let gates = json!({"is_real": 1}).to_string();
            let read_data = record.read_data.iter().copied().collect::<Vec<u8>>();
            let prev_data = record.prev_data.iter().copied().collect::<Vec<u32>>();
            let write_data = write_data.iter().copied().collect::<Vec<u32>>();
            let locals = json!({
                "local_opcode": (record.local_opcode as u64),
                "shift_amount": record.shift_amount,
                "read_data": read_data,
                "prev_data": prev_data,
                "write_data": write_data,
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
        }
"""
        if "beak_fuzz_emit_chip_row_v3_loadstore_core" in c:
            c2 = re.sub(
                r"\n\s*// beak_fuzz_emit_chip_row_v3_loadstore_core[\s\S]*?fuzzer_utils::print_chip_row_json\(\"openvm\", &chip, &gates, &locals\);\n\s*}\n",
                block + "\n",
                c,
                count=1,
                flags=re.DOTALL,
            )
            if c2 != c:
                ls.write_text(c2)
        else:
            c = _insert_before_fn_close(
                c,
                fn_name="fill_trace_row",
                guard="beak_fuzz_emit_chip_row_v3_loadstore_core",
                insert=block,
            )
            ls.write_text(c)


def _patch_segment_and_regzero_microops(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    resolved_commit = resolve_openvm_commit(commit_or_branch)

    # segment.rs:
    # - For older audit snapshots we patch in-place (file layout differs).
    # - For main/ca36de we overwrite from a known template.
    if resolved_commit in {OPENVM_BENCHMARK_336F_COMMIT, OPENVM_BENCHMARK_F038_COMMIT}:
        _patch_audit_segment_rs_for_microops(openvm_install_path)
    elif resolved_commit in _OPENVM_SNAPSHOT_COMMITS:
        logger.info(
            "snapshot commit without segment template; skipping segment overwrite: %s",
            resolved_commit,
        )

    if resolved_commit == OPENVM_BENCHMARK_REGZERO_COMMIT:
        _patch_regzero_interpreter_preflight_for_microops(openvm_install_path)
        _patch_regzero_tracegen_extensions_for_microops(openvm_install_path)
        _patch_regzero_rv32im_adapters_for_microops(openvm_install_path)
        _patch_regzero_rv32im_more_adapters_for_microops(openvm_install_path)
        _patch_regzero_rv32im_cores_for_microops(openvm_install_path)
        return

    if resolved_commit in _OPENVM_SNAPSHOT_COMMITS:
        return

    overwrite_file(
        openvm_install_path / "crates" / "vm" / "src" / "arch" / "segment.rs",
        openvm_crates_vm_src_arch_segment_rs(resolved_commit),
    )

