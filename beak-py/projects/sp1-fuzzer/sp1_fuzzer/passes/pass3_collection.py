from __future__ import annotations

from pathlib import Path

from zkvm_fuzzer_utils.file import prepend_file


def _runtime_mod_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for p in [
        sp1_install_path / "core" / "src" / "runtime" / "mod.rs",
        sp1_install_path / "crates" / "core" / "src" / "runtime" / "mod.rs",
    ]:
        if p.exists():
            out.append(p)
    return out


def _insert_after(contents: str, *, anchor: str, insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        return contents
    pos = idx + len(anchor)
    return contents[:pos] + insert + contents[pos:]


def _ensure_use_fuzzer_utils(path: Path) -> None:
    c = path.read_text()
    if "use fuzzer_utils;" in c:
        return
    prepend_file(path, "#[allow(unused_imports)]\nuse fuzzer_utils;\n")


def _patch_runtime_mod(path: Path) -> None:
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()

    c = _insert_after(
        c,
        anchor="let record = self.mr(addr, self.shard(), self.timestamp(&position));",
        guard="// BEAK-INSERT: sp1.mr_cpu.witness_inject",
        insert="""
 // BEAK-INSERT: sp1.mr_cpu.witness_inject
        let beak_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("sp1.audit_timestamp.mem_row_wraparound", beak_step) {
            record.prev_timestamp = record.timestamp;
            record.timestamp = 0;
        }
        // BEAK-INSERT-END
""",
    )

    c = c.replace(
        "let record = self.mr(addr, self.shard(), self.timestamp(&position));",
        "let mut record = self.mr(addr, self.shard(), self.timestamp(&position));",
    )

    c = _insert_after(
        c,
        anchor="""        if !self.unconstrained && self.emit_events {
            match position {
                MemoryAccessPosition::A => self.memory_accesses.a = Some(record.into()),
                MemoryAccessPosition::B => self.memory_accesses.b = Some(record.into()),
                MemoryAccessPosition::C => self.memory_accesses.c = Some(record.into()),
                MemoryAccessPosition::Memory => self.memory_accesses.memory = Some(record.into()),
            }
        }""",
        guard="// BEAK-INSERT: sp1.mr_cpu.memory_interaction",
        insert="""
        // BEAK-INSERT: sp1.mr_cpu.memory_interaction
        if self.emit_events {
            fuzzer_utils::emit_memory_interaction(
                "receive",
                addr,
                record.value,
                record.timestamp,
                false,
            );
        }
        // BEAK-INSERT-END
""",
    )

    c = c.replace(
        "let record = self.mw(addr, value, self.shard(), self.timestamp(&position));",
        "let mut record = self.mw(addr, value, self.shard(), self.timestamp(&position));",
    )

    c = _insert_after(
        c,
        anchor="let mut record = self.mw(addr, value, self.shard(), self.timestamp(&position));",
        guard="// BEAK-INSERT: sp1.mw_cpu.witness_inject",
        insert="""
        // BEAK-INSERT: sp1.mw_cpu.witness_inject
        let beak_step = fuzzer_utils::next_witness_step();
        if fuzzer_utils::should_inject_witness("sp1.audit_timestamp.mem_row_wraparound", beak_step) {
            record.prev_timestamp = record.timestamp;
            record.timestamp = 0;
        }
        if fuzzer_utils::should_inject_witness(
            "sp1.audit_multiplicity_bool_constraint.local_event_row",
            beak_step,
        ) {
            record.value ^= 1;
        }
        // BEAK-INSERT-END
""",
    )

    c = _insert_after(
        c,
        anchor="""        if !self.unconstrained {
            match position {
                MemoryAccessPosition::A => {
                    fuzzer_utils::fuzzer_assert!(self.memory_accesses.a.is_none());
                    self.memory_accesses.a = Some(record.into());
                }
                MemoryAccessPosition::B => {
                    fuzzer_utils::fuzzer_assert!(self.memory_accesses.b.is_none());
                    self.memory_accesses.b = Some(record.into());
                }
                MemoryAccessPosition::C => {
                    fuzzer_utils::fuzzer_assert!(self.memory_accesses.c.is_none());
                    self.memory_accesses.c = Some(record.into());
                }
                MemoryAccessPosition::Memory => {
                    fuzzer_utils::fuzzer_assert!(self.memory_accesses.memory.is_none());
                    self.memory_accesses.memory = Some(record.into());
                }
            }
        }""",
        guard="// BEAK-INSERT: sp1.mw_cpu.memory_interaction",
        insert="""
        // BEAK-INSERT: sp1.mw_cpu.memory_interaction
        if self.emit_events {
            fuzzer_utils::emit_memory_interaction("send", addr, record.value, record.timestamp, true);
        }
        // BEAK-INSERT-END
""",
    )

    c = _insert_after(
        c,
        anchor="self.record.cpu_events.push(cpu_event);",
        guard="// BEAK-INSERT: sp1.emit_cpu.microops",
        insert="""
        // BEAK-INSERT: sp1.emit_cpu.microops
        let beak_operands = [
            instruction.op_a,
            instruction.op_b,
            instruction.op_c,
            if instruction.imm_b { 1 } else { 0 },
            if instruction.imm_c { 1 } else { 0 },
            0,
            0,
        ];
        fuzzer_utils::emit_instruction(
            pc,
            clk,
            next_pc,
            self.state.clk,
            instruction.opcode as u32,
            beak_operands,
        );
        fuzzer_utils::emit_cpu_chip_row(
            clk,
            pc,
            next_pc,
            instruction.opcode as u32,
            a,
            b,
            c,
            memory_store_value,
        );
        fuzzer_utils::emit_program_interaction(
            "receive",
            None,
            pc,
            instruction.opcode as u32,
            beak_operands,
        );
        fuzzer_utils::emit_execution_interaction("receive", None, pc, clk);
        fuzzer_utils::emit_execution_interaction("send", None, next_pc, self.state.clk);
        // BEAK-INSERT-END
""",
    )

    c = _insert_after(
        c,
        anchor="""        let event = AluEvent {
            shard: self.shard(),
            clk,
            channel: self.channel(),
            opcode,
            a,
            b,
            c,
        };""",
        guard="// BEAK-INSERT: sp1.emit_alu.microops",
        insert="""
        // BEAK-INSERT: sp1.emit_alu.microops
        fuzzer_utils::emit_alu_chip_row(clk, opcode as u32, a, b, c);
        // BEAK-INSERT-END
""",
    )

    path.write_text(c)


def apply(*, sp1_install_path: Path, commit_or_branch: str) -> None:
    _ = commit_or_branch
    for path in _runtime_mod_candidates(sp1_install_path):
        _patch_runtime_mod(path)
