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


def _executor_candidates(sp1_install_path: Path) -> list[Path]:
    out: list[Path] = []
    for p in [
        sp1_install_path / "crates" / "core" / "executor" / "src" / "executor.rs",
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


def _replace_guarded_block(contents: str, *, guard: str, replacement: str) -> str:
    guard_idx = contents.find(guard)
    if guard_idx < 0:
        return contents
    start = contents.rfind("\n", 0, guard_idx) + 1
    end_marker = "// BEAK-INSERT-END"
    end_idx = contents.find(end_marker, guard_idx)
    if end_idx < 0:
        return contents
    end = contents.find("\n", end_idx + len(end_marker))
    if end < 0:
        end = len(contents)
    else:
        end += 1
    return contents[:start] + replacement.lstrip("\n") + contents[end:]


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
        if fuzzer_utils::should_inject_witness("sp1.semantic.memory.timestamped_load_path", beak_step) {
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
        if fuzzer_utils::should_inject_witness("sp1.semantic.memory.timestamped_load_path", beak_step) {
            record.prev_timestamp = record.timestamp;
            record.timestamp = 0;
        }
        if fuzzer_utils::should_inject_witness(
            "sp1.semantic.lookup.boolean_multiplicity",
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


def _patch_executor(path: Path, commit_or_branch: str) -> None:
    _ensure_use_fuzzer_utils(path)
    c = path.read_text()

    c = _insert_after(
        c,
        anchor="pub const UNUSED_PC: u32 = 1;\n",
        guard="// BEAK-INSERT: sp1.executor.control_flow_injection.helpers",
        insert="""

const BEAK_CONTROL_FLOW_INJECT_KIND: &str = "sp1.semantic.exec.control_flow_binding";

// BEAK-INSERT: sp1.executor.control_flow_injection.helpers
fn beak_inject_variant_value<'a>(kind: &'a str, key: &str) -> Option<&'a str> {
    let (_, variant) = kind.split_once("::")?;
    for field in variant.split(',') {
        let (field_key, field_value) = field.split_once('=')?;
        if field_key == key {
            return Some(field_value);
        }
    }
    None
}

fn beak_control_flow_family_for_opcode(opcode: Opcode) -> Option<&'static str> {
    match opcode {
        Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
            Some("branch")
        }
        Opcode::JAL | Opcode::JALR => Some("jump"),
        Opcode::ECALL => Some("ecall"),
        _ => None,
    }
}

fn beak_branch_next_pc_mutation(mode: Option<&str>, pc: u32, observed_next_pc: u32) -> Option<u32> {
    let sequential = pc.wrapping_add(4);
    match mode {
        Some("noop_prefix") => None,
        Some("force_fallthrough") => Some(sequential),
        Some("force_taken_near") => {
            let near_taken = if observed_next_pc == sequential {
                pc.wrapping_add(8)
            } else {
                sequential
            };
            Some(near_taken)
        }
        _ => Some(pc.wrapping_add(0x10000)),
    }
}

fn beak_jump_next_pc_mutation(mode: Option<&str>, pc: u32, observed_next_pc: u32) -> Option<u32> {
    let sequential = pc.wrapping_add(4);
    match mode {
        Some("noop_prefix") => None,
        Some("force_sequential") => Some(if observed_next_pc == sequential {
            pc.wrapping_add(8)
        } else {
            sequential
        }),
        Some("force_near_jump") => Some(if observed_next_pc == pc.wrapping_add(8) {
            pc.wrapping_add(12)
        } else {
            pc.wrapping_add(8)
        }),
        _ => Some(pc.wrapping_add(0x10000)),
    }
}

fn beak_ecall_next_pc_mutation(mode: Option<&str>, pc: u32, observed_next_pc: u32) -> Option<u32> {
    match mode {
        Some("noop_prefix") => None,
        Some("near_jump") => Some(if observed_next_pc == pc.wrapping_add(8) {
            pc.wrapping_add(12)
        } else {
            pc.wrapping_add(8)
        }),
        Some("mid_jump") => Some(if observed_next_pc == pc.wrapping_add(0x40) {
            pc.wrapping_add(0x44)
        } else {
            pc.wrapping_add(0x40)
        }),
        _ => Some(pc.wrapping_add(0x10000)),
    }
}

fn beak_mutated_control_flow_next_pc(
    kind: &str,
    opcode: Opcode,
    pc: u32,
    observed_next_pc: u32,
) -> Option<u32> {
    let family = beak_inject_variant_value(kind, "family")
        .or_else(|| beak_control_flow_family_for_opcode(opcode));
    let mode = beak_inject_variant_value(kind, "mode");
    match family {
        Some("branch")
            if matches!(
                opcode,
                Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU
            ) =>
        {
            beak_branch_next_pc_mutation(mode, pc, observed_next_pc)
        }
        Some("jump") if matches!(opcode, Opcode::JAL | Opcode::JALR) => {
            beak_jump_next_pc_mutation(mode, pc, observed_next_pc)
        }
        Some("ecall") if opcode == Opcode::ECALL => {
            beak_ecall_next_pc_mutation(mode, pc, observed_next_pc)
        }
        None if opcode == Opcode::ECALL => beak_ecall_next_pc_mutation(mode, pc, observed_next_pc),
        _ => None,
    }
}

fn beak_maybe_inject_control_flow_next_pc(
    opcode: Opcode,
    pc: u32,
    observed_next_pc: u32,
    step: u64,
) -> Option<(String, u32)> {
    let kind = fuzzer_utils::matching_injection_kind(BEAK_CONTROL_FLOW_INJECT_KIND, step)?;
    let mutated = beak_mutated_control_flow_next_pc(kind.as_str(), opcode, pc, observed_next_pc)?;
    Some((kind, mutated))
}
// BEAK-INSERT-END
""",
    )

    c = _insert_after(
        c,
        anchor="        // If the destination register is x0, then we need to make sure that a's value is 0.\n",
        guard="// BEAK-INSERT: sp1.execute_instruction.control_flow_injection",
        insert="""
        // BEAK-INSERT: sp1.execute_instruction.control_flow_injection
        let beak_exec_step = fuzzer_utils::next_executor_step();
        if let Some((beak_kind, beak_next_pc)) = beak_maybe_inject_control_flow_next_pc(
            instruction.opcode,
            self.state.pc,
            next_pc,
            beak_exec_step,
        ) {
            let beak_pc = self.state.pc;
            let beak_observed_before = next_pc;
            next_pc = beak_next_pc;
            let beak_rv_instruction =
                if instruction.opcode == Opcode::ECALL { 0x0000_0073 } else { 0 };
            let beak_ecall_registers = if instruction.opcode == Opcode::ECALL {
                [syscall as u32, b, c, self.register(Register::X12)]
            } else {
                [0, 0, 0, 0]
            };
            let _ = fuzzer_utils::record_executed_control_flow_receipt(
                beak_kind.as_str(),
                beak_exec_step,
                beak_exec_step,
                beak_pc,
                beak_rv_instruction,
                instruction.opcode as u32,
                instruction.opcode.mnemonic(),
                "__BEAK_SP1_COMMIT__",
                beak_pc.wrapping_add(4),
                beak_observed_before,
                next_pc,
                beak_ecall_registers,
            );
        }
        // BEAK-INSERT-END

""",
    )

    legacy_helper = """fn beak_maybe_inject_control_flow_next_pc(
    opcode: Opcode,
    pc: u32,
    observed_next_pc: u32,
    step: u64,
) -> Option<u32> {
    let kind = fuzzer_utils::matching_injection_kind(BEAK_CONTROL_FLOW_INJECT_KIND, step)?;
    beak_mutated_control_flow_next_pc(kind.as_str(), opcode, pc, observed_next_pc)
}"""
    typed_helper = """fn beak_maybe_inject_control_flow_next_pc(
    opcode: Opcode,
    pc: u32,
    observed_next_pc: u32,
    step: u64,
) -> Option<(String, u32)> {
    let kind = fuzzer_utils::matching_injection_kind(BEAK_CONTROL_FLOW_INJECT_KIND, step)?;
    let mutated = beak_mutated_control_flow_next_pc(kind.as_str(), opcode, pc, observed_next_pc)?;
    Some((kind, mutated))
}"""
    if legacy_helper in c:
        c = c.replace(legacy_helper, typed_helper, 1)

    legacy_executor_hook = """        // BEAK-INSERT: sp1.execute_instruction.control_flow_injection
        let beak_exec_step = fuzzer_utils::next_executor_step();
        if let Some(beak_next_pc) = beak_maybe_inject_control_flow_next_pc(
            instruction.opcode,
            self.state.pc,
            next_pc,
            beak_exec_step,
        ) {
            next_pc = beak_next_pc;
        }
        // BEAK-INSERT-END
"""
    typed_executor_hook = """        // BEAK-INSERT: sp1.execute_instruction.control_flow_injection
        let beak_exec_step = fuzzer_utils::next_executor_step();
        if let Some((beak_kind, beak_next_pc)) = beak_maybe_inject_control_flow_next_pc(
            instruction.opcode,
            self.state.pc,
            next_pc,
            beak_exec_step,
        ) {
            let beak_pc = self.state.pc;
            let beak_observed_before = next_pc;
            next_pc = beak_next_pc;
            let beak_rv_instruction =
                if instruction.opcode == Opcode::ECALL { 0x0000_0073 } else { 0 };
            let beak_ecall_registers = if instruction.opcode == Opcode::ECALL {
                [syscall as u32, b, c, self.register(Register::X12)]
            } else {
                [0, 0, 0, 0]
            };
            let _ = fuzzer_utils::record_executed_control_flow_receipt(
                beak_kind.as_str(),
                beak_exec_step,
                beak_exec_step,
                beak_pc,
                beak_rv_instruction,
                instruction.opcode as u32,
                instruction.opcode.mnemonic(),
                "__BEAK_SP1_COMMIT__",
                beak_pc.wrapping_add(4),
                beak_observed_before,
                next_pc,
                beak_ecall_registers,
            );
        }
        // BEAK-INSERT-END
"""
    if legacy_executor_hook in c:
        c = c.replace(legacy_executor_hook, typed_executor_hook, 1)
    c = _replace_guarded_block(
        c,
        guard="// BEAK-INSERT: sp1.execute_instruction.control_flow_injection",
        replacement=typed_executor_hook,
    )

    c = c.replace("__BEAK_SP1_COMMIT__", commit_or_branch)

    path.write_text(c)


def apply(*, sp1_install_path: Path, commit_or_branch: str) -> None:
    _ = commit_or_branch
    for path in _runtime_mod_candidates(sp1_install_path):
        _patch_runtime_mod(path)
    for path in _executor_candidates(sp1_install_path):
        _patch_executor(path, commit_or_branch)
