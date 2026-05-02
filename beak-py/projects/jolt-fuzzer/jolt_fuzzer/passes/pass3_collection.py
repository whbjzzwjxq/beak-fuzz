from __future__ import annotations

from pathlib import Path


def apply(*, jolt_install_path: Path, commit_or_branch: str) -> None:
    _ = commit_or_branch
    _patch_host_trace_injection(jolt_install_path)


def _patch_host_trace_injection(jolt_install_path: Path) -> None:
    host_mod = jolt_install_path / "jolt-core" / "src" / "host" / "mod.rs"
    c = host_mod.read_text()
    if (
        "// BEAK-INSERT: jolt.host.apply_semantic_injection" in c
        and "        let trace: Vec<_> = raw_trace" in c
    ):
        c = c.replace(
            "        let trace: Vec<_> = raw_trace",
            "        let mut trace: Vec<_> = raw_trace",
            1,
        )

    if "// BEAK-INSERT: jolt.host.semantic_injection_helpers" not in c:
        old_imports = """            div::DIVInstruction, divu::DIVUInstruction, lb::LBInstruction, lbu::LBUInstruction,
            lh::LHInstruction, lhu::LHUInstruction, mulh::MULHInstruction,
            mulhsu::MULHSUInstruction, rem::REMInstruction, remu::REMUInstruction,
            sb::SBInstruction, sh::SHInstruction, VirtualInstructionSequence,
"""
        new_imports = """            beq::BEQInstruction, bge::BGEInstruction, bgeu::BGEUInstruction,
            bne::BNEInstruction, div::DIVInstruction, divu::DIVUInstruction, lb::LBInstruction,
            lbu::LBUInstruction, lh::LHInstruction, lhu::LHUInstruction, mulh::MULHInstruction,
            mulhsu::MULHSUInstruction, rem::REMInstruction, remu::REMUInstruction,
            sb::SBInstruction, sh::SHInstruction, slt::SLTInstruction, sltu::SLTUInstruction,
            virtual_advice::ADVICEInstruction, VirtualInstructionSequence,
"""
        if old_imports not in c:
            raise RuntimeError("Jolt host instruction import anchor not found")
        c = c.replace(old_imports, new_imports)

        helper_anchor = 'pub const DEFAULT_TARGET_DIR: &str = "/tmp/jolt-guest-targets";\n'
        helpers = r'''
const BEAK_JOLT_INJECT_KIND_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_KIND";
const BEAK_JOLT_INJECT_STEP_ENV: &str = "BEAK_JOLT_WITNESS_INJECT_STEP";
const BEAK_JOLT_INJECT_APPLIED_ENV: &str = "BEAK_JOLT_WITNESS_INJECTION_APPLIED";
const BEAK_JOLT_UPPER_IMMEDIATE_INJECT_KIND: &str =
    "jolt.semantic.decode.upper_immediate_materialization";
const BEAK_JOLT_ENTRYPOINT_INJECT_KIND: &str = "jolt.semantic.control.entrypoint_binding";
const BEAK_JOLT_CONTROL_FLOW_INJECT_KIND: &str = "jolt.semantic.exec.control_flow_binding";

// BEAK-INSERT: jolt.host.semantic_injection_helpers
fn beak_base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

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

fn beak_inject_variant_mode(kind: &str) -> Option<&str> {
    beak_inject_variant_value(kind, "mode")
}

fn beak_inject_step_matches(configured_step: u64, candidate_step: u64) -> bool {
    configured_step == u64::MAX || configured_step == candidate_step
}

fn beak_is_real_lui_step(step: &JoltTraceStep<RV32I>) -> bool {
    matches!(step.instruction_lookup, Some(RV32I::VIRTUAL_ADVICE(_)))
        && !step.circuit_flags[common::rv_trace::CircuitFlags::Virtual as usize]
}

fn beak_is_branch_step(step: &JoltTraceStep<RV32I>) -> bool {
    step.circuit_flags[common::rv_trace::CircuitFlags::Branch as usize]
        && !step.circuit_flags[common::rv_trace::CircuitFlags::Virtual as usize]
}

fn beak_branch_mode_matches(mode: Option<&str>, family: &str) -> bool {
    match mode {
        None | Some("paired_flip") => true,
        Some("eq_flip") => family == "eq",
        Some("signed_cmp_flip") => family == "signed",
        Some("unsigned_cmp_flip") => family == "unsigned",
        _ => false,
    }
}

fn beak_mutate_branch_lookup(step_row: &mut JoltTraceStep<RV32I>, mode: Option<&str>) -> bool {
    let next_lookup = match step_row.instruction_lookup {
        Some(RV32I::BEQ(insn)) if beak_branch_mode_matches(mode, "eq") => {
            Some(RV32I::BNE(BNEInstruction::<32>(insn.0, insn.1)))
        }
        Some(RV32I::BNE(insn)) if beak_branch_mode_matches(mode, "eq") => {
            Some(RV32I::BEQ(BEQInstruction::<32>(insn.0, insn.1)))
        }
        Some(RV32I::SLT(insn)) if beak_branch_mode_matches(mode, "signed") => {
            Some(RV32I::BGE(BGEInstruction::<32>(insn.0, insn.1)))
        }
        Some(RV32I::BGE(insn)) if beak_branch_mode_matches(mode, "signed") => {
            Some(RV32I::SLT(SLTInstruction::<32>(insn.0, insn.1)))
        }
        Some(RV32I::SLTU(insn)) if beak_branch_mode_matches(mode, "unsigned") => {
            Some(RV32I::BGEU(BGEUInstruction::<32>(insn.0, insn.1)))
        }
        Some(RV32I::BGEU(insn)) if beak_branch_mode_matches(mode, "unsigned") => {
            Some(RV32I::SLTU(SLTUInstruction::<32>(insn.0, insn.1)))
        }
        _ => None,
    };

    if let Some(next_lookup) = next_lookup {
        step_row.instruction_lookup = Some(next_lookup);
        true
    } else {
        false
    }
}

fn beak_apply_semantic_injection(trace: &mut Vec<JoltTraceStep<RV32I>>) {
    let Ok(kind) = std::env::var(BEAK_JOLT_INJECT_KIND_ENV) else {
        return;
    };
    let inject_step = std::env::var(BEAK_JOLT_INJECT_STEP_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let base_kind = beak_base_inject_kind(&kind);
    let mode = beak_inject_variant_mode(&kind);
    let mut applied = false;

    if base_kind == BEAK_JOLT_ENTRYPOINT_INJECT_KIND {
        if beak_inject_step_matches(inject_step, 0) && !matches!(mode, Some("noop_prefix")) {
            let prefix_len = match mode {
                Some("skip_one") => 1usize,
                Some("skip_two") | Some("far_page") => 2usize,
                _ => 2usize,
            };
            if trace.len() > prefix_len {
                trace.drain(0..prefix_len);
                applied = true;
            }
        }
    } else if base_kind == BEAK_JOLT_CONTROL_FLOW_INJECT_KIND {
        for (idx, step_row) in trace.iter_mut().enumerate() {
            let step = idx as u64;
            if beak_is_branch_step(step_row)
                && beak_inject_step_matches(inject_step, step)
                && beak_mutate_branch_lookup(step_row, mode)
            {
                applied = true;
                break;
            }
        }
    } else if base_kind == BEAK_JOLT_UPPER_IMMEDIATE_INJECT_KIND
        && !matches!(mode, Some("noop_prefix"))
    {
        for (idx, step_row) in trace.iter_mut().enumerate() {
            let step = idx as u64;
            if !beak_is_real_lui_step(step_row) || !beak_inject_step_matches(inject_step, step) {
                continue;
            }
            let current = match step_row.instruction_lookup.as_ref() {
                Some(RV32I::VIRTUAL_ADVICE(advice)) => advice.0 as u32,
                _ => continue,
            };
            let next = match mode {
                Some("imm_add_page") => current.wrapping_add(0x1000),
                Some("imm_flip_sign") => current ^ (1u32 << 31),
                _ => current ^ 0x1000,
            };
            step_row.instruction_lookup = Some(ADVICEInstruction::<32>(next as u64).into());
            applied = true;
            break;
        }
    }

    if applied {
        std::env::set_var(BEAK_JOLT_INJECT_APPLIED_ENV, "1");
    }
}
// BEAK-INSERT-END
'''
        if helper_anchor not in c:
            raise RuntimeError("Jolt host helper anchor not found")
        c = c.replace(helper_anchor, helper_anchor + helpers + "\n")

    if "// BEAK-INSERT: jolt.host.apply_semantic_injection" not in c:
        old_collect = """            .map(|row| {
                let instruction_lookup = RV32I::try_from(&row).ok();

                JoltTraceStep {
                    instruction_lookup,
                    bytecode_row: BytecodeRow::from_instruction::<RV32I>(&row.instruction),
                    memory_ops: (&row).into(),
                    circuit_flags: row.instruction.to_circuit_flags(),
                }
            })
            .collect();

        (io_device, trace)
"""
        new_collect = """            .map(|row| {
                let instruction_lookup = RV32I::try_from(&row).ok();

                JoltTraceStep {
                    instruction_lookup,
                    bytecode_row: BytecodeRow::from_instruction::<RV32I>(&row.instruction),
                    memory_ops: (&row).into(),
                    circuit_flags: row.instruction.to_circuit_flags(),
                }
            })
            .collect();

        // BEAK-INSERT: jolt.host.apply_semantic_injection
        beak_apply_semantic_injection(&mut trace);
        // BEAK-INSERT-END

        (io_device, trace)
"""
        if "        let trace: Vec<_> = raw_trace" in c:
            c = c.replace(
                "        let trace: Vec<_> = raw_trace",
                "        let mut trace: Vec<_> = raw_trace",
                1,
            )
        if old_collect not in c:
            raise RuntimeError("Jolt host trace collect anchor not found")
        c = c.replace(old_collect, new_collect)

    host_mod.write_text(c)
