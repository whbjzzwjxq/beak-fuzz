use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;

use pico_vm::{
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            record::EmulationRecord,
            riscv_emulator::{EmulatorMode, RiscvEmulator},
        },
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        configs::riscv_config::StarkConfig as RiscvBBSC,
        machine::riscv::RiscvMachine,
    },
    machine::machine::MachineBehavior,
    primitives::consts::RISCV_NUM_PVS,
};
use rrs_lib::{
    instruction_formats::{BType, IType, ITypeCSR, ITypeShamt, JType, RType, SType, UType},
    process_instruction, InstructionProcessor,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct RunnerRequest {
    words: Vec<u32>,
    do_prove_verify: bool,
    inject_kind: Option<String>,
    inject_step: u64,
}

#[derive(Debug, Serialize)]
struct RunnerResponse {
    final_regs: Option<[u32; 32]>,
    micro_op_count: usize,
    prove_ok: bool,
    verify_ok: bool,
    error: Option<String>,
    observed_injection_sites: BTreeMap<String, Vec<u64>>,
    injection_applied: bool,
}

const TIMESTAMP_INJECT_KIND: &str = "pico.audit_timestamp.mem_offset_flip";
const BOOL_INJECT_KIND: &str = "pico.audit_multiplicity_bool_constraint.local_event_row";
const LEGACY_BOOL_INJECT_KIND: &str = "pico.audit_isreal.local_event_row";

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn inject_variant_value<'a>(kind: &'a str, key: &str) -> Option<&'a str> {
    let (_, variant) = kind.split_once("::")?;
    for field in variant.split(',') {
        let (field_key, field_value) = field.split_once('=')?;
        if field_key == key {
            return Some(field_value);
        }
    }
    None
}

fn inject_variant_mode(kind: &str) -> Option<&str> {
    inject_variant_value(kind, "mode")
}

fn mapped_env_inject_kind(kind: &str) -> String {
    let base = match base_inject_kind(kind) {
        BOOL_INJECT_KIND => LEGACY_BOOL_INJECT_KIND,
        other => other,
    };
    match kind.split_once("::") {
        Some((_, variant)) => format!("{base}::{variant}"),
        None => base.to_string(),
    }
}

fn i_from_r(opcode: Opcode, dec: &RType) -> Instruction {
    Instruction::new(opcode, dec.rd as u32, dec.rs1 as u32, dec.rs2 as u32, false, false)
}

fn i_from_i(opcode: Opcode, dec: &IType) -> Instruction {
    Instruction::new(opcode, dec.rd as u32, dec.rs1 as u32, dec.imm as u32, false, true)
}

fn i_from_i_shamt(opcode: Opcode, dec: &ITypeShamt) -> Instruction {
    Instruction::new(opcode, dec.rd as u32, dec.rs1 as u32, dec.shamt, false, true)
}

fn i_from_s(opcode: Opcode, dec: &SType) -> Instruction {
    Instruction::new(opcode, dec.rs2 as u32, dec.rs1 as u32, dec.imm as u32, false, true)
}

fn i_from_b(opcode: Opcode, dec: &BType) -> Instruction {
    Instruction::new(opcode, dec.rs1 as u32, dec.rs2 as u32, dec.imm as u32, false, true)
}

struct Transpiler;

impl InstructionProcessor for Transpiler {
    type InstructionResult = Instruction;

    fn process_add(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::ADD, &dec)
    }
    fn process_addi(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::ADD, &dec)
    }
    fn process_sub(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::SUB, &dec)
    }
    fn process_xor(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::XOR, &dec)
    }
    fn process_xori(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::XOR, &dec)
    }
    fn process_or(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::OR, &dec)
    }
    fn process_ori(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::OR, &dec)
    }
    fn process_and(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::AND, &dec)
    }
    fn process_andi(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::AND, &dec)
    }
    fn process_sll(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::SLL, &dec)
    }
    fn process_slli(&mut self, dec: ITypeShamt) -> Self::InstructionResult {
        i_from_i_shamt(Opcode::SLL, &dec)
    }
    fn process_srl(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::SRL, &dec)
    }
    fn process_srli(&mut self, dec: ITypeShamt) -> Self::InstructionResult {
        i_from_i_shamt(Opcode::SRL, &dec)
    }
    fn process_sra(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::SRA, &dec)
    }
    fn process_srai(&mut self, dec: ITypeShamt) -> Self::InstructionResult {
        i_from_i_shamt(Opcode::SRA, &dec)
    }
    fn process_slt(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::SLT, &dec)
    }
    fn process_slti(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::SLT, &dec)
    }
    fn process_sltu(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::SLTU, &dec)
    }
    fn process_sltui(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::SLTU, &dec)
    }
    fn process_lb(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::LB, &dec)
    }
    fn process_lh(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::LH, &dec)
    }
    fn process_lw(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::LW, &dec)
    }
    fn process_lbu(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::LBU, &dec)
    }
    fn process_lhu(&mut self, dec: IType) -> Self::InstructionResult {
        i_from_i(Opcode::LHU, &dec)
    }
    fn process_sb(&mut self, dec: SType) -> Self::InstructionResult {
        i_from_s(Opcode::SB, &dec)
    }
    fn process_sh(&mut self, dec: SType) -> Self::InstructionResult {
        i_from_s(Opcode::SH, &dec)
    }
    fn process_sw(&mut self, dec: SType) -> Self::InstructionResult {
        i_from_s(Opcode::SW, &dec)
    }
    fn process_beq(&mut self, dec: BType) -> Self::InstructionResult {
        i_from_b(Opcode::BEQ, &dec)
    }
    fn process_bne(&mut self, dec: BType) -> Self::InstructionResult {
        i_from_b(Opcode::BNE, &dec)
    }
    fn process_blt(&mut self, dec: BType) -> Self::InstructionResult {
        i_from_b(Opcode::BLT, &dec)
    }
    fn process_bge(&mut self, dec: BType) -> Self::InstructionResult {
        i_from_b(Opcode::BGE, &dec)
    }
    fn process_bltu(&mut self, dec: BType) -> Self::InstructionResult {
        i_from_b(Opcode::BLTU, &dec)
    }
    fn process_bgeu(&mut self, dec: BType) -> Self::InstructionResult {
        i_from_b(Opcode::BGEU, &dec)
    }
    fn process_jal(&mut self, dec: JType) -> Self::InstructionResult {
        Instruction::new(Opcode::JAL, dec.rd as u32, dec.imm as u32, 0, true, true)
    }
    fn process_jalr(&mut self, dec: IType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::JALR,
            dec.rd as u32,
            dec.rs1 as u32,
            dec.imm as u32,
            false,
            true,
        )
    }
    fn process_lui(&mut self, dec: UType) -> Self::InstructionResult {
        Instruction::new(Opcode::ADD, dec.rd as u32, 0, dec.imm as u32, true, true)
    }
    fn process_auipc(&mut self, dec: UType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::AUIPC,
            dec.rd as u32,
            dec.imm as u32,
            dec.imm as u32,
            true,
            true,
        )
    }
    fn process_ecall(&mut self) -> Self::InstructionResult {
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false)
    }
    fn process_mul(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::MUL, &dec)
    }
    fn process_mulh(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::MULH, &dec)
    }
    fn process_mulhu(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::MULHU, &dec)
    }
    fn process_mulhsu(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::MULHSU, &dec)
    }
    fn process_div(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::DIV, &dec)
    }
    fn process_divu(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::DIVU, &dec)
    }
    fn process_rem(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::REM, &dec)
    }
    fn process_remu(&mut self, dec: RType) -> Self::InstructionResult {
        i_from_r(Opcode::REMU, &dec)
    }

    // Unsupported in Pico VM transpiler path for this harness.
    fn process_csrrc(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }
    fn process_csrrci(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }
    fn process_csrrs(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }
    fn process_csrrsi(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }
    fn process_csrrw(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }
    fn process_csrrwi(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }
    fn process_fence(&mut self, _: IType) -> Self::InstructionResult {
        Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }
    fn process_ebreak(&mut self) -> Self::InstructionResult {
        Instruction::new(Opcode::EBREAK, 0, 0, 0, false, false)
    }
    fn process_mret(&mut self) -> Self::InstructionResult {
        Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }
    fn process_wfi(&mut self) -> Self::InstructionResult {
        Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }
}

fn decode_words(words: &[u32]) -> Result<Vec<Instruction>, String> {
    let mut tr = Transpiler;
    words
        .iter()
        .copied()
        .map(|w| {
            process_instruction(&mut tr, w).ok_or_else(|| format!("decode failed for 0x{w:08x}"))
        })
        .collect()
}

fn mutate_records_for_injection(
    _records: &mut [EmulationRecord],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<(), String> {
    let kind = inject_kind.unwrap_or("");
    std::env::set_var(
        "BEAK_PICO_WITNESS_INJECT_KIND",
        if kind.is_empty() {
            String::new()
        } else {
            mapped_env_inject_kind(kind)
        },
    );
    std::env::set_var("BEAK_PICO_WITNESS_INJECT_STEP", inject_step.to_string());
    if !kind.is_empty() {
        match base_inject_kind(kind) {
            TIMESTAMP_INJECT_KIND | BOOL_INJECT_KIND | LEGACY_BOOL_INJECT_KIND => {}
            _ => return Err(format!("unsupported inject_kind={kind}")),
        }
    }
    Ok(())
}

fn record_site(sites: &mut BTreeMap<String, Vec<u64>>, kind: &str, step: u64) {
    let steps = sites.entry(kind.to_string()).or_default();
    if steps.last().copied() != Some(step) {
        steps.push(step);
    }
}

fn collect_observed_injection_sites(records: &[EmulationRecord]) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    let mut memory_step = 0u64;
    let mut local_step = 0u64;
    let mut init_finalize_step = 0u64;

    for record in records {
        for event in &record.cpu_events {
            if event.instruction.is_memory_instruction() {
                record_site(&mut sites, TIMESTAMP_INJECT_KIND, memory_step);
                memory_step = memory_step.saturating_add(1);
            }
        }
        for _ in record.get_local_mem_events() {
            record_site(&mut sites, BOOL_INJECT_KIND, local_step);
            local_step = local_step.saturating_add(1);
        }
        for _ in &record.memory_initialize_events {
            record_site(&mut sites, TIMESTAMP_INJECT_KIND, init_finalize_step);
            init_finalize_step = init_finalize_step.saturating_add(1);
        }
        for _ in &record.memory_finalize_events {
            record_site(&mut sites, TIMESTAMP_INJECT_KIND, init_finalize_step);
            init_finalize_step = init_finalize_step.saturating_add(1);
        }
    }

    sites
}

fn injection_applies(
    inject_kind: Option<&str>,
    inject_step: u64,
    observed_injection_sites: &BTreeMap<String, Vec<u64>>,
) -> bool {
    let Some(kind) = inject_kind else {
        return false;
    };
    if matches!(inject_variant_mode(kind), Some("noop_prefix")) {
        return false;
    }
    let key = match base_inject_kind(kind) {
        LEGACY_BOOL_INJECT_KIND => BOOL_INJECT_KIND,
        other => other,
    };
    let Some(steps) = observed_injection_sites.get(key) else {
        return false;
    };
    if inject_step == u64::MAX {
        return !steps.is_empty();
    }
    steps.contains(&inject_step)
}

fn run_one(
    words: &[u32],
    do_prove_verify: bool,
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RunnerResponse, String> {
    let mut instructions = decode_words(words)?;
    // Ensure Pico witness generation ends with next_pc == 0.
    let mut tr = Transpiler;
    let halt =
        process_instruction(&mut tr, 0x0000_0067).ok_or_else(|| "failed to decode HALT jalr".to_string())?;
    instructions.push(halt);
    const ENTRY_PC: u32 = 0x1000;
    let program = Arc::new(Program::new(instructions, ENTRY_PC, ENTRY_PC));

    type Field = Val<RiscvBBSC>;
    let mut emulator = RiscvEmulator::new::<Field>(program.clone(), EmulatorOpts::default());
    emulator.emulator_mode = EmulatorMode::Trace;
    let mut records = Vec::<EmulationRecord>::new();
    loop {
        let (mut batch, done) = emulator
            .emulate_batch()
            .map_err(|e| format!("emulator emulate_batch(trace) failed: {e:?}"))?;
        records.append(&mut batch);
        if done {
            break;
        }
    }
    let regs = emulator.registers();
    let observed_injection_sites = collect_observed_injection_sites(&records);
    let injection_applied = injection_applies(inject_kind, inject_step, &observed_injection_sites);

    mutate_records_for_injection(&mut records, inject_kind, inject_step)?;

    if !do_prove_verify {
        return Ok(RunnerResponse {
            final_regs: Some(regs),
            micro_op_count: records.len(),
            prove_ok: false,
            verify_ok: false,
            error: None,
            observed_injection_sites,
            injection_applied,
        });
    }

    let prove_verify = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<bool, String> {
        let machine = RiscvMachine::new(RiscvBBSC::new(), RiscvChipType::all_chips(), RISCV_NUM_PVS);
        let (pk, vk) = machine.setup_keys(&program);
        machine.complement_record(&mut records);
        let proofs = machine.base_machine().prove_ensemble(&pk, &records);
        let verify_ok = machine.base_machine().verify_ensemble(&vk, &proofs).is_ok();
        Ok(verify_ok)
    }));
    let verify_ok = match prove_verify {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return Ok(RunnerResponse {
                final_regs: Some(regs),
                micro_op_count: records.len(),
                prove_ok: false,
                verify_ok: false,
                error: Some(e),
                observed_injection_sites,
                injection_applied,
            });
        }
        Err(p) => {
            return Ok(RunnerResponse {
                final_regs: Some(regs),
                micro_op_count: records.len(),
                prove_ok: false,
                verify_ok: false,
                error: Some(format!(
                    "prove/verify panic: {}",
                    panic_payload_to_string(p.as_ref())
                )),
                observed_injection_sites,
                injection_applied,
            });
        }
    };

    Ok(RunnerResponse {
        final_regs: Some(regs),
        micro_op_count: records.len(),
        prove_ok: true,
        verify_ok,
        error: if verify_ok { None } else { Some("verify failed".to_string()) },
        observed_injection_sites,
        injection_applied,
    })
}

fn main() {
    let mut stdin = String::new();
    if std::io::stdin().read_to_string(&mut stdin).is_err() {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
                serde_json::to_string(&RunnerResponse {
                    final_regs: None,
                    micro_op_count: 0,
                    prove_ok: false,
                    verify_ok: false,
                    error: Some("failed to read stdin".to_string()),
                    observed_injection_sites: BTreeMap::new(),
                    injection_applied: false,
                })
            .unwrap_or_else(|_| "{\"error\":\"failed to serialize error\"}".to_string())
        );
        return;
    }

    let req = match serde_json::from_str::<RunnerRequest>(stdin.trim()) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(
                std::io::stdout(),
                "{}",
                serde_json::to_string(&RunnerResponse {
                    final_regs: None,
                    micro_op_count: 0,
                    prove_ok: false,
                    verify_ok: false,
                    error: Some(format!("invalid request json: {e}")),
                    observed_injection_sites: BTreeMap::new(),
                    injection_applied: false,
                })
                .unwrap_or_else(|_| "{\"error\":\"failed to serialize error\"}".to_string())
            );
            return;
        }
    };

    let resp = match std::panic::catch_unwind(|| {
        run_one(
            &req.words,
            req.do_prove_verify,
            req.inject_kind.as_deref(),
            req.inject_step,
        )
    }) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => RunnerResponse {
            final_regs: None,
            micro_op_count: 0,
            prove_ok: false,
            verify_ok: false,
            error: Some(e),
            observed_injection_sites: BTreeMap::new(),
            injection_applied: false,
        },
        Err(p) => RunnerResponse {
            final_regs: None,
            micro_op_count: 0,
            prove_ok: false,
            verify_ok: false,
            error: Some(format!("runner panic: {}", panic_payload_to_string(p.as_ref()))),
            observed_injection_sites: BTreeMap::new(),
            injection_applied: false,
        },
    };

    let _ = writeln!(
        std::io::stdout(),
        "{}",
        serde_json::to_string(&resp)
            .unwrap_or_else(|_| "{\"error\":\"failed to serialize response\"}".to_string())
    );
}

fn panic_payload_to_string(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = p.downcast_ref::<String>() {
        return s.clone();
    }
    "non-string panic payload".to_string()
}
