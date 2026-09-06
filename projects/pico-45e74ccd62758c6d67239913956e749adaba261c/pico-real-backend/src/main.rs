use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;

use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecordEnum,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            record::EmulationRecord,
            riscv_emulator::{EmulatorMode, RiscvEmulator},
            syscalls::SyscallCode,
        },
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType, configs::riscv_config::StarkConfig as RiscvBBSC,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum SemanticMutationRelation {
    OpcodeSelectorEquation,
}

#[derive(Debug, Serialize)]
struct SemanticMutationEffect {
    relation: SemanticMutationRelation,
    preserved_before: Option<serde_json::Value>,
    preserved_after: Option<serde_json::Value>,
    context: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SemanticMutationReceipt {
    inject_kind: String,
    site: String,
    field: String,
    step: u64,
    before: serde_json::Value,
    after: serde_json::Value,
    effect: SemanticMutationEffect,
}

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
    semantic_mutation_receipt: Option<SemanticMutationReceipt>,
    executed_insns: Vec<ExecutedInsn>,
}

#[derive(Debug, Clone, Serialize)]
struct ExecutedInsn {
    step_idx: u64,
    chunk: u32,
    clk: u32,
    pc: u32,
    next_pc: u32,
    word: u32,
    opcode: String,
    a: u32,
    b: u32,
    c: u32,
    memory: Option<u32>,
    ecall_syscall_id: Option<u32>,
    ecall_operand_to_check: Option<u32>,
}

const TIMESTAMP_INJECT_KIND: &str = "pico.semantic.memory.timestamped_load_path";
const BOOL_INJECT_KIND: &str = "pico.semantic.lookup.boolean_multiplicity";
const OP_SELECTOR_INJECT_KIND: &str = "pico.semantic.exec.op_selector_binding";
const READ_WRITE_OP_SELECTOR_INJECT_KIND: &str =
    "pico.semantic.exec.op_selector_binding.read_write";
const ECALL_ARG_INJECT_KIND: &str = "pico.semantic.control.ecall_argument_decomposition";
const ECALL_WORD_INJECT_KIND: &str = "pico.semantic.control.ecall_word_validity";
const ZERO_REG_INJECT_KIND: &str = "pico.semantic.decode.zero_register_immutability";
const OPERAND_ROUTING_INJECT_KIND: &str = "pico.semantic.decode.operand_index_routing";
const DEST_BINDING_INJECT_KIND: &str = "pico.semantic.exec.dest_binding";
const FIELD_RANGE_INJECT_KIND: &str = "pico.semantic.decode.field_range";
const IMM_SIGN_INJECT_KIND: &str = "pico.semantic.decode.immediate_sign_extension";
const UPPER_IMM_INJECT_KIND: &str = "pico.semantic.decode.upper_immediate_materialization";
const FORMAT_IMM_INJECT_KIND: &str = "pico.semantic.decode.format_immediate_reassembly";
const ALU_IMM_INJECT_KIND: &str = "pico.semantic.alu.immediate_limb_consistency";
const SHIFT_INJECT_KIND: &str = "pico.semantic.alu.shift_mod32";
const CMP_BOOL_INJECT_KIND: &str = "pico.semantic.alu.comparison_booleanity";
const SUB_BORROW_INJECT_KIND: &str = "pico.semantic.alu.subtraction_borrow_chain";
const CMP_AUX_INJECT_KIND: &str = "pico.semantic.alu.comparison_auxiliary_chain";
const DIV_SPECIAL_INJECT_KIND: &str = "pico.semantic.arithmetic.special_case_consistency";
const DIV_BOUND_INJECT_KIND: &str = "pico.semantic.arithmetic.division_remainder_bound";
const PRODUCT_INJECT_KIND: &str = "pico.semantic.arithmetic.product_decomposition";
const MULHSU_INJECT_KIND: &str = "pico.semantic.arithmetic.signed_unsigned_product_correction";
const MEM_STORE_LOAD_INJECT_KIND: &str = "pico.semantic.memory.store_load_payload_flow";
const MEM_ADDR_ALIGN_INJECT_KIND: &str = "pico.semantic.memory.address_alignment_consistency";
const MEM_LOAD_VALUE_INJECT_KIND: &str = "pico.semantic.memory.load_value_binding";
const MEM_WRITE_PAYLOAD_INJECT_KIND: &str = "pico.semantic.memory.write_payload_consistency";
const MEM_ADDR_BOUNDARY_INJECT_KIND: &str = "pico.semantic.memory.address_boundary_range";
const MEM_ADDR_PROGRESS_INJECT_KIND: &str = "pico.semantic.memory.address_progression_consistency";
const MEM_KIND_INJECT_KIND: &str = "pico.semantic.memory.kind_selector_consistency";
const CONTROL_FLOW_INJECT_KIND: &str = "pico.semantic.exec.control_flow_binding";
const ENTRYPOINT_INJECT_KIND: &str = "pico.semantic.control.entrypoint_binding";
const TIME_BOUNDARY_INJECT_KIND: &str = "pico.semantic.time.boundary_origin_consistency";

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn mapped_env_inject_kind(kind: &str) -> String {
    kind.to_string()
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
        Instruction::new(Opcode::JALR, dec.rd as u32, dec.rs1 as u32, dec.imm as u32, false, true)
    }
    fn process_lui(&mut self, dec: UType) -> Self::InstructionResult {
        Instruction::new(Opcode::ADD, dec.rd as u32, 0, dec.imm as u32, true, true)
    }
    fn process_auipc(&mut self, dec: UType) -> Self::InstructionResult {
        Instruction::new(Opcode::AUIPC, dec.rd as u32, dec.imm as u32, dec.imm as u32, true, true)
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
    std::env::remove_var("BEAK_PICO_WITNESS_INJECTION_APPLIED");
    std::env::remove_var("BEAK_PICO_OPCODE_SELECTOR_MUTATION_STEP");
    std::env::remove_var("BEAK_PICO_OPCODE_SELECTOR_MEMORY_EVENT_INDEX");
    std::env::remove_var("BEAK_PICO_OPCODE_SELECTOR_BEFORE");
    std::env::remove_var("BEAK_PICO_OPCODE_SELECTOR_AFTER");
    let kind = inject_kind.unwrap_or("");
    std::env::set_var(
        "BEAK_PICO_WITNESS_INJECT_KIND",
        if kind.is_empty() { String::new() } else { mapped_env_inject_kind(kind) },
    );
    std::env::set_var("BEAK_PICO_WITNESS_INJECT_STEP", inject_step.to_string());
    if !kind.is_empty() {
        if kind.contains("::") {
            return Err(format!("unsupported pico inject variant: {kind}"));
        }
        match base_inject_kind(kind) {
            TIMESTAMP_INJECT_KIND
            | BOOL_INJECT_KIND
            | OP_SELECTOR_INJECT_KIND
            | READ_WRITE_OP_SELECTOR_INJECT_KIND
            | ECALL_ARG_INJECT_KIND
            | ZERO_REG_INJECT_KIND
            | OPERAND_ROUTING_INJECT_KIND
            | DEST_BINDING_INJECT_KIND
            | FIELD_RANGE_INJECT_KIND
            | IMM_SIGN_INJECT_KIND
            | UPPER_IMM_INJECT_KIND
            | FORMAT_IMM_INJECT_KIND
            | ALU_IMM_INJECT_KIND
            | SHIFT_INJECT_KIND
            | CMP_BOOL_INJECT_KIND
            | SUB_BORROW_INJECT_KIND
            | CMP_AUX_INJECT_KIND
            | DIV_SPECIAL_INJECT_KIND
            | DIV_BOUND_INJECT_KIND
            | PRODUCT_INJECT_KIND
            | MULHSU_INJECT_KIND
            | MEM_STORE_LOAD_INJECT_KIND
            | MEM_ADDR_ALIGN_INJECT_KIND
            | MEM_LOAD_VALUE_INJECT_KIND
            | MEM_WRITE_PAYLOAD_INJECT_KIND
            | MEM_ADDR_BOUNDARY_INJECT_KIND
            | MEM_ADDR_PROGRESS_INJECT_KIND
            | MEM_KIND_INJECT_KIND
            | CONTROL_FLOW_INJECT_KIND
            | ENTRYPOINT_INJECT_KIND
            | TIME_BOUNDARY_INJECT_KIND => {}
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

fn is_store_opcode(opcode: Opcode) -> bool {
    matches!(opcode, Opcode::SB | Opcode::SH | Opcode::SW)
}

fn opcode_selector_injection_step(opcode: Opcode, rd: u32, clk: u32) -> Option<u64> {
    matches!(opcode, Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW)
        .then_some(rd)
        .filter(|rd| *rd != 0)
        .map(|_| clk as u64 / 4)
}

fn collect_observed_injection_sites(records: &[EmulationRecord]) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    let mut memory_step = 0u64;
    let mut local_step = 0u64;
    let mut init_finalize_step = 0u64;
    let mut cpu_step = 0u64;

    for record in records {
        for event in &record.cpu_events {
            let cpu_anchor = event.clk as u64;
            if event.instruction.is_memory_instruction() {
                record_site(&mut sites, TIMESTAMP_INJECT_KIND, memory_step);
                if let Some(step) = opcode_selector_injection_step(
                    event.instruction.opcode,
                    event.instruction.op_a,
                    event.clk,
                ) {
                    // The durable read/write hook and the typed receipt both use the global
                    // executed-instruction step (Pico clocks advance by four per CPU row), not
                    // the ordinal among memory rows.  Advertising only applicable non-x0 loads
                    // makes the ordinary scheduler's first explicit trial constructive.
                    record_site(&mut sites, READ_WRITE_OP_SELECTOR_INJECT_KIND, step);
                }
                record_site(&mut sites, MEM_STORE_LOAD_INJECT_KIND, memory_step);
                record_site(&mut sites, MEM_ADDR_ALIGN_INJECT_KIND, memory_step);
                record_site(&mut sites, MEM_LOAD_VALUE_INJECT_KIND, memory_step);
                record_site(&mut sites, MEM_WRITE_PAYLOAD_INJECT_KIND, memory_step);
                record_site(&mut sites, MEM_ADDR_BOUNDARY_INJECT_KIND, memory_step);
                record_site(&mut sites, MEM_ADDR_PROGRESS_INJECT_KIND, memory_step);
                record_site(&mut sites, MEM_KIND_INJECT_KIND, memory_step);
                memory_step = memory_step.saturating_add(1);
            }
            record_site(&mut sites, OP_SELECTOR_INJECT_KIND, cpu_step);
            record_site(&mut sites, FIELD_RANGE_INJECT_KIND, cpu_anchor);
            record_site(&mut sites, CONTROL_FLOW_INJECT_KIND, cpu_anchor);
            if cpu_step == 0 {
                record_site(&mut sites, ENTRYPOINT_INJECT_KIND, cpu_anchor);
                record_site(&mut sites, TIME_BOUNDARY_INJECT_KIND, cpu_anchor);
            }
            if event.instruction.op_a == 0 {
                record_site(&mut sites, ZERO_REG_INJECT_KIND, cpu_anchor);
            } else if !event.instruction.is_branch_instruction()
                && !is_store_opcode(event.instruction.opcode)
            {
                record_site(&mut sites, DEST_BINDING_INJECT_KIND, cpu_anchor);
            }
            if !event.instruction.imm_b || !event.instruction.imm_c {
                record_site(&mut sites, OPERAND_ROUTING_INJECT_KIND, cpu_anchor);
            }
            if event.instruction.imm_b || event.instruction.imm_c {
                record_site(&mut sites, IMM_SIGN_INJECT_KIND, cpu_anchor);
                record_site(&mut sites, FORMAT_IMM_INJECT_KIND, cpu_anchor);
                record_site(&mut sites, UPPER_IMM_INJECT_KIND, cpu_anchor);
            }
            if event.instruction.opcode == Opcode::ECALL {
                record_site(&mut sites, ECALL_ARG_INJECT_KIND, cpu_step);
                record_site(&mut sites, ECALL_WORD_INJECT_KIND, cpu_step);
            }
            cpu_step = cpu_step.saturating_add(1);
        }
        let mut add_sub_step = 0u64;
        for event in record.add_events.iter().chain(record.sub_events.iter()) {
            record_site(&mut sites, ALU_IMM_INJECT_KIND, add_sub_step);
            if event.opcode == Opcode::SUB {
                record_site(&mut sites, SUB_BORROW_INJECT_KIND, add_sub_step);
            }
            add_sub_step = add_sub_step.saturating_add(1);
        }
        for (step, _) in record.shift_left_events.iter().enumerate() {
            record_site(&mut sites, ALU_IMM_INJECT_KIND, step as u64);
            record_site(&mut sites, SHIFT_INJECT_KIND, step as u64);
        }
        for (step, _) in record.shift_right_events.iter().enumerate() {
            record_site(&mut sites, ALU_IMM_INJECT_KIND, step as u64);
            record_site(&mut sites, SHIFT_INJECT_KIND, step as u64);
        }
        for (step, _) in record.lt_events.iter().enumerate() {
            record_site(&mut sites, ALU_IMM_INJECT_KIND, step as u64);
            record_site(&mut sites, CMP_BOOL_INJECT_KIND, step as u64);
            record_site(&mut sites, CMP_AUX_INJECT_KIND, step as u64);
        }
        for event in &record.mul_events {
            let step = event.clk as u64;
            record_site(&mut sites, PRODUCT_INJECT_KIND, step);
            if event.opcode == Opcode::MULHSU {
                record_site(&mut sites, MULHSU_INJECT_KIND, step);
            }
        }
        for event in &record.divrem_events {
            let step = event.clk as u64;
            record_site(&mut sites, DIV_SPECIAL_INJECT_KIND, step);
            record_site(&mut sites, DIV_BOUND_INJECT_KIND, step);
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

fn ecall_syscall_id(event: &pico_vm::chips::chips::riscv_cpu::event::CpuEvent) -> Option<u32> {
    if event.instruction.opcode != Opcode::ECALL {
        return None;
    }
    match event.a_record {
        Some(MemoryRecordEnum::Write(record)) => Some(record.prev_value),
        Some(MemoryRecordEnum::Read(record)) => Some(record.value),
        None => Some(event.a),
    }
}

fn collect_executed_insns(
    records: &[EmulationRecord],
    words: &[u32],
    entry_pc: u32,
) -> Vec<ExecutedInsn> {
    let mut out = Vec::new();
    for record in records {
        for event in &record.cpu_events {
            if event.pc < entry_pc {
                continue;
            }
            let word_idx = ((event.pc - entry_pc) / 4) as usize;
            let Some(&word) = words.get(word_idx) else {
                continue;
            };
            let ecall_syscall_id = ecall_syscall_id(event);
            out.push(ExecutedInsn {
                step_idx: out.len() as u64,
                chunk: event.chunk,
                clk: event.clk,
                pc: event.pc,
                next_pc: event.next_pc,
                word,
                opcode: event.instruction.opcode.mnemonic().to_string(),
                a: event.a,
                b: event.b,
                c: event.c,
                memory: event.memory,
                ecall_syscall_id,
                ecall_operand_to_check: if ecall_syscall_id == Some(SyscallCode::HALT.syscall_id())
                {
                    Some(event.b)
                } else {
                    None
                },
            });
        }
    }
    out
}

fn injection_applied_from_site_metadata() -> bool {
    std::env::var("BEAK_PICO_WITNESS_INJECTION_APPLIED").ok().as_deref() == Some("1")
}

fn semantic_opcode_selector_receipt(
    inject_kind: Option<&str>,
    executed: &[ExecutedInsn],
) -> Option<SemanticMutationReceipt> {
    if inject_kind != Some(READ_WRITE_OP_SELECTOR_INJECT_KIND) {
        return None;
    }
    let mutation_step =
        std::env::var("BEAK_PICO_OPCODE_SELECTOR_MUTATION_STEP").ok()?.parse::<usize>().ok()?;
    let before = std::env::var("BEAK_PICO_OPCODE_SELECTOR_BEFORE").ok()?.parse::<u64>().ok()?;
    let after = std::env::var("BEAK_PICO_OPCODE_SELECTOR_AFTER").ok()?.parse::<u64>().ok()?;
    let memory_event_idx = std::env::var("BEAK_PICO_OPCODE_SELECTOR_MEMORY_EVENT_INDEX")
        .ok()?
        .parse::<u64>()
        .ok()?;
    let event = executed.iter().find(|event| {
        event.step_idx == mutation_step as u64 && matches!(event.word & 0x7f, 0x03 | 0x23)
    })?;
    let rd = u64::from((event.word >> 7) & 0x1f);
    let cell_id = if event.word & 0x7f == 0x03 { "id4.load" } else { "id4.store" };
    let mut context = serde_json::Map::new();
    context.insert("bucket_id".into(), "sem.exec.op_selector_binding".into());
    context.insert("obligation_id".into(), "id4".into());
    context.insert("cell_id".into(), cell_id.into());
    context.insert("backend".into(), "pico".into());
    context.insert("commit".into(), "45e74ccd62758c6d67239913956e749adaba261c".into());
    context.insert("trace_source".into(), "instruction".into());
    context.insert("executed_read_write_row".into(), true.into());
    context.insert("mutation_step".into(), (mutation_step as u64).into());
    context.insert("memory_event_idx".into(), memory_event_idx.into());
    context.insert("step".into(), event.step_idx.into());
    context.insert("pc".into(), u64::from(event.pc).into());
    context.insert("opcode".into(), u64::from(event.word).into());
    context.insert("mnemonic".into(), event.opcode.clone().into());
    context.insert("rd".into(), rd.into());
    context.insert("selector_before".into(), before.into());
    context.insert("selector_after".into(), after.into());
    Some(SemanticMutationReceipt {
        inject_kind: READ_WRITE_OP_SELECTOR_INJECT_KIND.to_string(),
        site: "memory_read_write.op_a_0".to_string(),
        field: "instruction.op_a_0".to_string(),
        step: event.step_idx,
        before: before.into(),
        after: after.into(),
        effect: SemanticMutationEffect {
            relation: SemanticMutationRelation::OpcodeSelectorEquation,
            preserved_before: None,
            preserved_after: None,
            context,
        },
    })
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
    let halt = process_instruction(&mut tr, 0x0000_0067)
        .ok_or_else(|| "failed to decode HALT jalr".to_string())?;
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
    let executed_insns = collect_executed_insns(&records, words, ENTRY_PC);

    mutate_records_for_injection(&mut records, inject_kind, inject_step)?;

    if !do_prove_verify {
        return Ok(RunnerResponse {
            final_regs: Some(regs),
            micro_op_count: records.len(),
            prove_ok: false,
            verify_ok: false,
            error: None,
            observed_injection_sites,
            injection_applied: false,
            semantic_mutation_receipt: None,
            executed_insns,
        });
    }

    let prove_verify =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<bool, String> {
            let machine =
                RiscvMachine::new(RiscvBBSC::new(), RiscvChipType::all_chips(), RISCV_NUM_PVS);
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
                injection_applied: injection_applied_from_site_metadata(),
                semantic_mutation_receipt: semantic_opcode_selector_receipt(
                    inject_kind,
                    &executed_insns,
                ),
                executed_insns,
            });
        }
        Err(p) => {
            return Ok(RunnerResponse {
                final_regs: Some(regs),
                micro_op_count: records.len(),
                prove_ok: false,
                verify_ok: false,
                error: Some(format!("prove/verify panic: {}", panic_payload_to_string(p.as_ref()))),
                observed_injection_sites,
                injection_applied: injection_applied_from_site_metadata(),
                semantic_mutation_receipt: semantic_opcode_selector_receipt(
                    inject_kind,
                    &executed_insns,
                ),
                executed_insns,
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
        injection_applied: injection_applied_from_site_metadata(),
        semantic_mutation_receipt: semantic_opcode_selector_receipt(inject_kind, &executed_insns),
        executed_insns,
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
                semantic_mutation_receipt: None,
                executed_insns: Vec::new(),
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
                    semantic_mutation_receipt: None,
                    executed_insns: Vec::new(),
                })
                .unwrap_or_else(|_| "{\"error\":\"failed to serialize error\"}".to_string())
            );
            return;
        }
    };

    let resp = match std::panic::catch_unwind(|| {
        run_one(&req.words, req.do_prove_verify, req.inject_kind.as_deref(), req.inject_step)
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
            semantic_mutation_receipt: None,
            executed_insns: Vec::new(),
        },
        Err(p) => RunnerResponse {
            final_regs: None,
            micro_op_count: 0,
            prove_ok: false,
            verify_ok: false,
            error: Some(format!("runner panic: {}", panic_payload_to_string(p.as_ref()))),
            observed_injection_sites: BTreeMap::new(),
            injection_applied: false,
            semantic_mutation_receipt: None,
            executed_insns: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn executed(step_idx: u64, word: u32, opcode: &str) -> ExecutedInsn {
        ExecutedInsn {
            step_idx,
            chunk: 1,
            clk: step_idx as u32 * 4,
            pc: 0x1000 + step_idx as u32 * 4,
            next_pc: 0x1004 + step_idx as u32 * 4,
            word,
            opcode: opcode.to_string(),
            a: 0,
            b: 0,
            c: 0,
            memory: Some(0),
            ecall_syscall_id: None,
            ecall_operand_to_check: None,
        }
    }

    #[test]
    fn opcode_receipt_uses_the_executed_global_step_not_memory_ordinal() {
        assert_eq!(opcode_selector_injection_step(Opcode::LW, 3, 12), Some(3));
        assert_eq!(opcode_selector_injection_step(Opcode::LW, 0, 12), None);
        assert_eq!(opcode_selector_injection_step(Opcode::SW, 3, 12), None);

        std::env::set_var("BEAK_PICO_OPCODE_SELECTOR_MUTATION_STEP", "3");
        std::env::set_var("BEAK_PICO_OPCODE_SELECTOR_MEMORY_EVENT_INDEX", "1");
        std::env::set_var("BEAK_PICO_OPCODE_SELECTOR_BEFORE", "0");
        std::env::set_var("BEAK_PICO_OPCODE_SELECTOR_AFTER", "1");
        let events = [executed(2, 0x00a2_a023, "sw"), executed(3, 0x0002_a603, "lw")];
        let receipt =
            semantic_opcode_selector_receipt(Some(READ_WRITE_OP_SELECTOR_INJECT_KIND), &events)
                .expect("typed receipt");
        assert_eq!(receipt.step, 3);
        assert_eq!(receipt.effect.context.get("mutation_step"), Some(&serde_json::json!(3)));
        assert_eq!(receipt.effect.context.get("memory_event_idx"), Some(&serde_json::json!(1)));
        assert_eq!(receipt.effect.context.get("step"), Some(&serde_json::json!(3)));
        assert_eq!(receipt.effect.context.get("opcode"), Some(&serde_json::json!(0x0002_a603u64)));

        assert!(semantic_opcode_selector_receipt(Some(OP_SELECTOR_INJECT_KIND), &events).is_none());
        std::env::set_var("BEAK_PICO_OPCODE_SELECTOR_MUTATION_STEP", "1");
        assert!(semantic_opcode_selector_receipt(
            Some(READ_WRITE_OP_SELECTOR_INJECT_KIND),
            &events
        )
        .is_none());
        std::env::remove_var("BEAK_PICO_OPCODE_SELECTOR_AFTER");
        assert!(semantic_opcode_selector_receipt(
            Some(READ_WRITE_OP_SELECTOR_INJECT_KIND),
            &events
        )
        .is_none());
        std::env::remove_var("BEAK_PICO_OPCODE_SELECTOR_MUTATION_STEP");
        std::env::remove_var("BEAK_PICO_OPCODE_SELECTOR_MEMORY_EVENT_INDEX");
        std::env::remove_var("BEAK_PICO_OPCODE_SELECTOR_BEFORE");
    }
}
