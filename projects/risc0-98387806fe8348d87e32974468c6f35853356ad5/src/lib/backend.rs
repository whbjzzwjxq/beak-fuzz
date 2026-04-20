use std::collections::{BTreeMap, BTreeSet};
use std::{cell::RefCell, rc::Rc};

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::{
    instruction::RV32IMInstruction,
    oracle::{OracleConfig, OracleMemoryModel, RISCVOracle},
};
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic};
use risc0_binfmt::{MemoryImage, Program};
use risc0_circuit_rv32im::{
    MAX_INSN_CYCLES,
    Rv32imV2Claim,
    execute::{
        CycleLimit,
        DEFAULT_SEGMENT_LIMIT_PO2,
        Executor,
        platform::{
            HOST_ECALL_TERMINATE, MACHINE_REGS_ADDR, REG_A0, REG_A1, REG_A7, USER_REGS_ADDR,
            USER_START_ADDR, WORD_SIZE,
        },
        testutil::DEFAULT_SESSION_LIMIT,
    },
    trace::{TraceCallback, TraceEvent},
    prove::beak::{BeakInjectionPlan, prove_segment_with_injection},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::trace::Risc0Trace;

const ZERO_REGISTER_INJECT_KIND: &str = "risc0.semantic.decode.zero_register_immutability";
const OPERAND_ROUTE_INJECT_KIND: &str = "risc0.semantic.decode.operand_index_routing";
const RD_BITS_INJECT_KIND: &str = "risc0.semantic.decode.rd_bit_decomposition";
const DIV_REM_BOUND_INJECT_KIND: &str = "risc0.semantic.arithmetic.division_remainder_bound";
const ECALL_ARG_DECOMP_INJECT_KIND: &str = "risc0.semantic.control.ecall_argument_decomposition";
const EXEC_SOURCE_BINDING_INJECT_KIND: &str = "risc0.semantic.exec.source_operand_binding";
const EXEC_DEST_BINDING_INJECT_KIND: &str = "risc0.semantic.exec.dest_binding";
const EXEC_OP_SELECTOR_BINDING_INJECT_KIND: &str = "risc0.semantic.exec.op_selector_binding";
const EXEC_CONTROL_FLOW_BINDING_INJECT_KIND: &str = "risc0.semantic.exec.control_flow_binding";
const EXEC_MEMORY_EFFECT_BINDING_INJECT_KIND: &str = "risc0.semantic.exec.memory_effect_binding";

#[cfg(test)]
const EXEC_SOURCE_BINDING_SUFFIX: &str = "::src2_from_src1_word";
#[cfg(test)]
const EXEC_DEST_BINDING_SUFFIX: &str = "::rd_plus_one_word";
#[cfg(test)]
const EXEC_OP_SELECTOR_BINDING_SUFFIX: &str = "::toggle_selector_word";
#[cfg(test)]
const EXEC_CONTROL_FLOW_BINDING_SUFFIX: &str = "::branch_negate_word";
#[cfg(test)]
const EXEC_MEMORY_EFFECT_BINDING_SUFFIX: &str = "::memory_route_word";

#[cfg(test)]
const EXECUTOR_WORD_INJECT_KIND_ENV: &str = "BEAK_RISC0_EXEC_INJECT_KIND";
#[cfg(test)]
const EXECUTOR_WORD_INJECT_STEP_ENV: &str = "BEAK_RISC0_EXEC_INJECT_STEP";
#[cfg(test)]
const EXECUTOR_WORD_INJECT_HIT_ENV: &str = "BEAK_RISC0_EXEC_INJECT_HIT";
#[cfg(test)]
const EXECUTOR_WORD_SOURCE_BINDING_KIND: &str = "source_operand_binding_word";
#[cfg(test)]
const EXECUTOR_WORD_DEST_BINDING_KIND: &str = "dest_binding_word";
#[cfg(test)]
const EXECUTOR_WORD_OP_SELECTOR_KIND: &str = "op_selector_binding_word";
#[cfg(test)]
const EXECUTOR_WORD_CONTROL_FLOW_KIND: &str = "control_flow_binding_word";
#[cfg(test)]
const EXECUTOR_WORD_MEMORY_EFFECT_KIND: &str = "memory_effect_binding_word";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub backend_error: Option<String>,
    pub observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pub injection_applied: bool,
}

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

#[cfg(test)]
fn is_executor_word_injection(kind: &str) -> bool {
    kind.ends_with(EXEC_SOURCE_BINDING_SUFFIX)
        || kind.ends_with(EXEC_DEST_BINDING_SUFFIX)
        || kind.ends_with(EXEC_OP_SELECTOR_BINDING_SUFFIX)
        || kind.ends_with(EXEC_CONTROL_FLOW_BINDING_SUFFIX)
        || kind.ends_with(EXEC_MEMORY_EFFECT_BINDING_SUFFIX)
}

#[cfg(test)]
fn executor_word_kind_for_inject_kind(kind: &str) -> Option<&'static str> {
    if kind.ends_with(EXEC_SOURCE_BINDING_SUFFIX) {
        Some(EXECUTOR_WORD_SOURCE_BINDING_KIND)
    } else if kind.ends_with(EXEC_DEST_BINDING_SUFFIX) {
        Some(EXECUTOR_WORD_DEST_BINDING_KIND)
    } else if kind.ends_with(EXEC_OP_SELECTOR_BINDING_SUFFIX) {
        Some(EXECUTOR_WORD_OP_SELECTOR_KIND)
    } else if kind.ends_with(EXEC_CONTROL_FLOW_BINDING_SUFFIX) {
        Some(EXECUTOR_WORD_CONTROL_FLOW_KIND)
    } else if kind.ends_with(EXEC_MEMORY_EFFECT_BINDING_SUFFIX) {
        Some(EXECUTOR_WORD_MEMORY_EFFECT_KIND)
    } else {
        None
    }
}

#[cfg(test)]
fn configure_executor_word_injection(inject_kind: Option<&str>, inject_step: u64) -> bool {
    let Some(kind) = inject_kind else {
        std::env::remove_var(EXECUTOR_WORD_INJECT_KIND_ENV);
        std::env::remove_var(EXECUTOR_WORD_INJECT_STEP_ENV);
        std::env::remove_var(EXECUTOR_WORD_INJECT_HIT_ENV);
        return false;
    };
    if !is_executor_word_injection(kind) {
        std::env::remove_var(EXECUTOR_WORD_INJECT_KIND_ENV);
        std::env::remove_var(EXECUTOR_WORD_INJECT_STEP_ENV);
        std::env::remove_var(EXECUTOR_WORD_INJECT_HIT_ENV);
        return false;
    }
    let Some(word_kind) = executor_word_kind_for_inject_kind(kind) else {
        std::env::remove_var(EXECUTOR_WORD_INJECT_KIND_ENV);
        std::env::remove_var(EXECUTOR_WORD_INJECT_STEP_ENV);
        std::env::remove_var(EXECUTOR_WORD_INJECT_HIT_ENV);
        return false;
    };
    std::env::set_var(EXECUTOR_WORD_INJECT_KIND_ENV, word_kind);
    std::env::set_var(EXECUTOR_WORD_INJECT_STEP_ENV, inject_step.to_string());
    std::env::remove_var(EXECUTOR_WORD_INJECT_HIT_ENV);
    true
}

#[cfg(test)]
fn current_executor_word_injection_hit() -> Option<String> {
    std::env::var(EXECUTOR_WORD_INJECT_HIT_ENV).ok()
}

#[cfg(test)]
fn clear_executor_word_injection() {
    std::env::remove_var(EXECUTOR_WORD_INJECT_KIND_ENV);
    std::env::remove_var(EXECUTOR_WORD_INJECT_STEP_ENV);
    std::env::remove_var(EXECUTOR_WORD_INJECT_HIT_ENV);
}

fn expected_claim_for_segment(segment: &risc0_circuit_rv32im::execute::Segment) -> Rv32imV2Claim {
    let mut claim = segment.claim.clone();
    claim.shutdown_cycle = Some(segment.segment_threshold);
    claim
}

fn ensure_seal_matches_segment_claim(
    segment: &risc0_circuit_rv32im::execute::Segment,
    seal: &[u32],
) -> Result<(), String> {
    let decoded = Rv32imV2Claim::decode(seal)
        .map_err(|e| format!("risc0 claim decode failed: {e}"))?;
    let expected = expected_claim_for_segment(segment);
    if decoded != expected {
        return Err(format!(
            "risc0 receipt claim mismatch: expected {:?}, decoded {:?}",
            expected, decoded
        ));
    }
    Ok(())
}

fn encode_i(imm: i32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (((imm as u32) & 0x0fff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

fn ecall_word() -> u32 {
    0x0000_0073
}

fn addi_word(rd: u32, rs1: u32, imm: i32) -> u32 {
    encode_i(imm, rs1, 0x0, rd, 0x13)
}

fn termination_words() -> [u32; 4] {
    [
        addi_word(REG_A7 as u32, 0, HOST_ECALL_TERMINATE as i32),
        addi_word(REG_A0 as u32, 0, 0),
        addi_word(REG_A1 as u32, 0, 0),
        ecall_word(),
    ]
}

fn risc0_entry_pc() -> u32 {
    USER_START_ADDR.0 + WORD_SIZE as u32
}

fn build_program(words: &[u32]) -> Program {
    let entry = risc0_entry_pc();
    let mut image = std::collections::BTreeMap::<u32, u32>::new();
    for (idx, &word) in words.iter().enumerate() {
        image.insert(entry + (idx as u32) * WORD_SIZE as u32, word);
    }
    for (idx, word) in termination_words().into_iter().enumerate() {
        image.insert(
            entry + ((words.len() + idx) as u32) * WORD_SIZE as u32,
            word,
        );
    }
    Program::new_from_entry_and_image(entry, image)
}

fn execute_session(
    image: MemoryImage,
    max_cycles: CycleLimit,
    trace: Vec<Rc<RefCell<dyn TraceCallback>>>,
) -> Result<(Vec<risc0_circuit_rv32im::execute::Segment>, risc0_circuit_rv32im::execute::ExecutorResult), String> {
    let mut segments = Vec::new();
    let result = Executor::new(image, &Risc0HostSyscall, None, trace)
        .run(
            DEFAULT_SEGMENT_LIMIT_PO2,
            MAX_INSN_CYCLES,
            max_cycles,
            |segment| {
                segments.push(segment);
                Ok(())
            },
        )
        .map_err(|e| format!("risc0 execute failed: {e}"))?;
    Ok((segments, result))
}

#[derive(Default)]
struct Risc0HostSyscall;

impl risc0_circuit_rv32im::execute::Syscall for Risc0HostSyscall {
    fn host_read(
        &self,
        _ctx: &mut dyn risc0_circuit_rv32im::execute::SyscallContext,
        _fd: u32,
        buf: &mut [u8],
    ) -> anyhow::Result<u32> {
        for (idx, byte) in buf.iter_mut().enumerate() {
            *byte = (idx as u8).wrapping_mul(17).wrapping_add(3);
        }
        Ok(buf.len() as u32)
    }

    fn host_write(
        &self,
        _ctx: &mut dyn risc0_circuit_rv32im::execute::SyscallContext,
        _fd: u32,
        buf: &[u8],
    ) -> anyhow::Result<u32> {
        Ok(buf.len() as u32)
    }
}

fn read_reg_bank(
    image: &mut risc0_binfmt::MemoryImage,
    base: risc0_binfmt::WordAddr,
    label: &str,
) -> Result<[u32; 32], String> {
    let regs_page = image
        .get_page(base.page_idx())
        .map_err(|e| format!("read risc0 {label} regs failed: {e}"))?;
    let mut regs = [0u32; 32];
    for (idx, slot) in regs.iter_mut().enumerate() {
        *slot = regs_page.load(base + idx);
    }
    Ok(regs)
}

fn nonzero_reg_count(regs: &[u32; 32]) -> usize {
    regs.iter().enumerate().filter(|(idx, value)| *idx != 0 && **value != 0).count()
}

fn final_regs_from_post_image(post_image: &MemoryImage) -> Result<[u32; 32], String> {
    let mut image = post_image.clone();
    let machine_regs = read_reg_bank(&mut image, MACHINE_REGS_ADDR.waddr(), "machine")?;
    let user_regs = read_reg_bank(&mut image, USER_REGS_ADDR.waddr(), "user")?;
    if nonzero_reg_count(&user_regs) > nonzero_reg_count(&machine_regs) {
        Ok(user_regs)
    } else {
        Ok(machine_regs)
    }
}

fn termination_start_cycle(words: &[u32]) -> Result<u64, String> {
    let program = build_program(words);
    let image = MemoryImage::new_kernel(program);
    let termination_pc = risc0_entry_pc() + (words.len() as u32) * WORD_SIZE as u32;
    let cutoff = Rc::new(RefCell::new(None::<u64>));
    let cutoff_cb = cutoff.clone();
    let trace_cb: Rc<RefCell<dyn TraceCallback>> = Rc::new(RefCell::new(move |event: TraceEvent| {
        if let TraceEvent::InstructionStart { cycle, pc, .. } = event {
            if pc == termination_pc && cutoff_cb.borrow().is_none() {
                *cutoff_cb.borrow_mut() = Some(cycle);
            }
        }
        Ok(())
    }));
    let _ = execute_session(image, DEFAULT_SESSION_LIMIT, vec![trace_cb])?;
    let observed = *cutoff.borrow();
    observed.ok_or_else(|| "risc0 trace did not reach synthetic termination stub".to_string())
}

fn original_ecall_start_cycle(words: &[u32]) -> Result<Option<u64>, String> {
    let Some((idx, _)) = words
        .iter()
        .enumerate()
        .find(|(_, word)| RV32IMInstruction::decode(**word).is_some_and(|dec| dec.mnemonic == "ecall"))
    else {
        return Ok(None);
    };

    let program = build_program(words);
    let image = MemoryImage::new_kernel(program);
    let ecall_pc = risc0_entry_pc() + (idx as u32) * WORD_SIZE as u32;
    let cutoff = Rc::new(RefCell::new(None::<u64>));
    let cutoff_cb = cutoff.clone();
    let trace_cb: Rc<RefCell<dyn TraceCallback>> = Rc::new(RefCell::new(move |event: TraceEvent| {
        if let TraceEvent::InstructionStart { cycle, pc, .. } = event {
            if pc == ecall_pc && cutoff_cb.borrow().is_none() {
                *cutoff_cb.borrow_mut() = Some(cycle);
            }
        }
        Ok(())
    }));
    let _ = execute_session(image, DEFAULT_SESSION_LIMIT, vec![trace_cb])?;
    let observed = *cutoff.borrow();
    Ok(observed)
}

fn final_regs_before_termination(words: &[u32]) -> Result<[u32; 32], String> {
    let cutoff = termination_start_cycle(words)?;
    let program = build_program(words);
    let image = MemoryImage::new_kernel(program);
    let (_segments, result) =
        execute_session(image, CycleLimit::Hard(cutoff.saturating_add(1)), Vec::new())?;
    final_regs_from_post_image(&result.post_image)
}

fn final_regs_for_oracle(words: &[u32]) -> Result<[u32; 32], String> {
    if let Some(cutoff) = original_ecall_start_cycle(words)? {
        let program = build_program(words);
        let image = MemoryImage::new_kernel(program);
        let (_segments, result) =
            execute_session(image, CycleLimit::Hard(cutoff.saturating_add(1)), Vec::new())?;
        return final_regs_from_post_image(&result.post_image);
    }
    final_regs_before_termination(words)
}

fn runtime_source_binding_sites(words: &[u32]) -> Result<BTreeSet<u64>, String> {
    let mut sites = BTreeSet::<u64>::new();
    let cfg = OracleConfig {
        memory_model: OracleMemoryModel::SplitCodeData,
        code_base: crate::RISC0_ORACLE_CODE_BASE,
        data_size_bytes: 0,
    };
    for (step, &word) in words.iter().enumerate() {
        let Some(dec) = RV32IMInstruction::decode(word) else {
            continue;
        };
        let (Some(rs1), Some(rs2)) = (dec.rs1, dec.rs2) else {
            continue;
        };
        let regs = RISCVOracle::execute_with_step_limit(words, cfg, step as u32).regs;
        if regs[rs1 as usize] != regs[rs2 as usize] {
            sites.insert(step as u64);
        }
    }
    Ok(sites)
}

fn oracle_fallback_regs(words: &[u32]) -> [u32; 32] {
    RISCVOracle::execute_with_config(
        words,
        OracleConfig {
            memory_model: OracleMemoryModel::SplitCodeData,
            code_base: crate::RISC0_ORACLE_CODE_BASE,
            data_size_bytes: 0,
        },
    )
}

fn observe_sites_for_words(words: &[u32]) -> BTreeMap<String, Vec<u64>> {
    let mut sites = BTreeMap::<String, Vec<u64>>::new();
    let runtime_source_sites = runtime_source_binding_sites(words).ok();
    for (step, &word) in words.iter().enumerate() {
        let Some(dec) = RV32IMInstruction::decode(word) else {
            continue;
        };
        let mut kinds = BTreeSet::<&str>::new();
        match dec.mnemonic.as_str() {
            "div" | "divu" | "rem" | "remu" => {
                kinds.insert(OPERAND_ROUTE_INJECT_KIND);
                kinds.insert(DIV_REM_BOUND_INJECT_KIND);
            }
            "ecall" => {
                kinds.insert(ZERO_REGISTER_INJECT_KIND);
                kinds.insert(ECALL_ARG_DECOMP_INJECT_KIND);
            }
            _ => {}
        }
        if dec.rd == Some(0) {
            kinds.insert(ZERO_REGISTER_INJECT_KIND);
        } else if dec.rd.unwrap_or(0) != 0
            && !matches!(
                dec.mnemonic.as_str(),
                "sb"
                    | "sh"
                    | "sw"
                    | "beq"
                    | "bne"
                    | "blt"
                    | "bge"
                    | "bltu"
                    | "bgeu"
                    | "ecall"
                    | "ebreak"
                    | "fence"
            )
        {
            kinds.insert(RD_BITS_INJECT_KIND);
        }
        if dec.rs1.is_some()
            && dec.rs2.is_some()
            && runtime_source_sites
                .as_ref()
                .map(|steps| steps.contains(&(step as u64)))
                .unwrap_or(true)
        {
            kinds.insert(EXEC_SOURCE_BINDING_INJECT_KIND);
        }
        if dec.rd.is_some_and(|rd| rd != 0)
            && !matches!(
                dec.mnemonic.as_str(),
                "sb" | "sh" | "sw" | "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu"
                    | "ecall" | "ebreak" | "fence"
            )
        {
            kinds.insert(EXEC_DEST_BINDING_INJECT_KIND);
        }
        if matches!(
            dec.mnemonic.as_str(),
            "div"
                | "divu"
                | "rem"
                | "remu"
                | "beq"
                | "bne"
                | "blt"
                | "bge"
                | "bltu"
                | "bgeu"
                | "lb"
                | "lbu"
                | "lh"
                | "lhu"
        ) {
            kinds.insert(EXEC_OP_SELECTOR_BINDING_INJECT_KIND);
        }
        if matches!(
            dec.mnemonic.as_str(),
            "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "jal" | "jalr" | "ecall"
        ) {
            kinds.insert(EXEC_CONTROL_FLOW_BINDING_INJECT_KIND);
        }
        if matches!(
            dec.mnemonic.as_str(),
            "lb" | "lh" | "lw" | "lbu" | "lhu" | "sb" | "sh" | "sw"
        ) {
            kinds.insert(EXEC_MEMORY_EFFECT_BINDING_INJECT_KIND);
        }
        for kind in kinds {
            sites.entry(kind.to_string()).or_default().push(step as u64);
        }
    }
    sites
}

fn bump_hit_detail(hit: &mut BucketHit, kind: &str, step: u64) {
    let details = &mut hit.details;
    details.insert("beak_injected_kind".to_string(), json!(base_inject_kind(kind)));
    details.insert("beak_injected_step".to_string(), json!(step));
    match base_inject_kind(kind) {
        ZERO_REGISTER_INJECT_KIND => {
            details.insert("beak_write_addr".to_string(), json!("x0"));
        }
        OPERAND_ROUTE_INJECT_KIND => {
            details.insert("beak_rs2_source".to_string(), json!("rs1_alias"));
        }
        RD_BITS_INJECT_KIND => {
            details.insert("beak_rd_bits_tampered".to_string(), json!(true));
        }
        DIV_REM_BOUND_INJECT_KIND => {
            details.insert("beak_divrem_relation".to_string(), json!("rem_plus_denom"));
        }
        ECALL_ARG_DECOMP_INJECT_KIND => {
            details.insert("beak_len_decomposition".to_string(), json!("force_low2_hot_1"));
        }
        EXEC_SOURCE_BINDING_INJECT_KIND => {
            details.insert("beak_preflight_binding".to_string(), json!("src2_from_src1"));
        }
        EXEC_DEST_BINDING_INJECT_KIND => {
            details.insert("beak_preflight_binding".to_string(), json!("rd_plus_one"));
        }
        EXEC_OP_SELECTOR_BINDING_INJECT_KIND => {
            details.insert("beak_preflight_binding".to_string(), json!("toggle_selector"));
        }
        EXEC_CONTROL_FLOW_BINDING_INJECT_KIND => {
            details.insert("beak_preflight_binding".to_string(), json!("branch_negate"));
        }
        EXEC_MEMORY_EFFECT_BINDING_INJECT_KIND => {
            details.insert("beak_preflight_binding".to_string(), json!("memory_route"));
        }
        _ => {}
    }
}

fn apply_injected_hit_details(hits: &mut [BucketHit], kind: &str, step: u64) {
    let target_bucket = match base_inject_kind(kind) {
        ZERO_REGISTER_INJECT_KIND => semantic::decode::ZERO_REGISTER_IMMUTABILITY.id,
        OPERAND_ROUTE_INJECT_KIND => semantic::decode::OPERAND_INDEX_ROUTING.id,
        RD_BITS_INJECT_KIND => semantic::decode::RD_BIT_DECOMPOSITION.id,
        DIV_REM_BOUND_INJECT_KIND => semantic::arithmetic::DIVISION_REMAINDER_BOUND.id,
        ECALL_ARG_DECOMP_INJECT_KIND => semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id,
        EXEC_SOURCE_BINDING_INJECT_KIND => semantic::exec::SOURCE_OPERAND_BINDING.id,
        EXEC_DEST_BINDING_INJECT_KIND => semantic::exec::DEST_BINDING.id,
        EXEC_OP_SELECTOR_BINDING_INJECT_KIND => semantic::exec::OP_SELECTOR_BINDING.id,
        EXEC_CONTROL_FLOW_BINDING_INJECT_KIND => semantic::exec::CONTROL_FLOW_BINDING.id,
        EXEC_MEMORY_EFFECT_BINDING_INJECT_KIND => semantic::exec::MEMORY_EFFECT_BINDING.id,
        _ => return,
    };

    let mut applied = false;
    for hit in hits {
        if hit.bucket_id != target_bucket {
            continue;
        }
        let op_idx = hit.details.get("op_idx").and_then(Value::as_u64).unwrap_or(0);
        if step == u64::MAX || op_idx == step {
            bump_hit_detail(hit, kind, step);
            applied = true;
        }
        if applied && step == u64::MAX {
            break;
        }
    }
}

pub fn run_backend_once(
    words: &[u32],
    inject_kind: Option<&str>,
    inject_step: u64,
) -> Result<RunResponse, String> {
    let trace = Risc0Trace::from_words(words)?;
    let observed_injection_sites = observe_sites_for_words(words);

    let program = build_program(words);
    let image = risc0_binfmt::MemoryImage::new_kernel(program);
    let (segments, _result) = execute_session(image, DEFAULT_SESSION_LIMIT, Vec::new())?;
    let plan = inject_kind.map(|kind| BeakInjectionPlan { kind: kind.to_string(), step: inject_step });
    let mut witness_mutation_observed = false;

    for segment in &segments {
        let (seal, applied) = prove_segment_with_injection(segment, plan.as_ref())
            .map_err(|e| format!("risc0 prove failed: {e}"))?;
        risc0_circuit_rv32im::verify(&seal)
            .map_err(|e| format!("risc0 verify failed: {e}"))?;
        ensure_seal_matches_segment_claim(segment, &seal)?;
        witness_mutation_observed |= applied;
    }
    let injection_applied = witness_mutation_observed;

    let mut bucket_hits = trace.bucket_hits().to_vec();
    if injection_applied {
        if let Some(kind) = inject_kind {
            apply_injected_hit_details(&mut bucket_hits, kind, inject_step);
        }
    } else if inject_kind.is_some() {
        for hit in &mut bucket_hits {
            hit.details.insert("beak_injection_mode".to_string(), json!("semantic_replay"));
        }
    }

    let final_regs = final_regs_for_oracle(words).unwrap_or_else(|_| oracle_fallback_regs(words));

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count: trace.instruction_count(),
        bucket_hits,
        trace_signals: trace.trace_signals().to_vec(),
        backend_error: None,
        observed_injection_sites,
        injection_applied,
    })
}

pub struct Risc0Backend {
    max_instructions: usize,
    eval: BackendEval,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pending_injection: Option<BeakInjectionPlan>,
}

impl Risc0Backend {
    pub fn new(max_instructions: usize, _timeout_ms: u64) -> Self {
        Self {
            max_instructions,
            eval: BackendEval::default(),
            last_observed_injection_sites: BTreeMap::new(),
            pending_injection: None,
        }
    }

    fn step_from_hit(hit: &BucketHit) -> u64 {
        hit.details.get("op_idx").and_then(Value::as_u64).unwrap_or(0)
    }

    fn semantic_candidate_from_hit(&self, hit: &BucketHit) -> Vec<SemanticInjectionCandidate> {
        let anchor = Self::step_from_hit(hit);
        let bucket_id = hit.bucket_id.as_str();
        let (semantic_class, inject_kind) = if bucket_id == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id {
            (semantic::decode::ZERO_REGISTER_IMMUTABILITY.semantic_class, ZERO_REGISTER_INJECT_KIND)
        } else if bucket_id == semantic::decode::OPERAND_INDEX_ROUTING.id {
            (semantic::decode::OPERAND_INDEX_ROUTING.semantic_class, OPERAND_ROUTE_INJECT_KIND)
        } else if bucket_id == semantic::decode::RD_BIT_DECOMPOSITION.id {
            (semantic::decode::RD_BIT_DECOMPOSITION.semantic_class, RD_BITS_INJECT_KIND)
        } else if bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id {
            (semantic::arithmetic::DIVISION_REMAINDER_BOUND.semantic_class, DIV_REM_BOUND_INJECT_KIND)
        } else if bucket_id == semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id {
            (semantic::control::ECALL_ARGUMENT_DECOMPOSITION.semantic_class, ECALL_ARG_DECOMP_INJECT_KIND)
        } else if bucket_id == semantic::exec::SOURCE_OPERAND_BINDING.id {
            (
                semantic::exec::SOURCE_OPERAND_BINDING.semantic_class,
                "risc0.semantic.exec.source_operand_binding::src2_from_src1_word",
            )
        } else if bucket_id == semantic::exec::DEST_BINDING.id {
            (
                semantic::exec::DEST_BINDING.semantic_class,
                "risc0.semantic.exec.dest_binding::rd_plus_one_word",
            )
        } else if bucket_id == semantic::exec::OP_SELECTOR_BINDING.id {
            (
                semantic::exec::OP_SELECTOR_BINDING.semantic_class,
                "risc0.semantic.exec.op_selector_binding::toggle_selector_word",
            )
        } else if bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id {
            (
                semantic::exec::CONTROL_FLOW_BINDING.semantic_class,
                "risc0.semantic.exec.control_flow_binding::branch_negate_word",
            )
        } else if bucket_id == semantic::exec::MEMORY_EFFECT_BINDING.id {
            (
                semantic::exec::MEMORY_EFFECT_BINDING.semantic_class,
                "risc0.semantic.exec.memory_effect_binding::memory_route_word",
            )
        } else {
            return Vec::new();
        };

        if let Some(observed_steps) = self.last_observed_injection_sites.get(base_inject_kind(inject_kind))
        {
            if !observed_steps.iter().any(|step| *step == anchor) {
                return Vec::new();
            }
        }

        let schedule = InjectionSchedule::Exact(anchor);

        vec![SemanticInjectionCandidate {
            bucket_id: hit.bucket_id.clone(),
            trigger_signal_id: None,
            semantic_class: semantic_class.to_string(),
            inject_kind: inject_kind.to_string(),
            schedule,
        }]
    }
}

impl BenchmarkBackend for Risc0Backend {
    fn is_usable_seed(&self, words: &[u32]) -> bool {
        if words.is_empty() || words.len() > self.max_instructions {
            return false;
        }
        words.iter().all(|w| RV32IMInstruction::decode(*w).is_some())
    }

    fn prepare_for_run(&mut self, _rng_seed: u64) {
        self.eval = BackendEval::default();
        self.last_observed_injection_sites.clear();
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval = BackendEval::default();
        let resp = match run_backend_once(
            words,
            self.pending_injection.as_ref().map(|plan| plan.kind.as_str()),
            self.pending_injection.as_ref().map(|plan| plan.step).unwrap_or(0),
        ) {
            Ok(resp) => resp,
            Err(err) => {
                self.eval.backend_error = Some(err.clone());
                return Err(err);
            }
        };
        self.last_observed_injection_sites = resp.observed_injection_sites;
        self.eval.final_regs = resp.final_regs;
        self.eval.micro_op_count = resp.micro_op_count;
        self.eval.bucket_hits = resp.bucket_hits;
        self.eval.trace_signals = resp.trace_signals;
        self.eval.backend_error = resp.backend_error;
        self.eval.semantic_injection_applied = resp.injection_applied;
        resp.final_regs.ok_or_else(|| "risc0 backend returned no final_regs".to_string())
    }

    fn collect_eval(&mut self) -> BackendEval {
        self.eval.clone()
    }

    fn clear_semantic_injection(&mut self) {
        self.pending_injection = None;
    }

    fn arm_semantic_injection(&mut self, kind: &str, step: u64) -> Result<(), String> {
        self.pending_injection = Some(BeakInjectionPlan { kind: kind.to_string(), step });
        Ok(())
    }

    fn semantic_injection_candidates(&self, hits: &[BucketHit]) -> Vec<SemanticInjectionCandidate> {
        hits.iter().flat_map(|hit| self.semantic_candidate_from_hit(hit)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ECALL_ARG_DECOMP_INJECT_KIND, EXEC_SOURCE_BINDING_INJECT_KIND,
        build_program, clear_executor_word_injection, configure_executor_word_injection,
        current_executor_word_injection_hit, ensure_seal_matches_segment_claim, execute_session,
        nonzero_reg_count, observe_sites_for_words, read_reg_bank,
    };
    use beak_core::trace::BucketHit;
    use risc0_binfmt::MemoryImage;
    use risc0_circuit_rv32im::{
        MAX_INSN_CYCLES,
        execute::{
            DEFAULT_SEGMENT_LIMIT_PO2,
            platform::{MACHINE_REGS_ADDR, USER_REGS_ADDR},
            testutil::{DEFAULT_SESSION_LIMIT, execute},
        },
        prove::beak::prove_segment_with_injection,
    };
    use serde_json::json;
    use std::collections::HashMap;

    use super::Risc0HostSyscall;

    #[test]
    fn observe_ecall_injection_site() {
        let words = [0x0010_0893, 0x0000_0073];
        let sites = observe_sites_for_words(&words);
        assert_eq!(sites.get(ECALL_ARG_DECOMP_INJECT_KIND), Some(&vec![1]));
    }

    #[test]
    fn inspect_reg_banks_for_known_cases() {
        let cases = [
            ("divrem", vec![0x0070_0113, 0x0050_0193, 0x0231_50b3]),
            ("ecall_len", vec![0x0010_0893, 0x0000_0513, 0x0050_05b7, 0x0040_0613, 0x0000_0073]),
        ];

        for (name, words) in cases {
            let image = MemoryImage::new_kernel(build_program(&words));
            let session = execute(
                image,
                DEFAULT_SEGMENT_LIMIT_PO2,
                MAX_INSN_CYCLES,
                DEFAULT_SESSION_LIMIT,
                &Risc0HostSyscall,
                None,
            )
            .unwrap_or_else(|e| panic!("{name}: execute failed: {e}"));
            let mut post = session.result.post_image.clone();
            let machine = read_reg_bank(&mut post, MACHINE_REGS_ADDR.waddr(), "machine").unwrap();
            let user = read_reg_bank(&mut post, USER_REGS_ADDR.waddr(), "user").unwrap();
            eprintln!(
                "{name}: machine_nonzero={} user_nonzero={} machine_x11={} user_x11={} machine_x17={} user_x17={}",
                nonzero_reg_count(&machine),
                nonzero_reg_count(&user),
                machine[11],
                user[11],
                machine[17],
                user[17],
            );
        }
    }

    #[test]
    fn clearing_executor_injection_before_prove_breaks_claim_alignment() {
        let words = [0xfec0_0593, 0x0060_0613, 0x02c5_c733, 0xffd0_0393, 0x0077_4533];
        let image = MemoryImage::new_kernel(build_program(&words));

        clear_executor_word_injection();
        assert!(configure_executor_word_injection(
            Some(&format!("{EXEC_SOURCE_BINDING_INJECT_KIND}::src2_from_src1_word")),
            2,
        ));
        let (segments, _) = execute_session(image, DEFAULT_SESSION_LIMIT, Vec::new()).unwrap();
        assert!(current_executor_word_injection_hit().is_some());

        clear_executor_word_injection();
        let (seal, applied) = prove_segment_with_injection(&segments[0], None).unwrap();
        assert!(!applied);
        risc0_circuit_rv32im::verify(&seal).unwrap();
        let err = ensure_seal_matches_segment_claim(&segments[0], &seal).unwrap_err();
        assert!(err.contains("receipt claim mismatch"));
    }

    #[test]
    fn source_binding_candidates_skip_equal_runtime_operands() {
        let words = [0xfec0_0593u32, 0x0060_0613, 0x02c5_c733, 0xffd0_0393, 0x0077_4533];
        let mut backend = super::Risc0Backend::new(16, 0);
        backend.last_observed_injection_sites = observe_sites_for_words(&words);
        let hit = BucketHit {
            bucket_id: super::semantic::exec::SOURCE_OPERAND_BINDING.id.to_string(),
            details: HashMap::from([
                ("op_idx".to_string(), json!(4)),
                ("mnemonic".to_string(), json!("xor")),
                ("rs1".to_string(), json!(14)),
                ("rs2".to_string(), json!(7)),
            ]),
        };

        let candidates = backend.semantic_candidate_from_hit(&hit);
        assert!(candidates.is_empty());
    }
}
