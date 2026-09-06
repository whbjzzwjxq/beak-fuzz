use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::{cell::RefCell, rc::Rc};

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, ExecutedExceptionReceipt, InjectionSchedule,
    SemanticInjectionCandidate,
};
use beak_core::fuzz::bug_filter::has_exact_executed_exception_relation;
use beak_core::rv32im::{
    instruction::RV32IMInstruction,
    oracle::{OracleConfig, OracleMemoryModel, RISCVOracle},
};
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use risc0_binfmt::{MemoryImage, Program};
use risc0_circuit_rv32im::{
    execute::{
        platform::{
            HOST_ECALL_TERMINATE, LOOKUP_TABLE_CYCLES, MACHINE_REGS_ADDR, REG_A0, REG_A1, REG_A7,
            USER_REGS_ADDR, USER_START_ADDR, WORD_SIZE,
        },
        testutil::DEFAULT_SESSION_LIMIT,
        Executor, DEFAULT_SEGMENT_LIMIT_PO2,
    },
    prove::beak::{
        collect_preflight_trace_records, prove_segment_with_injection, BeakInjectionPlan,
    },
    trace::{TraceCallback, TraceEvent},
    MAX_INSN_CYCLES,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::trace::{
    executed_instructions, Risc0ExecutedInsnRecord, Risc0PreflightMemoryTxn,
    Risc0PreflightSegmentSummary, Risc0Trace,
};

const ZERO_REGISTER_INJECT_KIND: &str = "risc0.semantic.decode.zero_register_immutability";
const OPERAND_ROUTE_INJECT_KIND: &str = "risc0.semantic.decode.operand_index_routing";
const RD_BITS_INJECT_KIND: &str = "risc0.semantic.decode.rd_bit_decomposition";
const DIV_REM_BOUND_INJECT_KIND: &str = "risc0.semantic.arithmetic.division_remainder_bound";
const ECALL_ARG_DECOMP_INJECT_KIND: &str = "risc0.semantic.control.ecall_argument_decomposition";
const CONTROL_DONE_CYCLES_REQUIRED: u64 = 2;
const CONTROL_DONE_RECEIPT_ARMED_ENV: &str = "BEAK_RISC0_CONTROL_DONE_RECEIPT_ARMED";
const EXECUTED_EXCEPTION_RECEIPT_ENV: &str = "BEAK_RISC0_EXECUTED_EXCEPTION_RECEIPT";
const CONTROL_DONE_RECEIPT_BACKEND: &str = "risc0";
const CONTROL_DONE_RECEIPT_TRACE_SOURCE: &str = "segment_finalization";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub backend_error: Option<String>,
    pub observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pub injection_applied: bool,
    pub executed_exception_receipt: Option<ExecutedExceptionReceipt>,
}

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn semantic_replay_supported(kind: &str) -> bool {
    !matches!(base_inject_kind(kind), ZERO_REGISTER_INJECT_KIND | RD_BITS_INJECT_KIND)
}

fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    format!("non-string panic payload ({:?})", payload.type_id())
}

fn prove_panic_error(payload: &(dyn Any + Send), injection_armed: bool) -> String {
    let phase = if injection_armed { "semantic-injection attempt" } else { "non-injected proving" };
    format!("risc0 prove panicked during {phase}: {}", panic_payload_message(payload))
}

fn restore_env_var(name: &str, previous: Option<std::ffi::OsString>) {
    if let Some(value) = previous {
        std::env::set_var(name, value);
    } else {
        std::env::remove_var(name);
    }
}

fn parse_control_done_receipt(raw: Option<&str>) -> Option<ExecutedExceptionReceipt> {
    raw.and_then(|raw| serde_json::from_str(raw).ok())
}

fn validated_control_done_receipt(
    raw: Option<&str>,
    hits: &[BucketHit],
    inject_kind: Option<&str>,
    non_injected_panic_observed: bool,
) -> Option<ExecutedExceptionReceipt> {
    if inject_kind.is_some() || !non_injected_panic_observed {
        return None;
    }
    let receipt = parse_control_done_receipt(raw)?;
    if receipt.context.get("backend").and_then(Value::as_str) != Some(CONTROL_DONE_RECEIPT_BACKEND)
        || receipt.context.get("commit").and_then(Value::as_str) != Some(crate::RISC0_COMMIT)
        || receipt.context.get("trace_source").and_then(Value::as_str)
            != Some(CONTROL_DONE_RECEIPT_TRACE_SOURCE)
    {
        return None;
    }
    if !has_exact_executed_exception_relation(hits, Some(&receipt)) {
        return None;
    }
    hits.iter().find(|hit| {
        let hit_u64 = |key: &str| hit.details.get(key).and_then(Value::as_u64);
        let context_u64 = |key: &str| receipt.context.get(key).and_then(Value::as_u64);
        let (Some(actual), Some(accounted), Some(required), Some(capacity), Some(manifested)) = (
            hit_u64("actual_trace_cycles"),
            hit_u64("accounted_cycles"),
            hit_u64("required_cycles"),
            hit_u64("capacity_cycles"),
            hit_u64("manifested_control_done_cycles"),
        ) else {
            return false;
        };
        context_u64("actual_trace_cycles") == Some(actual)
            && context_u64("manifested_control_done_cycles") == Some(manifested)
            && manifested == 1
            && accounted.checked_add(manifested) == Some(actual)
            && actual > capacity
            && actual.checked_add(1) == Some(required)
            && hit.details.get("obligation_id").and_then(Value::as_str)
                == Some(receipt.obligation_id.as_str())
            && hit.details.get("cell_id").and_then(Value::as_str) == Some(receipt.cell_id.as_str())
            && hit_u64("step_idx") == Some(receipt.step)
    })?;
    Some(receipt)
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
        image.insert(entry + ((words.len() + idx) as u32) * WORD_SIZE as u32, word);
    }
    Program::new_from_entry_and_image(entry, image)
}

fn execute_session(
    image: MemoryImage,
    max_cycles: Option<u64>,
    trace: Vec<Rc<RefCell<dyn TraceCallback>>>,
) -> Result<
    (Vec<risc0_circuit_rv32im::execute::Segment>, risc0_circuit_rv32im::execute::ExecutorResult),
    String,
> {
    let mut segments = Vec::new();
    let result = Executor::new(image, &Risc0HostSyscall, None, trace)
        .run(DEFAULT_SEGMENT_LIMIT_PO2, MAX_INSN_CYCLES, max_cycles, |segment| {
            segments.push(segment);
            Ok(())
        })
        .map_err(|e| format!("risc0 execute failed: {e}"))?;
    Ok((segments, result))
}

fn collect_preflight_records_for_segments(
    segments: &[risc0_circuit_rv32im::execute::Segment],
) -> Result<(Vec<Risc0PreflightMemoryTxn>, Vec<Risc0PreflightSegmentSummary>), String> {
    let mut txns = Vec::new();
    let mut summaries = Vec::new();

    for segment in segments {
        let records = collect_preflight_trace_records(segment)
            .map_err(|e| format!("risc0 preflight record collection failed: {e}"))?;
        let segment_idx = segment.index;
        let segment_po2 = segment.po2 as u64;
        let capacity_cycles = 1u64.checked_shl(segment.po2).unwrap_or(u64::MAX);
        let user_cycles = segment.suspend_cycle as u64;
        let pager_cycles = segment.paging_cycles as u64;
        let lookup_table_cycles = LOOKUP_TABLE_CYCLES as u64;
        let accounted_cycles =
            user_cycles.saturating_add(pager_cycles).saturating_add(lookup_table_cycles);
        let required_cycles = accounted_cycles.saturating_add(CONTROL_DONE_CYCLES_REQUIRED);
        summaries.push(Risc0PreflightSegmentSummary {
            segment_idx,
            segment_po2,
            capacity_cycles,
            user_cycles,
            pager_cycles,
            lookup_table_cycles,
            accounted_cycles,
            control_done_cycles_required: CONTROL_DONE_CYCLES_REQUIRED,
            required_cycles,
            overflow_cycles: required_cycles.saturating_sub(capacity_cycles),
            table_split_cycle: records.table_split_cycle,
            padding_start_row: records.padding_start_row,
            total_rows: records.total_rows,
            lookup_table_rows: records.lookup_table_rows,
        });
        txns.extend(records.txns.into_iter().map(|txn| Risc0PreflightMemoryTxn {
            segment_idx,
            row_idx: txn.row_idx,
            row_step_idx: txn.row_step_idx,
            row_pc: txn.row_pc,
            major: txn.major,
            minor: txn.minor,
            machine_mode: txn.machine_mode,
            txn_idx: txn.txn_idx,
            row_txn_start: txn.row_txn_start,
            row_txn_end: txn.row_txn_end,
            addr_word: txn.addr_word,
            txn_cycle: txn.txn_cycle,
            word: txn.word,
            prev_cycle: txn.prev_cycle,
            prev_word: txn.prev_word,
            is_load: txn.is_load,
            is_store: txn.is_store,
        }));
    }

    Ok((txns, summaries))
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
    let trace_cb: Rc<RefCell<dyn TraceCallback>> =
        Rc::new(RefCell::new(move |event: TraceEvent| {
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
    let Some((idx, _)) = words.iter().enumerate().find(|(_, word)| {
        RV32IMInstruction::decode(**word).is_some_and(|dec| dec.mnemonic == "ecall")
    }) else {
        return Ok(None);
    };

    let program = build_program(words);
    let image = MemoryImage::new_kernel(program);
    let ecall_pc = risc0_entry_pc() + (idx as u32) * WORD_SIZE as u32;
    let cutoff = Rc::new(RefCell::new(None::<u64>));
    let cutoff_cb = cutoff.clone();
    let trace_cb: Rc<RefCell<dyn TraceCallback>> =
        Rc::new(RefCell::new(move |event: TraceEvent| {
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
    let (_segments, result) = execute_session(image, Some(cutoff.saturating_add(1)), Vec::new())?;
    final_regs_from_post_image(&result.post_image)
}

fn final_regs_for_oracle(words: &[u32]) -> Result<[u32; 32], String> {
    if let Some(cutoff) = original_ecall_start_cycle(words)? {
        let program = build_program(words);
        let image = MemoryImage::new_kernel(program);
        let (_segments, result) =
            execute_session(image, Some(cutoff.saturating_add(1)), Vec::new())?;
        return final_regs_from_post_image(&result.post_image);
    }
    final_regs_before_termination(words)
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
    let Ok(instructions) = executed_instructions(words) else {
        return sites;
    };
    for insn in instructions {
        let mut kinds = BTreeSet::<&str>::new();
        match insn.mnemonic.as_str() {
            "div" | "divu" | "rem" | "remu" => {
                kinds.insert(OPERAND_ROUTE_INJECT_KIND);
                if let Some(rs2) = insn.rs2 {
                    if insn.regs_before[rs2 as usize] != 0 {
                        kinds.insert(DIV_REM_BOUND_INJECT_KIND);
                    }
                }
            }
            "ecall" => {
                kinds.insert(ZERO_REGISTER_INJECT_KIND);
                kinds.insert(ECALL_ARG_DECOMP_INJECT_KIND);
            }
            _ => {}
        }
        if insn.rd == Some(0) {
            kinds.insert(ZERO_REGISTER_INJECT_KIND);
        } else if insn.rd.unwrap_or(0) != 0
            && !matches!(
                insn.mnemonic.as_str(),
                "sb" | "sh"
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
        for kind in kinds {
            sites.entry(kind.to_string()).or_default().push(insn.step_idx);
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
    if let Some(kind) = inject_kind {
        if !semantic_replay_supported(kind) {
            return Err(format!(
                "risc0 semantic replay is unsupported on 6f038bd for {}: injected prover path can trap with SIGFPE",
                base_inject_kind(kind)
            ));
        }
    }

    let observed_injection_sites = observe_sites_for_words(words);

    let program = build_program(words);
    let image = risc0_binfmt::MemoryImage::new_kernel(program);
    let executed_records = Rc::new(RefCell::new(Vec::<Risc0ExecutedInsnRecord>::new()));
    let records_cb = executed_records.clone();
    let trace_cb: Rc<RefCell<dyn TraceCallback>> =
        Rc::new(RefCell::new(move |event: TraceEvent| {
            if let TraceEvent::InstructionStart { cycle, pc, insn } = event {
                records_cb.borrow_mut().push(Risc0ExecutedInsnRecord {
                    step_idx: cycle,
                    pc,
                    word: insn,
                });
            }
            Ok(())
        }));
    let (segments, _result) = execute_session(image, DEFAULT_SESSION_LIMIT, vec![trace_cb])?;
    let executed_records = executed_records.borrow().clone();
    let (preflight_txns, preflight_summaries) = collect_preflight_records_for_segments(&segments)?;
    let trace = Risc0Trace::from_words_with_preflight_and_executed(
        words,
        &executed_records,
        &preflight_txns,
        &preflight_summaries,
    )?;

    let plan =
        inject_kind.map(|kind| BeakInjectionPlan { kind: kind.to_string(), step: inject_step });
    let mut witness_mutation_observed = false;
    let mut backend_error = None;
    let mut raw_executed_exception_receipt = None;
    let mut non_injected_panic_observed = false;

    for segment in &segments {
        let previous_armed = std::env::var_os(CONTROL_DONE_RECEIPT_ARMED_ENV);
        let previous_receipt = std::env::var_os(EXECUTED_EXCEPTION_RECEIPT_ENV);
        std::env::remove_var(EXECUTED_EXCEPTION_RECEIPT_ENV);
        if plan.is_none() {
            std::env::set_var(CONTROL_DONE_RECEIPT_ARMED_ENV, segment.index.to_string());
        } else {
            std::env::remove_var(CONTROL_DONE_RECEIPT_ARMED_ENV);
        }
        let proved =
            catch_unwind(AssertUnwindSafe(|| prove_segment_with_injection(segment, plan.as_ref())));
        let emitted_receipt = std::env::var(EXECUTED_EXCEPTION_RECEIPT_ENV).ok();
        restore_env_var(CONTROL_DONE_RECEIPT_ARMED_ENV, previous_armed);
        restore_env_var(EXECUTED_EXCEPTION_RECEIPT_ENV, previous_receipt);
        let (seal, applied) = match proved {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => return Err(format!("risc0 prove failed: {err}")),
            Err(payload) => {
                non_injected_panic_observed = plan.is_none();
                raw_executed_exception_receipt = emitted_receipt;
                backend_error = Some(prove_panic_error(payload.as_ref(), plan.is_some()));
                break;
            }
        };
        witness_mutation_observed |= applied;
        if let Err(err) = risc0_circuit_rv32im::verify(&seal) {
            backend_error = Some(format!("risc0 verify failed: {err}"));
            break;
        }
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

    let executed_exception_receipt = validated_control_done_receipt(
        raw_executed_exception_receipt.as_deref(),
        &bucket_hits,
        inject_kind,
        non_injected_panic_observed,
    );

    let final_regs = final_regs_for_oracle(words).unwrap_or_else(|_| oracle_fallback_regs(words));

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count: trace.instruction_count(),
        bucket_hits,
        trace_signals: trace.trace_signals().to_vec(),
        backend_error,
        observed_injection_sites,
        injection_applied,
        executed_exception_receipt,
    })
}

pub struct Risc0Backend {
    max_instructions: usize,
    eval: BackendEval,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pending_injection: Option<BeakInjectionPlan>,
}

impl Risc0Backend {
    pub fn new(max_instructions: usize) -> Self {
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
        let (semantic_class, inject_kind) = if bucket_id
            == semantic::decode::ZERO_REGISTER_IMMUTABILITY.id
        {
            (semantic::decode::ZERO_REGISTER_IMMUTABILITY.semantic_class, ZERO_REGISTER_INJECT_KIND)
        } else if bucket_id == semantic::decode::OPERAND_INDEX_ROUTING.id {
            (semantic::decode::OPERAND_INDEX_ROUTING.semantic_class, OPERAND_ROUTE_INJECT_KIND)
        } else if bucket_id == semantic::decode::RD_BIT_DECOMPOSITION.id {
            (semantic::decode::RD_BIT_DECOMPOSITION.semantic_class, RD_BITS_INJECT_KIND)
        } else if bucket_id == semantic::arithmetic::DIVISION_REMAINDER_BOUND.id {
            (
                semantic::arithmetic::DIVISION_REMAINDER_BOUND.semantic_class,
                DIV_REM_BOUND_INJECT_KIND,
            )
        } else if bucket_id == semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id {
            (
                semantic::control::ECALL_ARGUMENT_DECOMPOSITION.semantic_class,
                ECALL_ARG_DECOMP_INJECT_KIND,
            )
        } else {
            return Vec::new();
        };

        if !semantic_replay_supported(inject_kind) {
            return Vec::new();
        }

        let schedule = if self
            .last_observed_injection_sites
            .get(base_inject_kind(inject_kind))
            .map(|steps| steps.iter().any(|step| *step == anchor))
            .unwrap_or(false)
        {
            InjectionSchedule::Exact(anchor)
        } else {
            InjectionSchedule::Exact(anchor)
        };

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
        self.eval.executed_exception_receipt = resp.executed_exception_receipt;
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
    use std::any::Any;
    use std::collections::HashMap;

    use super::{
        build_program, nonzero_reg_count, observe_sites_for_words, prove_panic_error,
        read_reg_bank, validated_control_done_receipt, ECALL_ARG_DECOMP_INJECT_KIND,
    };
    use beak_core::fuzz::benchmark::{ExecutedExceptionEffect, ExecutedExceptionReceipt};
    use beak_core::trace::{semantic, BucketHit};
    use risc0_binfmt::MemoryImage;
    use risc0_circuit_rv32im::{
        execute::{
            platform::{MACHINE_REGS_ADDR, USER_REGS_ADDR},
            testutil::{execute, DEFAULT_SESSION_LIMIT},
            DEFAULT_SEGMENT_LIMIT_PO2,
        },
        MAX_INSN_CYCLES,
    };
    use serde_json::json;

    use super::Risc0HostSyscall;

    #[test]
    fn observe_ecall_injection_site() {
        let words = [0x0010_0893, 0x0000_0073];
        let sites = observe_sites_for_words(&words);
        assert_eq!(sites.get(ECALL_ARG_DECOMP_INJECT_KIND), Some(&vec![1]));
    }

    #[test]
    fn prove_panic_error_preserves_string_payload_and_phase() {
        let baseline_payload: Box<dyn Any + Send> = Box::new("cycles <= 1 << segment.po2");
        let injected_payload: Box<dyn Any + Send> =
            Box::new(String::from("constraint polynomial mismatch"));

        let baseline = prove_panic_error(baseline_payload.as_ref(), false);
        let injected = prove_panic_error(injected_payload.as_ref(), true);
        let distinct_baseline = prove_panic_error(injected_payload.as_ref(), false);

        assert_eq!(
            baseline,
            "risc0 prove panicked during non-injected proving: cycles <= 1 << segment.po2"
        );
        assert_eq!(
            injected,
            "risc0 prove panicked during semantic-injection attempt: constraint polynomial mismatch"
        );
        assert_ne!(baseline, distinct_baseline);
    }

    #[test]
    fn prove_panic_error_labels_non_string_payloads_in_each_phase() {
        let baseline_payload: Box<dyn Any + Send> = Box::new(7_u32);
        let injected_payload: Box<dyn Any + Send> = Box::new(false);

        let baseline = prove_panic_error(baseline_payload.as_ref(), false);
        let injected = prove_panic_error(injected_payload.as_ref(), true);
        let distinct_baseline = prove_panic_error(injected_payload.as_ref(), false);

        assert!(baseline.starts_with(
            "risc0 prove panicked during non-injected proving: non-string panic payload"
        ));
        assert!(injected.starts_with(
            "risc0 prove panicked during semantic-injection attempt: non-string panic payload"
        ));
        assert_ne!(baseline, distinct_baseline);
    }

    fn control_done_hit() -> BucketHit {
        BucketHit::semantic(
            semantic::row::TRACE_POWER2_BOUNDARY,
            HashMap::from([
                ("obligation_id".to_string(), json!("pd2")),
                ("cell_id".to_string(), json!("pd2.just_over")),
                ("backend".to_string(), json!("risc0")),
                ("commit".to_string(), json!("6f038bd11ed725d7025687d163977d93ac1f82f9")),
                ("trace_source".to_string(), json!("segment_finalization")),
                ("segment_idx".to_string(), json!(3)),
                ("step_idx".to_string(), json!(3)),
                ("segment_po2".to_string(), json!(4)),
                ("capacity_cycles".to_string(), json!(16)),
                ("user_cycles".to_string(), json!(9)),
                ("pager_cycles".to_string(), json!(2)),
                ("lookup_table_cycles".to_string(), json!(5)),
                ("accounted_cycles".to_string(), json!(16)),
                ("control_done_cycles_required".to_string(), json!(2)),
                ("required_cycles".to_string(), json!(18)),
                ("overflow_cycles".to_string(), json!(2)),
                ("actual_trace_cycles".to_string(), json!(17)),
                ("manifested_control_done_cycles".to_string(), json!(1)),
                ("relation".to_string(), json!("control_done_cycles_cross_segment_capacity")),
                ("relation_valid".to_string(), json!(true)),
                ("accounted_fits".to_string(), json!(true)),
                ("required_exceeds".to_string(), json!(true)),
            ]),
        )
    }

    fn control_done_receipt() -> ExecutedExceptionReceipt {
        ExecutedExceptionReceipt {
            effect: ExecutedExceptionEffect::ControlDoneCapacity,
            obligation_id: "pd2".to_string(),
            cell_id: "pd2.just_over".to_string(),
            stage: "risc0.segment.control_done_capacity".to_string(),
            step: 3,
            context: serde_json::Map::from_iter([
                ("backend".to_string(), json!("risc0")),
                ("commit".to_string(), json!("6f038bd11ed725d7025687d163977d93ac1f82f9")),
                ("trace_source".to_string(), json!("segment_finalization")),
                ("segment_idx".to_string(), json!(3)),
                ("segment_po2".to_string(), json!(4)),
                ("capacity_cycles".to_string(), json!(16)),
                ("user_cycles".to_string(), json!(9)),
                ("pager_cycles".to_string(), json!(2)),
                ("lookup_table_cycles".to_string(), json!(5)),
                ("accounted_cycles".to_string(), json!(16)),
                ("control_done_cycles_required".to_string(), json!(2)),
                ("required_cycles".to_string(), json!(18)),
                ("overflow_cycles".to_string(), json!(2)),
                ("actual_trace_cycles".to_string(), json!(17)),
                ("manifested_control_done_cycles".to_string(), json!(1)),
                ("accounted_fits".to_string(), json!(true)),
                ("required_exceeds".to_string(), json!(true)),
            ]),
        }
    }

    #[test]
    fn control_done_receipt_requires_non_injected_panic_and_exact_executed_relation() {
        let hit = control_done_hit();
        let receipt = control_done_receipt();
        let raw = serde_json::to_string(&receipt).unwrap();

        assert_eq!(
            validated_control_done_receipt(Some(&raw), std::slice::from_ref(&hit), None, true),
            Some(receipt.clone())
        );
        assert!(
            validated_control_done_receipt(None, std::slice::from_ref(&hit), None, true).is_none()
        );
        assert!(validated_control_done_receipt(
            Some(&raw),
            std::slice::from_ref(&hit),
            Some("risc0.semantic.decode.operand_index_routing"),
            true,
        )
        .is_none());
        assert!(validated_control_done_receipt(
            Some(&raw),
            std::slice::from_ref(&hit),
            None,
            false,
        )
        .is_none());

        assert!(validated_control_done_receipt(Some(&raw), &[], None, true).is_none());
        assert!(validated_control_done_receipt(
            Some(&raw),
            &[hit.clone(), hit.clone()],
            None,
            true,
        )
        .is_none());

        let mut wrong_effect = receipt.clone();
        wrong_effect.effect = ExecutedExceptionEffect::DoryShortTraceCapacity;
        let wrong_effect = serde_json::to_string(&wrong_effect).unwrap();
        assert!(validated_control_done_receipt(
            Some(&wrong_effect),
            std::slice::from_ref(&hit),
            None,
            true,
        )
        .is_none());

        let mut wrong_obligation = receipt.clone();
        wrong_obligation.obligation_id = "pd5".to_string();
        let wrong_obligation = serde_json::to_string(&wrong_obligation).unwrap();
        assert!(validated_control_done_receipt(
            Some(&wrong_obligation),
            std::slice::from_ref(&hit),
            None,
            true,
        )
        .is_none());

        let mut wrong_cell = receipt.clone();
        wrong_cell.cell_id = "pd2.exact".to_string();
        let wrong_cell = serde_json::to_string(&wrong_cell).unwrap();
        assert!(validated_control_done_receipt(
            Some(&wrong_cell),
            std::slice::from_ref(&hit),
            None,
            true,
        )
        .is_none());

        let mut wrong_stage = receipt.clone();
        wrong_stage.stage = "risc0.segment.unrelated".to_string();
        let wrong_stage = serde_json::to_string(&wrong_stage).unwrap();
        assert!(validated_control_done_receipt(
            Some(&wrong_stage),
            std::slice::from_ref(&hit),
            None,
            true,
        )
        .is_none());

        let mut wrong_step = receipt.clone();
        wrong_step.step = 2;
        let wrong_step = serde_json::to_string(&wrong_step).unwrap();
        assert!(validated_control_done_receipt(
            Some(&wrong_step),
            std::slice::from_ref(&hit),
            None,
            true,
        )
        .is_none());

        let mut wrong_context = receipt.clone();
        wrong_context.context.insert("required_cycles".to_string(), json!(17));
        let wrong_context = serde_json::to_string(&wrong_context).unwrap();
        assert!(validated_control_done_receipt(
            Some(&wrong_context),
            std::slice::from_ref(&hit),
            None,
            true,
        )
        .is_none());

        for (identity_key, identity_value) in [
            ("backend", json!("sp1")),
            ("commit", json!("0000000000000000000000000000000000000000")),
            ("trace_source", json!("panic_text")),
        ] {
            let mut wrong_identity = receipt.clone();
            wrong_identity.context.insert(identity_key.to_string(), identity_value.clone());
            let wrong_identity_raw = serde_json::to_string(&wrong_identity).unwrap();
            assert!(validated_control_done_receipt(
                Some(&wrong_identity_raw),
                std::slice::from_ref(&hit),
                None,
                true,
            )
            .is_none());

            let mut forged_hit = hit.clone();
            forged_hit.details.insert(identity_key.to_string(), identity_value);
            assert!(validated_control_done_receipt(
                Some(&wrong_identity_raw),
                std::slice::from_ref(&forged_hit),
                None,
                true,
            )
            .is_none());
        }

        let mut missing_identity = receipt.clone();
        missing_identity.context.remove("trace_source");
        let missing_identity = serde_json::to_string(&missing_identity).unwrap();
        assert!(validated_control_done_receipt(
            Some(&missing_identity),
            std::slice::from_ref(&hit),
            None,
            true,
        )
        .is_none());

        let mut wrong_manifestation = control_done_receipt();
        wrong_manifestation.context.insert("actual_trace_cycles".to_string(), json!(18));
        let wrong_manifestation = serde_json::to_string(&wrong_manifestation).unwrap();
        assert!(validated_control_done_receipt(
            Some(&wrong_manifestation),
            std::slice::from_ref(&hit),
            None,
            true,
        )
        .is_none());

        let mut core_only = control_done_hit();
        core_only.details.insert("actual_trace_cycles".to_string(), json!(18));
        let mut manifestation_only = control_done_hit();
        manifestation_only.details.insert("cell_id".to_string(), json!("pd2.exact"));
        let raw = serde_json::to_string(&control_done_receipt()).unwrap();
        assert!(validated_control_done_receipt(
            Some(&raw),
            &[core_only, manifestation_only],
            None,
            true,
        )
        .is_none());
    }

}
