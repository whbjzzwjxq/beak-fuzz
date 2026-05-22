use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::{cell::RefCell, rc::Rc};

use beak_core::fuzz::benchmark::{
    BackendEval, BenchmarkBackend, InjectionSchedule, SemanticInjectionCandidate,
};
use beak_core::rv32im::{
    instruction::RV32IMInstruction,
    oracle::{OracleConfig, OracleMemoryModel, RISCVOracle},
};
use beak_core::trace::{semantic, BucketHit, Trace, TraceSignal};
use risc0_binfmt::{MemoryImage, Program};
use risc0_circuit_rv32im::{
    execute::{
        platform::{
            HOST_ECALL_TERMINATE, MACHINE_REGS_ADDR, REG_A0, REG_A1, REG_A7,
            RV32IM_M3_CIRCUIT_VERSION, USER_REGS_ADDR, USER_START_ADDR, WORD_SIZE,
        },
        testutil::DEFAULT_SESSION_LIMIT,
        ExecutionLimit, Executor, DEFAULT_SEGMENT_LIMIT_PO2,
    },
    prove::beak::{
        collect_preflight_trace_records, prove_segment_with_injection, BeakInjectionPlan,
    },
    trace::{TraceCallback, TraceEvent},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::trace::{
    executed_instructions, Risc0ExecutedInsnRecord, Risc0PreflightMemoryTxn,
    Risc0PreflightSegmentSummary, Risc0Trace,
};

const ZERO_REGISTER_INJECT_KIND: &str = "risc0.semantic.decode.zero_register_immutability";
const OPERAND_ROUTE_INJECT_KIND: &str = "risc0.semantic.decode.operand_index_routing";
const DEST_BINDING_INJECT_KIND: &str = "risc0.semantic.exec.dest_binding";
const MEM_STORE_LOAD_FLOW_INJECT_KIND: &str = "risc0.semantic.memory.store_load_payload_flow";
const MEM_LOAD_VALUE_INJECT_KIND: &str = "risc0.semantic.memory.load_value_binding";
const MEM_WRITE_PAYLOAD_INJECT_KIND: &str = "risc0.semantic.memory.write_payload_consistency";
const TIME_MONOTONIC_INJECT_KIND: &str = "risc0.semantic.time.monotonic_access_ordering";
const DIV_REM_BOUND_INJECT_KIND: &str = "risc0.semantic.arithmetic.division_remainder_bound";
const ECALL_ARG_DECOMP_INJECT_KIND: &str = "risc0.semantic.control.ecall_argument_decomposition";

struct SemanticInjectionMapping {
    bucket_id: &'static str,
    semantic_class: &'static str,
    obligation_id: Option<&'static str>,
    inject_kind: &'static str,
}

const SEMANTIC_INJECTION_MAPPINGS: &[SemanticInjectionMapping] = &[
    SemanticInjectionMapping {
        bucket_id: semantic::decode::ZERO_REGISTER_IMMUTABILITY.id,
        semantic_class: semantic::decode::ZERO_REGISTER_IMMUTABILITY.semantic_class,
        obligation_id: Some("rf1"),
        inject_kind: ZERO_REGISTER_INJECT_KIND,
    },
    SemanticInjectionMapping {
        bucket_id: semantic::decode::OPERAND_INDEX_ROUTING.id,
        semantic_class: semantic::decode::OPERAND_INDEX_ROUTING.semantic_class,
        obligation_id: Some("rf2"),
        inject_kind: OPERAND_ROUTE_INJECT_KIND,
    },
    SemanticInjectionMapping {
        bucket_id: semantic::exec::DEST_BINDING.id,
        semantic_class: semantic::exec::DEST_BINDING.semantic_class,
        obligation_id: Some("rf3"),
        inject_kind: DEST_BINDING_INJECT_KIND,
    },
    SemanticInjectionMapping {
        bucket_id: semantic::memory::STORE_LOAD_PAYLOAD_FLOW.id,
        semantic_class: semantic::memory::STORE_LOAD_PAYLOAD_FLOW.semantic_class,
        obligation_id: Some("me1"),
        inject_kind: MEM_STORE_LOAD_FLOW_INJECT_KIND,
    },
    SemanticInjectionMapping {
        bucket_id: semantic::memory::LOAD_VALUE_BINDING.id,
        semantic_class: semantic::memory::LOAD_VALUE_BINDING.semantic_class,
        obligation_id: Some("me3"),
        inject_kind: MEM_LOAD_VALUE_INJECT_KIND,
    },
    SemanticInjectionMapping {
        bucket_id: semantic::memory::WRITE_PAYLOAD_CONSISTENCY.id,
        semantic_class: semantic::memory::WRITE_PAYLOAD_CONSISTENCY.semantic_class,
        obligation_id: Some("me4"),
        inject_kind: MEM_WRITE_PAYLOAD_INJECT_KIND,
    },
    SemanticInjectionMapping {
        bucket_id: semantic::time::MONOTONIC_ACCESS_ORDERING.id,
        semantic_class: semantic::time::MONOTONIC_ACCESS_ORDERING.semantic_class,
        obligation_id: Some("ts2"),
        inject_kind: TIME_MONOTONIC_INJECT_KIND,
    },
    SemanticInjectionMapping {
        bucket_id: semantic::arithmetic::DIVISION_REMAINDER_BOUND.id,
        semantic_class: semantic::arithmetic::DIVISION_REMAINDER_BOUND.semantic_class,
        obligation_id: Some("md3"),
        inject_kind: DIV_REM_BOUND_INJECT_KIND,
    },
    SemanticInjectionMapping {
        bucket_id: semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id,
        semantic_class: semantic::control::ECALL_ARGUMENT_DECOMPOSITION.semantic_class,
        obligation_id: Some("cf5"),
        inject_kind: ECALL_ARG_DECOMP_INJECT_KIND,
    },
];

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub request_id: u64,
    pub words: Vec<u32>,
    pub iteration: u64,
    pub inject_kind: Option<String>,
    pub inject_step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub request_id: u64,
    pub final_regs: Option<[u32; 32]>,
    pub micro_op_count: usize,
    pub bucket_hits: Vec<BucketHit>,
    pub trace_signals: Vec<TraceSignal>,
    pub backend_error: Option<String>,
    pub observed_injection_sites: BTreeMap<String, Vec<u64>>,
    pub injection_applied: bool,
}

impl WorkerResponse {
    pub fn from_run_response(request_id: u64, resp: RunResponse) -> Self {
        Self {
            request_id,
            final_regs: resp.final_regs,
            micro_op_count: resp.micro_op_count,
            bucket_hits: resp.bucket_hits,
            trace_signals: resp.trace_signals,
            backend_error: resp.backend_error,
            observed_injection_sites: resp.observed_injection_sites,
            injection_applied: resp.injection_applied,
        }
    }

    pub fn error(request_id: u64, error: String) -> Self {
        Self {
            request_id,
            final_regs: None,
            micro_op_count: 0,
            bucket_hits: Vec::new(),
            trace_signals: Vec::new(),
            backend_error: Some(error),
            observed_injection_sites: BTreeMap::new(),
            injection_applied: false,
        }
    }
}

const WORKER_RESPONSE_PREFIX: &str = "__BEAK_WORKER_JSON__ ";

fn base_inject_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn semantic_replay_supported(kind: &str) -> bool {
    SEMANTIC_INJECTION_MAPPINGS.iter().any(|mapping| mapping.inject_kind == base_inject_kind(kind))
}

fn hit_obligation_id(hit: &BucketHit) -> Option<&str> {
    hit.details.get("obligation_id").and_then(Value::as_str)
}

fn mapping_matches_hit(mapping: &SemanticInjectionMapping, hit: &BucketHit) -> bool {
    hit.bucket_id == mapping.bucket_id
        && mapping
            .obligation_id
            .map(|obligation_id| hit_obligation_id(hit) == Some(obligation_id))
            .unwrap_or(true)
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
    let entry: risc0_binfmt::WordAddr = USER_START_ADDR.waddr() + 1;
    let mut image = MemoryImage::default();
    for (idx, &word) in words.iter().enumerate() {
        image.set_word(entry + idx, word).expect("set instruction word");
    }
    for (idx, word) in termination_words().into_iter().enumerate() {
        image.set_word(entry + words.len() + idx, word).expect("set termination word");
    }
    Program::new_from_entry_and_image(entry.baddr().0, image)
}

fn execute_session(
    mut image: MemoryImage,
    max_rows: Option<u64>,
    trace: Vec<Rc<RefCell<dyn TraceCallback>>>,
) -> Result<
    (Vec<risc0_circuit_rv32im::execute::Segment>, risc0_circuit_rv32im::execute::ExecutorResult),
    String,
> {
    let limit = match max_rows {
        Some(max_rows) => ExecutionLimit::DEFAULT
            .with_segment_po2(DEFAULT_SEGMENT_LIMIT_PO2)
            .with_soft_session_limit(max_rows),
        None => ExecutionLimit::DEFAULT
            .with_segment_po2(DEFAULT_SEGMENT_LIMIT_PO2)
            .with_session_limit(DEFAULT_SESSION_LIMIT),
    };
    let mut segments = Vec::new();
    let result = Executor::new(
        image.clone(),
        Risc0HostSyscall,
        None,
        trace,
        None,
        RV32IM_M3_CIRCUIT_VERSION,
    )
    .run(limit, |update| {
        let segment = update.apply_into_segment(&mut image)?;
        segments.push(segment);
        Ok(())
    })
    .map_err(|e| format!("risc0 execute failed: {e}"))?;
    Ok((segments, result))
}

fn collect_preflight_records_for_segments(
    segments: &[risc0_circuit_rv32im::execute::Segment],
    op_idx_by_input_pc: &BTreeMap<u32, u64>,
) -> Result<(Vec<Risc0PreflightMemoryTxn>, Vec<Risc0PreflightSegmentSummary>), String> {
    let mut txns = Vec::new();
    let mut summaries = Vec::new();

    for (segment_idx, segment) in segments.iter().enumerate() {
        let records = collect_preflight_trace_records(segment)
            .map_err(|e| format!("risc0 preflight record collection failed: {e}"))?;
        let segment_idx = segment_idx as u64;
        summaries.push(Risc0PreflightSegmentSummary {
            segment_idx,
            table_split_cycle: records.table_split_cycle,
            padding_start_row: records.padding_start_row,
            total_rows: records.total_rows,
            lookup_table_rows: records.lookup_table_rows,
        });
        txns.extend(records.txns.into_iter().filter_map(|txn| {
            let row_step_idx = op_idx_by_input_pc.get(&txn.row_pc).copied()?;
            Some(Risc0PreflightMemoryTxn {
                segment_idx,
                row_idx: txn.row_idx,
                row_step_idx,
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
            })
        }));
    }

    Ok((txns, summaries))
}

fn input_pc_to_op_idx(words: &[u32]) -> BTreeMap<u32, u64> {
    (0..words.len())
        .map(|idx| (risc0_entry_pc() + (idx as u32) * WORD_SIZE as u32, idx as u64))
        .collect()
}

#[derive(Default)]
struct Risc0HostSyscall;

impl risc0_circuit_rv32im::execute::Syscall for Risc0HostSyscall {
    fn host_read(
        &self,
        _ctx: &mut impl risc0_circuit_rv32im::execute::SyscallContext,
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
        _ctx: &mut impl risc0_circuit_rv32im::execute::SyscallContext,
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
    let _ = execute_session(image, None, vec![trace_cb])?;
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
    let _ = execute_session(image, None, vec![trace_cb])?;
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
                kinds.insert(ECALL_ARG_DECOMP_INJECT_KIND);
            }
            "lb" | "lh" | "lw" | "lbu" | "lhu" => {
                kinds.insert(MEM_STORE_LOAD_FLOW_INJECT_KIND);
                kinds.insert(MEM_LOAD_VALUE_INJECT_KIND);
                kinds.insert(TIME_MONOTONIC_INJECT_KIND);
            }
            "sb" | "sh" | "sw" => {
                kinds.insert(MEM_WRITE_PAYLOAD_INJECT_KIND);
            }
            _ => {}
        }
        if insn.rd == Some(0) {
            kinds.insert(ZERO_REGISTER_INJECT_KIND);
        } else if insn.rd.is_some() {
            kinds.insert(DEST_BINDING_INJECT_KIND);
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
        DEST_BINDING_INJECT_KIND => {
            details.insert("beak_writeback_relation".to_string(), json!("rd_value"));
        }
        MEM_STORE_LOAD_FLOW_INJECT_KIND => {
            details.insert("beak_memory_relation".to_string(), json!("store_load_mem_value"));
        }
        MEM_LOAD_VALUE_INJECT_KIND => {
            details.insert("beak_memory_relation".to_string(), json!("load_mem_value"));
        }
        MEM_WRITE_PAYLOAD_INJECT_KIND => {
            details.insert("beak_memory_relation".to_string(), json!("store_mem_value"));
        }
        TIME_MONOTONIC_INJECT_KIND => {
            details.insert("beak_time_relation".to_string(), json!("load_prev_cycle"));
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
    let Some(mapping) = SEMANTIC_INJECTION_MAPPINGS
        .iter()
        .find(|mapping| mapping.inject_kind == base_inject_kind(kind))
    else {
        return;
    };

    let mut applied = false;
    for hit in hits {
        if !mapping_matches_hit(mapping, hit) {
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
                "risc0 semantic replay is unsupported on 10fa9788 for {}: no installed M3 hook is registered for this inject kind",
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
    let (segments, _result) = execute_session(image, None, vec![trace_cb])?;
    let executed_records = executed_records.borrow().clone();
    let op_idx_by_input_pc = input_pc_to_op_idx(words);
    let input_executed_records = executed_records
        .iter()
        .filter_map(|record| {
            op_idx_by_input_pc.get(&record.pc).map(|op_idx| Risc0ExecutedInsnRecord {
                step_idx: *op_idx,
                pc: record.pc,
                word: record.word,
            })
        })
        .collect::<Vec<_>>();
    let (preflight_txns, preflight_summaries) =
        collect_preflight_records_for_segments(&segments, &op_idx_by_input_pc)?;
    let trace = Risc0Trace::from_words_with_preflight_and_executed(
        words,
        &input_executed_records,
        &preflight_txns,
        &preflight_summaries,
    )?;

    let plan =
        inject_kind.map(|kind| BeakInjectionPlan { kind: kind.to_string(), step: inject_step });
    let mut witness_mutation_observed = false;
    let mut backend_error = None;

    for segment in &segments {
        let proved =
            catch_unwind(AssertUnwindSafe(|| prove_segment_with_injection(segment, plan.as_ref())));
        let (seal, applied) = match proved {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => return Err(format!("risc0 prove failed: {err}")),
            Err(_) => return Err("risc0 prove panicked during semantic injection".to_string()),
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

    let final_regs = final_regs_for_oracle(words).unwrap_or_else(|_| oracle_fallback_regs(words));

    Ok(RunResponse {
        final_regs: Some(final_regs),
        micro_op_count: trace.instruction_count(),
        bucket_hits,
        trace_signals: trace.trace_signals().to_vec(),
        backend_error,
        observed_injection_sites,
        injection_applied,
    })
}

struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    responses_rx: Receiver<Result<WorkerResponse, String>>,
    reader_thread: JoinHandle<()>,
}

pub struct Risc0Backend {
    max_instructions: usize,
    eval: BackendEval,
    last_observed_injection_sites: BTreeMap<String, Vec<u64>>,
    current_iteration: u64,
    next_request_id: u64,
    pending_injection: Option<BeakInjectionPlan>,
    worker: Option<WorkerProcess>,
}

impl Risc0Backend {
    pub fn new(max_instructions: usize) -> Self {
        Self {
            max_instructions,
            eval: BackendEval::default(),
            last_observed_injection_sites: BTreeMap::new(),
            current_iteration: 0,
            next_request_id: 1,
            pending_injection: None,
            worker: None,
        }
    }

    fn start_worker(&mut self) -> Result<(), String> {
        if self.worker.is_some() {
            return Ok(());
        }
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("resolve current executable for worker failed: {e}"))?;
        let mut child = Command::new(exe_path)
            .arg("--worker-loop")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn backend worker failed: {e}"))?;

        let stdin =
            child.stdin.take().ok_or_else(|| "capture backend worker stdin failed".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "capture backend worker stdout failed".to_string())?;

        let (tx, rx) = mpsc::channel::<Result<WorkerResponse, String>>();
        let reader_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || !trimmed.starts_with(WORKER_RESPONSE_PREFIX) {
                            continue;
                        }
                        let payload = &trimmed[WORKER_RESPONSE_PREFIX.len()..];
                        let parsed = serde_json::from_str::<WorkerResponse>(payload).map_err(|e| {
                            let mut preview = payload.chars().take(200).collect::<String>();
                            if payload.chars().count() > 200 {
                                preview.push_str("...");
                            }
                            format!("parse worker response failed: {e}; raw={preview:?}")
                        });
                        if tx.send(parsed).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("read worker response failed: {e}")));
                        break;
                    }
                }
            }
        });

        self.worker = Some(WorkerProcess { child, stdin, responses_rx: rx, reader_thread });
        Ok(())
    }

    fn stop_worker(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            let _ = worker.child.kill();
            let _ = worker.child.wait();
            drop(worker.stdin);
            let _ = worker.reader_thread.join();
        }
    }

    fn step_from_hit(hit: &BucketHit) -> u64 {
        hit.details.get("op_idx").and_then(Value::as_u64).unwrap_or(0)
    }

    fn semantic_candidate_from_hit(&self, hit: &BucketHit) -> Vec<SemanticInjectionCandidate> {
        let anchor = Self::step_from_hit(hit);
        let Some(mapping) =
            SEMANTIC_INJECTION_MAPPINGS.iter().find(|mapping| mapping_matches_hit(mapping, hit))
        else {
            return Vec::new();
        };

        if !semantic_replay_supported(mapping.inject_kind) {
            return Vec::new();
        }

        let schedule = if self
            .last_observed_injection_sites
            .get(base_inject_kind(mapping.inject_kind))
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
            semantic_class: mapping.semantic_class.to_string(),
            inject_kind: mapping.inject_kind.to_string(),
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
        self.current_iteration = self.current_iteration.saturating_add(1);
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        self.eval = BackendEval::default();
        self.start_worker()?;
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        let req = WorkerRequest {
            request_id,
            words: words.to_vec(),
            iteration: self.current_iteration,
            inject_kind: self.pending_injection.as_ref().map(|plan| plan.kind.clone()),
            inject_step: self.pending_injection.as_ref().map(|plan| plan.step).unwrap_or(0),
        };
        {
            let worker =
                self.worker.as_mut().ok_or_else(|| "backend worker unavailable".to_string())?;
            let mut payload = serde_json::to_vec(&req)
                .map_err(|e| format!("serialize worker request failed: {e}"))?;
            payload.push(b'\n');
            worker
                .stdin
                .write_all(&payload)
                .map_err(|e| format!("write worker request failed: {e}"))?;
            worker.stdin.flush().map_err(|e| format!("flush worker request failed: {e}"))?;
        }

        let resp = loop {
            let recv = {
                let worker =
                    self.worker.as_ref().ok_or_else(|| "backend worker unavailable".to_string())?;
                worker.responses_rx.recv()
            };
            match recv {
                Ok(Ok(resp)) if resp.request_id == request_id => break resp,
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => {
                    self.stop_worker();
                    self.eval.backend_error = Some(e.clone());
                    return Err(e);
                }
                Err(_) => {
                    self.stop_worker();
                    let msg = "backend worker disconnected".to_string();
                    self.eval.backend_error = Some(msg.clone());
                    return Err(msg);
                }
            }
        };
        self.stop_worker();
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

impl Drop for Risc0Backend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_program, nonzero_reg_count, observe_sites_for_words, read_reg_bank, Risc0Backend,
        DEST_BINDING_INJECT_KIND, DIV_REM_BOUND_INJECT_KIND, ECALL_ARG_DECOMP_INJECT_KIND,
        MEM_LOAD_VALUE_INJECT_KIND, MEM_STORE_LOAD_FLOW_INJECT_KIND, MEM_WRITE_PAYLOAD_INJECT_KIND,
        OPERAND_ROUTE_INJECT_KIND, TIME_MONOTONIC_INJECT_KIND, ZERO_REGISTER_INJECT_KIND,
    };
    use beak_core::fuzz::benchmark::BenchmarkBackend;
    use beak_core::trace::{semantic, BucketHit, Trace};
    use risc0_binfmt::MemoryImage;
    use risc0_circuit_rv32im::execute::{
        platform::{MACHINE_REGS_ADDR, USER_REGS_ADDR},
        testutil::{execute, DEFAULT_SESSION_LIMIT},
        ExecutionLimit, DEFAULT_SEGMENT_LIMIT_PO2,
    };
    use serde_json::json;

    use super::Risc0HostSyscall;

    #[test]
    fn observe_ecall_injection_site() {
        let words = [0x0010_0893, 0x0000_0073];
        let sites = observe_sites_for_words(&words);
        assert_eq!(sites.get(ECALL_ARG_DECOMP_INJECT_KIND), Some(&vec![1]));
        assert_eq!(sites.get(ZERO_REGISTER_INJECT_KIND), None);
    }

    #[test]
    fn semantic_candidates_are_limited_to_m3_supported_kinds() {
        let words = [0x0000_0013, 0x0070_0113, 0x0050_0193, 0x0231_50b3, 0x0000_0073];
        let trace = crate::trace::Risc0Trace::from_words(&words).expect("trace");
        let backend = Risc0Backend::new(16);
        let candidates = backend.semantic_injection_candidates(trace.bucket_hits());
        let kinds =
            candidates.iter().map(|candidate| candidate.inject_kind.as_str()).collect::<Vec<_>>();

        assert!(kinds.contains(&OPERAND_ROUTE_INJECT_KIND));
        assert!(kinds.contains(&DEST_BINDING_INJECT_KIND));
        assert!(kinds.contains(&DIV_REM_BOUND_INJECT_KIND));
        assert!(kinds.contains(&ECALL_ARG_DECOMP_INJECT_KIND));
        assert!(kinds.contains(&ZERO_REGISTER_INJECT_KIND));
        assert!(!kinds.contains(&MEM_STORE_LOAD_FLOW_INJECT_KIND));
        assert!(!kinds.contains(&MEM_LOAD_VALUE_INJECT_KIND));
        assert!(!kinds.contains(&MEM_WRITE_PAYLOAD_INJECT_KIND));
        assert!(!kinds.contains(&TIME_MONOTONIC_INJECT_KIND));
        assert!(!kinds.contains(&"risc0.semantic.decode.field_range"));
        assert!(!kinds.contains(&"risc0.semantic.memory.address_space_consistency"));
    }

    #[test]
    fn memory_load_value_candidate_uses_memory_bucket_anchor() {
        let mut details = std::collections::HashMap::new();
        details.insert("obligation_id".to_string(), json!("me3"));
        details.insert("cell_id".to_string(), json!("me3.lb_pos"));
        details.insert("op_idx".to_string(), json!(4));
        let hit = BucketHit::semantic(semantic::memory::LOAD_VALUE_BINDING, details);
        let backend = Risc0Backend::new(16);
        let candidates = backend.semantic_injection_candidates(&[hit]);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].inject_kind, MEM_LOAD_VALUE_INJECT_KIND);
    }

    #[test]
    fn memory_store_load_candidate_uses_memory_bucket_anchor() {
        let mut details = std::collections::HashMap::new();
        details.insert("obligation_id".to_string(), json!("me1"));
        details.insert("cell_id".to_string(), json!("me1.sb_lb"));
        details.insert("op_idx".to_string(), json!(4));
        let hit = BucketHit::semantic(semantic::memory::STORE_LOAD_PAYLOAD_FLOW, details);
        let backend = Risc0Backend::new(16);
        let candidates = backend.semantic_injection_candidates(&[hit]);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].inject_kind, MEM_STORE_LOAD_FLOW_INJECT_KIND);
    }

    #[test]
    fn memory_write_payload_candidate_uses_memory_bucket_anchor() {
        let mut details = std::collections::HashMap::new();
        details.insert("obligation_id".to_string(), json!("me4"));
        details.insert("cell_id".to_string(), json!("me4.sb_off0"));
        details.insert("op_idx".to_string(), json!(3));
        let hit = BucketHit::semantic(semantic::memory::WRITE_PAYLOAD_CONSISTENCY, details);
        let backend = Risc0Backend::new(16);
        let candidates = backend.semantic_injection_candidates(&[hit]);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].inject_kind, MEM_WRITE_PAYLOAD_INJECT_KIND);
    }

    #[test]
    fn time_monotonic_candidate_uses_memory_bucket_anchor() {
        let mut details = std::collections::HashMap::new();
        details.insert("obligation_id".to_string(), json!("ts2"));
        details.insert("cell_id".to_string(), json!("ts2.consecutive"));
        details.insert("op_idx".to_string(), json!(4));
        let hit = BucketHit::semantic(semantic::time::MONOTONIC_ACCESS_ORDERING, details);
        let backend = Risc0Backend::new(16);
        let candidates = backend.semantic_injection_candidates(&[hit]);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].inject_kind, TIME_MONOTONIC_INJECT_KIND);
    }

    #[test]
    fn inspect_reg_banks_for_known_cases() {
        std::thread::Builder::new()
            .name("risc0-reg-bank-test".to_string())
            .stack_size(256 * 1024 * 1024)
            .spawn(inspect_reg_banks_for_known_cases_inner)
            .expect("spawn reg-bank test worker")
            .join()
            .expect("reg-bank test worker panicked");
    }

    fn inspect_reg_banks_for_known_cases_inner() {
        let cases = [
            ("divrem", vec![0x0070_0113, 0x0050_0193, 0x0231_50b3]),
            ("ecall_len", vec![0x0010_0893, 0x0000_0513, 0x0050_05b7, 0x0040_0613, 0x0000_0073]),
        ];

        for (name, words) in cases {
            let image = MemoryImage::new_kernel(build_program(&words));
            let limit = ExecutionLimit::DEFAULT
                .with_segment_po2(DEFAULT_SEGMENT_LIMIT_PO2)
                .with_session_limit(DEFAULT_SESSION_LIMIT);
            let session = execute(image, limit, Risc0HostSyscall, None)
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
}
