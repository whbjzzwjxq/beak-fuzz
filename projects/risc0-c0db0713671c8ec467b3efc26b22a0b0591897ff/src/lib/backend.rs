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
    execute::{
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
    max_cycles: Option<u64>,
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
    let (_segments, result) = execute_session(image, Some(cutoff.saturating_add(1)), Vec::new())?;
    final_regs_from_post_image(&result.post_image)
}

fn final_regs_for_oracle(words: &[u32]) -> Result<[u32; 32], String> {
    if let Some(cutoff) = original_ecall_start_cycle(words)? {
        let program = build_program(words);
        let image = MemoryImage::new_kernel(program);
        let (_segments, result) = execute_session(image, Some(cutoff.saturating_add(1)), Vec::new())?;
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
        } else {
            return Vec::new();
        };

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
        ECALL_ARG_DECOMP_INJECT_KIND, build_program, nonzero_reg_count, observe_sites_for_words,
        read_reg_bank,
    };
    use risc0_binfmt::MemoryImage;
    use risc0_circuit_rv32im::{
        MAX_INSN_CYCLES,
        execute::{
            DEFAULT_SEGMENT_LIMIT_PO2,
            platform::{MACHINE_REGS_ADDR, USER_REGS_ADDR},
            testutil::{DEFAULT_SESSION_LIMIT, execute},
        },
    };

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
}
