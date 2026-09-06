use lazy_static::lazy_static;
use serde_json::{json, Value};
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct GlobalState {
    pub seq: u64,
    pub step_idx: u64,
    pub did_emit_instruction: bool,
    pub op_idx_in_step: u64,
    pub chip_row_op_idx_in_step: u64,
    pub row_count: u64,
    pub last_row_id: Option<String>,
    pub emitted_micro_ops: Vec<Value>,
    pub injection_enabled: bool,
    pub injection_kind: String,
    pub injection_step: u64,
    pub injection_applied: bool,
    pub semantic_mutation_receipt: Option<Value>,
    pub witness_step_idx: u64,
    pub memory_selector_step_idx: u64,
    pub executor_step_idx: u64,
    pub injection_run_id: String,
}

impl GlobalState {
    fn new() -> Self {
        let injection_kind = std::env::var("BEAK_SP1_WITNESS_INJECT_KIND").unwrap_or_default();
        let injection_step = std::env::var("BEAK_SP1_WITNESS_INJECT_STEP")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        Self {
            seq: 0,
            step_idx: 0,
            did_emit_instruction: false,
            op_idx_in_step: 0,
            chip_row_op_idx_in_step: 0,
            row_count: 0,
            last_row_id: None,
            emitted_micro_ops: Vec::new(),
            injection_enabled: !injection_kind.is_empty(),
            injection_kind,
            injection_step,
            injection_applied: false,
            semantic_mutation_receipt: None,
            witness_step_idx: 0,
            memory_selector_step_idx: 0,
            executor_step_idx: 0,
            injection_run_id: std::env::var("BEAK_SP1_WITNESS_RUN_ID").unwrap_or_default(),
        }
    }

    fn sync_injection_from_env(&mut self) {
        let env_kind = std::env::var("BEAK_SP1_WITNESS_INJECT_KIND").unwrap_or_default();
        let env_step = std::env::var("BEAK_SP1_WITNESS_INJECT_STEP")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let env_run_id = std::env::var("BEAK_SP1_WITNESS_RUN_ID").unwrap_or_default();

        if self.injection_kind != env_kind
            || self.injection_step != env_step
            || self.injection_run_id != env_run_id
        {
            self.injection_enabled = !env_kind.is_empty();
            self.injection_kind = env_kind;
            self.injection_step = env_step;
            self.injection_run_id = env_run_id;
            self.injection_applied = false;
            self.semantic_mutation_receipt = None;
            self.witness_step_idx = 0;
            self.memory_selector_step_idx = 0;
            self.executor_step_idx = 0;
        }
    }

    fn emit_micro_op(&mut self, v: Value) {
        self.emitted_micro_ops.push(v);
        self.seq = self.seq.saturating_add(1);
    }

    fn inc_step(&mut self) {
        if self.did_emit_instruction {
            self.step_idx = self.step_idx.saturating_add(1);
        } else {
            self.did_emit_instruction = true;
        }
        self.op_idx_in_step = 0;
        self.chip_row_op_idx_in_step = 0;
        self.last_row_id = None;
    }

    fn take_json_logs(&mut self) -> Vec<Value> {
        let out = std::mem::take(&mut self.emitted_micro_ops);
        self.seq = 0;
        self.step_idx = 0;
        self.did_emit_instruction = false;
        self.op_idx_in_step = 0;
        self.chip_row_op_idx_in_step = 0;
        self.row_count = 0;
        self.last_row_id = None;
        self.witness_step_idx = 0;
        self.memory_selector_step_idx = 0;
        self.executor_step_idx = 0;
        out
    }
}

lazy_static! {
    static ref GLOBAL_STATE: Mutex<GlobalState> = Mutex::new(GlobalState::new());
}

pub fn take_json_logs() -> Vec<Value> {
    GLOBAL_STATE.lock().unwrap().take_json_logs()
}

pub fn next_witness_step() -> u64 {
    let mut g = GLOBAL_STATE.lock().unwrap();
    g.sync_injection_from_env();
    let cur = g.witness_step_idx;
    g.witness_step_idx = g.witness_step_idx.saturating_add(1);
    cur
}

/// Stable executed-CPU-row identity for the strict memory-selector relation.
///
/// The general witness counter is shared by two CPU-row hooks, so its values are
/// interleaved.  This counter advances exactly once per CPU row and therefore
/// agrees with the baseline trace's `op_idx` without depending on other hooks.
pub fn next_memory_selector_step() -> u64 {
    let mut g = GLOBAL_STATE.lock().unwrap();
    g.sync_injection_from_env();
    let cur = g.memory_selector_step_idx;
    g.memory_selector_step_idx = g.memory_selector_step_idx.saturating_add(1);
    cur
}

pub fn next_executor_step() -> u64 {
    let mut g = GLOBAL_STATE.lock().unwrap();
    g.sync_injection_from_env();
    let cur = g.executor_step_idx;
    g.executor_step_idx = g.executor_step_idx.saturating_add(1);
    cur
}

pub fn should_inject_witness(kind: &str, step: u64) -> bool {
    let mut g = GLOBAL_STATE.lock().unwrap();
    g.sync_injection_from_env();
    let should_inject = g.injection_enabled && g.injection_kind == kind && g.injection_step == step;
    if should_inject {
        g.injection_applied = true;
    }
    should_inject
}

fn base_injection_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

pub fn matching_injection_kind(base_kind: &str, step: u64) -> Option<String> {
    let mut g = GLOBAL_STATE.lock().unwrap();
    g.sync_injection_from_env();
    if !g.injection_enabled || g.injection_step != step {
        return None;
    }
    if base_injection_kind(g.injection_kind.as_str()) == base_kind {
        g.injection_applied = true;
        Some(g.injection_kind.clone())
    } else {
        None
    }
}

pub fn injection_variant_value<'a>(kind: &'a str, key: &str) -> Option<&'a str> {
    let (_, variant) = kind.split_once("::")?;
    for field in variant.split(',') {
        let (field_key, field_value) = field.split_once('=')?;
        if field_key == key {
            return Some(field_value);
        }
    }
    None
}

pub fn injection_was_applied() -> bool {
    let mut g = GLOBAL_STATE.lock().unwrap();
    g.sync_injection_from_env();
    g.injection_applied
}

/// Record typed evidence at the concrete witness/executor field mutation.
///
/// The first changed receipt in a scoped run wins.  Unchanged writes and non-object
/// contexts are deliberately ignored so a no-op or malformed hook cannot manufacture
/// classifier evidence.
pub fn record_semantic_mutation_receipt(
    inject_kind: &str,
    site: &str,
    field: &str,
    step: u64,
    before: Value,
    after: Value,
    relation: &str,
    context: Value,
) -> bool {
    if before == after || !context.is_object() {
        return false;
    }
    let mut g = GLOBAL_STATE.lock().unwrap();
    g.sync_injection_from_env();
    if !g.injection_enabled
        || g.injection_kind != inject_kind
        || g.injection_step != step
        || g.semantic_mutation_receipt.is_some()
    {
        return false;
    }
    g.semantic_mutation_receipt = Some(json!({
        "inject_kind": inject_kind,
        "site": site,
        "field": field,
        "step": step,
        "before": before,
        "after": after,
        "effect": {
            "relation": relation,
            "context": context,
        },
    }));
    true
}

pub fn take_semantic_mutation_receipt() -> Option<Value> {
    let mut g = GLOBAL_STATE.lock().unwrap();
    g.sync_injection_from_env();
    g.semantic_mutation_receipt.take()
}

pub fn record_memory_selector_receipt(
    inject_kind: &str,
    step: u64,
    op_idx: u64,
    pc: u32,
    rv_instruction: u32,
    sp1_opcode: u32,
    mnemonic: &str,
    commit: &str,
    expected_is_memory: bool,
    selector_before: u32,
    selector_after: u32,
) -> bool {
    let rv_opcode = rv_instruction & 0x7f;
    let (cell_id, expected_sp1_opcode) = match (rv_opcode, mnemonic) {
        (0x03, "lb") => ("me10.load", 10),
        (0x03, "lh") => ("me10.load", 11),
        (0x03, "lw") => ("me10.load", 12),
        (0x03, "lbu") => ("me10.load", 13),
        (0x03, "lhu") => ("me10.load", 14),
        (0x23, "sb") => ("me10.store", 15),
        (0x23, "sh") => ("me10.store", 16),
        (0x23, "sw") => ("me10.store", 17),
        _ => return false,
    };
    let expected_selector = u32::from(expected_is_memory);
    if inject_kind != "sp1.semantic.exec.memory_effect_binding"
        || sp1_opcode != expected_sp1_opcode
        || !expected_is_memory
        || selector_before != expected_selector
        || selector_after != 0
    {
        return false;
    }
    record_semantic_mutation_receipt(
        inject_kind,
        "cpu_chip.generate_trace",
        "is_memory",
        step,
        json!(selector_before),
        json!(selector_after),
        "memory_selector_equation",
        json!({
            "bucket_id": "sem.exec.memory_effect_binding",
            "obligation_id": "me10",
            "cell_id": cell_id,
            "backend": "sp1",
            "commit": commit,
            "trace_source": "instruction",
            "anchor": step,
            "step": step,
            "op_idx": op_idx,
            "pc": pc,
            "opcode": rv_instruction,
            "sp1_opcode": sp1_opcode,
            "source_selector": sp1_opcode,
            "mnemonic": mnemonic,
            "expected_is_memory": expected_selector,
            "selector_before": selector_before,
            "selector_after": selector_after,
            "executed_cpu_row": true,
        }),
    )
}

pub fn record_executed_control_flow_receipt(
    inject_kind: &str,
    step: u64,
    op_idx: u64,
    pc: u32,
    rv_instruction: u32,
    sp1_opcode: u32,
    mnemonic: &str,
    commit: &str,
    expected_next_pc: u32,
    observed_before: u32,
    observed_after: u32,
    ecall_registers: [u32; 4],
) -> bool {
    let family = injection_variant_value(inject_kind, "family");
    let mode = injection_variant_value(inject_kind, "mode");
    if base_injection_kind(inject_kind) != "sp1.semantic.exec.control_flow_binding"
        || family != Some("ecall")
        || !matches!(mode, Some("near_jump" | "mid_jump" | "legacy_far_jump"))
        || rv_instruction != 0x0000_0073
        || sp1_opcode != 28
        || mnemonic != "ecall"
        || expected_next_pc != pc.wrapping_add(4)
        || observed_before != expected_next_pc
        || observed_after == observed_before
    {
        return false;
    }
    record_semantic_mutation_receipt(
        inject_kind,
        "executor.execute_instruction",
        "next_pc",
        step,
        json!(observed_before),
        json!(observed_after),
        "executed_control_flow_equation",
        json!({
            "bucket_id": "sem.exec.control_flow_binding",
            "obligation_id": "cf6",
            "cell_id": "cf6.normal",
            "backend": "sp1",
            "commit": commit,
            "trace_source": "instruction",
            "anchor": step,
            "step": step,
            "op_idx": op_idx,
            "pc": pc,
            "opcode": rv_instruction,
            "sp1_opcode": sp1_opcode,
            "source_selector": sp1_opcode,
            "mnemonic": mnemonic,
            "control_flow_family": "ecall",
            "family": family,
            "mode": mode,
            "expected_next_pc": expected_next_pc,
            "observed_next_pc_before": observed_before,
            "observed_next_pc_after": observed_after,
            "ecall_x5": ecall_registers[0],
            "ecall_x10": ecall_registers[1],
            "ecall_x11": ecall_registers[2],
            "ecall_x12": ecall_registers[3],
            "executed_instruction": true,
        }),
    )
}

#[cfg(test)]
mod relation_receipt_tests {
    use super::{
        configure_witness_injection, record_executed_control_flow_receipt,
        next_memory_selector_step, record_memory_selector_receipt,
        take_semantic_mutation_receipt,
    };

    #[test]
    fn typed_relation_receipts_bind_source_context_and_fail_closed() {
        let memory_kind = "sp1.semantic.exec.memory_effect_binding";
        std::env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", memory_kind);
        std::env::set_var("BEAK_SP1_WITNESS_INJECT_STEP", "3");
        std::env::set_var("BEAK_SP1_WITNESS_RUN_ID", "memory-receipt-test");
        configure_witness_injection(Some(memory_kind), 3);
        assert_eq!(next_memory_selector_step(), 0);
        assert_eq!(next_memory_selector_step(), 1);
        configure_witness_injection(Some(memory_kind), 3);
        assert_eq!(next_memory_selector_step(), 0);
        assert!(record_memory_selector_receipt(
            memory_kind,
            3,
            3,
            0x0020_0400,
            0x0001_2183,
            12,
            "lw",
            "39ab52fce38172c9d23feed7248198dc14c164a9",
            true,
            1,
            0,
        ));
        let memory = take_semantic_mutation_receipt().expect("memory selector receipt");
        let context = memory["effect"]["context"].as_object().expect("memory context");
        assert_eq!(context["bucket_id"], "sem.exec.memory_effect_binding");
        assert_eq!(context["anchor"], 3);
        assert_eq!(context["sp1_opcode"], 12);

        configure_witness_injection(Some(memory_kind), 3);
        assert!(!record_memory_selector_receipt(
            memory_kind,
            3,
            3,
            0x0020_0400,
            0x0001_2183,
            17,
            "lw",
            "39ab52fce38172c9d23feed7248198dc14c164a9",
            true,
            1,
            0,
        ));
        assert!(take_semantic_mutation_receipt().is_none());

        configure_witness_injection(Some(memory_kind), 3);
        assert!(!record_memory_selector_receipt(
            memory_kind,
            3,
            3,
            0x0020_0400,
            0x0001_2183,
            12,
            "lw",
            "39ab52fce38172c9d23feed7248198dc14c164a9",
            true,
            1,
            2,
        ));
        assert!(take_semantic_mutation_receipt().is_none());

        let control_kind =
            "sp1.semantic.exec.control_flow_binding::family=ecall,mode=near_jump";
        std::env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", control_kind);
        std::env::set_var("BEAK_SP1_WITNESS_INJECT_STEP", "9");
        std::env::set_var("BEAK_SP1_WITNESS_RUN_ID", "control-receipt-test");
        configure_witness_injection(Some(control_kind), 9);
        assert!(record_executed_control_flow_receipt(
            control_kind,
            9,
            9,
            16,
            0x0000_0073,
            28,
            "ecall",
            "7f643da16813af4c0fbaad4837cd7409386cf38c",
            20,
            20,
            24,
            [2, 3, 4096, 4],
        ));
        let control = take_semantic_mutation_receipt().expect("control-flow receipt");
        let context = control["effect"]["context"].as_object().expect("control context");
        assert_eq!(context["bucket_id"], "sem.exec.control_flow_binding");
        assert_eq!(context["anchor"], 9);
        assert_eq!(context["family"], "ecall");
        assert_eq!(context["mode"], "near_jump");

        let wrong_family =
            "sp1.semantic.exec.control_flow_binding::family=branch,mode=near_jump";
        std::env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", wrong_family);
        std::env::set_var("BEAK_SP1_WITNESS_RUN_ID", "wrong-family-receipt-test");
        configure_witness_injection(Some(wrong_family), 9);
        assert!(!record_executed_control_flow_receipt(
            wrong_family,
            9,
            9,
            16,
            0x0000_0073,
            28,
            "ecall",
            "7f643da16813af4c0fbaad4837cd7409386cf38c",
            20,
            20,
            24,
            [2, 3, 4096, 4],
        ));
        assert!(take_semantic_mutation_receipt().is_none());

        let noop_kind =
            "sp1.semantic.exec.control_flow_binding::family=ecall,mode=noop_prefix,rank=0";
        std::env::set_var("BEAK_SP1_WITNESS_INJECT_KIND", noop_kind);
        std::env::set_var("BEAK_SP1_WITNESS_RUN_ID", "noop-receipt-test");
        configure_witness_injection(Some(noop_kind), 9);
        assert!(!record_executed_control_flow_receipt(
            noop_kind,
            9,
            9,
            16,
            0x0000_0073,
            28,
            "ecall",
            "7f643da16813af4c0fbaad4837cd7409386cf38c",
            20,
            20,
            20,
            [2, 3, 4096, 4],
        ));
        assert!(take_semantic_mutation_receipt().is_none());

        std::env::remove_var("BEAK_SP1_WITNESS_INJECT_KIND");
        std::env::remove_var("BEAK_SP1_WITNESS_INJECT_STEP");
        std::env::remove_var("BEAK_SP1_WITNESS_RUN_ID");
        configure_witness_injection(None, 0);
    }
}

pub fn configure_witness_injection(kind: Option<&str>, step: u64) {
    let mut g = GLOBAL_STATE.lock().unwrap();
    match kind {
        Some(k) if !k.is_empty() => {
            g.injection_enabled = true;
            g.injection_kind = k.to_string();
            g.injection_step = step;
            g.injection_applied = false;
            g.semantic_mutation_receipt = None;
        }
        _ => {
            g.injection_enabled = false;
            g.injection_kind.clear();
            g.injection_step = 0;
            g.injection_applied = false;
            g.semantic_mutation_receipt = None;
        }
    }
    g.witness_step_idx = 0;
    g.memory_selector_step_idx = 0;
    g.executor_step_idx = 0;
    g.injection_run_id = std::env::var("BEAK_SP1_WITNESS_RUN_ID").unwrap_or_default();
}

pub fn emit_instruction(
    pc: u32,
    timestamp: u32,
    next_pc: u32,
    next_timestamp: u32,
    opcode: u32,
    operands: [u32; 7],
) {
    let mut g = GLOBAL_STATE.lock().unwrap();
    g.inc_step();
    let seq = g.seq;
    let step_idx = g.step_idx;
    g.emit_micro_op(json!({
        "type": "instruction",
        "data": {
            "seq": seq,
            "step_idx": step_idx,
            "pc": pc,
            "timestamp": timestamp,
            "next_pc": next_pc,
            "next_timestamp": next_timestamp,
            "opcode": opcode,
            "operands": operands,
        }
    }));
}

fn emit_chip_row(kind: &str, payload: Value) {
    let mut g = GLOBAL_STATE.lock().unwrap();
    let row_id = format!("step{}_row{}", g.step_idx, g.row_count);
    let seq = g.seq;
    let step_idx = g.step_idx;
    let op_idx = g.chip_row_op_idx_in_step;
    g.row_count = g.row_count.saturating_add(1);
    g.last_row_id = Some(row_id);
    g.emit_micro_op(json!({
        "type": "chip_row",
        "data": {
            "base": {
                "seq": seq,
                "step_idx": step_idx,
                "op_idx": op_idx,
                "is_valid": true
            },
            "kind": kind,
            "payload": payload
        }
    }));
    g.chip_row_op_idx_in_step = g.chip_row_op_idx_in_step.saturating_add(1);
}

fn emit_interaction(kind: &str, direction: &str, row_id: Option<&str>, payload: Value) {
    if direction != "send" && direction != "receive" {
        return;
    }
    let mut g = GLOBAL_STATE.lock().unwrap();
    let rid = row_id
        .map(|s| s.to_string())
        .or_else(|| g.last_row_id.clone())
        .unwrap_or_default();
    let seq = g.seq;
    let step_idx = g.step_idx;
    let op_idx = g.op_idx_in_step;
    g.emit_micro_op(json!({
        "type": "interaction",
        "data": {
            "base": {
                "seq": seq,
                "step_idx": step_idx,
                "op_idx": op_idx,
                "row_id": rid,
                "direction": direction,
                "kind": kind
            },
            "payload": payload
        }
    }));
    g.op_idx_in_step = g.op_idx_in_step.saturating_add(1);
}

pub fn emit_cpu_chip_row(
    clk: u32,
    pc: u32,
    next_pc: u32,
    opcode: u32,
    a: u32,
    b: u32,
    c: u32,
    memory_store_value: Option<u32>,
) {
    emit_chip_row(
        "cpu",
        json!({
            "type": "sp1_cpu",
            "data": {
                "clk": clk,
                "pc": pc,
                "next_pc": next_pc,
                "opcode": opcode,
                "a": a,
                "b": b,
                "c": c,
                "memory_store_value": memory_store_value,
            }
        }),
    );
}

pub fn emit_alu_chip_row(clk: u32, opcode: u32, a: u32, b: u32, c: u32) {
    emit_chip_row(
        "alu",
        json!({
            "type": "sp1_alu",
            "data": {
                "clk": clk,
                "opcode": opcode,
                "a": a,
                "b": b,
                "c": c,
            }
        }),
    );
}

pub fn emit_memory_interaction(
    direction: &str,
    addr: u32,
    value: u32,
    timestamp: u32,
    is_write: bool,
) {
    emit_interaction(
        "memory",
        direction,
        None,
        json!({
            "type": "sp1_memory",
            "data": {
                "addr": addr,
                "value": value,
                "timestamp": timestamp,
                "is_write": is_write
            }
        }),
    );
}

pub fn emit_program_interaction(
    direction: &str,
    row_id: Option<&str>,
    pc: u32,
    opcode: u32,
    operands: [u32; 7],
) {
    emit_interaction(
        "program",
        direction,
        row_id,
        json!({
            "type": "sp1_program",
            "data": {
                "pc": pc,
                "opcode": opcode,
                "operands": operands
            }
        }),
    );
}

pub fn emit_execution_interaction(direction: &str, row_id: Option<&str>, pc: u32, timestamp: u32) {
    emit_interaction(
        "execution",
        direction,
        row_id,
        json!({
            "type": "sp1_execution",
            "data": {
                "pc": pc,
                "timestamp": timestamp
            }
        }),
    );
}

#[macro_export]
macro_rules! fuzzer_assert {
    ($cond:expr) => {{
        if !$cond {
            eprintln!("[fuzzer_assert] condition failed: {}", stringify!($cond));
        }
    }};
    ($cond:expr, $($arg:tt)+) => {{
        if !$cond {
            eprintln!("[fuzzer_assert] {}", format!($($arg)+));
        }
    }};
}

#[macro_export]
macro_rules! fuzzer_assert_eq {
    ($left:expr, $right:expr $(,)?) => {{
        if $left != $right {
            eprintln!(
                "[fuzzer_assert_eq] left != right (left={:?}, right={:?})",
                &$left,
                &$right
            );
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        if $left != $right {
            eprintln!("[fuzzer_assert_eq] {}", format!($($arg)+));
        }
    }};
}

#[macro_export]
macro_rules! fuzzer_assert_ne {
    ($left:expr, $right:expr $(,)?) => {{
        if $left == $right {
            eprintln!("[fuzzer_assert_ne] left == right (value={:?})", &$left);
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        if $left == $right {
            eprintln!("[fuzzer_assert_ne] {}", format!($($arg)+));
        }
    }};
}
