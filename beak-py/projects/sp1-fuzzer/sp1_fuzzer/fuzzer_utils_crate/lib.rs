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
    pub witness_step_idx: u64,
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
            witness_step_idx: 0,
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
    let cur = g.witness_step_idx;
    g.witness_step_idx = g.witness_step_idx.saturating_add(1);
    cur
}

pub fn should_inject_witness(kind: &str, step: u64) -> bool {
    let g = GLOBAL_STATE.lock().unwrap();
    g.injection_enabled && g.injection_kind == kind && g.injection_step == step
}

pub fn configure_witness_injection(kind: Option<&str>, step: u64) {
    let mut g = GLOBAL_STATE.lock().unwrap();
    match kind {
        Some(k) if !k.is_empty() => {
            g.injection_enabled = true;
            g.injection_kind = k.to_string();
            g.injection_step = step;
        }
        _ => {
            g.injection_enabled = false;
            g.injection_kind.clear();
            g.injection_step = 0;
        }
    }
    g.witness_step_idx = 0;
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
