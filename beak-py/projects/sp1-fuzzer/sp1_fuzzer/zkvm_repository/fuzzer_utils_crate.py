from pathlib import Path

from zkvm_fuzzer_utils.file import create_file


def create_cargo_toml(root: Path):
    create_file(
        root / "crates" / "fuzzer_utils" / "Cargo.toml",
        """[package]
name = "fuzzer_utils"
version = "1.0.0"
edition = "2021"

[dependencies]
lazy_static = "1.4"
""",
    )


def create_lib_rs(root: Path):
    create_file(
        root / "crates" / "fuzzer_utils" / "src" / "lib.rs",
        """use std::sync::Mutex;

use lazy_static::lazy_static;

////////////////
// GLOBAL STATE
/////////

#[derive(Debug, Clone)]
pub struct GlobalState {
    pub trace_logging: bool,
    pub injection: bool,
    pub assertions: bool,
    pub seed: u64,

    // "op index" (instruction step) used for micro-op grouping.
    pub step: u64,
    // Per-op micro-op index.
    pub micro_idx: u32,
    // Global row id sequence to guarantee uniqueness even if `step` is reused.
    pub row_seq: u64,

    // Best-effort instruction context (used by bucket workflow for readability/debugging).
    pub pc_hint: u32,
    pub instruction_hint: String,
    pub assembly_hint: String,

    // Fault injection controls (kept for backwards compatibility with existing SP1 fuzzer).
    pub injection_kind: String,
    pub injection_step: u64,
    pub instruction_override: bool,

    pub last_row_id: String,
}

impl GlobalState {
    fn new() -> Self {
        Self {
            trace_logging: false,
            injection: false,
            assertions: true,
            seed: 0,
            step: 0,
            micro_idx: 0,
            row_seq: 0,
            pc_hint: 0,
            instruction_hint: String::new(),
            assembly_hint: String::new(),
            injection_kind: String::new(),
            injection_step: 0,
            instruction_override: false,
            last_row_id: String::new(),
        }
    }
}

lazy_static! {
    static ref GLOBAL_STATE: Mutex<GlobalState> = Mutex::new(GlobalState::new());
}

pub fn is_trace_logging() -> bool {
    GLOBAL_STATE.lock().unwrap().trace_logging
}

pub fn set_trace_logging(value: bool) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.trace_logging = value;
}

pub fn enable_trace_logging() {
    set_trace_logging(true);
}

pub fn disable_trace_logging() {
    set_trace_logging(false);
}

pub fn is_injection() -> bool {
    GLOBAL_STATE.lock().unwrap().injection
}

pub fn set_injection(value: bool) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.injection = value;
}

pub fn enable_injection() {
    set_injection(true);
}

pub fn disable_injection() {
    set_injection(false);
}

pub fn is_assertions() -> bool {
    GLOBAL_STATE.lock().unwrap().assertions
}

pub fn set_assertions(value: bool) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.assertions = value;
}

pub fn enable_assertions() {
    set_assertions(true);
}

pub fn disable_assertions() {
    set_assertions(false);
}

pub fn set_seed(value: u64) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.seed = value;
}

pub fn get_seed() -> u64 {
    GLOBAL_STATE.lock().unwrap().seed
}

pub fn is_injection_kind(value: &str) -> bool {
    GLOBAL_STATE.lock().unwrap().injection_kind == value
}

pub fn set_injection_kind(value: String) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.injection_kind = value;
}

pub fn get_injection_kind() -> String {
    GLOBAL_STATE.lock().unwrap().injection_kind.clone()
}

pub fn get_step() -> u64 {
    GLOBAL_STATE.lock().unwrap().step
}

pub fn get_injection_step() -> u64 {
    GLOBAL_STATE.lock().unwrap().injection_step
}

pub fn set_injection_step(value: u64) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.injection_step = value;
}

pub fn is_instruction_override() -> bool {
    GLOBAL_STATE.lock().unwrap().instruction_override
}

pub fn set_instruction_override(value: bool) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.instruction_override = value;
}

pub fn inc_step() {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.step += 1;
    state.micro_idx = 0;
}

pub fn update_hints(pc: u32, instruction: &str, assembly: &str) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.pc_hint = pc;
    state.instruction_hint = instruction.to_string();
    state.assembly_hint = assembly.to_string();
    state.micro_idx = 0;
}

fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\\\' => out.push_str(\"\\\\\\\\\"),
            '\"' => out.push_str(\"\\\\\\\"\"),
            '\\n' => out.push_str(\"\\\\n\"),
            '\\r' => out.push_str(\"\\\\r\"),
            '\\t' => out.push_str(\"\\\\t\"),
            _ => out.push(c),
        }
    }
    out
}

pub fn print_chip_row_json(domain: &str, chip: &str, gates_json: &str, values_json: &str) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    if !state.trace_logging {
        return;
    }
    let uop_idx = state.micro_idx;
    state.micro_idx = state.micro_idx.wrapping_add(1);
    let seq = state.row_seq;
    state.row_seq = state.row_seq.wrapping_add(1);
    let row_id = format!(\"sp1:{}:{}:{}\", state.step, uop_idx, seq);
    state.last_row_id = row_id.clone();

    let record = format!(
        r#\"{{\"context\":\"micro_op\",\"micro_op_type\":\"chip_row\",\"step\":{},\"pc\":{},\"instruction\":\"{}\",\"assembly\":\"{}\",\"row_id\":\"{}\",\"domain\":\"{}\",\"chip\":\"{}\",\"gates\":{},\"values\":{}}}\"#,
        state.step,
        state.pc_hint,
        escape_json_string(&state.instruction_hint),
        escape_json_string(&state.assembly_hint),
        escape_json_string(&row_id),
        escape_json_string(domain),
        escape_json_string(chip),
        gates_json,
        values_json,
    );
    println!(\"<record>{}</record>\", record);
}

pub fn get_last_row_id() -> String {
    GLOBAL_STATE.lock().unwrap().last_row_id.clone()
}

pub fn print_interaction_json(
    table_id: &str,
    io: &str,
    kind: &str,
    anchor_row_id: &str,
    payload_json: &str,
    multiplicity_value: u64,
    multiplicity_ref: &str,
) {
    let state = GLOBAL_STATE.lock().unwrap();
    if !state.trace_logging {
        return;
    }

    let record = format!(
        r#\"{{\"context\":\"micro_op\",\"micro_op_type\":\"interaction\",\"step\":{},\"pc\":{},\"instruction\":\"{}\",\"assembly\":\"{}\",\"table_id\":\"{}\",\"io\":\"{}\",\"kind\":\"{}\",\"scope\":\"global\",\"anchor_row_id\":\"{}\",\"multiplicity\":{{\"value\":{},\"ref\":\"{}\"}},\"payload\":{}}}\"#,
        state.step,
        state.pc_hint,
        escape_json_string(&state.instruction_hint),
        escape_json_string(&state.assembly_hint),
        escape_json_string(table_id),
        escape_json_string(io),
        escape_json_string(kind),
        escape_json_string(anchor_row_id),
        multiplicity_value,
        escape_json_string(multiplicity_ref),
        payload_json,
    );
    println!(\"<record>{}</record>\", record);
}

////////////////
// CUSTOM ASSERTION MACROS
/////////

#[macro_export]
macro_rules! fuzzer_assert {
    ($cond:expr $(,)?) => {{
        if $crate::is_assertions() {
            assert!($cond);
        } else if !$cond {
            println!(\"Warning: fuzzer_assert! failed: {}\", stringify!($cond));
        }
    }};
    ($cond:expr, $($arg:tt)+) => {{
        if $crate::is_assertions() {
            assert!($cond, $($arg)+);
        } else if !$cond {
            println!(\"Warning: fuzzer_assert! failed: {}\", format_args!($($arg)+));
        }
    }};
}

#[macro_export]
macro_rules! fuzzer_assert_eq {
    ($left:expr, $right:expr $(,)?) => {{
        if $crate::is_assertions() {
            assert_eq!($left, $right);
        } else if $left != $right {
            println!(
                \"Warning: fuzzer_assert_eq! failed: `{} != {}` (left: `{:?}`, right: `{:?}`)\",
                stringify!($left),
                stringify!($right),
                &$left,
                &$right,
            );
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        if $crate::is_assertions() {
            assert_eq!($left, $right, $($arg)+);
        } else if $left != $right {
            println!(
                \"Warning: fuzzer_assert_eq! failed: `{} != {}` (left: `{:?}`, right: `{:?}`): {}\",\n                stringify!($left),
                stringify!($right),
                &$left,
                &$right,
                format_args!($($arg)+),
            );
        }
    }};
}
""",
    )


def create_fuzzer_utils_crate(root: Path):
    create_cargo_toml(root)
    create_lib_rs(root)
