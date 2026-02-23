use lazy_static::lazy_static;
use openvm_stark_backend::p3_field::{Field, PrimeField32};
use serde_json::json;
use serde_json::{Map, Value};
use std::sync::Mutex;

use rand::rngs::StdRng;
use rand::seq::IndexedRandom;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

use openvm_rv32im_transpiler::{
    BaseAluOpcode,
    BranchEqualOpcode,
    BranchLessThanOpcode,
    DivRemOpcode,
    LessThanOpcode,
    MulHOpcode,
    MulOpcode,
    Rv32AuipcOpcode,
    Rv32HintStoreOpcode,
    // Rv32Phantom,
    Rv32JalLuiOpcode,
    Rv32JalrOpcode,
    Rv32LoadStoreOpcode,
    ShiftOpcode,
};

use openvm_instructions::{
    instruction::Instruction, LocalOpcode, PublishOpcode, SystemOpcode, VmOpcode,
};

// -----------------------------------------------------------------------------
// Row shape constants
// -----------------------------------------------------------------------------
//
// These are used by the micro-op JSON schema (loop1) so that core-side emitters
// can pass limbs as fixed-size arrays at call sites.
pub const NUM_LIMBS: usize = 4;
pub const LIMB_BITS: usize = 8;

////////////////
// GLOBAL STATE
/////////

#[derive(Debug, Clone)]
pub struct GlobalState {
    //////////////////////////////////////////////////////////////////////////////
    /// The state for the micro-operation emission (loop1).
    /// The number of times the zkvm has emitted a micro-operation: insn/chip_row/interaction.
    pub seq: u64,

    /// The number of times the zkvm has executed an insn.
    pub step_idx: u64,

    /// Interaction index within the current step (0..N-1).
    pub op_idx_in_step: u64,

    /// Chip-row index within the current step (0..N-1).
    pub chip_row_op_idx_in_step: u64,

    /// The number of times the zkvm has emitted a chip row.
    pub row_count: u64,

    /// Anchor id of the most recently emitted chip row.
    /// Interactions can reference this to tie back to a chip row.
    pub last_row_id: Option<String>,

    /// Stored emitted micro-operations.
    pub emitted_micro_ops: Vec<serde_json::Value>,

    //////////////////////////////////////////////////////////////////////////////
    /// TODO: Implement the state for the fault injection (loop2).
    pub injection_enabled: bool,
    pub injection_kind: String,
    pub injection_step: u64,
    pub assertions_enabled: bool,

    pub rng: StdRng,
    pub seed: u64,
    //////////////////////////////////////////////////////////////////////////////
}

impl GlobalState {
    fn new() -> Self {
        // Default state so that proc-macro (e.g. derive) can call fuzzer_assert! without
        // panicking when GLOBAL_STATE is first accessed.
        Self {
            seq: 0,
            step_idx: 0,
            op_idx_in_step: 0,
            chip_row_op_idx_in_step: 0,
            row_count: 0,
            last_row_id: None,
            emitted_micro_ops: Vec::new(),
            injection_enabled: false,
            injection_kind: String::new(),
            injection_step: 0,
            assertions_enabled: false,
            rng: StdRng::seed_from_u64(0),
            seed: 0,
        }
    }

    fn emit_micro_op(&mut self, micro_op: serde_json::Value) {
        self.emitted_micro_ops.push(micro_op);
        self.seq += 1;
    }

    fn rs2_source_json(rs2: i32, is_rs2_imm: bool) -> Value {
        if is_rs2_imm {
            json!({ "src": "imm", "value": rs2 })
        } else {
            // When rs2 is a register pointer, callers should pass a non-negative value.
            json!({ "src": "reg", "ptr": rs2.max(0) as u32 })
        }
    }

    pub fn emit_instruction(
        &mut self,
        pc: u32,
        timestamp: u32,
        next_pc: u32,
        next_timestamp: u32,
        opcode: u32,
        operands: [u32; 7],
    ) {
        // Start a new step: reset per-step interaction counter and anchor.
        self.op_idx_in_step = 0;
        self.chip_row_op_idx_in_step = 0;
        self.last_row_id = None;

        let micro_op = json!(
        {"type": "instruction",
        "data": {
            "seq": self.seq,
            "step_idx": self.step_idx,
            "pc": pc,
            "timestamp": timestamp,
            "next_pc": next_pc,
            "next_timestamp": next_timestamp,
            "opcode": opcode,
            "operands": operands,
        }});
        self.emit_micro_op(micro_op);
    }

    pub fn inc_step(&mut self) {
        self.step_idx += 1;
    }

    fn emit_chip_row_envelope(
        &mut self,
        kind: &str,
        chip_name: &str,
        timestamp: Option<u32>,
        payload_type: &str,
        payload_data: Value,
    ) {
        // Generate an anchor row id for downstream interaction events.
        // Format is intentionally simple and stable.
        let row_id = format!("step{}_row{}", self.step_idx, self.row_count);

        // Keep the JSON stable and explicit:
        // { "type": "chip_row", "data": { "base": {..}, "kind": "...", "payload": { "type": "...", "data": {..} } } }
        let mut base = Map::new();
        base.insert("seq".to_string(), json!(self.seq));
        base.insert("step_idx".to_string(), json!(self.step_idx));
        base.insert("op_idx".to_string(), json!(self.chip_row_op_idx_in_step));
        base.insert("is_valid".to_string(), json!(true));
        if let Some(ts) = timestamp {
            base.insert("timestamp".to_string(), json!(ts));
        }
        base.insert("chip_name".to_string(), json!(chip_name));

        let micro_op = json!({
            "type": "chip_row",
            "data": {
                "base": Value::Object(base),
                "kind": kind,
                "payload": {
                    "type": payload_type,
                    "data": payload_data,
                }
            }
        });

        self.row_count += 1;
        self.chip_row_op_idx_in_step += 1;
        self.last_row_id = Some(row_id);
        self.emit_micro_op(micro_op);
    }

    fn emit_interaction_envelope(
        &mut self,
        kind: &str,
        direction: &str,
        row_id: Option<&str>,
        timestamp: Option<u32>,
        payload_type: &str,
        payload_data: Value,
    ) {
        if direction != "send" && direction != "receive" {
            panic!("Invalid direction: {}", direction);
        }

        // Prefer explicit row_id; otherwise anchor to the most recent chip row.
        let row_id = row_id
            .map(|s| s.to_string())
            .or_else(|| self.last_row_id.clone())
            .unwrap_or_default();

        let base = json!({
            "seq": self.seq,
            "step_idx": self.step_idx,
            "op_idx": self.op_idx_in_step,
            "row_id": row_id,
            "direction": direction,
            "kind": kind,
            "timestamp": timestamp,
        });

        // JSON shape:
        // { "type": "interaction", "data": { "base": {...}, "payload": { "type": "...", "data": {...} } } }
        let micro_op = json!({
            "type": "interaction",
            "data": {
                "base": base,
                "payload": {
                    "type": payload_type,
                    "data": payload_data,
                }
            }
        });

        self.op_idx_in_step += 1;
        self.emit_micro_op(micro_op);
    }

    pub fn emit_base_alu_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2: i32,
        is_rs2_imm: bool,
        a: [u8; N],
        b: [u8; N],
        c: [u8; N],
    ) {
        let rs2 = Self::rs2_source_json(rs2, is_rs2_imm);
        let payload_data = json!({
            "op": opcode,
            "rd_ptr": rd_ptr,
            "rs1_ptr": rs1_ptr,
            "rs2": rs2,
            "a": a.to_vec(),
            "b": b.to_vec(),
            "c": c.to_vec(),
        });
        self.emit_chip_row_envelope("base_alu", "Rv32BaseAlu", None, "base_alu", payload_data);
    }

    pub fn emit_shift_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2: i32,
        is_rs2_imm: bool,
        a: [u8; N],
        b: [u8; N],
        c: [u8; N],
    ) {
        let rs2 = Self::rs2_source_json(rs2, is_rs2_imm);
        let payload_data = json!({
            "op": opcode,
            "rd_ptr": rd_ptr,
            "rs1_ptr": rs1_ptr,
            "rs2": rs2,
            "a": a.to_vec(),
            "b": b.to_vec(),
            "c": c.to_vec(),
        });
        self.emit_chip_row_envelope("shift", "Rv32Shift", None, "shift", payload_data);
    }

    pub fn emit_less_than_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2: i32,
        is_rs2_imm: bool,
        a: [u8; N],
        b: [u8; N],
        c: [u8; N],
    ) {
        let rs2 = Self::rs2_source_json(rs2, is_rs2_imm);
        let payload_data = json!({
            "op": opcode,
            "rd_ptr": rd_ptr,
            "rs1_ptr": rs1_ptr,
            "rs2": rs2,
            "a": a.to_vec(),
            "b": b.to_vec(),
            "c": c.to_vec(),
        });
        self.emit_chip_row_envelope("less_than", "Rv32LessThan", None, "less_than", payload_data);
    }

    pub fn emit_mul_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2_ptr: u32,
        a: [u8; N],
        b: [u8; N],
        c: [u8; N],
    ) {
        let payload_data = json!({
            "op": opcode,
            "rd_ptr": rd_ptr,
            "rs1_ptr": rs1_ptr,
            "rs2_ptr": rs2_ptr,
            "a": a.to_vec(),
            "b": b.to_vec(),
            "c": c.to_vec(),
        });
        self.emit_chip_row_envelope("mul", "Rv32Mul", None, "mul", payload_data);
    }

    pub fn emit_mulh_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2_ptr: u32,
        a: [u8; N],
        b: [u8; N],
        c: [u8; N],
    ) {
        let payload_data = json!({
            "op": opcode,
            "rd_ptr": rd_ptr,
            "rs1_ptr": rs1_ptr,
            "rs2_ptr": rs2_ptr,
            "a": a.to_vec(),
            "b": b.to_vec(),
            "c": c.to_vec(),
        });
        self.emit_chip_row_envelope("mul_h", "Rv32MulH", None, "mul_h", payload_data);
    }

    pub fn emit_divrem_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        rs2_ptr: u32,
        a: [u8; N],
        b: [u8; N],
        c: [u8; N],
    ) {
        let payload_data = json!({
            "op": opcode,
            "rd_ptr": rd_ptr,
            "rs1_ptr": rs1_ptr,
            "rs2_ptr": rs2_ptr,
            "a": a.to_vec(),
            "b": b.to_vec(),
            "c": c.to_vec(),
        });
        self.emit_chip_row_envelope("div_rem", "Rv32DivRem", None, "div_rem", payload_data);
    }

    pub fn emit_branch_equal_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rs1_ptr: u32,
        rs2_ptr: u32,
        imm: i32,
        is_taken: bool,
        from_pc: u32,
        to_pc: u32,
        a: [u8; N],
        b: [u8; N],
        cmp_result: bool,
    ) {
        let payload_data = json!({
            "op": opcode,
            "rs1_ptr": rs1_ptr,
            "rs2_ptr": rs2_ptr,
            "imm": imm,
            "is_taken": is_taken,
            "from_pc": from_pc,
            "to_pc": to_pc,
            "a": a.to_vec(),
            "b": b.to_vec(),
            "cmp_result": cmp_result,
        });
        self.emit_chip_row_envelope(
            "branch_equal",
            "Rv32BranchEqual",
            None,
            "branch_equal",
            payload_data,
        );
    }

    pub fn emit_branch_less_than_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rs1_ptr: u32,
        rs2_ptr: u32,
        imm: i32,
        is_taken: bool,
        from_pc: u32,
        to_pc: u32,
        a: [u8; N],
        b: [u8; N],
        cmp_result: bool,
    ) {
        let payload_data = json!({
            "op": opcode,
            "rs1_ptr": rs1_ptr,
            "rs2_ptr": rs2_ptr,
            "imm": imm,
            "is_taken": is_taken,
            "from_pc": from_pc,
            "to_pc": to_pc,
            "a": a.to_vec(),
            "b": b.to_vec(),
            "cmp_result": cmp_result,
        });
        self.emit_chip_row_envelope(
            "branch_less_than",
            "Rv32BranchLessThan",
            None,
            "branch_less_than",
            payload_data,
        );
    }

    pub fn emit_jal_lui_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rd_ptr: u32,
        imm: u32,
        needs_write: bool,
        from_pc: u32,
        to_pc: u32,
        rd_data: [u8; N],
        is_jal: bool,
    ) {
        let payload_data = json!({
            "op": opcode,
            "rd_ptr": rd_ptr,
            "imm": imm,
            "needs_write": needs_write,
            "from_pc": from_pc,
            "to_pc": to_pc,
            "rd_data": rd_data.to_vec(),
            "is_jal": is_jal,
        });
        self.emit_chip_row_envelope("jal_lui", "Rv32JalLui", None, "jal_lui", payload_data);
    }

    pub fn emit_jalr_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rd_ptr: u32,
        rs1_ptr: u32,
        imm: i32,
        imm_sign: bool,
        needs_write: bool,
        from_pc: u32,
        to_pc: u32,
        rs1_val: u32,
        rd_data: [u8; N],
    ) {
        let payload_data = json!({
            "op": opcode,
            "rd_ptr": rd_ptr,
            "rs1_ptr": rs1_ptr,
            "imm": imm,
            "imm_sign": imm_sign,
            "needs_write": needs_write,
            "from_pc": from_pc,
            "to_pc": to_pc,
            "rs1_val": rs1_val,
            "rd_data": rd_data.to_vec(),
        });
        self.emit_chip_row_envelope("jalr", "Rv32Jalr", None, "jalr", payload_data);
    }

    pub fn emit_auipc_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rd_ptr: u32,
        imm: u32,
        from_pc: u32,
        rd_data: [u8; N],
    ) {
        let payload_data = json!({
            "op": opcode,
            "rd_ptr": rd_ptr,
            "imm": imm,
            "from_pc": from_pc,
            "rd_data": rd_data.to_vec(),
        });
        self.emit_chip_row_envelope("auipc", "Rv32Auipc", None, "auipc", payload_data);
    }

    pub fn emit_load_store_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rs1_ptr: u32,
        rd_rs2_ptr: u32,
        imm: i32,
        imm_sign: bool,
        mem_as: u32,
        effective_ptr: u32,
        is_store: bool,
        needs_write: bool,
        is_load: bool,
        flags: [u32; 4],
        read_data: [u8; N],
        prev_data: [u32; N],
        write_data: [u32; N],
    ) {
        let payload_data = json!({
            "op": opcode,
            "rs1_ptr": rs1_ptr,
            "rd_rs2_ptr": rd_rs2_ptr,
            "imm": imm,
            "imm_sign": imm_sign,
            "mem_as": mem_as,
            "effective_ptr": effective_ptr,
            "is_store": is_store,
            "needs_write": needs_write,
            "is_load": is_load,
            "flags": flags,
            "read_data": read_data.to_vec(),
            "prev_data": prev_data.to_vec(),
            "write_data": write_data.to_vec(),
        });
        self.emit_chip_row_envelope(
            "load_store",
            "Rv32LoadStore",
            None,
            "load_store",
            payload_data,
        );
    }

    pub fn emit_load_sign_extend_chip_row<const N: usize>(
        &mut self,
        opcode: u32,
        rs1_ptr: u32,
        rd_ptr: u32,
        imm: i32,
        imm_sign: bool,
        mem_as: u32,
        effective_ptr: u32,
        needs_write: bool,
        prev_data: [u8; N],
        shifted_read_data: [u8; N],
        data_most_sig_bit: bool,
        shift_most_sig_bit: bool,
        opcode_loadh_flag: bool,
        opcode_loadb_flag1: bool,
        opcode_loadb_flag0: bool,
    ) {
        let payload_data = json!({
            "op": opcode,
            "rs1_ptr": rs1_ptr,
            "rd_ptr": rd_ptr,
            "imm": imm,
            "imm_sign": imm_sign,
            "mem_as": mem_as,
            "effective_ptr": effective_ptr,
            "needs_write": needs_write,
            "prev_data": prev_data.to_vec(),
            "shifted_read_data": shifted_read_data.to_vec(),
            "data_most_sig_bit": data_most_sig_bit,
            "shift_most_sig_bit": shift_most_sig_bit,
            "opcode_loadh_flag": opcode_loadh_flag,
            "opcode_loadb_flag1": opcode_loadb_flag1,
            "opcode_loadb_flag0": opcode_loadb_flag0,
        });
        self.emit_chip_row_envelope(
            "load_sign_extend",
            "Rv32LoadSignExtend",
            None,
            "load_sign_extend",
            payload_data,
        );
    }

    pub fn emit_phantom_chip_row(&mut self) {
        self.emit_chip_row_envelope("phantom", "Phantom", None, "phantom", json!({}));
    }

    pub fn emit_program_chip_row(
        &mut self,
        opcode: u32,
        operands: [u32; 7],
        execution_frequency: u32,
    ) {
        // Keep the wire format close to the typed version:
        // opcode: VmOpcode, operands: [FieldElement; 7]
        let payload_data = json!({
            "opcode": opcode,
            "operands": operands,
            "execution_frequency": execution_frequency,
        });
        self.emit_chip_row_envelope("program", "ProgramChip", None, "program", payload_data);
    }

    pub fn emit_connector_chip_row(
        &mut self,
        from_pc: u32,
        to_pc: u32,
        from_timestamp: Option<u32>,
        to_timestamp: Option<u32>,
        is_terminate: bool,
        exit_code: Option<u32>,
    ) {
        let payload_data = json!({
            "from_pc": from_pc,
            "to_pc": to_pc,
            "from_timestamp": from_timestamp,
            "to_timestamp": to_timestamp,
            "is_terminate": is_terminate,
            "exit_code": exit_code,
        });
        self.emit_chip_row_envelope(
            "connector",
            "VmConnectorAir",
            None,
            "connector",
            payload_data,
        );
    }

    pub fn emit_padding_chip_row(&mut self, data: &str) {
        let payload_data = json!({
            "data": data.to_string(),
        });
        self.emit_chip_row_envelope("padding", "RowMajorMatrix", None, "padding", payload_data);
    }

    pub fn get_last_row_id(&self) -> String {
        self.last_row_id.clone().unwrap_or_default()
    }

    // -------------------------------------------------------------------------
    // Interactions (envelope)
    // -------------------------------------------------------------------------

    pub fn emit_execution_interaction(
        &mut self,
        direction: &str,
        row_id: Option<&str>,
        pc: u32,
        timestamp: u32,
    ) {
        let payload_data = json!({
            "pc": pc,
            "timestamp": timestamp,
        });
        self.emit_interaction_envelope(
            "execution",
            direction,
            row_id,
            Some(timestamp),
            "execution",
            payload_data,
        );
    }

    pub fn emit_program_interaction(
        &mut self,
        direction: &str,
        row_id: Option<&str>,
        pc: u32,
        opcode: u32,
        operands: [u32; 7],
    ) {
        let payload_data = json!({
            "pc": pc,
            "opcode": opcode,
            "operands": operands,
        });
        self.emit_interaction_envelope("program", direction, row_id, None, "program", payload_data);
    }

    pub fn emit_memory_interaction(
        &mut self,
        direction: &str,
        row_id: Option<&str>,
        address_space: u32,
        pointer: u32,
        data: Vec<u32>,
        timestamp: u32,
    ) {
        let payload_data = json!({
            "address_space": address_space,
            "pointer": pointer,
            "data": data,
            "timestamp": timestamp,
        });
        self.emit_interaction_envelope(
            "memory",
            direction,
            row_id,
            Some(timestamp),
            "memory",
            payload_data,
        );
    }

    pub fn emit_range_check_interaction(
        &mut self,
        direction: &str,
        row_id: Option<&str>,
        value: u32,
        max_bits: u32,
    ) {
        let payload_data = json!({
            "value": value,
            "max_bits": max_bits,
        });
        self.emit_interaction_envelope(
            "range_check",
            direction,
            row_id,
            None,
            "range_check",
            payload_data,
        );
    }

    pub fn emit_bitwise_interaction(
        &mut self,
        direction: &str,
        row_id: Option<&str>,
        x: u32,
        y: u32,
        z: u32,
        op: u32,
    ) {
        let payload_data = json!({
            "x": x,
            "y": y,
            "z": z,
            "op": op,
        });
        self.emit_interaction_envelope("bitwise", direction, row_id, None, "bitwise", payload_data);
    }
}

lazy_static! {
    static ref GLOBAL_STATE: Mutex<GlobalState> = Mutex::new(GlobalState::new());
}

// -----------------------------------------------------------------------------
// Module-level emit API (locks GLOBAL_STATE internally)
// -----------------------------------------------------------------------------

pub fn emit_instruction(
    pc: u32,
    timestamp: u32,
    next_pc: u32,
    next_timestamp: u32,
    opcode: u32,
    operands: [u32; 7],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_instruction(pc, timestamp, next_pc, next_timestamp, opcode, operands);
}

pub fn emit_base_alu_chip_row<const N: usize>(
    opcode: u32,
    rd_ptr: u32,
    rs1_ptr: u32,
    rs2: i32,
    is_rs2_imm: bool,
    a: [u8; N],
    b: [u8; N],
    c: [u8; N],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_base_alu_chip_row(opcode, rd_ptr, rs1_ptr, rs2, is_rs2_imm, a, b, c);
}

pub fn emit_shift_chip_row<const N: usize>(
    opcode: u32,
    rd_ptr: u32,
    rs1_ptr: u32,
    rs2: i32,
    is_rs2_imm: bool,
    a: [u8; N],
    b: [u8; N],
    c: [u8; N],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_shift_chip_row(opcode, rd_ptr, rs1_ptr, rs2, is_rs2_imm, a, b, c);
}

pub fn emit_less_than_chip_row<const N: usize>(
    opcode: u32,
    rd_ptr: u32,
    rs1_ptr: u32,
    rs2: i32,
    is_rs2_imm: bool,
    a: [u8; N],
    b: [u8; N],
    c: [u8; N],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_less_than_chip_row(opcode, rd_ptr, rs1_ptr, rs2, is_rs2_imm, a, b, c);
}

pub fn emit_mul_chip_row<const N: usize>(
    opcode: u32,
    rd_ptr: u32,
    rs1_ptr: u32,
    rs2_ptr: u32,
    a: [u8; N],
    b: [u8; N],
    c: [u8; N],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_mul_chip_row(opcode, rd_ptr, rs1_ptr, rs2_ptr, a, b, c);
}

pub fn emit_mulh_chip_row<const N: usize>(
    opcode: u32,
    rd_ptr: u32,
    rs1_ptr: u32,
    rs2_ptr: u32,
    a: [u8; N],
    b: [u8; N],
    c: [u8; N],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_mulh_chip_row(opcode, rd_ptr, rs1_ptr, rs2_ptr, a, b, c);
}

pub fn emit_divrem_chip_row<const N: usize>(
    opcode: u32,
    rd_ptr: u32,
    rs1_ptr: u32,
    rs2_ptr: u32,
    a: [u8; N],
    b: [u8; N],
    c: [u8; N],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_divrem_chip_row(opcode, rd_ptr, rs1_ptr, rs2_ptr, a, b, c);
}

pub fn emit_branch_equal_chip_row<const N: usize>(
    opcode: u32,
    rs1_ptr: u32,
    rs2_ptr: u32,
    imm: i32,
    is_taken: bool,
    from_pc: u32,
    to_pc: u32,
    a: [u8; N],
    b: [u8; N],
    cmp_result: bool,
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_branch_equal_chip_row(
        opcode, rs1_ptr, rs2_ptr, imm, is_taken, from_pc, to_pc, a, b, cmp_result,
    );
}

pub fn emit_branch_less_than_chip_row<const N: usize>(
    opcode: u32,
    rs1_ptr: u32,
    rs2_ptr: u32,
    imm: i32,
    is_taken: bool,
    from_pc: u32,
    to_pc: u32,
    a: [u8; N],
    b: [u8; N],
    cmp_result: bool,
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_branch_less_than_chip_row(
        opcode, rs1_ptr, rs2_ptr, imm, is_taken, from_pc, to_pc, a, b, cmp_result,
    );
}

pub fn emit_jal_lui_chip_row<const N: usize>(
    opcode: u32,
    rd_ptr: u32,
    imm: u32,
    needs_write: bool,
    from_pc: u32,
    to_pc: u32,
    rd_data: [u8; N],
    is_jal: bool,
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_jal_lui_chip_row(
        opcode,
        rd_ptr,
        imm,
        needs_write,
        from_pc,
        to_pc,
        rd_data,
        is_jal,
    );
}

pub fn emit_jalr_chip_row<const N: usize>(
    opcode: u32,
    rd_ptr: u32,
    rs1_ptr: u32,
    imm: i32,
    imm_sign: bool,
    needs_write: bool,
    from_pc: u32,
    to_pc: u32,
    rs1_val: u32,
    rd_data: [u8; N],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_jalr_chip_row(
        opcode,
        rd_ptr,
        rs1_ptr,
        imm,
        imm_sign,
        needs_write,
        from_pc,
        to_pc,
        rs1_val,
        rd_data,
    );
}

pub fn emit_auipc_chip_row<const N: usize>(
    opcode: u32,
    rd_ptr: u32,
    imm: u32,
    from_pc: u32,
    rd_data: [u8; N],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_auipc_chip_row(opcode, rd_ptr, imm, from_pc, rd_data);
}

pub fn emit_load_store_chip_row<const N: usize>(
    opcode: u32,
    rs1_ptr: u32,
    rd_rs2_ptr: u32,
    imm: i32,
    imm_sign: bool,
    mem_as: u32,
    effective_ptr: u32,
    is_store: bool,
    needs_write: bool,
    is_load: bool,
    flags: [u32; 4],
    read_data: [u8; N],
    prev_data: [u32; N],
    write_data: [u32; N],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_load_store_chip_row(
        opcode,
        rs1_ptr,
        rd_rs2_ptr,
        imm,
        imm_sign,
        mem_as,
        effective_ptr,
        is_store,
        needs_write,
        is_load,
        flags,
        read_data,
        prev_data,
        write_data,
    );
}

pub fn emit_load_sign_extend_chip_row<const N: usize>(
    opcode: u32,
    rs1_ptr: u32,
    rd_ptr: u32,
    imm: i32,
    imm_sign: bool,
    mem_as: u32,
    effective_ptr: u32,
    needs_write: bool,
    prev_data: [u8; N],
    shifted_read_data: [u8; N],
    data_most_sig_bit: bool,
    shift_most_sig_bit: bool,
    opcode_loadh_flag: bool,
    opcode_loadb_flag1: bool,
    opcode_loadb_flag0: bool,
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_load_sign_extend_chip_row(
        opcode,
        rs1_ptr,
        rd_ptr,
        imm,
        imm_sign,
        mem_as,
        effective_ptr,
        needs_write,
        prev_data,
        shifted_read_data,
        data_most_sig_bit,
        shift_most_sig_bit,
        opcode_loadh_flag,
        opcode_loadb_flag1,
        opcode_loadb_flag0,
    );
}

pub fn emit_phantom_chip_row() {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_phantom_chip_row();
}

pub fn emit_program_chip_row(opcode: u32, operands: [u32; 7], execution_frequency: u32) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_program_chip_row(opcode, operands, execution_frequency);
}

pub fn emit_connector_chip_row(
    from_pc: u32,
    to_pc: u32,
    from_timestamp: Option<u32>,
    to_timestamp: Option<u32>,
    is_terminate: bool,
    exit_code: Option<u32>,
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_connector_chip_row(
        from_pc,
        to_pc,
        from_timestamp,
        to_timestamp,
        is_terminate,
        exit_code,
    );
}

pub fn emit_padding_chip_row(data: &str) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_padding_chip_row(data);
}

pub fn get_last_row_id() -> String {
    let state = GLOBAL_STATE.lock().unwrap();
    state.get_last_row_id()
}

pub fn emit_execution_interaction(direction: &str, row_id: Option<&str>, pc: u32, timestamp: u32) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_execution_interaction(direction, row_id, pc, timestamp);
}

pub fn emit_program_interaction(
    direction: &str,
    row_id: Option<&str>,
    pc: u32,
    opcode: u32,
    operands: [u32; 7],
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_program_interaction(direction, row_id, pc, opcode, operands);
}

pub fn emit_memory_interaction(
    direction: &str,
    row_id: Option<&str>,
    address_space: u32,
    pointer: u32,
    data: Vec<u32>,
    timestamp: u32,
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_memory_interaction(direction, row_id, address_space, pointer, data, timestamp);
}

pub fn emit_range_check_interaction(
    direction: &str,
    row_id: Option<&str>,
    value: u32,
    max_bits: u32,
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_range_check_interaction(direction, row_id, value, max_bits);
}

pub fn emit_bitwise_interaction(
    direction: &str,
    row_id: Option<&str>,
    x: u32,
    y: u32,
    z: u32,
    op: u32,
) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.emit_bitwise_interaction(direction, row_id, x, y, z, op);
}

pub fn is_assertions_enabled() -> bool {
    let state = GLOBAL_STATE.lock().unwrap();
    state.assertions_enabled
}

////////////////
// CUSTOM ASSERTION MACROS
/////////

/// Custom assert! macro
#[macro_export]
macro_rules! fuzzer_assert {
    ($cond:expr $(,)?) => {{
        if $crate::is_assertions_enabled() {
            assert!($cond);
        } else if !$cond {
            println!("Warning: fuzzer_assert! failed: {}", stringify!($cond));
        }
    }};
    ($cond:expr, $($arg:tt)+) => {{
        if $crate::is_assertions_enabled() {
            assert!($cond, $($arg)+);
        } else if !$cond {
            println!("Warning: fuzzer_assert! failed: {}", format_args!($($arg)+));
        }
    }};
}

/// Custom assert_eq! macro. Only borrows the expressions (like assert_eq!), never moves.
#[macro_export]
macro_rules! fuzzer_assert_eq {
    ($left:expr, $right:expr $(,)?) => {{
        if $crate::is_assertions_enabled() {
            assert_eq!($left, $right);
        } else {
            let left_val = &$left;
            let right_val = &$right;
            if *left_val != *right_val {
                println!(
                    "Warning: fuzzer_assert_eq! failed: `{} != {}` (left: `{:?}`, right: `{:?}`)",
                    stringify!($left),
                    stringify!($right),
                    left_val,
                    right_val,
                );
            }
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        if $crate::is_assertions_enabled() {
            assert_eq!($left, $right, $($arg)+);
        } else {
            let left_val = &$left;
            let right_val = &$right;
            if *left_val != *right_val {
                println!(
                    "Warning: fuzzer_assert_eq! failed: `{} != {}` (left: `{:?}`, right: `{:?}`): {}",
                    stringify!($left),
                    stringify!($right),
                    left_val,
                    right_val,
                    format_args!($($arg)+),
                );
            }
        }
    }};
}

/// Custom assert_ne! macro. Only borrows the expressions (like assert_ne!), never moves.
#[macro_export]
macro_rules! fuzzer_assert_ne {
    ($left:expr, $right:expr $(,)?) => {{
        if $crate::is_assertions_enabled() {
            assert_ne!($left, $right);
        } else {
            let left_val = &$left;
            let right_val = &$right;
            if *left_val == *right_val {
                println!(
                    "Warning: fuzzer_assert_ne! failed: `{} == {}` (left: `{:?}`, right: `{:?}`)",
                    stringify!($left),
                    stringify!($right),
                    left_val,
                    right_val,
                );
            }
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        if $crate::is_assertions_enabled() {
            assert_ne!($left, $right, $($arg)+);
        } else {
            let left_val = &$left;
            let right_val = &$right;
            if *left_val == *right_val {
                println!(
                    "Warning: fuzzer_assert_ne! failed: `{} == {}` (left: `{:?}`, right: `{:?}`): {}",
                    stringify!($left),
                    stringify!($right),
                    left_val,
                    right_val,
                    format_args!($($arg)+),
                );
            }
        }
    }};
}

////////////////
// RANDOMNESS
/////////

pub fn random_bool() -> bool {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.rng.random::<bool>()
}

pub fn random_from_choices<T>(choices: Vec<T>) -> T
where
    T: Clone,
{
    let mut state = GLOBAL_STATE.lock().unwrap();
    choices.choose(&mut state.rng).unwrap().clone()
}

pub fn random_opcode(rng: &mut StdRng) -> VmOpcode {
    match rng.random_range(0..=40) {
        0 => BaseAluOpcode::ADD.global_opcode(),
        1 => BaseAluOpcode::SUB.global_opcode(),
        2 => BaseAluOpcode::XOR.global_opcode(),
        3 => BaseAluOpcode::OR.global_opcode(),
        4 => BaseAluOpcode::AND.global_opcode(),
        5 => ShiftOpcode::SLL.global_opcode(),
        6 => ShiftOpcode::SRL.global_opcode(),
        7 => ShiftOpcode::SRA.global_opcode(),
        8 => LessThanOpcode::SLT.global_opcode(),
        9 => LessThanOpcode::SLTU.global_opcode(),
        10 => Rv32LoadStoreOpcode::LOADW.global_opcode(),
        11 => Rv32LoadStoreOpcode::LOADBU.global_opcode(),
        12 => Rv32LoadStoreOpcode::LOADHU.global_opcode(),
        13 => Rv32LoadStoreOpcode::STOREW.global_opcode(),
        14 => Rv32LoadStoreOpcode::STOREH.global_opcode(),
        15 => Rv32LoadStoreOpcode::STOREB.global_opcode(),
        16 => Rv32LoadStoreOpcode::LOADB.global_opcode(),
        17 => Rv32LoadStoreOpcode::LOADH.global_opcode(),
        18 => BranchEqualOpcode::BEQ.global_opcode(),
        19 => BranchEqualOpcode::BNE.global_opcode(),
        20 => BranchLessThanOpcode::BLT.global_opcode(),
        21 => BranchLessThanOpcode::BLTU.global_opcode(),
        22 => BranchLessThanOpcode::BGE.global_opcode(),
        23 => BranchLessThanOpcode::BGEU.global_opcode(),
        24 => Rv32JalLuiOpcode::JAL.global_opcode(),
        25 => Rv32JalLuiOpcode::LUI.global_opcode(),
        26 => Rv32JalrOpcode::JALR.global_opcode(),
        27 => Rv32AuipcOpcode::AUIPC.global_opcode(),
        28 => MulOpcode::MUL.global_opcode(),
        29 => MulHOpcode::MULH.global_opcode(),
        30 => MulHOpcode::MULHSU.global_opcode(),
        31 => MulHOpcode::MULHU.global_opcode(),
        32 => DivRemOpcode::DIV.global_opcode(),
        33 => DivRemOpcode::DIVU.global_opcode(),
        34 => DivRemOpcode::REM.global_opcode(),
        35 => DivRemOpcode::REMU.global_opcode(),
        36 => Rv32HintStoreOpcode::HINT_STOREW.global_opcode(),
        37 => Rv32HintStoreOpcode::HINT_BUFFER.global_opcode(),
        38 => SystemOpcode::TERMINATE.global_opcode(),
        39 => SystemOpcode::PHANTOM.global_opcode(),
        40 => PublishOpcode::PUBLISH.global_opcode(),
        // ? => Rv32Phantom::HintInput.global_opcode(),
        // ? => Rv32Phantom::PrintStr.global_opcode(),
        // ? => Rv32Phantom::HintRandom.global_opcode(),
        // ? => Rv32Phantom::HintLoadByKey.global_opcode(),
        _ => panic!("selector value was out of bounds!"),
    }
}

pub fn random_new_opcode(opcode: VmOpcode, rng: &mut StdRng) -> VmOpcode {
    loop {
        let new_opcode = random_opcode(rng);
        if new_opcode != opcode {
            return new_opcode;
        }
    }
}

fn internal_random_mod_of_u32(element: u32, rng: &mut StdRng) -> u32 {
    let mut new_element = element;
    while new_element == element {
        let selector: u32 = rng.random_range(0..=7);
        new_element = match selector {
            0 => 0,
            1 => 1,
            2 => 0xffffffff,
            3 => 0xfffffffe,
            4 => {
                let n = rng.random_range(1..=31);
                let bits_to_flip = rand::seq::index::sample(rng, 31, n).into_vec();
                let mut flipped_element = element;
                for bit_to_flip in bits_to_flip {
                    flipped_element ^= 1 << bit_to_flip;
                }
                flipped_element
            }
            5 => element.saturating_add(1),
            6 => element.saturating_sub(1),
            7 => rng.random::<u32>(),
            _ => unreachable!(),
        };
    }
    new_element
}

pub fn random_mod_of_u32_array<const LEN: usize>(elements: &[u32; LEN]) -> [u32; LEN] {
    let mut state = GLOBAL_STATE.lock().unwrap();

    let mut new_elements = *elements;
    let mut indices: Vec<usize> = (0..LEN).collect();
    indices.shuffle(&mut state.rng);
    let num_to_modify = state.rng.random_range(1..=LEN);

    for &i in indices.iter().take(num_to_modify) {
        new_elements[i] = internal_random_mod_of_u32(elements[i], &mut state.rng);
    }

    new_elements
}

pub fn random_mutate_field_element<F: Field + PrimeField32>(element: F, rng: &mut StdRng) -> F {
    F::from_canonical_u32(internal_random_mod_of_u32(element.as_canonical_u32(), rng))
}

pub fn random_mutate_instruction<F: Field + PrimeField32>(
    instruction: &Instruction<F>,
) -> Instruction<F> {
    let mut state = GLOBAL_STATE.lock().unwrap();

    // create a mutable copy of the old instruction
    let mut new_instruction = instruction.clone();

    // pick the fields to updated and how many should be modified
    let update_fields = state.rng.random_range(1..=8);
    let mut update_options: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];

    // pick random selection from the available options
    update_options.shuffle(&mut state.rng);
    update_options.truncate(update_fields);

    // sort the options such that we first pick the new opcode if it is there
    update_options.sort();

    // execute the picked modifications
    for option in update_options {
        match option {
            0 => {
                new_instruction = Instruction::default(); // full reset
                new_instruction.opcode = random_new_opcode(instruction.opcode, &mut state.rng);
            }
            1 => {
                new_instruction.a = random_mutate_field_element(new_instruction.a, &mut state.rng);
            }
            2 => {
                new_instruction.b = random_mutate_field_element(new_instruction.b, &mut state.rng);
            }
            3 => {
                new_instruction.c = random_mutate_field_element(new_instruction.c, &mut state.rng);
            }
            4 => {
                new_instruction.d = random_mutate_field_element(new_instruction.d, &mut state.rng);
            }
            5 => {
                new_instruction.e = random_mutate_field_element(new_instruction.e, &mut state.rng);
            }
            6 => {
                new_instruction.f = random_mutate_field_element(new_instruction.f, &mut state.rng);
            }
            7 => {
                new_instruction.g = random_mutate_field_element(new_instruction.g, &mut state.rng);
            }
            _ => unreachable!(),
        };
    }

    new_instruction
}
