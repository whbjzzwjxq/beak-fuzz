use std::rc::Rc;

use anyhow::Result;
use risc0_circuit_rv32im_sys::RawPreflightCycle;
use risc0_zkp::{
    adapter::{CircuitInfo as _, PROOF_SYSTEM_INFO},
    core::hash::poseidon2::Poseidon2HashSuite,
    field::Elem as _,
    hal::{Buffer as _, Hal as _},
    prove::Prover,
};

use super::{
    hal::{cpu::CpuCircuitHal, MetaBuffer, StepMode},
    witgen::{preflight::PreflightTrace, WitnessGenerator},
    Seal,
};
use crate::{
    execute::{
        platform::{ecall_minor, major, LOOKUP_TABLE_CYCLES, MACHINE_REGS_ADDR, RESERVED_CYCLES},
        segment::Segment,
    },
    zirgen::{
        circuit::{
            AddrDecomposeBitsLayout, AddrDecomposeLayout, CircuitField, DecoderLayout,
            DecomposeLow2Layout, DoDivLayout, ExtVal, IsForwardLayout, MemoryArgLayout,
            MemoryReadLayout, MemoryWriteLayout, NondetRegLayout, NondetU16RegLayout,
            NormalizeU32Layout, ReadRegLayout, Val, WriteRdLayout, LAYOUT_TOP, REGCOUNT_MIX,
            REGISTER_GROUP_ACCUM, REGISTER_GROUP_CODE, REGISTER_GROUP_DATA,
        },
        taps::TAPSET,
        CircuitImpl,
    },
    RV32IM_SEAL_VERSION,
};

type CpuHal = risc0_zkp::hal::cpu::CpuHal<CircuitField>;

#[derive(Debug, Clone)]
pub struct BeakPreflightMemoryTxn {
    pub row_idx: u64,
    pub row_step_idx: u64,
    pub row_pc: u32,
    pub major: u8,
    pub minor: u8,
    pub machine_mode: u8,
    pub txn_idx: u64,
    pub row_txn_start: u64,
    pub row_txn_end: u64,
    pub addr_word: u32,
    pub txn_cycle: u32,
    pub word: u32,
    pub prev_cycle: u32,
    pub prev_word: u32,
    pub is_load: bool,
    pub is_store: bool,
}

#[derive(Debug, Clone)]
pub struct BeakPreflightTraceRecords {
    pub table_split_cycle: u64,
    pub padding_start_row: u64,
    pub total_rows: u64,
    pub lookup_table_rows: u64,
    pub txns: Vec<BeakPreflightMemoryTxn>,
}

pub fn collect_preflight_trace_records(segment: &Segment) -> Result<BeakPreflightTraceRecords> {
    let mut rng = rand::thread_rng();
    let rand_z = ExtVal::random(&mut rng);
    let trace = segment.preflight(rand_z)?;
    let mut txns = Vec::new();

    for (row_idx, cycle) in trace.cycles.iter().enumerate() {
        let row_txn_start = cycle.txn_idx;
        let row_txn_end = trace
            .cycles
            .get(row_idx + 1)
            .map(|next| next.txn_idx)
            .unwrap_or(trace.txns.len() as u32);
        if row_txn_start > row_txn_end || row_txn_end as usize > trace.txns.len() {
            continue;
        }
        for txn_idx in row_txn_start..row_txn_end {
            let txn = &trace.txns[txn_idx as usize];
            let is_load = txn.cycle % 2 == 0;
            txns.push(BeakPreflightMemoryTxn {
                row_idx: row_idx as u64,
                row_step_idx: cycle.user_cycle as u64,
                row_pc: cycle.pc,
                major: cycle.major,
                minor: cycle.minor,
                machine_mode: cycle.machine_mode,
                txn_idx: txn_idx as u64,
                row_txn_start: row_txn_start as u64,
                row_txn_end: row_txn_end as u64,
                addr_word: txn.addr,
                txn_cycle: txn.cycle,
                word: txn.word,
                prev_cycle: txn.prev_cycle,
                prev_word: txn.prev_word,
                is_load,
                is_store: !is_load,
            });
        }
    }

    Ok(BeakPreflightTraceRecords {
        table_split_cycle: trace.table_split_cycle as u64,
        padding_start_row: trace.table_split_cycle as u64 + RESERVED_CYCLES as u64,
        total_rows: trace.cycles.len() as u64,
        lookup_table_rows: LOOKUP_TABLE_CYCLES as u64,
        txns,
    })
}

const KIND_ZERO_REGISTER: &str = "risc0.semantic.decode.zero_register_immutability";
const KIND_OPERAND_ROUTE: &str = "risc0.semantic.decode.operand_index_routing";
const KIND_RD_BITS: &str = "risc0.semantic.decode.rd_bit_decomposition";
const KIND_DECODE_FIELD_RANGE: &str = "risc0.semantic.decode.field_range";
const KIND_DECODE_IMM_SIGN: &str = "risc0.semantic.decode.immediate_sign_extension";
const KIND_DECODE_UPPER_IMM: &str = "risc0.semantic.decode.upper_immediate_materialization";
const KIND_DECODE_FORMAT_IMM: &str = "risc0.semantic.decode.format_immediate_reassembly";
const KIND_ALU_IMM_LIMB: &str = "risc0.semantic.alu.immediate_limb_consistency";
const KIND_ALU_SHIFT_MOD32: &str = "risc0.semantic.alu.shift_mod32";
const KIND_ALU_CMP_BOOL: &str = "risc0.semantic.alu.comparison_booleanity";
const KIND_ALU_SUB_BORROW: &str = "risc0.semantic.alu.subtraction_borrow_chain";
const KIND_ALU_CMP_AUX: &str = "risc0.semantic.alu.comparison_auxiliary_chain";
const KIND_ARITH_SPECIAL_CASE: &str = "risc0.semantic.arithmetic.special_case_consistency";
const KIND_DIV_REM_BOUND: &str = "risc0.semantic.arithmetic.division_remainder_bound";
const KIND_ARITH_PRODUCT: &str = "risc0.semantic.arithmetic.product_decomposition";
const KIND_ARITH_SIGNED_UNSIGNED_PRODUCT: &str =
    "risc0.semantic.arithmetic.signed_unsigned_product_correction";
const KIND_ECALL_ARG_DECOMP: &str = "risc0.semantic.control.ecall_argument_decomposition";
const KIND_ENTRYPOINT_BINDING: &str = "risc0.semantic.control.entrypoint_binding";
const KIND_EXEC_SOURCE_BINDING: &str = "risc0.semantic.exec.source_operand_binding";
const KIND_EXEC_DEST_BINDING: &str = "risc0.semantic.exec.dest_binding";
const KIND_EXEC_OP_SELECTOR_BINDING: &str = "risc0.semantic.exec.op_selector_binding";
const KIND_EXEC_CONTROL_FLOW_BINDING: &str = "risc0.semantic.exec.control_flow_binding";
const KIND_EXEC_MEMORY_EFFECT_BINDING: &str = "risc0.semantic.exec.memory_effect_binding";
const KIND_MEMORY_STORE_LOAD_FLOW: &str = "risc0.semantic.memory.store_load_payload_flow";
const KIND_MEMORY_ADDRESS_POINTER: &str = "risc0.semantic.memory.address_pointer_consistency";
const KIND_MEMORY_ADDRESS_SPACE: &str = "risc0.semantic.memory.address_space_consistency";
const KIND_MEMORY_VALUE_PAYLOAD: &str = "risc0.semantic.memory.value_payload_consistency";
const KIND_MEMORY_KIND_SELECTOR: &str = "risc0.semantic.memory.kind_selector_consistency";
const KIND_MEMORY_INITIAL_VALUE: &str = "risc0.semantic.memory.initial_value_binding";
const KIND_MEMORY_FINALIZATION: &str = "risc0.semantic.memory.finalization_consistency";
const KIND_TIME_MONOTONIC: &str = "risc0.semantic.time.monotonic_access_ordering";

#[derive(Clone, Debug)]
pub struct BeakInjectionPlan {
    pub kind: String,
    pub step: u64,
}

fn base_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn debug_injection_enabled() -> bool {
    std::env::var_os("BEAK_RISC0_DEBUG_ROWS").is_some()
}

fn cell_index(rows: usize, row: usize, col: usize) -> usize {
    col * rows + row
}

fn read_u32(data: &[Val], rows: usize, row: usize, col: usize) -> u32 {
    data[cell_index(rows, row, col)].as_u32()
}

fn write_u32(data: &mut [Val], rows: usize, row: usize, col: usize, value: u32) {
    data[cell_index(rows, row, col)] = Val::new(value);
}

fn get_reg(data: &[Val], rows: usize, row: usize, layout: &NondetRegLayout) -> u32 {
    read_u32(data, rows, row, layout._super.offset)
}

fn set_reg(data: &mut [Val], rows: usize, row: usize, layout: &NondetRegLayout, value: u32) {
    write_u32(data, rows, row, layout._super.offset, value);
}

fn x0_word_addr() -> u32 {
    MACHINE_REGS_ADDR.0 / 4
}

fn reg_word_addr(reg: u32) -> u32 {
    x0_word_addr() + reg
}

fn get_u16_reg(data: &[Val], rows: usize, row: usize, layout: &NondetU16RegLayout) -> u32 {
    get_reg(data, rows, row, layout.arg.val)
}

fn set_u16_reg(data: &mut [Val], rows: usize, row: usize, layout: &NondetU16RegLayout, value: u32) {
    set_reg(data, rows, row, layout.arg.count, 1);
    set_reg(data, rows, row, layout.arg.val, value & 0xffff);
}

fn read_memory_arg(data: &[Val], rows: usize, row: usize, layout: &MemoryArgLayout) -> u32 {
    get_reg(data, rows, row, layout.data_low) | (get_reg(data, rows, row, layout.data_high) << 16)
}

fn set_memory_arg_u32(
    data: &mut [Val],
    rows: usize,
    row: usize,
    layout: &MemoryArgLayout,
    value: u32,
) {
    set_reg(data, rows, row, layout.data_low, value & 0xffff);
    set_reg(data, rows, row, layout.data_high, value >> 16);
}

fn copy_memory_arg(
    data: &mut [Val],
    rows: usize,
    row: usize,
    dst: &MemoryArgLayout,
    src: &MemoryArgLayout,
) {
    set_reg(data, rows, row, dst.count, get_reg(data, rows, row, src.count));
    set_reg(data, rows, row, dst.addr, get_reg(data, rows, row, src.addr));
    set_reg(data, rows, row, dst.cycle, get_reg(data, rows, row, src.cycle));
    set_reg(data, rows, row, dst.data_low, get_reg(data, rows, row, src.data_low));
    set_reg(data, rows, row, dst.data_high, get_reg(data, rows, row, src.data_high));
}

fn perturb_memory_arg_data_low(
    data: &mut [Val],
    rows: usize,
    row: usize,
    layout: &MemoryArgLayout,
) {
    let low = get_reg(data, rows, row, layout.data_low);
    set_reg(data, rows, row, layout.data_low, low.wrapping_add(1) & 0xffff);
}

fn perturb_memory_arg_cycle(data: &mut [Val], rows: usize, row: usize, layout: &MemoryArgLayout) {
    let cycle = get_reg(data, rows, row, layout.cycle);
    set_reg(data, rows, row, layout.cycle, cycle.wrapping_add(2));
}

fn retarget_memory_arg_addr(
    data: &mut [Val],
    rows: usize,
    row: usize,
    layout: &MemoryArgLayout,
    addr_word: u32,
) {
    set_reg(data, rows, row, layout.addr, addr_word);
}

fn copy_is_forward(
    data: &mut [Val],
    rows: usize,
    row: usize,
    dst: &IsForwardLayout,
    src: &IsForwardLayout,
) {
    set_reg(data, rows, row, dst._0.arg.count, get_reg(data, rows, row, src._0.arg.count));
    set_reg(data, rows, row, dst._0.arg.cycle, get_reg(data, rows, row, src._0.arg.cycle));
}

fn read_reg_u32(data: &[Val], rows: usize, row: usize, layout: &ReadRegLayout) -> u32 {
    read_memory_arg(data, rows, row, layout._super.io.old_txn)
}

fn set_read_reg_u32(data: &mut [Val], rows: usize, row: usize, layout: &ReadRegLayout, value: u32) {
    set_memory_arg_u32(data, rows, row, layout._super.io.old_txn, value);
    set_memory_arg_u32(data, rows, row, layout._super.io.new_txn, value);
}

fn copy_read_reg(
    data: &mut [Val],
    rows: usize,
    row: usize,
    dst: &ReadRegLayout,
    src: &ReadRegLayout,
) {
    set_reg(data, rows, row, dst.addr, get_reg(data, rows, row, src.addr));
    copy_memory_arg(data, rows, row, dst._super.io.old_txn, src._super.io.old_txn);
    copy_memory_arg(data, rows, row, dst._super.io.new_txn, src._super.io.new_txn);
    copy_is_forward(data, rows, row, dst._super._0, src._super._0);
}

fn zero_read_reg(data: &mut [Val], rows: usize, row: usize, layout: &ReadRegLayout) {
    let addr = x0_word_addr();
    set_reg(data, rows, row, layout.addr, addr);
    set_reg(data, rows, row, layout._super.io.old_txn.addr, addr);
    set_reg(data, rows, row, layout._super.io.new_txn.addr, addr);
    set_reg(data, rows, row, layout._super.io.old_txn.data_low, 0);
    set_reg(data, rows, row, layout._super.io.old_txn.data_high, 0);
    set_reg(data, rows, row, layout._super.io.new_txn.data_low, 0);
    set_reg(data, rows, row, layout._super.io.new_txn.data_high, 0);
}

fn retarget_read_reg_addr(
    data: &mut [Val],
    rows: usize,
    row: usize,
    layout: &ReadRegLayout,
    addr_word: u32,
) {
    set_reg(data, rows, row, layout.addr, addr_word);
    retarget_memory_arg_addr(data, rows, row, layout._super.io.old_txn, addr_word);
    retarget_memory_arg_addr(data, rows, row, layout._super.io.new_txn, addr_word);
}

fn get_decoded_reg(
    data: &[Val],
    rows: usize,
    row: usize,
    bits34: &NondetRegLayout,
    bits12: &NondetRegLayout,
    bit0: &NondetRegLayout,
) -> u32 {
    ((get_reg(data, rows, row, bits34) & 0x3) << 3)
        | ((get_reg(data, rows, row, bits12) & 0x3) << 1)
        | (get_reg(data, rows, row, bit0) & 0x1)
}

fn set_decoded_reg(
    data: &mut [Val],
    rows: usize,
    row: usize,
    bits34: &NondetRegLayout,
    bits12: &NondetRegLayout,
    bit0: &NondetRegLayout,
    value: u32,
) {
    set_reg(data, rows, row, bits34, (value >> 3) & 0x3);
    set_reg(data, rows, row, bits12, (value >> 1) & 0x3);
    set_reg(data, rows, row, bit0, value & 0x1);
}

fn copy_decoded_reg(
    data: &mut [Val],
    rows: usize,
    row: usize,
    dst34: &NondetRegLayout,
    dst12: &NondetRegLayout,
    dst0: &NondetRegLayout,
    src34: &NondetRegLayout,
    src12: &NondetRegLayout,
    src0: &NondetRegLayout,
) {
    set_reg(data, rows, row, dst34, get_reg(data, rows, row, src34));
    set_reg(data, rows, row, dst12, get_reg(data, rows, row, src12));
    set_reg(data, rows, row, dst0, get_reg(data, rows, row, src0));
}

fn get_decoded_func3(
    data: &[Val],
    rows: usize,
    row: usize,
    f3_2: &NondetRegLayout,
    f3_01: &NondetRegLayout,
) -> u32 {
    ((get_reg(data, rows, row, f3_2) & 0x1) << 2) | (get_reg(data, rows, row, f3_01) & 0x3)
}

fn set_decoded_func3(
    data: &mut [Val],
    rows: usize,
    row: usize,
    f3_2: &NondetRegLayout,
    f3_01: &NondetRegLayout,
    value: u32,
) {
    set_reg(data, rows, row, f3_2, (value >> 2) & 0x1);
    set_reg(data, rows, row, f3_01, value & 0x3);
}

fn get_decoded_func7(
    data: &[Val],
    rows: usize,
    row: usize,
    decoded: &crate::zirgen::circuit::DecoderLayout,
) -> u32 {
    ((get_reg(data, rows, row, decoded._f7_6) & 0x1) << 6)
        | ((get_reg(data, rows, row, decoded._f7_45) & 0x3) << 4)
        | ((get_reg(data, rows, row, decoded._f7_23) & 0x3) << 2)
        | (get_reg(data, rows, row, decoded._f7_01) & 0x3)
}

fn retarget_write_rd(data: &mut [Val], rows: usize, row: usize, write_rd: &WriteRdLayout, rd: u32) {
    let addr = reg_word_addr(rd);
    set_reg(data, rows, row, write_rd.write_addr, addr);
    set_reg(data, rows, row, write_rd._0.io.old_txn.addr, addr);
    set_reg(data, rows, row, write_rd._0.io.new_txn.addr, addr);
    set_reg(data, rows, row, write_rd.is_rd0._super, u32::from(rd == 0));
    set_reg(data, rows, row, write_rd.is_rd0.inv, if rd == 0 { 0 } else { 1 });
}

fn retarget_write_rd_addr(
    data: &mut [Val],
    rows: usize,
    row: usize,
    write_rd: &WriteRdLayout,
    addr_word: u32,
) {
    set_reg(data, rows, row, write_rd.write_addr, addr_word);
    retarget_memory_arg_addr(data, rows, row, write_rd._0.io.old_txn, addr_word);
    retarget_memory_arg_addr(data, rows, row, write_rd._0.io.new_txn, addr_word);
}

fn perturb_write_rd_data(data: &mut [Val], rows: usize, row: usize, write_rd: &WriteRdLayout) {
    let low = get_reg(data, rows, row, write_rd._0.io.new_txn.data_low);
    set_reg(data, rows, row, write_rd._0.io.new_txn.data_low, low.wrapping_add(1) & 0xffff);
}

fn perturb_normalize_u32(data: &mut [Val], rows: usize, row: usize, layout: &NormalizeU32Layout) {
    let low = get_u16_reg(data, rows, row, layout.low16);
    set_u16_reg(data, rows, row, layout.low16, low.wrapping_add(1) & 0xffff);
}

fn perturb_addr_decompose(data: &mut [Val], rows: usize, row: usize, layout: &AddrDecomposeLayout) {
    let med14 = get_u16_reg(data, rows, row, layout.med14);
    set_u16_reg(data, rows, row, layout.med14, med14.wrapping_add(1) & 0x3fff);
}

fn perturb_addr_decompose_bits(
    data: &mut [Val],
    rows: usize,
    row: usize,
    layout: &AddrDecomposeBitsLayout,
) {
    let low0 = get_reg(data, rows, row, layout.low0) & 0x1;
    set_reg(data, rows, row, layout.low0, low0 ^ 0x1);
}

fn set_decompose_low2_high_one(
    data: &mut [Val],
    rows: usize,
    row: usize,
    layout: &DecomposeLow2Layout,
) {
    set_u16_reg(data, rows, row, layout.high, 1);
    set_reg(data, rows, row, layout.high_zero.inv, 1);
}

fn active_div_do_div(cycle: &RawPreflightCycle) -> Option<&'static DoDivLayout> {
    if cycle.major != major::DIV0 {
        return None;
    }
    if cycle.minor == 4 {
        Some(LAYOUT_TOP.inst_result.arm4.mul_output.arm4._super._0)
    } else if cycle.minor == 5 {
        Some(LAYOUT_TOP.inst_result.arm4.mul_output.arm5._super._0)
    } else if cycle.minor == 6 {
        Some(LAYOUT_TOP.inst_result.arm4.mul_output.arm6._super._0)
    } else if cycle.minor == 7 {
        Some(LAYOUT_TOP.inst_result.arm4.mul_output.arm7._super._0)
    } else {
        None
    }
}

fn active_decoder(cycle: &RawPreflightCycle) -> Option<&'static DecoderLayout> {
    match cycle.major {
        major::MISC0 => Some(LAYOUT_TOP.inst_result.arm0.input.decoded._super),
        major::MISC1 => Some(LAYOUT_TOP.inst_result.arm1.input.decoded._super),
        major::MISC2 => Some(LAYOUT_TOP.inst_result.arm2.input.decoded._super),
        major::MUL0 => Some(LAYOUT_TOP.inst_result.arm3.input.decoded._super),
        major::DIV0 => Some(LAYOUT_TOP.inst_result.arm4.input.decoded._super),
        major::MEM0 => Some(LAYOUT_TOP.inst_result.arm5.input.decoded._super),
        major::MEM1 => Some(LAYOUT_TOP.inst_result.arm6.input.decoded._super),
        _ => None,
    }
}

fn active_pc_addr(cycle: &RawPreflightCycle) -> Option<&'static AddrDecomposeLayout> {
    match cycle.major {
        major::MISC0 => Some(LAYOUT_TOP.inst_result.arm0.input.decoded.pc_addr),
        major::MISC1 => Some(LAYOUT_TOP.inst_result.arm1.input.decoded.pc_addr),
        major::MISC2 => Some(LAYOUT_TOP.inst_result.arm2.input.decoded.pc_addr),
        major::MUL0 => Some(LAYOUT_TOP.inst_result.arm3.input.decoded.pc_addr),
        major::DIV0 => Some(LAYOUT_TOP.inst_result.arm4.input.decoded.pc_addr),
        major::MEM0 => Some(LAYOUT_TOP.inst_result.arm5.input.decoded.pc_addr),
        major::MEM1 => Some(LAYOUT_TOP.inst_result.arm6.input.decoded.pc_addr),
        _ => None,
    }
}

fn active_rs1(cycle: &RawPreflightCycle) -> Option<&'static ReadRegLayout> {
    match cycle.major {
        major::MISC0 => Some(LAYOUT_TOP.inst_result.arm0.input.rs1),
        major::MISC1 => Some(LAYOUT_TOP.inst_result.arm1.input.rs1),
        major::MISC2 => Some(LAYOUT_TOP.inst_result.arm2.input.rs1),
        major::MUL0 => Some(LAYOUT_TOP.inst_result.arm3.input.rs1),
        major::DIV0 => Some(LAYOUT_TOP.inst_result.arm4.input.rs1),
        major::MEM0 => Some(LAYOUT_TOP.inst_result.arm5.input.rs1),
        major::MEM1 => Some(LAYOUT_TOP.inst_result.arm6.input.rs1),
        _ => None,
    }
}

fn active_rs2(cycle: &RawPreflightCycle) -> Option<&'static ReadRegLayout> {
    match cycle.major {
        major::MISC0 => Some(LAYOUT_TOP.inst_result.arm0.input.rs2),
        major::MISC1 => Some(LAYOUT_TOP.inst_result.arm1.input.rs2),
        major::MISC2 => Some(LAYOUT_TOP.inst_result.arm2.input.rs2),
        major::MUL0 => Some(LAYOUT_TOP.inst_result.arm3.input.rs2),
        major::DIV0 => Some(LAYOUT_TOP.inst_result.arm4.input.rs2),
        major::MEM1 => Some(LAYOUT_TOP.inst_result.arm6.input.rs2),
        _ => None,
    }
}

fn active_write_rd(cycle: &RawPreflightCycle) -> Option<&'static WriteRdLayout> {
    match cycle.major {
        major::MISC0 => Some(LAYOUT_TOP.inst_result.arm0._super._0),
        major::MISC1 => Some(LAYOUT_TOP.inst_result.arm1._super._0),
        major::MISC2 => Some(LAYOUT_TOP.inst_result.arm2._super._0),
        major::MUL0 => Some(LAYOUT_TOP.inst_result.arm3._1),
        major::DIV0 => Some(LAYOUT_TOP.inst_result.arm4._1),
        major::MEM0 => Some(LAYOUT_TOP.inst_result.arm5._1),
        _ => None,
    }
}

fn active_pc_norm(cycle: &RawPreflightCycle) -> Option<&'static NormalizeU32Layout> {
    match cycle.major {
        major::MISC0 => Some(LAYOUT_TOP.inst_result.arm0._super.pc_norm),
        major::MISC1 => Some(LAYOUT_TOP.inst_result.arm1._super.pc_norm),
        major::MISC2 => Some(LAYOUT_TOP.inst_result.arm2._super.pc_norm),
        major::MUL0 => Some(LAYOUT_TOP.inst_result.arm3.pc_add),
        major::DIV0 => Some(LAYOUT_TOP.inst_result.arm4.pc_add),
        major::MEM0 => Some(LAYOUT_TOP.inst_result.arm5.pc_add),
        major::MEM1 => Some(LAYOUT_TOP.inst_result.arm6.pc_add),
        _ => None,
    }
}

fn active_memory_addr_bits(cycle: &RawPreflightCycle) -> Option<&'static AddrDecomposeBitsLayout> {
    match cycle.major {
        major::MEM0 => Some(LAYOUT_TOP.inst_result.arm5.input.addr),
        major::MEM1 => Some(LAYOUT_TOP.inst_result.arm6.input.addr),
        _ => None,
    }
}

fn active_memory_read(cycle: &RawPreflightCycle) -> Option<&'static MemoryReadLayout> {
    match cycle.major {
        major::MEM0 => Some(LAYOUT_TOP.inst_result.arm5.input.data_0),
        major::MEM1 => Some(LAYOUT_TOP.inst_result.arm6.input.data_0),
        _ => None,
    }
}

fn active_memory_write(cycle: &RawPreflightCycle) -> Option<&'static MemoryWriteLayout> {
    match cycle.major {
        major::MEM1 => Some(LAYOUT_TOP.inst_result.arm6._1._0),
        _ => None,
    }
}

fn debug_row(label: &str, data: &[Val], rows: usize, row: usize, cycle: &RawPreflightCycle) {
    if !debug_injection_enabled() {
        return;
    }

    let minor = &LAYOUT_TOP.inst_input.minor_onehot._super;
    let active_minor = minor
        .iter()
        .enumerate()
        .filter_map(|(idx, layout)| {
            (read_u32(data, rows, row, layout._super.offset) == 1).then_some(idx)
        })
        .collect::<Vec<_>>();
    let decoder = active_decoder(cycle);
    let write_rd = active_write_rd(cycle);
    let rs1 = active_rs1(cycle);
    let rs2 = active_rs2(cycle);
    let div_layout = active_div_do_div(cycle);
    let rd12 = decoder.map(|decoder| get_reg(data, rows, row, decoder._rd_12)).unwrap_or(0);
    let rd0 = decoder.map(|decoder| get_reg(data, rows, row, decoder._rd_0)).unwrap_or(0);
    let write_addr =
        write_rd.map(|write_rd| get_reg(data, rows, row, write_rd.write_addr)).unwrap_or(0);
    let rs1_low = rs1.map(|rs1| read_reg_u32(data, rows, row, rs1)).unwrap_or(0);
    let rs2_low = rs2.map(|rs2| read_reg_u32(data, rows, row, rs2)).unwrap_or(0);

    eprintln!(
        "[beak-risc0-debug] {label} row={row} step={} pc=0x{:08x} major={} minor={} active_minor={active_minor:?} rd12={} rd0={} write_addr=0x{:08x} rs1_low=0x{:04x} rs1_high=0x{:04x} rs2_low=0x{:04x} rs2_high=0x{:04x} has_div_layout={}",
        cycle.user_cycle,
        cycle.pc,
        cycle.major,
        cycle.minor,
        rd12,
        rd0,
        write_addr,
        rs1_low,
        0,
        rs2_low,
        0,
        div_layout.is_some(),
    );

    if let Some(layout) = div_layout {
        eprintln!(
            "[beak-risc0-debug] div row={row} quot_low=0x{:04x} quot_high=0x{:04x} rem_low=0x{:04x} rem_high=0x{:04x}",
            get_reg(data, rows, row, layout.quot_low),
            get_reg(data, rows, row, layout.quot_high),
            get_u16_reg(data, rows, row, layout.rem_low),
            get_u16_reg(data, rows, row, layout.rem_high),
        );
    }
}

fn apply_zero_register_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(write_rd) = active_write_rd(cycle) else {
        return false;
    };
    retarget_write_rd(data, rows, row, write_rd, 0);
    true
}

fn ecall_register_write_layout(cycle: &RawPreflightCycle) -> Option<&'static MemoryWriteLayout> {
    let out = LAYOUT_TOP.inst_result.arm8.output;
    match cycle.minor {
        ecall_minor::HOST_READ_SETUP => Some(out.arm2._super._0),
        ecall_minor::HOST_WRITE => Some(out.arm3._super._0),
        _ => None,
    }
}

fn apply_ecall_zero_register_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(write) = ecall_register_write_layout(cycle) else {
        return false;
    };
    let x0_word_addr = x0_word_addr();
    set_reg(data, rows, row, write.io.old_txn.addr, x0_word_addr);
    set_reg(data, rows, row, write.io.new_txn.addr, x0_word_addr);
    true
}

fn apply_operand_route_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let (Some(decoded), Some(rs1), Some(rs2)) =
        (active_decoder(cycle), active_rs1(cycle), active_rs2(cycle))
    else {
        return false;
    };
    let rs1_idx =
        get_decoded_reg(data, rows, row, decoded._rs1_34, decoded._rs1_12, decoded._rs1_0);
    let rs2_idx =
        get_decoded_reg(data, rows, row, decoded._rs2_34, decoded._rs2_12, decoded._rs2_0);
    if rs1_idx == rs2_idx
        || read_reg_u32(data, rows, row, rs1) == read_reg_u32(data, rows, row, rs2)
    {
        return false;
    }
    copy_read_reg(data, rows, row, rs2, rs1);
    true
}

fn apply_exec_source_binding_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let (Some(decoded), Some(rs2)) = (active_decoder(cycle), active_rs2(cycle)) else {
        return false;
    };
    let rs1_idx =
        get_decoded_reg(data, rows, row, decoded._rs1_34, decoded._rs1_12, decoded._rs1_0);
    let rs2_idx =
        get_decoded_reg(data, rows, row, decoded._rs2_34, decoded._rs2_12, decoded._rs2_0);
    if rs1_idx == rs2_idx && rs1_idx != 0 {
        let value = read_reg_u32(data, rows, row, rs2);
        set_read_reg_u32(data, rows, row, rs2, value.wrapping_add(1));
        return true;
    }
    apply_operand_route_injection(data, rows, row, cycle)
}

fn bump_decoded_rd(data: &mut [Val], rows: usize, row: usize, decoder: &DecoderLayout) -> bool {
    let rd = get_decoded_reg(data, rows, row, decoder._rd_34, decoder._rd_12, decoder._rd_0);
    let next_rd = if rd < 31 {
        rd + 1
    } else if rd > 0 {
        rd - 1
    } else {
        return false;
    };
    set_decoded_reg(data, rows, row, decoder._rd_34, decoder._rd_12, decoder._rd_0, next_rd);
    true
}

fn apply_rd_bit_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(decoder) = active_decoder(cycle) else {
        return false;
    };
    let rd12 = get_reg(data, rows, row, decoder._rd_12);
    let rd0 = get_reg(data, rows, row, decoder._rd_0);
    if rd12 == 0 || rd0 > 1 {
        return false;
    }
    set_reg(data, rows, row, decoder._rd_12, rd12 - 1);
    set_reg(data, rows, row, decoder._rd_0, rd0 + 2);
    true
}

fn apply_decode_field_range_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(decoder) = active_decoder(cycle) else {
        return false;
    };
    let func3 = get_decoded_func3(data, rows, row, decoder._f3_2, decoder._f3_01);
    set_decoded_func3(data, rows, row, decoder._f3_2, decoder._f3_01, func3 ^ 0x1);
    true
}

fn apply_decode_imm_sign_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(decoder) = active_decoder(cycle) else {
        return false;
    };
    let sign = get_reg(data, rows, row, decoder._f7_6) & 0x1;
    set_reg(data, rows, row, decoder._f7_6, sign ^ 0x1);
    true
}

fn apply_decode_upper_imm_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(decoder) = active_decoder(cycle) else {
        return false;
    };
    let f7_45 = get_reg(data, rows, row, decoder._f7_45) & 0x3;
    set_reg(data, rows, row, decoder._f7_45, f7_45 ^ 0x1);
    true
}

fn apply_decode_format_imm_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(decoder) = active_decoder(cycle) else {
        return false;
    };
    let rd0 = get_reg(data, rows, row, decoder._rd_0) & 0x1;
    set_reg(data, rows, row, decoder._rd_0, rd0 ^ 0x1);
    true
}

fn apply_entrypoint_binding_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(pc_addr) = active_pc_addr(cycle) else {
        return false;
    };
    perturb_addr_decompose(data, rows, row, pc_addr);
    true
}

fn apply_exec_dest_binding_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let (Some(decoder), Some(write_rd)) = (active_decoder(cycle), active_write_rd(cycle)) else {
        return false;
    };
    let rd = get_decoded_reg(data, rows, row, decoder._rd_34, decoder._rd_12, decoder._rd_0);
    if rd == 0 {
        return false;
    }
    let next_rd = if rd < 31 { rd + 1 } else { 1 };
    set_decoded_reg(data, rows, row, decoder._rd_34, decoder._rd_12, decoder._rd_0, next_rd);
    retarget_write_rd(data, rows, row, write_rd, next_rd);
    true
}

fn apply_exec_op_selector_binding_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(decoded) = active_decoder(cycle) else {
        return false;
    };
    let opcode = get_reg(data, rows, row, decoded.opcode);
    let func3 = get_decoded_func3(data, rows, row, decoded._f3_2, decoded._f3_01);
    let func7 = get_decoded_func7(data, rows, row, decoded);
    let next_func3 = match (opcode, func3, func7) {
        (0b0110011, 0b000, 0b0000000)
        | (0b0110011, 0b010, 0b0000000)
        | (0b0110011, 0b011, 0b0000000)
        | (0b0110011, 0b100, 0b0000000)
        | (0b0110011, 0b101, 0b0000000)
        | (0b0110011, 0b110, 0b0000000)
        | (0b0110011, 0b111, 0b0000000) => Some(func3 ^ 0b001),
        (0b0010011, 0b000, _)
        | (0b0010011, 0b010, _)
        | (0b0010011, 0b011, _)
        | (0b0010011, 0b100, _)
        | (0b0010011, 0b110, _)
        | (0b0010011, 0b111, _) => Some(func3 ^ 0b001),
        (0b0110011, 0b100, 0b0000001)
        | (0b0110011, 0b101, 0b0000001)
        | (0b0110011, 0b110, 0b0000001)
        | (0b0110011, 0b111, 0b0000001) => Some(func3 ^ 0b010),
        (0b0000011, 0b000, _)
        | (0b0000011, 0b001, _)
        | (0b0000011, 0b100, _)
        | (0b0000011, 0b101, _) => Some(func3 ^ 0b100),
        (0b0100011, 0b000, _) | (0b0100011, 0b001, _) | (0b0100011, 0b010, _) => {
            Some(func3 ^ 0b001)
        }
        (0b1100011, 0b000, _)
        | (0b1100011, 0b001, _)
        | (0b1100011, 0b100, _)
        | (0b1100011, 0b101, _)
        | (0b1100011, 0b110, _)
        | (0b1100011, 0b111, _) => Some(func3 ^ 0b001),
        _ => None,
    };
    let Some(next_func3) = next_func3 else {
        return false;
    };
    set_decoded_func3(data, rows, row, decoded._f3_2, decoded._f3_01, next_func3);
    true
}

fn apply_exec_control_flow_binding_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(decoded) = active_decoder(cycle) else {
        return false;
    };
    let opcode = get_reg(data, rows, row, decoded.opcode);
    let func3 = get_decoded_func3(data, rows, row, decoded._f3_2, decoded._f3_01);
    if opcode == 0b1100011 {
        let next_func3 = match func3 {
            0b000 | 0b001 | 0b100 | 0b101 | 0b110 | 0b111 => Some(func3 ^ 0b001),
            _ => None,
        };
        let Some(next_func3) = next_func3 else {
            return false;
        };
        set_decoded_func3(data, rows, row, decoded._f3_2, decoded._f3_01, next_func3);
        return true;
    }
    if opcode == 0b1101111 {
        if bump_decoded_rd(data, rows, row, decoded) {
            return true;
        }
        let Some(pc_norm) = active_pc_norm(cycle) else {
            return false;
        };
        perturb_normalize_u32(data, rows, row, pc_norm);
        return true;
    }
    if opcode == 0b1100111 {
        let Some(rs1_layout) = active_rs1(cycle) else {
            return false;
        };
        let rs1 =
            get_decoded_reg(data, rows, row, decoded._rs1_34, decoded._rs1_12, decoded._rs1_0);
        if rs1 != 0 {
            set_decoded_reg(data, rows, row, decoded._rs1_34, decoded._rs1_12, decoded._rs1_0, 0);
            zero_read_reg(data, rows, row, rs1_layout);
            return true;
        }
    }
    let Some(pc_norm) = active_pc_norm(cycle) else {
        return false;
    };
    perturb_normalize_u32(data, rows, row, pc_norm);
    true
}

fn apply_exec_memory_effect_binding_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let (Some(decoded), Some(rs1_layout)) = (active_decoder(cycle), active_rs1(cycle)) else {
        return false;
    };
    let opcode = get_reg(data, rows, row, decoded.opcode);
    if opcode == 0b0100011 {
        let Some(rs2_layout) = active_rs2(cycle) else {
            return false;
        };
        let rs1 =
            get_decoded_reg(data, rows, row, decoded._rs1_34, decoded._rs1_12, decoded._rs1_0);
        let rs2 =
            get_decoded_reg(data, rows, row, decoded._rs2_34, decoded._rs2_12, decoded._rs2_0);
        if rs1 == rs2 {
            return false;
        }
        copy_decoded_reg(
            data,
            rows,
            row,
            decoded._rs1_34,
            decoded._rs1_12,
            decoded._rs1_0,
            decoded._rs2_34,
            decoded._rs2_12,
            decoded._rs2_0,
        );
        copy_read_reg(data, rows, row, rs1_layout, rs2_layout);
        return true;
    }
    if opcode == 0b0000011 {
        let rs1 =
            get_decoded_reg(data, rows, row, decoded._rs1_34, decoded._rs1_12, decoded._rs1_0);
        if rs1 == 0 {
            return false;
        }
        set_decoded_reg(data, rows, row, decoded._rs1_34, decoded._rs1_12, decoded._rs1_0, 0);
        zero_read_reg(data, rows, row, rs1_layout);
        return true;
    }
    false
}

fn apply_memory_address_pointer_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(addr) = active_memory_addr_bits(cycle) else {
        return false;
    };
    perturb_addr_decompose_bits(data, rows, row, addr);
    true
}

fn apply_memory_read_value_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(read) = active_memory_read(cycle) else {
        return false;
    };
    perturb_memory_arg_data_low(data, rows, row, read.io.new_txn);
    true
}

fn apply_memory_write_value_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(write) = active_memory_write(cycle) else {
        return false;
    };
    perturb_memory_arg_data_low(data, rows, row, write.io.new_txn);
    true
}

fn apply_memory_value_payload_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    if apply_memory_write_value_injection(data, rows, row, cycle) {
        return true;
    }
    apply_memory_read_value_injection(data, rows, row, cycle)
}

fn apply_memory_address_space_injection(
    kind: &str,
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let non_register_word = x0_word_addr().wrapping_sub(1);
    if kind.contains("domain=reg_write") {
        let Some(write_rd) = active_write_rd(cycle) else {
            return false;
        };
        retarget_write_rd_addr(data, rows, row, write_rd, non_register_word);
        return true;
    }
    if kind.contains("domain=reg_read") {
        if let Some(rs1) = active_rs1(cycle) {
            retarget_read_reg_addr(data, rows, row, rs1, non_register_word);
            return true;
        }
        if let Some(rs2) = active_rs2(cycle) {
            retarget_read_reg_addr(data, rows, row, rs2, non_register_word);
            return true;
        }
        return false;
    }

    let register_word = x0_word_addr();
    if kind.contains("domain=mem_write") {
        let Some(write) = active_memory_write(cycle) else {
            return false;
        };
        retarget_memory_arg_addr(data, rows, row, write.io.old_txn, register_word);
        retarget_memory_arg_addr(data, rows, row, write.io.new_txn, register_word);
        return true;
    }
    let Some(read) = active_memory_read(cycle) else {
        return false;
    };
    retarget_memory_arg_addr(data, rows, row, read.io.old_txn, register_word);
    retarget_memory_arg_addr(data, rows, row, read.io.new_txn, register_word);
    true
}

fn apply_memory_kind_selector_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(decoded) = active_decoder(cycle) else {
        return false;
    };
    let opcode = get_reg(data, rows, row, decoded.opcode);
    if opcode == 0b0000011 {
        set_reg(data, rows, row, decoded.opcode, 0b0100011);
        return true;
    }
    if opcode == 0b0100011 {
        set_reg(data, rows, row, decoded.opcode, 0b0000011);
        return true;
    }
    false
}

fn apply_time_monotonic_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    if let Some(write) = active_memory_write(cycle) {
        perturb_memory_arg_cycle(data, rows, row, write.io.old_txn);
        return true;
    }
    let Some(read) = active_memory_read(cycle) else {
        return false;
    };
    perturb_memory_arg_cycle(data, rows, row, read.io.old_txn);
    true
}

fn apply_active_write_data_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(write_rd) = active_write_rd(cycle) else {
        return false;
    };
    perturb_write_rd_data(data, rows, row, write_rd);
    true
}

fn apply_arithmetic_special_case_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(layout) = active_div_do_div(cycle) else {
        return false;
    };
    let quot_low = get_reg(data, rows, row, layout.quot_low);
    set_reg(data, rows, row, layout.quot_low, quot_low.wrapping_add(1) & 0xffff);
    true
}

fn apply_div_rem_bound_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    let Some(layout) = active_div_do_div(cycle) else {
        return false;
    };
    let quot = get_reg(data, rows, row, layout.quot_low)
        | (get_reg(data, rows, row, layout.quot_high) << 16);
    let rem = get_u16_reg(data, rows, row, layout.rem_low)
        | (get_u16_reg(data, rows, row, layout.rem_high) << 16);
    let Some(rs2) = active_rs2(cycle) else {
        return false;
    };
    let denom = read_reg_u32(data, rows, row, rs2);
    if denom == 0 || quot == 0 {
        return false;
    }
    let next_quot = quot.wrapping_sub(1);
    let next_rem = rem.wrapping_add(denom);
    set_reg(data, rows, row, layout.quot_low, next_quot & 0xffff);
    set_reg(data, rows, row, layout.quot_high, next_quot >> 16);
    set_u16_reg(data, rows, row, layout.rem_low, next_rem & 0xffff);
    set_u16_reg(data, rows, row, layout.rem_high, next_rem >> 16);
    true
}

fn apply_ecall_decomposition_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
    cycle: &RawPreflightCycle,
) -> bool {
    if cycle.major != major::ECALL0 || cycle.minor != ecall_minor::HOST_READ_SETUP {
        return false;
    }
    let out = LAYOUT_TOP.inst_result.arm8.output;
    let layout = out.arm2._super.len_decomp;
    let high = get_u16_reg(data, rows, row, layout.high);
    if high <= 1 {
        return false;
    }
    if get_reg(data, rows, row, layout.high_zero._super) != 0
        || get_reg(data, rows, row, layout.is_zero) != 0
    {
        return false;
    }
    set_decompose_low2_high_one(data, rows, row, layout);
    true
}

fn is_normal_insn_row(cycle: &RawPreflightCycle) -> bool {
    cycle.major <= major::MEM1
}

fn is_ecall_decomp_row(cycle: &RawPreflightCycle) -> bool {
    cycle.major == major::ECALL0 && cycle.minor == ecall_minor::HOST_READ_SETUP
}

fn is_ecall_register_write_row(cycle: &RawPreflightCycle) -> bool {
    cycle.major == major::ECALL0
        && matches!(cycle.minor, ecall_minor::HOST_READ_SETUP | ecall_minor::HOST_WRITE)
}

fn apply_injection(
    trace: &PreflightTrace,
    data: &MetaBuffer<CpuHal>,
    injection: Option<&BeakInjectionPlan>,
) -> bool {
    let Some(injection) = injection else {
        return false;
    };
    let target_step = if injection.step == u64::MAX { None } else { Some(injection.step as u32) };
    let mut slice = data.buf.as_slice_mut();
    let rows = data.rows;
    let mut applied = false;

    for (row, cycle) in trace.cycles.iter().enumerate() {
        if target_step.map(|step| cycle.user_cycle != step).unwrap_or(false) {
            continue;
        }
        debug_row(base_kind(&injection.kind), &slice, rows, row, cycle);
        match base_kind(&injection.kind) {
            KIND_ZERO_REGISTER => {
                if is_normal_insn_row(cycle) {
                    applied = apply_zero_register_injection(&mut slice, rows, row, cycle);
                    if applied {
                        break;
                    }
                }
                if is_ecall_register_write_row(cycle) {
                    applied = apply_ecall_zero_register_injection(&mut slice, rows, row, cycle);
                    if applied {
                        break;
                    }
                }
            }
            KIND_OPERAND_ROUTE => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_operand_route_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_RD_BITS => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_rd_bit_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_DECODE_FIELD_RANGE => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_decode_field_range_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_DECODE_IMM_SIGN => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_decode_imm_sign_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_DECODE_UPPER_IMM => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_decode_upper_imm_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_DECODE_FORMAT_IMM => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_decode_format_imm_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_ALU_IMM_LIMB
            | KIND_ALU_SHIFT_MOD32
            | KIND_ALU_CMP_BOOL
            | KIND_ALU_SUB_BORROW
            | KIND_ALU_CMP_AUX
            | KIND_ARITH_PRODUCT
            | KIND_ARITH_SIGNED_UNSIGNED_PRODUCT => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_active_write_data_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_ARITH_SPECIAL_CASE => {
                applied = apply_arithmetic_special_case_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_DIV_REM_BOUND => {
                applied = apply_div_rem_bound_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_ECALL_ARG_DECOMP => {
                if !is_ecall_decomp_row(cycle) {
                    continue;
                }
                applied = apply_ecall_decomposition_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_EXEC_SOURCE_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_exec_source_binding_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_EXEC_DEST_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_exec_dest_binding_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_EXEC_OP_SELECTOR_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_exec_op_selector_binding_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_EXEC_CONTROL_FLOW_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_exec_control_flow_binding_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_ENTRYPOINT_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_entrypoint_binding_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_EXEC_MEMORY_EFFECT_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_exec_memory_effect_binding_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_MEMORY_ADDRESS_POINTER => {
                applied = apply_memory_address_pointer_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_MEMORY_ADDRESS_SPACE => {
                applied = apply_memory_address_space_injection(
                    &injection.kind,
                    &mut slice,
                    rows,
                    row,
                    cycle,
                );
                if applied {
                    break;
                }
            }
            KIND_MEMORY_VALUE_PAYLOAD | KIND_MEMORY_INITIAL_VALUE | KIND_MEMORY_FINALIZATION => {
                applied = apply_memory_value_payload_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_MEMORY_STORE_LOAD_FLOW => {
                applied = apply_memory_write_value_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_MEMORY_KIND_SELECTOR => {
                applied = apply_memory_kind_selector_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            KIND_TIME_MONOTONIC => {
                applied = apply_time_monotonic_injection(&mut slice, rows, row, cycle);
                if applied {
                    break;
                }
            }
            _ => {}
        }
    }
    applied
}

pub fn prove_segment_with_injection(
    segment: &Segment,
    injection: Option<&BeakInjectionPlan>,
) -> Result<(Seal, bool)> {
    let mut rng = rand::thread_rng();
    let rand_z = ExtVal::random(&mut rng);

    let suite = Poseidon2HashSuite::new_suite();
    let hal = Rc::new(CpuHal::new(suite));
    let circuit_hal = Rc::new(CpuCircuitHal);

    let witgen = WitnessGenerator::new(
        hal.as_ref(),
        circuit_hal.as_ref(),
        segment,
        StepMode::Parallel,
        rand_z,
    )?;
    let applied = apply_injection(&witgen.trace, &witgen.data, injection);

    let code = &witgen.code.buf;
    let data = &witgen.data.buf;
    let global = &witgen.global.buf;

    let mut prover = Prover::new(hal.as_ref(), TAPSET);
    let hashfn = &hal.get_hash_suite().hashfn;
    prover.iop().write_u32_slice(&[RV32IM_SEAL_VERSION]);
    prover.iop().commit(&hashfn.hash_elem_slice(&PROOF_SYSTEM_INFO.encode()));
    prover.iop().commit(&hashfn.hash_elem_slice(&CircuitImpl::CIRCUIT_INFO.encode()));

    let global_len = global.size();
    let mut header = vec![Val::ZERO; global_len + 1];
    global.view_mut(|view| {
        for (idx, elem) in view.iter_mut().enumerate() {
            *elem = elem.valid_or_zero();
            header[idx] = *elem;
        }
        header[global_len] = Val::new_raw(segment.po2);
    });

    let header_digest = hashfn.hash_elem_slice(&header);
    prover.iop().commit(&header_digest);
    prover.iop().write_field_elem_slice(header.as_slice());
    prover.set_po2(segment.po2 as usize);
    prover.commit_group(REGISTER_GROUP_CODE, code);
    prover.commit_group(REGISTER_GROUP_DATA, data);

    let mix: [Val; REGCOUNT_MIX] = std::array::from_fn(|_| prover.iop().random_elem());
    let mix = witgen.accum(hal.as_ref(), circuit_hal.as_ref(), &mix)?;
    prover.commit_group(REGISTER_GROUP_ACCUM, &witgen.accum.buf);
    let seal = prover.finalize(&[&mix.buf, global], circuit_hal.as_ref());
    Ok((seal, applied))
}
