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
    Seal,
    hal::{
        MetaBuffer, StepMode,
        cpu::CpuCircuitHal,
    },
    witgen::{WitnessGenerator, preflight::PreflightTrace},
};
use crate::{
    RV32IM_SEAL_VERSION,
    execute::{
        platform::{MACHINE_REGS_ADDR, ecall_minor, major},
        segment::Segment,
    },
    zirgen::{
        CircuitImpl,
        circuit::{
            CircuitField, DecomposeLow2Layout, DoDivLayout, ExtVal, IsForwardLayout, MemoryArgLayout,
            MemoryWriteLayout, NondetRegLayout, NondetU16RegLayout, ReadRegLayout, REGCOUNT_MIX,
            REGISTER_GROUP_ACCUM, REGISTER_GROUP_CODE, REGISTER_GROUP_DATA, Val, LAYOUT_TOP,
        },
        taps::TAPSET,
    },
};

type CpuHal = risc0_zkp::hal::cpu::CpuHal<CircuitField>;

const KIND_ZERO_REGISTER: &str = "risc0.semantic.decode.zero_register_immutability";
const KIND_OPERAND_ROUTE: &str = "risc0.semantic.decode.operand_index_routing";
const KIND_RD_BITS: &str = "risc0.semantic.decode.rd_bit_decomposition";
const KIND_DIV_REM_BOUND: &str = "risc0.semantic.arithmetic.division_remainder_bound";
const KIND_ECALL_ARG_DECOMP: &str = "risc0.semantic.control.ecall_argument_decomposition";
const KIND_EXEC_SOURCE_BINDING: &str = "risc0.semantic.exec.source_operand_binding";
const KIND_EXEC_DEST_BINDING: &str = "risc0.semantic.exec.dest_binding";
const KIND_EXEC_OP_SELECTOR_BINDING: &str = "risc0.semantic.exec.op_selector_binding";
const KIND_EXEC_CONTROL_FLOW_BINDING: &str = "risc0.semantic.exec.control_flow_binding";
const KIND_EXEC_MEMORY_EFFECT_BINDING: &str = "risc0.semantic.exec.memory_effect_binding";

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

fn get_decoded_reg(
    data: &[Val],
    rows: usize,
    row: usize,
    bits34: &NondetRegLayout,
    bits12: &NondetRegLayout,
    bit0: &NondetRegLayout,
) -> u32 {
    get_reg(data, rows, row, bits34) * 8
        + get_reg(data, rows, row, bits12) * 2
        + get_reg(data, rows, row, bit0)
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

fn get_decoded_func3(data: &[Val], rows: usize, row: usize, f3_2: &NondetRegLayout, f3_01: &NondetRegLayout) -> u32 {
    get_reg(data, rows, row, f3_2) * 4 + get_reg(data, rows, row, f3_01)
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

fn get_decoded_func7(data: &[Val], rows: usize, row: usize, decoded: &crate::zirgen::circuit::DecoderLayout) -> u32 {
    get_reg(data, rows, row, decoded._f7_6) * 64
        + get_reg(data, rows, row, decoded._f7_45) * 16
        + get_reg(data, rows, row, decoded._f7_23) * 4
        + get_reg(data, rows, row, decoded._f7_01)
}

fn retarget_write_rd(data: &mut [Val], rows: usize, row: usize, rd: u32) {
    let write_rd = LAYOUT_TOP.inst_result.arm4._1;
    let addr = reg_word_addr(rd);
    set_reg(data, rows, row, write_rd.write_addr, addr);
    set_reg(data, rows, row, write_rd._0.io.old_txn.addr, addr);
    set_reg(data, rows, row, write_rd._0.io.new_txn.addr, addr);
    set_reg(data, rows, row, write_rd.is_rd0._super, u32::from(rd == 0));
    set_reg(data, rows, row, write_rd.is_rd0.inv, if rd == 0 { 0 } else { 1 });
}

fn set_decompose_low2(
    data: &mut [Val],
    rows: usize,
    row: usize,
    layout: &DecomposeLow2Layout,
    high: u32,
    low2: u32,
) {
    set_u16_reg(data, rows, row, layout.high, high);
    set_reg(data, rows, row, layout.low2, low2 & 0x3);
    for (idx, bit) in layout.low2_hot._super.iter().enumerate() {
        set_reg(data, rows, row, bit, u32::from(idx as u32 == (low2 & 0x3)));
    }
    let high_is_zero = u32::from(high == 0);
    set_reg(data, rows, row, layout.high_zero._super, high_is_zero);
    set_reg(data, rows, row, layout.high_zero.inv, if high == 0 { 0 } else { 1 });
    let is_zero = u32::from(high == 0 && (low2 & 0x3) == 0);
    set_reg(data, rows, row, layout.is_zero, is_zero);
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

fn debug_row(label: &str, data: &[Val], rows: usize, row: usize, cycle: &RawPreflightCycle) {
    if !debug_injection_enabled() {
        return;
    }

    let minor = &LAYOUT_TOP.inst_input.minor_onehot._super;
    let active_minor = minor
        .iter()
        .enumerate()
        .filter_map(|(idx, layout)| (read_u32(data, rows, row, layout._super.offset) == 1).then_some(idx))
        .collect::<Vec<_>>();
    let decoder = LAYOUT_TOP.inst_result.arm4.input.decoded._super;
    let write_rd = LAYOUT_TOP.inst_result.arm4._1;
    let rs1 = LAYOUT_TOP.inst_result.arm4.input.rs1;
    let rs2 = LAYOUT_TOP.inst_result.arm4.input.rs2;
    let div_layout = active_div_do_div(cycle);

    eprintln!(
        "[beak-risc0-debug] {label} row={row} step={} pc=0x{:08x} major={} minor={} active_minor={active_minor:?} rd12={} rd0={} write_addr=0x{:08x} rs1_low=0x{:04x} rs1_high=0x{:04x} rs2_low=0x{:04x} rs2_high=0x{:04x} has_div_layout={}",
        cycle.user_cycle,
        cycle.pc,
        cycle.major,
        cycle.minor,
        get_reg(data, rows, row, decoder._rd_12),
        get_reg(data, rows, row, decoder._rd_0),
        get_reg(data, rows, row, write_rd.write_addr),
        read_reg_u32(data, rows, row, rs1),
        0,
        read_reg_u32(data, rows, row, rs2),
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

fn apply_zero_register_injection(data: &mut [Val], rows: usize, row: usize) {
    let x0_word_addr = x0_word_addr();
    let write_rd = LAYOUT_TOP.inst_result.arm4._1;
    set_reg(data, rows, row, write_rd.write_addr, x0_word_addr);
    set_reg(data, rows, row, write_rd._0.io.old_txn.addr, x0_word_addr);
    set_reg(data, rows, row, write_rd._0.io.new_txn.addr, x0_word_addr);
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

fn apply_operand_route_injection(data: &mut [Val], rows: usize, row: usize) {
    let input = LAYOUT_TOP.inst_result.arm4.input;
    let decoded = input.decoded._super;
    copy_decoded_reg(
        data,
        rows,
        row,
        decoded._rs2_34,
        decoded._rs2_12,
        decoded._rs2_0,
        decoded._rs1_34,
        decoded._rs1_12,
        decoded._rs1_0,
    );
    copy_read_reg(data, rows, row, input.rs2, input.rs1);
}

fn apply_exec_source_binding_injection(data: &mut [Val], rows: usize, row: usize) {
    apply_operand_route_injection(data, rows, row);
}

fn apply_rd_bit_injection(data: &mut [Val], rows: usize, row: usize) -> bool {
    let decoder = LAYOUT_TOP.inst_result.arm4.input.decoded._super;
    let rd = get_decoded_reg(data, rows, row, decoder._rd_34, decoder._rd_12, decoder._rd_0);
    let next_rd = if rd < 31 {
        rd + 1
    } else if rd > 0 {
        rd - 1
    } else {
        return false;
    };
    set_decoded_reg(
        data,
        rows,
        row,
        decoder._rd_34,
        decoder._rd_12,
        decoder._rd_0,
        next_rd,
    );
    true
}

fn apply_exec_dest_binding_injection(data: &mut [Val], rows: usize, row: usize) -> bool {
    let decoder = LAYOUT_TOP.inst_result.arm4.input.decoded._super;
    let rd = get_decoded_reg(data, rows, row, decoder._rd_34, decoder._rd_12, decoder._rd_0);
    if rd == 0 {
        return false;
    }
    let next_rd = if rd < 31 { rd + 1 } else { 1 };
    set_decoded_reg(
        data,
        rows,
        row,
        decoder._rd_34,
        decoder._rd_12,
        decoder._rd_0,
        next_rd,
    );
    retarget_write_rd(data, rows, row, next_rd);
    true
}

fn apply_exec_op_selector_binding_injection(data: &mut [Val], rows: usize, row: usize) -> bool {
    let decoded = LAYOUT_TOP.inst_result.arm4.input.decoded._super;
    let opcode = get_reg(data, rows, row, decoded.opcode);
    let func3 = get_decoded_func3(data, rows, row, decoded._f3_2, decoded._f3_01);
    let func7 = get_decoded_func7(data, rows, row, decoded);
    let next_func3 = match (opcode, func3, func7) {
        (0b0110011, 0b100, 0b0000001)
        | (0b0110011, 0b101, 0b0000001)
        | (0b0110011, 0b110, 0b0000001)
        | (0b0110011, 0b111, 0b0000001) => Some(func3 ^ 0b010),
        (0b0000011, 0b000, _) | (0b0000011, 0b001, _) | (0b0000011, 0b100, _) | (0b0000011, 0b101, _) => {
            Some(func3 ^ 0b100)
        }
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
) -> bool {
    let input = LAYOUT_TOP.inst_result.arm4.input;
    let decoded = input.decoded._super;
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
    if opcode == 0b1100111 {
        let rs1 = get_decoded_reg(data, rows, row, decoded._rs1_34, decoded._rs1_12, decoded._rs1_0);
        if rs1 == 0 {
            return false;
        }
        set_decoded_reg(
            data,
            rows,
            row,
            decoded._rs1_34,
            decoded._rs1_12,
            decoded._rs1_0,
            0,
        );
        zero_read_reg(data, rows, row, input.rs1);
        return true;
    }
    false
}

fn apply_exec_memory_effect_binding_injection(
    data: &mut [Val],
    rows: usize,
    row: usize,
) -> bool {
    let input = LAYOUT_TOP.inst_result.arm4.input;
    let decoded = input.decoded._super;
    let opcode = get_reg(data, rows, row, decoded.opcode);
    if opcode == 0b0100011 {
        let rs1 = get_decoded_reg(data, rows, row, decoded._rs1_34, decoded._rs1_12, decoded._rs1_0);
        let rs2 = get_decoded_reg(data, rows, row, decoded._rs2_34, decoded._rs2_12, decoded._rs2_0);
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
        copy_read_reg(data, rows, row, input.rs1, input.rs2);
        return true;
    }
    if opcode == 0b0000011 {
        let rs1 = get_decoded_reg(data, rows, row, decoded._rs1_34, decoded._rs1_12, decoded._rs1_0);
        if rs1 == 0 {
            return false;
        }
        set_decoded_reg(
            data,
            rows,
            row,
            decoded._rs1_34,
            decoded._rs1_12,
            decoded._rs1_0,
            0,
        );
        zero_read_reg(data, rows, row, input.rs1);
        return true;
    }
    false
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
    let quot =
        get_reg(data, rows, row, layout.quot_low) | (get_reg(data, rows, row, layout.quot_high) << 16);
    let rem = get_u16_reg(data, rows, row, layout.rem_low)
        | (get_u16_reg(data, rows, row, layout.rem_high) << 16);
    let denom = read_reg_u32(data, rows, row, LAYOUT_TOP.inst_result.arm4.input.rs2);
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

fn apply_ecall_decomposition_injection(data: &mut [Val], rows: usize, row: usize) {
    let out = LAYOUT_TOP.inst_result.arm8.output;
    set_decompose_low2(data, rows, row, out.arm2._super.ptr_decomp, 0, 1);
    set_decompose_low2(data, rows, row, out.arm2._super.len_decomp, 0, 1);
    set_decompose_low2(data, rows, row, out.arm4._super.len_decomp, 0, 1);
    set_decompose_low2(data, rows, row, out.arm5._super.len_decomp, 0, 1);
    set_decompose_low2(data, rows, row, out.arm5._super.words_decomp, 0, 1);
}

fn is_normal_insn_row(cycle: &RawPreflightCycle) -> bool {
    cycle.major <= major::MEM1
}

fn is_ecall_decomp_row(cycle: &RawPreflightCycle) -> bool {
    cycle.major == major::ECALL0
        && matches!(
            cycle.minor,
            ecall_minor::HOST_READ_SETUP
                | ecall_minor::HOST_READ_BYTES
                | ecall_minor::HOST_READ_WORDS
        )
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
    let target_step = if injection.step == u64::MAX {
        None
    } else {
        Some(injection.step as u32)
    };
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
                    apply_zero_register_injection(&mut slice, rows, row);
                    applied = true;
                    break;
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
                apply_operand_route_injection(&mut slice, rows, row);
                applied = true;
                break;
            }
            KIND_RD_BITS => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_rd_bit_injection(&mut slice, rows, row);
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
                apply_ecall_decomposition_injection(&mut slice, rows, row);
                applied = true;
                break;
            }
            KIND_EXEC_SOURCE_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                apply_exec_source_binding_injection(&mut slice, rows, row);
                applied = true;
                break;
            }
            KIND_EXEC_DEST_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_exec_dest_binding_injection(&mut slice, rows, row);
                if applied {
                    break;
                }
            }
            KIND_EXEC_OP_SELECTOR_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_exec_op_selector_binding_injection(&mut slice, rows, row);
                if applied {
                    break;
                }
            }
            KIND_EXEC_CONTROL_FLOW_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_exec_control_flow_binding_injection(&mut slice, rows, row);
                if applied {
                    break;
                }
            }
            KIND_EXEC_MEMORY_EFFECT_BINDING => {
                if !is_normal_insn_row(cycle) {
                    continue;
                }
                applied = apply_exec_memory_effect_binding_injection(&mut slice, rows, row);
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
    prover
        .iop()
        .commit(&hashfn.hash_elem_slice(&PROOF_SYSTEM_INFO.encode()));
    prover
        .iop()
        .commit(&hashfn.hash_elem_slice(&CircuitImpl::CIRCUIT_INFO.encode()));

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
