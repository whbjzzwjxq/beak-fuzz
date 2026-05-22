use std::mem::size_of;

use anyhow::Result;
use bytemuck::Pod;

use super::{Seal, SegmentContext, segment_prover};
use crate::execute::{platform::LOOKUP_TABLE_CYCLES, segment::Segment};
use risc0_circuit_rv32im_sys::{
    BlockType, EcallReadWitness, EcallTerminateWitness, EcallWriteWitness, InstAuipcWitness,
    InstBranchWitness, InstImmWitness, InstJalWitness, InstJalrWitness, InstLoadWitness,
    InstLuiWitness, InstRegWitness, InstStoreWitness, PhysMemReadWitness, PhysMemWriteWitness,
    UnitDivWitness,
};

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

#[derive(Clone, Debug)]
pub struct BeakInjectionPlan {
    pub kind: String,
    pub step: u64,
}

#[derive(Debug)]
struct TxnCollector {
    txns: Vec<BeakPreflightMemoryTxn>,
    next_txn_idx: u64,
}

impl TxnCollector {
    fn new() -> Self {
        Self { txns: Vec::new(), next_txn_idx: 0 }
    }

    fn push_read(
        &mut self,
        row_idx: u64,
        row_step_idx: u64,
        row_pc: u32,
        machine_mode: u8,
        read: PhysMemReadWitness,
    ) {
        let txn_idx = self.next_txn_idx;
        self.next_txn_idx += 1;
        self.txns.push(BeakPreflightMemoryTxn {
            row_idx,
            row_step_idx,
            row_pc,
            major: 0,
            minor: 0,
            machine_mode,
            txn_idx,
            row_txn_start: txn_idx,
            row_txn_end: txn_idx + 1,
            addr_word: read.wordAddr,
            txn_cycle: (row_step_idx as u32).saturating_mul(2),
            word: read.value,
            prev_cycle: read.prevCycle,
            prev_word: read.value,
            is_load: true,
            is_store: false,
        });
    }

    fn push_write(
        &mut self,
        row_idx: u64,
        row_step_idx: u64,
        row_pc: u32,
        machine_mode: u8,
        write: PhysMemWriteWitness,
    ) {
        let txn_idx = self.next_txn_idx;
        self.next_txn_idx += 1;
        self.txns.push(BeakPreflightMemoryTxn {
            row_idx,
            row_step_idx,
            row_pc,
            major: 0,
            minor: 0,
            machine_mode,
            txn_idx,
            row_txn_start: txn_idx,
            row_txn_end: txn_idx + 1,
            addr_word: write.wordAddr,
            txn_cycle: (row_step_idx as u32).saturating_mul(2).saturating_add(1),
            word: write.value,
            prev_cycle: write.prevCycle,
            prev_word: write.prevValue,
            is_load: false,
            is_store: true,
        });
    }
}

fn base_kind(kind: &str) -> &str {
    kind.split_once("::").map(|(base, _)| base).unwrap_or(kind)
}

fn is_supported_kind(kind: &str) -> bool {
    matches!(
        base_kind(kind),
        "risc0.semantic.decode.zero_register_immutability"
            | "risc0.semantic.decode.operand_index_routing"
            | "risc0.semantic.exec.dest_binding"
            | "risc0.semantic.memory.store_load_payload_flow"
            | "risc0.semantic.memory.load_value_binding"
            | "risc0.semantic.memory.write_payload_consistency"
            | "risc0.semantic.time.monotonic_access_ordering"
            | "risc0.semantic.arithmetic.division_remainder_bound"
            | "risc0.semantic.control.ecall_argument_decomposition"
    )
}

pub fn collect_preflight_trace_records(segment: &Segment) -> Result<BeakPreflightTraceRecords> {
    let segment_ctx = SegmentContext::new(segment)?;
    let preflight = segment_ctx.preflight(segment.po2 as usize)?;
    let total_rows = preflight.row_info.len() as u64;
    let mut txns = TxnCollector::new();

    collect_inst_reg_txns(&preflight, &mut txns);
    collect_inst_imm_txns(&preflight, &mut txns);
    collect_inst_load_txns(&preflight, &mut txns);
    collect_inst_store_txns(&preflight, &mut txns);
    collect_inst_branch_txns(&preflight, &mut txns);
    collect_inst_jal_txns(&preflight, &mut txns);
    collect_inst_jalr_txns(&preflight, &mut txns);
    collect_inst_lui_txns(&preflight, &mut txns);
    collect_inst_auipc_txns(&preflight, &mut txns);

    Ok(BeakPreflightTraceRecords {
        table_split_cycle: segment.used_rows as u64,
        padding_start_row: segment.used_rows as u64,
        total_rows,
        lookup_table_rows: LOOKUP_TABLE_CYCLES as u64,
        txns: txns.txns,
    })
}

fn witness_ref<WitnessT: Pod>(aux: &[u32], start: usize) -> &WitnessT {
    let words = size_of::<WitnessT>() / size_of::<u32>();
    &bytemuck::cast_slice::<u32, WitnessT>(&aux[start..start + words])[0]
}

fn witness_mut<WitnessT: Pod>(aux: &mut [u32], start: usize) -> &mut WitnessT {
    let words = size_of::<WitnessT>() / size_of::<u32>();
    &mut bytemuck::cast_slice_mut::<u32, WitnessT>(&mut aux[start..start + words])[0]
}

fn block_starts<WitnessT: Pod>(
    preflight: &super::PreflightContext,
    block_type: BlockType,
    pred: impl Fn(&WitnessT) -> bool,
) -> Vec<usize> {
    let words = size_of::<WitnessT>() / size_of::<u32>();
    let mut starts = Vec::new();
    for row in &preflight.row_info {
        if BlockType::try_from(row.row_type).ok() != Some(block_type) {
            continue;
        }
        let row_start = row.aux_offset as usize;
        for i in 0..row.block_count as usize {
            let start = row_start + i * words;
            if start + words <= preflight.aux.len() && pred(witness_ref(&preflight.aux, start)) {
                starts.push(start);
            }
        }
    }
    starts
}

fn visit_blocks<WitnessT: Pod>(
    preflight: &super::PreflightContext,
    block_type: BlockType,
    mut visit: impl FnMut(u64, usize, &WitnessT),
) {
    let words = size_of::<WitnessT>() / size_of::<u32>();
    for (row_idx, row) in preflight.row_info.iter().enumerate() {
        if BlockType::try_from(row.row_type).ok() != Some(block_type) {
            continue;
        }
        let row_start = row.aux_offset as usize;
        for i in 0..row.block_count as usize {
            let start = row_start + i * words;
            if start + words <= preflight.aux.len() {
                visit(row_idx as u64, i, witness_ref(&preflight.aux, start));
            }
        }
    }
}

fn collect_inst_reg_txns(preflight: &super::PreflightContext, txns: &mut TxnCollector) {
    visit_blocks::<InstRegWitness>(preflight, BlockType::InstReg, |row_idx, _, wit| {
        let step = wit.cycle as u64;
        let mode = wit.fetch.mode as u8;
        txns.push_read(row_idx, step, wit.fetch.pc, mode, wit.rs1);
        txns.push_read(row_idx, step, wit.fetch.pc, mode, wit.rs2);
        txns.push_write(row_idx, step, wit.fetch.pc, mode, wit.rd);
    });
}

fn collect_inst_imm_txns(preflight: &super::PreflightContext, txns: &mut TxnCollector) {
    visit_blocks::<InstImmWitness>(preflight, BlockType::InstImm, |row_idx, _, wit| {
        let step = wit.cycle as u64;
        let mode = wit.fetch.mode as u8;
        txns.push_read(row_idx, step, wit.fetch.pc, mode, wit.rs1);
        txns.push_write(row_idx, step, wit.fetch.pc, mode, wit.rd);
    });
}

fn collect_inst_load_txns(preflight: &super::PreflightContext, txns: &mut TxnCollector) {
    visit_blocks::<InstLoadWitness>(preflight, BlockType::InstLoad, |row_idx, _, wit| {
        let step = wit.cycle as u64;
        let mode = wit.fetch.mode as u8;
        txns.push_read(row_idx, step, wit.fetch.pc, mode, wit.rs1);
        txns.push_read(row_idx, step, wit.fetch.pc, mode, wit.mem);
        txns.push_write(row_idx, step, wit.fetch.pc, mode, wit.rd);
    });
}

fn collect_inst_store_txns(preflight: &super::PreflightContext, txns: &mut TxnCollector) {
    visit_blocks::<InstStoreWitness>(preflight, BlockType::InstStore, |row_idx, _, wit| {
        let step = wit.cycle as u64;
        let mode = wit.fetch.mode as u8;
        txns.push_read(row_idx, step, wit.fetch.pc, mode, wit.rs1);
        txns.push_read(row_idx, step, wit.fetch.pc, mode, wit.rs2);
        txns.push_write(row_idx, step, wit.fetch.pc, mode, wit.mem);
    });
}

fn collect_inst_branch_txns(preflight: &super::PreflightContext, txns: &mut TxnCollector) {
    visit_blocks::<InstBranchWitness>(preflight, BlockType::InstBranch, |row_idx, _, wit| {
        let step = wit.cycle as u64;
        let mode = wit.fetch.mode as u8;
        txns.push_read(row_idx, step, wit.fetch.pc, mode, wit.rs1);
        txns.push_read(row_idx, step, wit.fetch.pc, mode, wit.rs2);
    });
}

fn collect_inst_jal_txns(preflight: &super::PreflightContext, txns: &mut TxnCollector) {
    visit_blocks::<InstJalWitness>(preflight, BlockType::InstJal, |row_idx, _, wit| {
        txns.push_write(row_idx, wit.cycle as u64, wit.fetch.pc, wit.fetch.mode as u8, wit.rd);
    });
}

fn collect_inst_jalr_txns(preflight: &super::PreflightContext, txns: &mut TxnCollector) {
    visit_blocks::<InstJalrWitness>(preflight, BlockType::InstJalr, |row_idx, _, wit| {
        let step = wit.cycle as u64;
        let mode = wit.fetch.mode as u8;
        txns.push_read(row_idx, step, wit.fetch.pc, mode, wit.rs1);
        txns.push_write(row_idx, step, wit.fetch.pc, mode, wit.rd);
    });
}

fn collect_inst_lui_txns(preflight: &super::PreflightContext, txns: &mut TxnCollector) {
    visit_blocks::<InstLuiWitness>(preflight, BlockType::InstLui, |row_idx, _, wit| {
        txns.push_write(row_idx, wit.cycle as u64, wit.fetch.pc, wit.fetch.mode as u8, wit.rd);
    });
}

fn collect_inst_auipc_txns(preflight: &super::PreflightContext, txns: &mut TxnCollector) {
    visit_blocks::<InstAuipcWitness>(preflight, BlockType::InstAuipc, |row_idx, _, wit| {
        txns.push_write(row_idx, wit.cycle as u64, wit.fetch.pc, wit.fetch.mode as u8, wit.rd);
    });
}

fn choose_start(starts: &[usize], step: u64) -> Option<usize> {
    if starts.is_empty() {
        return None;
    }
    let idx = if step == u64::MAX { 0 } else { (step as usize).min(starts.len() - 1) };
    Some(starts[idx])
}

fn cycle_matches(_step: u64, _cycle: u32) -> bool {
    // RISC0 M3 witness cycles are not normalized to Beak op_idx. Keep this
    // hook type-local, and only map kinds whose matching block is smoke-proven.
    true
}

fn mutate_block<WitnessT: Pod>(
    preflight: &mut super::PreflightContext,
    block_type: BlockType,
    step: u64,
    pred: impl Fn(&WitnessT) -> bool,
    mutate: impl FnOnce(&mut WitnessT) -> String,
) -> Option<String> {
    let start = choose_start(&block_starts::<WitnessT>(preflight, block_type, pred), step)?;
    let desc = mutate(witness_mut::<WitnessT>(&mut preflight.aux, start));
    Some(format!("block={} aux_idx={} {}", block_type.name(), start, desc))
}

fn bump_u32(value: &mut u32) -> String {
    let old = *value;
    *value = if old == u32::MAX { old - 1 } else { old + 1 };
    format!("old=0x{old:08x} new=0x{:08x}", *value)
}

fn rd_is_x0_shadow(rd: &PhysMemWriteWitness) -> bool {
    rd.wordAddr & 31 == 0
}

fn mutate_inst_rd_value(
    preflight: &mut super::PreflightContext,
    step: u64,
    x0_only: bool,
) -> Option<String> {
    macro_rules! try_inst {
        ($block:expr, $wit:ty) => {
            if let Some(desc) = mutate_block::<$wit>(
                preflight,
                $block,
                step,
                |wit| cycle_matches(step, wit.cycle) && (!x0_only || rd_is_x0_shadow(&wit.rd)),
                |wit| bump_u32(&mut wit.rd.value),
            ) {
                return Some(desc);
            }
        };
    }
    try_inst!(BlockType::InstReg, InstRegWitness);
    try_inst!(BlockType::InstImm, InstImmWitness);
    try_inst!(BlockType::InstLoad, InstLoadWitness);
    try_inst!(BlockType::InstJal, InstJalWitness);
    try_inst!(BlockType::InstJalr, InstJalrWitness);
    try_inst!(BlockType::InstLui, InstLuiWitness);
    try_inst!(BlockType::InstAuipc, InstAuipcWitness);
    None
}

fn mutate_ecall_arg(preflight: &mut super::PreflightContext, step: u64) -> Option<String> {
    if let Some(desc) = mutate_block::<EcallTerminateWitness>(
        preflight,
        BlockType::EcallTerminate,
        step,
        |wit| cycle_matches(step, wit.cycle),
        |wit| bump_u32(&mut wit.a1.value),
    ) {
        return Some(desc);
    }
    if let Some(desc) = mutate_block::<EcallReadWitness>(
        preflight,
        BlockType::EcallRead,
        step,
        |wit| cycle_matches(step, wit.cycle),
        |wit| bump_u32(&mut wit.a2.value),
    ) {
        return Some(desc);
    }
    mutate_block::<EcallWriteWitness>(
        preflight,
        BlockType::EcallWrite,
        step,
        |wit| cycle_matches(step, wit.cycle),
        |wit| bump_u32(&mut wit.a2.value),
    )
}

fn mutate_load_mem_value(preflight: &mut super::PreflightContext, step: u64) -> Option<String> {
    mutate_block::<InstLoadWitness>(
        preflight,
        BlockType::InstLoad,
        step,
        |wit| cycle_matches(step, wit.cycle),
        |wit| bump_u32(&mut wit.mem.value),
    )
}

fn mutate_store_mem_value(preflight: &mut super::PreflightContext, step: u64) -> Option<String> {
    mutate_block::<InstStoreWitness>(
        preflight,
        BlockType::InstStore,
        step,
        |wit| cycle_matches(step, wit.cycle),
        |wit| bump_u32(&mut wit.mem.value),
    )
}

fn mutate_load_prev_cycle(preflight: &mut super::PreflightContext, step: u64) -> Option<String> {
    mutate_block::<InstLoadWitness>(
        preflight,
        BlockType::InstLoad,
        step,
        |wit| cycle_matches(step, wit.cycle),
        |wit| bump_u32(&mut wit.mem.prevCycle),
    )
}

fn apply_supported_injection(
    preflight: &mut super::PreflightContext,
    kind: &str,
    step: u64,
) -> Option<String> {
    match kind {
        "risc0.semantic.decode.zero_register_immutability" => {
            mutate_inst_rd_value(preflight, step, true)
        }
        "risc0.semantic.exec.dest_binding" => mutate_inst_rd_value(preflight, step, false),
        "risc0.semantic.decode.operand_index_routing" => mutate_block::<InstRegWitness>(
            preflight,
            BlockType::InstReg,
            step,
            |wit| cycle_matches(step, wit.cycle),
            |wit| bump_u32(&mut wit.rs2.wordAddr),
        )
        .or_else(|| {
            mutate_block::<InstBranchWitness>(
                preflight,
                BlockType::InstBranch,
                step,
                |wit| cycle_matches(step, wit.cycle),
                |wit| bump_u32(&mut wit.rs2.wordAddr),
            )
        }),
        "risc0.semantic.arithmetic.division_remainder_bound" => mutate_block::<UnitDivWitness>(
            preflight,
            BlockType::UnitDiv,
            step,
            |wit| wit.count != 0,
            |wit| bump_u32(&mut wit.out1),
        ),
        "risc0.semantic.memory.store_load_payload_flow"
        | "risc0.semantic.memory.load_value_binding" => mutate_load_mem_value(preflight, step),
        "risc0.semantic.memory.write_payload_consistency" => {
            mutate_store_mem_value(preflight, step)
        }
        "risc0.semantic.time.monotonic_access_ordering" => {
            mutate_load_prev_cycle(preflight, step)
        }
        "risc0.semantic.control.ecall_argument_decomposition" => mutate_ecall_arg(preflight, step),
        _ => None,
    }
}

fn apply_injection(
    preflight: &mut super::PreflightContext,
    injection: Option<&BeakInjectionPlan>,
) -> bool {
    let Some(injection) = injection else {
        return false;
    };
    if !is_supported_kind(&injection.kind) || preflight.aux.is_empty() {
        return false;
    }

    let Some(desc) =
        apply_supported_injection(preflight, base_kind(&injection.kind), injection.step)
    else {
        return false;
    };
    eprintln!(
        "[beak-risc0-m3] witness injection applied kind={} step={} {}",
        base_kind(&injection.kind),
        injection.step,
        desc,
    );
    true
}

pub fn prove_segment_with_injection(
    segment: &Segment,
    injection: Option<&BeakInjectionPlan>,
) -> Result<(Seal, bool)> {
    let segment_ctx = SegmentContext::new(segment)?;
    let mut preflight = segment_ctx.preflight(segment.po2 as usize)?;
    let applied = apply_injection(&mut preflight, injection);
    let prover = segment_prover(segment.po2 as usize)?;
    match prover.prove(&preflight) {
        Ok(seal) => Ok((seal, applied)),
        Err(err) if applied => {
            eprintln!("[beak-risc0-m3] prover rejected injected witness: {err}");
            Ok((Vec::new(), true))
        }
        Err(err) => Err(err),
    }
}
