use std::collections::{HashMap, HashSet};

use beak_core::trace::observations::{
    ArithmeticSpecialCaseObservation, AuipcPcLimbObservation, BoundaryOriginObservation,
    ImmediateLimbObservation, MemoryAddressSpaceObservation, MemoryImmediateSignObservation,
    VolatileBoundaryObservation, XorMultiplicityObservation,
};
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic_matchers};
use serde_json::Value;

use crate::chip_row::{OpenVMChipRow, OpenVMChipRowKind, OpenVMChipRowPayload, Rs2Source};
use crate::insn::OpenVMInsn;
use crate::interaction::OpenVMInteraction;

#[derive(Debug, Clone)]
pub struct OpenVMTrace {
    instructions: Vec<OpenVMInsn>,
    chip_rows: Vec<OpenVMChipRow>,
    interactions: Vec<OpenVMInteraction>,

    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,

    // ---- Global seq -> vec index -------------------------------------------
    insn_by_seq: Vec<Option<usize>>,
    chip_row_by_seq: Vec<Option<usize>>,
    interaction_by_seq: Vec<Option<usize>>,

    // ---- step_idx -> vec index (1:1 for insn and chip_row) -----------------
    insn_by_step: Vec<Option<usize>>,
    // NOTE: chip rows are 1:N per step (one insn can touch multiple chips/rows).
    chip_rows_by_step: Vec<Vec<usize>>,

    // ---- step_idx -> vec of interaction indices (1:N) -----------------------
    interactions_by_step: Vec<Vec<usize>>,

    // ---- row_id / bus_kind -> interaction indices (no cloning) --------------
    interactions_by_row_id: HashMap<String, Vec<usize>>,
    interactions_by_bus: HashMap<crate::interaction::OpenVMInteractionKind, Vec<usize>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenVmMemoryObservationProfile {
    None,
    ImmediateSign,
    AddressSpace,
}

#[derive(Debug, Clone, Copy)]
struct OpenVmObservationProfile {
    emit_alu_immediate_limb_semantic: bool,
    emit_xor_multiplicity_semantic: bool,
    emit_auipc_pc_limb_semantic: bool,
    memory_semantic: OpenVmMemoryObservationProfile,
    emit_boundary_origin_semantic: bool,
    emit_volatile_boundary_semantic: bool,
    emit_arithmetic_special_case_semantic: bool,
}

fn kind_snake(kind: OpenVMChipRowKind) -> String {
    match serde_json::to_value(kind) {
        Ok(Value::String(s)) => s,
        _ => format!("{kind:?}").to_lowercase(),
    }
}

fn le_u32_from_bytes(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[..4]);
    Some(u32::from_le_bytes(arr))
}

fn rs2_imm_value(rs2: &Rs2Source) -> Option<i32> {
    match rs2 {
        Rs2Source::Imm { value } => Some(*value),
        Rs2Source::Reg { .. } => None,
    }
}

fn record_signal(
    signals: &mut Vec<TraceSignal>,
    seen: &mut HashSet<TraceSignal>,
    signal: TraceSignal,
) {
    if seen.insert(signal) {
        signals.push(signal);
    }
}

fn derive_semantic_feedback(
    trace: &OpenVMTrace,
    profile: OpenVmObservationProfile,
) -> (Vec<BucketHit>, Vec<TraceSignal>) {
    let mut signals = Vec::new();
    let mut seen_signals = HashSet::new();
    let mut immediate_limb = Vec::new();
    let mut xor_multiplicity = Vec::new();
    let mut auipc_pc_limb = Vec::new();
    let mut memory_immediate_sign = Vec::new();
    let mut memory_address_space = Vec::new();
    let mut boundary_origin = Vec::new();
    let mut volatile_boundary = Vec::new();
    let mut arithmetic_special_case = Vec::new();

    let mut saw_system_terminate = false;
    let mut saw_missing_row_timestamp = false;
    let mut saw_memory_access = false;

    for row in trace.chip_rows() {
        let base = row.base();
        let kind = kind_snake(row.kind);
        if base.timestamp.is_none() {
            saw_missing_row_timestamp = true;
        }
        if base.chip_name.contains("Volatile") {
            record_signal(
                &mut signals,
                &mut seen_signals,
                TraceSignal::ObservedVolatileBoundaryRange,
            );
            if profile.emit_volatile_boundary_semantic {
                volatile_boundary.push(VolatileBoundaryObservation {
                    step_idx: base.step_idx,
                    op_idx: base.op_idx,
                    kind: kind.clone(),
                    chip_name: base.chip_name.clone(),
                });
            }
        }

        match &row.payload {
            OpenVMChipRowPayload::BaseAlu { rs2, a, b, c, .. } => {
                if profile.emit_alu_immediate_limb_semantic {
                    if let Some(imm) = rs2_imm_value(rs2) {
                        immediate_limb.push(ImmediateLimbObservation {
                            step_idx: base.step_idx,
                            op_idx: base.op_idx,
                            kind: kind.clone(),
                            chip_name: base.chip_name.clone(),
                            imm,
                        });
                    }
                }
                if profile.emit_xor_multiplicity_semantic {
                    if let (Some(out), Some(lhs), Some(rhs)) =
                        (le_u32_from_bytes(a), le_u32_from_bytes(b), le_u32_from_bytes(c))
                    {
                        if out == (lhs ^ rhs) && (lhs & rhs) != 0 {
                            xor_multiplicity.push(XorMultiplicityObservation {
                                step_idx: base.step_idx,
                                op_idx: base.op_idx,
                                kind: kind.clone(),
                                chip_name: base.chip_name.clone(),
                                lhs,
                                rhs,
                            });
                        }
                    }
                }
            }
            OpenVMChipRowPayload::DivRem { b, c, .. } => {
                if profile.emit_arithmetic_special_case_semantic {
                    if let (Some(rs1), Some(rs2)) = (le_u32_from_bytes(b), le_u32_from_bytes(c)) {
                        if rs2 == 0 || (rs1 == 0x8000_0000 && rs2 == 0xFFFF_FFFF) {
                            arithmetic_special_case.push(ArithmeticSpecialCaseObservation {
                                step_idx: base.step_idx,
                                op_idx: base.op_idx,
                                rs1,
                                rs2,
                            });
                        }
                    }
                }
            }
            OpenVMChipRowPayload::Auipc { imm, from_pc, .. } => {
                if profile.emit_auipc_pc_limb_semantic {
                    auipc_pc_limb.push(AuipcPcLimbObservation {
                        step_idx: base.step_idx,
                        op_idx: base.op_idx,
                        kind: kind.clone(),
                        chip_name: base.chip_name.clone(),
                        from_pc: *from_pc,
                        imm: *imm,
                    });
                }
            }
            OpenVMChipRowPayload::LoadStore {
                imm,
                imm_sign,
                mem_as,
                is_store,
                is_load,
                ..
            } => {
                saw_memory_access = true;
                if *is_load {
                    record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoad);
                    record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoadStore);
                }
                if *is_store {
                    record_signal(&mut signals, &mut seen_signals, TraceSignal::HasStore);
                    record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoadStore);
                }
                match profile.memory_semantic {
                    OpenVmMemoryObservationProfile::ImmediateSign => {
                        memory_immediate_sign.push(MemoryImmediateSignObservation {
                            step_idx: base.step_idx,
                            op_idx: base.op_idx,
                            kind: kind.clone(),
                            chip_name: base.chip_name.clone(),
                            imm: *imm,
                            imm_sign: *imm_sign,
                        });
                    }
                    OpenVmMemoryObservationProfile::AddressSpace => {
                        memory_address_space.push(MemoryAddressSpaceObservation {
                            step_idx: base.step_idx,
                            op_idx: base.op_idx,
                            kind: kind.clone(),
                            chip_name: base.chip_name.clone(),
                            mem_as: *mem_as,
                        });
                    }
                    OpenVmMemoryObservationProfile::None => {}
                }
            }
            OpenVMChipRowPayload::LoadSignExtend { imm, imm_sign, mem_as, .. } => {
                saw_memory_access = true;
                record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoad);
                record_signal(&mut signals, &mut seen_signals, TraceSignal::HasLoadStore);
                match profile.memory_semantic {
                    OpenVmMemoryObservationProfile::ImmediateSign => {
                        memory_immediate_sign.push(MemoryImmediateSignObservation {
                            step_idx: base.step_idx,
                            op_idx: base.op_idx,
                            kind: kind.clone(),
                            chip_name: base.chip_name.clone(),
                            imm: *imm,
                            imm_sign: *imm_sign,
                        });
                    }
                    OpenVmMemoryObservationProfile::AddressSpace => {
                        memory_address_space.push(MemoryAddressSpaceObservation {
                            step_idx: base.step_idx,
                            op_idx: base.op_idx,
                            kind: kind.clone(),
                            chip_name: base.chip_name.clone(),
                            mem_as: *mem_as,
                        });
                    }
                    OpenVmMemoryObservationProfile::None => {}
                }
            }
            OpenVMChipRowPayload::Connector {
                from_timestamp,
                to_timestamp,
                is_terminate,
                ..
            } => {
                if *is_terminate {
                    saw_system_terminate = true;
                    record_signal(&mut signals, &mut seen_signals, TraceSignal::HasEcall);
                }
                if profile.emit_boundary_origin_semantic && matches!(from_timestamp, Some(0)) {
                    boundary_origin.push(BoundaryOriginObservation {
                        step_idx: base.step_idx,
                        op_idx: base.op_idx,
                        kind: kind.clone(),
                        chip_name: base.chip_name.clone(),
                        from_timestamp: *from_timestamp,
                        to_timestamp: *to_timestamp,
                        is_terminate: *is_terminate,
                    });
                }
            }
            _ => {}
        }
    }

    if profile.emit_boundary_origin_semantic
        && saw_system_terminate
        && saw_missing_row_timestamp
        && !saw_memory_access
    {
        boundary_origin.push(BoundaryOriginObservation {
            step_idx: 0,
            op_idx: 0,
            kind: "connector_fallback".to_string(),
            chip_name: "SystemConnector".to_string(),
            from_timestamp: Some(0),
            to_timestamp: None,
            is_terminate: true,
        });
    }

    let mut bucket_hits = Vec::new();
    bucket_hits.extend(semantic_matchers::match_immediate_limb_semantic_hits(&immediate_limb));
    bucket_hits.extend(semantic_matchers::match_xor_multiplicity_semantic_hits(&xor_multiplicity));
    bucket_hits.extend(semantic_matchers::match_auipc_pc_limb_semantic_hits(&auipc_pc_limb));
    bucket_hits
        .extend(semantic_matchers::match_memory_immediate_sign_semantic_hits(&memory_immediate_sign));
    bucket_hits
        .extend(semantic_matchers::match_memory_address_space_semantic_hits(&memory_address_space));
    bucket_hits.extend(semantic_matchers::match_boundary_origin_semantic_hits(&boundary_origin));
    bucket_hits
        .extend(semantic_matchers::match_volatile_boundary_semantic_hits(&volatile_boundary));
    bucket_hits.extend(
        semantic_matchers::match_arithmetic_special_case_semantic_hits(&arithmetic_special_case),
    );
    (bucket_hits, signals)
}

impl OpenVMTrace {
    fn ensure_len<T: Default + Clone>(v: &mut Vec<T>, idx: usize) {
        if v.len() <= idx {
            v.resize(idx + 1, T::default());
        }
    }

    /// Build an `OpenVMTrace` from fuzzer_utils emitted JSON logs.
    ///
    /// Each log entry is `{ "type": "instruction"|"chip_row"|"interaction", "data": {...} }`.
    pub fn from_logs(logs: Vec<Value>) -> Result<Self, String> {
        let mut instructions = Vec::new();
        let mut chip_rows = Vec::new();
        let mut interactions = Vec::new();

        for (idx, log) in logs.into_iter().enumerate() {
            let obj = log.as_object().ok_or_else(|| format!("log[{}]: not an object", idx))?;
            let ty = obj
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("log[{}]: missing or invalid \"type\"", idx))?;
            let data = obj
                .get("data")
                .cloned()
                .ok_or_else(|| format!("log[{}]: missing \"data\"", idx))?;

            match ty {
                "instruction" => {
                    let insn: OpenVMInsn = serde_json::from_value(data)
                        .map_err(|e| format!("log[{}] instruction: {}", idx, e))?;
                    instructions.push(insn);
                }
                "chip_row" => {
                    let row: OpenVMChipRow = serde_json::from_value(data)
                        .map_err(|e| format!("log[{}] chip_row: {}", idx, e))?;
                    chip_rows.push(row);
                }
                "interaction" => {
                    let ia: OpenVMInteraction = serde_json::from_value(data)
                        .map_err(|e| format!("log[{}] interaction: {}", idx, e))?;
                    interactions.push(ia);
                }
                _ => return Err(format!("log[{}]: unknown type \"{}\"", idx, ty)),
            }
        }

        Ok(Self::new(instructions, chip_rows, interactions))
    }
}

impl OpenVMTrace {
    /// Instructions, chip_rows, and interactions with index maps. Use `from_logs` to build from JSON.
    pub fn new(
        instructions: Vec<OpenVMInsn>,
        chip_rows: Vec<OpenVMChipRow>,
        interactions: Vec<OpenVMInteraction>,
    ) -> Self {
        let mut insn_by_seq: Vec<Option<usize>> = Vec::new();
        let mut chip_row_by_seq: Vec<Option<usize>> = Vec::new();
        let mut interaction_by_seq: Vec<Option<usize>> = Vec::new();

        let mut insn_by_step: Vec<Option<usize>> = Vec::new();
        let mut chip_rows_by_step: Vec<Vec<usize>> = Vec::new();
        let mut interactions_by_step: Vec<Vec<usize>> = Vec::new();

        let mut interactions_by_row_id: HashMap<String, Vec<usize>> = HashMap::new();
        let mut interactions_by_bus: HashMap<
            crate::interaction::OpenVMInteractionKind,
            Vec<usize>,
        > = HashMap::new();

        for (i, insn) in instructions.iter().enumerate() {
            let seq = insn.seq as usize;
            let step = insn.step_idx as usize;

            Self::ensure_len(&mut insn_by_seq, seq);
            assert!(insn_by_seq[seq].is_none(), "duplicate insn seq={}", seq);
            insn_by_seq[seq] = Some(i);

            Self::ensure_len(&mut insn_by_step, step);
            assert!(insn_by_step[step].is_none(), "duplicate insn step_idx={}", step);
            insn_by_step[step] = Some(i);
        }

        for (i, row) in chip_rows.iter().enumerate() {
            let b = row.base();
            let seq = b.seq as usize;
            let step = b.step_idx as usize;

            Self::ensure_len(&mut chip_row_by_seq, seq);
            assert!(chip_row_by_seq[seq].is_none(), "duplicate chip_row seq={}", seq);
            chip_row_by_seq[seq] = Some(i);

            Self::ensure_len(&mut chip_rows_by_step, step);
            // Enforce uniqueness of op_idx within a step.
            let op_idx = b.op_idx;
            if chip_rows_by_step[step].iter().any(|&j| chip_rows[j].base().op_idx == op_idx) {
                panic!("duplicate chip_row op_idx={} for step_idx={}", op_idx, step);
            }
            chip_rows_by_step[step].push(i);
        }

        for (i, ia) in interactions.iter().enumerate() {
            let b = ia.base();
            let seq = b.seq as usize;
            let step = b.step_idx as usize;

            Self::ensure_len(&mut interaction_by_seq, seq);
            assert!(interaction_by_seq[seq].is_none(), "duplicate interaction seq={}", seq);
            interaction_by_seq[seq] = Some(i);

            Self::ensure_len(&mut interactions_by_step, step);
            interactions_by_step[step].push(i);

            interactions_by_row_id.entry(b.row_id.clone()).or_default().push(i);
            interactions_by_bus.entry(b.kind).or_default().push(i);
        }

        let mut out = Self {
            instructions,
            chip_rows,
            interactions,
            bucket_hits: Vec::new(),
            trace_signals: Vec::new(),
            insn_by_seq,
            chip_row_by_seq,
            interaction_by_seq,
            insn_by_step,
            chip_rows_by_step,
            interactions_by_step,
            interactions_by_row_id,
            interactions_by_bus,
        };

        let (bucket_hits, trace_signals) = derive_semantic_feedback(
            &out,
            OpenVmObservationProfile {
                emit_alu_immediate_limb_semantic: true,
                emit_xor_multiplicity_semantic: true,
                emit_auipc_pc_limb_semantic: true,
                memory_semantic: OpenVmMemoryObservationProfile::ImmediateSign,
                emit_boundary_origin_semantic: false,
                emit_volatile_boundary_semantic: false,
                emit_arithmetic_special_case_semantic: true,
            },
        );
        out.bucket_hits = bucket_hits;
        out.trace_signals = trace_signals;
        out
    }

    pub fn instructions(&self) -> &[OpenVMInsn] {
        &self.instructions
    }

    pub fn chip_rows(&self) -> &[OpenVMChipRow] {
        &self.chip_rows
    }

    pub fn interactions(&self) -> &[OpenVMInteraction] {
        &self.interactions
    }

    pub fn get_instruction_global(&self, seq: usize) -> &OpenVMInsn {
        let i = self.insn_by_seq[seq].expect("missing insn for seq");
        &self.instructions[i]
    }

    pub fn get_chip_row_global(&self, seq: usize) -> &OpenVMChipRow {
        let i = self.chip_row_by_seq[seq].expect("missing chip_row for seq");
        &self.chip_rows[i]
    }

    pub fn get_interaction_global(&self, seq: usize) -> &OpenVMInteraction {
        let i = self.interaction_by_seq[seq].expect("missing interaction for seq");
        &self.interactions[i]
    }

    pub fn get_instruction_in_step(&self, step_idx: usize, op_idx: usize) -> &OpenVMInsn {
        assert_eq!(op_idx, 0, "OpenVMInsn is 1-per-step; op_idx must be 0");
        let i = self.insn_by_step[step_idx].expect("missing insn for step");
        &self.instructions[i]
    }

    pub fn get_chip_row_in_step(&self, step_idx: usize, op_idx: usize) -> &OpenVMChipRow {
        let indices = self
            .chip_rows_by_step
            .get(step_idx)
            .unwrap_or_else(|| panic!("missing chip_rows for step={}", step_idx));
        let i = indices
            .iter()
            .find(|&&idx| self.chip_rows[idx].base().op_idx == op_idx as u64)
            .copied()
            .unwrap_or_else(|| panic!("missing chip_row for step={}, op_idx={}", step_idx, op_idx));
        &self.chip_rows[i]
    }

    pub fn get_interaction_in_step(&self, step_idx: usize, op_idx: usize) -> &OpenVMInteraction {
        let indices = &self.interactions_by_step[step_idx];
        let i = indices
            .iter()
            .find(|&&idx| self.interactions[idx].base().op_idx == op_idx as u64)
            .copied()
            .unwrap_or_else(|| {
                panic!("missing interaction for step={}, op_idx={}", step_idx, op_idx)
            });
        &self.interactions[i]
    }

    /// Slice of interactions for a row_id.
    ///
    /// Note: this is currently not implemented (would require allocation to materialize a slice of
    /// references). Prefer `interaction_indices_by_row_id` / `interactions_for_step` instead.
    pub fn get_interactions_by_row_id(&self, _row_id: &str) -> &[OpenVMInteraction] {
        &[]
    }

    /// Slice of interactions for a table_id.
    ///
    /// Note: currently not implemented; keep the API surface minimal until we settle on a stable
    /// table-id taxonomy.
    pub fn get_interactions_by_table_id(&self, _table_id: &str) -> &[OpenVMInteraction] {
        &[]
    }
}

impl OpenVMTrace {
    /// All chip row indices for a given step (zero-copy).
    pub fn chip_row_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.chip_rows_by_step.get(step_idx).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// All interaction indices for a given step (zero-copy).
    pub fn interaction_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.interactions_by_step.get(step_idx).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// All interaction indices produced by a specific chip row.
    pub fn interaction_indices_by_row_id(&self, row_id: &str) -> &[usize] {
        self.interactions_by_row_id.get(row_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// All interaction indices on a specific bus (interaction kind).
    pub fn interaction_indices_by_bus(
        &self,
        kind: crate::interaction::OpenVMInteractionKind,
    ) -> &[usize] {
        self.interactions_by_bus.get(&kind).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Iterate over all interactions for a step, yielding references.
    pub fn interactions_for_step(
        &self,
        step_idx: usize,
    ) -> impl Iterator<Item = &OpenVMInteraction> {
        self.interaction_indices_for_step(step_idx).iter().map(|&i| &self.interactions[i])
    }

    /// Iterate over all chip rows for a step, yielding references.
    pub fn chip_rows_for_step(&self, step_idx: usize) -> impl Iterator<Item = &OpenVMChipRow> {
        self.chip_row_indices_for_step(step_idx).iter().map(|&i| &self.chip_rows[i])
    }

    /// Number of instructions in this trace (for micro_op_count / feedback).
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}

impl Trace for OpenVMTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }

    fn trace_signals(&self) -> &[TraceSignal] {
        &self.trace_signals
    }
}
