use std::collections::HashMap;

use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::observations::{SequenceInsnObservation, SequenceSemanticMatcherProfile};
use beak_core::trace::{semantic, semantic_matchers, BucketHit, Trace, TraceSignal};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::chip_row::{PicoChipRow, PicoChipRowBase, PicoChipRowKind, PicoChipRowPayload};
use crate::insn::PicoInsn;
use crate::interaction::{
    InteractionDirection, PicoInteraction, PicoInteractionBase, PicoInteractionKind,
    PicoInteractionPayload,
};

pub const PICO_COMMIT: &str = "45e74ccd62758c6d67239913956e749adaba261c";
const PICO_HALT_SYSCALL_ID: u32 = 0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PicoExecutedInsn {
    pub step_idx: u64,
    pub chunk: u32,
    pub clk: u32,
    pub pc: u32,
    pub next_pc: u32,
    pub word: u32,
    pub opcode: String,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub memory: Option<u32>,
    #[serde(default)]
    pub ecall_syscall_id: Option<u32>,
    #[serde(default)]
    pub ecall_operand_to_check: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct PicoTrace {
    instructions: Vec<PicoInsn>,
    chip_rows: Vec<PicoChipRow>,
    interactions: Vec<PicoInteraction>,
    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,

    insn_by_step: Vec<Option<usize>>,
    chip_rows_by_step: Vec<Vec<usize>>,
    interactions_by_step: Vec<Vec<usize>>,
    interactions_by_row_id: HashMap<String, Vec<usize>>,
}

impl PicoTrace {
    fn ensure_len<T: Default + Clone>(v: &mut Vec<T>, idx: usize) {
        if v.len() <= idx {
            v.resize(idx + 1, T::default());
        }
    }

    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        let executed = words
            .iter()
            .enumerate()
            .map(|(step_idx, &word)| PicoExecutedInsn {
                step_idx: step_idx as u64,
                chunk: 0,
                clk: step_idx as u32,
                pc: (step_idx as u32).wrapping_mul(4),
                next_pc: (step_idx as u32).wrapping_add(1).wrapping_mul(4),
                word,
                opcode: String::new(),
                a: 0,
                b: 0,
                c: 0,
                memory: None,
                ecall_syscall_id: None,
                ecall_operand_to_check: None,
            })
            .collect::<Vec<_>>();
        Self::from_executed(&executed)
    }

    pub fn from_executed(executed: &[PicoExecutedInsn]) -> Result<Self, String> {
        let mut instructions = Vec::new();
        let mut chip_rows = Vec::new();
        let mut interactions = Vec::new();

        let mut seq = 0u64;

        for event in executed {
            let step_idx = event.step_idx as usize;
            let word = event.word;
            let dec = RV32IMInstruction::decode_with_pc(word, event.pc)
                .ok_or_else(|| format!("decode failed at step {step_idx}"))?;

            let mut insn =
                PicoInsn::from_decoded(seq, event.step_idx, event.pc, event.clk, dec.clone());
            insn.next_pc = event.next_pc;
            insn.chunk = Some(event.chunk);
            insn.runtime_a = Some(event.a);
            insn.runtime_b = Some(event.b);
            insn.runtime_c = Some(event.c);
            insn.memory_value = event.memory;
            insn.ecall_syscall_id = event.ecall_syscall_id;
            insn.ecall_operand_to_check = event.ecall_operand_to_check;
            instructions.push(insn.clone());
            seq = seq.saturating_add(1);

            let cpu_row = PicoChipRow {
                base: PicoChipRowBase {
                    seq,
                    step_idx: event.step_idx,
                    op_idx: 0,
                    is_valid: true,
                    timestamp: Some(event.clk),
                    chip_name: "pico_cpu".to_string(),
                },
                kind: PicoChipRowKind::Cpu,
                payload: PicoChipRowPayload::Cpu {
                    mnemonic: dec.mnemonic.clone(),
                    rd: dec.rd,
                    rs1: dec.rs1,
                    rs2: dec.rs2,
                    imm: dec.imm,
                },
            };
            chip_rows.push(cpu_row);
            seq = seq.saturating_add(1);

            let row_id = format!("step{}_cpu0", step_idx);
            interactions.push(PicoInteraction {
                base: PicoInteractionBase {
                    seq,
                    step_idx: event.step_idx,
                    op_idx: 0,
                    row_id: row_id.clone(),
                    direction: InteractionDirection::Send,
                    kind: PicoInteractionKind::Execution,
                    timestamp: Some(event.clk),
                },
                payload: PicoInteractionPayload::Execution { pc: event.pc },
            });
            seq = seq.saturating_add(1);

            if matches!(
                dec.mnemonic.as_str(),
                "lb" | "lh" | "lw" | "lbu" | "lhu" | "sb" | "sh" | "sw"
            ) {
                let mem_row = PicoChipRow {
                    base: PicoChipRowBase {
                        seq,
                        step_idx: event.step_idx,
                        op_idx: 1,
                        is_valid: true,
                        timestamp: Some(event.clk),
                        chip_name: "pico_memory".to_string(),
                    },
                    kind: PicoChipRowKind::Memory,
                    payload: PicoChipRowPayload::Memory {
                        is_load: matches!(
                            dec.mnemonic.as_str(),
                            "lb" | "lh" | "lw" | "lbu" | "lhu"
                        ),
                        is_store: matches!(dec.mnemonic.as_str(), "sb" | "sh" | "sw"),
                        base_reg: dec.rs1,
                        offset: dec.imm,
                    },
                };
                chip_rows.push(mem_row);
                seq = seq.saturating_add(1);

                let effective_addr = dec.imm.map(|imm| event.b.wrapping_add(imm as u32));
                interactions.push(PicoInteraction {
                    base: PicoInteractionBase {
                        seq,
                        step_idx: event.step_idx,
                        op_idx: 1,
                        row_id: format!("step{}_mem1", step_idx),
                        direction: InteractionDirection::Send,
                        kind: PicoInteractionKind::Memory,
                        timestamp: Some(event.clk),
                    },
                    payload: PicoInteractionPayload::Memory { effective_addr },
                });
                seq = seq.saturating_add(1);
            }
        }

        Ok(Self::new(instructions, chip_rows, interactions))
    }

    pub fn new(
        instructions: Vec<PicoInsn>,
        chip_rows: Vec<PicoChipRow>,
        interactions: Vec<PicoInteraction>,
    ) -> Self {
        let mut insn_by_step = Vec::<Option<usize>>::new();
        let mut chip_rows_by_step = Vec::<Vec<usize>>::new();
        let mut interactions_by_step = Vec::<Vec<usize>>::new();
        let mut interactions_by_row_id = HashMap::<String, Vec<usize>>::new();

        for (i, insn) in instructions.iter().enumerate() {
            let step = insn.step_idx as usize;
            Self::ensure_len(&mut insn_by_step, step);
            insn_by_step[step] = Some(i);
        }
        for (i, row) in chip_rows.iter().enumerate() {
            let step = row.base().step_idx as usize;
            Self::ensure_len(&mut chip_rows_by_step, step);
            chip_rows_by_step[step].push(i);
        }
        for (i, ia) in interactions.iter().enumerate() {
            let step = ia.base().step_idx as usize;
            Self::ensure_len(&mut interactions_by_step, step);
            interactions_by_step[step].push(i);
            interactions_by_row_id.entry(ia.base().row_id.clone()).or_default().push(i);
        }

        let mut out = Self {
            instructions,
            chip_rows,
            interactions,
            bucket_hits: Vec::new(),
            trace_signals: Vec::new(),
            insn_by_step,
            chip_rows_by_step,
            interactions_by_step,
            interactions_by_row_id,
        };
        let insns = out
            .instructions()
            .iter()
            .map(|insn| SequenceInsnObservation {
                step_idx: insn.step_idx,
                word: insn.word,
                mnemonic: insn.mnemonic.clone(),
                rs1: insn.rs1,
                imm: insn.imm,
            })
            .collect::<Vec<_>>();
        out.trace_signals = semantic_matchers::sequence_trace_signals(&insns);
        out.bucket_hits = semantic_matchers::match_sequence_semantic_hits(
            SequenceSemanticMatcherProfile {
                emit_padding_interaction_send: false,
                emit_boolean_on_store: false,
                emit_boolean_on_load_after_store: true,
                emit_kind_selector: false,
                emit_digest_route: false,
                emit_control_flow_bindings: true,
                emit_memory_alignment: false,
                emit_memory_address_progression: false,
                emit_load_value_binding: false,
                emit_opcode_selector_bindings: true,
                emit_partial_word_write: false,
                emit_ecall_word_validity: true,
            },
            &insns,
        );
        out.emit_pico_semantic_hits();
        out.enrich_semantic_hits();
        out
    }

    fn emit_pico_semantic_hits(&mut self) {
        let mut last_mem_access = HashMap::<u32, (u64, u32)>::new();
        let insns = self.instructions.clone();
        for insn in &insns {
            self.emit_instruction_semantics(insn);
            if let Some((addr, width, is_load, is_store)) = self.memory_shape_for_insn(insn) {
                self.emit_memory_semantics(
                    insn,
                    addr,
                    width,
                    is_load,
                    is_store,
                    &mut last_mem_access,
                );
            }
        }
        if let Some(first) = insns.first() {
            self.push_hit(
                semantic::control::ENTRYPOINT_BINDING,
                first,
                "cf4",
                "cf4.default_entry",
                "control",
            );
            self.push_hit(
                semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
                first,
                "ts1",
                "ts1.standard",
                "time",
            );
            self.push_hit(
                semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
                first,
                "ts3",
                "ts3.standard",
                "time",
            );
        }
    }

    fn emit_instruction_semantics(&mut self, insn: &PicoInsn) {
        self.push_hit(semantic::decode::FIELD_RANGE, insn, "id1", id1_cell(insn), "instruction");
        self.push_hit(
            semantic::exec::OP_SELECTOR_BINDING,
            insn,
            "id4",
            id4_cell(insn),
            "instruction",
        );

        if let Some(cell) = id2_cell(insn) {
            self.push_hit(
                semantic::decode::IMMEDIATE_SIGN_EXTENSION,
                insn,
                "id2",
                cell,
                "instruction",
            );
        }
        if let Some(cell) = id3_cell(insn) {
            self.push_hit(
                semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION,
                insn,
                "id3",
                cell,
                "instruction",
            );
        }
        if let Some(cell) = id5_cell(insn) {
            self.push_hit(
                semantic::decode::FORMAT_IMMEDIATE_REASSEMBLY,
                insn,
                "id5",
                cell,
                "instruction",
            );
        }
        if let Some(cell) = rf2_cell(insn) {
            self.push_hit(
                semantic::decode::OPERAND_INDEX_ROUTING,
                insn,
                "rf2",
                cell,
                "instruction",
            );
        }
        if let Some(cell) = write_source_cell(insn, "rf1") {
            if insn.rd == Some(0) {
                self.push_hit(
                    semantic::decode::ZERO_REGISTER_IMMUTABILITY,
                    insn,
                    "rf1",
                    cell,
                    "instruction",
                );
            }
        }
        if let Some(cell) = write_source_cell(insn, "rf3") {
            if insn.rd.is_some_and(|rd| rd != 0) {
                self.push_hit(semantic::exec::DEST_BINDING, insn, "rf3", cell, "instruction");
            }
        }
        if matches!(insn.mnemonic.as_str(), "slti" | "sltiu") {
            self.push_hit(
                semantic::alu::COMPARISON_BOOLEANITY,
                insn,
                "al3",
                al3_cell(insn),
                "instruction",
            );
            self.push_hit(
                semantic::alu::COMPARISON_AUXILIARY_CHAIN,
                insn,
                "al5",
                "al5.first_limb_diff",
                "instruction",
            );
        }
        match insn.mnemonic.as_str() {
            "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai" => {
                self.push_hit(
                    semantic::alu::IMMEDIATE_LIMB_CONSISTENCY,
                    insn,
                    "al1",
                    al1_cell(insn),
                    "instruction",
                );
            }
            "sll" | "srl" | "sra" => {
                self.push_hit(
                    semantic::alu::SHIFT_MOD32,
                    insn,
                    "al2",
                    al2_cell(insn),
                    "instruction",
                );
            }
            "slt" | "sltu" => {
                self.push_hit(
                    semantic::alu::COMPARISON_BOOLEANITY,
                    insn,
                    "al3",
                    al3_cell(insn),
                    "instruction",
                );
                self.push_hit(
                    semantic::alu::COMPARISON_AUXILIARY_CHAIN,
                    insn,
                    "al5",
                    "al5.first_limb_diff",
                    "instruction",
                );
            }
            "sub" => {
                self.push_hit(
                    semantic::alu::SUBTRACTION_BORROW_CHAIN,
                    insn,
                    "al4",
                    "al4.no_borrow",
                    "instruction",
                );
            }
            "div" | "divu" | "rem" | "remu" => {
                if let Some((obligation_id, cell_id)) = div_special_cell(insn) {
                    self.push_hit(
                        semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                        insn,
                        obligation_id,
                        cell_id,
                        "instruction",
                    );
                }
                self.push_hit(
                    semantic::arithmetic::DIVISION_REMAINDER_BOUND,
                    insn,
                    "md3",
                    md3_cell(insn),
                    "instruction",
                );
            }
            "mul" | "mulh" | "mulhu" => {
                self.push_hit(
                    semantic::arithmetic::PRODUCT_DECOMPOSITION,
                    insn,
                    "md4",
                    md4_cell(insn),
                    "instruction",
                );
            }
            "mulhsu" => {
                self.push_hit(
                    semantic::arithmetic::PRODUCT_DECOMPOSITION,
                    insn,
                    "md4",
                    "md4.mulh_pn",
                    "instruction",
                );
                self.push_hit(
                    semantic::arithmetic::SIGNED_UNSIGNED_PRODUCT_CORRECTION,
                    insn,
                    "md5",
                    "md5.pos_any",
                    "instruction",
                );
            }
            "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
                self.push_hit(
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    "cf1",
                    cf1_cell(insn),
                    "instruction",
                );
            }
            "jal" => {
                self.push_hit(
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    "cf2",
                    if insn.rd == Some(0) { "cf2.jal_x0" } else { "cf2.jal_rd" },
                    "instruction",
                );
            }
            "jalr" => {
                self.push_hit(
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    "cf2",
                    if insn.rd == Some(0) { "cf2.jalr_x0" } else { "cf2.jalr_rd" },
                    "instruction",
                );
                self.push_hit(
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    "cf3",
                    cf3_cell(insn),
                    "instruction",
                );
            }
            "ecall" => {
                self.push_ecall_argument_hit(insn);
                self.push_hit(
                    semantic::control::ECALL_WORD_VALIDITY,
                    insn,
                    "cf7",
                    "cf7.standard",
                    "instruction",
                );
            }
            _ if !matches!(
                insn.mnemonic.as_str(),
                "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "jal" | "jalr" | "ecall"
            ) =>
            {
                self.push_hit(
                    semantic::exec::CONTROL_FLOW_BINDING,
                    insn,
                    "cf6",
                    "cf6.normal",
                    "instruction",
                );
            }
            _ => {}
        }
    }

    fn memory_shape_for_insn(&self, insn: &PicoInsn) -> Option<(u32, u8, bool, bool)> {
        let width = match insn.mnemonic.as_str() {
            "lb" | "lbu" | "sb" => 1,
            "lh" | "lhu" | "sh" => 2,
            "lw" | "sw" => 4,
            _ => return None,
        };
        let base_plus_imm = insn.runtime_b?.wrapping_add(insn.imm.unwrap_or(0) as u32);
        let is_load = matches!(insn.mnemonic.as_str(), "lb" | "lh" | "lw" | "lbu" | "lhu");
        Some((base_plus_imm, width, is_load, !is_load))
    }

    fn emit_memory_semantics(
        &mut self,
        insn: &PicoInsn,
        addr: u32,
        width: u8,
        is_load: bool,
        is_store: bool,
        last_mem_access: &mut HashMap<u32, (u64, u32)>,
    ) {
        if width > 1 {
            self.push_hit(
                semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                insn,
                "me2",
                me2_cell(addr, width, is_load),
                "memory",
            );
        }
        if width < 4 {
            self.push_hit(
                semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY,
                insn,
                "me9",
                me9_cell(addr),
                "memory",
            );
        }
        self.push_hit(
            semantic::memory::ADDRESS_SPACE_CONSISTENCY,
            insn,
            "me5",
            if is_load { "me5.mem_read" } else { "me5.mem_write" },
            "memory",
        );
        self.push_hit(
            semantic::memory::KIND_SELECTOR_CONSISTENCY,
            insn,
            "me10",
            if is_load { "me10.load" } else { "me10.store" },
            "memory",
        );
        if is_load {
            self.push_hit(
                semantic::memory::LOAD_VALUE_BINDING,
                insn,
                "me3",
                me3_cell(insn),
                "memory",
            );
            if let Some((prev_step, prev_clk)) = last_mem_access.get(&addr).copied() {
                let mut details = base_details(insn, "ts2", "ts2.small_gap", "time");
                details.insert("prev_step_idx".to_string(), json!(prev_step));
                details.insert("prev_timestamp".to_string(), json!(prev_clk));
                details.insert("timestamp".to_string(), json!(insn.timestamp));
                details.insert("effective_addr".to_string(), json!(addr));
                self.bucket_hits
                    .push(BucketHit::semantic(semantic::time::MONOTONIC_ACCESS_ORDERING, details));
                self.push_hit(
                    semantic::memory::STORE_LOAD_PAYLOAD_FLOW,
                    insn,
                    "me1",
                    me1_cell(width),
                    "memory",
                );
            }
        } else if is_store {
            self.push_hit(
                semantic::memory::WRITE_PAYLOAD_CONSISTENCY,
                insn,
                "me4",
                me4_cell(addr, width),
                "memory",
            );
        }
        if addr >= u32::MAX.saturating_sub(4) {
            self.push_hit(
                semantic::memory::ADDRESS_BOUNDARY_RANGE,
                insn,
                "me6",
                me6_cell(insn),
                "memory",
            );
        }
        last_mem_access.insert(addr, (insn.step_idx, insn.timestamp));
    }

    fn push_hit(
        &mut self,
        bucket: semantic::SemanticBucket,
        insn: &PicoInsn,
        obligation_id: &str,
        cell_id: &str,
        trace_source: &str,
    ) {
        self.bucket_hits.push(BucketHit::semantic(
            bucket,
            base_details(insn, obligation_id, cell_id, trace_source),
        ));
    }

    fn push_ecall_argument_hit(&mut self, insn: &PicoInsn) {
        let mut details = base_details(insn, "cf5", cf5_cell(insn), "instruction");
        details.insert("semantic_family".to_string(), json!("ecall_argument_decomposition"));
        details.insert("syscall_id".to_string(), json!(insn.ecall_syscall_id));
        details.insert("syscall_nr".to_string(), json!(insn.ecall_syscall_id));
        details.insert("operand_to_check".to_string(), json!(insn.ecall_operand_to_check));
        details.insert(
            "operand_range_check_enabled".to_string(),
            json!(insn.ecall_operand_to_check.is_some()),
        );
        details.insert("pico_syscall_register".to_string(), json!("x5"));
        details.insert("pico_halt_syscall_id".to_string(), json!(PICO_HALT_SYSCALL_ID));
        details.insert("op_b".to_string(), json!(insn.runtime_b));
        details.insert("op_c".to_string(), json!(insn.runtime_c));
        details.insert("a0".to_string(), json!(insn.runtime_b));
        details.insert("a1".to_string(), json!(insn.runtime_c));
        for idx in 2..=7 {
            details.insert(format!("a{idx}"), Value::Null);
        }
        self.bucket_hits
            .push(BucketHit::semantic(semantic::control::ECALL_ARGUMENT_DECOMPOSITION, details));
    }

    fn enrich_semantic_hits(&mut self) {
        let insns_by_step =
            self.instructions.iter().map(|insn| (insn.step_idx, insn)).collect::<HashMap<_, _>>();
        for hit in &mut self.bucket_hits {
            if hit.details.contains_key("backend") {
                continue;
            }
            let step = hit
                .details
                .get("step_idx")
                .and_then(Value::as_u64)
                .or_else(|| hit.details.get("op_idx").and_then(Value::as_u64));
            if let Some(insn) = step.and_then(|s| insns_by_step.get(&s).copied()) {
                for (k, v) in base_details_for_bucket(&hit.bucket_id, insn) {
                    hit.details.entry(k).or_insert(v);
                }
            }
        }
    }

    pub fn instructions(&self) -> &[PicoInsn] {
        &self.instructions
    }

    pub fn chip_rows(&self) -> &[PicoChipRow] {
        &self.chip_rows
    }

    pub fn interactions(&self) -> &[PicoInteraction] {
        &self.interactions
    }

    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    pub fn get_instruction_in_step(&self, step_idx: usize, op_idx: usize) -> &PicoInsn {
        assert_eq!(op_idx, 0, "PicoInsn is 1-per-step; op_idx must be 0");
        let i = self.insn_by_step[step_idx].expect("missing instruction for step");
        &self.instructions[i]
    }

    pub fn chip_row_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.chip_rows_by_step.get(step_idx).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn interaction_indices_for_step(&self, step_idx: usize) -> &[usize] {
        self.interactions_by_step.get(step_idx).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn interaction_indices_by_row_id(&self, row_id: &str) -> &[usize] {
        self.interactions_by_row_id.get(row_id).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

fn base_details(
    insn: &PicoInsn,
    obligation_id: &str,
    cell_id: &str,
    trace_source: &str,
) -> HashMap<String, Value> {
    let mut details = HashMap::new();
    details.insert("obligation_id".to_string(), json!(obligation_id));
    details.insert("cell_id".to_string(), json!(cell_id));
    details.insert("op_idx".to_string(), json!(insn.step_idx));
    details.insert("step_idx".to_string(), json!(insn.step_idx));
    details.insert("pc".to_string(), json!(insn.pc));
    details.insert("opcode".to_string(), json!(insn.word));
    details.insert("mnemonic".to_string(), json!(insn.mnemonic));
    details.insert("rd".to_string(), json!(insn.rd));
    details.insert("rs1".to_string(), json!(insn.rs1));
    details.insert("rs2".to_string(), json!(insn.rs2));
    details.insert("imm".to_string(), json!(insn.imm));
    details.insert("chunk".to_string(), json!(insn.chunk));
    details.insert("runtime_a".to_string(), json!(insn.runtime_a));
    details.insert("runtime_b".to_string(), json!(insn.runtime_b));
    details.insert("runtime_c".to_string(), json!(insn.runtime_c));
    details.insert("memory_value".to_string(), json!(insn.memory_value));
    details.insert("backend".to_string(), json!("pico"));
    details.insert("commit".to_string(), json!(PICO_COMMIT));
    details.insert("trace_source".to_string(), json!(trace_source));
    details
}

fn base_details_for_bucket(bucket_id: &str, insn: &PicoInsn) -> HashMap<String, Value> {
    let (obligation_id, cell_id, trace_source) = match bucket_id {
        id if id == semantic::memory::TIMESTAMPED_LOAD_PATH.id => {
            ("ts2", "ts2.small_gap", "memory")
        }
        id if id == semantic::lookup::BOOLEAN_MULTIPLICITY.id => ("bu1", "bu1.real_row", "bus"),
        id if id == semantic::exec::OP_SELECTOR_BINDING.id => {
            ("id4", id4_cell(insn), "instruction")
        }
        id if id == semantic::control::ECALL_WORD_VALIDITY.id => {
            ("cf7", "cf7.standard", "instruction")
        }
        id if id == semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id => {
            ("cf5", cf5_cell(insn), "instruction")
        }
        id if id == semantic::exec::CONTROL_FLOW_BINDING.id => ("cf6", "cf6.normal", "instruction"),
        id if id == semantic::memory::LOAD_VALUE_BINDING.id => ("me3", me3_cell(insn), "memory"),
        id if id == semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY.id => {
            ("me2", "me2.byte_any", "memory")
        }
        id if id == semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY.id => {
            ("me9", "me9.off0", "memory")
        }
        _ => ("unknown", "unknown", "instruction"),
    };
    base_details(insn, obligation_id, cell_id, trace_source)
}

fn cf5_cell(insn: &PicoInsn) -> &'static str {
    if insn.ecall_syscall_id == Some(PICO_HALT_SYSCALL_ID) || insn.ecall_operand_to_check.is_some()
    {
        "cf5.halt"
    } else {
        "cf5.operand_to_check_word"
    }
}

fn id1_cell(insn: &PicoInsn) -> &'static str {
    if [insn.rd, insn.rs1, insn.rs2].into_iter().flatten().any(|r| r == 31) {
        "id1.reg_max"
    } else if [insn.rd, insn.rs1, insn.rs2].into_iter().flatten().any(|r| r == 0) {
        "id1.reg_zero"
    } else if ((insn.word >> 12) & 7) == 7 || ((insn.word >> 25) & 0x7f) == 0x7f {
        "id1.funct_max"
    } else {
        "id1.reg_mid"
    }
}

fn id2_cell(insn: &PicoInsn) -> Option<&'static str> {
    let neg = insn.imm.unwrap_or(0) < 0;
    match insn.mnemonic.as_str() {
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai" | "lb"
        | "lh" | "lw" | "lbu" | "lhu" | "jalr" => Some(if neg { "id2.i_neg" } else { "id2.i_pos" }),
        "sb" | "sh" | "sw" => Some(if neg { "id2.s_neg" } else { "id2.s_pos" }),
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
            Some(if neg { "id2.b_neg" } else { "id2.b_pos" })
        }
        "jal" => Some(if neg { "id2.j_neg" } else { "id2.j_pos" }),
        _ => None,
    }
}

fn id3_cell(insn: &PicoInsn) -> Option<&'static str> {
    let imm20 = (insn.word >> 12) & 0x000f_ffff;
    match insn.mnemonic.as_str() {
        "lui" if imm20 == 0 => Some("id3.lui_zero"),
        "lui" if imm20 == 0x000f_ffff => Some("id3.lui_max"),
        "lui" => Some("id3.lui_mid"),
        "auipc" if insn.pc.checked_add(imm20 << 12).is_some() => Some("id3.auipc_no_wrap"),
        "auipc" => Some("id3.auipc_wrap"),
        _ => None,
    }
}

fn id4_cell(insn: &PicoInsn) -> &'static str {
    match insn.mnemonic.as_str() {
        "add" | "sub" | "sll" | "slt" | "sltu" | "xor" | "srl" | "sra" | "or" | "and" => {
            "id4.alu_r"
        }
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai" => {
            "id4.alu_i"
        }
        "lb" | "lh" | "lw" | "lbu" | "lhu" => "id4.load",
        "sb" | "sh" | "sw" => "id4.store",
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => "id4.branch",
        "jal" => "id4.jal",
        "jalr" => "id4.jalr",
        "lui" => "id4.lui",
        "auipc" => "id4.auipc",
        "ecall" => "id4.ecall",
        "mul" | "mulh" | "mulhsu" | "mulhu" => "id4.mul",
        "div" | "divu" | "rem" | "remu" => "id4.div",
        _ => "id4.alu_i",
    }
}

fn id5_cell(insn: &PicoInsn) -> Option<&'static str> {
    match insn.mnemonic.as_str() {
        "sb" | "sh" | "sw" => Some("id5.s_type"),
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => Some("id5.b_type"),
        "jal" => Some("id5.j_type"),
        _ => None,
    }
}

fn rf2_cell(insn: &PicoInsn) -> Option<&'static str> {
    let rs1 = insn.rs1?;
    let rs2 = insn.rs2;
    let rd = insn.rd;
    if rs1 == 0 {
        Some("rf2.rs1_x0")
    } else if rs2 == Some(0) {
        Some("rf2.rs2_x0")
    } else if Some(rs1) == rs2 && rd == Some(rs1) {
        Some("rf2.all_same")
    } else if Some(rs1) == rs2 {
        Some("rf2.rs1_eq_rs2")
    } else if rd == Some(rs1) {
        Some("rf2.rs1_eq_rd")
    } else if rs2.is_some() && rd == rs2 {
        Some("rf2.rs2_eq_rd")
    } else {
        Some("rf2.no_alias")
    }
}

fn write_source_cell(insn: &PicoInsn, prefix: &str) -> Option<&'static str> {
    let suffix = match insn.mnemonic.as_str() {
        "add" | "sub" | "sll" | "slt" | "sltu" | "xor" | "srl" | "sra" | "or" | "and" => {
            if prefix == "rf1" {
                "alu_r"
            } else {
                "alu"
            }
        }
        "addi" | "slti" | "sltiu" | "xori" | "ori" | "andi" | "slli" | "srli" | "srai" => {
            if prefix == "rf1" {
                "alu_i"
            } else {
                "alu"
            }
        }
        "lb" | "lh" | "lw" | "lbu" | "lhu" => "load",
        "jal" | "jalr" => {
            if prefix == "rf1" {
                insn.mnemonic.as_str()
            } else {
                "link"
            }
        }
        "lui" | "auipc" => {
            if prefix == "rf1" {
                insn.mnemonic.as_str()
            } else {
                "upper"
            }
        }
        "mul" | "mulh" | "mulhsu" | "mulhu" | "div" | "divu" | "rem" | "remu" => {
            if prefix == "rf1" {
                if matches!(insn.mnemonic.as_str(), "mul" | "mulh" | "mulhsu" | "mulhu") {
                    "mul"
                } else {
                    "div"
                }
            } else {
                "muldiv"
            }
        }
        _ => return None,
    };
    Some(match (prefix, suffix) {
        ("rf1", "alu_r") => "rf1.alu_r",
        ("rf1", "alu_i") => "rf1.alu_i",
        ("rf1", "load") => "rf1.load",
        ("rf1", "jal") => "rf1.jal",
        ("rf1", "jalr") => "rf1.jalr",
        ("rf1", "lui") => "rf1.lui",
        ("rf1", "auipc") => "rf1.auipc",
        ("rf1", "mul") => "rf1.mul",
        ("rf1", "div") => "rf1.div",
        ("rf3", "load") => "rf3.load",
        ("rf3", "link") => "rf3.link",
        ("rf3", "upper") => "rf3.upper",
        ("rf3", "muldiv") => "rf3.muldiv",
        _ => "rf3.alu",
    })
}

fn al1_cell(insn: &PicoInsn) -> &'static str {
    let imm = insn.imm.unwrap_or(0);
    if matches!(imm, 255 | 256 | -1 | -2048 | 2047) {
        "al1.boundary"
    } else if imm < 0 {
        "al1.negative"
    } else if imm <= 255 {
        "al1.single_limb"
    } else {
        "al1.cross_01"
    }
}

fn al2_cell(insn: &PicoInsn) -> &'static str {
    match insn.mnemonic.as_str() {
        "sll" => "al2.sll_lt32",
        "srl" => "al2.srl_lt32",
        "sra" => "al2.sra_lt32_pos",
        _ => "al2.shamt_zero",
    }
}

fn al3_cell(insn: &PicoInsn) -> &'static str {
    match insn.mnemonic.as_str() {
        "slt" | "slti" => "al3.slt_true",
        "sltu" | "sltiu" => "al3.sltu_true",
        _ => "al3.equal",
    }
}

fn div_special_cell(insn: &PicoInsn) -> Option<(&'static str, &'static str)> {
    let dividend = insn.runtime_b?;
    let divisor = insn.runtime_c?;
    if divisor == 0 {
        let cell = match insn.mnemonic.as_str() {
            "div" => "md1.div_zero",
            "divu" => "md1.divu_zero",
            "rem" => "md1.rem_zero",
            "remu" => "md1.remu_zero",
            _ => return None,
        };
        return Some(("md1", cell));
    }
    if dividend == 0x8000_0000 && divisor == 0xffff_ffff {
        let cell = match insn.mnemonic.as_str() {
            "div" => "md2.div_overflow",
            "rem" => "md2.rem_overflow",
            _ => return None,
        };
        return Some(("md2", cell));
    }
    None
}

fn md3_cell(insn: &PicoInsn) -> &'static str {
    if matches!(insn.mnemonic.as_str(), "divu" | "remu") {
        "md3.unsigned"
    } else {
        "md3.pp"
    }
}

fn md4_cell(insn: &PicoInsn) -> &'static str {
    match insn.mnemonic.as_str() {
        "mul" => "md4.mul_small",
        "mulhu" => "md4.mulhu",
        "mulh" => "md4.mulh_pp",
        _ => "md4.mul_small",
    }
}

fn cf1_cell(insn: &PicoInsn) -> &'static str {
    match insn.mnemonic.as_str() {
        "beq" => "cf1.beq_equal",
        "bne" => "cf1.bne_not_equal",
        "blt" => "cf1.blt_taken",
        "bge" => "cf1.bge_taken",
        "bltu" => "cf1.bltu_taken",
        "bgeu" => "cf1.bgeu_taken",
        _ => "cf1.beq_equal",
    }
}

fn cf3_cell(insn: &PicoInsn) -> &'static str {
    match insn.imm.unwrap_or(0).cmp(&0) {
        std::cmp::Ordering::Less => "cf3.imm_neg",
        std::cmp::Ordering::Equal => "cf3.imm_zero",
        std::cmp::Ordering::Greater => "cf3.imm_pos",
    }
}

fn me1_cell(width: u8) -> &'static str {
    match width {
        1 => "me1.sb_lb",
        2 => "me1.sh_lh",
        _ => "me1.sw_lw",
    }
}

fn me2_cell(addr: u32, width: u8, is_load: bool) -> &'static str {
    match (width, addr & 3, is_load) {
        (2, 1 | 3, _) => "me2.half_off1",
        (4, 1, _) => "me2.word_off1",
        (4, 2, _) => "me2.word_off2",
        (4, 3, _) => "me2.word_off3",
        (_, _, true) => "me2.byte_any",
        _ => "me2.byte_any",
    }
}

fn me3_cell(insn: &PicoInsn) -> &'static str {
    match insn.mnemonic.as_str() {
        "lb" => "me3.lb_pos",
        "lh" => "me3.lh_pos",
        "lbu" => "me3.lbu",
        "lhu" => "me3.lhu",
        _ => "me3.lbu",
    }
}

fn me4_cell(addr: u32, width: u8) -> &'static str {
    match (width, addr & 3) {
        (1, 0) => "me4.sb_off0",
        (1, 1) => "me4.sb_off1",
        (1, 2) => "me4.sb_off2",
        (1, _) => "me4.sb_off3",
        (2, 2 | 3) => "me4.sh_off2",
        _ => "me4.sh_off0",
    }
}

fn me6_cell(insn: &PicoInsn) -> &'static str {
    match insn.mnemonic.as_str() {
        "lw" => "me6.near_max_lw",
        "sw" => "me6.near_max_sw",
        "lh" | "lhu" => "me6.near_max_lh",
        _ => "me6.near_max_sb",
    }
}

fn me9_cell(addr: u32) -> &'static str {
    match addr & 3 {
        0 => "me9.off0",
        1 => "me9.off1",
        2 => "me9.off2",
        _ => "me9.off3",
    }
}

impl Trace for PicoTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }

    fn trace_signals(&self) -> &[TraceSignal] {
        &self.trace_signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beak_core::trace::Trace;

    #[test]
    fn ecall_argument_decomposition_emits_cf5_details() {
        let trace = PicoTrace::from_executed(&[PicoExecutedInsn {
            step_idx: 0,
            chunk: 0,
            clk: 0,
            pc: 0x1000,
            next_pc: 0,
            word: 0x0000_0073,
            opcode: "ecall".to_string(),
            a: 0,
            b: 7,
            c: 9,
            memory: None,
            ecall_syscall_id: Some(PICO_HALT_SYSCALL_ID),
            ecall_operand_to_check: Some(7),
        }])
        .expect("ecall trace");

        let hit = trace
            .bucket_hits()
            .iter()
            .find(|hit| hit.bucket_id == semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id)
            .expect("cf5 hit");

        assert_eq!(hit.details.get("obligation_id").and_then(Value::as_str), Some("cf5"));
        assert_eq!(hit.details.get("cell_id").and_then(Value::as_str), Some("cf5.halt"));
        assert_eq!(
            hit.details.get("syscall_id").and_then(Value::as_u64),
            Some(PICO_HALT_SYSCALL_ID as u64)
        );
        assert_eq!(hit.details.get("operand_to_check").and_then(Value::as_u64), Some(7));
        assert_eq!(
            hit.details.get("operand_range_check_enabled").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(hit.details.get("op_b").and_then(Value::as_u64), Some(7));
        assert_eq!(hit.details.get("op_c").and_then(Value::as_u64), Some(9));
        assert_eq!(hit.details.get("a0").and_then(Value::as_u64), Some(7));
        assert_eq!(hit.details.get("a1").and_then(Value::as_u64), Some(9));
        for idx in 2..=7 {
            assert_eq!(hit.details.get(&format!("a{idx}")), Some(&Value::Null));
        }
    }
}
