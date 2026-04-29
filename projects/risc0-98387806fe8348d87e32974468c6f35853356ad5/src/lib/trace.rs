use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::observations::{
    DivisionInsnObservation, EcallInsnObservation, RdBitDecompositionObservation,
    SequenceInsnObservation, SequenceSemanticMatcherProfile, ZeroRegisterWriteObservation,
};
use beak_core::trace::{semantic, semantic_matchers, BucketHit, Trace, TraceSignal};
use serde_json::json;

#[derive(Debug, Clone)]
pub struct Risc0Trace {
    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,
    instruction_count: usize,
}

fn writes_rd(mnemonic: &str) -> bool {
    !matches!(
        mnemonic,
        "sb" | "sh"
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
}

fn details_kv(
    entries: &[(&str, serde_json::Value)],
) -> std::collections::HashMap<String, serde_json::Value> {
    entries.iter().map(|(key, value)| ((*key).to_string(), value.clone())).collect()
}

fn supports_exec_source_binding(dec: &RV32IMInstruction) -> bool {
    dec.rs1.is_some() && dec.rs2.is_some()
}

fn supports_exec_dest_binding(dec: &RV32IMInstruction) -> bool {
    writes_rd(&dec.mnemonic) && dec.rd.is_some_and(|rd| rd != 0)
}

fn supports_exec_op_selector_binding(dec: &RV32IMInstruction) -> bool {
    matches!(dec.mnemonic.as_str(), "div" | "divu" | "rem" | "remu" | "lb" | "lbu" | "lh" | "lhu")
}

fn supports_exec_control_binding(dec: &RV32IMInstruction) -> bool {
    matches!(
        dec.mnemonic.as_str(),
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "jal" | "jalr" | "ecall"
    )
}

fn supports_exec_memory_binding(dec: &RV32IMInstruction) -> bool {
    matches!(dec.mnemonic.as_str(), "lb" | "lh" | "lw" | "lbu" | "lhu" | "sb" | "sh" | "sw")
}

fn exec_bucket_hits_for_instruction(
    op_idx: u64,
    pc: u64,
    word: u32,
    dec: &RV32IMInstruction,
) -> Vec<BucketHit> {
    let mut hits = Vec::new();
    if supports_exec_source_binding(dec) {
        hits.push(BucketHit::semantic(
            semantic::exec::SOURCE_OPERAND_BINDING,
            details_kv(&[
                ("op_idx", json!(op_idx)),
                ("pc", json!(pc)),
                ("raw_word", json!(word)),
                ("mnemonic", json!(dec.mnemonic)),
                ("rd", json!(dec.rd)),
                ("rs1", json!(dec.rs1)),
                ("rs2", json!(dec.rs2)),
                ("semantic_family", json!("exec_source_operand_binding")),
            ]),
        ));
    }
    if supports_exec_dest_binding(dec) {
        hits.push(BucketHit::semantic(
            semantic::exec::DEST_BINDING,
            details_kv(&[
                ("op_idx", json!(op_idx)),
                ("pc", json!(pc)),
                ("raw_word", json!(word)),
                ("mnemonic", json!(dec.mnemonic)),
                ("rd", json!(dec.rd)),
                ("semantic_family", json!("exec_dest_binding")),
            ]),
        ));
    }
    if supports_exec_op_selector_binding(dec) {
        hits.push(BucketHit::semantic(
            semantic::exec::OP_SELECTOR_BINDING,
            details_kv(&[
                ("op_idx", json!(op_idx)),
                ("pc", json!(pc)),
                ("raw_word", json!(word)),
                ("mnemonic", json!(dec.mnemonic)),
                ("semantic_family", json!("exec_op_selector_binding")),
            ]),
        ));
    }
    if supports_exec_control_binding(dec) {
        hits.push(BucketHit::semantic(
            semantic::exec::CONTROL_FLOW_BINDING,
            details_kv(&[
                ("op_idx", json!(op_idx)),
                ("pc", json!(pc)),
                ("raw_word", json!(word)),
                ("mnemonic", json!(dec.mnemonic)),
                ("semantic_family", json!("exec_control_flow_binding")),
            ]),
        ));
    }
    if supports_exec_memory_binding(dec) {
        hits.push(BucketHit::semantic(
            semantic::exec::MEMORY_EFFECT_BINDING,
            details_kv(&[
                ("op_idx", json!(op_idx)),
                ("pc", json!(pc)),
                ("raw_word", json!(word)),
                ("mnemonic", json!(dec.mnemonic)),
                ("rs1", json!(dec.rs1)),
                ("rs2", json!(dec.rs2)),
                ("semantic_family", json!("exec_memory_effect_binding")),
            ]),
        ));
    }
    hits
}

impl Risc0Trace {
    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        let mut sequence = Vec::new();
        let mut zero_reg = Vec::new();
        let mut rd_bits = Vec::new();
        let mut divisions = Vec::new();
        let mut ecalls = Vec::new();
        let mut bucket_hits = Vec::new();

        for (op_idx, &word) in words.iter().enumerate() {
            let pc = crate::RISC0_ORACLE_CODE_BASE as u64 + (op_idx as u64) * 4;
            let dec = RV32IMInstruction::from_word(word)
                .map_err(|e| format!("decode failed at step {op_idx}: {e}"))?;

            sequence.push(SequenceInsnObservation {
                step_idx: op_idx as u64,
                word,
                mnemonic: dec.mnemonic.clone(),
                rs1: dec.rs1,
                imm: dec.imm,
            });

            if dec.mnemonic == "ecall" {
                zero_reg.push(ZeroRegisterWriteObservation {
                    op_idx: op_idx as u64,
                    pc,
                    raw_word: word,
                    mnemonic: dec.mnemonic.clone(),
                });
                ecalls.push(EcallInsnObservation {
                    op_idx: op_idx as u64,
                    pc,
                    raw_word: word,
                    mnemonic: dec.mnemonic.clone(),
                });
            }

            if matches!(dec.mnemonic.as_str(), "div" | "divu" | "rem" | "remu") {
                divisions.push(DivisionInsnObservation {
                    op_idx: op_idx as u64,
                    pc,
                    raw_word: word,
                    mnemonic: dec.mnemonic.clone(),
                    rd: dec.rd.unwrap_or(0),
                    rs1: dec.rs1.unwrap_or(0),
                    rs2: dec.rs2.unwrap_or(0),
                });
            }

            if writes_rd(&dec.mnemonic) {
                if let Some(rd) = dec.rd {
                    if rd == 0 {
                        zero_reg.push(ZeroRegisterWriteObservation {
                            op_idx: op_idx as u64,
                            pc,
                            raw_word: word,
                            mnemonic: dec.mnemonic.clone(),
                        });
                    } else {
                        rd_bits.push(RdBitDecompositionObservation {
                            op_idx: op_idx as u64,
                            pc,
                            raw_word: word,
                            rd,
                            mnemonic: dec.mnemonic.clone(),
                        });
                    }
                }
            }

            bucket_hits.extend(exec_bucket_hits_for_instruction(op_idx as u64, pc, word, &dec));
        }

        let trace_signals = semantic_matchers::sequence_trace_signals(&sequence);
        bucket_hits.extend(semantic_matchers::match_sequence_semantic_hits(
            SequenceSemanticMatcherProfile {
                emit_padding_interaction_send: false,
                emit_boolean_on_store: false,
                emit_boolean_on_load_after_store: false,
                emit_kind_selector: false,
                emit_digest_route: false,
                emit_control_flow_bindings: false,
                emit_memory_alignment: false,
                emit_memory_address_progression: false,
                emit_load_value_binding: false,
                emit_opcode_selector_bindings: false,
                emit_partial_word_write: false,
                emit_ecall_word_validity: false,
            },
            &sequence,
        ));
        bucket_hits.extend(semantic_matchers::match_zero_register_semantic_hits(&zero_reg));
        bucket_hits.extend(semantic_matchers::match_rd_bit_semantic_hits(&rd_bits));
        bucket_hits.extend(semantic_matchers::match_division_semantic_hits(&divisions));
        bucket_hits.extend(semantic_matchers::match_ecall_semantic_hits(&ecalls));

        Ok(Self { bucket_hits, trace_signals, instruction_count: words.len() })
    }

    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }
}

impl Trace for Risc0Trace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }

    fn trace_signals(&self) -> &[TraceSignal] {
        &self.trace_signals
    }
}

#[cfg(test)]
mod tests {
    use beak_core::trace::semantic;
    use beak_core::trace::Trace;

    use super::Risc0Trace;

    #[test]
    fn risc0_trace_emits_risc0_semantics() {
        let words = [0x0010_0093, 0x0231_50b3, 0x0000_0073];
        let trace = Risc0Trace::from_words(&words).expect("trace");
        let sigs = trace.bucket_hits().iter().map(|hit| hit.bucket_id.as_str()).collect::<Vec<_>>();
        assert!(sigs.iter().all(|id| semantic::by_id(id).is_some()));
        assert!(sigs.contains(&semantic::decode::RD_BIT_DECOMPOSITION.id));
        assert!(sigs.contains(&semantic::decode::OPERAND_INDEX_ROUTING.id));
        assert!(sigs.contains(&semantic::arithmetic::DIVISION_REMAINDER_BOUND.id));
        assert!(sigs.contains(&semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id));
        assert!(sigs.contains(&semantic::exec::SOURCE_OPERAND_BINDING.id));
        assert!(sigs.contains(&semantic::exec::DEST_BINDING.id));
    }
}
