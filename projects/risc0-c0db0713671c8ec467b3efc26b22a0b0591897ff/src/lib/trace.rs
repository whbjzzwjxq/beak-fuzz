use beak_core::rv32im::instruction::RV32IMInstruction;
use beak_core::trace::observations::{
    DivisionInsnObservation, EcallInsnObservation, RdBitDecompositionObservation,
    SequenceInsnObservation, SequenceSemanticMatcherProfile, ZeroRegisterWriteObservation,
};
use beak_core::trace::{BucketHit, Trace, TraceSignal, semantic_matchers};

#[derive(Debug, Clone)]
pub struct Risc0Trace {
    bucket_hits: Vec<BucketHit>,
    trace_signals: Vec<TraceSignal>,
    instruction_count: usize,
}

fn writes_rd(mnemonic: &str) -> bool {
    !matches!(
        mnemonic,
        "sb"
            | "sh"
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

impl Risc0Trace {
    pub fn from_words(words: &[u32]) -> Result<Self, String> {
        let mut sequence = Vec::new();
        let mut zero_reg = Vec::new();
        let mut rd_bits = Vec::new();
        let mut divisions = Vec::new();
        let mut ecalls = Vec::new();

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
        }

        let trace_signals = semantic_matchers::sequence_trace_signals(&sequence);
        let mut bucket_hits = Vec::new();
        bucket_hits.extend(semantic_matchers::match_sequence_semantic_hits(
            SequenceSemanticMatcherProfile {
                emit_padding_interaction_send: false,
                emit_boolean_on_store: false,
                emit_boolean_on_load_after_store: false,
                emit_kind_selector: false,
                emit_digest_route: false,
                emit_ecall_next_pc: false,
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
    use beak_core::trace::Trace;
    use beak_core::trace::semantic;

    use super::Risc0Trace;

    #[test]
    fn risc0_trace_emits_risc0_semantics() {
        let words = [0x0010_0093, 0x0231_50b3, 0x0000_0073];
        let trace = Risc0Trace::from_words(&words).expect("trace");
        let sigs = trace
            .bucket_hits()
            .iter()
            .map(|hit| hit.bucket_id.as_str())
            .collect::<Vec<_>>();
        assert!(sigs.iter().all(|id| semantic::by_id(id).is_some()));
        assert!(sigs.contains(&semantic::decode::RD_BIT_DECOMPOSITION.id));
        assert!(sigs.contains(&semantic::decode::OPERAND_INDEX_ROUTING.id));
        assert!(sigs.contains(&semantic::arithmetic::DIVISION_REMAINDER_BOUND.id));
        assert!(sigs.contains(&semantic::control::ECALL_ARGUMENT_DECOMPOSITION.id));
    }
}
