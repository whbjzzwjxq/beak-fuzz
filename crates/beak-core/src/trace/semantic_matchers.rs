use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};

use crate::trace::observations::{
    ArithmeticSpecialCaseObservation, AuipcPcLimbObservation, BoundaryOriginObservation,
    ImmediateLimbObservation, MemoryAddressSpaceObservation, MemoryImmediateSignObservation,
    MemoryWriteObservation, SequenceInsnObservation, SequenceSemanticMatcherProfile,
    UpperImmediateInsnObservation, VolatileBoundaryObservation, XorMultiplicityObservation,
};
use crate::trace::{BucketHit, TraceSignal, semantic};

fn details_kv(kvs: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    for (key, value) in kvs {
        out.insert((*key).to_string(), value.clone());
    }
    out
}

fn push_semantic_once(
    hits: &mut Vec<BucketHit>,
    seen: &mut HashSet<&'static str>,
    bucket: semantic::SemanticBucket,
    details: HashMap<String, Value>,
) {
    if !seen.insert(bucket.id) {
        return;
    }
    hits.push(BucketHit::semantic(bucket, details));
}

pub fn sequence_trace_signals(instructions: &[SequenceInsnObservation]) -> Vec<TraceSignal> {
    let mut seen = HashSet::new();
    let mut signals = Vec::new();
    for insn in instructions {
        let signal = match insn.mnemonic.as_str() {
            "lw" => Some(TraceSignal::HasLoad),
            "sw" => Some(TraceSignal::HasStore),
            "auipc" => Some(TraceSignal::HasAuipc),
            "ecall" | "ebreak" => Some(TraceSignal::HasEcall),
            _ => None,
        };
        if let Some(signal) = signal {
            if seen.insert(signal) {
                signals.push(signal);
            }
            if matches!(signal, TraceSignal::HasLoad | TraceSignal::HasStore)
                && seen.insert(TraceSignal::HasLoadStore)
            {
                signals.push(TraceSignal::HasLoadStore);
            }
        }
    }
    signals
}

pub fn match_sequence_semantic_hits(
    profile: SequenceSemanticMatcherProfile,
    instructions: &[SequenceInsnObservation],
) -> Vec<BucketHit> {
    let mut hits = Vec::new();
    let mut seen = HashSet::<&'static str>::new();
    let mut saw_store = false;
    let mut saw_store_before_ecall = false;
    let mut saw_ecall_after_store = false;

    for insn in instructions {
        match insn.mnemonic.as_str() {
            "add" | "addi" | "sub" | "xor" | "xori" | "or" | "ori" | "and" | "andi" => {
                if profile.emit_padding_interaction_send {
                    push_semantic_once(
                        &mut hits,
                        &mut seen,
                        semantic::row::PADDING_INTERACTION_SEND,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("mnemonic", json!(insn.mnemonic)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                        ]),
                    );
                }
            }
            "lw" => {
                push_semantic_once(
                    &mut hits,
                    &mut seen,
                    semantic::memory::TIMESTAMPED_LOAD_PATH,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                    ]),
                );
                if profile.emit_boolean_on_load_after_store && saw_store {
                    push_semantic_once(
                        &mut hits,
                        &mut seen,
                        semantic::lookup::BOOLEAN_MULTIPLICITY,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                        ]),
                    );
                }
                if profile.emit_kind_selector {
                    push_semantic_once(
                        &mut hits,
                        &mut seen,
                        semantic::memory::KIND_SELECTOR_CONSISTENCY,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                        ]),
                    );
                }
                if profile.emit_digest_route && saw_ecall_after_store {
                    push_semantic_once(
                        &mut hits,
                        &mut seen,
                        semantic::interaction::DIGEST_KIND_ROUTE,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                        ]),
                    );
                }
            }
            "sw" => {
                saw_store = true;
                saw_store_before_ecall = true;
                if profile.emit_boolean_on_store {
                    push_semantic_once(
                        &mut hits,
                        &mut seen,
                        semantic::lookup::BOOLEAN_MULTIPLICITY,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                        ]),
                    );
                }
            }
            "ecall" => {
                if profile.emit_ecall_next_pc {
                    push_semantic_once(
                        &mut hits,
                        &mut seen,
                        semantic::control::ECALL_NEXT_PC,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                        ]),
                    );
                }
                if saw_store_before_ecall {
                    saw_ecall_after_store = true;
                }
            }
            _ => {}
        }
    }

    hits
}

pub fn match_upper_immediate_semantic_hits(
    instructions: &[UpperImmediateInsnObservation],
) -> Vec<BucketHit> {
    instructions
        .iter()
        .map(|insn| {
            BucketHit::semantic(
                semantic::decode::UPPER_IMMEDIATE_MATERIALIZATION,
                details_kv(&[
                    ("op_idx", json!(insn.op_idx)),
                    ("pc", json!(insn.pc)),
                    ("raw_word", json!(insn.raw_word)),
                    ("rd", json!((insn.raw_word >> 7) & 0x1f)),
                    ("u_imm20", json!((insn.raw_word >> 12) & 0x000f_ffff)),
                    ("semantic_family", json!("upper_immediate")),
                ]),
            )
        })
        .collect()
}

pub fn match_memory_write_semantic_hits(observations: &[MemoryWriteObservation]) -> Vec<BucketHit> {
    let mut hits = Vec::new();

    for obs in observations {
        if obs.has_followup_load {
            hits.push(BucketHit::semantic(
                semantic::memory::STORE_LOAD_PAYLOAD_FLOW,
                details_kv(&[
                    ("op_idx", json!(obs.op_idx)),
                    ("pc", json!(obs.pc)),
                    ("address", json!(obs.address)),
                    ("size_bytes", json!(obs.size_bytes)),
                    ("value", json!(obs.value)),
                    ("prev_value", json!(obs.prev_value)),
                    ("semantic_family", json!("store_to_load_payload_flow")),
                ]),
            ));
        }

        hits.push(BucketHit::semantic(
            semantic::memory::WRITE_PAYLOAD_CONSISTENCY,
            details_kv(&[
                ("op_idx", json!(obs.op_idx)),
                ("pc", json!(obs.pc)),
                ("address", json!(obs.address)),
                ("size_bytes", json!(obs.size_bytes)),
                ("value", json!(obs.value)),
                ("prev_value", json!(obs.prev_value)),
                ("value_low_bits", json!(obs.value & 0xff)),
                ("semantic_family", json!("memory_write_payload")),
            ]),
        ));
    }

    hits
}

pub fn match_immediate_limb_semantic_hits(
    observations: &[ImmediateLimbObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::alu::IMMEDIATE_LIMB_CONSISTENCY,
                details_kv(&[
                    ("kind", json!(obs.kind)),
                    ("chip_name", json!(obs.chip_name)),
                    ("step_idx", json!(obs.step_idx)),
                    ("op_idx", json!(obs.op_idx)),
                    ("imm", json!(obs.imm)),
                ]),
            )
        })
        .collect()
}

pub fn match_xor_multiplicity_semantic_hits(
    observations: &[XorMultiplicityObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::lookup::XOR_MULTIPLICITY_CONSISTENCY,
                details_kv(&[
                    ("kind", json!(obs.kind)),
                    ("chip_name", json!(obs.chip_name)),
                    ("step_idx", json!(obs.step_idx)),
                    ("op_idx", json!(obs.op_idx)),
                    ("lhs", json!(obs.lhs)),
                    ("rhs", json!(obs.rhs)),
                ]),
            )
        })
        .collect()
}

pub fn match_auipc_pc_limb_semantic_hits(
    observations: &[AuipcPcLimbObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::control::AUIPC_PC_LIMB_CONSISTENCY,
                details_kv(&[
                    ("kind", json!(obs.kind)),
                    ("chip_name", json!(obs.chip_name)),
                    ("step_idx", json!(obs.step_idx)),
                    ("op_idx", json!(obs.op_idx)),
                    ("from_pc", json!(obs.from_pc)),
                    ("imm", json!(obs.imm)),
                ]),
            )
        })
        .collect()
}

pub fn match_memory_immediate_sign_semantic_hits(
    observations: &[MemoryImmediateSignObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::memory::IMMEDIATE_SIGN_CONSISTENCY,
                details_kv(&[
                    ("kind", json!(obs.kind)),
                    ("chip_name", json!(obs.chip_name)),
                    ("step_idx", json!(obs.step_idx)),
                    ("op_idx", json!(obs.op_idx)),
                    ("imm", json!(obs.imm)),
                    ("imm_sign", json!(obs.imm_sign)),
                ]),
            )
        })
        .collect()
}

pub fn match_memory_address_space_semantic_hits(
    observations: &[MemoryAddressSpaceObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::memory::ADDRESS_SPACE_CONSISTENCY,
                details_kv(&[
                    ("kind", json!(obs.kind)),
                    ("chip_name", json!(obs.chip_name)),
                    ("step_idx", json!(obs.step_idx)),
                    ("op_idx", json!(obs.op_idx)),
                    ("mem_as", json!(obs.mem_as)),
                ]),
            )
        })
        .collect()
}

pub fn match_boundary_origin_semantic_hits(
    observations: &[BoundaryOriginObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::time::BOUNDARY_ORIGIN_CONSISTENCY,
                details_kv(&[
                    ("kind", json!(obs.kind)),
                    ("chip_name", json!(obs.chip_name)),
                    ("step_idx", json!(obs.step_idx)),
                    ("op_idx", json!(obs.op_idx)),
                    ("from_timestamp", json!(obs.from_timestamp)),
                    ("to_timestamp", json!(obs.to_timestamp)),
                    ("is_terminate", json!(obs.is_terminate)),
                ]),
            )
        })
        .collect()
}

pub fn match_volatile_boundary_semantic_hits(
    observations: &[VolatileBoundaryObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::memory::VOLATILE_BOUNDARY_RANGE,
                details_kv(&[
                    ("kind", json!(obs.kind)),
                    ("chip_name", json!(obs.chip_name)),
                    ("step_idx", json!(obs.step_idx)),
                    ("op_idx", json!(obs.op_idx)),
                ]),
            )
        })
        .collect()
}

pub fn match_arithmetic_special_case_semantic_hits(
    observations: &[ArithmeticSpecialCaseObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::arithmetic::SPECIAL_CASE_CONSISTENCY,
                details_kv(&[
                    ("step_idx", json!(obs.step_idx)),
                    ("op_idx", json!(obs.op_idx)),
                    ("rs1", json!(obs.rs1)),
                    ("rs2", json!(obs.rs2)),
                ]),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        match_sequence_semantic_hits, sequence_trace_signals,
    };
    use crate::trace::observations::{SequenceInsnObservation, SequenceSemanticMatcherProfile};
    use crate::trace::{TraceSignal, semantic};

    #[test]
    fn semantic_matchers_only_emit_registered_semantic_ids() {
        let instructions = vec![
            SequenceInsnObservation {
                step_idx: 0,
                word: 0,
                mnemonic: "sw".to_string(),
                rs1: Some(0),
                imm: Some(0),
            },
            SequenceInsnObservation {
                step_idx: 1,
                word: 0,
                mnemonic: "ecall".to_string(),
                rs1: None,
                imm: None,
            },
            SequenceInsnObservation {
                step_idx: 2,
                word: 0,
                mnemonic: "lw".to_string(),
                rs1: Some(0),
                imm: Some(0),
            },
            SequenceInsnObservation {
                step_idx: 3,
                word: 0,
                mnemonic: "add".to_string(),
                rs1: None,
                imm: None,
            },
        ];

        let hits = match_sequence_semantic_hits(
            SequenceSemanticMatcherProfile {
                emit_padding_interaction_send: true,
                emit_boolean_on_store: true,
                emit_boolean_on_load_after_store: true,
                emit_kind_selector: true,
                emit_digest_route: true,
                emit_ecall_next_pc: true,
            },
            &instructions,
        );

        assert!(!hits.is_empty());
        assert!(hits.iter().all(|hit| semantic::by_id(&hit.bucket_id).is_some()));
    }

    #[test]
    fn input_features_stay_in_trace_signals_not_bucket_hits() {
        let instructions = vec![
            SequenceInsnObservation {
                step_idx: 0,
                word: 0,
                mnemonic: "sw".to_string(),
                rs1: Some(0),
                imm: Some(0),
            },
            SequenceInsnObservation {
                step_idx: 1,
                word: 0,
                mnemonic: "lw".to_string(),
                rs1: Some(0),
                imm: Some(0),
            },
            SequenceInsnObservation {
                step_idx: 2,
                word: 0,
                mnemonic: "auipc".to_string(),
                rs1: None,
                imm: None,
            },
        ];

        let hits = match_sequence_semantic_hits(
            SequenceSemanticMatcherProfile {
                emit_padding_interaction_send: false,
                emit_boolean_on_store: false,
                emit_boolean_on_load_after_store: true,
                emit_kind_selector: false,
                emit_digest_route: false,
                emit_ecall_next_pc: false,
            },
            &instructions,
        );
        let signals = sequence_trace_signals(&instructions);

        assert!(hits.iter().all(|hit| !hit.bucket_id.contains(".input.")));
        assert!(signals.contains(&TraceSignal::HasStore));
        assert!(signals.contains(&TraceSignal::HasLoad));
        assert!(signals.contains(&TraceSignal::HasAuipc));
    }
}
