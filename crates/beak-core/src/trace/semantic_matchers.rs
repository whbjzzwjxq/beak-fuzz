use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};

use crate::trace::observations::{
    ArithmeticSpecialCaseObservation, AuipcPcLimbObservation, BoundaryOriginObservation,
    DivisionInsnObservation, EcallInsnObservation, ImmediateLimbObservation,
    MemoryAddressSpaceObservation, MemoryImmediateSignObservation, MemoryWriteObservation,
    RdBitDecompositionObservation, SequenceInsnObservation, SequenceSemanticMatcherProfile,
    TimestampedLoadPathObservation, UpperImmediateInsnObservation, VolatileBoundaryObservation,
    XorMultiplicityObservation, ZeroRegisterWriteObservation,
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

fn control_flow_family(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => Some("branch"),
        "jal" | "jalr" => Some("jump"),
        "ecall" => Some("ecall"),
        _ => None,
    }
}

fn memory_access_shape(mnemonic: &str) -> Option<(&'static str, u8)> {
    match mnemonic {
        "lb" | "lbu" | "sb" => Some(("byte", 1)),
        "lh" | "lhu" | "sh" => Some(("halfword", 2)),
        "lw" | "sw" => Some(("word", 4)),
        _ => None,
    }
}

pub fn sequence_trace_signals(instructions: &[SequenceInsnObservation]) -> Vec<TraceSignal> {
    let mut seen = HashSet::new();
    let mut signals = Vec::new();
    for insn in instructions {
        let signal = match insn.mnemonic.as_str() {
            "lb" | "lbu" | "lh" | "lhu" | "lw" => Some(TraceSignal::HasLoad),
            "sb" | "sh" | "sw" => Some(TraceSignal::HasStore),
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
    let mut seen_control_flow_families = HashSet::<&'static str>::new();
    let mut saw_store = false;
    let mut saw_store_before_ecall = false;
    let mut saw_ecall_after_store = false;

    for insn in instructions {
        if let Some((access_width_name, access_size_bytes)) =
            memory_access_shape(insn.mnemonic.as_str())
        {
            let is_load =
                matches!(insn.mnemonic.as_str(), "lb" | "lbu" | "lh" | "lhu" | "lw");
            let is_store = matches!(insn.mnemonic.as_str(), "sb" | "sh" | "sw");
            let required_alignment = if access_size_bytes >= 4 {
                4
            } else if access_size_bytes >= 2 {
                2
            } else {
                1
            };

            if is_load {
                push_semantic_once(
                    &mut hits,
                    &mut seen,
                    semantic::memory::TIMESTAMPED_LOAD_PATH,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                        ("mnemonic", json!(insn.mnemonic)),
                        ("access_size_bytes", json!(access_size_bytes)),
                    ]),
                );

                if profile.emit_load_value_binding {
                    push_semantic_once(
                        &mut hits,
                        &mut seen,
                        semantic::memory::LOAD_VALUE_BINDING,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                            ("mnemonic", json!(insn.mnemonic)),
                            ("access_size_bytes", json!(access_size_bytes)),
                            ("semantic_family", json!("load_value_binding")),
                        ]),
                    );
                }

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

            if is_store {
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

            if profile.emit_opcode_selector_bindings {
                push_semantic_once(
                    &mut hits,
                    &mut seen,
                    semantic::exec::OP_SELECTOR_BINDING,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                        ("mnemonic", json!(insn.mnemonic)),
                        (
                            "access_kind",
                            json!(if is_load { "load" } else { "store" }),
                        ),
                        ("semantic_family", json!("memory_opcode_selector_binding")),
                    ]),
                );
            }

            if access_size_bytes > 1 && profile.emit_memory_alignment {
                push_semantic_once(
                    &mut hits,
                    &mut seen,
                    semantic::memory::ADDRESS_ALIGNMENT_CONSISTENCY,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                        ("mnemonic", json!(insn.mnemonic)),
                        ("access_size_bytes", json!(access_size_bytes)),
                        ("required_alignment", json!(required_alignment)),
                        ("semantic_family", json!("address_alignment_consistency")),
                    ]),
                );
            }

            if access_size_bytes > 1 && profile.emit_memory_address_progression {
                push_semantic_once(
                    &mut hits,
                    &mut seen,
                    semantic::memory::ADDRESS_PROGRESSION_CONSISTENCY,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                        ("mnemonic", json!(insn.mnemonic)),
                        ("access_size_bytes", json!(access_size_bytes)),
                        ("access_width_name", json!(access_width_name)),
                        ("semantic_family", json!("address_progression_consistency")),
                    ]),
                );
            }

            if is_load && access_size_bytes < 4 && profile.emit_partial_word_write {
                push_semantic_once(
                    &mut hits,
                    &mut seen,
                    semantic::exec::PARTIAL_WORD_WRITE_CONSISTENCY,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                        ("mnemonic", json!(insn.mnemonic)),
                        ("written_bits", json!(u64::from(access_size_bytes) * 8)),
                        ("word_bits", json!(32)),
                        ("semantic_family", json!("partial_word_write_consistency")),
                    ]),
                );
            }
        }

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
            "ecall" => {
                if saw_store_before_ecall {
                    saw_ecall_after_store = true;
                }
                if profile.emit_ecall_word_validity {
                    push_semantic_once(
                        &mut hits,
                        &mut seen,
                        semantic::control::ECALL_WORD_VALIDITY,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                            ("mnemonic", json!(insn.mnemonic)),
                            ("semantic_family", json!("ecall_word_validity")),
                        ]),
                    );
                }
            }
            _ => {}
        }

        if profile.emit_control_flow_bindings {
            if let Some(family) = control_flow_family(insn.mnemonic.as_str()) {
                if seen_control_flow_families.insert(family) {
                    hits.push(BucketHit::semantic(
                        semantic::exec::CONTROL_FLOW_BINDING,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                            ("mnemonic", json!(insn.mnemonic)),
                            ("semantic_family", json!("control_flow_binding")),
                            ("semantic_subclass", json!(family)),
                            ("control_flow_family", json!(family)),
                            ("control_flow_opcode", json!(insn.mnemonic)),
                        ]),
                    ));
                }
            }
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
                    ("op", json!(obs.op)),
                    ("imm", json!(obs.imm)),
                    ("imm_sign", json!(obs.imm_sign)),
                    ("rs1_ptr", json!(obs.rs1_ptr)),
                    ("rd_rs2_ptr", json!(obs.rd_rs2_ptr)),
                    ("mem_as", json!(obs.mem_as)),
                    ("effective_ptr", json!(obs.effective_ptr)),
                    ("alt_effective_ptr", json!(obs.alt_effective_ptr)),
                    ("alt_ptr_delta", json!(obs.alt_ptr_delta)),
                    ("alt_ptr_in_range_29", json!(obs.alt_ptr_in_range_29)),
                    ("is_load", json!(obs.is_load)),
                    ("is_store", json!(obs.is_store)),
                    ("needs_write", json!(obs.needs_write)),
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

pub fn match_timestamped_load_path_semantic_hits(
    observations: &[TimestampedLoadPathObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::memory::TIMESTAMPED_LOAD_PATH,
                details_kv(&[
                    ("kind", json!(obs.kind)),
                    ("chip_name", json!(obs.chip_name)),
                    ("step_idx", json!(obs.step_idx)),
                    ("op_idx", json!(obs.op_idx)),
                    ("timestamp", json!(obs.timestamp)),
                    ("is_load", json!(obs.is_load)),
                    ("is_store", json!(obs.is_store)),
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

pub fn match_zero_register_semantic_hits(
    observations: &[ZeroRegisterWriteObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::decode::ZERO_REGISTER_IMMUTABILITY,
                details_kv(&[
                    ("op_idx", json!(obs.op_idx)),
                    ("pc", json!(obs.pc)),
                    ("raw_word", json!(obs.raw_word)),
                    ("mnemonic", json!(obs.mnemonic)),
                    ("semantic_family", json!("zero_register_write")),
                ]),
            )
        })
        .collect()
}

pub fn match_rd_bit_semantic_hits(
    observations: &[RdBitDecompositionObservation],
) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::decode::RD_BIT_DECOMPOSITION,
                details_kv(&[
                    ("op_idx", json!(obs.op_idx)),
                    ("pc", json!(obs.pc)),
                    ("raw_word", json!(obs.raw_word)),
                    ("rd", json!(obs.rd)),
                    ("mnemonic", json!(obs.mnemonic)),
                    ("semantic_family", json!("rd_bit_decomposition")),
                ]),
            )
        })
        .collect()
}

pub fn match_division_semantic_hits(observations: &[DivisionInsnObservation]) -> Vec<BucketHit> {
    let mut hits = Vec::new();
    for obs in observations {
        hits.push(BucketHit::semantic(
            semantic::decode::OPERAND_INDEX_ROUTING,
            details_kv(&[
                ("op_idx", json!(obs.op_idx)),
                ("pc", json!(obs.pc)),
                ("raw_word", json!(obs.raw_word)),
                ("mnemonic", json!(obs.mnemonic)),
                ("rd", json!(obs.rd)),
                ("rs1", json!(obs.rs1)),
                ("rs2", json!(obs.rs2)),
                ("semantic_family", json!("division_operand_routing")),
            ]),
        ));
        hits.push(BucketHit::semantic(
            semantic::arithmetic::DIVISION_REMAINDER_BOUND,
            details_kv(&[
                ("op_idx", json!(obs.op_idx)),
                ("pc", json!(obs.pc)),
                ("raw_word", json!(obs.raw_word)),
                ("mnemonic", json!(obs.mnemonic)),
                ("rd", json!(obs.rd)),
                ("rs1", json!(obs.rs1)),
                ("rs2", json!(obs.rs2)),
                ("semantic_family", json!("division_remainder_bound")),
            ]),
        ));
    }
    hits
}

pub fn match_ecall_semantic_hits(observations: &[EcallInsnObservation]) -> Vec<BucketHit> {
    observations
        .iter()
        .map(|obs| {
            BucketHit::semantic(
                semantic::control::ECALL_ARGUMENT_DECOMPOSITION,
                details_kv(&[
                    ("op_idx", json!(obs.op_idx)),
                    ("pc", json!(obs.pc)),
                    ("raw_word", json!(obs.raw_word)),
                    ("mnemonic", json!(obs.mnemonic)),
                    ("semantic_family", json!("ecall_argument_decomposition")),
                ]),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{match_sequence_semantic_hits, sequence_trace_signals};
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
                emit_control_flow_bindings: true,
                emit_memory_alignment: true,
                emit_memory_address_progression: true,
                emit_load_value_binding: true,
                emit_opcode_selector_bindings: true,
                emit_partial_word_write: true,
                emit_ecall_word_validity: true,
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
                emit_control_flow_bindings: false,
                emit_memory_alignment: false,
                emit_memory_address_progression: false,
                emit_load_value_binding: false,
                emit_opcode_selector_bindings: false,
                emit_partial_word_write: false,
                emit_ecall_word_validity: false,
            },
            &instructions,
        );
        let signals = sequence_trace_signals(&instructions);

        assert!(hits.iter().all(|hit| !hit.bucket_id.contains(".input.")));
        assert!(signals.contains(&TraceSignal::HasStore));
        assert!(signals.contains(&TraceSignal::HasLoad));
        assert!(signals.contains(&TraceSignal::HasAuipc));
    }

    #[test]
    fn control_flow_binding_emits_one_hit_per_family() {
        let instructions = vec![
            SequenceInsnObservation {
                step_idx: 0,
                word: 0x0000_0063,
                mnemonic: "beq".to_string(),
                rs1: Some(1),
                imm: Some(8),
            },
            SequenceInsnObservation {
                step_idx: 1,
                word: 0x0000_006f,
                mnemonic: "jal".to_string(),
                rs1: None,
                imm: Some(8),
            },
            SequenceInsnObservation {
                step_idx: 2,
                word: 0x0000_0073,
                mnemonic: "ecall".to_string(),
                rs1: None,
                imm: None,
            },
            SequenceInsnObservation {
                step_idx: 3,
                word: 0x0000_1063,
                mnemonic: "bne".to_string(),
                rs1: Some(2),
                imm: Some(12),
            },
        ];

        let hits = match_sequence_semantic_hits(
            SequenceSemanticMatcherProfile {
                emit_padding_interaction_send: false,
                emit_boolean_on_store: false,
                emit_boolean_on_load_after_store: false,
                emit_kind_selector: false,
                emit_digest_route: false,
                emit_control_flow_bindings: true,
                emit_memory_alignment: false,
                emit_memory_address_progression: false,
                emit_load_value_binding: false,
                emit_opcode_selector_bindings: false,
                emit_partial_word_write: false,
                emit_ecall_word_validity: false,
            },
            &instructions,
        );

        let mut families = hits
            .iter()
            .filter(|hit| hit.bucket_id == semantic::exec::CONTROL_FLOW_BINDING.id)
            .map(|hit| {
                hit.details
                    .get("control_flow_family")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string()
            })
            .collect::<Vec<_>>();
        families.sort();

        assert_eq!(families, vec!["branch", "ecall", "jump"]);
    }
}
