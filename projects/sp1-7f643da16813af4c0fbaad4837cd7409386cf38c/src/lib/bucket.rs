use std::collections::{HashMap, HashSet};

use beak_core::trace::BucketHit;
use serde_json::{json, Value};

use crate::bucket_id::Sp1BucketId;
use crate::trace::Sp1Trace;

fn details_kv(kvs: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    for (k, v) in kvs {
        out.insert((*k).to_string(), v.clone());
    }
    out
}

fn push_hit(
    hits: &mut Vec<BucketHit>,
    seen: &mut HashSet<String>,
    bucket_id: Sp1BucketId,
    details: HashMap<String, Value>,
) {
    let id = bucket_id.as_ref().to_string();
    if !seen.insert(id.clone()) {
        return;
    }
    hits.push(BucketHit::new(id, details));
}

pub fn match_bucket_hits(trace: &Sp1Trace) -> Vec<BucketHit> {
    let mut hits = Vec::new();
    let mut seen = HashSet::<String>::new();
    let mut saw_store = false;
    let mut saw_store_before_ecall = false;
    let mut saw_ecall_after_store = false;

    for insn in trace.instructions() {
        match insn.mnemonic.as_str() {
            "add" | "addi" | "sub" | "xor" | "xori" | "or" | "ori" | "and" | "andi" => {
                // s26 PoC shape: normal arithmetic instruction can coexist with forged syscall-table send
                // in a padding row. This bucket is detection-only (no direct injection).
                push_hit(
                    &mut hits,
                    &mut seen,
                    Sp1BucketId::Loop2TargetS26PaddingSendToTable,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("mnemonic", json!(insn.mnemonic)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                    ]),
                );
            }
            "lw" => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    Sp1BucketId::InputHasLoad,
                    HashMap::new(),
                );
                push_hit(
                    &mut hits,
                    &mut seen,
                    Sp1BucketId::Loop2TargetMemLoadPath,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                    ]),
                );
                if saw_store {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        Sp1BucketId::Loop2TargetMultiplicityBoolConstraint,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                        ]),
                    );
                }
                push_hit(
                    &mut hits,
                    &mut seen,
                    Sp1BucketId::Loop2TargetS27MemoryIsMemory,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                    ]),
                );
                if saw_ecall_after_store {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        Sp1BucketId::Loop2TargetS29DigestInteractionKind,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                        ]),
                    );
                }
            }
            "sw" => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    Sp1BucketId::InputHasStore,
                    HashMap::new(),
                );
                saw_store = true;
                saw_store_before_ecall = true;
                if insn.rs1 == Some(0) && insn.imm == Some(0) {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        Sp1BucketId::Loop1OracleRegzeroStoreAddr0,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                        ]),
                    );
                }
            }
            "ecall" => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    Sp1BucketId::Loop2TargetS28EcallNextPc,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                    ]),
                );
                if saw_store_before_ecall {
                    saw_ecall_after_store = true;
                }
            }
            "auipc" => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    Sp1BucketId::InputHasAuipc,
                    HashMap::new(),
                );
            }
            _ => {}
        }
    }

    hits
}
