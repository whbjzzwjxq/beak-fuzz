use std::collections::{HashMap, HashSet};

use beak_core::trace::BucketHit;
use serde_json::{json, Value};

use crate::bucket_id::PicoBucketId;
use crate::trace::PicoTrace;

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
    bucket_id: PicoBucketId,
    details: HashMap<String, Value>,
) {
    let id = bucket_id.as_ref().to_string();
    if !seen.insert(id.clone()) {
        return;
    }
    hits.push(BucketHit::new(id, details));
}

pub fn match_bucket_hits(trace: &PicoTrace) -> Vec<BucketHit> {
    let mut hits = Vec::new();
    let mut seen = HashSet::<String>::new();
    let mut saw_store = false;

    for insn in trace.instructions() {
        match insn.mnemonic.as_str() {
            "lw" => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    PicoBucketId::InputHasLoad,
                    HashMap::new(),
                );
                push_hit(
                    &mut hits,
                    &mut seen,
                    PicoBucketId::SemMemoryTimestampedLoadPath,
                    details_kv(&[
                        ("step_idx", json!(insn.step_idx)),
                        ("word", json!(format!("0x{:08x}", insn.word))),
                    ]),
                );
                if saw_store {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        PicoBucketId::SemLookupBooleanMultiplicity,
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
                    PicoBucketId::InputHasStore,
                    HashMap::new(),
                );
                saw_store = true;
                if insn.rs1 == Some(0) && insn.imm == Some(0) {
                    push_hit(
                        &mut hits,
                        &mut seen,
                        PicoBucketId::RegStoreAddrZeroViaX0,
                        details_kv(&[
                            ("step_idx", json!(insn.step_idx)),
                            ("word", json!(format!("0x{:08x}", insn.word))),
                        ]),
                    );
                }
            }
            "auipc" => {
                push_hit(
                    &mut hits,
                    &mut seen,
                    PicoBucketId::InputHasAuipc,
                    HashMap::new(),
                );
            }
            _ => {}
        }
    }

    hits
}
