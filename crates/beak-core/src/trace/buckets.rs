use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::trace::micro_ops::{ChipRow, GateValue, Interaction, MicroOp, ZKVMTrace};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketType {
    NextPcUnderconstrained,
    GateBoolDomain,
    InactiveRowSideEffects,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketHit {
    pub bucket_type: BucketType,
    pub core_instruction_idxs: Vec<usize>,
    #[serde(default)]
    pub details: HashMap<String, Value>,
}

pub trait Bucket: Send + Sync {
    fn bucket_type(&self) -> BucketType;

    /// Returns a hit if this bucket matches the op-level micro-ops.
    fn match_hit(&self, context: &ZKVMTrace, op_idx: usize, op_micro_ops: &[MicroOp])
        -> Option<BucketHit>;
}

fn gate_value_is_activated(v: &GateValue) -> Option<bool> {
    // We only treat canonical 0/1 as meaningful. Anything else is "unknown".
    if *v == GateValue::from(0u64) {
        Some(false)
    } else if *v == GateValue::from(1u64) {
        Some(true)
    } else {
        None
    }
}

fn gate_value_to_json(v: &GateValue) -> Value {
    // Keep it lossless / cross-backend friendly (U256).
    Value::String(format!("{v:?}"))
}

fn interaction_kind_to_json(i: &Interaction) -> Value {
    Value::String(format!("{:?}", i.kind()))
}

fn multiplicity_value_to_json(v: &Option<crate::trace::micro_ops::FieldElement>) -> Value {
    match v {
        Some(x) => Value::String(format!("{x:?}")),
        None => Value::Null,
    }
}

pub struct NextPcUnderconstrainedBucket {
    instruction_label: String,
    chip: String,
    is_real_gate: String,
    min_following_instructions: usize,
}

impl NextPcUnderconstrainedBucket {
    pub fn new(
        instruction_label: impl Into<String>,
        chip: impl Into<String>,
        is_real_gate: impl Into<String>,
        min_following_instructions: usize,
    ) -> Result<Self, String> {
        let instruction_label = instruction_label.into();
        let chip = chip.into();
        let is_real_gate = is_real_gate.into();
        if chip.trim().is_empty() {
            return Err("chip must be a non-empty string".to_string());
        }
        Ok(Self {
            instruction_label,
            chip,
            is_real_gate,
            min_following_instructions,
        })
    }

    fn is_real_row(&self, row: &ChipRow) -> bool {
        // If the backend doesn't expose is_real, treat the row as eligible.
        let Some(v) = row.gates.get(&self.is_real_gate) else {
            return true;
        };
        gate_value_is_activated(v) == Some(true)
    }
}

impl Bucket for NextPcUnderconstrainedBucket {
    fn bucket_type(&self) -> BucketType {
        BucketType::NextPcUnderconstrained
    }

    fn match_hit(
        &self,
        context: &ZKVMTrace,
        op_idx: usize,
        op_micro_ops: &[MicroOp],
    ) -> Option<BucketHit> {
        // This bucket is op-level: we need op_spans so we can talk about "following ops".
        let spans = context.op_spans.as_ref()?;
        if op_idx >= spans.len() {
            return None;
        }

        let mut matched_chip_row: Option<&ChipRow> = None;
        for uop in op_micro_ops {
            let MicroOp::ChipRow(row) = uop else { continue };
            if row.chip != self.chip {
                continue;
            }
            if !self.is_real_row(row) {
                continue;
            }
            matched_chip_row = Some(row);
            break;
        }
        let matched_chip_row = matched_chip_row?;

        let following_ops = spans.len().saturating_sub(op_idx + 1);
        if following_ops < self.min_following_instructions {
            return None;
        }

        Some(BucketHit {
            bucket_type: self.bucket_type(),
            core_instruction_idxs: vec![op_idx],
            details: HashMap::from([
                (
                    "instruction_label".to_string(),
                    Value::String(self.instruction_label.clone()),
                ),
                ("chip".to_string(), Value::String(matched_chip_row.chip.clone())),
                (
                    "min_following_instructions".to_string(),
                    json!(self.min_following_instructions),
                ),
                ("following_ops".to_string(), json!(following_ops)),
            ]),
        })
    }
}

pub struct GateBoolDomainBucket {
    gate_keys: Vec<String>,
}

impl GateBoolDomainBucket {
    pub fn new(gate_keys: Option<Vec<String>>) -> Self {
        Self {
            gate_keys: gate_keys.unwrap_or_else(|| vec!["is_real".to_string(), "is_valid".to_string()]),
        }
    }
}

impl Bucket for GateBoolDomainBucket {
    fn bucket_type(&self) -> BucketType {
        BucketType::GateBoolDomain
    }

    fn match_hit(
        &self,
        _context: &ZKVMTrace,
        op_idx: usize,
        op_micro_ops: &[MicroOp],
    ) -> Option<BucketHit> {
        // Build per-op chip rows with gates, plus a row_id -> row mapping.
        let mut anchored_rows: HashMap<String, &ChipRow> = HashMap::new();
        for uop in op_micro_ops {
            let MicroOp::ChipRow(row) = uop else { continue };
            anchored_rows.insert(row.row_id.clone(), row);
        }

        let mut hits: Vec<Value> = Vec::new();
        for uop in op_micro_ops {
            let MicroOp::Interaction(interaction) = uop else { continue };
            let base = interaction.base();
            let Some(mult) = &base.multiplicity else { continue };
            let Some(mult_ref) = mult.ref_.as_deref() else { continue };
            let Some(anchor) = base.anchor_row_id.as_deref() else { continue };
            let Some(candidate) = anchored_rows.get(anchor) else { continue };

            for key in &self.gate_keys {
                // Strict linkage: require the interaction to declare it is using this gate field.
                if mult_ref != format!("gates.{key}") {
                    continue;
                }
                let Some(gate_value) = candidate.gates.get(key) else { continue };
                hits.push(json!({
                    "gate": key,
                    "gate_value": gate_value_to_json(gate_value),
                    "chip": candidate.chip,
                    "interaction_table_id": base.table_id,
                    "interaction_kind": interaction_kind_to_json(interaction),
                    "multiplicity": multiplicity_value_to_json(&mult.value),
                    "multiplicity_ref": mult_ref,
                    "anchor_row_id": anchor,
                }));
                break;
            }
        }

        if hits.is_empty() {
            return None;
        }

        Some(BucketHit {
            bucket_type: self.bucket_type(),
            core_instruction_idxs: vec![op_idx],
            details: HashMap::from([
                (
                    "status".to_string(),
                    Value::String("gate_used_as_multiplicity".to_string()),
                ),
                ("match_count".to_string(), json!(hits.len())),
                ("example".to_string(), hits[0].clone()),
            ]),
        })
    }
}

pub struct InactiveRowEffectsBucket {
    activation_gate: String,
    effect_gate_keys: Vec<String>,
    effect_attr_keys: Vec<String>,
}

impl InactiveRowEffectsBucket {
    pub fn new(
        activation_gate: impl Into<String>,
        effect_gate_keys: Option<Vec<String>>,
        effect_attr_keys: Option<Vec<String>>,
    ) -> Self {
        Self {
            activation_gate: activation_gate.into(),
            effect_gate_keys: effect_gate_keys.unwrap_or_default(),
            // NOTE: `ChipRow` currently only exposes `gates`; attribute-level checks are kept for API
            // compatibility with the Python version but are not yet supported in Rust.
            effect_attr_keys: effect_attr_keys.unwrap_or_default(),
        }
    }

    fn is_effectful_interaction(interaction: &Interaction) -> bool {
        let Some(mult) = &interaction.base().multiplicity else {
            return true;
        };
        let Some(v) = &mult.value else {
            return true;
        };
        *v != GateValue::from(0u64)
    }
}

impl Bucket for InactiveRowEffectsBucket {
    fn bucket_type(&self) -> BucketType {
        BucketType::InactiveRowSideEffects
    }

    fn match_hit(
        &self,
        _context: &ZKVMTrace,
        op_idx: usize,
        op_micro_ops: &[MicroOp],
    ) -> Option<BucketHit> {
        let mut anchored_rows: HashMap<String, &ChipRow> = HashMap::new();
        for uop in op_micro_ops {
            let MicroOp::ChipRow(row) = uop else { continue };
            anchored_rows.insert(row.row_id.clone(), row);
        }

        let mut inactive_rows: Vec<&ChipRow> = Vec::new();
        let mut inactive_row_ids: Vec<String> = Vec::new();
        for uop in op_micro_ops {
            let MicroOp::ChipRow(row) = uop else { continue };
            let Some(v) = row.gates.get(&self.activation_gate) else { continue };
            if gate_value_is_activated(v) == Some(false) {
                inactive_rows.push(row);
                inactive_row_ids.push(row.row_id.clone());
            }
        }
        if inactive_rows.is_empty() {
            return None;
        }

        let inactive_row_id_set: HashSet<String> = inactive_row_ids.iter().cloned().collect();
        let mut effectful_interactions: Vec<&Interaction> = Vec::new();
        for uop in op_micro_ops {
            let MicroOp::Interaction(interaction) = uop else { continue };
            let Some(anchor) = interaction.base().anchor_row_id.as_deref() else {
                continue;
            };
            if !inactive_row_id_set.contains(anchor) {
                continue;
            }
            if !anchored_rows.contains_key(anchor) {
                continue;
            }
            if Self::is_effectful_interaction(interaction) {
                effectful_interactions.push(interaction);
            }
        }

        let mut flagged: Vec<Value> = Vec::new();
        for row in &inactive_rows {
            for k in &self.effect_gate_keys {
                let Some(v) = row.gates.get(k) else { continue };
                if gate_value_is_activated(v) == Some(true) {
                    flagged.push(json!({
                        "source": "gates",
                        "key": k,
                        "value": gate_value_to_json(v),
                    }));
                    break;
                }
            }

            // Placeholder for attribute-based checks (not yet supported by ChipRow).
            for _k in &self.effect_attr_keys {
                // no-op
            }
        }

        if effectful_interactions.is_empty() && flagged.is_empty() {
            return None;
        }

        let example_interaction = effectful_interactions.first().copied();
        Some(BucketHit {
            bucket_type: self.bucket_type(),
            core_instruction_idxs: vec![op_idx],
            details: HashMap::from([
                (
                    "activation_gate".to_string(),
                    Value::String(self.activation_gate.clone()),
                ),
                ("inactive_row_count".to_string(), json!(inactive_rows.len())),
                (
                    "effectful_interaction_count".to_string(),
                    json!(effectful_interactions.len()),
                ),
                ("flagged_count".to_string(), json!(flagged.len())),
                (
                    "example".to_string(),
                    json!({
                        "inactive_chip": inactive_rows.first().map(|r| r.chip.clone()).unwrap_or_default(),
                        "inactive_row_id": inactive_rows.first().map(|r| r.row_id.clone()).unwrap_or_default(),
                        "interaction_table_id": example_interaction.map(|i| i.base().table_id.clone()),
                        "interaction_kind": example_interaction.map(interaction_kind_to_json).unwrap_or(Value::Null),
                        "interaction_anchor_row_id": example_interaction.and_then(|i| i.base().anchor_row_id.clone()),
                        "flagged": flagged.first().cloned().unwrap_or(Value::Null),
                    }),
                ),
            ]),
        })
    }
}

pub type BucketBox = Box<dyn Bucket>;

/// Convenience factory for SP1 instruction chips that expose `pc`/`next_pc`.
///
/// These buckets are meant to drive Loop2-style injections that mutate `next_pc`
/// to skip at least one subsequent instruction.
pub fn sp1_next_pc_underconstrained_buckets(min_following_instructions: usize) -> Vec<BucketBox> {
    let chips = [
        // control-flow
        "AUIPC",
        "Branch",
        "Jump",
        "SyscallInstrs",
        // common instruction families
        "AddSub",
        "Bitwise",
        "Mul",
        "DivRem",
        "ShiftLeft",
        "ShiftRight",
        "Lt",
        "MemoryInstructions",
    ];

    chips
        .into_iter()
        .filter_map(|chip| {
            let b = NextPcUnderconstrainedBucket::new(
                format!("sp1.{chip}"),
                chip.to_string(),
                "is_real".to_string(),
                min_following_instructions,
            )
            .ok()?;
            Some(Box::new(b) as BucketBox)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::micro_ops::{
        CustomInteraction, InteractionBase, InteractionMultiplicity, InteractionType, MicroOp,
    };

    fn chip_row(row_id: &str, chip: &str, gates: &[(&str, u64)]) -> MicroOp {
        let mut m = HashMap::new();
        for (k, v) in gates {
            m.insert((*k).to_string(), GateValue::from(*v));
        }
        MicroOp::ChipRow(ChipRow {
            row_id: row_id.to_string(),
            domain: "d".to_string(),
            chip: chip.to_string(),
            kind: crate::trace::micro_ops::ChipRowKind::CUSTOM,
            gates: m,
            event_id: None,
        })
    }

    fn custom_interaction(
        table_id: &str,
        anchor_row_id: Option<&str>,
        multiplicity_ref: Option<&str>,
        multiplicity_value: Option<u64>,
    ) -> MicroOp {
        let mut base = InteractionBase::default();
        base.table_id = table_id.to_string();
        base.io = InteractionType::SEND;
        base.anchor_row_id = anchor_row_id.map(|s| s.to_string());
        base.multiplicity = Some(InteractionMultiplicity {
            value: multiplicity_value.map(GateValue::from),
            ref_: multiplicity_ref.map(|s| s.to_string()),
        });
        MicroOp::Interaction(Interaction::Custom(CustomInteraction {
            base,
            a0: GateValue::from(0u64),
            a1: GateValue::from(0u64),
            a2: GateValue::from(0u64),
            a3: GateValue::from(0u64),
        }))
    }

    #[test]
    fn next_pc_underconstrained_matches_chip_row_and_following_ops() {
        let micro_ops = vec![
            chip_row("r0", "AddSub", &[("is_real", 1)]),
            chip_row("r1", "Other", &[("is_real", 1)]),
            chip_row("r2", "Other", &[("is_real", 1)]),
        ];
        let trace = ZKVMTrace::new(
            micro_ops.clone(),
            None,
            Some(vec![vec![0], vec![1], vec![2]]),
        )
        .unwrap();
        let op_micro_ops = vec![micro_ops[0].clone()];
        let bucket = NextPcUnderconstrainedBucket::new("sp1.AddSub", "AddSub", "is_real", 2).unwrap();
        let hit = bucket.match_hit(&trace, 0, &op_micro_ops);
        assert!(hit.is_some());
    }

    #[test]
    fn gate_bool_domain_matches_when_used_as_multiplicity() {
        let micro_ops = vec![
            chip_row("r0", "Foo", &[("is_real", 1)]),
            custom_interaction("t", Some("r0"), Some("gates.is_real"), Some(1)),
        ];
        let trace = ZKVMTrace::new(micro_ops.clone(), None, Some(vec![vec![0, 1]])).unwrap();
        let bucket = GateBoolDomainBucket::new(None);
        let hit = bucket.match_hit(&trace, 0, &micro_ops);
        assert!(hit.is_some());
    }

    #[test]
    fn inactive_row_effects_matches_on_effectful_interaction_or_flagged_gate() {
        let micro_ops = vec![
            chip_row("r0", "Foo", &[("is_real", 0), ("wen", 1)]),
            custom_interaction("t", Some("r0"), Some("gates.wen"), Some(1)),
        ];
        let trace = ZKVMTrace::new(micro_ops.clone(), None, Some(vec![vec![0, 1]])).unwrap();
        let bucket = InactiveRowEffectsBucket::new("is_real", Some(vec!["wen".to_string()]), None);
        let hit = bucket.match_hit(&trace, 0, &micro_ops);
        assert!(hit.is_some());
    }
}
