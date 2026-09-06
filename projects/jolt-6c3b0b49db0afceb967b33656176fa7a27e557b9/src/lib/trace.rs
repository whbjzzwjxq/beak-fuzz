use std::collections::HashMap;

use beak_core::trace::{semantic, BucketHit, Trace};
use common::rv_trace::ELFInstruction;
use serde_json::{json, Value};

const BACKEND: &str = "jolt";
const COMMIT: &str = "6c3b0b49db0afceb967b33656176fa7a27e557b9";

pub struct JoltTrace {
    bucket_hits: Vec<BucketHit>,
    instruction_count: usize,
}

fn push_table_hit_extra(
    hits: &mut Vec<BucketHit>,
    bucket: semantic::SemanticBucket,
    obligation_id: &str,
    cell_id: &str,
    trace_source: &str,
    step_idx: u64,
    extras: &[(&str, Value)],
) {
    let mut details = HashMap::from([
        ("obligation_id".to_string(), json!(obligation_id)),
        ("cell_id".to_string(), json!(cell_id)),
        ("op_idx".to_string(), json!(step_idx)),
        ("step_idx".to_string(), json!(step_idx)),
        ("backend".to_string(), json!(BACKEND)),
        ("commit".to_string(), json!(COMMIT)),
        ("trace_source".to_string(), json!(trace_source)),
    ]);
    for (key, value) in extras {
        details.insert((*key).to_string(), value.clone());
    }
    hits.push(BucketHit::semantic(bucket, details));
}

pub fn bytecode_boundary_hit_from_receipt(raw: &str) -> Option<BucketHit> {
    let receipt: Value = serde_json::from_str(raw).ok()?;
    let receipt = receipt.as_object()?;
    let schema_version = receipt.get("schema_version")?.as_u64()?;
    let relation = receipt.get("relation")?.as_str()?;
    let table_name = receipt.get("table_name")?.as_str()?;
    let population_start = usize::try_from(receipt.get("population_start")?.as_u64()?).ok()?;
    let population_end = usize::try_from(receipt.get("population_end")?.as_u64()?).ok()?;
    let population_rows = usize::try_from(receipt.get("population_rows")?.as_u64()?).ok()?;
    let allocated_rows = usize::try_from(receipt.get("allocated_rows")?.as_u64()?).ok()?;
    let boundary_k = u32::try_from(receipt.get("boundary_k")?.as_u64()?).ok()?;
    let receipt_exact_crossing = receipt.get("exact_crossing")?.as_bool()?;
    let expected_end = population_start.checked_add(population_rows)?;
    let boundary_rows = 1usize.checked_shl(boundary_k)?;
    let exact_crossing = schema_version == 1
        && relation == "preprocessed_bytecode_end_crosses_allocated_rows_by_one"
        && table_name == "read_write_memory.v_init"
        && receipt_exact_crossing
        && population_rows > 0
        && allocated_rows.is_power_of_two()
        && boundary_rows == allocated_rows
        && expected_end == population_end
        && population_end > allocated_rows;
    if !exact_crossing {
        return None;
    }

    let mut hits = Vec::new();
    push_table_hit_extra(
        &mut hits,
        semantic::row::BYTECODE_TABLE_BOUNDARY,
        "pd4",
        "pd4.just_over",
        "jolt.read_write_memory.preprocessed_bytecode",
        allocated_rows as u64,
        &[
            ("table_name", json!(table_name)),
            ("population_start", json!(population_start)),
            ("population_end", json!(population_end)),
            ("population_rows", json!(population_rows)),
            ("allocated_rows", json!(allocated_rows)),
            ("boundary_k", json!(boundary_k)),
            ("exact_crossing", json!(true)),
            ("relation", json!(relation)),
            ("relation_valid", json!(true)),
        ],
    );
    hits.pop()
}

impl JoltTrace {
    pub fn from_execution(bytecode: &[ELFInstruction]) -> Result<Self, String> {
        Ok(Self { bucket_hits: Vec::new(), instruction_count: bytecode.len() })
    }

    #[allow(dead_code)]
    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }
}

#[cfg(test)]
mod tests {
    use super::bytecode_boundary_hit_from_receipt;

    fn receipt(population_start: usize, population_rows: usize, allocated_rows: usize) -> String {
        let population_end = population_start + population_rows;
        format!(
            r#"{{"schema_version":1,"relation":"preprocessed_bytecode_end_crosses_allocated_rows_by_one","table_name":"read_write_memory.v_init","population_start":{population_start},"population_end":{population_end},"population_rows":{population_rows},"allocated_rows":{allocated_rows},"boundary_k":{},"exact_crossing":{}}}"#,
            allocated_rows.trailing_zeros(),
            population_end == allocated_rows + 1,
        )
    }

    #[test]
    fn exact_preprocessed_bytecode_crossing_emits_pd4() {
        let hit = bytecode_boundary_hit_from_receipt(&receipt(12, 5, 16)).unwrap();
        assert_eq!(hit.bucket_id, "sem.row.bytecode_table_boundary");
        assert_eq!(hit.details["cell_id"], "pd4.just_over");
        assert_eq!(hit.details["population_end"], 17);
        assert_eq!(hit.details["allocated_rows"], 16);
        assert_eq!(hit.details["step_idx"], 16);
        assert_eq!(hit.details["relation_valid"], true);
    }

    #[test]
    fn nearby_and_invalid_population_receipts_stay_clean() {
        assert!(bytecode_boundary_hit_from_receipt(&receipt(12, 4, 16)).is_none());
        assert!(bytecode_boundary_hit_from_receipt(&receipt(12, 6, 16)).is_none());
        assert!(bytecode_boundary_hit_from_receipt("{}").is_none());
        assert!(bytecode_boundary_hit_from_receipt(
            r#"{"schema_version":1,"relation":"unsupported","table_name":"read_write_memory.v_init","population_start":12,"population_end":17,"population_rows":5,"allocated_rows":16,"boundary_k":4,"exact_crossing":true}"#,
        )
        .is_none());
        assert!(bytecode_boundary_hit_from_receipt(
            r#"{"schema_version":1,"relation":"preprocessed_bytecode_end_crosses_allocated_rows_by_one","table_name":"read_write_memory.v_init","population_start":12,"population_end":17,"population_rows":5,"allocated_rows":16,"boundary_k":4,"exact_crossing":false}"#,
        )
        .is_none());
        assert!(bytecode_boundary_hit_from_receipt(
            r#"{"schema_version":1,"relation":"preprocessed_bytecode_end_crosses_allocated_rows_by_one","table_name":"read_write_memory.v_init","population_start":12,"population_end":17,"population_rows":5,"allocated_rows":16,"exact_crossing":true}"#,
        )
        .is_none());
    }
}

impl Trace for JoltTrace {
    fn bucket_hits(&self) -> &[BucketHit] {
        &self.bucket_hits
    }
}
