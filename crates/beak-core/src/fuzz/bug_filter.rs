use std::collections::HashSet;

use serde_json::Value;

use crate::fuzz::benchmark::{ExecutedExceptionEffect, ExecutedExceptionReceipt};
use crate::trace::BucketHit;

const UNSUPPORTED_EXCEPTION_PATTERNS: &[&str] = &[
    "Invalid trap address: 0x00000000, cause: IllegalInstruction",
    "IllegalInstruction(",
    "unsupported CSR",
    "unsupported rv32 mnemonic",
    "decode failed for 0x10200073",
    "emulator emulate_batch(trace) failed: Unimplemented",
    "execute_metered failed: FailedWithExitCode(2)",
];

const CSR_SURFACE_SOURCE: &str = "storage/riscv-tests-artifacts/rv32si-p-csr.dump";

fn metadata_str<'a>(metadata: &'a Value, key: &str) -> Option<&'a str> {
    metadata.as_object()?.get(key)?.as_str()
}

pub fn is_suppressed_exception(
    seed_or_record_metadata: &Value,
    backend_error: Option<&str>,
    oracle_error: Option<&str>,
) -> bool {
    let message = backend_error.or(oracle_error).unwrap_or_default();
    if UNSUPPORTED_EXCEPTION_PATTERNS.iter().any(|pattern| message.contains(pattern)) {
        return true;
    }

    metadata_str(seed_or_record_metadata, "source") == Some(CSR_SURFACE_SOURCE)
}

fn hit_u64(hit: &BucketHit, key: &str) -> Option<u64> {
    hit.details.get(key)?.as_u64()
}

fn hit_i64(hit: &BucketHit, key: &str) -> Option<i64> {
    hit.details.get(key)?.as_i64()
}

fn hit_str<'a>(hit: &'a BucketHit, key: &str) -> Option<&'a str> {
    hit.details.get(key)?.as_str()
}

fn hit_bool(hit: &BucketHit, key: &str) -> Option<bool> {
    hit.details.get(key)?.as_bool()
}

fn hit_u64_array(hit: &BucketHit, key: &str) -> Option<Vec<u64>> {
    hit.details.get(key)?.as_array()?.iter().map(Value::as_u64).collect()
}

fn exact_receipt_source_identity(hit: &BucketHit, receipt: &ExecutedExceptionReceipt) -> bool {
    ["backend", "commit", "trace_source"].into_iter().all(|key| {
        let hit_value = hit_str(hit, key);
        let receipt_value = receipt.context.get(key).and_then(Value::as_str);
        hit_value.is_some_and(|value| !value.trim().is_empty()) && receipt_value == hit_value
    })
}

fn exact_receipt_source_identity_for(
    hit: &BucketHit,
    receipt: &ExecutedExceptionReceipt,
    backend: &str,
    commit: &str,
    trace_source: &str,
) -> bool {
    exact_receipt_source_identity(hit, receipt)
        && hit_str(hit, "backend") == Some(backend)
        && hit_str(hit, "commit") == Some(commit)
        && hit_str(hit, "trace_source") == Some(trace_source)
}

/// Every execution anchor emitted by a hit must name the receipt's exact row.
/// Accepting when only one of `op_idx`/`step_idx` matches lets a stale receipt
/// borrow an otherwise valid relation from a different executed instruction.
fn exact_execution_anchor(hit: &BucketHit, receipt: &ExecutedExceptionReceipt) -> bool {
    let anchors = ["op_idx", "step_idx"]
        .into_iter()
        .filter_map(|key| hit_u64(hit, key))
        .collect::<Vec<_>>();
    !anchors.is_empty() && anchors.into_iter().all(|anchor| anchor == receipt.step)
}

fn receipt_context_matches_hit(
    hit: &BucketHit,
    receipt: &ExecutedExceptionReceipt,
    keys: &[&str],
) -> bool {
    keys.iter().all(|key| {
        hit.details.get(*key).is_some()
            && receipt.context.get(*key).is_some()
            && hit.details.get(*key) == receipt.context.get(*key)
    })
}

fn exact_failure_manifestation(
    receipt: &ExecutedExceptionReceipt,
    expected: &str,
) -> bool {
    receipt.context.get("failure_observed").and_then(Value::as_bool) == Some(true)
        && receipt.context.get("failure_manifestation").and_then(Value::as_str) == Some(expected)
}

fn exact_memory_table_crossing(hit: &BucketHit) -> bool {
    let (
        Some(population),
        Some(allocated),
        Some(public),
        Some(boundary_k),
        Some(crossing_row_idx),
        Some(overflow_rows),
    ) = (
        hit_u64(hit, "population_rows"),
        hit_u64(hit, "allocated_rows"),
        hit_u64(hit, "public_rows"),
        hit_u64(hit, "boundary_k"),
        hit_u64(hit, "crossing_row_idx"),
        hit_u64(hit, "overflow_rows"),
    )
    else {
        return false;
    };
    hit.bucket_id == "sem.row.table_power2_boundary"
        && hit_str(hit, "cell_id") == Some("pd3.mem_table")
        && hit_str(hit, "table_name") == Some("rw_mem_check.last_access")
        && hit_str(hit, "relation")
            == Some("last_access_population_crosses_allocated_rows_at_first_overflow")
        && hit_bool(hit, "exact_crossing") == Some(true)
        && hit_bool(hit, "relation_valid") == Some(true)
        && allocated.is_power_of_two()
        && 1u64.checked_shl(boundary_k as u32) == Some(allocated)
        && population > allocated
        && crossing_row_idx == allocated
        && population.checked_sub(allocated) == Some(overflow_rows)
        && public <= allocated
}

fn exact_memory_table_receipt_context(hit: &BucketHit, receipt: &ExecutedExceptionReceipt) -> bool {
    let context_u64 = |key: &str| receipt.context.get(key).and_then(Value::as_u64);
    [
        "population_rows",
        "allocated_rows",
        "public_rows",
        "boundary_k",
        "crossing_row_idx",
        "overflow_rows",
    ]
    .into_iter()
    .all(|key| context_u64(key) == hit_u64(hit, key))
        && context_u64("failing_row_idx") == Some(receipt.step)
        && context_u64("crossing_row_idx") == Some(receipt.step)
        && receipt.context.get("table_name").and_then(Value::as_str)
            == hit.details.get("table_name").and_then(Value::as_str)
        && receipt.context.get("relation").and_then(Value::as_str)
            == hit.details.get("relation").and_then(Value::as_str)
        && receipt.context.get("exact_crossing").and_then(Value::as_bool) == Some(true)
        && receipt.context.get("relation_valid").and_then(Value::as_bool) == Some(true)
        && exact_failure_manifestation(receipt, "capacity_write_out_of_bounds")
}

fn exact_bytecode_table_crossing(hit: &BucketHit) -> bool {
    let (Some(start), Some(end), Some(population), Some(allocated), Some(boundary_k)) = (
        hit_u64(hit, "population_start"),
        hit_u64(hit, "population_end"),
        hit_u64(hit, "population_rows"),
        hit_u64(hit, "allocated_rows"),
        hit_u64(hit, "boundary_k"),
    ) else {
        return false;
    };
    hit.bucket_id == "sem.row.bytecode_table_boundary"
        && hit_str(hit, "cell_id") == Some("pd4.just_over")
        && hit_str(hit, "table_name") == Some("read_write_memory.v_init")
        && hit_str(hit, "relation")
            == Some("preprocessed_bytecode_end_crosses_allocated_rows_by_one")
        && hit_bool(hit, "exact_crossing") == Some(true)
        && hit_bool(hit, "relation_valid") == Some(true)
        && population > 0
        && allocated.is_power_of_two()
        && 1u64.checked_shl(boundary_k as u32) == Some(allocated)
        && start.checked_add(population) == Some(end)
        && end > allocated
}

fn exact_bytecode_table_receipt_context(
    hit: &BucketHit,
    receipt: &ExecutedExceptionReceipt,
) -> bool {
    let context_u64 = |key: &str| receipt.context.get(key).and_then(Value::as_u64);
    ["population_start", "population_end", "population_rows", "allocated_rows", "boundary_k"]
        .into_iter()
        .all(|key| context_u64(key) == hit_u64(hit, key))
        && receipt.context.get("table_name").and_then(Value::as_str)
            == hit.details.get("table_name").and_then(Value::as_str)
        && receipt.context.get("exact_crossing").and_then(Value::as_bool) == Some(true)
        && receipt.context.get("relation").and_then(Value::as_str)
            == hit.details.get("relation").and_then(Value::as_str)
        && receipt.context.get("relation_valid").and_then(Value::as_bool) == Some(true)
        && context_u64("failing_index") == Some(receipt.step)
        && hit_u64(hit, "step_idx") == Some(receipt.step)
        && context_u64("failing_index") == context_u64("allocated_rows")
        && exact_failure_manifestation(receipt, "capacity_write_out_of_bounds")
}

fn exact_mul_overflow_relation(hit: &BucketHit) -> bool {
    let (Some(lhs), Some(rhs), Some(product_hi), Some(product_lo), Some(expected), Some(observed)) = (
        hit_u64(hit, "rs1_val"),
        hit_u64(hit, "rs2_val"),
        hit_u64(hit, "product_hi"),
        hit_u64(hit, "product_lo"),
        hit_u64(hit, "expected_rd_val"),
        hit_u64(hit, "observed_rd_val"),
    ) else {
        return false;
    };
    let product = u128::from(lhs).checked_mul(u128::from(rhs));
    hit.bucket_id == "sem.arithmetic.product_decomposition"
        && hit_str(hit, "cell_id") == Some("md4.mul_overflow")
        && hit_str(hit, "mnemonic") == Some("mul")
        && hit_str(hit, "relation") == Some("product_hi_lo_matches_operands")
        && hit_bool(hit, "relation_valid") == Some(true)
        && product.is_some_and(|value| {
            product_lo == value as u32 as u64
                && product_hi == ((value >> 32) as u32 as u64)
                && product_hi > 0
        })
        && expected == product_lo
        && observed == expected
}

fn nexus_mul_carry_1(lhs: u32, rhs: u32) -> u32 {
    let b = lhs.to_le_bytes().map(u32::from);
    let c = rhs.to_le_bytes().map(u32::from);
    let z = std::array::from_fn::<_, 4, _>(|idx| b[idx] * c[idx]);
    let p1 = (c[0] + c[1]) * (b[0] + b[1]) - z[0] - z[1];
    let p2_prime = (c[0] + c[2]) * (b[0] + b[2]) - z[0] - z[2];
    let p3_prime = (c[0] + c[3]) * (b[0] + b[3]) - z[0] - z[3];
    let p3_prime_prime = (c[1] + c[2]) * (b[1] + b[2]) - z[1] - z[2];
    let carry_0 = (z[0] + ((p1 & 0xff) << 8)) >> 16;
    let a23 = z[1]
        + ((p1 >> 8) & 0xff)
        + p2_prime
        + carry_0
        + (((p3_prime & 0xff) + (p3_prime_prime & 0xff) + (p1 >> 16)) << 8);
    a23 >> 16
}

fn exact_mul_overflow_receipt_context(
    hit: &BucketHit,
    receipt: &ExecutedExceptionReceipt,
) -> bool {
    let context_u64 = |key: &str| receipt.context.get(key).and_then(Value::as_u64);
    let (Some(lhs), Some(rhs), Some(carry), Some(bound)) = (
        context_u64("rs1_val"),
        context_u64("rs2_val"),
        context_u64("carry_1"),
        context_u64("carry_bound_exclusive"),
    ) else {
        return false;
    };
    lhs <= u32::MAX as u64
        && rhs <= u32::MAX as u64
        && bound == 4
        && carry >= bound
        && nexus_mul_carry_1(lhs as u32, rhs as u32) == carry as u32
        && receipt_context_matches_hit(
            hit,
            receipt,
            &[
                "op_idx",
                "step_idx",
                "pc",
                "opcode",
                "mnemonic",
                "rs1_val",
                "rs2_val",
                "product_hi",
                "product_lo",
                "expected_rd_val",
                "observed_rd_val",
                "relation",
                "relation_valid",
            ],
        )
        && exact_failure_manifestation(receipt, "carry_bound_assertion")
}

fn exact_signed_divrem_relation(hit: &BucketHit) -> bool {
    let (Some(dividend), Some(divisor), Some(quotient), Some(remainder), Some(recomposed)) = (
        hit_i64(hit, "dividend"),
        hit_i64(hit, "divisor"),
        hit_i64(hit, "quotient"),
        hit_i64(hit, "remainder"),
        hit_i64(hit, "recomposed"),
    ) else {
        return false;
    };
    let cell = hit_str(hit, "cell_id").unwrap_or_default();
    let arithmetic = quotient.checked_mul(divisor).and_then(|value| value.checked_add(remainder));
    hit.bucket_id == "sem.arithmetic.division_remainder_bound"
        && cell.starts_with("md3.")
        && cell != "md3.unsigned"
        && matches!(hit_str(hit, "mnemonic"), Some("div" | "rem"))
        && hit_str(hit, "relation") == Some("quotient_times_divisor_plus_remainder")
        && hit_bool(hit, "relation_valid") == Some(true)
        && hit_bool(hit, "remainder_bound_holds") == Some(true)
        && hit_bool(hit, "remainder_sign_holds") == Some(true)
        && divisor != 0
        && arithmetic == Some(dividend)
        && recomposed == dividend
        && remainder.unsigned_abs() < divisor.unsigned_abs()
        && (remainder == 0 || remainder.signum() == dividend.signum())
}

fn exact_signed_divrem_receipt_context(
    hit: &BucketHit,
    receipt: &ExecutedExceptionReceipt,
) -> bool {
    receipt_context_matches_hit(
        hit,
        receipt,
        &[
            "op_idx",
            "step_idx",
            "pc",
            "opcode",
            "mnemonic",
            "dividend",
            "divisor",
            "quotient",
            "remainder",
            "recomposed",
            "remainder_bound_holds",
            "remainder_sign_holds",
            "relation",
            "relation_valid",
        ],
    ) && exact_failure_manifestation(receipt, "primary_sumcheck_mismatch")
}

fn exact_mulhsu_mismatch_relation(hit: &BucketHit) -> bool {
    let (
        Some(signed_lhs),
        Some(unsigned_rhs),
        Some(product_hi),
        Some(product_lo),
        Some(_architectural),
        Some(observed),
        Some(op_idx),
        Some(rd),
        Some(processed_row_idx),
        Some(segment_start),
        Some(segment_end),
        Some(final_write_step),
        Some(final_rd_address),
    ) = (
        hit_i64(hit, "signed_lhs"),
        hit_u64(hit, "unsigned_rhs"),
        hit_u64(hit, "product_hi"),
        hit_u64(hit, "product_lo"),
        hit_u64(hit, "architectural_result"),
        hit_u64(hit, "observed_result"),
        hit_u64(hit, "op_idx"),
        hit_u64(hit, "rd"),
        hit_u64(hit, "processed_row_idx"),
        hit_u64(hit, "processed_segment_start_step"),
        hit_u64(hit, "processed_segment_end_step"),
        hit_u64(hit, "processed_final_rd_write_step"),
        hit_u64(hit, "processed_final_rd_address"),
    ) else {
        return false;
    };
    let product = i128::from(signed_lhs) * i128::from(unsigned_rhs);
    let expected_lo = product as u32 as u64;
    let expected_hi = ((product as u128 >> 32) as u32) as u64;
    hit.bucket_id == "sem.arithmetic.signed_unsigned_product_correction"
        && hit_str(hit, "cell_id").is_some_and(|cell| cell.starts_with("md5."))
        && hit_str(hit, "mnemonic") == Some("mulhsu")
        && hit_str(hit, "relation") == Some("high32_signed_lhs_times_unsigned_rhs")
        && hit_bool(hit, "relation_valid") == Some(true)
        && hit_bool(hit, "result_mismatch") == Some(true)
        && hit_bool(hit, "result_matches") == Some(false)
        && hit_str(hit, "observed_result_source")
            == Some("processed_virtual_sequence.final_rd_write")
        && hit_u64(hit, "expected_high32") == Some(product_hi)
        && product_hi == expected_hi
        && product_lo == expected_lo
        && observed != product_hi
        // The architectural register state may itself diverge from the recomputed
        // product at this commit (executor-side mulhsu bug), so the exact gate is
        // the executed provenance plus the prover-claimed result disagreeing with
        // the spec recomputation.
        && processed_row_idx == op_idx
        && segment_start <= final_write_step
        && final_write_step <= segment_end
        && final_rd_address == rd
}

fn exact_mulhsu_receipt_context(hit: &BucketHit, receipt: &ExecutedExceptionReceipt) -> bool {
    receipt_context_matches_hit(
        hit,
        receipt,
        &[
            "op_idx",
            "step_idx",
            "pc",
            "opcode",
            "mnemonic",
            "signed_lhs",
            "unsigned_rhs",
            "product_hi",
            "product_lo",
            "expected_high32",
            "architectural_result",
            "architectural_result_matches",
            "observed_result",
            "observed_result_source",
            "rd",
            "processed_row_idx",
            "processed_segment_start_step",
            "processed_segment_end_step",
            "processed_final_rd_write_step",
            "processed_final_rd_address",
            "result_matches",
            "result_mismatch",
            "relation",
            "relation_valid",
        ],
    ) && exact_failure_manifestation(receipt, "inner_sumcheck_mismatch")
}

fn exact_dory_short_trace_relation(hit: &BucketHit) -> bool {
    let (
        Some(input_words_len),
        Some(unpadded_trace_len),
        Some(domain),
        Some(matrix_width),
        Some(dimension),
        Some(boundary_k),
    ) = (
        hit_u64(hit, "input_words_len"),
        hit_u64(hit, "unpadded_trace_len"),
        hit_u64(hit, "dory_domain_size"),
        hit_u64(hit, "matrix_width_k"),
        hit_u64(hit, "dory_dimension"),
        hit_u64(hit, "boundary_k"),
    )
    else {
        return false;
    };
    let recomputed_dimension =
        matrix_width.checked_mul(domain).map(u64::isqrt).and_then(u64::checked_next_power_of_two);
    hit.bucket_id == "sem.row.trace_power2_boundary"
        && hit_str(hit, "obligation_id") == Some("pd2")
        && hit_str(hit, "cell_id") == Some("pd2.very_short")
        && hit_str(hit, "trace_source") == Some("prover.dory")
        && hit_str(hit, "relation") == Some("dory_domain_not_greater_than_matrix_dimension")
        && hit_bool(hit, "relation_valid") == Some(true)
        && input_words_len > 0
        && input_words_len < 8
        && unpadded_trace_len >= input_words_len
        && unpadded_trace_len <= domain
        && domain.is_power_of_two()
        && domain == 32
        && unpadded_trace_len.checked_next_power_of_two() == Some(domain)
        && matrix_width > 0
        && recomputed_dimension == Some(dimension)
        && domain <= dimension
        && 1u64.checked_shl(boundary_k as u32) == Some(domain)
}

fn exact_dory_receipt_context(hit: &BucketHit, receipt: &ExecutedExceptionReceipt) -> bool {
    let context_u64 = |key: &str| receipt.context.get(key).and_then(Value::as_u64);
    [
        "input_words_len",
        "unpadded_trace_len",
        "dory_domain_size",
        "matrix_width_k",
        "dory_dimension",
        "boundary_k",
    ]
    .into_iter()
    .all(|key| context_u64(key) == hit_u64(hit, key))
        && context_u64("failing_domain_size") == hit_u64(hit, "dory_domain_size")
        && receipt.context.get("relation").and_then(Value::as_str)
            == hit.details.get("relation").and_then(Value::as_str)
}

fn exact_bigint_opcode_conversion_relation(hit: &BucketHit) -> bool {
    let (
        Some(global_opcode),
        Some(chip_class_offset),
        Some(local_opcode),
        Some(from_pc),
        Some(step),
        Some(supported),
    ) = (
        hit_u64(hit, "global_opcode"),
        hit_u64(hit, "chip_class_offset"),
        hit_u64(hit, "local_opcode"),
        hit_u64(hit, "from_pc"),
        hit_u64(hit, "step_idx"),
        hit_u64_array(hit, "supported_local_opcodes"),
    )
    else {
        return false;
    };
    hit.bucket_id == "sem.decode.field_range"
        && hit_str(hit, "obligation_id") == Some("id4")
        && hit_str(hit, "cell_id") == Some("id4.branch")
        && hit_str(hit, "backend") == Some("openvm")
        && hit_str(hit, "commit") == Some("336f1a475e5aa3513c4c5a266399f4128c119bba")
        && hit_str(hit, "trace_source")
            == Some("extensions/rv32im/circuit/src/branch_lt/core.rs::execute_instruction")
        && hit_str(hit, "conversion_target") == Some("BranchLessThanOpcode")
        && hit_str(hit, "relation") == Some("local_opcode_not_in_branch_less_than_domain")
        && hit_bool(hit, "relation_valid") == Some(true)
        && global_opcode == 0x425
        && chip_class_offset == 0x408
        && local_opcode == 29
        && global_opcode.checked_sub(chip_class_offset) == Some(local_opcode)
        && hit_u64(hit, "op_idx") == Some(step)
        && from_pc <= u32::MAX as u64
        && supported == [0, 1, 2, 3]
        && !supported.contains(&local_opcode)
}

fn exact_bigint_receipt_context(hit: &BucketHit, receipt: &ExecutedExceptionReceipt) -> bool {
    ["global_opcode", "chip_class_offset", "local_opcode", "from_pc"]
        .into_iter()
        .all(|key| receipt.context.get(key).and_then(Value::as_u64) == hit_u64(hit, key))
        && receipt
            .context
            .get("supported_local_opcodes")
            .and_then(Value::as_array)
            .and_then(|values| values.iter().map(Value::as_u64).collect::<Option<Vec<_>>>())
            == hit_u64_array(hit, "supported_local_opcodes")
        && ["conversion_target", "relation"].into_iter().all(|key| {
            receipt.context.get(key).and_then(Value::as_str)
                == hit.details.get(key).and_then(Value::as_str)
        })
        && receipt.context.get("relation_valid").and_then(Value::as_bool)
            == hit_bool(hit, "relation_valid")
        && receipt.context.get("hook_fired").and_then(Value::as_bool) == Some(true)
}

fn exact_control_done_capacity_relation(hit: &BucketHit) -> bool {
    let (
        Some(segment_idx),
        Some(po2),
        Some(capacity),
        Some(user),
        Some(pager),
        Some(lookup),
        Some(accounted),
        Some(control_done),
        Some(required),
        Some(overflow),
        Some(actual),
        Some(manifested),
    ) = (
        hit_u64(hit, "segment_idx"),
        hit_u64(hit, "segment_po2"),
        hit_u64(hit, "capacity_cycles"),
        hit_u64(hit, "user_cycles"),
        hit_u64(hit, "pager_cycles"),
        hit_u64(hit, "lookup_table_cycles"),
        hit_u64(hit, "accounted_cycles"),
        hit_u64(hit, "control_done_cycles_required"),
        hit_u64(hit, "required_cycles"),
        hit_u64(hit, "overflow_cycles"),
        hit_u64(hit, "actual_trace_cycles"),
        hit_u64(hit, "manifested_control_done_cycles"),
    )
    else {
        return false;
    };
    let recomputed_accounted = user.checked_add(pager).and_then(|value| value.checked_add(lookup));
    let recomputed_required = accounted.checked_add(control_done);
    let recomputed_actual = accounted.checked_add(manifested);
    hit.bucket_id == "sem.row.trace_power2_boundary"
        && hit_str(hit, "obligation_id") == Some("pd2")
        && hit_str(hit, "cell_id") == Some("pd2.just_over")
        && hit_str(hit, "trace_source") == Some("segment_finalization")
        && hit_str(hit, "relation") == Some("control_done_cycles_cross_segment_capacity")
        && hit_bool(hit, "relation_valid") == Some(true)
        && hit_bool(hit, "accounted_fits") == Some(true)
        && hit_bool(hit, "required_exceeds") == Some(true)
        && hit_u64(hit, "step_idx") == Some(segment_idx)
        && 1u64.checked_shl(po2 as u32) == Some(capacity)
        && recomputed_accounted == Some(accounted)
        && accounted <= capacity
        && control_done > 0
        && recomputed_required == Some(required)
        && required > capacity
        && required.checked_sub(capacity) == Some(overflow)
        && manifested == 1
        && recomputed_actual == Some(actual)
        && actual > capacity
        && actual.checked_add(1) == Some(required)
}

fn exact_control_done_receipt_context(hit: &BucketHit, receipt: &ExecutedExceptionReceipt) -> bool {
    let context_u64 = |key: &str| receipt.context.get(key).and_then(Value::as_u64);
    [
        "segment_idx",
        "segment_po2",
        "capacity_cycles",
        "user_cycles",
        "pager_cycles",
        "lookup_table_cycles",
        "accounted_cycles",
        "control_done_cycles_required",
        "required_cycles",
        "overflow_cycles",
        "actual_trace_cycles",
        "manifested_control_done_cycles",
    ]
    .into_iter()
    .all(|key| context_u64(key) == hit_u64(hit, key))
        && context_u64("segment_idx") == Some(receipt.step)
        && receipt.context.get("accounted_fits").and_then(Value::as_bool) == Some(true)
        && receipt.context.get("required_exceeds").and_then(Value::as_bool) == Some(true)
}

/// A baseline prover/executor exception is reportable only when the same ordinary run also
/// produced an executed/table-local exact obligation relation. This prevents broad runtime text
/// or input-only features from being promoted to reproducibility evidence.
pub fn has_exact_executed_exception_relation(
    hits: &[BucketHit],
    receipt: Option<&ExecutedExceptionReceipt>,
) -> bool {
    let Some(receipt) = receipt else {
        return false;
    };
    if receipt.obligation_id.trim().is_empty()
        || receipt.cell_id.trim().is_empty()
        || receipt.stage.trim().is_empty()
    {
        return false;
    }
    if std::env::var_os("BEAK_DEBUG_UC_GATES").is_some() {
        eprintln!(
            "BEAKDBG exc-relation hits={} receipt_obl={} cell={} stage={} effect={:?}",
            hits.len(), receipt.obligation_id, receipt.cell_id, receipt.stage, receipt.effect,
        );
        for hit in hits {
            let id_ok = hit_str(hit, "obligation_id") == Some(&receipt.obligation_id)
                && hit_str(hit, "cell_id") == Some(&receipt.cell_id);
            let anchor_ok = exact_execution_anchor(hit, receipt);
            let src_ok = exact_receipt_source_identity(hit, receipt);
            let extra = if receipt.effect == ExecutedExceptionEffect::MultiplicationCarryBound
            {
                let mismatches: Vec<String> = [
                    "op_idx",
                    "step_idx",
                    "pc",
                    "opcode",
                    "mnemonic",
                    "rs1_val",
                    "rs2_val",
                    "product_hi",
                    "product_lo",
                    "expected_rd_val",
                    "observed_rd_val",
                    "relation",
                    "relation_valid",
                ]
                .into_iter()
                .filter(|key| {
                    !(hit.details.get(*key).is_some()
                        && receipt.context.get(*key).is_some()
                        && hit.details.get(*key) == receipt.context.get(*key))
                })
                .map(|key| {
                    format!(
                        "{key}: hit={:?} rcpt={:?}",
                        hit.details.get(key),
                        receipt.context.get(key)
                    )
                })
                .collect();
                format!(
                    " rel={} ctx={} manifest={} mismatch=[{}]",
                    exact_mul_overflow_relation(hit),
                    exact_mul_overflow_receipt_context(hit, receipt),
                    exact_failure_manifestation(receipt, "carry_bound_assertion"),
                    mismatches.join("; "),
                )
            } else {
                String::new()
            };
            eprintln!(
                "BEAKDBG   hit bucket={} id_ok={} anchor_ok={} src_ok={}{}",
                hit.bucket_id, id_ok, anchor_ok, src_ok, extra,
            );
        }
    }
    hits.iter()
        .filter(|hit| {
            let identity_matches = hit_str(hit, "obligation_id") == Some(&receipt.obligation_id)
                && hit_str(hit, "cell_id") == Some(&receipt.cell_id);
            let effect_matches = match receipt.effect {
                ExecutedExceptionEffect::MemoryTableCapacityWrite => {
                    receipt.obligation_id == "pd3"
                        && receipt.cell_id == "pd3.mem_table"
                        && receipt.stage == "rw_mem_check.last_access.write"
                        && exact_memory_table_crossing(hit)
                        && exact_memory_table_receipt_context(hit, receipt)
                        && exact_receipt_source_identity_for(
                            hit,
                            receipt,
                            "nexus",
                            "41c6c6080f46b97980053c47b078321225b4338a",
                            "prover.rw_mem_check.last_access",
                        )
                }
                ExecutedExceptionEffect::BytecodeTableCapacityWrite => {
                    receipt.obligation_id == "pd4"
                        && receipt.cell_id == "pd4.just_over"
                        && receipt.stage == "read_write_memory.v_init.write"
                        && exact_bytecode_table_crossing(hit)
                        && exact_bytecode_table_receipt_context(hit, receipt)
                        && exact_receipt_source_identity_for(
                            hit,
                            receipt,
                            "jolt",
                            "6c3b0b49db0afceb967b33656176fa7a27e557b9",
                            "jolt.read_write_memory.preprocessed_bytecode",
                        )
                }
                ExecutedExceptionEffect::MultiplicationCarryBound => {
                    receipt.obligation_id == "md4"
                        && receipt.cell_id == "md4.mul_overflow"
                        && receipt.stage == "mul.witness.carry_1_bound"
                        && exact_mul_overflow_relation(hit)
                        && exact_mul_overflow_receipt_context(hit, receipt)
                        && exact_receipt_source_identity_for(
                            hit,
                            receipt,
                            "nexus",
                            "f1b895b868915fd4d0a794a5bc730e6cb8d840f6",
                            "instruction",
                        )
                }
                ExecutedExceptionEffect::SignedDivisionRemainderVerification => {
                    receipt.obligation_id == "md3"
                        && receipt.cell_id.starts_with("md3.")
                        && receipt.cell_id != "md3.unsigned"
                        && receipt.stage == "instruction_lookup.primary_sumcheck"
                        && exact_signed_divrem_relation(hit)
                        && exact_signed_divrem_receipt_context(hit, receipt)
                        && exact_receipt_source_identity_for(
                            hit,
                            receipt,
                            "jolt",
                            "e9caa23565dbb13019afe61a2c95f51d1999e286",
                            "instruction",
                        )
                }
                ExecutedExceptionEffect::SignedUnsignedProductVerification => {
                    receipt.obligation_id == "md5"
                        && receipt.cell_id.starts_with("md5.")
                        && receipt.stage == "r1cs.inner_sumcheck"
                        && exact_mulhsu_mismatch_relation(hit)
                        && exact_mulhsu_receipt_context(hit, receipt)
                        && exact_receipt_source_identity_for(
                            hit,
                            receipt,
                            "jolt",
                            "e9caa23565dbb13019afe61a2c95f51d1999e286",
                            "instruction",
                        )
                }
                ExecutedExceptionEffect::DoryShortTraceCapacity => {
                    receipt.stage == "dory.commitment.domain_size"
                        && exact_dory_short_trace_relation(hit)
                        && exact_dory_receipt_context(hit, receipt)
                        && exact_receipt_source_identity(hit, receipt)
                }
                ExecutedExceptionEffect::BigIntOpcodeConversion => {
                    receipt.stage == "openvm.bigint.branch_less_than_opcode_conversion"
                        && exact_bigint_opcode_conversion_relation(hit)
                        && exact_bigint_receipt_context(hit, receipt)
                        && exact_receipt_source_identity(hit, receipt)
                }
                ExecutedExceptionEffect::ControlDoneCapacity => {
                    receipt.stage == "risc0.segment.control_done_capacity"
                        && exact_control_done_capacity_relation(hit)
                        && exact_control_done_receipt_context(hit, receipt)
                        && exact_receipt_source_identity(hit, receipt)
                }
            };
            exact_execution_anchor(hit, receipt)
                && identity_matches
                && hit_str(hit, "trace_source").is_some_and(|source| !source.trim().is_empty())
                && effect_matches
        })
        .count()
        == 1
}

#[derive(Debug, Default)]
pub struct BugNoveltyFilter {
    seen: HashSet<String>,
}

impl BugNoveltyFilter {
    pub fn should_record(
        &mut self,
        kind: &str,
        metadata: &Value,
        bucket_hits_sig: &str,
        signal_sig: &str,
        backend_error: Option<&str>,
        oracle_error: Option<&str>,
        mismatch_regs: &[(u32, u32, u32)],
    ) -> bool {
        let Some(key) = strict_bug_key(
            kind,
            metadata,
            bucket_hits_sig,
            signal_sig,
            backend_error,
            oracle_error,
            mismatch_regs,
        ) else {
            return false;
        };
        self.seen.insert(key)
    }
}

fn metadata_value_string(metadata: &Value, key: &str) -> Option<String> {
    match metadata.as_object()?.get(key)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Array(items) => {
            let mut strings: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
            if strings.is_empty() {
                return None;
            }
            strings.sort_unstable();
            strings.dedup();
            Some(strings.join(","))
        }
        _ => None,
    }
}

fn normalized_error_key(message: Option<&str>) -> String {
    let Some(message) = message else {
        return "none".to_string();
    };
    let first_line = message.lines().next().unwrap_or(message).trim();
    first_line.chars().take(240).collect()
}

fn strict_bug_key(
    kind: &str,
    metadata: &Value,
    bucket_hits_sig: &str,
    signal_sig: &str,
    backend_error: Option<&str>,
    oracle_error: Option<&str>,
    mismatch_regs: &[(u32, u32, u32)],
) -> Option<String> {
    match kind {
        "underconstrained_candidate" => {
            if metadata.as_object()?.get("underconstrained_candidate")?.as_bool()? != true {
                return None;
            }
            if backend_error.is_some() || oracle_error.is_some() {
                return None;
            }
            let object = metadata.as_object()?;
            if object.get("semantic_injection_applied").and_then(Value::as_bool) != Some(true)
                || object.get("semantic_relation_validated").and_then(Value::as_bool) != Some(true)
            {
                return None;
            }
            let receipt = object.get("semantic_mutation_receipt")?.as_object()?;
            let inject_kind = receipt.get("inject_kind")?.as_str()?;
            let site = receipt.get("site")?.as_str()?;
            let field = receipt.get("field")?.as_str()?;
            let before = receipt.get("before")?;
            let after = receipt.get("after")?;
            let relation = receipt.get("effect")?.as_object()?.get("relation")?.as_str()?;
            if inject_kind.trim().is_empty()
                || site.trim().is_empty()
                || field.trim().is_empty()
                || relation.trim().is_empty()
                || before == after
            {
                return None;
            }
            let trigger = metadata_value_string(metadata, "trigger_bucket_id")
                .or_else(|| metadata_value_string(metadata, "target_buckets"))
                .or_else(|| metadata_value_string(metadata, "baseline_bucket_hits_sig"))
                .unwrap_or_else(|| bucket_hits_sig.to_string());
            let inject = metadata_value_string(metadata, "inject_kind")
                .or_else(|| metadata_value_string(metadata, "direct_injection_kind"))
                .unwrap_or_else(|| "unknown".to_string());
            Some(format!("underconstrained|trigger={trigger}|inject={inject}"))
        }
        "mismatch" => {
            if mismatch_regs.is_empty() {
                return None;
            }
            let regs = mismatch_regs
                .iter()
                .map(|(idx, _, _)| idx.to_string())
                .collect::<Vec<_>>()
                .join(",");
            Some(format!("mismatch|buckets={bucket_hits_sig}|signals={signal_sig}|regs={regs}"))
        }
        "exception" => {
            if backend_error.is_none() && oracle_error.is_none() {
                return None;
            }
            let receipt = metadata.as_object()?.get("executed_exception_receipt")?.as_object()?;
            let effect = receipt.get("effect")?.as_str()?;
            let obligation_id = receipt.get("obligation_id")?.as_str()?;
            let cell_id = receipt.get("cell_id")?.as_str()?;
            let stage = receipt.get("stage")?.as_str()?;
            receipt.get("step")?.as_u64()?;
            let context = receipt.get("context")?.as_object()?;
            if effect.trim().is_empty()
                || obligation_id.trim().is_empty()
                || cell_id.trim().is_empty()
                || stage.trim().is_empty()
                || context.is_empty()
            {
                return None;
            }
            Some(format!(
                "exception|effect={effect}|cell={cell_id}|stage={stage}|buckets={bucket_hits_sig}|signals={signal_sig}|pop={:?}|fail={:?}|backend={}|oracle={}",
                context.get("population_rows").and_then(Value::as_u64),
                context
                    .get("failing_index")
                    .or_else(|| context.get("failing_row_idx"))
                    .and_then(Value::as_u64),
                normalized_error_key(backend_error),
                normalized_error_key(oracle_error)
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::{
        has_exact_executed_exception_relation, is_suppressed_exception, strict_bug_key,
        BugNoveltyFilter,
    };
    use crate::fuzz::benchmark::{ExecutedExceptionEffect, ExecutedExceptionReceipt};
    use crate::trace::BucketHit;

    fn relation_hit(bucket_id: &str, pairs: &[(&str, serde_json::Value)]) -> BucketHit {
        let mut details = HashMap::from([
            ("step_idx".to_string(), json!(0)),
            ("trace_source".to_string(), json!("executed_relation")),
        ]);
        details.extend(pairs.iter().map(|(key, value)| ((*key).to_string(), value.clone())));
        BucketHit::semantic_id(bucket_id, details)
    }

    fn exception_receipt(
        effect: ExecutedExceptionEffect,
        obligation_id: &str,
        cell_id: &str,
        stage: &str,
    ) -> ExecutedExceptionReceipt {
        ExecutedExceptionReceipt {
            effect,
            obligation_id: obligation_id.to_string(),
            cell_id: cell_id.to_string(),
            stage: stage.to_string(),
            step: 0,
            context: Default::default(),
        }
    }

    #[test]
    fn exact_exception_relations_reject_legacy_receipts_and_nearby_controls() {
        let pd3 = relation_hit(
            "sem.row.table_power2_boundary",
            &[
                ("step_idx", json!(16)),
                ("obligation_id", json!("pd3")),
                ("cell_id", json!("pd3.mem_table")),
                ("table_name", json!("rw_mem_check.last_access")),
                ("population_rows", json!(23)),
                ("allocated_rows", json!(16)),
                ("public_rows", json!(2)),
                ("boundary_k", json!(4)),
                ("crossing_row_idx", json!(16)),
                ("overflow_rows", json!(7)),
                ("exact_crossing", json!(true)),
                (
                    "relation",
                    json!("last_access_population_crosses_allocated_rows_at_first_overflow"),
                ),
                ("relation_valid", json!(true)),
            ],
        );
        let pd4 = relation_hit(
            "sem.row.bytecode_table_boundary",
            &[
                ("step_idx", json!(16)),
                ("obligation_id", json!("pd4")),
                ("cell_id", json!("pd4.just_over")),
                ("table_name", json!("read_write_memory.v_init")),
                ("population_start", json!(12)),
                ("population_rows", json!(5)),
                ("population_end", json!(17)),
                ("allocated_rows", json!(16)),
                ("boundary_k", json!(4)),
                ("exact_crossing", json!(true)),
                ("relation", json!("preprocessed_bytecode_end_crosses_allocated_rows_by_one")),
                ("relation_valid", json!(true)),
            ],
        );
        let md4 = relation_hit(
            "sem.arithmetic.product_decomposition",
            &[
                ("obligation_id", json!("md4")),
                ("cell_id", json!("md4.mul_overflow")),
                ("mnemonic", json!("mul")),
                ("rs1_val", json!(65536)),
                ("rs2_val", json!(65536)),
                ("product_hi", json!(1)),
                ("product_lo", json!(0)),
                ("expected_rd_val", json!(0)),
                ("observed_rd_val", json!(0)),
                ("relation", json!("product_hi_lo_matches_operands")),
                ("relation_valid", json!(true)),
            ],
        );
        let md3 = relation_hit(
            "sem.arithmetic.division_remainder_bound",
            &[
                ("obligation_id", json!("md3")),
                ("cell_id", json!("md3.np")),
                ("dividend", json!(-7)),
                ("divisor", json!(3)),
                ("quotient", json!(-2)),
                ("remainder", json!(-1)),
                ("recomposed", json!(-7)),
                ("remainder_bound_holds", json!(true)),
                ("remainder_sign_holds", json!(true)),
                ("relation", json!("quotient_times_divisor_plus_remainder")),
                ("relation_valid", json!(true)),
            ],
        );
        let md5 = relation_hit(
            "sem.arithmetic.signed_unsigned_product_correction",
            &[
                ("obligation_id", json!("md5")),
                ("cell_id", json!("md5.neg_one")),
                ("mnemonic", json!("mulhsu")),
                ("signed_lhs", json!(-1)),
                ("unsigned_rhs", json!(1)),
                ("product_hi", json!(u32::MAX)),
                ("product_lo", json!(u32::MAX)),
                ("expected_high32", json!(u32::MAX)),
                ("observed_result", json!(0)),
                ("result_matches", json!(false)),
                ("result_mismatch", json!(true)),
                ("relation", json!("high32_signed_lhs_times_unsigned_rhs")),
                ("relation_valid", json!(true)),
            ],
        );
        let mut receipts = [
            exception_receipt(
                ExecutedExceptionEffect::MemoryTableCapacityWrite,
                "pd3",
                "pd3.mem_table",
                "rw_mem_check.last_access.write",
            ),
            exception_receipt(
                ExecutedExceptionEffect::BytecodeTableCapacityWrite,
                "pd4",
                "pd4.just_over",
                "read_write_memory.v_init.write",
            ),
            exception_receipt(
                ExecutedExceptionEffect::MultiplicationCarryBound,
                "md4",
                "md4.mul_overflow",
                "mul.witness.carry_1_bound",
            ),
            exception_receipt(
                ExecutedExceptionEffect::SignedDivisionRemainderVerification,
                "md3",
                "md3.np",
                "instruction_lookup.primary_sumcheck",
            ),
            exception_receipt(
                ExecutedExceptionEffect::SignedUnsignedProductVerification,
                "md5",
                "md5.neg_one",
                "r1cs.inner_sumcheck",
            ),
        ];
        receipts[0].step = 16;
        receipts[0].context = serde_json::Map::from_iter([
            ("failing_row_idx".to_string(), json!(16)),
            ("population_rows".to_string(), json!(23)),
            ("allocated_rows".to_string(), json!(16)),
            ("public_rows".to_string(), json!(2)),
            ("boundary_k".to_string(), json!(4)),
            ("crossing_row_idx".to_string(), json!(16)),
            ("overflow_rows".to_string(), json!(7)),
        ]);
        receipts[1].step = 16;
        receipts[1].context = serde_json::Map::from_iter([
            ("table_name".to_string(), json!("read_write_memory.v_init")),
            ("population_start".to_string(), json!(12)),
            ("population_end".to_string(), json!(17)),
            ("population_rows".to_string(), json!(5)),
            ("allocated_rows".to_string(), json!(16)),
            ("boundary_k".to_string(), json!(4)),
            ("failing_index".to_string(), json!(16)),
            ("exact_crossing".to_string(), json!(true)),
        ]);
        for (hit, receipt) in [&pd3, &pd4, &md4, &md3, &md5].into_iter().zip(&receipts) {
            assert!(!has_exact_executed_exception_relation(
                std::slice::from_ref(hit),
                Some(receipt),
            ));
        }
        assert!(!has_exact_executed_exception_relation(&[pd3.clone()], None));
        let mut wrong_stage = receipts[0].clone();
        wrong_stage.stage = "unrelated.stage".to_string();
        assert!(!has_exact_executed_exception_relation(&[pd3.clone()], Some(&wrong_stage),));

        let mut wrong_context = receipts[0].clone();
        wrong_context.context.insert("overflow_rows".to_string(), json!(6));
        assert!(!has_exact_executed_exception_relation(&[pd3.clone()], Some(&wrong_context),));

        let mut wrong_bytecode_context = receipts[1].clone();
        wrong_bytecode_context.context.insert("population_end".to_string(), json!(18));
        assert!(!has_exact_executed_exception_relation(
            &[pd4.clone()],
            Some(&wrong_bytecode_context),
        ));

        let mut near_crossing = pd3;
        near_crossing.details.insert("population_rows".to_string(), json!(16));
        assert!(!has_exact_executed_exception_relation(&[near_crossing], Some(&receipts[0]),));
        let mut mulhu_control = md4;
        mulhu_control.details.insert("cell_id".to_string(), json!("md4.mulhu"));
        mulhu_control.details.insert("mnemonic".to_string(), json!("mulhu"));
        assert!(!has_exact_executed_exception_relation(&[mulhu_control], Some(&receipts[2]),));
        let mut positive_mulhsu = md5;
        positive_mulhsu.details.insert("result_mismatch".to_string(), json!(false));
        positive_mulhsu.details.insert("result_matches".to_string(), json!(true));
        assert!(!has_exact_executed_exception_relation(&[positive_mulhsu], Some(&receipts[4]),));
    }

    #[test]
    fn bigint_conversion_relation_matches_only_the_concrete_installed_hook_schema() {
        let hit = relation_hit(
            "sem.decode.field_range",
            &[
                ("obligation_id", json!("id4")),
                ("cell_id", json!("id4.branch")),
                ("backend", json!("openvm")),
                ("commit", json!("336f1a475e5aa3513c4c5a266399f4128c119bba")),
                (
                    "trace_source",
                    json!("extensions/rv32im/circuit/src/branch_lt/core.rs::execute_instruction"),
                ),
                ("step_idx", json!(3)),
                ("op_idx", json!(3)),
                ("from_pc", json!(17)),
                ("global_opcode", json!(0x425)),
                ("chip_class_offset", json!(0x408)),
                ("local_opcode", json!(29)),
                ("supported_local_opcodes", json!([0, 1, 2, 3])),
                ("conversion_target", json!("BranchLessThanOpcode")),
                ("relation", json!("local_opcode_not_in_branch_less_than_domain")),
                ("relation_valid", json!(true)),
            ],
        );
        let receipt = ExecutedExceptionReceipt {
            effect: ExecutedExceptionEffect::BigIntOpcodeConversion,
            obligation_id: "id4".to_string(),
            cell_id: "id4.branch".to_string(),
            stage: "openvm.bigint.branch_less_than_opcode_conversion".to_string(),
            step: 3,
            context: serde_json::Map::from_iter([
                ("backend".to_string(), json!("openvm")),
                ("commit".to_string(), json!("336f1a475e5aa3513c4c5a266399f4128c119bba")),
                (
                    "trace_source".to_string(),
                    json!("extensions/rv32im/circuit/src/branch_lt/core.rs::execute_instruction"),
                ),
                ("from_pc".to_string(), json!(17)),
                ("global_opcode".to_string(), json!(0x425)),
                ("chip_class_offset".to_string(), json!(0x408)),
                ("local_opcode".to_string(), json!(29)),
                ("supported_local_opcodes".to_string(), json!([0, 1, 2, 3])),
                ("conversion_target".to_string(), json!("BranchLessThanOpcode")),
                ("relation".to_string(), json!("local_opcode_not_in_branch_less_than_domain")),
                ("relation_valid".to_string(), json!(true)),
                ("hook_fired".to_string(), json!(true)),
            ]),
        };
        assert!(has_exact_executed_exception_relation(std::slice::from_ref(&hit), Some(&receipt),));

        for (key, forged) in [
            ("global_opcode", json!(0x424)),
            ("chip_class_offset", json!(0x409)),
            ("local_opcode", json!(28)),
            ("from_pc", json!(16)),
            ("hook_fired", json!(false)),
        ] {
            let mut wrong_receipt = receipt.clone();
            wrong_receipt.context.insert(key.to_string(), forged);
            assert!(
                !has_exact_executed_exception_relation(
                    std::slice::from_ref(&hit),
                    Some(&wrong_receipt),
                ),
                "forged receipt field {key} must fail closed"
            );
        }

        let mut legacy_hit = hit.clone();
        legacy_hit.details.insert("trace_source".to_string(), json!("openvm_bigint_constructor"));
        assert!(!has_exact_executed_exception_relation(&[legacy_hit], Some(&receipt)));

        let mut legacy_receipt = receipt;
        legacy_receipt.context.remove("hook_fired");
        legacy_receipt.context.insert("constructor_executed".to_string(), json!(true));
        assert!(!has_exact_executed_exception_relation(
            std::slice::from_ref(&hit),
            Some(&legacy_receipt),
        ));
    }

    #[test]
    fn control_done_relation_recomputes_the_same_hits_concrete_manifestation() {
        let hit = relation_hit(
            "sem.row.trace_power2_boundary",
            &[
                ("obligation_id", json!("pd2")),
                ("cell_id", json!("pd2.just_over")),
                ("backend", json!("risc0")),
                ("commit", json!("6f038bd11ed725d7025687d163977d93ac1f82f9")),
                ("trace_source", json!("segment_finalization")),
                ("segment_idx", json!(3)),
                ("step_idx", json!(3)),
                ("segment_po2", json!(4)),
                ("capacity_cycles", json!(16)),
                ("user_cycles", json!(9)),
                ("pager_cycles", json!(2)),
                ("lookup_table_cycles", json!(5)),
                ("accounted_cycles", json!(16)),
                ("control_done_cycles_required", json!(2)),
                ("required_cycles", json!(18)),
                ("overflow_cycles", json!(2)),
                ("actual_trace_cycles", json!(17)),
                ("manifested_control_done_cycles", json!(1)),
                ("relation", json!("control_done_cycles_cross_segment_capacity")),
                ("relation_valid", json!(true)),
                ("accounted_fits", json!(true)),
                ("required_exceeds", json!(true)),
            ],
        );
        let receipt = ExecutedExceptionReceipt {
            effect: ExecutedExceptionEffect::ControlDoneCapacity,
            obligation_id: "pd2".to_string(),
            cell_id: "pd2.just_over".to_string(),
            stage: "risc0.segment.control_done_capacity".to_string(),
            step: 3,
            context: serde_json::Map::from_iter([
                ("segment_idx".to_string(), json!(3)),
                ("segment_po2".to_string(), json!(4)),
                ("capacity_cycles".to_string(), json!(16)),
                ("user_cycles".to_string(), json!(9)),
                ("pager_cycles".to_string(), json!(2)),
                ("lookup_table_cycles".to_string(), json!(5)),
                ("accounted_cycles".to_string(), json!(16)),
                ("control_done_cycles_required".to_string(), json!(2)),
                ("required_cycles".to_string(), json!(18)),
                ("overflow_cycles".to_string(), json!(2)),
                ("actual_trace_cycles".to_string(), json!(17)),
                ("manifested_control_done_cycles".to_string(), json!(1)),
                ("accounted_fits".to_string(), json!(true)),
                ("required_exceeds".to_string(), json!(true)),
                ("backend".to_string(), json!("risc0")),
                ("commit".to_string(), json!("6f038bd11ed725d7025687d163977d93ac1f82f9")),
                ("trace_source".to_string(), json!("segment_finalization")),
            ]),
        };
        assert!(has_exact_executed_exception_relation(std::slice::from_ref(&hit), Some(&receipt),));

        assert!(!has_exact_executed_exception_relation(
            &[hit.clone(), hit.clone()],
            Some(&receipt),
        ));
        for (key, value) in [
            ("backend", json!("foreign")),
            ("commit", json!("stale")),
            ("trace_source", json!("caller_forged")),
        ] {
            let mut wrong_identity = receipt.clone();
            wrong_identity.context.insert(key.to_string(), value);
            assert!(!has_exact_executed_exception_relation(
                std::slice::from_ref(&hit),
                Some(&wrong_identity),
            ));
        }
        let mut missing_identity = receipt.clone();
        missing_identity.context.remove("commit");
        assert!(!has_exact_executed_exception_relation(
            std::slice::from_ref(&hit),
            Some(&missing_identity),
        ));

        for (key, value) in
            [("actual_trace_cycles", json!(18)), ("manifested_control_done_cycles", json!(2))]
        {
            let mut wrong_hit = hit.clone();
            wrong_hit.details.insert(key.to_string(), value);
            assert!(!has_exact_executed_exception_relation(&[wrong_hit], Some(&receipt)));
        }
        let mut missing_actual = hit.clone();
        missing_actual.details.remove("actual_trace_cycles");
        assert!(!has_exact_executed_exception_relation(&[missing_actual], Some(&receipt)));

        let mut relation_only = hit.clone();
        relation_only.details.insert("actual_trace_cycles".to_string(), json!(18));
        let mut manifestation_only = hit;
        manifestation_only.details.insert("cell_id".to_string(), json!("pd2.exact"));
        assert!(!has_exact_executed_exception_relation(
            &[relation_only, manifestation_only],
            Some(&receipt),
        ));
    }

    #[test]
    fn suppresses_invalid_or_unsupported_exception_surfaces() {
        assert!(is_suppressed_exception(
            &json!({}),
            Some("risc0 execute failed: Invalid trap address: 0x00000000, cause: IllegalInstruction(0x14002573, 1)"),
            None,
        ));
        assert!(is_suppressed_exception(
            &json!({}),
            Some("decode rv32 word to sp1 instruction failed: unsupported rv32 mnemonic for sp1 executor: csrrwi"),
            None,
        ));
        assert!(is_suppressed_exception(
            &json!({}),
            Some("emulator emulate_batch(trace) failed: Unimplemented"),
            None,
        ));
        assert!(is_suppressed_exception(
            &json!({}),
            Some("execute_metered failed: FailedWithExitCode(2)"),
            None,
        ));
    }

    #[test]
    fn suppresses_csr_surface_exceptions_by_seed_source() {
        assert!(is_suppressed_exception(
            &json!({"source": "storage/riscv-tests-artifacts/rv32si-p-csr.dump"}),
            Some("backend failed on csr surface"),
            None,
        ));
    }

    #[test]
    fn keeps_valid_rv32i_prove_verify_failures() {
        assert!(!is_suppressed_exception(
            &json!({"source": "storage/riscv-tests-artifacts/rv32ui-p-add.dump"}),
            Some("sp1 prove/verify panicked: cumulative sums error"),
            None,
        ));
        assert!(!is_suppressed_exception(
            &json!({"source": "storage/riscv-tests-artifacts/rv32ui-p-add.dump"}),
            Some("jolt verify failed: R1CS proof verification failed"),
            None,
        ));
    }

    #[test]
    fn exception_key_requires_typed_context_and_an_actual_exception() {
        let metadata = json!({
            "executed_exception_receipt": {
                "effect": "bytecode_table_capacity_write",
                "obligation_id": "pd4",
                "cell_id": "pd4.just_over",
                "stage": "read_write_memory.v_init.write",
                "step": 16,
                "context": {
                    "table_name": "read_write_memory.v_init",
                    "failing_index": 16
                }
            }
        });
        assert!(strict_bug_key(
            "exception",
            &metadata,
            "sem.row.bytecode_table_boundary",
            "",
            Some("jolt panic: index out of bounds"),
            None,
            &[],
        )
        .is_some());
        assert!(strict_bug_key(
            "exception",
            &metadata,
            "sem.row.bytecode_table_boundary",
            "",
            None,
            None,
            &[(6, 160, 0)],
        )
        .is_none());

        let mut malformed = metadata;
        malformed["executed_exception_receipt"]["context"] = json!({});
        assert!(strict_bug_key(
            "exception",
            &malformed,
            "sem.row.bytecode_table_boundary",
            "",
            Some("unrelated panic"),
            None,
            &[],
        )
        .is_none());
    }

    #[test]
    fn strict_underconstrained_key_requires_applied_clean_injection() {
        let metadata = json!({
            "kind": "underconstrained_candidate",
            "underconstrained_candidate": true,
            "semantic_injection_applied": true,
            "semantic_relation_validated": true,
            "semantic_mutation_receipt": {
                "inject_kind": "vm.semantic.memory.foo",
                "site": "table::row",
                "field": "value",
                "step": 3,
                "before": 1,
                "after": 2,
                "effect": {"relation": "witness_value_changed", "context": {}},
            },
            "trigger_bucket_id": "sem.memory.foo",
            "inject_kind": "vm.semantic.memory.foo",
        });
        assert_eq!(
            strict_bug_key("underconstrained_candidate", &metadata, "sig", "", None, None, &[],)
                .as_deref(),
            Some("underconstrained|trigger=sem.memory.foo|inject=vm.semantic.memory.foo"),
        );
        assert!(strict_bug_key(
            "underconstrained_candidate",
            &metadata,
            "sig",
            "",
            Some("backend rejected"),
            None,
            &[],
        )
        .is_none());

        for key in [
            "semantic_injection_applied",
            "semantic_relation_validated",
            "semantic_mutation_receipt",
        ] {
            let mut missing = metadata.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(strict_bug_key(
                "underconstrained_candidate",
                &missing,
                "sig",
                "",
                None,
                None,
                &[],
            )
            .is_none());
        }

        let injected_phase_only = json!({
            "kind": "underconstrained_candidate",
            "underconstrained_candidate": true,
            "injected_phase": true,
            "trigger_bucket_id": "sem.memory.foo",
            "inject_kind": "vm.semantic.memory.foo",
        });
        assert!(strict_bug_key(
            "underconstrained_candidate",
            &injected_phase_only,
            "sig",
            "",
            None,
            None,
            &[],
        )
        .is_none());

        let mut unchanged = metadata.clone();
        unchanged["semantic_mutation_receipt"]["after"] = json!(1);
        assert!(strict_bug_key(
            "underconstrained_candidate",
            &unchanged,
            "sig",
            "",
            None,
            None,
            &[],
        )
        .is_none());
    }

    #[test]
    fn novelty_filter_deduplicates_semantic_bug_key() {
        let metadata = json!({
            "kind": "underconstrained_candidate",
            "underconstrained_candidate": true,
            "semantic_injection_applied": true,
            "semantic_relation_validated": true,
            "semantic_mutation_receipt": {
                "inject_kind": "nexus.semantic.row.padding_interaction_send",
                "site": "padding::row",
                "field": "multiplicity",
                "step": 0,
                "before": 0,
                "after": 1,
                "effect": {"relation": "padding_interaction_send", "context": {}},
            },
            "trigger_bucket_id": "sem.row.padding_interaction_send",
            "inject_kind": "nexus.semantic.row.padding_interaction_send",
        });
        let mut filter = BugNoveltyFilter::default();
        assert!(filter.should_record(
            "underconstrained_candidate",
            &metadata,
            "sig-a",
            "",
            None,
            None,
            &[],
        ));
        assert!(!filter.should_record(
            "underconstrained_candidate",
            &metadata,
            "sig-b",
            "",
            None,
            None,
            &[],
        ));
    }
}
