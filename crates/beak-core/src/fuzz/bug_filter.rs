use serde_json::Value;

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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::is_suppressed_exception;

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
}
