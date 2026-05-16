# Jolt d67 RV64/Dory Benchmark Backend

This project wires the Jolt snapshot `d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b`
into Beak's normal `beak-trace` and `beak-fuzz` entrypoints for
`Jolt-Dory-ShortTrace-01`.

The adapter is intentionally narrow: it converts Beak hex-word seeds into a real
RV64 ELF, runs d67 `JoltRV64IMAC` with `DoryCommitmentScheme`, and reports
non-injected prover panics as ordinary baseline `backend_error` JSONL records.
It does not claim RV64 semantic bucket or injection coverage.

Minimal smoke:

```bash
cargo run -q --bin beak-trace -- --bin 00700593
cargo run -q --bin beak-fuzz -- --bin 00700593 --initial-limit 1 --output-prefix jolt-d67-dory-shorttrace
```
