# Jolt d67 RV64/Dory Benchmark Backend

This project wires the Jolt snapshot `d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b`
into Beak's normal `beak-trace` and `beak-fuzz` entrypoints for
`Jolt-Dory-ShortTrace-01`.

The adapter is intentionally narrow: it converts Beak hex-word seeds into a real
RV64 ELF and runs d67 `JoltRV64IMAC` with `DoryCommitmentScheme`. For a concrete
short execution, it independently derives `sem.row.trace_power2_boundary` from
the executed trace length and Dory's matrix-width equation. The install pass
records the actual Dory `K`, padded domain, and matrix dimension at the failing
commitment assertion. A non-injected failure is reportable only when the typed
`DoryShortTraceCapacity` receipt matches that executed hit exactly. There is no
semantic injection route for this snapshot.

Minimal smoke:

```bash
cargo run -q --bin beak-trace -- --bin 00700593
cargo run -q --bin beak-fuzz -- --bin 00700593 --initial-limit 1 --output-prefix jolt-d67-dory-shorttrace
```
