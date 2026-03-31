# Jolt Benchmark Backend

This project wires the Jolt snapshot `e9caa23565dbb13019afe61a2c95f51d1999e286`
into the same `beak-trace` / `beak-fuzz` benchmark entrypoints used by the other
zkVM integrations.

Current semantic coverage:

- `sem.decode.upper_immediate_materialization`
  - generalized class: `semantic.decode.upper_immediate_materialization`
  - injection family: `jolt.semantic.decode.upper_immediate_materialization`
- `sem.control.entrypoint_binding`
  - generalized class: `semantic.control.entrypoint_binding`
  - injection family: `jolt.semantic.control.entrypoint_binding`

The current backend executes the real Jolt emulator and drives semantic trace-row
search end-to-end through the real Jolt `prover_preprocess -> prove -> verify`
path.

Minimal smoke checks:

```bash
cargo run --bin beak-trace -- --bin 123450b7 --print-buckets
cargo run --bin beak-fuzz -- --bin 123450b7 --initial-limit 1 --semantic-max-trials-per-bucket 4 --timeout-ms 10000
```
