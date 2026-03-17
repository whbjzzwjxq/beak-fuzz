# Nexus Benchmark Backend

This project wires the Nexus zkVM snapshot `636ccb360d0f4ae657ae4bb64e1e275ccec8826`
into the same `beak-trace` / `beak-fuzz` benchmark entrypoints used by the other
zkVM integrations.

Current semantic coverage:

- `sem.memory.write_payload_consistency`
  - generalized class: `semantic.memory.write_payload_flow_consistency`
  - injection family: `nexus.audit_memory.store_payload_trace`
- `sem.memory.store_load_payload_flow`
  - generalized class: `semantic.memory.write_payload_flow_consistency`
  - injection family: `nexus.audit_memory.store_payload_trace`

Minimal smoke checks:

```bash
cargo run --bin beak-trace -- --bin "00100093 00112023 00012183" --print-buckets
cargo run --bin beak-fuzz -- --bin "00100093 00112023 00012183" --initial-limit 1 --semantic-max-trials-per-bucket 4 --timeout-ms 5000
```
