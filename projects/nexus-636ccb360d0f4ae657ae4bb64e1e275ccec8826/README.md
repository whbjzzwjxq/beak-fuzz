# Nexus Benchmark Backend

This project wires the Nexus zkVM snapshot `636ccb360d0f4ae657ae4bb64e1e275ccec8826`
into the same `beak-trace` / `beak-fuzz` benchmark entrypoints used by the other
zkVM integrations.

Current semantic coverage is derived from executed Nexus `UniformTrace` steps
plus memory records:

- Register/decode/ALU/control: `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`,
  `cf1`-`cf6`.
- Mul/div: `md1`-`md5` when the executed operands expose the special case or
  product/division class. Nexus prover smoke currently reports unsupported
  DIV for some prover paths, so these are not verified.
- Memory/time: `me1`-`me7`, `me9`, `me10`, `ts1`, same-address `ts2`, and
  `ts3` from `UniformTrace` memory records.

Most groups are still bucket-only under the shared implementation contract.
The exceptions are installed-source load/store prover hooks for:

- `me1` / `nexus.semantic.memory.store_load_payload_flow`
- `me4` / `nexus.semantic.memory.write_payload_consistency`
- `me10` / `nexus.semantic.memory.kind_selector_consistency`

The previous backend semantic candidate mapping for local trace-rewrite
experiments remains disabled. Current mappings only target the pass3 hook in
`prover/src/chips/instructions/load_store.rs::LoadStoreChip::fill_main_trace`
and require applied-site evidence from the installed prover path.

Minimal smoke checks:

```bash
cargo run --bin beak-trace -- --bin "00100093 00200113 002081b3 40218233 0020c463 00300293 00500313" --print-buckets
cargo run --bin beak-trace -- --bin "00100093 00112023 00012183" --print-buckets
cargo run --bin beak-trace -- --bin "08000093 00110023 00010183" --print-buckets
cargo run --bin beak-trace -- --bin "fff00093 ffd0a103" --print-buckets
```

Verified injected load/store smokes:

```bash
cargo run --bin beak-trace -- --bin "00100093 00112023 00012183" --inject-kind nexus.semantic.memory.store_load_payload_flow --inject-step 1 --print-buckets
cargo run --bin beak-trace -- --bin "08000093 00110023 00010183" --inject-kind nexus.semantic.memory.write_payload_consistency --inject-step 1 --print-buckets
cargo run --bin beak-trace -- --bin "00100093 00112023 00012183" --inject-kind nexus.semantic.memory.kind_selector_consistency --inject-step 1 --print-buckets
```

Remaining gaps need Nexus installed-source instrumentation: ECALL syscall
arguments/raw ECALL baseline, ELF/stack provenance, memory initialization and
finalization rows, cross-segment ordering, decode/register/ALU/muldiv/control
prover rows outside load/store, bus/lookup multiplicity rows, and
padding/table lifecycle rows.
