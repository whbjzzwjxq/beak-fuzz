# Jolt Benchmark Backend

This project wires the Jolt snapshot `e9caa23565dbb13019afe61a2c95f51d1999e286`
into the same `beak-trace` / `beak-fuzz` benchmark entrypoints used by the other
zkVM integrations.

Current semantic coverage:

- `sem.decode.zero_register_immutability`
- `sem.decode.operand_index_routing`
- `sem.exec.dest_binding`
- `sem.decode.field_range`
- `sem.decode.immediate_sign_extension`
- `sem.control.entrypoint_binding`
- `sem.exec.op_selector_binding`
- `sem.decode.format_immediate_reassembly`
- `sem.alu.immediate_limb_consistency`
- `sem.alu.shift_mod32`
- `sem.alu.comparison_booleanity`
- `sem.alu.subtraction_borrow_chain`
- `sem.alu.comparison_auxiliary_chain`
- `sem.arithmetic.special_case_consistency`
- `sem.arithmetic.division_remainder_bound`
- `sem.arithmetic.product_decomposition`
- `sem.arithmetic.signed_unsigned_product_correction`
- `sem.decode.upper_immediate_materialization`
- `sem.exec.control_flow_binding`
- `sem.memory.address_alignment_consistency`
- `sem.memory.load_value_binding`
- `sem.memory.write_payload_consistency`
- `sem.memory.address_progression_consistency`
- `sem.memory.kind_selector_consistency`
- `sem.time.boundary_origin_consistency`

Bucket hits are derived from executed Jolt `RVTraceRow`s whose PC maps back to
the input program, not from unexecuted input words. The Jolt install pass now
patches `jolt-core/src/host/mod.rs::Program::trace` with env-controlled
processed-trace witness mutations for:

- `jolt.semantic.decode.upper_immediate_materialization`
- `jolt.semantic.exec.control_flow_binding`
- `jolt.semantic.control.entrypoint_binding`

The backend maps observed `id3`, `cf1`, and `cf4` buckets to those real hooks
and reads `BEAK_JOLT_WITNESS_INJECTION_APPLIED` as applied-site evidence.
These are `semantic_injection_mapped`, not `verified`, because the Jolt prover
path still panics in memory verification before verifier evidence is available.

Minimal smoke checks:

```bash
cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets
cargo run -q --bin beak-trace -- --bin 123450b7 --print-buckets
cargo run -q --bin beak-trace -- --bin "00100093 00200113 0020c463 00300193" --print-buckets
cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3" --print-buckets
cargo run -q --bin beak-trace -- --bin "00700093 00500113 022081b3" --print-buckets
cargo run -q --bin beak-trace -- --bin "7fffc0b7 10008093 0000c183" --print-buckets
cargo run -q --bin beak-trace -- --bin "7fffd0b7 10008093 07f00113 00208023" --print-buckets
cargo run -q --bin beak-trace -- --bin 123450b7 --inject-kind jolt.semantic.decode.upper_immediate_materialization --inject-step 18446744073709551615 --print-buckets
cargo run -q --bin beak-trace -- --bin "00100093 00200113 0020c463 00300193" --inject-kind jolt.semantic.exec.control_flow_binding --inject-step 18446744073709551615 --print-buckets
cargo run -q --bin beak-trace -- --bin 123450b7 --inject-kind jolt.semantic.control.entrypoint_binding --inject-step 0 --print-buckets
cargo run -q --bin beak-fuzz -- --bin 123450b7 --initial-limit 1 --semantic-max-trials-per-bucket 4
```

Current prover smoke note: the baseline commands above emit the expected
semantic buckets and match final registers. The injected commands report
`injection_applied = true`, but the installed Jolt snapshot currently panics
during prover memory verification with an out-of-bounds index before a verifier
result is available. Do not mark these cells `verified` until that prover smoke
is fixed and recorded.

Known missing evidence:

- `me1` store-load payload flow: Jolt's current public I/O mapping allows
  stores to output and loads from input, while heap addresses at/above
  `0x80000000` sign-extend into invalid 64-bit addresses in this harness.
- `me5`-`me8`, `me11`, `ts2`, `cf5`, `cf6.near_segment_end`, `cf7`, bus/lookup,
  and padding rows need address-space selectors, initialization/finalization
  provenance, timestamps, syscall arguments, raw ECALL execution, segment
  metadata, or prover table visibility that the current trace does not expose.
