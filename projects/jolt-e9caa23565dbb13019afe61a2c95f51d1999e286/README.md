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
- `sem.memory.address_space_consistency`
- `sem.memory.address_boundary_range`
- `sem.memory.initial_value_binding`
- `sem.memory.address_progression_consistency`
- `sem.memory.kind_selector_consistency`
- `sem.memory.finalization_consistency`
- `sem.lookup.boolean_multiplicity`
- `sem.row.padding_interaction_send`
- `sem.time.boundary_origin_consistency`
- `sem.time.monotonic_access_ordering`

Bucket hits are derived from executed Jolt `RVTraceRow`s whose PC maps back to
the input program, not from unexecuted input words. The Jolt install pass now
patches these concrete witness/prover rows with env-controlled mutations:

- `jolt.semantic.decode.upper_immediate_materialization`
- `jolt.semantic.exec.control_flow_binding`
- `jolt.semantic.control.entrypoint_binding`
- `jolt-core/src/jolt/vm/read_write_memory.rs::generate_witness` register,
  RAM address/value, initial/final memory values, and timestamp columns for
  `rf1`-`rf3`, `me2`-`me7`, `me9`, `me11`, `ts1`, `ts2.same-address`, and
  `ts3`
- `jolt-core/src/jolt/vm/bytecode.rs::generate_witness` bytecode
  `bitflags`/register/immediate columns for `id1`, `id2`, `id4`, `id5`,
  and `al1`
- `jolt-core/src/jolt/vm/instruction_lookups.rs::generate_witness`
  `lookup_outputs` rows for `al2`-`al5`, `md1`, and `md3`-`md5`, plus
  instruction flag bitvectors for `bu1`
- `jolt-core/src/host/mod.rs::Program::trace` memory-op mutations for `me5`
  address-space and `me10` kind-selector checks
- `jolt-core/src/jolt/vm/mod.rs::JoltTraceStep::pad` padding-row mutations for
  `pd1`

The backend maps observed buckets to these hooks and reads
`BEAK_JOLT_WITNESS_INJECTION_APPLIED` as applied-site evidence. The old prover
smoke blocker was fixed by sizing Jolt read/write memory witness vectors from
the trace, bytecode initialization, and input initialization ranges; baseline
prover smokes now complete.

Minimal smoke checks:

```bash
cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets
cargo run -q --bin beak-trace -- --bin 123450b7 --print-buckets
cargo run -q --bin beak-trace -- --bin "00100093 00200113 0020c463 00300193" --print-buckets
cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3" --print-buckets
cargo run -q --bin beak-trace -- --bin "00700093 00500113 022081b3" --print-buckets
cargo run -q --bin beak-trace -- --bin "7fffc0b7 10008093 0000c183" --print-buckets
cargo run -q --bin beak-trace -- --bin "7fffc0b7 10008093 0000c183 0000c203" --print-buckets
cargo run -q --bin beak-trace -- --bin "7fffd0b7 10008093 07f00113 00208023" --print-buckets
cargo run -q --bin beak-trace -- --bin 123450b7 --inject-kind jolt.semantic.decode.upper_immediate_materialization --inject-step 18446744073709551615 --print-buckets
cargo run -q --bin beak-trace -- --bin "00100093 00200113 0020c463 00300193" --inject-kind jolt.semantic.exec.control_flow_binding --inject-step 18446744073709551615 --print-buckets
cargo run -q --bin beak-trace -- --bin 123450b7 --inject-kind jolt.semantic.control.entrypoint_binding --inject-step 0 --print-buckets
cargo run -q --bin beak-trace -- --bin 00100013 --inject-kind jolt.semantic.decode.zero_register_immutability --inject-step 18446744073709551615 --print-buckets
cargo run -q --bin beak-trace -- --bin 10000093 --inject-kind jolt.semantic.alu.immediate_limb_consistency --inject-step 18446744073709551615 --print-buckets
cargo run -q --bin beak-trace -- --bin "000010b7 00002137 002091b3" --inject-kind jolt.semantic.alu.shift_mod32 --inject-step 2 --print-buckets
cargo run -q --bin beak-trace -- --bin "000010b7 0200c1b3" --inject-kind jolt.semantic.arithmetic.special_case_consistency --inject-step 1 --print-buckets
cargo run -q --bin beak-trace -- --bin "7fffc0b7 10008093 0000c183" --inject-kind jolt.semantic.memory.address_pointer_consistency --inject-step 18446744073709551615 --print-buckets
cargo run -q --bin beak-trace -- --bin "7fffc0b7 10008093 0000c183 0000c203" --inject-kind jolt.semantic.memory.address_space_consistency --inject-step 18446744073709551615
cargo run -q --bin beak-trace -- --bin "7fffc0b7 10008093 0000c183 0000c203" --inject-kind jolt.semantic.memory.initial_value_binding --inject-step 18446744073709551615
cargo run -q --bin beak-trace -- --bin "7fffc0b7 10008093 0000c183 0000c203" --inject-kind jolt.semantic.memory.finalization_consistency --inject-step 18446744073709551615
cargo run -q --bin beak-trace -- --bin "7fffc0b7 10008093 0000c183 0000c203" --inject-kind jolt.semantic.time.monotonic_access_ordering --inject-step 18446744073709551615
cargo run -q --bin beak-trace -- --bin "7fffc0b7 10008093 0000c183 0000c203" --inject-kind jolt.semantic.lookup.boolean_multiplicity --inject-step 18446744073709551615
cargo run -q --bin beak-trace -- --bin "7fffc0b7 10008093 0000c183 0000c203" --inject-kind jolt.semantic.row.padding_interaction_send --inject-step 18446744073709551615
cargo run -q --bin beak-fuzz -- --bin 123450b7 --initial-limit 1 --semantic-max-trials-per-bucket 4
```

Current prover smoke note: the baseline commands above emit the expected
semantic buckets and match final registers. Injected smokes report
`injection_applied = true`; most fail verifier/prover checks as expected.
`id3` upper-immediate injection currently preserves registers and verifies,
which is recorded as underconstrained evidence rather than a rejected proof.
The new kind-selector and padding hooks also apply and verify, so they are
recorded as mapped/underconstrained rather than verified.
`md2` signed division/remainder overflow still panics in
`jolt-core/src/jolt/instruction/{div,rem}.rs` before a baseline bucket is
available.

Known missing evidence:

- `me1` store-load payload flow: Jolt's current public I/O mapping allows
  stores to output and loads from input, while heap addresses at/above
  `0x80000000` sign-extend into invalid 64-bit addresses in this harness.
- `me8.double_init`, `me7.rodata`, `me7.stack_uninit`, and
  `ts2.cross_segment` need duplicate-init provenance before coalescing,
  ELF/stack region metadata, or segment-continuity evidence that this snapshot
  does not expose.
- `cf2`, `cf3.imm_*`, and `cf6.normal/after_branch_not_taken` are still
  bucket-only: JAL/JALR and sequential control-flow buckets are observable, but
  no concrete Jolt witness hook was added for those rows.
- `cf5`, `cf6.near_segment_end`, `cf7`, and remaining bus families need syscall
  arguments, segment-boundary metadata, raw ECALL execution, or bus/permutation
  table visibility that the current trace does not expose.
