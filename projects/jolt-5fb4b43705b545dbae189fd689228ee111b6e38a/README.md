# Jolt 5fb4b437 BEAK Harness

This snapshot covers the latest Jolt layout at
`5fb4b43705b545dbae189fd689228ee111b6e38a`.

Implemented latest-layout trace-row slice:

- Source install hook:
  `beak-py/projects/jolt-fuzzer/jolt_fuzzer/passes/pass3_collection.py`
  patches `jolt-core/src/host/program.rs::Program::trace`.
- Injection hook: removes one matching returned `Cycle` row and records
  `BEAK_JOLT_WITNESS_INJECTION_APPLIED=1`.
- Bucket emission: instruction-local buckets are derived only from executed
  `Cycle` PCs that map back to input program words.
- Backend mapping: `src/lib/backend.rs` maps observed bucket hits to exact
  cycle-step injection candidates.

Mapped inject kinds:

- `jolt.semantic.control.entrypoint_binding`
- `jolt.semantic.decode.field_range`
- `jolt.semantic.decode.format_immediate_reassembly`
- `jolt.semantic.decode.immediate_sign_extension`
- `jolt.semantic.decode.upper_immediate_materialization`
- `jolt.semantic.decode.zero_register_immutability`
- `jolt.semantic.exec.source_operand_binding`
- `jolt.semantic.exec.dest_binding`
- `jolt.semantic.alu.immediate_limb_consistency`
- `jolt.semantic.alu.shift_mod32`
- `jolt.semantic.alu.comparison_booleanity`
- `jolt.semantic.alu.comparison_auxiliary_chain`
- `jolt.semantic.alu.subtraction_borrow_chain`
- `jolt.semantic.control.branch_signedness`
- `jolt.semantic.control.link_register`

This latest harness is trace/hook smoke coverage only. Full proof/verify is not
wired for this snapshot, and no memory, bus, padding, ID4 selector, JALR target,
sequential-PC, or ECALL obligation is claimed here.

Smoke commands:

```bash
cargo +nightly run -q --manifest-path projects/jolt-5fb4b43705b545dbae189fd689228ee111b6e38a/Cargo.toml --bin beak-trace -- --bin 00100093 --print-buckets --print-candidates
cargo +nightly run -q --manifest-path projects/jolt-5fb4b43705b545dbae189fd689228ee111b6e38a/Cargo.toml --bin beak-trace -- --bin 00100093 --inject-kind jolt.semantic.control.entrypoint_binding --inject-step 0 --print-buckets --print-candidates
```

The older Jolt read/write-memory, bytecode, instruction-lookup, and VM-padding
source files used by the `e9caa235` harness do not exist in this snapshot.
Those obligations are therefore not claimed as semantic-injection mapped here.
