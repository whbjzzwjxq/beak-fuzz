# Risc0 98387806 Beak Target

Target snapshot: `98387806fe8348d87e32974468c6f35853356ad5`.

This target derives obligation buckets from executed RV32IM oracle steps using
Risc0's split code/data layout at `0x00010004`. A raw ECALL at the next
sequential PC is included because the Risc0 backend executes it through the
host syscall path even though the shared oracle stops before ECALL.

## Implemented Coverage

- Verified semantic injection mappings:
  - `sem.decode.zero_register_immutability` -> `risc0.semantic.decode.zero_register_immutability`
  - `sem.decode.operand_index_routing` -> `risc0.semantic.decode.operand_index_routing`
  - `sem.decode.rd_bit_decomposition` -> `risc0.semantic.decode.rd_bit_decomposition`
  - `sem.decode.field_range` -> `risc0.semantic.decode.field_range`
  - `sem.decode.immediate_sign_extension` -> `risc0.semantic.decode.immediate_sign_extension`
  - `sem.decode.upper_immediate_materialization` -> `risc0.semantic.decode.upper_immediate_materialization`
  - `sem.decode.format_immediate_reassembly` -> `risc0.semantic.decode.format_immediate_reassembly`
  - `sem.exec.dest_binding` -> `risc0.semantic.exec.dest_binding`
  - `sem.exec.op_selector_binding` -> `risc0.semantic.exec.op_selector_binding`
  - `sem.alu.immediate_limb_consistency` -> `risc0.semantic.alu.immediate_limb_consistency`
  - `sem.alu.shift_mod32` -> `risc0.semantic.alu.shift_mod32`
  - `sem.alu.comparison_booleanity` -> `risc0.semantic.alu.comparison_booleanity`
  - `sem.alu.subtraction_borrow_chain` -> `risc0.semantic.alu.subtraction_borrow_chain`
  - `sem.alu.comparison_auxiliary_chain` -> `risc0.semantic.alu.comparison_auxiliary_chain`
  - `sem.arithmetic.special_case_consistency` -> `risc0.semantic.arithmetic.special_case_consistency`
  - `sem.arithmetic.division_remainder_bound` -> `risc0.semantic.arithmetic.division_remainder_bound`
  - `sem.arithmetic.product_decomposition` -> `risc0.semantic.arithmetic.product_decomposition`
  - `sem.arithmetic.signed_unsigned_product_correction` -> `risc0.semantic.arithmetic.signed_unsigned_product_correction`
  - `sem.control.entrypoint_binding` -> `risc0.semantic.control.entrypoint_binding`
  - `sem.exec.control_flow_binding` -> `risc0.semantic.exec.control_flow_binding`
  - `sem.control.ecall_argument_decomposition` -> `risc0.semantic.control.ecall_argument_decomposition`
  - `sem.memory.store_load_payload_flow` -> `risc0.semantic.memory.store_load_payload_flow`
  - `sem.memory.address_alignment_consistency`, `sem.memory.address_boundary_range`,
    and `sem.memory.address_progression_consistency` -> `risc0.semantic.memory.address_pointer_consistency`
  - `sem.memory.load_value_binding` and `sem.memory.write_payload_consistency` -> `risc0.semantic.memory.value_payload_consistency`
  - `sem.memory.address_space_consistency` main-memory cells -> `risc0.semantic.memory.address_space_consistency::domain=mem_read/mem_write`
  - `sem.memory.kind_selector_consistency` -> `risc0.semantic.memory.kind_selector_consistency`
  - `sem.memory.initial_value_binding` -> `risc0.semantic.memory.initial_value_binding`
  - `sem.memory.finalization_consistency` -> `risc0.semantic.memory.finalization_consistency`
  - `sem.time.monotonic_access_ordering` -> `risc0.semantic.time.monotonic_access_ordering`
- Bucket-only coverage remains for `ts1`, `ts3`, `cf7`, `pd1.exec_padding`,
  and the ECALL/register address-space `me5.reg_*` cells. Memory/time buckets
  are derived from Risc0 prover preflight `RawMemoryTransaction` rows joined
  with actual `InstructionStart` events and register-memory reads.
- `cf3.clear_lsb/even/wrap` is backend-mapped through
  `risc0.semantic.exec.control_flow_binding`; `cf3.even` has a verified smoke,
  but `cf3.clear_lsb` still fails baseline witness generation before injection
  and wrap targets leave the installed code region.

## Gaps

- `sem.exec.memory_effect_binding` has a Risc0 asset hook, but memory-effect
  seeds still hit Risc0 access faults before successful contract-complete
  baseline plus injected replay.
- `pd1.exec_padding` remains bucket-only. Risc0 exposes a stable padding start
  row, but the emitted row has `interaction_kind = "none"` and the inspected
  installed source does not expose a padding interaction-send column to mutate.
- `me7.rodata/stack_uninit`, `me8`, `me11.untouched_cells`,
  `ts2.cross_segment`, `cf6.near_segment_end`, `bu1` and broader bus/table
  obligations need fields not currently exposed: the inspected executor,
  pager, preflight, and lookup/padding table sources expose accessed memory
  transactions and padding start rows, but not ELF/stack provenance, duplicate
  pre-coalescing init events, untouched final-memory cells, cross-segment
  memory continuity, or lookup multiplicity/is_real rows.

## Smoke

Representative baseline and injected replay:

```bash
cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3 00000073" --print-buckets
cargo run -q --bin beak-trace -- --bin "00100013" \
  --inject-kind risc0.semantic.decode.zero_register_immutability \
  --inject-step 0 --print-buckets
```

The full per-obligation smoke commands and results are in the `risc0-98387806`
column of `docs/OBLIGATION_IMPLEMENTATION_MATRIX.md`.
