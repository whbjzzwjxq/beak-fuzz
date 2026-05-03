# Risc0 98387806 Beak Target

Target snapshot: `98387806fe8348d87e32974468c6f35853356ad5`.

This target derives obligation buckets from executed RV32IM oracle steps using
Risc0's split code/data layout at `0x00010004`. A raw ECALL at the next
sequential PC is included because the Risc0 backend executes it through the
host syscall path even though the shared oracle stops before ECALL.

## Implemented Coverage

- Verified semantic injection mappings:
  - `sem.decode.zero_register_immutability` ->
    `risc0.semantic.decode.zero_register_immutability`
  - `sem.decode.operand_index_routing` ->
    `risc0.semantic.decode.operand_index_routing`
  - `sem.decode.rd_bit_decomposition` ->
    `risc0.semantic.decode.rd_bit_decomposition`
  - `sem.decode.field_range` ->
    `risc0.semantic.decode.field_range`
  - `sem.decode.immediate_sign_extension` ->
    `risc0.semantic.decode.immediate_sign_extension`
  - `sem.decode.upper_immediate_materialization` ->
    `risc0.semantic.decode.upper_immediate_materialization`
  - `sem.decode.format_immediate_reassembly` ->
    `risc0.semantic.decode.format_immediate_reassembly`
  - `sem.exec.dest_binding` ->
    `risc0.semantic.exec.dest_binding`
  - `sem.exec.op_selector_binding` ->
    `risc0.semantic.exec.op_selector_binding`
  - `sem.alu.immediate_limb_consistency` ->
    `risc0.semantic.alu.immediate_limb_consistency`
  - `sem.alu.shift_mod32` -> `risc0.semantic.alu.shift_mod32`
  - `sem.alu.comparison_booleanity` ->
    `risc0.semantic.alu.comparison_booleanity`
  - `sem.alu.subtraction_borrow_chain` ->
    `risc0.semantic.alu.subtraction_borrow_chain`
  - `sem.alu.comparison_auxiliary_chain` ->
    `risc0.semantic.alu.comparison_auxiliary_chain`
  - `sem.arithmetic.special_case_consistency` ->
    `risc0.semantic.arithmetic.special_case_consistency`
  - `sem.arithmetic.division_remainder_bound` ->
    `risc0.semantic.arithmetic.division_remainder_bound`
  - `sem.arithmetic.product_decomposition` ->
    `risc0.semantic.arithmetic.product_decomposition`
  - `sem.arithmetic.signed_unsigned_product_correction` ->
    `risc0.semantic.arithmetic.signed_unsigned_product_correction`
  - `sem.control.entrypoint_binding` ->
    `risc0.semantic.control.entrypoint_binding`
  - `sem.exec.control_flow_binding` ->
    `risc0.semantic.exec.control_flow_binding`
  - `sem.control.ecall_argument_decomposition` ->
    `risc0.semantic.control.ecall_argument_decomposition`
  - `sem.memory.store_load_payload_flow` ->
    `risc0.semantic.memory.store_load_payload_flow`
  - `sem.memory.address_alignment_consistency`,
    `sem.memory.address_boundary_range`, and
    `sem.memory.address_progression_consistency` ->
    `risc0.semantic.memory.address_pointer_consistency`
  - `sem.memory.load_value_binding` and
    `sem.memory.write_payload_consistency` ->
    `risc0.semantic.memory.value_payload_consistency`
  - `sem.memory.address_space_consistency` main-memory cells ->
    `risc0.semantic.memory.address_space_consistency::domain=mem_read/mem_write`
  - `sem.memory.kind_selector_consistency` ->
    `risc0.semantic.memory.kind_selector_consistency`
  - `sem.memory.initial_value_binding` ->
    `risc0.semantic.memory.initial_value_binding`
  - `sem.memory.finalization_consistency` ->
    `risc0.semantic.memory.finalization_consistency`
  - `sem.time.monotonic_access_ordering` ->
    `risc0.semantic.time.monotonic_access_ordering`
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
  obligations need fields not currently exposed. Inspected source paths include
  `risc0/circuit/rv32im/src/trace.rs::TraceEvent`,
  `execute/executor.rs::{load_u32,store_u32}`,
  `execute/r0vm.rs::{load_memory,store_memory}`,
  `execute/pager.rs::{load,store}`,
  `prove/witgen/preflight.rs::{load_u32,store_u32}`, and lookup/padding table
  generation. Preflight exposes accessed memory transactions and padding start
  rows, but not ELF/stack provenance, duplicate pre-coalescing init events,
  untouched final-memory cells, cross-segment memory continuity, or lookup
  multiplicity/is_real rows.

## Smoke Commands

- Baseline:
  `cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3 00000073" --print-buckets`
  emitted decode/register/ALU/div/ecall/entry/time buckets.
- Zero-register injection:
  `cargo run -q --bin beak-trace -- --bin "00100013" --inject-kind risc0.semantic.decode.zero_register_immutability --inject-step 0 --print-buckets`
  reported `injection_applied = true`.
- Operand-routing injection:
  `cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3" --inject-kind risc0.semantic.decode.operand_index_routing --inject-step 2 --print-buckets`
  reported `injection_applied = true` and verifier rejection.
- Op-selector injection:
  `cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3" --inject-kind risc0.semantic.exec.op_selector_binding --inject-step 2 --print-buckets`
  reported `injection_applied = true` and verifier rejection.
- Div/rem injection:
  `cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3 00000073" --inject-kind risc0.semantic.arithmetic.division_remainder_bound --inject-step 2 --print-buckets`
  reported `injection_applied = true` and verifier rejection.
- ECALL decomposition injection:
  `cargo run -q --bin beak-trace -- --bin "00100893 00000073" --inject-kind risc0.semantic.control.ecall_argument_decomposition --inject-step 1 --print-buckets`
  reported `injection_applied = true` and verifier rejection.
- Shift partition smoke:
  `cargo run -q --bin beak-trace -- --bin "02100093 00109113 002091b3" --print-buckets`
  emitted `al2.sll_lt32` and `al2.sll_ge32`.
- Deep hook smokes:
  `00100093` verified `rf3`, `id1`, `id2`, `al1`, `cf4`, and `rc1`;
  `000010b7` verified `id3`; `00100093 00200113 0020c463 00300193`
  verified `cf1`; `008000ef 00100113 00200193` verified `cf2`;
  `004000ef 00408067 00100113` verified `cf3.even`; and
  `00100113 00200193 00208463 00300193` verified `cf6.after_branch_not_taken`.
  All injected runs reported `injection_applied = true` and verifier rejection.
- Memory/preflight smokes:
  `cargo run -q --bin beak-trace -- --bin "000100b7 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`
  emitted `me1`, `me2`, `me3`, `me4`, `me5`, `me9`, `me11.written_cells`,
  `ts2.same-address`, and `pd1`; `000100b7 0000a183` emitted
  `me7.bss_zero` and `me11.read_only_cells`; `bffff0b7 0000a183` emitted
  `me6.near_max_lw`.
- Memory/preflight injections on the main memory seed reported
  `injection_applied = true` and verifier rejection for
  `risc0.semantic.memory.store_load_payload_flow --inject-step 2`,
  `risc0.semantic.memory.address_pointer_consistency --inject-step 4`,
  `risc0.semantic.memory.value_payload_consistency --inject-step 4/5`,
  `risc0.semantic.memory.address_space_consistency::domain=mem_write --inject-step 4`,
  `risc0.semantic.memory.address_space_consistency::domain=mem_read --inject-step 5`,
  `risc0.semantic.memory.kind_selector_consistency --inject-step 4/5`,
  `risc0.semantic.memory.finalization_consistency --inject-step 5`, and
  `risc0.semantic.time.monotonic_access_ordering --inject-step 5`.
- Initial/finalization/boundary injections reported `injection_applied = true`
  and verifier rejection for `000100b7 0000a183` with
  `risc0.semantic.memory.initial_value_binding --inject-step 1`,
  `risc0.semantic.memory.finalization_consistency --inject-step 1`, and
  `risc0.semantic.memory.address_space_consistency::domain=mem_read --inject-step 1`;
  `000100b7 0040a183` emitted `me7.data_loaded` and the initial-value
  injection at step 1 also rejected; `bffff0b7 0000a183` with
  `risc0.semantic.memory.address_pointer_consistency --inject-step 1`
  rejected after applying the hook.
