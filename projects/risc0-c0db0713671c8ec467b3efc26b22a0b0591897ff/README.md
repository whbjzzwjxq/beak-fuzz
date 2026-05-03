# Risc0 c0db0713 Beak Target

Target snapshot: `c0db0713671c8ec467b3efc26b22a0b0591897ff`.

This target derives obligation buckets from executed RV32IM oracle steps using
Risc0's split code/data layout at `0x00010004`. A raw ECALL at the next
sequential PC is included because the Risc0 backend executes it through the
host syscall path even though the shared oracle stops before ECALL.

## Implemented Coverage

- Verified semantic injection mappings:
  - `sem.decode.operand_index_routing` ->
    `risc0.semantic.decode.operand_index_routing`
  - `sem.arithmetic.division_remainder_bound` ->
    `risc0.semantic.arithmetic.division_remainder_bound`
  - `sem.control.ecall_argument_decomposition` ->
    `risc0.semantic.control.ecall_argument_decomposition`
- Hook-present but not mapped:
  - `sem.decode.zero_register_immutability` has a legacy prover hook, but c0db
    semantic replay is blocked because the prover path can trap with SIGFPE.
  - `sem.decode.rd_bit_decomposition` has a legacy prover hook, but is also
    blocked by the same c0db replay risk.
- Bucket emission from executed instruction trace:
  `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md1`-`md5`, `me10`, `cf1`-`cf7`
  except JALR clear-LSB/even/wrap target cells, `ts1`, `ts3`, and
  `rc1.alu_result`.
- Bucket-only preflight memory/padding coverage:
  `me1`-`me7.bss_zero/data_loaded`, `me9`,
  `me11.written_cells/read_only_cells`, `ts2.same-address`, and
  `pd1.exec_padding`. These buckets come from legacy Risc0 prover
  `RawMemoryTransaction` rows joined with actual `InstructionStart` events and
  register-memory reads.

## Gaps

- No semantic injection mapping is claimed for the new memory/timestamp/padding
  buckets: no stable legacy prover mutation hook has been validated for the
  relevant preflight memory rows, timestamp links, or padding rows.
- `me7.rodata/stack_uninit`, `me8`, `me11.untouched_cells`,
  `ts2.cross_segment`, `cf6.near_segment_end`, and `bu1` need provenance,
  duplicate-init, untouched final-memory, cross-segment continuity, or lookup
  multiplicity/is_real rows not currently exposed.
- Representative JALR target-cell replay terminates before bucket output on
  c0db, so `cf3.clear_lsb`, `cf3.even`, and `cf3.wrap` remain `trace_missing`.

## Smoke Commands

- Baseline:
  `cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3 00000073" --print-buckets`
  emitted decode/register/ALU/div/ecall/control/time buckets.
- Operand-routing injection:
  `cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3" --inject-kind risc0.semantic.decode.operand_index_routing --inject-step 2 --print-buckets`
  reported `injection_applied = true` and verifier rejection.
- Div/rem injection:
  `cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3 00000073" --inject-kind risc0.semantic.arithmetic.division_remainder_bound --inject-step 2 --print-buckets`
  reported `injection_applied = true` and verifier rejection.
- ECALL decomposition injection:
  `cargo run -q --bin beak-trace -- --bin "00100893 00000073" --inject-kind risc0.semantic.control.ecall_argument_decomposition --inject-step 1 --print-buckets`
  reported `injection_applied = true` and verifier rejection.
- Zero-register blocked replay:
  `cargo run -q --bin beak-trace -- --bin "00100013" --inject-kind risc0.semantic.decode.zero_register_immutability --inject-step 0 --print-buckets`
  emitted the baseline zero-register bucket and reported the c0db SIGFPE replay
  blocker with `injection_applied = false`.
- Shift partition smoke:
  `cargo run -q --bin beak-trace -- --bin "02100093 00109113 002091b3" --print-buckets`
  emitted `al2.sll_lt32` and `al2.sll_ge32`.
- Memory kind-selector smoke:
  `cargo run -q --bin beak-trace -- --bin "00400113 00202023" --print-buckets`
  emitted `sem.memory.kind_selector_consistency`; backend execution then
  reported `StoreAccessFault`, so no memory-effect injection mapping is
  claimed.
- Memory/preflight smoke:
  `cargo run -q --bin beak-trace -- --bin "000100b7 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`
  emitted `me1`, `me2`, `me3`, `me4`, `me5`, `me9`,
  `me11.written_cells`, `ts2.same-address`, and `pd1`.
- Initial/read-only memory smoke:
  `cargo run -q --bin beak-trace -- --bin "000100b7 0000a183" --print-buckets`
  emitted `me7.bss_zero`, `me11.read_only_cells`, and `pd1`.
- Boundary memory smoke:
  `cargo run -q --bin beak-trace -- --bin "bffff0b7 0000a183" --print-buckets`
  emitted `me6.near_max_lw`.
- Branch/control smoke:
  `cargo run -q --bin beak-trace -- --bin "00100093 00200113 0020c463 00300193" --print-buckets`
  emitted a BLT not-taken `sem.exec.control_flow_binding` bucket and
  `cf6.normal`.
