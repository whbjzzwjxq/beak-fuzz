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
  - `sem.exec.op_selector_binding` ->
    `risc0.semantic.exec.op_selector_binding`
  - `sem.arithmetic.division_remainder_bound` ->
    `risc0.semantic.arithmetic.division_remainder_bound`
  - `sem.control.ecall_argument_decomposition` ->
    `risc0.semantic.control.ecall_argument_decomposition`
- Bucket emission from executed instruction trace:
  `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md1`-`md5`,
  `cf1`-`cf7` where the corresponding instruction/cell is observed,
  `me10` load/store kind selectors, `ts1`, `ts3`, and `rc1.alu_result`.
  Shift buckets include runtime `rs2 >= 32` cells, and JALR target buckets
  include `target_before_lsb_clear` / `target_after_lsb_clear` details from
  executed register state when observed.

## Gaps

- `sem.exec.dest_binding`, `sem.decode.rd_bit_decomposition`,
  `sem.exec.control_flow_binding`, and `sem.exec.memory_effect_binding` have
  Risc0 asset hooks, but they are not backend-mapped: dest-binding panicked in
  prover smoke, control-flow did not report contract-complete applied evidence
  and a JALR target seed hit witness generation failure, and memory effect
  seeds hit Risc0 memory traps before successful baseline replay.
- Address/value memory obligations (`me1`-`me9`, `me11`) lack a Risc0
  `memory_access` or init/finalization record with contract fields.
- `ts2.cross_segment`, `cf6.near_segment_end`, `bu1` and broader bus/padding
  obligations need segment, bus, lookup, transcript, or table-lifecycle rows
  not currently exposed.

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
- JALR target-cell smoke:
  `cargo run -q --bin beak-trace -- --bin "000100b7 01108093 00008067 00100113" --print-buckets`
  emitted `cf3.imm_zero` and `cf3.clear_lsb`; Risc0 prover reported witness
  generation failure, so this is not verified or backend-mapped.
