# Risc0 10fa9788 Beak Target

Target snapshot: `10fa97888d16cebf1b924c2079d9d18b939da6d3`.

This target adapts the c0db RISC0 harness to the latest flat `prove.rs` / M3
source layout. The Python installer selects `prove/beak_m3.rs`, wires it into
`risc0/circuit/rv32im/src/prove.rs`, and leaves the latest upstream executor in
place.

## Implemented Coverage

- Bucket emission from executed RV32IM instruction traces:
  `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md1`-`md5`, `me10`,
  `cf1`-`cf7`, `ts1`, `ts3`, and `rc1.alu_result`.
- Bucket emission from M3 preflight summary:
  `pd1.exec_padding` via `sem.row.padding_interaction_send`.
- Bucket emission from concrete M3 instruction witness memory transactions:
  register address-space reads/writes, load/store memory reads/writes,
  store-load payload flow, initial-value reads, finalization rows, and
  timestamp/order buckets when the corresponding executed load/store pattern is
  present.
- Smoke-verified semantic injection mappings for M3 install-supported buckets:
  `risc0.semantic.decode.zero_register_immutability`,
  `risc0.semantic.decode.operand_index_routing`,
  `risc0.semantic.exec.dest_binding`,
  `risc0.semantic.memory.store_load_payload_flow`,
  `risc0.semantic.memory.load_value_binding`,
  `risc0.semantic.memory.write_payload_consistency`,
  `risc0.semantic.time.monotonic_access_ordering`,
  `risc0.semantic.arithmetic.division_remainder_bound`, and
  `risc0.semantic.control.ecall_argument_decomposition`.

The M3 hook mutates `PreflightContext.aux` for the requested `inject_kind` and
reports applied status through `prove_segment_with_injection`. Risc0 M3 witness
cycles are not normalized to Beak `op_idx`, so mapped hooks are intentionally
limited to smoke-proven same-kind witness blocks.

## Gaps

- M3 does not expose the legacy raw memory transaction rows used by c0db. The
  latest harness reconstructs Beak memory-access observations from
  `InstLoadWitness`, `InstStoreWitness`, and register witness rows. The current
  M3 memory mutation coverage is limited to store-load payload flow and
  load-value binding through `InstLoadWitness.mem.value`, plus write-payload
  consistency through `InstStoreWitness.mem.value`, and same-address timestamp
  ordering through `InstLoadWitness.mem.prevCycle`; address-space,
  initial-memory, and finalization hooks remain unmapped.
- Other emitted buckets remain bucket-only until a concrete M3 row-level
  witness hook is audited for the matching semantic and its schedule can reach
  that hook through normal replay.

## Smoke Commands

- Baseline:
  `cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3 00000073" --print-buckets`
  emits div/ecall execution buckets and `pd1.exec_padding`.
- Zero-register injection:
  `cargo run -q --bin beak-trace -- --bin "00000013" --inject-kind risc0.semantic.decode.zero_register_immutability --inject-step 0 --print-buckets`
  reports `injection_applied = true`, logs an M3 `InstImm` witness mutation,
  annotates the `rf1` bucket with `beak_injected_kind`, and returns verifier
  rejection.
- Operand-routing injection:
  `cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3" --inject-kind risc0.semantic.decode.operand_index_routing --inject-step 2 --print-buckets`
  reports `injection_applied = true`, logs the M3 witness mutation, annotates
  the trigger bucket with `beak_injected_kind`, and returns verifier rejection.
- Destination-binding injection:
  `cargo run -q --bin beak-trace -- --bin "00100093" --inject-kind risc0.semantic.exec.dest_binding --inject-step 0 --print-buckets`
  reports `injection_applied = true`, logs an M3 destination-register witness
  mutation, annotates the `rf3` bucket, and returns verifier rejection.
- M3 memory transaction exposure:
  `cargo run -q --bin beak-trace -- --bin "000100b7 00408093 07f00113 0020a023 0000a183" --print-buckets`
  emits M3-derived memory-access buckets including register address-space,
  main-memory store/load payload flow, and finalization buckets.
- Load-value injection:
  `cargo run -q --bin beak-trace -- --bin "000100b7 00408093 07f00113 00208023 00008183" --inject-kind risc0.semantic.memory.load_value_binding --inject-step 4 --print-buckets`
  reports `injection_applied = true`, logs an M3 `InstLoadWitness.mem.value`
  mutation, annotates the `me3` bucket, and returns verifier rejection.
- Store-load payload-flow injection:
  `cargo run -q --bin beak-trace -- --bin "000100b7 00408093 07f00113 00208023 00008183" --inject-kind risc0.semantic.memory.store_load_payload_flow --inject-step 4 --print-buckets`
  reports `injection_applied = true`, logs an M3 `InstLoadWitness.mem.value`
  mutation, annotates the `me1` bucket, and returns verifier rejection.
- Write-payload injection:
  `cargo run -q --bin beak-trace -- --bin "000100b7 00408093 07f00113 00208023 00008183" --inject-kind risc0.semantic.memory.write_payload_consistency --inject-step 3 --print-buckets`
  reports `injection_applied = true`, logs an M3 `InstStoreWitness.mem.value`
  mutation, annotates the `me4` bucket, and returns verifier rejection.
- Timestamp-order injection:
  `cargo run -q --bin beak-trace -- --bin "000100b7 00408093 07f00113 00208023 00008183" --inject-kind risc0.semantic.time.monotonic_access_ordering --inject-step 4 --print-buckets`
  reports `injection_applied = true`, logs an M3 `InstLoadWitness.mem.prevCycle`
  mutation, annotates the `ts2` bucket, and returns verifier rejection.
- Division-bound injection:
  `cargo run -q --bin beak-trace -- --bin "00700113 00500193 023150b3" --inject-kind risc0.semantic.arithmetic.division_remainder_bound --inject-step 2 --print-buckets`
  reports `injection_applied = true` and annotates the `md3` bucket.
- Ecall-argument injection:
  `cargo run -q --bin beak-trace -- --bin "00100893 00000513 005005b7 00400613 00000073" --inject-kind risc0.semantic.control.ecall_argument_decomposition --inject-step 4 --print-buckets`
  reports `injection_applied = true` and annotates the `cf5` bucket.
