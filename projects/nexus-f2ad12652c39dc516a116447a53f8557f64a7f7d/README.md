# Nexus Benchmark Backend

This project wires the Nexus zkVM snapshot `f2ad12652c39dc516a116447a53f8557f64a7f7d`
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

The following rows are now mapped to installed-source prover hooks, but are not
marked verified because injected smokes fire the hook and then fail Nexus
constraints/prover checks:

- Register/decode/ALU/control: `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`,
  `cf1`-`cf4`, `cf6.normal/after_branch_not_taken`, and `cf7`.
- Memory/time: `me2`, `me3`, `me6`, `me7.bss_zero/data_loaded`, `me9`,
  `me11.written_cells/read_only_cells`, `ts1`, same-address `ts2`, and `ts3`.

The verified rows remain installed-source load/store prover hooks for:

- `me1` / `nexus.semantic.memory.store_load_payload_flow`
- `me4` / `nexus.semantic.memory.write_payload_consistency`
- `me10` / `nexus.semantic.memory.kind_selector_consistency`

Strict ordinary e2e evidence is also recorded for:

- `pd1.mem_padding` / `nexus.semantic.row.padding_interaction_send`

Current mappings target pass3 hooks in `prover/src/chips/cpu.rs`,
`prover/src/chips/memory_check/register_mem_check.rs`,
`prover/src/chips/instructions/{sll,srl,sra}.rs`,
`prover/src/chips/instructions/{slt,sltu,sub}.rs`, branch/JAL/JALR chips,
`prover/src/chips/instructions/load_store.rs`, and f2ad prover2 components
under `prover2/machine/src/components/`. Each hook reports applied-site
evidence from the installed prover path through
`BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED` and backend `injection_applied = true`.
The `pd1` hook now has strict Beak Good evidence when the ordinary
non-injected memory seed uses Nexus prover2 private-memory addresses. The old seed
`000020b7 0000a183` loads address `0x2000` and remains an invalid strict
baseline because it is outside the prover2 private-memory layout. The repaired
seed `000810b7 00808093 0000a183` loads from `0x81008`, verifies cleanly, and
ordinary `beak-fuzz` reports `underconstrained_candidate=true` for
`sem.row.padding_interaction_send`.
The `me7` hook maps first-load initial-value buckets to the prover2
`read_write_memory` row where the previous RAM timestamp is zero and mutates
`Ram1ValPrev`; it remains mapping evidence only because the repaired private
memory seed fires the hook but the injected prover run fails constraints, so
semantic replay records `underconstrained_candidate=false` for `me7`.
The `me11` hook maps private-memory written-cell and load-only read-only-cell
finalization buckets to `PrivateMemoryBoundary::generate_main_trace` rows and
mutates `RamValFinal`; it is same-semantics mapping evidence only. Focused
store and load-only seeds fire the hook, but injected runs fail verification
with logup-sum errors, so these paths are not strict Beak Good.

Minimal smoke checks:

```bash
cargo run --bin beak-trace -- --bin "00100093 00200113 002081b3 40218233 0020c463 00300293 00500313" --print-buckets
cargo run --bin beak-trace -- --bin "00100093 00112023 00012183" --print-buckets
cargo run --bin beak-trace -- --bin "08000093 00110023 00010183" --print-buckets
cargo run --bin beak-trace -- --bin "fff00093 ffd0a103" --print-buckets
```

Mapped injected smoke examples:

```bash
cargo run --bin beak-trace -- --bin "00100013" --inject-kind nexus.semantic.decode.zero_register_immutability --inject-step 0 --print-buckets
cargo run --bin beak-trace -- --bin "00100093 02000113 002091b3" --inject-kind nexus.semantic.alu.shift_mod32 --inject-step 2 --print-buckets
cargo run --bin beak-trace -- --bin "008000ef 00100113 00200193" --inject-kind nexus.semantic.exec.control_flow_binding --inject-step 0 --print-buckets
cargo run --bin beak-trace -- --bin "20100893 00000073" --inject-kind nexus.semantic.control.ecall_word_validity --inject-step 1 --print-buckets
cargo run --bin beak-trace -- --bin "08000093 00110023 00010183" --inject-kind nexus.semantic.memory.address_alignment_consistency --inject-step 1 --print-buckets
cargo run --bin beak-trace -- --bin "00100093 00112023 00012183" --inject-kind nexus.semantic.memory.store_load_payload_flow --inject-step 1 --print-buckets
cargo run --bin beak-trace -- --bin "08000093 00110023 00010183" --inject-kind nexus.semantic.memory.write_payload_consistency --inject-step 1 --print-buckets
cargo run --bin beak-trace -- --bin "00100093 00112023 00012183" --inject-kind nexus.semantic.memory.kind_selector_consistency --inject-step 1 --print-buckets
cargo run --bin beak-trace -- --bin "000810b7 00808093 0000a183" --inject-kind nexus.semantic.memory.initial_value_binding --inject-step 3 --print-buckets
cargo run --bin beak-trace -- --bin "000810b7 00808093 07f00113 0020a023" --inject-kind nexus.semantic.memory.finalization_consistency --inject-step 1 --print-buckets
cargo run --bin beak-trace -- --bin "000810b7 00808093 0000a183" --oracle-data-size-bytes 0x82020 --inject-kind nexus.semantic.memory.finalization_consistency --inject-step 1 --print-buckets
cargo run --bin beak-fuzz -- --bin "000810b7 00808093 0000a183" --oracle-data-size-bytes 0x82020 --semantic-window-before 0 --semantic-window-after 0 --semantic-max-trials-per-bucket 1
```

Remaining gaps after inspection:

- `md1`-`md5` stay bucket-only: installed `prover/src/machine.rs::BaseComponent`
  and `prover/src/chips/instructions/` expose no mul/div/rem prover chip files
  in this Nexus snapshot.
- `me5` stays bucket-only: `load_store.rs` and
  `memory_check/register_mem_check.rs` use separate RAM/register paths with no
  address-space selector to mutate.
- `me7.rodata/stack_uninit` stays trace-missing: executed memory records do not
  expose ELF/stack provenance.
- `me11.untouched_cells` stays trace-missing: the current trace does not
  enumerate untouched allocated memory cells.
- Trace-missing rows still need durable evidence for ECALL syscall arguments,
  ELF/stack provenance, finalization/untouched memory, cross-segment ordering,
  bus/lookup multiplicity, and non-memory-table padding lifecycle rows.
