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

The following rows are now mapped to installed-source prover hooks, but are not
marked verified because injected smokes fire the hook and then fail Nexus
constraints/prover checks:

- Register/decode/ALU/control: `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`,
  `cf1`-`cf4`, `cf6.normal/after_branch_not_taken`, and `cf7`.
- Memory/time: `me2`, `me3`, `me6`, `me9`, `ts1`, same-address `ts2`, and
  `ts3`.

The verified rows remain installed-source load/store prover hooks for:

- `me1` / `nexus.semantic.memory.store_load_payload_flow`
- `me4` / `nexus.semantic.memory.write_payload_consistency`
- `me10` / `nexus.semantic.memory.kind_selector_consistency`

Current mappings target pass3 hooks in `prover/src/chips/cpu.rs`,
`prover/src/chips/memory_check/register_mem_check.rs`,
`prover/src/chips/instructions/{sll,srl,sra}.rs`,
`prover/src/chips/instructions/{slt,sltu,sub}.rs`, branch/JAL/JALR chips, and
`prover/src/chips/instructions/load_store.rs`. Each hook reports applied-site
evidence from the installed prover path through
`BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED` and backend `injection_applied = true`.

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
```

Remaining gaps after inspection:

- `md1`-`md5` stay bucket-only: installed `prover/src/machine.rs::BaseComponent`
  and `prover/src/chips/instructions/` expose no mul/div/rem prover chip files
  in this Nexus snapshot.
- `me5` stays bucket-only: `load_store.rs` and
  `memory_check/register_mem_check.rs` use separate RAM/register paths with no
  address-space selector to mutate.
- `me7.bss_zero/data_loaded` stays bucket-only: `extensions/ram_init_final.rs`
  has init/final rows, but they are keyed by final memory address order rather
  than the `UniformTrace` `op_idx` in the first-load bucket.
- Trace-missing rows still need durable evidence for ECALL syscall arguments,
  ELF/stack provenance, finalization/untouched memory, cross-segment ordering,
  bus/lookup multiplicity, and padding lifecycle rows.
