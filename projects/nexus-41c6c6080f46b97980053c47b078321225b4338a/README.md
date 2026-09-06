# Nexus Benchmark Backend

This project wires the Nexus zkVM snapshot `41c6c6080f46b97980053c47b078321225b4338a`
into the same `beak-trace` / `beak-fuzz` benchmark entrypoints used by the other
zkVM integrations.

The upstream Nexus and stwo sources are installed by `nexus_fuzzer.cli` under:

- `beak-py/out/nexus-41c6c6080f46b97980053c47b078321225b4338a/nexus-src`
- `beak-py/out/nexus-41c6c6080f46b97980053c47b078321225b4338a/stwo-src`

The wrapper keeps only Beak adapter logic in `src/`; it should not vendor
upstream source under this project directory.

Current semantic coverage is derived from executed Nexus `UniformTrace` steps
plus memory records:

- Register/decode/ALU/control: `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`,
  `cf1`-`cf6`.
- Mul/div: `md1`-`md5` when the executed operands expose the special case or
  product/division class. Nexus prover smoke currently reports unsupported
  DIV for some prover paths, so these are not verified.
- Memory/time: `me1`-`me7`, `me9`, `me10`, `ts1`, same-address `ts2`, and
  `ts3` from `UniformTrace` memory records.
- `pd3.mem_table` is emitted only from the installed prover's concrete
  `rw_mem_check.last_access` population when the write loop reaches the first
  row outside its allocated power-of-two table. The typed receipt records the
  total population, first overflowing row, and overflow size; missing,
  malformed, non-power-of-two, or nearby non-crossing receipts fail closed.

Executed `md4` hits include `rs1_val`, `rs2_val`, `rd_val`, `product_hi`, and
`product_lo`, and are emitted only when the executed destination agrees with
the exact 64-bit product relation.

This snapshot's MemorySize target is a baseline prover exception. The backend
does not advertise semantic candidates, and injected calls fail closed because
the install path has no witness-mutation hook for this snapshot.

Minimal smoke checks:

```bash
cargo run --bin beak-trace -- --bin "00100093 00200113 002081b3 40218233 0020c463 00300293 00500313" --print-buckets
cargo run --bin beak-trace -- --bin "00100093 00112023 00012183" --print-buckets
cargo run --bin beak-trace -- --bin "08000093 00110023 00010183" --print-buckets
cargo run --bin beak-trace -- --bin "fff00093 ffd0a103" --print-buckets
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
