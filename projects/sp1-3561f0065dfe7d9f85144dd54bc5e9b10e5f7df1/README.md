# SP1 3561f006 Obligation Coverage

Target commit:

- `3561f0065dfe7d9f85144dd54bc5e9b10e5f7df1`

This project targets the vulnerable side of `sp1#746`
(`underconstrained uint256_div`) and now also exposes central RV32IM
obligation buckets from the older SP1 `Runtime` execution records.

Semantic coverage:

- Executed-instruction buckets:
  `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md3`-`md5`,
  `cf1`-`cf4`, `cf6.normal/after_branch_not_taken`, `cf7`,
  `ts1.standard`, `ts3.standard`, memory shape buckets `me2`, `me3`,
  `me4`, `me9`, `me10`, and `pd1.short_trace`.
- Verified CPU-row semantic injection mappings for `rf1`-`rf3`, `id1`, `id2`,
  `id4`, and `id5` through the old SP1
  `core/src/cpu/trace.rs::CpuChip::event_to_row` prover-row hook. The installed
  old SP1 hooks for `sp1.semantic.memory.timestamped_load_path` and
  `sp1.semantic.lookup.boolean_multiplicity` still do not report applied-site
  metadata to this backend, so those memory/lookup candidates remain disabled.
- `sem.arithmetic.division_remainder_bound`
  - generalized class: `semantic.arithmetic.division_remainder_bound`
  - injection family: `sp1.semantic.arithmetic.division_remainder_bound`
  - legacy uint256-div precompile scenario, not a central RV32IM `md3`
    witness mapping

Install the patched snapshot first:

```bash
cd path/to/beak/beak-py
uv run sp1-fuzzer install --commit-or-branch 3561f0065dfe7d9f85144dd54bc5e9b10e5f7df1
```

Then run:

```bash
cd path/to/beak/projects/sp1-3561f0065dfe7d9f85144dd54bc5e9b10e5f7df1
cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets
cargo run -q --bin beak-trace -- --bin "00100013" --inject-kind "sp1.semantic.decode.zero_register_immutability::site=op_a_access" --inject-step 18446744073709551615 --print-buckets
cargo run -q --bin beak-trace -- --bin "000010b7 00002137 022081b3" --print-buckets
cargo run -q --bin beak-trace -- --bin "00012183" --print-buckets
cargo run -q --bin beak-trace -- --bin "00012183" --inject-kind "sp1.semantic.exec.op_selector_binding::site=opcode" --inject-step 18446744073709551615 --print-buckets
cargo run -q --bin beak-trace -- --bin "00100093 00108463 00200113" --print-buckets
cargo run -q --bin beak-trace -- --bin "00100093 00108463 00200113" --inject-kind "sp1.semantic.decode.format_immediate_reassembly::site=instruction_op_c" --inject-step 18446744073709551615 --print-buckets
```

The legacy uint256-div reproducer remains available through `beak-fuzz` or the
old no-`--bin` comparison path:

```bash
cargo run -q --bin beak-fuzz -- --json
```
