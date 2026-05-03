# OpenVM d7eab708 Benchmark Repro

Target commit:

- `d7eab708f43487b2e7c00524ffd611f835e8e6b5`

## Build

```bash
cd path/to/beak/projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Semantic Instrumentation

This snapshot has d7-specific semantic injection mappings for observable
memory/table prover rows. The backend remains tracegen-only, so these rows are
`semantic_injection_mapped`, not `verified`.

Mapped d7 rows include `me1`-`me6`, `me9`, `me10`,
`me11.written_cells/read_only_cells`, `ts2.same-address`, and `bu1`.
Bucket-only d7 rows include `me7.bss_zero/data_loaded`, `me8.no_conflict`, and
`pd1.short_trace`.

Known trace-missing rows are `me7.rodata`, `me7.stack_uninit`,
`me8.double_init`, `me11.untouched_cells`, `ts2.cross_segment`, `cf5`,
`cf6.near_segment_end`, and `cf7`.

## Smokes

Rebuild the installed d7 OpenVM snapshot after changing the install pass:

```bash
cd path/to/beak/beak-py
uv run openvm-fuzzer install --commit-or-branch bmk-regzero
```

Baseline memory/table smoke:

```bash
cd path/to/beak/projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5
cargo run -q --bin beak-trace -- --bin \
  "04000093 07f00113 0020a023 0000a183 002080a3 00108203" \
  --print-buckets
```

Result: matched oracle registers and emitted 91 hits including memory
store/load, alignment/progression/space, load/write/kind, finalization,
same-address `ts2`, and `bu1`.

Injected replay examples:

```bash
cargo run -q --bin beak-trace -- --bin \
  "04000093 07f00113 0020a023 0000a183 002080a3 00108203" \
  --inject-kind openvm.semantic.memory.address_pointer_consistency \
  --inject-step 18446744073709551615

cargo run -q --bin beak-trace -- --bin \
  "04000093 07f00113 0020a023 0000a183 002080a3 00108203" \
  --inject-kind openvm.semantic.lookup.boolean_multiplicity \
  --inject-step 18446744073709551615
```

Result: mapped injected replays reported `semantic_injection_applied = true`
and `UNDERCONSTRAINED CANDIDATE DETECTED` in tracegen-only mode.

Boundary/init smokes:

```bash
cargo run -q --bin beak-trace -- --bin \
  "200000b7 ff008093 0000a103" --print-buckets

BEAK_OPENVM_INIT_MEMORY="2:96:127" cargo run -q --bin beak-trace -- \
  --bin "00000013" --print-buckets
```

Result: the boundary seed emitted `sem.memory.address_boundary_range`; the init
seed emitted four `sem.memory.initial_value_binding` hits. Both matched oracle
registers.

## Benchmark run

Run the initial-corpus benchmark:

```bash
cd path/to/beak/projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 500 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

## Output

```bash
ls -lt path/to/beak/storage/fuzzing_seeds/benchmark-openvm-d7eab708-*-bugs.jsonl | head
```
