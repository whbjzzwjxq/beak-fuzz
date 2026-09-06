# OpenVM 336f1a47 Benchmark Repro

Target commit:

- `336f1a475e5aa3513c4c5a266399f4128c119bba`

This snapshot backs the OpenVM benchmark targets `o1/o2/o3/o5/o7/o8/o15/o19`
and the broader obligation matrix for the OpenVM-336 column.

## Install

From repo root (`beak/`):

```bash
UV_CACHE_DIR=/tmp/uv-cache make openvm-install COMMIT=336f1a475e5aa3513c4c5a266399f4128c119bba
```

## Build

```bash
cd path/to/beak/projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Benchmark run

```bash
cd path/to/beak/projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 500 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64 \
  --oracle-precheck-max-steps 400
```

Representative single-seed verifier replay (baseline emits the bucket; the
injected replay reports `UNDERCONSTRAINED CANDIDATE DETECTED`):

```bash
./target/release/beak-trace --bin "00100093 02800113 002091b3" \
  --inject-kind "openvm.semantic.alu.immediate_limb_consistency::mode=byte_bias,slot=0,strength=0" \
  --inject-step 2 \
  --print-buckets
```

## Coverage and limits

The full obligation-by-obligation status, bucket-to-hook mapping, and smoke
evidence for this snapshot live in the OpenVM-336 column of
`docs/OBLIGATION_IMPLEMENTATION_MATRIX.md`. Not all 8 `o..` targets are covered
yet. Known limits:

- Initial-memory injection is intentionally not backend-mapped: attempted
  `set_initial_memory` / boundary-vs-merkle hooks were underconstrained in
  prover smoke.
- `cf7` has a program-table TERMINATE opcode hook but stays
  `install_patch_available`: the raw RV ECALL word `0x00000073` transpiles to
  `unimp`, so no baseline bucket is observable.
- `cf5` is trace-missing: OpenVM-336 does not expose Linux-style ECALL syscall
  number plus a0-a7 dispatch values.
- Remaining bucket-only gaps: `me7.rodata`, `me7.stack_uninit`,
  `me8.double_init`, `me11.untouched_cells`, `ts2.cross_segment`.

## Inspect outputs

```bash
ls -lt path/to/beak/storage/fuzzing_seeds/benchmark-openvm-336f1a47-*-bugs.jsonl | head
```

For semantic search entries, check:

- `metadata.phase = "semantic_search"`
- `metadata.semantic_class` is populated
- `metadata.kind` is one of `underconstrained_candidate`, `mismatch`, `exception`
