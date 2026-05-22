# Pico 22b0aae Latest Snapshot Repro

Target commit:

- `22b0aae6321c1f63c72aafd0b506b5f45b91ffb1`

## 1) Install Pico snapshot

From repo root (`beak/`):

```bash
UV_CACHE_DIR=/tmp/uv-cache make pico-install PICO_COMMIT=22b0aae6321c1f63c72aafd0b506b5f45b91ffb1
```

## 2) Build project binaries

```bash
cd path/to/beak/projects/pico-22b0aae6321c1f63c72aafd0b506b5f45b91ffb1
cargo build --release --bin beak-trace --bin beak-fuzz
```

## 3) Benchmark run (single command)

Run the initial-corpus benchmark with semantic witness search:

```bash
cd path/to/beak/projects/pico-22b0aae6321c1f63c72aafd0b506b5f45b91ffb1
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 1000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

Outputs are written under `path/to/beak/storage/fuzzing_seeds/` with the
prefix `benchmark-pico-22b0aae-...`.

Install location (OpenVM-style):

- `path/to/beak/beak-py/out/pico-22b0aae6321c1f63c72aafd0b506b5f45b91ffb1/pico-src`

## 4) Targeted trace run (`beak-trace`)

Run a targeted benchmark for one inline binary:

```bash
cd path/to/beak/projects/pico-22b0aae6321c1f63c72aafd0b506b5f45b91ffb1
cargo run --release -q --bin beak-trace -- --bin "00010337 00100293 00532023 00032283" --print-buckets
```

`beak-trace` aligns with OpenVM-style trace flags (`--oracle-*`, `--print-*`) and runs
oracle-vs-backend comparison with derived bucket signatures.

Useful flags:

```bash
--oracle-memory-model shared-code-data
--print-buckets
```

## Memory Proof-Path Status

The ordinary Beak RV32 inline memory path is meaningful when the seed uses a
Pico-valid guarded memory address. The old low-address examples wrote below the
`addr[1] + addr[2] != 0` memory-chip guard and rejected before injection.

Round11 repaired baseline:

```bash
cargo run -q --bin beak-trace -- --bin "00010337 00100293 00532023 00032283" --print-buckets
```

This store-then-load seed uses address `0x10000`, proves/verifies, emits the
memory buckets, and matches all registers. Round48 added the 22b0
`MemoryLocal` and `MemoryReadWrite::extra_record` balancing patches for
`pico.semantic.memory.timestamped_load_path`. The ordinary semantic-search smoke:

```bash
cargo run -q --bin beak-fuzz -- --bin "00010337 00100293 00532023 00032283" \
  --semantic-window-before 0 --semantic-window-after 0 --semantic-max-trials-per-bucket 1 \
  --mutation-iters 0
```

now completes with `bug_records=1`. The bug record is for
`trigger_bucket_id=sem.time.monotonic_access_ordering`,
`inject_kind=pico.semantic.memory.timestamped_load_path`, `inject_step=1`,
`semantic_injection_applied=true`, `backend_error=null`, and
`underconstrained_candidate=true`. Treat `ts2.same-address` as strict Beak Good.

Round16 added the 22b0 `MemoryInitializeFinalize` companion hook for
`pico.semantic.memory.timestamped_load_path`, so the timestamp replay now also
patches the matching finalization row. Round48 completed the missing local and
extra-record balancing needed for the ordinary strict TS2 replay.
