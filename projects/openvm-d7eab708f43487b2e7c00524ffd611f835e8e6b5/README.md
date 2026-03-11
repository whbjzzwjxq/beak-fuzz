# OpenVM d7eab708 Benchmark Repro

Target commit:

- `d7eab708f43487b2e7c00524ffd611f835e8e6b5`

## Build

```bash
cd path/to/beak/projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Benchmark run

Run the initial-corpus benchmark. This snapshot currently has the benchmark
runner wired in, but does not yet expose commit-specific semantic injection
targets.

```bash
cd path/to/beak/projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 500 \
  --timeout-ms 3000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

## Output

```bash
ls -lt path/to/beak/storage/fuzzing_seeds/benchmark-openvm-d7eab708-*-bugs.jsonl | head
```
