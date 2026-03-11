# SP1 7f643da1 Benchmark Repro

Target commit:

- `7f643da16813af4c0fbaad4837cd7409386cf38c`

## Build

```bash
cd path/to/beak/projects/sp1-7f643da16813af4c0fbaad4837cd7409386cf38c
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Benchmark run

```bash
cd path/to/beak/projects/sp1-7f643da16813af4c0fbaad4837cd7409386cf38c
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 1000 \
  --timeout-ms 3000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

## Output

Benchmark JSONL files are written to:

- `path/to/beak/storage/fuzzing_seeds/`
