# SP1 811a3f2c Benchmark Repro

Target commit:

- `811a3f2c03914088c7c9e1774266934a3f9f5359`

## Build

```bash
cd path/to/beak/projects/sp1-811a3f2c03914088c7c9e1774266934a3f9f5359
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Benchmark run

```bash
cd path/to/beak/projects/sp1-811a3f2c03914088c7c9e1774266934a3f9f5359
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
