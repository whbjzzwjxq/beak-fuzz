# OpenVM f038f61d Benchmark Repro

Target commit:

- `f038f61d21db3aecd3029e1a23ba1ba0bb314800`

## Build

```bash
cd path/to/beak/projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Benchmark run

Run the initial-corpus benchmark with semantic witness search:

```bash
cd path/to/beak/projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 500 \
  --timeout-ms 3000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64 \
  --oracle-precheck-max-steps 400
```

## Output

```bash
ls -lt path/to/beak/storage/fuzzing_seeds/benchmark-openvm-f038f61d-*-bugs.jsonl | head
```
