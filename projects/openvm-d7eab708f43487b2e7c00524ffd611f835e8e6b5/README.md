# OpenVM d7eab708 Repro (Loop1 + Targeted Injection)

Target commit:

- `d7eab708f43487b2e7c00524ffd611f835e8e6b5`

## Build

```bash
cd path/to/beak/projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Loop1 + targeted injection (single run)

Use chained direct-injection replay from loop1.  
`--timeout-ms 100000` is chosen to avoid dropping slow but valid repros.

```bash
cd path/to/beak/projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5 && cargo run --release -q --bin beak-fuzz -- --chain-direct-injection --iters 1000 --timeout-ms 100000 --oracle-precheck-max-steps 0
```

## Output

```bash
ls -lt path/to/beak/storage/fuzzing_seeds/loop1-openvm-d7eab708-*-bugs.jsonl | head
```
