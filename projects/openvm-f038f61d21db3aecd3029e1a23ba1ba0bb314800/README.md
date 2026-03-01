# OpenVM f038f61d Repro (Loop1 + Targeted Injection)

Target commit:

- `f038f61d21db3aecd3029e1a23ba1ba0bb314800`

## Build

```bash
cd path/to/beak/projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Loop1 + targeted injection (single run)

Use chained direct-injection replay from loop1.  
`--timeout-ms 100000` is chosen to avoid dropping slow but valid repros.

```bash
cd path/to/beak/projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800 && cargo run --release -q --bin beak-fuzz -- --chain-direct-injection --iters 1000 --timeout-ms 100000 --oracle-precheck-max-steps 0
```

## Output

```bash
ls -lt path/to/beak/storage/fuzzing_seeds/loop1-openvm-f038f61d-*-bugs.jsonl | head
```
