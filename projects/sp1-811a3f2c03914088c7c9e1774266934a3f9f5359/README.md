# SP1 811a3f2c Repro (OpenVM-style Project Entry)

Target commit:

- `811a3f2c03914088c7c9e1774266934a3f9f5359`

## Build

```bash
cd path/to/beak/projects/sp1-811a3f2c03914088c7c9e1774266934a3f9f5359
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Loop1 run

```bash
cd path/to/beak/projects/sp1-811a3f2c03914088c7c9e1774266934a3f9f5359
cargo run --release -q --bin beak-fuzz -- --iters 1000
```

## Output

Loop1 output JSONL files are written to:

- `path/to/beak/storage/fuzzing_seeds/`
