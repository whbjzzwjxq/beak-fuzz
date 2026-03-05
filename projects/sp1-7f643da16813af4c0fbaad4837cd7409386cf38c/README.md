# SP1 7f643da1 Repro (OpenVM-style Project Entry)

Target commit:

- `7f643da16813af4c0fbaad4837cd7409386cf38c`

## Build

```bash
cd path/to/beak/projects/sp1-7f643da16813af4c0fbaad4837cd7409386cf38c
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Loop1 run

```bash
cd path/to/beak/projects/sp1-7f643da16813af4c0fbaad4837cd7409386cf38c
cargo run --release -q --bin beak-fuzz -- --iters 1000
```

## Output

Loop1 output JSONL files are written to:

- `path/to/beak/storage/fuzzing_seeds/`
