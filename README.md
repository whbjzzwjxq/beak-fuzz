# beak-fuzz Quick Start

Minimal setup and run guide for the current OpenVM backend.

For architecture details, see `docs/ARCHITECTURE.md`.

## 1) Environment Setup

### Python side (`beak-py`)

Required:

- `python3`
- `uv`
- `make`

Quick check:

```bash
python3 --version
uv --version
make --version
```

### Rust side

Required:

- `rustup`
- `cargo`

Quick check:

```bash
rustup --version
cargo --version
```

Notes:

- `crates/beak-core` is typically built with stable.
- OpenVM snapshot projects pin their own toolchain via `rust-toolchain.toml`.
- On first build, `cargo`/`rustup` may download toolchains and git dependencies.

## 2) Install OpenVM Snapshot

From repo root:

```bash
make openvm-install COMMIT=bmk-regzero
```

`COMMIT` can be:

- an alias (for example `bmk-regzero`), or
- a full OpenVM commit SHA.

## 3) Run Minimal Example (`openvm-example-x0`)

This runs a tiny `beak-trace` example that checks x0 behavior.

```bash
make openvm-example-x0
```

Equivalent explicit command:

```bash
make openvm-run COMMIT=bmk-regzero BIN=beak-trace ARGS='--bin "12345017 00000533"'
```

## 4) Run Minimal Fuzz (10 iterations)

### Prepare initial seeds (if needed)

If `storage/fuzzing_seeds/initial.jsonl` does not exist yet:

```bash
make extract-initial-seeds
```

### Run loop1 for 10 iterations

```bash
make openvm-fuzz \
  COMMIT=bmk-regzero \
  ITERS=10 \
  INITIAL_LIMIT=1 \
  MAX_INSTRUCTIONS=32 \
  TIMEOUT_MS=2000 \
  FAST_TEST=1 \
  NO_INITIAL_EVAL=1
```

Notes:

- The fuzz target is run in release mode by default (`cargo run --release -q --bin beak-fuzz`).
- `FAST_TEST=1` enables fast insecure parameters for local fuzz/debug.
- `NO_INITIAL_EVAL=1` skips the initial corpus evaluation pass for faster smoke runs.
- Outputs are written to `storage/fuzzing_seeds/` as:
  - `loop1-...-corpus.jsonl`
  - `loop1-...-bugs.jsonl`

