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
  FAST_TEST=1
```

Notes:

- The fuzz target is run in release mode by default (`cargo run --release -q --bin beak-fuzz`).
- `FAST_TEST=1` enables fast insecure parameters for local fuzz/debug.
- Outputs are written to `storage/fuzzing_seeds/` as:
  - `loop1-...-corpus.jsonl`
  - `loop1-...-bugs.jsonl`

## 5) Pico Audit Workflow (45e74 commit)

Pico audit commit from CSV:

- `45e74ccd62758c6d67239913956e749adaba261c`

This workflow is managed from `beak/`, with project-local binaries under:

- `projects/pico-45e74ccd62758c6d67239913956e749adaba261c/`

Install snapshot:

```bash
make pico-install PICO_COMMIT=45e74ccd62758c6d67239913956e749adaba261c
```

Pico source snapshot path (same style as OpenVM under `beak-py/out`):

- `beak-py/out/pico-45e74ccd62758c6d67239913956e749adaba261c/pico-src`

Build project binaries:

```bash
make pico-build PICO_COMMIT=45e74ccd62758c6d67239913956e749adaba261c
```

Run full workflow (single entry, OpenVM-style):

```bash
make pico-fuzz PICO_COMMIT=45e74ccd62758c6d67239913956e749adaba261c PICO_ITERS=1000
```

Run with chained direct injection enabled:

```bash
make pico-fuzz \
  PICO_COMMIT=45e74ccd62758c6d67239913956e749adaba261c \
  PICO_ITERS=1000 \
  PICO_CHAIN_DIRECT_INJECTION=1
```

Note: Pico currently uses an OpenVM-compatible Rust CLI surface for loop1/loop2 orchestration, but its
backend replay/injection path is still partial (not yet equivalent to OpenVM backend completeness).

## 6) SP1 Audit Workflow (7f64 / 811a / 39ab commits)

SP1 commits from benchmark CSV:

- `7f643da16813af4c0fbaad4837cd7409386cf38c`
- `811a3f2c03914088c7c9e1774266934a3f9f5359`

SP1 latest-audit vulnerable commit:

- `39ab52fce38172c9d23feed7248198dc14c164a9` (`[High] is_memory underconstrained`, fixed by `185d266233e09a15bc3d5d077d36b714d5d55084`)

Install snapshot:

```bash
make sp1-install SP1_COMMIT=7f643da16813af4c0fbaad4837cd7409386cf38c
```

Build project binaries:

```bash
make sp1-build SP1_COMMIT=7f643da16813af4c0fbaad4837cd7409386cf38c
```

Run full workflow:

```bash
make sp1-fuzz SP1_COMMIT=7f643da16813af4c0fbaad4837cd7409386cf38c SP1_ITERS=1000
```

Run with chained direct injection enabled:

```bash
make sp1-fuzz \
  SP1_COMMIT=811a3f2c03914088c7c9e1774266934a3f9f5359 \
  SP1_ITERS=1000 \
  SP1_CHAIN_DIRECT_INJECTION=1
```

Convenience targets for the real v4 audit snapshot:

```bash
make sp1-install-v4
make sp1-build-v4
make sp1-fuzz-v4
```
