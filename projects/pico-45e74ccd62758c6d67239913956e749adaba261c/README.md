# Pico 45e74ccd Benchmark Repro

Target commit:

- `45e74ccd62758c6d67239913956e749adaba261c`

## 1) Install Pico snapshot

From repo root (`beak/`):

```bash
UV_CACHE_DIR=/tmp/uv-cache make pico-install PICO_COMMIT=45e74ccd62758c6d67239913956e749adaba261c
```

## 2) Build project binaries

```bash
cd path/to/beak/projects/pico-45e74ccd62758c6d67239913956e749adaba261c
cargo build --release --bin beak-trace --bin beak-fuzz
```

## 3) Benchmark run (single command)

Run the initial-corpus benchmark with semantic witness search:

```bash
cd path/to/beak/projects/pico-45e74ccd62758c6d67239913956e749adaba261c
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 1000 \
  --timeout-ms 3000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

Outputs are written under `path/to/beak/storage/fuzzing_seeds/` with the
prefix `benchmark-pico-45e74ccd-...`.

Install location (OpenVM-style):

- `path/to/beak/beak-py/out/pico-45e74ccd62758c6d67239913956e749adaba261c/pico-src`

## 4) Targeted trace run (`beak-trace`)

Run a targeted benchmark for one inline binary:

```bash
cd path/to/beak/projects/pico-45e74ccd62758c6d67239913956e749adaba261c
cargo run --release -q --bin beak-trace -- --bin "00100293 00000313 00532023"
```

`beak-trace` aligns with OpenVM-style trace flags (`--oracle-*`, `--print-*`) and runs
oracle-vs-backend comparison with derived bucket signatures.

Useful flags:

```bash
--oracle-memory-model shared-code-data
--print-buckets
```
