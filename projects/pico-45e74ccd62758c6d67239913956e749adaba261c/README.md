# Pico 45e74ccd Repro (OpenVM-style Project Entry)

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

## 3) Full workflow (single command)

Run install + loop1 using a single project-local Rust entry:

```bash
cd path/to/beak/projects/pico-45e74ccd62758c6d67239913956e749adaba261c
cargo run --release -q --bin beak-fuzz -- --iters 1000
```

Optional flags:

- `--chain-direct-injection`: emit loop2-direct output skeleton

Install location (OpenVM-style):

- `path/to/beak/beak-py/out/pico-45e74ccd62758c6d67239913956e749adaba261c/pico-src`

## 4) Targeted trace run (`beak-trace`)

Run loop2 replay for one inline binary (no `audit-check/` fixtures):

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
