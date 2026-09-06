# Beak-py: zkVM Guest Trace Collection

Beak-py is a Python monorepo for **collecting zkVM guest program execution traces**, supporting multiple zkVMs. It is a part of beak project.

## Quick Start

### 1. Prerequisites

- Install UV for Python environment management:
  ```
  # On macOS and Linux.
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
- Install Rust toolchain with RISC-V target:
  ```bash
  rustup target add riscv32im-unknown-none-elf
  rustup component add llvm-tools-preview
  ```

### 2. Setup Python environment

Initialize the workspace and install dependencies:

```bash
make install
```

### 3. Install a zkVM snapshot (OpenVM example)

Beak-py's role is to **materialize and patch** pinned zkVM snapshots under `beak-py/out/`.
The installer default is now repo-stable rather than `cwd`-relative, but the repo-level `Makefile`
is still the preferred entrypoint because the Rust projects are pinned to that install root.

From `beak-fuzz/`:

```bash
make openvm-install COMMIT=bmk-regzero
```

Direct CLI usage from `beak-py/` is also fine:

```bash
cd beak-py
uv run openvm-fuzzer install --commit-or-branch bmk-regzero
```

If you previously installed snapshots into a legacy `out/<zkvm>-<commit>/...` location, migrate them with:

```bash
cd ..
make repair-install-roots
```

### 4. Run a seed (via Rust beak-trace)

This repository's current integration test runner for OpenVM is the Rust binary in a commit-pinned project:
`projects/openvm-<commit>` -> `beak-trace`.

```bash
# From the repo root, use the Makefile helpers to resolve aliases and run the right project.
cd ..

# (If you haven't installed the snapshot yet)
make openvm-install COMMIT=bmk-regzero

# Baseline: should PASS (oracle regs match OpenVM regs)
make openvm-run COMMIT=bmk-regzero BIN=beak-trace ARGS='--bin "00100513 00200593 00b50633"'

# Soundness example: writes x0 (rd=0), should DETECT mismatch
make openvm-run COMMIT=bmk-regzero BIN=beak-trace ARGS='--bin "12345017 00000533"'
```

## Core Architecture

1. **`libs/zkvm-fuzzer-utils`**: Shared utilities (git worktrees, record parsing, injection helpers).
2. **`projects/*-fuzzer`**: Per-zkVM packages that can:
   - materialize a local zkVM repo snapshot into `beak-py/out/<zkvm>-<commit>/...`
   - optionally apply instrumentation / fault-injection patches (where supported)
3. **`crates/beak-core`** (Rust): shared ISA/oracle, seed format, fuzz loop scaffolding, and bucket/feedback traits used by backend runners (e.g. `beak-trace`, `beak-fuzz`).

## Commit Options

`*-fuzzer install --commit-or-branch <alias|hash>` accepts pinned aliases and full commit hashes; the alias lists live in each fuzzer's `settings.py`.
