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

Beak-py's role is to **materialize and patch** a pinned zkVM snapshot under `out/`.
For OpenVM, `openvm-fuzzer install` will clone the upstream repo and apply patches automatically.

```bash
uv run openvm-fuzzer install --commit-or-branch bmk-regzero
```

### 4. Run a seed (via Rust beak-trace)

This repository's current integration test runner for OpenVM is the Rust binary:
`projects/openvm` -> `beak-trace`.

```bash
cd ../projects/openvm

# Baseline: should PASS (oracle regs match OpenVM regs)
cargo run --bin beak-trace -- --bin "00100513 00200593 00b50633"

# Soundness example: writes x0 (rd=0), should DETECT mismatch
cargo run --bin beak-trace -- --bin "12345017 00000533"
```

## Core Architecture

1. **`libs/zkvm-fuzzer-utils`**: Shared utilities (git worktrees, record parsing, injection helpers).
2. **`projects/*-fuzzer`**: Per-zkVM packages that can:
   - materialize a local zkVM repo snapshot into `out/<zkvm>-<commit>/...`
   - optionally apply instrumentation / fault-injection patches (where supported)
3. **`crates/beak-core`** (Rust): shared canonical trace types and parsing used by Rust binaries (e.g. `beak-trace`).

## Register Safety

Beak-py uses a subset of safe RISC-V registers (`x5-x7`, `x10-x17`, `x28-x31`) to avoid conflicts with system-reserved registers like `sp` (stack pointer) and `gp` (global pointer).

## OpenVM Commit Options

`openvm-fuzzer install --commit-or-branch <alias|hash>` accepts both pinned aliases (e.g. `bmk-regzero`)
and full commit hashes. See `beak-py/projects/openvm-fuzzer/openvm_fuzzer/settings.py` for the current
alias list and pinned commits.
