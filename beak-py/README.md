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

1. **`libs/beak-core`**: Platform-independent trace types + bucket matchers.
2. **`libs/zkvm-fuzzer-utils`**: Shared utilities (git worktrees, record parsing, injection helpers).
3. **`projects/*-fuzzer`**: Per-zkVM packages that can:
   - materialize a local zkVM repo snapshot into `out/<zkvm>-<commit>/...`
   - optionally apply instrumentation / fault-injection patches (where supported)
4. **`scripts/*_bucket_workflow.py`**: legacy/memo scripts (not the primary supported flow).

## Register Safety

Beak-py uses a subset of safe RISC-V registers (`x5-x7`, `x10-x17`, `x28-x31`) to avoid conflicts with system-reserved registers like `sp` (stack pointer) and `gp` (global pointer).

## Bucket Workflow: Trace-Only Mode

`scripts/openvm_bucket_workflow.py` and `scripts/sp1_bucket_workflow.py` support `--trace-only`.

- Purpose: run from an instruction file and export only micro-op trace artifacts for downstream tooling.
- Behavior: skip bucket matching and do not write `bucket_hits.json`.
- Output: always writes `micro_op_records.json` + run stdout/stderr files.

### Commit Options

- OpenVM (`--openvm-commit`):
  - aliases: `bmk-regzero`, `bmk-336f`, `bmk-f038`
  - or pass a full commit hash directly
  - current pinned hashes:
    - `bmk-regzero` -> `d7eab708f43487b2e7c00524ffd611f835e8e6b5`
    - `bmk-336f` -> `336f1a475e5aa3513c4c5a266399f4128c119bba`
    - `bmk-f038` -> `f038f61d21db3aecd3029e1a23ba1ba0bb314800`

- SP1 (`--sp1-commit`):
  - aliases: `s26`, `s27`, `s29`
  - or pass a full commit hash directly
  - current pinned hashes:
    - `s26` -> `7f643da16813af4c0fbaad4837cd7409386cf38c`
    - `s27` -> `f3326e6d0bf78d6b4650ea1e26c501d72fb3c90b`
    - `s29` -> `811a3f2c03914088c7c9e1774266934a3f9f5359`

### OpenVM

```bash
uv run python scripts/openvm_bucket_workflow.py \
  --openvm-commit bmk-f038 \
  --install-openvm \
  --instructions-file /tmp/openvm_insts.txt \
  --trace-only
```

Output directory:

- `out/openvm-<commit>/from-insts/micro_op_records.json`
- `out/openvm-<commit>/from-insts/openvm_run.stdout.txt`
- `out/openvm-<commit>/from-insts/openvm_run.stderr.txt`

### SP1

```bash
uv run python scripts/sp1_bucket_workflow.py \
  --sp1-commit 7f643da16813af4c0fbaad4837cd7409386cf38c \
  --install-sp1 \
  --instructions-file /tmp/sp1_insts.txt \
  --trace-only
```

Output directory:

- `out/sp1-<commit>/from-insts/micro_op_records.json`
- `out/sp1-<commit>/from-insts/sp1_run.stdout.txt`
- `out/sp1-<commit>/from-insts/sp1_run.stderr.txt`
