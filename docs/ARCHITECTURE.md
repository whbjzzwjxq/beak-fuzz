# beak-fuzz Architecture

`beak-fuzz` is a meta-repository for zkVM fuzzing work. Different zkVMs typically require:

- different SDK/toolchain dependencies,
- different Rust toolchains (often pinned nightlies),
- different binaries and runtimes,

while still benefiting from a shared "core" (ISA/oracles/trace abstractions/seed formats).

This repository is organized to keep zkVM-specific code isolated, and keep shared logic reusable.

## Repository Layout

- `crates/beak-core/`
  - Shared Rust library (`beak-core`) with zkVM-agnostic logic.
  - Intended to be buildable on a stable toolchain when possible.
  - Example modules:
    - `rv32im`: RISC-V RV32IM instruction parsing/encoding and an oracle executor.
    - `trace`: bucket/feedback traits and canonicalization helpers (backend-specific trace schemas live in `projects/<zkvm>-<commit>/`).
    - `fuzz`: shared seed format (`FuzzingSeed`) and metadata helpers.
- `projects/<zkvm>-<commit>/`
  - One independent Rust project per zkVM snapshot (zkVM + pinned commit).
  - Owns its own dependencies and binaries.
  - Owns its own `Cargo.lock` and `rust-toolchain.toml`.
  - Example:
    - `projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5/`: OpenVM-specific binaries for one snapshot.
    - `projects/sp1-7f643da16813af4c0fbaad4837cd7409386cf38c/`: SP1-specific binaries for one snapshot.
- `beak-py/`
  - Python tooling and workflows (project scaffolding, utilities, offline processing, etc.).
- `storage/`
  - Local artifacts and corpora (e.g., extracted seeds, risc-v test dumps).
- `docs/`
  - Project documentation (this file).

## Core vs. Projects

The key separation is:

- `beak-core` contains reusable logic that should not depend on a specific zkVM SDK.
- `projects/<zkvm>-<commit>` contains the integration layer and binaries for that zkVM snapshot.

This keeps the shared code easy to test and reuse across multiple zkVM backends, while allowing each backend to evolve independently.

## Toolchain Strategy

Each Rust sub-project pins its own toolchain:

- `crates/beak-core/rust-toolchain.toml`: typically `stable`
- `projects/openvm-<commit>/rust-toolchain.toml`: pinned nightly required by that OpenVM snapshot

This avoids forcing the entire repository to use a single Rust toolchain and avoids the limitation that a single Cargo workspace cannot build members with different `rustc` toolchains in one invocation.

## Binaries

Each zkVM snapshot project provides its own binaries under `projects/<zkvm>-<commit>/src/bin/`.

For example, `projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5` provides:

- `beak-trace`: runs oracle execution and compares it against backend execution for a given input; can also print captured trace JSON logs (when enabled by snapshot instrumentation).
- `beak-fuzz`: runs the beak-core benchmark loop (`run_benchmark_threaded`): differential oracle-vs-backend checking, bucket-guided feedback, and typed semantic-injection trials.

## Campaign Runner

`scripts/run_serial_install_injection.py` is the single entrypoint for
multi-target campaigns. It installs each configured snapshot, then runs the
ordinary `beak-fuzz` benchmark per target with a wall-clock budget, and writes
`summary.tsv` / `summary.json` plus per-run JSONL artifacts.

## Data Flow (Benchmark Path)

At a high level, each evaluated input follows this shape:

```text
seed/input_words
  -> oracle_execute (beak-core, rrs-lib based)
  -> transpile_to_vm_program
  -> execute+tracegen (VM SDK)
  -> extract backend final registers + micro-op logs
  -> derive bucket hits
  -> compare (oracle regs vs backend regs)
```

## Benchmark Execution Model

- Initial seeds are loaded from `--seeds-jsonl` (optionally capped by `--initial-limit`).
- Benchmark JSONL output uses each wrapper's configured directory by default. Set
  `BEAK_BENCHMARK_OUT_DIR` to route an ordinary benchmark run into a fresh
  campaign- or test-owned directory without changing backend behavior.
- Every scheduled seed is evaluated once as a baseline before semantic-injection
  trials and mutation rounds (`--mutation-iters`).
- Program length is scheduled with a soft nominal cap (`--max-instructions`,
  default 256) plus a long-tail quota lane up to `--long-tail-max-instructions`
  (runner default 8192), so long programs appear rarely instead of never.

## Bucket and Feedback Model

- Backend traces are converted to bucket hits (`BucketHit`), each identified by `bucket_id` (string).
- Obligation-derived semantic buckets are registered in `crates/beak-core/src/trace/semantic.rs`.
- `docs/OBLIGATIONS.md` defines the high-level obligation/cell taxonomy.
- `docs/OBLIGATION_IMPLEMENTATION_CONTRACT.md` defines the cross-VM contract for bucket names, `BucketHit.details`, injection kinds, and install instrumentation.
- `docs/OBLIGATION_IMPLEMENTATION_MATRIX.md` tracks per-VM implementation status.
- Hit bucket IDs are canonicalized into a stable signature (`bucket_hits_sig`, separated by `;`) for novelty tracking.
- Mutation arm selection uses a UCB bandit built into `crates/beak-core/src/fuzz/seed_mutation.rs`.

## How to Build / Test

Because each sub-project is independent:

- Core library:
  - `cd crates/beak-core && cargo test`
- OpenVM project (explicit snapshot):
  - `cd projects/openvm-<commit> && cargo build --bin beak-trace`
  - `cd projects/openvm-<commit> && cargo run --bin beak-trace -- --bin <hex_word> ...`
  - `cd projects/openvm-<commit> && FAST_TEST=1 cargo run --release --bin beak-fuzz -- --seeds-jsonl <path> --iters 500`

Note: backend projects may pull git dependencies; network access may be required for a first build.

## Adding a New zkVM Backend

To add a new backend snapshot `projects/<newzkvm>-<commit>/`:

1. Create a new Rust package under `projects/<newzkvm>-<commit>/` with its own `Cargo.toml`.
2. Pin a toolchain in `projects/<newzkvm>-<commit>/rust-toolchain.toml`.
3. Depend on core via path dependency:
   - `beak-core = { path = "../../crates/beak-core" }`
4. Implement backend-specific binaries under `projects/<newzkvm>-<commit>/src/bin/`.

The goal is to share logic by expanding `beak-core` APIs, rather than duplicating code across projects.
