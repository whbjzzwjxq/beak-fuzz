# beak-fuzz Architecture

`beak-fuzz` is a meta-repository for zkVM fuzzing work. Different zkVMs typically require:

- different SDK/toolchain dependencies,
- different Rust toolchains (often pinned nightlies),
- different binaries and runtimes,

while still benefiting from a shared “core” (ISA/oracles/trace abstractions/seed formats).

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

- `beak-trace`: runs oracle execution and compares it against OpenVM execution for a given input; can also print captured trace JSON logs (when enabled by snapshot instrumentation).
- `beak-fuzz`: runs loop1 (libAFL in-process mutational fuzzing) for oracle vs OpenVM differential checking with bucket-guided feedback.

## Data Flow (Loop1, Current OpenVM Path)

At a high level, loop1 for OpenVM currently follows this shape:

```text
seed/input_words
  -> oracle_execute (beak-core, rrs-lib based)
  -> transpile_to_openvm_program
  -> execute+tracegen (OpenVM SDK)
  -> extract backend final registers + micro-op logs
  -> derive bucket hits
  -> compare (oracle regs vs backend regs)
```

OpenVM loop1 intentionally uses **trace-only + execute-only** for speed:

- Runs metered execution and preflight execution.
- Runs proving-context generation (`generate_proving_ctx`) to trigger chip trace generation (`fill_trace_row` path).
- Skips `engine.prove` (the expensive proof generation stage).

This preserves differential checking and bucket extraction while keeping per-input runtime much lower than full proof generation.

## Loop1 Execution Model

- Initial seeds are loaded from `--seeds-jsonl` (optionally capped by `--initial-limit`).
- If `--no-initial-eval` is not set, loop1 evaluates each initial corpus entry once before mutational fuzzing.
- Then loop1 runs `--iters` times, where each iteration executes one `fuzz_one` step.
- A single `fuzz_one` can evaluate multiple candidate inputs internally, so backend run counters can exceed `--iters`.

## Timeout Semantics

- `--timeout-ms` is a **soft timeout signal** used for run classification/metadata (`timed_out`), not an immediate interrupt.
- libAFL in-process execution also has a separate **hard timeout** configured in code (`InProcessExecutor::with_timeout`).

## Bucket and Feedback Model

- Backend traces are converted to bucket hits (`BucketHit`), each identified by `bucket_id` (string).
- OpenVM bucket IDs are defined in `projects/openvm-<commit>/src/lib/bucket_id.rs` using `strum`.
- Loop1 canonicalizes hit bucket IDs into a stable signature (`bucket_hits_sig`, separated by `;`) for novelty tracking.
- Mutator arm selection is controlled by a multi-armed bandit (`crates/beak-core/src/fuzz/bandit.rs`).

## How to Build / Test

Because each sub-project is independent:

- Core library:
  - `cd crates/beak-core && cargo test`
- OpenVM project (explicit snapshot):
  - `cd projects/openvm-<commit> && cargo build --bin beak-trace`
  - `cd projects/openvm-<commit> && cargo run --bin beak-trace -- --bin <hex_word> ...`
  - `cd projects/openvm-<commit> && FAST_TEST=1 cargo run --release --bin beak-fuzz -- --seeds-jsonl <path> --iters 500 --timeout-ms 2000`

Note: backend projects may pull git dependencies; network access may be required for a first build.

## Adding a New zkVM Backend

To add a new backend snapshot `projects/<newzkvm>-<commit>/`:

1. Create a new Rust package under `projects/<newzkvm>-<commit>/` with its own `Cargo.toml`.
2. Pin a toolchain in `projects/<newzkvm>-<commit>/rust-toolchain.toml`.
3. Depend on core via path dependency:
   - `beak-core = { path = "../../crates/beak-core" }`
4. Implement backend-specific binaries under `projects/<newzkvm>-<commit>/src/bin/`.

The goal is to share logic by expanding `beak-core` APIs, rather than duplicating code across projects.
