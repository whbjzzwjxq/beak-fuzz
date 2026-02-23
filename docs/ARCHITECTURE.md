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

- `beak-trace`: runs oracle execution and compares it against OpenVM execution/proving/verification; can also print captured trace JSON logs (when enabled by snapshot instrumentation).
- `beak-fuzz`: runs loop1 (libAFL in-process mutational fuzzing) for oracle vs OpenVM differential checking. Bucket-guided feedback is currently best-effort and depends on backend bucket implementation.

## Data Flow (Typical Differential Check)

At a high level, a backend-specific tracer/fuzzer typically follows this shape:

```text
seed/input_words
  -> oracle_execute (beak-core, rrs-lib based)
  -> transpile_to_backend_program (backend-specific)
  -> run/prove/verify (backend-specific SDK)
  -> extract_backend_state (e.g., registers/memory)
  -> compare (oracle vs backend state)
```

The oracle and shared data structures live in `beak-core`; transpilation and execution live in the backend project.

## How to Build / Test

Because each sub-project is independent:

- Core library:
  - `cd crates/beak-core && cargo test`
- OpenVM project (explicit snapshot):
  - `cd projects/openvm-<commit> && cargo build --bin beak-trace`
  - `cd projects/openvm-<commit> && cargo run --bin beak-trace -- --bin <hex_word> ...`

Note: backend projects may pull git dependencies; network access may be required for a first build.

## Adding a New zkVM Backend

To add a new backend snapshot `projects/<newzkvm>-<commit>/`:

1. Create a new Rust package under `projects/<newzkvm>-<commit>/` with its own `Cargo.toml`.
2. Pin a toolchain in `projects/<newzkvm>-<commit>/rust-toolchain.toml`.
3. Depend on core via path dependency:
   - `beak-core = { path = "../../crates/beak-core" }`
4. Implement backend-specific binaries under `projects/<newzkvm>-<commit>/src/bin/`.

The goal is to share logic by expanding `beak-core` APIs, rather than duplicating code across projects.
