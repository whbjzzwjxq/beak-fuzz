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
    - `trace`: cross-zkVM-friendly trace/micro-op data structures.
    - `fuzz`: shared seed format (`FuzzingSeed`) and metadata helpers.
- `projects/<zkvm>/`
  - One independent Rust project per zkVM integration.
  - Owns its own dependencies and binaries.
  - Owns its own `Cargo.lock` and `rust-toolchain.toml`.
  - Example:
    - `projects/openvm/`: OpenVM-specific binaries and OpenVM SDK dependencies.
- `beak-py/`
  - Python tooling and workflows (project scaffolding, utilities, offline processing, etc.).
- `storage/`
  - Local artifacts and corpora (e.g., extracted seeds, risc-v test dumps).
- `docs/`
  - Project documentation (this file).

## Core vs. Projects

The key separation is:

- `beak-core` contains reusable logic that should not depend on a specific zkVM SDK.
- `projects/<zkvm>` contains the integration layer and binaries that depend on that zkVM.

This keeps the shared code easy to test and reuse across multiple zkVM backends, while allowing each backend to evolve independently.

## Toolchain Strategy

Each Rust sub-project pins its own toolchain:

- `crates/beak-core/rust-toolchain.toml`: typically `stable`
- `projects/openvm/rust-toolchain.toml`: pinned nightly required by OpenVM

This avoids forcing the entire repository to use a single Rust toolchain and avoids the limitation that a single Cargo workspace cannot build members with different `rustc` toolchains in one invocation.

## Binaries

Each zkVM project provides its own binaries under `projects/<zkvm>/src/bin/`.

For example, `projects/openvm` provides:

- `beak-trace`: runs an oracle execution (rrs-lib) and compares it against OpenVM execution/proving/verification.
- `beak-fuzz`: placeholder binary currently; intended to host fuzz loops and integration with fuzzing engines.

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
- OpenVM project:
  - `cd projects/openvm && cargo build --bin beak-trace`
  - `cd projects/openvm && cargo run --bin beak-trace -- --bin <hex_word> ...`

Note: backend projects may pull git dependencies; network access may be required for a first build.

## Adding a New zkVM Backend

To add a new backend `projects/<newzkvm>/`:

1. Create a new Rust package under `projects/<newzkvm>/` with its own `Cargo.toml`.
2. Pin a toolchain in `projects/<newzkvm>/rust-toolchain.toml`.
3. Depend on core via path dependency:
   - `beak-core = { path = "../../crates/beak-core" }`
4. Implement backend-specific binaries under `projects/<newzkvm>/src/bin/`.

The goal is to share logic by expanding `beak-core` APIs, rather than duplicating code across projects.
