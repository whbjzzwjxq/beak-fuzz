# Beak-py Architecture (Installer/Patcher Layer)

## One-line description

Beak-py is a Python orchestration layer that materializes pinned zkVM snapshots and applies
instrumentation/patches so a Rust runner can execute, prove/verify, and collect traces.

## Repository layout

Typical structure:

```
beak-py/
  libs/
    beak-core/               Platform-independent models (RISC-V, trace schema, buckets)
    zkvm-fuzzer-utils/       Shared utilities used by project installers/patchers
  projects/
    openvm-fuzzer/           OpenVM snapshot materialization + patch pipeline
    <other-zkvm>-fuzzer/     Similar per-zkVM packages (optional / evolving)
  scripts/                   End-to-end workflows (historical; may be superseded)
  out/                       Materialized snapshots and generated artifacts
```

## Key concepts

- **Snapshot**: A checkout of a specific zkVM commit (or alias resolved to a commit) placed under
  `out/<zkvm>-<commit>/...`. Snapshots are treated as disposable build inputs.
- **Patch pipeline**: A deterministic sequence of edits applied to a snapshot to:
  - enable JSON trace emission (e.g. `<record>...</record>`)
  - relax protections / assertions for fuzzing-style workloads
  - add small helper crates or wiring needed by the Rust-side runner
- **Separation of concerns**:
  - Python: *fetch + patch + stage* zkVM sources
  - Rust: *execute + prove + verify + compare + analyze traces*

## OpenVM flow (current primary target)

The OpenVM support lives in `projects/openvm-fuzzer/openvm_fuzzer/`.

### Responsibilities

- Resolve a `--commit-or-branch` alias to a concrete commit.
- Materialize `openvm-src` into:
  `out/openvm-<commit>/openvm-src/`
- Apply patches from `openvm_fuzzer/patches/` onto that snapshot.

### Patch steps

Patches are plain Python modules under:

`projects/openvm-fuzzer/openvm_fuzzer/patches/`

The install command applies a fixed list of patch `apply(...)` functions. Patches generally use
simple text/file operations (write, overwrite, regex replace) and should avoid complex coupling
to Rust in-memory structs.

### fuzzer_utils crate template

Some OpenVM-side instrumentation is delivered by *creating or overwriting* the
`crates/fuzzer_utils` crate inside the snapshot using templates under:

`projects/openvm-fuzzer/openvm_fuzzer/patches/fuzzer_utils_crate/`

This is the preferred place to inject helpers that the Rust runner can call (e.g. toggles,
logging hooks, trace capture).

## Shared utilities (`libs/zkvm-fuzzer-utils`)

This library is intended to stay small and boring: filesystem helpers and minimal git helpers
used by per-zkVM installers.

If a feature is only needed by execution/trace analysis (process management, record parsing,
project generation), it should generally live outside the install layer (typically on the Rust
side), not here.

## Outputs (`out/`)

`out/` is the build staging area and is expected to contain:

- `out/openvm-<commit>/openvm-src/` (patched snapshot)
- optionally, workflow artifacts produced by scripts or runners (stdout/stderr dumps, JSON logs)

`out/` is not a source of truth; it is safe to delete and re-materialize.

## Design goals

- **Reproducible**: pin commits and make patches deterministic.
- **Minimal coupling**: keep Python focused on installation/patching; avoid circular dependencies
  between Python and Rust trace schemas.
- **Readable**: prefer straightforward file edits over meta-programming or heavy frameworks.

