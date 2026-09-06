# beak-fuzz

Differential fuzzing and semantic-injection benchmark over six zkVM families
(OpenVM, SP1, Pico, RISC0, Jolt, Nexus), each pinned to a specific vulnerable
commit as a project under `projects/<vm>-<commit>/`.

## Layout

- `crates/beak-core` - shared RV32IM oracle, trace/bucket model, benchmark loop.
- `projects/<vm>-<commit>/` - one crate per snapshot: `src/lib` (trace +
  backend) and `src/bin` (`beak-fuzz`, `beak-trace`).
- `beak-py/` - install passes that stage and patch VM snapshots into
  `beak-py/out/<vm>-<commit>/`.
- `scripts/` - campaign runner and corpus tools.
- `storage/fuzzing_seeds/initial.jsonl` - the benchmark corpus.
- `docs/` - architecture and obligation references.

## Prerequisites

`python3`, `uv`, `make`, and a Rust toolchain via `rustup`. Snapshot projects
pin their own toolchain with `rust-toolchain.toml`; the first build downloads
toolchains and git dependencies.

## Quick start

```bash
make openvm-install COMMIT=bmk-regzero   # stage + patch one snapshot
make openvm-example-x0                   # minimal beak-trace differential check
make extract-initial-seeds               # build initial.jsonl if missing
make openvm-fuzz COMMIT=bmk-regzero ITERS=10 FAST_TEST=1
```

Every VM family follows the same `<vm>-install` / `<vm>-build` / `<vm>-fuzz`
target pattern; see the `Makefile` for the commit variables each accepts
(`COMMIT`, `PICO_COMMIT`, `SP1_COMMIT`, ...; full SHA or the aliases defined in
`beak-py/projects/<vm>-fuzzer/*/settings.py`).

## Full campaign

One runner drives every configured VM commit:

```bash
python3 scripts/run_serial_install_injection.py
```

It installs each target when needed, runs the benchmark with semantic
injection, and writes `summary.tsv` / `summary.json` under `RUN_ROOT` plus
per-run JSONL records. Common knobs (all optional, shown with defaults):

| Knob | Default | Meaning |
|---|---|---|
| `CPU_SET` / `VM_CORES` / `PARALLEL_VMS` | all cores / 32 / derived | CPU pool, cores per VM, VM-level parallelism |
| `SOFT_TIMEOUT_SECONDS` | 14400 | per-target wall-clock budget |
| `INITIAL_LIMIT` / `MUTATION_ITERS` | 0 / 0 | corpus size cap (0 = all) / mutation rounds |
| `MAX_INSTRUCTIONS` | 256 | nominal program length |
| `LONG_TAIL_MAX_INSTRUCTIONS` | 8192 | absolute length ceiling; longer seeds enter a small deterministic quota lane instead of being truncated |
| `SEEDS_JSONL` | `storage/fuzzing_seeds/initial.jsonl` | input corpus |
| `--skip-install` | off | reuse installed snapshots |
| `--only-commit` / `--exclude-commit` | - | select targets |
| `--print-commands` | - | dry run |

A warmed-cache smoke run for a new machine just lowers the budget, e.g.
`SOFT_TIMEOUT_SECONDS=600 INITIAL_LIMIT=1 MAX_INSTRUCTIONS=64 FAST_TEST=1`.
`THREADS` remains a legacy alias for `VM_CORES`.

`initial.jsonl` is the discovery corpus. `replay_seed.jsonl` is the
ground-truth manifest of confirmed strict cases - do not pass it as
`SEEDS_JSONL`; to replay it inside the normal campaign shape, build a mixed
corpus with `scripts/build_replay_corpus.py`.

## Documentation

- `docs/ARCHITECTURE.md` - repository layout and trace/injection architecture.
- `docs/OBLIGATIONS.md` - obligation taxonomy (the `sem.*` bucket families).
- `docs/OBLIGATION_IMPLEMENTATION_CONTRACT.md` - instrumentation contract.
- `docs/OBLIGATION_IMPLEMENTATION_MATRIX.md` - per-VM implementation status.
- `beak-py/README.md` - the install-pass side.
