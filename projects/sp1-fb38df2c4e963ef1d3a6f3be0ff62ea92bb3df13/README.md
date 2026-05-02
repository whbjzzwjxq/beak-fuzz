# Legacy SP1 Recursion Runner

This project targets the historical SP1 recursion snapshot:

- `fb38df2c4e963ef1d3a6f3be0ff62ea92bb3df13`

Unlike the other `sp1-*` projects under `beak/projects`, this one is **not**
plugged into the generic RV32 benchmark loop. The old recursion VM is not an
RV32 instruction machine, so the current `RISCVOracle`-based harness is not a
sound fit.

What this project does provide:

- scenario builders for the three Kalos recursion findings
- baseline vs injected execution
- proof generation and verification on the patched historical snapshot

Central `docs/OBLIGATIONS.md` RV32 buckets are not emitted for this target.
This snapshot executes SP1 recursion-core programs, not RV32IM instruction
words, and it has no `trace.rs`/`BucketHit`/`BenchmarkBackend` semantic
candidate path. The legacy hooks below are real regression smokes, but they are
not central `sem.*` obligation mappings and should not be marked
`semantic_injection_mapped`.

The injected runs use the legacy recursion injection kinds added by
`sp1-fuzzer install`:

- `sp1.legacy_recursion.memory.load_binding`
- `sp1.legacy_recursion.exec.jump_binding`
- `sp1.legacy_recursion.exec.bneinc_upper_limbs`

Current default mutations are:

- `load`: mutate the loaded block before it is written back to `a`
- `jump`: mutate the `JAL` return value written to `a`
- `bneinc`: mutate the upper limbs after the low-limb increment

The CLI auto-selects the right injection step for each scenario. You can still
override it with `--inject-step` when needed.

## Usage

Install the historical snapshot first:

```bash
cd beak/beak-py
. .venv/bin/activate
sp1-fuzzer install --commit-or-branch fb38df2c4e963ef1d3a6f3be0ff62ea92bb3df13 --out-root out
```

Then run a scenario:

```bash
cd beak/projects/sp1-fb38df2c4e963ef1d3a6f3be0ff62ea92bb3df13
cargo run --bin beak-trace -- --scenario load
cargo run --bin beak-trace -- --scenario jump
cargo run --bin beak-trace -- --scenario bneinc
```

Use `--json` if you want the baseline/injected comparison in machine-readable
form.
