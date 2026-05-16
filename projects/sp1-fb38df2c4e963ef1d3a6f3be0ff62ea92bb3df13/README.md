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

This snapshot executes SP1 recursion-core programs, not RV32IM instruction
words, so it is outside the generic RV32 benchmark loop. The runner must not be
counted as a beak-fuzz e2e discovery path; it does not emit central semantic
bucket hits or `underconstrained_candidate` results.

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

For phase2 scaffold work, the runner also accepts a typed recursion seed:

```bash
cargo run --bin beak-fuzz -- --seed-json path/to/seed.json --json
```

This mode executes the seed through the same legacy recursion proof path and
prints projected `sem.recursion.*` evidence derived from executed runtime rows.
Those projected hits are intentionally marked `central_semantic_registered=false`
and `strict_countable=false` until the shared REC obligation registry,
non-RV32 seed frontend, and `BenchmarkBackend` semantic candidate mapping land.
