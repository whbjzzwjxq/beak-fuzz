# SP1 3561f006 uint256-div Repro

Target commit:

- `3561f0065dfe7d9f85144dd54bc5e9b10e5f7df1`

This project targets the vulnerable side of `sp1#746` (`underconstrained uint256_div`).

Semantic coverage:

- `sem.arithmetic.division_remainder_bound`
  - generalized class: `semantic.arithmetic.division_remainder_bound`
  - injection family: `sp1.semantic.arithmetic.division_remainder_bound`

Install the patched snapshot first:

```bash
cd path/to/beak/beak-py
uv run sp1-fuzzer install --commit-or-branch 3561f0065dfe7d9f85144dd54bc5e9b10e5f7df1
```

Then run:

```bash
cd path/to/beak/projects/sp1-3561f0065dfe7d9f85144dd54bc5e9b10e5f7df1
cargo run --bin beak-trace -- --json
```
