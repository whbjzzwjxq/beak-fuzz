# OpenVM 336f1a47 Benchmark Repro

Target commit:

- `336f1a475e5aa3513c4c5a266399f4128c119bba`

## 1) Install patched OpenVM snapshot

From repo root (`beak/`):

```bash
UV_CACHE_DIR=/tmp/uv-cache make openvm-install COMMIT=336f1a475e5aa3513c4c5a266399f4128c119bba
```

## 2) Build

```bash
cd path/to/beak/projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba
cargo build --release --bin beak-trace --bin beak-fuzz
```

## 3) Benchmark run

Run the initial-corpus benchmark with semantic witness search. The default search
window is intentionally broader than the old fixed injection so detections come
from bounded witness search rather than a single hard-coded step.

```bash
cd path/to/beak/projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 500 \
  --timeout-ms 3000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64 \
  --oracle-precheck-max-steps 400
```

## 4) Current semantic coverage

This commit has 8 relevant `o..` targets:

- `o19, o1, o2, o3, o5, o7, o8, o15`

Current semantic bucket -> injected bug family mapping supports:

- `o1` via `sem.lookup.xor_multiplicity_consistency -> openvm.audit_o1.bitwise_mult_p_plus_1`
- `o5` via `sem.alu.immediate_limb_consistency -> openvm.audit_o5.rs2_imm_limbs`
- `o7` via `sem.control.auipc_pc_limb_consistency -> openvm.audit_o7.auipc_pc_limbs`
- `o8` via `sem.memory.immediate_sign_consistency -> openvm.audit_o8.loadstore_imm_sign`
- `o15` via `sem.arithmetic.special_case_consistency -> openvm.audit_o15.divrem_special_case_on_invalid`

So the answer to "all 336 `o..` targets?" is: **not yet**.

## 5) Targeted inline-seed examples

All commands run from `projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba`.
Each example feeds one initial seed and lets the benchmark search within the
configured witness window.

### o5 (ALU immediate limbs)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bin "10000093" \
  --timeout-ms 3000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

### o7 (AUIPC pc limbs)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bin "0badc297 00000293" \
  --timeout-ms 3000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

### o8 (Load/store immediate sign)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" \
  --timeout-ms 3000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

### o15 (Div/rem invalid-row special case)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bin "00700313 800005b7 fff00613 02c5c733 800003b7 00774533" \
  --timeout-ms 3000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

## 6) Inspect outputs

```bash
ls -lt path/to/beak/storage/fuzzing_seeds/benchmark-openvm-336f1a47-*-bugs.jsonl | head
```

For semantic search entries, check:

- `metadata.phase = "semantic_search"`
- `metadata.semantic_class` is populated
- `metadata.kind` is one of `underconstrained_candidate`, `mismatch`, `exception`
