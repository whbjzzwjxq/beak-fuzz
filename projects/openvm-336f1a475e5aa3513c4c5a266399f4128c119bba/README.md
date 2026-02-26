# OpenVM 336f1a47 Repro (Bucket + Witness Injection)

Target commit:

- `336f1a475e5aa3513c4c5a266399f4128c119bba`

## 1) Install patched OpenVM snapshot

From repo root (`beak/`):

```bash
UV_CACHE_DIR=/tmp/uv-cache make openvm-install COMMIT=336f1a475e5aa3513c4c5a266399f4128c119bba
```

## 2) Build

```bash
cd projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba
cargo build --release --bin beak-trace --bin beak-fuzz
```

## 3) Coverage status for commit 336f

This commit has 8 relevant `o..` targets:

- `o19, o1, o2, o3, o5, o7, o8, o15`

Current bucket->injection pipeline supports and was validated for:

- `o5` via `openvm.loop2.target.base_alu_imm_limbs -> openvm.audit_o5.rs2_imm_limbs`
- `o7` via `openvm.auipc.seen -> openvm.audit_o7.auipc_pc_limbs`
- `o8` via `openvm.mem.access_seen -> openvm.audit_o8.loadstore_imm_sign`
- `o15` via `openvm.divrem.* -> openvm.audit_o15.divrem_special_case_on_invalid`

So the answer to "all 336 `o..` targets?" is: **not yet**.

## 4) Repro commands (direct bucket->injection)

All commands run from `projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba`.

### o5 (RangeCheck, ALU immediate limbs)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bucket-direct-mutate \
  --bin "00100093" \
  --timeout-ms 3000
```

Expected log contains:

- `[beak-witness-inject] kind=openvm.audit_o5.rs2_imm_limbs ...`

### o7 (RangeCheck, AUIPC pc limbs)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bucket-direct-mutate \
  --bin "00000097" \
  --timeout-ms 3000
```

Expected log contains:

- `[beak-witness-inject] kind=openvm.audit_o7.auipc_pc_limbs ...`

### o8 (SignBit, Load/Store imm_sign)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bucket-direct-mutate \
  --bin "00002083" \
  --timeout-ms 3000
```

Expected log contains:

- `[beak-witness-inject] kind=openvm.audit_o8.loadstore_imm_sign ...`

### o15 (DivRem special-case invalid row)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bucket-direct-mutate \
  --bin "020140b3" \
  --timeout-ms 3000
```

Expected log contains:

- `[beak-witness-inject] kind=openvm.audit_o15.divrem_special_case_on_invalid ...`

## 5) Inspect outputs

```bash
ls -lt ../../storage/fuzzing_seeds/loop2-direct-openvm-336f1a47-*-bugs.jsonl | head
```

For injected phase entries, check:

- `metadata.injected_phase = true`
- `metadata.has_direct_injection_target = true`
- `metadata.kind` is one of:
  - `underconstrained_candidate`
  - `mismatch` (can still have `underconstrained_candidate=true`)
