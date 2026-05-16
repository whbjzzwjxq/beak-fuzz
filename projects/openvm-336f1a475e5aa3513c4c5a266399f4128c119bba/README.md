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
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64 \
  --oracle-precheck-max-steps 400
```

## 4) Current semantic coverage

This commit has 8 relevant `o..` targets:

- `o19, o1, o2, o3, o5, o7, o8, o15`

Current semantic bucket -> injected bug family mapping supports:

- `bu1/o1` via canonical
  `sem.lookup.boolean_multiplicity -> openvm.semantic.lookup.boolean_multiplicity`
  for lookup multiplicity rows. The older
  `sem.lookup.xor_multiplicity_consistency` path is retained only as a legacy
  audit smoke because its witness mutation currently rejects with
  `ChallengePhaseError`, not an underconstrained proof.
- `o5` via `sem.alu.immediate_limb_consistency -> openvm.semantic.alu.immediate_limb_consistency`
- `o7` via `sem.control.auipc_pc_limb_consistency -> openvm.semantic.control.auipc_pc_limb_consistency`
- `o8` via `sem.memory.immediate_sign_consistency -> openvm.semantic.memory.immediate_sign_consistency`
- `o15` via `sem.arithmetic.special_case_consistency -> openvm.semantic.arithmetic.special_case_consistency`
- `rf1` via `sem.decode.zero_register_immutability -> openvm.semantic.decode.zero_register_immutability`
- `rf2` via `sem.decode.operand_index_routing -> openvm.semantic.decode.operand_index_routing`
- `id5` via `sem.decode.format_immediate_reassembly -> openvm.semantic.decode.format_immediate_reassembly`
- `al2` via `sem.alu.shift_mod32 -> openvm.semantic.alu.shift_mod32`
- `al3` via `sem.alu.comparison_booleanity -> openvm.semantic.alu.comparison_booleanity`
- `al4` via `sem.alu.subtraction_borrow_chain -> openvm.semantic.alu.subtraction_borrow_chain`
- `al5` via `sem.alu.comparison_auxiliary_chain -> openvm.semantic.alu.comparison_auxiliary_chain`
- `md3` via `sem.arithmetic.division_remainder_bound -> openvm.semantic.arithmetic.division_remainder_bound`
- `md4` via `sem.arithmetic.product_decomposition -> openvm.semantic.arithmetic.product_decomposition`
- `md5` via `sem.arithmetic.signed_unsigned_product_correction -> openvm.semantic.arithmetic.signed_unsigned_product_correction`
- `me1` via `sem.memory.store_load_payload_flow -> openvm.semantic.memory.store_load_payload_flow`
- `me2/me6/me9` via `sem.memory.*address* -> openvm.semantic.memory.address_pointer_consistency`
- `me3/me4` via `sem.memory.*payload* -> openvm.semantic.memory.value_payload_consistency`
- `me5` via `sem.memory.address_space_consistency -> openvm.semantic.memory.address_space_consistency`
- `me10` via `sem.memory.kind_selector_consistency -> openvm.semantic.memory.kind_selector_consistency`
- `ts1/ts3` via `sem.time.boundary_origin_consistency -> openvm.semantic.time.boundary_origin_consistency`
- `ts2.small_gap/large_gap/consecutive` via `sem.time.monotonic_access_ordering -> openvm.semantic.time.monotonic_access_ordering`
- `cf4` via `sem.control.entrypoint_binding -> openvm.semantic.control.entrypoint_binding`
- `cf1/cf2/cf3/cf6` via `sem.exec.control_flow_binding -> openvm.semantic.exec.control_flow_binding`
- `cf7` has `openvm.semantic.control.ecall_word_validity` program-table hook
  available, but is not verified because the raw RV ECALL bucket was not
  observed for `0x00000073`.

So the answer to "all 336 `o..` targets?" is: **not yet**.

Additional obligation bucket coverage without new injection hooks:

- Memory init/finalization/segment gaps: `me7.bss_zero` and
  `me7.data_loaded` are emitted from first-load/no-prior-write inference and
  explicit nonzero `memory_init` records; `me8.no_conflict` is also emitted
  from those init records. Initial-memory injection is intentionally not
  mapped because prover smoke found the attempted hooks underconstrained.
  `me11.written_cells/read_only_cells` now uses persistent finalization rows
  and verifies through `openvm.semantic.memory.finalization_consistency`.
  Remaining gaps are `me7.rodata`, `me7.stack_uninit`, `me8.double_init`,
  `me11.untouched_cells`, and `ts2.cross_segment`.
- Control flow: `cf7` now has a program-table TERMINATE opcode mutation hook,
  but raw RV ECALL bucket emission is still evidence-missing for the simple
  `0x00000073` seed because the transpiler emits `unimp` with no executed
  instruction bucket. `cf5` remains trace-missing because OpenVM-336 does not
  expose Linux-style ECALL syscall number plus a0-a7 dispatch values.

## 5) Targeted inline-seed examples

All commands run from `projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba`.
Each example feeds one initial seed and lets the benchmark search within the
configured witness window.

For verifier smoke, `beak-trace` also supports a single explicit semantic
injection replay via `--inject-kind` and `--inject-step`. Baseline commands
should emit the target `sem.*` bucket with `semantic_injection_applied = false`;
injected commands should report `semantic_injection_applied = true` and either a
verifier exception or `UNDERCONSTRAINED CANDIDATE DETECTED`.

### Verified decode/program-table semantic smoke

| obligation | baseline seed | inject kind / step | result |
|---|---|---|---|
| `rf1` | `00100013` | `openvm.semantic.decode.zero_register_immutability`, step `0` | Baseline emitted `sem.decode.zero_register_immutability`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: ChallengePhaseError`. |
| `rf2` | `00100013` | `openvm.semantic.decode.operand_index_routing`, step `0` | Baseline emitted `sem.decode.operand_index_routing`; injected replay printed the program-table mutation, reported `semantic_injection_applied = true`, and failed proof with `ChallengePhaseError`. |
| `id5` | `00100113 00200193 00208463 00300193` | `openvm.semantic.decode.format_immediate_reassembly`, step `2` | Baseline emitted `sem.decode.format_immediate_reassembly`; injected replay printed `pc=8`, reported `semantic_injection_applied = true`, and failed proof with `ChallengePhaseError`. |
| `cf7` | `00000073` | `openvm.semantic.control.ecall_word_validity`, step `0` | Hook smoke applied and failed proof with `ChallengePhaseError`, but baseline emitted 0 buckets because the RV system word transpiled to `unimp`; this remains `install_patch_available`, not `verified`. |

### Canonical BU1 and legacy o1 smoke

```bash
# canonical BU1 baseline: emits sem.lookup.boolean_multiplicity when lookup
# multiplicity rows are present
./target/release/beak-trace --bin "01400313 01400393 00734533" --print-buckets

# legacy o1 baseline: may also emit sem.lookup.xor_multiplicity_consistency
./target/release/beak-trace --bin "01400313 01400393 00734533" --print-buckets

# legacy o1 injected: semantic_injection_applied=true, but verifier rejects with
# ChallengePhaseError. This is legacy_rejected, not canonical BU1 verified.
./target/release/beak-trace --bin "01400313 01400393 00734533" \
  --inject-kind "openvm.semantic.lookup.xor_multiplicity_consistency::mode=p_plus_mask,rank=0,strength=0" \
  --inject-step 0 \
  --print-buckets

# o5 baseline: emits sem.alu.immediate_limb_consistency
./target/release/beak-trace --bin "00100093 02800113 002091b3" --print-buckets

# o5 injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "00100093 02800113 002091b3" \
  --inject-kind "openvm.semantic.alu.immediate_limb_consistency::mode=byte_bias,slot=0,strength=0" \
  --inject-step 2 \
  --print-buckets

# o7/o8 baseline: emits sem.control.auipc_pc_limb_consistency and sem.memory.immediate_sign_consistency
./target/release/beak-trace --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" --print-buckets

# o7 injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" \
  --inject-kind "openvm.semantic.control.auipc_pc_limb_consistency::mode=from_pc_high_single_mod_p,slot=1,strength=0,mult=1" \
  --inject-step 3 \
  --print-buckets

# o8 targeted baseline: emits sem.memory.immediate_sign_consistency
./target/release/beak-trace --bin "000010b7 ffc0a103" --print-buckets

# o8 injected: real sign flip with orig_ptr=4092, flipped_ptr=69628, flipped_sign=0;
# semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "000010b7 ffc0a103" \
  --inject-kind "openvm.semantic.memory.immediate_sign_consistency::mode=flip_sign,domain=load,guard=none" \
  --inject-step 1 \
  --print-buckets

# o15 baseline: emits sem.arithmetic.special_case_consistency
./target/release/beak-trace --bin "00700313 800005b7 fff00613 02c5c733 800003b7 00774533" --print-buckets

# o15 injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "00700313 800005b7 fff00613 02c5c733 800003b7 00774533" \
  --inject-kind "openvm.semantic.arithmetic.special_case_consistency::mode=shadow_invalid_one,search=wildcard" \
  --inject-step 7 \
  --print-buckets

# Memory/Time baseline: emits me1/me2/me3/me4/me5/me9/me10 and ts1/ts2.same-address/ts3 buckets
./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets

# me1 injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" \
  --inject-kind openvm.semantic.memory.store_load_payload_flow \
  --inject-step 17

# me2/me9 injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" \
  --inject-kind openvm.semantic.memory.address_pointer_consistency \
  --inject-step 4

# me3/me4 injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" \
  --inject-kind openvm.semantic.memory.value_payload_consistency \
  --inject-step 13

# me5 injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" \
  --inject-kind openvm.semantic.memory.address_space_consistency \
  --inject-step 3

# me10 injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" \
  --inject-kind openvm.semantic.memory.kind_selector_consistency \
  --inject-step 13

# ts1/ts3 injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" \
  --inject-kind openvm.semantic.time.boundary_origin_consistency \
  --inject-step 0

# ts2.same-address injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" \
  --inject-kind openvm.semantic.time.monotonic_access_ordering \
  --inject-step 7

# me6 baseline: emits sem.memory.address_boundary_range
./target/release/beak-trace --bin "200000b7 ff008093 0000a103" --print-buckets

# me6 injected: semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "200000b7 ff008093 0000a103" \
  --inject-kind openvm.semantic.memory.address_pointer_consistency \
  --inject-step 2

# Original memory immediate-sign smoke on the o7/o8 seed:
# semantic_injection_applied=true; UNDERCONSTRAINED CANDIDATE DETECTED
./target/release/beak-trace --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" \
  --inject-kind "openvm.semantic.memory.immediate_sign_consistency::mode=flip_sign,domain=load,guard=none" \
  --inject-step 5
```

### o5 (ALU immediate limbs)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bin "10000093" \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

### o7 (AUIPC pc limbs)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bin "0badc297 00000293" \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

### o8 (Load/store immediate sign)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

### o15 (Div/rem invalid-row special case)

```bash
cargo run --release -q --bin beak-fuzz -- \
  --bin "00700313 800005b7 fff00613 02c5c733 800003b7 00774533" \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

## 6) Targeted verifier smoke

For ALU/arithmetic mapped obligations, a direct verifier smoke can be run with
`beak-trace`. Each row below was run with a clean baseline and an injected replay
using `--inject-step 18446744073709551615` to apply the matching witness hook at
all observed sites for that kind.

| obligation | baseline seed | inject kind | result |
|---|---|---|---|
| `al1` | `10000093` | `openvm.semantic.alu.immediate_limb_consistency` | Baseline emitted `sem.alu.immediate_limb_consistency`; injected replay reported `semantic_injection_applied = true` and `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| `al2` | `000010b7 00002137 002091b3` | `openvm.semantic.alu.shift_mod32` | Baseline emitted `sem.alu.shift_mod32`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: OodEvaluationMismatch`. |
| `al3` | `800000b7 00001137 0020a1b3` | `openvm.semantic.alu.comparison_booleanity` | Baseline emitted `sem.alu.comparison_booleanity`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: OodEvaluationMismatch`. |
| `al4` | `000010b7 00002137 402081b3` | `openvm.semantic.alu.subtraction_borrow_chain` | Baseline emitted `sem.alu.subtraction_borrow_chain`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: OodEvaluationMismatch`. |
| `al5` | `800000b7 00001137 0020a1b3` | `openvm.semantic.alu.comparison_auxiliary_chain` | Baseline emitted `sem.alu.comparison_auxiliary_chain`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: OodEvaluationMismatch`. |
| `md1` | `000010b7 0200c1b3` | `openvm.semantic.arithmetic.special_case_consistency` | Baseline emitted `sem.arithmetic.special_case_consistency`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: ChallengePhaseError`. |
| `md2` | `800000b7 fff00113 0220c1b3` | `openvm.semantic.arithmetic.special_case_consistency` | Baseline emitted `sem.arithmetic.special_case_consistency`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: OodEvaluationMismatch`. |
| `md3` | `000100b7 00001137 0220c1b3` | `openvm.semantic.arithmetic.division_remainder_bound` | Baseline emitted `sem.arithmetic.division_remainder_bound`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: ChallengePhaseError`. |
| `md4` | `000010b7 00002137 022081b3` | `openvm.semantic.arithmetic.product_decomposition` | Baseline emitted `sem.arithmetic.product_decomposition`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: ChallengePhaseError`. |
| `md5` | `800000b7 00001137 0220a1b3` | `openvm.semantic.arithmetic.signed_unsigned_product_correction` | Baseline emitted `sem.arithmetic.signed_unsigned_product_correction`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: OodEvaluationMismatch`. |

For control-flow mapped obligations, the same direct smoke shape was run with
the exact observed witness step for each seed:

| obligation | baseline seed | inject kind / step | result |
|---|---|---|---|
| `cf1` | `800000b7 00100113 0020c463 00300193` | `openvm.semantic.exec.control_flow_binding`, step `6` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=branch_lt`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| `cf2` | `008000ef 00100113 00200193` | `openvm.semantic.exec.control_flow_binding`, step `3` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=jal`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| `cf3.clear_lsb` | `00d00093 00008067 00500113 00600193` | `openvm.semantic.exec.control_flow_binding`, step `4` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=jalr`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| `cf3.even` | `00c00093 00008067 00500113 00600193` | `openvm.semantic.exec.control_flow_binding`, step `4` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=jalr`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| `cf3.wrap` | `fff00093 00908067 00500113 00600193` | `openvm.semantic.exec.control_flow_binding`, step `5` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=jalr`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| `cf4` | `00100093` | `openvm.semantic.control.entrypoint_binding`, step `0` | Baseline emitted `sem.control.entrypoint_binding`; injected replay printed the boundary-PC witness mutation, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| `cf6` | `00100093 00200113 00208463 00300193` | `openvm.semantic.exec.control_flow_binding`, step `6` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=branch_eq`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| `o7` | `00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533` | `openvm.semantic.control.auipc_pc_limb_consistency::mode=from_pc_high_single_mod_p,slot=1,strength=0,mult=1`, step `3` | Baseline emitted `sem.control.auipc_pc_limb_consistency`; injected replay printed the AUIPC witness mutation, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |

Example command shape:

```bash
./target/release/beak-trace --bin "<seed>" --print-buckets
./target/release/beak-trace --bin "<seed>" \
  --inject-kind "<inject-kind>" \
  --inject-step 18446744073709551615 \
  --print-buckets
```

## 7) Inspect outputs

```bash
ls -lt path/to/beak/storage/fuzzing_seeds/benchmark-openvm-336f1a47-*-bugs.jsonl | head
```

For semantic search entries, check:

- `metadata.phase = "semantic_search"`
- `metadata.semantic_class` is populated
- `metadata.kind` is one of `underconstrained_candidate`, `mismatch`, `exception`
