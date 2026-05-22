# OpenVM bf11b4a5 Benchmark Repro

Target commit:

- `bf11b4a5f79d20fa14d01f78b41d54df4acd0ee0`

## Install

```bash
cd path/to/beak/beak-py
uv run openvm-fuzzer install --commit-or-branch bmk-bf11
```

The installer applies bf11-compatible versions of the d7/regzero trace and
witness hooks, including the renamed `v1.3.0` stark-backend field constructors
and `ProgramChip::row_slice` layout.

## Build

```bash
cd path/to/beak/projects/openvm-bf11b4a5f79d20fa14d01f78b41d54df4acd0ee0
cargo test -q --lib
cargo run -q --bin beak-trace -- --bin "00100093 02100113 002091b3" --print-buckets
```

## Semantic Instrumentation

This snapshot uses tracegen-only execution. Bucket emission is implemented for
decoded instruction, ALU/mul/div/control chip rows, memory access/lifecycle rows,
timestamp rows, and lookup multiplicities where bf11 emits the needed fields.

Mapped injection kinds with matching Python VM hooks include:

- `openvm.semantic.alu.shift_mod32`
- `openvm.semantic.alu.immediate_limb_consistency`
- `openvm.semantic.alu.comparison_booleanity`
- `openvm.semantic.alu.comparison_auxiliary_chain`
- `openvm.semantic.alu.subtraction_borrow_chain`
- `openvm.semantic.arithmetic.special_case_consistency`
- `openvm.semantic.arithmetic.division_remainder_bound`
- `openvm.semantic.arithmetic.product_decomposition`
- `openvm.semantic.arithmetic.signed_unsigned_product_correction`
- `openvm.semantic.control.auipc_pc_limb_consistency`
- `openvm.semantic.exec.control_flow_binding`
- `openvm.semantic.decode.zero_register_immutability`
- `openvm.semantic.memory.address_pointer_consistency`
- `openvm.semantic.memory.address_space_consistency`
- `openvm.semantic.memory.value_payload_consistency`
- `openvm.semantic.memory.store_load_payload_flow`
- `openvm.semantic.memory.kind_selector_consistency`
- `openvm.semantic.memory.finalization_consistency`
- `openvm.semantic.time.boundary_origin_consistency`

Unsupported/trace-missing cells remain those requiring fields not emitted by
the current OpenVM trace hooks, such as read-only rodata classification,
stack-uninitialized reads, cross-segment timestamp ordering, untouched memory
finalization cells, boolean lookup multiplicity rows, and detailed
public-value/host-IO tables.

Same-address timestamp monotonic buckets are currently bucket-only for bf11:
the clean install did not install/reach a matching
`openvm.semantic.time.monotonic_access_ordering` hook.

PD1 padding interaction buckets are also bucket-only for bf11. Focused smokes
emit `sem.row.padding_interaction_send`, but both exact step 0 and wildcard
step `u64::MAX` replays with `openvm.semantic.row.padding_interaction_send`
report `semantic_injection_applied = false`; the installed record-arena padding
hook is not reached by the normal tracegen-focused path. A valid mapping needs
a reachable padding row hook in the normal integration trace path, not the
record-arena sample/proxy path.

## Smoke

Baseline shift-mod32 seed:

```bash
FAST_TEST=1 cargo run -q --bin beak-trace -- \
  --bin "00100093 02100113 002091b3" --print-buckets
```

Result: matched oracle registers and emitted 30 hits, including
`sem.alu.shift_mod32`.

Injected replay:

```bash
FAST_TEST=1 cargo run -q --bin beak-trace -- \
  --bin "00100093 02100113 002091b3" \
  --inject-kind openvm.semantic.alu.shift_mod32 \
  --inject-step 18446744073709551615
```

Result: reached `[beak-witness-inject] kind=openvm.semantic.alu.shift_mod32
step=2`, reported `semantic_injection_applied = true`, and printed
`UNDERCONSTRAINED CANDIDATE DETECTED` in tracegen-only mode.

## Benchmark Run

```bash
cd path/to/beak/projects/openvm-bf11b4a5f79d20fa14d01f78b41d54df4acd0ee0
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 500 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```
