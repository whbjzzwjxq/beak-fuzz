# SP1 98a376e Audit Repro

This snapshot targets the last known vulnerable commit for the SP1 v4 audit finding
`[High] is_memory underconstrained`.

Relevant commits:

- vulnerable: `98a376e87ec9dd5c3ae3495b98846bf921d6035b`
- fix: `185d266233e09a15bc3d5d077d36b714d5d55084`

This project depends on the locally installed SP1 checkout under:

- `beak-py/out/sp1-98a376e87ec9dd5c3ae3495b98846bf921d6035b/sp1-src`

## Install

```bash
cd path/to/beak
make sp1-install SP1_COMMIT=98a376e87ec9dd5c3ae3495b98846bf921d6035b
```

## Build

```bash
cd path/to/beak
make sp1-build SP1_COMMIT=98a376e87ec9dd5c3ae3495b98846bf921d6035b
```

## Trace

```bash
cd path/to/beak/projects/sp1-98a376e87ec9dd5c3ae3495b98846bf921d6035b
cargo run --release --bin beak-trace -- --bin "00012183" --print-buckets
```

Injected replay example:

```bash
cargo run --release --bin beak-trace -- --bin "00012183" \
  --inject-kind sp1.semantic.exec.memory_effect_binding \
  --inject-step 0 \
  --print-buckets
```

## Benchmark

```bash
cd path/to/beak
make sp1-fuzz SP1_COMMIT=98a376e87ec9dd5c3ae3495b98846bf921d6035b
```

The semantic injection kind for the real audit issue is:

- `sp1.semantic.exec.memory_effect_binding`

Additional installed SP1 hooks currently mapped by the target backend:

- CPU-row decode/register hooks from `pass4_v4_is_memory.py`:
  `sp1.semantic.decode.zero_register_immutability`,
  `sp1.semantic.decode.operand_index_routing`,
  `sp1.semantic.exec.dest_binding`,
  `sp1.semantic.decode.field_range`,
  `sp1.semantic.decode.immediate_sign_extension`,
  `sp1.semantic.exec.op_selector_binding`, and
  `sp1.semantic.decode.format_immediate_reassembly`
- ALU/mul/div chip hooks from `pass4_v4_is_memory.py`:
  `sp1.semantic.alu.immediate_limb_consistency`,
  `sp1.semantic.alu.shift_mod32`,
  `sp1.semantic.alu.comparison_booleanity`,
  `sp1.semantic.alu.subtraction_borrow_chain`,
  `sp1.semantic.alu.comparison_auxiliary_chain`,
  `sp1.semantic.arithmetic.division_remainder_bound`,
  `sp1.semantic.arithmetic.product_decomposition`, and
  `sp1.semantic.arithmetic.signed_unsigned_product_correction`
- `sp1.semantic.exec.control_flow_binding`

The old timestamped-load and lookup-boolean install hooks in
`pass3_collection.py` target an older runtime-module layout and are not present
in this installed v4 executor. They are intentionally not advertised as central
semantic injection candidates for this snapshot.

Useful smoke commands:

```bash
./target/debug/beak-trace --bin "00012183" --print-buckets
./target/debug/beak-trace --bin "00012183" --inject-kind sp1.semantic.exec.memory_effect_binding --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "00010033" --inject-kind "sp1.semantic.decode.zero_register_immutability::site=op_a_access" --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "00100093 00108463 00200113" --inject-kind sp1.semantic.alu.immediate_limb_consistency --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "020141b3" --inject-kind sp1.semantic.arithmetic.division_remainder_bound --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "00100093 00108463 00200113" --inject-kind sp1.semantic.exec.control_flow_binding --inject-step 18446744073709551615 --print-buckets
```
