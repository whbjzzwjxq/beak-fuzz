# SP1 811a3f2c Benchmark Repro

Target commit:

- `811a3f2c03914088c7c9e1774266934a3f9f5359`

## Build

```bash
cd path/to/beak/projects/sp1-811a3f2c03914088c7c9e1774266934a3f9f5359
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Benchmark run

```bash
cd path/to/beak/projects/sp1-811a3f2c03914088c7c9e1774266934a3f9f5359
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 1000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

## Output

Benchmark JSONL files are written to:

- `path/to/beak/storage/fuzzing_seeds/`

## Obligation Coverage

This snapshot emits central `sem.*` buckets from executed SP1
`ExecutionRecord.cpu_events`, with raw RV32 words resolved by executed PC.
Implemented bucket coverage includes RF/decode/ALU, partial mul/div
(`md3`-`md5`), memory shape (`me2`, `me3`, `me4`, `me9`, `me10`), timestamp
boundary buckets, control flow, ECALL word validity, and short-trace padding.

Mapped semantic injections are intentionally limited to installed hooks that
exist in this 811a3f2c source:

- `sp1.semantic.decode.zero_register_immutability`
- `sp1.semantic.decode.operand_index_routing`
- `sp1.semantic.exec.dest_binding`
- `sp1.semantic.decode.field_range`
- `sp1.semantic.decode.immediate_sign_extension`
- `sp1.semantic.exec.op_selector_binding`
- `sp1.semantic.decode.format_immediate_reassembly`
- `sp1.semantic.exec.memory_effect_binding`
- `sp1.semantic.exec.control_flow_binding`

Older SP1 timestamp/lookup runtime hooks are not present in this installed
snapshot, so the backend does not expose candidates for those buckets.

Representative smokes:

```bash
./target/debug/beak-trace --bin "00100013" --print-buckets
./target/debug/beak-trace --bin "00100013" \
  --inject-kind "sp1.semantic.decode.zero_register_immutability::site=op_a_access" \
  --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "00100093" \
  --inject-kind "sp1.semantic.decode.operand_index_routing::site=op_b_access" \
  --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "00100093" \
  --inject-kind "sp1.semantic.exec.dest_binding::site=op_a_access" \
  --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "00100093" \
  --inject-kind "sp1.semantic.decode.field_range::site=instruction_op_a" \
  --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "00100093" \
  --inject-kind "sp1.semantic.decode.immediate_sign_extension::site=instruction_op_c" \
  --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "00100093" \
  --inject-kind "sp1.semantic.exec.op_selector_binding::site=opcode" \
  --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "00100093 00108463 00200113" \
  --inject-kind "sp1.semantic.decode.format_immediate_reassembly::site=instruction_op_c" \
  --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "04000093 0000a183" --print-buckets
./target/debug/beak-trace --bin "04000093 0000a183" \
  --inject-kind sp1.semantic.exec.memory_effect_binding \
  --inject-step 18446744073709551615 --print-buckets
./target/debug/beak-trace --bin "00100093 00108463 00200113" \
  --inject-kind "sp1.semantic.exec.control_flow_binding::family=branch" \
  --inject-step 1 --print-buckets
```
