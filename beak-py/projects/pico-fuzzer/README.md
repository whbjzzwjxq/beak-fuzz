# pico-fuzzer (Beak Loop1)

This package integrates Pico zkVM into Beak's Loop 1 instruction-sequence fuzzing flow:
generate RV32IM asm, compute expected register results via the Oracle, prove/execute in Pico,
and diff the public outputs.

Entry point:
- `pico-fuzzer`

## multiplicity_bool_domain / is_real fault injection (Pico-IsReal-01)

This repo includes an internal fault-injection hook for exercising the `multiplicity_bool_domain` bucket
against Pico's `MemoryLocalChip.is_real`.
