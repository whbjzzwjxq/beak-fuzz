# nexus-fuzzer (Beak Loop1)

This package integrates Nexus zkVM into Beak's Loop 1 instruction-sequence fuzzing flow:
generate RV32IM asm, compute expected register results via the Oracle, prove/execute in Nexus,
and diff the outputs.

Entry point:
- `nexus-fuzzer`

