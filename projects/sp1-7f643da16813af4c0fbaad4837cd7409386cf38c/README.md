# SP1 7f643da1 Benchmark Repro

Target commit:

- `7f643da16813af4c0fbaad4837cd7409386cf38c`

## Build

```bash
cd path/to/beak/projects/sp1-7f643da16813af4c0fbaad4837cd7409386cf38c
cargo build --release --bin beak-trace --bin beak-fuzz
```

## Benchmark run

```bash
cd path/to/beak/projects/sp1-7f643da16813af4c0fbaad4837cd7409386cf38c
cargo run --release -q --bin beak-fuzz -- \
  --initial-limit 1000 \
  --semantic-window-before 16 \
  --semantic-window-after 64 \
  --semantic-max-trials-per-bucket 64
```

## Output

Benchmark JSONL files are written to:

- `path/to/beak/storage/fuzzing_seeds/`

## Ordinary ECALL Carrier Lane

Without `--bin`, `beak-fuzz` prepends three generated write-syscall ECALL
programs (fds 1, 3, 4) to the initial corpus. Executed ECALL hits are accepted
as evidence only through a typed `ExecutedControlFlowEquation` receipt matching
the executed word/opcode, PC, step, expected `PC + 4`, and changed next PC.

## Obligation Status

- Executed-instruction semantic buckets cover `rf1`-`rf3`, `id1`-`id5`,
  `al1`-`al5`, `md3`-`md5`, `cf1`-`cf4`, `cf6`, `cf7`, `ts1`, `ts3`,
  `me2`, `me3`, `me4`, `me9`, `me10`, and `pd1`.
- Verified injection hooks:
  `sp1.semantic.decode.zero_register_immutability`,
  `sp1.semantic.decode.operand_index_routing`,
  `sp1.semantic.exec.dest_binding`,
  `sp1.semantic.decode.field_range`,
  `sp1.semantic.decode.immediate_sign_extension`,
  `sp1.semantic.exec.op_selector_binding`,
  `sp1.semantic.decode.format_immediate_reassembly`,
  `sp1.semantic.exec.memory_effect_binding`,
  `sp1.semantic.memory.timestamped_load_path`, and
  `sp1.semantic.exec.control_flow_binding`.
- `sp1.semantic.lookup.boolean_multiplicity` has an install hook and backend
  mapping, but store/load smoke is blocked by the installed SP1 memory
  timestamp ordering assertion.
- `id3` upper-immediate and `al1` immediate-limb cells remain bucket-only in
  this snapshot: the simple LUI proof path panics before bucket output, and the
  ALU probe did not emit `sem.alu.immediate_limb_consistency`.
- Remaining gaps need SP1 prover/table rows for memory address/value
  provenance, initialization/finalization, syscall arguments, range/bus rows,
  segment boundaries, and padding lifecycle metadata.
