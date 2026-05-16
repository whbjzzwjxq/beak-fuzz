# Risc0 6f038bd Beak Target

Target snapshot: `6f038bd11ed725d7025687d163977d93ac1f82f9`.

This is the release-2.0 parent immediately before backport
`7f1e79677b9e12e874d7d2c084389c7664e93716` of RISC Zero PR #3015. It is a
pre-ControlDone-fix snapshot: `Executor::segment_cycles()` still counts
`user_cycles + pager.cycles + LOOKUP_TABLE_CYCLES` and
`platform.rs` has no `CONTROL_DONE_CYCLES` or `RESERVED_CYCLES`.

The local install under `beak-py/out/risc0-6f038bd.../risc0-src` has the
standard Beak RISC0 instrumentation copied in. The generated
`prove/beak.rs` helper is adjusted only for compatibility with the pre-fix
source by using `LOOKUP_TABLE_CYCLES` for Beak padding metadata; the vulnerable
executor and preflight accounting are unchanged.

## ControlDone Boundary Repro

The strict non-injected prover exception is reproducible with a generic counted
loop that lands the final segment at the missing-ControlDone boundary:

```sh
cargo run --release -q --bin beak-fuzz -- \
  --bin "00000713 000037b7 46578793 00000013 00170713 fef74ee3" \
  --oracle-precheck-max-steps 40000 \
  --semantic-window-before 0 \
  --semantic-window-after 0 \
  --semantic-step-stride 1 \
  --semantic-max-trials-per-bucket 0
```

The seed is:

```text
addi a4, x0, 0
lui  a5, 0x3
addi a5, a5, 0x465
addi x0, x0, 0
loop:
addi a4, a4, 1
blt  a4, a5, loop
```

The ordinary `beak-fuzz` run records a baseline bug with
`semantic_injection_applied=false`, `underconstrained_candidate=false`, and
`backend_error="risc0 prove panicked during semantic injection"`. The captured
RISC0 panic is from `prove/witgen/mod.rs:90`:
`cycles <= 1 << segment.po2`.

Earlier checks with the prior minimized loop
`00000713 000017b7 4e778793 00170713 fef74ee3` and with the release example
limit `12413` both proved cleanly on this snapshot; the extra pre-loop no-op
above is what aligns this adapter's loop shape to the 32,768-row boundary.
