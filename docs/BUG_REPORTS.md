# OpenVM Follow-up TODOs

## OpenVM 336 - o3 (Invalid-Row Interaction) Assessment

Current conclusion: this case should be treated as **pending semantic validation**, not as an automatically confirmed bug from injection alone.

Reasoning:
- The injected behavior can create an interaction on a row where `is_valid = 0` (an "invalid" or padding-style row).
- However, this signal by itself is not sufficient to prove a concrete vulnerability.
- To classify it as a real bug, we need a dedicated checker that explicitly enforces and verifies an invariant such as:
  - **No memory/execution interaction is allowed when `is_valid = 0`.**

Implication:
- Without this dedicated detection logic, injection outcomes here are better interpreted as a **suspicious weak signal** rather than a finalized vulnerability report.

## OpenVM 336 - o2 (Timestamp Wraparound) Assessment

Current conclusion: this case is **not directly reproducible under the current local injection model**.

Issues encountered during evaluation:
- Timestamp values are tightly coupled across runtime memory state, adapter/runtime execution state, and boundary chips.
- Initial/boundary timestamp behavior is anchored by memory-side logic (not a single free witness field in one place).
- Per-step timestamp progression is constrained by execution/memory consistency (delta is effectively structured, not freely chosen at one row).
- As a result, single-point witness injection (e.g., only changing a start timestamp) usually breaks consistency before it can demonstrate the intended wraparound vulnerability signal.

Implication:
- In the current framework, o2 should be tracked as a **latent corner-case risk** rather than a reliably reproducible injected bug.
- A stronger, chain-consistent multi-location instrumentation strategy would be required for meaningful confirmation.

## OpenVM 336 - o19 (Opcode Offset / ISA Routing) Assessment

Current conclusion: this case is **not well-suited to witness-only injection-based confirmation**.

Issues encountered during evaluation:
- The failure mode is primarily an opcode-domain/routing correctness issue (chip/offset semantics), not a local arithmetic witness inconsistency.
- The bug sits at instruction decoding/dispatch semantics, where proving behavior is controlled by structural opcode mapping.
- Local witness mutation can produce noisy exceptions or mismatches, but those outcomes do not cleanly demonstrate the specific offset/routing root cause.

Implication:
- o19 is better validated through directed instruction-level differential tests and opcode-routing assertions, rather than Loop2-style witness mutation alone.

## OpenVM f038 - o25 (Volatile Boundary Address Range) Activation Note

Current conclusion: this case is **reproducible in Loop2 injection mode only when volatile memory path is active**.

Key prerequisite:
- If VM runs with continuations enabled, memory goes through persistent/merkle path, and `VolatileBoundaryChip` injection site is not executed.
- To trigger `openvm.audit_o25.volatile_addr_range`, run with volatile memory mode (for current harness this can be forced via `BEAK_OPENVM_FORCE_VOLATILE=1`).

Practical implication:
- Treat this as a workflow TODO/precondition item, not a standalone bug report.
- Future harness cleanup should expose this as an explicit CLI option instead of environment-variable-only control.
