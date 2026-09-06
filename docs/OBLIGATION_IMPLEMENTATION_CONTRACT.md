# Obligation Implementation Contract

This document defines the shared contract for implementing
`docs/OBLIGATIONS.md` across `projects/<vm>-<commit>/` snapshots.

`docs/OBLIGATIONS.md` is the high-level coverage taxonomy. Backend projects
must map that taxonomy into trace-derived `BucketHit`s and, where supported,
semantic or direct witness injection.

## Scope

The contract has three layers:

1. **Obligation coverage**: a backend can observe a condition from
   `OBLIGATIONS.md` and emit a stable semantic bucket.
2. **Semantic injection**: a backend can map a bucket hit to an injection plan
   and replay the same input with a witness/prover mutation.
3. **Install instrumentation**: a backend can patch the upstream zkVM snapshot
   to expose trace signals or injection hooks that are not available by default.

Do not implement backend-specific bucket names or ad hoc metadata when a shared
semantic bucket and details schema can express the case.

## Naming

Use these names consistently across Rust projects, Python install passes, JSONL
metadata, and docs.

| Entity | Format | Example |
|---|---|---|
| Obligation id | Lowercase group prefix plus number/name from `OBLIGATIONS.md` | `rf1`, `mem6`, `bu1` |
| Cell id | `<obligation_id>.<cell>` | `rf1.alu_r`, `mem6.wraparound` |
| Semantic bucket id | `sem.<category>.<semantic_name>` | `sem.decode.zero_register_immutability` |
| Semantic class | `semantic.<category>.<semantic_name>` | `semantic.decode.zero_register_immutability` |
| Inject kind | `<vm>.semantic.<category>.<semantic_name>[::variant]` | `openvm.semantic.memory.timestamped_load_path::mode=skip_read` |
| Trace signal id | `signal.<scope>.<name>` | `signal.input.has_load` |

Semantic bucket ids must be registered in
`crates/beak-core/src/trace/semantic.rs`. Backend code must not emit an
unregistered `sem.*` id.

Cell ids are finer than current semantic buckets. Prefer putting the precise
cell in `BucketHit.details["cell_id"]` instead of creating hundreds of
near-duplicate buckets. Add a new semantic bucket only when the obligation has a
meaningfully different invariant or injection target.

## BucketHit Details Schema

Every obligation-derived `BucketHit` should include the following keys when the
backend can observe them:

| Key | Required | Meaning |
|---|---|---|
| `obligation_id` | Yes | High-level obligation id, such as `rf1` |
| `cell_id` | Yes | Partition cell id, such as `rf1.alu_r` |
| `op_idx` | Yes for instruction-local hits | Instruction or micro-op index in the trace |
| `step_idx` | Yes for non-instruction-local hits | Backend step, row, shard, segment, or table index |
| `pc` | Yes if instruction-local | Program counter as an integer |
| `opcode` | Yes if available | Raw instruction word or backend opcode |
| `mnemonic` | Yes if decoded | Canonical RV32IM mnemonic |
| `backend` | Yes | VM family, such as `openvm`, `sp1`, `pico`, `risc0` |
| `commit` | Yes | Full snapshot commit when available |
| `trace_source` | Yes | Where the hit came from, such as `instruction`, `memory`, `bus`, `padding` |

Additional backend-specific fields are allowed, but they must not be required
for cross-backend matching. Bucket signatures use only `bucket_id`; details are
for reporting, scheduling, and debugging.

For injection scheduling, include at least one stable anchor:

- Instruction-local buckets: `op_idx`
- VM row/table buckets: `step_idx`
- Segment/shard buckets: `segment_idx` or `shard_idx`
- Padding/table lifecycle buckets: `table_name` plus `step_idx`

Instruction-local obligation hits must be derived from instructions that
actually appear in the backend execution trace. If the backend needs the
original RV32 word to classify a hit, map trace `pc`/`step_idx` back to the
input word and skip unexecuted words. Do not emit obligation `BucketHit`s for
input words that were not executed; use `TraceSignal` for input-only features.
When a hit is anchored to an executed instruction but also references a backend
row, keep `op_idx` as the instruction step and put the backend row-local index
in `row_op_idx`.

## Shared Core Touch Points

Shared behavior belongs in `crates/beak-core/`.

| File | Ownership |
|---|---|
| `src/trace/semantic.rs` | Registry of semantic bucket ids and semantic classes |
| `src/trace/semantic_matchers.rs` | Backend-independent matchers over shared observation structs |
| `src/trace/observations.rs` | Shared observation structs used by matchers |
| `src/trace/mod.rs` | `BucketHit`, `TraceSignal`, and trace canonicalization contract |
| `src/fuzz/benchmark.rs` | Semantic search candidate/replay loop and run/bug metadata recording |

One-off backend logic should stay under `projects/<vm>-<commit>/`.
General logic used by at least two VM families should move into
`beak-core`.

## Backend Project Touch Points

Each `projects/<vm>-<commit>/` implementation should keep backend-specific
logic in a small number of files.

| File | Responsibility |
|---|---|
| `src/lib/trace.rs` | Convert backend trace data into observations and `BucketHit`s |
| `src/lib/backend.rs` | Run the backend, collect eval metadata, and map buckets to injection candidates |
| `src/bin/beak-trace.rs` or equivalent | Smoke/debug entrypoint for a single input and optional injection |
| `README.md` | Snapshot-specific supported buckets and smoke commands |

`trace.rs` should prefer shared matchers from `beak-core` when the backend can
produce the required observations. `backend.rs` owns only the VM-specific
mapping from semantic bucket to injection kind and schedule.

## Semantic Injection Contract

Backends that support semantic injection must implement the relevant methods in
their `BenchmarkBackend` implementation:

- `clear_semantic_injection`
- `arm_semantic_injection`
- `semantic_injection_candidates`

The candidate must be derived from an existing `BucketHit`; do not try
injection for an obligation that was not observed in the baseline run.

Candidate construction rules:

1. Read `bucket_id` and stable anchors from `BucketHit.details`.
2. Select an inject kind using the naming rules above.
3. Select one schedule:
   - `Exact(step)` when the backend exposes exact injection sites.
   - `AroundAnchor(step)` when nearby rows may contain the relevant witness.
   - `Explicit(steps)` when the install patch has observed exact candidate sites.
   - `Sweep { start, end }` only for small bounded ranges.
4. Set `semantic_class` from the registered `SemanticBucket`.
5. Preserve `bucket_id` and optional `trigger_signal_id` for JSONL metadata.

The injected run must report whether the mutation was applied:

- `BackendEval.semantic_injection_applied`
- JSONL metadata key `semantic_injection_applied`
- `inject_kind`
- `inject_step`
- `trigger_bucket_id`

If the backend cannot determine whether the mutation happened, mark the
obligation as `bucket_emitted` or `semantic_injection_mapped`, not `verified`.

`semantic_injection_mapped` is a concrete VM integration status, not just a
bucket naming status. A bucket may use this status only when all of these exist:

- `projects/<vm>-<commit>/src/lib/backend.rs` maps the observed `BucketHit` to
  one or more `SemanticInjectionCandidate`s.
- The matching Python install pass patches the VM source with a real mutation
  or witness-corruption hook for the same `inject_kind`.
- The patched VM code reaches that hook through the normal installed-source
  execution path and calls `fuzzer_utils::should_inject_witness(...)` or an
  equivalent helper.
- The run records applied-site metadata, or the backend has another reliable
  signal for whether the mutation was actually applied.

If only the bucket is emitted, keep the status as `bucket_emitted`. If the VM
source patch exists but no bucket-to-candidate mapping exists yet, use
`install_patch_available`.

Bucket coverage and injection coverage are separate deliverables. A batch that
implements obligation coverage may stop at `bucket_emitted` only when the task
is explicitly scoped to observability, or when the matrix notes explain why a
real injection hook is not yet feasible. A batch that is asked to implement
obligations end-to-end must continue past bucket emission and do one of:

- implement a real VM mutation hook plus backend candidate mapping and mark
  `semantic_injection_mapped`;
- mark `install_patch_available` when the VM hook exists but the backend
  mapping or smoke coverage is incomplete;
- mark `trace_missing` when the required VM witness/prover fields are not
  currently observable; or
- leave `bucket_emitted` only with a note that names the missing concrete
  mutation point.

Do not treat `bucket_emitted` as equivalent to an implemented injection path.

## Install Instrumentation Contract

When a VM snapshot lacks trace fields or injection hooks, add the minimum
required instrumentation in the VM-specific Python pass under `beak-py/`.

| VM family | Expected location |
|---|---|
| OpenVM | `beak-py/projects/openvm-fuzzer/openvm_fuzzer/passes/` |
| SP1 | `beak-py/projects/sp1-fuzzer/sp1_fuzzer/passes/` |
| Pico | `beak-py/projects/pico-fuzzer/pico_fuzzer/passes/` |
| Jolt | `beak-py/projects/jolt-fuzzer/jolt_fuzzer/passes/` |
| Nexus | `beak-py/projects/nexus-fuzzer/nexus_fuzzer/passes/` |
| Risc0 | `beak-py/projects/risc0-fuzzer/risc0_fuzzer/passes/` |

Install patches must follow these rules:

1. Be commit-aware when anchors differ across snapshots.
2. Use stable `BEAK-INSERT` guards so repeated installs are idempotent.
3. Emit trace data through existing fuzzer utility surfaces when available.
4. Keep witness mutation hooks named by the shared inject kind.
5. Record observed and applied injection sites when possible.
6. Avoid unrelated SDK rewrites or behavior changes.

An install patch that implements semantic injection must document the concrete
mapping it adds:

- `inject_kind`
- Python pass function that applies the patch
- VM source file and function/method being patched
- observed-site anchor, when scheduling can be narrowed before injection
- applied-site signal used to set `semantic_injection_applied`
- variant names, if the backend may arm `inject_kind::variant`

If a required hook is broadly useful across VM families, add the shared helper
in `beak-py/libs/zkvm-fuzzer-utils/` or `crates/beak-core/` instead of copying
logic into every VM pass.

## Instrumentation Data Flow

Instrumentation must be integrated through the install pipeline, not by
manually editing generated files under `beak-py/out/`.

The expected path is:

```text
beak-py/projects/<vm>-fuzzer/.../passes/
  -> patch installed VM source under beak-py/out/<vm>-<commit>/<vm>-src/
  -> VM runtime emits trace and injection metadata through fuzzer_utils
  -> projects/<vm>-<commit>/src/lib/trace.rs parses emitted JSON logs
  -> trace.rs emits registered sem.* BucketHit values
  -> projects/<vm>-<commit>/src/lib/backend.rs maps BucketHit to injection candidates
  -> beak-core benchmark records run metadata and bug candidates
```

Use this flow for both observability-only hooks and witness/prover mutation
hooks.

### Python Install Pass

The Python pass owns source patching for a VM family. It should:

- Locate commit-specific source files under the installed snapshot.
- Apply only the minimum source edits needed for trace collection or injection.
- Use stable `BEAK-INSERT` guards so repeated installs are idempotent.
- Prefer existing shared `fuzzer_utils::emit_*` and injection helper APIs.
- Add shared helpers in `beak-py/libs/zkvm-fuzzer-utils/` only when multiple
  VM families or multiple passes need the same behavior.

Do not directly edit files under `beak-py/out/...` as the implementation
artifact. Those files are install outputs; the durable implementation belongs
in the Python pass.

### VM Runtime Emission

Patched VM source should emit one of:

- Instruction/micro-op records.
- Chip/table row records.
- Bus/interaction records.
- Padding/table lifecycle records.
- Observed witness injection sites.
- Applied witness injection sites.

For injection hooks, the VM runtime must use the same inject kind naming as the
Rust backend:

```text
<vm>.semantic.<category>.<semantic_name>[::variant]
```

When possible, record both observed sites and applied sites. Observed sites are
used for scheduling; applied sites are used to decide whether a run can be
reported as injected.

For memory/timestamp obligations, prefer a standard `memory_access` emitted
record when adding new instrumentation. Use these field names when available:

| Field | Meaning |
|---|---|
| `step_idx` | Executed instruction step |
| `row_op_idx` | Backend row-local index within the step |
| `pc` | Executed instruction PC |
| `opcode` | Backend opcode or RV32 word if available |
| `mnemonic` | RV32 mnemonic if available |
| `address_space` | Backend memory/address-space id |
| `raw_ptr` | Base plus immediate before alignment/masking |
| `effective_ptr` | Effective pointer/address used by the VM memory operation |
| `aligned_ptr` | Word-aligned address when applicable |
| `byte_offset` | `effective_ptr mod word_size` or backend equivalent |
| `width` | Access width in bytes |
| `is_load` | Load direction flag |
| `is_store` | Store direction flag |
| `needs_write` | Whether the operation writes a destination/register/memory cell |
| `timestamp` | Current memory timestamp, if available |
| `prev_timestamp` | Previous timestamp for same memory cell, if available |
| `read_data` | Loaded/read payload |
| `prev_data` | Previous word/cell payload before a write |
| `write_data` | Payload after a write |
| `rs1_ptr` | Source base register pointer/index when available |
| `rd_rs2_ptr` | Destination or store-value register pointer/index when available |

If a VM cannot provide one of these fields, omit it rather than inventing a
synthetic value. In particular, do not use placeholder addresses or timestamps
for memory obligations that rely on address/timestamp correctness.

### Rust Trace Parsing

`projects/<vm>-<commit>/src/lib/trace.rs` owns parsing emitted logs into
backend-local trace structs and then into `BucketHit`s.

Rules:

- Emit only registered `sem.*` ids from `crates/beak-core/src/trace/semantic.rs`.
- Put fine-grained obligation cells in `BucketHit.details["cell_id"]`.
- Include the common details schema when fields are available.
- Derive instruction-local hits from executed instructions, not unexecuted input
  words.
- Use shared matchers from `crates/beak-core/src/trace/semantic_matchers.rs`
  when the required observations are backend-independent.

### Backend Injection Mapping

`projects/<vm>-<commit>/src/lib/backend.rs` owns mapping observed buckets to
backend-specific injection plans.

The backend should:

- Implement `semantic_injection_candidates` for semantic search.
- Implement direct injection methods only for high-confidence mappings.
- Read scheduling anchors from `BucketHit.details`.
- Use observed injection site metadata when available.
- Report `semantic_injection_applied` only when the applied-site metadata or
  equivalent backend signal confirms the mutation happened.

If a bucket has no real injection hook, leave it at `bucket_emitted` rather
than inventing an inject kind.

The backend mapping and install patch are intentionally VM-specific. Shared
bucket ids describe what semantic condition was observed; they do not imply that
every VM can corrupt the same witness field or use the same source anchor.
Workers should adapt the hook to the VM's actual prover/witness code, then keep
the public `inject_kind` stable so benchmark metadata and matrix tracking remain
comparable across snapshots.

### Benchmark Metadata

The benchmark and loop code should receive enough metadata to explain each run:

- `trigger_bucket_id`
- `trigger_signal_id`, when applicable
- `inject_kind`
- `inject_step`
- `semantic_injection_applied`
- `baseline_bucket_hits_sig`

This metadata is what lets the serial install/injection campaign connect an
obligation cell, a bucket hit, an injection attempt, and a bug candidate.

## Implementation Status

Track per-VM progress in `docs/OBLIGATION_IMPLEMENTATION_MATRIX.md`.

Use these status values:

| Status | Meaning |
|---|---|
| `not_started` | No implementation work has been done |
| `trace_missing` | The VM cannot currently observe the required trace fields |
| `trace_observable` | Trace fields exist, but no bucket is emitted yet |
| `bucket_emitted` | Baseline runs emit the registered bucket |
| `semantic_injection_mapped` | Bucket hits produce candidates and the installed VM has a matching real injection hook |
| `install_patch_available` | Install pass exposes required trace/injection hooks, but the project mapping or smoke coverage is not complete |
| `verified` | Smoke test proves baseline bucket and injection metadata work |
| `unsupported` | The obligation does not apply to this VM or snapshot |

Do not mark `verified` without recording the smoke command and result in the
matrix or the snapshot README.

## Pilot Workflow

Before parallelizing across VM commits, run one vertical slice on a single
snapshot. Do not assign all 54 obligations to a single worker as an unbounded
implementation task; first require a small batch that produces reviewable code,
test output, and matrix updates.

1. Select 5-10 representative obligations from different groups.
2. Implement bucket emission with the details schema above.
3. Add injection candidate mapping only for buckets with a real mutation hook.
4. Add or adjust the install pass only when required.
5. Run a minimal baseline and injected smoke.
6. Update the implementation matrix.
7. Review naming, details schema, and patch fragility before cloning the pattern
   to other snapshots.

After the pilot is accepted, assign one Codex process per `projects/<vm>-<commit>`
directory. Each process should own only that project, the matching `beak-py`
VM pass, and that VM's matrix column.

## Batch Workflow

For full 54-obligation coverage, use batches after the pilot:

1. Create a read-only 54-obligation mapping for the target VM:
   - bucket id
   - required trace fields
   - install hook requirement
   - injection feasibility
   - concrete VM mutation point, or why it is missing
   - expected status before implementation
2. Implement one batch at a time, grouped by trace source:
   - register/decode/ALU
   - memory/timestamp
   - control/ecall
   - bus/interaction/padding
3. Each batch must end with:
   - code diff
   - matrix updates for that batch
   - smoke command and result
   - injection status for each implemented bucket
   - contract deviations or missing trace fields
4. Only start the next batch after reviewing the previous batch.

This keeps the worker scope small enough to produce auditable changes and makes
contract problems visible before they are duplicated across VM commits.
