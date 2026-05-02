# Obligation Implementation Matrix

This matrix tracks how `docs/OBLIGATIONS.md` is implemented across VM
snapshots. See `docs/OBLIGATION_IMPLEMENTATION_CONTRACT.md` for the required
naming, details schema, injection hooks, and status values.

Status values:

`not_started`, `trace_missing`, `trace_observable`, `bucket_emitted`,
`semantic_injection_mapped`, `install_patch_available`, `verified`,
`unsupported`.

## Pilot Scope

Start with one VM commit and a representative vertical slice before filling the
full matrix. A good pilot should cover at least one obligation from each of:

- Register/decode
- ALU/arithmetic
- Memory/timestamp
- Control flow/ecall
- Bus/padding when the backend exposes prover-level rows

Do not use a single unbounded worker task for all 54 obligations. First produce
a 54-obligation mapping for one VM, then implement coverage in reviewable
batches grouped by trace source.

## Matrix Template

Use one row per obligation/cell when tracking fine-grained progress. If a
backend only supports the coarser semantic bucket, keep the cell-specific rows
but use the same bucket id and explain the limitation in `notes`.

| obligation_id | cell_id | semantic_bucket | required_trace_fields | openvm-336f1a47 | openvm-d7eab708 | openvm-f038f61d | pico-45e74ccd | sp1-39ab52fc | sp1-7f643da1 | sp1-811a3f2c | sp1-3561f006 | sp1-fb38df2c | jolt-e9caa235 | nexus-636ccb36 | risc0-98387806 | risc0-c0db0713 | injection_kind | smoke | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| rf1 | rf1.alu_r | sem.decode.zero_register_immutability | op_idx, pc, opcode, mnemonic, rd, write_source | verified | bucket_emitted | bucket_emitted | verified | not_started | verified | verified | verified | unsupported | bucket_emitted | bucket_emitted | verified | install_patch_available | `openvm.semantic.decode.zero_register_immutability` | Baseline: `cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.decode.zero_register_immutability --inject-step 0`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: ChallengePhaseError`. | OpenVM-336 emits decoded RF1 write-source cells when observed; 336 install pass mutates the program table operand `a` for targeted decoded instruction rows. OpenVM-f038 emits this bucket from executed instruction trace only; no f038 program-table mutation hook is mapped. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012003 --print-buckets` emitted the bucket and injected `sp1.semantic.decode.zero_register_immutability::site=op_a_access` reported `semantic_injection_applied = true` with proof rejection recorded in `agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| rf2 | rf2.rs1_eq_rs2 | sem.decode.operand_index_routing | op_idx, pc, opcode, mnemonic, rs1, rs2, rd | verified | bucket_emitted | bucket_emitted | verified | not_started | verified | verified | verified | unsupported | bucket_emitted | bucket_emitted | verified | verified | `openvm.semantic.decode.operand_index_routing` | Baseline: `cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.decode.operand_index_routing --inject-step 0`; injected replay printed the program-table mutation and reported `semantic_injection_applied = true` / `verify_app_proof failed: ChallengePhaseError`. | OpenVM-336 emits alias cells from decoded RV32IM operands; 336 install pass mutates the program table operand `b` for targeted decoded instruction rows. OpenVM-f038 emits this bucket from executed instruction trace only; no f038 program-table mutation hook is mapped. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012183 --print-buckets` emitted the bucket and injected `sp1.semantic.decode.operand_index_routing::site=op_b_access` reported `semantic_injection_applied = true` in `agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| rf3 | rf3.alu/rf3.load/rf3.link/rf3.upper/rf3.muldiv | sem.exec.dest_binding | op_idx, pc, opcode, mnemonic, rd, write_source | bucket_emitted | bucket_emitted | bucket_emitted | verified | not_started | verified | verified | verified | unsupported | bucket_emitted | bucket_emitted | install_patch_available | bucket_emitted |  | d7 baseline examples: `cargo run -q --bin beak-trace -- --bin "10000093" --print-buckets`; load/muldiv/link/upper cells need matching executed instructions. | d7 emits decoded writeback-source cells from executed instruction trace; no d7 mutation hook/applied-site replay plumbing is mapped. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012183 --print-buckets` emitted the bucket and injected `sp1.semantic.exec.dest_binding::site=op_a_access` reported `semantic_injection_applied = true` with proof rejection recorded in `agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| id1 | id1.reg_zero/id1.reg_max/id1.reg_mid/id1.funct_max | sem.decode.field_range | op_idx, pc, opcode, mnemonic, rd, rs1, rs2, funct3, funct7 | bucket_emitted | bucket_emitted | bucket_emitted | verified | not_started | verified | verified | verified | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted |  | d7 baseline examples: `cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets`. | d7 emits field-range cells from executed decoded RV32IM words; no d7 decode/program-table hook is mapped. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012183 --print-buckets` emitted the bucket and injected `sp1.semantic.decode.field_range::site=instruction_op_a` reported `semantic_injection_applied = true` in `agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| id2 | id2.i_pos/id2.i_neg/id2.s_pos/id2.s_neg/id2.b_pos/id2.b_neg/id2.j_pos/id2.j_neg | sem.decode.immediate_sign_extension | op_idx, pc, opcode, mnemonic, imm | bucket_emitted | bucket_emitted | bucket_emitted | verified | not_started | verified | verified | verified | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted |  | d7 baseline examples: `cargo run -q --bin beak-trace -- --bin "008000ef 00100113 00200193" --print-buckets`. | d7 emits sign-extension cells from executed decoded immediates; no d7 immediate mutation hook is mapped. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012183 --print-buckets` emitted the bucket and injected `sp1.semantic.decode.immediate_sign_extension::site=instruction_op_c` reported `semantic_injection_applied = true` in `agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| id3 | id3.lui_zero/id3.lui_max/id3.lui_mid/id3.auipc_no_wrap/id3.auipc_wrap | sem.decode.upper_immediate_materialization; sem.control.auipc_pc_limb_consistency | op_idx, pc, opcode, mnemonic, imm, rd | semantic_injection_mapped | semantic_injection_mapped | bucket_emitted | verified | not_started | bucket_emitted | bucket_emitted | bucket_emitted | unsupported | semantic_injection_mapped | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.control.auipc_pc_limb_consistency` for OpenVM d7/336; `jolt.semantic.decode.upper_immediate_materialization` for Jolt | d7 baseline/injected: `./target/debug/beak-trace --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" --inject-kind openvm.semantic.control.auipc_pc_limb_consistency --inject-step 18446744073709551615 --print-buckets` emitted `sem.control.auipc_pc_limb_consistency` and reported `semantic_injection_applied = true`. Jolt baseline: `cargo run -q --bin beak-trace -- --bin 123450b7 --print-buckets` emitted `sem.decode.upper_immediate_materialization`; injected Jolt smoke with `--inject-kind jolt.semantic.decode.upper_immediate_materialization --inject-step 18446744073709551615` reported `injection_applied = true` but still hit the known Jolt memory panic, so not verified. | d7 emits LUI/AUIPC upper-immediate buckets from executed trace; only the AUIPC PC-limb sub-bucket is mapped, via `extensions/rv32im/circuit/src/auipc/core.rs::fill_trace_row` mutating `pc_limbs`. Program-table LUI/operand mutation remains unavailable. Jolt emits LUI/AUIPC cells only from executed `RVTraceRow`s whose PC maps back to the input program; Jolt install pass mutates the processed `JoltTraceStep.instruction_lookup` virtual advice value in `jolt-core/src/host/mod.rs::Program::trace` and backend maps observed `id3` hits. |
| id4 | id4.alu_r/id4.alu_i/id4.load/id4.store/id4.branch/id4.jal/id4.jalr/id4.lui/id4.auipc/id4.ecall/id4.mul/id4.div | sem.exec.op_selector_binding | op_idx, pc, opcode, mnemonic | bucket_emitted | bucket_emitted | bucket_emitted | verified | not_started | verified | verified | verified | unsupported | bucket_emitted | bucket_emitted | verified | bucket_emitted |  | d7 baseline examples: `cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets`. | d7 emits opcode-class selector cells from executed instruction trace. Raw RV ECALL is not observable for d7 because it transpiles to `unimp`; that cell remains covered by the cf5/cf7 trace-missing notes. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012183 --print-buckets` emitted the bucket and injected `sp1.semantic.exec.op_selector_binding::site=opcode` reported `semantic_injection_applied = true` in `agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| id5 | id5.s_type/id5.b_type/id5.j_type/id5.cross_field | sem.decode.format_immediate_reassembly | op_idx, pc, opcode, mnemonic, imm | verified | bucket_emitted | bucket_emitted | verified | not_started | verified | verified | verified | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.decode.format_immediate_reassembly` | Baseline: `cargo run -q --bin beak-trace -- --bin "00100113 00200193 00208463 00300193" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.decode.format_immediate_reassembly --inject-step 2`; injected replay printed `pc=8`, reported `semantic_injection_applied = true`, and failed proof with `ChallengePhaseError`. | OpenVM-336 emits decoded S/B/J scattered immediate cells; 336 install pass mutates the program table operand `c` for targeted decoded instruction rows. OpenVM-f038 emits this bucket from executed instruction trace only; no f038 program-table mutation hook is mapped. I-immediate limb coverage is tracked as AL1. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00100093 00108463 00200113 --print-buckets` emitted the bucket and injected `sp1.semantic.decode.format_immediate_reassembly::site=instruction_op_c` reported `semantic_injection_applied = true` in `agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| al1 | al1.single_limb/al1.cross_01/al1.negative/al1.boundary | sem.alu.immediate_limb_consistency | op_idx, pc, opcode, mnemonic, imm | verified | semantic_injection_mapped | verified | verified | not_started | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.alu.immediate_limb_consistency`; `sp1.semantic.alu.immediate_limb_consistency` | d7 baseline/injected: `./target/debug/beak-trace --bin "10000093" --inject-kind openvm.semantic.alu.immediate_limb_consistency --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.c[0]` in `extensions/rv32im/circuit/src/base_alu/core.rs::fill_trace_row`; OpenVM-336 emits decoded I-ALU immediate limb cells and mutates adapter immediate limbs in `adapters/alu.rs`. SP1 7/811/356: shared install pass `pass4_v4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| al2 | al2.sll_lt32/al2.sll_ge32/al2.srl_lt32/al2.srl_ge32/al2.sra_*/al2.shamt_zero | sem.alu.shift_mod32 | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, effective_shamt | verified | semantic_injection_mapped | verified | verified | not_started | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.alu.shift_mod32`; `sp1.semantic.alu.shift_mod32` | d7 baseline `./target/debug/beak-trace --bin "000010b7 00002137 002091b3" --print-buckets` emitted `sem.alu.shift_mod32`; injected same seed with `--inject-kind openvm.semantic.alu.shift_mod32 --inject-step 18446744073709551615` reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.a[0]` in `extensions/rv32im/circuit/src/shift/core.rs::fill_trace_row`; OpenVM-336 emits Shift chip rows and mutates the shift output limb in `shift/core.rs`. SP1 7/811/356: shared install pass `pass4_v4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| al3 | al3.slt_true/al3.slt_false/al3.sltu_true/al3.sltu_false/al3.equal/al3.sign_disagree | sem.alu.comparison_booleanity | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rd_val, rs1_val, rs2_or_imm_val | verified | semantic_injection_mapped | verified | verified | not_started | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.alu.comparison_booleanity`; `sp1.semantic.alu.comparison_booleanity` | d7 baseline `./target/debug/beak-trace --bin "800000b7 00001137 0020a1b3" --print-buckets` emitted `sem.alu.comparison_booleanity`; injected same seed with `--inject-kind openvm.semantic.alu.comparison_booleanity --inject-step 18446744073709551615` reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 flips `core_row.cmp_result` in `extensions/rv32im/circuit/src/less_than/core.rs::fill_trace_row`; OpenVM-336 emits LessThan chip rows and flips the comparison result column in `less_than/core.rs`. SP1 7/811/356: shared install pass `pass4_v4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| al4 | al4.no_borrow/al4.borrow/al4.equal/al4.cross_limb | sem.alu.subtraction_borrow_chain | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val | verified | semantic_injection_mapped | verified | verified | not_started | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.alu.subtraction_borrow_chain`; `sp1.semantic.alu.subtraction_borrow_chain` | d7 injected smoke `./target/debug/beak-trace --bin "000010b7 00002137 402081b3" --inject-kind openvm.semantic.alu.subtraction_borrow_chain --inject-step 18446744073709551615 --print-buckets` emitted `sem.alu.subtraction_borrow_chain` and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.a[0]` for SUB in `extensions/rv32im/circuit/src/base_alu/core.rs::fill_trace_row`; OpenVM-336 emits BaseAlu SUB rows and mutates the SUB result limb in `base_alu/core.rs`. SP1 7/811/356: shared install pass `pass4_v4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| al5 | al5.first_limb_diff/al5.last_limb_diff/al5.all_equal/al5.alternating_borrow | sem.alu.comparison_auxiliary_chain | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val | verified | semantic_injection_mapped | verified | verified | not_started | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.alu.comparison_auxiliary_chain`; `sp1.semantic.alu.comparison_auxiliary_chain` | d7 injected smoke `./target/debug/beak-trace --bin "800000b7 00001137 0020a1b3" --inject-kind openvm.semantic.alu.comparison_auxiliary_chain --inject-step 18446744073709551615 --print-buckets` emitted `sem.alu.comparison_auxiliary_chain` and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.diff_marker[0]` in `extensions/rv32im/circuit/src/less_than/core.rs::fill_trace_row`; OpenVM-336 emits LessThan comparison aux rows and mutates `diff_val`/`diff_marker` in `less_than/core.rs`. SP1 7/811/356: shared install pass `pass4_v4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| md1 | md1.div_zero/md1.divu_zero/md1.rem_zero/md1.remu_zero/md1.dividend_* | sem.arithmetic.special_case_consistency | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, rd_val | verified | semantic_injection_mapped | verified | verified | not_started | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.arithmetic.special_case_consistency`; `sp1.semantic.arithmetic.special_case_consistency` | d7 injected smoke `./target/debug/beak-trace --bin "000010b7 0200c1b3" --inject-kind openvm.semantic.arithmetic.special_case_consistency --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.q[0]` in `extensions/rv32im/circuit/src/divrem/core.rs::fill_trace_row`; OpenVM-336 emits div-by-zero cells from executed DivRem chip rows; reuses existing special-case injection hook. SP1 7/811/356: shared install pass `pass4_v4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| md2 | md2.div_overflow/md2.rem_overflow | sem.arithmetic.special_case_consistency | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, rd_val | verified | semantic_injection_mapped | verified | verified | not_started | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.arithmetic.special_case_consistency`; `sp1.semantic.arithmetic.special_case_consistency` | d7 uses the same DivRem special-case hook as md1; targeted div-by-zero smoke reported `semantic_injection_applied = true`, and overflow cells use the same concrete `divrem/core.rs::fill_trace_row` mutation point. SP1 7/811/356 chip-hook smokes are recorded in `agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | OpenVM-336 emits signed DIV/REM overflow cells from executed DivRem chip rows; reuses existing special-case injection hook. SP1 7/811/356: shared install pass `pass4_v4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| md3 | md3.pp/md3.pn/md3.np/md3.nn/md3.exact/md3.large_q/md3.one/md3.unsigned | sem.arithmetic.division_remainder_bound | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, rd_val | verified | semantic_injection_mapped | verified | verified | not_started | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | bucket_emitted | bucket_emitted | verified | verified | `openvm.semantic.arithmetic.division_remainder_bound`; `sp1.semantic.arithmetic.division_remainder_bound` | d7 baseline/injected `./target/debug/beak-trace --bin "000100b7 00001137 0220c1b3" --inject-kind openvm.semantic.arithmetic.division_remainder_bound --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.q[0]` for nonzero-divisor rows using preserved `beak_record_c` in `extensions/rv32im/circuit/src/divrem/core.rs::fill_trace_row`; OpenVM-336 emits nonzero-divisor division/remainder cells from executed DivRem chip rows. SP1 7/811/356: shared install pass `pass4_v4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| md4 | md4.mul_small/md4.mul_overflow/md4.mulh_pp/md4.mulh_pn/md4.mulh_nn/md4.mulhu/md4.zero_op/md4.max_product | sem.arithmetic.product_decomposition | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, rd_val, product_hi, product_lo | verified | semantic_injection_mapped | verified | verified | not_started | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.arithmetic.product_decomposition`; `sp1.semantic.arithmetic.product_decomposition` | d7 injected smoke `./target/debug/beak-trace --bin "000010b7 00002137 022081b3" --inject-kind openvm.semantic.arithmetic.product_decomposition --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.a[0]` in `extensions/rv32im/circuit/src/mul/core.rs::fill_trace_row` and `mulh/core.rs::fill_trace_row`; OpenVM-336 emits product decomposition cells from executed Mul/MulH chip rows. MULHSU-specific correction remains tracked by MD5. SP1 7/811/356: shared install pass `pass4_v4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| md5 | md5.pos_any/md5.neg_small/md5.neg_large/md5.neg_max/md5.neg_one | sem.arithmetic.signed_unsigned_product_correction | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, rd_val, product_hi, product_lo | verified | semantic_injection_mapped | verified | verified | not_started | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.arithmetic.signed_unsigned_product_correction`; `sp1.semantic.arithmetic.signed_unsigned_product_correction` | d7 injected smoke `./target/debug/beak-trace --bin "800000b7 00001137 0220a1b3" --inject-kind openvm.semantic.arithmetic.signed_unsigned_product_correction --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.b_ext` for MULHSU in `extensions/rv32im/circuit/src/mulh/core.rs::fill_trace_row`; OpenVM-336 emits MULHSU correction cells from executed MulH chip rows. SP1 7/811/356: shared install pass `pass4_v4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| me1 | me1.sw_lw/me1.sb_lb/me1.sh_lh/me1.sb_lw/me1.sw_lb/me1.sw_lhu/me1.overwrite | sem.memory.store_load_payload_flow | op_idx, pc, opcode, mnemonic, effective_ptr, width, timestamp, read_data, write_data, store_step_idx | verified | trace_missing | verified | verified | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | verified | trace_missing | trace_missing | `openvm.semantic.memory.store_load_payload_flow` | See OpenVM-336 Memory/Time verifier smoke below: pass | OpenVM-336 tracks adapter memory_access store bytes and later loads to the same true address; backend anchors injection to `store_step_idx` and the 336 install pass mutates loadstore core `write_data` at the store payload row. Nexus emits this bucket from executed `UniformTrace` store records only when a later executed load record reaches the same address (width-specific cells when applicable); Nexus pass3 patches `prover/src/chips/instructions/load_store.rs::LoadStoreChip::fill_main_trace` and mutates `Ram1ValCur` at the store row for `nexus.semantic.memory.store_load_payload_flow`. |
| me2 | me2.half_off1/me2.word_off*/me2.byte_any | sem.memory.address_alignment_consistency | op_idx, pc, opcode, mnemonic, effective_ptr, aligned_ptr, byte_offset, width | verified | trace_missing | verified | verified | not_started | bucket_emitted | bucket_emitted | bucket_emitted | unsupported | bucket_emitted | bucket_emitted | trace_missing | trace_missing | `openvm.semantic.memory.address_pointer_consistency` | See OpenVM-336 Memory/Time verifier smoke below: pass | OpenVM-336 emits true adapter memory_access records; 336 install pass mutates loadstore adapter `mem_ptr_limbs`. |
| me3 | me3.lb_*/me3.lh_*/me3.lbu/me3.lhu | sem.memory.load_value_binding | op_idx, pc, opcode, mnemonic, effective_ptr, byte_offset, width, read_data | verified | trace_missing | verified | verified | not_started | bucket_emitted | bucket_emitted | bucket_emitted | unsupported | bucket_emitted | bucket_emitted | trace_missing | trace_missing | `openvm.semantic.memory.value_payload_consistency` | See OpenVM-336 Memory/Time verifier smoke below: pass | OpenVM-336 derives sign/zero-extension cells from adapter memory_access read_data; 336 install pass mutates loadstore core `write_data`. |
| me4 | me4.sb_off*/me4.sh_off* | sem.memory.write_payload_consistency | op_idx, pc, opcode, mnemonic, effective_ptr, byte_offset, width, read_data, prev_data | verified | trace_missing | verified | verified | not_started | bucket_emitted | bucket_emitted | bucket_emitted | unsupported | bucket_emitted | verified | trace_missing | trace_missing | `openvm.semantic.memory.value_payload_consistency` | See OpenVM-336 Memory/Time verifier smoke below: pass | OpenVM-336 emits subword store mask cells from adapter memory_access records; 336 install pass mutates loadstore core `write_data`. Nexus emits subword SB/SH offset cells from executed `UniformTrace` store records; Nexus pass3 patches `LoadStoreChip::fill_main_trace` and mutates `Ram1ValPrev` at the store row for `nexus.semantic.memory.write_payload_consistency`. |
| me5 | me5.reg_read/me5.reg_write/me5.mem_read/me5.mem_write | sem.memory.address_space_consistency | op_idx, pc, opcode, mnemonic, address_space, is_load, is_store | verified | trace_missing | verified | bucket_emitted | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | bucket_emitted | trace_missing | trace_missing | `openvm.semantic.memory.address_space_consistency` | See OpenVM-336 Memory/Time verifier smoke below: pass | OpenVM-336 emits load/store address-space direction cells from adapter memory_access records; 336 install pass now mutates loadstore adapter `ReadRecord.mem_as`. |
| me6 | me6.near_max_lw/me6.near_max_sw/me6.near_max_lh/me6.near_max_sb/me6.heap_boundary | sem.memory.address_boundary_range | op_idx, pc, opcode, mnemonic, effective_ptr, width, address_space | verified | trace_missing | verified | semantic_injection_mapped | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | bucket_emitted | trace_missing | trace_missing | `openvm.semantic.memory.address_pointer_consistency` | See OpenVM-336 Memory/Time verifier smoke below: pass | OpenVM-336 emits address-boundary cells only when adapter memory_access records actually reach boundary addresses; 336 install pass mutates loadstore adapter `mem_ptr_limbs`. |
| me7 | me7.bss_zero/me7.data_loaded | sem.memory.initial_value_binding | op_idx, pc, opcode, mnemonic, effective_ptr, width, read_data, no_prior_write; memory_init seq/address/value for explicit nonzero init cells | bucket_emitted | trace_missing | bucket_emitted | trace_missing | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | bucket_emitted | trace_missing | trace_missing |  | `BEAK_OPENVM_INIT_MEMORY='2:64:127' cargo run -q --bin beak-trace -- --bin '00100013' --print-buckets`: pass; injected initial-value smoke was underconstrained and is not mapped | First observed load with no prior same-address store is classified as zero vs nonzero initial value; OpenVM-336 now also emits explicit nonzero `memory_init` cells. No semantic injection mapping: attempted initial-memory mutation hooks were underconstrained in prover smoke. |
| me7 | me7.rodata/me7.stack_uninit | sem.memory.initial_value_binding | ELF/load-region metadata, stack-region metadata | trace_missing | trace_missing | trace_missing | trace_missing | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | trace_missing | trace_missing |  |  | Adapter memory_access exposes values and addresses but not ELF/stack region provenance. |
| me8 | me8.no_conflict | sem.memory.initial_value_binding | memory_init seq/address/value for explicit nonzero init cells | bucket_emitted | trace_missing | trace_missing | trace_missing | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | trace_missing | trace_missing |  | `BEAK_OPENVM_INIT_MEMORY='2:64:127' cargo run -q --bin beak-trace -- --bin '00100013' --print-buckets`: pass | OpenVM-336 emits non-conflicting explicit nonzero initialization cells from `MemoryController::set_initial_memory`; no injection mapping because initial-memory mutation smoke was underconstrained. |
| me8 | me8.double_init | sem.memory.initial_value_binding | duplicate initialization writes before MemoryImage coalescing | trace_missing | trace_missing | trace_missing | trace_missing | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | trace_missing | trace_missing |  |  | OpenVM-336 receives a coalesced `MemoryImage`, so duplicate initialization writes are lost before `set_initial_memory`; this needs earlier ELF/loader instrumentation. |
| me9 | me9.off*/me9.adjacent_* | sem.memory.address_progression_consistency | op_idx, pc, opcode, mnemonic, effective_ptr, aligned_ptr, byte_offset, width | verified | trace_missing | verified | verified | not_started | bucket_emitted | bucket_emitted | bucket_emitted | unsupported | bucket_emitted | bucket_emitted | trace_missing | trace_missing | `openvm.semantic.memory.address_pointer_consistency` | See OpenVM-336 Memory/Time verifier smoke below: pass | OpenVM-336 emits byte-offset cells from adapter memory_access records; 336 install pass mutates loadstore adapter `mem_ptr_limbs`. |
| me10 | me10.load/me10.store | sem.memory.kind_selector_consistency | op_idx, pc, opcode, mnemonic, is_load, is_store, width | verified | trace_missing | verified | verified | not_started | verified | verified | bucket_emitted | unsupported | bucket_emitted | verified | bucket_emitted | bucket_emitted | `openvm.semantic.memory.kind_selector_consistency` | See OpenVM-336 Memory/Time verifier smoke below: pass | OpenVM-336 emits load/store direction cells from adapter memory_access records; 336 install pass mutates loadstore core `is_load`. Nexus emits load/store direction cells from executed `UniformTrace` memory records; Nexus pass3 patches `LoadStoreChip::fill_main_trace` and flips `IsSw`/`IsLw` selector columns for `nexus.semantic.memory.kind_selector_consistency`. |
| me11 | me11.written_cells/me11.read_only_cells | sem.memory.finalization_consistency | memory_finalization seq, op_idx, address_space, pointer, timestamp, values, was_initial, changed_from_initial | verified | trace_missing | verified | trace_missing | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | trace_missing | trace_missing | `openvm.semantic.memory.finalization_consistency` | `BEAK_OPENVM_INIT_MEMORY='2:64:1' cargo run -q --bin beak-trace -- --bin '04000093 07f00113 0020a023' --print-buckets`: pass; injected same seed with `--inject-kind openvm.semantic.memory.finalization_consistency --inject-step 0`: `verify_app_proof failed: ChallengePhaseError` | OpenVM-336 now emits persistent memory finalization rows from `MemoryController::finalize`; the 336 install pass mutates `final_partition` values before boundary/merkle finalization, and baseline+injected prover smoke passed. |
| me11 | me11.untouched_cells | sem.memory.finalization_consistency | complete final memory universe / untouched finalization rows | trace_missing | trace_missing | trace_missing | trace_missing | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | trace_missing | trace_missing |  |  | The exposed `final_partition` covers accessed/finalized blocks; it does not enumerate untouched memory cells. |
| ts1 | ts1.standard | sem.time.boundary_origin_consistency | op_idx, pc, timestamp, next_timestamp | verified | semantic_injection_mapped | verified | verified | not_started | bucket_emitted | bucket_emitted | bucket_emitted | trace_missing | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.time.boundary_origin_consistency` | d7 injected smoke `./target/debug/beak-trace --bin "00100013" --inject-kind openvm.semantic.time.boundary_origin_consistency --inject-step 0 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. | d7 mutates connector boundary `state.timestamp` in `crates/vm/src/system/connector/mod.rs::generate_proving_ctx`; OpenVM-336 derives standard initial timestamp cell from the first executed instruction and mutates connector boundary timestamp. |
| ts2 | ts2.small_gap/ts2.large_gap/ts2.consecutive | sem.time.monotonic_access_ordering | op_idx, pc, effective_ptr, address_space, timestamp, previous_timestamp, ts_diff | verified | trace_missing | verified | verified | not_started | verified | bucket_emitted | trace_missing | trace_missing | trace_missing | bucket_emitted | trace_missing | trace_missing | `openvm.semantic.time.monotonic_access_ordering` | See OpenVM-336 Memory/Time verifier smoke below: pass | OpenVM-f038 derives same-address timestamp gaps from adapter memory_access records; shared timestamp-aux hook failed injected smoke with `OodEvaluationMismatch`. Pico emits same-address timestamp buckets and verifies the paired `sem.memory.timestamped_load_path` hook with base inject kind `pico.semantic.memory.timestamped_load_path`; `ts2.cross_segment` remains trace_missing until segment-boundary memory continuity is exposed. |
| ts2 | ts2.cross_segment | sem.time.monotonic_access_ordering | segment_idx/shard boundary plus memory access continuity | trace_missing | trace_missing | trace_missing | trace_missing | not_started | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing |  |  | Current trace does not expose cross-segment memory ordering boundaries. |
| ts3 | ts3.standard | sem.time.boundary_origin_consistency | op_idx, pc, timestamp | verified | semantic_injection_mapped | verified | verified | not_started | bucket_emitted | bucket_emitted | bucket_emitted | trace_missing | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.time.boundary_origin_consistency` | d7 injected smoke `./target/debug/beak-trace --bin "00100013" --inject-kind openvm.semantic.time.boundary_origin_consistency --inject-step 0 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. | d7 mutates connector boundary `state.timestamp` in `crates/vm/src/system/connector/mod.rs::generate_proving_ctx`; OpenVM-336 derives standard clk/pc initialization cell from the first executed instruction and mutates connector boundary timestamp. |
| cf1 | cf1.blt*/cf1.bge*/cf1.bltu*/cf1.bgeu*/cf1.beq_equal/cf1.bne_not_equal/cf1.sign_flip | sem.exec.control_flow_binding | op_idx, pc, opcode, mnemonic, next_pc, target_pc, taken, chip-row operands for sign_flip | verified | semantic_injection_mapped | bucket_emitted | verified | not_started | verified | verified | bucket_emitted | unsupported | semantic_injection_mapped | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.exec.control_flow_binding`; `jolt.semantic.exec.control_flow_binding` | d7 injected branch smoke `./target/debug/beak-trace --bin "00100113 00200193 00208463 00300193" --inject-kind openvm.semantic.exec.control_flow_binding --inject-step 18446744073709551615 --print-buckets` emitted `sem.exec.control_flow_binding` and reported `semantic_injection_applied = true`. Jolt baseline: `cargo run -q --bin beak-trace -- --bin "00100093 00200113 0020c463 00300193" --print-buckets` emitted `sem.exec.control_flow_binding`; injected Jolt smoke with `--inject-kind jolt.semantic.exec.control_flow_binding --inject-step 18446744073709551615` reported `injection_applied = true` but still hit the known Jolt memory panic, so not verified. | d7 mutates branch compare result in `extensions/rv32im/circuit/src/branch_eq/core.rs` and `branch_lt/core.rs`; branch taken/not-taken cells come from executed instruction next_pc. OpenVM-f038 emits branch buckets from executed instruction trace only; no f038 branch mutation hook is mapped. Jolt emits branch cells from executed `RVTraceRow` register operands and input-PC mapping; Jolt install pass mutates branch `JoltTraceStep.instruction_lookup` variants. |
| cf2 | cf2.jal_rd/cf2.jal_x0/cf2.jalr_rd/cf2.jalr_x0 | sem.exec.control_flow_binding | op_idx, pc, opcode, mnemonic, rd, next_pc, link_pc | verified | semantic_injection_mapped | bucket_emitted | verified | not_started | verified | semantic_injection_mapped | bucket_emitted | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.exec.control_flow_binding` | d7 branch/JAL/JALR control-flow hooks are mapped; branch smoke above reported `semantic_injection_applied = true`, and JAL/JALR use the same base inject kind at `jal_lui/core.rs` and `jalr/core.rs`. | Link-register cells are emitted from executed JAL/JALR instruction trace; d7 mutates JAL/JALR link/target witness columns. OpenVM-f038 emits this bucket from executed instruction trace only; no f038 JAL/JALR mutation hook is mapped. |
| cf3 | cf3.imm_zero/cf3.imm_pos/cf3.imm_neg | sem.exec.control_flow_binding | op_idx, pc, opcode, mnemonic, imm, next_pc | verified | semantic_injection_mapped | bucket_emitted | verified | not_started | verified | semantic_injection_mapped | bucket_emitted | unsupported | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.exec.control_flow_binding` | d7 JALR hook is mapped in `extensions/rv32im/circuit/src/jalr/core.rs::fill_trace_row`; control-flow injected smoke reported applied-site evidence for the shared base kind. | JALR immediate-sign cells are observable from executed decode; d7/336 JALR hooks mutate target/link witness columns. OpenVM-f038 emits JALR immediate buckets from executed instruction trace only; no f038 JALR mutation hook is mapped. |
| cf3 | cf3.clear_lsb/cf3.even/cf3.wrap | sem.exec.control_flow_binding | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, rs1_val, imm, target_before_lsb_clear, target_after_lsb_clear, next_pc | verified | semantic_injection_mapped | trace_missing | trace_missing | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | bucket_emitted | install_patch_available | trace_missing | `openvm.semantic.exec.control_flow_binding` | d7 JALR chip-row emission includes `target_before_lsb_clear`; mapped JALR hook mutates `rd_data[0]` and `imm_sign` in `jalr/core.rs::fill_trace_row`. | OpenVM-f038 baseline JALR emits executed control-flow buckets, but the installed f038 source does not expose `target_before_lsb_clear` chip-row evidence; clear/even/wrap remain trace_missing. Risc0-98387806 emits JALR target cells from executed register state with `target_before_lsb_clear` / `target_after_lsb_clear`; the Risc0 control-flow prover hook remains unmapped because injected smoke did not provide contract-complete applied evidence. Pico currently emits JALR immediate cells only; `target_before_lsb_clear` / `target_after_lsb_clear` are not emitted in `projects/pico-45e74ccd62758c6d67239913956e749adaba261c/src/lib/trace.rs::cf3_cell`. |
| cf4 | cf4.default_entry/cf4.custom_entry | sem.control.entrypoint_binding | first op_idx, first pc | verified | semantic_injection_mapped | bucket_emitted | verified | not_started | bucket_emitted | bucket_emitted | bucket_emitted | unsupported | semantic_injection_mapped | bucket_emitted | bucket_emitted | bucket_emitted | `openvm.semantic.control.entrypoint_binding`; `jolt.semantic.control.entrypoint_binding` | d7 injected smoke `./target/debug/beak-trace --bin "00100013" --inject-kind openvm.semantic.control.entrypoint_binding --inject-step 0 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. Jolt baseline: `cargo run -q --bin beak-trace -- --bin 123450b7 --print-buckets` emitted `sem.control.entrypoint_binding`; injected Jolt smoke with `--inject-kind jolt.semantic.control.entrypoint_binding --inject-step 0` reported `injection_applied = true` but still hit the known Jolt memory panic, so not verified. | d7 mutates connector boundary `state.pc` in `crates/vm/src/system/connector/mod.rs::generate_proving_ctx`; first executed instruction PC is emitted as OpenVM instruction-index PC. OpenVM-f038 emits entrypoint buckets from executed instruction trace only; no f038 boundary-PC mutation hook is mapped. |
| cf5 | cf5.halt/cf5.io_read/cf5.io_write/cf5.precompile/cf5.arg_zero/cf5.arg_max | sem.control.ecall_argument_decomposition | op_idx, pc, syscall_nr, a0-a7 register values | trace_missing | trace_missing | trace_missing | trace_missing | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | verified | verified | `<vm>.semantic.control.ecall_argument_decomposition` |  | OpenVM-f038 does not expose Linux-style ECALL syscall dispatch or a0-a7 argument reads; RV32 system encodings are transpiled before a raw ECALL obligation bucket is observable. |
| cf6 | cf6.normal/cf6.after_branch_not_taken | sem.exec.control_flow_binding | op_idx, pc, opcode, mnemonic, next_pc, previous branch next_pc | verified | semantic_injection_mapped | bucket_emitted | verified | not_started | verified | verified | bucket_emitted | unsupported | bucket_emitted | bucket_emitted | install_patch_available | bucket_emitted | `openvm.semantic.exec.control_flow_binding` | d7 injected smoke `./target/debug/beak-trace --bin "00100113 00200193 00208463 00300193" --inject-kind openvm.semantic.exec.control_flow_binding --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. | Sequential and after-branch-not-taken cells use executed instruction trace; d7 branch/JAL/JALR hooks cover concrete control-flow witness mutation. OpenVM-f038 emits sequential buckets from executed instruction trace only; no f038 control-flow mutation hook is mapped. `near_segment_end` still needs segment metadata. |
| cf6 | cf6.near_segment_end | sem.exec.control_flow_binding | segment boundary metadata | trace_missing | trace_missing | trace_missing | trace_missing | not_started | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | trace_missing | trace_missing |  |  | Current trace lacks segment-boundary position metadata; d7eab708 and Pico likewise have no segment-boundary position metadata in the emitted instruction/chip-row trace. |
| cf7 | cf7.standard | sem.control.ecall_word_validity | op_idx, pc, opcode, mnemonic, raw instruction word | install_patch_available | trace_missing | trace_missing | bucket_emitted | not_started | bucket_emitted | semantic_injection_mapped | bucket_emitted | unsupported | trace_missing | trace_missing | bucket_emitted | bucket_emitted | `openvm.semantic.control.ecall_word_validity` | Hook smoke: `cargo run -q --bin beak-trace -- --bin "00000073" --inject-kind openvm.semantic.control.ecall_word_validity --inject-step 0` printed the program-table mutation and reported `semantic_injection_applied = true` / `verify_app_proof failed: ChallengePhaseError`; baseline `00000073 --print-buckets` emitted 0 buckets because the RV system word transpiled to `unimp`. | OpenVM-f038 has no mapped program-table ECALL hook and no baseline raw-RV ECALL bucket; status remains trace_missing. Pico emits the executed ECALL word bucket when observable, but no real Pico install mutation hook exists for `pico.semantic.control.ecall_word_validity`, so it is bucket-only. |
| bu1 | bu1.real_row | sem.lookup.boolean_multiplicity | step_idx, table_name, multiplicity, is_real | not_started | trace_missing | trace_missing | verified | trace_missing | install_patch_available | trace_missing | install_patch_available | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | `<vm>.semantic.lookup.boolean_multiplicity` | Pico base-kind injected smoke `pico.semantic.lookup.boolean_multiplicity` at step 0 reported `injection_applied=true` and failed with `Constraint verification failed` after the hook was corrected to mutate `is_real_shadow`. | Requires prover/table instrumentation; f038 does not expose boolean lookup multiplicity rows in the current trace. |
| pd1 | pd1.short_trace | sem.row.padding_interaction_send | step_idx, table_name, is_padding, interaction_kind | not_started | bucket_emitted | bucket_emitted | trace_missing | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | `<vm>.semantic.row.padding_interaction_send` |  | f038 baseline smokes emit padding interaction-send buckets; no mutation hook is mapped. |

## Per-VM Notes

Add short notes here as pilots progress.

### sp1-39ab52fc

- Status: full-completion pass completed for currently observable SP1 evidence.
  Instruction-local semantic buckets now come only from oracle-executed
  instructions, not unexecuted input words.
- Bucket-emitted from executed instruction trace with contract details:
  `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md3`-`md5`,
  `cf1`-`cf4`, `cf6.normal/after_branch_not_taken`, `cf7`,
  `ts1.standard`, `ts3.standard`, and SP1 memory-effect `me10`.
- Verified SP1 semantic injection mappings:
  `sem.exec.memory_effect_binding` maps to
  `sp1.semantic.exec.memory_effect_binding`; baseline
  `cargo run -q --bin beak-trace -- --bin "00012183" --print-buckets`
  emitted `sem.exec.memory_effect_binding`, and injected
  `cargo run -q --bin beak-trace -- --bin "00012183" --inject-kind sp1.semantic.exec.memory_effect_binding --inject-step 0 --print-buckets`
  reported `semantic_injection_applied = true` with oracle/SP1 registers matching.
- Verified SP1 installed hook replay:
  `sem.memory.timestamped_load_path` maps to
  `sp1.semantic.memory.timestamped_load_path`; injected replay on `00012183`
  with `--inject-step 0` reported `semantic_injection_applied = true`.
- Verified SP1 control-flow hook replay:
  `sem.exec.control_flow_binding` maps to
  `sp1.semantic.exec.control_flow_binding`; injected replay
  `cargo run -q --bin beak-trace -- --bin "00100093 00108463 00200113" --inject-kind sp1.semantic.exec.control_flow_binding --inject-step 1 --print-buckets`
  emitted the control-flow bucket and reported
  `semantic_injection_applied = true`.
- Install patch available but not verified:
  `sem.lookup.boolean_multiplicity` maps to
  `sp1.semantic.lookup.boolean_multiplicity`, and the install pass has a memory
  write-record hook. A store/load smoke
  `cargo run -q --bin beak-trace -- --bin "00002023 00002083" --print-buckets`
  panicked in the installed SP1 memory timestamp ordering assertion before
  buckets/final regs, so this remains `install_patch_available`.
- Trace-missing or unsupported cells:
  `md1`/`md2` exact div-by-zero and signed-overflow cells need per-step operand
  values; most `me1`-`me9`/`me11`, `ts2.cross_segment`, `cf5`,
  `cf6.near_segment_end`, `rc1`-`rc4`, `bu2`-`bu6`, and `pd2`-`pd5`
  need real SP1 memory accesses, memory init/finalization rows, syscall
  argument values, range-check/flag decomposition rows, bus/permutation rows,
  transcript data, or segment/table lifecycle metadata that the current target
  trace does not expose.
- Verification: `cargo check -q` passed in the target project with pre-existing
  installed-SP1 warnings. Required final test commands are recorded in the run
  log `agent_runs/vm-distributed/lead-sp1-39ab52fc.md`.

### openvm-336f1a47

- Status: Group 1-4 bounded pilot plus Memory/Timestamp adapter instrumentation
  and instruction-trace control-flow coverage implemented for OpenVM-336.
- Owner scope: `projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba/` and
  `beak-py/projects/openvm-fuzzer/`.
- First batch status:

| obligation_id | status | semantic_bucket | notes |
|---|---|---|---|
| rf1 | verified | sem.decode.zero_register_immutability | Decoded RV32IM write-to-x0 cells across ALU/I/upper/load/jump/muldiv classes; program-table operand mutation hook passed baseline+injected verifier smoke. |
| rf2 | verified | sem.decode.operand_index_routing | Decoded rs1/rs2/rd alias cells, including x0 sources; program-table operand mutation hook passed baseline+injected verifier smoke. |
| rf3 | bucket_emitted | sem.exec.dest_binding | Decoded rd != x0 writeback source classes: ALU, load, link, upper, muldiv. |
| id1 | bucket_emitted | sem.decode.field_range | New shared bucket; decoded register/funct boundary cells. |
| id2 | bucket_emitted | sem.decode.immediate_sign_extension | New shared bucket; decoded I/S/B/J positive and negative immediate cells. |
| id3 | semantic_injection_mapped | sem.decode.upper_immediate_materialization; sem.control.auipc_pc_limb_consistency | LUI/AUIPC decode bucket emitted; AUIPC also reuses existing OpenVM AUIPC injection hook bucket. |
| id4 | bucket_emitted | sem.exec.op_selector_binding | Decoded opcode class cells for RV32IM instruction classes. |
| id5 | verified | sem.decode.format_immediate_reassembly | New shared bucket; decoded S/B/J scattered immediate cells; program-table operand mutation hook passed baseline+injected verifier smoke. |
| al1 | verified | sem.alu.immediate_limb_consistency | Decoded I-ALU immediate cells reuse existing OpenVM semantic injection mapping; baseline+injected verifier smoke passed. |
| al2 | verified | sem.alu.shift_mod32 | OpenVM Shift rows provide rs1/rs2 values and shamt partition; 336 install pass emits Shift chip rows and mutates the shift output limb; baseline+injected verifier smoke passed. |
| al3 | verified | sem.alu.comparison_booleanity | OpenVM LessThan rows provide result and operand values; 336 install pass emits LessThan chip rows and flips the comparison result column; baseline+injected verifier smoke passed. |
| al4 | verified | sem.alu.subtraction_borrow_chain | OpenVM BaseAlu SUB rows provide operand values for borrow cells; 336 install pass mutates the SUB result limb; baseline+injected verifier smoke passed. |
| al5 | verified | sem.alu.comparison_auxiliary_chain | OpenVM LessThan rows provide comparison limb partitions; 336 install pass mutates `diff_val`/`diff_marker` aux-chain columns; baseline+injected verifier smoke passed. |
| md1 | verified | sem.arithmetic.special_case_consistency | OpenVM DivRem rows provide div-by-zero and dividend sign cells; reuses existing special-case injection hook; baseline+injected verifier smoke passed. |
| md2 | verified | sem.arithmetic.special_case_consistency | OpenVM DivRem rows provide signed DIV/REM overflow cells; reuses existing special-case injection hook; baseline+injected verifier smoke passed. |
| md3 | verified | sem.arithmetic.division_remainder_bound | OpenVM DivRem rows provide nonzero-divisor sign/exact/large quotient/divisor-one/unsigned cells; 336 install pass mutates the quotient limb on nonzero-divisor rows; baseline+injected verifier smoke passed. |
| md4 | verified | sem.arithmetic.product_decomposition | OpenVM Mul/MulH rows provide product decomposition cells; 336 install pass emits Mul/MulH chip rows and mutates output limbs; baseline+injected verifier smoke passed. |
| md5 | verified | sem.arithmetic.signed_unsigned_product_correction | OpenVM MulH rows provide MULHSU correction cells; 336 install pass mutates the MULHSU signed-extension correction column; baseline+injected verifier smoke passed. |
| me1 | verified | sem.memory.store_load_payload_flow | Store-to-load same-address cells use adapter memory_access plus install-pass `write_data` emission; targeted verifier smoke applied the store-load payload hook and reported an underconstrained candidate. |
| me2 | verified | sem.memory.address_alignment_consistency | Adapter memory_access instrumentation emits true effective_ptr/aligned_ptr/byte_offset; targeted verifier smoke applied the address-pointer hook and reported an underconstrained candidate. |
| me3 | verified | sem.memory.load_value_binding | Adapter memory_access instrumentation emits read_data for signed/unsigned byte and halfword load cells; targeted verifier smoke applied the value-payload hook and reported an underconstrained candidate. |
| me4 | verified | sem.memory.write_payload_consistency | Adapter memory_access instrumentation emits subword store offset cells; targeted verifier smoke applied the value-payload hook and reported an underconstrained candidate. |
| me5 | verified | sem.memory.address_space_consistency | Adapter memory_access instrumentation emits memory/register read-write direction cells; targeted verifier smoke applied the address-space hook and reported an underconstrained candidate. |
| me6 | verified | sem.memory.address_boundary_range | Boundary seed emits true high-address adapter memory_access cells; targeted verifier smoke applied the address-pointer hook and reported an underconstrained candidate. |
| me7 | bucket_emitted/trace_missing | sem.memory.initial_value_binding | First-load zero/nonzero cells and explicit nonzero memory_init cells are emitted. No initial-memory injection mapping: attempted hooks were underconstrained; rodata/stack provenance remains trace_missing. |
| me8 | bucket_emitted/trace_missing | sem.memory.initial_value_binding | `me8.no_conflict` emits for explicit nonzero memory_init cells; `me8.double_init` remains trace_missing because duplicate initialization writes are coalesced before `MemoryImage`. |
| me9 | verified | sem.memory.address_progression_consistency | Adapter memory_access instrumentation emits byte offset and adjacent subword address cells; targeted verifier smoke applied the address-pointer hook and reported an underconstrained candidate. |
| me10 | verified | sem.memory.kind_selector_consistency | Adapter memory_access instrumentation emits load/store direction cells; targeted verifier smoke applied the kind-selector hook and reported an underconstrained candidate. |
| me11 | verified/trace_missing | sem.memory.finalization_consistency | Persistent memory finalization rows now emit written/read-only cells and map to `openvm.semantic.memory.finalization_consistency`; `me11.untouched_cells` remains trace_missing because untouched memory is not enumerated. |
| ts1 | verified | sem.time.boundary_origin_consistency | First executed instruction timestamp provides standard init-zero cell; targeted verifier smoke applied the connector boundary timestamp hook and reported an underconstrained candidate. |
| ts2 | verified/trace_missing | sem.time.monotonic_access_ordering | Same-address adapter memory_access timestamp gaps map to `openvm.semantic.time.monotonic_access_ordering`; targeted verifier smoke applied the memory aux prev-timestamp hook and reported an underconstrained candidate. `ts2.cross_segment` remains trace_missing. |
| ts3 | verified | sem.time.boundary_origin_consistency | First executed instruction PC/timestamp provides standard clk/pc init cell; targeted verifier smoke applied the connector boundary timestamp hook and reported an underconstrained candidate. |
| cf1 | verified | sem.exec.control_flow_binding | Branch taken/not-taken cells use executed instruction next_pc; targeted branch_lt verifier smoke applied the control-flow hook and reported an underconstrained candidate. |
| cf2 | verified | sem.exec.control_flow_binding | JAL/JALR link-register cells use executed instruction trace; targeted JAL verifier smoke applied the control-flow hook and reported an underconstrained candidate. |
| cf3 | verified | sem.exec.control_flow_binding | JALR immediate sign and pre-mask target cells are emitted from executed instruction/chip-row traces; targeted JALR verifier smoke covered clear_lsb, even, and wrap cells and reported underconstrained candidates. |
| cf4 | verified | sem.control.entrypoint_binding | First executed instruction PC classifies default/custom entry; targeted entrypoint verifier smoke applied the connector boundary-PC hook and reported an underconstrained candidate. |
| cf5 | trace_missing | sem.control.ecall_argument_decomposition | Linux-style ECALL/syscall a0-a7 values are not exposed at dispatch; OpenVM transpiles RV32 system encodings to OpenVM system operands. |
| cf6 | verified/trace_missing | sem.exec.control_flow_binding | Sequential and after-branch-not-taken cells are emitted and mapped; targeted after-branch-not-taken verifier smoke applied the branch_eq control-flow hook and reported an underconstrained candidate. `near_segment_end` needs segment metadata. |
| cf7 | install_patch_available | sem.control.ecall_word_validity | Backend mapping and program-table TERMINATE opcode hook exist, but raw RV ECALL baseline bucket was not observed for `0x00000073`; the transpiler emitted `unimp` with no executed instruction bucket. |

- Legacy/original semantic smoke verification:

| obligation_id | status | semantic_bucket | smoke | result |
|---|---|---|---|---|
| o1 | verified | sem.lookup.xor_multiplicity_consistency | Baseline: `./target/release/beak-trace --bin "01400313 01400393 00734533" --print-buckets`; injected: `./target/release/beak-trace --bin "01400313 01400393 00734533" --inject-kind "openvm.semantic.lookup.xor_multiplicity_consistency::mode=p_plus_mask,rank=0,strength=0" --inject-step 0 --print-buckets` | Baseline emitted `sem.lookup.xor_multiplicity_consistency`; injected replay reported `semantic_injection_applied = true` and `backend_error = verify_app_proof failed: ChallengePhaseError`. |
| o5 | verified | sem.alu.immediate_limb_consistency | Baseline: `./target/release/beak-trace --bin "00100093 02800113 002091b3" --print-buckets`; injected: `./target/release/beak-trace --bin "00100093 02800113 002091b3" --inject-kind "openvm.semantic.alu.immediate_limb_consistency::mode=byte_bias,slot=0,strength=0" --inject-step 2 --print-buckets` | Baseline emitted `sem.alu.immediate_limb_consistency`; injected replay printed the o5 witness mutation, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| o7 | verified | sem.control.auipc_pc_limb_consistency | Baseline: `./target/release/beak-trace --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" --print-buckets`; injected: `./target/release/beak-trace --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" --inject-kind "openvm.semantic.control.auipc_pc_limb_consistency::mode=from_pc_high_single_mod_p,slot=1,strength=0,mult=1" --inject-step 3 --print-buckets` | Baseline emitted `sem.control.auipc_pc_limb_consistency`; injected replay printed the o7 witness mutation, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| o8 | verified | sem.memory.immediate_sign_consistency | Baseline: `./target/release/beak-trace --bin "000010b7 ffc0a103" --print-buckets`; injected: `./target/release/beak-trace --bin "000010b7 ffc0a103" --inject-kind "openvm.semantic.memory.immediate_sign_consistency::mode=flip_sign,domain=load,guard=none" --inject-step 1 --print-buckets` | Baseline emitted `sem.memory.immediate_sign_consistency`; injected replay printed a real sign-flip mutation with `orig_ptr=4092`, `flipped_ptr=69628`, `flipped_sign=0`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| o15 | verified | sem.arithmetic.special_case_consistency | Baseline: `./target/release/beak-trace --bin "00700313 800005b7 fff00613 02c5c733 800003b7 00774533" --print-buckets`; injected: `./target/release/beak-trace --bin "00700313 800005b7 fff00613 02c5c733 800003b7 00774533" --inject-kind "openvm.semantic.arithmetic.special_case_consistency::mode=shadow_invalid_one,search=wildcard" --inject-step 7 --print-buckets` | Baseline emitted `sem.arithmetic.special_case_consistency`; injected replay printed the o15 witness mutation, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |

OpenVM-336 ALU/Arithmetic verifier smoke:

| obligation_id | status | semantic_bucket | smoke | result |
|---|---|---|---|---|
| al1 | verified | sem.alu.immediate_limb_consistency | Baseline: `./target/release/beak-trace --bin "10000093" --print-buckets`; injected: `./target/release/beak-trace --bin "10000093" --inject-kind "openvm.semantic.alu.immediate_limb_consistency" --inject-step 18446744073709551615 --print-buckets` | Baseline emitted `sem.alu.immediate_limb_consistency`; injected replay printed the immediate-limb witness mutation, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| al2 | verified | sem.alu.shift_mod32 | Baseline: `./target/release/beak-trace --bin "000010b7 00002137 002091b3" --print-buckets`; injected: `./target/release/beak-trace --bin "000010b7 00002137 002091b3" --inject-kind "openvm.semantic.alu.shift_mod32" --inject-step 18446744073709551615 --print-buckets` | Baseline emitted `sem.alu.shift_mod32`; injected replay printed the shift witness mutation, reported `semantic_injection_applied = true`, and failed verifier with `backend_error = verify_app_proof failed: OodEvaluationMismatch`. |
| al3 | verified | sem.alu.comparison_booleanity | Baseline: `./target/release/beak-trace --bin "800000b7 00001137 0020a1b3" --print-buckets`; injected: `./target/release/beak-trace --bin "800000b7 00001137 0020a1b3" --inject-kind "openvm.semantic.alu.comparison_booleanity" --inject-step 18446744073709551615 --print-buckets` | Baseline emitted `sem.alu.comparison_booleanity`; injected replay printed the comparison-result witness mutation, reported `semantic_injection_applied = true`, and failed verifier with `backend_error = verify_app_proof failed: OodEvaluationMismatch`. |
| al4 | verified | sem.alu.subtraction_borrow_chain | Baseline: `./target/release/beak-trace --bin "000010b7 00002137 402081b3" --print-buckets`; injected: `./target/release/beak-trace --bin "000010b7 00002137 402081b3" --inject-kind "openvm.semantic.alu.subtraction_borrow_chain" --inject-step 18446744073709551615 --print-buckets` | Baseline emitted `sem.alu.subtraction_borrow_chain`; injected replay printed the SUB-result witness mutation, reported `semantic_injection_applied = true`, and failed verifier with `backend_error = verify_app_proof failed: OodEvaluationMismatch`. |
| al5 | verified | sem.alu.comparison_auxiliary_chain | Baseline: `./target/release/beak-trace --bin "800000b7 00001137 0020a1b3" --print-buckets`; injected: `./target/release/beak-trace --bin "800000b7 00001137 0020a1b3" --inject-kind "openvm.semantic.alu.comparison_auxiliary_chain" --inject-step 18446744073709551615 --print-buckets` | Baseline emitted `sem.alu.comparison_auxiliary_chain`; injected replay printed the comparison-aux witness mutation, reported `semantic_injection_applied = true`, and failed verifier with `backend_error = verify_app_proof failed: OodEvaluationMismatch`. |
| md1 | verified | sem.arithmetic.special_case_consistency | Baseline: `./target/release/beak-trace --bin "000010b7 0200c1b3" --print-buckets`; injected: `./target/release/beak-trace --bin "000010b7 0200c1b3" --inject-kind "openvm.semantic.arithmetic.special_case_consistency" --inject-step 18446744073709551615 --print-buckets` | Baseline emitted `sem.arithmetic.special_case_consistency`; injected replay printed the DivRem special-case witness mutation, reported `semantic_injection_applied = true`, and failed verifier with `backend_error = verify_app_proof failed: ChallengePhaseError`. |
| md2 | verified | sem.arithmetic.special_case_consistency | Baseline: `./target/release/beak-trace --bin "800000b7 fff00113 0220c1b3" --print-buckets`; injected: `./target/release/beak-trace --bin "800000b7 fff00113 0220c1b3" --inject-kind "openvm.semantic.arithmetic.special_case_consistency" --inject-step 18446744073709551615 --print-buckets` | Baseline emitted `sem.arithmetic.special_case_consistency`; injected replay printed the DivRem special-case witness mutation, reported `semantic_injection_applied = true`, and failed verifier with `backend_error = verify_app_proof failed: OodEvaluationMismatch`. |
| md3 | verified | sem.arithmetic.division_remainder_bound | Baseline: `./target/release/beak-trace --bin "000100b7 00001137 0220c1b3" --print-buckets`; injected: `./target/release/beak-trace --bin "000100b7 00001137 0220c1b3" --inject-kind "openvm.semantic.arithmetic.division_remainder_bound" --inject-step 18446744073709551615 --print-buckets` | Baseline emitted `sem.arithmetic.division_remainder_bound`; injected replay printed the quotient-limb witness mutation, reported `semantic_injection_applied = true`, and failed verifier with `backend_error = verify_app_proof failed: ChallengePhaseError`. |
| md4 | verified | sem.arithmetic.product_decomposition | Baseline: `./target/release/beak-trace --bin "000010b7 00002137 022081b3" --print-buckets`; injected: `./target/release/beak-trace --bin "000010b7 00002137 022081b3" --inject-kind "openvm.semantic.arithmetic.product_decomposition" --inject-step 18446744073709551615 --print-buckets` | Baseline emitted `sem.arithmetic.product_decomposition`; injected replay printed the MUL product witness mutation, reported `semantic_injection_applied = true`, and failed verifier with `backend_error = verify_app_proof failed: ChallengePhaseError`. |
| md5 | verified | sem.arithmetic.signed_unsigned_product_correction | Baseline: `./target/release/beak-trace --bin "800000b7 00001137 0220a1b3" --print-buckets`; injected: `./target/release/beak-trace --bin "800000b7 00001137 0220a1b3" --inject-kind "openvm.semantic.arithmetic.signed_unsigned_product_correction" --inject-step 18446744073709551615 --print-buckets` | Baseline emitted `sem.arithmetic.signed_unsigned_product_correction`; injected replay printed the MULHSU correction witness mutation, reported `semantic_injection_applied = true`, and failed verifier with `backend_error = verify_app_proof failed: OodEvaluationMismatch`. |

OpenVM-336 Memory/Time verifier smoke:

| obligation_id | status | semantic_bucket | smoke | result |
|---|---|---|---|---|
| me1 | verified | sem.memory.store_load_payload_flow | Baseline: `./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.memory.store_load_payload_flow --inject-step 17` | Baseline emitted `sem.memory.store_load_payload_flow`; injected replay reported `semantic_injection_applied = true` and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| me2/me9 | verified | sem.memory.address_alignment_consistency; sem.memory.address_progression_consistency | Baseline: `./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.memory.address_pointer_consistency --inject-step 4` | Baseline emitted both address alignment and address progression buckets; injected replay reported `semantic_injection_applied = true` and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| me3/me4 | verified | sem.memory.load_value_binding; sem.memory.write_payload_consistency | Baseline: `./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.memory.value_payload_consistency --inject-step 13` | Baseline emitted both load-value and write-payload buckets; injected replay reported `semantic_injection_applied = true` and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| me5 | verified | sem.memory.address_space_consistency | Baseline: `./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.memory.address_space_consistency --inject-step 3` | Baseline emitted `sem.memory.address_space_consistency`; injected replay reported `semantic_injection_applied = true` and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| me6 | verified | sem.memory.address_boundary_range | Baseline: `./target/release/beak-trace --bin "200000b7 ff008093 0000a103" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.memory.address_pointer_consistency --inject-step 2` | Baseline emitted `sem.memory.address_boundary_range`; injected replay reported `semantic_injection_applied = true` and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| me10 | verified | sem.memory.kind_selector_consistency | Baseline: `./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.memory.kind_selector_consistency --inject-step 13` | Baseline emitted `sem.memory.kind_selector_consistency`; injected replay reported `semantic_injection_applied = true` and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| ts1/ts3 | verified | sem.time.boundary_origin_consistency | Baseline: `./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.time.boundary_origin_consistency --inject-step 0` | Baseline emitted `sem.time.boundary_origin_consistency`; injected replay reported `semantic_injection_applied = true` and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| ts2.same-address | verified | sem.time.monotonic_access_ordering | Baseline: `./target/release/beak-trace --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.time.monotonic_access_ordering --inject-step 7` | Baseline emitted `sem.time.monotonic_access_ordering`; injected replay reported `semantic_injection_applied = true` and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| o8 | verified | sem.memory.immediate_sign_consistency | Baseline: `./target/release/beak-trace --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" --print-buckets`; injected: same seed with `--inject-kind "openvm.semantic.memory.immediate_sign_consistency::mode=flip_sign,domain=load,guard=none" --inject-step 5` | Baseline emitted `sem.memory.immediate_sign_consistency`; injected replay reported `semantic_injection_applied = true` and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |

OpenVM-336 Control verifier smoke:

| obligation_id | status | semantic_bucket | smoke | result |
|---|---|---|---|---|
| cf1 | verified | sem.exec.control_flow_binding | Baseline: `./target/release/beak-trace --bin "800000b7 00100113 0020c463 00300193" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.exec.control_flow_binding --inject-step 6` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=branch_lt`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| cf2 | verified | sem.exec.control_flow_binding | Baseline: `./target/release/beak-trace --bin "008000ef 00100113 00200193" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.exec.control_flow_binding --inject-step 3` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=jal`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| cf3.clear_lsb | verified | sem.exec.control_flow_binding | Baseline: `./target/release/beak-trace --bin "00d00093 00008067 00500113 00600193" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.exec.control_flow_binding --inject-step 4` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=jalr`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| cf3.even | verified | sem.exec.control_flow_binding | Baseline: `./target/release/beak-trace --bin "00c00093 00008067 00500113 00600193" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.exec.control_flow_binding --inject-step 4` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=jalr`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| cf3.wrap | verified | sem.exec.control_flow_binding | Baseline: `./target/release/beak-trace --bin "fff00093 00908067 00500113 00600193" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.exec.control_flow_binding --inject-step 5` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=jalr`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| cf4 | verified | sem.control.entrypoint_binding | Baseline: `./target/release/beak-trace --bin "00100093" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.control.entrypoint_binding --inject-step 0` | Baseline emitted `sem.control.entrypoint_binding`; injected replay printed the boundary-PC witness mutation, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| cf6 | verified | sem.exec.control_flow_binding | Baseline: `./target/release/beak-trace --bin "00100093 00200113 00208463 00300193" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.exec.control_flow_binding --inject-step 6` | Baseline emitted `sem.exec.control_flow_binding`; injected replay printed `site=branch_eq`, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |
| o7 | verified | sem.control.auipc_pc_limb_consistency | Baseline: `./target/release/beak-trace --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" --print-buckets`; injected: same seed with `--inject-kind "openvm.semantic.control.auipc_pc_limb_consistency::mode=from_pc_high_single_mod_p,slot=1,strength=0,mult=1" --inject-step 3` | Baseline emitted `sem.control.auipc_pc_limb_consistency`; injected replay printed the AUIPC witness mutation, reported `semantic_injection_applied = true`, and printed `UNDERCONSTRAINED CANDIDATE DETECTED`. |

- Smoke/verification: `cargo check` and `cargo test -q` passed in `crates/beak-core/` and
  `projects/openvm-336f1a475e5aa3513c4c5a266399f4128c119bba/` for the first
  implementation batch. The legacy/original o1/o5/o7/o8/o15 mappings above have
  passed baseline+injected verifier smoke and are marked `verified`. ALU and
  arithmetic obligations `al1`-`al5` and `md1`-`md5` also passed targeted
  baseline+injected verifier smoke and are marked `verified`. OpenVM-336
  Memory/Time obligations `me1`, `me2`, `me3`, `me4`, `me5`, `me6`, `me9`,
  `me10`, `ts1`, `ts2.same-address`, and `ts3`, plus the original memory
  immediate-sign bucket `o8`, passed targeted baseline+injected verifier smoke.
  OpenVM-336 Control obligations `cf1`, `cf2`, `cf3` including
  `clear_lsb`/`even`/`wrap`, `cf4`, and `cf6`, plus the AUIPC PC-limb bucket
  `o7`, passed targeted baseline+injected verifier smoke. `cf5`, `cf7`, and
  `cf6.near_segment_end` remain at their documented non-verified statuses.
- 54-obligation mapping snapshot: 37/54 are currently bucket-emitted or
  injection-mapped for OpenVM-336. Remaining trace_missing areas are precise
  ECALL argument values, memory initialization and finalization tables,
  cross-segment timestamp continuity, and prover-level
  bus/padding/table lifecycle rows.

### openvm-d7eab708

- Status: full-completion pass blocked only by documented missing VM evidence /
  replay plumbing; no d7 cells are marked `semantic_injection_mapped` or
  `verified`.
- Owner scope: `projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5/` and
  `beak-py/projects/openvm-fuzzer/`.
- Bucket emission: d7eab708 derives contract-style bucket details for executed
  decode/register/control rows and re-anchored regzero chip rows. Table rows
  are `bucket_emitted` for `rf1`, `rf2`, `rf3`, `id1`-`id5`, `al1`-`al5`,
  `md1`-`md5`, `cf1`, `cf2`, `cf3`, `cf4`,
  `cf6.normal/after_branch_not_taken`, `ts1`, `ts3`, and `pd1`.
- Install-pass note: regzero chip-row emission now copies required `record.*`
  fields before the mutable core-row borrow. Without that copy, tail emission
  read overwritten trace columns and falsely reported DivRem nonzero-divisor
  rows as zero-divisor rows.
- Smoke:
  `cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets`,
  `cargo run -q --bin beak-trace -- --bin "10000093" --print-buckets`, and
  `cargo run -q --bin beak-trace -- --bin "00100113 00200193 00208463 00300193" --print-buckets`
  all emitted the expected semantic buckets and matched oracle registers.
- Additional smokes: ALU/mul/div/control seeds for `al2`-`al5`, `md1`-`md5`,
  `cf2`, and `cf3` emitted their expected buckets. The nonzero DivRem smoke
  `BEAK_OPENVM_DUMP_RAW_LOGS=1 cargo run -q --bin beak-trace -- --bin "000100b7 00001137 0220c1b3" --print-buckets`
  showed true nonzero `b/c` limbs and emitted
  `sem.arithmetic.division_remainder_bound`.
- Injection status: no d7eab708 backend semantic mapping was added. The current
  d7 backend/CLI path has no durable injected replay plumbing or reliable
  applied-site signal, so bucket-emitted rows remain bucket-only under the
  central contract.
- Trace-missing gaps: `me1`-`me11` and `ts2` lack contract-level
  `memory_access`, memory-init, memory-finalization, and same-address timestamp
  lifecycle rows; `cf5`/`cf7` lack syscall argument / raw ECALL observability;
  `cf6.near_segment_end` lacks segment-boundary metadata; `bu1` lacks lookup
  multiplicity rows.

### openvm-f038f61d

- Status: full-completion pass applied for all currently observable OpenVM
  obligations.
- Owner scope: `projects/openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800/` and
  `beak-py/projects/openvm-fuzzer/`.
- Verified with baseline plus injected proof/OOD-failure smokes:
  `al1`-`al5`, `md1`-`md5`, `me1`-`me6`, `me9`, `me10`,
  `me11.written_cells/read_only_cells`, `ts1`, `ts2.same-address`, and `ts3`.
- Bucket-only rows: `rf1`, `rf2`, `id1`-`id5`, `cf1`, `cf2`, `cf3.imm_*`,
  `cf4`, `cf6.normal/after_branch_not_taken`, `me7.bss_zero`, and `pd1`.
  These have baseline trace evidence but no mapped f038 mutation hook, or no
  non-underconstrained hook for the initial-value case.
- Added f038 install hooks for loadstore immediate-sign and persistent memory
  finalization. Replayed `openvm-fuzzer install --commit-or-branch bmk-f038`;
  installed source now contains the f038 immediate-sign/finalization guards.
- Representative f038 smokes: shift/product/memory baseline seeds emitted the
  expected buckets; injected smokes for shift, comparison, SUB, mul/div/mulhsu,
  address-pointer, address-space, payload, kind-selector, store-load,
  monotonic timestamp, immediate-sign, and finalization all reported
  `semantic_injection_applied = true` and failed with
  `ChallengePhaseError` or `OodEvaluationMismatch`.
- Volatile-specific hook status: f038 `volatile_boundary_range` hook applies
  under `BEAK_OPENVM_FORCE_VOLATILE=1` and fails
  `verify_app_proof_without_continuations` with `OodEvaluationMismatch`, but
  the normal derived bucket list did not emit `sem.memory.volatile_boundary_range`
  for the tested seed, so no first-class matrix row is marked verified for it.
- Trace-missing gaps: `me7.rodata/stack_uninit`, `me8.no_conflict`,
  `me8.double_init`, `me11.untouched_cells`, `ts2.cross_segment`,
  `cf3.clear_lsb/even/wrap`, `cf5`, `cf6.near_segment_end`, `cf7`, and `bu1`.
  Reasons are missing ELF/stack provenance, duplicate-init/untouched-cell
  enumeration, segment-boundary metadata, JALR pre-mask target evidence, raw
  ECALL/syscall visibility, or boolean lookup multiplicity rows.

### pico-45e74ccd

- Status: full-completion pass applied for currently observable Pico trace
  sources. Follow-up review found the first injected smokes used unsupported
  `::mode` variants and overreported `injection_applied`; Pico now uses
  base-kind injection only for real hooks.
- Owner scope: `projects/pico-45e74ccd62758c6d67239913956e749adaba261c/` and
  `beak-py/projects/pico-fuzzer/`.
- Trace source: the Pico runner now returns actual executed CPU events
  (`pc`, `next_pc`, chunk/clk, raw RV32 word, Pico opcode, operand values,
  memory value) and `trace.rs` derives instruction-local buckets only from
  those executed events. The synthetic auto-halt appended by the runner is not
  converted into obligation hits.
- Bucket emission: executed-event coverage is present for `rf1`-`rf3`,
  `id1`-`id5`, `al1`-`al5`, `md1`-`md5` when the corresponding runtime
  condition is observed, memory rows `me1`-`me6`, `me9`, `me10`, timestamp
  rows `ts1`, `ts2.same-address`, `ts3`, control rows `cf1`-`cf4`,
  `cf6.normal`, `cf7`, and `bu1.real_row`. Memory address-sensitive buckets use
  runtime operand values from executed Pico CPU events.
- Verified semantic injection mappings with install hooks now cover:
  `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md1`-`md5`, `me1`-`me4`, `me9`,
  `me10`, `ts1`, `ts2.same-address`, `ts3`, `cf1`, `cf2`, `cf3.imm_*`,
  `cf4`, `cf6.normal`, `id4`, and `bu1`. The CPU-row hooks are in
  `vm/src/chips/chips/riscv_cpu/traces.rs::CpuChip::generate_main`; ALU and
  mul/div hooks are in `alu/add_sub`, `alu/sll`, `alu/sr`, `alu/lt`,
  `alu/mul`, and `alu/divrem` trace generation; memory hooks are in
  `riscv_memory/read_write/traces.rs::MemoryReadWriteChip::generate_main`; the
  boolean lookup hook mutates `is_real_shadow` in local memory trace rows.
  Injected smokes reported source-site `semantic_injection_applied=true` and
  verifier rejection.
- Mapped but not verified: `me6` / `sem.memory.address_boundary_range` maps to
  `pico.semantic.memory.address_boundary_range` at the same read/write memory
  row `addr_word` mutation point. The direct hook smoke applied and failed
  proof verification, but no baseline high-address boundary bucket smoke was
  recorded in this pass.
- Bucket-only rows with no real Pico mutation hook: `me5` /
  `sem.memory.address_space_consistency` and `cf7` /
  `sem.control.ecall_word_validity`. Pico read/write memory rows expose
  load/store kind and address words, but not a VM address-space selector to
  mutate for `me5`. ECALL remains bucket-only because the inspected Pico prover
  source exposes transpiled `Instruction`/ECALL selector rows, not the raw RV32
  `0x00000073` word needed for a faithful ECALL-word-validity mutation.
- Smoke: baseline direct runner for
  `[0x04000093,0x07f00113,0x0020a023,0x0000a183]` returned
  `prove_ok=true`, `verify_ok=true`, and observed injection sites for boolean
  multiplicity and timestamped load path. Injected base-kind smokes at step 0
  for `pico.semantic.memory.timestamped_load_path` and
  `pico.semantic.lookup.boolean_multiplicity` both reported
  source-site `semantic_injection_applied=true` and failed with
  `Constraint verification failed`. Selector baseline
  `cargo run -q --bin beak-trace -- --bin "00100093" --print-buckets` emitted
  `sem.exec.op_selector_binding`; injected selector smoke with
  `--inject-kind pico.semantic.exec.op_selector_binding --inject-step 0`
  reported `semantic_injection_applied=true` and failed with
  `Regional cumulative sum is not zero`. Unsupported variants now return
  `injection_applied=false` with an unsupported variant error.
- Trace-missing / unsupported gaps: `me7`, `me8`, and `me11` were inspected in
  `vm/src/chips/chips/riscv_memory/initialize_finalize/traces.rs`,
  `local/traces.rs`, and `read_write/traces.rs`; missing mutation points are
  durable initial provenance, duplicate-init-before-coalescing, and an
  untouched final-memory universe. `ts2.cross_segment` and
  `cf6.near_segment_end` need segment boundary metadata not present in the
  Pico `EmulationRecord`/CPU events. `cf3.clear_lsb/even/wrap` need
  target-before/after-LSB-clear details beyond the current `trace.rs::cf3_cell`
  immediate cells. `cf5` needs syscall argument/register records from
  `riscv_cpu/ecall/traces.rs`, and `cf7` needs a raw RV32 program-word column
  rather than the transpiled ECALL selector. `pd1` and broader `bu2`-`bu6` need
  prover table, padding row, transcript, or LogUp/cumsum visibility not exposed
  by the current Pico runner.

### sp1-7f643da1

- Status: full-completion pass completed for currently observable SP1 evidence.
  Instruction-local buckets are derived from SP1 `ExecutionRecord.cpu_events`
  and raw words are resolved by executed PC, so unexecuted input words do not
  emit obligation hits.
- Bucket-emitted from executed instruction trace with contract details:
  `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md3`-`md5`,
  `cf1`-`cf4`, `cf6.normal/after_branch_not_taken`, `cf7`,
  `ts1.standard`, `ts3.standard`, memory shape buckets `me2`, `me3`,
  `me4`, `me9`, `me10`, and padding short-trace `pd1`.
- Verified SP1 semantic injection mappings with real install hooks:
  `sem.exec.memory_effect_binding` maps to
  `sp1.semantic.exec.memory_effect_binding`; baseline
  `cargo run -q --bin beak-trace -- --bin "00012183" --print-buckets`
  emitted `sem.exec.memory_effect_binding`, and injected
  `cargo run -q --bin beak-trace -- --bin "00012183" --inject-kind sp1.semantic.exec.memory_effect_binding --inject-step 0 --print-buckets`
  reported `semantic_injection_applied = true` with oracle/SP1 registers
  matching.
- Verified SP1 timestamp hook replay:
  `sem.memory.timestamped_load_path` maps to
  `sp1.semantic.memory.timestamped_load_path`; injected replay on `00012183`
  with `--inject-step 0` reported `semantic_injection_applied = true`.
- Verified SP1 control-flow hook replay:
  `sem.exec.control_flow_binding` maps to
  `sp1.semantic.exec.control_flow_binding`; injected replay
  `cargo run -q --bin beak-trace -- --bin "00100093 00108463 00200113" --inject-kind sp1.semantic.exec.control_flow_binding --inject-step 1 --print-buckets`
  emitted control-flow buckets and reported `semantic_injection_applied = true`.
- Install patch available but not verified:
  `sem.lookup.boolean_multiplicity` maps to
  `sp1.semantic.lookup.boolean_multiplicity`, and the SP1 install pass has a
  memory write-record hook. Store/load smoke
  `cargo run -q --bin beak-trace -- --bin "00002023 00002083" --inject-kind sp1.semantic.lookup.boolean_multiplicity --inject-step 0 --print-buckets`
  panicked in the installed SP1 memory timestamp ordering assertion before
  buckets/final regs, so this remains `install_patch_available`.
- Trace-missing or unsupported cells:
  `md1`/`md2` exact div-by-zero and signed-overflow cells need per-step operand
  values; most `me1`, `me5`-`me8`, `me11`, `ts2.cross_segment`, `cf5`,
  `cf6.near_segment_end`, `cf3.clear_lsb/even/wrap`, `rc1`-`rc4`,
  `bu2`-`bu6`, and `pd2`-`pd5` need real SP1 memory address/value/provenance
  records, memory init/finalization rows, syscall argument values,
  range-check/flag decomposition rows, bus/permutation rows, transcript data,
  or segment/table lifecycle metadata that this target trace does not expose.
- Verification commands and results are recorded in
  `agent_runs/vm-distributed/lead-sp1-7f643da1.md`.

### sp1-811a3f2c

- Status: install-completion pass verified SP1-811 CPU-row semantic hooks for
  RF/decode buckets with currently observable SP1 evidence. Instruction-local
  buckets are derived from SP1 `ExecutionRecord.cpu_events` and raw words are
  resolved by executed PC through the target program, so unexecuted input words
  do not emit obligation hits.
- Bucket-emitted from executed instruction trace with contract details:
  verified injection rows for `rf1`-`rf3`, `id1`, `id2`, `id4`, and `id5`;
  bucket-only coverage remains for `id3`, `al1`-`al5`, `md3`-`md5`, `cf4`,
  `cf7`, `ts1`, `ts2.same-record`, `ts3`, memory-shape buckets `me2`, `me3`,
  `me4`, `me9`, `me10`, and padding short-trace `pd1`.
- Verified CPU-row semantic injection mappings with real installed hooks in
  `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`:
  `sem.decode.zero_register_immutability` ->
  `sp1.semantic.decode.zero_register_immutability::site=op_a_access`
  (baseline `00100013`, injected replay reported
  `semantic_injection_applied = true` with proof rejection);
  `sem.decode.operand_index_routing` ->
  `sp1.semantic.decode.operand_index_routing::site=op_b_access`;
  `sem.exec.dest_binding` -> `sp1.semantic.exec.dest_binding::site=op_a_access`;
  `sem.decode.field_range` ->
  `sp1.semantic.decode.field_range::site=instruction_op_a`;
  `sem.decode.immediate_sign_extension` ->
  `sp1.semantic.decode.immediate_sign_extension::site=instruction_op_c`;
  `sem.exec.op_selector_binding` ->
  `sp1.semantic.exec.op_selector_binding::site=opcode`; and
  `sem.decode.format_immediate_reassembly` ->
  `sp1.semantic.decode.format_immediate_reassembly::site=instruction_op_c`.
  Baselines `00100093` and `00100093 00108463 00200113` emitted the relevant
  buckets, and all injected replays reported `semantic_injection_applied = true`.
- Verified SP1 semantic injection mappings with real installed hooks:
  `sem.exec.memory_effect_binding` maps to
  `sp1.semantic.exec.memory_effect_binding`; baseline
  `./target/debug/beak-trace --bin "04000093 0000a183" --print-buckets`
  emitted `sem.exec.memory_effect_binding`, and injected
  `./target/debug/beak-trace --bin "04000093 0000a183" --inject-kind sp1.semantic.exec.memory_effect_binding --inject-step 18446744073709551615 --print-buckets`
  reported `semantic_injection_applied = true` with oracle/SP1 registers
  matching. The concrete witness step for that load row is `2` because the
  earlier memory-effect hook consumes one witness step per CPU row before the
  CPU semantic hook.
- Verified control-flow hook replay:
  `sem.exec.control_flow_binding` maps to
  `sp1.semantic.exec.control_flow_binding`; injected replay
  `./target/debug/beak-trace --bin "00100093 00108463 00200113" --inject-kind "sp1.semantic.exec.control_flow_binding::family=branch" --inject-step 1 --print-buckets`
  emitted control-flow buckets and reported `semantic_injection_applied = true`.
- Conservative injection status: timestamp/lookup runtime hooks from older SP1
  passes are not present in this installed 811a3f2c source, so the backend does
  not expose candidates for `sem.memory.timestamped_load_path` or
  `sem.lookup.boolean_multiplicity`. Bus/lookup remains `trace_missing`.
- Trace-missing or unsupported cells: `md1`/`md2` exact div-by-zero and
  signed-overflow cells need per-step operand values; address/value-sensitive
  memory cells (`me1`, `me5`, `me6`, most `me7`, `me8`, `me11`) need real SP1
  memory address/value/provenance and finalization records; `ts2.cross_segment`,
  `cf5`, `cf6.near_segment_end`, range-check/bus/permutation/transcript rows,
  and broad padding lifecycle cells need VM evidence not exposed by this target.
- Verification commands and results are recorded in
  `agent_runs/vm-distributed/lead-sp1-811a3f2c.md`.

### sp1-3561f006

- Status: central executed-trace bucket pass completed for currently observable
  evidence in the older SP1 layout. Instruction-local buckets are derived from
  SP1 `Runtime` `ExecutionRecord.cpu_events`; RV32 words are resolved by the
  executed PC and no unexecuted input words emit obligation hits.
- Bucket-emitted from executed instruction trace with contract details:
  `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md3`-`md5`,
  `cf1`-`cf4`, `cf6.normal/after_branch_not_taken`, `cf7`,
  `ts1.standard`, `ts3.standard`, memory shape buckets `me2`, `me3`,
  `me4`, `me9`, `me10`, and padding short-trace `pd1`.
- Verified SP1-356 CPU-row semantic injection mappings with a real installed
  hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`:
  `sem.decode.zero_register_immutability`,
  `sem.decode.operand_index_routing`, `sem.exec.dest_binding`,
  `sem.decode.field_range`, `sem.decode.immediate_sign_extension`,
  `sem.exec.op_selector_binding`, and
  `sem.decode.format_immediate_reassembly`. Baselines `00100013`,
  `00012183`, and `00100093 00108463 00200113` emitted the relevant buckets;
  injected replays with the matching `sp1.semantic.*::site=...` kinds reported
  `semantic_injection_applied = true`.
- Existing installed SP1 hooks for
  `sp1.semantic.memory.timestamped_load_path` and
  `sp1.semantic.lookup.boolean_multiplicity` remain conservative:
  the old `fuzzer_utils` hook path can mutate witness records but does not
  report applied-site metadata to the project backend, so central backend
  candidates stay disabled for those memory/lookup buckets.
- The legacy uint256-div reproducer path is still present for
  `sp1.semantic.arithmetic.division_remainder_bound`, but it is a precompile
  scenario rather than a central RV32IM `md3` witness mapping and is not used
  to upgrade central matrix cells.
- Trace-missing or unsupported cells:
  `md1`/`md2` exact div-by-zero and signed-overflow cells need per-step operand
  values; most address/value/provenance-sensitive memory cells (`me1`,
  `me5`-`me8`, `me11`), `ts2.cross_segment`, `cf5`,
  `cf6.near_segment_end`, `cf3.clear_lsb/even/wrap`, `rc1`-`rc4`,
  `bu2`-`bu6`, and `pd2`-`pd5` need memory access/init/finalization rows,
  syscall argument values, target-before-LSB-clear fields, range/decomposition
  rows, bus/permutation rows, transcript data, or segment/table lifecycle
  metadata not exposed by this snapshot.
- Verification commands and results are recorded in
  `agent_runs/vm-distributed/lead-sp1-3561f006.md`.

### sp1-fb38df2c

- Status: central RV32 obligation implementation is not applicable to this
  snapshot as currently integrated. `sp1-fb38df2c` is the historical SP1
  recursion runner, not a generic RV32 SP1 backend.
- Matrix status: RV32 instruction, register, ALU/muldiv, memory, and control
  cells are marked `unsupported` because the runner executes
  `sp1_recursion_core::runtime::Instruction` programs with recursion opcodes
  such as `LOAD`, `JAL`, and `BNEINC`, not RV32IM words. Emitting central
  `rf*`/`id*`/`al*`/`md*`/`me*`/`cf*` buckets from those records would not
  satisfy the executed-RV32-instruction contract.
- Trace-missing status: `ts1`-`ts3`, `bu1`, and `pd1` remain
  `trace_missing`. The recursion AIR has timestamp/table concepts, but this
  project has no `trace.rs`, no `BucketHit` path, no `BenchmarkBackend`
  semantic candidate mapping, and no durable central table/row emission.
- Existing durable hooks are legacy-only:
  `sp1.legacy_recursion.memory.load_binding`,
  `sp1.legacy_recursion.exec.jump_binding`, and
  `sp1.legacy_recursion.exec.bneinc_upper_limbs`. These are real
  install-pass hooks in `pass5_legacy_recursion.py`, but they are not central
  `sem.*` obligation mappings and do not report contract-complete applied-site
  metadata.
- Verification and command results are recorded in
  `agent_runs/vm-distributed/lead-sp1-fb38df2c.md`.

### sp1 snapshots

- Status: other SP1 snapshots not covered here remain as recorded in their
  commit-specific notes.
- Owner scope: the specific `projects/sp1-<commit>/` snapshot and
  `beak-py/projects/sp1-fuzzer/`.

### jolt-e9caa235

- Status: broad executed-row bucket pass complete for currently observable
  Jolt `RVTraceRow` evidence. Instruction-local hits come only from rows whose
  executed PC maps back to the input program.
- Bucket emission: `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md1`-`md5`,
  `cf1`-`cf4`, `cf6.normal/after_branch_not_taken`, `ts1.standard`,
  `ts3.standard`, and Jolt memory-shape buckets `me2`, `me3`, `me4`, `me9`,
  and `me10` when the matching executed memory row is present.
- Injection status: `id3`, `cf1`, and `cf4` are now
  `semantic_injection_mapped`. The Jolt install pass patches
  `jolt-core/src/host/mod.rs::Program::trace` to mutate processed
  `JoltTraceStep` witness inputs and set
  `BEAK_JOLT_WITNESS_INJECTION_APPLIED`; `backend.rs` maps only matching
  observed baseline buckets. They are not `verified` because baseline and
  injected prover smokes still hit the known
  `read_write_memory.rs` out-of-bounds panic before verification.
- Remaining bucket-only groups inspected:
  `jolt-core/src/jolt/vm/instruction_lookups.rs::generate_witness`
  materializes instruction flags, subtable lookups, and lookup outputs from the
  generic processed trace, but no narrow install hook was added yet for
  register/decode/ALU/muldiv cells beyond the LUI and branch variants above.
  `jolt-core/src/jolt/vm/bytecode.rs::generate_witness` exposes bytecode
  rd/rs1/rs2/imm columns, but mapping those rows still needs a cell-specific
  mutation design. `jolt-core/src/jolt/vm/read_write_memory.rs::generate_witness`
  exposes memory values/timestamps, but the current harness panics in that
  module before verifier evidence is available.
- Trace-missing gaps: store-load payload flow (`me1`) lacks a valid same-address
  store-then-load path in the current Jolt public I/O memory model; `me5`-`me8`,
  `me11`, `ts2`, `cf5`, `cf6.near_segment_end`, `cf7`, bus/lookup, and padding
  rows need address-space selectors, init/finalization/provenance, timestamps,
  syscall arguments, raw ECALL execution, segment boundaries, or prover table
  evidence not exposed by the current target trace.
- Smoke evidence and command results are recorded in
  `agent_runs/vm-distributed/lead-jolt-e9caa235.md`.
- Owner scope: `projects/jolt-e9caa23565dbb13019afe61a2c95f51d1999e286/` and
  `beak-py/projects/jolt-fuzzer/`.

### nexus-636ccb36

- Status: expanded bucket pass complete for currently observable Nexus
  `UniformTrace` evidence; memory buckets `me1`, `me4`, and `me10` are now
  verified through real installed-source load/store prover hooks.
- Owner scope: `projects/nexus-636ccb360d0f4ae657ae4bb64e1e275ccec8826/` and
  `beak-py/projects/nexus-fuzzer/`.
- Bucket emission now comes from executed Nexus `UniformTrace` steps and memory
  records, not raw unexecuted input words. Covered groups:
  `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md1`-`md5`, `me1`-`me7`,
  `me9`, `me10`, `ts1`-`ts3` same-address cells, and `cf1`-`cf6`.
- Backend candidate mapping for the old local Nexus trace-rewrite experiment
  remains disabled. The current contract-valid mappings are
  `nexus.semantic.memory.store_load_payload_flow`,
  `nexus.semantic.memory.write_payload_consistency`, and
  `nexus.semantic.memory.kind_selector_consistency`; pass3 patches
  `prover/src/chips/instructions/load_store.rs::LoadStoreChip::fill_main_trace`
  and reports applied-site evidence through
  `BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED` plus backend
  `injection_applied = true`.
- Smoke highlights: broad decode/ALU/control seed
  `00100093 00200113 002081b3 40218233 0020c463 00300293 00500313`
  emitted 50 hits; memory seed `00100093 00112023 00012183` emitted
  `me1`/`me5`/`me10`/`ts2`; subword/sign seed
  `08000093 00110023 00010183` emitted `me2`/`me3`/`me4`/`me9`; boundary
  seed `fff00093 ffd0a103` emitted `me6`. All matched oracle registers.
- Verified Nexus memory injection smokes: `me1` injected
  `nexus.semantic.memory.store_load_payload_flow` at step 1 and mutated
  `Ram1ValCur`; `me4` injected
  `nexus.semantic.memory.write_payload_consistency` at step 1 and mutated
  `Ram1ValPrev`; `me10` injected
  `nexus.semantic.memory.kind_selector_consistency` at step 1 and flipped a
  load/store selector. Each replay printed
  `BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED`, reported
  `injection_applied = true`, and failed proof/verification as expected.
- Remaining trace-missing gaps: `me7.rodata/stack`, `me8`, `me11`,
  `ts2.cross_segment`, `cf5`, `cf6.near_segment_end`, `cf7`, `bu1`, and
  `pd1` need syscall, ELF/provenance, finalization, segment-boundary, or
  prover/table rows not exposed by the current Nexus trace.
- Missing concrete mutation points for future injection: decode/register/ALU,
  mul/div, and control buckets still need installed-source hooks under
  `prover/src/chips/instructions/*`; timestamp/order rows need hooks under
  `prover/src/chips/memory_check/{timestamp,program_mem_check,register_mem_check}.rs`;
  bus/lookup/padding remain blocked on table/padding interaction visibility.

### risc0 snapshots

- `risc0-98387806`: obligation pass completed to current Risc0 visibility.
  Instruction-local buckets now come from executed RV32IM oracle steps under the
  Risc0 split code/data layout; a raw ECALL at the next sequential PC is added
  because Risc0 handles it through host syscall flow while the shared oracle
  stops before ECALL.
- Verified semantic mappings with baseline plus applied injected smoke:
  `sem.decode.zero_register_immutability`,
  `sem.decode.operand_index_routing`, `sem.exec.op_selector_binding`,
  `sem.arithmetic.division_remainder_bound`, and
  `sem.control.ecall_argument_decomposition`.
- Bucket-only executed-instruction coverage: `rf3`, `id1`-`id3`, `id5`,
  `al1`-`al5`, `md1`, `md2`, `md4`, `md5`, `me10`, `cf1`-`cf4`, `cf7`, `ts1`,
  `ts3`, and `rc1.alu_result`. Risc0 now includes AL2 `rs2 >= 32` shift cells
  and JALR target cells from executed register state when observed. `rf3`/`rc1`,
  `sem.exec.control_flow_binding`, and `sem.exec.memory_effect_binding` have
  Risc0 asset hooks or emitted buckets but are not backend-mapped because smoke
  did not satisfy the contract: dest-binding panicked, control-flow reported
  `injection_applied=false` or baseline witness-generation failure on a JALR
  target seed, and memory seeds hit Risc0 access faults.
- Trace-missing gaps for `risc0-98387806`: address/value/provenance memory
  obligations `me1`-`me9`, `me11`, same-address and cross-segment timestamp
  ordering `ts2`, `cf6.near_segment_end`, bus/lookup rows, and padding
  lifecycle rows need Risc0 prover/table evidence not currently exposed.
- Smoke evidence is recorded in
  `agent_runs/vm-distributed/lead-risc0-98387806.md`.
- `risc0-c0db0713`: obligation pass ported the Risc0 executed-instruction
  trace path to the legacy commit. Instruction-local buckets now come from
  executed RV32IM oracle steps under the Risc0 split code/data layout, with
  contract details including `backend`, full commit, `trace_source`, `op_idx`,
  `pc`, `opcode`, `mnemonic`, operands, runtime operand values, and ECALL
  `a0`/`a1`/`a7` when available.
- Verified c0db semantic mappings with baseline plus applied injected smoke:
  `sem.decode.operand_index_routing`,
  `sem.arithmetic.division_remainder_bound`, and
  `sem.control.ecall_argument_decomposition`. The legacy c0db prover asset also
  contains hooks for zero-register and rd-bit mutations, but the target backend
  keeps those unmapped because injected replay is blocked by a SIGFPE-prone
  prover path.
- Bucket-only c0db executed-instruction coverage: `rf3`, `id1`-`id5`,
  `al1`-`al5`, `md1`, `md2`, `md4`, `md5`, `me10`, `cf1`-`cf4`, `cf6`,
  `cf7`, `ts1`, `ts3`, and `rc1.alu_result`. JALR clear-LSB target cells are
  not claimed for c0db because the representative JALR backend smoke terminated
  before bucket output.
- Trace-missing c0db gaps: address/value/provenance memory obligations
  `me1`-`me9` except `me10`, memory finalization `me11`, same-address and
  cross-segment timestamp ordering `ts2`, JALR target clear-LSB/even/wrap cells,
  `cf6.near_segment_end`, bus/lookup rows, and padding lifecycle rows.
- Smoke evidence is recorded in
  `agent_runs/vm-distributed/lead-risc0-c0db0713.md`.
- Owner scope: the specific `projects/risc0-<commit>/` snapshot and
  `beak-py/projects/risc0-fuzzer/`.
