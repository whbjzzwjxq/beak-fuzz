# Obligation Implementation Matrix

This matrix tracks how `docs/OBLIGATIONS.md` is implemented across VM
snapshots. See `docs/OBLIGATION_IMPLEMENTATION_CONTRACT.md` for the required
naming, details schema, injection hooks, and status values.

Status values:

`not_started`, `trace_missing`, `trace_observable`, `bucket_emitted`,
`semantic_injection_mapped`, `install_patch_available`, `verified`,
`unsupported`, `legacy_rejected`.

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
| rf1 | rf1.alu_r | sem.decode.zero_register_immutability | op_idx, pc, opcode, mnemonic, rd, write_source | verified | bucket_emitted | bucket_emitted | verified | semantic_injection_mapped | verified | verified | verified | unsupported | verified | semantic_injection_mapped | verified | install_patch_available | `openvm.semantic.decode.zero_register_immutability` | Baseline: `cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.decode.zero_register_immutability --inject-step 0`; injected replay reported `semantic_injection_applied = true` and `verify_app_proof failed: ChallengePhaseError`. | OpenVM-336 emits decoded RF1 write-source cells when observed; 336 install pass mutates the program table operand `a` for targeted decoded instruction rows. OpenVM-f038 emits this bucket from executed instruction trace only; no f038 program-table mutation hook is mapped. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012003 --print-buckets` emitted the bucket and injected `sp1.semantic.decode.zero_register_immutability::site=op_a_access` reported `semantic_injection_applied = true` with proof rejection recorded in `../agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `../agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| rf2 | rf2.rs1_eq_rs2 | sem.decode.operand_index_routing | op_idx, pc, opcode, mnemonic, rs1, rs2, rd | verified | bucket_emitted | bucket_emitted | verified | semantic_injection_mapped | verified | verified | verified | unsupported | verified | semantic_injection_mapped | verified | verified | `openvm.semantic.decode.operand_index_routing` | Baseline: `cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.decode.operand_index_routing --inject-step 0`; injected replay printed the program-table mutation and reported `semantic_injection_applied = true` / `verify_app_proof failed: ChallengePhaseError`. | OpenVM-336 emits alias cells from decoded RV32IM operands; 336 install pass mutates the program table operand `b` for targeted decoded instruction rows. OpenVM-f038 emits this bucket from executed instruction trace only; no f038 program-table mutation hook is mapped. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012183 --print-buckets` emitted the bucket and injected `sp1.semantic.decode.operand_index_routing::site=op_b_access` reported `semantic_injection_applied = true` in `../agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `../agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| rf3 | rf3.alu/rf3.load/rf3.link/rf3.upper/rf3.muldiv | sem.exec.dest_binding | op_idx, pc, opcode, mnemonic, rd, write_source | bucket_emitted | bucket_emitted | bucket_emitted | verified | semantic_injection_mapped | verified | verified | verified | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted |  | d7 baseline examples: `cargo run -q --bin beak-trace -- --bin "10000093" --print-buckets`; load/muldiv/link/upper cells need matching executed instructions. | d7 emits decoded writeback-source cells from executed instruction trace; no d7 mutation hook/applied-site replay plumbing is mapped. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012183 --print-buckets` emitted the bucket and injected `sp1.semantic.exec.dest_binding::site=op_a_access` reported `semantic_injection_applied = true` with proof rejection recorded in `../agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `../agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| id1 | id1.reg_zero/id1.reg_max/id1.reg_mid/id1.funct_max | sem.decode.field_range | op_idx, pc, opcode, mnemonic, rd, rs1, rs2, funct3, funct7 | bucket_emitted | bucket_emitted | bucket_emitted | verified | semantic_injection_mapped | verified | verified | verified | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted |  | d7 baseline examples: `cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets`. | d7 emits field-range cells from executed decoded RV32IM words; no d7 decode/program-table hook is mapped. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012183 --print-buckets` emitted the bucket and injected `sp1.semantic.decode.field_range::site=instruction_op_a` reported `semantic_injection_applied = true` in `../agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `../agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| id2 | id2.i_pos/id2.i_neg/id2.s_pos/id2.s_neg/id2.b_pos/id2.b_neg/id2.j_pos/id2.j_neg | sem.decode.immediate_sign_extension | op_idx, pc, opcode, mnemonic, imm | bucket_emitted | bucket_emitted | bucket_emitted | verified | semantic_injection_mapped | verified | verified | verified | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted |  | d7 baseline examples: `cargo run -q --bin beak-trace -- --bin "008000ef 00100113 00200193" --print-buckets`. | d7 emits sign-extension cells from executed decoded immediates; no d7 immediate mutation hook is mapped. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012183 --print-buckets` emitted the bucket and injected `sp1.semantic.decode.immediate_sign_extension::site=instruction_op_c` reported `semantic_injection_applied = true` in `../agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `../agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| id3 | id3.lui_zero/id3.lui_max/id3.lui_mid/id3.auipc_no_wrap/id3.auipc_wrap | sem.decode.upper_immediate_materialization; sem.control.auipc_pc_limb_consistency | op_idx, pc, opcode, mnemonic, imm, rd | semantic_injection_mapped | semantic_injection_mapped | bucket_emitted | verified | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.control.auipc_pc_limb_consistency` for OpenVM d7/336; `jolt.semantic.decode.upper_immediate_materialization` for Jolt | d7 baseline/injected: `./target/debug/beak-trace --bin "00200313 0ff00793 00002297 e6c28293 0002c703 0ff00393 00774533" --inject-kind openvm.semantic.control.auipc_pc_limb_consistency --inject-step 18446744073709551615 --print-buckets` emitted `sem.control.auipc_pc_limb_consistency` and reported `semantic_injection_applied = true`. Jolt baseline: `cargo run -q --bin beak-trace -- --bin 123450b7 --print-buckets` emitted `sem.decode.upper_immediate_materialization`; injected Jolt smoke with `--inject-kind jolt.semantic.decode.upper_immediate_materialization --inject-step 18446744073709551615` reported `injection_applied = true` but still hit the known Jolt memory panic, so not verified. | d7 emits LUI/AUIPC upper-immediate buckets from executed trace; only the AUIPC PC-limb sub-bucket is mapped, via `extensions/rv32im/circuit/src/auipc/core.rs::fill_trace_row` mutating `pc_limbs`. Program-table LUI/operand mutation remains unavailable. Jolt emits LUI/AUIPC cells only from executed `RVTraceRow`s whose PC maps back to the input program; Jolt install pass mutates the processed `JoltTraceStep.instruction_lookup` virtual advice value in `jolt-core/src/host/mod.rs::Program::trace` and backend maps observed `id3` hits. |
| id4 | id4.alu_r/id4.alu_i/id4.load/id4.store/id4.branch/id4.jal/id4.jalr/id4.lui/id4.auipc/id4.ecall/id4.mul/id4.div | sem.exec.op_selector_binding | op_idx, pc, opcode, mnemonic | bucket_emitted | bucket_emitted | bucket_emitted | verified | semantic_injection_mapped | verified | verified | verified | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted |  | d7 baseline examples: `cargo run -q --bin beak-trace -- --bin "00100013" --print-buckets`. | d7 emits opcode-class selector cells from executed instruction trace. Raw RV ECALL is not observable for d7 because it transpiles to `unimp`; that cell remains covered by the cf5/cf7 trace-missing notes. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00012183 --print-buckets` emitted the bucket and injected `sp1.semantic.exec.op_selector_binding::site=opcode` reported `semantic_injection_applied = true` in `../agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `../agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| id5 | id5.s_type/id5.b_type/id5.j_type/id5.cross_field | sem.decode.format_immediate_reassembly | op_idx, pc, opcode, mnemonic, imm | verified | bucket_emitted | bucket_emitted | verified | semantic_injection_mapped | verified | verified | verified | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.decode.format_immediate_reassembly` | Baseline: `cargo run -q --bin beak-trace -- --bin "00100113 00200193 00208463 00300193" --print-buckets`; injected: same seed with `--inject-kind openvm.semantic.decode.format_immediate_reassembly --inject-step 2`; injected replay printed `pc=8`, reported `semantic_injection_applied = true`, and failed proof with `ChallengePhaseError`. | OpenVM-336 emits decoded S/B/J scattered immediate cells; 336 install pass mutates the program table operand `c` for targeted decoded instruction rows. OpenVM-f038 emits this bucket from executed instruction trace only; no f038 program-table mutation hook is mapped. I-immediate limb coverage is tracked as AL1. SP1-7 verified via CPU-row witness hook in `crates/core/machine/src/cpu/trace.rs::CpuChip::event_to_row`; baseline `00100093 00108463 00200113 --print-buckets` emitted the bucket and injected `sp1.semantic.decode.format_immediate_reassembly::site=instruction_op_c` reported `semantic_injection_applied = true` in `../agent_runs/vm-distributed/lead-sp1-7f643da1.md`. SP1-356 verified via 356-only CPU-row hook in `core/src/cpu/trace.rs::CpuChip::event_to_row`; baseline and injected smoke results are recorded in `../agent_runs/vm-distributed/lead-sp1-3561f006.md`. |
| al1 | al1.single_limb/al1.cross_01/al1.negative/al1.boundary | sem.alu.immediate_limb_consistency | op_idx, pc, opcode, mnemonic, imm | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.alu.immediate_limb_consistency`; `sp1.semantic.alu.immediate_limb_consistency` | d7 baseline/injected: `./target/debug/beak-trace --bin "10000093" --inject-kind openvm.semantic.alu.immediate_limb_consistency --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `../agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.c[0]` in `extensions/rv32im/circuit/src/base_alu/core.rs::fill_trace_row`; OpenVM-336 emits decoded I-ALU immediate limb cells and mutates adapter immediate limbs in `adapters/alu.rs`. SP1 7/811/356: shared install pass `pass4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| al2 | al2.sll_lt32/al2.sll_ge32/al2.srl_lt32/al2.srl_ge32/al2.sra_*/al2.shamt_zero | sem.alu.shift_mod32 | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, effective_shamt | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.alu.shift_mod32`; `sp1.semantic.alu.shift_mod32` | d7 baseline `./target/debug/beak-trace --bin "000010b7 00002137 002091b3" --print-buckets` emitted `sem.alu.shift_mod32`; injected same seed with `--inject-kind openvm.semantic.alu.shift_mod32 --inject-step 18446744073709551615` reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `../agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.a[0]` in `extensions/rv32im/circuit/src/shift/core.rs::fill_trace_row`; OpenVM-336 emits Shift chip rows and mutates the shift output limb in `shift/core.rs`. SP1 7/811/356: shared install pass `pass4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| al3 | al3.slt_true/al3.slt_false/al3.sltu_true/al3.sltu_false/al3.equal/al3.sign_disagree | sem.alu.comparison_booleanity | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rd_val, rs1_val, rs2_or_imm_val | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.alu.comparison_booleanity`; `sp1.semantic.alu.comparison_booleanity` | d7 baseline `./target/debug/beak-trace --bin "800000b7 00001137 0020a1b3" --print-buckets` emitted `sem.alu.comparison_booleanity`; injected same seed with `--inject-kind openvm.semantic.alu.comparison_booleanity --inject-step 18446744073709551615` reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `../agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 flips `core_row.cmp_result` in `extensions/rv32im/circuit/src/less_than/core.rs::fill_trace_row`; OpenVM-336 emits LessThan chip rows and flips the comparison result column in `less_than/core.rs`. SP1 7/811/356: shared install pass `pass4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| al4 | al4.no_borrow/al4.borrow/al4.equal/al4.cross_limb | sem.alu.subtraction_borrow_chain | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.alu.subtraction_borrow_chain`; `sp1.semantic.alu.subtraction_borrow_chain` | d7 injected smoke `./target/debug/beak-trace --bin "000010b7 00002137 402081b3" --inject-kind openvm.semantic.alu.subtraction_borrow_chain --inject-step 18446744073709551615 --print-buckets` emitted `sem.alu.subtraction_borrow_chain` and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `../agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.a[0]` for SUB in `extensions/rv32im/circuit/src/base_alu/core.rs::fill_trace_row`; OpenVM-336 emits BaseAlu SUB rows and mutates the SUB result limb in `base_alu/core.rs`. SP1 7/811/356: shared install pass `pass4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| al5 | al5.first_limb_diff/al5.last_limb_diff/al5.all_equal/al5.alternating_borrow | sem.alu.comparison_auxiliary_chain | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.alu.comparison_auxiliary_chain`; `sp1.semantic.alu.comparison_auxiliary_chain` | d7 injected smoke `./target/debug/beak-trace --bin "800000b7 00001137 0020a1b3" --inject-kind openvm.semantic.alu.comparison_auxiliary_chain --inject-step 18446744073709551615 --print-buckets` emitted `sem.alu.comparison_auxiliary_chain` and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `../agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.diff_marker[0]` in `extensions/rv32im/circuit/src/less_than/core.rs::fill_trace_row`; OpenVM-336 emits LessThan comparison aux rows and mutates `diff_val`/`diff_marker` in `less_than/core.rs`. SP1 7/811/356: shared install pass `pass4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| md1 | md1.div_zero/md1.divu_zero/md1.rem_zero/md1.remu_zero/md1.dividend_* | sem.arithmetic.special_case_consistency | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, rd_val | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | verified | bucket_emitted | verified | bucket_emitted | `openvm.semantic.arithmetic.special_case_consistency`; `sp1.semantic.arithmetic.special_case_consistency` | d7 injected smoke `./target/debug/beak-trace --bin "000010b7 0200c1b3" --inject-kind openvm.semantic.arithmetic.special_case_consistency --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `../agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.q[0]` in `extensions/rv32im/circuit/src/divrem/core.rs::fill_trace_row`; OpenVM-336 emits div-by-zero cells from executed DivRem chip rows; reuses existing special-case injection hook. SP1 7/811/356: shared install pass `pass4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| md2 | md2.div_overflow/md2.rem_overflow | sem.arithmetic.special_case_consistency | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, rd_val | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | install_patch_available | bucket_emitted | verified | bucket_emitted | `openvm.semantic.arithmetic.special_case_consistency`; `sp1.semantic.arithmetic.special_case_consistency` | d7 uses the same DivRem special-case hook as md1; targeted div-by-zero smoke reported `semantic_injection_applied = true`, and overflow cells use the same concrete `divrem/core.rs::fill_trace_row` mutation point. SP1 7/811/356 chip-hook smokes are recorded in `../agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | OpenVM-336 emits signed DIV/REM overflow cells from executed DivRem chip rows; reuses existing special-case injection hook. SP1 7/811/356: shared install pass `pass4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| md3 | md3.pp/md3.pn/md3.np/md3.nn/md3.exact/md3.large_q/md3.one/md3.unsigned | sem.arithmetic.division_remainder_bound | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, rd_val | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | verified | bucket_emitted | verified | verified | `openvm.semantic.arithmetic.division_remainder_bound`; `sp1.semantic.arithmetic.division_remainder_bound` | d7 baseline/injected `./target/debug/beak-trace --bin "000100b7 00001137 0220c1b3" --inject-kind openvm.semantic.arithmetic.division_remainder_bound --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `../agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.q[0]` for nonzero-divisor rows using preserved `beak_record_c` in `extensions/rv32im/circuit/src/divrem/core.rs::fill_trace_row`; OpenVM-336 emits nonzero-divisor division/remainder cells from executed DivRem chip rows. SP1 7/811/356: shared install pass `pass4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| md4 | md4.mul_small/md4.mul_overflow/md4.mulh_pp/md4.mulh_pn/md4.mulh_nn/md4.mulhu/md4.zero_op/md4.max_product | sem.arithmetic.product_decomposition | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, rd_val, product_hi, product_lo | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | verified | bucket_emitted | verified | bucket_emitted | `openvm.semantic.arithmetic.product_decomposition`; `sp1.semantic.arithmetic.product_decomposition` | d7 injected smoke `./target/debug/beak-trace --bin "000010b7 00002137 022081b3" --inject-kind openvm.semantic.arithmetic.product_decomposition --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `../agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.a[0]` in `extensions/rv32im/circuit/src/mul/core.rs::fill_trace_row` and `mulh/core.rs::fill_trace_row`; OpenVM-336 emits product decomposition cells from executed Mul/MulH chip rows. MULHSU-specific correction remains tracked by MD5. SP1 7/811/356: shared install pass `pass4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| md5 | md5.pos_any/md5.neg_small/md5.neg_large/md5.neg_max/md5.neg_one | sem.arithmetic.signed_unsigned_product_correction | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, chip_name, kind, rs1_val, rs2_val, rd_val, product_hi, product_lo | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | unsupported | verified | bucket_emitted | verified | bucket_emitted | `openvm.semantic.arithmetic.signed_unsigned_product_correction`; `sp1.semantic.arithmetic.signed_unsigned_product_correction` | d7 injected smoke `./target/debug/beak-trace --bin "800000b7 00001137 0220a1b3" --inject-kind openvm.semantic.arithmetic.signed_unsigned_product_correction --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. SP1 7/811/356 chip-hook smokes are recorded in `../agent_runs/vm-distributed/lead-sp1-deep-instrumentation.md`. | d7 mutates `core_row.b_ext` for MULHSU in `extensions/rv32im/circuit/src/mulh/core.rs::fill_trace_row`; OpenVM-336 emits MULHSU correction cells from executed MulH chip rows. SP1 7/811/356: shared install pass `pass4_is_memory.py` patches concrete ALU/mul/div chip trace rows in v4 `crates/core/machine/src/alu/*/mod.rs` and legacy 356 `core/src/alu/*/mod.rs`; target backends map executed bucket hits to pc/clk-anchored applied-site hooks. |
| me1 | me1.sw_lw/me1.sb_lb/me1.sh_lh/me1.sb_lw/me1.sw_lb/me1.sw_lhu/me1.overwrite | sem.memory.store_load_payload_flow | op_idx, pc, opcode, mnemonic, effective_ptr, width, timestamp, read_data, write_data, store_step_idx | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | trace_missing | unsupported | install_patch_available | verified | verified | bucket_emitted | `openvm.semantic.memory.store_load_payload_flow`; `sp1.semantic.memory.store_load_payload_flow` | See OpenVM-d7 and OpenVM-336 Memory/Time smokes below: pass | OpenVM-d7/OpenVM-336 track adapter memory_access store bytes and later loads to the same true address; backend anchors injection to `store_step_idx`; d7 mutates loadstore core `write_data` at the store payload row. Nexus emits this bucket from executed `UniformTrace` store records only when a later executed load record reaches the same address (width-specific cells when applicable); Nexus pass3 patches `prover/src/chips/instructions/load_store.rs::LoadStoreChip::fill_main_trace` and mutates `Ram1ValCur` at the store row for `nexus.semantic.memory.store_load_payload_flow`. |
| me2 | me2.half_off1/me2.word_off*/me2.byte_any | sem.memory.address_alignment_consistency | op_idx, pc, opcode, mnemonic, effective_ptr, aligned_ptr, byte_offset, width | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | bucket_emitted | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.memory.address_pointer_consistency`; `sp1.semantic.memory.address_pointer_consistency` | See OpenVM-d7 and OpenVM-336 Memory/Time smokes below: pass | OpenVM-d7/OpenVM-336 emit true adapter memory_access records; d7/336 install passes mutate loadstore adapter `mem_ptr_limbs`. |
| me3 | me3.lb_*/me3.lh_*/me3.lbu/me3.lhu | sem.memory.load_value_binding | op_idx, pc, opcode, mnemonic, effective_ptr, byte_offset, width, read_data | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | bucket_emitted | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.memory.value_payload_consistency`; `sp1.semantic.memory.value_payload_consistency` | See OpenVM-d7 and OpenVM-336 Memory/Time smokes below: pass | OpenVM-d7/OpenVM-336 derive sign/zero-extension cells from adapter memory_access read_data; d7 mutates loadstore/load-sign-extend core value columns. |
| me4 | me4.sb_off*/me4.sh_off* | sem.memory.write_payload_consistency | op_idx, pc, opcode, mnemonic, effective_ptr, byte_offset, width, read_data, prev_data | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | bucket_emitted | unsupported | verified | verified | verified | bucket_emitted | `openvm.semantic.memory.value_payload_consistency`; `sp1.semantic.memory.value_payload_consistency` | See OpenVM-d7 and OpenVM-336 Memory/Time smokes below: pass | OpenVM-d7/OpenVM-336 emit subword store mask cells from adapter memory_access records; d7 mutates loadstore core `write_data`. Nexus emits subword SB/SH offset cells from executed `UniformTrace` store records; Nexus pass3 patches `LoadStoreChip::fill_main_trace` and mutates `Ram1ValPrev` at the store row for `nexus.semantic.memory.write_payload_consistency`. |
| me5 | me5.reg_read/me5.reg_write/me5.mem_read/me5.mem_write | sem.memory.address_space_consistency | op_idx, pc, opcode, mnemonic, address_space, is_load, is_store | verified | semantic_injection_mapped | verified | bucket_emitted | trace_missing | trace_missing | trace_missing | trace_missing | unsupported | semantic_injection_mapped | bucket_emitted | semantic_injection_mapped | bucket_emitted | `openvm.semantic.memory.address_space_consistency` | See OpenVM-d7 and OpenVM-336 Memory/Time smokes below: pass | OpenVM-d7/OpenVM-336 emit load/store address-space direction cells from adapter memory_access records; d7 mutates loadstore adapter `mem_as`. |
| me6 | me6.near_max_lw/me6.near_max_sw/me6.near_max_lh/me6.near_max_sb/me6.heap_boundary | sem.memory.address_boundary_range | op_idx, pc, opcode, mnemonic, effective_ptr, width, address_space | verified | semantic_injection_mapped | verified | semantic_injection_mapped | trace_missing | trace_missing | trace_missing | trace_missing | unsupported | semantic_injection_mapped | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.memory.address_pointer_consistency` | See OpenVM-d7 and OpenVM-336 Memory/Time smokes below: pass | OpenVM-d7/OpenVM-336 emit address-boundary cells only when adapter memory_access records actually reach boundary addresses; d7/336 install passes mutate loadstore adapter `mem_ptr_limbs`. |
| me7 | me7.bss_zero/me7.data_loaded | sem.memory.initial_value_binding | op_idx, pc, opcode, mnemonic, effective_ptr, width, read_data, no_prior_write; memory_init seq/address/value for explicit nonzero init cells | bucket_emitted | bucket_emitted | bucket_emitted | trace_missing | bucket_emitted | bucket_emitted | bucket_emitted | trace_missing | unsupported | semantic_injection_mapped | bucket_emitted | verified | bucket_emitted |  | `BEAK_OPENVM_INIT_MEMORY='2:96:127' cargo run -q --bin beak-trace -- --bin '00000013' --print-buckets`: pass; no d7 initial-value hook mapped | First observed load with no prior same-address store is classified as zero vs nonzero initial value; OpenVM-d7/336 now also emit explicit nonzero `memory_init` cells. No d7 semantic injection mapping: no non-underconstrained initial-memory mutation row is identified. |
| me7 | me7.rodata/me7.stack_uninit | sem.memory.initial_value_binding | ELF/load-region metadata, stack-region metadata | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | trace_missing | trace_missing |  |  | Adapter memory_access exposes values and addresses but not ELF/stack region provenance. |
| me8 | me8.no_conflict | sem.memory.initial_value_binding | memory_init seq/address/value for explicit nonzero init cells | bucket_emitted | bucket_emitted | trace_missing | trace_missing | bucket_emitted | bucket_emitted | bucket_emitted | trace_missing | unsupported | bucket_emitted | trace_missing | trace_missing | trace_missing |  | `BEAK_OPENVM_INIT_MEMORY='2:96:127' cargo run -q --bin beak-trace -- --bin '00000013' --print-buckets`: pass | OpenVM-d7/336 emit non-conflicting explicit nonzero initialization cells from the initial-memory image; no d7 injection mapping because duplicate/non-underconstrained initial mutation rows are not exposed. |
| me8 | me8.double_init | sem.memory.initial_value_binding | duplicate initialization writes before MemoryImage coalescing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | trace_missing | trace_missing |  |  | OpenVM-336 receives a coalesced `MemoryImage`, so duplicate initialization writes are lost before `set_initial_memory`; this needs earlier ELF/loader instrumentation. |
| me9 | me9.off*/me9.adjacent_* | sem.memory.address_progression_consistency | op_idx, pc, opcode, mnemonic, effective_ptr, aligned_ptr, byte_offset, width | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | semantic_injection_mapped | semantic_injection_mapped | bucket_emitted | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.memory.address_pointer_consistency`; `sp1.semantic.memory.address_pointer_consistency` | See OpenVM-d7 and OpenVM-336 Memory/Time smokes below: pass | OpenVM-d7/OpenVM-336 emit byte-offset cells from adapter memory_access records; d7/336 install passes mutate loadstore adapter `mem_ptr_limbs`. |
| me10 | me10.load/me10.store | sem.memory.kind_selector_consistency | op_idx, pc, opcode, mnemonic, is_load, is_store, width | verified | semantic_injection_mapped | verified | verified | verified | verified | verified | bucket_emitted | unsupported | semantic_injection_mapped | verified | verified | bucket_emitted | `openvm.semantic.memory.kind_selector_consistency`; `sp1.semantic.memory.kind_selector_consistency` | See OpenVM-d7 and OpenVM-336 Memory/Time smokes below: pass | OpenVM-d7/OpenVM-336 emit load/store direction cells from adapter memory_access records; d7 mutates loadstore core `is_load`. Nexus emits load/store direction cells from executed `UniformTrace` memory records; Nexus pass3 patches `LoadStoreChip::fill_main_trace` and flips `IsSw`/`IsLw` selector columns for `nexus.semantic.memory.kind_selector_consistency`. |
| me11 | me11.written_cells/me11.read_only_cells | sem.memory.finalization_consistency | memory_finalization seq, op_idx, address_space, pointer, timestamp, values, was_initial, changed_from_initial | verified | semantic_injection_mapped | verified | trace_missing | bucket_emitted | bucket_emitted | bucket_emitted | trace_missing | unsupported | semantic_injection_mapped | trace_missing | verified | bucket_emitted | `openvm.semantic.memory.finalization_consistency` | d7 memory seed plus `--inject-kind openvm.semantic.memory.finalization_consistency --inject-step 18446744073709551615`: `semantic_injection_applied = true`; 336 prover smoke: pass | OpenVM-d7/336 emit persistent memory finalization rows from `MemoryController`; d7 mutates final `TimestampedValues` before boundary/merkle finalization. |
| me11 | me11.untouched_cells | sem.memory.finalization_consistency | complete final memory universe / untouched finalization rows | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | unsupported | semantic_injection_mapped | trace_missing | trace_missing | trace_missing |  |  | The exposed `final_partition` covers accessed/finalized blocks; it does not enumerate untouched memory cells. |
| ts1 | ts1.standard | sem.time.boundary_origin_consistency | op_idx, pc, timestamp, next_timestamp | verified | semantic_injection_mapped | verified | verified | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | trace_missing | verified | semantic_injection_mapped | bucket_emitted | bucket_emitted | `openvm.semantic.time.boundary_origin_consistency` | d7 injected smoke `./target/debug/beak-trace --bin "00100013" --inject-kind openvm.semantic.time.boundary_origin_consistency --inject-step 0 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. | d7 mutates connector boundary `state.timestamp` in `crates/vm/src/system/connector/mod.rs::generate_proving_ctx`; OpenVM-336 derives standard initial timestamp cell from the first executed instruction and mutates connector boundary timestamp. |
| ts2 | ts2.small_gap/ts2.large_gap/ts2.consecutive | sem.time.monotonic_access_ordering | op_idx, pc, effective_ptr, address_space, timestamp, previous_timestamp, ts_diff | verified | semantic_injection_mapped | verified | verified | semantic_injection_mapped | verified | semantic_injection_mapped | trace_missing | trace_missing | semantic_injection_mapped | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.time.monotonic_access_ordering`; `sp1.semantic.time.monotonic_access_ordering` | See OpenVM-d7 and OpenVM-336 Memory/Time smokes below: pass | OpenVM-d7/f038 derive same-address timestamp gaps from adapter memory_access records; d7 mutates `MemoryAuxColsFactory::fill` prev-timestamp column after aux generation. Pico emits same-address timestamp buckets and verifies the paired `sem.memory.timestamped_load_path` hook with base inject kind `pico.semantic.memory.timestamped_load_path`; `ts2.cross_segment` remains trace_missing until segment-boundary memory continuity is exposed. |
| ts2 | ts2.cross_segment | sem.time.monotonic_access_ordering | segment_idx/shard boundary plus memory access continuity | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing |  |  | Current trace does not expose cross-segment memory ordering boundaries. |
| ts3 | ts3.standard | sem.time.boundary_origin_consistency | op_idx, pc, timestamp | verified | semantic_injection_mapped | verified | verified | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | trace_missing | verified | semantic_injection_mapped | bucket_emitted | bucket_emitted | `openvm.semantic.time.boundary_origin_consistency` | d7 injected smoke `./target/debug/beak-trace --bin "00100013" --inject-kind openvm.semantic.time.boundary_origin_consistency --inject-step 0 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. | d7 mutates connector boundary `state.timestamp` in `crates/vm/src/system/connector/mod.rs::generate_proving_ctx`; OpenVM-336 derives standard clk/pc initialization cell from the first executed instruction and mutates connector boundary timestamp. |
| cf1 | cf1.blt*/cf1.bge*/cf1.bltu*/cf1.bgeu*/cf1.beq_equal/cf1.bne_not_equal/cf1.sign_flip | sem.exec.control_flow_binding | op_idx, pc, opcode, mnemonic, next_pc, target_pc, taken, chip-row operands for sign_flip | verified | semantic_injection_mapped | bucket_emitted | verified | semantic_injection_mapped | verified | verified | bucket_emitted | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.exec.control_flow_binding`; `jolt.semantic.exec.control_flow_binding` | d7 injected branch smoke `./target/debug/beak-trace --bin "00100113 00200193 00208463 00300193" --inject-kind openvm.semantic.exec.control_flow_binding --inject-step 18446744073709551615 --print-buckets` emitted `sem.exec.control_flow_binding` and reported `semantic_injection_applied = true`. Jolt baseline: `cargo run -q --bin beak-trace -- --bin "00100093 00200113 0020c463 00300193" --print-buckets` emitted `sem.exec.control_flow_binding`; injected Jolt smoke with `--inject-kind jolt.semantic.exec.control_flow_binding --inject-step 18446744073709551615` reported `injection_applied = true` but still hit the known Jolt memory panic, so not verified. | d7 mutates branch compare result in `extensions/rv32im/circuit/src/branch_eq/core.rs` and `branch_lt/core.rs`; branch taken/not-taken cells come from executed instruction next_pc. OpenVM-f038 emits branch buckets from executed instruction trace only; no f038 branch mutation hook is mapped. Jolt emits branch cells from executed `RVTraceRow` register operands and input-PC mapping; Jolt install pass mutates branch `JoltTraceStep.instruction_lookup` variants. |
| cf2 | cf2.jal_rd/cf2.jal_x0/cf2.jalr_rd/cf2.jalr_x0 | sem.exec.control_flow_binding | op_idx, pc, opcode, mnemonic, rd, next_pc, link_pc | verified | semantic_injection_mapped | bucket_emitted | verified | semantic_injection_mapped | verified | semantic_injection_mapped | bucket_emitted | unsupported | bucket_emitted | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.exec.control_flow_binding` | d7 branch/JAL/JALR control-flow hooks are mapped; branch smoke above reported `semantic_injection_applied = true`, and JAL/JALR use the same base inject kind at `jal_lui/core.rs` and `jalr/core.rs`. | Link-register cells are emitted from executed JAL/JALR instruction trace; d7 mutates JAL/JALR link/target witness columns. OpenVM-f038 emits this bucket from executed instruction trace only; no f038 JAL/JALR mutation hook is mapped. |
| cf3 | cf3.imm_zero/cf3.imm_pos/cf3.imm_neg | sem.exec.control_flow_binding | op_idx, pc, opcode, mnemonic, imm, next_pc | verified | semantic_injection_mapped | bucket_emitted | verified | semantic_injection_mapped | verified | semantic_injection_mapped | bucket_emitted | unsupported | bucket_emitted | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.exec.control_flow_binding` | d7 JALR hook is mapped in `extensions/rv32im/circuit/src/jalr/core.rs::fill_trace_row`; control-flow injected smoke reported applied-site evidence for the shared base kind. | JALR immediate-sign cells are observable from executed decode; d7/336 JALR hooks mutate target/link witness columns. OpenVM-f038 emits JALR immediate buckets from executed instruction trace only; no f038 JALR mutation hook is mapped. |
| cf3 | cf3.clear_lsb/cf3.even/cf3.wrap | sem.exec.control_flow_binding | op_idx, pc, opcode, mnemonic, step_idx, row_op_idx, rs1_val, imm, target_before_lsb_clear, target_after_lsb_clear, next_pc | verified | semantic_injection_mapped | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | semantic_injection_mapped | semantic_injection_mapped | trace_missing | `openvm.semantic.exec.control_flow_binding` | d7 JALR chip-row emission includes `target_before_lsb_clear`; mapped JALR hook mutates `rd_data[0]` and `imm_sign` in `jalr/core.rs::fill_trace_row`. | OpenVM-f038 baseline JALR emits executed control-flow buckets, but the installed f038 source does not expose `target_before_lsb_clear` chip-row evidence; clear/even/wrap remain trace_missing. Risc0-98387806 emits JALR target cells from executed register state with `target_before_lsb_clear` / `target_after_lsb_clear`; the shared Risc0 control-flow prover hook maps this row and `cf3.even` has baseline plus injected smoke evidence, while `cf3.clear_lsb` still fails baseline witness generation before injection and wrap targets leave the installed code region. Pico currently emits JALR immediate cells only; `target_before_lsb_clear` / `target_after_lsb_clear` are not emitted in `projects/pico-45e74ccd62758c6d67239913956e749adaba261c/src/lib/trace.rs::cf3_cell`. |
| cf4 | cf4.default_entry/cf4.custom_entry | sem.control.entrypoint_binding | first op_idx, first pc | verified | semantic_injection_mapped | bucket_emitted | verified | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | unsupported | verified | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.control.entrypoint_binding`; `jolt.semantic.control.entrypoint_binding` | d7 injected smoke `./target/debug/beak-trace --bin "00100013" --inject-kind openvm.semantic.control.entrypoint_binding --inject-step 0 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. Jolt baseline: `cargo run -q --bin beak-trace -- --bin 123450b7 --print-buckets` emitted `sem.control.entrypoint_binding`; injected Jolt smoke with `--inject-kind jolt.semantic.control.entrypoint_binding --inject-step 0` reported `injection_applied = true` but still hit the known Jolt memory panic, so not verified. | d7 mutates connector boundary `state.pc` in `crates/vm/src/system/connector/mod.rs::generate_proving_ctx`; first executed instruction PC is emitted as OpenVM instruction-index PC. OpenVM-f038 emits entrypoint buckets from executed instruction trace only; no f038 boundary-PC mutation hook is mapped. |
| cf5 | cf5.halt/cf5.io_read/cf5.io_write/cf5.precompile/cf5.arg_zero/cf5.arg_max | sem.control.ecall_argument_decomposition | op_idx, pc, syscall_nr, a0-a7 register values | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | verified | verified | `<vm>.semantic.control.ecall_argument_decomposition` |  | OpenVM-f038 does not expose Linux-style ECALL syscall dispatch or a0-a7 argument reads; RV32 system encodings are transpiled before a raw ECALL obligation bucket is observable. |
| cf6 | cf6.normal/cf6.after_branch_not_taken | sem.exec.control_flow_binding | op_idx, pc, opcode, mnemonic, next_pc, previous branch next_pc | verified | semantic_injection_mapped | bucket_emitted | verified | semantic_injection_mapped | verified | verified | bucket_emitted | unsupported | bucket_emitted | semantic_injection_mapped | verified | bucket_emitted | `openvm.semantic.exec.control_flow_binding` | d7 injected smoke `./target/debug/beak-trace --bin "00100113 00200193 00208463 00300193" --inject-kind openvm.semantic.exec.control_flow_binding --inject-step 18446744073709551615 --print-buckets` emitted the bucket and reported `semantic_injection_applied = true`. | Sequential and after-branch-not-taken cells use executed instruction trace; d7 branch/JAL/JALR hooks cover concrete control-flow witness mutation. OpenVM-f038 emits sequential buckets from executed instruction trace only; no f038 control-flow mutation hook is mapped. `near_segment_end` still needs segment metadata. |
| cf6 | cf6.near_segment_end | sem.exec.control_flow_binding | segment boundary metadata | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | unsupported | trace_missing | trace_missing | trace_missing | trace_missing |  |  | Current trace lacks segment-boundary position metadata; d7eab708 and Pico likewise have no segment-boundary position metadata in the emitted instruction/chip-row trace. |
| cf7 | cf7.standard | sem.control.ecall_word_validity | op_idx, pc, opcode, mnemonic, raw instruction word | install_patch_available | trace_missing | trace_missing | bucket_emitted | bucket_emitted | bucket_emitted | semantic_injection_mapped | bucket_emitted | unsupported | trace_missing | semantic_injection_mapped | bucket_emitted | bucket_emitted | `openvm.semantic.control.ecall_word_validity` | Hook smoke: `cargo run -q --bin beak-trace -- --bin "00000073" --inject-kind openvm.semantic.control.ecall_word_validity --inject-step 0` printed the program-table mutation and reported `semantic_injection_applied = true` / `verify_app_proof failed: ChallengePhaseError`; baseline `00000073 --print-buckets` emitted 0 buckets because the RV system word transpiled to `unimp`. | OpenVM-f038 has no mapped program-table ECALL hook and no baseline raw-RV ECALL bucket; status remains trace_missing. Pico emits the executed ECALL word bucket when observable, but no real Pico install mutation hook exists for `pico.semantic.control.ecall_word_validity`, so it is bucket-only. |
| bu1 | bu1.real_row | sem.lookup.boolean_multiplicity | step_idx, table_name, multiplicity, is_real | not_started | semantic_injection_mapped | trace_missing | verified | install_patch_available | install_patch_available | trace_missing | install_patch_available | trace_missing | semantic_injection_mapped | trace_missing | trace_missing | trace_missing | `<vm>.semantic.lookup.boolean_multiplicity` | d7 bitwise lookup smoke emitted `sem.lookup.boolean_multiplicity`; injected `openvm.semantic.lookup.boolean_multiplicity` replay reported `semantic_injection_applied = true`. Pico base-kind injected smoke reported `injection_applied=true` and failed with `Constraint verification failed`. | d7 pass emits nonzero bitwise lookup multiplicity rows from `BitwiseOperationLookupChip::generate_trace` and mutates `mult_range`/`mult_xor`; f038 does not expose boolean lookup multiplicity rows in the current trace. SP1 v4 byte-record/byte-table install patches exist for 39/7/811, but injected lookup replays still reported `semantic_injection_applied = false`; only 39/7 are install-patch-available and 811 remains trace-missing without a durable baseline bucket. |
| pd1 | pd1.short_trace | sem.row.padding_interaction_send | step_idx, table_name, is_padding, interaction_kind | verified | bucket_emitted | bucket_emitted | trace_missing | bucket_emitted | bucket_emitted | bucket_emitted | bucket_emitted | trace_missing | semantic_injection_mapped | trace_missing | bucket_emitted | bucket_emitted | `<vm>.semantic.row.padding_interaction_send` | OpenVM-336 strict e2e: `FAST_TEST=1 ./target/debug/beak-fuzz --seeds-jsonl .../seed_three_base_alu_xor_padding.jsonl --initial-limit 1 --mutation-iters 0 --semantic-window-before 2 --semantic-window-after 8 --semantic-max-trials-per-bucket 8` reported `trigger_bucket_id=sem.row.padding_interaction_send`, `semantic_injection_applied=true`, and `underconstrained_candidate=true`. | OpenVM-336 maps BaseAlu padding interaction sends to a real padding-row hook and balances the injected ghost read through the memory final-merge/access-adapter path. f038 baseline smokes emit padding interaction-send buckets; no mutation hook is mapped. |
| pd3 | pd3.mem_table/pd3.range_table/pd3.lookup_accum/pd3.commit_vector | sem.row.table_power2_boundary | step_idx, table_name, real_rows, log_size, padded_rows, padding_rows, boundary_k | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_observable | trace_missing | trace_missing | `<vm>.semantic.row.table_power2_boundary` | Nexus-MemorySize-01 fixability pass selected `pd3.mem_table` as the first implementable cell. | This is intentionally separate from PD1 `sem.row.padding_interaction_send`: PD3 is table-size boundary coverage, not padding-row inertness. Nexus-41 now records the concrete first out-of-capacity `rw_mem_check.last_access` row, total population, and overflow size in matching bucket/exception receipts; ordinary replay remains pending. |
| pd4 | pd4.just_over/pd4.just_under/pd4.large_program/pd4.small_program | sem.row.bytecode_table_boundary | step_idx, table_name, bytecode_len, virtualized_bytecode_len, padded_bytecode_len, crossed_k | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_missing | trace_observable | trace_missing | trace_missing | trace_missing | `<vm>.semantic.row.bytecode_table_boundary` | Jolt-HighBytecode-01 fixability pass selected Jolt bytecode table metadata as the first implementable source. | This is intentionally separate from PD1 `sem.row.padding_interaction_send`: PD4 is bytecode table expansion, not generic padding interaction. |

## Per-VM Notes

Add short notes here as pilots progress.

### sp1-39ab52fc

- Status: central completion pass completed for currently observable SP1 v4
  evidence. Instruction-local semantic buckets come only from oracle-executed
  instructions, not unexecuted input words.
- Backend-mapped with real installed-source hooks and applied-site evidence:
  CPU-row register/decode buckets `rf1`-`rf3`, `id1`, `id2`, `id4`, `id5`;
  ALU/mul/div chip buckets `al1`-`al5`, `md1`-`md5`; memory buckets `me1`,
  `me2`, `me3`, `me4`, `me9`, and `me10`; same-address timestamp bucket
  `ts2`; and control-flow buckets `cf1`, `cf2`, `cf3.imm_*`, and
  `cf6.normal/after_branch_not_taken`. The durable hooks are in
  `pass4_is_memory.py` CPU/ALU/mul/div/memory trace patches and the
  `pass3_collection.py` executor next-PC patch.
- Verified SP1 memory-effect row: baseline
  `./target/debug/beak-trace --bin "00012183" --print-buckets` emitted
  `sem.exec.memory_effect_binding`; injected
  `./target/debug/beak-trace --bin "00012183" --inject-kind sp1.semantic.exec.memory_effect_binding --inject-step 18446744073709551615 --print-buckets`
  reported `semantic_injection_applied = true` with proof verification still
  accepted and oracle/SP1 registers matching. This is the documented
  underconstrained SP1 v4 `is_memory` candidate.
- Applied-site smokes for mapped hook families:
  RF/decode
  `./target/debug/beak-trace --bin "00010033" --inject-kind "sp1.semantic.decode.zero_register_immutability::site=op_a_access" --inject-step 18446744073709551615 --print-buckets`
  reported `semantic_injection_applied = true` and prover rejection;
  ALU
  `./target/debug/beak-trace --bin "00100093 00108463 00200113" --inject-kind sp1.semantic.alu.immediate_limb_consistency --inject-step 18446744073709551615 --print-buckets`
  reported applied with AddSub rejection; mul/div chip smokes for
  `sp1.semantic.arithmetic.division_remainder_bound` on `020141b3` and
  `sp1.semantic.arithmetic.product_decomposition` on `020101b3` reported
  applied with DivRem/Mul rejection; control-flow injected replay on
  `00100093 00108463 00200113` reported applied with proof accepted.
- SP1 memory/timestamp smokes: baseline
  `./target/debug/beak-trace --bin "000020b7 02a00113 0020a023 0000a183" --oracle-data-size-bytes 0x3000 --print-buckets`
  emitted `me1`, `me2`, `me3`, `me8.no_conflict`, `me9`, `me10`, `me11`,
  and `ts2` buckets. Injected replays with
  `sp1.semantic.memory.address_pointer_consistency::site=addr_word`,
  `sp1.semantic.memory.value_payload_consistency::site=access_value`,
  `sp1.semantic.memory.store_load_payload_flow::site=access_value`,
  `sp1.semantic.memory.kind_selector_consistency::site=kind_selector`, and
  `sp1.semantic.time.monotonic_access_ordering::site=prev_clk` all reported
  `semantic_injection_applied = true`, proof rejection, and matching oracle/SP1
  registers. Subword smoke
  `000020b7 02a00113 00208023 0000c183` emitted `me4` and applied the value
  hook; first-load smoke `000020b7 0000a183` emitted `me7.bss_zero`.
- SP1-39 `md1`/`md2` now use real DivRem event operands. Div-by-zero seed
  `000010b7 0200c1b3` and signed-overflow seed
  `800000b7 fff00113 0220c1b3` emitted the special-case bucket; injected
  `sp1.semantic.arithmetic.special_case_consistency` replays reported
  `semantic_injection_applied = true`, proof rejection, and matching registers.
- Lookup status: byte lookup buckets can be emitted from executed records and
  the install pass patches byte-record/byte-table counters, but injected
  `sp1.semantic.lookup.boolean_multiplicity` replays on 39/7/811 still reported
  `semantic_injection_applied = false`. `bu1` is therefore not mapped.
- Trace-missing or unsupported cells:
  `id3` is bucket-only; `me5`, exercised `me6` boundary rows,
  `me7` provenance beyond first-load zero, `me8.double_init`,
  `me11.untouched_cells`, `ts2.cross_segment`, `cf5`,
  `cf6.near_segment_end`, `rc1`-`rc4`, `bu2`-`bu6`, and `pd2`-`pd5`
  need stable address-space selectors, boundary seeds, provenance/duplicate
  init evidence, complete final-memory enumeration, syscall argument values,
  range-check/flag decomposition rows, bus/permutation rows, transcript data,
  or segment/table lifecycle metadata that the current target trace does not
  expose.
- Verification: `cargo check -q`, `cargo build -q --bin beak-trace`, and
  targeted smokes above passed in the target project with pre-existing
  installed-SP1 warnings. Required final test commands are recorded in the run
  log `../agent_runs/vm-distributed/lead-sp1-39ab52fc.md`.

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
| o1 | legacy_rejected | sem.lookup.xor_multiplicity_consistency | Baseline: `./target/release/beak-trace --bin "01400313 01400393 00734533" --print-buckets`; injected: `./target/release/beak-trace --bin "01400313 01400393 00734533" --inject-kind "openvm.semantic.lookup.xor_multiplicity_consistency::mode=p_plus_mask,rank=0,strength=0" --inject-step 0 --print-buckets` | Baseline emitted legacy `sem.lookup.xor_multiplicity_consistency`; injected replay reported `semantic_injection_applied = true` but failed with `ChallengePhaseError`. This is not canonical BU1 coverage; migrate verification to `sem.lookup.boolean_multiplicity`. |
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

- Status: deep memory/table instrumentation pass completed for observable d7
  prover rows. Memory/value/address/finalization same-address timestamp, and
  bitwise lookup multiplicity rows are `semantic_injection_mapped`; no d7 rows
  are marked `verified` because the d7 backend path still runs tracegen-only
  (`new_local_prover` through `generate_proving_ctx`) and does not run proof
  verification.
- Owner scope: `projects/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5/` and
  `beak-py/projects/openvm-fuzzer/`.
- Bucket emission: d7eab708 derives contract-style bucket details for executed
  decode/register/control rows, re-anchored regzero chip rows, adapter
  `memory_access` rows with source PC, explicit `memory_init` rows, persistent
  `memory_finalization` rows, and bitwise lookup multiplicity rows.
- Install-pass notes:
  `beak-py/projects/openvm-fuzzer/openvm_fuzzer/passes/pass3_collection.py`
  now patches d7 loadstore/load-sign-extend core rows, loadstore adapter rows,
  memory timestamp aux rows, persistent memory lifecycle rows, and
  `BitwiseOperationLookupChip::generate_trace`. `pass1_infrastructure.py`
  adds `fuzzer_utils` to `openvm-circuit-primitives` so lookup table
  instrumentation compiles.
- Replayed install:
  `cd beak-py && uv run openvm-fuzzer install --commit-or-branch bmk-regzero`
  completed and refreshed
  `beak-py/out/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5/openvm-src`.
- Baseline memory/table smoke:
  `cargo run -q --bin beak-trace -- --bin "04000093 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`
  matched oracle registers and emitted 91 hits including
  `sem.memory.store_load_payload_flow`, `sem.memory.address_alignment_consistency`,
  `sem.memory.address_progression_consistency`,
  `sem.memory.address_space_consistency`, `sem.memory.initial_value_binding`,
  `sem.memory.finalization_consistency`, `sem.memory.kind_selector_consistency`,
  `sem.memory.load_value_binding`, `sem.memory.write_payload_consistency`,
  `sem.time.monotonic_access_ordering`, and `sem.lookup.boolean_multiplicity`.
- Boundary/init smokes:
  `cargo run -q --bin beak-trace -- --bin "200000b7 ff008093 0000a103" --print-buckets`
  emitted `sem.memory.address_boundary_range` and matched registers.
  `BEAK_OPENVM_INIT_MEMORY="2:96:127" cargo run -q --bin beak-trace -- --bin "00000013" --print-buckets`
  emitted four `sem.memory.initial_value_binding` hits and matched registers.
- Injected replay smokes on the memory seed above all reported
  `semantic_injection_applied = true` and `UNDERCONSTRAINED CANDIDATE DETECTED`
  for `openvm.semantic.memory.address_pointer_consistency`,
  `openvm.semantic.memory.address_space_consistency`,
  `openvm.semantic.memory.value_payload_consistency`,
  `openvm.semantic.memory.store_load_payload_flow`,
  `openvm.semantic.memory.kind_selector_consistency`,
  `openvm.semantic.memory.finalization_consistency`,
  `openvm.semantic.time.monotonic_access_ordering`, and
  `openvm.semantic.lookup.boolean_multiplicity`.
- Trace-missing gaps after audit: `me7.rodata`, `me7.stack_uninit`,
  `me8.double_init`, and `me11.untouched_cells` still lack stable source rows.
  d7 exposes a coalesced `SparseMemoryImage` and a touched/finalized memory
  partition, not duplicate init writes or a complete untouched memory universe.
  `ts2.cross_segment`, `cf5`, `cf6.near_segment_end`, and `cf7` remain
  `trace_missing` because the d7 traces still lack segment-boundary memory
  continuity, Linux-style syscall args/raw ECALL visibility, and near-segment
  position metadata. `pd1` remains `bucket_emitted`; padding sample rows are
  visible, but no stable prover/table mutation hook is mapped.

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
- Volatile-specific hook status: f038 `volatile_boundary_range` now stages a
  typed `rc3.volatile_pointer` mutation after volatile range/order auxiliary
  witnesses are generated in `VolatileBoundaryChip::generate_air_proof_input`,
  while leaving finalized memory keys and address-space limbs unchanged. The
  fresh ordinary replay emits a complete receipt, but verification still
  returns `ChallengePhaseError`/`OodEvaluationMismatch`, so the obligation
  remains non-exact and is not marked verified.
- Trace-missing gaps: `me7.rodata/stack_uninit`, `me8.no_conflict`,
  `me8.double_init`, `me11.untouched_cells`, `ts2.cross_segment`,
  `cf3.clear_lsb/even/wrap`, `cf5`, `cf6.near_segment_end`, `cf7`, and `bu1`.
  Reasons are missing ELF/stack provenance, duplicate-init/untouched-cell
  enumeration, segment-boundary metadata, JALR pre-mask target evidence, raw
  ECALL/syscall visibility, or boolean lookup multiplicity rows.

### openvm-bf11b4a5 (latest)

- Round8 PD1 audit: `pd1` remains `bucket_emitted`. The normal tracegen path
  emits `sem.row.padding_interaction_send` for the BaseAlu padding candidate,
  but no reachable normal padding interaction mutation hook is mapped.
- Focused smoke
  `FAST_TEST=1 cargo run -q --bin beak-trace -- --bin "00100093 02100113 002091b3" --print-buckets`
  matched registers and emitted 37 hits including
  `sem.row.padding_interaction_send`.
- Direct replays with the same seed and
  `--inject-kind openvm.semantic.row.padding_interaction_send --inject-step 0`
  and `--inject-step 18446744073709551615` both matched registers and reported
  `semantic_injection_applied = false`.
- Backend status: `projects/openvm-bf11b4a5f79d20fa14d01f78b41d54df4acd0ee0/src/lib/backend.rs`
  does not create a `semantic::row::PADDING_INTERACTION_SEND` candidate, so
  normal semantic search will not treat the record-arena sample hook as valid
  PD1 mapping evidence.
- Inspected hook candidates: the installed
  `crates/vm/src/arch/record_arena.rs` sample hook is a record-arena padding
  row/proxy path and is not reached by the normal tracegen-focused candidate
  flow. The 336 BaseAlu hook mutates a real padding row and balances the ghost
  read through memory final-merge/access-adapter state; bf11 has no adapted
  same-semantics balancing hook in the current pass. Do not broaden bf11 PD1 to
  the record-arena sample path.

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
  Most injected smokes reported source-site `semantic_injection_applied=true`
  and verifier rejection. The read/write-memory `id4.load` hook is the current
  accepted underconstrained exception: it leaves opcode and operand lookup
  values unchanged while setting the row-local load destination selector
  `op_a_0` and dependent load-value flags so the load-value binding gate is
  disabled.
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
  `Regional cumulative sum is not zero`. The older read/write selector-family
  flip for `pico.semantic.memory.kind_selector_consistency` still rejects with
  `Constraint verification failed`; the distinct read/write `id4.load`
  injection
  `--inject-kind pico.semantic.exec.op_selector_binding.read_write --inject-step 1`
  on `[0x04000293,0x07b00513,0x00a2a023,0x0002a603]` now proves and verifies,
  and normal `beak-fuzz` semantic search reports
  `underconstrained_candidate=true`. Unsupported variants now return
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
  `ts1.standard`, `ts3.standard`, mapped memory buckets `me1`-`me4`,
  `me9`, `me10`, and `ts2.same-address`; bucket-only memory lifecycle buckets
  `me7.bss_zero`, `me8.no_conflict`, `me11.written_cells/read_only_cells`;
  and padding short-trace `pd1`.
- Verified SP1 semantic injection mappings with real install hooks:
  `sem.exec.memory_effect_binding` maps to
  `sp1.semantic.exec.memory_effect_binding`; baseline
  `cargo run -q --bin beak-trace -- --bin "00012183" --print-buckets`
  emitted `sem.exec.memory_effect_binding`, and injected
  `cargo run -q --bin beak-trace -- --bin "00012183" --inject-kind sp1.semantic.exec.memory_effect_binding --inject-step 0 --print-buckets`
  reported `semantic_injection_applied = true` with oracle/SP1 registers
  matching.
- Verified SP1 memory/timestamp hook replay:
  `sem.memory.store_load_payload_flow`,
  `sem.memory.address_alignment_consistency`,
  `sem.memory.address_progression_consistency`,
  `sem.memory.load_value_binding`, `sem.memory.write_payload_consistency`,
  `sem.memory.kind_selector_consistency`, and
  `sem.time.monotonic_access_ordering` map to the v4 memory-instruction trace
  hook in `pass4_is_memory.py`. Store/load smoke
  `000020b7 02a00113 0020a023 0000a183` with `--oracle-data-size-bytes 0x3000`
  and subword smoke `000020b7 02a00113 00208023 0000c183` both emitted the
  expected buckets; injected replays for the address/value/store-load/kind/time
  hook families reported `semantic_injection_applied = true`, proof rejection,
  and matching oracle/SP1 registers.
- Verified SP1 control-flow hook replay:
  `sem.exec.control_flow_binding` maps to
  `sp1.semantic.exec.control_flow_binding`; injected replay
  `cargo run -q --bin beak-trace -- --bin "00100093 00108463 00200113" --inject-kind sp1.semantic.exec.control_flow_binding --inject-step 1 --print-buckets`
  emitted control-flow buckets and reported `semantic_injection_applied = true`.
- Install patch available but not verified:
  `sem.lookup.boolean_multiplicity` has byte-record/byte-table install patches,
  but injected replay with
  `sp1.semantic.lookup.boolean_multiplicity --inject-step 18446744073709551615`
  reported `semantic_injection_applied = false`, so this remains
  `install_patch_available` and is not promoted to mapped.
- Trace-missing or unsupported cells:
  `me5`, exercised `me6` boundary rows, `me7` provenance beyond first-load
  zero, `me8.double_init`, `me11.untouched_cells`, `ts2.cross_segment`,
  `cf5`, `cf6.near_segment_end`, `cf3.clear_lsb/even/wrap`, `rc1`-`rc4`,
  `bu2`-`bu6`, and `pd2`-`pd5` need stable address-space selectors, boundary
  seeds, provenance/duplicate init evidence, complete final-memory
  enumeration, syscall argument values, range-check/flag decomposition rows,
  bus/permutation rows, transcript data, or segment/table lifecycle metadata
  that this target trace does not expose.
- Verification commands and results are recorded in
  `../agent_runs/vm-distributed/lead-sp1-7f643da1.md`.

### sp1-811a3f2c

- Status: install-completion pass verified SP1-811 CPU-row semantic hooks for
  RF/decode buckets with currently observable SP1 evidence. Instruction-local
  buckets are derived from SP1 `ExecutionRecord.cpu_events` and raw words are
  resolved by executed PC through the target program, so unexecuted input words
  do not emit obligation hits.
- Bucket-emitted from executed instruction trace with contract details:
  verified injection rows for `rf1`-`rf3`, `id1`, `id2`, `id4`, and `id5`;
  bucket-only coverage remains for `id3`, `al1`-`al5`, `md3`-`md5`, `cf4`,
  `cf7`, `ts1`, `ts3`, mapped memory buckets `me1`-`me4`, `me9`, `me10`,
  and `ts2.same-address`; bucket-only memory lifecycle buckets
  `me7.bss_zero`, `me8.no_conflict`, `me11.written_cells/read_only_cells`;
  and padding short-trace `pd1`.
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
- SP1 memory/timestamp hook replay:
  `sem.memory.store_load_payload_flow`,
  `sem.memory.address_alignment_consistency`,
  `sem.memory.address_progression_consistency`,
  `sem.memory.load_value_binding`, `sem.memory.write_payload_consistency`,
  `sem.memory.kind_selector_consistency`, and
  `sem.time.monotonic_access_ordering` map to the v4 memory-instruction trace
  hook in `pass4_is_memory.py`. Store/load smoke
  `000020b7 02a00113 0020a023 0000a183` with `--oracle-data-size-bytes 0x3000`
  and subword smoke `000020b7 02a00113 00208023 0000c183` both emitted the
  expected buckets; injected replays for the address/value/store-load/kind/time
  hook families reported `semantic_injection_applied = true`, proof rejection,
  and matching oracle/SP1 registers.
- Verified control-flow hook replay:
  `sem.exec.control_flow_binding` maps to
  `sp1.semantic.exec.control_flow_binding`; injected replay
  `./target/debug/beak-trace --bin "00100093 00108463 00200113" --inject-kind "sp1.semantic.exec.control_flow_binding::family=branch" --inject-step 1 --print-buckets`
  emitted control-flow buckets and reported `semantic_injection_applied = true`.
- Conservative lookup status: byte-record/byte-table install patches are
  present, but injected `sp1.semantic.lookup.boolean_multiplicity` replay
  reported `semantic_injection_applied = false`, and the memory/bitwise smokes
  used here did not emit a durable 811 `bu1.real_row` baseline. Lookup remains
  `trace_missing` for this snapshot.
- Trace-missing or unsupported cells: `me5`, exercised `me6` boundary rows,
  `me7` provenance beyond first-load zero, `me8.double_init`,
  `me11.untouched_cells`, `ts2.cross_segment`, `cf5`, `cf6.near_segment_end`,
  range-check/bus/permutation/transcript rows, and broad padding lifecycle
  cells need VM evidence not exposed by this target.
- Verification commands and results are recorded in
  `../agent_runs/vm-distributed/lead-sp1-811a3f2c.md`.

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
  `../agent_runs/vm-distributed/lead-sp1-3561f006.md`.

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
- Verification: `cargo check -q`, `cargo test -q`, and JSON smokes for
  `--scenario load`, `--scenario jump`, and `--scenario bneinc` passed. Each
  injected legacy run diverged while proof verification still succeeded, so the
  legacy regressions remain covered outside the central matrix. Command results
  are recorded in `../agent_runs/vm-distributed/lead-sp1-fb38df2c.md`.

### sp1 snapshots

- Status: other SP1 snapshots not covered here remain as recorded in their
  commit-specific notes.
- Owner scope: the specific `projects/sp1-<commit>/` snapshot and
  `beak-py/projects/sp1-fuzzer/`.

### jolt-e9caa235

- Status: deep instrumentation pass completed for currently reachable Jolt
  witness/prover rows. Instruction-local hits still come only from rows whose
  executed PC maps back to the input program.
- Prover smoke blocker fixed: Jolt read/write memory witness sizing now includes
  trace RAM rows, bytecode initialization, input initialization, and a minimum
  size. Baseline `123450b7 --print-buckets` now completes without the previous
  `read_write_memory.rs` out-of-bounds panic.
- Verified rows: `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md1`,
  `md3`-`md5`, `me2`, `me3`, `me4`, `me9`, `ts1`, `ts3`, `cf1`, and `cf4`.
  `id3` is verified with underconstrained evidence: the applied
  upper-immediate trace hook preserved registers and the proof verified.
- Installed hook locations:
  `jolt-core/src/host/mod.rs::Program::trace` mutates processed
  `JoltTraceStep` rows for `id3`, `cf1`, `cf4`, `me5` address-space, and
  `me10` kind-selector hooks;
  `jolt-core/src/jolt/vm/read_write_memory.rs::generate_witness` mutates
  register read/write, RAM address/value, initial/final memory values, and
  timestamp columns for `rf1`-`rf3`, `me2`-`me7`, `me9`, `me11`, `ts1`,
  `ts2.same-address`, and `ts3`;
  `jolt-core/src/jolt/vm/bytecode.rs::generate_witness` mutates bytecode
  `bitflags`, register, and immediate columns for `id1`, `id2`, `id4`, `id5`,
  and `al1`;
  `jolt-core/src/jolt/vm/instruction_lookups.rs::generate_witness` mutates
  `lookup_outputs` rows for `al2`-`al5`, `md1`, and `md3`-`md5`, and mutates
  lookup instruction flag bitvectors for `bu1`;
  `jolt-core/src/jolt/vm/mod.rs::JoltTraceStep::pad` mutates padding rows for
  `pd1`.
  `projects/jolt-e9caa235.../src/lib/backend.rs` maps observed buckets to these
  base inject kinds and keeps the env-armed injection live through
  `prove_and_verify`.
- Newly mapped rows from the table/prover pass: `me5`, `me6`, `me7.bss_zero`
  / `me7.data_loaded`, `me10`, `me11.written_cells/read_only_cells`,
  `me11.untouched_cells`, `ts2.same-address`, `bu1.real_row`, and `pd1`
  padding rows. `me8.no_conflict` is bucket-emitted from initialization table
  evidence but remains unmapped because no duplicate-init/provenance mutation
  hook was added.
- Install-patch-available rows: `md2` has the shared special-case lookup hook,
  but DIV and REM overflow seeds panic in
  `jolt-core/src/jolt/instruction/{div,rem}.rs` before a baseline bucket is
  collectable. `me1` has a RAM value hook and backend mapping, but a valid
  same-address store-then-load baseline remains unavailable in the current Jolt
  public I/O memory model.
- Current smoke behavior for new hooks: the repeated-load seed
  `7fffc0b7 10008093 0000c183 0000c203` emits the new buckets. Injected
  replays for address-space, address-boundary/address-pointer,
  initial-value, finalization, timestamp monotonicity, and lookup booleanity all
  reported `injection_applied = true` and failed prover checks. Kind-selector
  and padding hooks also reported `injection_applied = true` but preserved
  registers and verified, so they remain mapped/underconstrained rather than
  verified.
- Remaining bucket-only / trace-missing gaps: `cf2`, `cf3.imm_*`, and
  `cf6.normal/after_branch_not_taken` remain bucket-only because no JAL/JALR or
  sequential control-flow witness hook was added. `me7.rodata/stack_uninit`,
  `me8.double_init`, `ts2.cross_segment`, `cf5`, `cf6.near_segment_end`,
  `cf7`, and bus families still need ELF/stack provenance, duplicate-init
  evidence before coalescing, segment continuity, syscall arguments, raw ECALL
  execution, or bus/permutation table visibility not exposed by this snapshot.
- Owner scope: `projects/jolt-e9caa23565dbb13019afe61a2c95f51d1999e286/` and
  `beak-py/projects/jolt-fuzzer/`.

### nexus-636ccb36

- Status: deep instrumentation pass mapped high-value Nexus bucket-only rows to
  real installed-source prover hooks. Existing verified rows remain `me1`,
  `me4`, and `me10`.
- Owner scope: `projects/nexus-636ccb360d0f4ae657ae4bb64e1e275ccec8826/` and
  `beak-py/projects/nexus-fuzzer/`.
- Bucket emission now comes from executed Nexus `UniformTrace` steps and memory
  records, not raw unexecuted input words. Covered groups:
  `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `md1`-`md5`, `me1`-`me7`,
  `me9`, `me10`, `ts1`-`ts3` same-address cells, and `cf1`-`cf6`.
- Newly mapped rows: `rf1`-`rf3`, `id1`-`id5`, `al1`-`al5`, `cf1`-`cf4`,
  `cf6.normal/after_branch_not_taken`, `cf7`, `me2`, `me3`, `me6`, `me9`,
  `ts1`, `ts2.same-address`, and `ts3`. Pass3 now patches concrete prover columns in
  `cpu.rs`, `memory_check/register_mem_check.rs`, `instructions/{sll,srl,sra}.rs`,
  `instructions/{slt,sltu,sub}.rs`, branch/JAL/JALR instruction chips, and
  `instructions/load_store.rs`.
- All new mapped smokes printed `BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED` and
  backend `injection_applied = true`; injected prover runs then failed
  constraints or Nexus prover checks, so these rows are mapped but not
  `verified`.
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
- Remaining bucket-only rows and inspected missing mutation points:
  `md1`-`md5` have executed `UniformTrace` buckets, but installed
  `prover/src/machine.rs::BaseComponent` and
  `prover/src/chips/instructions/` expose no mul/div/rem prover chip files in
  this snapshot. `me5` is emitted as `main_memory` read/write only; inspected
  `load_store.rs` and `register_mem_check.rs` use separate RAM/register check
  paths with no address-space selector to mutate. `me7.bss_zero/data_loaded`
  remains bucket-only because `extensions/ram_init_final.rs` rows are keyed by
  final memory address order, not the `UniformTrace` `op_idx` emitted for the
  first-load bucket.
- Remaining trace-missing gaps: `me7.rodata/stack`, `me8`, `me11`,
  `ts2.cross_segment`, `cf5`, `cf6.near_segment_end`, `bu1`, and
  `pd1`. Inspected paths include `instructions/syscall.rs`,
  `chips/decoding/type_sys.rs`, `extensions/ram_init_final.rs`,
  `components/lookups.rs`, and extension padding/lookup trace code; current
  backend buckets do not expose syscall argument vectors, raw-RV ECALL baseline
  evidence, segment boundaries, bus multiplicity rows, or padding lifecycle
  rows with stable row anchors.

### nexus-f2ad126

- Round7 mapping: `me7.bss_zero/data_loaded` now maps
  `sem.memory.initial_value_binding` to a reachable same-semantics prover2
  hook in `prover2/machine/src/components/read_write_memory/trace.rs`. The
  hook fires only for load rows whose previous RAM timestamp is zero and
  mutates `Ram1ValPrev`. Focused smoke
  `cargo run -q --bin beak-trace -- --bin "000020b7 0000a183" --inject-kind nexus.semantic.memory.initial_value_binding --inject-step 2 --print-buckets`
  emitted `sem.memory.initial_value_binding`, printed
  `BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED kind=nexus.semantic.memory.initial_value_binding step=2 site=read_write_memory.ram1_val_prev_initial`,
  and reported `injection_applied = true`. Semantic-search smoke with the same
  seed also mapped the observed bucket to the hook and recorded
  `trigger_bucket_id=sem.memory.initial_value_binding`,
  `inject_kind=nexus.semantic.memory.initial_value_binding`, and
  `semantic_injection_applied=true`.
- Round9 repaired the ordinary f2ad memory proof baseline by moving the memory
  seed into the Nexus prover2 private-memory region:
  `cargo run -q --bin beak-trace -- --bin "000810b7 00808093 0000a183" --print-buckets`
  emitted `sem.memory.initial_value_binding`,
  `sem.row.padding_interaction_send`, and
  `sem.row.table_power2_boundary`, matched registers, and reported no
  backend error. The old `000020b7 0000a183` seed loads address `0x2000`,
  outside the prover2 private-memory layout, and remains invalid as strict
  baseline evidence.
- `me7` is still not strict Beak Good: the repaired private-memory seed with
  `--inject-kind nexus.semantic.memory.initial_value_binding --inject-step 3`
  fires the hook at `read_write_memory.ram1_val_prev_initial`, but the injected
  prover run fails constraints and semantic replay records
  `underconstrained_candidate=false`.
- Round10 mapping: `me11.written_cells` now maps
  `sem.memory.finalization_consistency` to a same-semantics prover2
  private-memory boundary hook in
  `prover2/machine/src/components/read_write_memory_boundary/private_memory/mod.rs`.
  The hook mutates `RamValFinal` on the boundary row selected by
  `private_boundary_row_idx`. Focused smoke
  `cargo run -q --bin beak-trace -- --bin "000810b7 00808093 07f00113 0020a023" --inject-kind nexus.semantic.memory.finalization_consistency --inject-step 1 --print-buckets`
  emitted `sem.memory.finalization_consistency`, printed
  `BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED kind=nexus.semantic.memory.finalization_consistency step=1 site=private_memory_boundary.ram_val_final`,
  and reported `injection_applied = true` with
  `backend_error = nexus verify failed: Proof has invalid structure: claimed logup sum is not zero`.
  This is mapping evidence only, not strict Beak Good.
- Round78 mapping: `me11.read_only_cells` now emits for private-memory bytes
  that are actually loaded and have no overlapping executed store. The bucket
  maps to the same private-memory boundary `RamValFinal` hook as
  `me11.written_cells`, anchored by `private_boundary_row_idx`. Focused smoke
  `cargo run -q --bin beak-trace -- --bin "000810b7 00808093 0000a183" --oracle-data-size-bytes 0x82020 --print-buckets`
  emitted `sem.memory.finalization_consistency` with
  `cell_id=me11.read_only_cells`. Ordinary semantic search on the same seed
  applied `nexus.semantic.memory.finalization_consistency` at private boundary
  step 1 and recorded `underconstrained_candidate=false` with
  `backend_error = nexus verify failed: Proof has invalid structure: claimed logup sum is not zero`.
  This is same-semantics mapping evidence only, not strict Beak Good.
- Round6 classification: `pd1.mem_padding` now has a reachable same-semantics
  prover2 hook for `sem.row.padding_interaction_send` in
  `prover2/machine/src/components/read_write_memory/trace.rs`. Focused smoke
  `cargo run -q --bin beak-trace -- --bin "00100093 00112023 00012183" --inject-kind nexus.semantic.row.padding_interaction_send --inject-step 2 --print-buckets`
  emitted `sem.row.padding_interaction_send`, printed
  `BEAK_NEXUS_SEMANTIC_INJECTION_APPLIED kind=nexus.semantic.row.padding_interaction_send step=2 site=prover2.read_write_memory.padding_row`,
  and reported `injection_applied = true`.
- Round9 strict Beak Good: ordinary `beak-fuzz` e2e on the repaired
  private-memory seed
  `cargo run -q --bin beak-fuzz -- --bin "000810b7 00808093 0000a183" --oracle-data-size-bytes 0x82020 --semantic-window-before 0 --semantic-window-after 0 --semantic-max-trials-per-bucket 1`
  recorded `trigger_bucket_id=sem.row.padding_interaction_send`,
  `inject_kind=nexus.semantic.row.padding_interaction_send`, `inject_step=1`,
  `semantic_injection_applied=true`, `backend_error=null`, and
  `underconstrained_candidate=true`.
- Invalid broadening kept rejected: `me11` is mapped only through the real
  private-memory boundary row, not the read/write-memory padding hook. Focused
  `nexus.semantic.memory.finalization_consistency` at the old padding step 2
  reports `injection_applied = false`. `me11.untouched_cells` remains
  trace-missing because the current trace does not enumerate untouched
  allocated memory cells. `pd3.mem_table` remains
  trace-observable/bucket-only because no table-size boundary mutation hook is
  identified. `me5` remains bucket-only for the missing mutation point
  described in the Nexus notes above; `me7.rodata/stack_uninit` remains
  trace-missing because the executed memory records do not expose provenance.
- Round12 strict replay audit: ordinary `beak-fuzz` e2e with exact-anchor
  semantic search on the repaired private-memory `me7` seed
  `000810b7 00808093 0000a183` applied
  `nexus.semantic.memory.initial_value_binding` at step 3 but recorded
  `underconstrained_candidate=false` with constraint/proof rejection. The same
  run rediscovered only the existing `pd1.mem_padding` strict bug. The
  `me11.written_cells` seed `000810b7 00808093 07f00113 0020a023` likewise
  applied `nexus.semantic.memory.finalization_consistency` at private boundary
  step 1 but recorded `underconstrained_candidate=false` with
  `claimed logup sum is not zero`; its only bug record was also the prior
  `pd1.mem_padding` candidate. No same-semantics prover2 mutation point was
  added for `me5` or `pd3`.
- Round15 rechecked the same repaired private-memory strict paths. `me7`
  still applies at step 3 but records `underconstrained_candidate=false` with
  `nexus prove failed: Constraints not satisfied`; `me11.written_cells` still
  applies at private-boundary step 1 but records
  `underconstrained_candidate=false` with the invalid-logup-sum verifier error.
  Both rechecks rediscovered only the existing strict `pd1.mem_padding`
  candidate. Source audit again found no same-semantics prover2 address-space
  selector for `me5` and no safe table-size/log-size witness row for
  `pd3.mem_table`.

### risc0 snapshots

- `risc0-98387806`: obligation pass completed to current Risc0 visibility.
  Instruction-local buckets now come from executed RV32IM oracle steps under the
  Risc0 split code/data layout; a raw ECALL at the next sequential PC is added
  because Risc0 handles it through host syscall flow while the shared oracle
  stops before ECALL.
- Verified semantic mappings with baseline plus applied injected smoke:
  `sem.decode.zero_register_immutability`,
  `sem.decode.operand_index_routing`,
  `sem.decode.rd_bit_decomposition`, `sem.decode.field_range`,
  `sem.decode.immediate_sign_extension`,
  `sem.decode.upper_immediate_materialization`,
  `sem.decode.format_immediate_reassembly`,
  `sem.exec.dest_binding`, `sem.exec.op_selector_binding`,
  `sem.alu.immediate_limb_consistency`, `sem.alu.shift_mod32`,
  `sem.alu.comparison_booleanity`, `sem.alu.subtraction_borrow_chain`,
  `sem.alu.comparison_auxiliary_chain`,
  `sem.arithmetic.special_case_consistency`,
  `sem.arithmetic.division_remainder_bound`,
  `sem.arithmetic.product_decomposition`,
  `sem.arithmetic.signed_unsigned_product_correction`,
  `sem.control.entrypoint_binding`,
  `sem.exec.control_flow_binding`, and
  `sem.control.ecall_argument_decomposition`.
- Risc0-98387806 deep hook pass: `rf3`, `id1`-`id3`, `id5`,
  `al1`-`al5`, `md1`, `md2`, `md4`, `md5`, `cf1`, `cf2`, `cf3` immediate
  cells, `cf4`, and `cf6.normal/after_branch_not_taken` now have
  baseline bucket evidence plus applied injected smokes. `cf3.clear_lsb/even/wrap`
  is mapped to the shared Risc0 control-flow hook; `cf3.even` verifies with
  `004000ef 00408067 00100113`, while `cf3.clear_lsb` still fails baseline
  witness generation before injection (`set(row: 1209, col: 14, val:
  0x0000000d) cur: 0x0000000c`) and wrap targets leave the installed code
  region, so that row is not marked verified.
- Risc0-98387806 memory/preflight hook pass: `me1`, `me2`, `me3`, `me4`,
  `me6`, `me7.bss_zero/data_loaded`, `me9`, `me10`,
  `me11.written_cells/read_only_cells`, and `ts2.same-address` now have
  baseline bucket evidence plus applied injected smokes. The installed-source
  hooks mutate Risc0 preflight load/store address decomposition, memory
  transaction value/cycle/address fields, and load/store decoder selectors.
  Main-memory `me5.mem_read/mem_write` is mapped through domain-specific
  address-space hooks; the ECALL/register `me5.reg_*` bucket remains
  bucket-only, so the coarse `me5` row is marked `semantic_injection_mapped`
  rather than verified. Baseline smokes:
  `cargo run -q --bin beak-trace -- --bin "000100b7 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`
  emitted `me1`, `me2`, `me3`, `me4`, `me5`, `me9`, `me11.written_cells`,
  `ts2.same-address`, and `pd1`; `000100b7 0000a183` emitted
  `me7.bss_zero` and `me11.read_only_cells`; `000100b7 0040a183` emitted
  `me7.data_loaded`; `bffff0b7 0000a183` emitted `me6.near_max_lw`. Injected
  replays for `risc0.semantic.memory.store_load_payload_flow` step 2,
  `risc0.semantic.memory.address_pointer_consistency` steps 1/4,
  `risc0.semantic.memory.value_payload_consistency` steps 4/5,
  `risc0.semantic.memory.address_space_consistency::domain=mem_read/mem_write`
  steps 1/4/5, `risc0.semantic.memory.kind_selector_consistency` steps 4/5,
  `risc0.semantic.memory.initial_value_binding` step 1,
  `risc0.semantic.memory.finalization_consistency` steps 1/5, and
  `risc0.semantic.time.monotonic_access_ordering` step 5 all reported
  `injection_applied = true` and verifier rejection.
- Trace-missing gaps for `risc0-98387806`: `me7.rodata/stack_uninit`, `me8`
  init-conflict cells, `me11.untouched_cells`, `ts2.cross_segment`,
  `cf6.near_segment_end`, `bu1`, and padding interaction sends remain
  trace_missing or bucket-only. Inspected paths
  include `risc0/circuit/rv32im/src/trace.rs::TraceEvent`,
  `execute/executor.rs`, `execute/r0vm.rs`, `execute/pager.rs`,
  `prove/witgen/preflight.rs`, and lookup/padding table generation. Preflight
  exposes accessed memory transactions and stable padding start rows, but not
  ELF/stack provenance, duplicate pre-coalescing memory init events, a complete
  untouched final-memory universe, cross-segment memory continuity, a padding
  interaction-send column, or a lookup-table multiplicity/is_real row suitable
  for `bu1`.
- Smoke evidence is recorded in
  `../agent_runs/vm-distributed/lead-risc0-98387806-deep-instrumentation.md`.
- `risc0-10fa9788` latest/M3: `me1`, `me3`, `me4`, and
  `ts2.same-address` are now
  `semantic_injection_mapped`. `me1` maps through
  `sem.memory.store_load_payload_flow -> risc0.semantic.memory.store_load_payload_flow`;
  `me3` maps through
  `sem.memory.load_value_binding -> risc0.semantic.memory.load_value_binding`;
  `me4` maps through
  `sem.memory.write_payload_consistency -> risc0.semantic.memory.write_payload_consistency`;
  `ts2.same-address` maps through
  `sem.time.monotonic_access_ordering -> risc0.semantic.time.monotonic_access_ordering`.
  The install asset patches the normal M3 `prove/beak.rs` path and mutates
  `InstLoadWitness.mem.value` for `me1`/`me3` and
  `InstStoreWitness.mem.value` for `me4`, and
  `InstLoadWitness.mem.prevCycle` for `ts2`; the backend maps only observed
  matching `obligation_id=me1`, `obligation_id=me3`, `obligation_id=me4`,
  and `obligation_id=ts2` bucket hits. Focused `me3` smoke
  `cargo run -q --bin beak-trace -- --bin "000100b7 00408093 07f00113 00208023 00008183" --inject-kind risc0.semantic.memory.load_value_binding --inject-step 4 --print-buckets`
  emitted `sem.memory.load_value_binding`, reported `injection_applied = true`,
  logged the `InstLoadWitness` mutation, and returned verifier rejection.
  Focused `me1` smoke with the same seed and
  `--inject-kind risc0.semantic.memory.store_load_payload_flow --inject-step 4`
  emitted `sem.memory.store_load_payload_flow`, reported
  `injection_applied = true`, logged the same proof-facing load memory value
  mutation, and returned verifier rejection. Focused `me4` smoke with the same
  seed and
  `--inject-kind risc0.semantic.memory.write_payload_consistency --inject-step 3`
  emitted `sem.memory.write_payload_consistency`, reported
  `injection_applied = true`, logged the proof-facing store memory value
  mutation, and returned verifier rejection. Focused `ts2` smoke with the same
  seed and
  `--inject-kind risc0.semantic.time.monotonic_access_ordering --inject-step 4`
  emitted `sem.time.monotonic_access_ordering`, reported
  `injection_applied = true`, logged the proof-facing load previous-cycle
  mutation, and returned verifier rejection. This is mapping evidence, not
  strict Beak Good. Other 10fa M3 memory buckets (`me2`, `me5`-`me7`,
  `me9`-`me11`) remain bucket-only until a same-semantics
  witness/prover mutation hook is added.
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
- Bucket-only c0db preflight coverage: `me1`-`me7.bss_zero/data_loaded`,
  `me9`, `me11.written_cells/read_only_cells`, `ts2.same-address`, and
  `pd1.exec_padding`. The legacy asset exports `RawMemoryTransaction` rows and
  preflight padding summaries; the backend joins them with actual
  `InstructionStart` events and register-memory reads. Baseline smokes:
  `cargo run -q --bin beak-trace -- --bin "000100b7 07f00113 0020a023 0000a183 002080a3 00108203" --print-buckets`
  emitted `me1`, `me2`, `me3`, `me4`, `me5`, `me9`, `me11.written_cells`,
  `ts2.same-address`, and `pd1`; `000100b7 0000a183` emitted
  `me7.bss_zero` and `me11.read_only_cells`; `bffff0b7 0000a183` emitted
  `me6.near_max_lw`.
- Remaining trace-missing c0db gaps: `me7.rodata/stack_uninit`, `me8`,
  `me11.untouched_cells`, `ts2.cross_segment`, JALR target
  clear-LSB/even/wrap cells, `cf6.near_segment_end`, `bu1`, and broader
  bus/lookup rows. Preflight exposes accessed memory transactions and padding
  start rows, but not ELF/stack provenance, duplicate pre-coalescing memory init
  events, a complete untouched final-memory universe, cross-segment memory
  continuity, or lookup multiplicity/is_real rows. No semantic injection mapping
  was added for the new memory/time/padding buckets because no stable legacy
  mutation hook has been validated.
- Smoke evidence is recorded in
  `../agent_runs/vm-distributed/lead-risc0-c0db0713.md`.
- Owner scope: the specific `projects/risc0-<commit>/` snapshot and
  `beak-py/projects/risc0-fuzzer/`.
