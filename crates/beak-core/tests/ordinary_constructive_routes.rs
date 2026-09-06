use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use beak_core::fuzz::benchmark::{
    run_benchmark, BenchmarkBackend, BenchmarkConfig, InjectionSchedule,
    SemanticInjectionCandidate,
};
use beak_core::fuzz::benchmark::{
    BackendEval, ExecutedExceptionEffect, ExecutedExceptionReceipt, SemanticMutationEffect,
    SemanticMutationReceipt, SemanticMutationRelation,
};
use beak_core::rv32im::oracle::{OracleConfig, RISCVOracle};
use beak_core::trace::BucketHit;
use serde_json::{json, Map, Value};

#[derive(Clone)]
struct SemanticRoute {
    expected_case_id: &'static str,
    backend: &'static str,
    commit: &'static str,
    carrier: Vec<u32>,
    hit: BucketHit,
    candidate: SemanticInjectionCandidate,
    relation: SemanticMutationRelation,
    receipt: SemanticMutationReceipt,
    executed_key: &'static str,
}

#[derive(Clone, Copy, Default)]
enum SemanticFault {
    #[default]
    None,
    MissingReceipt,
    StaleStep,
    ForgedIdentity,
    Unchanged,
    DuplicateHit,
    Nonexecuted,
    NotApplied,
}

struct SemanticRouteBackend {
    route: SemanticRoute,
    fault: SemanticFault,
    armed: bool,
}

impl BenchmarkBackend for SemanticRouteBackend {
    fn is_usable_seed(&self, words: &[u32]) -> bool {
        words == self.route.carrier
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        Ok(RISCVOracle::execute_with_config(words, OracleConfig::default()))
    }

    fn collect_eval(&mut self) -> BackendEval {
        let mut hits = vec![self.route.hit.clone()];
        if matches!(self.fault, SemanticFault::DuplicateHit) {
            hits.push(self.route.hit.clone());
        }
        let mut receipt = self.armed.then(|| self.route.receipt.clone());
        if let Some(receipt) = receipt.as_mut() {
            match self.fault {
                SemanticFault::StaleStep => receipt.step = receipt.step.saturating_add(1),
                SemanticFault::ForgedIdentity => {
                    receipt.effect.context.insert("commit".to_string(), json!("stale"));
                }
                SemanticFault::Unchanged => receipt.after = receipt.before.clone(),
                SemanticFault::Nonexecuted => {
                    receipt
                        .effect
                        .context
                        .insert(self.route.executed_key.to_string(), json!(false));
                }
                _ => {}
            }
        }
        if matches!(self.fault, SemanticFault::MissingReceipt) {
            receipt = None;
        }
        let applied = self.armed && !matches!(self.fault, SemanticFault::NotApplied);
        BackendEval {
            bucket_hits: hits,
            semantic_injection_applied: applied,
            semantic_mutation_receipt: receipt,
            ..BackendEval::default()
        }
    }

    fn clear_semantic_injection(&mut self) {
        self.armed = false;
    }

    fn arm_semantic_injection(&mut self, kind: &str, step: u64) -> Result<(), String> {
        if kind != self.route.candidate.inject_kind {
            return Err("unexpected constructive inject kind".to_string());
        }
        if step != self.route.receipt.step {
            return Err("unexpected constructive inject step".to_string());
        }
        self.armed = true;
        Ok(())
    }

    fn semantic_mutation_relation(
        &self,
        candidate: &SemanticInjectionCandidate,
    ) -> Option<SemanticMutationRelation> {
        (candidate.inject_kind == self.route.candidate.inject_kind).then_some(self.route.relation)
    }

    fn semantic_injection_candidates(&self, hits: &[BucketHit]) -> Vec<SemanticInjectionCandidate> {
        hits
            .iter()
            .any(|hit| hit.bucket_id == self.route.candidate.bucket_id)
            .then(|| self.route.candidate.clone())
            .into_iter()
            .collect()
    }
}

fn semantic_route(
    expected_case_id: &'static str,
    backend: &'static str,
    commit: &'static str,
    carrier: &[u32],
    bucket: &'static str,
    obligation: &'static str,
    cell: &'static str,
    source: &'static str,
    inject_kind: &'static str,
    relation: SemanticMutationRelation,
    step: u64,
    site: &'static str,
    field: &'static str,
    before: Value,
    after: Value,
    extra_context: impl IntoIterator<Item = (&'static str, Value)>,
    hit_pairs: impl IntoIterator<Item = (&'static str, &'static str)>,
    extra_hit: impl IntoIterator<Item = (&'static str, Value)>,
    executed_key: &'static str,
) -> SemanticRoute {
    let mut context = Map::from_iter([
        ("bucket_id".to_string(), json!(bucket)),
        ("obligation_id".to_string(), json!(obligation)),
        ("cell_id".to_string(), json!(cell)),
        ("backend".to_string(), json!(backend)),
        ("commit".to_string(), json!(commit)),
        ("trace_source".to_string(), json!(source)),
    ]);
    for (key, value) in extra_context {
        context.insert(key.to_string(), value);
    }
    let mut details = HashMap::from([
        ("obligation_id".to_string(), json!(obligation)),
        ("cell_id".to_string(), json!(cell)),
        ("backend".to_string(), json!(backend)),
        ("commit".to_string(), json!(commit)),
        ("trace_source".to_string(), json!(source)),
    ]);
    for (detail, context_key) in hit_pairs {
        details.insert(
            detail.to_string(),
            context.get(context_key).unwrap_or_else(|| panic!("missing {context_key}")).clone(),
        );
    }
    for (key, value) in extra_hit {
        details.insert(key.to_string(), value);
    }
    let candidate = SemanticInjectionCandidate {
        bucket_id: bucket.to_string(),
        trigger_signal_id: None,
        semantic_class: bucket.replacen("sem.", "semantic.", 1),
        inject_kind: inject_kind.to_string(),
        schedule: InjectionSchedule::Exact(step),
    };
    let receipt = SemanticMutationReceipt {
        inject_kind: inject_kind.to_string(),
        site: site.to_string(),
        field: field.to_string(),
        step,
        before,
        after,
        effect: SemanticMutationEffect {
            relation,
            preserved_before: None,
            preserved_after: None,
            context,
        },
    };
    SemanticRoute {
        expected_case_id,
        backend,
        commit,
        carrier: carrier.to_vec(),
        hit: BucketHit::semantic_id(bucket, details),
        candidate,
        relation,
        receipt,
        executed_key,
    }
}

fn semantic_routes() -> Vec<SemanticRoute> {
    const JOLT_E9: &str = "e9caa23565dbb13019afe61a2c95f51d1999e286";
    const NEXUS: &str = "636ccb360d0f4ae657ae4bb64e1e275ccec8826";
    const OPENVM_336: &str = "336f1a475e5aa3513c4c5a266399f4128c119bba";
    const OPENVM_F038: &str = "f038f61d21db3aecd3029e1a23ba1ba0bb314800";
    const SP1_39: &str = "39ab52fce38172c9d23feed7248198dc14c164a9";
    const SP1_7F: &str = "7f643da16813af4c0fbaad4837cd7409386cf38c";
    const MEMORY: &[u32] = &[0x0400_0093, 0x0070_0113, 0x0020_a023, 0x0000_a183];
    const DIV: &[u32] = &[0x8000_00b7, 0xfff0_0113, 0x0220_c1b3];

    vec![
        semantic_route(
            "Jolt-EntryPc-Binding-01",
            "jolt",
            JOLT_E9,
            &[0x0010_0093],
            "sem.control.entrypoint_binding",
            "cf4",
            "cf4.default_entry",
            "instruction",
            "jolt.semantic.control.entrypoint_binding",
            SemanticMutationRelation::EntrypointPcEquation,
            0,
            "bytecode.row0",
            "address",
            json!(0),
            json!(4),
            [
                ("boundary_row", json!(0)),
                ("declared_entry", json!(0)),
                ("witnessed_pc_before", json!(0)),
                ("witnessed_pc_after", json!(4)),
                ("executed_boundary_row", json!(true)),
                ("pc", json!(0)),
                ("opcode", json!(0x0010_0093u64)),
                ("mnemonic", json!("addi")),
            ],
            [
                ("op_idx", "boundary_row"),
                ("pc", "pc"),
                ("opcode", "opcode"),
                ("mnemonic", "mnemonic"),
                ("declared_entry", "declared_entry"),
            ],
            [],
            "executed_boundary_row",
        ),
        semantic_route(
            "Jolt-Immediate-01",
            "jolt",
            JOLT_E9,
            DIV,
            "sem.decode.upper_immediate_materialization",
            "id3",
            "id3.lui_mid",
            "instruction",
            "jolt.semantic.decode.upper_immediate_materialization",
            SemanticMutationRelation::UpperImmediateEquation,
            0,
            "instruction_lookup.row0",
            "materialized_value",
            json!(0x8000_0000u64),
            json!(0x8000_0001u64),
            [
                ("op_idx", json!(0)),
                ("pc", json!(0)),
                ("opcode", json!(0x8000_00b7u64)),
                ("mnemonic", json!("lui")),
                ("imm20", json!(0x80000)),
                ("expected_result", json!(0x8000_0000u64)),
                ("witnessed_result_before", json!(0x8000_0000u64)),
                ("witnessed_result_after", json!(0x8000_0001u64)),
                ("executed_instruction", json!(true)),
            ],
            [("op_idx", "op_idx"), ("pc", "pc"), ("opcode", "opcode"), ("mnemonic", "mnemonic")],
            [],
            "executed_instruction",
        ),
        semantic_route(
            "Nexus-Operand-01",
            "nexus",
            NEXUS,
            MEMORY,
            "sem.memory.store_load_payload_flow",
            "me1",
            "me1.sw_lw",
            "memory",
            "nexus.semantic.memory.store_load_payload_flow",
            SemanticMutationRelation::StoreLoadPayloadEquation,
            2,
            "uniform.memory.store",
            "store_value",
            json!(7),
            json!(0x5a),
            [
                ("store_step", json!(2)),
                ("load_step", json!(3)),
                ("store_address", json!(64)),
                ("load_address", json!(64)),
                ("store_value", json!(7)),
                ("store_value_before", json!(7)),
                ("store_value_after", json!(0x5a)),
                ("load_value_before", json!(7)),
                ("load_value_after", json!(0x5a)),
                ("width", json!(4)),
                ("mutation_mode", json!("replace_low_byte_5a_a5")),
                ("executed_store", json!(true)),
                ("executed_load", json!(true)),
            ],
            [
                ("op_idx", "store_step"),
                ("load_step_idx", "load_step"),
                ("effective_ptr", "store_address"),
                ("write_data", "store_value"),
                ("read_data", "load_value_before"),
                ("width", "width"),
            ],
            [],
            "executed_store",
        ),
        semantic_route(
            "OpenVM-AddrSpace-Audit-o51",
            "openvm",
            OPENVM_F038,
            MEMORY,
            "sem.memory.address_space_consistency",
            "me5",
            "me5.mem_write",
            "memory_access",
            "openvm.semantic.memory.address_space_consistency::mode=bus_mem_as_reg",
            SemanticMutationRelation::AddressSpaceConsistencyEquation,
            2,
            "rv32_loadstore_adapter.preprocess",
            "memory_address_space",
            json!(2),
            json!(1),
            [
                ("row_idx", json!(2)),
                ("pc", json!(8)),
                ("opcode", json!(0x0020_a023u64)),
                ("mnemonic", json!("sw")),
                ("is_memory", json!(true)),
                ("register_address_space", json!(1)),
                ("memory_address_space", json!(2)),
                ("address_space_before", json!(2)),
                ("address_space_after", json!(1)),
                ("mode", json!("bus_mem_as_reg")),
                ("executed_access", json!(true)),
            ],
            [
                ("op_idx", "row_idx"),
                ("pc", "pc"),
                ("opcode", "opcode"),
                ("mnemonic", "mnemonic"),
                ("address_space", "address_space_before"),
            ],
            [("is_load", json!(false)), ("is_store", json!(true))],
            "executed_access",
        ),
        semantic_route(
            "OpenVM-Multiple-Audit-o15",
            "openvm",
            OPENVM_336,
            DIV,
            "sem.arithmetic.special_case_consistency",
            "md2",
            "md2.div_overflow",
            "chip_row",
            "openvm.semantic.arithmetic.special_case_consistency",
            SemanticMutationRelation::DivisionRemainderSpecialCaseEquation,
            2,
            "divrem_core.execute_instruction",
            "operand_divisor",
            json!(0xffff_ffffu64),
            json!(0),
            [
                ("step", json!(2)),
                ("pc", json!(8)),
                ("opcode", json!(0x0220_c1b3u64)),
                ("mnemonic", json!("div")),
                ("mutation_mode", json!("executor_divisor_reclass")),
                ("dividend", json!(i32::MIN as i64)),
                ("dividend_word", json!(0x8000_0000u64)),
                ("claimed_divisor", json!(-1)),
                ("claimed_divisor_word", json!(0xffff_ffffu64)),
                ("materialized_divisor_word", json!(0)),
                ("quotient", json!(i32::MIN as i64)),
                ("remainder", json!(0)),
                ("special_selector_before", json!(0)),
                ("special_selector_after", json!(1)),
                ("executed_instruction", json!(true)),
            ],
            [
                ("op_idx", "step"),
                ("pc", "pc"),
                ("opcode", "opcode"),
                ("mnemonic", "mnemonic"),
                ("rs1_val", "dividend_word"),
                ("rs2_val", "claimed_divisor_word"),
            ],
            [],
            "executed_instruction",
        ),
        semantic_route(
            "OpenVM-RangeCheck-Audit-o5",
            "openvm",
            OPENVM_336,
            &[0x0010_0093],
            "sem.alu.immediate_limb_consistency",
            "al1",
            "al1.single_limb",
            "decoded_instruction",
            "openvm.semantic.alu.immediate_limb_consistency::mode=adjacent_radix_carry,carry_slot=0,borrow_slot=1",
            SemanticMutationRelation::FullLimbValueRepresentation,
            0,
            "rv32_base_alu_adapter.preprocess",
            "rs2_data_limbs",
            json!([1, 0, 0, 0]),
            json!([257, 2_013_265_920u64, 0, 0]),
            [
                ("op_idx", json!(0)),
                ("imm", json!(1)),
                ("value", json!(1)),
                ("mode", json!("adjacent_radix_carry")),
                ("carry_slot", json!(0)),
                ("borrow_slot", json!(1)),
                ("radix", json!(256)),
                ("field_modulus", json!(2_013_265_921u64)),
                ("limb_count", json!(4)),
                ("before_limbs", json!([1, 0, 0, 0])),
                ("after_limbs", json!([257, 2_013_265_920u64, 0, 0])),
                ("recomposed_before", json!(1)),
                ("recomposed_after", json!(1)),
                ("executed_instruction", json!(true)),
            ],
            [("op_idx", "op_idx"), ("imm", "value")],
            [],
            "executed_instruction",
        ),
        semantic_route(
            "Sp1-Memory-Audit-s27",
            "sp1",
            SP1_39,
            MEMORY,
            "sem.exec.memory_effect_binding",
            "me10",
            "me10.load",
            "instruction",
            "sp1.semantic.exec.memory_effect_binding",
            SemanticMutationRelation::MemorySelectorEquation,
            3,
            "cpu.event_to_row",
            "is_memory",
            json!(1),
            json!(0),
            [
                ("step", json!(3)),
                ("op_idx", json!(3)),
                ("pc", json!(12)),
                ("opcode", json!(0x0000_a183u64)),
                ("mnemonic", json!("lw")),
                ("expected_is_memory", json!(1)),
                ("selector_before", json!(1)),
                ("selector_after", json!(0)),
                ("executed_cpu_row", json!(true)),
            ],
            [("op_idx", "op_idx"), ("pc", "pc"), ("opcode", "opcode"), ("mnemonic", "mnemonic")],
            [],
            "executed_cpu_row",
        ),
        semantic_route(
            "Sp1-Pc-Audit-s28",
            "sp1",
            SP1_7F,
            &[0x0020_0293, 0x0000_0073, 0x0000_0293, 0x0000_0073],
            "sem.exec.control_flow_binding",
            "cf6",
            "cf6.normal",
            "instruction",
            "sp1.semantic.exec.control_flow_binding::family=ecall,mode=near_jump",
            SemanticMutationRelation::ExecutedControlFlowEquation,
            1,
            "executor.execute_cycle",
            "next_pc",
            json!(8),
            json!(12),
            [
                ("step", json!(1)),
                ("op_idx", json!(1)),
                ("pc", json!(4)),
                ("opcode", json!(0x73)),
                ("mnemonic", json!("ecall")),
                ("expected_next_pc", json!(8)),
                ("observed_next_pc_before", json!(8)),
                ("observed_next_pc_after", json!(12)),
                ("executed_instruction", json!(true)),
                ("control_flow_family", json!("ecall")),
                ("family", json!("ecall")),
                ("mode", json!("near_jump")),
            ],
            [("op_idx", "op_idx"), ("pc", "pc"), ("opcode", "opcode"), ("mnemonic", "mnemonic")],
            [],
            "executed_instruction",
        ),
    ]
}

#[derive(Clone)]
struct ExceptionRoute {
    expected_case_id: &'static str,
    backend: &'static str,
    commit: &'static str,
    carrier: Vec<u32>,
    hit: BucketHit,
    receipt: ExecutedExceptionReceipt,
}

struct ExceptionRouteBackend(ExceptionRoute);

impl BenchmarkBackend for ExceptionRouteBackend {
    fn is_usable_seed(&self, words: &[u32]) -> bool {
        words == self.0.carrier
    }

    fn prove_and_read_final_regs(&mut self, words: &[u32]) -> Result<[u32; 32], String> {
        Ok(RISCVOracle::execute_with_config(words, OracleConfig::default()))
    }

    fn collect_eval(&mut self) -> BackendEval {
        BackendEval {
            bucket_hits: vec![self.0.hit.clone()],
            backend_error: Some("typed constructive exception".to_string()),
            executed_exception_receipt: Some(self.0.receipt.clone()),
            ..BackendEval::default()
        }
    }
}

fn exception_routes() -> Vec<ExceptionRoute> {
    let dory_commit = "d67f5a2a4f465891d9ab5039fd3f18b19c38fe3b";
    let dory_details = HashMap::from([
        ("backend".to_string(), json!("jolt")),
        ("commit".to_string(), json!(dory_commit)),
        ("trace_source".to_string(), json!("prover.dory")),
        ("obligation_id".to_string(), json!("pd2")),
        ("cell_id".to_string(), json!("pd2.very_short")),
        ("step_idx".to_string(), json!(32)),
        ("input_words_len".to_string(), json!(1)),
        ("unpadded_trace_len".to_string(), json!(20)),
        ("dory_domain_size".to_string(), json!(32)),
        ("matrix_width_k".to_string(), json!(256)),
        ("dory_dimension".to_string(), json!(128)),
        ("boundary_k".to_string(), json!(5)),
        ("relation".to_string(), json!("dory_domain_not_greater_than_matrix_dimension")),
        ("relation_valid".to_string(), json!(true)),
    ]);
    let dory_receipt = ExecutedExceptionReceipt {
        effect: ExecutedExceptionEffect::DoryShortTraceCapacity,
        obligation_id: "pd2".to_string(),
        cell_id: "pd2.very_short".to_string(),
        stage: "dory.commitment.domain_size".to_string(),
        step: 32,
        context: Map::from_iter([
            ("backend".to_string(), json!("jolt")),
            ("commit".to_string(), json!(dory_commit)),
            ("trace_source".to_string(), json!("prover.dory")),
            ("input_words_len".to_string(), json!(1)),
            ("unpadded_trace_len".to_string(), json!(20)),
            ("dory_domain_size".to_string(), json!(32)),
            ("matrix_width_k".to_string(), json!(256)),
            ("dory_dimension".to_string(), json!(128)),
            ("boundary_k".to_string(), json!(5)),
            ("failing_domain_size".to_string(), json!(32)),
            ("relation".to_string(), json!("dory_domain_not_greater_than_matrix_dimension")),
        ]),
    };

    let bigint_commit = "336f1a475e5aa3513c4c5a266399f4128c119bba";
    let bigint_source = "extensions/rv32im/circuit/src/branch_lt/core.rs::execute_instruction";
    let bigint_details = HashMap::from([
        ("obligation_id".to_string(), json!("id4")),
        ("cell_id".to_string(), json!("id4.branch")),
        ("backend".to_string(), json!("openvm")),
        ("commit".to_string(), json!(bigint_commit)),
        ("trace_source".to_string(), json!(bigint_source)),
        ("step_idx".to_string(), json!(3)),
        ("op_idx".to_string(), json!(3)),
        ("from_pc".to_string(), json!(17)),
        ("global_opcode".to_string(), json!(0x425)),
        ("chip_class_offset".to_string(), json!(0x408)),
        ("local_opcode".to_string(), json!(29)),
        ("supported_local_opcodes".to_string(), json!([0, 1, 2, 3])),
        ("conversion_target".to_string(), json!("BranchLessThanOpcode")),
        ("relation".to_string(), json!("local_opcode_not_in_branch_less_than_domain")),
        ("relation_valid".to_string(), json!(true)),
    ]);
    let bigint_receipt = ExecutedExceptionReceipt {
        effect: ExecutedExceptionEffect::BigIntOpcodeConversion,
        obligation_id: "id4".to_string(),
        cell_id: "id4.branch".to_string(),
        stage: "openvm.bigint.branch_less_than_opcode_conversion".to_string(),
        step: 3,
        context: Map::from_iter([
            ("backend".to_string(), json!("openvm")),
            ("commit".to_string(), json!(bigint_commit)),
            ("trace_source".to_string(), json!(bigint_source)),
            ("from_pc".to_string(), json!(17)),
            ("global_opcode".to_string(), json!(0x425)),
            ("chip_class_offset".to_string(), json!(0x408)),
            ("local_opcode".to_string(), json!(29)),
            ("supported_local_opcodes".to_string(), json!([0, 1, 2, 3])),
            ("conversion_target".to_string(), json!("BranchLessThanOpcode")),
            ("relation".to_string(), json!("local_opcode_not_in_branch_less_than_domain")),
            ("relation_valid".to_string(), json!(true)),
            ("hook_fired".to_string(), json!(true)),
        ]),
    };

    let control_commit = "6f038bd11ed725d7025687d163977d93ac1f82f9";
    let control_details = HashMap::from([
        ("obligation_id".to_string(), json!("pd2")),
        ("cell_id".to_string(), json!("pd2.just_over")),
        ("backend".to_string(), json!("risc0")),
        ("commit".to_string(), json!(control_commit)),
        ("trace_source".to_string(), json!("segment_finalization")),
        ("segment_idx".to_string(), json!(3)),
        ("step_idx".to_string(), json!(3)),
        ("segment_po2".to_string(), json!(4)),
        ("capacity_cycles".to_string(), json!(16)),
        ("user_cycles".to_string(), json!(9)),
        ("pager_cycles".to_string(), json!(2)),
        ("lookup_table_cycles".to_string(), json!(5)),
        ("accounted_cycles".to_string(), json!(16)),
        ("control_done_cycles_required".to_string(), json!(2)),
        ("required_cycles".to_string(), json!(18)),
        ("overflow_cycles".to_string(), json!(2)),
        ("actual_trace_cycles".to_string(), json!(17)),
        ("manifested_control_done_cycles".to_string(), json!(1)),
        ("relation".to_string(), json!("control_done_cycles_cross_segment_capacity")),
        ("relation_valid".to_string(), json!(true)),
        ("accounted_fits".to_string(), json!(true)),
        ("required_exceeds".to_string(), json!(true)),
    ]);
    let control_context = Map::from_iter([
        ("segment_idx".to_string(), json!(3)),
        ("segment_po2".to_string(), json!(4)),
        ("capacity_cycles".to_string(), json!(16)),
        ("user_cycles".to_string(), json!(9)),
        ("pager_cycles".to_string(), json!(2)),
        ("lookup_table_cycles".to_string(), json!(5)),
        ("accounted_cycles".to_string(), json!(16)),
        ("control_done_cycles_required".to_string(), json!(2)),
        ("required_cycles".to_string(), json!(18)),
        ("overflow_cycles".to_string(), json!(2)),
        ("actual_trace_cycles".to_string(), json!(17)),
        ("manifested_control_done_cycles".to_string(), json!(1)),
        ("accounted_fits".to_string(), json!(true)),
        ("required_exceeds".to_string(), json!(true)),
        ("backend".to_string(), json!("risc0")),
        ("commit".to_string(), json!(control_commit)),
        ("trace_source".to_string(), json!("segment_finalization")),
    ]);

    vec![
        ExceptionRoute {
            expected_case_id: "Jolt-Dory-ShortTrace-01",
            backend: "jolt",
            commit: dory_commit,
            carrier: vec![0x0010_0093],
            hit: BucketHit::semantic_id("sem.row.trace_power2_boundary", dory_details),
            receipt: dory_receipt,
        },
        ExceptionRoute {
            expected_case_id: "OpenVM-Memory-Audit-o19",
            backend: "openvm",
            commit: bigint_commit,
            carrier: vec![0x8000_02b7, 0xfff0_0313, 0x0062_c263, 0x0000_0073],
            hit: BucketHit::semantic_id("sem.decode.field_range", bigint_details),
            receipt: bigint_receipt,
        },
        ExceptionRoute {
            expected_case_id: "Risc0-ControlDone-Cycle-01",
            backend: "risc0",
            commit: control_commit,
            carrier: vec![0x0080_0093, 0xfff0_8093, 0xfe00_9ee3, 0x0000_0073],
            hit: BucketHit::semantic_id("sem.row.trace_power2_boundary", control_details),
            receipt: ExecutedExceptionReceipt {
                effect: ExecutedExceptionEffect::ControlDoneCapacity,
                obligation_id: "pd2".to_string(),
                cell_id: "pd2.just_over".to_string(),
                stage: "risc0.segment.control_done_capacity".to_string(),
                step: 3,
                context: control_context,
            },
        },
    ]
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("beak-r2-{label}-{}-{nonce}", std::process::id()))
}

fn config(backend: &str, commit: &str, dir: &std::path::Path, seeds: PathBuf) -> BenchmarkConfig {
    BenchmarkConfig {
        zkvm_tag: backend.to_string(),
        zkvm_commit: commit.to_string(),
        rng_seed: 2026,
        oracle: OracleConfig::default(),
        seeds_jsonl: seeds,
        out_dir: dir.to_path_buf(),
        output_prefix: Some("constructive-route".to_string()),
        initial_limit: 1,
        mutation_iterations: 0,
        max_instructions: 256,
        long_tail_max_instructions: 0,
        precheck_oracle_max_steps: 32,
        semantic_search_enabled: true,
        semantic_window_before: 16,
        semantic_window_after: 64,
        semantic_step_stride: 1,
        semantic_max_trials_per_bucket: 1,
        stack_size_bytes: 16 * 1024 * 1024,
    }
}

fn write_seed(dir: &std::path::Path, carrier: &[u32]) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("ordinary.jsonl");
    std::fs::write(
        &path,
        format!(
            "{}\n",
            json!({
                "instructions": carrier,
                "metadata": {"source": "ordinary_corpus", "case_id": "caller-forged"}
            })
        ),
    )
    .unwrap();
    path
}

fn bug_rows(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn all_non_pico_semantic_routes_join_carrier_scheduler_receipt_classifier_and_persistence() {
    for route in semantic_routes() {
        let dir = temp_dir(route.expected_case_id);
        let seeds = write_seed(&dir, &route.carrier);
        let outputs = run_benchmark(
            config(route.backend, route.commit, &dir, seeds),
            SemanticRouteBackend { route: route.clone(), fault: SemanticFault::None, armed: false },
        )
        .unwrap_or_else(|error| panic!("{} route failed: {error}", route.expected_case_id));
        let rows = bug_rows(&outputs.bugs_path);
        assert_eq!(rows.len(), 1, "{} must persist one strict bug", route.expected_case_id);
        let metadata = &rows[0]["metadata"];
        assert_eq!(metadata["kind"], json!("underconstrained_candidate"));
        assert_eq!(metadata["semantic_injection_applied"], json!(true));
        assert_eq!(metadata["semantic_relation_validated"], json!(true));
        assert_eq!(metadata["case_id"], json!(route.expected_case_id));
        assert_ne!(metadata["case_id"], json!("caller-forged"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn all_non_pico_semantic_routes_fail_closed_on_bad_evidence() {
    let faults = [
        SemanticFault::MissingReceipt,
        SemanticFault::StaleStep,
        SemanticFault::ForgedIdentity,
        SemanticFault::Unchanged,
        SemanticFault::DuplicateHit,
        SemanticFault::Nonexecuted,
        SemanticFault::NotApplied,
    ];
    for route in semantic_routes() {
        for (fault_idx, fault) in faults.into_iter().enumerate() {
            let dir = temp_dir(&format!("{}-{fault_idx}", route.expected_case_id));
            let seeds = write_seed(&dir, &route.carrier);
            let outputs = run_benchmark(
                config(route.backend, route.commit, &dir, seeds),
                SemanticRouteBackend { route: route.clone(), fault, armed: false },
            )
            .unwrap();
            assert!(
                bug_rows(&outputs.bugs_path).is_empty(),
                "{} fault {fault_idx} must fail closed",
                route.expected_case_id
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[test]
fn all_typed_exception_routes_join_carrier_scheduler_receipt_classifier_and_persistence() {
    for route in exception_routes() {
        let dir = temp_dir(route.expected_case_id);
        let seeds = write_seed(&dir, &route.carrier);
        let outputs = run_benchmark(
            config(route.backend, route.commit, &dir, seeds),
            ExceptionRouteBackend(route.clone()),
        )
        .unwrap();
        let rows = bug_rows(&outputs.bugs_path);
        assert_eq!(rows.len(), 1, "{} must persist one strict exception", route.expected_case_id);
        let metadata = &rows[0]["metadata"];
        assert_eq!(metadata["kind"], json!("exception"));
        assert_eq!(metadata["case_id"], json!(route.expected_case_id));
        assert_ne!(metadata["case_id"], json!("caller-forged"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
