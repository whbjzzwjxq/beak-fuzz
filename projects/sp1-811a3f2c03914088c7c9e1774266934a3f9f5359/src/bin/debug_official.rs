use beak_sp1_811a3f2c::trace::build_sp1_program;
use sp1_core_executor::{Executor, ExecutorMode, Instruction, Opcode, Program};
use sp1_core_machine::utils::run_test;
use sp1_prover::SP1Prover;
use sp1_stark::{CpuProver, MachineProver, SP1CoreOpts, StarkGenericConfig};

fn local_simple_memory_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 29, 0, 0x12348765, false, true),
        Instruction::new(Opcode::SW, 29, 0, 0x27654320, false, true),
        Instruction::new(Opcode::LW, 28, 0, 0x27654320, false, true),
        Instruction::new(Opcode::LBU, 27, 0, 0x27654320, false, true),
        Instruction::new(Opcode::LBU, 26, 0, 0x27654321, false, true),
        Instruction::new(Opcode::LBU, 25, 0, 0x27654322, false, true),
        Instruction::new(Opcode::LBU, 24, 0, 0x27654323, false, true),
        Instruction::new(Opcode::LB, 23, 0, 0x27654320, false, true),
        Instruction::new(Opcode::LB, 22, 0, 0x27654321, false, true),
        Instruction::new(Opcode::LHU, 21, 0, 0x27654320, false, true),
        Instruction::new(Opcode::LHU, 20, 0, 0x27654322, false, true),
        Instruction::new(Opcode::LH, 19, 0, 0x27654320, false, true),
        Instruction::new(Opcode::LH, 18, 0, 0x27654322, false, true),
        Instruction::new(Opcode::ADD, 17, 0, 0x38276525, false, true),
        Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
        Instruction::new(Opcode::SB, 17, 0, 0x43627530, false, true),
        Instruction::new(Opcode::LW, 16, 0, 0x43627530, false, true),
        Instruction::new(Opcode::SB, 17, 0, 0x43627531, false, true),
        Instruction::new(Opcode::LW, 15, 0, 0x43627530, false, true),
        Instruction::new(Opcode::SB, 17, 0, 0x43627532, false, true),
        Instruction::new(Opcode::LW, 14, 0, 0x43627530, false, true),
        Instruction::new(Opcode::SB, 17, 0, 0x43627533, false, true),
        Instruction::new(Opcode::LW, 13, 0, 0x43627530, false, true),
        Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
        Instruction::new(Opcode::SH, 17, 0, 0x43627530, false, true),
        Instruction::new(Opcode::LW, 12, 0, 0x43627530, false, true),
        Instruction::new(Opcode::SH, 17, 0, 0x43627532, false, true),
        Instruction::new(Opcode::LW, 11, 0, 0x43627530, false, true),
    ];
    Program::new(instructions, 0, 0)
}

fn local_lui_load_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 2, 0, 0x27654000, true, true),
        Instruction::new(Opcode::LW, 3, 2, 0x320, false, true),
    ];
    Program::new(instructions, 0, 0)
}

fn local_lui_store_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 2, 0, 0x27654000, true, true),
        Instruction::new(Opcode::ADD, 3, 0, 1, false, true),
        Instruction::new(Opcode::SW, 3, 2, 0x320, false, true),
    ];
    Program::new(instructions, 0, 0)
}

fn local_ecall_program() -> Program {
    let instructions = vec![Instruction::new(Opcode::ECALL, 0, 0, 0, false, false)];
    Program::new(instructions, 0, 0)
}

fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let dump_runtime = if matches!(args.first().map(|s| s.as_str()), Some("--dump-runtime")) {
        args.remove(0);
        true
    } else {
        false
    };
    let dump_checkpoint_records =
        if matches!(args.first().map(|s| s.as_str()), Some("--dump-checkpoint-records")) {
            args.remove(0);
            true
        } else {
            false
        };
    let use_simple_memory = if matches!(args.first().map(|s| s.as_str()), Some("--simple-memory")) {
        args.remove(0);
        true
    } else {
        false
    };
    let use_lui_load = if matches!(args.first().map(|s| s.as_str()), Some("--lui-load")) {
        args.remove(0);
        true
    } else {
        false
    };
    let use_lui_store = if matches!(args.first().map(|s| s.as_str()), Some("--lui-store")) {
        args.remove(0);
        true
    } else {
        false
    };
    let use_ecall = if matches!(args.first().map(|s| s.as_str()), Some("--ecall")) {
        args.remove(0);
        true
    } else {
        false
    };
    let prove_records_shaped =
        if matches!(args.first().map(|s| s.as_str()), Some("--prove-records-shaped")) {
            args.remove(0);
            true
        } else {
            false
        };
    let words = args
        .into_iter()
        .map(|arg| u32::from_str_radix(arg.trim_start_matches("0x"), 16).expect("invalid hex word"))
        .collect::<Vec<_>>();
    let program = if use_simple_memory {
        local_simple_memory_program()
    } else if use_lui_load {
        local_lui_load_program()
    } else if use_lui_store {
        local_lui_store_program()
    } else if use_ecall {
        local_ecall_program()
    } else {
        build_sp1_program(&words).expect("build_sp1_program failed")
    };
    if dump_runtime {
        let mut executor = Executor::new(program.clone(), SP1CoreOpts::default());
        executor.executor_mode = ExecutorMode::Trace;
        executor.run().expect("executor.run failed");
        println!("runtime_records={}", executor.records.len());
        for (idx, record) in executor.records.iter().enumerate() {
            println!(
                "record[{idx}]: cpu_events={} init_events={} finalize_events={} shard={} exec_shard={} start_pc={} next_pc={} prev_fin_addr0={} last_fin_addr0={}",
                record.cpu_events.len(),
                record.global_memory_initialize_events.len(),
                record.global_memory_finalize_events.len(),
                record.public_values.shard,
                record.public_values.execution_shard,
                record.public_values.start_pc,
                record.public_values.next_pc,
                record.public_values.previous_finalize_addr_bits[0],
                record.public_values.last_finalize_addr_bits[0],
            );
            println!(
                "  init_addrs={:?}",
                record
                    .global_memory_initialize_events
                    .iter()
                    .map(|event| event.addr)
                    .collect::<Vec<_>>()
            );
            println!(
                "  finalize_addrs={:?}",
                record
                    .global_memory_finalize_events
                    .iter()
                    .map(|event| event.addr)
                    .collect::<Vec<_>>()
            );
        }
        return;
    }
    if dump_checkpoint_records {
        let prover: SP1Prover = SP1Prover::new();
        let mut program = program;
        if let Some(shape_config) = &prover.core_shape_config {
            shape_config
                .fix_preprocessed_shape(&mut program)
                .expect("fix_preprocessed_shape failed");
        }
        let maximal_shapes = prover
            .core_shape_config
            .as_ref()
            .map(|shape_config| {
                shape_config
                    .maximal_core_shapes()
                    .into_iter()
                    .map(|shape| shape.inner)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut executor = Executor::new(program.clone(), SP1CoreOpts::default());
        executor.maximal_shapes = Some(maximal_shapes);
        let (checkpoint, done) = executor.execute_state().expect("execute_state failed");
        println!("checkpoint_done={done}");
        let mut recovered = sp1_core_executor::Executor::recover(
            program.clone(),
            checkpoint,
            SP1CoreOpts::default(),
        );
        recovered.executor_mode = ExecutorMode::Trace;
        let (records, done_after) = recovered.execute_record().expect("execute_record failed");
        println!("execute_record_done={done_after}");
        println!("checkpoint_records={}", records.len());
        for (idx, record) in records.iter().enumerate() {
            println!(
                "record[{idx}]: cpu_events={} init_events={} finalize_events={} shard={} exec_shard={} start_pc={} next_pc={}",
                record.cpu_events.len(),
                record.global_memory_initialize_events.len(),
                record.global_memory_finalize_events.len(),
                record.public_values.shard,
                record.public_values.execution_shard,
                record.public_values.start_pc,
                record.public_values.next_pc,
            );
            println!(
                "  init_addrs={:?}",
                record
                    .global_memory_initialize_events
                    .iter()
                    .map(|event| event.addr)
                    .collect::<Vec<_>>()
            );
            println!(
                "  finalize_addrs={:?}",
                record
                    .global_memory_finalize_events
                    .iter()
                    .map(|event| event.addr)
                    .collect::<Vec<_>>()
            );
        }
        return;
    }
    if prove_records_shaped {
        let prover: SP1Prover = SP1Prover::new();
        let mut program = program;
        let shape_config = prover.core_shape_config.as_ref().expect("core shape config");
        shape_config
            .fix_preprocessed_shape(&mut program)
            .expect("fix_preprocessed_shape failed");
        let mut executor = Executor::new(program.clone(), SP1CoreOpts::default());
        executor.maximal_shapes = Some(
            shape_config
                .maximal_core_shapes()
                .into_iter()
                .map(|shape| shape.inner)
                .collect(),
        );
        executor.executor_mode = ExecutorMode::Trace;
        executor.run().expect("executor.run failed");
        let mut records = std::mem::take(&mut executor.records);
        prover
            .core_prover
            .machine()
            .generate_dependencies(&mut records, &SP1CoreOpts::default(), None);
        for record in records.iter_mut() {
            shape_config.fix_shape(record).expect("fix_shape failed");
        }
        for (idx, record) in records.iter_mut().enumerate() {
            record.public_values.shard = (idx + 1) as u32;
        }
        let (pk, vk) = prover.core_prover.setup(&program);
        let mut challenger = prover.core_prover.config().challenger();
        let proof = prover
            .core_prover
            .prove(&pk, records, &mut challenger, SP1CoreOpts::default())
            .expect("core_prover.prove failed");
        let mut verify_challenger = prover.core_prover.config().challenger();
        prover
            .core_prover
            .machine()
            .verify(&vk, &proof, &mut verify_challenger)
            .expect("verify failed");
        println!("prove_records_shaped=ok");
        return;
    }
    match run_test::<CpuProver<_, _>>(program) {
        Ok(_) => {
            println!("official_run_test=ok");
        }
        Err(err) => {
            println!("official_run_test=err");
            println!("{err}");
            std::process::exit(1);
        }
    }
}
