//! RISC-V oracle: compute expected register results by simulating execution with rrs-lib.

use std::collections::HashMap;

use rrs_lib::HartState;
use rrs_lib::instruction_executor::{InstructionException, InstructionExecutor};
use rrs_lib::memories::{MemorySpace, VecMemory};

use crate::fuzz::seed::FuzzingSeed;
use crate::rv32im::instruction::RV32IMInstruction;

/// Default code base (PC start). Matches riscv-tests dump entry `_start` at 0x8000_0000 and
/// typical zkVM / RISC-V test harness layout (see `storage/riscv-tests-artifacts/*.dump`).
pub const DEFAULT_CODE_BASE: u32 = 0x8000_0000;

/// Maximum number of instructions to execute to avoid infinite loops.
const MAX_INSTRUCTIONS: u32 = 1000;

/// Oracle that computes expected register values by running the seed's program in rrs-lib.
pub struct RISCVOracle;

impl RISCVOracle {
    /// Run the program from `seed` in the rrs-lib simulator and return the final register values
    /// for every register that was in `initial_regs`. Execution is limited to `MAX_INSTRUCTIONS`;
    /// on fetch/illegal/load/store/align errors execution stops and current register state is returned.
    pub fn compute_expected_results(seed: &FuzzingSeed) -> HashMap<u32, u32> {
        if seed.instructions.is_empty() {
            return seed
                .initial_regs
                .keys()
                .copied()
                .map(|idx| (idx, if idx == 0 { 0 } else { seed.initial_regs[&idx] }))
                .collect();
        }

        let base_addr = DEFAULT_CODE_BASE;
        let code_words: Vec<u32> =
            seed.instructions.iter().map(|inst: &RV32IMInstruction| inst.word).collect();
        let code_len_bytes = code_words.len().saturating_mul(4);

        let mut mem_space = MemorySpace::new();
        mem_space
            .add_memory(base_addr, code_len_bytes as u32, Box::new(VecMemory::new(code_words)))
            .expect("add code region at DEFAULT_CODE_BASE");

        let mut hart = HartState::new();
        hart.pc = base_addr;
        for (reg_idx, &val) in &seed.initial_regs {
            let i = *reg_idx as usize;
            if i < 32 {
                hart.registers[i] = val;
            }
        }
        hart.registers[0] = 0;

        let mut executor = InstructionExecutor {
            hart_state: &mut hart,
            mem: &mut mem_space,
        };

        let mut steps = 0u32;
        while steps < MAX_INSTRUCTIONS {
            match executor.step() {
                Ok(()) => steps += 1,
                Err(
                    InstructionException::FetchError(_)
                    | InstructionException::IllegalInstruction(_, _)
                    | InstructionException::LoadAccessFault(_)
                    | InstructionException::StoreAccessFault(_)
                    | InstructionException::AlignmentFault(_),
                ) => break,
            }
        }

        seed.initial_regs
            .keys()
            .copied()
            .map(|idx| {
                let i = idx as usize;
                let val = if i < 32 { hart.registers[i] } else { 0 };
                (idx, val)
            })
            .collect()
    }
}
