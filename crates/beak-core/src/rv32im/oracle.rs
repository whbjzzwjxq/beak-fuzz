use rrs_lib::HartState;
use rrs_lib::instruction_executor::{InstructionException, InstructionExecutor};
use rrs_lib::memories::{MemorySpace, VecMemory};

const MAX_INSTRUCTIONS: u32 = 1000;

pub struct RISCVOracle;

impl RISCVOracle {
    /// Execute instruction words starting at pc=0 with all registers zeroed.
    /// Returns all 32 register values after execution completes or faults.
    pub fn execute(words: &[u32]) -> [u32; 32] {
        let mut regs = [0u32; 32];
        if words.is_empty() {
            return regs;
        }

        let code_len_bytes = (words.len() * 4) as u32;
        let mut mem_space = MemorySpace::new();
        mem_space
            .add_memory(0, code_len_bytes, Box::new(VecMemory::new(words.to_vec())))
            .expect("add code region");

        let mut hart = HartState::new();
        hart.pc = 0;

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

        for i in 0..32 {
            regs[i] = hart.registers[i];
        }
        regs[0] = 0; // x0 is always 0
        regs
    }
}
