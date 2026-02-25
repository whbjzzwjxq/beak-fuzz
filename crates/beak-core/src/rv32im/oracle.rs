use rrs_lib::HartState;
use rrs_lib::instruction_executor::{InstructionException, InstructionExecutor};
use rrs_lib::memories::{MemorySpace, VecMemory};

const MAX_INSTRUCTIONS: u32 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleMemoryModel {
    /// Legacy model: code and data share one region at address 0.
    SharedCodeData,
    /// OpenVM-aligned model: data RAM at low addresses, code mapped at a separate base.
    SplitCodeData,
}

impl OracleMemoryModel {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "shared" | "shared-code-data" | "unified" | "legacy" => Ok(Self::SharedCodeData),
            "split" | "split-code-data" | "separate" | "openvm" => Ok(Self::SplitCodeData),
            other => Err(format!(
                "invalid oracle memory model '{other}', expected one of: \
shared-code-data, split-code-data"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OracleConfig {
    pub memory_model: OracleMemoryModel,
    /// Base address used to map instruction words when `memory_model` is split.
    pub code_base: u32,
    /// Size of zero-initialized data RAM region mapped at address 0 in split mode.
    pub data_size_bytes: u32,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            memory_model: OracleMemoryModel::SharedCodeData,
            code_base: 0,
            data_size_bytes: 0,
        }
    }
}

pub struct RISCVOracle;

impl RISCVOracle {
    /// Execute instruction words starting at pc=0 with all registers zeroed.
    /// Returns all 32 register values after execution completes or faults.
    pub fn execute(words: &[u32]) -> [u32; 32] {
        Self::execute_with_config(words, OracleConfig::default())
    }

    /// Execute with configurable memory model so backends can align oracle semantics.
    pub fn execute_with_config(words: &[u32], cfg: OracleConfig) -> [u32; 32] {
        let mut regs = [0u32; 32];
        if words.is_empty() {
            return regs;
        }

        let code_len_bytes = (words.len() * 4) as u32;
        let mut mem_space = MemorySpace::new();
        let mut hart = HartState::new();
        match cfg.memory_model {
            OracleMemoryModel::SharedCodeData => {
                mem_space
                    .add_memory(0, code_len_bytes, Box::new(VecMemory::new(words.to_vec())))
                    .expect("add code region");
                hart.pc = 0;
            }
            OracleMemoryModel::SplitCodeData => {
                let data_bytes = cfg.data_size_bytes.max(4);
                let data_words = ((data_bytes as usize) + 3) / 4;
                let data_region_len = (data_words * 4) as u32;
                mem_space
                    .add_memory(0, data_region_len, Box::new(VecMemory::new(vec![0; data_words])))
                    .expect("add zeroed data region");

                let min_code_base = data_region_len.saturating_add(4);
                let mut code_base = cfg.code_base.max(min_code_base);
                code_base &= !0x3; // 4-byte alignment
                mem_space
                    .add_memory(code_base, code_len_bytes, Box::new(VecMemory::new(words.to_vec())))
                    .expect("add code region");
                hart.pc = code_base;
            }
        }

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
