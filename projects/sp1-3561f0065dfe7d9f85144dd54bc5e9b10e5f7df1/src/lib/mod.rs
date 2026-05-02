pub mod backend;
pub mod chip_row;
pub mod insn;
pub mod interaction;
pub mod trace;

pub type Pc = u32;
pub type Timestamp = u32;
pub type FieldElement = u32;

pub const SP1_COMMIT: &str = "3561f0065dfe7d9f85144dd54bc5e9b10e5f7df1";
pub const SP1_REPO_URL: &str = "https://github.com/succinctlabs/sp1.git";
