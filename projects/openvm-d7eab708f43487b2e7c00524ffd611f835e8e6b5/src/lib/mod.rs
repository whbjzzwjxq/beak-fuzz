pub mod backend;
pub mod bucket;
pub mod chip_row;
pub mod insn;
pub mod interaction;
pub mod trace;

use serde::{Deserialize, Serialize};
use strum::{EnumString, VariantNames};

pub type Pc = u32;
pub type Timestamp = u32;
pub type FieldElement = u32;

/// Address space for memory interactions (RAM, registers, volatile, I/O).
#[derive(Debug, Clone, Copy, EnumString, VariantNames, Serialize, Deserialize)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum MemorySpace {
    Ram,
    Reg,
    Volatile,
    Io,
}

/// Size of a memory access in bytes.
#[derive(Debug, Clone, Copy, EnumString, VariantNames, Serialize, Deserialize)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum MemorySize {
    Byte,
    Half,
    Word,
}

impl MemorySize {
    pub fn len(self) -> usize {
        match self {
            MemorySize::Byte => 1,
            MemorySize::Half => 2,
            MemorySize::Word => 4,
        }
    }
}
