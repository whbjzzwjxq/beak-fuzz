// We decide to use different insn for different zkvm.
// So we only define the trait here, and let each zkvm implement its own insn.
// insn means a single instruction (maybe internal instruction or rv32im instruction) in the trace generation of a zkvm.
pub trait Insn: Send + Sync {}
