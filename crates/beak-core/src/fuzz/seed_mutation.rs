use std::num::NonZeroUsize;

use libafl_bolts::rands::{Rand, StdRand};

use crate::rv32im::instruction::RV32IMInstruction;

fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n.max(1)).unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationArm {
    Splice,
    RegisterReuse,
    ConstantBoundary,
    InsertInstruction,
    DeleteInstruction,
    DuplicateInstruction,
    SwapAdjacent,
    ReplaceMnemonic,
}

impl MutationArm {
    pub const COUNT: usize = 8;

    pub fn from_index(i: usize) -> Self {
        match i {
            0 => Self::Splice,
            1 => Self::RegisterReuse,
            2 => Self::ConstantBoundary,
            3 => Self::InsertInstruction,
            4 => Self::DeleteInstruction,
            5 => Self::DuplicateInstruction,
            6 => Self::SwapAdjacent,
            7 => Self::ReplaceMnemonic,
            _ => Self::InsertInstruction,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Splice => "splice",
            Self::RegisterReuse => "register_reuse",
            Self::ConstantBoundary => "constant_boundary",
            Self::InsertInstruction => "insert_instruction",
            Self::DeleteInstruction => "delete_instruction",
            Self::DuplicateInstruction => "duplicate_instruction",
            Self::SwapAdjacent => "swap_adjacent",
            Self::ReplaceMnemonic => "replace_mnemonic",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SeedMutation {
    pub words: Vec<u32>,
    pub arm: MutationArm,
    pub arm_index: usize,
}

#[derive(Debug, Clone)]
struct ArmStats {
    pulls: u64,
    total_reward: f64,
}

impl ArmStats {
    fn new() -> Self {
        Self { pulls: 0, total_reward: 0.0 }
    }

    fn mean_reward(&self) -> f64 {
        if self.pulls == 0 {
            0.0
        } else {
            self.total_reward / self.pulls as f64
        }
    }
}

#[derive(Debug, Default, Clone)]
struct UsedOperands {
    regs: Vec<u32>,
    mem_bases: Vec<u32>,
    mem_imms: Vec<i32>,
}

pub struct SeedMutationEngine {
    max_instructions: usize,
    hard_max_instructions: usize,
    rng: StdRand,
    arms: Vec<ArmStats>,
    epsilon: f64,
    ucb_c: f64,
}

impl SeedMutationEngine {
    pub fn new(max_instructions: usize, hard_max_instructions: usize, rng_seed: u64) -> Self {
        Self {
            max_instructions: max_instructions.max(1),
            hard_max_instructions: hard_max_instructions.max(max_instructions).max(1),
            rng: StdRand::with_seed(rng_seed),
            arms: (0..MutationArm::COUNT).map(|_| ArmStats::new()).collect(),
            epsilon: 0.05,
            ucb_c: 1.5,
        }
    }

    pub fn select_corpus_index(&mut self, corpus_len: usize) -> Option<usize> {
        if corpus_len == 0 {
            None
        } else {
            Some(self.rng.below(nz(corpus_len)))
        }
    }

    pub fn record_reward(&mut self, arm_index: usize, reward: f64) {
        if self.arms.is_empty() {
            return;
        }
        let i = arm_index.min(self.arms.len() - 1);
        self.arms[i].pulls = self.arms[i].pulls.saturating_add(1);
        self.arms[i].total_reward += reward;
    }

    pub fn mutate_from_corpus(
        &mut self,
        seed_words: &[u32],
        corpus_words: &[Vec<u32>],
    ) -> Option<SeedMutation> {
        if seed_words.is_empty() {
            return None;
        }

        let mut words = seed_words.to_vec();
        words.truncate(self.hard_max_instructions);
        let original = words.clone();
        let used = collect_used_operands(&words);
        let arm_index = self.select_arm();
        let arm = MutationArm::from_index(arm_index);

        match arm {
            MutationArm::Splice => self.splice_two(&mut words, corpus_words),
            MutationArm::RegisterReuse => self.mutate_registers(&mut words, &used.regs),
            MutationArm::ConstantBoundary => self.mutate_constants(&mut words),
            MutationArm::InsertInstruction => self.insert_random_instruction(&mut words, &used),
            MutationArm::DeleteInstruction => self.delete_one_instruction(&mut words),
            MutationArm::DuplicateInstruction => self.duplicate_one_instruction(&mut words),
            MutationArm::SwapAdjacent => self.swap_adjacent_instructions(&mut words),
            MutationArm::ReplaceMnemonic => self.replace_mnemonic_same_format(&mut words),
        }

        words.truncate(self.hard_max_instructions);
        if words.is_empty() || words == original {
            return None;
        }
        if words.iter().any(|w| RV32IMInstruction::from_word(*w).is_err()) {
            return None;
        }

        Some(SeedMutation { words, arm, arm_index })
    }

    fn select_arm(&mut self) -> usize {
        let n = self.arms.len();
        if n == 0 {
            return 0;
        }

        let unpulled: Vec<usize> = self
            .arms
            .iter()
            .enumerate()
            .filter_map(|(i, s)| if s.pulls == 0 { Some(i) } else { None })
            .collect();
        if !unpulled.is_empty() {
            return unpulled[self.rng.below(nz(unpulled.len()))];
        }

        let roll = self.rng.below(nz(10_000));
        let threshold = (self.epsilon * 10_000.0) as usize;
        if roll < threshold {
            return self.rng.below(nz(n));
        }

        let total_pulls: u64 = self.arms.iter().map(|a| a.pulls).sum();
        let log_total = (total_pulls.max(1) as f64).ln();
        let mut best_i = 0usize;
        let mut best_score = f64::NEG_INFINITY;
        for (i, arm) in self.arms.iter().enumerate() {
            let mean = arm.mean_reward();
            let bonus = self.ucb_c * (log_total / arm.pulls as f64).sqrt();
            let score = mean + bonus;
            if score > best_score {
                best_score = score;
                best_i = i;
            }
        }
        best_i
    }

    fn pick_u32(&mut self, xs: &[u32]) -> u32 {
        if xs.is_empty() {
            self.rng.below(nz(32)) as u32
        } else {
            xs[self.rng.below(nz(xs.len()))]
        }
    }

    fn pick_i32(&mut self, xs: &[i32]) -> i32 {
        if xs.is_empty() {
            self.rng.below(nz(64)) as i32 - 32
        } else {
            xs[self.rng.below(nz(xs.len()))]
        }
    }

    fn mutate_registers(&mut self, words: &mut [u32], used_regs: &[u32]) {
        if words.is_empty() {
            return;
        }
        let idx = self.rng.below(nz(words.len()));
        let Ok(insn) = RV32IMInstruction::from_word(words[idx]) else { return };

        let mut rd = insn.rd;
        let mut rs1 = insn.rs1;
        let mut rs2 = insn.rs2;
        match self.rng.below(nz(3)) {
            0 if rd.is_some() => rd = Some(self.pick_u32(used_regs)),
            1 if rs1.is_some() => rs1 = Some(self.pick_u32(used_regs)),
            _ if rs2.is_some() => rs2 = Some(self.pick_u32(used_regs)),
            _ => {}
        }

        let Ok(new_insn) = RV32IMInstruction::from_parts(&insn.mnemonic, rd, rs1, rs2, insn.imm)
        else {
            return;
        };
        words[idx] = new_insn.word;
    }

    fn mutate_constants(&mut self, words: &mut [u32]) {
        if words.is_empty() {
            return;
        }
        let idx = self.rng.below(nz(words.len()));
        let Ok(insn) = RV32IMInstruction::from_word(words[idx]) else { return };
        if insn.imm.is_none() {
            return;
        }
        let choices = [
            0i32, 1, -1, 2, 4, 8, 16, 32, 127, -128, 255, -256, 4095, -4096, 0x7fff, 0x8000,
            0x7fffffff,
        ];
        let imm = choices[self.rng.below(nz(choices.len()))];
        let Ok(new_insn) =
            RV32IMInstruction::from_parts(&insn.mnemonic, insn.rd, insn.rs1, insn.rs2, Some(imm))
        else {
            return;
        };
        words[idx] = new_insn.word;
    }

    fn insert_random_instruction(&mut self, words: &mut Vec<u32>, used: &UsedOperands) {
        if words.len() >= self.hard_max_instructions {
            return;
        }
        // Long-tail growth: beyond the nominal length, allow growth with a Pareto-style
        // probability (nominal/len)^2 so longer programs appear rarely instead of never.
        if words.len() >= self.max_instructions {
            let len = words.len() as u64;
            let nominal = self.max_instructions as u64;
            if self.rng.below(nz((len * len) as usize)) >= (nominal * nominal) as usize {
                return;
            }
        }

        let choose_mem = !used.mem_bases.is_empty() && self.rng.below(nz(4)) == 0;
        let insn = if choose_mem {
            let mem_mnems = ["lw", "sw", "lh", "sh", "lb", "sb", "lhu", "lbu"];
            let mnemonic = mem_mnems[self.rng.below(nz(mem_mnems.len()))];
            let rs1 = Some(self.pick_u32(&used.mem_bases));
            let imm = Some(self.pick_i32(&used.mem_imms));
            if matches!(mnemonic, "sw" | "sh" | "sb") {
                RV32IMInstruction::from_parts(
                    mnemonic,
                    None,
                    rs1,
                    Some(self.pick_u32(&used.regs)),
                    imm,
                )
            } else {
                RV32IMInstruction::from_parts(
                    mnemonic,
                    Some(self.pick_u32(&used.regs)),
                    rs1,
                    None,
                    imm,
                )
            }
        } else {
            let mnems = ["addi", "xori", "ori", "andi", "slli", "srli"];
            let mnemonic = mnems[self.rng.below(nz(mnems.len()))];
            let imm = if matches!(mnemonic, "slli" | "srli") {
                Some(self.rng.below(nz(32)) as i32)
            } else {
                Some(self.rng.below(nz(64)) as i32 - 32)
            };
            RV32IMInstruction::from_parts(
                mnemonic,
                Some(self.pick_u32(&used.regs)),
                Some(self.pick_u32(&used.regs)),
                None,
                imm,
            )
        };

        let Ok(insn) = insn else { return };
        let pos = self.rng.below(nz(words.len() + 1));
        words.insert(pos, insn.word);
    }

    fn delete_one_instruction(&mut self, words: &mut Vec<u32>) {
        if words.len() <= 1 {
            return;
        }
        let idx = self.rng.below(nz(words.len()));
        words.remove(idx);
    }

    fn duplicate_one_instruction(&mut self, words: &mut Vec<u32>) {
        if words.is_empty() || words.len() >= self.hard_max_instructions {
            return;
        }
        if words.len() >= self.max_instructions {
            let len = words.len() as u64;
            let nominal = self.max_instructions as u64;
            if self.rng.below(nz((len * len) as usize)) >= (nominal * nominal) as usize {
                return;
            }
        }
        let idx = self.rng.below(nz(words.len()));
        words.insert(idx + 1, words[idx]);
    }

    fn swap_adjacent_instructions(&mut self, words: &mut [u32]) {
        if words.len() < 2 {
            return;
        }
        let idx = self.rng.below(nz(words.len() - 1));
        words.swap(idx, idx + 1);
    }

    fn replace_mnemonic_same_format(&mut self, words: &mut [u32]) {
        if words.is_empty() {
            return;
        }
        let idx = self.rng.below(nz(words.len()));
        let Ok(insn) = RV32IMInstruction::from_word(words[idx]) else { return };
        let replacement = replacement_mnemonic(&insn);
        let Some(new_mnemonic) = replacement else { return };
        let Ok(new_insn) =
            RV32IMInstruction::from_parts(new_mnemonic, insn.rd, insn.rs1, insn.rs2, insn.imm)
        else {
            return;
        };
        words[idx] = new_insn.word;
    }

    fn splice_two(&mut self, words: &mut Vec<u32>, corpus_words: &[Vec<u32>]) {
        if words.is_empty() || corpus_words.len() < 2 {
            return;
        }
        let other = &corpus_words[self.rng.below(nz(corpus_words.len()))];
        if other.is_empty() {
            return;
        }
        let cut_a = self.rng.below(nz(words.len()));
        let cut_b = self.rng.below(nz(other.len()));
        let mut out = Vec::new();
        out.extend_from_slice(&words[..cut_a]);
        out.extend_from_slice(&other[cut_b..]);
        out.truncate(self.hard_max_instructions);
        if !out.is_empty() {
            *words = out;
        }
    }
}

fn collect_used_operands(words: &[u32]) -> UsedOperands {
    let mut used = UsedOperands::default();
    for &word in words {
        let Ok(insn) = RV32IMInstruction::from_word(word) else { continue };
        for r in [insn.rd, insn.rs1, insn.rs2].into_iter().flatten() {
            used.regs.push(r);
        }
        if matches!(insn.mnemonic.as_str(), "lb" | "lh" | "lw" | "lbu" | "lhu" | "sb" | "sh" | "sw")
        {
            if let Some(rs1) = insn.rs1 {
                used.mem_bases.push(rs1);
            }
            if let Some(imm) = insn.imm {
                used.mem_imms.push(imm);
            }
        }
    }
    used.regs.sort_unstable();
    used.regs.dedup();
    used.mem_bases.sort_unstable();
    used.mem_bases.dedup();
    used.mem_imms.sort_unstable();
    used.mem_imms.dedup();
    used
}

fn replacement_mnemonic(insn: &RV32IMInstruction) -> Option<&'static str> {
    let m = insn.mnemonic.as_str();
    if insn.rs2.is_some() && insn.imm.is_none() {
        match m {
            "add" => Some("sub"),
            "sub" => Some("add"),
            "and" => Some("or"),
            "or" => Some("xor"),
            "xor" => Some("and"),
            "slt" => Some("sltu"),
            "sltu" => Some("slt"),
            "mul" => Some("mulh"),
            "mulh" => Some("mulhu"),
            "mulhu" => Some("mul"),
            "div" => Some("divu"),
            "divu" => Some("rem"),
            "rem" => Some("remu"),
            "remu" => Some("div"),
            _ => None,
        }
    } else if insn.rs2.is_none() && insn.imm.is_some() {
        match m {
            "addi" => Some("xori"),
            "xori" => Some("ori"),
            "ori" => Some("andi"),
            "andi" => Some("addi"),
            "slli" => Some("srli"),
            "srli" => Some("srai"),
            "srai" => Some("slli"),
            "slti" => Some("sltiu"),
            "sltiu" => Some("slti"),
            _ => None,
        }
    } else {
        match m {
            "lw" => Some("lh"),
            "lh" => Some("lb"),
            "lb" => Some("lbu"),
            "lbu" => Some("lhu"),
            "lhu" => Some("lw"),
            "sw" => Some("sh"),
            "sh" => Some("sb"),
            "sb" => Some("sw"),
            "beq" => Some("bne"),
            "bne" => Some("blt"),
            "blt" => Some("bge"),
            "bge" => Some("bltu"),
            "bltu" => Some("bgeu"),
            "bgeu" => Some("beq"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SeedMutationEngine;

    #[test]
    fn mutates_seed_without_invalid_words() {
        let seed = vec![0x00100093, 0x00208113, 0x002081b3];
        let corpus = vec![seed.clone(), vec![0x00310193, 0x00418213]];
        let mut engine = SeedMutationEngine::new(16, 16, 7);
        let mut seen_mutation = false;
        for _ in 0..32 {
            if let Some(m) = engine.mutate_from_corpus(&seed, &corpus) {
                assert!(!m.words.is_empty());
                seen_mutation = true;
                engine.record_reward(m.arm_index, 1.0);
            }
        }
        assert!(seen_mutation);
    }
}
