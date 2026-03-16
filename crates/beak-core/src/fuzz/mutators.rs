use std::num::NonZeroUsize;

use libafl::prelude::*;
use libafl_bolts::Named;
use libafl_bolts::rands::Rand;

use crate::rv32im::instruction::RV32IMInstruction;

use super::bandit;

type LoopState = StdState<InMemoryCorpus<BytesInput>, BytesInput, libafl_bolts::rands::StdRand, InMemoryCorpus<BytesInput>>;

fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n.max(1)).unwrap()
}

fn decode_words_from_input(input: &BytesInput, max_instructions: usize) -> Vec<u32> {
    let bytes: &[u8] = input.as_ref();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= bytes.len() && out.len() < max_instructions {
        let w = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        out.push(w);
        i += 4;
    }
    out
}

fn encode_words(words: &[u32]) -> BytesInput {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for &w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    BytesInput::new(bytes)
}

#[derive(Debug, Default, Clone)]
struct UsedOperands {
    regs: Vec<u32>,
    mem_bases: Vec<u32>,
    mem_imms: Vec<i32>,
}

fn collect_used_operands(words: &[u32]) -> UsedOperands {
    let mut used = UsedOperands::default();
    for &word in words {
        let Ok(insn) = RV32IMInstruction::from_word(word) else { continue };

        for r in [insn.rd, insn.rs1, insn.rs2] {
            if let Some(r) = r {
                used.regs.push(r);
            }
        }

        // Track “previously used memory address components” using load/store patterns.
        // We do not simulate execution here; we approximate “address reuse” as reusing the base
        // register (rs1) and the immediate offset observed in existing load/store instructions.
        let m = insn.mnemonic.as_str();
        let is_mem = matches!(m, "lb" | "lh" | "lw" | "lbu" | "lhu" | "sb" | "sh" | "sw");
        if is_mem {
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

fn pick_from_slice_u32(state: &mut LoopState, xs: &[u32]) -> u32 {
    if xs.is_empty() {
        // Fallback only; most callers require “reuse previously used regs”.
        return state.rand_mut().below(nz(32)) as u32;
    }
    let idx = state.rand_mut().below(nz(xs.len()));
    xs[idx]
}

fn pick_from_slice_i32(state: &mut LoopState, xs: &[i32]) -> i32 {
    if xs.is_empty() {
        // Fallback small imm window.
        return (state.rand_mut().below(nz(64)) as i32) - 32;
    }
    let idx = state.rand_mut().below(nz(xs.len()));
    xs[idx]
}

pub const SEED_MUTATOR_NUM_ARMS: usize = 8;

impl SeedMutator {
    pub fn new(max_instructions: usize) -> Self {
        Self {
            max_instructions,
            name: "SeedMutator".into(),
            last_arm: None,
            last_ctx: Vec::new(),
        }
    }

    fn mutate_registers(state: &mut LoopState, words: &mut [u32], used_regs: &[u32]) {
        if words.is_empty() {
            return;
        }
        let idx = state.rand_mut().below(nz(words.len()));
        let word = words[idx];
        let Ok(insn) = RV32IMInstruction::from_word(word) else { return };

        let mut rd = insn.rd;
        let mut rs1 = insn.rs1;
        let mut rs2 = insn.rs2;

        let which = state.rand_mut().below(nz(3));
        let mut pick_reg = || -> u32 { pick_from_slice_u32(state, used_regs) };
        match which {
            0 => {
                if rd.is_some() {
                    rd = Some(pick_reg());
                }
            }
            1 => {
                if rs1.is_some() {
                    rs1 = Some(pick_reg());
                }
            }
            _ => {
                if rs2.is_some() {
                    rs2 = Some(pick_reg());
                }
            }
        }

        let imm = insn.imm;
        let Ok(new_insn) = RV32IMInstruction::from_parts(&insn.mnemonic, rd, rs1, rs2, imm) else {
            return;
        };
        words[idx] = new_insn.word;
    }

    fn mutate_constants(state: &mut LoopState, words: &mut [u32]) {
        if words.is_empty() {
            return;
        }
        let idx = state.rand_mut().below(nz(words.len()));
        let word = words[idx];
        let Ok(insn) = RV32IMInstruction::from_word(word) else { return };
        let Some(old_imm) = insn.imm else { return };
        let choices = [0i32, 1, -1, 2, 4, 8, 16, 32, 127, -128];
        let new_imm = choices[state.rand_mut().below(nz(choices.len()))];
        if new_imm == old_imm {
            return;
        }
        let Ok(new_insn) =
            RV32IMInstruction::from_parts(&insn.mnemonic, insn.rd, insn.rs1, insn.rs2, Some(new_imm))
        else {
            return;
        };
        words[idx] = new_insn.word;
    }

    fn insert_random_instruction(state: &mut LoopState, words: &mut Vec<u32>, used: &UsedOperands) {
        if words.len() >= 2048 {
            return;
        }

        // Prefer inserting a memory op when we already have memory-address components to reuse.
        // This increases the odds of hitting memory-related boundary buckets while respecting:
        // “must use previously used registers / memory addresses”.
        let choose_mem = !used.mem_bases.is_empty() && state.rand_mut().below(nz(4)) == 0;
        let insn = if choose_mem {
            let mem_mnems = ["lw", "sw", "lh", "sh", "lb", "sb", "lhu", "lbu"];
            let mnemonic = mem_mnems[state.rand_mut().below(nz(mem_mnems.len()))];
            let is_store = matches!(mnemonic, "sw" | "sh" | "sb");

            let rs1 = Some(pick_from_slice_u32(state, &used.mem_bases));
            let imm = Some(pick_from_slice_i32(state, &used.mem_imms));

            if is_store {
                let rs2 = Some(pick_from_slice_u32(state, &used.regs));
                RV32IMInstruction::from_parts(mnemonic, None, rs1, Some(rs2.unwrap()), imm)
            } else {
                let rd = Some(pick_from_slice_u32(state, &used.regs));
                RV32IMInstruction::from_parts(mnemonic, rd, rs1, None, imm)
            }
        } else {
            // Keep this set conservative; we can expand once the loop is stable.
            let mnems = ["addi", "xori", "ori", "andi", "slli", "srli"];
            let mnemonic = mnems[state.rand_mut().below(nz(mnems.len()))];
            let rd = Some(pick_from_slice_u32(state, &used.regs));
            let rs1 = Some(pick_from_slice_u32(state, &used.regs));
            let imm = Some((state.rand_mut().below(nz(64)) as i32) - 32);
            RV32IMInstruction::from_parts(mnemonic, rd, rs1, None, imm)
        };

        let Ok(insn) = insn else { return };

        // Append one instruction at the end.
        words.push(insn.word);
    }

    fn delete_one_instruction(state: &mut LoopState, words: &mut Vec<u32>) {
        if words.len() <= 1 {
            return;
        }
        let idx = state.rand_mut().below(nz(words.len()));
        words.remove(idx);
    }

    fn duplicate_one_instruction(state: &mut LoopState, words: &mut Vec<u32>) {
        if words.is_empty() || words.len() >= 2048 {
            return;
        }
        let idx = state.rand_mut().below(nz(words.len()));
        let w = words[idx];
        // Duplicate right after the original (keeps locality, tends to preserve decode validity).
        words.insert(idx + 1, w);
    }

    fn swap_adjacent_instructions(state: &mut LoopState, words: &mut [u32]) {
        if words.len() < 2 {
            return;
        }
        let idx = state.rand_mut().below(nz(words.len() - 1));
        words.swap(idx, idx + 1);
    }

    fn replace_mnemonic_same_format(state: &mut LoopState, words: &mut [u32]) {
        if words.is_empty() {
            return;
        }
        let idx = state.rand_mut().below(nz(words.len()));
        let word = words[idx];
        let Ok(insn) = RV32IMInstruction::from_word(word) else { return };

        let m = insn.mnemonic.as_str();

        let replacement = if insn.rs2.is_some() && insn.imm.is_none() {
            // R-type style substitutions.
            match m {
                "add" => Some("sub"),
                "sub" => Some("add"),
                "and" => Some("or"),
                "or" => Some("xor"),
                "xor" => Some("and"),
                "slt" => Some("sltu"),
                "sltu" => Some("slt"),
                _ => None,
            }
        } else if insn.rs2.is_none() && insn.imm.is_some() {
            // I-type immediate substitutions.
            match m {
                "addi" => Some("xori"),
                "xori" => Some("ori"),
                "ori" => Some("andi"),
                "andi" => Some("addi"),
                "slli" => Some("srli"),
                "srli" => Some("srai"),
                "srai" => Some("slli"),
                _ => None,
            }
        } else {
            // Load/store mnemonic substitutions (keep operands).
            match m {
                "lw" => Some("lh"),
                "lh" => Some("lb"),
                "lb" => Some("lbu"),
                "lbu" => Some("lhu"),
                "lhu" => Some("lw"),
                "sw" => Some("sh"),
                "sh" => Some("sb"),
                "sb" => Some("sw"),
                _ => None,
            }
        };

        let Some(new_mnemonic) = replacement else { return };
        let Ok(new_insn) = RV32IMInstruction::from_parts(
            new_mnemonic,
            insn.rd,
            insn.rs1,
            insn.rs2,
            insn.imm,
        ) else {
            return;
        };
        words[idx] = new_insn.word;
    }

    fn splice_two(state: &mut LoopState, words: &mut Vec<u32>) {
        let corpus_count = state.corpus().count();
        if corpus_count < 2 || words.is_empty() {
            return;
        }
        let other_idx = state.rand_mut().below(nz(corpus_count));
        let id = CorpusId::from(other_idx);
        let Ok(tc_cell) = state.corpus().get(id) else {
            return;
        };
        let other_words = {
            let tc = tc_cell.borrow();
            let Some(other_input) = tc.input().as_ref() else {
                return;
            };
            decode_words_from_input(other_input, 2048)
        };
        if other_words.is_empty() {
            return;
        }
        let cut_a = state.rand_mut().below(nz(words.len()));
        let cut_b = state.rand_mut().below(nz(other_words.len()));
        let mut new_words = Vec::new();
        new_words.extend_from_slice(&words[..cut_a]);
        new_words.extend_from_slice(&other_words[cut_b..]);
        if new_words.is_empty() {
            return;
        }
        new_words.truncate(2048);
        *words = new_words;
    }
}

impl Named for SeedMutator {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        &self.name
    }
}

impl Mutator<BytesInput, LoopState> for SeedMutator {
    fn mutate(&mut self, state: &mut LoopState, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let mut words = decode_words_from_input(input, self.max_instructions);
        if words.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let used = collect_used_operands(&words);
        let context = extract_context(&words);
        let ctx: Vec<f64> = context.iter().map(|v| *v as f64).collect();
        let arm = bandit::select_arm(state.rand_mut(), &ctx);

        self.last_arm = Some(arm);
        self.last_ctx = ctx.clone();

        bandit::diagnostic_tick();
        match arm {
            0 => Self::splice_two(state, &mut words),
            1 => Self::mutate_registers(state, &mut words, &used.regs),
            2 => Self::mutate_constants(state, &mut words),
            3 => Self::insert_random_instruction(state, &mut words, &used),
            4 => Self::delete_one_instruction(state, &mut words),
            5 => Self::duplicate_one_instruction(state, &mut words),
            6 => Self::swap_adjacent_instructions(state, &mut words),
            7 => Self::replace_mnemonic_same_format(state, &mut words),
            _ => Self::insert_random_instruction(state, &mut words, &used),
        }

        words.truncate(self.max_instructions);
        *input = encode_words(&words);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(
    &mut self,
    _state: &mut LoopState,
    new_corpus_id: Option<CorpusId>,
    ) -> Result<(), Error> {

        let reward = if new_corpus_id.is_some() { 1.0 } else { 0.0 };

        if let Some(arm) = self.last_arm {
            bandit::update(arm, &self.last_ctx, reward);
        }

        Ok(())
    }
}

pub fn extract_context(words: &[u32]) -> Vec<f64> {

    let mut branches = 0;
    let mut mem = 0;
    let mut alu = 0;
    let mut system = 0;

    let mut opcode_counts = [0u32; 128];
    let mut regs = [false; 32];

    for w in words {

        let opcode = (w & 0x7f) as usize;
        opcode_counts[opcode] += 1;

        match opcode {
            0x63 | 0x6f | 0x67 => branches += 1,
            0x03 | 0x23 => mem += 1,
            0x33 | 0x13 => alu += 1,
            0x73 => system += 1,
            _ => {}
        }

        let rs1 = ((w >> 15) & 0x1f) as usize;
        let rs2 = ((w >> 20) & 0x1f) as usize;

        regs[rs1] = true;
        regs[rs2] = true;
    }

    let n = words.len() as f64;

    let unique_opcodes =
        opcode_counts.iter().filter(|&&c| c > 0).count() as f64;

    let reg_diversity =
        regs.iter().filter(|&&r| r).count() as f64 / 32.0;

    vec![
        n / 32.0,
        branches as f64 / n,
        mem as f64 / n,
        alu as f64 / n,
        system as f64 / n,
        unique_opcodes / n,
        reg_diversity,
    ]
}

pub struct SeedMutator {
    max_instructions: usize,
    name: std::borrow::Cow<'static, str>,
    last_arm: Option<usize>,
    last_ctx: Vec<f64>,
}