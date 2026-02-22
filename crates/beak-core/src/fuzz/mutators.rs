use std::num::NonZeroUsize;

use libafl::prelude::*;
use libafl_bolts::Named;
use libafl_bolts::rands::Rand;

use crate::rv32im::instruction::RV32IMInstruction;

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

/// Custom mutator implementing the requested strategies on 32-bit word-aligned inputs.
pub struct SeedMutator {
    max_instructions: usize,
    name: std::borrow::Cow<'static, str>,
}

impl SeedMutator {
    pub fn new(max_instructions: usize) -> Self {
        Self {
            max_instructions,
            name: "SeedMutator".into(),
        }
    }

    fn mutate_registers(state: &mut LoopState, words: &mut [u32]) {
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
        let mut pick_reg = || -> u32 { state.rand_mut().below(nz(32)) as u32 };
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

    fn insert_random_instruction(state: &mut LoopState, words: &mut Vec<u32>) {
        if words.len() >= 2048 {
            return;
        }
        // Keep this set conservative; we can expand once the loop is stable.
        let mnems = ["addi", "xori", "ori", "andi", "slli", "srli"];
        let mnemonic = mnems[state.rand_mut().below(nz(mnems.len()))];
        let rd = Some(state.rand_mut().below(nz(32)) as u32);
        let rs1 = Some(state.rand_mut().below(nz(32)) as u32);
        let imm = Some((state.rand_mut().below(nz(64)) as i32) - 32);
        let Ok(insn) = RV32IMInstruction::from_parts(mnemonic, rd, rs1, None, imm) else {
            return;
        };
        let pos = state.rand_mut().below(nz(words.len() + 1));
        words.insert(pos, insn.word);
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

        let which = state.rand_mut().below(nz(4));
        match which {
            0 => Self::splice_two(state, &mut words),
            1 => Self::mutate_registers(state, &mut words),
            2 => Self::mutate_constants(state, &mut words),
            _ => Self::insert_random_instruction(state, &mut words),
        }

        words.truncate(self.max_instructions);
        *input = encode_words(&words);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        _state: &mut LoopState,
        _new_corpus_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

