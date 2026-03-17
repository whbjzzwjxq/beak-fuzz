use std::sync::{Arc, Mutex};

use libafl::prelude::*;
use libafl_bolts::prelude::MatchName;

use super::policy::{FuzzerState, PolicyProvider};

type LoopState = StdState<InMemoryCorpus<BytesInput>, BytesInput, libafl_bolts::rands::StdRand, InMemoryCorpus<BytesInput>>;

/// Seed scheduler driven by a PolicyProvider.
///
/// Instead of FIFO (QueueScheduler), this scheduler delegates seed selection
/// to the RL policy, allowing learned prioritization of corpus entries.
pub struct RLScheduler {
    policy: Arc<Mutex<dyn PolicyProvider>>,
    fuzzer_state: Arc<Mutex<FuzzerState>>,
    current: Option<CorpusId>,
    rng_counter: u64,
}

impl RLScheduler {
    pub fn new(
        policy: Arc<Mutex<dyn PolicyProvider>>,
        fuzzer_state: Arc<Mutex<FuzzerState>>,
    ) -> Self {
        Self {
            policy,
            fuzzer_state,
            current: None,
            rng_counter: 0,
        }
    }
}

impl RemovableScheduler<BytesInput, LoopState> for RLScheduler {
    fn on_remove(
        &mut self,
        _state: &mut LoopState,
        _id: CorpusId,
        _testcase: &Option<Testcase<BytesInput>>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl Scheduler<BytesInput, LoopState> for RLScheduler {
    fn on_add(&mut self, _state: &mut LoopState, _id: CorpusId) -> Result<(), Error> {
        Ok(())
    }

    fn on_evaluation<OT>(&mut self, _state: &mut LoopState, _input: &BytesInput, _observers: &OT) -> Result<(), Error>
    where
        OT: MatchName,
    {
        Ok(())
    }

    fn set_current_scheduled(
        &mut self,
        _state: &mut LoopState,
        id: Option<CorpusId>,
    ) -> Result<(), Error> {
        self.current = id;
        Ok(())
    }

    fn next(&mut self, state: &mut LoopState) -> Result<CorpusId, Error> {
        let corpus_count = state.corpus().count();
        if corpus_count == 0 {
            return Err(Error::empty("No entries in corpus".to_string()));
        }

        self.rng_counter = self.rng_counter.wrapping_add(1);
        let random_seed = {
            let mut z = self.rng_counter.wrapping_mul(0x9e3779b97f4a7c15);
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z ^ (z >> 27)
        };

        let fs = self.fuzzer_state.lock().unwrap().clone();
        let idx = {
            let mut pol = self.policy.lock().unwrap();
            pol.select_seed(&fs, corpus_count, random_seed)
        };

        let bounded_idx = idx.min(corpus_count.saturating_sub(1));
        let id = CorpusId::from(bounded_idx);
        self.current = Some(id);
        Ok(id)
    }
}
