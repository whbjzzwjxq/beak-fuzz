import logging
from dataclasses import dataclass
from random import Random
from typing import Generic

from zkvm_fuzzer_utils.kinds import InjectionKind, InstrKind
from zkvm_fuzzer_utils.trace import Trace, TraceStep

logger = logging.getLogger("fuzzer")


@dataclass
class InjectionArguments(Generic[InjectionKind]):
    kind: InjectionKind
    step: int


class InjectionContext(Generic[InstrKind, InjectionKind]):
    # internal state
    _instruction_kind_counter: dict[InstrKind, int]

    # internal lookup
    _available_injections_lookup: dict[InstrKind, list[InjectionKind]]
    _disable_schedular: bool
    _preferred_instructions: list[InstrKind]

    # variable to keep track of the last injection
    _targeted_trace_step: TraceStep | None
    _selected_injection_kind: InjectionKind | None

    def __init__(
        self,
        available_injections_lookup: dict[InstrKind, list[InjectionKind]],
        preferred_instructions: list[InstrKind] = [],
    ):
        self._available_injections_lookup = available_injections_lookup
        self._disable_schedular = False
        self._preferred_instructions = preferred_instructions
        self._instruction_kind_counter = {}
        self._targeted_trace_step = None
        self._selected_injection_kind = None

    def arguments_from_trace(self, trace: Trace, rng: Random) -> InjectionArguments | None:
        instr_step_lookup = trace.as_instruction_to_steps()
        candidates = [
            candidate
            for candidate in instr_step_lookup.keys()
            if len(self._available_injections_lookup.get(candidate, [])) > 0
        ]

        if len(candidates) == 0:
            self._targeted_trace_step = None
            return None  # unable to create a trace

        instr_kind = self.select_injection_candidate(candidates, rng)
        return self.arguments_from_step(rng.choice(instr_step_lookup[instr_kind]), rng)

    def select_injection_candidate(self, candidates: list[InstrKind], rng: Random) -> InstrKind:

        assert len(candidates) > 0, "empty candidate list"
        picked_candidate = None

        if self._disable_schedular:
            # if schedular is disabled, return a random candidate
            return rng.choice(candidates)

        if len(self._preferred_instructions) > 0:
            picked_candidate = self.try_select_preferred_candidate(candidates)
            # no return as it could be None and we default to distribution

        # it could be that preferred was triggered so we double check
        if picked_candidate is None:
            picked_candidate = self.select_with_even_distribution(candidates, rng)

        return picked_candidate

    def select_with_even_distribution(self, candidates: list[InstrKind], rng: Random) -> InstrKind:
        min_value = min([self.get_instr_kind_count(c) for c in candidates])
        preferences = [c for c in candidates if self.get_instr_kind_count(c) == min_value]
        picked_candidate = preferences[0] if len(preferences) == 1 else rng.choice(preferences)
        return picked_candidate

    def try_select_preferred_candidate(self, candidates: list[InstrKind]) -> InstrKind | None:
        # order preferred instructions based on occurrences
        ordered_preferred_instructions = sorted(
            self._preferred_instructions, key=lambda x: self.get_instr_kind_count(x)
        )
        for preferred_candidate in ordered_preferred_instructions:
            if preferred_candidate in candidates:
                return preferred_candidate
        return None

    def arguments_from_step(self, step: TraceStep, rng: Random) -> InjectionArguments:
        self._targeted_trace_step = step

        instr_kind = self._targeted_trace_step.instruction
        self.inc_instr_kind_count(instr_kind)

        injection_step = self._targeted_trace_step.step
        self._selected_injection_kind = rng.choice(self.get_available_injections(instr_kind))

        logger.info(
            f"injection planned for {instr_kind} @ step "
            f"{injection_step} with type {self._selected_injection_kind}"
        )

        return InjectionArguments(self._selected_injection_kind, injection_step)

    def get_instr_kind_count(self, instr_kind: InstrKind) -> int:
        if instr_kind not in self._instruction_kind_counter:
            self._instruction_kind_counter[instr_kind] = 0
        return self._instruction_kind_counter[instr_kind]

    def inc_instr_kind_count(self, instr_kind: InstrKind):
        if instr_kind not in self._instruction_kind_counter:
            self._instruction_kind_counter[instr_kind] = 0
        self._instruction_kind_counter[instr_kind] += 1

    def get_available_injections(self, instr_kind: InstrKind) -> list[InjectionKind]:
        if instr_kind not in self._available_injections_lookup:
            self._available_injections_lookup[instr_kind] = []
        return self._available_injections_lookup[instr_kind]

    @property
    def targeted_trace_step(self) -> TraceStep:
        if self._targeted_trace_step is None:
            raise ValueError("unable to access 'last_trace_step'!")
        return self._targeted_trace_step

    @property
    def selected_injection_kind(self) -> InjectionKind:
        if self._selected_injection_kind is None:
            raise ValueError("unable to access 'last_injection_kind'!")
        return self._selected_injection_kind

    def disable_schedular(self):
        self._disable_schedular = True

    def enable_schedular(self):
        self._disable_schedular = False

    def is_schedular(self) -> bool:
        return not self._disable_schedular
