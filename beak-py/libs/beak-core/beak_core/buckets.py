from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from beak_core.micro_ops import InteractionBase, InteractionMultiplicity, MicroOp, ZKVMTrace


class BucketType(str, Enum):
    NEXT_PC_UNDERCONSTRAINED = "next_pc_underconstrained"
    GATE_BOOL_DOMAIN = "gate_bool_domain"
    INACTIVE_ROW_SIDE_EFFECTS = "inactive_row_side_effects"
    # PROGRAM_NEXT_PC_CANDIDATE = "program_next_pc_candidate"
    # REG_ZERO_WRITE = "reg_zero_write"
    # BYTE_RANGE_INTERACTION = "byte_range_interaction"


@dataclass(frozen=True)
class BucketHit:
    bucket_type: BucketType
    core_instruction_idxs: List[int]
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "details", dict(self.details))


class Bucket(ABC):
    @abstractmethod
    def get_type(self) -> BucketType:
        raise NotImplementedError

    @abstractmethod
    def match_hits(
        self, context: ZKVMTrace, op_idx: int, op_micro_ops: List[MicroOp]
    ) -> Optional[BucketHit]:
        raise NotImplementedError


class NextPcUnderconstrainedBucket(Bucket):
    """
    Candidate bucket for detect `next_pc underconstrained` vulnerabilities.
    """

    def __init__(
        self,
        *,
        instruction_label: str,
        chip: str,
        is_real_gate: str = "is_real",
        min_following_instructions: int = 2,
    ):
        if min_following_instructions < 0:
            raise ValueError("min_following_instructions must be >= 0")
        self._instruction_label = instruction_label
        if not isinstance(chip, str) or not chip.strip():
            raise ValueError("chip must be a non-empty string")
        self._chip = chip
        # Field name of the chip "activation" flag in ChipRow.gates (e.g. `is_real`).
        self._is_real_gate = is_real_gate
        self._min_following = min_following_instructions

    def get_type(self) -> BucketType:
        return BucketType.NEXT_PC_UNDERCONSTRAINED

    @staticmethod
    def _is_activated(value: Any) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value == 1
        if isinstance(value, str):
            v = value.strip().lower()
            if v in ("1", "true", "yes"):
                return True
            if v in ("0", "false", "no"):
                return False
            return None
        return None

    def _is_real_row(self, micro_op: MicroOp) -> bool:
        gates = getattr(micro_op, "gates", None)
        if not isinstance(gates, dict) or self._is_real_gate not in gates:
            # If the backend doesn't expose is_real, treat the row as eligible.
            return True
        return self._is_activated(gates.get(self._is_real_gate)) is True

    def match_hits(
        self, context: ZKVMTrace, op_idx: int, op_micro_ops: List[MicroOp]
    ) -> Optional[BucketHit]:
        # This bucket is op-level: the caller must provide op_spans so we can reason about
        # "following ops >= 2" even when one op expands to many micro-ops.
        if context.op_spans is None:
            return None

        matched_chip_uop: MicroOp | None = None
        for uop in op_micro_ops:
            if getattr(uop, "chip", None) != self._chip:
                continue
            if not self._is_real_row(uop):
                continue
            matched_chip_uop = uop
            break
        if matched_chip_uop is None:
            return None

        following_ops = len(context.op_spans) - op_idx - 1
        if following_ops < self._min_following:
            return None

        return BucketHit(
            bucket_type=self.get_type(),
            core_instruction_idxs=[op_idx],
            details={
                "instruction_label": self._instruction_label,
                "chip": getattr(matched_chip_uop, "chip", None),
                "min_following_instructions": self._min_following,
                "following_ops": following_ops,
            },
        )


class GateBoolDomainBucket(Bucket):
    """
    We only care about boolean-domain checks when a gate actually
    participates in an interaction (most commonly as a lookup multiplicity).
    """

    def __init__(self, *, gate_keys: Optional[List[str]] = None):
        self._gate_keys = gate_keys or ["is_real", "is_valid"]

    def get_type(self) -> BucketType:
        return BucketType.GATE_BOOL_DOMAIN

    def match_hits(
        self, context: ZKVMTrace, op_idx: int, op_micro_ops: List[MicroOp]
    ) -> Optional[BucketHit]:
        # Build per-op chip rows with gates, plus a row_id -> row mapping.
        anchored_rows: Dict[str, MicroOp] = {}
        for uop in op_micro_ops:
            row_id = getattr(uop, "row_id", None)
            gates = getattr(uop, "gates", None)
            if isinstance(row_id, str) and isinstance(gates, dict):
                anchored_rows[row_id] = uop

        hits: List[Dict[str, Any]] = []
        for uop in op_micro_ops:
            if not isinstance(uop, InteractionBase):
                continue
            mult = getattr(uop, "multiplicity", None)
            if not isinstance(mult, InteractionMultiplicity):
                continue
            mult_ref = mult.ref
            if not isinstance(mult_ref, str) or not mult_ref:
                continue
            anchor = getattr(uop, "anchor_row_id", None)
            if not isinstance(anchor, str) or not anchor:
                continue
            candidate = anchored_rows.get(anchor)
            if candidate is None:
                continue
            gates = getattr(candidate, "gates", None)
            if not isinstance(gates, dict):
                continue

            for key in self._gate_keys:
                # Strict linkage: require the interaction to declare it is using this gate field.
                if mult_ref != f"gates.{key}":
                    continue
                if key not in gates:
                    continue

                hits.append(
                    {
                        "gate": key,
                        "gate_value": gates.get(key),
                        "chip": getattr(candidate, "chip", None),
                        "interaction_table_id": getattr(uop, "table_id", None),
                        "interaction_kind": getattr(uop, "kind", None),
                        "multiplicity": mult.value,
                        "multiplicity_ref": mult_ref,
                        "anchor_row_id": anchor,
                    }
                )
                break

        if not hits:
            return None

        return BucketHit(
            bucket_type=self.get_type(),
            core_instruction_idxs=[op_idx],
            details={
                "status": "gate_used_as_multiplicity",
                "match_count": len(hits),
                "example": hits[0],
            },
        )


class InactiveRowEffectsBucket(Bucket):
    """
    Bucket for detecting side effects on inactive (padding/dummy) rows.
    """

    def __init__(
        self,
        *,
        activation_gate: str = "is_real",
        effect_gate_keys: Optional[List[str]] = None,
        effect_attr_keys: Optional[List[str]] = None,
    ):
        self._activation_gate = activation_gate
        self._effect_gate_keys = effect_gate_keys or []
        self._effect_attr_keys = effect_attr_keys or []

    def get_type(self) -> BucketType:
        return BucketType.INACTIVE_ROW_SIDE_EFFECTS

    @staticmethod
    def _is_activated(value: Any) -> bool | None:
        return NextPcUnderconstrainedBucket._is_activated(value)

    @staticmethod
    def _is_effectful_interaction(uop: InteractionBase) -> bool:
        mult = getattr(uop, "multiplicity", None)
        if mult is None:
            return True
        if isinstance(mult, InteractionMultiplicity):
            mult = mult.value
        try:
            return int(mult) != 0
        except Exception:
            return True

    def match_hits(self, context: ZKVMTrace, op_idx: int, op_micro_ops: List[MicroOp]) -> Optional[BucketHit]:
        anchored_rows: Dict[str, MicroOp] = {}
        for uop in op_micro_ops:
            row_id = getattr(uop, "row_id", None)
            if isinstance(row_id, str):
                anchored_rows[row_id] = uop

        inactive_rows: List[MicroOp] = []
        inactive_row_ids: List[str] = []
        for uop in op_micro_ops:
            gates = getattr(uop, "gates", None)
            if not isinstance(gates, dict) or self._activation_gate not in gates:
                continue
            active = self._is_activated(gates.get(self._activation_gate))
            if active is False:
                inactive_rows.append(uop)
                row_id = getattr(uop, "row_id", None)
                if isinstance(row_id, str):
                    inactive_row_ids.append(row_id)

        if not inactive_rows:
            return None

        inactive_row_id_set = set(inactive_row_ids)
        effectful_interactions: List[InteractionBase] = []
        for uop in op_micro_ops:
            if not isinstance(uop, InteractionBase):
                continue
            anchor = getattr(uop, "anchor_row_id", None)
            if not isinstance(anchor, str) or anchor not in inactive_row_id_set:
                continue
            if anchor not in anchored_rows:
                continue
            if self._is_effectful_interaction(uop):
                effectful_interactions.append(uop)

        flagged: List[Dict[str, Any]] = []
        for uop in inactive_rows:
            gates = getattr(uop, "gates", None)
            if isinstance(gates, dict):
                for k in self._effect_gate_keys:
                    if k in gates and self._is_activated(gates.get(k)) is True:
                        flagged.append({"source": "gates", "key": k, "value": gates.get(k)})
                        break
            for k in self._effect_attr_keys:
                v = getattr(uop, k, None)
                if self._is_activated(v) is True:
                    flagged.append({"source": "attrs", "key": k, "value": v})
                    break

        if not effectful_interactions and not flagged:
            return None

        example_interaction = effectful_interactions[0] if effectful_interactions else None
        return BucketHit(
            bucket_type=self.get_type(),
            core_instruction_idxs=[op_idx],
            details={
                "activation_gate": self._activation_gate,
                "inactive_row_count": len(inactive_rows),
                "effectful_interaction_count": len(effectful_interactions),
                "flagged_count": len(flagged),
                "example": {
                    "inactive_chip": getattr(inactive_rows[0], "chip", None),
                    "inactive_row_id": getattr(inactive_rows[0], "row_id", None),
                    "interaction_table_id": getattr(example_interaction, "table_id", None)
                    if example_interaction is not None
                    else None,
                    "interaction_kind": getattr(example_interaction, "kind", None)
                    if example_interaction is not None
                    else None,
                    "interaction_anchor_row_id": getattr(example_interaction, "anchor_row_id", None)
                    if example_interaction is not None
                    else None,
                    "flagged": flagged[0] if flagged else None,
                },
            },
        )

if False:
    # NOTE: Temporarily disabled (pending validation).

    class ProgramNextPcCandidateBucket(Bucket):
        """
        Generic (VM-agnostic) candidate for `next_pc underconstrained` style issues.

        This bucket looks for a ProgramInteraction in the op and ensures there are enough
        following ops so a next_pc mutation could skip meaningful work.
        """

        def __init__(self, *, min_following_instructions: int = 2):
            if min_following_instructions < 0:
                raise ValueError("min_following_instructions must be >= 0")
            self._min_following = min_following_instructions

        def get_type(self) -> BucketType:
            return BucketType.PROGRAM_NEXT_PC_CANDIDATE

        def match_hits(
            self, context: ZKVMTrace, op_idx: int, op_micro_ops: List[MicroOp]
        ) -> Optional[BucketHit]:
            if context.op_spans is None:
                return None

            prog: ProgramInteraction | None = None
            for uop in op_micro_ops:
                if isinstance(uop, ProgramInteraction):
                    prog = uop
                    break
            if prog is None:
                return None

            following_ops = len(context.op_spans) - op_idx - 1
            if following_ops < self._min_following:
                return None

            return BucketHit(
                bucket_type=self.get_type(),
                core_instruction_idxs=[op_idx],
                details={
                    "min_following_instructions": self._min_following,
                    "following_ops": following_ops,
                    "pc": prog.pc,
                    "next_pc": prog.next_pc,
                    "delta": int(prog.next_pc) - int(prog.pc),
                    "table_id": prog.table_id,
                    "anchor_row_id": prog.anchor_row_id,
                },
            )

    class RegZeroWriteBucket(Bucket):
        """
        Candidate bucket for `x0/zero-register underconstrained` issues.

        This focuses on traces that model register file accesses as MemoryInteractions
        in the REG space.
        """

        def __init__(
            self,
            *,
            reg_space: MemorySpace = MemorySpace.REG,
            reg_addr: int = 0,
        ):
            self._reg_space = reg_space
            self._reg_addr = int(reg_addr)

        def get_type(self) -> BucketType:
            return BucketType.REG_ZERO_WRITE

        @staticmethod
        def _is_effectful(multiplicity: Optional[InteractionMultiplicity]) -> bool:
            if multiplicity is None:
                return True
            v = multiplicity.value
            if v is None:
                return True
            try:
                return int(v) != 0
            except Exception:
                return True

        def match_hits(
            self, context: ZKVMTrace, op_idx: int, op_micro_ops: List[MicroOp]
        ) -> Optional[BucketHit]:
            hits: List[Dict[str, Any]] = []
            for uop in op_micro_ops:
                if not isinstance(uop, MemoryInteraction):
                    continue
                if uop.space != self._reg_space:
                    continue
                if int(uop.addr) != self._reg_addr:
                    continue
                if int(uop.is_write) != 1:
                    continue
                if not self._is_effectful(uop.multiplicity):
                    continue
                hits.append(
                    {
                        "table_id": uop.table_id,
                        "addr": int(uop.addr),
                        "value": int(uop.value),
                        "size_bytes": int(uop.size.byte_len),
                        "multiplicity": None
                        if uop.multiplicity is None
                        else uop.multiplicity.value,
                        "multiplicity_ref": None
                        if uop.multiplicity is None
                        else uop.multiplicity.ref,
                        "anchor_row_id": uop.anchor_row_id,
                    }
                )

            if not hits:
                return None

            return BucketHit(
                bucket_type=self.get_type(),
                core_instruction_idxs=[op_idx],
                details={
                    "reg_space": str(self._reg_space),
                    "reg_addr": self._reg_addr,
                    "match_count": len(hits),
                    "example": hits[0],
                },
            )

    class ByteRangeInteractionBucket(Bucket):
        """
        Candidate bucket for range/byte decomposition soundness issues.

        It flags the presence of ByteInteraction or RangeInteraction micro-ops,
        which are natural targets for out-of-domain witness mutations.
        """

        def get_type(self) -> BucketType:
            return BucketType.BYTE_RANGE_INTERACTION

        def match_hits(
            self, context: ZKVMTrace, op_idx: int, op_micro_ops: List[MicroOp]
        ) -> Optional[BucketHit]:
            hits: List[Dict[str, Any]] = []
            for uop in op_micro_ops:
                if isinstance(uop, ByteInteraction):
                    hits.append(
                        {
                            "kind": "byte",
                            "table_id": uop.table_id,
                            "value": int(uop.value),
                            "multiplicity": None
                            if uop.multiplicity is None
                            else uop.multiplicity.value,
                            "multiplicity_ref": None
                            if uop.multiplicity is None
                            else uop.multiplicity.ref,
                            "anchor_row_id": uop.anchor_row_id,
                        }
                    )
                elif isinstance(uop, RangeInteraction):
                    hits.append(
                        {
                            "kind": "range",
                            "table_id": uop.table_id,
                            "value": int(uop.value),
                            "bits": int(uop.bits),
                            "multiplicity": None
                            if uop.multiplicity is None
                            else uop.multiplicity.value,
                            "multiplicity_ref": None
                            if uop.multiplicity is None
                            else uop.multiplicity.ref,
                            "anchor_row_id": uop.anchor_row_id,
                        }
                    )

            if not hits:
                return None

            return BucketHit(
                bucket_type=self.get_type(),
                core_instruction_idxs=[op_idx],
                details={
                    "match_count": len(hits),
                    "example": hits[0],
                },
            )


def sp1_next_pc_underconstrained_buckets(*, min_following_instructions: int = 2) -> List[Bucket]:
    """
    Convenience factory for SP1 instruction chips that expose `pc`/`next_pc`.

    These buckets are meant to drive Loop2-style injections that mutate `next_pc`
    to skip at least one subsequent instruction.
    """

    chips = [
        # control-flow
        "AUIPC",
        "Branch",
        "Jump",
        "SyscallInstrs",
        # common instruction families
        "AddSub",
        "Bitwise",
        "Mul",
        "DivRem",
        "ShiftLeft",
        "ShiftRight",
        "Lt",
        "MemoryInstructions",
    ]
    return [
        NextPcUnderconstrainedBucket(
            instruction_label=f"sp1.{chip}",
            chip=chip,
            min_following_instructions=min_following_instructions,
        )
        for chip in chips
    ]
