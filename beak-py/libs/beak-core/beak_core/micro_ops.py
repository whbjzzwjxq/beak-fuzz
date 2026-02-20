from collections import OrderedDict
from dataclasses import dataclass, field
from typing import ClassVar, Dict, List, Optional, Sequence

from enum import Enum

FieldElement = int

PossibleBooleanElement = int

PossibleFieldElement = int

GateValue = int


class InteractionType(str, Enum):
    SEND = "send"
    RECV = "recv"


class InteractionScope(str, Enum):
    # the balancing domain this interaction belongs to.
    # local means it is balanced within a private permutation/logup domain.
    # global means it is balanced via a global ledger/table and often anchored to a public digest/sum.
    LOCAL = "local"
    GLOBAL = "global"


class InteractionKind(str, Enum):
    # coarse interaction kind. use table_id (and/or payload_schema) for vm-specific sub-kinds.
    MEMORY = "memory"
    PROGRAM = "program"
    INSTRUCTION = "instruction"
    ALU = "alu"
    BYTE = "byte"
    RANGE = "range"
    FIELD = "field"
    SYSCALL = "syscall"
    GLOBAL = "global"
    POSEIDON2 = "poseidon2"
    BITWISE = "bitwise"
    KECCAK = "keccak"
    SHA256 = "sha256"
    CUSTOM = "custom"


class MemorySpace(str, Enum):
    RAM = "ram"
    REG = "reg"
    VOLATILE = "volatile"
    IO = "io"


class MemorySize(str, Enum):
    BYTE = "byte"
    HALF_WORD = "half_word"
    WORD = "word"

    @property
    def byte_len(self) -> int:
        if self == MemorySize.BYTE:
            return 1
        if self == MemorySize.HALF_WORD:
            return 2
        return 4


class ChipRowKind(str, Enum):
    # Coarse, cross-vm chip-row semantics.
    PROGRAM = "program"
    CONTROL_FLOW = "control_flow"
    ALU = "alu"
    MEMORY = "memory"
    CONNECTOR = "connector"
    CPU = "cpu"
    HASH = "hash"
    SYSCALL = "syscall"
    CUSTOM = "custom"


@dataclass
class ChipRow:
    """
    A first-class "row semantics" object.

    This represents shared identity/gating metadata for a single row in a zkVM
    AIR/chip trace. Kind-specific semantic attributes live on concrete subclasses.

    ChipRow is intentionally *not* an Interaction: interactions are sent/recv
    messages used for cross-table balancing, while ChipRow captures per-chip
    row semantics (selectors, is_real, enabled, ...).
    """

    row_id: str
    domain: str
    chip: str
    gates: Dict[str, GateValue] = field(default_factory=dict)
    event_id: Optional[str] = None
    KIND: ClassVar[ChipRowKind] = ChipRowKind.CUSTOM

    @property
    def kind(self) -> ChipRowKind:
        return type(self).KIND


@dataclass
class ProgramChipRow(ChipRow):
    KIND: ClassVar[ChipRowKind] = ChipRowKind.PROGRAM
    pc: Optional[FieldElement] = None
    opcode: Optional[PossibleFieldElement] = None
    op_a: Optional[FieldElement] = None
    op_b: Optional[FieldElement] = None
    op_c: Optional[FieldElement] = None
    imm_b: Optional[bool] = None
    imm_c: Optional[bool] = None


@dataclass
class ControlFlowChipRow(ChipRow):
    KIND: ClassVar[ChipRowKind] = ChipRowKind.CONTROL_FLOW
    pc: Optional[FieldElement] = None
    next_pc: Optional[FieldElement] = None
    from_pc: Optional[FieldElement] = None
    to_pc: Optional[FieldElement] = None
    from_timestamp: Optional[FieldElement] = None
    to_timestamp: Optional[FieldElement] = None
    opcode: Optional[PossibleFieldElement] = None
    clk: Optional[FieldElement] = None
    op_a: Optional[FieldElement] = None
    op_b: Optional[FieldElement] = None
    op_c: Optional[FieldElement] = None
    imm_b: Optional[bool] = None
    imm_c: Optional[bool] = None


@dataclass
class AluChipRow(ChipRow):
    KIND: ClassVar[ChipRowKind] = ChipRowKind.ALU
    pc: Optional[FieldElement] = None
    clk: Optional[FieldElement] = None
    opcode: Optional[PossibleFieldElement] = None
    rd: Optional[FieldElement] = None
    rs1: Optional[FieldElement] = None
    rs2: Optional[FieldElement] = None
    imm: Optional[PossibleFieldElement] = None
    value: Optional[PossibleFieldElement] = None
    op_a: Optional[FieldElement] = None
    op_b: Optional[FieldElement] = None
    op_c: Optional[FieldElement] = None
    imm_b: Optional[bool] = None
    imm_c: Optional[bool] = None


@dataclass
class MemoryChipRow(ChipRow):
    KIND: ClassVar[ChipRowKind] = ChipRowKind.MEMORY
    pc: Optional[FieldElement] = None
    clk: Optional[FieldElement] = None
    opcode: Optional[PossibleFieldElement] = None
    from_pc: Optional[FieldElement] = None
    to_pc: Optional[FieldElement] = None
    from_timestamp: Optional[FieldElement] = None
    to_timestamp: Optional[FieldElement] = None
    addr: Optional[FieldElement] = None
    value: Optional[PossibleFieldElement] = None
    size_bytes: Optional[FieldElement] = None
    space: Optional[PossibleFieldElement] = None
    is_write: Optional[PossibleBooleanElement] = None
    rd: Optional[FieldElement] = None
    rs1: Optional[FieldElement] = None
    rs2: Optional[FieldElement] = None
    op_a: Optional[FieldElement] = None
    op_b: Optional[FieldElement] = None
    op_c: Optional[FieldElement] = None
    imm_b: Optional[bool] = None
    imm_c: Optional[bool] = None
    record_id: Optional[FieldElement] = None
    length: Optional[FieldElement] = None
    access_count: Optional[FieldElement] = None


@dataclass
class ConnectorChipRow(ChipRow):
    KIND: ClassVar[ChipRowKind] = ChipRowKind.CONNECTOR
    pc: Optional[FieldElement] = None
    from_pc: Optional[FieldElement] = None
    to_pc: Optional[FieldElement] = None
    timestamp: Optional[FieldElement] = None
    from_timestamp: Optional[FieldElement] = None
    to_timestamp: Optional[FieldElement] = None
    access_count: Optional[FieldElement] = None
    width: Optional[FieldElement] = None


@dataclass
class CpuChipRow(ChipRow):
    KIND: ClassVar[ChipRowKind] = ChipRowKind.CPU
    pc: Optional[FieldElement] = None
    clk: Optional[FieldElement] = None
    opcode: Optional[PossibleFieldElement] = None
    op_a: Optional[FieldElement] = None
    op_b: Optional[FieldElement] = None
    op_c: Optional[FieldElement] = None
    imm_b: Optional[bool] = None
    imm_c: Optional[bool] = None


@dataclass
class HashChipRow(ChipRow):
    KIND: ClassVar[ChipRowKind] = ChipRowKind.HASH
    pc: Optional[FieldElement] = None
    clk: Optional[FieldElement] = None
    opcode: Optional[PossibleFieldElement] = None
    value: Optional[PossibleFieldElement] = None


@dataclass
class SyscallChipRow(ChipRow):
    KIND: ClassVar[ChipRowKind] = ChipRowKind.SYSCALL
    pc: Optional[FieldElement] = None
    clk: Optional[FieldElement] = None
    opcode: Optional[PossibleFieldElement] = None
    syscall_id: Optional[FieldElement] = None


@dataclass
class CustomChipRow(ChipRow):
    KIND: ClassVar[ChipRowKind] = ChipRowKind.CUSTOM
    pc: Optional[FieldElement] = None
    opcode: Optional[PossibleFieldElement] = None


def _encode_memory_space(space: MemorySpace) -> int:
    return {
        MemorySpace.RAM: 0,
        MemorySpace.REG: 1,
        MemorySpace.VOLATILE: 2,
        MemorySpace.IO: 3,
    }[space]


def _encode_interaction_kind(kind: InteractionKind) -> int:
    # Stable tags for (coarse, cross-vm) kinds.
    order = list(InteractionKind)
    return order.index(kind)


@dataclass
class InteractionMultiplicity:
    value: Optional[FieldElement] = None
    # Optional provenance for multiplicity when it is derived from a specific trace field.
    #
    # This lets buckets/injections distinguish "same numeric value" vs "same underlying field".
    # Convention: "gates.<key>" or "<attr>" on the anchor row.
    ref: Optional[str] = None


@dataclass
class InteractionBase:
    """
    Interaction micro-op: the only micro-op type we keep.

    An interaction represents a single send/recv message to a balancing argument
    (permutation / logup / sumcheck-like accumulator). Payload is kind-specific.
    """

    table_id: str
    io: InteractionType
    # the balancing domain this interaction belongs to.
    scope: Optional[InteractionScope] = None
    # optional linkage to a specific chip row that "emits" this interaction.
    anchor_row_id: Optional[str] = None
    # optional cross-table event identifier (join key).
    event_id: Optional[str] = None
    # the interaction kind (coarse, cross-vm). use table_id for sub-kinds.
    kind: InteractionKind = InteractionKind.CUSTOM
    # The interaction multiplicity (count/weight) used by the balancing argument.
    # If present, `ref` can optionally point at the anchor-row field it was derived from.
    multiplicity: Optional[InteractionMultiplicity] = None

    def __post_init__(self):
        if not isinstance(self.io, InteractionType):
            raise ValueError(f"Interaction io {self.io} invalid")
        if self.scope is not None and not isinstance(self.scope, InteractionScope):
            raise ValueError(f"Interaction scope {self.scope} invalid")
        if not isinstance(self.kind, InteractionKind):
            # Allow callers/serializers to pass raw strings.
            self.kind = InteractionKind(str(self.kind))
        if self.multiplicity is not None and not isinstance(self.multiplicity, InteractionMultiplicity):
            raise ValueError("multiplicity must be an InteractionMultiplicity when set")

    def payload_schema(self) -> List[str]:
        return []

    def payload(self) -> List[FieldElement]:
        return []

    def payload_value(self, name: str) -> Optional[FieldElement]:
        schema = self.payload_schema()
        if not schema:
            return None
        try:
            idx = schema.index(name)
        except ValueError:
            return None
        payload = self.payload()
        if idx >= len(payload):
            return None
        return payload[idx]

    def payload_as_dict(self) -> Dict[str, FieldElement]:
        schema = self.payload_schema()
        payload = self.payload()
        if not schema:
            return {}
        return dict(zip(schema, payload))


@dataclass
class MemoryInteraction(InteractionBase):
    """
    Memory-like interaction (includes RAM/REG/IO spaces).

    Payload is a fixed schema so that it depends only on InteractionKind.MEMORY.
    """

    kind: InteractionKind = InteractionKind.MEMORY
    space: MemorySpace = MemorySpace.RAM
    addr: int = 0
    size: MemorySize = MemorySize.WORD
    value: FieldElement = 0
    is_write: PossibleBooleanElement = 0
    wen: Optional[PossibleBooleanElement] = None

    def payload_schema(self) -> List[str]:
        return ["space", "addr", "size_bytes", "value", "is_write", "wen"]

    def payload(self) -> List[FieldElement]:
        return [
            _encode_memory_space(self.space),
            int(self.addr),
            int(self.size.byte_len),
            int(self.value),
            int(self.is_write),
            int(self.wen) if self.wen is not None else 1,
        ]


@dataclass
class ProgramInteraction(InteractionBase):
    """
    Program / instruction-stream interaction.

    Use this for "program table" style arguments (PC, instruction word, next PC).
    """

    kind: InteractionKind = InteractionKind.PROGRAM
    pc: int = 0
    inst_word: int = 0
    next_pc: int = 0

    def payload_schema(self) -> List[str]:
        return ["pc", "inst_word", "next_pc"]

    def payload(self) -> List[FieldElement]:
        return [int(self.pc), int(self.inst_word), int(self.next_pc)]


@dataclass
class InstructionInteraction(InteractionBase):
    """
    Decoded-instruction interaction (opcode + operands), when the backend has one.
    """

    kind: InteractionKind = InteractionKind.INSTRUCTION
    opcode: int = 0
    rd: int = 0
    rs1: int = 0
    rs2: int = 0
    imm: int = 0

    def payload_schema(self) -> List[str]:
        return ["opcode", "rd", "rs1", "rs2", "imm"]

    def payload(self) -> List[FieldElement]:
        return [int(self.opcode), int(self.rd), int(self.rs1), int(self.rs2), int(self.imm)]


@dataclass
class AluInteraction(InteractionBase):
    kind: InteractionKind = InteractionKind.ALU
    op: int = 0
    a: FieldElement = 0
    b: FieldElement = 0
    out: FieldElement = 0

    def payload_schema(self) -> List[str]:
        return ["op", "a", "b", "out"]

    def payload(self) -> List[FieldElement]:
        return [int(self.op), int(self.a), int(self.b), int(self.out)]


@dataclass
class ByteInteraction(InteractionBase):
    kind: InteractionKind = InteractionKind.BYTE
    value: FieldElement = 0

    def payload_schema(self) -> List[str]:
        return ["value"]

    def payload(self) -> List[FieldElement]:
        return [int(self.value)]


@dataclass
class RangeInteraction(InteractionBase):
    kind: InteractionKind = InteractionKind.RANGE
    value: FieldElement = 0
    bits: int = 0

    def payload_schema(self) -> List[str]:
        return ["value", "bits"]

    def payload(self) -> List[FieldElement]:
        return [int(self.value), int(self.bits)]


@dataclass
class FieldInteraction(InteractionBase):
    kind: InteractionKind = InteractionKind.FIELD
    value: FieldElement = 0

    def payload_schema(self) -> List[str]:
        return ["value"]

    def payload(self) -> List[FieldElement]:
        return [int(self.value)]


@dataclass
class SyscallInteraction(InteractionBase):
    kind: InteractionKind = InteractionKind.SYSCALL
    syscall_id: int = 0
    arg0: FieldElement = 0
    arg1: FieldElement = 0
    arg2: FieldElement = 0
    arg3: FieldElement = 0
    ret0: FieldElement = 0

    def payload_schema(self) -> List[str]:
        return ["syscall_id", "arg0", "arg1", "arg2", "arg3", "ret0"]

    def payload(self) -> List[FieldElement]:
        return [
            int(self.syscall_id),
            int(self.arg0),
            int(self.arg1),
            int(self.arg2),
            int(self.arg3),
            int(self.ret0),
        ]


@dataclass
class GlobalInteraction(InteractionBase):
    kind: InteractionKind = InteractionKind.GLOBAL
    # Backends often include the local kind in the global message to avoid collisions.
    local_kind: InteractionKind = InteractionKind.CUSTOM
    digest_lo: FieldElement = 0
    digest_hi: FieldElement = 0

    def payload_schema(self) -> List[str]:
        return ["local_kind", "digest_lo", "digest_hi"]

    def payload(self) -> List[FieldElement]:
        return [int(_encode_interaction_kind(self.local_kind)), int(self.digest_lo), int(self.digest_hi)]


@dataclass
class BitwiseInteraction(InteractionBase):
    kind: InteractionKind = InteractionKind.BITWISE
    op: int = 0
    a: FieldElement = 0
    b: FieldElement = 0
    out: FieldElement = 0

    def payload_schema(self) -> List[str]:
        return ["op", "a", "b", "out"]

    def payload(self) -> List[FieldElement]:
        return [int(self.op), int(self.a), int(self.b), int(self.out)]


@dataclass
class HashInteraction(InteractionBase):
    """
    Common payload shape for hash-like chips.

    This is used for POSEIDON2 / KECCAK / SHA256 kinds.
    """

    block_idx: int = 0
    in_lo: FieldElement = 0
    in_hi: FieldElement = 0
    out_lo: FieldElement = 0
    out_hi: FieldElement = 0

    def payload_schema(self) -> List[str]:
        return ["block_idx", "in_lo", "in_hi", "out_lo", "out_hi"]

    def payload(self) -> List[FieldElement]:
        return [int(self.block_idx), int(self.in_lo), int(self.in_hi), int(self.out_lo), int(self.out_hi)]


@dataclass
class Poseidon2Interaction(HashInteraction):
    kind: InteractionKind = InteractionKind.POSEIDON2


@dataclass
class KeccakInteraction(HashInteraction):
    kind: InteractionKind = InteractionKind.KECCAK


@dataclass
class Sha256Interaction(HashInteraction):
    kind: InteractionKind = InteractionKind.SHA256


@dataclass
class CustomInteraction(InteractionBase):
    """
    Catch-all kind for vm-specific tables/chips.

    Payload is fixed-width; use table_id + field meanings in the adapter layer.
    """

    kind: InteractionKind = InteractionKind.CUSTOM
    a0: FieldElement = 0
    a1: FieldElement = 0
    a2: FieldElement = 0
    a3: FieldElement = 0

    def payload_schema(self) -> List[str]:
        return ["a0", "a1", "a2", "a3"]

    def payload(self) -> List[FieldElement]:
        return [int(self.a0), int(self.a1), int(self.a2), int(self.a3)]


MicroOp = ChipRow | InteractionBase


class ZKVMTrace:
    def __init__(
        self,
        micro_ops: Sequence[MicroOp],
        *,
        chip_rows: Optional[Sequence[ChipRow]] = None,
        # Optional op-level grouping: a list of op-spans, where each span is a list
        # of indices into `micro_ops` belonging to the same "core instruction / op".
        #
        # This is used by buckets/injections that need op-level reasoning (e.g. "does this
        # instruction have >=2 following instructions?") even when a single op expands
        # into multiple micro-ops across chips.
        op_spans: Optional[Sequence[Sequence[int]]] = None,
    ):
        # Preserve input order (caller decides ordering / grouping).
        self.micro_ops: List[MicroOp] = list(micro_ops)

        self.op_spans: Optional[List[List[int]]] = None
        if op_spans is not None:
            spans: List[List[int]] = [list(s) for s in op_spans]
            for op_idx, span in enumerate(spans):
                if not span:
                    raise ValueError(f"op_spans[{op_idx}] is empty")
                for i in span:
                    if not isinstance(i, int):
                        raise ValueError(f"op_spans[{op_idx}] contains non-int index: {i!r}")
                    if i < 0 or i >= len(self.micro_ops):
                        raise ValueError(
                            f"op_spans[{op_idx}] contains out-of-range index: {i} "
                            f"(len(micro_ops)={len(self.micro_ops)})"
                        )
            self.op_spans = spans

        # Allow callers to pass chip_rows separately (legacy) while also supporting
        # ChipRow entries directly in micro_ops.
        self.chip_rows: List[ChipRow] = [x for x in self.micro_ops if isinstance(x, ChipRow)]
        if chip_rows is not None:
            self.chip_rows.extend(list(chip_rows))

        self.interactions: List[InteractionBase] = [
            x for x in self.micro_ops if isinstance(x, InteractionBase)
        ]

        self.interactions_by_table: OrderedDict[str, List[InteractionBase]] = OrderedDict()
        for uop in self.interactions:
            self.interactions_by_table.setdefault(uop.table_id, []).append(uop)

        self.chip_rows_by_id: Dict[str, ChipRow] = {r.row_id: r for r in self.chip_rows}
        self.chip_rows_by_kind: OrderedDict[ChipRowKind, List[ChipRow]] = OrderedDict()
        for row in self.chip_rows:
            self.chip_rows_by_kind.setdefault(row.kind, []).append(row)

        self.interactions_by_anchor_row_id: OrderedDict[str, List[InteractionBase]] = OrderedDict()
        for uop in self.interactions:
            if uop.anchor_row_id is None:
                continue
            self.interactions_by_anchor_row_id.setdefault(uop.anchor_row_id, []).append(uop)

    def by_table_id(self, table_id: str) -> List[InteractionBase]:
        return self.interactions_by_table.get(table_id, [])

    def chip_row(self, row_id: str) -> Optional[ChipRow]:
        return self.chip_rows_by_id.get(row_id)

    def chip_rows_of_kind(self, kind: ChipRowKind) -> List[ChipRow]:
        return self.chip_rows_by_kind.get(kind, [])

    def by_anchor_row_id(self, row_id: str) -> List[InteractionBase]:
        return self.interactions_by_anchor_row_id.get(row_id, [])

    def op_micro_ops(self, op_idx: int) -> List[MicroOp]:
        if self.op_spans is None:
            raise ValueError("Trace has no op_spans; op-level access is unavailable")
        span = self.op_spans[op_idx]
        return [self.micro_ops[i] for i in span]

    def validate(self) -> List[str]:
        if not self.micro_ops:
            return ["Trace is empty"]
        errors: List[str] = []
        if len(self.chip_rows_by_id) != len(self.chip_rows):
            errors.append("Trace has duplicate ChipRow.row_id values")
        for uop in self.interactions:
            if uop.anchor_row_id is not None and uop.anchor_row_id not in self.chip_rows_by_id:
                errors.append(f"Interaction references missing anchor_row_id={uop.anchor_row_id!r}")
        return errors
