from __future__ import annotations

import json
from typing import Any, Dict, Optional

from beak_core.micro_ops import (
    AluChipRow,
    ChipRow,
    ChipRowKind,
    ConnectorChipRow,
    CpuChipRow,
    CustomChipRow,
    GateValue,
    HashChipRow,
    MemoryChipRow,
    PossibleFieldElement,
    ProgramChipRow,
    SyscallChipRow,
    ControlFlowChipRow,
)


def classify_chip_row_kind(*, domain: str, chip: str, gates: Dict[str, GateValue], values: Dict[str, Any]) -> ChipRowKind:
    del gates
    chip_l = chip.strip().lower()
    domain_l = domain.strip().lower()
    value_keys = {str(k).strip().lower() for k in values.keys()}

    if chip_l == "cpu":
        return ChipRowKind.CPU

    if "program" in chip_l:
        return ChipRowKind.PROGRAM

    if (
        any(tok in chip_l for tok in ("branch", "jal", "jalr", "jump", "auipc"))
        or any(tok in value_keys for tok in ("next_pc", "from_pc", "to_pc"))
        or (chip_l.startswith("exec(") and any(tok in chip_l for tok in ("beq", "bne", "blt", "bge", "jal", "jalr")))
    ):
        return ChipRowKind.CONTROL_FLOW

    if (
        any(tok in chip_l for tok in ("memory", "loadstore", "load_store", "rdwrite", "accessadapter"))
        or (
            chip_l.startswith("exec(")
            and any(tok in chip_l for tok in ("lw", "lh", "lb", "lbu", "lhu", "sw", "sh", "sb", "load", "store"))
        )
    ):
        return ChipRowKind.MEMORY

    if any(tok in chip_l for tok in ("connector", "wrapper", "bus")):
        return ChipRowKind.CONNECTOR

    if any(tok in chip_l for tok in ("poseidon", "keccak", "sha", "hash")):
        return ChipRowKind.HASH

    if "syscall" in chip_l or (domain_l == "sp1" and chip_l == "exec(ecall)"):
        return ChipRowKind.SYSCALL

    if (
        any(tok in chip_l for tok in ("alu", "add", "sub", "mul", "div", "bitwise", "xor", "and", "or", "shift", "sll", "srl", "sra", "slt"))
        or (chip_l.startswith("exec(") and any(tok in chip_l for tok in ("add", "sub", "mul", "div", "and", "or", "xor", "sll", "srl", "sra", "slt")))
    ):
        return ChipRowKind.ALU

    return ChipRowKind.CUSTOM


_CHIP_ROW_CLASS_BY_KIND = {
    ChipRowKind.PROGRAM: ProgramChipRow,
    ChipRowKind.CONTROL_FLOW: ControlFlowChipRow,
    ChipRowKind.ALU: AluChipRow,
    ChipRowKind.MEMORY: MemoryChipRow,
    ChipRowKind.CONNECTOR: ConnectorChipRow,
    ChipRowKind.CPU: CpuChipRow,
    ChipRowKind.HASH: HashChipRow,
    ChipRowKind.SYSCALL: SyscallChipRow,
    ChipRowKind.CUSTOM: CustomChipRow,
}


_CHIP_VALUE_KEYS = (
    "pc",
    "next_pc",
    "clk",
    "timestamp",
    "from_pc",
    "to_pc",
    "from_timestamp",
    "to_timestamp",
    "opcode",
    "rd",
    "rs1",
    "rs2",
    "imm",
    "addr",
    "value",
    "size_bytes",
    "space",
    "is_write",
    "op_a",
    "op_b",
    "op_c",
    "imm_b",
    "imm_c",
    "record_id",
    "length",
    "access_count",
    "width",
)


def _normalize_field_value(v: Any) -> Optional[PossibleFieldElement]:
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return int(v)
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        return s
    return None


def _pick_first_field(src: Dict[str, Any], *names: str) -> Optional[PossibleFieldElement]:
    for n in names:
        if n not in src:
            continue
        v = _normalize_field_value(src.get(n))
        if v is not None:
            return v
    return None


def extract_chip_row_values(*, record: Dict[str, Any], raw_values: Dict[str, Any]) -> Dict[str, PossibleFieldElement]:
    out: Dict[str, PossibleFieldElement] = {}

    payload_json = raw_values.get("payload_json")
    payload: Dict[str, Any] = {}
    if isinstance(payload_json, str):
        try:
            obj = json.loads(payload_json)
            if isinstance(obj, dict):
                payload = obj
        except Exception:
            payload = {}

    def set_field(name: str, v: Optional[PossibleFieldElement]):
        if v is not None:
            out[name] = v

    set_field("pc", _pick_first_field(raw_values, "pc"))
    if "pc" not in out:
        set_field("pc", _normalize_field_value(record.get("pc")))

    set_field("next_pc", _pick_first_field(raw_values, "next_pc", "to_pc"))
    set_field("clk", _pick_first_field(raw_values, "clk"))
    set_field("timestamp", _pick_first_field(raw_values, "timestamp"))
    set_field("from_pc", _pick_first_field(raw_values, "from_pc"))
    set_field("to_pc", _pick_first_field(raw_values, "to_pc"))
    set_field("from_timestamp", _pick_first_field(raw_values, "from_timestamp"))
    set_field("to_timestamp", _pick_first_field(raw_values, "to_timestamp"))
    set_field("opcode", _pick_first_field(raw_values, "opcode"))
    if "opcode" not in out:
        set_field("opcode", _pick_first_field(raw_values, "opcode_name", "local_opcode"))
    if "opcode" not in out:
        chip_name = record.get("chip")
        if isinstance(chip_name, str) and chip_name.startswith("Exec(") and chip_name.endswith(")"):
            out["opcode"] = chip_name[len("Exec(") : -1]
    set_field("rd", _pick_first_field(raw_values, "rd", "rd_id"))
    set_field("rs1", _pick_first_field(raw_values, "rs1", "rs1_id"))
    set_field("rs2", _pick_first_field(raw_values, "rs2", "rs2_id"))
    set_field("imm", _pick_first_field(raw_values, "imm", "imm_b", "imm_c"))
    set_field("addr", _pick_first_field(raw_values, "addr", "pointer", "ptr"))
    set_field("value", _pick_first_field(raw_values, "value"))
    set_field("size_bytes", _pick_first_field(raw_values, "size_bytes", "size"))
    set_field("space", _pick_first_field(raw_values, "space", "memory_space", "address_space"))
    set_field("is_write", _pick_first_field(raw_values, "is_write", "write", "is_store"))
    set_field("op_a", _pick_first_field(raw_values, "op_a"))
    set_field("op_b", _pick_first_field(raw_values, "op_b"))
    set_field("op_c", _pick_first_field(raw_values, "op_c"))
    set_field("imm_b", _pick_first_field(raw_values, "imm_b"))
    set_field("imm_c", _pick_first_field(raw_values, "imm_c"))
    set_field("record_id", _pick_first_field(raw_values, "record_id"))
    set_field("length", _pick_first_field(raw_values, "length", "len"))
    set_field("access_count", _pick_first_field(raw_values, "access_count"))
    set_field("width", _pick_first_field(raw_values, "width"))

    if "rd" not in out and "op_a" in out:
        out["rd"] = out["op_a"]
    if "rs1" not in out and out.get("imm_b") is False and "op_b" in out:
        out["rs1"] = out["op_b"]
    if "rs2" not in out and out.get("imm_c") is False and "op_c" in out:
        out["rs2"] = out["op_c"]
    if "imm" not in out:
        if out.get("imm_b") is True and "op_b" in out:
            out["imm"] = out["op_b"]
        elif out.get("imm_c") is True and "op_c" in out:
            out["imm"] = out["op_c"]

    if payload:
        from_state = payload.get("adapter_write", {}).get("from_state") if isinstance(payload.get("adapter_write"), dict) else None
        if isinstance(from_state, dict):
            set_field("from_pc", _pick_first_field(from_state, "pc"))
            set_field("from_timestamp", _pick_first_field(from_state, "timestamp"))
        set_field("rd", _pick_first_field(payload.get("adapter_write", {}) if isinstance(payload.get("adapter_write"), dict) else {}, "rd_id"))
        set_field("rs1", _pick_first_field(payload.get("adapter_read", {}) if isinstance(payload.get("adapter_read"), dict) else {}, "rs1_id"))
        set_field("rs2", _pick_first_field(payload.get("adapter_read", {}) if isinstance(payload.get("adapter_read"), dict) else {}, "rs2_id"))

    return {k: out[k] for k in _CHIP_VALUE_KEYS if k in out}


def _chip_row_semantic_kwargs(cls: type[ChipRow], values: Dict[str, PossibleFieldElement]) -> Dict[str, PossibleFieldElement]:
    base_keys = {"row_id", "domain", "chip", "gates", "event_id"}
    allow = set(getattr(cls, "__dataclass_fields__", {}).keys()) - base_keys
    return {k: v for k, v in values.items() if k in allow}


def make_chip_row(
    *,
    row_id: str,
    domain: str,
    chip: str,
    gates: Optional[Dict[str, Any]] = None,
    values: Optional[Dict[str, PossibleFieldElement]] = None,
    event_id: Optional[str] = None,
    kind: Optional[ChipRowKind] = None,
) -> ChipRow:
    gates_obj = dict(gates or {})
    values_obj = dict(values or {})
    kind_t = kind or classify_chip_row_kind(
        domain=domain,
        chip=chip,
        gates=gates_obj,
        values=values_obj,
    )
    cls = _CHIP_ROW_CLASS_BY_KIND.get(kind_t, CustomChipRow)
    return cls(
        row_id=row_id,
        domain=domain,
        chip=chip,
        gates=gates_obj,
        event_id=event_id,
        **_chip_row_semantic_kwargs(cls, values_obj),
    )


def chip_row_from_record(rec: Dict[str, Any]) -> Optional[ChipRow]:
    row_id = rec.get("row_id")
    domain = rec.get("domain")
    chip = rec.get("chip")
    gates = rec.get("gates")
    raw_values = rec.get("values")
    event_id = rec.get("event_id")
    kind_raw = rec.get("chip_kind")

    if not isinstance(row_id, str) or not isinstance(domain, str) or not isinstance(chip, str):
        return None
    if not isinstance(gates, dict):
        gates = {}
    if not isinstance(raw_values, dict):
        raw_values = {}
    if event_id is not None and not isinstance(event_id, str):
        event_id = None

    kind_t: Optional[ChipRowKind] = None
    if isinstance(kind_raw, str):
        try:
            kind_t = ChipRowKind(kind_raw)
        except Exception:
            kind_t = None

    return make_chip_row(
        row_id=row_id,
        domain=domain,
        chip=chip,
        gates=gates,
        values=extract_chip_row_values(record=rec, raw_values=raw_values),
        event_id=event_id,
        kind=kind_t,
    )
