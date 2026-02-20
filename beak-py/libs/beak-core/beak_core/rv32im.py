import re
from dataclasses import dataclass, field
from enum import Enum
import struct
from typing import List, Dict, Optional

# --- Memory Layout Constants ---
DEFAULT_CODE_BASE = 0x1000  # Where code is loaded
DEFAULT_DATA_BASE = 0x20000  # Safe region for memory ops


class RV32Type(str, Enum):
    R = "r"
    I = "i"
    S = "s"
    B = "b"
    U = "u"
    J = "j"
    SYSTEM = "system"


class RV32Trap(str, Enum):
    INSTRUCTION_ADDRESS_MISALIGNED = "instruction_address_misaligned"
    INSTRUCTION_ACCESS_FAULT = "instruction_access_fault"
    ILLEGAL_INSTRUCTION = "illegal_instruction"
    BREAKPOINT = "breakpoint"
    LOAD_ADDRESS_MISALIGNED = "load_address_misaligned"
    LOAD_ACCESS_FAULT = "load_access_fault"
    STORE_ADDRESS_MISALIGNED = "store_address_misaligned"
    STORE_ACCESS_FAULT = "store_access_fault"
    ENV_CALL_FROM_UMODE = "env_call_from_umode"
    ENV_CALL_FROM_SMODE = "env_call_from_smode"
    ENV_CALL_FROM_MMODE = "env_call_from_mmode"
    INSTRUCTION_PAGE_FAULT = "instruction_page_fault"
    LOAD_PAGE_FAULT = "load_page_fault"
    STORE_PAGE_FAULT = "store_page_fault"


# --- Assembly Templates ---
TEMPLATE_RTYPE = "{mnemonic} x{rd}, x{rs1}, x{rs2}"
TEMPLATE_ITYPE = "{mnemonic} x{rd}, x{rs1}, {imm}"
TEMPLATE_STYPE = "{mnemonic} x{rs2}, {imm}(x{rs1})"
TEMPLATE_BTYPE = "{mnemonic} x{rs1}, x{rs2}, .{imm:+d}"
TEMPLATE_UTYPE = "{mnemonic} x{rd}, {imm:#x}"
TEMPLATE_JTYPE = "{mnemonic} x{rd}, .{imm:+d}"
TEMPLATE_SYSTEM = "{mnemonic}"
TEMPLATE_JALR_AND_LOAD = "{mnemonic} x{rd}, {imm}(x{rs1})"


@dataclass
class RV32Mnemonic:
    literal: str
    format: RV32Type
    opcode: int
    f3: int = 0
    f7: int = 0
    assembly_template: str = ""


# --- RV32IM Standard Instruction Set ---

# Opcode 0x33: R-type (ALU & M-Extension)
ADD = RV32Mnemonic("add", RV32Type.R, 0x33, 0x0, 0x00, TEMPLATE_RTYPE)
SUB = RV32Mnemonic("sub", RV32Type.R, 0x33, 0x0, 0x20, TEMPLATE_RTYPE)
SLL = RV32Mnemonic("sll", RV32Type.R, 0x33, 0x1, 0x00, TEMPLATE_RTYPE)
SLT = RV32Mnemonic("slt", RV32Type.R, 0x33, 0x2, 0x00, TEMPLATE_RTYPE)
SLTU = RV32Mnemonic("sltu", RV32Type.R, 0x33, 0x3, 0x00, TEMPLATE_RTYPE)
XOR = RV32Mnemonic("xor", RV32Type.R, 0x33, 0x4, 0x00, TEMPLATE_RTYPE)
SRL = RV32Mnemonic("srl", RV32Type.R, 0x33, 0x5, 0x00, TEMPLATE_RTYPE)
SRA = RV32Mnemonic("sra", RV32Type.R, 0x33, 0x5, 0x20, TEMPLATE_RTYPE)
OR = RV32Mnemonic("or", RV32Type.R, 0x33, 0x6, 0x00, TEMPLATE_RTYPE)
AND = RV32Mnemonic("and", RV32Type.R, 0x33, 0x7, 0x00, TEMPLATE_RTYPE)
MUL = RV32Mnemonic("mul", RV32Type.R, 0x33, 0x0, 0x01, TEMPLATE_RTYPE)
MULH = RV32Mnemonic("mulh", RV32Type.R, 0x33, 0x1, 0x01, TEMPLATE_RTYPE)
MULHSU = RV32Mnemonic("mulhsu", RV32Type.R, 0x33, 0x2, 0x01, TEMPLATE_RTYPE)
MULHU = RV32Mnemonic("mulhu", RV32Type.R, 0x33, 0x3, 0x01, TEMPLATE_RTYPE)
DIV = RV32Mnemonic("div", RV32Type.R, 0x33, 0x4, 0x01, TEMPLATE_RTYPE)
DIVU = RV32Mnemonic("divu", RV32Type.R, 0x33, 0x5, 0x01, TEMPLATE_RTYPE)
REM = RV32Mnemonic("rem", RV32Type.R, 0x33, 0x6, 0x01, TEMPLATE_RTYPE)
REMU = RV32Mnemonic("remu", RV32Type.R, 0x33, 0x7, 0x01, TEMPLATE_RTYPE)

# Opcode 0x13: I-type (ALU Immediate & Shifts)
ADDI = RV32Mnemonic("addi", RV32Type.I, 0x13, 0x0, 0x00, TEMPLATE_ITYPE)
SLTI = RV32Mnemonic("slti", RV32Type.I, 0x13, 0x2, 0x00, TEMPLATE_ITYPE)
SLTIU = RV32Mnemonic("sltiu", RV32Type.I, 0x13, 0x3, 0x00, TEMPLATE_ITYPE)
XORI = RV32Mnemonic("xori", RV32Type.I, 0x13, 0x4, 0x00, TEMPLATE_ITYPE)
ORI = RV32Mnemonic("ori", RV32Type.I, 0x13, 0x6, 0x00, TEMPLATE_ITYPE)
ANDI = RV32Mnemonic("andi", RV32Type.I, 0x13, 0x7, 0x00, TEMPLATE_ITYPE)
SLLI = RV32Mnemonic("slli", RV32Type.I, 0x13, 0x1, 0x00, TEMPLATE_ITYPE)
SRLI = RV32Mnemonic("srli", RV32Type.I, 0x13, 0x5, 0x00, TEMPLATE_ITYPE)
SRAI = RV32Mnemonic("srai", RV32Type.I, 0x13, 0x5, 0x20, TEMPLATE_ITYPE)

# Opcode 0x03: I-type (Load)
LB = RV32Mnemonic("lb", RV32Type.I, 0x03, 0x0, 0x00, TEMPLATE_JALR_AND_LOAD)
LH = RV32Mnemonic("lh", RV32Type.I, 0x03, 0x1, 0x00, TEMPLATE_JALR_AND_LOAD)
LW = RV32Mnemonic("lw", RV32Type.I, 0x03, 0x2, 0x00, TEMPLATE_JALR_AND_LOAD)
LBU = RV32Mnemonic("lbu", RV32Type.I, 0x03, 0x4, 0x00, TEMPLATE_JALR_AND_LOAD)
LHU = RV32Mnemonic("lhu", RV32Type.I, 0x03, 0x5, 0x00, TEMPLATE_JALR_AND_LOAD)

# Opcode 0x23: S-type (Store)
SB = RV32Mnemonic("sb", RV32Type.S, 0x23, 0x0, 0x00, TEMPLATE_STYPE)
SH = RV32Mnemonic("sh", RV32Type.S, 0x23, 0x1, 0x00, TEMPLATE_STYPE)
SW = RV32Mnemonic("sw", RV32Type.S, 0x23, 0x2, 0x00, TEMPLATE_STYPE)

# Opcode 0x63: B-type (Branch)
BEQ = RV32Mnemonic("beq", RV32Type.B, 0x63, 0x0, 0x00, TEMPLATE_BTYPE)
BNE = RV32Mnemonic("bne", RV32Type.B, 0x63, 0x1, 0x00, TEMPLATE_BTYPE)
BLT = RV32Mnemonic("blt", RV32Type.B, 0x63, 0x4, 0x00, TEMPLATE_BTYPE)
BGE = RV32Mnemonic("bge", RV32Type.B, 0x63, 0x5, 0x00, TEMPLATE_BTYPE)
BLTU = RV32Mnemonic("bltu", RV32Type.B, 0x63, 0x6, 0x00, TEMPLATE_BTYPE)
BGEU = RV32Mnemonic("bgeu", RV32Type.B, 0x63, 0x7, 0x00, TEMPLATE_BTYPE)

# Opcode 0x37 & 0x17: U-type
LUI = RV32Mnemonic("lui", RV32Type.U, 0x37, 0x0, 0x00, TEMPLATE_UTYPE)
AUIPC = RV32Mnemonic("auipc", RV32Type.U, 0x17, 0x0, 0x00, TEMPLATE_UTYPE)

# Jumps
JAL = RV32Mnemonic("jal", RV32Type.J, 0x6F, 0x0, 0x00, TEMPLATE_JTYPE)
JALR = RV32Mnemonic("jalr", RV32Type.I, 0x67, 0x0, 0x00, TEMPLATE_JALR_AND_LOAD)

# Opcode 0x73: System & CSR (Simplified)
ECALL = RV32Mnemonic("ecall", RV32Type.SYSTEM, 0x73, 0x0, 0x00, TEMPLATE_SYSTEM)
EBREAK = RV32Mnemonic("ebreak", RV32Type.SYSTEM, 0x73, 0x0, 0x01, TEMPLATE_SYSTEM)

# Opcode 0x0F: Fence, not used in the fuzzer
FENCE = RV32Mnemonic("fence", RV32Type.I, 0x0F, 0x0, 0x00, TEMPLATE_SYSTEM)
FENCE_I = RV32Mnemonic("fence.i", RV32Type.I, 0x0F, 0x1, 0x00, TEMPLATE_SYSTEM)

LITERAL_TO_MNEMONIC = {
    "add": ADD,
    "sub": SUB,
    "xor": XOR,
    "or": OR,
    "and": AND,
    "sll": SLL,
    "srl": SRL,
    "sra": SRA,
    "slt": SLT,
    "sltu": SLTU,
    "mul": MUL,
    "mulh": MULH,
    "mulhsu": MULHSU,
    "mulhu": MULHU,
    "div": DIV,
    "divu": DIVU,
    "rem": REM,
    "remu": REMU,
    "addi": ADDI,
    "xori": XORI,
    "ori": ORI,
    "andi": ANDI,
    "slli": SLLI,
    "srli": SRLI,
    "srai": SRAI,
    "slti": SLTI,
    "sltiu": SLTIU,
    "jal": JAL,
    "jalr": JALR,
    "beq": BEQ,
    "bne": BNE,
    "blt": BLT,
    "bge": BGE,
    "bltu": BLTU,
    "bgeu": BGEU,
    "lb": LB,
    "lh": LH,
    "lw": LW,
    "lbu": LBU,
    "lhu": LHU,
    "sb": SB,
    "sh": SH,
    "sw": SW,
    "lui": LUI,
    "auipc": AUIPC,
    "ecall": ECALL,
    "ebreak": EBREAK,
    "fence": FENCE,
    "fence.i": FENCE_I,
}

R_TYPE_INSTRUCTIONS = [v for v in LITERAL_TO_MNEMONIC.values() if v.format == RV32Type.R]
I_TYPE_INSTRUCTIONS = [v for v in LITERAL_TO_MNEMONIC.values() if v.format == RV32Type.I]
U_TYPE_INSTRUCTIONS = [v for v in LITERAL_TO_MNEMONIC.values() if v.format == RV32Type.U]
SIGNED_OPERAND_INSTRUCTIONS = [SLT, SLTU, SLTI, SLTIU]
JUMP_INSTRUCTIONS = [JAL, JALR]
SHIFT_INSTRUCTIONS = [SLL, SRL, SRA, SLLI, SRLI, SRAI]
LOAD_INSTRUCTIONS = [LB, LH, LW, LBU, LHU]
STORE_INSTRUCTIONS = [SB, SH, SW]
BRANCH_INSTRUCTIONS = [BEQ, BNE, BLT, BGE, BLTU, BGEU]
SYSTEM_INSTRUCTIONS = [ECALL, EBREAK]
FENCE_INSTRUCTIONS = [FENCE, FENCE_I]


@dataclass
class Instruction:
    mnemonic: RV32Mnemonic
    rd: Optional[int] = None
    rs1: Optional[int] = None
    rs2: Optional[int] = None
    imm: Optional[int] = None

    _asm: str = field(init=False, repr=False)
    _binary: bytes = field(init=False, repr=False)
    _hex: str = field(init=False, repr=False)

    def __post_init__(self):
        self._asm = self.__get_asm()
        self._binary = self.__get_binary()
        self._hex = f"0x{struct.unpack('<I', self._binary)[0]:08x}"

    def __get_asm(self) -> str:
        template = self.mnemonic.assembly_template
        imm = self.imm if self.imm is not None else 0
        # RV32 shift-immediate instructions encode shamt in 5 bits. Our encoder already masks
        # the immediate, but emitting the raw value breaks inline asm compilation.
        if self.mnemonic.literal in ("slli", "srli", "srai"):
            imm &= 0x1F
        return template.format(
            mnemonic=self.mnemonic.literal,
            rd=self.rd,
            rs1=self.rs1,
            rs2=self.rs2,
            imm=imm,
        )

    def __get_binary(self) -> bytes:
        m = self.mnemonic
        fmt, op, f3, f7 = m.format, m.opcode, m.f3, m.f7
        rd = self.rd or 0
        rs1 = self.rs1 or 0
        rs2 = self.rs2 or 0
        imm = self.imm or 0

        res = 0
        if fmt == RV32Type.R:
            res = (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
        elif fmt == RV32Type.I:
            if m.literal in ("slli", "srli", "srai"):
                res = (f7 << 25) | ((imm & 0x1F) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
            else:
                res = ((imm & 0xFFF) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
        elif fmt == RV32Type.S:
            res = (
                (((imm >> 5) & 0x7F) << 25)
                | (rs2 << 20)
                | (rs1 << 15)
                | (f3 << 12)
                | ((imm & 0x1F) << 7)
                | op
            )
        elif fmt == RV32Type.B:
            res = (
                (((imm >> 12) & 1) << 31)
                | (((imm >> 5) & 0x3F) << 25)
                | (rs2 << 20)
                | (rs1 << 15)
                | (f3 << 12)
                | (((imm >> 1) & 0xF) << 8)
                | (((imm >> 11) & 1) << 7)
                | op
            )
        elif fmt == RV32Type.U:
            res = ((imm & 0xFFFFF) << 12) | (rd << 7) | op
        elif fmt == RV32Type.J:
            res = (
                (((imm >> 20) & 1) << 31)
                | (((imm >> 1) & 0x3FF) << 21)
                | (((imm >> 11) & 1) << 20)
                | (((imm >> 12) & 0xFF) << 12)
                | (rd << 7)
                | op
            )
        elif fmt == RV32Type.SYSTEM:
            # For ECALL/EBREAK, bits [31:20] are a 12-bit immediate:
            # - ecall:  imm=0
            # - ebreak: imm=1
            # We store that 12-bit immediate in RV32Mnemonic.f7 for these simplified SYSTEM mnemonics.
            res = ((f7 & 0xFFF) << 20) | (f3 << 12) | op

        return struct.pack("<I", res)

    @property
    def opcode(self) -> int:
        return self.mnemonic.opcode

    @property
    def f3(self) -> int:
        return self.mnemonic.f3

    @property
    def f7(self) -> int:
        return self.mnemonic.f7

    @property
    def format(self) -> RV32Type:
        return self.mnemonic.format

    @property
    def asm(self) -> str:
        return self._asm

    @property
    def binary(self) -> bytes:
        return self._binary

    @staticmethod
    def from_asm(line: str) -> "Instruction":
        # Example: "add x1, x2, x3" -> ["add", "x1", "x2", "x3"]
        # Example: "beq x1, x2, .+4" -> ["beq", "x1", "x2", ".+4"]
        # Example: "lw x1, -4(x2)" -> ["lw", "x1", "-4", "x2"]
        parts = re.findall(r"[\w\.\+-]+", line.replace(",", " "))
        if not parts:
            raise ValueError(f"CRITICAL: Empty instruction line: {line}")
        literal = parts[0]
        if literal not in LITERAL_TO_MNEMONIC:
            raise ValueError(f"CRITICAL: Unknown mnemonic '{literal}' in line: {line}")

        mnemonic = LITERAL_TO_MNEMONIC[literal]

        def r_idx(s):
            return int(s.replace("x", ""))

        def imm_val(s):
            if s.startswith("0x"):
                return int(s, 16)
            if ".+" in s:
                return int(s.split("+")[1])
            if "." in s and len(s) > 1:
                return int(s.split(".")[1])
            return int(s)

        fmt = mnemonic.format
        try:
            if fmt == RV32Type.R:
                return Instruction(
                    mnemonic, rd=r_idx(parts[1]), rs1=r_idx(parts[2]), rs2=r_idx(parts[3])
                )
            if fmt == RV32Type.I:
                # Some I-type mnemonics in this simplified model omit operands (e.g. "fence").
                if mnemonic.assembly_template == TEMPLATE_SYSTEM and len(parts) == 1:
                    return Instruction(mnemonic)
                if mnemonic.assembly_template == TEMPLATE_JALR_AND_LOAD:
                    return Instruction(
                        mnemonic, rd=r_idx(parts[1]), imm=imm_val(parts[2]), rs1=r_idx(parts[3])
                    )
                return Instruction(
                    mnemonic, rd=r_idx(parts[1]), rs1=r_idx(parts[2]), imm=imm_val(parts[3])
                )
            if fmt == RV32Type.S:
                return Instruction(
                    mnemonic, rs2=r_idx(parts[1]), imm=imm_val(parts[2]), rs1=r_idx(parts[3])
                )
            if fmt == RV32Type.B:
                return Instruction(
                    mnemonic, rs1=r_idx(parts[1]), rs2=r_idx(parts[2]), imm=imm_val(parts[3])
                )
            if fmt in [RV32Type.U, RV32Type.J]:
                return Instruction(mnemonic, rd=r_idx(parts[1]), imm=imm_val(parts[2]))
            if fmt == RV32Type.SYSTEM:
                return Instruction(mnemonic)
        except Exception as e:
            raise ValueError(f"CRITICAL: Failed to parse instruction: {line} - {e}")

        raise ValueError(f"CRITICAL: Unhandled format '{fmt}' for instruction: {mnemonic}")

    @staticmethod
    def from_binary(binary: bytes) -> "Instruction":
        if len(binary) != 4:
            raise ValueError(f"Invalid binary length: {len(binary)}")
        val = struct.unpack("<I", binary)[0]
        opcode = val & 0x7F
        f3 = (val >> 12) & 0x7
        f7 = (val >> 25) & 0x7F
        target_mnemonic = None
        for m in LITERAL_TO_MNEMONIC.values():
            if m.opcode != opcode:
                continue
            # U/J formats do not have funct3; bits [14:12] are part of the immediate.
            if m.format not in (RV32Type.U, RV32Type.J) and m.f3 != f3:
                continue
            if m.format == RV32Type.R and m.f7 != f7:
                continue
            if m.format == RV32Type.SYSTEM:
                imm12 = (val >> 20) & 0xFFF
                if (m.f7 & 0xFFF) != imm12:
                    continue
            if m.format == RV32Type.I and m.literal in ("slli", "srli", "srai") and m.f7 != f7:
                continue
            target_mnemonic = m
            break
        if not target_mnemonic:
            raise ValueError(f"Unknown instruction binary: 0x{val:08x}")
        fmt = target_mnemonic.format
        rd = (val >> 7) & 0x1F
        rs1 = (val >> 15) & 0x1F
        rs2 = (val >> 20) & 0x1F
        imm = None
        if fmt == RV32Type.I:
            imm = val >> 20
            if imm & 0x800:
                imm |= ~0xFFF
            if target_mnemonic.literal in ("slli", "srli", "srai"):
                imm &= 0x1F
        elif fmt == RV32Type.S:
            imm = ((val >> 25) << 5) | ((val >> 7) & 0x1F)
            if imm & 0x800:
                imm |= ~0xFFF
        elif fmt == RV32Type.B:
            imm = (
                (((val >> 31) & 1) << 12)
                | (((val >> 7) & 1) << 11)
                | (((val >> 25) & 0x3F) << 5)
                | (((val >> 8) & 0xF) << 1)
            )
            if imm & 0x1000:
                imm |= ~0x1FFF
        elif fmt == RV32Type.U:
            imm = (val >> 12) & 0xFFFFF
        elif fmt == RV32Type.J:
            imm = (
                (((val >> 31) & 1) << 20)
                | (((val >> 12) & 0xFF) << 12)
                | (((val >> 20) & 1) << 11)
                | (((val >> 21) & 0x3FF) << 1)
            )
            if imm & 0x100000:
                imm |= ~0x1FFFFF
        return Instruction(target_mnemonic, rd=rd, rs1=rs1, rs2=rs2, imm=imm)

    @staticmethod
    def from_hex(hex: str) -> "Instruction":
        # The textual hex is a 32-bit instruction *word* (e.g. "00c58533"),
        # but from_binary expects little-endian bytes (as laid out in memory).
        word = int(hex.replace("0x", ""), 16)
        return Instruction.from_binary(word.to_bytes(4, "little"))


@dataclass
class FuzzingInstance:
    instructions: List[Instruction]

    # The key is the register index, the value is the initial value.
    initial_regs: Dict[int, int] = field(default_factory=dict)

    # The key is the register index, the value is the expected result.
    expected_results: Dict[int, int] = field(default_factory=dict)

    def asm_block(self) -> str:
        return "\n".join([inst.asm for inst in self.instructions])
