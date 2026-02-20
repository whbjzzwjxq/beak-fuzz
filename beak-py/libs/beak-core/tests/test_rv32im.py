import struct

import pytest

from beak_core.rv32im import (
    ADD,
    ADDI,
    AUIPC,
    BEQ,
    ECALL,
    EBREAK,
    FENCE,
    FENCE_I,
    Instruction,
    JAL,
    LUI,
    LW,
    SRAI,
    SUB,
    SW,
)


def _u32(inst: Instruction) -> int:
    return struct.unpack("<I", inst.binary)[0]


@pytest.mark.parametrize(
    "asm, expected_u32",
    [
        # R-type
        ("add x1, x2, x3", 0x003100B3),
        ("sub x1, x2, x3", 0x403100B3),
        # I-type (arith)
        ("addi x1, x2, -1", 0xFFF10093),
        # I-type (shift imm)
        ("srai x1, x2, 31", 0x41F15093),
        # I-type (load)
        ("lw x1, -4(x2)", 0xFFC12083),
        # S-type (store)
        ("sw x3, 8(x2)", 0x00312423),
        # B-type (branch)
        ("beq x1, x2, .+16", 0x00208863),
        # U-type
        ("lui x1, 0x12345", 0x123450B7),
        # J-type
        ("jal x1, .+16", 0x010000EF),
        # SYSTEM
        ("ecall", 0x00000073),
        ("ebreak", 0x00100073),
        # "Simplified" fence encoding in this project: operands omitted => all zeros.
        ("fence", 0x0000000F),
        ("fence.i", 0x0000100F),
    ],
)
def test_from_asm_known_encodings(asm: str, expected_u32: int):
    inst = Instruction.from_asm(asm)
    assert _u32(inst) == expected_u32


def test_from_binary_roundtrip_for_all_formats():
    """
    Ensure binary -> Instruction -> binary roundtrips for representative mnemonics
    across all supported formats.
    """
    insts = [
        Instruction(ADD, rd=1, rs1=2, rs2=3),
        Instruction(SUB, rd=1, rs1=2, rs2=3),
        Instruction(ADDI, rd=1, rs1=2, imm=-1),
        Instruction(SRAI, rd=1, rs1=2, imm=31),
        Instruction(LW, rd=1, rs1=2, imm=-4),
        Instruction(SW, rs2=3, rs1=2, imm=8),
        Instruction(BEQ, rs1=1, rs2=2, imm=16),
        Instruction(LUI, rd=1, imm=0x12345),
        Instruction(AUIPC, rd=1, imm=0x54321),
        Instruction(JAL, rd=1, imm=16),
        Instruction(ECALL),
        Instruction(EBREAK),
        Instruction(FENCE),
    ]

    for inst in insts:
        decoded = Instruction.from_binary(inst.binary)
        assert decoded.binary == inst.binary


def test_system_ecall_ebreak_are_distinguished_in_from_binary():
    ecall = Instruction(ECALL)
    ebreak = Instruction(EBREAK)
    assert Instruction.from_binary(ecall.binary).mnemonic is ECALL
    assert Instruction.from_binary(ebreak.binary).mnemonic is EBREAK


def test_fence_parses_as_operandless_i_type():
    inst = Instruction.from_asm("fence")
    assert inst.mnemonic is FENCE
    assert _u32(inst) == 0x0000000F


