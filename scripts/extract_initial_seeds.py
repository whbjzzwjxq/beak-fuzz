from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable


def _sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    mask = (1 << bits) - 1
    value &= mask
    return (value ^ sign_bit) - sign_bit


def _opcode(word: int) -> int:
    return word & 0x7F


def _rd(word: int) -> int:
    return (word >> 7) & 0x1F


def _funct3(word: int) -> int:
    return (word >> 12) & 0x7


def _rs1(word: int) -> int:
    return (word >> 15) & 0x1F


def _rs2(word: int) -> int:
    return (word >> 20) & 0x1F


def _is_bne(word: int) -> bool:
    return _opcode(word) == 0x63 and _funct3(word) == 0x1


def _is_branch_b_type(word: int) -> bool:
    return _opcode(word) == 0x63


def _imm_b(word: int) -> int:
    imm12 = (word >> 31) & 1
    imm11 = (word >> 7) & 1
    imm10_5 = (word >> 25) & 0x3F
    imm4_1 = (word >> 8) & 0xF
    imm = (imm12 << 11) | (imm11 << 10) | (imm10_5 << 4) | (imm4_1 << 1)
    return _sign_extend(imm, 12) * 2


def _encode_rtype(
    funct7: int, rs2: int, rs1: int, funct3: int, rd: int, opcode: int = 0x33
) -> int:
    return (
        ((funct7 & 0x7F) << 25)
        | ((rs2 & 0x1F) << 20)
        | ((rs1 & 0x1F) << 15)
        | ((funct3 & 0x7) << 12)
        | ((rd & 0x1F) << 7)
        | (opcode & 0x7F)
    )


ORACLE_RESULT_REG = 10  # a0
GP_REG = 3

# Map zkvm-unsupported / reserved regs to temporaries:
# sp(2), gp(3), tp(4), x8/fp(8), x9/s1(9) -> t0(5), t1(6), t2(7), t3(28), t4(29)
REG_REMAP = {2: 5, 3: 6, 4: 7, 8: 28, 9: 29}


def _remap_reg(r: int) -> int:
    return REG_REMAP.get(r, r)


def _rewrite_word_regs(word: int) -> int:
    """Rewrite rd/rs1/rs2: sp,gp,tp,x8,x9 -> t0,t1,t2,t3,t4."""
    opcode = _opcode(word)
    if opcode in (0x33, 0x3B):
        rd, rs1, rs2 = _rd(word), _rs1(word), _rs2(word)
        rd, rs1, rs2 = _remap_reg(rd), _remap_reg(rs1), _remap_reg(rs2)
        return (word & 0xFE00007F) | (rd << 7) | (rs1 << 15) | (rs2 << 20)
    if opcode in (0x13, 0x03, 0x67, 0x73):
        rd, rs1 = _rd(word), _rs1(word)
        rd, rs1 = _remap_reg(rd), _remap_reg(rs1)
        return (word & 0xFFFFE07F) | (rd << 7) | (rs1 << 15)
    if opcode == 0x23:
        rs1, rs2 = _rs1(word), _rs2(word)
        rs1, rs2 = _remap_reg(rs1), _remap_reg(rs2)
        return (word & 0x01FFF07F) | (rs1 << 15) | (rs2 << 20)
    if opcode == 0x63:
        rs1, rs2 = _rs1(word), _rs2(word)
        rs1, rs2 = _remap_reg(rs1), _remap_reg(rs2)
        return (word & 0x01FFF07F) | (rs1 << 15) | (rs2 << 20)
    if opcode in (0x37, 0x17):
        rd = _remap_reg(_rd(word))
        return (word & 0xFFFFF07F) | (rd << 7)
    if opcode == 0x6F:
        rd = _remap_reg(_rd(word))
        return (word & 0xFFFFF07F) | (rd << 7)
    return word


def _strip_trailing_bne_zero_gp_pass(words: list[int]) -> list[int]:
    while len(words) >= 1:
        br = words[-1]
        if not _is_bne(br) or _imm_b(br) <= 0:
            break
        r1, r2 = _rs1(br), _rs2(br)
        if {r1, r2} == {0, GP_REG}:
            words = words[:-1]
            continue
        break
    return words


def _replace_branch_to_fail(words: list[int]) -> list[int]:
    words = _strip_trailing_bne_zero_gp_pass(words)
    if len(words) < 1:
        return words

    br = words[-1]
    if not _is_branch_b_type(br) or _imm_b(br) <= 0:
        return words

    rs1, rs2 = _rs1(br), _rs2(br)
    xor_inst = _encode_rtype(0x0, rs2, rs1, 0x4, ORACLE_RESULT_REG)
    return words[:-1] + [xor_inst]


def _parse_inst_words(lines: Iterable[str]) -> list[int]:
    inst_re = re.compile(r"^\s*[0-9a-fA-F]+:\s*([0-9a-fA-F]{8})\b")
    words: list[int] = []
    for line in lines:
        m_inst = inst_re.match(line)
        if not m_inst:
            continue
        words.append(int(m_inst.group(1), 16))
    return words


def parse_riscv_tests(
    lines: Path,
    *,
    source: str = None,
    verbose: bool = False,
) -> list[dict]:
    """
    Parse a riscv64-unknown-elf-objdump .dump file and extract instruction
    streams from labels starting with `test`. Output is pure u32 word arrays.
    """

    label_re = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")

    seeds: list[dict] = []
    current_label: str | None = None
    current_label_addr: int | None = None
    current_lines: list[str] = []

    def flush():
        nonlocal current_label, current_label_addr, current_lines
        if (
            current_label is None
            or not current_label.startswith("test")
            or not current_lines
        ):
            current_label = None
            current_label_addr = None
            current_lines = []
            return

        words = _parse_inst_words(current_lines)
        if not words:
            current_label = None
            current_label_addr = None
            current_lines = []
            return

        inst_words = _replace_branch_to_fail(words)
        inst_words = [_rewrite_word_regs(w) for w in inst_words]

        seed = {
            "instructions": inst_words,
            "metadata": {
                "source": source,
                "label": current_label,
                "label_addr": current_label_addr,
            },
        }
        if verbose:
            preview = " | ".join(str(w) for w in seed["instructions"][:8])
            if len(seed["instructions"]) > 8:
                preview += " | ..."
            print(
                f"[parse_riscv_tests] matched {seed['metadata']['label']} "
                f"@0x{seed['metadata']['label_addr']:x}: "
                f"{len(seed['instructions'])} insts [{preview}]"
            )
        seeds.append(seed)
        current_label = None
        current_label_addr = None
        current_lines = []

    for line in lines:
        m_label = label_re.match(line)
        if m_label:
            flush()
            current_label_addr = int(m_label.group(1), 16)
            current_label = m_label.group(2)
            current_lines = []
            continue

        if current_label is None or not current_label.startswith("test"):
            continue

        current_lines.append(line)

    flush()
    return seeds


def _main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract initial seeds from RISC-V test dump files"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to a single .dump file or a directory containing .dump files",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Path to the output JSONL file",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_file = Path(args.output)

    if input_path.is_file():
        dump_files = [input_path]
        root = input_path.parent
    elif input_path.is_dir():
        dump_files = sorted(input_path.glob("*.dump"))
        root = input_path
    else:
        raise SystemExit(
            f"Input path does not exist or is not a file/dir: {input_path}"
        )

    all_seeds: list[dict] = []
    for dump_file in dump_files:
        text = dump_file.read_text(encoding="utf-8", errors="replace").splitlines()
        seeds = parse_riscv_tests(
            text,
            source=root.joinpath(dump_file.relative_to(root)).as_posix(),
            verbose=args.verbose,
        )
        if args.verbose:
            print(
                f"[parse_riscv_tests] {dump_file}: total matched seeds = {len(seeds)}\n"
            )
        all_seeds.extend(seeds)

    with output_file.open("w", encoding="utf-8") as f:
        for seed in all_seeds:
            f.write(json.dumps(seed) + "\n")

    print(f"Wrote {len(all_seeds)} seeds to {output_file}")


if __name__ == "__main__":
    _main()
