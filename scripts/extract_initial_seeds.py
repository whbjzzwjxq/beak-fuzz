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


def _imm_i(word: int) -> int:
    return _sign_extend(word >> 20, 12)


def _imm_u(word: int) -> int:
    return word & 0xFFFFF000


def _is_addi(word: int) -> bool:
    return _opcode(word) == 0x13 and _funct3(word) == 0x0


def _is_lui(word: int) -> bool:
    return _opcode(word) == 0x37


def _is_branch(word: int) -> bool:
    return _opcode(word) == 0x63


def _is_bne(word: int) -> bool:
    return _opcode(word) == 0x63 and _funct3(word) == 0x1


def _is_branch_b_type(word: int) -> bool:
    """True if word is a B-type branch (opcode 0x63)."""
    return _opcode(word) == 0x63


def _imm_b(word: int) -> int:
    """Decode B-type immediate (branch offset in bytes). Positive = forward (e.g. to fail)."""
    imm12 = (word >> 31) & 1
    imm11 = (word >> 7) & 1
    imm10_5 = (word >> 25) & 0x3F
    imm4_1 = (word >> 8) & 0xF
    imm = (imm12 << 11) | (imm11 << 10) | (imm10_5 << 4) | (imm4_1 << 1)
    return _sign_extend(imm, 12) * 2


def _encode_rtype(
    funct7: int, rs2: int, rs1: int, funct3: int, rd: int, opcode: int = 0x33
) -> int:
    """Encode R-type instruction (opcode 0x33). All args in range 0..31."""
    return (
        ((funct7 & 0x7F) << 25)
        | ((rs2 & 0x1F) << 20)
        | ((rs1 & 0x1F) << 15)
        | ((funct3 & 0x7) << 12)
        | ((rd & 0x1F) << 7)
        | (opcode & 0x7F)
    )


# Register used to output comparison result for fuzzing oracle (0 = pass, 1 = fail).
ORACLE_RESULT_REG = 10  # a0

# gp = x3, used in structural "bne zero, gp, pass" at end of many test blocks.
GP_REG = 3

# Map zkvm-unsupported / reserved regs to temporaries for fuzzing:
# sp(2), gp(3), tp(4), x8/fp(8), x9/s1(9) -> t0(5), t1(6), t2(7), t3(28), t4(29)
REG_REMAP = {2: 5, 3: 6, 4: 7, 8: 28, 9: 29}


def _remap_reg(r: int) -> int:
    return REG_REMAP.get(r, r)


def _rewrite_word_regs(word: int) -> int:
    """
    Rewrite rd/rs1/rs2 in instruction word: sp,gp,tp,x8,x9 -> t0,t1,t2,t3,t4.
    So zkvm tests avoid using stack pointer, frame pointer, base pointer, gp, tp.
    """
    opcode = _opcode(word)
    # R-type: 0x33 (OP), 0x3b (OP-64)
    if opcode in (0x33, 0x3B):
        rd, rs1, rs2 = _rd(word), _rs1(word), _rs2(word)
        rd, rs1, rs2 = _remap_reg(rd), _remap_reg(rs1), _remap_reg(rs2)
        return (word & 0xFE00007F) | (rd << 7) | (rs1 << 15) | (rs2 << 20)
    # I-type: 0x13 (opimm), 0x03 (load), 0x67 (jalr), 0x73 (csr/csrr/csrw etc)
    if opcode in (0x13, 0x03, 0x67, 0x73):
        rd, rs1 = _rd(word), _rs1(word)
        rd, rs1 = _remap_reg(rd), _remap_reg(rs1)
        return (word & 0xFFFFE07F) | (rd << 7) | (rs1 << 15)
    # S-type: 0x23 (store)
    if opcode == 0x23:
        rs1, rs2 = _rs1(word), _rs2(word)
        rs1, rs2 = _remap_reg(rs1), _remap_reg(rs2)
        return (word & 0x01FFF07F) | (rs1 << 15) | (rs2 << 20)
    # B-type: 0x63 (branch)
    if opcode == 0x63:
        rs1, rs2 = _rs1(word), _rs2(word)
        rs1, rs2 = _remap_reg(rs1), _remap_reg(rs2)
        return (word & 0x01FFF07F) | (rs1 << 15) | (rs2 << 20)
    # U-type: 0x37 (lui), 0x17 (auipc)
    if opcode in (0x37, 0x17):
        rd = _remap_reg(_rd(word))
        return (word & 0xFFFFF07F) | (rd << 7)
    # J-type: 0x6f (jal)
    if opcode == 0x6F:
        rd = _remap_reg(_rd(word))
        return (word & 0xFFFFF07F) | (rd << 7)
    return word


def _regs_used_in_word(word: int) -> set[int]:
    """Return set of register indices (rd, rs1, rs2) used in one instruction word."""
    opcode = _opcode(word)
    regs: set[int] = set()
    if opcode in (0x33, 0x3B):
        regs.add(_rd(word))
        regs.add(_rs1(word))
        regs.add(_rs2(word))
    elif opcode in (0x13, 0x03, 0x67, 0x73):
        regs.add(_rd(word))
        regs.add(_rs1(word))
    elif opcode == 0x23 or opcode == 0x63:
        regs.add(_rs1(word))
        regs.add(_rs2(word))
    elif opcode in (0x37, 0x17, 0x6F):
        regs.add(_rd(word))
    return regs


def _used_regs_from_words(words: list[int]) -> list[int]:
    """Collect all registers read or written in the instruction stream; return sorted list."""
    seen: set[int] = set()
    for w in words:
        seen.update(_regs_used_in_word(w))
    return sorted(seen)


def _strip_trailing_bne_zero_gp_pass(words: list[int]) -> list[int]:
    """
    Many blocks end with result-check BNE then structural "bne zero, gp, pass".
    Strip trailing BNE that is (rs1, rs2) in {(0, gp), (gp, 0)} and forward,
    so the result-check BNE becomes the last instruction and can be replaced.
    """
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
    """
    Eliminate the last branch (to <fail>): oracle gets only the test block, no
    fail label. Strip trailing "bne zero, gp, pass", then replace the last
    forward B-type branch with xor a0, rs1, rs2 (rs1/rs2 from that branch).
    a0 = 0 means equal (pass), a0 != 0 means not equal (fail).
    """
    words = _strip_trailing_bne_zero_gp_pass(words)
    if len(words) < 1:
        return words

    br = words[-1]
    if not _is_branch_b_type(br) or _imm_b(br) <= 0:
        return words  # not a branch, or backward (loop), leave unchanged

    rs1, rs2 = _rs1(br), _rs2(br)
    xor_inst = _encode_rtype(0x0, rs2, rs1, 0x4, ORACLE_RESULT_REG)  # xor a0, rs1, rs2
    return words[:-1] + [xor_inst]


def _parse_inst_words(lines: Iterable[str]) -> list[int]:
    # Example instruction line: 80000198:    00c58733           add a4,a1,a2
    inst_re = re.compile(r"^\s*[0-9a-fA-F]+:\s*([0-9a-fA-F]{8})\b")
    words: list[int] = []
    for line in lines:
        m_inst = inst_re.match(line)
        if not m_inst:
            continue
        words.append(int(m_inst.group(1), 16))
    return words


def _infer_initial_regs(
    words: list[int],
) -> tuple[dict[int, int], list[int]]:
    """
    Infer initial register values from a simple prologue at the start of a test block.

    Supported patterns (at the beginning of the block):
    - addi rd, x0, imm           (i.e., objdump might show this as `li rd, imm`)
    - lui rd, imm20              (upper 20 bits)
    - lui rd, imm20; addi rd, rd, imm12  (common `li rd, imm32` expansion)
    """
    regs: dict[int, int] = {}
    i = 0
    while i < len(words):
        word = words[i]
        if _is_addi(word) and _rs1(word) == 0:
            regs[_rd(word)] = _imm_i(word)
            i += 1
            continue

        if _is_lui(word):
            val = _imm_u(word)
            consumed = 1
            if i + 1 < len(words):
                nxt = words[i + 1]
                if _is_addi(nxt) and _rd(nxt) == _rd(word) and _rs1(nxt) == _rd(word):
                    val = (val + _imm_i(nxt)) & 0xFFFFFFFF
                    consumed = 2
            regs[_rd(word)] = _sign_extend(val, 32)
            i += consumed
            continue

        break

    if len(regs) > 1:
        return regs, words[i:]
    return regs, words


def parse_riscv_tests(
    lines: Path,
    *,
    source: str = None,
    verbose: bool = False,
    infer_initial_regs: bool = True,
) -> list[dict]:
    """
    Parse a standard `riscv64-unknown-elf-objdump -d` style `.dump` file and
    extract ONLY the instruction streams inside labels that start with `test`
    (e.g. `test_2`, `test_3`, ...). Returns one JSON-serializable dict per test block.

    The riscv-tests result-check tail (expected-construction + bne to fail) is
    replaced by xor a0,rs1,rs2 so the comparison result is in a0 (0=pass, non-zero=fail)
    for oracle vs zkvm comparison during fuzzing.

    The last branch (to <fail>) is replaced by xor a0, rs1, rs2 (rs1/rs2 from that
    branch) so the oracle needs no fail label. Trailing "bne zero, gp, pass" is
    stripped first. Only forward branches are replaced; backward (loop) branches
    are left unchanged.
    """

    # Example label line:
    #   8000018c <test_2>:
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

        inferred_regs: dict[int, int] = {}
        inst_words = words
        if infer_initial_regs:
            inferred_regs, inst_words = _infer_initial_regs(inst_words)
        inst_words = _replace_branch_to_fail(inst_words)

        # 1. Remove x0 from initial_regs (zkvm: no need for "0": 0).
        # 2. Remap sp(2), gp(3), tp(4), x8(8), x9(9) -> t0(5), t1(6), t2(7), t3(28), t4(29).
        initial_regs_remapped: dict[str, int] = {}
        for k, v in inferred_regs.items():
            if k == 0:
                continue
            key_remapped = _remap_reg(k)
            initial_regs_remapped[str(key_remapped)] = v & 0xFFFFFFFF

        # Rewrite instruction words so rd/rs1/rs2 use remapped registers.
        inst_words = [_rewrite_word_regs(w) for w in inst_words]

        used_regs = _used_regs_from_words(inst_words)

        seed = {
            "instructions": inst_words,
            "initial_regs": initial_regs_remapped,
            "used_regs": used_regs,
            "metadata": {
                "source": source,
                "label": current_label,
                "label_addr": current_label_addr,
            },
        }
        if verbose:
            preview = " | ".join(seed["instructions"][:8])
            if len(seed["instructions"]) > 8:
                preview += " | ..."
            print(
                f"[parse_riscv_tests] matched {seed['metadata']['label']} "
                f"@0x{seed['metadata']['label_addr']:x}: {len(seed['instructions'])} insts "
                f"(init_regs={len(seed['initial_regs'])}) "
                f"[{preview}]"
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
            continue

        if current_label is None or not current_label.startswith("test"):
            continue

        current_lines.append(line)

    flush()
    return seeds


def _main() -> None:
    """
    Manual verification:
    - Search "<test_\\d+>:" occurrences in the input dump files, and then compare the count with the number of seeds in the output JSONL file. Currently, there are 2172 seeds in the output JSONL file.
    - Check the generated seeds in the output JSONL file:
      - {
        "instructions": [35698483, 1180179, 2097811, 4266792675, 37815, 4026762131, 7816499],
        "initial_regs": {"3": 14, "4": 0, "1": 13631488, "2": 11534336},
        "metadata": {"source": "storage/riscv-tests-artifacts/rv32um-v-mulhu.dump", "label": "test_14", "label_addr": 2147494960}
        }
      - 80002c30 <test_14>:
        80002c30:	00e00193          	li	gp,14
        80002c34:	00000213          	li	tp,0
        80002c38:	00d000b7          	lui	ra,0xd00
        80002c3c:	00b00137          	lui	sp,0xb00
        80002c40:	0220b733          	mulhu	a4,ra,sp
        80002c44:	00120213          	addi	tp,tp,1 # 1 <_start-0x7fffffff>
        80002c48:	00200293          	li	t0,2
        80002c4c:	fe5216e3          	bne	tp,t0,80002c38 <test_14+0x8>
        80002c50:	000093b7          	lui	t2,0x9
        80002c54:	f0038393          	addi	t2,t2,-256 # 8f00 <_start-0x7fff7100>
        80002c58:	26771e63          	bne	a4,t2,80002ed4 <fail>
      - The "initial_regs" field should be the same as the register values in the dump file:
        - gp == 14
        - tp == 0
        - ra == 0xd00 << 12 = 13631488
        - sp == 0xb00 << 12 = 11534336
      - The "instructions" field should be the same as the instruction stream in the dump file:
        - 0220b733 == 35698483
        - 00120213 == 1180179
        - 00200293 == 2097811
        - fe5216e3 == 4266792675
        - 000093b7 == 37815
        - f0038393 == 4026762131
      - The last instruction should be xor a0,a4,t2 (a0 = 0 iff equal, non-zero iff not equal).
        - xor a0,a4,t2 == 7816499
    """
    parser = argparse.ArgumentParser(
        description="Extract initial seeds from RISC-V test dump files"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to a single .dump file or a directory containing RISC-V test dump files",
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


if __name__ == "__main__":
    _main()
