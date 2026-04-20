# BEAK Constraint Obligations — Complete Definition

> **54 obligations** across 10 groups, each defined as a triple (κ, μ, V):
>
> - **κ (trigger_condition)**: A state in the execution trace where constraints are most likely to be incorrect
> - **μ (mathematical_invariant)**: The mathematical fact that the constraint system must guarantee in that state
> - **V (value_partition)**: Partitioning the operand space into finite equivalence classes along ISA semantic boundaries

**Derivation methodology**: Three layers of first principles — ISA Spec (RV32IM), F_p Embedding (Z_{2^32} → F_p), and STARK Structure (2^n padding). The criterion for each obligation: "this property is free in hardware but must be explicitly enforced in an F_p constraint system," and holds for any RISC-V + AIR backend.

**Coverage dimensions**: 54 obligations × ~5 partition cells each ≈ **269 (obligation, cell) pairs**, forming the Phase 2 coverage bitmap.

---

## Group 1: Register File (3)

### RF1 `reg.x0_immutable`

- **κ**: `rd = x0 ∧ instr writes rd`
- **μ**: `reg[0]_after = 0`
- **V** (partitioned by the constraint path of the write source):

| Cell | Description |
|---|---|
| `rf1.alu_r` | R-type ALU writes x0 (ADD/SUB/SLL/SLT/SLTU/XOR/SRL/SRA/OR/AND) |
| `rf1.alu_i` | I-type ALU writes x0 (ADDI/SLTI/SLTIU/XORI/ORI/ANDI/SLLI/SRLI/SRAI) |
| `rf1.lui` | LUI x0, imm |
| `rf1.auipc` | AUIPC x0, imm |
| `rf1.load` | LW/LH/LB/LHU/LBU x0, offset(rs1) |
| `rf1.jal` | JAL x0, offset |
| `rf1.jalr` | JALR x0, rs1, imm |
| `rf1.mul` | MUL/MULH/MULHSU/MULHU x0, rs1, rs2 |
| `rf1.div` | DIV/DIVU/REM/REMU x0, rs1, rs2 |

**Gadget**: `{wr_instr} x0, {ops}; reveal x0;`

**Rationale**: Each instruction class uses a different chip's write path; x0 immutability must be independently constrained on every path.

---

### RF2 `reg.operand_fetch`

- **κ**: `instr reads rs1 or rs2`
- **μ**: `constraint_rs1_val = regfile[rs1_index] ∧ constraint_rs2_val = regfile[rs2_index]`
- **V** (partitioned by register aliasing relationship):

| Cell | Description |
|---|---|
| `rf2.no_alias` | rs1 ≠ rs2 ≠ rd, three distinct registers |
| `rf2.rs1_eq_rs2` | rs1 = rs2 (same-source operands, e.g., `sub x1, x2, x2`) |
| `rf2.rs1_eq_rd` | rs1 = rd (read-write same register) |
| `rf2.rs2_eq_rd` | rs2 = rd |
| `rf2.all_same` | rs1 = rs2 = rd |
| `rf2.rs1_x0` | rs1 = x0 (reading hardwired zero) |
| `rf2.rs2_x0` | rs2 = x0 |

**Gadget**: `{instr} {rd}, {rs1}, {rs2}; reveal {rd};` where rs1,rs2 drawn from {x0, rd, distinct}`

**Rationale**: Aliasing changes the constraint system's operand routing path; x0 is a special source (hardwired zero).

---

### RF3 `reg.writeback_bind`

- **κ**: `instr writes rd ∧ rd ≠ x0`
- **μ**: `regfile[rd]_after = computed_result`
- **V** (partitioned by the chip that produces the result):

| Cell | Description |
|---|---|
| `rf3.alu` | ALU computation result |
| `rf3.load` | Memory load result |
| `rf3.link` | JAL/JALR return address (PC+4) |
| `rf3.upper` | LUI/AUIPC upper-immediate result |
| `rf3.muldiv` | MUL/DIV result |

**Gadget**: `{instr} {rd}, {src_ops}; reveal {rd};`

**Rationale**: Results from different sources are computed in different chips; writeback binding is independently implemented on each path.

---

## Group 2: Instruction Decode (5)

### ID1 `decode.field_range`

- **κ**: `Any instruction`
- **μ**: `rd ∈ [0,31] ∧ rs1 ∈ [0,31] ∧ rs2 ∈ [0,31] ∧ funct3 ∈ [0,7] ∧ funct7 ∈ [0,127]`
- **V** (partitioned by field value boundaries):

| Cell | Description |
|---|---|
| `id1.reg_zero` | Field value = 0 |
| `id1.reg_max` | Field value = 31 (5-bit upper bound) |
| `id1.reg_mid` | Field value ∈ (0, 31) |
| `id1.funct_max` | funct3 = 7 or funct7 = 127 (upper bound) |

**Gadget**: `{instr} x{0|31}, x{0|31}, x{0|31}; reveal x1;`

---

### ID2 `decode.imm_signext`

- **κ**: `I/S/B-type instruction`
- **μ**: `imm_32 = sign_extend(imm_raw, width)`, i.e., `imm_raw[MSB] = 1 → imm_32[31:width] are all 1`
- **V** (partitioned by immediate sign and format width):

| Cell | Description |
|---|---|
| `id2.i_pos` | I-type, imm ≥ 0 (imm[11]=0) |
| `id2.i_neg` | I-type, imm < 0 (imm[11]=1) |
| `id2.s_pos` | S-type, imm ≥ 0 |
| `id2.s_neg` | S-type, imm < 0 |
| `id2.b_pos` | B-type, offset ≥ 0 |
| `id2.b_neg` | B-type, offset < 0 |
| `id2.j_pos` | J-type (JAL), offset ≥ 0 |
| `id2.j_neg` | J-type (JAL), offset < 0 |

**Gadget**: `{I|S|B|J-instr} {regs}, {±imm}; reveal {rd};`

**Rationale**: Sign extension is not free in F_p; positive/negative immediates take different constraint paths (sign bit = 0 vs 1).

---

### ID3 `decode.upper_imm`

- **κ**: `instr ∈ {LUI, AUIPC}`
- **μ**: LUI: `rd = imm << 12`; AUIPC: `rd = PC + (imm << 12)`
- **V**:

| Cell | Description |
|---|---|
| `id3.lui_zero` | LUI x, 0 (result = 0) |
| `id3.lui_max` | LUI x, 0xFFFFF (result = 0xFFFFF000, all upper 20 bits set) |
| `id3.lui_mid` | LUI x, imm ∈ (0, 0xFFFFF) |
| `id3.auipc_no_wrap` | AUIPC, PC + imm<<12 < 2^32 |
| `id3.auipc_wrap` | AUIPC, PC + imm<<12 ≥ 2^32 (32-bit wrap) |

**Gadget**: `lui {rd}, {imm}; reveal {rd};` or `auipc {rd}, {imm}; reveal {rd};`

---

### ID4 `decode.opcode_unique`

- **κ**: `Any instruction`
- **μ**: `Σ selector_i = 1 ∧ ∀i: selector_i ∈ {0,1} ∧ active selector matches decoded opcode`
- **V** (partitioned by instruction class):

| Cell | Description |
|---|---|
| `id4.alu_r` | R-type ALU |
| `id4.alu_i` | I-type ALU |
| `id4.load` | Load |
| `id4.store` | Store |
| `id4.branch` | Branch |
| `id4.jal` | JAL |
| `id4.jalr` | JALR |
| `id4.lui` | LUI |
| `id4.auipc` | AUIPC |
| `id4.ecall` | ECALL |
| `id4.mul` | MUL/MULH/MULHSU/MULHU |
| `id4.div` | DIV/DIVU/REM/REMU |

**Gadget**: `{any_opcode} {rd}, {ops}; reveal {rd};`

---

### ID5 `decode.format_imm`

- **κ**: `S/B/J-type instruction` (immediate assembled from scattered bit fields)
- **μ**: S: `imm = instr[31:25]||instr[11:7]`; B: `imm = instr[31]||instr[7]||instr[30:25]||instr[11:8]||0`; J: `imm = instr[31]||instr[19:12]||instr[20]||instr[30:21]||0`
- **V**:

| Cell | Description |
|---|---|
| `id5.s_type` | S-type (SW/SH/SB) |
| `id5.b_type` | B-type (BEQ/BNE/BLT/BGE/BLTU/BGEU) |
| `id5.j_type` | J-type (JAL) |
| `id5.cross_field` | Immediate value causes scattered bits to cross byte boundaries |

**Gadget**: `{S|B|J-instr} {regs}, {imm_cross_field};`

**Rationale**: S/B/J immediates are scatter/gathered from the instruction word; the reassembly logic is error-prone.
## Group 3: ALU (5)

### AL1 `alu.imm_decomp`

- **κ**: `I-type ALU instruction`
- **μ**: `imm = Σ limb_i · 256^i ∧ ∀i: limb_i ∈ [0, 255]`
- **V** (partitioned by where the imm value crosses limb boundaries):

| Cell | Description |
|---|---|
| `al1.single_limb` | imm ∈ [0, 255] (fits in a single limb) |
| `al1.cross_01` | imm ∈ [256, 2047] (crosses the 0th–1st limb boundary) |
| `al1.negative` | imm is negative (sign-extended upper bits are all 1, crossing all limbs) |
| `al1.boundary` | imm ∈ {255, 256, -1, -2048, 2047} (exact limb boundary values) |

**Gadget**: `{I-alu} {rd}, {rs1}, {±imm}; reveal {rd};`

---

### AL2 `alu.shift_mod32`

- **κ**: `instr ∈ {SLL, SRL, SRA}`
- **μ**: `effective_shamt = rs2_val[4:0]`; SLL: `rd = rs1 << shamt`; SRL: `rd = rs1 >> shamt (logical)`; SRA: `rd = rs1 >> shamt (arithmetic)`
- **V**:

| Cell | Description |
|---|---|
| `al2.sll_lt32` | SLL, shamt ∈ [0, 31] |
| `al2.sll_ge32` | SLL, rs2 ≥ 32 (shamt is masked) |
| `al2.srl_lt32` | SRL, shamt ∈ [0, 31] |
| `al2.srl_ge32` | SRL, rs2 ≥ 32 |
| `al2.sra_lt32_pos` | SRA, shamt < 32, rs1 ≥ 0 |
| `al2.sra_lt32_neg` | SRA, shamt < 32, rs1 < 0 (sign bit propagation) |
| `al2.sra_ge32_pos` | SRA, rs2 ≥ 32, rs1 ≥ 0 (result = 0) |
| `al2.sra_ge32_neg` | SRA, rs2 ≥ 32, rs1 < 0 (result = -1) |
| `al2.shamt_zero` | Any shift, shamt = 0 (identity operation) |

**Gadget**: `{sll|srl|sra} {rd}, {rs1}, {rs2}; reveal {rd};` where rs2 ∈ {0..63}

**Rationale**: SRA sign propagation is not free in F_p; the shamt ≥ 32 masking behavior is required by the ISA but easily overlooked.

---

### AL3 `alu.cmp_boolean`

- **κ**: `instr ∈ {SLT, SLTU, SLTI, SLTIU}`
- **μ**: `rd ∈ {0, 1}`
- **V**:

| Cell | Description |
|---|---|
| `al3.slt_true` | SLT/SLTI, rs1 (signed) < rs2/imm (signed) → rd = 1 |
| `al3.slt_false` | SLT/SLTI, rs1 ≥ rs2/imm → rd = 0 |
| `al3.sltu_true` | SLTU/SLTIU, rs1 (unsigned) < rs2/imm → rd = 1 |
| `al3.sltu_false` | SLTU/SLTIU, rs1 ≥ rs2/imm → rd = 0 |
| `al3.equal` | rs1 = rs2/imm (boundary: exactly not less than) |
| `al3.sign_disagree` | signed_cmp ≠ unsigned_cmp (rs1 negative, rs2 positive, or vice versa) |

**Gadget**: `{slt|sltu|slti|sltiu} {rd}, {rs1}, {rs2|imm}; reveal {rd};`

---

### AL4 `alu.sub_borrow`

- **κ**: `SUB or any operation that internally uses subtraction (SLT family, branches)`
- **μ**: `diff = rs1 - rs2 (mod 2^32)`; borrow/carry chain: `borrow_i ∈ {0,1} ∧ limb_diff_i + borrow_i · base = rs1_limb_i - rs2_limb_i + borrow_{i-1}`
- **V**:

| Cell | Description |
|---|---|
| `al4.no_borrow` | rs1 ≥ rs2 (unsigned), no borrow |
| `al4.borrow` | rs1 < rs2 (unsigned), borrow generated (wrap around 2^32) |
| `al4.equal` | rs1 = rs2, difference is 0 |
| `al4.cross_limb` | Difference crosses limb boundary (one limb_diff generates borrow but the adjacent one does not) |

**Gadget**: `sub {rd}, {rs1}, {rs2}; reveal {rd};`

---

### AL5 `alu.comparison_aux`

- **κ**: `Any comparison using an IsLessThan / IsLtArray sub-circuit`
- **μ**: All auxiliary variables in the comparison sub-circuit satisfy the constraint chain: `∀i: diff_limb_i = a_limb_i - b_limb_i + borrow_i · base ∧ borrow_i ∈ {0,1}`; per-limb comparison cannot skip partial evaluation
- **V**:

| Cell | Description |
|---|---|
| `al5.first_limb_diff` | Most-significant limb already differs (comparison decided in the first round) |
| `al5.last_limb_diff` | Only the least-significant limb differs (comparison chain runs to the end) |
| `al5.all_equal` | All limbs are equal |
| `al5.alternating_borrow` | Borrows alternate between generated and absorbed (stress-tests the borrow chain) |

**Gadget**: `li {r1}, {v1}; li {r2}, {v2}; {slt|blt|...} {rd}, {r1}, {r2}; reveal {rd};`

---

## Group 4: Mul/Div (5)

### MD1 `muldiv.div_by_zero`

- **κ**: `instr ∈ {DIV, DIVU, REM, REMU} ∧ divisor = 0`
- **μ**: DIV: `q = -1 (0xFFFFFFFF)`; DIVU: `q = 0xFFFFFFFF`; REM: `r = dividend`; REMU: `r = dividend`
- **V**:

| Cell | Description |
|---|---|
| `md1.div_zero` | DIV x, y, 0 |
| `md1.divu_zero` | DIVU x, y, 0 |
| `md1.rem_zero` | REM x, y, 0 |
| `md1.remu_zero` | REMU x, y, 0 |
| `md1.dividend_pos` | dividend > 0 |
| `md1.dividend_neg` | dividend < 0 (signed) |
| `md1.dividend_zero` | dividend = 0 |

**Gadget**: `li {rs2}, 0; {div|divu|rem|remu} {rd}, {rs1}, {rs2}; reveal {rd};`

---

### MD2 `muldiv.signed_overflow`

- **κ**: `DIV/REM ∧ dividend = -2^31 (0x80000000) ∧ divisor = -1 (0xFFFFFFFF)`
- **μ**: DIV: `q = -2^31`; REM: `r = 0`
- **V**:

| Cell | Description |
|---|---|
| `md2.div_overflow` | DIV x, -2^31, -1 |
| `md2.rem_overflow` | REM x, -2^31, -1 |

**Gadget**: `lui {rs1}, 0x80000; li {rs2}, -1; {div|rem} {rd}, {rs1}, {rs2}; reveal {rd};`

---

### MD3 `muldiv.remainder_rel`

- **κ**: `instr ∈ {DIV, DIVU, REM, REMU} ∧ divisor ≠ 0`
- **μ**: `q · d + r = n ∧ |r| < |d|` (signed) or `q · d + r = n ∧ r < d` (unsigned); remainder sign matches dividend sign (signed)
- **V** (partitioned by dividend/divisor sign combination):

| Cell | Description |
|---|---|
| `md3.pp` | dividend > 0, divisor > 0 |
| `md3.pn` | dividend > 0, divisor < 0 |
| `md3.np` | dividend < 0, divisor > 0 |
| `md3.nn` | dividend < 0, divisor < 0 |
| `md3.exact` | dividend mod divisor = 0 (exact division) |
| `md3.large_q` | quotient near 2^31 (large quotient) |
| `md3.one` | divisor = 1 or -1 (quotient = ±dividend) |
| `md3.unsigned` | DIVU/REMU (unsigned division) |

**Gadget**: `li {rs1}, {n}; li {rs2}, {d}; {div|rem} {rd}, {rs1}, {rs2}; reveal {rd};`

---

### MD4 `muldiv.product_decomp`

- **κ**: `instr ∈ {MUL, MULH, MULHSU, MULHU}`
- **μ**: `product_hi : product_lo = rs1 × rs2` (64-bit); `Σ prod_limb_i · 2^(8i) = product`, each limb ∈ [0, 255]
- **V**:

| Cell | Description |
|---|---|
| `md4.mul_small` | MUL, both operands small (product < 2^32, no high bits) |
| `md4.mul_overflow` | MUL, product ≥ 2^32 (lower 32 bits wrap) |
| `md4.mulh_pp` | MULH, both positive |
| `md4.mulh_pn` | MULH, one positive one negative |
| `md4.mulh_nn` | MULH, both negative |
| `md4.mulhu` | MULHU, unsigned |
| `md4.zero_op` | Any MUL variant, one operand = 0 |
| `md4.max_product` | rs1 = rs2 = 0xFFFFFFFF or 0x7FFFFFFF (maximum product) |

**Gadget**: `li {rs1}, {a}; li {rs2}, {b}; {mul|mulh|mulhu} {rd}, {rs1}, {rs2}; reveal {rd};`

---

### MD5 `muldiv.signed_unsigned_mix`

- **κ**: `MULHSU`
- **μ**: `result = (signed(rs1) × unsigned(rs2))[63:32]`; correction term: `rs1 < 0 ? subtract rs2 from upper half : no correction`
- **V**:

| Cell | Description |
|---|---|
| `md5.pos_any` | rs1 ≥ 0 (no correction term) |
| `md5.neg_small` | rs1 < 0, rs2 small (correction term does not affect upper-word limb carry) |
| `md5.neg_large` | rs1 < 0, rs2 large (correction term crosses limb carry) |
| `md5.neg_max` | rs1 = -1, rs2 = 0xFFFFFFFF (maximum correction) |
| `md5.neg_one` | rs1 < 0, rs2 = 1 |

**Gadget**: `li {rs1}, {signed_a}; li {rs2}, {unsigned_b}; mulhsu {rd}, {rs1}, {rs2}; reveal {rd};`

## Group 5: Memory (11)

### ME1 `mem.read_after_write`

- **κ**: `SW/SH/SB followed by LW/LH/LB/LHU/LBU to the same address`
- **μ**: `load_result = stored_value` (accounting for width and extension)
- **V**:

| Cell | Description |
|---|---|
| `me1.sw_lw` | Word store → word load (exact match) |
| `me1.sb_lb` | Byte store → byte load (same offset) |
| `me1.sh_lh` | Half store → half load |
| `me1.sb_lw` | Byte store → word load (partial read) |
| `me1.sw_lb` | Word store → byte load (partial read) |
| `me1.sw_lhu` | Word store → unsigned half load |
| `me1.overwrite` | Multiple stores to the same address followed by load (takes last write) |

**Gadget**: `{sw|sh|sb} {rs}, 0({addr}); {lw|lh|lb|lhu|lbu} {rd}, 0({addr}); reveal {rd};`

---

### ME2 `mem.alignment`

- **κ**: `LH/LHU/SH ∧ addr mod 2 ≠ 0, or LW/SW ∧ addr mod 4 ≠ 0`
- **μ**: Unaligned access handled correctly (reads correct bytes across word boundary, or traps)
- **V**:

| Cell | Description |
|---|---|
| `me2.half_off1` | LH/SH, addr mod 2 = 1 |
| `me2.word_off1` | LW/SW, addr mod 4 = 1 |
| `me2.word_off2` | LW/SW, addr mod 4 = 2 |
| `me2.word_off3` | LW/SW, addr mod 4 = 3 |
| `me2.byte_any` | LB/SB requires no alignment (baseline) |

**Gadget**: `li {addr}, {unaligned}; {lw|lh|sw|sh} {rd}, 0({addr}); reveal {rd};`

---

### ME3 `mem.sign_extension`

- **κ**: `instr ∈ {LB, LH}` (signed load)
- **μ**: LB: `rd = sign_extend_8(mem[addr])`; LH: `rd = sign_extend_16(mem[addr])`
- **V**:

| Cell | Description |
|---|---|
| `me3.lb_pos` | LB, loaded byte ∈ [0, 127] (sign bit = 0) |
| `me3.lb_neg` | LB, loaded byte ∈ [128, 255] (sign bit = 1, extended to negative) |
| `me3.lh_pos` | LH, loaded half ∈ [0, 32767] |
| `me3.lh_neg` | LH, loaded half ∈ [32768, 65535] |
| `me3.lbu` | LBU (zero extension, no sign) — baseline comparison |
| `me3.lhu` | LHU baseline |

**Gadget**: `{sb} {rs}, 0({addr}); {lb|lh} {rd}, 0({addr}); reveal {rd};`

---

### ME4 `mem.subword_mask`

- **κ**: `instr ∈ {SB, SH}`
- **μ**: SB: only the 1 byte at the addressed position is modified; the remaining 3 bytes in the word are preserved. SH: only 2 bytes modified.
- **V**:

| Cell | Description |
|---|---|
| `me4.sb_off0` | SB, byte offset = 0 |
| `me4.sb_off1` | SB, byte offset = 1 |
| `me4.sb_off2` | SB, byte offset = 2 |
| `me4.sb_off3` | SB, byte offset = 3 |
| `me4.sh_off0` | SH, half offset = 0 |
| `me4.sh_off2` | SH, half offset = 2 |

**Gadget**: `sw {fill}, 0({addr}); {sb|sh} {val}, {off}({addr}); lw {rd}, 0({addr}); reveal {rd};`

---

### ME5 `mem.addr_space`

- **κ**: `Any load/store`
- **μ**: Address space selector is correct: `is_register_space` vs `is_memory_space`; no cross-space reads/writes
- **V**:

| Cell | Description |
|---|---|
| `me5.reg_read` | Operand fetch from register space |
| `me5.reg_write` | Writeback to register space |
| `me5.mem_read` | Load from main memory space |
| `me5.mem_write` | Store to main memory space |

**Gadget**: `{lw|sw} {rd}, 0({addr}); reveal {rd};`

---

### ME6 `mem.addr_overflow`

- **κ**: `addr + width - 1 approaches or exceeds 2^32`
- **μ**: `addr + width - 1 < 2^32` (no address wrap-around)
- **V**:

| Cell | Description |
|---|---|
| `me6.near_max_lw` | LW, addr near 0xFFFFFFFC |
| `me6.near_max_sw` | SW, addr near 0xFFFFFFFC |
| `me6.near_max_lh` | LH/LHU, addr near 0xFFFFFFFE |
| `me6.near_max_sb` | SB, addr = 0xFFFFFFFF |
| `me6.heap_boundary` | addr near heap upper bound |

**Gadget**: `li {addr}, 0xFFFFFFFC; {lw|sw} {rd}, 0({addr}); reveal {rd};`

---

### ME7 `mem.init_value`

- **κ**: `First read to an address with no prior write in the trace`
- **μ**: `loaded_value = 0 (BSS) or ELF-loaded value (.data/.rodata)`
- **V**:

| Cell | Description |
|---|---|
| `me7.bss_zero` | Read from uninitialized region (expected 0) |
| `me7.data_loaded` | Read from .data segment with initialized value (expected ELF value) |
| `me7.rodata` | Read from .rodata segment (read-only data) |
| `me7.stack_uninit` | First read from stack region |

**Gadget**: `lw {rd}, {bss|data|rodata_addr}(x0); reveal {rd};`

---

### ME8 `mem.single_init`

- **κ**: `Same address initialized multiple times during the initialization phase`
- **μ**: `Each address is initialized at most once`
- **V**:

| Cell | Description |
|---|---|
| `me8.no_conflict` | Each address initialized exactly once (normal) |
| `me8.double_init` | Same address initialized twice (overlapping ELF segments) |

**Gadget**: `lw {rd}, {elf_overlap_addr}(x0); reveal {rd};`

---

### ME9 `mem.byte_offset`

- **κ**: `SB/SH/LB/LH/LBU/LHU (sub-word access)`
- **μ**: `byte_offset = addr mod 4`; the byte position extracted from / inserted into the word matches the offset
- **V**:

| Cell | Description |
|---|---|
| `me9.off0` | byte_offset = 0 |
| `me9.off1` | byte_offset = 1 |
| `me9.off2` | byte_offset = 2 |
| `me9.off3` | byte_offset = 3 |
| `me9.adjacent_diff_word` | Two sub-word accesses to adjacent addresses landing in different words |
| `me9.adjacent_same_word` | Two sub-word accesses to different addresses landing in the same word |

**Gadget**: `{sb|lb|sh|lh} {rd}, {off}({addr}); reveal {rd};`

---

### ME10 `mem.rw_direction`

- **κ**: `Any memory access`
- **μ**: `is_load ∈ {0,1} ∧ is_store ∈ {0,1} ∧ is_load + is_store = 1 ∧ is_load iff opcode is Load`
- **V**:

| Cell | Description |
|---|---|
| `me10.load` | LW/LH/LB/LHU/LBU → is_load = 1 |
| `me10.store` | SW/SH/SB → is_store = 1 |

**Gadget**: `{lw|sw} {rd}, 0({addr}); reveal {rd};`

---

### ME11 `mem.finalize`

- **κ**: `End of trace`
- **μ**: `Every memory cell's last-access record is consistent with the finalization table; no dangling writes`
- **V**:

| Cell | Description |
|---|---|
| `me11.written_cells` | Written cells correctly closed during finalization |
| `me11.read_only_cells` | Read-only cells (ELF loaded) correctly closed |
| `me11.untouched_cells` | Allocated but never accessed cells |

**Gadget**: `sw {rs}, 0({addr}); [end_trace]; /* verify finalization table */`

## Group 6: Control Flow (7)

### CF1 `ctrl.branch_signedness`

- **κ**: `instr ∈ {BEQ, BNE, BLT, BGE, BLTU, BGEU}`
- **μ**: BLT/BGE use signed comparison; BLTU/BGEU use unsigned comparison; BEQ/BNE use equality
- **V**:

| Cell | Description |
|---|---|
| `cf1.blt_taken` | BLT, signed(rs1) < signed(rs2), taken |
| `cf1.blt_not_taken` | BLT, signed(rs1) ≥ signed(rs2) |
| `cf1.bge_taken` | BGE, taken |
| `cf1.bge_not_taken` | BGE, not taken |
| `cf1.bltu_taken` | BLTU, unsigned(rs1) < unsigned(rs2) |
| `cf1.bltu_not_taken` | BLTU |
| `cf1.bgeu_taken` | BGEU |
| `cf1.bgeu_not_taken` | BGEU |
| `cf1.sign_flip` | rs1 negative, rs2 positive (signed < but unsigned >) |
| `cf1.beq_equal` | BEQ, rs1 = rs2 |
| `cf1.bne_not_equal` | BNE, rs1 ≠ rs2 |

**Gadget**: `li {r1}, {a}; li {r2}, {b}; {beq|bne|blt|bge|bltu|bgeu} {r1}, {r2}, {off}; reveal {rd};`

---

### CF2 `ctrl.link_register`

- **κ**: `instr ∈ {JAL, JALR}`
- **μ**: `rd = PC + 4`
- **V**:

| Cell | Description |
|---|---|
| `cf2.jal_rd` | JAL, rd ≠ x0 (saves return address) |
| `cf2.jal_x0` | JAL x0 (no save, pure jump) |
| `cf2.jalr_rd` | JALR, rd ≠ x0 |
| `cf2.jalr_x0` | JALR x0 |
| `cf2.pc_near_max` | PC + 4 near 2^32 (wrap boundary) |

**Gadget**: `{jal|jalr} {rd}, {target}; reveal {rd};`

---

### CF3 `ctrl.jalr_target`

- **κ**: `JALR`
- **μ**: `PC_next = (rs1 + sign_extend(imm)) & ~1` (clear lowest bit)
- **V**:

| Cell | Description |
|---|---|
| `cf3.imm_zero` | imm = 0 (target = rs1 & ~1) |
| `cf3.imm_pos` | imm > 0 |
| `cf3.imm_neg` | imm < 0 |
| `cf3.clear_lsb` | rs1 + imm is odd (bit 0 must be cleared) |
| `cf3.even` | rs1 + imm is even (bit 0 already 0) |
| `cf3.wrap` | rs1 + imm exceeds 32 bits (wrap around) |

**Gadget**: `li {rs1}, {base}; jalr {rd}, {rs1}, {imm}; reveal {rd};`

---

### CF4 `ctrl.entry_point`

- **κ**: `First step of the trace`
- **μ**: `PC_0 = ELF entry_point`
- **V**:

| Cell | Description |
|---|---|
| `cf4.default_entry` | entry_point = standard start address (e.g., 0x00200800) |
| `cf4.custom_entry` | entry_point ≠ default |

**Gadget**: `/* first instruction at entry_point */ {instr} {rd}, {ops}; reveal {rd};`

---

### CF5 `ctrl.ecall_arg`

- **κ**: `ECALL instruction`
- **μ**: `Syscall arguments are read from the correct registers (a0–a7 = x10–x17); argument values and addresses are within valid range`
- **V**:

| Cell | Description |
|---|---|
| `cf5.halt` | ECALL with a0 = halt syscall number |
| `cf5.io_read` | ECALL with a0 = input syscall |
| `cf5.io_write` | ECALL with a0 = output/commit syscall |
| `cf5.precompile` | ECALL routing to precompile (sha256, keccak, etc.) |
| `cf5.arg_zero` | Argument a1 = 0 |
| `cf5.arg_max` | Argument near address space upper bound |

**Gadget**: `li a0, {syscall_nr}; li a1, {arg}; ecall; reveal a0;`

---

### CF6 `ctrl.sequential_pc`

- **κ**: `Non-branch, non-jump, non-ecall instruction`
- **μ**: `PC_next = PC + 4`
- **V**:

| Cell | Description |
|---|---|
| `cf6.normal` | Normal sequential execution |
| `cf6.after_branch_not_taken` | Instruction immediately after a branch-not-taken |
| `cf6.near_segment_end` | PC near segment boundary |

**Gadget**: `{non_jump_instr} {rd}, {ops}; {non_jump_instr} {rd2}, {ops2}; reveal {rd2};`

---

### CF7 `ctrl.ecall_encoding`

- **κ**: `ECALL instruction`
- **μ**: `instruction_word_at_PC = 0x00000073`
- **V**:

| Cell | Description |
|---|---|
| `cf7.standard` | Standard ECALL encoding |

**Gadget**: `ecall;`

---

## Group 7: Range Check & Decomposition (4)

> Universal F_p embedding layer, not tied to any specific instruction.

### RC1 `range.limb_decomp`

- **κ**: `Any 32-bit value decomposed into multiple limbs (occurs in ALU, Memory, PC computation, etc.)`
- **μ**: `original = Σ limb_i · base^i ∧ ∀i: limb_i ∈ [0, base)`
- **V** (partitioned by the semantic role of the decomposed value):

| Cell | Description |
|---|---|
| `rc1.alu_result` | ALU computation result decomposed into limbs |
| `rc1.immediate` | Immediate value decomposition |
| `rc1.pc` | PC value decomposition |
| `rc1.memory_addr` | Memory address decomposition |
| `rc1.memory_value` | Memory load/store value decomposition |
| `rc1.mul_product` | Multiplication 64-bit product decomposition |

**Gadget**: `li {rs1}, {val}; {add|sub|lw|sw|auipc|mul} {rd}, {ops}; reveal {rd};`

---

### RC2 `range.boolean_flag`

- **κ**: `Any selector, flag, or is_real field`
- **μ**: `flag · (1 - flag) = 0`
- **V** (partitioned by the semantic role of the flag):

| Cell | Description |
|---|---|
| `rc2.opcode_sel` | Instruction opcode selector |
| `rc2.is_real` | Row validity flag |
| `rc2.is_read` | Memory read/write selector |
| `rc2.sign_bit` | Sign bit |
| `rc2.branch_taken` | Branch taken/not-taken flag |
| `rc2.carry_borrow` | Carry/borrow flag |

**Gadget**: `{instr_with_flag} {rd}, {ops}; reveal {rd};`

---

### RC3 `range.u32_bound`

- **κ**: `Any intermediate variable claimed to be 32-bit`
- **μ**: `value ∈ [0, 2^32)`
- **V**:

| Cell | Description |
|---|---|
| `rc3.near_zero` | value near 0 |
| `rc3.near_max` | value near 2^32 - 1 |
| `rc3.mid` | value in the middle range |
| `rc3.power_of_2` | value = 2^k (exact limb boundary value) |

**Gadget**: `li {rs1}, {near_0|near_max|mid|pow2}; add {rd}, {rs1}, x0; reveal {rd};`

---

### RC4 `range.sign_bit`

- **κ**: `Any operation using a sign bit (signed comparison, SRA, signed load, signed division)`
- **μ**: `sign_bit ∈ {0,1} ∧ signed_value = unsigned_value - sign_bit · 2^32`
- **V**:

| Cell | Description |
|---|---|
| `rc4.positive` | sign_bit = 0 (positive or zero) |
| `rc4.negative` | sign_bit = 1 (negative) |
| `rc4.boundary_pos` | value = 2^31 - 1 (maximum positive) |
| `rc4.boundary_neg` | value = 2^31 (minimum negative, i.e., -2^31) |

**Gadget**: `li {rs1}, {0x7FFFFFFF|0x80000000|pos|neg}; {slt|sra|lb} {rd}, {ops}; reveal {rd};`

## Group 8: Timestamp & Ordering (3)

### TS1 `time.init_zero`

- **κ**: `First timestamp assignment in the trace`
- **μ**: `initial_timestamp = 0`
- **V**:

| Cell | Description |
|---|---|
| `ts1.standard` | Standard trace start |
| `ts1.after_segment` | Start of a non-first segment (timestamp continues from the previous segment) |

**Gadget**: `{first_instr} {rd}, {ops}; reveal {rd};`

---

### TS2 `time.monotonic`

- **κ**: `Consecutive memory access pair to the same address`
- **μ**: `ts_diff = ts_new - ts_old ∈ [0, 2^k)`; the difference is range-checked and cannot wrap around p
- **V**:

| Cell | Description |
|---|---|
| `ts2.small_gap` | Two accesses separated by few cycles (small ts_diff) |
| `ts2.large_gap` | ts_diff near 2^k (large gap) |
| `ts2.consecutive` | ts_diff = 1 (consecutive-cycle access to the same address) |
| `ts2.cross_segment` | Timestamp increment across a segment boundary |

**Gadget**: `sw {rs}, 0({addr}); {N nops}; lw {rd}, 0({addr}); reveal {rd};`

---

### TS3 `time.clk_pc_init`

- **κ**: `First row of the CPU chip`
- **μ**: `clk = 0 (or 1) ∧ PC = entry_point`
- **V**:

| Cell | Description |
|---|---|
| `ts3.standard` | Standard initialization |
| `ts3.multi_core` | Initialization of each CPU chip instance when multiple exist |

**Gadget**: `{first_instr} {rd}, {ops}; reveal {rd};`

---

## Group 9: Bus & Interaction (6)

### BU1 `bus.multiplicity_bool`

- **κ**: `Multiplicity field of any bus interaction`
- **μ**: `multiplicity ∈ {0, 1}` (or non-negative, depending on protocol)
- **V**:

| Cell | Description |
|---|---|
| `bu1.real_row` | is_real = 1, multiplicity = 1 |
| `bu1.padding_row` | is_real = 0, multiplicity should be 0 |
| `bu1.multi_send` | One row sends multiple bus messages (multiplicity > 1, a legitimate case such as range-check tables) |

**Gadget**: `{instr} {rd}, {ops}; reveal {rd};` /* multiplicity checked via witness perturbation */

---

### BU2 `bus.digest_separation`

- **κ**: `Cross-chip interactions with different InteractionKind (e.g., memory bus vs ALU bus vs syscall bus)`
- **μ**: `Different kinds of interaction produce distinct digests; Hash(kind_1 || data) ≠ Hash(kind_2 || data')`
- **V**:

| Cell | Description |
|---|---|
| `bu2.mem_vs_alu` | Memory interaction vs ALU interaction coexisting |
| `bu2.mem_vs_syscall` | Memory vs syscall interaction |
| `bu2.alu_vs_range` | ALU vs range-check interaction |
| `bu2.same_data_diff_kind` | Two interactions with identical data but different kinds (collision test) |

**Gadget**: `{mem_instr} {rd}, 0({addr}); {alu_instr} {rd2}, {ops}; reveal {rd}; reveal {rd2};`

---

### BU3 `bus.cumsum_final`

- **κ**: `End of trace, LogUp/permutation argument final check`
- **μ**: `cumulative_sum = 0` (sends and receives are perfectly balanced)
- **V**:

| Cell | Description |
|---|---|
| `bu3.balanced` | Normal balanced trace |
| `bu3.many_interactions` | Many interactions (cumsum undergoes many additions/subtractions) |
| `bu3.few_interactions` | Very few interactions (short program) |

**Gadget**: `{short_or_long_program}; reveal {rd};`

---

### BU4 `bus.send_receive_balance`

- **κ**: `Bus interactions across all chips`
- **μ**: `∀ bus_id: Σ_{sender} mult_send = Σ_{receiver} mult_receive`
- **V**:

| Cell | Description |
|---|---|
| `bu4.single_chip_pair` | Only one pair of chips communicating |
| `bu4.multi_chip` | Multiple chips sharing the same bus |
| `bu4.asymmetric` | One sender corresponding to multiple receivers |

**Gadget**: `{multi_chip_instr_seq}; reveal {rd};`

---

### BU5 `bus.invalid_row_silent`

- **κ**: `Chip row with is_valid = 0 (logically invalid row, distinct from padding rows)`
- **μ**: `All bus multiplicities of an invalid row = 0; cannot send or receive messages with mult ≠ 0 (including -1)`
- **V**:

| Cell | Description |
|---|---|
| `bu5.alu_invalid` | ALU chip invalid row |
| `bu5.div_invalid` | DivRem chip invalid row |
| `bu5.mem_invalid` | Memory chip invalid row |
| `bu5.range_invalid` | Range-check chip invalid row |

**Gadget**: `{instr} {rd}, {ops}; reveal {rd};` /* invalid-row silence checked via witness perturbation */

---

### BU6 `bus.transcript_complete`

- **κ**: `Fiat-Shamir transcript construction`
- **μ**: `All commitments, cumulative_sum, AIR IDs, and permutation_commit are observed into the transcript`
- **V**:

| Cell | Description |
|---|---|
| `bu6.main_commit` | Main trace commitment observed |
| `bu6.perm_commit` | Permutation commitment + cumsum observed |
| `bu6.air_ids` | All AIR IDs observed |
| `bu6.cross_phase` | Commitments across challenge phases observed |

**Gadget**: `{any_program};` /* transcript completeness checked via witness perturbation */

---

## Group 10: Padding & Table Lifecycle (5)

### PD1 `pad.row_inert`

- **κ**: `is_real = 0 (padding row)`
- **μ**: `∀ selector: sel = 0 ∧ ∀ bus interaction: mult = 0 ∧ no state modification`
- **V**:

| Cell | Description |
|---|---|
| `pd1.exec_padding` | Execution trace padding row |
| `pd1.mem_padding` | Memory table padding row |
| `pd1.range_padding` | Range-check table padding row |
| `pd1.lookup_padding` | Lookup table padding row |

**Gadget**: `{1..3 instr}; halt;` /* minimal program to maximize padding rows */

---

### PD2 `pad.trace_2k`

- **κ**: `Total trace rows cross a 2^k boundary`
- **μ**: `After padding to the next power of 2, all real-row constraints remain correct`
- **V**:

| Cell | Description |
|---|---|
| `pd2.just_over` | trace = 2^k + 1 (just crossed, heavy padding) |
| `pd2.just_under` | trace = 2^k - 1 (about to cross) |
| `pd2.exact` | trace = 2^k (no padding) |
| `pd2.very_short` | trace < 8 (extremely short, almost entirely padding) |
| `pd2.cross_k8` | Crossing the k=8 (256 rows) boundary |
| `pd2.cross_k16` | Crossing the k=16 (65536 rows) boundary |

**Gadget**: `li {t0}, 0; li {t1}, {2^k±1}; loop: addi {t0}, {t0}, 1; blt {t0}, {t1}, loop; reveal {t0};`

---

### PD3 `pad.memory_2k`

- **κ**: `Memory table / range-check table / lookup accumulator table crosses a 2^k boundary`
- **μ**: `After table expansion, all existing entries are preserved; range table still contains all values in [0, 2^b - 1]`
- **V**:

| Cell | Description |
|---|---|
| `pd3.mem_table` | Memory address table crossing boundary |
| `pd3.range_table` | Range-check table crossing boundary |
| `pd3.lookup_accum` | Lookup accumulator crossing boundary |
| `pd3.commit_vector` | Commitment vector crossing boundary |

**Gadget**: `{N×(sw/lw)} to distinct addrs; reveal {rd};` /* N chosen to cross memory table 2^k boundary */

---

### PD4 `pad.bytecode_2k`

- **κ**: `Program bytecode table crosses a 2^k boundary`
- **μ**: `Instruction lookup remains valid after program table expansion`
- **V**:

| Cell | Description |
|---|---|
| `pd4.just_over` | bytecode = 2^k + 1 instructions |
| `pd4.just_under` | bytecode = 2^k - 1 |
| `pd4.large_program` | bytecode > 2^14 (large program) |
| `pd4.small_program` | bytecode < 16 (very short program) |

**Gadget**: `{2^k±1 instructions}; reveal {rd};` /* pad bytecode near boundary */

---

### PD5 `pad.segment_boundary`

- **κ**: `Execution is split into multiple segments/shards`
- **μ**: `PC, register file, and memory state are continuous at the boundary between adjacent segments; transition constraints are correct`
- **V**:

| Cell | Description |
|---|---|
| `pd5.mid_basic_block` | Segment boundary falls in the middle of a basic block |
| `pd5.at_branch` | Segment boundary exactly at a branch instruction |
| `pd5.at_ecall` | Segment boundary at an ecall |
| `pd5.memory_dirty` | Many un-finalized dirty memory cells at the boundary |
| `pd5.two_segments` | Minimum segment count (2 segments) |
| `pd5.many_segments` | Many segments (> 8) |

**Gadget**: `li {t0}, 0; li {t1}, {shard_size}; loop: addi {t0}, {t0}, 1; blt {t0}, {t1}, loop; reveal {t0};`

---

## Summary

| Group | Obligations | Partition Cells |
|---|---|---|
| Register File | 3 | 21 |
| Instruction Decode | 5 | 32 |
| ALU | 5 | 30 |
| Mul/Div | 5 | 28 |
| Memory | 11 | 48 |
| Control Flow | 7 | 36 |
| Range Check & Decomposition | 4 | 19 |
| Timestamp & Ordering | 3 | 8 |
| Bus & Interaction | 6 | 22 |
| Padding & Table Lifecycle | 5 | 25 |
| **Total** | **54** | **~269** |
