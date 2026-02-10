use std::fmt;

use rrs_lib::instruction_formats;
use rrs_lib::instruction_string_outputter::InstructionStringOutputter;
use rrs_lib::{InstructionProcessor, process_instruction};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RV32IMFormat {
    R,
    I,
    S,
    B,
    U,
    J,
    CSR,
}

#[derive(Debug, Clone, Copy)]
struct MnemonicSpec {
    literal: &'static str,
    format: RV32IMFormat,
    opcode: u32,
    funct3: u32,
    funct7: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RV32IMEncodeError {
    UnknownMnemonic(String),
    InvalidRegister { field: &'static str, value: u32 },
    InvalidRegisterToken { field: &'static str, token: String },
    MissingOperand(&'static str),
    InvalidImmediate(String),
    InvalidOperandCount { mnemonic: String, expected: &'static str, found: usize },
    EmptyAsm,
    DecodeFailed,
}

impl fmt::Display for RV32IMEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RV32IMEncodeError::UnknownMnemonic(mnemonic) => {
                write!(f, "unknown mnemonic '{mnemonic}'")
            }
            RV32IMEncodeError::InvalidRegister { field, value } => {
                write!(f, "invalid register {field}: x{value}")
            }
            RV32IMEncodeError::InvalidRegisterToken { field, token } => {
                write!(f, "invalid register {field}: '{token}'")
            }
            RV32IMEncodeError::MissingOperand(field) => {
                write!(f, "missing operand: {field}")
            }
            RV32IMEncodeError::InvalidImmediate(message) => write!(f, "{message}"),
            RV32IMEncodeError::InvalidOperandCount {
                mnemonic,
                expected,
                found,
            } => write!(
                f,
                "invalid operand count for '{mnemonic}': expected {expected}, got {found}"
            ),
            RV32IMEncodeError::EmptyAsm => write!(f, "empty asm line"),
            RV32IMEncodeError::DecodeFailed => write!(f, "failed to decode instruction word"),
        }
    }
}

impl std::error::Error for RV32IMEncodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RV32IMInstruction {
    pub mnemonic: String,
    pub rd: Option<u32>,
    pub rs1: Option<u32>,
    pub rs2: Option<u32>,
    pub imm: Option<i32>,
    pub word: u32,
    pub asm: String,
}

impl RV32IMInstruction {
    pub fn from_word(word: u32) -> Result<Self, RV32IMEncodeError> {
        Self::decode(word).ok_or(RV32IMEncodeError::DecodeFailed)
    }

    pub fn from_parts(
        mnemonic: &str,
        rd: Option<u32>,
        rs1: Option<u32>,
        rs2: Option<u32>,
        imm: Option<i32>,
    ) -> Result<Self, RV32IMEncodeError> {
        let mnemonic = mnemonic.to_ascii_lowercase();
        let word = encode_from_parts(&mnemonic, rd, rs1, rs2, imm)?;
        Self::from_word(word)
    }

    pub fn from_asm(line: &str) -> Result<Self, RV32IMEncodeError> {
        let tokens = tokenize_asm(line);
        if tokens.is_empty() {
            return Err(RV32IMEncodeError::EmptyAsm);
        }
        let mnemonic = tokens[0].to_ascii_lowercase();
        let spec = mnemonic_spec(&mnemonic)
            .ok_or_else(|| RV32IMEncodeError::UnknownMnemonic(mnemonic.clone()))?;

        let operands = &tokens[1..];
        let (rd, rs1, rs2, imm) = parse_operands(spec, operands)?;
        Self::from_parts(&mnemonic, rd, rs1, rs2, imm)
    }

    pub fn decode(word: u32) -> Option<Self> {
        Self::decode_with_pc(word, 0)
    }

    pub fn decode_with_pc(word: u32, pc: u32) -> Option<Self> {
        if let Some(system) = decode_system_instruction(word) {
            return Some(system);
        }
        let mut outputter = InstructionStringOutputter { insn_pc: pc };
        let asm = process_instruction(&mut outputter, word)?;

        let mut builder = InstructionBuilder { word, asm };
        process_instruction(&mut builder, word)
    }

    pub fn new(
        mnemonic: &'static str,
        word: u32,
        asm: String,
        rd: Option<u32>,
        rs1: Option<u32>,
        rs2: Option<u32>,
        imm: Option<i32>,
    ) -> Self {
        Self {
            mnemonic: mnemonic.to_string(),
            rd,
            rs1,
            rs2,
            imm,
            word,
            asm,
        }
    }
}

impl Serialize for RV32IMInstruction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.word)
    }
}

impl<'de> Deserialize<'de> for RV32IMInstruction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let word = u32::deserialize(deserializer)?;
        RV32IMInstruction::decode(word)
            .ok_or_else(|| serde::de::Error::custom(format!("failed to decode rv32im instruction: {}", word)))
    }
}

fn mnemonic_spec(literal: &str) -> Option<MnemonicSpec> {
    match literal {
        "add" => Some(MnemonicSpec {
            literal: "add",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "sub" => Some(MnemonicSpec {
            literal: "sub",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x0,
            funct7: 0x20,
        }),
        "sll" => Some(MnemonicSpec {
            literal: "sll",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x1,
            funct7: 0x00,
        }),
        "slt" => Some(MnemonicSpec {
            literal: "slt",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x2,
            funct7: 0x00,
        }),
        "sltu" => Some(MnemonicSpec {
            literal: "sltu",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x3,
            funct7: 0x00,
        }),
        "xor" => Some(MnemonicSpec {
            literal: "xor",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x4,
            funct7: 0x00,
        }),
        "srl" => Some(MnemonicSpec {
            literal: "srl",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x5,
            funct7: 0x00,
        }),
        "sra" => Some(MnemonicSpec {
            literal: "sra",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x5,
            funct7: 0x20,
        }),
        "or" => Some(MnemonicSpec {
            literal: "or",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x6,
            funct7: 0x00,
        }),
        "and" => Some(MnemonicSpec {
            literal: "and",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x7,
            funct7: 0x00,
        }),
        "mul" => Some(MnemonicSpec {
            literal: "mul",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x0,
            funct7: 0x01,
        }),
        "mulh" => Some(MnemonicSpec {
            literal: "mulh",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x1,
            funct7: 0x01,
        }),
        "mulhsu" => Some(MnemonicSpec {
            literal: "mulhsu",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x2,
            funct7: 0x01,
        }),
        "mulhu" => Some(MnemonicSpec {
            literal: "mulhu",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x3,
            funct7: 0x01,
        }),
        "div" => Some(MnemonicSpec {
            literal: "div",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x4,
            funct7: 0x01,
        }),
        "divu" => Some(MnemonicSpec {
            literal: "divu",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x5,
            funct7: 0x01,
        }),
        "rem" => Some(MnemonicSpec {
            literal: "rem",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x6,
            funct7: 0x01,
        }),
        "remu" => Some(MnemonicSpec {
            literal: "remu",
            format: RV32IMFormat::R,
            opcode: 0x33,
            funct3: 0x7,
            funct7: 0x01,
        }),
        "addi" => Some(MnemonicSpec {
            literal: "addi",
            format: RV32IMFormat::I,
            opcode: 0x13,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "slti" => Some(MnemonicSpec {
            literal: "slti",
            format: RV32IMFormat::I,
            opcode: 0x13,
            funct3: 0x2,
            funct7: 0x00,
        }),
        "sltiu" => Some(MnemonicSpec {
            literal: "sltiu",
            format: RV32IMFormat::I,
            opcode: 0x13,
            funct3: 0x3,
            funct7: 0x00,
        }),
        "xori" => Some(MnemonicSpec {
            literal: "xori",
            format: RV32IMFormat::I,
            opcode: 0x13,
            funct3: 0x4,
            funct7: 0x00,
        }),
        "ori" => Some(MnemonicSpec {
            literal: "ori",
            format: RV32IMFormat::I,
            opcode: 0x13,
            funct3: 0x6,
            funct7: 0x00,
        }),
        "andi" => Some(MnemonicSpec {
            literal: "andi",
            format: RV32IMFormat::I,
            opcode: 0x13,
            funct3: 0x7,
            funct7: 0x00,
        }),
        "slli" => Some(MnemonicSpec {
            literal: "slli",
            format: RV32IMFormat::I,
            opcode: 0x13,
            funct3: 0x1,
            funct7: 0x00,
        }),
        "srli" => Some(MnemonicSpec {
            literal: "srli",
            format: RV32IMFormat::I,
            opcode: 0x13,
            funct3: 0x5,
            funct7: 0x00,
        }),
        "srai" => Some(MnemonicSpec {
            literal: "srai",
            format: RV32IMFormat::I,
            opcode: 0x13,
            funct3: 0x5,
            funct7: 0x20,
        }),
        "lb" => Some(MnemonicSpec {
            literal: "lb",
            format: RV32IMFormat::I,
            opcode: 0x03,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "lh" => Some(MnemonicSpec {
            literal: "lh",
            format: RV32IMFormat::I,
            opcode: 0x03,
            funct3: 0x1,
            funct7: 0x00,
        }),
        "lw" => Some(MnemonicSpec {
            literal: "lw",
            format: RV32IMFormat::I,
            opcode: 0x03,
            funct3: 0x2,
            funct7: 0x00,
        }),
        "lbu" => Some(MnemonicSpec {
            literal: "lbu",
            format: RV32IMFormat::I,
            opcode: 0x03,
            funct3: 0x4,
            funct7: 0x00,
        }),
        "lhu" => Some(MnemonicSpec {
            literal: "lhu",
            format: RV32IMFormat::I,
            opcode: 0x03,
            funct3: 0x5,
            funct7: 0x00,
        }),
        "sb" => Some(MnemonicSpec {
            literal: "sb",
            format: RV32IMFormat::S,
            opcode: 0x23,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "sh" => Some(MnemonicSpec {
            literal: "sh",
            format: RV32IMFormat::S,
            opcode: 0x23,
            funct3: 0x1,
            funct7: 0x00,
        }),
        "sw" => Some(MnemonicSpec {
            literal: "sw",
            format: RV32IMFormat::S,
            opcode: 0x23,
            funct3: 0x2,
            funct7: 0x00,
        }),
        "beq" => Some(MnemonicSpec {
            literal: "beq",
            format: RV32IMFormat::B,
            opcode: 0x63,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "bne" => Some(MnemonicSpec {
            literal: "bne",
            format: RV32IMFormat::B,
            opcode: 0x63,
            funct3: 0x1,
            funct7: 0x00,
        }),
        "blt" => Some(MnemonicSpec {
            literal: "blt",
            format: RV32IMFormat::B,
            opcode: 0x63,
            funct3: 0x4,
            funct7: 0x00,
        }),
        "bge" => Some(MnemonicSpec {
            literal: "bge",
            format: RV32IMFormat::B,
            opcode: 0x63,
            funct3: 0x5,
            funct7: 0x00,
        }),
        "bltu" => Some(MnemonicSpec {
            literal: "bltu",
            format: RV32IMFormat::B,
            opcode: 0x63,
            funct3: 0x6,
            funct7: 0x00,
        }),
        "bgeu" => Some(MnemonicSpec {
            literal: "bgeu",
            format: RV32IMFormat::B,
            opcode: 0x63,
            funct3: 0x7,
            funct7: 0x00,
        }),
        "lui" => Some(MnemonicSpec {
            literal: "lui",
            format: RV32IMFormat::U,
            opcode: 0x37,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "auipc" => Some(MnemonicSpec {
            literal: "auipc",
            format: RV32IMFormat::U,
            opcode: 0x17,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "jal" => Some(MnemonicSpec {
            literal: "jal",
            format: RV32IMFormat::J,
            opcode: 0x6F,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "jalr" => Some(MnemonicSpec {
            literal: "jalr",
            format: RV32IMFormat::I,
            opcode: 0x67,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "fence" => Some(MnemonicSpec {
            literal: "fence",
            format: RV32IMFormat::I,
            opcode: 0x0F,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "fence.i" => Some(MnemonicSpec {
            literal: "fence.i",
            format: RV32IMFormat::I,
            opcode: 0x0F,
            funct3: 0x1,
            funct7: 0x00,
        }),
        "ecall" => Some(MnemonicSpec {
            literal: "ecall",
            format: RV32IMFormat::I,
            opcode: 0x73,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "ebreak" => Some(MnemonicSpec {
            literal: "ebreak",
            format: RV32IMFormat::I,
            opcode: 0x73,
            funct3: 0x0,
            funct7: 0x00,
        }),
        "csrrw" => Some(MnemonicSpec {
            literal: "csrrw",
            format: RV32IMFormat::CSR,
            opcode: 0x73,
            funct3: 0x1,
            funct7: 0x00,
        }),
        "csrrs" => Some(MnemonicSpec {
            literal: "csrrs",
            format: RV32IMFormat::CSR,
            opcode: 0x73,
            funct3: 0x2,
            funct7: 0x00,
        }),
        "csrrc" => Some(MnemonicSpec {
            literal: "csrrc",
            format: RV32IMFormat::CSR,
            opcode: 0x73,
            funct3: 0x3,
            funct7: 0x00,
        }),
        "csrrwi" => Some(MnemonicSpec {
            literal: "csrrwi",
            format: RV32IMFormat::CSR,
            opcode: 0x73,
            funct3: 0x5,
            funct7: 0x00,
        }),
        "csrrsi" => Some(MnemonicSpec {
            literal: "csrrsi",
            format: RV32IMFormat::CSR,
            opcode: 0x73,
            funct3: 0x6,
            funct7: 0x00,
        }),
        "csrrci" => Some(MnemonicSpec {
            literal: "csrrci",
            format: RV32IMFormat::CSR,
            opcode: 0x73,
            funct3: 0x7,
            funct7: 0x00,
        }),
        _ => None,
    }
}

fn tokenize_asm(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in line.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '+' || ch == '-' {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(current.clone());
            current.clear();
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn parse_register(token: &str, field: &'static str) -> Result<u32, RV32IMEncodeError> {
    let stripped = token.strip_prefix('x').ok_or_else(|| {
        RV32IMEncodeError::InvalidRegisterToken {
            field,
            token: token.to_string(),
        }
    })?;
    let value = stripped.parse::<u32>().map_err(|_| {
        RV32IMEncodeError::InvalidRegisterToken {
            field,
            token: token.to_string(),
        }
    })?;
    if value > 31 {
        return Err(RV32IMEncodeError::InvalidRegister { field, value });
    }
    Ok(value)
}

fn parse_immediate(token: &str) -> Result<i32, RV32IMEncodeError> {
    let t = token.trim();
    if let Some(hex) = t.strip_prefix("0x") {
        return i32::from_str_radix(hex, 16)
            .map_err(|_| RV32IMEncodeError::InvalidImmediate(format!("invalid hex immediate '{t}'")));
    }
    if let Some(rest) = t.strip_prefix(".+") {
        return rest.parse::<i32>().map_err(|_| {
            RV32IMEncodeError::InvalidImmediate(format!("invalid immediate '{t}'"))
        });
    }
    if let Some(rest) = t.strip_prefix(".-") {
        return rest.parse::<i32>().map(|v| -v).map_err(|_| {
            RV32IMEncodeError::InvalidImmediate(format!("invalid immediate '{t}'"))
        });
    }
    if let Some(rest) = t.strip_prefix('.') {
        return rest.parse::<i32>().map_err(|_| {
            RV32IMEncodeError::InvalidImmediate(format!("invalid immediate '{t}'"))
        });
    }
    t.parse::<i32>()
        .map_err(|_| RV32IMEncodeError::InvalidImmediate(format!("invalid immediate '{t}'")))
}

fn parse_operands(
    spec: MnemonicSpec,
    operands: &[String],
) -> Result<(Option<u32>, Option<u32>, Option<u32>, Option<i32>), RV32IMEncodeError> {
    let count = operands.len();
    match spec.format {
        RV32IMFormat::R => {
            if count != 3 {
                return Err(RV32IMEncodeError::InvalidOperandCount {
                    mnemonic: spec.literal.to_string(),
                    expected: "rd, rs1, rs2",
                    found: count,
                });
            }
            let rd = parse_register(&operands[0], "rd")?;
            let rs1 = parse_register(&operands[1], "rs1")?;
            let rs2 = parse_register(&operands[2], "rs2")?;
            Ok((Some(rd), Some(rs1), Some(rs2), None))
        }
        RV32IMFormat::I => {
            if let Some(default_imm) = no_operand_imm(spec.literal) {
                if count == 0 {
                    return Ok((Some(0), Some(0), None, Some(default_imm)));
                }
                return Err(RV32IMEncodeError::InvalidOperandCount {
                    mnemonic: spec.literal.to_string(),
                    expected: "no operands",
                    found: count,
                });
            }
            if is_load_or_jalr(spec.literal) {
                if count != 3 {
                    return Err(RV32IMEncodeError::InvalidOperandCount {
                        mnemonic: spec.literal.to_string(),
                        expected: "rd, imm(rs1)",
                        found: count,
                    });
                }
                let rd = parse_register(&operands[0], "rd")?;
                let imm = parse_immediate(&operands[1])?;
                let rs1 = parse_register(&operands[2], "rs1")?;
                return Ok((Some(rd), Some(rs1), None, Some(imm)));
            }
            if count != 3 {
                return Err(RV32IMEncodeError::InvalidOperandCount {
                    mnemonic: spec.literal.to_string(),
                    expected: "rd, rs1, imm",
                    found: count,
                });
            }
            let rd = parse_register(&operands[0], "rd")?;
            let rs1 = parse_register(&operands[1], "rs1")?;
            let imm = parse_immediate(&operands[2])?;
            Ok((Some(rd), Some(rs1), None, Some(imm)))
        }
        RV32IMFormat::S => {
            if count != 3 {
                return Err(RV32IMEncodeError::InvalidOperandCount {
                    mnemonic: spec.literal.to_string(),
                    expected: "rs2, imm(rs1)",
                    found: count,
                });
            }
            let rs2 = parse_register(&operands[0], "rs2")?;
            let imm = parse_immediate(&operands[1])?;
            let rs1 = parse_register(&operands[2], "rs1")?;
            Ok((None, Some(rs1), Some(rs2), Some(imm)))
        }
        RV32IMFormat::B => {
            if count != 3 {
                return Err(RV32IMEncodeError::InvalidOperandCount {
                    mnemonic: spec.literal.to_string(),
                    expected: "rs1, rs2, imm",
                    found: count,
                });
            }
            let rs1 = parse_register(&operands[0], "rs1")?;
            let rs2 = parse_register(&operands[1], "rs2")?;
            let imm = parse_immediate(&operands[2])?;
            Ok((None, Some(rs1), Some(rs2), Some(imm)))
        }
        RV32IMFormat::U => {
            if count != 2 {
                return Err(RV32IMEncodeError::InvalidOperandCount {
                    mnemonic: spec.literal.to_string(),
                    expected: "rd, imm",
                    found: count,
                });
            }
            let rd = parse_register(&operands[0], "rd")?;
            let imm = parse_immediate(&operands[1])?;
            Ok((Some(rd), None, None, Some(imm)))
        }
        RV32IMFormat::J => {
            if count != 2 {
                return Err(RV32IMEncodeError::InvalidOperandCount {
                    mnemonic: spec.literal.to_string(),
                    expected: "rd, imm",
                    found: count,
                });
            }
            let rd = parse_register(&operands[0], "rd")?;
            let imm = parse_immediate(&operands[1])?;
            Ok((Some(rd), None, None, Some(imm)))
        }
        RV32IMFormat::CSR => {
            if count != 3 {
                return Err(RV32IMEncodeError::InvalidOperandCount {
                    mnemonic: spec.literal.to_string(),
                    expected: "rd, csr, rs1/uimm",
                    found: count,
                });
            }
            let rd = parse_register(&operands[0], "rd")?;
            let csr = parse_csr(&operands[1])?;
            let is_imm = matches!(spec.literal, "csrrwi" | "csrrsi" | "csrrci");
            if is_imm {
                let uimm = parse_csr_uimm(&operands[2])?;
                Ok((Some(rd), Some(uimm), None, Some(csr)))
            } else {
                let rs1 = parse_register(&operands[2], "rs1")?;
                Ok((Some(rd), Some(rs1), None, Some(csr)))
            }
        }
    }
}

fn parse_csr(token: &str) -> Result<i32, RV32IMEncodeError> {
    let t = token.trim();
    if let Some(hex) = t.strip_prefix("0x") {
        return i32::from_str_radix(hex, 16).map_err(|_| {
            RV32IMEncodeError::InvalidImmediate(format!("invalid csr '{t}'"))
        });
    }
    t.parse::<i32>()
        .map_err(|_| RV32IMEncodeError::InvalidImmediate(format!("invalid csr '{t}'")))
}

fn parse_csr_uimm(token: &str) -> Result<u32, RV32IMEncodeError> {
    let t = token.trim();
    let v = if let Some(hex) = t.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).map_err(|_| {
            RV32IMEncodeError::InvalidImmediate(format!("invalid csr uimm '{t}'"))
        })?
    } else {
        t.parse::<u32>().map_err(|_| {
            RV32IMEncodeError::InvalidImmediate(format!("invalid csr uimm '{t}'"))
        })?
    };
    if v > 31 {
        return Err(RV32IMEncodeError::InvalidImmediate(format!(
            "csr uimm must be 0-31, got {v}"
        )));
    }
    Ok(v)
}

fn encode_from_parts(
    mnemonic: &str,
    rd: Option<u32>,
    rs1: Option<u32>,
    rs2: Option<u32>,
    imm: Option<i32>,
) -> Result<u32, RV32IMEncodeError> {
    let spec = mnemonic_spec(mnemonic)
        .ok_or_else(|| RV32IMEncodeError::UnknownMnemonic(mnemonic.to_string()))?;
    let op = spec.opcode;
    let f3 = spec.funct3;
    let f7 = spec.funct7;
    let (rd, rs1, imm) = if let Some(default_imm) = no_operand_imm(spec.literal) {
        (Some(0), Some(0), Some(default_imm))
    } else {
        (rd, rs1, imm)
    };

    let word = match spec.format {
        RV32IMFormat::R => {
            let rd = require_reg(rd, "rd")?;
            let rs1 = require_reg(rs1, "rs1")?;
            let rs2 = require_reg(rs2, "rs2")?;
            (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
        }
        RV32IMFormat::I => {
            let rd = require_reg(rd, "rd")?;
            let rs1 = require_reg(rs1, "rs1")?;
            let imm = imm.ok_or(RV32IMEncodeError::MissingOperand("imm"))?;
            if is_shift_imm(spec.literal) {
                (f7 << 25)
                    | (((imm as u32) & 0x1F) << 20)
                    | (rs1 << 15)
                    | (f3 << 12)
                    | (rd << 7)
                    | op
            } else {
                (((imm as u32) & 0xFFF) << 20)
                    | (rs1 << 15)
                    | (f3 << 12)
                    | (rd << 7)
                    | op
            }
        }
        RV32IMFormat::S => {
            let rs1 = require_reg(rs1, "rs1")?;
            let rs2 = require_reg(rs2, "rs2")?;
            let imm = imm.ok_or(RV32IMEncodeError::MissingOperand("imm"))?;
            ((((imm >> 5) & 0x7F) as u32) << 25)
                | (rs2 << 20)
                | (rs1 << 15)
                | (f3 << 12)
                | (((imm as u32) & 0x1F) << 7)
                | op
        }
        RV32IMFormat::B => {
            let rs1 = require_reg(rs1, "rs1")?;
            let rs2 = require_reg(rs2, "rs2")?;
            let imm = imm.ok_or(RV32IMEncodeError::MissingOperand("imm"))?;
            ((((imm >> 12) & 1) as u32) << 31)
                | ((((imm >> 5) & 0x3F) as u32) << 25)
                | (rs2 << 20)
                | (rs1 << 15)
                | (f3 << 12)
                | ((((imm >> 1) & 0xF) as u32) << 8)
                | ((((imm >> 11) & 1) as u32) << 7)
                | op
        }
        RV32IMFormat::U => {
            let rd = require_reg(rd, "rd")?;
            let imm = imm.ok_or(RV32IMEncodeError::MissingOperand("imm"))?;
            (((imm as u32) & 0xFFFFF) << 12) | (rd << 7) | op
        }
        RV32IMFormat::J => {
            let rd = require_reg(rd, "rd")?;
            let imm = imm.ok_or(RV32IMEncodeError::MissingOperand("imm"))?;
            ((((imm >> 20) & 1) as u32) << 31)
                | ((((imm >> 1) & 0x3FF) as u32) << 21)
                | ((((imm >> 11) & 1) as u32) << 20)
                | ((((imm >> 12) & 0xFF) as u32) << 12)
                | (rd << 7)
                | op
        }
        RV32IMFormat::CSR => {
            let rd = require_reg(rd, "rd")?;
            let rs1 = require_reg(rs1, "rs1")?;
            let csr = imm.ok_or(RV32IMEncodeError::MissingOperand("csr"))?;
            let csr_u = (csr as u32) & 0xfff;
            (csr_u << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
        }
    };
    Ok(word)
}

fn require_reg(value: Option<u32>, field: &'static str) -> Result<u32, RV32IMEncodeError> {
    let value = value.ok_or(RV32IMEncodeError::MissingOperand(field))?;
    if value > 31 {
        return Err(RV32IMEncodeError::InvalidRegister { field, value });
    }
    Ok(value)
}

fn is_shift_imm(mnemonic: &str) -> bool {
    matches!(mnemonic, "slli" | "srli" | "srai")
}

fn is_load_or_jalr(mnemonic: &str) -> bool {
    matches!(mnemonic, "lb" | "lh" | "lw" | "lbu" | "lhu" | "jalr")
}

fn no_operand_imm(mnemonic: &str) -> Option<i32> {
    match mnemonic {
        "fence" | "fence.i" => Some(0),
        "ecall" => Some(0),
        "ebreak" => Some(1),
        _ => None,
    }
}

fn decode_system_instruction(word: u32) -> Option<RV32IMInstruction> {
    let opcode = word & 0x7f;
    let rd = (word >> 7) & 0x1f;
    let funct3 = (word >> 12) & 0x7;
    let rs1 = (word >> 15) & 0x1f;
    let imm12 = ((word >> 20) & 0xfff) as i32;

    if opcode == 0x0f && funct3 == 0x1 && rd == 0 && rs1 == 0 && imm12 == 0 {
        return Some(RV32IMInstruction::new(
            "fence.i",
            word,
            "fence.i".to_string(),
            None,
            None,
            None,
            None,
        ));
    }

    if opcode == 0x73 && funct3 == 0x0 {
        if rd == 0 && rs1 == 0 {
            match imm12 {
                0 => {
                    return Some(RV32IMInstruction::new(
                        "ecall",
                        word,
                        "ecall".to_string(),
                        None,
                        None,
                        None,
                        None,
                    ));
                }
                1 => {
                    return Some(RV32IMInstruction::new(
                        "ebreak",
                        word,
                        "ebreak".to_string(),
                        None,
                        None,
                        None,
                        None,
                    ));
                }
                0x102 => {
                    return Some(RV32IMInstruction::new(
                        "sret",
                        word,
                        "sret".to_string(),
                        None,
                        None,
                        None,
                        None,
                    ));
                }
                0x302 => {
                    return Some(RV32IMInstruction::new(
                        "mret",
                        word,
                        "mret".to_string(),
                        None,
                        None,
                        None,
                        None,
                    ));
                }
                0x105 => {
                    return Some(RV32IMInstruction::new(
                        "wfi",
                        word,
                        "wfi".to_string(),
                        None,
                        None,
                        None,
                        None,
                    ));
                }
                _ => {}
            }
        }
        if (word >> 20) & 0xfff == 0x120 {
            return Some(RV32IMInstruction::new(
                "sfence.vma",
                word,
                format!("sfence.vma x{rs1}"),
                None,
                Some(rs1),
                None,
                None,
            ));
        }
    }

    if opcode == 0x73 && (funct3 == 1 || funct3 == 2 || funct3 == 3 || funct3 == 5 || funct3 == 6 || funct3 == 7) {
        let csr = (word >> 20) & 0xfff;
        let mnemonic = match funct3 {
            1 => "csrrw",
            2 => "csrrs",
            3 => "csrrc",
            5 => "csrrwi",
            6 => "csrrsi",
            7 => "csrrci",
            _ => unreachable!(),
        };
        let asm = if funct3 >= 5 {
            format!("{mnemonic} x{rd}, 0x{csr:x}, {rs1}")
        } else {
            format!("{mnemonic} x{rd}, 0x{csr:x}, x{rs1}")
        };
        return Some(RV32IMInstruction::new(
            mnemonic,
            word,
            asm,
            Some(rd),
            Some(rs1),
            None,
            Some(csr as i32),
        ));
    }

    None
}

struct InstructionBuilder {
    word: u32,
    asm: String,
}

impl InstructionBuilder {
    fn build_rtype(
        &self,
        mnemonic: &'static str,
        dec_insn: instruction_formats::RType,
    ) -> RV32IMInstruction {
        RV32IMInstruction::new(
            mnemonic,
            self.word,
            self.asm.clone(),
            Some(dec_insn.rd as u32),
            Some(dec_insn.rs1 as u32),
            Some(dec_insn.rs2 as u32),
            None,
        )
    }

    fn build_itype(
        &self,
        mnemonic: &'static str,
        dec_insn: instruction_formats::IType,
    ) -> RV32IMInstruction {
        RV32IMInstruction::new(
            mnemonic,
            self.word,
            self.asm.clone(),
            Some(dec_insn.rd as u32),
            Some(dec_insn.rs1 as u32),
            None,
            Some(dec_insn.imm),
        )
    }

    fn build_itype_shamt(
        &self,
        mnemonic: &'static str,
        dec_insn: instruction_formats::ITypeShamt,
    ) -> RV32IMInstruction {
        RV32IMInstruction::new(
            mnemonic,
            self.word,
            self.asm.clone(),
            Some(dec_insn.rd as u32),
            Some(dec_insn.rs1 as u32),
            None,
            Some(dec_insn.shamt as i32),
        )
    }

    fn build_stype(
        &self,
        mnemonic: &'static str,
        dec_insn: instruction_formats::SType,
    ) -> RV32IMInstruction {
        RV32IMInstruction::new(
            mnemonic,
            self.word,
            self.asm.clone(),
            None,
            Some(dec_insn.rs1 as u32),
            Some(dec_insn.rs2 as u32),
            Some(dec_insn.imm),
        )
    }

    fn build_btype(
        &self,
        mnemonic: &'static str,
        dec_insn: instruction_formats::BType,
    ) -> RV32IMInstruction {
        RV32IMInstruction::new(
            mnemonic,
            self.word,
            self.asm.clone(),
            None,
            Some(dec_insn.rs1 as u32),
            Some(dec_insn.rs2 as u32),
            Some(dec_insn.imm),
        )
    }

    fn build_utype(
        &self,
        mnemonic: &'static str,
        dec_insn: instruction_formats::UType,
    ) -> RV32IMInstruction {
        RV32IMInstruction::new(
            mnemonic,
            self.word,
            self.asm.clone(),
            Some(dec_insn.rd as u32),
            None,
            None,
            Some(dec_insn.imm),
        )
    }

    fn build_jtype(
        &self,
        mnemonic: &'static str,
        dec_insn: instruction_formats::JType,
    ) -> RV32IMInstruction {
        RV32IMInstruction::new(
            mnemonic,
            self.word,
            self.asm.clone(),
            Some(dec_insn.rd as u32),
            None,
            None,
            Some(dec_insn.imm),
        )
    }
}

macro_rules! rtype {
    ($name:ident, $mnemonic:expr) => {
        fn $name(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult {
            self.build_rtype($mnemonic, dec_insn)
        }
    };
}

macro_rules! itype {
    ($name:ident, $mnemonic:expr) => {
        fn $name(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult {
            self.build_itype($mnemonic, dec_insn)
        }
    };
}

macro_rules! itype_shamt {
    ($name:ident, $mnemonic:expr) => {
        fn $name(&mut self, dec_insn: instruction_formats::ITypeShamt) -> Self::InstructionResult {
            self.build_itype_shamt($mnemonic, dec_insn)
        }
    };
}

macro_rules! stype {
    ($name:ident, $mnemonic:expr) => {
        fn $name(&mut self, dec_insn: instruction_formats::SType) -> Self::InstructionResult {
            self.build_stype($mnemonic, dec_insn)
        }
    };
}

macro_rules! btype {
    ($name:ident, $mnemonic:expr) => {
        fn $name(&mut self, dec_insn: instruction_formats::BType) -> Self::InstructionResult {
            self.build_btype($mnemonic, dec_insn)
        }
    };
}

macro_rules! utype {
    ($name:ident, $mnemonic:expr) => {
        fn $name(&mut self, dec_insn: instruction_formats::UType) -> Self::InstructionResult {
            self.build_utype($mnemonic, dec_insn)
        }
    };
}

macro_rules! jtype {
    ($name:ident, $mnemonic:expr) => {
        fn $name(&mut self, dec_insn: instruction_formats::JType) -> Self::InstructionResult {
            self.build_jtype($mnemonic, dec_insn)
        }
    };
}

impl InstructionProcessor for InstructionBuilder {
    type InstructionResult = RV32IMInstruction;

    rtype!(process_add, "add");
    rtype!(process_sub, "sub");
    rtype!(process_sll, "sll");
    rtype!(process_slt, "slt");
    rtype!(process_sltu, "sltu");
    rtype!(process_xor, "xor");
    rtype!(process_srl, "srl");
    rtype!(process_sra, "sra");
    rtype!(process_or, "or");
    rtype!(process_and, "and");

    itype!(process_addi, "addi");
    itype_shamt!(process_slli, "slli");
    itype!(process_slti, "slti");
    itype!(process_sltui, "sltiu");
    itype!(process_xori, "xori");
    itype_shamt!(process_srli, "srli");
    itype_shamt!(process_srai, "srai");
    itype!(process_ori, "ori");
    itype!(process_andi, "andi");

    utype!(process_lui, "lui");
    utype!(process_auipc, "auipc");

    btype!(process_beq, "beq");
    btype!(process_bne, "bne");
    btype!(process_blt, "blt");
    btype!(process_bltu, "bltu");
    btype!(process_bge, "bge");
    btype!(process_bgeu, "bgeu");

    itype!(process_lb, "lb");
    itype!(process_lbu, "lbu");
    itype!(process_lh, "lh");
    itype!(process_lhu, "lhu");
    itype!(process_lw, "lw");

    stype!(process_sb, "sb");
    stype!(process_sh, "sh");
    stype!(process_sw, "sw");

    jtype!(process_jal, "jal");
    itype!(process_jalr, "jalr");

    rtype!(process_mul, "mul");
    rtype!(process_mulh, "mulh");
    rtype!(process_mulhu, "mulhu");
    rtype!(process_mulhsu, "mulhsu");
    rtype!(process_div, "div");
    rtype!(process_divu, "divu");
    rtype!(process_rem, "rem");
    rtype!(process_remu, "remu");

    itype!(process_fence, "fence");
}
