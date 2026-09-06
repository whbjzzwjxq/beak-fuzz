use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, Command};
use serde_json::json;

use beak_core::fuzz::benchmark::{run_benchmark_threaded, BenchmarkConfig, DEFAULT_RNG_SEED};
use beak_core::rv32im::oracle::{OracleConfig, OracleMemoryModel};
use risc0_circuit_rv32im::execute::platform::{
    LOOKUP_TABLE_CYCLES, MACHINE_REGS_ADDR, MERKLE_TREE_DEPTH, PAGE_BYTES, USER_START_ADDR,
    WORD_SIZE,
};

use beak_risc0_6f038bd::backend::Risc0Backend;
use beak_risc0_6f038bd::RISC0_ORACLE_CODE_BASE;

const ZKVM_COMMIT: &str = "6f038bd11ed725d7025687d163977d93ac1f82f9";
const CARRIER_SEGMENT_PO2: u32 = 15;
const CONTROL_DONE_CYCLES: u64 = 2;
// The wrapper appends three register setup instructions and a two-cycle machine
// terminate ECALL to every input program.
const TERMINATION_SEQUENCE_USER_CYCLES: u64 = 5;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn resolve_path(root: &Path, arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.is_absolute() {
        p
    } else {
        root.join(p)
    }
}

fn parse_u32_arg(value: &str, name: &str) -> u32 {
    let s = value.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("invalid {name}: {value}"))
    } else {
        s.parse::<u32>().unwrap_or_else(|_| panic!("invalid {name}: {value}"))
    }
}

fn parse_hex_word(value: &str) -> u32 {
    let s = value.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(s, 16).unwrap_or_else(|_| panic!("invalid hex word: {value}"))
}

fn collect_bin_words(matches: &clap::ArgMatches) -> Vec<u32> {
    let mut out = Vec::new();
    if let Some(values) = matches.get_many::<String>("bin") {
        for value in values {
            for token in value.split(|c: char| c.is_whitespace() || c == ',') {
                let t = token.trim();
                if !t.is_empty() {
                    out.push(parse_hex_word(t));
                }
            }
        }
    }
    out
}

fn write_inline_seed_jsonl(root: &Path, words: &[u32]) -> PathBuf {
    let ts_millis = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let dir = root.join("storage/fuzzing_seeds");
    std::fs::create_dir_all(&dir).expect("create storage/fuzzing_seeds");
    let path =
        dir.join(format!(".tmp-inline-risc0-6f038bd-{ts_millis}-pid{}.jsonl", std::process::id()));
    let line = json!({
        "instructions": words,
        "metadata": {
            "source": "cli_bin",
            "label": "inline_bin",
        }
    })
    .to_string();
    std::fs::write(&path, format!("{line}\n")).expect("write inline seed jsonl");
    path
}

fn encode_i_word(imm: i32, rs1: u32, rd: u32) -> u32 {
    (((imm as u32) & 0x0fff) << 20) | (rs1 << 15) | (rd << 7) | 0x13
}

fn encode_u_word(upper_20: u32, rd: u32) -> u32 {
    (upper_20 << 12) | (rd << 7) | 0x37
}

fn encode_r_word(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x33
}

fn encode_blt_word(rs1: u32, rs2: u32, offset: i32) -> u32 {
    assert_eq!(offset & 1, 0, "branch offset must be two-byte aligned");
    assert!((-4096..=4094).contains(&offset), "branch offset out of range");
    let imm = (offset as u32) & 0x1fff;
    (((imm >> 12) & 1) << 31)
        | (((imm >> 5) & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (0x4 << 12)
        | (((imm >> 1) & 0x0f) << 8)
        | (((imm >> 11) & 1) << 7)
        | 0x63
}

fn materialize_positive_i32(words: &mut Vec<u32>, rd: u32, value: i32) {
    assert!(value > 0, "carrier loop bound must be positive");
    let upper_20 = ((value + 0x800) >> 12) as u32;
    let lower_12 = value - ((upper_20 as i32) << 12);
    words.push(encode_u_word(upper_20, rd));
    words.push(encode_i_word(lower_12, rd, rd));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SegmentCapacityAccounting {
    capacity_cycles: u64,
    lookup_table_cycles: u64,
    pager_cycles: u64,
    user_cycles: u64,
    program_user_cycles: u64,
    required_cycles: u64,
}

fn shared_internal_ancestor_count(lhs_page: u32, rhs_page: u32, depth: u32) -> u64 {
    if lhs_page == rhs_page {
        return depth as u64;
    }
    let differing_bits = u32::BITS - (lhs_page ^ rhs_page).leading_zeros();
    depth
        .saturating_sub(differing_bits)
        .saturating_add(1)
        .min(depth) as u64
}

fn segment_capacity_accounting() -> SegmentCapacityAccounting {
    // These formulas mirror this snapshot's pager.rs constants. The carrier
    // touches one code page and the machine/register page; those page paths
    // share only their common Merkle ancestors. The register page is also
    // written during suspend/commit.
    let page_words = PAGE_BYTES as u64 / WORD_SIZE as u64;
    let poseidon_page_rounds = page_words / 8;
    let page_cycles = 1 + 10 * poseidon_page_rounds + 1;
    let node_cycles = 1 + 2 + 8 + 1 + 1;
    let reserved_pager_cycles = 1 + 1 + 1 + 2 + 2 + 1 + 1 + 1;
    let depth = MERKLE_TREE_DEPTH as u32;
    let code_page = USER_START_ADDR.0 / PAGE_BYTES as u32;
    let register_page = MACHINE_REGS_ADDR.0 / PAGE_BYTES as u32;
    let shared_ancestors = shared_internal_ancestor_count(code_page, register_page, depth);
    let first_page_in = page_cycles + depth as u64 * node_cycles;
    let second_page_in =
        page_cycles + (depth as u64).saturating_sub(shared_ancestors) * node_cycles;
    let register_page_out = page_cycles + depth as u64 * node_cycles;
    let pager_cycles =
        reserved_pager_cycles + first_page_in + second_page_in + register_page_out;

    let capacity_cycles = 1u64 << CARRIER_SEGMENT_PO2;
    let lookup_table_cycles = LOOKUP_TABLE_CYCLES as u64;
    let user_cycles = capacity_cycles
        .checked_sub(lookup_table_cycles)
        .and_then(|cycles| cycles.checked_sub(pager_cycles))
        .expect("segment accounting leaves no user-cycle budget");
    let program_user_cycles = user_cycles
        .checked_sub(TERMINATION_SEQUENCE_USER_CYCLES)
        .expect("termination sequence exceeds user-cycle budget");

    SegmentCapacityAccounting {
        capacity_cycles,
        lookup_table_cycles,
        pager_cycles,
        user_cycles,
        program_user_cycles,
        required_cycles: capacity_cycles + CONTROL_DONE_CYCLES,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopBodyFamily {
    AdditiveAccumulator,
    RegisterMix,
    SplitAccumulator,
}

impl LoopBodyFamily {
    const ALL: [Self; 3] = [
        Self::AdditiveAccumulator,
        Self::RegisterMix,
        Self::SplitAccumulator,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::AdditiveAccumulator => "additive_accumulator_3cycle",
            Self::RegisterMix => "register_mix_4cycle",
            Self::SplitAccumulator => "split_accumulator_5cycle",
        }
    }

    fn setup_cycles(self) -> u64 {
        match self {
            Self::AdditiveAccumulator => 4,
            Self::RegisterMix => 6,
            Self::SplitAccumulator => 5,
        }
    }

    fn body_cycles(self) -> u64 {
        match self {
            Self::AdditiveAccumulator => 3,
            Self::RegisterMix => 4,
            Self::SplitAccumulator => 5,
        }
    }

    fn counter_register(self) -> u32 {
        match self {
            Self::AdditiveAccumulator => 14,
            Self::RegisterMix => 12,
            Self::SplitAccumulator => 10,
        }
    }

    fn state_registers(self) -> &'static [u32] {
        match self {
            Self::AdditiveAccumulator => &[13, 14, 15],
            Self::RegisterMix => &[11, 12, 13, 14, 15],
            Self::SplitAccumulator => &[10, 11, 13, 14, 15],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SegmentCapacityCarrier {
    family: LoopBodyFamily,
    words: Vec<u32>,
    loop_bound: u32,
    setup_cycles: u64,
    body_cycles: u64,
}

fn accounting_derived_loop_bound(
    accounting: SegmentCapacityAccounting,
    family: LoopBodyFamily,
) -> u32 {
    let dynamic_cycles = accounting
        .program_user_cycles
        .checked_sub(family.setup_cycles())
        .expect("carrier setup exceeds program budget");
    assert_eq!(
        dynamic_cycles % family.body_cycles(),
        0,
        "carrier body does not divide accounting-derived cycle budget"
    );
    u32::try_from(dynamic_cycles / family.body_cycles()).expect("carrier loop bound exceeds u32")
}

fn segment_capacity_carrier(
    accounting: SegmentCapacityAccounting,
    family: LoopBodyFamily,
) -> SegmentCapacityCarrier {
    let loop_bound = accounting_derived_loop_bound(accounting, family);
    let mut words = Vec::new();
    match family {
        LoopBodyFamily::AdditiveAccumulator => {
            words.push(encode_i_word(0, 0, 14));
            materialize_positive_i32(&mut words, 15, loop_bound as i32);
            words.push(encode_i_word(7, 0, 13));
            words.push(encode_i_word(1, 14, 14));
            words.push(encode_i_word(3, 13, 13));
            words.push(encode_blt_word(14, 15, -8));
        }
        LoopBodyFamily::RegisterMix => {
            words.push(encode_i_word(0, 0, 12));
            materialize_positive_i32(&mut words, 15, loop_bound as i32);
            words.push(encode_i_word(11, 0, 13));
            words.push(encode_i_word(0x55, 0, 14));
            words.push(encode_i_word(2, 0, 11));
            words.push(encode_i_word(1, 12, 12));
            words.push(encode_r_word(0, 11, 13, 0, 13));
            words.push(encode_r_word(0, 12, 14, 4, 14));
            words.push(encode_blt_word(12, 15, -12));
        }
        LoopBodyFamily::SplitAccumulator => {
            words.push(encode_i_word(0, 0, 10));
            materialize_positive_i32(&mut words, 15, loop_bound as i32);
            words.push(encode_i_word(13, 0, 13));
            words.push(encode_i_word(3, 0, 14));
            words.push(encode_i_word(1, 10, 10));
            words.push(encode_i_word(2, 11, 11));
            words.push(encode_i_word(5, 13, 13));
            words.push(encode_r_word(0, 10, 14, 4, 14));
            words.push(encode_blt_word(10, 15, -16));
        }
    }
    SegmentCapacityCarrier {
        family,
        words,
        loop_bound,
        setup_cycles: family.setup_cycles(),
        body_cycles: family.body_cycles(),
    }
}

fn segment_capacity_carriers() -> Vec<SegmentCapacityCarrier> {
    let accounting = segment_capacity_accounting();
    LoopBodyFamily::ALL
        .into_iter()
        .map(|family| segment_capacity_carrier(accounting, family))
        .collect()
}

fn segment_capacity_carrier_lines() -> Vec<String> {
    let accounting = segment_capacity_accounting();
    segment_capacity_carriers()
        .into_iter()
        .enumerate()
        .map(|(lane_idx, carrier)| {
            json!({
                "instructions": carrier.words,
                "metadata": {
                    "source": "generated_initial_corpus",
                    "label": "accounting_derived_segment_capacity_loop",
                    "carrier_lane": "accounting_derived_control_done",
                    "lane_idx": lane_idx,
                    "loop_body_family": carrier.family.label(),
                    "loop_bound": carrier.loop_bound,
                    "counter_register": carrier.family.counter_register(),
                    "state_registers": carrier.family.state_registers(),
                    "setup_cycles": carrier.setup_cycles,
                    "body_cycles": carrier.body_cycles,
                    "accounting": {
                        "segment_po2": CARRIER_SEGMENT_PO2,
                        "capacity_cycles": accounting.capacity_cycles,
                        "lookup_table_cycles": accounting.lookup_table_cycles,
                        "pager_cycles": accounting.pager_cycles,
                        "program_user_cycles": accounting.program_user_cycles,
                        "termination_user_cycles": TERMINATION_SEQUENCE_USER_CYCLES,
                        "user_cycles": accounting.user_cycles,
                        "legacy_accounted_cycles": accounting.capacity_cycles,
                        "control_done_cycles": CONTROL_DONE_CYCLES,
                        "required_cycles": accounting.required_cycles,
                    },
                }
            })
            .to_string()
        })
        .collect()
}

fn segment_capacity_augmented_contents(original_contents: &str) -> (String, usize) {
    let carrier_lines = segment_capacity_carrier_lines();
    let mut contents = carrier_lines.join("\n");
    contents.push('\n');
    if !original_contents.is_empty() {
        contents.push_str(original_contents);
        if !original_contents.ends_with('\n') {
            contents.push('\n');
        }
    }
    (contents, carrier_lines.len())
}

fn write_segment_capacity_augmented_seed_jsonl(root: &Path, original: &Path) -> (PathBuf, usize) {
    let original_contents = std::fs::read_to_string(original)
        .unwrap_or_else(|err| panic!("read ordinary seeds JSONL {}: {err}", original.display()));
    let (contents, carrier_count) = segment_capacity_augmented_contents(&original_contents);

    let ts_millis = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let dir = root.join("storage/fuzzing_seeds");
    std::fs::create_dir_all(&dir).expect("create storage/fuzzing_seeds");
    let path = dir.join(format!(
        ".tmp-risc0-segment-capacity-corpus-{ts_millis}-pid{}.jsonl",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("write segment-capacity augmented seed jsonl");
    (path, carrier_count)
}

fn effective_initial_limit(requested: usize, carrier_count: usize, inline: bool) -> usize {
    if inline {
        1
    } else if requested == 0 {
        0
    } else {
        requested.saturating_add(carrier_count)
    }
}

fn main() {
    let matches = Command::new("beak-fuzz")
        .about("Initial-corpus benchmark with semantic trace search (oracle vs RISC0).")
        .arg(
            Arg::new("bin")
                .long("bin")
                .help("Hex encoded RISC-V instruction word(s). Can be repeated, or passed as a space/comma separated list.")
                .num_args(1..)
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("seeds_jsonl")
                .long("seeds-jsonl")
                .default_value("storage/fuzzing_seeds/initial.jsonl"),
        )
        .arg(Arg::new("initial_limit").long("initial-limit").default_value("0"))
        .arg(
            Arg::new("mutation_iters")
                .long("mutation-iters")
                .alias("iters")
                .default_value("0"),
        )
        .arg(Arg::new("max_instructions").long("max-instructions").default_value("256"))
        .arg(
            Arg::new("long_tail_max_instructions")
                .long("long-tail-max-instructions")
                .default_value("0")
                .help("Absolute length ceiling for long-tail scheduling; 0 keeps the hard cap at max-instructions."),
        )
        .arg(Arg::new("semantic_window_before").long("semantic-window-before").default_value("8"))
        .arg(Arg::new("semantic_window_after").long("semantic-window-after").default_value("24"))
        .arg(Arg::new("semantic_step_stride").long("semantic-step-stride").default_value("1"))
        .arg(
            Arg::new("semantic_max_trials_per_bucket")
                .long("semantic-max-trials-per-bucket")
                .default_value("32"),
        )
        .arg(
            Arg::new("oracle_precheck_max_steps")
                .long("oracle-precheck-max-steps")
                .default_value("32"),
        )
        .arg(
            Arg::new("oracle_memory_model")
                .long("oracle-memory-model")
                .default_value("split-code-data"),
        )
        .arg(
            Arg::new("oracle_code_base")
                .long("oracle-code-base")
                .default_value("0x10004"),
        )
        .arg(
            Arg::new("oracle_data_size_bytes")
                .long("oracle-data-size-bytes")
                .default_value("0"),
        )
        .get_matches();

    let root = workspace_root();
    let inline_words = collect_bin_words(&matches);
    let (seeds_path, carrier_count) = if inline_words.is_empty() {
        let ordinary_seeds = resolve_path(&root, matches.get_one::<String>("seeds_jsonl").unwrap());
        write_segment_capacity_augmented_seed_jsonl(&root, &ordinary_seeds)
    } else {
        (write_inline_seed_jsonl(&root, &inline_words), 0)
    };
    let requested_initial_limit: usize =
        matches.get_one::<String>("initial_limit").unwrap().parse().expect("initial-limit");
    let requested_mutation_iterations: usize =
        matches.get_one::<String>("mutation_iters").unwrap().parse().expect("mutation-iters");
    let requested_max_instructions: usize =
        matches.get_one::<String>("max_instructions").unwrap().parse().expect("max-instructions");
    let requested_long_tail_max: usize = matches
        .get_one::<String>("long_tail_max_instructions")
        .unwrap()
        .parse()
        .expect("long-tail-max-instructions");
    let precheck_oracle_max_steps: u32 = matches
        .get_one::<String>("oracle_precheck_max_steps")
        .unwrap()
        .parse()
        .expect("oracle-precheck-max-steps");
    let semantic_window_before: u64 = matches
        .get_one::<String>("semantic_window_before")
        .unwrap()
        .parse()
        .expect("semantic-window-before");
    let semantic_window_after: u64 = matches
        .get_one::<String>("semantic_window_after")
        .unwrap()
        .parse()
        .expect("semantic-window-after");
    let semantic_step_stride: u64 = matches
        .get_one::<String>("semantic_step_stride")
        .unwrap()
        .parse()
        .expect("semantic-step-stride");
    let semantic_max_trials_per_bucket: usize = matches
        .get_one::<String>("semantic_max_trials_per_bucket")
        .unwrap()
        .parse()
        .expect("semantic-max-trials-per-bucket");
    let oracle_memory_model =
        OracleMemoryModel::parse(matches.get_one::<String>("oracle_memory_model").unwrap())
            .expect("oracle-memory-model");
    let oracle_code_base =
        parse_u32_arg(matches.get_one::<String>("oracle_code_base").unwrap(), "oracle-code-base");
    let oracle_data_size_bytes = parse_u32_arg(
        matches.get_one::<String>("oracle_data_size_bytes").unwrap(),
        "oracle-data-size-bytes",
    );

    let initial_limit =
        effective_initial_limit(requested_initial_limit, carrier_count, !inline_words.is_empty());
    let mutation_iterations: usize =
        if inline_words.is_empty() { requested_mutation_iterations } else { 0 };
    let max_instructions: usize = if inline_words.is_empty() {
        requested_max_instructions
    } else {
        inline_words.len().max(1)
    };
    let long_tail_max_instructions: usize = if inline_words.is_empty() {
        requested_long_tail_max
    } else {
        0
    };
    let backend_max_instructions = long_tail_max_instructions.max(max_instructions);

    let cfg = BenchmarkConfig {
        zkvm_tag: "risc0".to_string(),
        zkvm_commit: ZKVM_COMMIT.to_string(),
        rng_seed: DEFAULT_RNG_SEED,
        oracle: OracleConfig {
            memory_model: oracle_memory_model,
            code_base: oracle_code_base,
            data_size_bytes: oracle_data_size_bytes,
        },
        seeds_jsonl: seeds_path,
        out_dir: root.join("storage/fuzzing_seeds"),
        output_prefix: None,
        initial_limit,
        mutation_iterations,
        max_instructions,
        long_tail_max_instructions,
        precheck_oracle_max_steps,
        semantic_search_enabled: true,
        semantic_window_before,
        semantic_window_after,
        semantic_step_stride,
        semantic_max_trials_per_bucket,
        stack_size_bytes: 256 * 1024 * 1024,
    };

    println!("oracle_code_base = 0x{RISC0_ORACLE_CODE_BASE:08x}");
    println!("ordinary_segment_capacity_carriers = {carrier_count}");
    let res = run_benchmark_threaded(cfg, move || Risc0Backend::new(backend_max_instructions));
    match res {
        Ok(out) => {
            println!("Wrote corpus JSONL: {}", out.corpus_path.display());
            println!("Wrote bugs JSONL: {}", out.bugs_path.display());
            if let Some(runs_path) = out.runs_path.as_ref() {
                println!("Wrote runs JSONL: {}", runs_path.display());
            }
        }
        Err(e) => {
            eprintln!("benchmark failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        effective_initial_limit, segment_capacity_accounting, segment_capacity_augmented_contents,
        segment_capacity_carrier_lines, segment_capacity_carriers, LoopBodyFamily,
        CONTROL_DONE_CYCLES, TERMINATION_SEQUENCE_USER_CYCLES,
    };

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct ExecutedState {
        registers: [u32; 32],
        executed_steps: u64,
        visited_pcs: BTreeSet<u32>,
    }

    fn sign_extend(raw: u32, bits: u32) -> i32 {
        ((raw << (u32::BITS - bits)) as i32) >> (u32::BITS - bits)
    }

    fn execute_counted_loop(words: &[u32]) -> ExecutedState {
        let mut registers = [0u32; 32];
        let mut executed_steps = 0u64;
        let mut visited_pcs = BTreeSet::new();
        let mut pc = 0u32;

        while let Some(&word) = words.get((pc / 4) as usize) {
            assert_eq!(pc % 4, 0, "carrier jumped to an unaligned PC");
            assert!(executed_steps < 100_000, "carrier model did not terminate");
            visited_pcs.insert(pc);
            executed_steps += 1;

            let opcode = word & 0x7f;
            let rd = ((word >> 7) & 0x1f) as usize;
            let rs1 = ((word >> 15) & 0x1f) as usize;
            let rs2 = ((word >> 20) & 0x1f) as usize;
            match opcode {
                0x13 => {
                    assert_eq!((word >> 12) & 0x7, 0, "model only accepts ADDI");
                    let imm = sign_extend(word >> 20, 12) as u32;
                    if rd != 0 {
                        registers[rd] = registers[rs1].wrapping_add(imm);
                    }
                    pc = pc.wrapping_add(4);
                }
                0x37 => {
                    if rd != 0 {
                        registers[rd] = word & 0xffff_f000;
                    }
                    pc = pc.wrapping_add(4);
                }
                0x33 => {
                    let result = match ((word >> 25) & 0x7f, (word >> 12) & 0x7) {
                        (0, 0) => registers[rs1].wrapping_add(registers[rs2]),
                        (0, 4) => registers[rs1] ^ registers[rs2],
                        selector => panic!("unsupported carrier R-type selector {selector:?}"),
                    };
                    if rd != 0 {
                        registers[rd] = result;
                    }
                    pc = pc.wrapping_add(4);
                }
                0x63 => {
                    assert_eq!((word >> 12) & 0x7, 4, "model only accepts BLT");
                    let raw_imm = (((word >> 31) & 1) << 12)
                        | (((word >> 7) & 1) << 11)
                        | (((word >> 25) & 0x3f) << 5)
                        | (((word >> 8) & 0x0f) << 1);
                    let offset = sign_extend(raw_imm, 13);
                    if (registers[rs1] as i32) < (registers[rs2] as i32) {
                        pc = pc.wrapping_add(offset as u32);
                    } else {
                        pc = pc.wrapping_add(4);
                    }
                }
                _ => panic!("unsupported carrier opcode 0x{opcode:02x}"),
            }
            registers[0] = 0;
        }

        ExecutedState { registers, executed_steps, visited_pcs }
    }

    #[test]
    fn carrier_budget_is_derived_from_snapshot_accounting() {
        let accounting = segment_capacity_accounting();
        assert_eq!(
            accounting.user_cycles + accounting.pager_cycles + accounting.lookup_table_cycles,
            accounting.capacity_cycles,
        );
        assert_eq!(
            accounting.program_user_cycles + TERMINATION_SEQUENCE_USER_CYCLES,
            accounting.user_cycles,
        );
        assert_eq!(
            accounting.required_cycles,
            accounting.capacity_cycles + CONTROL_DONE_CYCLES,
        );
    }

    #[test]
    fn ordinary_carriers_are_byte_and_executed_state_distinct_from_history() {
        let historical_words = vec![
            0x0000_0713,
            0x0000_37b7,
            0x4657_8793,
            0x0000_0013,
            0x0017_0713,
            0xfef7_4ee3,
        ];
        let historical_state = execute_counted_loop(&historical_words);
        let accounting = segment_capacity_accounting();
        let carriers = segment_capacity_carriers();
        assert_eq!(carriers.len(), LoopBodyFamily::ALL.len());

        let mut byte_identities = BTreeSet::new();
        let mut executed_identities = BTreeSet::new();
        for carrier in carriers {
            let state = execute_counted_loop(&carrier.words);
            assert_ne!(carrier.words, historical_words, "historical byte row was regenerated");
            assert_ne!(
                state.registers, historical_state.registers,
                "carrier reproduced the historical final register state"
            );
            assert_eq!(state.executed_steps, accounting.program_user_cycles);
            assert_eq!(state.registers[carrier.family.counter_register() as usize], carrier.loop_bound);
            assert_eq!(
                carrier.setup_cycles + carrier.body_cycles * carrier.loop_bound as u64,
                accounting.program_user_cycles,
            );
            assert_eq!(carrier.words.len() as u64, carrier.setup_cycles + carrier.body_cycles);
            byte_identities.insert(carrier.words);
            executed_identities.insert(state);
        }

        assert_eq!(byte_identities.len(), LoopBodyFamily::ALL.len());
        assert_eq!(executed_identities.len(), LoopBodyFamily::ALL.len());
        assert_eq!(historical_state.executed_steps, accounting.program_user_cycles);
    }

    #[test]
    fn ordinary_carrier_rows_publish_the_accounting_and_state_family() {
        let lines = segment_capacity_carrier_lines();
        assert_eq!(lines.len(), LoopBodyFamily::ALL.len());

        let mut observed_families = BTreeSet::new();
        for line in &lines {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(row["metadata"]["source"], "generated_initial_corpus");
            assert_eq!(row["metadata"]["carrier_lane"], "accounting_derived_control_done");
            assert!(row["metadata"]["loop_bound"].as_u64().unwrap() > 0);
            assert!(row["metadata"]["body_cycles"].as_u64().unwrap() >= 3);
            assert!(row["metadata"]["state_registers"].as_array().unwrap().len() >= 3);
            assert_eq!(
                row["metadata"]["accounting"]["legacy_accounted_cycles"],
                row["metadata"]["accounting"]["capacity_cycles"],
            );
            observed_families.insert(
                row["metadata"]["loop_body_family"].as_str().unwrap().to_string(),
            );
        }

        let expected = LoopBodyFamily::ALL
            .into_iter()
            .map(|family| family.label().to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(observed_families, expected);
        let serialized = lines.join("\n");
        assert!(!serialized.contains("Risc0-ControlDone-Cycle-01"));
        assert!(!serialized.contains("cycles <= 1 << segment.po2"));
    }

    #[test]
    fn ordinary_initial_limit_keeps_the_requested_corpus_plus_the_carrier_family() {
        let carrier_count = LoopBodyFamily::ALL.len();
        assert_eq!(effective_initial_limit(0, carrier_count, false), 0);
        assert_eq!(effective_initial_limit(12, carrier_count, false), 12 + carrier_count);
        assert_eq!(effective_initial_limit(12, carrier_count, true), 1);
    }

    #[test]
    fn ordinary_carriers_are_prepended_without_replacing_the_requested_corpus() {
        let original = r#"{"instructions":[19],"metadata":{"source":"ordinary"}}"#;
        let (contents, carrier_count) = segment_capacity_augmented_contents(original);
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(carrier_count, LoopBodyFamily::ALL.len());
        assert_eq!(lines.len(), carrier_count + 1);
        assert_eq!(lines.last(), Some(&original));
        assert!(lines[..carrier_count]
            .iter()
            .all(|line| line.contains("accounting_derived_control_done")));
    }
}
