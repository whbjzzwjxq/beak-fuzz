use std::{fs::File, io::{BufRead, BufReader}, path::PathBuf};

use beak_core::trace::{Trace, semantic};
use beak_risc0_98387806::{backend::run_backend_once, trace::Risc0Trace};
use serde::Deserialize;

const EXEC_SOURCE_BINDING_INJECT_KIND: &str =
    "risc0.semantic.exec.source_operand_binding::src2_from_src1_word";

#[derive(Debug, Deserialize)]
struct SeedMetadata {
    source: String,
    label: String,
}

#[derive(Debug, Deserialize)]
struct SeedRecord {
    instructions: Vec<u32>,
    metadata: SeedMetadata,
}

fn initial_seed_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../storage/fuzzing_seeds/initial.jsonl")
}

#[test]
fn trireg_executor_source_binding_changes_semantics() {
    let words = [0x0070_0113, 0x0050_0193, 0x0231_70b3];

    let baseline = run_backend_once(&words, None, 0).expect("baseline run");
    let injected = run_backend_once(&words, Some(EXEC_SOURCE_BINDING_INJECT_KIND), 2)
        .expect("injected run");

    let baseline_regs = baseline.final_regs.expect("baseline final regs");
    let injected_regs = injected.final_regs.expect("injected final regs");

    assert!(injected.injection_applied, "executor injection did not fire");
    assert_eq!((baseline_regs[1], baseline_regs[2], baseline_regs[3]), (2, 7, 5));
    assert_eq!((injected_regs[1], injected_regs[2], injected_regs[3]), (0, 7, 5));
    assert_ne!(baseline_regs, injected_regs, "executor rewrite should change semantics");

    eprintln!(
        "trireg: baseline x1/x2/x3 = {}/{}/{}, injected x1/x2/x3 = {}/{}/{}",
        baseline_regs[1],
        baseline_regs[2],
        baseline_regs[3],
        injected_regs[1],
        injected_regs[2],
        injected_regs[3],
    );
}

#[test]
fn first_div_family_seed_in_initial_corpus_triggers_exec_source_binding() {
    let seed_file = File::open(initial_seed_path()).expect("open initial seed corpus");
    let reader = BufReader::new(seed_file);

    let mut first_trigger = None;

    for (idx, line) in reader.lines().enumerate() {
        let line = line.expect("read seed line");
        let seed: SeedRecord = serde_json::from_str(&line).expect("parse seed line");
        let trace = match Risc0Trace::from_words(&seed.instructions) {
            Ok(trace) => trace,
            Err(_) => continue,
        };

        let div_family_step = trace.bucket_hits().iter().find_map(|hit| {
            if hit.bucket_id != semantic::exec::SOURCE_OPERAND_BINDING.id {
                return None;
            }
            let mnemonic = hit.details.get("mnemonic")?.as_str()?;
            if !matches!(mnemonic, "div" | "divu" | "rem" | "remu") {
                return None;
            }
            hit.details.get("op_idx")?.as_u64().map(|step| (step, mnemonic.to_string()))
        });

        let Some((step, mnemonic)) = div_family_step else {
            continue;
        };

        let baseline = run_backend_once(&seed.instructions, None, 0).expect("baseline run");
        let injected =
            run_backend_once(&seed.instructions, Some(EXEC_SOURCE_BINDING_INJECT_KIND), step)
                .expect("injected run");

        let baseline_regs = baseline.final_regs.expect("baseline final regs");
        let injected_regs = injected.final_regs.expect("injected final regs");
        if !injected.injection_applied || baseline_regs == injected_regs {
            continue;
        }

        first_trigger = Some((
            idx,
            step,
            mnemonic,
            seed.metadata.source,
            seed.metadata.label,
            seed.instructions,
            baseline_regs,
            injected_regs,
        ));
        break;
    }

    let (
        idx,
        step,
        mnemonic,
        source,
        label,
        words,
        baseline_regs,
        injected_regs,
    ) = first_trigger.expect("no div-family source-binding trigger found in initial corpus");

    assert_eq!(idx, 1832, "unexpected earliest seed index");
    assert_eq!(step, 3, "unexpected trigger step");
    assert_eq!(mnemonic, "div", "unexpected first trigger mnemonic");

    eprintln!(
        "initial first div-family trigger: idx={} step={} mnemonic={} source={} label={} words={:08x?}",
        idx, step, mnemonic, source, label, words
    );
    eprintln!(
        "baseline x10/x14 = {}/{}, injected x10/x14 = {}/{}",
        baseline_regs[10],
        baseline_regs[14],
        injected_regs[10],
        injected_regs[14],
    );
}
