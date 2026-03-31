from __future__ import annotations

from pathlib import Path

from sp1_fuzzer.settings import SP1_UINT256_DIV_3561_COMMIT

_HINT_RS = ("core", "src", "syscall", "hint.rs")
_UINT256_AIR_RS = ("core", "src", "syscall", "precompiles", "uint256", "air.rs")
_PROGRAM_DIR = ("tests", "beak-uint256-div")

_PROGRAM_CARGO = """[workspace]
[package]
name = "beak-uint256-div"
version = "0.1.0"
edition = "2021"

[dependencies]
sp1-zkvm = { path = "../../zkvm/entrypoint" }
sp1-derive = { path = "../../derive" }
"""

_PROGRAM_MAIN = """#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::io;
use sp1_zkvm::precompiles::uint256_div::uint256_div;

fn main() {
    let mut dividend = io::read::<[u8; 32]>();
    let divisor = io::read::<[u8; 32]>();
    let quotient = uint256_div(&mut dividend, &divisor);
    io::commit(&quotient);
}
"""


def _insert_after(contents: str, *, anchor: str, insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        return contents
    pos = idx + len(anchor)
    return contents[:pos] + insert + contents[pos:]


def _patch_hint_source(sp1_install_path: Path) -> None:
    path = sp1_install_path.joinpath(*_HINT_RS)
    if not path.exists():
        return

    contents = path.read_text()

    contents = _insert_after(
        contents,
        anchor="use crate::runtime::{Syscall, SyscallContext};\n",
        guard="// BEAK-INSERT: sp1.uint256_div.hint_inject_helpers",
        insert="""
use num::BigUint;

const BEAK_DIV_REM_BOUND_INJECT_KIND: &str = "sp1.semantic.arithmetic.division_remainder_bound";

// BEAK-INSERT: sp1.uint256_div.hint_inject_helpers
fn beak_inject_variant_value<'a>(kind: &'a str, key: &str) -> Option<&'a str> {
    let (_, variant) = kind.split_once("::")?;
    for field in variant.split(',') {
        let (field_key, field_value) = field.split_once('=')?;
        if field_key == key {
            return Some(field_value);
        }
    }
    None
}

fn beak_configured_injection_kind(base_kind: &str) -> Option<String> {
    let kind = std::env::var("BEAK_SP1_WITNESS_INJECT_KIND").ok()?;
    let configured_base = kind
        .split_once("::")
        .map(|(base, _)| base)
        .unwrap_or(kind.as_str());
    if configured_base == base_kind {
        Some(kind)
    } else {
        None
    }
}

fn beak_state_vec_as_bytes32(vec: &[u8]) -> Option<[u8; 32]> {
    if vec.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(vec);
    Some(out)
}

fn beak_try_apply_div_rem_bound_mutation(
    state: &mut crate::runtime::ExecutionState,
    quotient_idx: usize,
    kind: &str,
) -> bool {
    if matches!(beak_inject_variant_value(kind, "mode"), Some("noop_prefix")) {
        return false;
    }

    let remainder_idx = quotient_idx.saturating_add(1);
    let Some(dividend_bytes) = state.input_stream.get(0).and_then(|vec| beak_state_vec_as_bytes32(vec))
    else {
        return false;
    };
    let Some(divisor_bytes) = state.input_stream.get(1).and_then(|vec| beak_state_vec_as_bytes32(vec))
    else {
        return false;
    };
    let Some(quotient_bytes) = state
        .input_stream
        .get(quotient_idx)
        .and_then(|vec| beak_state_vec_as_bytes32(vec))
    else {
        return false;
    };
    let Some(remainder_bytes) = state
        .input_stream
        .get(remainder_idx)
        .and_then(|vec| beak_state_vec_as_bytes32(vec))
    else {
        return false;
    };

    let dividend = BigUint::from_bytes_le(&dividend_bytes);
    let quotient = BigUint::from_bytes_le(&quotient_bytes);
    let remainder = BigUint::from_bytes_le(&remainder_bytes);
    let divisor = BigUint::from_bytes_le(&divisor_bytes);
    if quotient == BigUint::from(0u8) || divisor == BigUint::from(0u8) {
        return false;
    }
    if &quotient * &divisor != &dividend - &remainder {
        return false;
    }

    let mutated_quotient = &quotient - BigUint::from(1u8);
    let mutated_remainder = remainder + divisor;

    let mut mutated_quotient_bytes = mutated_quotient.to_bytes_le();
    mutated_quotient_bytes.resize(32, 0u8);

    let mut mutated_remainder_bytes = mutated_remainder.to_bytes_le();
    mutated_remainder_bytes.resize(32, 0u8);
    state.input_stream[quotient_idx] = mutated_quotient_bytes;
    state.input_stream[remainder_idx] = mutated_remainder_bytes;
    true
}
// BEAK-INSERT-END
""",
    )

    contents = _insert_after(
        contents,
        anchor="        if ctx.rt.state.input_stream_ptr >= ctx.rt.state.input_stream.len() {\n            panic!(\"not enough vecs in hint input stream\");\n        }\n",
        guard="// BEAK-INSERT: sp1.uint256_div.hint_inject_call",
        insert="""
        // BEAK-INSERT: sp1.uint256_div.hint_inject_call
        let input_stream_ptr = ctx.rt.state.input_stream_ptr;
        if let Some(kind) = beak_configured_injection_kind(BEAK_DIV_REM_BOUND_INJECT_KIND) {
            let _ = beak_try_apply_div_rem_bound_mutation(
                &mut ctx.rt.state,
                input_stream_ptr,
                kind.as_str(),
            );
        }
        // BEAK-INSERT-END
""",
    )

    path.write_text(contents)


def _create_program(sp1_install_path: Path) -> None:
    program_dir = sp1_install_path.joinpath(*_PROGRAM_DIR)
    (program_dir / "src").mkdir(parents=True, exist_ok=True)
    (program_dir / "Cargo.toml").write_text(_PROGRAM_CARGO)
    (program_dir / "src" / "main.rs").write_text(_PROGRAM_MAIN)


def _patch_uint256_air(sp1_install_path: Path) -> None:
    path = sp1_install_path.joinpath(*_UINT256_AIR_RS)
    if not path.exists():
        return
    contents = path.read_text()
    old = "        let modulus_limbs = limbs_from_access(&local.modulus_memory);"
    new = (
        "        let modulus_limbs: Limbs<AB::Var, <U256Field as NumLimbs>::Limbs> =\n"
        "            limbs_from_access(&local.modulus_memory);"
    )
    if old in contents and new not in contents:
        path.write_text(contents.replace(old, new, 1))


def apply(*, sp1_install_path: Path, commit_or_branch: str) -> None:
    if commit_or_branch != SP1_UINT256_DIV_3561_COMMIT:
        return
    _patch_hint_source(sp1_install_path)
    _patch_uint256_air(sp1_install_path)
    _create_program(sp1_install_path)
