from pathlib import Path

from zkvm_fuzzer_utils.rust.panics import RustPanicInfo, parse_panic_info

RUST_NUM_OF_PANICS = 3
RUST_PANIC_MESSAGES = """
========================

thread '<unnamed>' panicked at /root/sp1/crates/core/executor/src/register.rs:114:18:
invalid register 138
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

========================

warning: sp1-host@0.1.0: sp1-guest built at 2025-06-05 14:11:56
    Finished `release` profile [optimized] target(s) in 0.27s
     Running `target/release/sp1-host --in0 1412267577 --in2`

thread 'main' panicked at host/src/main.rs:81:13:
<@> VERIFIER ERROR: Invalid public values
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

========================

   Compiling playground v0.0.1 (/playground)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.05s
     Running `target/debug/playground`

thread 'main' panicked at src/main.rs:3:5:
pan-
ic
stack backtrace:
   0: __rustc::rust_begin_unwind
             at /rustc/17067e9ac6d7ecb70e50f92c1944e545188d2359/library/std/src/panicking.rs:697:5
   1: core::panicking::panic_fmt
             at /rustc/17067e9ac6d7ecb70e50f92c1944e545188d2359/library/core/src/panicking.rs:75:14
   2: playground::main
             at ./src/main.rs:3:5
   3: core::ops::function::FnOnce::call_once

========================
"""


def test_parse_panic_info():
    infos = parse_panic_info(RUST_PANIC_MESSAGES)

    print(infos)

    # check if all panics are found and parsed
    found_panics = len(infos)
    assert (
        found_panics == RUST_NUM_OF_PANICS
    ), f"expected {RUST_NUM_OF_PANICS} panics but found {found_panics}"

    # Found panics should be ordered so
    #   info[0]: invalid register
    #   info[1]: Invalid public values
    #   info[2]: panic

    # inspecting invalid register panic
    assert infos[0] == RustPanicInfo(
        thread="<unnamed>",
        file_dir=Path("/root/sp1/crates/core/executor/src"),
        file_name="register.rs",
        file_line=114,
        file_column=18,
        message="invalid register 138",
    )

    # inspecting invalid public values panic
    assert infos[1] == RustPanicInfo(
        thread="main",
        file_dir=Path("host/src"),
        file_name="main.rs",
        file_line=81,
        file_column=13,
        message="<@> VERIFIER ERROR: Invalid public values",
    )

    # inspecting multiline panic
    assert infos[2] == RustPanicInfo(
        thread="main",
        file_dir=Path("src"),
        file_name="main.rs",
        file_line=3,
        file_column=5,
        message="pan-\nic",
    )
