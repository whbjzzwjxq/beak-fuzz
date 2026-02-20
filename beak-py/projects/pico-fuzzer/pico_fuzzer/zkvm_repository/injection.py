import logging
from pathlib import Path

from zkvm_fuzzer_utils.file import replace_in_file

logger = logging.getLogger("fuzzer")


def pico_bool_domain_is_real_fault_injection(pico_install_path: Path) -> None:
    """
    Patch Pico so a malicious prover can set MemoryLocalChip's `is_real` witness column
    to a non-boolean value (e.g. 2) for a chosen local memory event.

    Additionally, introduce a shadow multiplicity column (`is_real_shadow`) that is
    kept honest (0/1) and used for lookups/interactions. This allows beak-fuzz to
    test whether the original `is_real` is only constrained via lookup coupling.

    This is meant to exercise the `multiplicity_bool_domain` bucket (Pico-IsReal-01 in beak-scopes).

    Control via env vars (read during proving):
      - BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL=1
      - BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL_ADDR=<u32>
      - BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL_VALUE=<u32>   (default: 2)
    """

    columns_rs = (
        pico_install_path / "vm" / "src" / "chips" / "chips" / "riscv_memory" / "local" / "columns.rs"
    )
    constraints_rs = (
        pico_install_path
        / "vm"
        / "src"
        / "chips"
        / "chips"
        / "riscv_memory"
        / "local"
        / "constraints.rs"
    )
    traces_rs = (
        pico_install_path / "vm" / "src" / "chips" / "chips" / "riscv_memory" / "local" / "traces.rs"
    )

    for p in (columns_rs, constraints_rs, traces_rs):
        if not p.exists():
            raise FileNotFoundError(f"pico MemoryLocal file not found at {p}")

    columns_content = columns_rs.read_text()
    constraints_content = constraints_rs.read_text()
    traces_content = traces_rs.read_text()

    # 1) Add the shadow column to the local memory entry struct.
    if "is_real_shadow" not in columns_content:
        updated = replace_in_file(
            columns_rs,
            [
                (
                    r"([ \t]*/// Whether the memory access is a real access\.\n[ \t]*pub is_real: T,\n)",
                    r"""\1

    /// Shadow multiplicity used for lookups/interactions (kept honest in traces).
    pub is_real_shadow: T,
""",
                )
            ],
            flags=0,
        )
        if not updated:
            raise RuntimeError(
                "Unable to patch pico MemoryLocal columns.rs (is_real_shadow insertion did not match). "
                "Upstream file likely changed."
            )

    # 2) Route MemoryLocal lookups through the shadow multiplicity.
    #
    # NOTE: We only touch `local.is_real.into()` occurrences used as lookup multiplicities.
    if "local.is_real_shadow.into()" not in constraints_content:
        updated = replace_in_file(
            constraints_rs,
            [(r"\blocal\.is_real\.into\(\)", "local.is_real_shadow.into()")],
            flags=0,
        )
        if not updated:
            raise RuntimeError(
                "Unable to patch pico MemoryLocal constraints.rs (lookup multiplicity replacement did not match). "
                "Upstream file likely changed."
            )

    # Insert deterministic target selection before the parallel trace fill.
    # Match the `values` init line, but do NOT consume indentation from the next line.
    insert_after = (
        r"([ \t]*let mut values = zeroed_f_vec\(padded_nb_rows \* NUM_MEMORY_LOCAL_INIT_COLS\);\n)"
    )
    injection_prelude = r"""\1

        // --- beak-fuzz fault injection (multiplicity_bool_domain / Pico-IsReal-01) ---
        // Allow setting MemoryLocalChip's `is_real` to a non-boolean value (e.g. 2) on a chosen
        // local memory event. This intentionally models an under-constrained boolean domain.
        let beak_inject_enabled = std::env::var("BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL")
            .ok()
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                v == "1" || v == "true" || v == "yes"
            })
            .unwrap_or(false);
        let beak_inject_addr: Option<u32> =
            std::env::var("BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL_ADDR")
                .ok()
                .and_then(|v| v.trim().parse::<u32>().ok());
        let beak_inject_value: u32 = std::env::var("BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL_VALUE")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(2);

        // Pick the *first* matching event index deterministically (avoid rayon scheduling nondeterminism).
        let beak_inject_event_idx: Option<usize> = if beak_inject_enabled {
            if let Some(addr) = beak_inject_addr {
                events.iter().position(|e| e.addr == addr)
            } else if !events.is_empty() {
                // Default: inject the first local memory event to make smoke-testing easy.
                Some(0)
            } else {
                None
            }
        } else {
            None
        };
"""

    if "BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL" not in traces_content:
        updated = replace_in_file(traces_rs, [(insert_after, injection_prelude)], flags=0)
        if not updated:
            raise RuntimeError(
                "Unable to patch pico MemoryLocal traces.rs (prelude insertion did not match). "
                "Upstream file likely changed."
            )
        traces_content = traces_rs.read_text()

    # Replace the concrete witness assignment.
    # Replace only the assignment line (including its newline), without consuming indentation
    # from the following line.
    # Capture only indentation (no newlines), otherwise backreferences can inject extra blank lines.
    replace_pattern = r"([ \t]*)cols\.is_real\s*=\s*F::ONE;\n"
    replace_with = r"""\1cols.is_real = if beak_inject_event_idx == Some(base_event_idx + k) {
\1    F::from_canonical_u32(beak_inject_value)
\1} else {
\1    F::ONE
\1};
"""
    if "cols.is_real = if beak_inject_event_idx" not in traces_content:
        updated = replace_in_file(traces_rs, [(replace_pattern, replace_with)], flags=0)
        if not updated:
            raise RuntimeError(
                "Unable to patch pico MemoryLocal traces.rs (is_real assignment replacement did not match). "
                "Upstream file likely changed."
            )
        traces_content = traces_rs.read_text()

    # 3) Keep the shadow multiplicity honest for real events (independent of injected `is_real`).
    #
    # Insert `cols.is_real_shadow = F::ONE;` after we set values for a real event.
    shadow_insert_pattern = (
        r"([ \t]*cols\.final_value\s*=\s*event\.final_mem_access\.value\.into\(\);\n)"
    )
    shadow_insert_with = r"""\1
                        cols.is_real_shadow = F::ONE;
"""
    if "cols.is_real_shadow" not in traces_content:
        updated = replace_in_file(traces_rs, [(shadow_insert_pattern, shadow_insert_with)], flags=0)
        if not updated:
            raise RuntimeError(
                "Unable to patch pico MemoryLocal traces.rs (is_real_shadow assignment insertion did not match). "
                "Upstream file likely changed."
            )

    logger.info("applied pico multiplicity_bool_domain/is_real fault injection patch")
