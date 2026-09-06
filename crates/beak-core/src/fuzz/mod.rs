pub mod benchmark;
pub mod bug_filter;
pub mod jsonl;
pub mod seed;
pub mod seed_mutation;

/// Preserve every independently observed backend failure without allowing a
/// best-effort `collect_eval` value to erase the `Result::Err` returned by the
/// production execution call. A single error is kept byte-for-byte so typed
/// backend diagnostics and suppression rules remain stable.
pub(crate) fn merge_backend_errors(
    collected: Option<String>,
    returned: Option<String>,
    panicked: Option<String>,
) -> Option<String> {
    let mut errors = Vec::new();
    for error in [collected, returned, panicked].into_iter().flatten() {
        if !errors.iter().any(|seen| seen == &error) {
            errors.push(error);
        }
    }
    match errors.len() {
        0 => None,
        1 => errors.pop(),
        _ => Some(errors.join(" | ")),
    }
}
