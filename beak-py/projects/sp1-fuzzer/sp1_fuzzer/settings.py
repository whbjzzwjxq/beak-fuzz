from sp1_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

# NOTE: "all" is a convenience option that iterates over the supported commits.
#
# For audit reproduction we also expose short aliases:
# - `s26`: S26 (+ S28 family) snapshot
# - `s27`: S27 snapshot
# - `s29`: S29 snapshot
#
# These aliases resolve to fixed commit hashes via `resolve_sp1_commit()`.

SP1_S26_COMMIT = "7f643da16813af4c0fbaad4837cd7409386cf38c"
SP1_S27_COMMIT = "f3326e6d0bf78d6b4650ea1e26c501d72fb3c90b"
SP1_S29_COMMIT = "811a3f2c03914088c7c9e1774266934a3f9f5359"

SP1_AVAILABLE_COMMITS_OR_BRANCHES = [
    "all",
    "s26",
    "s27",
    "s29",
    # Fuzzer-maintained vulnerable snapshots (from audit mapping):
    # - `7f643da...`: S26 + S28 family (old architecture)
    # - `f3326e6...`: S27 (v4 CPU chip; is_memory not sent in instruction interaction ABI)
    # - `811a3f2...`: S29 (global interaction kind missing from message)
    SP1_S26_COMMIT,
    SP1_S27_COMMIT,
    SP1_S29_COMMIT,
]
SP1_ZKVM_GIT_REPOSITORY = "https://github.com/succinctlabs/sp1.git"
RUST_TOOLCHAIN_VERSION = "stable"

#
# Special Timeout handling
#

TIMEOUT_PER_RUN = 60 * 4  # 4 min, in seconds
TIMEOUT_PER_BUILD = 60 * 30  # 30 min, in seconds

#
# Injection Specifics (unused for loop1 baseline)
#

ENABLED_INJECTION_KINDS: list[InjectionKind] = [InjectionKind.NONE]
PREFERRED_INSTRUCTIONS: list[InstrKind] = []


def resolve_sp1_commit(commit_or_branch: str) -> str:
    """Resolve a human-friendly alias to its pinned commit hash."""
    if commit_or_branch == "s26":
        return SP1_S26_COMMIT
    if commit_or_branch == "s27":
        return SP1_S27_COMMIT
    if commit_or_branch == "s29":
        return SP1_S29_COMMIT
    return commit_or_branch


def iter_sp1_snapshots() -> list[str]:
    """The canonical set of audit snapshots to exercise in versioned loop1 runs."""
    return ["s26", "s27", "s29"]
