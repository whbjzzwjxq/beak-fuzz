from pico_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

# NOTE: "all" is a convenience option that iterates over the supported commits.
PICO_AVAILABLE_COMMITS_OR_BRANCHES = [
    "all",
    "main",
    # Snapshot used by existing scripts/config in this repo:
    "dd5b7d1f4e164d289d110f1688509a22af6b241c",
]
PICO_ZKVM_GIT_REPOSITORY = "https://github.com/DanielHoffmann91/pico.git"
RUST_TOOLCHAIN_VERSION = "nightly-2024-11-27"

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

