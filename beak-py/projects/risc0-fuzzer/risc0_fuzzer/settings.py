from risc0_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

# NOTE: "all" is a convenience option that iterates over the supported commits.
RISC0_AVAILABLE_COMMITS_OR_BRANCHES = [
    "all",
    "main",
    "ebd64e43e7d953e0edcee2d4e0225b75458d80b5",
    "67f2d81c638bff5f4fcfe11a084ebb34799b7a89",  # <= fix
    "98387806fe8348d87e32974468c6f35853356ad5",  # <= bug
    "31f657014488940913e3ced0367610225ab32ada",  # <= fix
    "4c65c85a1ec6ce7df165ef9c57e1e13e323f7e01",  # <= bug
]
RISC0_ZKVM_GIT_REPOSITORY = "https://github.com/risc0/risc0.git"

#
# Special Timeout handling
#

TIMEOUT_PER_RUN = 60 * 10  # 10 min
TIMEOUT_PER_BUILD = 60 * 60 * 2  # 2 h

#
# Injection Specifics (unused for loop1 baseline)
#

ENABLED_INJECTION_KINDS: list[InjectionKind] = [InjectionKind.NONE]
PREFERRED_INSTRUCTIONS: list[InstrKind] = []

