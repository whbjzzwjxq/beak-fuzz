from nexus_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

# Arguzz: Nexus-Operand-01
NEXUS_OPERAND_COMMIT = "636ccb360d0f4ae657ae4bb64e1e275ccec8826"

# NOTE: "all" is a convenience option that iterates over the supported commits.
NEXUS_AVAILABLE_COMMITS_OR_BRANCHES = [
    "all",
    "operand",
    NEXUS_OPERAND_COMMIT,
]
NEXUS_ZKVM_GIT_REPOSITORY = "https://github.com/DanielHoffmann91/nexus-zkvm.git"


def resolve_nexus_commit(commit_or_branch: str) -> str:
    if commit_or_branch == "operand":
        return NEXUS_OPERAND_COMMIT
    return commit_or_branch


def iter_nexus_snapshots() -> list[str]:
    return ["operand"]


def get_rust_toolchain_version(commit_or_branch: str) -> str:
    commit_or_branch = resolve_nexus_commit(commit_or_branch)
    return "nightly-2025-04-06"


def get_riscv_target(commit_or_branch: str) -> str:
    commit_or_branch = resolve_nexus_commit(commit_or_branch)
    return "riscv32im-unknown-none-elf"


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
