RISC0_BENCHMARK_ALIAS = "bmk-risc0"
RISC0_BENCHMARK_COMMIT = "c0db0713671c8ec467b3efc26b22a0b0591897ff"

RISC0_V2_0_2_ALIAS = "v2.0.2"

RISC0_AVAILABLE_COMMITS_OR_BRANCHES = [
    RISC0_BENCHMARK_ALIAS,
    RISC0_V2_0_2_ALIAS,
    RISC0_BENCHMARK_COMMIT,
    "main",
]

RISC0_ZKVM_GIT_REPOSITORY = "https://github.com/risc0/risc0.git"


def resolve_risc0_commit(commit_or_branch: str) -> str:
    if commit_or_branch in (RISC0_BENCHMARK_ALIAS, RISC0_V2_0_2_ALIAS):
        return RISC0_BENCHMARK_COMMIT
    return commit_or_branch
