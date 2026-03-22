RISC0_BENCHMARK_ALIAS = "bmk-risc0"
RISC0_BENCHMARK_COMMIT = "c0db0713671c8ec467b3efc26b22a0b0591897ff"
RISC0_TRI_REG_ALIAS = "bmk-trireg"
RISC0_TRI_REG_COMMIT = "98387806fe8348d87e32974468c6f35853356ad5"

RISC0_V2_0_2_ALIAS = "v2.0.2"

RISC0_AVAILABLE_COMMITS_OR_BRANCHES = [
    RISC0_BENCHMARK_ALIAS,
    RISC0_TRI_REG_ALIAS,
    RISC0_V2_0_2_ALIAS,
    RISC0_BENCHMARK_COMMIT,
    RISC0_TRI_REG_COMMIT,
    "main",
]

RISC0_ZKVM_GIT_REPOSITORY = "https://github.com/risc0/risc0.git"


def resolve_risc0_commit(commit_or_branch: str) -> str:
    if commit_or_branch in (RISC0_BENCHMARK_ALIAS, RISC0_V2_0_2_ALIAS):
        return RISC0_BENCHMARK_COMMIT
    if commit_or_branch == RISC0_TRI_REG_ALIAS:
        return RISC0_TRI_REG_COMMIT
    return commit_or_branch
