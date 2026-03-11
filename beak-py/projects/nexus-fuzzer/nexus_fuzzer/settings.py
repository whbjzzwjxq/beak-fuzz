NEXUS_BENCHMARK_ALIAS = "bmk-nexus"
NEXUS_BENCHMARK_COMMIT = "636ccb360d0f4ae657ae4bb64e1e275ccec8826"

NEXUS_AVAILABLE_COMMITS_OR_BRANCHES = [
    NEXUS_BENCHMARK_ALIAS,
    NEXUS_BENCHMARK_COMMIT,
    "main",
]

NEXUS_ZKVM_GIT_REPOSITORY = "https://github.com/nexus-xyz/nexus-zkvm.git"


def resolve_nexus_commit(commit_or_branch: str) -> str:
    if commit_or_branch == NEXUS_BENCHMARK_ALIAS:
        return NEXUS_BENCHMARK_COMMIT
    return commit_or_branch
