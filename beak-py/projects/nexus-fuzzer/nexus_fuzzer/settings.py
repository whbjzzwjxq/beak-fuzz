NEXUS_BENCHMARK_ALIAS = "bmk-nexus"
NEXUS_BENCHMARK_COMMIT = "636ccb360d0f4ae657ae4bb64e1e275ccec8826"
NEXUS_MEMORY_SIZE_COMMIT = "41c6c6080f46b97980053c47b078321225b4338a"
NEXUS_STWO_COMMIT = "a194fad63ea75d93e5fe5a4ef50029dccadc51c1"

NEXUS_AVAILABLE_COMMITS_OR_BRANCHES = [
    NEXUS_BENCHMARK_ALIAS,
    NEXUS_BENCHMARK_COMMIT,
    NEXUS_MEMORY_SIZE_COMMIT,
    "main",
]

NEXUS_ZKVM_GIT_REPOSITORY = "https://github.com/nexus-xyz/nexus-zkvm.git"
NEXUS_STWO_GIT_REPOSITORY = "https://github.com/starkware-libs/stwo.git"


def resolve_nexus_commit(commit_or_branch: str) -> str:
    if commit_or_branch == NEXUS_BENCHMARK_ALIAS:
        return NEXUS_BENCHMARK_COMMIT
    return commit_or_branch
