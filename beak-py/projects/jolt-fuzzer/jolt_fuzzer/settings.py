JOLT_BENCHMARK_ALIAS = "bmk-jolt"
JOLT_BENCHMARK_COMMIT = "e9caa23565dbb13019afe61a2c95f51d1999e286"

JOLT_AVAILABLE_COMMITS_OR_BRANCHES = [
    JOLT_BENCHMARK_ALIAS,
    JOLT_BENCHMARK_COMMIT,
    "main",
]

JOLT_ZKVM_GIT_REPOSITORY = "https://github.com/a16z/jolt.git"


def resolve_jolt_commit(commit_or_branch: str) -> str:
    if commit_or_branch == JOLT_BENCHMARK_ALIAS:
        return JOLT_BENCHMARK_COMMIT
    return commit_or_branch
