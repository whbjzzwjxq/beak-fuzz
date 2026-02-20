from jolt_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

# NOTE: "all" is a convenience option that iterates over the supported commits.
JOLT_AVAILABLE_COMMITS_OR_BRANCHES = [
    "all",
    "main",
    # Keep parity with arguzz's curated snapshots.
    "1687134d117a19d1f6c6bd03fd23191013c53d1b",
    "0369981446471c2ed2c4a4d2f24d61205a2d0853",
    "d59219a0633d91dc5dbe19ade5f66f179c27c834",
    "0582b2aa4a33944506d75ce891db7cf090814ff6",
    "57ea518d6d9872fb221bf6ac97df1456a5494cf2",
    "20ac6eb526af383e7b597273990b5e4b783cc2a6",
    "70c77337426615b67191b301e9175e2bb093830d",
    "55b9830a3944dde55d33a55c42522b81dd49f87a",
    "42de0ca1f581dd212dda7ff44feee806556531d2",
    "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788",
    "e9caa23565dbb13019afe61a2c95f51d1999e286",
]
JOLT_ZKVM_GIT_REPOSITORY = "https://github.com/DanielHoffmann91/jolt.git"


def get_rust_toolchain_version(commit_or_branch: str) -> str:
    # Mirrors arguzz: a few snapshots require nightly.
    if commit_or_branch in [
        "55b9830a3944dde55d33a55c42522b81dd49f87a",
        "42de0ca1f581dd212dda7ff44feee806556531d2",
        "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788",
        "e9caa23565dbb13019afe61a2c95f51d1999e286",
    ]:
        return "nightly-2025-04-06"
    return "1.88"


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
