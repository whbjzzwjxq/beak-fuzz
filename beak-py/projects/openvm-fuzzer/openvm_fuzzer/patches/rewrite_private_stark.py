from pathlib import Path
import re
from openvm_fuzzer.settings import (
    OPENVM_BENCHMARK_336F_COMMIT,
    OPENVM_BENCHMARK_F038_COMMIT,
    OPENVM_BENCHMARK_REGZERO_COMMIT,
    resolve_openvm_commit,
)

_PLONKY3_TAG_BY_REV = {
    "539bbc84085efb609f4f62cb03cf49588388abdb": "v1.2.0-rc.0",
    "b0591e9": "v1.0.0-rc.0",
    "88d7f05": "v1.0.0-rc.2",
}

_STARK_BACKEND_TAG_BY_COMMIT = {
    OPENVM_BENCHMARK_REGZERO_COMMIT: "v1.2.0-rc.0",
    OPENVM_BENCHMARK_336F_COMMIT: "v1.0.0-rc.0",
    OPENVM_BENCHMARK_F038_COMMIT: "v1.0.0-rc.2",
}


def apply(*, openvm_install_path: Path, commit_or_branch: str) -> None:
    _rewrite_private_stark_backend(
        openvm_install_path=openvm_install_path, commit_or_branch=commit_or_branch
    )


def _resolve_stark_backend_tag(contents: str, commit_or_branch: str) -> str:
    resolved_commit = resolve_openvm_commit(commit_or_branch)
    if resolved_commit in _STARK_BACKEND_TAG_BY_COMMIT:
        return _STARK_BACKEND_TAG_BY_COMMIT[resolved_commit]

    match = re.search(r'Plonky3\\.git", rev = "([0-9a-f]+)"', contents)
    if match:
        plonky3_rev = match.group(1)
        if plonky3_rev in _PLONKY3_TAG_BY_REV:
            return _PLONKY3_TAG_BY_REV[plonky3_rev]

    return "v1.0.0-rc.2"


def _rewrite_private_stark_backend(openvm_install_path: Path, commit_or_branch: str):
    cargo_toml = openvm_install_path / "Cargo.toml"
    if not cargo_toml.exists():
        return
    contents = cargo_toml.read_text()
    if "stark-backend-private" not in contents:
        return
    tag = _resolve_stark_backend_tag(contents, commit_or_branch)
    contents = contents.replace(
        "ssh://git@github.com/axiom-crypto/stark-backend-private.git",
        "https://github.com/openvm-org/stark-backend.git",
    )
    contents = re.sub(
        r"(openvm-stark-(?:backend|sdk) = \\{[^\\n]*?)(?:rev|tag) = \"[^\"]+\"",
        rf'\\1tag = "{tag}"',
        contents,
    )
    cargo_toml.write_text(contents)
