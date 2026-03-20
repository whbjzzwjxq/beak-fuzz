import logging
import shutil
from pathlib import Path

from risc0_fuzzer.settings import RISC0_ZKVM_GIT_REPOSITORY, resolve_risc0_commit
from zkvm_fuzzer_utils.git import (
    GitException,
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


def _assets_root() -> Path:
    return Path(__file__).resolve().parent / "assets"


def apply_beak_risc0_patches(zkvm_src: Path) -> None:
    asset_root = _assets_root()
    prove_dir = zkvm_src / "risc0/circuit/rv32im/src/prove"
    prove_dir.mkdir(parents=True, exist_ok=True)
    witgen_mod = prove_dir / "witgen/mod.rs"

    beak_src = asset_root / "risc0/circuit/rv32im/src/prove/beak.rs"
    if witgen_mod.exists():
        witgen_mod_contents = witgen_mod.read_text(encoding="utf-8")
        if "pub struct PreflightResults" not in witgen_mod_contents:
            beak_src = asset_root / "risc0/circuit/rv32im/src/prove/beak_legacy.rs"
    beak_dst = prove_dir / "beak.rs"
    shutil.copyfile(beak_src, beak_dst)

    mod_rs = prove_dir / "mod.rs"
    contents = mod_rs.read_text(encoding="utf-8")
    marker = "pub mod beak;\n"
    if marker not in contents:
        anchor = "#[cfg(test)]\nmod tests;\n"
        if anchor in contents:
            contents = contents.replace(anchor, anchor + marker, 1)
        else:
            contents = marker + contents
        mod_rs.write_text(contents, encoding="utf-8")


def clone_and_checkout_risc0(
    *, dest: Path, commit_or_branch: str, zkvm_src: Path | None = None
) -> Path:
    resolved = resolve_risc0_commit(commit_or_branch)
    dest = dest.expanduser().resolve()
    repo = str(zkvm_src.expanduser().resolve()) if zkvm_src else RISC0_ZKVM_GIT_REPOSITORY

    if dest.exists() and not is_git_repository(dest):
        shutil.rmtree(dest)

    if not is_git_repository(dest):
        logger.info("cloning risc0 repo to %s", dest)
        git_clone_and_switch(dest, repo, resolved)
    else:
        logger.info("resetting and switching risc0 repo @ %s", dest)
        try:
            git_reset_and_switch(dest, resolved)
        except GitException:
            logger.warning("risc0 repo at %s is invalid; recloning", dest)
            shutil.rmtree(dest, ignore_errors=True)
            git_clone_and_switch(dest, repo, resolved)

    apply_beak_risc0_patches(dest)
    return dest
