from __future__ import annotations

import shutil
from pathlib import Path


def _assets_root() -> Path:
    return Path(__file__).resolve().parents[1] / "assets"


def apply(*, risc0_install_path: Path, commit_or_branch: str) -> None:
    _ = commit_or_branch
    asset_root = _assets_root()
    prove_dir = risc0_install_path / "risc0" / "circuit" / "rv32im" / "src" / "prove"
    prove_dir.mkdir(parents=True, exist_ok=True)

    witgen_mod = prove_dir / "witgen" / "mod.rs"
    beak_src = asset_root / "risc0" / "circuit" / "rv32im" / "src" / "prove" / "beak.rs"
    if witgen_mod.exists():
        witgen_mod_contents = witgen_mod.read_text(encoding="utf-8")
        if "pub struct PreflightResults" not in witgen_mod_contents:
            beak_src = (
                asset_root / "risc0" / "circuit" / "rv32im" / "src" / "prove" / "beak_legacy.rs"
            )

    shutil.copyfile(beak_src, prove_dir / "beak.rs")

    mod_rs = prove_dir / "mod.rs"
    contents = mod_rs.read_text(encoding="utf-8")
    marker = "pub mod beak;\n"
    if marker in contents:
        return

    anchor = "#[cfg(test)]\nmod tests;\n"
    if anchor in contents:
        contents = contents.replace(anchor, anchor + marker, 1)
    else:
        contents = marker + contents
    mod_rs.write_text(contents, encoding="utf-8")

