from __future__ import annotations

import shutil
from pathlib import Path


def _assets_root() -> Path:
    return Path(__file__).resolve().parents[1] / "assets"


def _executor_asset_name(contents: str) -> str:
    if "FastDecodeTable" in contents:
        return "rv32im_fastdecode.rs"
    return "rv32im_legacy.rs"


def apply(*, risc0_install_path: Path, commit_or_branch: str) -> None:
    _ = commit_or_branch
    executor_rs = (
        risc0_install_path / "risc0" / "circuit" / "rv32im" / "src" / "execute" / "rv32im.rs"
    )
    if not executor_rs.exists():
        return

    contents = executor_rs.read_text(encoding="utf-8")
    asset = (
        _assets_root()
        / "risc0"
        / "circuit"
        / "rv32im"
        / "src"
        / "execute"
        / _executor_asset_name(contents)
    )
    shutil.copyfile(asset, executor_rs)

