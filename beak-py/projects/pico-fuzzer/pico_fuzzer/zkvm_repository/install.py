import logging
import shutil
from pathlib import Path

from pico_fuzzer.settings import (
    PICO_ZKVM_GIT_REPOSITORY,
    RUST_TOOLCHAIN_VERSION,
)
from pico_fuzzer.zkvm_repository.injection import pico_bool_domain_is_real_fault_injection
from zkvm_fuzzer_utils.cmd import invoke_command
from zkvm_fuzzer_utils.file import path_to_binary, replace_in_file
from zkvm_fuzzer_utils.git import (
    GitException,
    git_checkout,
    git_clone_and_switch,
    git_clean,
    git_fetch,
    git_reset_hard,
    is_git_repository,
)
from zkvm_fuzzer_utils.rust.cargo import CargoCmd

logger = logging.getLogger("fuzzer")

RUSTUP = path_to_binary("rustup")


class PicoManagerException(Exception):
    pass


def install_pico(
    pico_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,  # reserved for future parity
):
    logger.info(f"installing pico zkvm @ {pico_install_path}")

    if commit_or_branch == "all":
        raise PicoManagerException("'all' is not a valid install target; pick a concrete commit")

    if not is_git_repository(pico_install_path):
        logger.info(f"cloning pico repo to {pico_install_path}")
        git_clone_and_switch(pico_install_path, PICO_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        logger.info(f"resetting and switching pico repo @ {pico_install_path}")
        git_reset_hard(pico_install_path)
        git_clean(pico_install_path)
        try:
            git_checkout(pico_install_path, commit_or_branch)
        except GitException:
            # Fallback: fetch (network) in case the commit is not available locally yet.
            git_fetch(pico_install_path)
            git_checkout(pico_install_path, commit_or_branch)

    if enable_zkvm_modification:
        logger.info("applying pico zkvm modifications (fault injection hooks)")
        pico_bool_domain_is_real_fault_injection(pico_install_path)

    # Pico currently enables a `strict` feature by default in `pico-vm`, which promotes warnings
    # (including deprecations from transitive deps) to hard errors. For fuzzing, prefer a buildable
    # harness; we disable `strict` in the checked-out repo after each reset/checkout.
    #
    # This is intentionally applied *after* checkout, because install resets the repo each time.
    try:
        vm_cargo_toml = pico_install_path / "vm" / "Cargo.toml"
        replace_in_file(
            vm_cargo_toml,
            [
                (r',\s*"strict"\s*', ""),  # remove trailing strict
                (r'"strict"\s*,\s*', ""),  # remove leading strict
            ],
        )
    except FileNotFoundError:
        # Older/newer layouts may not have this crate path.
        logger.warning("Unable to find pico-vm Cargo.toml to disable strict feature")

    # `cargo pico build` uses `-Z build-std`, which requires the `rust-src` component for the
    # selected toolchain (otherwise it fails looking for `library/Cargo.lock`).
    rust_src = invoke_command(
        [RUSTUP, "component", "add", "rust-src", "--toolchain", RUST_TOOLCHAIN_VERSION]
    )
    if rust_src.is_failure():
        logger.critical(f"Unable to install rust-src for toolchain {RUST_TOOLCHAIN_VERSION}")
        logger.info(rust_src)
        raise RuntimeError("failed to install rust-src")

    # Install cargo subcommand: `cargo pico ...`
    #
    # NOTE: `pico-vm` has a default `strict` feature, which can promote warnings to errors
    # (e.g. deprecations in transitive deps). Cap lints so CLI installation is resilient.
    #
    # This step also requires crates.io index access; to keep Loop1 runnable under flaky network,
    # skip re-installing if `cargo-pico` is already present in PATH.
    if shutil.which("cargo-pico") is not None:
        logger.info("cargo-pico already installed; skipping pico-cli install")
        return

    pico_cli_path = pico_install_path / "sdk" / "cli"
    install_run = (
        CargoCmd.install()
        .with_toolchain(RUST_TOOLCHAIN_VERSION)
        .with_path(Path("."))
        .with_cd(pico_cli_path)
        .with_env(
            {
                "RUSTFLAGS": "--cap-lints allow",
                "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
            }
        )
        .use_force()
        .use_locked()
        .execute()
    )
    if install_run.is_failure():
        logger.info(install_run)
        logger.critical(f"Unable to install pico-cli binary from {pico_cli_path}")
        raise RuntimeError("failed to install pico-cli")
