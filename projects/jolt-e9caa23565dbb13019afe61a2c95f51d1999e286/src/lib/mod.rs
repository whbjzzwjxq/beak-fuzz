use std::fs;
use std::path::Path;
use std::process::Command;

pub mod backend;
pub mod trace;

pub const JOLT_COMMIT: &str = "e9caa23565dbb13019afe61a2c95f51d1999e286";
pub const JOLT_REPO_URL: &str = "https://github.com/a16z/jolt.git";
pub const JOLT_ORACLE_CODE_BASE: u32 = 0x8000_0000;

pub fn run_checked(cmd: &mut Command) -> Result<(), String> {
    let status = cmd
        .status()
        .map_err(|e| format!("failed to spawn command: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed with status: {status}"))
    }
}

pub fn ensure_jolt_checkout(zkvm_dir: &Path) -> Result<(), String> {
    let parent = zkvm_dir
        .parent()
        .ok_or_else(|| format!("invalid zkvm dir: {}", zkvm_dir.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("create parent dir failed: {e}"))?;

    if !zkvm_dir.join(".git").exists() {
        let mut clone = Command::new("git");
        clone.args(["clone", JOLT_REPO_URL, zkvm_dir.to_string_lossy().as_ref()]);
        run_checked(&mut clone).map_err(|e| format!("git clone failed: {e}"))?;
    }

    let mut fetch = Command::new("git");
    fetch.args([
        "-C",
        zkvm_dir.to_string_lossy().as_ref(),
        "fetch",
        "--all",
        "--tags",
        "--prune",
    ]);
    run_checked(&mut fetch).map_err(|e| format!("git fetch failed: {e}"))?;

    let mut checkout = Command::new("git");
    checkout.args([
        "-C",
        zkvm_dir.to_string_lossy().as_ref(),
        "checkout",
        "--force",
        JOLT_COMMIT,
    ]);
    run_checked(&mut checkout).map_err(|e| format!("git checkout failed: {e}"))?;
    Ok(())
}
