use std::fs;
use std::path::Path;
use std::process::Command;

pub mod backend;
pub mod bucket;
pub mod bucket_id;
pub mod chip_row;
pub mod insn;
pub mod interaction;
pub mod trace;

pub type Pc = u32;
pub type Timestamp = u32;
pub type FieldElement = u32;

pub const SP1_COMMIT: &str = "7f643da16813af4c0fbaad4837cd7409386cf38c";
pub const SP1_REPO_URL: &str = "https://github.com/succinctlabs/sp1.git";

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

pub fn ensure_sp1_checkout(zkvm_dir: &Path) -> Result<(), String> {
    let parent = zkvm_dir
        .parent()
        .ok_or_else(|| format!("invalid zkvm dir: {}", zkvm_dir.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("create parent dir failed: {e}"))?;

    if !zkvm_dir.join(".git").exists() {
        let mut clone = Command::new("git");
        clone.args(["clone", SP1_REPO_URL, zkvm_dir.to_string_lossy().as_ref()]);
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
        SP1_COMMIT,
    ]);
    run_checked(&mut checkout).map_err(|e| format!("git checkout failed: {e}"))?;
    Ok(())
}
