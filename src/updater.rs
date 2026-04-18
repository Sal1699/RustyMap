use anyhow::{anyhow, Result};
use self_update::cargo_crate_version;

const REPO_OWNER: &str = "Sal1699";
const REPO_NAME: &str = "RustyMap";
const BIN_NAME: &str = "rustymap";

fn target_triple() -> &'static str {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "windows-x86_64"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "macos-aarch64"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "linux-x86_64"
    } else {
        "unsupported"
    }
}

pub fn check() -> Result<()> {
    let target = target_triple();
    if target == "unsupported" {
        return Err(anyhow!(
            "auto-update not supported on this platform. Use the installer from https://sal1699.github.io/RustyMap/"
        ));
    }
    let current = cargo_crate_version!();
    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()?
        .fetch()?;
    let latest = releases
        .first()
        .ok_or_else(|| anyhow!("no releases published on github.com/{}/{}", REPO_OWNER, REPO_NAME))?;

    let cmp = self_update::version::bump_is_greater(current, &latest.version).unwrap_or(false);
    if cmp {
        println!("Update available: v{} → v{}", current, latest.version);
        println!("Run: rustymap --update");
    } else {
        println!(
            "RustyMap v{} is up to date (latest published: v{}).",
            current, latest.version
        );
    }
    Ok(())
}

pub fn update() -> Result<()> {
    let target = target_triple();
    if target == "unsupported" {
        return Err(anyhow!(
            "auto-update not supported on this platform. Use the installer from https://sal1699.github.io/RustyMap/"
        ));
    }
    let current = cargo_crate_version!();
    let status = self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .target(target)
        .show_download_progress(true)
        .current_version(current)
        .no_confirm(true)
        .build()?
        .update()?;

    if status.updated() {
        println!("Updated RustyMap v{} → v{}.", current, status.version());
        println!("Run `rustymap --version` to verify.");
    } else {
        println!("Already up to date (v{}).", current);
    }
    Ok(())
}
