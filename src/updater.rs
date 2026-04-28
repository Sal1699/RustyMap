use anyhow::{anyhow, Context, Result};
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

fn asset_name(target: &str) -> &'static str {
    match target {
        "windows-x86_64" => "rustymap-windows-x86_64.zip",
        "macos-aarch64" => "rustymap-macos-aarch64.tar.gz",
        "linux-x86_64" => "rustymap-linux-x86_64.tar.gz",
        _ => "?",
    }
}

/// Writability pre-check for the running binary. Self-update needs to
/// rename(2) the new binary on top of the current one — that requires
/// write access to the parent directory.
fn check_writable() -> Result<()> {
    let exe = std::env::current_exe().context("locate current binary")?;
    let parent = exe
        .parent()
        .ok_or_else(|| anyhow!("binary path has no parent: {:?}", exe))?;
    let probe = parent.join(format!(".rustymap-update-probe-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => {
            let hint = if cfg!(unix) {
                "\n  • Re-run with sudo, or\n  • install into a user-writable path:\n      mkdir -p ~/.local/bin && cp $(which rustymap) ~/.local/bin/"
            } else {
                "\n  • Re-run as Administrator (right-click → Run as Administrator)"
            };
            Err(anyhow!(
                "cannot write next to current binary at {:?}\n  reason: {}{}",
                exe, e, hint
            ))
        }
    }
}

/// Manual download instructions printed when self_update fails — gives
/// the user something they can always do without touching the tool.
fn manual_install_hint(target: &str, version: &str) {
    let asset = asset_name(target);
    eprintln!("\n[fallback] manual install — same release, no self-update layer:");
    let url = format!(
        "https://github.com/{}/{}/releases/download/v{}/{}",
        REPO_OWNER, REPO_NAME, version, asset
    );
    if cfg!(windows) {
        eprintln!(
            "  curl -fSL \"{}\" -o {}\n  Expand-Archive -Force {} .  # or unzip\n  Move-Item rustymap.exe \"$(Get-Command rustymap).Source\"",
            url, asset, asset
        );
    } else {
        eprintln!(
            "  curl -fSL '{}' | tar -xz -C /tmp\n  sudo install /tmp/rustymap $(command -v rustymap)",
            url
        );
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

    // Pre-flight: check we can write to the binary's directory before
    // spending time downloading. Common failure on Kali/Debian: rustymap
    // installed to /usr/local/bin owned by root and the user runs
    // `rustymap --update` without sudo.
    if let Err(e) = check_writable() {
        return Err(e);
    }

    let status = self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .target(target)
        .show_download_progress(true)
        .current_version(current)
        .no_confirm(true)
        .build()
        .map_err(|e| {
            manual_install_hint(target, "<latest>");
            anyhow!("self_update build failed: {}", e)
        })?
        .update()
        .map_err(|e| {
            // self_update wraps errors generically; surface the kind to
            // help users diagnose.
            let extra = match &e {
                self_update::errors::Error::Io(io) => format!(" (io: {})", io.kind()),
                self_update::errors::Error::Reqwest(_) => " (network error — check connectivity / outbound 443 access)".to_string(),
                self_update::errors::Error::Json(_) => " (GitHub API parse error)".to_string(),
                self_update::errors::Error::Release(_) => " (no matching release asset for this platform)".to_string(),
                _ => String::new(),
            };
            manual_install_hint(target, "<latest>");
            anyhow!("self_update failed{}: {}", extra, e)
        })?;

    if status.updated() {
        println!("Updated RustyMap v{} → v{}.", current, status.version());
        println!("Run `rustymap --version` to verify.");
    } else {
        println!("Already up to date (v{}).", current);
    }
    Ok(())
}
