//! Self-update via GitHub releases — written from scratch.
//!
//! Replaces the previous `self_update` crate integration which was an
//! opaque box. This impl prints every step so failures are visible:
//!
//!   [1/7] resolving latest release …
//!   [2/7] comparing versions: v0.40.0 → v0.41.0 …
//!   [3/7] picking asset for linux-x86_64 …
//!   [4/7] downloading rustymap-linux-x86_64.tar.gz (8.4 MiB) …
//!   [5/7] verifying SHA256 against SHA256SUMS.txt …
//!   [6/7] extracting binary …
//!   [7/7] swapping in new binary at /usr/local/bin/rustymap …
//!   ✓ Updated to v0.41.0
//!
//! Any failure includes the manual `curl + tar + install` one-liner
//! pointing at the exact GitHub asset for the platform.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize, Clone)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
}

fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Strip leading "v" from "vX.Y.Z" and compare semver-style. Returns
/// true when `latest` > `current`.
fn is_newer(latest: &str, current: &str) -> bool {
    fn nums(v: &str) -> Vec<u64> {
        v.trim_start_matches('v')
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<u64>().ok())
            .collect()
    }
    let l = nums(latest);
    let c = nums(current);
    for i in 0..l.len().max(c.len()) {
        let li = *l.get(i).unwrap_or(&0);
        let ci = *c.get(i).unwrap_or(&0);
        if li > ci {
            return true;
        }
        if li < ci {
            return false;
        }
    }
    false
}

fn build_client(timeout: Duration) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent(format!("rustymap/{}", current_version()))
        .build()
        .context("build HTTP client")
}

fn fetch_latest_release(client: &reqwest::blocking::Client) -> Result<Release> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        REPO_OWNER, REPO_NAME
    );
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .with_context(|| format!("GET {}", url))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!(
            "GitHub returned {} for /releases/latest — rate limited? \
             try in an hour, or `curl https://api.github.com/repos/{}/{}/releases/latest` \
             from another IP",
            status,
            REPO_OWNER,
            REPO_NAME
        ));
    }
    resp.json::<Release>().context("parse GitHub releases JSON")
}

fn pick_asset<'a>(release: &'a Release, target: &str) -> Result<&'a Asset> {
    let want = asset_name(target);
    release
        .assets
        .iter()
        .find(|a| a.name == want)
        .ok_or_else(|| {
            let names: Vec<&str> = release.assets.iter().map(|a| a.name.as_str()).collect();
            anyhow!(
                "no asset named '{}' in release {} (assets present: {:?})",
                want,
                release.tag_name,
                names
            )
        })
}

fn download(client: &reqwest::blocking::Client, asset: &Asset, dst: &Path) -> Result<()> {
    let mut resp = client
        .get(&asset.browser_download_url)
        .send()
        .with_context(|| format!("GET {}", asset.browser_download_url))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "download returned {} ({})",
            resp.status(),
            asset.browser_download_url
        ));
    }
    let pb = indicatif::ProgressBar::new(asset.size);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "{spinner:.cyan} [{elapsed_precise}] {wide_bar:.cyan/blue} {bytes}/{total_bytes} ({eta})",
        )
        .unwrap(),
    );
    let mut f = std::fs::File::create(dst).with_context(|| format!("create {:?}", dst))?;
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = resp.read(&mut buf).context("read body chunk")?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n]).context("write download")?;
        total += n as u64;
        pb.set_position(total);
    }
    pb.finish_and_clear();
    Ok(())
}

/// Verify against SHA256SUMS.txt published in the same release.
/// Best-effort: if the checksum file is missing or unparseable, log
/// and proceed (binary is downloaded over HTTPS anyway).
fn verify_checksum(
    client: &reqwest::blocking::Client,
    release: &Release,
    asset: &Asset,
    archive_path: &Path,
) -> Result<bool> {
    let sums_url = release
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS.txt")
        .map(|a| a.browser_download_url.clone());
    let Some(url) = sums_url else {
        return Ok(false); // not present, skip
    };
    let body = client.get(&url).send()?.text()?;
    let want = body
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let hash = parts.next()?;
            let name = parts.next()?.trim_start_matches('*');
            if name == asset.name {
                Some(hash.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("{} not listed in SHA256SUMS.txt", asset.name))?;

    let mut f = std::fs::File::open(archive_path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let got = format!("{:x}", hasher.finalize());
    if got != want {
        return Err(anyhow!(
            "SHA256 mismatch — expected {}, got {} (download corrupted or tampered)",
            want,
            got
        ));
    }
    Ok(true)
}

/// Extract the rustymap binary from the downloaded archive into
/// `dst_dir`. Returns the path of the extracted binary.
fn extract(archive_path: &Path, dst_dir: &Path) -> Result<PathBuf> {
    let lower = archive_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    if lower.ends_with(".tar.gz") {
        let f = std::fs::File::open(archive_path)?;
        let gz = flate2::read::GzDecoder::new(f);
        let mut archive = tar::Archive::new(gz);
        for entry in archive.entries()? {
            let mut e = entry?;
            let path = e.path()?.into_owned();
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if name == BIN_NAME || name == format!("{}.exe", BIN_NAME) {
                let out = dst_dir.join(&name);
                e.unpack(&out)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perm = std::fs::metadata(&out)?.permissions();
                    perm.set_mode(0o755);
                    std::fs::set_permissions(&out, perm)?;
                }
                return Ok(out);
            }
        }
        Err(anyhow!("rustymap binary not found inside tar.gz"))
    } else if lower.ends_with(".zip") {
        let f = std::fs::File::open(archive_path)?;
        let mut zip = zip::ZipArchive::new(f)?;
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            let name = entry.name().to_string();
            let leaf = name.rsplit('/').next().unwrap_or("").to_string();
            if leaf == BIN_NAME || leaf == format!("{}.exe", BIN_NAME) {
                let out = dst_dir.join(&leaf);
                let mut o = std::fs::File::create(&out)?;
                std::io::copy(&mut entry, &mut o)?;
                return Ok(out);
            }
        }
        Err(anyhow!("rustymap.exe not found inside zip"))
    } else {
        Err(anyhow!(
            "unrecognized archive format: {:?} (expected .tar.gz or .zip)",
            archive_path
        ))
    }
}

/// Atomically swap the running binary with `new_bin`. On Unix uses
/// rename. On Windows can't replace a running .exe directly — uses
/// the rename-self trick: move current to .old, then rename new.
fn swap_in(new_bin: &Path) -> Result<()> {
    let exe = std::env::current_exe()?;

    #[cfg(windows)]
    {
        // Move the running .exe out of the way (allowed even while
        // running on NTFS), then move the new one into place.
        let backup = exe.with_extension("old");
        let _ = std::fs::remove_file(&backup);
        std::fs::rename(&exe, &backup)
            .with_context(|| format!("rename {:?} → {:?}", exe, backup))?;
        match std::fs::rename(new_bin, &exe) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Restore the original on failure
                let _ = std::fs::rename(&backup, &exe);
                Err(anyhow!("failed to install new binary: {}", e))
            }
        }
    }

    #[cfg(unix)]
    {
        // rename(2) fails with EXDEV (errno 18) when source and target
        // live on different filesystems — happens on Kali/Debian where
        // /tmp is tmpfs and /usr/local/bin is the root ext4. Fall back
        // to copy-then-atomic-rename via a sibling staging file in the
        // target's own directory so the second rename is intra-fs.
        match std::fs::rename(new_bin, &exe) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(18) => {
                cross_fs_install(new_bin, &exe)
            }
            Err(e) => Err(anyhow!("rename {:?} → {:?}: {}", new_bin, exe, e)),
        }
    }
}

#[cfg(unix)]
fn cross_fs_install(new_bin: &Path, exe: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = exe
        .parent()
        .ok_or_else(|| anyhow!("target path has no parent: {:?}", exe))?;
    let staging = parent.join(format!(".rustymap-new-{}", std::process::id()));
    std::fs::copy(new_bin, &staging).with_context(|| {
        format!(
            "cross-fs copy {:?} → {:?} (fallback after EXDEV)",
            new_bin, &staging
        )
    })?;
    let mut perm = std::fs::metadata(&staging)?.permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&staging, perm)?;
    // Now src and dst are on the same filesystem — rename is atomic.
    std::fs::rename(&staging, exe).with_context(|| {
        format!(
            "final rename {:?} → {:?} (cross-fs fallback)",
            &staging, exe
        )
    })?;
    let _ = std::fs::remove_file(new_bin);
    Ok(())
}

fn check_writable(exe: &Path) -> Result<()> {
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

fn manual_install_hint(target: &str, version: &str) {
    let asset = asset_name(target);
    eprintln!(
        "\n[fallback] manual install — same release, no self-update layer:"
    );
    let url = format!(
        "https://github.com/{}/{}/releases/download/{}/{}",
        REPO_OWNER, REPO_NAME, version, asset
    );
    if cfg!(windows) {
        eprintln!(
            "  curl -fSL \"{}\" -o {}\n  Expand-Archive -Force {} .\n  Move-Item rustymap.exe \"$(Get-Command rustymap).Source\"",
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
    let client = build_client(Duration::from_secs(20))?;
    eprintln!("[1/2] resolving latest release …");
    let release = fetch_latest_release(&client)?;
    let cur = current_version();
    eprintln!("[2/2] comparing versions: v{} ↔ {} …", cur, release.tag_name);
    if is_newer(&release.tag_name, cur) {
        println!("Update available: v{} → {}", cur, release.tag_name);
        println!("Run: rustymap --update");
    } else {
        println!(
            "RustyMap v{} is up to date (latest: {}).",
            cur, release.tag_name
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
    let exe = std::env::current_exe()?;
    check_writable(&exe)?;

    let client = build_client(Duration::from_secs(60))?;
    eprintln!("[1/7] resolving latest release …");
    let release = fetch_latest_release(&client).inspect_err(|_e| {
        manual_install_hint(target, "latest");
    })?;

    let cur = current_version();
    eprintln!("[2/7] comparing versions: v{} ↔ {} …", cur, release.tag_name);
    if !is_newer(&release.tag_name, cur) {
        println!("Already up to date (v{}).", cur);
        return Ok(());
    }

    eprintln!("[3/7] picking asset for {} …", target);
    let asset = pick_asset(&release, target).inspect_err(|_e| {
        manual_install_hint(target, &release.tag_name);
    })?;

    eprintln!(
        "[4/7] downloading {} ({:.1} MiB) …",
        asset.name,
        asset.size as f64 / (1024.0 * 1024.0)
    );
    let temp_dir = std::env::temp_dir();
    let archive_path = temp_dir.join(&asset.name);
    download(&client, asset, &archive_path).inspect_err(|_e| {
        manual_install_hint(target, &release.tag_name);
    })?;

    eprintln!("[5/7] verifying SHA256 …");
    match verify_checksum(&client, &release, asset, &archive_path) {
        Ok(true) => eprintln!("       ✓ checksum match"),
        Ok(false) => eprintln!("       (no SHA256SUMS.txt published, skipping)"),
        Err(e) => {
            let _ = std::fs::remove_file(&archive_path);
            return Err(e);
        }
    }

    eprintln!("[6/7] extracting binary …");
    let new_bin = extract(&archive_path, &temp_dir).inspect_err(|_e| {
        manual_install_hint(target, &release.tag_name);
    })?;
    let _ = std::fs::remove_file(&archive_path);

    eprintln!("[7/7] swapping in new binary at {:?} …", exe);
    swap_in(&new_bin).inspect_err(|_e| {
        manual_install_hint(target, &release.tag_name);
    })?;

    println!("✓ Updated RustyMap v{} → {}.", cur, release.tag_name);
    println!("Run `rustymap --version` to verify.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert!(is_newer("v0.41.0", "0.40.0"));
        assert!(is_newer("0.40.1", "0.40.0"));
        assert!(is_newer("v1.0.0", "0.99.99"));
        assert!(!is_newer("v0.40.0", "0.40.0"));
        assert!(!is_newer("v0.39.0", "0.40.0"));
    }

    #[test]
    fn asset_name_matches_release_workflow() {
        assert_eq!(asset_name("linux-x86_64"), "rustymap-linux-x86_64.tar.gz");
        assert_eq!(asset_name("macos-aarch64"), "rustymap-macos-aarch64.tar.gz");
        assert_eq!(asset_name("windows-x86_64"), "rustymap-windows-x86_64.zip");
    }

    #[cfg(unix)]
    #[test]
    fn cross_fs_install_intra_fs_smoke() {
        // We can't easily set up two filesystems in a unit test, but we
        // can verify the helper works when src/dst are on the same fs
        // (no actual EXDEV): copy + chmod + atomic rename still
        // produces a binary at the target path.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rustymap-xfs-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("new-bin");
        let dst = dir.join("installed");
        std::fs::write(&src, b"#!/bin/sh\necho ok\n").unwrap();
        cross_fs_install(&src, &dst).unwrap();
        let meta = std::fs::metadata(&dst).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o755);
        assert_eq!(std::fs::read(&dst).unwrap(), b"#!/bin/sh\necho ok\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
