use anyhow::{anyhow, Result};
use std::path::PathBuf;

const NPCAP_DLL: &str = "wpcap.dll";
const NPCAP_DOWNLOAD_URL: &str = "https://npcap.com/dist/npcap-1.81.exe";
const NPCAP_INSTALLER_NAME: &str = "npcap-setup.exe";

/// Check if Npcap runtime is available on this system.
pub fn is_installed() -> bool {
    if !cfg!(windows) {
        return true;
    }
    npcap_dll_path().is_some()
}

fn npcap_dll_path() -> Option<PathBuf> {
    let sys = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let candidates = [
        format!(r"{}\System32\Npcap\{}", sys, NPCAP_DLL),
        format!(r"{}\System32\{}", sys, NPCAP_DLL),
    ];
    for c in &candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Offer to download and install Npcap. Returns Ok(true) if user accepted and install ran.
pub fn auto_install(silent: bool) -> Result<bool> {
    if !cfg!(windows) {
        return Ok(false);
    }

    let temp = std::env::temp_dir().join(NPCAP_INSTALLER_NAME);

    // Download
    eprintln!("[npcap] Downloading Npcap installer...");
    let status = std::process::Command::new("curl")
        .args([
            "-fSL",
            "--progress-bar",
            "-o",
            temp.to_str().unwrap(),
            NPCAP_DOWNLOAD_URL,
        ])
        .status()?;
    if !status.success() {
        return Err(anyhow!(
            "download failed. Install Npcap manually from https://npcap.com"
        ));
    }

    // Verify size (> 500KB)
    let meta = std::fs::metadata(&temp)?;
    if meta.len() < 500_000 {
        return Err(anyhow!("downloaded file too small — may be corrupted"));
    }

    // Run installer (needs UAC elevation)
    eprintln!("[npcap] Launching installer (requires admin)...");
    let mut cmd = std::process::Command::new(&temp);
    if silent {
        cmd.args(["/S", "/winpcap_mode=no"]);
    }
    let status = cmd.status()?;

    // Cleanup
    let _ = std::fs::remove_file(&temp);

    if status.success() {
        eprintln!("[npcap] Installation completed.");
        Ok(true)
    } else {
        Err(anyhow!("installer exited with {}", status))
    }
}

/// Ensure Npcap is available. If missing, auto-install or error.
pub fn ensure_available() -> Result<()> {
    if is_installed() {
        return Ok(());
    }

    eprintln!("[!] Npcap runtime not found. Raw scans (SYN/FIN/NULL/Xmas/ACK/UDP/ICMP) require Npcap on Windows.");
    eprintln!("[*] Attempting automatic installation...");

    match auto_install(false) {
        Ok(true) => {
            if is_installed() {
                eprintln!("[+] Npcap is now available.");
                Ok(())
            } else {
                Err(anyhow!("Npcap installed but DLL not found. Reboot may be required."))
            }
        }
        Ok(false) => Err(anyhow!("Npcap auto-install not available on this platform")),
        Err(e) => Err(anyhow!(
            "auto-install failed: {}. Download manually from https://npcap.com",
            e
        )),
    }
}
