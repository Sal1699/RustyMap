//! OS-fingerprint submission pack generator.
//!
//! When a scan produces a confident OS guess on a host the
//! community DB doesn't already cover well, the user can dump the
//! raw signal data to a file in a format inspired by nmap's
//! `nmap-os-db` submission template. The output isn't auto-uploaded
//! — we never touch the user's network — but it's a copy-paste-able
//! pack the user can attach to a bug report or a community DB PR.
//!
//! Format (text):
//!
//! ```
//! # Submitted by rustymap vX.Y.Z on 2026-05-09
//! # Host:   10.0.0.42
//! # User-supplied OS label: "Ubuntu 22.04 server"
//!
//! Fingerprint Ubuntu 22.04 server
//! Class Linux | Linux | 5.X | general purpose
//! CPE cpe:/o:linux:linux_kernel:5.15
//!
//! ## Signals observed by the scan
//! TTL=64
//! Open ports: 22,80,443
//! Service banners:
//!   22/tcp  OpenSSH/8.9 Ubuntu
//!   80/tcp  Apache/2.4.41 (Ubuntu)
//! ```
//!
//! The user is expected to fill in any fingerprint-test fields the
//! upstream community DB requires before submitting. Our job is to
//! collect every observed signal so they're not re-running scans
//! to gather data.

use crate::cpe;
use crate::scanner::{HostResult, PortState};
use anyhow::Result;
use std::fmt::Write as _;
use std::path::Path;

pub fn build_pack(host: &HostResult, user_label: &str) -> String {
    let mut s = String::new();
    let _ = writeln!(
        &mut s,
        "# Submitted by rustymap {} on {}",
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z")
    );
    let _ = writeln!(&mut s, "# Host:   {}", host.target.ip);
    if let Some(hn) = &host.target.hostname {
        let _ = writeln!(&mut s, "# Name:   {}", hn);
    }
    let _ = writeln!(&mut s, "# User-supplied OS label: \"{}\"\n", user_label);

    let _ = writeln!(&mut s, "Fingerprint {}", user_label);

    // Class line: best-effort from existing os.family
    let family = host
        .os
        .as_ref()
        .map(|g| g.family.clone())
        .unwrap_or_else(|| "Unknown".into());
    let class = map_to_class(&family);
    let _ = writeln!(&mut s, "Class {}", class);

    // CPE
    let version = extract_version(&family);
    let cpe = cpe::from_family(&family, version.as_deref());
    let _ = writeln!(&mut s, "CPE {}", cpe.raw);

    // Signal block
    let _ = writeln!(&mut s, "\n## Signals observed by the scan");
    if let Some(g) = &host.os {
        if let Some(ttl) = g.ttl {
            let _ = writeln!(&mut s, "TTL={}", ttl);
        }
        if g.confidence > 0 {
            let _ = writeln!(&mut s, "Tool confidence: {}%", g.confidence);
        }
        if !g.hints.is_empty() {
            let _ = writeln!(&mut s, "Hints: {}", g.hints.join(" | "));
        }
    }
    let open: Vec<String> = host
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .map(|p| p.port.to_string())
        .collect();
    if !open.is_empty() {
        let _ = writeln!(&mut s, "Open ports: {}", open.join(","));
    }
    let _ = writeln!(&mut s, "\n## Service banners");
    for p in &host.ports {
        if p.state != PortState::Open {
            continue;
        }
        if let Some(svc) = &p.service {
            if let Some(prod) = &svc.product {
                let _ = writeln!(&mut s, "  {}/tcp  {}", p.port, prod);
            }
        }
    }
    if let Some(m) = host.mac {
        let _ = writeln!(
            &mut s,
            "\nMAC address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
    }
    s
}

#[allow(dead_code)]
pub fn write_pack(path: &Path, host: &HostResult, user_label: &str) -> Result<()> {
    let body = build_pack(host, user_label);
    std::fs::write(path, body)?;
    Ok(())
}

/// Map a family string to a nmap-style "Class A | B | C | D" line.
/// Best-effort, leaves slots that can't be inferred as "general
/// purpose" / "unknown".
fn map_to_class(family: &str) -> String {
    let lower = family.to_lowercase();
    if lower.contains("windows") {
        let gen = if lower.contains("11") {
            "11"
        } else if lower.contains("10") {
            "10"
        } else if lower.contains("server 2022") {
            "Server 2022"
        } else if lower.contains("server 2019") {
            "Server 2019"
        } else if lower.contains("server 2016") {
            "Server 2016"
        } else if lower.contains("server") {
            "Server"
        } else {
            "general"
        };
        format!("Microsoft | Windows | {} | general purpose", gen)
    } else if lower.contains("linux") {
        let kernel = extract_version(family).unwrap_or_else(|| "X".into());
        format!("Linux | Linux | {} | general purpose", kernel)
    } else if lower.contains("freebsd") {
        let v = extract_version(family).unwrap_or_else(|| "X".into());
        format!("FreeBSD | FreeBSD | {} | general purpose", v)
    } else if lower.contains("macos") || lower.contains("darwin") {
        let v = extract_version(family).unwrap_or_else(|| "X".into());
        format!("Apple | macOS | {} | general purpose", v)
    } else if lower.contains("cisco") {
        format!("Cisco | IOS | general | router")
    } else if lower.contains("printer") {
        format!("Generic | embedded | general | printer")
    } else {
        format!("Unknown | Unknown | Unknown | general purpose")
    }
}

fn extract_version(family: &str) -> Option<String> {
    // Pull the first "X.Y" or "X.Y.Z" version-shaped token.
    let re = regex::Regex::new(r"(\d+(?:\.\d+){1,3})").ok()?;
    re.captures(family).map(|c| c[1].to_string())
}

pub fn print_pack(pack: &str) {
    use colored::*;
    println!();
    println!("{}", "OS-DB submission pack".bold().underline());
    println!("{}", pack);
    println!(
        "{}",
        "Save with --osdb-submit-out FILE to share with the community DB maintainers.".dimmed()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os_fp::OsGuess;
    use crate::scanner::{PortResult, PortState};
    use crate::target::Target;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn host(family: &str, ports: &[u16]) -> HostResult {
        HostResult {
            target: Target {
                ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                hostname: Some("test.local".into()),
                zone: None,
            },
            up: true,
            ports: ports
                .iter()
                .map(|&p| PortResult {
                    port: p,
                    state: PortState::Open,
                    rtt: Duration::from_millis(0),
                    service: None,
                })
                .collect(),
            elapsed: Duration::from_millis(0),
            os: Some(OsGuess {
                family: family.into(),
                confidence: 80,
                ttl: Some(64),
                hints: vec!["ttl=64".into()],
            }),
            device: None,
            mac: None,
        }
    }

    #[test]
    fn build_pack_includes_label_and_class() {
        let h = host("Linux 5.15", &[22, 80, 443]);
        let pack = build_pack(&h, "Ubuntu 22.04 server");
        assert!(pack.contains("Fingerprint Ubuntu 22.04 server"));
        assert!(pack.contains("Class Linux | Linux"));
        assert!(pack.contains("cpe:2.3:o:linux:linux_kernel"));
        assert!(pack.contains("TTL=64"));
        assert!(pack.contains("Open ports: 22,80,443"));
    }

    #[test]
    fn map_to_class_recognises_windows_server() {
        let s = map_to_class("Windows Server 2019");
        assert!(s.contains("Microsoft | Windows | Server 2019"));
    }

    #[test]
    fn map_to_class_recognises_macos() {
        let s = map_to_class("macOS Ventura 13.4");
        assert!(s.contains("Apple | macOS"));
        assert!(s.contains("13.4"));
    }

    #[test]
    fn extract_version_picks_first_dotted_number() {
        assert_eq!(extract_version("Linux 5.15.0-generic"), Some("5.15.0".into()));
        assert_eq!(extract_version("Ubuntu 22.04 server"), Some("22.04".into()));
        assert_eq!(extract_version("Windows"), None);
    }
}
