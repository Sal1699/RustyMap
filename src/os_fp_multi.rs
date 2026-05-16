//! Multi-candidate OS fingerprint scoring.
//!
//! The existing `os_fp::fingerprint` returns a single best-guess
//! `OsGuess`. That's nmap-compatible for the typical case but
//! hides ambiguity — when the signals split between two near-equal
//! candidates the user just sees the winner. This module produces
//! a ranked list of candidates with explicit confidence percentages,
//! matching nmap's `--osscan-guess` output style.
//!
//! Inputs (no extra network — we work from what `HostResult`
//! already carries):
//!   - **TTL / hop-limit** narrows the OS family (64 → Linux/BSD,
//!     128 → Windows, 255 → network gear).
//!   - **Open-port mix** votes for likely roles: 3389 → Windows,
//!     22 alone → Unix-like, 445+135+139 → AD member, 161 SNMP +
//!     22 SSH → likely router/printer, etc.
//!   - **Service banners** when `--sV` ran — strings like "OpenSSH
//!     for Windows" or "Apache/2.4 (Ubuntu)" trump everything.
//!
//! We compute per-family scores, normalise to a 0-100 confidence,
//! and surface the top N. Ties broken by signal-count.

use crate::os_fp::OsGuess;
use crate::scanner::{HostResult, PortState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsCandidate {
    pub family: String,
    pub confidence: u8,
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsCandidateList {
    pub primary: OsGuess,
    pub candidates: Vec<OsCandidate>,
}

/// Heuristic family vote for a single signal source.
/// Returns a list of `(family, weight, signal_description)` tuples.
type FamilyVote = (&'static str, i32, String);

pub fn rank(host: &HostResult, primary: OsGuess, top_n: usize) -> OsCandidateList {
    let mut scores: HashMap<&'static str, (i32, Vec<String>)> = HashMap::new();

    // Seed with the primary guess so we never lose the single best guess.
    scores
        .entry(map_family(&primary.family))
        .or_insert_with(|| (0, Vec::new()))
        .0 += 60;
    scores
        .entry(map_family(&primary.family))
        .or_default()
        .1
        .push(format!("primary fingerprint ({})", primary.family));

    // TTL signal
    if let Some(ttl) = primary.ttl {
        for vote in ttl_votes(ttl) {
            let entry = scores.entry(vote.0).or_default();
            entry.0 += vote.1;
            entry.1.push(vote.2);
        }
    }

    // Port-mix signals
    let open_ports: Vec<u16> = host
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .map(|p| p.port)
        .collect();
    for vote in port_mix_votes(&open_ports) {
        let entry = scores.entry(vote.0).or_default();
        entry.0 += vote.1;
        entry.1.push(vote.2);
    }

    // Service-banner signals (--sV)
    for p in &host.ports {
        if p.state != PortState::Open {
            continue;
        }
        if let Some(svc) = &p.service {
            if let Some(banner) = svc.product.as_deref() {
                for vote in banner_votes(banner) {
                    let entry = scores.entry(vote.0).or_default();
                    entry.0 += vote.1;
                    entry.1.push(vote.2);
                }
            }
        }
    }

    // Normalise to 0..=100 confidence
    let max_score = scores.values().map(|(s, _)| *s).max().unwrap_or(1).max(1);
    let mut candidates: Vec<OsCandidate> = scores
        .into_iter()
        .filter(|(_, (s, _))| *s > 0)
        .map(|(family, (score, signals))| OsCandidate {
            family: family.to_string(),
            confidence: ((score as f64 / max_score as f64) * 100.0).round().min(99.0) as u8,
            signals,
        })
        .collect();
    candidates.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(b.signals.len().cmp(&a.signals.len()))
    });
    candidates.truncate(top_n.max(1));

    OsCandidateList {
        primary,
        candidates,
    }
}

/// Map free-text family strings ("Linux 5.x", "Windows 10", "FreeBSD")
/// to a canonical short family.
pub fn map_family(s: &str) -> &'static str {
    let lower = s.to_lowercase();
    if lower.contains("windows") {
        "Windows"
    } else if lower.contains("linux") {
        "Linux"
    } else if lower.contains("freebsd") || lower.contains("openbsd") || lower.contains("netbsd") {
        "BSD"
    } else if lower.contains("macos") || lower.contains("darwin") || lower.contains("os x") {
        "macOS"
    } else if lower.contains("cisco") || lower.contains("ios") {
        "Cisco IOS"
    } else if lower.contains("solaris") || lower.contains("sunos") {
        "Solaris"
    } else if lower.contains("android") {
        "Android"
    } else if lower.contains("printer") {
        "Embedded printer"
    } else {
        "Unknown"
    }
}

fn ttl_votes(ttl: u8) -> Vec<FamilyVote> {
    let mut out = Vec::new();
    // Estimate the original initial TTL (vantage typically ≤30 hops)
    let initial = if ttl > 225 {
        255
    } else if ttl > 96 {
        128
    } else if ttl > 32 {
        64
    } else {
        ttl
    };
    match initial {
        64 => {
            out.push(("Linux", 20, format!("TTL≈64 (Linux/BSD default)")));
            out.push(("BSD", 15, format!("TTL≈64 (BSD default)")));
            out.push(("macOS", 12, format!("TTL≈64 (macOS default)")));
            out.push(("Android", 10, format!("TTL≈64 (Android default)")));
        }
        128 => {
            out.push(("Windows", 25, format!("TTL≈128 (Windows default)")));
        }
        255 => {
            out.push(("Cisco IOS", 25, format!("TTL≈255 (router/Cisco default)")));
            out.push(("Solaris", 15, format!("TTL≈255 (Solaris default)")));
        }
        _ => {}
    }
    out
}

fn port_mix_votes(ports: &[u16]) -> Vec<FamilyVote> {
    let set: std::collections::HashSet<u16> = ports.iter().copied().collect();
    let mut out = Vec::new();
    let has = |p: u16| set.contains(&p);

    // RDP → Windows
    if has(3389) {
        out.push(("Windows", 30, "RDP/3389 open".into()));
    }
    // SMB + NetBIOS → Windows / Samba
    if has(445) && (has(139) || has(135)) {
        out.push(("Windows", 25, "SMB + NetBIOS/RPC suite (445+139/135)".into()));
    } else if has(445) {
        out.push(("Windows", 10, "SMB/445 open".into()));
        out.push(("Linux", 5, "SMB/445 open (Samba)".into()));
    }
    // WinRM
    if has(5985) || has(5986) {
        out.push(("Windows", 20, "WinRM/5985 or 5986 open".into()));
    }
    // SSH-only host → likely Unix-like
    if has(22) && !has(3389) && !has(445) && !has(139) {
        out.push(("Linux", 18, "SSH only (no SMB/RDP)".into()));
        out.push(("BSD", 12, "SSH only".into()));
        out.push(("macOS", 8, "SSH only".into()));
    }
    // Printer / embedded: 9100 JetDirect, 631 IPP, 161 SNMP
    if has(9100) || has(631) {
        out.push(("Embedded printer", 35, "JetDirect/9100 or IPP/631 open".into()));
    }
    // Router fingerprint: SSH + SNMP + no SMB
    if has(22) && has(161) && !has(445) && !has(3389) {
        out.push(("Cisco IOS", 15, "SSH + SNMP, no SMB/RDP — likely router".into()));
    }
    out
}

fn banner_votes(banner: &str) -> Vec<FamilyVote> {
    let mut out = Vec::new();
    let b = banner.to_lowercase();

    if b.contains("microsoft") || b.contains("windows") || b.contains("microsoft-iis") {
        out.push(("Windows", 35, format!("banner mentions Microsoft/Windows: '{}'", banner)));
    }
    if b.contains("ubuntu") || b.contains("debian") || b.contains("redhat") || b.contains("centos")
        || b.contains("fedora") || b.contains("rocky") || b.contains("almalinux") || b.contains("(linux)")
    {
        out.push(("Linux", 35, format!("banner mentions a Linux distro: '{}'", banner)));
    }
    if b.contains("freebsd") {
        out.push(("BSD", 35, format!("banner mentions FreeBSD: '{}'", banner)));
    }
    if b.contains("openbsd") {
        out.push(("BSD", 35, format!("banner mentions OpenBSD: '{}'", banner)));
    }
    if b.contains("darwin") || b.contains("mac os") || b.contains("macos") {
        out.push(("macOS", 35, format!("banner mentions Darwin/macOS: '{}'", banner)));
    }
    if b.contains("cisco") || b.contains("ios-xe") {
        out.push(("Cisco IOS", 35, format!("banner mentions Cisco IOS: '{}'", banner)));
    }
    if b.contains("jetdirect") || b.contains("hp-chai") || b.contains("printer") {
        out.push(("Embedded printer", 35, format!("banner mentions printer firmware: '{}'", banner)));
    }
    out
}

pub fn print_candidates(host_label: &str, list: &OsCandidateList) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!("OS candidates for {} (top {})", host_label, list.candidates.len()).bold()
    );
    for c in &list.candidates {
        let bar = "█".repeat((c.confidence / 5) as usize);
        println!(
            "  {:<20} {:>3}% {}",
            c.family.bold(),
            c.confidence,
            bar.green()
        );
        for s in &c.signals {
            println!("    · {}", s.dimmed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_family_recognises_common_strings() {
        assert_eq!(map_family("Windows 10 build 19042"), "Windows");
        assert_eq!(map_family("Linux 5.10 kernel"), "Linux");
        assert_eq!(map_family("FreeBSD 13.2"), "BSD");
        assert_eq!(map_family("Darwin 22.4 (macOS)"), "macOS");
        assert_eq!(map_family("Cisco IOS 15.x"), "Cisco IOS");
        assert_eq!(map_family("Solaris 11.4"), "Solaris");
        assert_eq!(map_family("Android 14"), "Android");
        assert_eq!(map_family("something weird"), "Unknown");
    }

    #[test]
    fn ttl_64_votes_unix_family() {
        let v = ttl_votes(60);
        assert!(v.iter().any(|x| x.0 == "Linux"));
        assert!(v.iter().any(|x| x.0 == "BSD"));
        assert!(v.iter().any(|x| x.0 == "macOS"));
        assert!(!v.iter().any(|x| x.0 == "Windows"));
    }

    #[test]
    fn ttl_128_votes_windows() {
        let v = ttl_votes(120);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "Windows");
    }

    #[test]
    fn ttl_255_votes_router_family() {
        let v = ttl_votes(250);
        assert!(v.iter().any(|x| x.0 == "Cisco IOS"));
    }

    #[test]
    fn port_mix_3389_strong_windows_signal() {
        let v = port_mix_votes(&[3389]);
        let w = v.iter().find(|x| x.0 == "Windows").unwrap();
        assert!(w.1 >= 30);
    }

    #[test]
    fn port_mix_smb_plus_netbios_stronger_than_smb_alone() {
        let v1 = port_mix_votes(&[445]);
        let v2 = port_mix_votes(&[445, 139, 135]);
        let w1 = v1.iter().find(|x| x.0 == "Windows").map(|x| x.1).unwrap_or(0);
        let w2 = v2.iter().find(|x| x.0 == "Windows").map(|x| x.1).unwrap_or(0);
        assert!(w2 > w1);
    }

    #[test]
    fn port_mix_jetdirect_flags_printer() {
        let v = port_mix_votes(&[9100, 631]);
        assert!(v.iter().any(|x| x.0 == "Embedded printer" && x.1 >= 30));
    }

    #[test]
    fn banner_ubuntu_votes_linux_strongly() {
        let v = banner_votes("Apache/2.4.41 (Ubuntu)");
        assert!(v.iter().any(|x| x.0 == "Linux" && x.1 >= 30));
    }

    #[test]
    fn banner_microsoft_iis_votes_windows() {
        let v = banner_votes("Microsoft-IIS/10.0");
        assert!(v.iter().any(|x| x.0 == "Windows"));
    }
}
