use crate::scanner::{HostResult, PortState};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsGuess {
    pub family: String,
    pub confidence: u8, // 0-100
    pub ttl: Option<u8>,
    pub hints: Vec<String>,
}

static TTL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)ttl[=:]\s*(\d+)").unwrap());

/// Ping the host and parse TTL from system ping output.
fn ping_ttl(ip: IpAddr, timeout: Duration) -> Option<u8> {
    let ip_s = ip.to_string();
    let timeout_ms = timeout.as_millis().max(200) as u64;
    let out = if cfg!(windows) {
        Command::new("ping")
            .args(["-n", "1", "-w", &timeout_ms.to_string(), &ip_s])
            .output()
            .ok()?
    } else {
        let secs = timeout_ms.div_ceil(1000).max(1);
        Command::new("ping")
            .args(["-c", "1", "-W", &secs.to_string(), &ip_s])
            .output()
            .ok()?
    };
    let text = String::from_utf8_lossy(&out.stdout);
    TTL_RE.captures(&text).and_then(|c| c.get(1)).and_then(|m| m.as_str().parse::<u8>().ok())
}

fn family_from_ttl(ttl: u8) -> (&'static str, u8) {
    // Hop count ambiguity: most hosts are within ~30 hops.
    match ttl {
        1..=64 => ("Linux/BSD/macOS", 55),
        65..=128 => ("Windows", 55),
        129..=255 => ("Network device (Cisco/router)", 50),
        0 => ("unknown", 0),
    }
}

fn refine_from_ports(host: &HostResult, guess: &mut OsGuess) {
    let open: Vec<u16> = host
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .map(|p| p.port)
        .collect();

    let has = |p: u16| open.contains(&p);

    if has(135) || has(139) || has(445) || has(3389) || has(5357) {
        guess.hints.push("RPC/SMB/RDP open".into());
        if guess.family != "Windows" {
            guess.family = "Windows".into();
            guess.confidence = guess.confidence.max(70);
        } else {
            guess.confidence = (guess.confidence + 20).min(95);
        }
    }
    if has(22) {
        guess.hints.push("SSH open".into());
        if guess.family.starts_with("Linux") {
            guess.confidence = (guess.confidence + 10).min(95);
        }
    }
    if has(548) {
        guess.hints.push("AFP open (likely macOS)".into());
        guess.family = "macOS".into();
        guess.confidence = guess.confidence.max(70);
    }
    if has(23) && has(80) && !has(445) {
        guess.hints.push("telnet+http, likely embedded/network device".into());
    }
}

fn refine_from_banners(host: &HostResult, guess: &mut OsGuess) {
    for p in &host.ports {
        if let Some(svc) = &p.service {
            let s = svc.display().to_lowercase();
            let b = svc.banner.as_deref().unwrap_or("").to_lowercase();
            let all = format!("{} {}", s, b);
            if all.contains("ubuntu") {
                guess.family = "Linux (Ubuntu)".into();
                guess.confidence = 90;
                guess.hints.push("Ubuntu banner".into());
            } else if all.contains("debian") {
                guess.family = "Linux (Debian)".into();
                guess.confidence = 90;
                guess.hints.push("Debian banner".into());
            } else if all.contains("centos") || all.contains("rhel") || all.contains("red hat") {
                guess.family = "Linux (RHEL/CentOS)".into();
                guess.confidence = 90;
                guess.hints.push("RHEL/CentOS banner".into());
            } else if all.contains("freebsd") {
                guess.family = "FreeBSD".into();
                guess.confidence = 90;
            } else if all.contains("microsoft-iis") || all.contains("microsoft ftp") {
                guess.family = "Windows".into();
                guess.confidence = guess.confidence.max(80);
                guess.hints.push("Microsoft server banner".into());
            }
        }
    }
}

pub fn fingerprint(host: &HostResult, timeout: Duration) -> OsGuess {
    let ttl = ping_ttl(host.target.ip, timeout);
    let (family, base_conf) = ttl.map(family_from_ttl).unwrap_or(("unknown", 0));
    let mut guess = OsGuess {
        family: family.to_string(),
        confidence: base_conf,
        ttl,
        hints: if let Some(t) = ttl { vec![format!("TTL={}", t)] } else { vec![] },
    };
    refine_from_ports(host, &mut guess);
    refine_from_banners(host, &mut guess);
    guess
}
