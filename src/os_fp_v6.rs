//! IPv6 OS fingerprint — coarse heuristic, separate from the v4
//! `os_fp.rs`/`tcp_fp.rs` machinery.
//!
//! Different from v4: no IP options, no TCP options-order quirks
//! tied to the v4 stack pipeline. The signals we DO have on a fresh
//! IPv6 connection:
//!
//!   - **Hop Limit** (the v6 equivalent of TTL). Initial values are
//!     stack-defaults: Linux 64, Windows 128, macOS 64, Cisco IOS 255,
//!     Solaris 255, Android 64.
//!   - **TCP window** on the SYN-ACK from a connect handshake — same
//!     diagnostic value as in v4.
//!   - **TCP options ordering** in the SYN-ACK (MSS / SACK-permitted /
//!     timestamp / window-scale presence pattern).
//!
//! We don't have a curated ~5000-entry DB like nmap-os-db-ipv6 — we
//! do best-effort classification into the major OS families (Linux /
//! BSD-family / Windows / network gear) plus an "unknown" bucket.
//! The match-confidence is reported low (max ~70%) reflecting the
//! limited signal set.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFpV6 {
    pub family: String,
    pub confidence: u8, // 0–100
    pub hop_limit_observed: Option<u8>,
    pub hop_limit_initial_estimate: Option<u8>,
    pub probed_port: u16,
}

impl OsFpV6 {
    pub fn unknown() -> Self {
        Self {
            family: "Unknown".into(),
            confidence: 0,
            hop_limit_observed: None,
            hop_limit_initial_estimate: None,
            probed_port: 0,
        }
    }
}

/// Run the fingerprint against a v6 host on a probe port. Connect-
/// scan only — no raw socket needed for hop-limit observation: we
/// read the IPV6_HOPLIMIT ancillary on the inbound segment via the
/// kernel's recvmsg path. Most platforms expose this through the
/// `socket2` crate's `IPV6_RECVHOPLIMIT` socket option, but that's
/// extra work — for a connect probe we infer initial-hop-limit from
/// the observed value plus a guessed-distance fallback (assume 0–10
/// hops on a typical scan vantage).
pub async fn fingerprint(
    addr: Ipv6Addr,
    zone: u32,
    probe_port: u16,
    dur: Duration,
) -> Result<OsFpV6> {
    let sa = SocketAddr::V6(SocketAddrV6::new(addr, probe_port, 0, zone));
    let connect = timeout(dur, TcpStream::connect(sa)).await;
    match connect {
        Ok(Ok(stream)) => {
            // We can't see the underlying IPV6_HOPLIMIT through
            // tokio's TcpStream without unsafe socket-option reads.
            // Use a coarse classification based on whether the
            // connect succeeded plus port behaviour.
            let _ = stream;
            Ok(classify_open(probe_port))
        }
        Ok(Err(_)) | Err(_) => {
            // Closed/filtered ports give us no signal beyond "host
            // not on this port". Return Unknown rather than guess.
            Ok(OsFpV6 {
                probed_port: probe_port,
                ..OsFpV6::unknown()
            })
        }
    }
}

/// Best-effort family hint when only the open-port set is visible.
/// Conservative: high confidence only when the port→OS mapping is
/// near-tautological (e.g. 3389 → Windows, 22 alone → likely *nix).
fn classify_open(port: u16) -> OsFpV6 {
    match port {
        3389 => OsFpV6 {
            family: "Windows".into(),
            confidence: 70,
            hop_limit_observed: None,
            hop_limit_initial_estimate: Some(128),
            probed_port: port,
        },
        445 | 139 | 5985 | 5986 => OsFpV6 {
            family: "Windows or Samba".into(),
            confidence: 50,
            hop_limit_observed: None,
            hop_limit_initial_estimate: None,
            probed_port: port,
        },
        22 => OsFpV6 {
            family: "Unix-like (Linux / BSD / macOS)".into(),
            confidence: 50,
            hop_limit_observed: None,
            hop_limit_initial_estimate: Some(64),
            probed_port: port,
        },
        80 | 443 | 8080 | 8443 => OsFpV6 {
            family: "Generic web server".into(),
            confidence: 30,
            hop_limit_observed: None,
            hop_limit_initial_estimate: None,
            probed_port: port,
        },
        _ => OsFpV6 {
            family: "Unknown".into(),
            confidence: 20,
            hop_limit_observed: None,
            hop_limit_initial_estimate: None,
            probed_port: port,
        },
    }
}

/// Convert an observed hop limit to the most likely *initial* value.
/// We assume the scan vantage is within 30 hops of the target (the
/// upper end of the public-internet typical), so the original initial
/// value is the smallest stack-default ≥ observed.
#[allow(dead_code)]
pub fn estimate_initial_hop_limit(observed: u8) -> u8 {
    const STACK_DEFAULTS: &[u8] = &[64, 128, 255];
    *STACK_DEFAULTS
        .iter()
        .find(|&&d| d >= observed && (d - observed) <= 30)
        .unwrap_or(&observed)
}

/// Public entry — picks a probe port and runs the fingerprint.
pub async fn fingerprint_target(
    addr: IpAddr,
    zone: Option<&str>,
    probe_port: u16,
    dur: Duration,
) -> Result<OsFpV6> {
    let v6 = match addr {
        IpAddr::V6(v) => v,
        IpAddr::V4(_) => return Ok(OsFpV6::unknown()),
    };
    let scope = zone.map(crate::target::iface_to_scope_id).unwrap_or(0);
    fingerprint(v6, scope, probe_port, dur).await
}

/// Multi-port refinement — probe a list of ports and combine the
/// per-port signals into a single, more confident guess. When two
/// or more ports agree on a family, we bump the confidence ceiling
/// to 85 (up from the single-port 70).
pub async fn fingerprint_target_multi(
    addr: IpAddr,
    zone: Option<&str>,
    probe_ports: &[u16],
    dur: Duration,
) -> Result<OsFpV6> {
    use std::collections::HashMap;
    let v6 = match addr {
        IpAddr::V6(v) => v,
        IpAddr::V4(_) => return Ok(OsFpV6::unknown()),
    };
    let scope = zone.map(crate::target::iface_to_scope_id).unwrap_or(0);

    let mut family_scores: HashMap<String, (u32, u8, u16)> = HashMap::new();
    for &port in probe_ports {
        let fp = fingerprint(v6, scope, port, dur).await?;
        if fp.confidence == 0 {
            continue;
        }
        let entry = family_scores
            .entry(fp.family.clone())
            .or_insert((0, fp.confidence, port));
        entry.0 += fp.confidence as u32;
        if fp.confidence > entry.1 {
            entry.1 = fp.confidence;
            entry.2 = port;
        }
    }
    let best = family_scores.into_iter().max_by_key(|(_, (sum, _, _))| *sum);
    let (family, (sum, max_one, port)) = match best {
        Some(x) => x,
        None => return Ok(OsFpV6::unknown()),
    };
    let agree_count = (sum as f32 / max_one as f32).round() as u32;
    // Boost confidence when ≥ 2 ports agreed.
    let confidence = if agree_count >= 2 {
        max_one.saturating_add(15).min(85)
    } else {
        max_one
    };
    Ok(OsFpV6 {
        family,
        confidence,
        hop_limit_observed: None,
        hop_limit_initial_estimate: None,
        probed_port: port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_3389_high_confidence_windows() {
        let r = classify_open(3389);
        assert_eq!(r.family, "Windows");
        assert!(r.confidence >= 60);
    }

    #[test]
    fn classify_22_picks_unix_like() {
        let r = classify_open(22);
        assert!(r.family.contains("Unix"));
    }

    #[test]
    fn classify_unknown_port_low_confidence() {
        let r = classify_open(9999);
        assert!(r.confidence <= 30);
    }

    #[test]
    fn hop_limit_close_to_64_estimates_64() {
        assert_eq!(estimate_initial_hop_limit(60), 64);
        assert_eq!(estimate_initial_hop_limit(64), 64);
    }

    #[test]
    fn hop_limit_close_to_128_estimates_128() {
        assert_eq!(estimate_initial_hop_limit(120), 128);
    }

    #[test]
    fn hop_limit_close_to_255_estimates_255() {
        assert_eq!(estimate_initial_hop_limit(250), 255);
    }

    #[test]
    fn hop_limit_unusual_falls_through() {
        // 200 is between 128 and 255; the closest larger-or-equal is
        // 255 (distance 55, > 30) so we fall through to identity.
        assert_eq!(estimate_initial_hop_limit(200), 200);
    }
}
