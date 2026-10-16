//! Fase 34 — mobile **device** detection on the network (as opposed to static
//! app analysis in `apk_scan`/`ipa_scan`). Fingerprints phones/tablets by the
//! management/debug services they expose: Android ADB-over-WiFi (tcp/5555),
//! iOS lockdownd/usbmuxd-over-WiFi (tcp/62078), and Apple mDNS service types
//! (`_airplay`/`_raop`/`_companion-link`/`_apple-mobdev`). The classifier is a
//! pure function (unit-tested); `probe` does the TCP checks.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileDevice {
    /// "Android", "iOS/iPadOS", or "Apple device".
    pub os: &'static str,
    /// Short descriptor, e.g. "ADB debug bridge exposed".
    pub kind: &'static str,
    pub evidence: Vec<String>,
}

/// ADB wireless debug bridge. Open to the LAN = unauthenticated shell on many
/// devices → flagged as high-signal.
pub const ADB_PORT: u16 = 5555;
/// iOS lockdownd over WiFi (usbmuxd TCP relay).
pub const LOCKDOWND_PORT: u16 = 62078;

/// Classify a device from the services it exposes. `open_ports` are TCP ports
/// found open; `mdns_services` are mDNS/Bonjour service types seen (e.g. from
/// `--iot-discover`). Returns `None` when nothing looks mobile.
pub fn classify(open_ports: &[u16], mdns_services: &[String]) -> Option<MobileDevice> {
    let mut evidence = Vec::new();
    let has = |p: u16| open_ports.contains(&p);

    let android = has(ADB_PORT);
    if android {
        evidence.push(format!("tcp/{} ADB debug bridge open", ADB_PORT));
    }

    let apple_mdns = mdns_services.iter().any(|s| {
        let s = s.to_lowercase();
        s.contains("_airplay")
            || s.contains("_raop")
            || s.contains("_companion-link")
            || s.contains("_apple-mobdev")
    });
    if apple_mdns {
        evidence.push("Apple mDNS service (_airplay/_raop/_companion-link)".into());
    }
    let ios = has(LOCKDOWND_PORT);
    if ios {
        evidence.push(format!("tcp/{} iOS lockdownd open", LOCKDOWND_PORT));
    }

    if android {
        Some(MobileDevice {
            os: "Android",
            kind: "ADB debug bridge exposed",
            evidence,
        })
    } else if ios {
        Some(MobileDevice {
            os: "iOS/iPadOS",
            kind: "lockdownd (pairing/management) reachable",
            evidence,
        })
    } else if apple_mdns {
        Some(MobileDevice {
            os: "Apple device",
            kind: "AirPlay/Companion (iPhone/iPad/Apple TV/Mac)",
            evidence,
        })
    } else {
        None
    }
}

async fn tcp_open(ip: IpAddr, port: u16, dur: Duration) -> bool {
    matches!(
        timeout(dur, TcpStream::connect(SocketAddr::new(ip, port))).await,
        Ok(Ok(_))
    )
}

/// Probe a single host for mobile-device management services. `mdns_services`
/// may carry service types already discovered elsewhere (else pass empty).
pub async fn probe(ip: IpAddr, dur: Duration, mdns_services: &[String]) -> Option<MobileDevice> {
    let mut open = Vec::new();
    if tcp_open(ip, ADB_PORT, dur).await {
        open.push(ADB_PORT);
    }
    if tcp_open(ip, LOCKDOWND_PORT, dur).await {
        open.push(LOCKDOWND_PORT);
    }
    classify(&open, mdns_services)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_from_adb_port() {
        let d = classify(&[5555, 80], &[]).unwrap();
        assert_eq!(d.os, "Android");
        assert!(d.evidence.iter().any(|e| e.contains("ADB")));
    }

    #[test]
    fn ios_from_lockdownd() {
        let d = classify(&[62078], &[]).unwrap();
        assert_eq!(d.os, "iOS/iPadOS");
    }

    #[test]
    fn apple_from_mdns_only() {
        let d = classify(&[], &["_airplay._tcp.local".to_string()]).unwrap();
        assert_eq!(d.os, "Apple device");
    }

    #[test]
    fn android_wins_over_apple_mdns() {
        // A device exposing both ADB and Apple mDNS is almost certainly Android
        // with an AirPlay receiver app; ADB is the stronger, actionable signal.
        let d = classify(&[5555], &["_raop._tcp".to_string()]).unwrap();
        assert_eq!(d.os, "Android");
    }

    #[test]
    fn nothing_mobile() {
        assert!(classify(&[80, 443, 22], &["_http._tcp".to_string()]).is_none());
    }
}
