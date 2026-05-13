//! `-iR N` — generate N random *public* IPv4 addresses for research
//! / measurement scans. Skips reserved, private, and well-known
//! special-use ranges so the scan stays in scope of "addresses that
//! could plausibly answer".
//!
//! **Hard-gated** behind `--internet-consent`. Without it, generation
//! refuses outright. The user has to type the flag — it's the closest
//! we can get to "I know what I'm doing" without a captcha.
//!
//! Excluded ranges (RFC 1918, 5735, 6598, 6890, 6598, plus IANA
//! special-use additions through 2026):
//!
//!   - 0.0.0.0/8       this network
//!   - 10.0.0.0/8      RFC 1918
//!   - 100.64.0.0/10   RFC 6598 carrier-grade NAT
//!   - 127.0.0.0/8     loopback
//!   - 169.254.0.0/16  link-local
//!   - 172.16.0.0/12   RFC 1918
//!   - 192.0.0.0/24    RFC 6890 IETF protocol assignments
//!   - 192.0.2.0/24    TEST-NET-1
//!   - 192.88.99.0/24  6to4 anycast (deprecated)
//!   - 192.168.0.0/16  RFC 1918
//!   - 198.18.0.0/15   RFC 2544 benchmarking
//!   - 198.51.100.0/24 TEST-NET-2
//!   - 203.0.113.0/24  TEST-NET-3
//!   - 224.0.0.0/4     multicast
//!   - 240.0.0.0/4     reserved (includes 255.255.255.255)
//!
//! Skipping these matches what nmap's `-iR` does internally.

use crate::target::Target;
use anyhow::{anyhow, Result};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};

/// Returns true when `ip` falls inside any reserved / private /
/// special-use IPv4 block we don't want to scan blindly.
pub fn is_reserved(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // 0.0.0.0/8
    if o[0] == 0 { return true; }
    // 10.0.0.0/8
    if o[0] == 10 { return true; }
    // 100.64.0.0/10
    if o[0] == 100 && o[1] >= 64 && o[1] <= 127 { return true; }
    // 127.0.0.0/8
    if o[0] == 127 { return true; }
    // 169.254.0.0/16
    if o[0] == 169 && o[1] == 254 { return true; }
    // 172.16.0.0/12
    if o[0] == 172 && o[1] >= 16 && o[1] <= 31 { return true; }
    // 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24
    if o[0] == 192 && o[1] == 0 && o[2] == 0 { return true; }
    if o[0] == 192 && o[1] == 0 && o[2] == 2 { return true; }
    if o[0] == 192 && o[1] == 88 && o[2] == 99 { return true; }
    // 192.168.0.0/16
    if o[0] == 192 && o[1] == 168 { return true; }
    // 198.18.0.0/15
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) { return true; }
    // 198.51.100.0/24
    if o[0] == 198 && o[1] == 51 && o[2] == 100 { return true; }
    // 203.0.113.0/24
    if o[0] == 203 && o[1] == 0 && o[2] == 113 { return true; }
    // 224.0.0.0/4 multicast & 240.0.0.0/4 reserved
    if o[0] >= 224 { return true; }

    false
}

pub fn generate(n: usize, consent: bool) -> Result<Vec<Target>> {
    if !consent {
        return Err(anyhow!(
            "-iR refuses without --internet-consent. Random Internet scanning \
             may violate provider AUP and target ToS — set the flag explicitly \
             to confirm you have authorisation for this measurement."
        ));
    }
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut rng = rand::thread_rng();
    let mut out: Vec<Target> = Vec::with_capacity(n);
    let mut attempts = 0usize;
    while out.len() < n {
        attempts += 1;
        if attempts > n * 50 {
            // Shouldn't happen with public IPv4 still being most of the
            // space; bail rather than spin forever.
            return Err(anyhow!(
                "couldn't generate {} non-reserved addresses after {} attempts",
                n, attempts
            ));
        }
        let raw: u32 = rng.gen();
        let ip = Ipv4Addr::from(raw);
        if is_reserved(ip) {
            continue;
        }
        out.push(Target {
            ip: IpAddr::V4(ip),
            hostname: None,
            zone: None,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_rfc1918() {
        assert!(is_reserved("10.0.0.1".parse().unwrap()));
        assert!(is_reserved("172.16.0.1".parse().unwrap()));
        assert!(is_reserved("172.31.255.254".parse().unwrap()));
        assert!(is_reserved("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn rejects_loopback_linklocal_multicast() {
        assert!(is_reserved("127.0.0.1".parse().unwrap()));
        assert!(is_reserved("169.254.1.1".parse().unwrap()));
        assert!(is_reserved("224.0.0.1".parse().unwrap()));
        assert!(is_reserved("239.0.0.1".parse().unwrap()));
        assert!(is_reserved("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn rejects_documentation_test_nets() {
        assert!(is_reserved("192.0.2.1".parse().unwrap()));
        assert!(is_reserved("198.51.100.42".parse().unwrap()));
        assert!(is_reserved("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn rejects_cgnat_and_benchmarking() {
        assert!(is_reserved("100.64.0.1".parse().unwrap()));
        assert!(is_reserved("198.18.0.1".parse().unwrap()));
        assert!(is_reserved("198.19.255.255".parse().unwrap()));
    }

    #[test]
    fn accepts_genuine_public_addresses() {
        assert!(!is_reserved("8.8.8.8".parse().unwrap()));
        assert!(!is_reserved("1.1.1.1".parse().unwrap()));
        assert!(!is_reserved("142.251.41.46".parse().unwrap()));
    }

    #[test]
    fn rejects_when_consent_missing() {
        let r = generate(5, false);
        assert!(r.is_err());
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("--internet-consent"));
    }

    #[test]
    fn generate_returns_n_public_addresses() {
        let v = generate(20, true).unwrap();
        assert_eq!(v.len(), 20);
        for t in &v {
            if let IpAddr::V4(v4) = t.ip {
                assert!(!is_reserved(v4));
            }
        }
    }

    #[test]
    fn generate_zero_returns_empty() {
        let v = generate(0, true).unwrap();
        assert!(v.is_empty());
    }
}
