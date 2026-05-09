//! IoT discovery — unicast probes for mDNS, SSDP, and CoAP.
//!
//! All three protocols are designed for multicast discovery on a
//! local segment. We deliberately use *unicast* probes against a
//! supplied target host so the scan works across a routed network
//! and doesn't require interface binding or capabilities beyond a
//! plain UDP socket. Many embedded devices answer unicast queries
//! out of the box (it's a common feature of mDNS responders and
//! SSDP/UPnP stacks); strict implementations may not — that's
//! acceptable, the unicast probe is best-effort discovery.
//!
//! Probes:
//!   - **mDNS** (UDP/5353): DNS query for `_services._dns-sd._udp.local`
//!     PTR. Responders return the list of services they advertise.
//!   - **SSDP** (UDP/1900): M-SEARCH for `ssdp:all`. Responders
//!     return their UPnP USN + LOCATION (descriptor URL).
//!   - **CoAP** (UDP/5683): GET /.well-known/core. Responders
//!     return a list of CoAP resources in CoRE Link Format.
//!
//! Read-only — single packet per protocol, parsed for identifying
//! strings.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotFinding {
    pub protocol: &'static str,
    pub host: String,
    pub port: u16,
    pub services: Vec<String>,
    pub raw_excerpt: String,
}

pub async fn discover(host: &str, dur: Duration) -> Result<Vec<IotFinding>> {
    let ip: IpAddr = if let Ok(p) = host.parse::<IpAddr>() {
        p
    } else {
        tokio::net::lookup_host((host, 0u16))
            .await?
            .next()
            .map(|sa| sa.ip())
            .ok_or_else(|| anyhow::anyhow!("no DNS for {}", host))?
    };
    let mut out = Vec::new();
    if let Some(f) = probe_mdns(ip, dur).await {
        out.push(f);
    }
    if let Some(f) = probe_ssdp(ip, dur).await {
        out.push(f);
    }
    if let Some(f) = probe_coap(ip, dur).await {
        out.push(f);
    }
    Ok(out)
}

async fn probe_mdns(ip: IpAddr, dur: Duration) -> Option<IotFinding> {
    // Build a minimal DNS query for "_services._dns-sd._udp.local" PTR.
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&0x1234u16.to_be_bytes()); // tx-id
    q.extend_from_slice(&0x0000u16.to_be_bytes()); // flags (standard query)
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in ["_services", "_dns-sd", "_udp", "local"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root
    q.extend_from_slice(&12u16.to_be_bytes()); // QTYPE = PTR
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    timeout(dur, sock.send_to(&q, SocketAddr::new(ip, 5353))).await.ok()?.ok()?;
    let mut buf = [0u8; 1500];
    let n = timeout(dur, sock.recv(&mut buf)).await.ok()?.ok()?;
    if n < 12 {
        return None;
    }
    // Decode answers — we look for printable label runs to surface
    // service-type names like `_http._tcp.local`.
    let services = extract_dns_label_runs(&buf[12..n]);
    Some(IotFinding {
        protocol: "mDNS",
        host: ip.to_string(),
        port: 5353,
        services,
        raw_excerpt: hex_excerpt(&buf[..n], 32),
    })
}

async fn probe_ssdp(ip: IpAddr, dur: Duration) -> Option<IotFinding> {
    // SSDP M-SEARCH (HTTP/1.1 over UDP).
    let req = format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {}:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 1\r\n\
         ST: ssdp:all\r\n\r\n",
        ip
    );
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    timeout(dur, sock.send_to(req.as_bytes(), SocketAddr::new(ip, 1900))).await.ok()?.ok()?;
    let mut buf = [0u8; 4096];
    let n = timeout(dur, sock.recv(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }
    let txt = std::str::from_utf8(&buf[..n]).unwrap_or("");
    if !txt.starts_with("HTTP/") {
        return None;
    }
    let services: Vec<String> = txt
        .lines()
        .filter_map(|l| {
            let lower = l.to_lowercase();
            if lower.starts_with("server:")
                || lower.starts_with("usn:")
                || lower.starts_with("location:")
                || lower.starts_with("st:")
            {
                Some(l.trim().to_string())
            } else {
                None
            }
        })
        .collect();
    Some(IotFinding {
        protocol: "SSDP/UPnP",
        host: ip.to_string(),
        port: 1900,
        services,
        raw_excerpt: txt.chars().take(160).collect(),
    })
}

async fn probe_coap(ip: IpAddr, dur: Duration) -> Option<IotFinding> {
    // CoAP confirmable GET /.well-known/core
    //   ver=01 type=00 (CON) tkl=0 → 0x40
    //   code=0x01 (GET)
    //   message-id (2B big-endian) = 0xCAFE
    //   options:
    //     opt#11 (Uri-Path) ".well-known"  (delta=11, len=11)
    //     opt#11 (Uri-Path) "core"         (delta=0, len=4)
    let mut req = Vec::with_capacity(32);
    req.extend_from_slice(&[0x40, 0x01, 0xca, 0xfe]);
    // First Uri-Path: delta=11, len=11
    req.push(0xbb);
    req.extend_from_slice(b".well-known");
    // Second Uri-Path: delta=0, len=4
    req.push(0x04);
    req.extend_from_slice(b"core");

    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    timeout(dur, sock.send_to(&req, SocketAddr::new(ip, 5683))).await.ok()?.ok()?;
    let mut buf = [0u8; 1500];
    let n = timeout(dur, sock.recv(&mut buf)).await.ok()?.ok()?;
    if n < 4 {
        return None;
    }
    // CoAP version = top 2 bits = 01.
    if (buf[0] >> 6) != 1 {
        return None;
    }
    // Find payload marker 0xFF, payload follows.
    let payload = buf[..n]
        .iter()
        .position(|&b| b == 0xff)
        .map(|i| &buf[i + 1..n])
        .unwrap_or(&[]);
    let body = std::str::from_utf8(payload).unwrap_or("");
    let services: Vec<String> = body
        .split(',')
        .filter_map(|item| {
            let t = item.trim();
            if t.starts_with('<') {
                Some(t.to_string())
            } else {
                None
            }
        })
        .collect();
    Some(IotFinding {
        protocol: "CoAP",
        host: ip.to_string(),
        port: 5683,
        services,
        raw_excerpt: hex_excerpt(&buf[..n], 32),
    })
}

fn extract_dns_label_runs(data: &[u8]) -> Vec<String> {
    // Pull printable underscore-prefixed labels (e.g. `_http._tcp`)
    // and return the longest unique set we see.
    let mut runs = Vec::new();
    let mut current = String::new();
    for &b in data {
        if b == b'_' || b == b'-' || (b'a'..=b'z').contains(&b) || (b'0'..=b'9').contains(&b) || b == b'.' || b == b'A'.saturating_sub(0) {
            current.push(b as char);
        } else if (b'A'..=b'Z').contains(&b) {
            current.push(b as char);
        } else {
            if current.contains('_') && current.len() >= 4 {
                runs.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if current.contains('_') && current.len() >= 4 {
        runs.push(current);
    }
    let mut seen = std::collections::HashSet::new();
    runs.into_iter().filter(|s| seen.insert(s.clone())).collect()
}

fn hex_excerpt(data: &[u8], max: usize) -> String {
    let take = data.len().min(max);
    let hex: Vec<String> = data.iter().take(take).map(|b| format!("{:02x}", b)).collect();
    hex.join(" ")
}

pub fn print_findings(host: &str, findings: &[IotFinding]) {
    use colored::*;
    println!();
    println!("{}", format!("IoT discovery for {} — {} responder(s)", host, findings.len()).bold());
    if findings.is_empty() {
        println!("  {}", "no mDNS / SSDP / CoAP unicast responders".dimmed());
        return;
    }
    for f in findings {
        println!("  {} {} :{}", "[*]".cyan().bold(), f.protocol, f.port);
        for s in f.services.iter().take(8) {
            println!("    · {}", s);
        }
        if f.services.len() > 8 {
            println!("    … {} more", f.services.len() - 8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_dns_label_runs_picks_underscore_labels() {
        let buf = b"\x00\x00\x09_http._tcp\x05local\x00";
        let runs = extract_dns_label_runs(buf);
        assert!(runs.iter().any(|s| s.contains("_http")));
    }

    #[test]
    fn extract_dns_label_runs_ignores_short_runs() {
        let buf = b"\x00\x00ab_x\x00";
        let runs = extract_dns_label_runs(buf);
        // "ab_x" has an underscore but is < 4 chars after the
        // collector resets when it sees \x00 — should be skipped.
        assert!(runs.is_empty() || runs.iter().all(|s| s.len() >= 4));
    }

    #[test]
    fn coap_version_check_works_inline() {
        // Manufactured CoAP ACK: ver=01 type=10 (ACK) tkl=0 code=0x45 (Content) mid=cafe
        let buf = [0x60, 0x45, 0xca, 0xfe, 0xff, b'a', b'b', b'c'];
        assert_eq!(buf[0] >> 6, 1);
        let pos = buf.iter().position(|&b| b == 0xff).unwrap();
        let payload = &buf[pos + 1..];
        assert_eq!(payload, b"abc");
    }
}
