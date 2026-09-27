//! QUIC / HTTP-3 detection scan (`--quic`) — a modern scan type (2020s).
//!
//! HTTP/3 runs over QUIC (UDP), invisible to every TCP scan. We send a
//! QUIC long-header packet carrying a deliberately **unsupported version**
//! (`0x1a2a3a4a`). Per RFC 9000 §6, a QUIC server must answer with a
//! **Version Negotiation** packet (version field = 0) listing the versions
//! it *does* speak — which both proves "this is QUIC/HTTP-3" and enumerates
//! the supported QUIC versions. Plain UDP, so no privileges needed.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicInfo {
    pub port: u16,
    pub versions: Vec<u32>,
}

impl QuicInfo {
    pub fn version_labels(&self) -> Vec<String> {
        self.versions.iter().map(|v| format!("{} (0x{:08x})", version_name(*v), v)).collect()
    }
}

/// Human name for a known QUIC version number.
pub fn version_name(v: u32) -> &'static str {
    match v {
        0x0000_0001 => "QUIC v1 (RFC 9000)",
        0x6b33_43cf => "QUIC v2 (RFC 9369)",
        0xff00_001d => "draft-29",
        0xface_b002 | 0xfaceb00e => "Google QUIC",
        v if (v & 0x0f0f_0f0f) == 0x0a0a_0a0a => "GREASE (reserved)",
        _ => "unknown QUIC version",
    }
}

/// Build a QUIC long-header packet with an unsupported version so the
/// server replies with a Version Negotiation packet. Padded to 1200 bytes
/// (QUIC's anti-amplification minimum for an Initial).
pub fn build_version_negotiation_trigger() -> Vec<u8> {
    let mut p = Vec::with_capacity(1200);
    p.push(0xC0); // long header, fixed bit set, type=Initial
    p.extend_from_slice(&0x1a2a_3a4au32.to_be_bytes()); // unsupported version
    p.push(8); // DCID length
    p.extend_from_slice(&[0x11; 8]); // DCID
    p.push(8); // SCID length
    p.extend_from_slice(&[0x22; 8]); // SCID (server echoes this as its DCID)
    p.push(0x00); // token length (varint 0) for Initial
    p.extend_from_slice(&[0x40, 0x00]); // length (varint, placeholder)
    p.resize(1200, 0x00); // pad
    p
}

/// Parse a Version Negotiation reply → the list of supported versions.
/// Returns `None` if `buf` isn't a QUIC VN packet.
pub fn parse_version_negotiation(buf: &[u8]) -> Option<Vec<u32>> {
    // Long header (high bit set) + version field == 0x00000000 == VN.
    if buf.len() < 7 || (buf[0] & 0x80) == 0 {
        return None;
    }
    if buf[1..5] != [0, 0, 0, 0] {
        return None;
    }
    let dcid_len = buf[5] as usize;
    let mut i = 6 + dcid_len;
    if i >= buf.len() {
        return None;
    }
    let scid_len = buf[i] as usize;
    i += 1 + scid_len;
    // Remainder is a list of 4-byte versions.
    let mut versions = Vec::new();
    while i + 4 <= buf.len() {
        let v = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        if v != 0 {
            versions.push(v);
        }
        i += 4;
    }
    if versions.is_empty() {
        None
    } else {
        Some(versions)
    }
}

/// Probe one UDP port for QUIC/HTTP-3.
pub async fn probe(ip: IpAddr, port: u16, dur: Duration) -> Option<QuicInfo> {
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(SocketAddr::new(ip, port)).await.ok()?;
    let pkt = build_version_negotiation_trigger();
    timeout(dur, sock.send(&pkt)).await.ok()?.ok()?;
    let mut buf = vec![0u8; 2048];
    let n = timeout(dur, sock.recv(&mut buf)).await.ok()?.ok()?;
    let versions = parse_version_negotiation(&buf[..n])?;
    Some(QuicInfo { port, versions })
}

pub fn print_report(host: &str, results: &[QuicInfo]) {
    use colored::*;
    println!();
    println!("{}", format!("QUIC / HTTP-3 scan of {}", host).bold());
    if results.is_empty() {
        println!("  {}", "no QUIC responder (no HTTP-3 on probed UDP ports)".dimmed());
        return;
    }
    for r in results {
        println!("  {}/udp  {}", r.port.to_string().green(), "QUIC / HTTP-3".green());
        for v in r.version_labels() {
            println!("      {}", v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_is_long_header_unsupported_version() {
        let p = build_version_negotiation_trigger();
        assert_eq!(p.len(), 1200);
        assert_eq!(p[0] & 0x80, 0x80); // long header
        assert_eq!(&p[1..5], &[0x1a, 0x2a, 0x3a, 0x4a]); // forced VN version
    }

    #[test]
    fn parse_vn_extracts_versions() {
        // VN: first byte long-header, version=0, DCID len 0, SCID len 0,
        // then versions v1 and v2.
        let mut buf = vec![0xC0u8, 0, 0, 0, 0, 0x00, 0x00];
        buf.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        buf.extend_from_slice(&0x6b33_43cfu32.to_be_bytes());
        let vs = parse_version_negotiation(&buf).unwrap();
        assert_eq!(vs, vec![0x0000_0001, 0x6b33_43cf]);
    }

    #[test]
    fn parse_rejects_non_vn() {
        // Short-header packet (high bit clear) → not VN.
        assert!(parse_version_negotiation(&[0x40, 1, 2, 3, 4, 5, 6]).is_none());
        // Long header but non-zero version → a real handshake, not VN.
        assert!(parse_version_negotiation(&[0xC0, 0, 0, 0, 1, 0, 0, 9, 9, 9, 9]).is_none());
    }

    #[test]
    fn version_names_known() {
        assert!(version_name(0x0000_0001).contains("v1"));
        assert!(version_name(0x6b33_43cf).contains("v2"));
        assert!(version_name(0x0a0a_0a0a).contains("GREASE"));
    }
}
