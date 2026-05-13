//! NetBIOS Name Service — NBSTAT query (UDP/137).
//!
//! Sends an NBSTAT (NetBIOS Adapter Status) request asking for `*` and
//! parses the responder's name table + MAC address. Surfaces:
//!
//!   - Computer name (NetBIOS hostname)
//!   - Workgroup / Domain
//!   - User logged on (if any name has the 0x03 suffix)
//!   - MAC address of the responding adapter
//!   - Role flags (Server, Domain Controller, Master Browser, …)
//!
//! NBT name encoding is the famous "first-half + second-half ASCII
//! nibbles" trick: each byte of the unencoded name becomes two
//! bytes in the wire form, by splitting it into the upper and lower
//! nibbles and adding `A` (0x41) to each. We send the encoded `*`
//! padded to 16 bytes with NUL (yields 32-byte encoded form).
//!
//! Read-only — single UDP packet round-trip.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NbtName {
    pub name: String,
    pub suffix: u8,
    pub flags: u16,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NbtFinding {
    pub host: String,
    pub computer_name: Option<String>,
    pub workgroup: Option<String>,
    pub logged_user: Option<String>,
    pub mac: Option<String>,
    pub names: Vec<NbtName>,
}

/// Encode a NetBIOS name (padded to 16 bytes with 0x20) using the
/// first-half/second-half nibble trick, then wrap in a labelled
/// DNS-style name component.
fn encode_netbios_name(name: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(34);
    out.push(0x20); // length of the encoded label = 32 bytes
    for &b in name {
        out.push((b >> 4) + b'A');
        out.push((b & 0x0f) + b'A');
    }
    out.push(0x00); // terminator
    out
}

/// Build an NBSTAT query for the wildcard name (`*` followed by NUL
/// padding). The query type is 0x21 (NBSTAT), class 0x0001 (IN).
fn build_nbstat_query(tx_id: u16) -> Vec<u8> {
    let mut wildcard = [0u8; 16];
    wildcard[0] = b'*';

    let mut pkt = Vec::with_capacity(50);
    // DNS header: tx_id, flags(0x0010 broadcast), QD/AN/NS/AR counts
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0010u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    pkt.extend_from_slice(&encode_netbios_name(&wildcard));
    pkt.extend_from_slice(&0x0021u16.to_be_bytes()); // QTYPE = NBSTAT
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS = IN
    pkt
}

pub async fn query(host: IpAddr, dur: Duration) -> Result<Option<NbtFinding>> {
    let bind = if host.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    let dst = SocketAddr::new(host, 137);

    let tx_id = (std::process::id() & 0xffff) as u16;
    let pkt = build_nbstat_query(tx_id);
    if timeout(dur, sock.send_to(&pkt, dst)).await.is_err() {
        return Ok(None);
    }
    let mut buf = vec![0u8; 1500];
    let n = match timeout(dur, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return Ok(None),
    };
    Ok(parse_nbstat_response(&buf[..n], host))
}

fn parse_nbstat_response(buf: &[u8], host: IpAddr) -> Option<NbtFinding> {
    if buf.len() < 12 {
        return None;
    }
    // Skip the DNS-style header + question section to the answer.
    // Header is 12 bytes; question = encoded-name (34) + type(2) + class(2) = 38.
    // Answer name (compressed or full) + type(2) + class(2) + ttl(4) + rdlength(2).
    // We seek to the NUM_NAMES byte: it sits right after the RR header.
    let mut p = 12usize;
    // Skip question encoded name (assumed 34 bytes since our query used a full
    // label) + type(2) + class(2).
    p += 34 + 4;
    if p >= buf.len() {
        return None;
    }
    // Skip answer-section RR name. May be compressed (0xC0 0x0C pointer
    // → 2 bytes) or a full 34-byte label.
    if buf[p] & 0xC0 == 0xC0 {
        p += 2;
    } else {
        p += 34;
    }
    // Type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes
    p += 10;
    if p + 1 > buf.len() {
        return None;
    }
    let num_names = buf[p] as usize;
    p += 1;
    if p + num_names * 18 + 6 > buf.len() {
        return None;
    }

    let mut finding = NbtFinding {
        host: host.to_string(),
        ..Default::default()
    };

    for _ in 0..num_names {
        let raw_name = &buf[p..p + 15];
        let suffix = buf[p + 15];
        let flags = u16::from_be_bytes([buf[p + 16], buf[p + 17]]);
        p += 18;
        let name_trimmed = String::from_utf8_lossy(raw_name).trim_end().to_string();
        let kind = classify_suffix(suffix, flags);
        match suffix {
            0x00 if (flags & 0x8000) == 0 => {
                // Workstation service (unique name) — computer name
                finding.computer_name = Some(name_trimmed.clone());
            }
            0x00 if (flags & 0x8000) != 0 => {
                // Workgroup name (group name)
                finding.workgroup = Some(name_trimmed.clone());
            }
            0x03 => {
                finding.logged_user = Some(name_trimmed.clone());
            }
            0x20 if (flags & 0x8000) == 0 => {
                // File-server service — confirms it's a "Server"
                if finding.computer_name.is_none() {
                    finding.computer_name = Some(name_trimmed.clone());
                }
            }
            _ => {}
        }
        finding.names.push(NbtName {
            name: name_trimmed,
            suffix,
            flags,
            kind: kind.to_string(),
        });
    }

    // MAC: 6 bytes immediately after the names table
    if p + 6 <= buf.len() {
        let m = &buf[p..p + 6];
        finding.mac = Some(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        ));
    }
    Some(finding)
}

fn classify_suffix(suffix: u8, flags: u16) -> &'static str {
    let group = (flags & 0x8000) != 0;
    match (suffix, group) {
        (0x00, false) => "Workstation",
        (0x00, true) => "Workgroup",
        (0x03, _) => "Messenger / logged user",
        (0x20, false) => "File Server",
        (0x1B, false) => "Domain Master Browser",
        (0x1C, true) => "Domain Controllers group",
        (0x1D, false) => "Master Browser",
        (0x1E, true) => "Browser Service Elections",
        _ => "Other",
    }
}

pub fn print_finding(f: &NbtFinding) {
    use colored::*;
    println!();
    println!("{}", format!("NetBIOS NBSTAT on {}", f.host).bold());
    if let Some(c) = &f.computer_name {
        println!("  computer : {}", c.bold());
    }
    if let Some(w) = &f.workgroup {
        println!("  workgroup: {}", w);
    }
    if let Some(u) = &f.logged_user {
        println!("  user     : {} {}", u.yellow(), "(currently logged on)".dimmed());
    }
    if let Some(m) = &f.mac {
        println!("  MAC      : {}", m);
    }
    if !f.names.is_empty() {
        println!("  name table ({} entries):", f.names.len());
        for n in &f.names {
            println!("    [{:02x}] {:<16} {}", n.suffix, n.name, n.kind);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_netbios_wildcard_matches_reference() {
        let mut wildcard = [0u8; 16];
        wildcard[0] = b'*';
        let encoded = encode_netbios_name(&wildcard);
        // length-byte 0x20, '*' = 0x2A → 0x02+0x41=0x43('C'), 0x0A+0x41=0x4B('K')
        assert_eq!(encoded[0], 0x20);
        assert_eq!(encoded[1], b'C');
        assert_eq!(encoded[2], b'K');
        // padding bytes (0x00) → 0x00+0x41=0x41, 0x00+0x41=0x41
        for i in 3..33 {
            assert_eq!(encoded[i], b'A');
        }
        // terminator
        assert_eq!(encoded[33], 0x00);
    }

    #[test]
    fn build_nbstat_query_size_and_qtype() {
        let pkt = build_nbstat_query(0x1234);
        // 12 (header) + 34 (encoded name) + 4 (type+class) = 50
        assert_eq!(pkt.len(), 50);
        // QTYPE NBSTAT (0x0021)
        assert_eq!(&pkt[46..48], &[0x00, 0x21]);
        // QCLASS IN
        assert_eq!(&pkt[48..50], &[0x00, 0x01]);
    }

    #[test]
    fn classify_suffix_recognises_common_codes() {
        assert_eq!(classify_suffix(0x00, 0x0000), "Workstation");
        assert_eq!(classify_suffix(0x00, 0x8000), "Workgroup");
        assert_eq!(classify_suffix(0x20, 0x0000), "File Server");
        assert_eq!(classify_suffix(0x1B, 0x0000), "Domain Master Browser");
        assert_eq!(classify_suffix(0x1D, 0x0000), "Master Browser");
        assert_eq!(classify_suffix(0xFF, 0x0000), "Other");
    }
}
