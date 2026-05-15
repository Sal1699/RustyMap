//! NetBIOS Name Service broadcast sweep (UDP/137 → 255.255.255.255).
//!
//! Companion to the unicast `netbios_ns::query` — this variant
//! blasts the NBSTAT request to the broadcast address. Every NBT-
//! enabled host on the segment replies in the same name-table
//! format. Useful when you want a one-shot inventory of the
//! Windows side of a LAN without enumerating every IP.
//!
//! We re-use the encoder + classifier from `netbios_ns.rs` so the
//! per-host parse stays consistent.

use crate::netbios_ns::NbtFinding;
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Send the wildcard NBSTAT query to 255.255.255.255 and collect
/// every reply seen within `dur`. Returns a HashMap keyed by source
/// IP so duplicates from the same responder are folded.
pub async fn sweep(dur: Duration) -> Result<Vec<NbtFinding>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.set_broadcast(true)?;

    let tx_id = (std::process::id() & 0xffff) as u16;
    let pkt = build_nbstat_wildcard(tx_id);
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, 137));
    sock.send_to(&pkt, dst).await?;

    let deadline = Instant::now() + dur;
    let mut by_src: HashMap<IpAddr, NbtFinding> = HashMap::new();
    let mut buf = vec![0u8; 1500];
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let r = timeout(remaining, sock.recv_from(&mut buf)).await;
        let Ok(Ok((n, src))) = r else { break };
        if let Some(f) = crate::netbios_ns::parse_nbstat_for_broadcast(&buf[..n], src.ip()) {
            by_src.insert(src.ip(), f);
        }
    }
    let mut out: Vec<NbtFinding> = by_src.into_values().collect();
    out.sort_by(|a, b| a.host.cmp(&b.host));
    Ok(out)
}

/// Build a wildcard NBSTAT query. Same packet shape as the unicast
/// version in `netbios_ns.rs` — duplicated here to keep this module
/// self-contained (the unicast module's `query` function calls
/// `recv` which assumes a unicast reply path).
pub fn build_nbstat_wildcard(tx_id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0010u16.to_be_bytes()); // flags = broadcast
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // Encode NetBIOS name "*" + NUL padding using first-half/second-half nibbles.
    let mut wildcard = [0u8; 16];
    wildcard[0] = b'*';
    pkt.push(0x20);
    for &b in &wildcard {
        pkt.push((b >> 4) + b'A');
        pkt.push((b & 0x0f) + b'A');
    }
    pkt.push(0x00); // terminator
    pkt.extend_from_slice(&0x0021u16.to_be_bytes()); // QTYPE = NBSTAT
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS = IN
    pkt
}

pub fn print_findings(findings: &[NbtFinding]) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!("NetBIOS broadcast sweep — {} responder(s)", findings.len()).bold()
    );
    if findings.is_empty() {
        println!("  {}", "no NBSTAT replies (segment may not run NBT, or broadcast blocked)".dimmed());
        return;
    }
    for f in findings {
        println!("  {}", f.host.bold());
        if let Some(c) = &f.computer_name {
            println!("    computer : {}", c);
        }
        if let Some(w) = &f.workgroup {
            println!("    workgroup: {}", w);
        }
        if let Some(u) = &f.logged_user {
            println!("    user     : {}", u.yellow());
        }
        if let Some(m) = &f.mac {
            println!("    MAC      : {}", m);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_wildcard_query_has_correct_qtype() {
        let pkt = build_nbstat_wildcard(0x1234);
        // 12 (header) + 34 (encoded name) + 4 (type+class) = 50
        assert_eq!(pkt.len(), 50);
        // QTYPE NBSTAT (0x0021)
        assert_eq!(&pkt[46..48], &[0x00, 0x21]);
        // QCLASS IN
        assert_eq!(&pkt[48..50], &[0x00, 0x01]);
        // tx-id round-trip
        assert_eq!(&pkt[0..2], &[0x12, 0x34]);
    }

    #[test]
    fn build_wildcard_encodes_star_as_ck_prefix() {
        let pkt = build_nbstat_wildcard(0);
        // After 12-byte header and length-byte 0x20, "*" encodes to "CK"
        // (0x2A → 0x02|A and 0x0A|A).
        assert_eq!(pkt[12], 0x20);
        assert_eq!(pkt[13], b'C');
        assert_eq!(pkt[14], b'K');
    }
}
