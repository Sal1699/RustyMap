//! LLMNR multicast discovery on 224.0.0.252:5355.
//!
//! Link-Local Multicast Name Resolution (RFC 4795) is the Microsoft
//! fallback for hostname resolution when DNS fails. Every Windows
//! host has it enabled by default. We send an LLMNR query for a
//! deliberately-suspicious name (`rustymap-LLMNR-probe`); a Windows
//! host that hasn't been hardened against LLMNR poisoning *will
//! reply* claiming it owns that name — confirming the responder is
//! present and willing to answer arbitrary queries.
//!
//! This doubles as a passive **LLMNR poisoning surface check**:
//! anything that volunteers an A-record for a name nobody actually
//! owns is exactly the misconfiguration Responder / Inveigh
//! exploits.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const LLMNR_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
const LLMNR_PORT: u16 = 5355;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmnrResponder {
    pub source: String,
    pub claimed_name: String,
    pub answered_ip: Option<String>,
}

pub async fn discover(probe_name: &str, dur: Duration) -> Result<Vec<LlmnrResponder>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.set_multicast_loop_v4(false)?;

    let tx_id: u16 = rand::random();
    let query = build_llmnr_query(probe_name, tx_id);
    let dst = SocketAddr::V4(SocketAddrV4::new(LLMNR_GROUP, LLMNR_PORT));
    sock.send_to(&query, dst).await?;

    let deadline = Instant::now() + dur;
    let mut out: Vec<LlmnrResponder> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut buf = vec![0u8; 1500];

    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let r = timeout(remaining, sock.recv_from(&mut buf)).await;
        let Ok(Ok((n, src))) = r else { break };
        if let Some(ans) = parse_a_response(&buf[..n], tx_id, probe_name) {
            let key = format!("{}|{}", src.ip(), ans.0);
            if seen.insert(key) {
                out.push(LlmnrResponder {
                    source: src.ip().to_string(),
                    claimed_name: ans.0,
                    answered_ip: Some(ans.1),
                });
            }
        }
    }
    Ok(out)
}

pub fn build_llmnr_query(qname: &str, tx_id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&tx_id.to_be_bytes());
    q.extend_from_slice(&0x0000u16.to_be_bytes()); // flags
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in qname.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // QTYPE A
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS IN
    q
}

/// Parse an LLMNR response. Returns `(answered_name, ip)` when a
/// type-A answer is present for the probe.
pub fn parse_a_response(pkt: &[u8], expected_xid: u16, probe: &str) -> Option<(String, String)> {
    if pkt.len() < 12 {
        return None;
    }
    let xid = u16::from_be_bytes([pkt[0], pkt[1]]);
    if xid != expected_xid {
        return None;
    }
    let qd = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let an = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    if an == 0 {
        return None;
    }
    let mut p = 12usize;
    for _ in 0..qd {
        p = skip_name(pkt, p) + 4;
        if p > pkt.len() {
            return None;
        }
    }
    for _ in 0..an {
        if p >= pkt.len() {
            return None;
        }
        let name = read_name(pkt, p).unwrap_or_default();
        p = skip_name(pkt, p);
        if p + 10 > pkt.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([pkt[p], pkt[p + 1]]);
        let rdlen = u16::from_be_bytes([pkt[p + 8], pkt[p + 9]]) as usize;
        p += 10;
        if p + rdlen > pkt.len() {
            return None;
        }
        if rtype == 1 && rdlen == 4 {
            let ip = Ipv4Addr::new(pkt[p], pkt[p + 1], pkt[p + 2], pkt[p + 3]).to_string();
            let answered = if !name.is_empty() { name } else { probe.to_string() };
            return Some((answered, ip));
        }
        p += rdlen;
    }
    None
}

fn skip_name(pkt: &[u8], mut p: usize) -> usize {
    loop {
        if p >= pkt.len() {
            return p;
        }
        let b = pkt[p];
        if b == 0 {
            return p + 1;
        }
        if b & 0xc0 == 0xc0 {
            return p + 2;
        }
        p += 1 + b as usize;
    }
}

fn read_name(pkt: &[u8], start: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut p = start;
    let mut jumps = 0;
    let mut bounds = pkt.len();
    while p < bounds {
        let b = pkt[p];
        if b == 0 {
            break;
        }
        if b & 0xc0 == 0xc0 {
            if p + 1 >= pkt.len() {
                return None;
            }
            let off = (((b as usize) & 0x3f) << 8) | pkt[p + 1] as usize;
            if off >= pkt.len() || off >= bounds {
                return None;
            }
            jumps += 1;
            if jumps > 8 {
                return None;
            }
            bounds = p;
            p = off;
            continue;
        }
        if p + 1 + b as usize > pkt.len() {
            return None;
        }
        let label = &pkt[p + 1..p + 1 + b as usize];
        labels.push(String::from_utf8_lossy(label).into_owned());
        p += 1 + b as usize;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

pub fn print_finding(responders: &[LlmnrResponder]) {
    use colored::*;
    println!();
    println!("{}", format!("LLMNR poisoning surface — {} responder(s)", responders.len()).bold());
    if responders.is_empty() {
        println!("  {}", "no host volunteered an answer for the bogus name".green());
        return;
    }
    for r in responders {
        let ip = r.answered_ip.as_deref().unwrap_or("?");
        println!(
            "  {} answered {} → {}  (Responder/Inveigh-poisonable)",
            r.source.bold(),
            r.claimed_name.yellow(),
            ip
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_llmnr_query_layout() {
        let q = build_llmnr_query("xyz.local", 0xCAFE);
        assert_eq!(&q[0..2], &[0xCA, 0xFE]);
        // QDCOUNT = 1
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        // ends with type A (1) and class IN (1)
        let l = q.len();
        assert_eq!(&q[l - 4..l - 2], &[0x00, 0x01]);
        assert_eq!(&q[l - 2..l], &[0x00, 0x01]);
    }

    #[test]
    fn parse_response_finds_a_record() {
        // Manual LLMNR response: query for "rustymap-LLMNR-probe", answer
        // type A pointing to 10.0.0.42.
        let mut pkt = vec![
            0x00, 0x01, // xid
            0x84, 0x00, // flags (response, AA)
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        // Question
        let label = "rustymap-LLMNR-probe";
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A / IN
        // Answer: compression pointer back to offset 12, type A, IN, TTL 60, rdlen 4
        pkt.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04]);
        pkt.extend_from_slice(&[10, 0, 0, 42]);

        let r = parse_a_response(&pkt, 0x0001, "rustymap-LLMNR-probe").unwrap();
        assert_eq!(r.1, "10.0.0.42");
        assert!(r.0.contains("rustymap"));
    }

    #[test]
    fn parse_response_rejects_wrong_xid() {
        let mut pkt = vec![0x00, 0xff, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        pkt.resize(40, 0);
        assert!(parse_a_response(&pkt, 0x0001, "x").is_none());
    }

    #[test]
    fn parse_response_handles_no_answers() {
        let pkt = vec![0x00, 0x01, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(parse_a_response(&pkt, 0x0001, "x").is_none());
    }
}
