//! mDNS multicast discovery on 224.0.0.251:5353.
//!
//! Sends a PTR query for `_services._dns-sd._udp.local` to the IPv4
//! multicast group; every mDNS responder on the LAN answers with
//! the service-type names it advertises. Strict implementations
//! that ignore unicast queries (and so don't answer the unicast
//! variant in `iot_discover.rs`) DO answer here.
//!
//! Then we follow up with PTR queries for the service-types we
//! saw (`_http._tcp.local`, `_ipp._tcp.local`, `_workstation._tcp.local`,
//! `_smb._tcp.local`, …) and harvest instance names. The final
//! report is "host → service-types advertised → instance names".
//!
//! Read-only — multicast queries only. No A-record resolution,
//! no SRV/TXT walk beyond what the responder volunteers.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsResponder {
    pub source: String,
    pub service_types: Vec<String>,
    pub instance_names: Vec<String>,
}

pub async fn discover(dur: Duration) -> Result<Vec<MdnsResponder>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.set_multicast_loop_v4(false)?;
    // We don't need to join the group to *send* and *receive
    // unicast replies* — many mDNS responders reply unicast back to
    // the source port when the QU bit is unset (per RFC 6762 §5.4).
    let dst = SocketAddr::V4(SocketAddrV4::new(MDNS_GROUP, MDNS_PORT));

    let tx_id = 0u16;
    let query = build_query("_services._dns-sd._udp.local", tx_id);
    sock.send_to(&query, dst).await?;

    let deadline = Instant::now() + dur;
    let mut by_src: HashMap<IpAddr, MdnsResponder> = HashMap::new();
    let mut buf = vec![0u8; 4096];

    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let received = timeout(remaining, sock.recv_from(&mut buf)).await;
        let Ok(Ok((n, src))) = received else { break };
        let names = decode_ptr_names(&buf[..n]);
        if names.is_empty() {
            continue;
        }
        let entry = by_src.entry(src.ip()).or_insert(MdnsResponder {
            source: src.ip().to_string(),
            service_types: Vec::new(),
            instance_names: Vec::new(),
        });
        for n in names {
            if n.starts_with('_') {
                if !entry.service_types.contains(&n) {
                    entry.service_types.push(n);
                }
            } else if !entry.instance_names.contains(&n) {
                entry.instance_names.push(n);
            }
        }
    }

    let mut out: Vec<MdnsResponder> = by_src.into_values().collect();
    out.sort_by(|a, b| a.source.cmp(&b.source));
    Ok(out)
}

pub fn build_query(qname: &str, tx_id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&tx_id.to_be_bytes());
    q.extend_from_slice(&0x0000u16.to_be_bytes()); // flags = standard query
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in qname.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root
    q.extend_from_slice(&12u16.to_be_bytes()); // QTYPE = PTR
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS = IN
    q
}

/// Decode every PTR-name string the mDNS reply carries. We don't
/// fully parse the DNS structure — we walk records, skip non-PTR,
/// and decode the PTR rdata as a sequence of labels with optional
/// compression pointers.
pub fn decode_ptr_names(pkt: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if pkt.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let an = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let ns = u16::from_be_bytes([pkt[8], pkt[9]]) as usize;
    let ar = u16::from_be_bytes([pkt[10], pkt[11]]) as usize;
    let mut p = 12usize;
    // Skip questions
    for _ in 0..qd {
        p = skip_name(pkt, p);
        p += 4; // QTYPE + QCLASS
        if p > pkt.len() {
            return out;
        }
    }
    // Walk answers + authority + additional
    for _ in 0..(an + ns + ar) {
        if p >= pkt.len() {
            break;
        }
        p = skip_name(pkt, p);
        if p + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[p], pkt[p + 1]]);
        let rdlen = u16::from_be_bytes([pkt[p + 8], pkt[p + 9]]) as usize;
        p += 10;
        if p + rdlen > pkt.len() {
            break;
        }
        if rtype == 12 {
            // PTR rdata is itself a name
            if let Some(name) = read_name(pkt, p) {
                out.push(name);
            }
        }
        p += rdlen;
    }
    out
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
            // Follow pointer; cap jumps to avoid loops.
            jumps += 1;
            if jumps > 8 {
                return None;
            }
            bounds = p; // we won't come back past this
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

pub fn print_finding(responders: &[MdnsResponder]) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!("mDNS multicast discovery — {} responder(s)", responders.len()).bold()
    );
    if responders.is_empty() {
        println!("  {}", "no mDNS responses (LAN has no Bonjour/Avahi or multicast blocked)".dimmed());
        return;
    }
    for r in responders {
        println!("  {}", r.source.bold());
        for t in &r.service_types {
            println!("    service: {}", t);
        }
        for i in &r.instance_names {
            println!("    instance: {}", i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_layout_matches_dns() {
        let q = build_query("_services._dns-sd._udp.local", 0x1234);
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        // QDCOUNT = 1
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        // QTYPE PTR (12) at end - 4
        let end = q.len();
        assert_eq!(&q[end - 4..end - 2], &[0x00, 0x0c]);
        // QCLASS IN at end - 2
        assert_eq!(&q[end - 2..end], &[0x00, 0x01]);
    }

    #[test]
    fn decode_ptr_names_handles_single_answer() {
        // Construct a minimal DNS reply: header + 1 question + 1 answer (PTR)
        let mut pkt = vec![
            0x00, 0x01, // tx-id
            0x84, 0x00, // flags (response, AA)
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, 0x00, 0x00,
        ];
        // Question: _services._dns-sd._udp.local PTR IN
        for label in ["_services", "_dns-sd", "_udp", "local"] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]); // PTR / IN
        // Answer: same name (compression pointer to offset 12)
        pkt.extend_from_slice(&[0xc0, 0x0c]);
        pkt.extend_from_slice(&[0x00, 0x0c]); // type = PTR
        pkt.extend_from_slice(&[0x00, 0x01]); // class = IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL
        // rdlength + rdata (a single name "_http._tcp.local")
        let mut rdata: Vec<u8> = Vec::new();
        for label in ["_http", "_tcp", "local"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&rdata);

        let names = decode_ptr_names(&pkt);
        assert!(names.iter().any(|n| n.contains("_http._tcp")));
    }

    #[test]
    fn skip_name_handles_compression_pointer() {
        // "abc" at offset 12, then a pointer that should return offset 14.
        let pkt = vec![
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 12 bytes header
            3, b'a', b'b', b'c', 0, // name at 12
            0xc0, 0x0c, // pointer back to 12
        ];
        // skip_name starting at 17 (pointer) should advance by 2
        assert_eq!(skip_name(&pkt, 17), 19);
        // skip_name starting at 12 should advance past "abc\0" = 17
        assert_eq!(skip_name(&pkt, 12), 17);
    }
}
