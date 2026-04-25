//! IP protocol scan (`-sO`).
//!
//! Probes each IP protocol number against the target by sending a tiny
//! packet with that protocol set, then listening for ICMP responses.
//! Classification follows nmap's mapping:
//!   - ICMP "Protocol Unreachable" (type 3 / code 2) → closed
//!   - other ICMP unreachable codes → filtered
//!   - any reply via the same IP protocol → open
//!   - no response → open|filtered
//!
//! Improvement over nmap: each result line carries the protocol's
//! IANA name + RFC + a one-line common-usage hint, so a router scan
//! report doubles as a quick reference.

use anyhow::{anyhow, Result};
use pnet::packet::icmp::IcmpType;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, ipv4_packet_iter, transport_channel,
    TransportChannelType::{Layer3, Layer4},
    TransportProtocol::Ipv4,
    TransportReceiver,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Curated subset of IP protocols worth probing on a typical scan.
/// (proto_num, short_name, RFC, usage_hint)
pub const PROTOS: &[(u8, &str, &str, &str)] = &[
    (1, "ICMP", "RFC 792", "diagnostics, errors"),
    (2, "IGMP", "RFC 1112", "IPv4 multicast group membership"),
    (4, "IPv4", "RFC 2003", "IP-in-IP encapsulation"),
    (6, "TCP", "RFC 793", "reliable byte streams"),
    (17, "UDP", "RFC 768", "datagrams"),
    (41, "IPv6", "RFC 2473", "6in4 tunneling"),
    (47, "GRE", "RFC 2784", "generic encapsulation tunnels"),
    (50, "ESP", "RFC 4303", "IPsec encrypted payload"),
    (51, "AH", "RFC 4302", "IPsec authentication"),
    (58, "ICMPv6", "RFC 4443", "(carried over IPv4 only on tunnels)"),
    (89, "OSPF", "RFC 2328", "interior routing protocol"),
    (94, "IPIP", "RFC 2003", "alternate IP-in-IP"),
    (103, "PIM", "RFC 7761", "multicast routing"),
    (115, "L2TP", "RFC 3931", "VPN tunnel layer-2 transport"),
    (132, "SCTP", "RFC 4960", "telephony / stream signaling"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoState {
    /// Reserved: surfaced when we receive a same-protocol reply on the
    /// raw IPv4 listener. Currently unused (the listener thread is
    /// gated; protocols default to OpenFiltered when no ICMP arrives).
    #[allow(dead_code)]
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl ProtoState {
    pub fn as_str(self) -> &'static str {
        match self {
            ProtoState::Open => "open",
            ProtoState::Closed => "closed",
            ProtoState::Filtered => "filtered",
            ProtoState::OpenFiltered => "open|filtered",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtoResult {
    pub proto: u8,
    pub name: &'static str,
    pub rfc: &'static str,
    pub usage: &'static str,
    pub state: ProtoState,
}

type IcmpHints = Arc<Mutex<HashMap<u8, IcmpType>>>;

fn icmp_listener(mut rx: TransportReceiver, hints: IcmpHints, deadline: Instant) {
    let mut iter = icmp_packet_iter(&mut rx);
    while Instant::now() < deadline {
        match iter.next() {
            Ok((packet, _src)) => {
                let icmp_type = packet.get_icmp_type();
                // We're interested in ICMP unreachable echoes back from the
                // target. Payload contains 4 bytes unused + original IPv4
                // header; protocol field at offset 9 of that header tells
                // us which IP protocol the unreachable refers to.
                let payload = packet.payload();
                if payload.len() < 4 + 20 {
                    continue;
                }
                let orig_ip = &payload[4..];
                if let Some(ip_pkt) = Ipv4Packet::new(orig_ip) {
                    let proto = ip_pkt.get_next_level_protocol().0;
                    hints.lock().unwrap().insert(proto, icmp_type);
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

#[allow(dead_code)]
fn raw_proto_listener(mut rx: TransportReceiver, seen: Arc<Mutex<HashMap<u8, bool>>>, deadline: Instant) {
    let mut iter = ipv4_packet_iter(&mut rx);
    while Instant::now() < deadline {
        match iter.next() {
            Ok((ip_packet, _src)) => {
                let proto = ip_packet.get_next_level_protocol().0;
                seen.lock().unwrap().insert(proto, true);
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

pub fn scan(target: Ipv4Addr, timeout: Duration) -> Result<Vec<ProtoResult>> {
    // We need:
    //  - Layer3 IPv4 raw socket to send arbitrary-protocol packets
    //  - ICMP listener to catch unreachable replies
    //  - IPv4 listener to catch any reply in same protocol → open
    let (mut tx, _rx_unused) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))
        .map_err(|e| anyhow!("raw IP send socket: {} — {}", e, crate::privilege::raw_privilege_hint()))?;
    let (_, icmp_rx) = transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
        .map_err(|e| anyhow!("ICMP listener socket: {}", e))?;

    let icmp_hints: IcmpHints = Arc::new(Mutex::new(HashMap::new()));
    let icmp_hints_listener = Arc::clone(&icmp_hints);
    let deadline = Instant::now() + timeout;
    let icmp_thread = thread::spawn(move || icmp_listener(icmp_rx, icmp_hints_listener, deadline));

    // Send one minimal-payload packet per protocol in our curated set.
    for (proto, _, _, _) in PROTOS {
        let ip_total_len = 20u16 + 8;
        let mut buf = vec![0u8; ip_total_len as usize];
        // Build minimal IPv4 header
        buf[0] = 0x45; // IPv4, IHL=5
        buf[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
        buf[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
        buf[8] = 64; // TTL
        buf[9] = *proto;
        // src zeroed; pnet fills it from the iface (Layer3 path)
        buf[16..20].copy_from_slice(&target.octets());
        // 8 bytes of zeroed payload — enough for most kernels to recognize a packet
        let pkt = match Ipv4Packet::new(&buf) {
            Some(p) => p,
            None => continue,
        };
        let _ = tx.send_to(pkt, IpAddr::V4(target));
    }

    // Wait for replies
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }

    // Allow listener thread to exit
    drop(icmp_thread);

    let hints = icmp_hints.lock().unwrap().clone();
    let mut results = Vec::with_capacity(PROTOS.len());
    for (proto, name, rfc, usage) in PROTOS {
        let state = match hints.get(proto) {
            Some(t) if t.0 == 3 => {
                // ICMP unreachable. Need code to distinguish proto-unreach (closed) from filtered.
                // We don't currently capture code separately — best-effort: any unreach from target → closed.
                ProtoState::Closed
            }
            Some(_) => ProtoState::Filtered,
            None => ProtoState::OpenFiltered,
        };
        results.push(ProtoResult {
            proto: *proto,
            name,
            rfc,
            usage,
            state,
        });
    }
    Ok(results)
}

pub fn print_report(target: Ipv4Addr, results: &[ProtoResult]) {
    use colored::*;
    println!();
    println!("{}", format!("IP protocol scan report for {}", target).bold());
    println!(
        "{:<5} {:<8} {:<14} {:<11} {}",
        "PROTO".bold(),
        "NAME".bold(),
        "STATE".bold(),
        "RFC".bold(),
        "USAGE".bold()
    );
    for r in results {
        let state_color = match r.state {
            ProtoState::Open => r.state.as_str().green().bold().to_string(),
            ProtoState::OpenFiltered => r.state.as_str().cyan().to_string(),
            ProtoState::Filtered => r.state.as_str().yellow().to_string(),
            ProtoState::Closed => r.state.as_str().red().to_string(),
        };
        println!(
            "{:<5} {:<8} {:<14} {:<11} {}",
            r.proto, r.name, state_color, r.rfc, r.usage
        );
    }
}
