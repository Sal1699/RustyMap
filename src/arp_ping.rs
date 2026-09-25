//! ARP-based host discovery for the local LAN.
//!
//! When the target shares a /24 (or whatever broadcast domain we're on)
//! with our scanner interface, ARP is dramatically faster and more
//! reliable than ICMP/TCP ping — switches will reply directly without
//! involving any application or firewall on the target. We auto-detect
//! the LAN-overlap case and prefer ARP whenever possible.

use anyhow::{anyhow, Result};
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Pick the first interface whose IPv4 subnet contains `target`.
/// Returns the interface, our source IP, and our MAC.
/// True only for IPv4 addresses that can actually be on our local link:
/// RFC1918 private, RFC3927 link-local, and RFC6598 CGNAT (100.64/10).
/// A public/routable address is always reached via the default gateway,
/// never by ARP — so it must never enter the ARP path. Loopback,
/// unspecified and broadcast are all non-private, so this also excludes
/// them.
fn is_lan_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_private() || ip.is_link_local() {
        return true;
    }
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 0x40 // 100.64.0.0/10 (CGNAT)
}

pub fn pick_interface_for(target: Ipv4Addr) -> Option<(NetworkInterface, Ipv4Addr, MacAddr)> {
    // Only ARP for genuinely on-link (private/link-local) targets. Two
    // failure modes this guards against:
    //  1. A PUBLIC target (scanme.nmap.org, github.com, …) could match an
    //     interface carrying a broad or unusual subnet (VPN, virtual
    //     adapter) and get dropped into an ARP sweep that finds nothing
    //     and wrongly marks the host down — breaking default discovery on
    //     remote hosts (lab bug #1). Public IPs go via the gateway.
    //  2. Localhost: on Windows the Npcap loopback adapter carries
    //     127.0.0.0/8 without a loopback flag, so a naive subnet match
    //     ARP-swept localhost and hung past the deadline.
    // Both are non-private, so a single range check at this chokepoint —
    // which both the LAN check and the ARP sweep pass through — fixes them.
    if !is_lan_ipv4(target) {
        return None;
    }
    for iface in datalink::interfaces() {
        if iface.is_loopback() || iface.mac.is_none() {
            continue;
        }
        for ip in &iface.ips {
            if let pnet::ipnetwork::IpNetwork::V4(net) = ip {
                if net.contains(target) {
                    return Some((iface.clone(), net.ip(), iface.mac.unwrap()));
                }
            }
        }
    }
    None
}

/// Same as `arp_discover` but also records the per-target reply RTT
/// (Bug-06 fix). The old API kept all hosts at the call-site's
/// scan-elapsed time which equalled the discovery timeout, masking the
/// real RTT. Callers that need real latency use this entry point.
pub fn arp_discover_timed(
    targets: &[Ipv4Addr],
    timeout: Duration,
) -> Result<HashMap<Ipv4Addr, (MacAddr, Duration)>> {
    if targets.is_empty() {
        return Ok(HashMap::new());
    }
    // All targets must share a single broadcast domain; pick the iface for the first.
    let (iface, src_ip, src_mac) = pick_interface_for(targets[0])
        .ok_or_else(|| anyhow!("no interface in same subnet as {}", targets[0]))?;

    // Bug-06 (v0.66.5): the default pcap channel buffers packets in
    // a 1s-batched mmap ring, so rx.next() returns each ARP reply
    // 1+ seconds after it actually arrived — that's why every host
    // showed `started.elapsed() ≈ 1.5s` regardless of real RTT. Set
    // a tight read_timeout so the kernel flushes per-packet rather
    // than batched.
    let cfg = datalink::Config {
        read_timeout: Some(Duration::from_millis(50)),
        write_timeout: Some(Duration::from_millis(500)),
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(&iface, cfg)? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow!("unsupported datalink channel")),
    };

    let target_set: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut found: HashMap<Ipv4Addr, (MacAddr, Duration)> = HashMap::new();
    let send_at: HashMap<Ipv4Addr, Instant> = targets.iter().map(|&t| (t, Instant::now())).collect();
    let _ = &send_at;

    // ── Send all ARP requests up front ──
    let started = Instant::now();
    for &t in targets {
        let mut buf = [0u8; 42];
        {
            let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
            eth.set_destination(MacAddr::broadcast());
            eth.set_source(src_mac);
            eth.set_ethertype(EtherTypes::Arp);
            let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Request);
            arp.set_sender_hw_addr(src_mac);
            arp.set_sender_proto_addr(src_ip);
            arp.set_target_hw_addr(MacAddr::zero());
            arp.set_target_proto_addr(t);
        }
        let _ = tx.send_to(&buf, Some(iface.clone()));
    }

    // ── Listen for replies up to deadline ──
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && found.len() < targets.len() {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() != EtherTypes::Arp {
                        continue;
                    }
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() != ArpOperations::Reply {
                            continue;
                        }
                        let sender = arp.get_sender_proto_addr();
                        let mac = arp.get_sender_hw_addr();
                        if target_set.contains(&sender) {
                            let rtt = started.elapsed();
                            found.entry(sender).or_insert((mac, rtt));
                        }
                    }
                }
            }
            Err(_) => {
                // Brief backoff so we don't busy-loop on transient errors
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    Ok(found)
}

/// True when at least one of our IPv4 interfaces shares a subnet with
/// `target` — i.e. ARP is going to work and is preferable to TCP ping.
pub fn target_is_on_lan(target: Ipv4Addr) -> bool {
    pick_interface_for(target).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_never_on_lan() {
        // Regression: 127.0.0.1 was matched by the Npcap loopback
        // adapter's 127.0.0.0/8 and driven into an ARP sweep that hung
        // past the deadline. Localhost must always bypass ARP.
        assert!(!target_is_on_lan(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(pick_interface_for(Ipv4Addr::new(127, 0, 0, 1)).is_none());
    }

    #[test]
    fn public_ip_is_never_on_lan() {
        // Lab bug #1: public targets (scanme.nmap.org 45.33.32.156,
        // github.com 140.82.x, google.com 142.250.x) must never be
        // ARP-swept — they go via the gateway. If they did, ARP would
        // find nothing and the host would be wrongly marked down.
        assert!(!target_is_on_lan(Ipv4Addr::new(45, 33, 32, 156)));
        assert!(pick_interface_for(Ipv4Addr::new(140, 82, 121, 3)).is_none());
        assert!(pick_interface_for(Ipv4Addr::new(8, 8, 8, 8)).is_none());
    }

    #[test]
    fn range_classifier_matches_rfc() {
        assert!(is_lan_ipv4(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(is_lan_ipv4(Ipv4Addr::new(172, 16, 4, 9)));
        assert!(is_lan_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_lan_ipv4(Ipv4Addr::new(169, 254, 3, 2))); // link-local
        assert!(is_lan_ipv4(Ipv4Addr::new(100, 64, 0, 1))); // CGNAT
        assert!(!is_lan_ipv4(Ipv4Addr::new(100, 128, 0, 1))); // outside CGNAT
        assert!(!is_lan_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_lan_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn unspecified_and_broadcast_bypass_arp() {
        assert!(pick_interface_for(Ipv4Addr::UNSPECIFIED).is_none());
        assert!(pick_interface_for(Ipv4Addr::BROADCAST).is_none());
    }
}
