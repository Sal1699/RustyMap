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
pub fn pick_interface_for(target: Ipv4Addr) -> Option<(NetworkInterface, Ipv4Addr, MacAddr)> {
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

/// Send ARP "who has X.X.X.X tell <us>" for each target in `targets`,
/// listen for replies for `timeout`, and return the set of IPs that
/// answered (with their MAC, useful for vendor classification later).
pub fn arp_discover(
    targets: &[Ipv4Addr],
    timeout: Duration,
) -> Result<HashMap<Ipv4Addr, MacAddr>> {
    if targets.is_empty() {
        return Ok(HashMap::new());
    }
    // All targets must share a single broadcast domain; pick the iface for the first.
    let (iface, src_ip, src_mac) = pick_interface_for(targets[0])
        .ok_or_else(|| anyhow!("no interface in same subnet as {}", targets[0]))?;

    let (mut tx, mut rx) = match datalink::channel(&iface, Default::default())? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow!("unsupported datalink channel")),
    };

    let target_set: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut found: HashMap<Ipv4Addr, MacAddr> = HashMap::new();

    // ── Send all ARP requests up front ──
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
                            found.entry(sender).or_insert(mac);
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
