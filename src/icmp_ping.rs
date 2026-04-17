use crate::target::Target;
use anyhow::{anyhow, Result};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType::Layer4,
    TransportProtocol::Ipv4,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Send a single ICMP echo request and wait for a matching reply (with timeout).
pub fn icmp_echo(dst: Ipv4Addr, timeout: Duration) -> bool {
    let (mut tx, mut rx) = match transport_channel(
        4096,
        Layer4(Ipv4(IpNextHeaderProtocols::Icmp)),
    ) {
        Ok(pair) => pair,
        Err(_) => return false,
    };

    let mut buf = [0u8; 16];
    {
        let mut pkt = MutableEchoRequestPacket::new(&mut buf).unwrap();
        pkt.set_icmp_type(IcmpTypes::EchoRequest);
        pkt.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
        pkt.set_identifier(std::process::id() as u16);
        pkt.set_sequence_number(1);
        pkt.set_payload(&[0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let cs = pnet::util::checksum(pkt.packet(), 1);
        pkt.set_checksum(cs);
    }

    let icmp = IcmpPacket::new(&buf).unwrap();
    if tx.send_to(icmp, IpAddr::V4(dst)).is_err() {
        return false;
    }

    // Wait for reply on a worker thread so we can enforce a timeout.
    let (tx_chan, rx_chan) = mpsc::channel::<bool>();
    thread::spawn(move || {
        let mut iter = icmp_packet_iter(&mut rx);
        loop {
            match iter.next() {
                Ok((packet, src)) => {
                    if src != IpAddr::V4(dst) {
                        continue;
                    }
                    if packet.get_icmp_type() == IcmpTypes::EchoReply {
                        let _ = tx_chan.send(true);
                        return;
                    }
                }
                Err(_) => {
                    let _ = tx_chan.send(false);
                    return;
                }
            }
        }
    });

    matches!(rx_chan.recv_timeout(timeout), Ok(true))
}

pub fn icmp_discover(targets: Vec<Target>, timeout: Duration) -> Result<Vec<Target>> {
    // Sanity-check that we can open a raw ICMP socket before sweeping.
    let _probe = transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
        .map_err(|e| anyhow!("failed to open raw ICMP socket: {} — {}", e, crate::privilege::raw_privilege_hint()))?;
    drop(_probe);

    let mut alive = Vec::new();
    for t in targets {
        if let IpAddr::V4(v4) = t.ip {
            if icmp_echo(v4, timeout) {
                alive.push(t);
            }
        }
    }
    Ok(alive)
}
