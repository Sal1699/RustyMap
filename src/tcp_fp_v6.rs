//! Raw IPv6 TCP SYN/ACK fingerprint probe (#6 — make IPv6 a first-class
//! detector, not a fallback).
//!
//! Mirrors `tcp_fp::probe` but over IPv6: send a SYN with nmap's T1
//! option set to an open port and capture the SYN/ACK's window and TCP
//! options. Combined with `os_fp_v6::classify_v6` this gives a real
//! stack signature (window scale / timestamp / SACK) instead of the
//! port-only heuristic. Raw sockets → needs privileges; **experimental,
//! validate on a dual-stack lab host.**

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{
    ipv6_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket,
};
use pnet::packet::Packet;
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv6,
};
use rand::Rng;
use std::net::{IpAddr, Ipv6Addr, UdpSocket};
use std::time::{Duration, Instant};

/// Captured IPv6 SYN/ACK signals.
#[derive(Debug, Clone)]
pub struct V6Fingerprint {
    pub window: u16,
    pub options: String,
    pub ws: Option<u8>,
    pub ts: bool,
    pub sack: bool,
}

/// Best-effort local IPv6 source address for reaching `dst` — the UDP
/// "connect" trick reads the kernel's chosen egress address without
/// sending anything, so we can checksum the TCP segment correctly.
pub fn source_ipv6_for(dst: Ipv6Addr) -> Option<Ipv6Addr> {
    let sock = UdpSocket::bind("[::]:0").ok()?;
    sock.connect((IpAddr::V6(dst), 80)).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V6(v) => Some(v),
        _ => None,
    }
}

fn t1_options() -> Vec<TcpOption> {
    vec![
        TcpOption::mss(1440), // v6 has a smaller default MSS than v4
        TcpOption::nop(),
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::timestamp(0xff_ff_ff_ff, 0),
        TcpOption::sack_perm(),
    ]
}

/// Send one SYN to `[dst]:port` and capture the SYN/ACK fingerprint.
pub fn probe(dst: Ipv6Addr, open_port: u16, timeout: Duration) -> Option<V6Fingerprint> {
    let src = source_ipv6_for(dst)?;
    let (mut tx, rx) = transport_channel(4096, Layer4(Ipv6(IpNextHeaderProtocols::Tcp))).ok()?;

    let opts = t1_options();
    let opts_bytes_len: usize = 22;
    let padded = (20 + opts_bytes_len).div_ceil(4) * 4;
    let mut buf = vec![0u8; padded];

    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(40000..60000);
    let seq: u32 = rng.gen();
    {
        let mut tcp = MutableTcpPacket::new(&mut buf)?;
        tcp.set_source(src_port);
        tcp.set_destination(open_port);
        tcp.set_sequence(seq);
        tcp.set_data_offset((padded / 4) as u8);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(0x4000);
        tcp.set_options(&opts);
        let cs = ipv6_checksum(&tcp.to_immutable(), &src, &dst);
        tcp.set_checksum(cs);
    }

    let pkt = TcpPacket::new(&buf)?;
    if tx.send_to(pkt, IpAddr::V6(dst)).is_err() {
        return None;
    }

    let deadline = Instant::now() + timeout;
    let mut rx = rx;
    let mut iter = tcp_packet_iter(&mut rx);
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        match iter.next() {
            Ok((reply, addr)) => {
                if addr != IpAddr::V6(dst) {
                    continue;
                }
                if reply.get_source() != open_port || reply.get_destination() != src_port {
                    continue;
                }
                let flags = reply.get_flags();
                if flags & TcpFlags::SYN == 0 || flags & TcpFlags::ACK == 0 {
                    return None;
                }
                let opt_len = (reply.get_data_offset() as usize * 4).saturating_sub(20);
                let raw = reply.packet();
                let opts_str = if raw.len() >= 20 + opt_len {
                    crate::tcp_fp::encode_options(&raw[20..20 + opt_len])
                } else {
                    String::new()
                };
                return Some(V6Fingerprint {
                    window: reply.get_window(),
                    ws: crate::os_fp_v6::parse_ws(&opts_str),
                    ts: opts_str.contains('T'),
                    sack: opts_str.contains('S'),
                    options: opts_str,
                });
            }
            Err(_) => return None,
        }
    }
}
