use crate::net_util::source_ipv4_for;
use crate::scanner::{HostResult, PortResult, PortState};
use crate::target::Target;
use anyhow::{anyhow, Result};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType::Layer4,
    TransportProtocol::Ipv4, TransportReceiver, TransportSender,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type PendingMap = Arc<Mutex<HashMap<(Ipv4Addr, u16), mpsc::Sender<IcmpHint>>>>;

#[derive(Debug, Clone, Copy)]
enum IcmpHint {
    PortUnreachable, // closed
    OtherUnreachable, // filtered (admin prohibited, host unreachable, etc.)
}

pub struct UdpScanner {
    tx: Arc<Mutex<TransportSender>>,
    pending: PendingMap,
    _icmp_thread: thread::JoinHandle<()>,
}

impl UdpScanner {
    pub fn new() -> Result<Self> {
        let (tx, _rx_unused) = transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Udp)))
            .map_err(|e| anyhow!("failed to open raw UDP socket: {} — {}", e, crate::privilege::raw_privilege_hint()))?;
        // Separate receiver for ICMP
        let (_tx_unused, icmp_rx) = transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
            .map_err(|e| anyhow!("failed to open raw ICMP socket: {}", e))?;

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_rx = Arc::clone(&pending);

        let icmp_thread = thread::spawn(move || icmp_listener(icmp_rx, pending_rx));

        Ok(Self {
            tx: Arc::new(Mutex::new(tx)),
            pending,
            _icmp_thread: icmp_thread,
        })
    }

    pub fn probe(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        timeout: Duration,
    ) -> PortState {
        let src_port: u16 = 45678; // fixed; ICMP reply embeds our original header for correlation
        let (sender, receiver) = mpsc::channel::<IcmpHint>();
        self.pending.lock().unwrap().insert((dst_ip, dst_port), sender);

        let mut buf = [0u8; 8];
        {
            let mut pkt = MutableUdpPacket::new(&mut buf).unwrap();
            pkt.set_source(src_port);
            pkt.set_destination(dst_port);
            pkt.set_length(8);
            pkt.set_checksum(ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip));
        }

        let send_result = {
            let mut tx = self.tx.lock().unwrap();
            let pkt = UdpPacket::new(&buf).unwrap();
            tx.send_to(pkt, IpAddr::V4(dst_ip))
        };

        let state = if send_result.is_err() {
            PortState::Filtered
        } else {
            match receiver.recv_timeout(timeout) {
                Ok(IcmpHint::PortUnreachable) => PortState::Closed,
                Ok(IcmpHint::OtherUnreachable) => PortState::Filtered,
                // No ICMP reply → port open|filtered (nmap convention)
                Err(_) => PortState::OpenFiltered,
            }
        };

        self.pending.lock().unwrap().remove(&(dst_ip, dst_port));
        state
    }
}

fn icmp_listener(mut rx: TransportReceiver, pending: PendingMap) {
    let mut iter = icmp_packet_iter(&mut rx);
    while let Ok((packet, _src)) = iter.next() {
        let icmp_type = packet.get_icmp_type();
        if icmp_type != IcmpTypes::DestinationUnreachable {
            continue;
        }
        // Payload: 4 bytes of unused + original IPv4 header + first 8 bytes of UDP header
        let payload = packet.payload();
        if payload.len() < 4 + 20 + 8 {
            continue;
        }
        let code = packet.get_icmp_code().0;
        let orig_ip_bytes = &payload[4..];
        if let Some(ip_pkt) = Ipv4Packet::new(orig_ip_bytes) {
            let ihl = (ip_pkt.get_header_length() as usize) * 4;
            if orig_ip_bytes.len() < ihl + 8 {
                continue;
            }
            let orig_dst = ip_pkt.get_destination();
            let udp_bytes = &orig_ip_bytes[ihl..ihl + 8];
            let orig_dst_port = u16::from_be_bytes([udp_bytes[2], udp_bytes[3]]);

            let hint = if code == 3 {
                IcmpHint::PortUnreachable
            } else {
                IcmpHint::OtherUnreachable
            };
            let sender_opt = {
                let pend = pending.lock().unwrap();
                pend.get(&(orig_dst, orig_dst_port)).cloned()
            };
            if let Some(s) = sender_opt {
                let _ = s.send(hint);
            }
        }
    }
}

pub fn run_udp_scan(
    target: Target,
    ports: Arc<Vec<u16>>,
    scanner: Arc<UdpScanner>,
    timeout: Duration,
    parallel: usize,
) -> HostResult {
    let start = Instant::now();
    let dst = match target.ip {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => {
            return HostResult { target, up: false, ports: vec![], elapsed: start.elapsed(), os: None, device: None, mac: None };
        }
    };
    let src = match source_ipv4_for(dst) {
        Ok(s) => s,
        Err(_) => return HostResult { target, up: false, ports: vec![], elapsed: start.elapsed(), os: None, device: None, mac: None },
    };

    let chunk = (ports.len() + parallel - 1) / parallel.max(1);
    let mut handles = Vec::new();
    for chunk_idx in 0..parallel {
        let s_scanner = Arc::clone(&scanner);
        let s_ports = Arc::clone(&ports);
        let begin = chunk_idx * chunk;
        let end = ((chunk_idx + 1) * chunk).min(s_ports.len());
        if begin >= end { continue; }
        let h = thread::spawn(move || {
            let mut results = Vec::with_capacity(end - begin);
            for &p in &s_ports[begin..end] {
                let st = s_scanner.probe(src, dst, p, timeout);
                results.push(PortResult { port: p, state: st, rtt: Duration::from_millis(0), service: None });
            }
            results
        });
        handles.push(h);
    }

    let mut all = Vec::new();
    for h in handles {
        if let Ok(v) = h.join() { all.extend(v); }
    }
    all.sort_by_key(|p| p.port);

    let interesting: Vec<PortResult> = all.into_iter()
        .filter(|p| matches!(p.state, PortState::Open | PortState::OpenFiltered | PortState::Closed))
        .collect();

    HostResult {
        up: !interesting.is_empty(),
        target,
        ports: interesting,
        elapsed: start.elapsed(),
        os: None,
        device: None,
        mac: None,
    }
}
