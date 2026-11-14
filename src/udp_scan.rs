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
    icmp_packet_iter, udp_packet_iter, transport_channel, TransportChannelType::Layer4,
    TransportProtocol::Ipv4, TransportReceiver, TransportSender,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use parking_lot::Mutex;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

type PendingMap = Arc<Mutex<HashMap<(Ipv4Addr, u16), mpsc::Sender<ProbeHint>>>>;

/// Fixed source port for every probe; both the ICMP and UDP reply listeners
/// correlate replies back to a pending probe on it.
const SRC_PORT: u16 = 45678;

#[derive(Debug, Clone, Copy)]
enum ProbeHint {
    UdpResponse,      // a UDP reply from the port → definitively OPEN (bug 1.A)
    PortUnreachable,  // ICMP type 3 code 3 → closed
    OtherUnreachable, // ICMP type 3 other code → filtered (admin-prohibited, etc.)
}

pub struct UdpScanner {
    tx: Arc<Mutex<TransportSender>>,
    pending: PendingMap,
    _icmp_thread: thread::JoinHandle<()>,
    _udp_thread: thread::JoinHandle<()>,
}

impl UdpScanner {
    pub fn new() -> Result<Self> {
        // Keep the UDP channel's receiver (don't discard it): a UDP reply from a
        // probed port is the only positive proof the port is OPEN (bug 1.A).
        let (tx, udp_rx) = transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Udp)))
            .map_err(|e| anyhow!("failed to open raw UDP socket: {} — {}", e, crate::privilege::raw_privilege_hint()))?;
        // Separate receiver for ICMP (closed / filtered hints).
        let (_tx_unused, icmp_rx) = transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
            .map_err(|e| anyhow!("failed to open raw ICMP socket: {}", e))?;

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let icmp_pending = Arc::clone(&pending);
        let udp_pending = Arc::clone(&pending);

        let icmp_thread = thread::spawn(move || icmp_listener(icmp_rx, icmp_pending));
        let udp_thread = thread::spawn(move || udp_listener(udp_rx, udp_pending));

        Ok(Self {
            tx: Arc::new(Mutex::new(tx)),
            pending,
            _icmp_thread: icmp_thread,
            _udp_thread: udp_thread,
        })
    }

    pub fn probe(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        timeout: Duration,
    ) -> PortState {
        let src_port = SRC_PORT;
        let (sender, receiver) = mpsc::channel::<ProbeHint>();
        self.pending.lock().insert((dst_ip, dst_port), sender);

        // A protocol-specific payload (DNS/NTP/SNMP/…) makes the service answer
        // so the port reads OPEN; unknown ports get an empty datagram and rely on
        // ICMP to tell closed from open|filtered.
        let payload = udp_payload(dst_port);
        let mut buf = vec![0u8; 8 + payload.len()];
        {
            let mut pkt = MutableUdpPacket::new(&mut buf[..]).unwrap();
            pkt.set_source(src_port);
            pkt.set_destination(dst_port);
            pkt.set_length((8 + payload.len()) as u16);
            pkt.set_payload(payload);
            pkt.set_checksum(ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip));
        }

        let send_result = {
            let mut tx = self.tx.lock();
            let pkt = UdpPacket::new(&buf[..]).unwrap();
            tx.send_to(pkt, IpAddr::V4(dst_ip))
        };

        let state = if send_result.is_err() {
            PortState::Filtered
        } else {
            match receiver.recv_timeout(timeout) {
                Ok(ProbeHint::UdpResponse) => PortState::Open,
                Ok(ProbeHint::PortUnreachable) => PortState::Closed,
                Ok(ProbeHint::OtherUnreachable) => PortState::Filtered,
                // No reply at all → nmap's open|filtered.
                Err(_) => PortState::OpenFiltered,
            }
        };

        self.pending.lock().remove(&(dst_ip, dst_port));
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
                ProbeHint::PortUnreachable
            } else {
                ProbeHint::OtherUnreachable
            };
            let sender_opt = {
                let pend = pending.lock();
                pend.get(&(orig_dst, orig_dst_port)).cloned()
            };
            if let Some(s) = sender_opt {
                let _ = s.send(hint);
            }
        }
    }
}

/// Listen for UDP replies from probed ports. A datagram whose *source*
/// (ip, port) matches a pending probe and is addressed back to our fixed source
/// port is positive proof the port is OPEN (bug 1.A). Usually only a
/// protocol-matched `udp_payload` elicits one.
fn udp_listener(mut rx: TransportReceiver, pending: PendingMap) {
    let mut iter = udp_packet_iter(&mut rx);
    while let Ok((packet, src)) = iter.next() {
        let IpAddr::V4(src_ip) = src else { continue };
        if packet.get_destination() != SRC_PORT {
            continue;
        }
        let src_port = packet.get_source();
        let sender_opt = {
            let pend = pending.lock();
            pend.get(&(src_ip, src_port)).cloned()
        };
        if let Some(s) = sender_opt {
            let _ = s.send(ProbeHint::UdpResponse);
        }
    }
}

/// Protocol-specific UDP probe payloads (mirrors nmap-payloads) for ports whose
/// service only answers a well-formed request. A reply lets `udp_listener` mark
/// the port OPEN; unknown ports get an empty datagram and depend on ICMP to
/// separate closed from open|filtered.
fn udp_payload(port: u16) -> &'static [u8] {
    match port {
        // DNS: a CHAOS TXT query for "version.bind". BIND answers it; other
        // resolvers refuse but still reply — either way the port is proven up.
        53 => &[
            0x00, 0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd',
            0x00, 0x00, 0x10, 0x00, 0x03,
        ],
        // NTP v3 client-mode request (LI=0, VN=3, Mode=3); servers always reply.
        123 => &[
            0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        // SNMPv1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0), community "public".
        161 => &[
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',
            0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e,
            0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ],
        // NetBIOS name service node-status query for "*".
        137 => &[
            0xa2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
            0x00, 0x21, 0x00, 0x01,
        ],
        // SSDP M-SEARCH (UPnP discovery).
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
        // IKE/ISAKMP main-mode SA proposal (3DES / SHA1 / MODP-1024).
        500 => &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x01, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x20, 0x01, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x05,
            0x80, 0x02, 0x00, 0x02, 0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x02,
            0x80, 0x0b, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x04, 0x00, 0x00, 0x70, 0x80,
        ],
        // RPC portmapper NULL call (program 100000 v2).
        111 => &[
            0x72, 0xfe, 0x1d, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // MS-SQL Server browser: a single 0x02 byte elicits the instance list.
        1434 => &[0x02],
        // TFTP read-request (RRQ) for file "r", mode octet. A tftpd answers
        // with DATA or (for a missing file) an ERROR packet — either proves the
        // port open (lab bug 1.A: the one open UDP service RustyMap under-read).
        69 => &[0x00, 0x01, b'r', 0x00, b'o', b'c', b't', b'e', b't', 0x00],
        // mDNS: a unicast PTR query for "_services._dns-sd._udp.local" — a
        // responder (avahi/Bonjour) answers with its advertised services.
        5353 => &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's',
            0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
            0x04, b'_', b'u', b'd', b'p',
            0x05, b'l', b'o', b'c', b'a', b'l',
            0x00, 0x00, 0x0c, 0x00, 0x01,
        ],
        // SIP OPTIONS — any SIP UA/proxy replies with a status line (200/403/…).
        5060 => b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bKnm\r\nFrom: <sip:nm@nm>;tag=rm\r\nTo: <sip:nm@nm>\r\nCall-ID: rustymap\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        _ => &[],
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

    // Re-probe open|filtered ports sequentially with pacing (lab bug B20):
    // the target rate-limits ICMP port-unreachables (~1/s on Linux), so a
    // single high-parallelism pass suppresses most of them and over-reports
    // open|filtered. Retrying the undecided ports slowly lets the limiter
    // emit the unreachable, reclassifying genuinely-closed ports as closed.
    let max_retries = crate::scanner::max_retries();
    for _round in 0..max_retries {
        let undecided: Vec<usize> = all
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state == PortState::OpenFiltered)
            .map(|(i, _)| i)
            .collect();
        if undecided.is_empty() {
            break;
        }
        for i in undecided {
            thread::sleep(Duration::from_millis(200)); // dodge the ICMP rate limit
            let st = scanner.probe(src, dst, all[i].port, timeout);
            if st != PortState::OpenFiltered {
                all[i].state = st;
            }
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_payloads_cover_common_services() {
        // NTP client-mode request (the bug-1.A validation case): 48 bytes, first
        // byte 0x1b (LI=0, VN=3, Mode=3).
        assert_eq!(udp_payload(123).len(), 48);
        assert_eq!(udp_payload(123)[0], 0x1b);
        // DNS version.bind query, SNMP SEQUENCE, SSDP M-SEARCH, IKE, ms-sql.
        assert!(udp_payload(53).windows(4).any(|w| w == b"bind"));
        assert_eq!(udp_payload(161)[0], 0x30);
        assert!(udp_payload(1900).starts_with(b"M-SEARCH"));
        assert!(udp_payload(500).len() > 40);
        assert_eq!(udp_payload(1434), &[0x02]);
        // v0.108.x payload gap fills (lab bug 1.A): TFTP RRQ, mDNS PTR, SIP.
        assert_eq!(&udp_payload(69)[..2], &[0x00, 0x01]); // TFTP RRQ opcode
        assert!(udp_payload(69).windows(5).any(|w| w == b"octet"));
        assert!(udp_payload(5353).windows(9).any(|w| w == b"_services"));
        assert!(udp_payload(5060).starts_with(b"OPTIONS sip:"));
        // Unknown ports get no payload (empty datagram; ICMP-only classification).
        assert!(udp_payload(9999).is_empty());
        assert!(udp_payload(80).is_empty());
    }
}
