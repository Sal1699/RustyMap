//! SCTP scan support — `-sY` INIT scan, `-sZ` COOKIE-ECHO scan,
//! `-PY` SCTP INIT ping.
//!
//! SCTP rides on IP protocol 132. We hand-roll the SCTP common header
//! and chunks (no SCTP packet builder in pnet 0.34) and send via the
//! pnet `Layer4` transport with `IpNextHeaderProtocols::Sctp`.
//!
//! Per RFC 4960:
//!
//!   - **`-sY` INIT scan**: send INIT chunk; INIT-ACK reply means open,
//!     ABORT means closed, no reply means filtered.
//!   - **`-sZ` COOKIE-ECHO scan**: send a COOKIE-ECHO chunk (which only
//!     makes sense mid-handshake). Stateless firewalls let it through;
//!     a real SCTP responder ABORTs since there's no matching cookie.
//!     No ABORT → either filtered or open-but-listening; ABORT →
//!     stack is alive, port not in handshake state.
//!   - **`-PY` ping**: same as `-sY` but used for host discovery
//!     (any reply at all = host up).
//!
//! Checksum is CRC32c (Castagnoli, polynomial 0x1EDC6F41) per
//! RFC 4960 §6.8. We use the `crc32c` crate.
//!
//! Windows note: requires Npcap (raw IP send works through the same
//! channel as the existing TCP raw scans). Linux: requires
//! CAP_NET_RAW or root.

use crate::scanner::{HostResult, PortResult, PortState};
use crate::target::Target;
use anyhow::{anyhow, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const SCTP_INIT: u8 = 1;
const SCTP_INIT_ACK: u8 = 2;
const SCTP_ABORT: u8 = 6;
const SCTP_COOKIE_ECHO: u8 = 10;
#[allow(dead_code)]
const SCTP_COOKIE_ACK: u8 = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpScanKind {
    Init,
    CookieEcho,
}

/// Build an SCTP common header + INIT chunk targeting `dst_port`.
/// `vt = 0` is required for INIT per RFC 4960 §3.3.2.
fn build_init(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let init_tag: u32 = rng.gen_range(1..=u32::MAX);
    let initial_tsn: u32 = rng.gen();

    // Common header (12B)
    let mut buf = Vec::with_capacity(12 + 20);
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // verification tag = 0
    buf.extend_from_slice(&0u32.to_be_bytes()); // checksum placeholder

    // INIT chunk (20B header + no params)
    buf.push(SCTP_INIT);            // chunk type
    buf.push(0);                     // chunk flags
    buf.extend_from_slice(&20u16.to_be_bytes()); // chunk length
    buf.extend_from_slice(&init_tag.to_be_bytes());
    buf.extend_from_slice(&65536u32.to_be_bytes()); // a_rwnd
    buf.extend_from_slice(&10u16.to_be_bytes()); // outbound streams
    buf.extend_from_slice(&10u16.to_be_bytes()); // inbound streams
    buf.extend_from_slice(&initial_tsn.to_be_bytes());

    fill_checksum(&mut buf);
    buf
}

/// Build a COOKIE-ECHO chunk with a random 8-byte cookie body.
fn build_cookie_echo(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let cookie: [u8; 8] = rng.gen();

    let mut buf = Vec::with_capacity(12 + 4 + 8);
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // VT (0 for unknown association)
    buf.extend_from_slice(&0u32.to_be_bytes()); // checksum placeholder

    // COOKIE-ECHO chunk: type=10, flags=0, length=4+8=12, body=cookie
    buf.push(SCTP_COOKIE_ECHO);
    buf.push(0);
    buf.extend_from_slice(&12u16.to_be_bytes());
    buf.extend_from_slice(&cookie);

    fill_checksum(&mut buf);
    buf
}

/// SCTP CRC32c per RFC 4960 §6.8 — checksum field is zeroed during
/// computation, then the resulting CRC is written little-endian
/// into the same field.
fn fill_checksum(buf: &mut [u8]) {
    // Zero the checksum field (already zero from build, but safe).
    buf[8..12].fill(0);
    let crc = crc32c::crc32c(buf);
    buf[8..12].copy_from_slice(&crc.to_le_bytes());
}

/// Decode the chunk type at offset 12 (start of first chunk after the
/// common header). Returns the chunk type byte or None on a runt.
fn first_chunk_type(packet: &[u8]) -> Option<u8> {
    if packet.len() < 13 {
        return None;
    }
    Some(packet[12])
}

/// Wait up to `timeout` for an SCTP packet from `dst` and decode the
/// first chunk type. None on timeout.
fn await_response(rx: &mut pnet::transport::TransportReceiver, dst: Ipv4Addr, timeout: Duration) -> Option<u8> {
    use pnet::transport::ipv4_packet_iter;
    let deadline = Instant::now() + timeout;
    let mut iter = ipv4_packet_iter(rx);
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let _ = remaining;
        match iter.next() {
            Ok((packet, src)) => {
                if src != IpAddr::V4(dst) {
                    continue;
                }
                let payload = packet.payload();
                if let Some(t) = first_chunk_type(payload) {
                    return Some(t);
                }
            }
            Err(_) => return None,
        }
    }
}

/// Probe one port. Returns `PortState` based on chunk-type response.
pub fn probe_one(dst: Ipv4Addr, port: u16, kind: SctpScanKind, timeout: Duration) -> Result<PortState> {
    let (mut tx, mut rx) = transport_channel(
        4096,
        Layer4(Ipv4(IpNextHeaderProtocols::Sctp)),
    )
    .map_err(|e| anyhow!("SCTP raw socket: {} (need root/CAP_NET_RAW or Npcap)", e))?;

    let src_port: u16 = rand::thread_rng().gen_range(32768..=u16::MAX);
    let pkt = match kind {
        SctpScanKind::Init => build_init(src_port, port),
        SctpScanKind::CookieEcho => build_cookie_echo(src_port, port),
    };

    // pnet's send_to wants a Packet trait impl; for raw Layer4 we
    // wrap the bytes in a generic packet. The simplest path is the
    // ipv4 packet send via Layer3, but Layer4 with no checksum is
    // cleaner — pnet writes IP header automatically.
    use pnet::packet::PacketSize;
    struct Raw<'a>(&'a [u8]);
    impl<'a> pnet::packet::Packet for Raw<'a> {
        fn packet(&self) -> &[u8] { self.0 }
        fn payload(&self) -> &[u8] { &[] }
    }
    impl<'a> PacketSize for Raw<'a> {
        fn packet_size(&self) -> usize { self.0.len() }
    }
    let _ = tx
        .send_to(Raw(&pkt), IpAddr::V4(dst))
        .map_err(|e| anyhow!("SCTP send: {}", e))?;

    let chunk = await_response(&mut rx, dst, timeout);

    Ok(classify(kind, chunk))
}

fn classify(kind: SctpScanKind, chunk: Option<u8>) -> PortState {
    match (kind, chunk) {
        (SctpScanKind::Init, Some(SCTP_INIT_ACK)) => PortState::Open,
        (SctpScanKind::Init, Some(SCTP_ABORT)) => PortState::Closed,
        (SctpScanKind::CookieEcho, Some(SCTP_ABORT)) => PortState::Closed,
        // No reply in either mode = filtered (could also be open-cookie for COOKIE-ECHO,
        // but distinguishing requires seeing the actual ABORT we'd otherwise get on
        // a closed port, so OpenFiltered is the safe label).
        (_, None) => PortState::Filtered,
        // Any other chunk type means the stack answered something we didn't expect —
        // call it OpenFiltered so the user investigates.
        _ => PortState::OpenFiltered,
    }
}

/// Multi-port scan returning a HostResult shape compatible with the
/// existing scanner pipeline. Sequential — SCTP is not the hot path,
/// per-port latency is fine.
pub fn sctp_scan(target: Target, ports: &[u16], kind: SctpScanKind, timeout: Duration) -> HostResult {
    let mut results = Vec::with_capacity(ports.len());
    let started = Instant::now();
    let mut any_responded = false;
    let ip = match target.ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            // SCTP over IPv6 needs a separate channel; out of scope for v0.53.
            return HostResult {
                target,
                up: false,
                ports: vec![],
                elapsed: started.elapsed(),
                os: None,
                device: None,
                mac: None,
            };
        }
    };
    for &p in ports {
        let state = probe_one(ip, p, kind, timeout).unwrap_or(PortState::Filtered);
        if matches!(state, PortState::Open | PortState::Closed) {
            any_responded = true;
        }
        results.push(PortResult { port: p, state, rtt: Duration::from_millis(0), service: None });
    }
    HostResult {
        target,
        up: any_responded,
        ports: results,
        elapsed: started.elapsed(),
        os: None,
        device: None,
        mac: None,
    }
}

/// SCTP INIT ping for host discovery. Returns true if the host
/// produced any SCTP reply (INIT-ACK, ABORT, or ICMP-unreachable
/// from upstream router would also count as alive — but we keep
/// the SCTP-only signal here for purity).
pub fn sctp_ping(dst: Ipv4Addr, port: u16, timeout: Duration) -> bool {
    matches!(
        probe_one(dst, port, SctpScanKind::Init, timeout),
        Ok(PortState::Open) | Ok(PortState::Closed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_init_has_expected_layout() {
        let pkt = build_init(12345, 80);
        // Common header is 12B + INIT chunk header 4B + INIT body 16B = 32B
        assert_eq!(pkt.len(), 32);
        // src/dst port at offsets 0..2 / 2..4
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), 12345);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 80);
        // Verification tag is 0 for INIT
        assert_eq!(&pkt[4..8], &[0, 0, 0, 0]);
        // First chunk type is INIT (1)
        assert_eq!(pkt[12], SCTP_INIT);
        // Chunk length field at 14..16 = 20
        assert_eq!(u16::from_be_bytes([pkt[14], pkt[15]]), 20);
    }

    #[test]
    fn build_cookie_echo_has_expected_layout() {
        let pkt = build_cookie_echo(12345, 9999);
        assert_eq!(pkt.len(), 12 + 12);
        assert_eq!(pkt[12], SCTP_COOKIE_ECHO);
        assert_eq!(u16::from_be_bytes([pkt[14], pkt[15]]), 12);
    }

    #[test]
    fn checksum_is_nonzero_after_fill() {
        let pkt = build_init(1234, 5678);
        let cs = u32::from_le_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);
        assert_ne!(cs, 0, "CRC32c should be non-zero on a non-empty INIT");
    }

    #[test]
    fn checksum_changes_with_payload() {
        let a = build_init(1234, 5678);
        let b = build_init(1234, 5679); // dst port differs
        assert_ne!(&a[8..12], &b[8..12]);
    }

    #[test]
    fn classify_init_ack_open() {
        assert_eq!(classify(SctpScanKind::Init, Some(SCTP_INIT_ACK)), PortState::Open);
    }

    #[test]
    fn classify_abort_closed() {
        assert_eq!(classify(SctpScanKind::Init, Some(SCTP_ABORT)), PortState::Closed);
        assert_eq!(classify(SctpScanKind::CookieEcho, Some(SCTP_ABORT)), PortState::Closed);
    }

    #[test]
    fn classify_no_reply_filtered() {
        assert_eq!(classify(SctpScanKind::Init, None), PortState::Filtered);
        assert_eq!(classify(SctpScanKind::CookieEcho, None), PortState::Filtered);
    }

    #[test]
    fn first_chunk_type_extracts_correctly() {
        let pkt = build_init(1, 2);
        assert_eq!(first_chunk_type(&pkt), Some(SCTP_INIT));
    }
}
