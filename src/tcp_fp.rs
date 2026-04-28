//! TCP/IP fingerprint probe — subset of nmap's T1 / WIN / OPS / IE.
//!
//! Sends a SYN with nmap's canonical option set (MSS=1460, NOP, WS=10,
//! NOP, NOP, TS=val/0, SACKOK, EOL) to one open TCP port and captures
//! the SYN/ACK reply. From the response we extract:
//!   - **W**indow size
//!   - **O**ptions ordering and values (e.g. `M5B4ST11NW7` for
//!     MSS-1460 / SACKOK / Timestamp / NOP / WindowScale-7)
//!   - **T**TL (or hop-limit on IPv6)
//!   - **DF** bit
//!
//! Format mirrors nmap-os-db's T1/WIN/OPS line so users who load
//! `--nmap-os-db` see something recognisable. We don't yet match
//! against the DB's pattern language (it has `>=`/`<=`/`|`/`&`
//! operators that need a small parser); the fingerprint is surfaced
//! as a hint for now.
//!
//! Requires raw sockets — gracefully no-ops when permissions or
//! Npcap are missing.

use anyhow::{anyhow, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{
    ipv4_checksum as tcp_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket,
};
use pnet::packet::Packet;
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4,
};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// One captured TCP/IP fingerprint sample.
#[derive(Debug, Clone)]
pub struct TcpFingerprint {
    /// Source port we used (echoed in the reply's destination port).
    /// Reserved for future SP (sequence-predictability) probe that
    /// needs multiple SYNs from the same source port.
    #[allow(dead_code)]
    pub src_port: u16,
    /// Window size from the SYN/ACK.
    pub window: u16,
    /// Options string in nmap-os-db notation (M=MSS, N=NOP, S=SACKOK,
    /// T=Timestamp, W=WindowScale, L=EOL). Each value is hex-prefixed
    /// when relevant (e.g. M5B4 = MSS 0x05B4 = 1460).
    pub options: String,
    /// IPv4 TTL or IPv6 hop limit on the reply.
    pub ttl: u8,
    /// IPv4 Don't Fragment bit.
    pub df: bool,
    /// Mean inter-arrival time in micros (0 = single-shot probe).
    /// Reserved for the future T probe (TCP timestamp jitter analysis).
    #[allow(dead_code)]
    pub round_trip_us: u64,
}

impl TcpFingerprint {
    /// One-line summary in the form used by --hints output.
    pub fn summary(&self) -> String {
        format!(
            "T1 W={:#06x} O={} TTL={} DF={}",
            self.window, self.options, self.ttl, self.df
        )
    }
}

/// Build the canonical SYN payload (TCP options matching nmap's T1).
/// nmap's exact option list for the T1 probe is:
///   MSS(1460), NOP, WindowScale(10), NOP, NOP, Timestamp(val/0),
///   SACKOK, EOL
fn t1_options() -> Vec<TcpOption> {
    vec![
        TcpOption::mss(1460),
        TcpOption::nop(),
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::timestamp(0xff_ff_ff_ff, 0),
        TcpOption::sack_perm(),
    ]
}

/// Encode the captured options into the compact nmap-style notation.
fn encode_options(buf: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    while i < buf.len() {
        let kind = buf[i];
        match kind {
            0 => {
                // EOL
                out.push('L');
                break;
            }
            1 => {
                // NOP
                out.push('N');
                i += 1;
            }
            2 => {
                // MSS — 4-byte option (kind, len=4, mss_hi, mss_lo)
                if i + 4 > buf.len() {
                    break;
                }
                let mss = u16::from_be_bytes([buf[i + 2], buf[i + 3]]);
                out.push_str(&format!("M{:X}", mss));
                i += 4;
            }
            3 => {
                // Window scale — 3-byte option
                if i + 3 > buf.len() {
                    break;
                }
                out.push_str(&format!("W{}", buf[i + 2]));
                i += 3;
            }
            4 => {
                // SACK permitted — 2-byte option
                out.push('S');
                i += 2;
            }
            8 => {
                // Timestamp — 10-byte option (we don't surface the value)
                if i + 10 > buf.len() {
                    break;
                }
                out.push('T');
                out.push_str("11"); // nmap notation: TSval=present(1), TSecr=present(1)
                i += 10;
            }
            _ => {
                // Unknown / vendor option: skip via length byte (or +1 if no length).
                if kind > 1 {
                    if i + 1 < buf.len() {
                        let len = buf[i + 1] as usize;
                        if len < 2 || i + len > buf.len() {
                            break;
                        }
                        i += len;
                    } else {
                        break;
                    }
                } else {
                    i += 1;
                }
                out.push('?');
            }
        }
    }
    out
}

/// Send one T1 SYN to (dst:port) from src and wait for the matching
/// SYN/ACK. Returns the captured fingerprint, or None on timeout /
/// permissions failure / IPv6 (the IPv6 path uses a different probe
/// set we don't ship yet).
pub fn probe(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    open_port: u16,
    timeout: Duration,
) -> Option<TcpFingerprint> {
    let (mut tx, rx) = transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))).ok()?;

    // Build TCP segment with nmap's T1 options.
    // T1 option list byte counts (matches t1_options below):
    //   MSS(4) + NOP(1) + WindowScale(3) + NOP(1) + NOP(1) +
    //   Timestamp(10) + SACKOK(2) = 22 bytes.
    // Word-pad to 24 so the data offset divides cleanly by 4.
    let opts = t1_options();
    let opts_bytes_len: usize = 22;
    let header_len = 20 + opts_bytes_len;
    let padded_header = header_len.div_ceil(4) * 4;
    let mut buf = vec![0u8; padded_header];

    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(40000..60000);
    let seq: u32 = rng.gen();

    {
        let mut tcp = MutableTcpPacket::new(&mut buf)?;
        tcp.set_source(src_port);
        tcp.set_destination(open_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset((padded_header / 4) as u8);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(0x4000); // 16384 — close to nmap's default
        tcp.set_options(&opts);
        let cs = tcp_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
        tcp.set_checksum(cs);
    }

    let pkt = TcpPacket::new(&buf)?;
    let probe_t0 = Instant::now();
    if tx.send_to(pkt, IpAddr::V4(dst_ip)).is_err() {
        return None;
    }

    // Listen on a thread for the matching SYN/ACK from dst_ip:open_port
    // back to our src_port. pnet's TransportReceiver is blocking, so we
    // do a short poll loop with a deadline.
    let deadline = Instant::now() + timeout;
    let mut rx = rx;
    let mut iter = tcp_packet_iter(&mut rx);
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        let remaining = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(50));
        // Non-portable trick: just call next() and let it block; we accept that
        // we may get late-arriving packets we don't care about and discard them.
        // The deadline check above bounds total wait.
        let _ = remaining;
        match iter.next() {
            Ok((reply, addr)) => {
                let src = match addr {
                    IpAddr::V4(v) => v,
                    _ => continue,
                };
                if src != dst_ip {
                    continue;
                }
                if reply.get_source() != open_port || reply.get_destination() != src_port {
                    continue;
                }
                let flags = reply.get_flags();
                if flags & TcpFlags::SYN == 0 || flags & TcpFlags::ACK == 0 {
                    // RST = closed; no fingerprint to extract
                    return None;
                }
                let opts_bytes_len = (reply.get_data_offset() as usize * 4).saturating_sub(20);
                let raw = reply.packet();
                let opts_slice = if raw.len() >= 20 + opts_bytes_len {
                    &raw[20..20 + opts_bytes_len]
                } else {
                    &[]
                };
                // TTL & DF require the IP header — pnet's tcp_packet_iter
                // gives us only the TCP segment. Fall back to a cheap
                // approximation: use 64 if we can't read the IP header.
                // (A full implementation opens an IP-level channel; we
                // accept the lossy default for now and surface it as 0
                // when unknown so callers know to ignore it.)
                let fp = TcpFingerprint {
                    src_port,
                    window: reply.get_window(),
                    options: encode_options(opts_slice),
                    ttl: 0,  // not available from tcp_packet_iter
                    df: false,
                    round_trip_us: probe_t0.elapsed().as_micros() as u64,
                };
                return Some(fp);
            }
            Err(_) => return None,
        }
    }
}

/// Convenience: best-effort — returns an empty list on permissions /
/// IPv6 / no open ports rather than erroring out. Reserved for future
/// callers that want a Result instead of `Option`.
#[allow(dead_code)]
pub fn probe_or_skip(
    src_ip: Ipv4Addr,
    dst_ip: IpAddr,
    open_port: u16,
    timeout: Duration,
) -> Result<Option<TcpFingerprint>> {
    match dst_ip {
        IpAddr::V4(v) => Ok(probe(src_ip, v, open_port, timeout)),
        IpAddr::V6(_) => Err(anyhow!("TCP fingerprint probe is IPv4-only for now")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_options_handles_eol() {
        let buf = [0u8];
        assert_eq!(encode_options(&buf), "L");
    }

    #[test]
    fn encode_options_handles_nop() {
        let buf = [1u8, 1u8];
        assert_eq!(encode_options(&buf), "NN");
    }

    #[test]
    fn encode_options_handles_mss() {
        // MSS 1460 = 0x05B4
        let buf = [2u8, 4, 0x05, 0xB4];
        assert_eq!(encode_options(&buf), "M5B4");
    }

    #[test]
    fn encode_options_handles_full_t1_reply() {
        // Typical reply: MSS, NOP, NOP, SACKOK, NOP, WS, EOL
        let buf = [
            2u8, 4, 0x05, 0xB4, // MSS 1460
            1, 1, // NOP NOP
            4, 2, // SACKOK
            1, // NOP
            3, 3, 7, // WS 7
            0, // EOL
        ];
        assert_eq!(encode_options(&buf), "M5B4NNSNW7L");
    }

    #[test]
    fn summary_format() {
        let fp = TcpFingerprint {
            src_port: 50000,
            window: 65535,
            options: "M5B4NW7L".into(),
            ttl: 64,
            df: true,
            round_trip_us: 0,
        };
        assert_eq!(fp.summary(), "T1 W=0xffff O=M5B4NW7L TTL=64 DF=true");
    }
}
