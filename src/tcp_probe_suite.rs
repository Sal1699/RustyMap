//! nmap-style secondary OS-detection probes: T2–T7, ECN, ICMP echo (IE)
//! and the UDP U1 probe.
//!
//! `tcp_fp` sends only the T1 SYN. nmap's full engine follows it with a
//! battery of probes whose *responses* (or lack of them) discriminate
//! between stacks that share a T1 signature:
//!
//! | Probe | TCP flags        | window | DF  | target port |
//! |-------|------------------|--------|-----|-------------|
//! | T2    | (none)           | 128    | yes | open        |
//! | T3    | SYN·FIN·URG·PSH  | 256    | no  | open        |
//! | T4    | ACK              | 1024   | yes | open        |
//! | T5    | SYN              | 31337  | no  | closed      |
//! | T6    | ACK              | 32768  | yes | closed      |
//! | T7    | FIN·PSH·URG      | 65535  | no  | closed      |
//! | ECN   | SYN·ECE·CWR      | 3      | no  | open        |
//!
//! Plus an ICMP echo (IE) and a UDP probe to a closed port (U1) that
//! elicits an ICMP port-unreachable.
//!
//! Unlike the text/TCP-connect paths, these need **raw sockets** and are
//! built on an IPv4 Layer3 channel so we can read the reply's TTL and
//! DF bit (which the Layer4 TCP path in `tcp_fp` cannot). The send/recv
//! halves therefore only work as root/Administrator with a raw-capable
//! driver (Npcap on Windows); everything degrades to "no response"
//! otherwise. **These probes have not been validated on the lab yet and
//! can be perturbed by the scanning host's own kernel emitting RSTs to
//! the unexpected replies — treat the raw suite as experimental.**
//!
//! The pure logic (packet builders, response classification, TTL
//! aggregation and the diagnostic formatter) is unit-tested and
//! platform-independent.

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{checksum as ipv4_checksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{
    ipv4_checksum as tcp_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket,
};
use pnet::packet::Packet;
use pnet::transport::{
    ipv4_packet_iter, transport_channel, TransportChannelType::Layer3,
};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// A T2–T7 / ECN probe definition.
#[derive(Debug, Clone, Copy)]
pub struct TProbe {
    pub name: &'static str,
    pub flags: u8,
    pub window: u16,
    pub df: bool,
    /// `true` = send to an open port, `false` = send to a closed port.
    pub to_open: bool,
}

pub const T_PROBES: &[TProbe] = &[
    TProbe { name: "T2", flags: 0, window: 128, df: true, to_open: true },
    TProbe { name: "T3", flags: TcpFlags::SYN | TcpFlags::FIN | TcpFlags::URG | TcpFlags::PSH, window: 256, df: false, to_open: true },
    TProbe { name: "T4", flags: TcpFlags::ACK, window: 1024, df: true, to_open: true },
    TProbe { name: "T5", flags: TcpFlags::SYN, window: 31337, df: false, to_open: false },
    TProbe { name: "T6", flags: TcpFlags::ACK, window: 32768, df: true, to_open: false },
    TProbe { name: "T7", flags: TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG, window: 65535, df: false, to_open: false },
];

/// Captured reply to one TCP probe, with the raw fields the nmap
/// fingerprint (S/A/O/RD/Q) is computed from.
#[derive(Debug, Clone, Default)]
pub struct TResult {
    pub name: &'static str,
    pub responded: bool,
    pub df: bool,
    pub ttl: u8,
    pub window: u16,
    pub flags: u8,
    /// IP identification field of the reply (feeds CI/II classification).
    pub ip_id: u16,
    /// nmap S field (response SEQ vs the probe's ACK).
    pub seq_code: &'static str,
    /// nmap A field (response ACK vs the probe's SEQ).
    pub ack_code: &'static str,
    /// nmap O field — TCP options in compact notation.
    pub opts: String,
    /// nmap Q field — quirks (reserved bits / urgent-without-URG).
    pub quirks: String,
    /// nmap RD field — CRC32 of any RST payload (0 = empty).
    pub rd: u32,
}

impl TResult {
    fn none(name: &'static str) -> Self {
        TResult { name, ..Default::default() }
    }

    /// nmap-flavoured one-probe summary, e.g. `T5(R=Y TTL=64 W=0 F=AR)`.
    pub fn summary(&self) -> String {
        if !self.responded {
            return format!("{}(R=N)", self.name);
        }
        format!(
            "{}(R=Y TTL={} W={} DF={} F={})",
            self.name,
            self.ttl,
            self.window,
            if self.df { "Y" } else { "N" },
            flags_str(self.flags),
        )
    }

    /// Full nmap-style coded line (`S=`/`A=`/`O=`/`RD=`/`Q=` …).
    pub fn fields(&self, cc: Option<char>) -> crate::nmap_fp::ProbeFields {
        if !self.responded {
            return crate::nmap_fp::ProbeFields::not_responded(self.name);
        }
        crate::nmap_fp::ProbeFields {
            name: self.name.to_string(),
            responded: true,
            df: Some(self.df),
            ttl: Some(self.ttl),
            window: Some(self.window),
            seq: Some(self.seq_code),
            ack: Some(self.ack_code),
            flags: Some(flags_str(self.flags)),
            options: Some(self.opts.clone()),
            rd: Some(self.rd),
            quirks: Some(self.quirks.clone()),
            cc,
        }
    }
}

/// Compact TCP-flags rendering in nmap's letter notation.
fn flags_str(f: u8) -> String {
    let mut s = String::new();
    if f & TcpFlags::URG != 0 { s.push('U'); }
    if f & TcpFlags::ACK != 0 { s.push('A'); }
    if f & TcpFlags::PSH != 0 { s.push('P'); }
    if f & TcpFlags::RST != 0 { s.push('R'); }
    if f & TcpFlags::SYN != 0 { s.push('S'); }
    if f & TcpFlags::FIN != 0 { s.push('F'); }
    if f & TcpFlags::ECE != 0 { s.push('E'); }
    if f & TcpFlags::CWR != 0 { s.push('C'); }
    if s.is_empty() { s.push('-'); }
    s
}

/// Result of the UDP U1 probe (closed UDP port → ICMP port-unreachable).
#[derive(Debug, Clone, Default)]
pub struct U1Result {
    pub responded: bool,
    pub ttl: u8,
}

/// Result of the ICMP echo (IE) probe.
#[derive(Debug, Clone, Default)]
pub struct IeResult {
    pub responded: bool,
    pub ttl: u8,
    pub df: bool,
}

/// SEQ line: ISN predictability numbers + IP-ID / timestamp generation.
#[derive(Debug, Clone, Default)]
pub struct SeqInfo {
    pub seq: Option<crate::nmap_fp::SeqResult>,
    /// TI — IP-ID class from the SEQ (open-port SYN) probes.
    pub ti: &'static str,
    /// TS — timestamp-option rate class.
    pub ts: &'static str,
}

/// Everything the secondary suite gathered.
#[derive(Debug, Clone, Default)]
pub struct SuiteResult {
    pub t: Vec<TResult>,
    pub ecn: Option<TResult>,
    pub u1: U1Result,
    pub ie: IeResult,
    pub seq: SeqInfo,
}

impl SuiteResult {
    /// The most common TTL seen across every responder — a far more
    /// robust initial-TTL estimate than a single ping, and directly
    /// feeds `os_db::match_os`.
    pub fn observed_ttl(&self) -> Option<u8> {
        let mut ttls: Vec<u8> = self
            .t
            .iter()
            .filter(|r| r.responded && r.ttl > 0)
            .map(|r| r.ttl)
            .collect();
        if let Some(e) = &self.ecn {
            if e.responded && e.ttl > 0 {
                ttls.push(e.ttl);
            }
        }
        if self.u1.responded && self.u1.ttl > 0 {
            ttls.push(self.u1.ttl);
        }
        if self.ie.responded && self.ie.ttl > 0 {
            ttls.push(self.ie.ttl);
        }
        if ttls.is_empty() {
            return None;
        }
        // Mode (most frequent), tie-break on the largest.
        ttls.sort_unstable();
        let mut best = ttls[0];
        let mut best_n = 0usize;
        let mut i = 0;
        while i < ttls.len() {
            let v = ttls[i];
            let run = ttls[i..].iter().take_while(|&&x| x == v).count();
            if run >= best_n {
                best_n = run;
                best = v;
            }
            i += run;
        }
        Some(best)
    }

    /// nmap-style multi-probe fingerprint block for `-O -v`.
    pub fn diagnostic(&self) -> String {
        let mut parts: Vec<String> = self.t.iter().map(|r| r.summary()).collect();
        if let Some(e) = &self.ecn {
            parts.push(if e.responded {
                format!("ECN(R=Y TTL={} W={} F={})", e.ttl, e.window, flags_str(e.flags))
            } else {
                "ECN(R=N)".to_string()
            });
        }
        parts.push(if self.u1.responded {
            format!("U1(R=Y TTL={})", self.u1.ttl)
        } else {
            "U1(R=N)".to_string()
        });
        parts.push(if self.ie.responded {
            format!("IE(R=Y TTL={} DF={})", self.ie.ttl, if self.ie.df { "Y" } else { "N" })
        } else {
            "IE(R=N)".to_string()
        });
        parts.join(" ")
    }

    /// Human-readable behavioural signals derived from the suite.
    pub fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();

        // Closed-port RST behaviour (T5, SYN → closed port): a clean RST
        // means a standards-compliant, reachable (unfiltered) TCP stack.
        if let Some(t5) = self.t.iter().find(|r| r.name == "T5") {
            if t5.responded && t5.flags & TcpFlags::RST != 0 {
                out.push("closed port answers RST (unfiltered TCP stack)".to_string());
            } else if !t5.responded {
                out.push("closed-port SYN dropped (filtered / no RST)".to_string());
            }
        }

        // ECN support = modern stack (Linux 4+, Windows 10+, recent BSD/macOS).
        if let Some(e) = &self.ecn {
            if e.responded && e.flags & TcpFlags::ECE != 0 {
                out.push("ECN negotiated (modern TCP stack)".to_string());
            }
        }

        // Weird-flags-to-open-port (T2 null / T3 Xmas-ish): BSD-derived
        // stacks tend to RST; Linux and Windows usually stay silent.
        if let Some(t2) = self.t.iter().find(|r| r.name == "T2") {
            if t2.responded && t2.flags & TcpFlags::RST != 0 {
                out.push("responds to NULL-flag probe (BSD/Unix-derived stack)".to_string());
            }
        }

        if self.u1.responded {
            out.push("UDP closed port returns ICMP unreachable".to_string());
        }

        out
    }

    /// Slirp/QEMU user-mode NAT signature (lab bug B10): its RST/reply
    /// probes come back with the maximum initial TTL (255) **and** the DF
    /// bit cleared — unlike a real Linux/BSD host, whose RSTs carry TTL 64
    /// and usually set DF. Callers combine this with a predictable ISN and
    /// a 0xFFFF T1 window to name the gateway. Requires at least two
    /// responders so a lone stray reply can't trigger it.
    pub fn nat_gateway_signature(&self) -> bool {
        let resp: Vec<&TResult> = self.t.iter().filter(|r| r.responded).collect();
        if resp.len() < 2 {
            return false;
        }
        let ttl255 = resp.iter().filter(|r| r.ttl >= 129).count();
        let df_clear = resp.iter().filter(|r| !r.df).count();
        ttl255 * 2 > resp.len() && df_clear * 2 > resp.len()
    }

    /// Full nmap-style fingerprint block (SEQ + T2–T7 + ECN + IE + U1),
    /// directly comparable with `nmap -O -d`. T1 and OPS/WIN (nmap's
    /// six-SEQ-probe option/window lines) are not reproduced here — the
    /// SEQ line carries the ISN math and this block carries the coded
    /// per-probe fields (S/A/O/RD/Q/CC), which is the discriminating part.
    pub fn fingerprint(&self) -> String {
        let mut lines: Vec<String> = Vec::new();

        // SEQ line.
        let (sp, gcd, isr) = self
            .seq
            .seq
            .map(|r| (r.sp, format!("{:X}", r.gcd), r.isr))
            .unwrap_or((0, String::new(), 0));
        // CI = IP-ID class across the closed-port responses (T5–T7).
        let ci_ids: Vec<u16> = self
            .t
            .iter()
            .filter(|r| r.responded && matches!(r.name, "T5" | "T6" | "T7"))
            .map(|r| r.ip_id)
            .collect();
        let ci = crate::nmap_fp::ip_id_class(&ci_ids);
        lines.push(format!(
            "SEQ(SP={}%GCD={}%ISR={}%TI={}%CI={}%TS={})",
            sp, gcd, isr, self.seq.ti, ci, self.seq.ts
        ));

        // T2–T7 coded lines.
        for r in &self.t {
            lines.push(r.fields(None).line());
        }

        // ECN with the CC field.
        if let Some(e) = &self.ecn {
            let cc = if e.responded {
                Some(crate::nmap_fp::ecn_cc(
                    e.flags & TcpFlags::ECE != 0,
                    e.flags & TcpFlags::CWR != 0,
                ))
            } else {
                None
            };
            lines.push(e.fields(cc).line());
        }

        // IE / U1 (ICMP / UDP).
        lines.push(if self.ie.responded {
            format!(
                "IE(R=Y%DFI={}%T={:X})",
                if self.ie.df { "Y" } else { "N" },
                self.ie.ttl
            )
        } else {
            "IE(R=N)".to_string()
        });
        lines.push(if self.u1.responded {
            format!("U1(R=Y%T={:X})", self.u1.ttl)
        } else {
            "U1(R=N)".to_string()
        });

        lines.join("\n")
    }
}

/// Encoded byte length of the T-series option template (below).
/// WScale(3) + NOP(1) + MSS(4) + Timestamp(10) + SACK-permitted(2) = 20.
const T_OPTS_LEN: usize = 20;
/// Encoded byte length of the ECN option set (below).
/// WScale(3) + NOP(1) + MSS(4) + SACK-permitted(2) + NOP(1) + NOP(1) = 12.
const ECN_OPTS_LEN: usize = 12;

/// nmap's shared TCP option template for probes T2–T7:
/// WScale(10), NOP, MSS(265), Timestamp(0xFFFFFFFF/0), SACK-permitted.
fn t_series_options() -> Vec<TcpOption> {
    vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFF_FFFF, 0),
        TcpOption::sack_perm(),
    ]
}

/// ECN probe options: WScale(10), NOP, MSS(1460), SACK-permitted, NOP, NOP.
fn ecn_options() -> Vec<TcpOption> {
    vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::nop(),
        TcpOption::nop(),
    ]
}

/// Build a full IPv4+TCP packet for one probe. `opts_len` is the encoded
/// byte length of `opts` (a named constant — the `#[packet]`-derived
/// `TcpOption` doesn't expose its size, so we track it alongside).
/// Returns the raw bytes.
#[allow(clippy::too_many_arguments)]
fn build_ipv4_tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    urgent: u16,
    opts: &[TcpOption],
    opts_len: usize,
    df: bool,
) -> Vec<u8> {
    let tcp_hdr_len = (20 + opts_len).div_ceil(4) * 4;
    let total_len = 20 + tcp_hdr_len;
    let mut buf = vec![0u8; total_len];

    // IPv4 header.
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..20]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len as u16);
        ip.set_identification(rand::thread_rng().gen());
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src);
        ip.set_destination(dst);
        if df {
            ip.set_flags(Ipv4Flags::DontFragment);
        }
        ip.set_checksum(ipv4_checksum(&ip.to_immutable()));
    }

    // TCP header.
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[20..]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset((tcp_hdr_len / 4) as u8);
        tcp.set_flags(flags);
        tcp.set_window(window);
        tcp.set_urgent_ptr(urgent);
        if !opts.is_empty() {
            tcp.set_options(opts);
        }
        let cs = tcp_checksum(&tcp.to_immutable(), &src, &dst);
        tcp.set_checksum(cs);
    }

    buf
}

/// Send one crafted TCP probe and capture the first matching reply.
#[allow(clippy::too_many_arguments)]
fn send_tcp_probe(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    dst_port: u16,
    flags: u8,
    window: u16,
    df: bool,
    opts: &[TcpOption],
    opts_len: usize,
    urgent: u16,
    timeout: Duration,
    name: &'static str,
) -> TResult {
    let (mut tx, mut rx) = match transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp)) {
        Ok(p) => p,
        Err(_) => return TResult::none(name),
    };

    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(40000..60000);
    let seq: u32 = rng.gen();
    // For an ACK probe, a plausible ack number avoids trivially-invalid pkt.
    let ack: u32 = if flags & TcpFlags::ACK != 0 { rng.gen() } else { 0 };

    let buf = build_ipv4_tcp(src, dst, src_port, dst_port, seq, ack, flags, window, urgent, opts, opts_len, df);
    let ip_pkt = match Ipv4Packet::new(&buf) {
        Some(p) => p,
        None => return TResult::none(name),
    };
    if tx.send_to(ip_pkt, IpAddr::V4(dst)).is_err() {
        return TResult::none(name);
    }

    // Listen for a TCP reply from dst back to our src_port.
    let (chan_tx, chan_rx) = mpsc::channel::<TResult>();
    thread::spawn(move || {
        let mut iter = ipv4_packet_iter(&mut rx);
        loop {
            match iter.next() {
                Ok((pkt, addr)) => {
                    if addr != IpAddr::V4(dst) {
                        continue;
                    }
                    if pkt.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                        continue;
                    }
                    let Some(tcp) = TcpPacket::new(pkt.payload()) else { continue };
                    if tcp.get_source() != dst_port || tcp.get_destination() != src_port {
                        continue;
                    }
                    let df_set = pkt.get_flags() & Ipv4Flags::DontFragment != 0;
                    let rflags = tcp.get_flags();
                    // TCP options bytes = header beyond the fixed 20.
                    let raw = tcp.packet();
                    let opt_len = (tcp.get_data_offset() as usize * 4).saturating_sub(20);
                    let opts = if raw.len() >= 20 + opt_len {
                        crate::tcp_fp::encode_options(&raw[20..20 + opt_len])
                    } else {
                        String::new()
                    };
                    let urg = tcp.get_urgent_ptr();
                    let quirks = crate::nmap_fp::quirks(
                        tcp.get_reserved() != 0,
                        urg,
                        rflags & TcpFlags::URG != 0,
                    );
                    let _ = chan_tx.send(TResult {
                        name,
                        responded: true,
                        df: df_set,
                        ttl: pkt.get_ttl(),
                        window: tcp.get_window(),
                        flags: rflags,
                        ip_id: pkt.get_identification(),
                        // S/A are computed relative to what WE sent.
                        seq_code: crate::nmap_fp::seq_field(tcp.get_sequence(), ack),
                        ack_code: crate::nmap_fp::ack_field(tcp.get_acknowledgement(), seq),
                        opts,
                        quirks,
                        rd: crate::nmap_fp::rst_data(tcp.payload()),
                    });
                    return;
                }
                Err(_) => {
                    let _ = chan_tx.send(TResult::none(name));
                    return;
                }
            }
        }
    });

    chan_rx.recv_timeout(timeout).unwrap_or_else(|_| TResult::none(name))
}

/// UDP U1 probe: send a UDP datagram to a (presumed) closed port and
/// wait for the ICMP port-unreachable it elicits. Received on a Layer3
/// ICMP channel so the outer IP header's TTL is captured (lab bug B9 —
/// the Layer4 path returned TTL 0).
fn send_u1(src: Ipv4Addr, dst: Ipv4Addr, closed_udp_port: u16, timeout: Duration) -> U1Result {
    use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
    let _ = src;

    // Send the UDP datagram (kernel builds the IP header).
    let sock = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return U1Result::default(),
    };
    // 300 bytes of 'C', matching nmap's U1 payload volume.
    let payload = vec![0x43u8; 300];

    // Open the ICMP listener BEFORE sending so we don't race the reply.
    let (_itx, mut irx) = match transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp)) {
        Ok(p) => p,
        Err(_) => return U1Result::default(),
    };

    if sock
        .send_to(&payload, (IpAddr::V4(dst), closed_udp_port))
        .is_err()
    {
        return U1Result::default();
    }

    let (chan_tx, chan_rx) = mpsc::channel::<U1Result>();
    thread::spawn(move || {
        let mut iter = ipv4_packet_iter(&mut irx);
        loop {
            match iter.next() {
                Ok((pkt, addr)) => {
                    if addr != IpAddr::V4(dst) {
                        continue;
                    }
                    if pkt.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                        continue;
                    }
                    let Some(icmp) = IcmpPacket::new(pkt.payload()) else { continue };
                    if icmp.get_icmp_type() == IcmpTypes::DestinationUnreachable {
                        // Outer IP TTL of the ICMP reply is the useful stack
                        // signal (Linux 64, Slirp/network gear 255, …).
                        let _ = chan_tx.send(U1Result { responded: true, ttl: pkt.get_ttl() });
                        return;
                    }
                }
                Err(_) => {
                    let _ = chan_tx.send(U1Result::default());
                    return;
                }
            }
        }
    });

    chan_rx.recv_timeout(timeout).unwrap_or_default()
}

/// ICMP echo (IE) probe over a Layer3 channel so we can read the reply
/// TTL and DF bit.
fn send_ie(src: Ipv4Addr, dst: Ipv4Addr, timeout: Duration) -> IeResult {
    let _ = src;
    let (mut tx, mut rx) = match transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp)) {
        Ok(p) => p,
        Err(_) => return IeResult::default(),
    };

    // Build IPv4 + ICMP echo request (DF set, 8-byte payload).
    let icmp_len = 8 + 8;
    let total = 20 + icmp_len;
    let mut buf = vec![0u8; total];
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..20]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total as u16);
        ip.set_identification(rand::thread_rng().gen());
        ip.set_ttl(64);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(ipv4_checksum(&ip.to_immutable()));
    }
    {
        use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
        use pnet::packet::icmp::{IcmpCode, IcmpTypes};
        let mut echo = MutableEchoRequestPacket::new(&mut buf[20..]).unwrap();
        echo.set_icmp_type(IcmpTypes::EchoRequest);
        echo.set_icmp_code(IcmpCode(0));
        echo.set_identifier(std::process::id() as u16);
        echo.set_sequence_number(1);
        echo.set_payload(&[0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let cs = pnet::util::checksum(echo.packet(), 1);
        echo.set_checksum(cs);
    }

    let ip_pkt = match Ipv4Packet::new(&buf) {
        Some(p) => p,
        None => return IeResult::default(),
    };
    if tx.send_to(ip_pkt, IpAddr::V4(dst)).is_err() {
        return IeResult::default();
    }

    let (chan_tx, chan_rx) = mpsc::channel::<IeResult>();
    thread::spawn(move || {
        use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
        let mut iter = ipv4_packet_iter(&mut rx);
        loop {
            match iter.next() {
                Ok((pkt, addr)) => {
                    if addr != IpAddr::V4(dst) {
                        continue;
                    }
                    if pkt.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                        continue;
                    }
                    let Some(icmp) = IcmpPacket::new(pkt.payload()) else { continue };
                    if icmp.get_icmp_type() == IcmpTypes::EchoReply {
                        let df_set = pkt.get_flags() & Ipv4Flags::DontFragment != 0;
                        let _ = chan_tx.send(IeResult {
                            responded: true,
                            ttl: pkt.get_ttl(),
                            df: df_set,
                        });
                        return;
                    }
                }
                Err(_) => {
                    let _ = chan_tx.send(IeResult::default());
                    return;
                }
            }
        }
    });

    chan_rx.recv_timeout(timeout).unwrap_or_default()
}

/// Parse the timestamp option's TSval from a TCP options byte slice.
fn parse_tsval(opts: &[u8]) -> Option<u32> {
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i] {
            0 => break,     // EOL
            1 => i += 1,    // NOP
            8 => {
                // Timestamp: kind(1) len(1)=10 TSval(4) TSecr(4)
                if i + 6 <= opts.len() {
                    return Some(u32::from_be_bytes([
                        opts[i + 2], opts[i + 3], opts[i + 4], opts[i + 5],
                    ]));
                }
                return None;
            }
            _ => {
                if i + 1 < opts.len() {
                    let l = opts[i + 1] as usize;
                    if l < 2 || i + l > opts.len() {
                        break;
                    }
                    i += l;
                } else {
                    break;
                }
            }
        }
    }
    None
}

/// One SEQ sample from an open-port SYN: (ISN, IP-ID, TSval, capture µs).
fn capture_seq_sample(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    open_port: u16,
    timeout: Duration,
) -> Option<(u32, u16, Option<u32>, u64)> {
    let (mut tx, mut rx) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp)).ok()?;
    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(40000..60000);
    let seq: u32 = rng.gen();
    let opts = t_series_options();
    let buf = build_ipv4_tcp(src, dst, src_port, open_port, seq, 0, TcpFlags::SYN, 1, 0, &opts, T_OPTS_LEN, false);
    let ip_pkt = Ipv4Packet::new(&buf)?;
    let t0 = std::time::Instant::now();
    if tx.send_to(ip_pkt, IpAddr::V4(dst)).is_err() {
        return None;
    }

    let (chan_tx, chan_rx) = mpsc::channel::<(u32, u16, Option<u32>, u64)>();
    thread::spawn(move || {
        let mut iter = ipv4_packet_iter(&mut rx);
        loop {
            match iter.next() {
                Ok((pkt, addr)) => {
                    if addr != IpAddr::V4(dst)
                        || pkt.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
                    {
                        continue;
                    }
                    let Some(tcp) = TcpPacket::new(pkt.payload()) else { continue };
                    if tcp.get_source() != open_port || tcp.get_destination() != src_port {
                        continue;
                    }
                    // Only a SYN/ACK carries a usable ISN.
                    if tcp.get_flags() & TcpFlags::SYN == 0 {
                        let _ = chan_tx.send((0, 0, None, 0));
                        return;
                    }
                    let raw = tcp.packet();
                    let ol = (tcp.get_data_offset() as usize * 4).saturating_sub(20);
                    let tsval = if raw.len() >= 20 + ol {
                        parse_tsval(&raw[20..20 + ol])
                    } else {
                        None
                    };
                    let _ = chan_tx.send((
                        tcp.get_sequence(),
                        pkt.get_identification(),
                        tsval,
                        t0.elapsed().as_micros() as u64,
                    ));
                    return;
                }
                Err(_) => {
                    let _ = chan_tx.send((0, 0, None, 0));
                    return;
                }
            }
        }
    });
    match chan_rx.recv_timeout(timeout) {
        Ok((isn, _, _, _)) if isn == 0 => None,
        Ok(sample) => Some(sample),
        Err(_) => None,
    }
}

/// Six SYN probes to the open port → SEQ line (GCD/ISR/SP), TI (IP-ID
/// class) and TS (timestamp rate class). nmap's Probe #1–#6.
fn run_seq(src: Ipv4Addr, dst: Ipv4Addr, open_port: u16, timeout: Duration) -> SeqInfo {
    let mut isns = Vec::new();
    let mut ids = Vec::new();
    let mut tsvals = Vec::new();
    let mut times = Vec::new();
    let mut ts_supported = false;
    for _ in 0..6 {
        if let Some((isn, id, tsval, t)) = capture_seq_sample(src, dst, open_port, timeout) {
            isns.push(isn);
            ids.push(id);
            times.push(t);
            if let Some(v) = tsval {
                ts_supported = true;
                tsvals.push((v, t));
            }
        }
        std::thread::sleep(Duration::from_millis(110));
    }
    // Times are per-probe elapsed; make them a monotonic timeline.
    let mut clock = 0u64;
    let mut timeline = Vec::with_capacity(times.len());
    for (i, _t) in times.iter().enumerate() {
        clock += 110_000 + times[i];
        timeline.push(clock);
    }
    let seq = crate::nmap_fp::seq_analysis(&isns, &timeline);
    let ti = crate::nmap_fp::ip_id_class(&ids);

    // TS rate from the first/last TSval samples.
    let ts = if !ts_supported {
        "U"
    } else if tsvals.len() >= 2 {
        let (v0, t0) = tsvals[0];
        let (v1, t1) = *tsvals.last().unwrap();
        let dt = (t1.saturating_sub(t0)) as f64 / 1_000_000.0 + 0.11 * (tsvals.len() - 1) as f64;
        let always_zero = tsvals.iter().all(|(v, _)| *v == 0);
        let hz = if dt > 0.0 { Some((v1.wrapping_sub(v0) as f64) / dt) } else { None };
        crate::nmap_fp::ts_field(true, always_zero, hz)
    } else {
        crate::nmap_fp::ts_field(true, tsvals.iter().all(|(v, _)| *v == 0), None)
    };

    SeqInfo { seq, ti, ts }
}

/// Run the full secondary suite. `open_port` must be an open TCP port;
/// `closed_tcp_port`/`closed_udp_port` are ports believed closed (used
/// for T5–T7 and U1). Returns `None` only if no raw channel can be
/// opened at all (no privileges) — otherwise per-probe non-responses are
/// recorded inside the result.
pub fn run_suite(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    open_port: u16,
    closed_tcp_port: Option<u16>,
    closed_udp_port: u16,
    per_probe_timeout: Duration,
) -> Option<SuiteResult> {
    // Bail out early (return None) if we can't even open a raw channel,
    // so the caller can stay silent instead of printing all-N results.
    let probe = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp));
    match probe {
        Ok(_) => {}
        Err(_) => return None,
    }

    let mut result = SuiteResult::default();
    let t_opts = t_series_options();

    // T5–T7 target a closed port. When the scan found no confirmed-closed
    // TCP port, don't skip them (lab bug B8) — probe a presumed-closed high
    // port, exactly as nmap does. On a stack that RSTs unmapped ports
    // (e.g. VirtualBox/QEMU Slirp NAT) this still elicits the RST that
    // fingerprints it; on a fully-filtered host it simply reads R=N.
    let closed_port = closed_tcp_port.unwrap_or_else(|| {
        let mut rng = rand::thread_rng();
        loop {
            let p = rng.gen_range(40000..60000);
            if p != open_port {
                break p;
            }
        }
    });

    for spec in T_PROBES {
        let port = if spec.to_open { open_port } else { closed_port };
        let r = send_tcp_probe(
            src,
            dst,
            port,
            spec.flags,
            spec.window,
            spec.df,
            &t_opts,
            T_OPTS_LEN,
            0,
            per_probe_timeout,
            spec.name,
        );
        result.t.push(r);
    }

    // ECN probe → open port.
    let ecn = send_tcp_probe(
        src,
        dst,
        open_port,
        TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR,
        3,
        false,
        &ecn_options(),
        ECN_OPTS_LEN,
        0xF7F5,
        per_probe_timeout,
        "ECN",
    );
    result.ecn = Some(ecn);

    result.u1 = send_u1(src, dst, closed_udp_port, per_probe_timeout);
    result.ie = send_ie(src, dst, per_probe_timeout);
    // SEQ line (6 open-port SYNs) — ISN math + IP-ID/timestamp classes.
    result.seq = run_seq(src, dst, open_port, per_probe_timeout);

    Some(result)
}

// Keep the IpNextHeaderProtocol import used even if the proto-ping path
// changes; silences dead-import warnings on some feature combos.
#[allow(dead_code)]
fn _proto_marker(_p: IpNextHeaderProtocol) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_table_has_t2_to_t7() {
        assert_eq!(T_PROBES.len(), 6);
        assert_eq!(T_PROBES[0].name, "T2");
        assert_eq!(T_PROBES[5].name, "T7");
        // T5–T7 target closed ports.
        assert!(!T_PROBES[3].to_open);
        assert!(!T_PROBES[4].to_open);
        assert!(!T_PROBES[5].to_open);
    }

    #[test]
    fn flags_string_matches_nmap_notation() {
        assert_eq!(flags_str(TcpFlags::RST | TcpFlags::ACK), "AR");
        assert_eq!(flags_str(TcpFlags::SYN | TcpFlags::ACK), "AS");
        assert_eq!(flags_str(TcpFlags::ECE | TcpFlags::SYN | TcpFlags::CWR), "SEC");
        assert_eq!(flags_str(0), "-");
    }

    #[test]
    fn build_packet_is_well_formed() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let opts = t_series_options();
        let buf = build_ipv4_tcp(src, dst, 55555, 80, 0x1234, 0, TcpFlags::SYN, 128, 0, &opts, T_OPTS_LEN, true);
        let ip = Ipv4Packet::new(&buf).unwrap();
        assert_eq!(ip.get_version(), 4);
        assert_eq!(ip.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);
        assert_eq!(ip.get_destination(), dst);
        // DF bit set.
        assert!(ip.get_flags() & Ipv4Flags::DontFragment != 0);
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        assert_eq!(tcp.get_destination(), 80);
        assert_eq!(tcp.get_window(), 128);
        assert_eq!(tcp.get_flags(), TcpFlags::SYN);
    }

    #[test]
    fn observed_ttl_picks_the_mode() {
        let mut s = SuiteResult::default();
        s.t.push(TResult { name: "T4", responded: true, df: true, ttl: 64, window: 0, flags: TcpFlags::RST, ..Default::default() });
        s.t.push(TResult { name: "T5", responded: true, df: false, ttl: 64, window: 0, flags: TcpFlags::RST, ..Default::default() });
        s.t.push(TResult { name: "T6", responded: true, df: true, ttl: 128, window: 0, flags: TcpFlags::RST, ..Default::default() });
        s.t.push(TResult::none("T7"));
        assert_eq!(s.observed_ttl(), Some(64));
    }

    #[test]
    fn observed_ttl_none_when_silent() {
        let s = SuiteResult::default();
        assert_eq!(s.observed_ttl(), None);
    }

    #[test]
    fn diagnostic_renders_all_probes() {
        let mut s = SuiteResult::default();
        s.t.push(TResult { name: "T2", responded: false, df: false, ttl: 0, window: 0, flags: 0, ..Default::default() });
        s.ecn = Some(TResult { name: "ECN", responded: true, df: false, ttl: 64, window: 3, flags: TcpFlags::SYN | TcpFlags::ACK | TcpFlags::ECE, ..Default::default() });
        s.u1 = U1Result { responded: true, ttl: 64 };
        s.ie = IeResult { responded: true, ttl: 64, df: true };
        let d = s.diagnostic();
        assert!(d.contains("T2(R=N)"), "{}", d);
        assert!(d.contains("ECN(R=Y"), "{}", d);
        assert!(d.contains("U1(R=Y"), "{}", d);
        assert!(d.contains("IE(R=Y"), "{}", d);
    }

    #[test]
    fn nat_gateway_signature_detects_slirp() {
        // Slirp: RST replies with TTL 255 and DF cleared.
        let mut s = SuiteResult::default();
        for name in ["T2", "T3", "T4", "T6"] {
            s.t.push(TResult { name, responded: true, df: false, ttl: 255, window: 0, flags: TcpFlags::RST, ..Default::default() });
        }
        assert!(s.nat_gateway_signature());

        // A real Linux host: RSTs carry TTL 64 with DF set → not a NAT gw.
        let mut lin = SuiteResult::default();
        for name in ["T4", "T5", "T6", "T7"] {
            lin.t.push(TResult { name, responded: true, df: true, ttl: 64, window: 0, flags: TcpFlags::RST, ..Default::default() });
        }
        assert!(!lin.nat_gateway_signature());

        // Too few responders → never fires.
        let mut lone = SuiteResult::default();
        lone.t.push(TResult { name: "T2", responded: true, df: false, ttl: 255, window: 0, flags: TcpFlags::RST, ..Default::default() });
        assert!(!lone.nat_gateway_signature());
    }

    #[test]
    fn notes_flag_ecn_and_closed_rst() {
        let mut s = SuiteResult::default();
        s.t.push(TResult { name: "T5", responded: true, df: false, ttl: 64, window: 0, flags: TcpFlags::RST | TcpFlags::ACK, ..Default::default() });
        s.ecn = Some(TResult { name: "ECN", responded: true, df: false, ttl: 64, window: 3, flags: TcpFlags::SYN | TcpFlags::ACK | TcpFlags::ECE, ..Default::default() });
        let notes = s.notes();
        assert!(notes.iter().any(|n| n.contains("RST")), "{:?}", notes);
        assert!(notes.iter().any(|n| n.contains("ECN")), "{:?}", notes);
    }
}
