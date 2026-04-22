use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::TransportSender;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

// ── TCP/IP Stack Emulation Profiles (technique 1) ────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackProfile {
    Default,
    Windows11,
    Windows10,
    Linux6,
    MacOS,
    FreeBSD,
    Android14,
}

impl StackProfile {
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "default" | "none" => Some(Self::Default),
            "windows11" | "win11" | "w11" => Some(Self::Windows11),
            "windows10" | "win10" | "w10" => Some(Self::Windows10),
            "linux" | "linux6" => Some(Self::Linux6),
            "macos" | "darwin" | "osx" => Some(Self::MacOS),
            "freebsd" | "bsd" => Some(Self::FreeBSD),
            "android" | "android14" => Some(Self::Android14),
            _ => None,
        }
    }

    pub fn ttl(&self) -> u8 {
        match self {
            Self::Default => 64,
            Self::Windows11 | Self::Windows10 => 128,
            Self::Linux6 | Self::Android14 => 64,
            Self::MacOS | Self::FreeBSD => 64,
        }
    }

    pub fn window_size(&self) -> u16 {
        match self {
            Self::Default => 64240,
            Self::Windows11 | Self::Windows10 => 65535,
            Self::Linux6 | Self::Android14 => 64240,
            Self::MacOS | Self::FreeBSD => 65535,
        }
    }

    /// Raw TCP options bytes matching real OS SYN fingerprints (4-byte aligned).
    pub fn tcp_options(&self) -> Vec<u8> {
        match self {
            Self::Default => vec![],
            // Windows: MSS 1460, NOP, WS 8, NOP, NOP, SACK_PERM (12 bytes)
            Self::Windows11 | Self::Windows10 => {
                vec![2, 4, 0x05, 0xB4, 1, 3, 3, 8, 1, 1, 4, 2]
            }
            // Linux: MSS 1460, SACK_PERM, TS val ecr, NOP, WS 7 (20 bytes)
            Self::Linux6 | Self::Android14 => {
                let ts = synthetic_timestamp().to_be_bytes();
                let mut o = vec![2, 4, 0x05, 0xB4, 4, 2, 8, 10];
                o.extend_from_slice(&ts);
                o.extend_from_slice(&[0, 0, 0, 0]);
                o.extend_from_slice(&[1, 3, 3, 7]);
                o
            }
            // macOS/Darwin: MSS 1460, NOP, NOP, TS val ecr, NOP, WS 6, SACK_PERM, EOL
            Self::MacOS => {
                let ts = synthetic_timestamp().to_be_bytes();
                let mut o = vec![2, 4, 0x05, 0xB4, 1, 1, 8, 10];
                o.extend_from_slice(&ts);
                o.extend_from_slice(&[0, 0, 0, 0]);
                o.extend_from_slice(&[1, 3, 3, 6, 4, 2, 0, 0]);
                o
            }
            // FreeBSD: MSS 1460, NOP, WS 6, SACK_PERM, NOP, NOP, TS val ecr
            Self::FreeBSD => {
                let ts = synthetic_timestamp().to_be_bytes();
                let mut o = vec![2, 4, 0x05, 0xB4, 1, 3, 3, 6, 4, 2, 1, 1, 8, 10];
                o.extend_from_slice(&ts);
                o.extend_from_slice(&[0, 0, 0, 0]);
                o
            }
        }
    }
}

fn synthetic_timestamp() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u32
}

// ── Evasion Presets / Framework (technique 25) ───────────────────

#[derive(Debug, Clone, Copy)]
pub enum EvasionPreset {
    Stealth,
    Aggressive,
    Paranoid,
    Ghost,
}

impl EvasionPreset {
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "stealth" | "s" => Some(Self::Stealth),
            "aggressive" | "a" => Some(Self::Aggressive),
            "paranoid" | "p" => Some(Self::Paranoid),
            "ghost" | "g" => Some(Self::Ghost),
            _ => None,
        }
    }

    pub fn to_config(self) -> EvasionConfig {
        match self {
            // Stealth: mimic Windows browsing traffic, slow jitter
            Self::Stealth => EvasionConfig {
                source_port: Some(443),
                ip_ttl: 128,
                stack_profile: StackProfile::Windows11,
                jitter: JitterMode::Gaussian(200),
                ..Default::default()
            },
            // Aggressive: fragmentation, rotation, fast
            Self::Aggressive => EvasionConfig {
                source_port: Some(53),
                fragment: true,
                frag_mtu: 8,
                data_length: 24,
                rotate: true,
                jitter: JitterMode::Uniform(30),
                ..Default::default()
            },
            // Paranoid: everything combined, slow
            Self::Paranoid => EvasionConfig {
                source_port: Some(80),
                ip_ttl: 128,
                data_length: 16,
                fragment: true,
                frag_mtu: 8,
                stack_profile: StackProfile::Windows11,
                jitter: JitterMode::Gaussian(500),
                rotate: true,
                frag_overlap: true,
                ..Default::default()
            },
            // Ghost: maximum anti-DPI — overlapping frags, TTL jitter,
            // decoy pre-ping, rotation, Linux stack, uniform jitter. Slower
            // than aggressive but less deterministic than paranoid.
            Self::Ghost => EvasionConfig {
                source_port: Some(443),
                ip_ttl: 64,
                ttl_jitter: 8,
                data_length: 12,
                fragment: true,
                frag_mtu: 8,
                frag_overlap: true,
                stack_profile: StackProfile::Linux6,
                jitter: JitterMode::Gaussian(120),
                rotate: true,
                decoy_preping: true,
                ..Default::default()
            },
        }
    }
}

// ── Jitter / Realistic Timing (technique 15) ─────────────────────

#[derive(Debug, Clone, Copy)]
#[derive(Default)]
pub enum JitterMode {
    #[default]
    None,
    /// Uniform random delay up to max_ms.
    Uniform(u64),
    /// Gaussian distribution with given mean (stddev = mean/3).
    Gaussian(u64),
}


/// Blocking sleep with jitter (for raw scanner threads).
pub fn jitter_sleep(mode: &JitterMode) {
    let ms = match mode {
        JitterMode::None => return,
        JitterMode::Uniform(max) => {
            if *max == 0 {
                return;
            }
            rand::thread_rng().gen_range(0..*max)
        }
        JitterMode::Gaussian(mean) => {
            if *mean == 0 {
                return;
            }
            // Box-Muller transform for gaussian distribution
            let mut rng = rand::thread_rng();
            let u1: f64 = rng.gen_range(0.001f64..1.0);
            let u2: f64 = rng.gen_range(0.0f64..1.0);
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            let stddev = *mean as f64 / 3.0;
            (*mean as f64 + z * stddev).max(0.0) as u64
        }
    };
    if ms > 0 {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

// ── Evasion Configuration ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EvasionConfig {
    // Layer 3-4 basic
    pub source_port: Option<u16>,
    pub decoys: Vec<Ipv4Addr>,
    pub ip_ttl: u8,
    /// Per-probe TTL jitter (±N). Independent of `rotate`.
    pub ttl_jitter: u8,
    pub data_length: usize,
    pub fragment: bool,
    pub frag_mtu: u16,
    pub bad_checksum: bool,
    // Stack emulation (technique 1)
    pub stack_profile: StackProfile,
    // Timing (technique 15)
    pub jitter: JitterMode,
    // Rotation (technique 17)
    pub rotate: bool,
    // Overlap fragmentation (technique 2)
    pub frag_overlap: bool,
    // Custom TCP flags (technique 7 — protocol exceptions)
    pub custom_flags: Option<u8>,
    /// Send a short dummy SYN from each decoy before the real probe,
    /// confusing stateful firewalls that build connection tables.
    pub decoy_preping: bool,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            source_port: None,
            decoys: Vec::new(),
            ip_ttl: 64,
            ttl_jitter: 0,
            data_length: 0,
            fragment: false,
            frag_mtu: 8,
            bad_checksum: false,
            stack_profile: StackProfile::Default,
            jitter: JitterMode::None,
            rotate: false,
            frag_overlap: false,
            custom_flags: None,
            decoy_preping: false,
        }
    }
}

impl EvasionConfig {
    /// Whether we need a raw IP socket (Layer3) for full packet control.
    pub fn needs_layer3(&self) -> bool {
        self.ip_ttl != 64
            || self.ttl_jitter > 0
            || self.fragment
            || !self.decoys.is_empty()
            || self.stack_profile != StackProfile::Default
            || self.custom_flags.is_some()
            || self.rotate // rotation varies TTL → needs IP header control
    }

    pub fn is_active(&self) -> bool {
        self.source_port.is_some()
            || !self.decoys.is_empty()
            || self.ip_ttl != 64
            || self.ttl_jitter > 0
            || self.data_length > 0
            || self.fragment
            || self.bad_checksum
            || self.stack_profile != StackProfile::Default
            || !matches!(self.jitter, JitterMode::None)
            || self.rotate
            || self.frag_overlap
            || self.custom_flags.is_some()
            || self.decoy_preping
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(p) = self.source_port {
            parts.push(format!("src-port={}", p));
        }
        if !self.decoys.is_empty() {
            parts.push(format!("{} decoy(s)", self.decoys.len()));
        }
        if self.ip_ttl != 64 {
            parts.push(format!("ttl={}", self.ip_ttl));
        }
        if self.ttl_jitter > 0 {
            parts.push(format!("ttl-jitter=±{}", self.ttl_jitter));
        }
        if self.decoy_preping {
            parts.push("decoy-preping".to_string());
        }
        if self.data_length > 0 {
            parts.push(format!("pad={}B", self.data_length));
        }
        if self.fragment {
            let mode = if self.frag_overlap { "overlap" } else { "basic" };
            parts.push(format!("frag/{}/{}", self.frag_mtu, mode));
        }
        if self.bad_checksum {
            parts.push("badsum".to_string());
        }
        if self.stack_profile != StackProfile::Default {
            parts.push(format!("stack={:?}", self.stack_profile));
        }
        match self.jitter {
            JitterMode::Uniform(ms) => parts.push(format!("jitter=uniform/{}ms", ms)),
            JitterMode::Gaussian(ms) => parts.push(format!("jitter=gauss/{}ms", ms)),
            JitterMode::None => {}
        }
        if self.rotate {
            parts.push("rotate".to_string());
        }
        if let Some(f) = self.custom_flags {
            parts.push(format!("flags=0x{:02X}", f));
        }
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join(", ")
        }
    }

    /// Return a per-probe variant with slightly randomized parameters (technique 17).
    pub fn rotated(&self) -> Self {
        let mut c = self.clone();
        let mut rng = rand::thread_rng();
        // Vary TTL ±0..12 around base
        let delta: i16 = rng.gen_range(-6..12);
        c.ip_ttl = (c.ip_ttl as i16 + delta).clamp(1, 255) as u8;
        // Vary data length ±0..16
        let d: i32 = rng.gen_range(-8..16);
        c.data_length = (c.data_length as i32 + d).max(0) as usize;
        // Randomize source port even if one was fixed
        if c.source_port.is_some() {
            c.source_port = Some(rng.gen_range(1024..65000));
        }
        c
    }

    /// Apply independent per-probe TTL jitter (±ttl_jitter). Used on every probe
    /// even when `rotate` is off, so stateful scrubbers can't key on a fixed TTL.
    pub fn jittered_ttl(&self) -> u8 {
        if self.ttl_jitter == 0 {
            return self.ip_ttl;
        }
        let j = self.ttl_jitter as i16;
        let delta: i16 = rand::thread_rng().gen_range(-j..=j);
        (self.ip_ttl as i16 + delta).clamp(1, 255) as u8
    }

    /// Effective TCP flags: custom_flags overrides scan-type flags.
    pub fn effective_flags(&self, kind_flags: u8) -> u8 {
        self.custom_flags.unwrap_or(kind_flags)
    }
}

// ── TCP Segment Builder ──────────────────────────────────────────

/// Build a TCP segment with stack emulation and evasion options.
pub fn build_tcp_segment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    flags: u8,
    seq: u32,
    src_port: u16,
    cfg: &EvasionConfig,
) -> Vec<u8> {
    let options = cfg.stack_profile.tcp_options();
    let tcp_hdr_len = 20 + options.len();
    let data_offset = (tcp_hdr_len / 4) as u8;
    let total = tcp_hdr_len + cfg.data_length;
    let mut buf = vec![0u8; total];

    // Write TCP options into header space
    if !options.is_empty() {
        buf[20..20 + options.len()].copy_from_slice(&options);
    }

    // Random padding bytes in payload area
    if cfg.data_length > 0 {
        rand::thread_rng().fill(&mut buf[tcp_hdr_len..]);
    }

    {
        let mut pkt = MutableTcpPacket::new(&mut buf).unwrap();
        pkt.set_source(src_port);
        pkt.set_destination(dst_port);
        pkt.set_sequence(seq);
        pkt.set_acknowledgement(0);
        pkt.set_data_offset(data_offset);
        pkt.set_flags(flags);
        pkt.set_window(cfg.stack_profile.window_size());
        pkt.set_urgent_ptr(0);

        if cfg.bad_checksum {
            pkt.set_checksum(0xDEAD);
        } else {
            let cs = ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip);
            pkt.set_checksum(cs);
        }
    }

    buf
}

// ── IPv4 Packet Builder ─────────────────────────────────────────

pub fn build_ip_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    tcp_bytes: &[u8],
    ttl: u8,
) -> Vec<u8> {
    let total = 20 + tcp_bytes.len();
    let mut buf = vec![0u8; total];

    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total as u16);
        ip.set_identification(rand::thread_rng().gen());
        ip.set_flags(0x02); // DF
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_payload(tcp_bytes);
        let cs = ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(cs);
    }

    buf
}

// ── IP Fragmentation (techniques 2 + A.1) ────────────────────────

/// Fragment an IP packet. `frag_payload_size` is rounded to multiple of 8.
/// When `overlap` is true, fragments overlap by half (technique 2).
pub fn fragment_ip(ip_bytes: &[u8], frag_payload_size: u16, overlap: bool) -> Vec<Vec<u8>> {
    let frag_size = ((frag_payload_size / 8) * 8).max(8) as usize;
    let ip_hdr_len = 20;

    if ip_bytes.len() <= ip_hdr_len {
        return vec![ip_bytes.to_vec()];
    }

    let payload = &ip_bytes[ip_hdr_len..];
    if payload.len() <= frag_size {
        let mut single = ip_bytes.to_vec();
        if let Some(mut ip) = MutableIpv4Packet::new(&mut single) {
            ip.set_flags(0);
            ip.set_checksum(0);
            let cs = ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(cs);
        }
        return vec![single];
    }

    let orig_id = Ipv4Packet::new(ip_bytes)
        .map(|p| p.get_identification())
        .unwrap_or(0);

    // Overlap: advance by half the fragment size so each fragment shares data with the next
    let step = if overlap {
        ((frag_size / 2) / 8 * 8).max(8)
    } else {
        frag_size
    };

    let mut frags = Vec::new();
    let mut off = 0usize;

    while off < payload.len() {
        let end = (off + frag_size).min(payload.len());
        let is_last = end >= payload.len();
        let chunk = &payload[off..end];

        let frag_total = ip_hdr_len + chunk.len();
        let mut buf = vec![0u8; frag_total];
        buf[..ip_hdr_len].copy_from_slice(&ip_bytes[..ip_hdr_len]);
        buf[ip_hdr_len..].copy_from_slice(chunk);

        {
            let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
            ip.set_total_length(frag_total as u16);
            ip.set_identification(orig_id);
            ip.set_fragment_offset((off / 8) as u16);
            ip.set_flags(if is_last { 0 } else { 0x01 }); // MF
            ip.set_checksum(0);
            let cs = ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(cs);
        }

        frags.push(buf);
        off += step;
    }

    frags
}

// ── Sending Helpers ──────────────────────────────────────────────

/// Send an IP packet (optionally fragmented) via Layer3 transport.
pub fn send_ip_raw(
    tx: &mut TransportSender,
    ip_bytes: &[u8],
    dst: Ipv4Addr,
    cfg: &EvasionConfig,
) -> std::io::Result<()> {
    if cfg.fragment {
        for f in &fragment_ip(ip_bytes, cfg.frag_mtu, cfg.frag_overlap) {
            let pkt = Ipv4Packet::new(f).unwrap();
            tx.send_to(pkt, IpAddr::V4(dst))?;
        }
    } else {
        let pkt = Ipv4Packet::new(ip_bytes).unwrap();
        tx.send_to(pkt, IpAddr::V4(dst))?;
    }
    Ok(())
}

/// Send decoy probes from spoofed IPs, then the real probe.
pub fn send_with_decoys(
    tx: &mut TransportSender,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    flags: u8,
    src_port: u16,
    cfg: &EvasionConfig,
) -> bool {
    let mut rng = rand::thread_rng();

    // Pre-ping: benign SYNs to port 80/443 from each decoy, to seed the
    // firewall's connection table and blend the real probe into "normal" noise.
    if cfg.decoy_preping {
        for &decoy_ip in &cfg.decoys {
            let warm_port = if rng.gen_bool(0.5) { 80 } else { 443 };
            let warm_tcp = build_tcp_segment(
                decoy_ip,
                dst_ip,
                warm_port,
                TcpFlags::SYN,
                rng.gen(),
                rng.gen_range(40000..60000),
                cfg,
            );
            let ip = build_ip_packet(decoy_ip, dst_ip, &warm_tcp, cfg.jittered_ttl());
            let _ = send_ip_raw(tx, &ip, dst_ip, cfg);
        }
    }

    // Decoy probes (spoofed source IPs)
    for &decoy_ip in &cfg.decoys {
        let decoy_tcp = build_tcp_segment(
            decoy_ip,
            dst_ip,
            dst_port,
            flags,
            rng.gen(),
            rng.gen_range(40000..60000),
            cfg,
        );
        let ip = build_ip_packet(decoy_ip, dst_ip, &decoy_tcp, cfg.jittered_ttl());
        let _ = send_ip_raw(tx, &ip, dst_ip, cfg);
    }

    // Real probe
    let tcp = build_tcp_segment(src_ip, dst_ip, dst_port, flags, rng.gen(), src_port, cfg);
    let ip = build_ip_packet(src_ip, dst_ip, &tcp, cfg.jittered_ttl());
    send_ip_raw(tx, &ip, dst_ip, cfg).is_ok()
}

// ── Scanflags Parser ─────────────────────────────────────────────

const TCP_ECE: u8 = 0x40;
const TCP_CWR: u8 = 0x80;

/// Parse custom TCP flags from hex (0x02) or names (SYN,FIN,ECE).
pub fn parse_scanflags(s: &str) -> Result<u8, String> {
    // Hex: 0x02, 0x12, etc.
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u8::from_str_radix(hex, 16).map_err(|e| format!("invalid hex flags: {}", e));
    }
    // Pure numeric
    if s.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = s.parse::<u8>() {
            return Ok(n);
        }
    }
    // Named flags: SYN,FIN,PSH,ACK,URG,RST,ECE,CWR
    let mut flags = 0u8;
    for name in s.split(',') {
        flags |= match name.trim().to_uppercase().as_str() {
            "FIN" => TcpFlags::FIN,
            "SYN" => TcpFlags::SYN,
            "RST" => TcpFlags::RST,
            "PSH" => TcpFlags::PSH,
            "ACK" => TcpFlags::ACK,
            "URG" => TcpFlags::URG,
            "ECE" => TCP_ECE,
            "CWR" => TCP_CWR,
            other => return Err(format!("unknown TCP flag: {}", other)),
        };
    }
    Ok(flags)
}
