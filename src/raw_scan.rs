use crate::evasion::{self, EvasionConfig};
use crate::net_util::source_ipv4_for;
use crate::scanner::{HostResult, PortResult, PortState};
use crate::target::Target;
use anyhow::{anyhow, Result};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::transport::{
    icmp_packet_iter, tcp_packet_iter, transport_channel,
    TransportChannelType::{Layer3, Layer4},
    TransportProtocol::Ipv4,
    TransportReceiver, TransportSender,
};
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use parking_lot::Mutex;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

/// Global trace toggle — flipped by `set_trace` from main when --trace-raw is on.
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_RX_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn set_trace(on: bool) {
    TRACE_ENABLED.store(on, Ordering::Relaxed);
}

pub fn rx_count() -> u64 {
    TRACE_RX_COUNT.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawTcpKind {
    Syn,
    Fin,
    Null,
    Xmas,
    Ack,
    /// Window scan — like ACK, but examines TCP window of the RST reply.
    /// Open ports return RST with non-zero window; closed return RST with
    /// zero window on most stacks.
    Window,
    /// Maimon scan — FIN+ACK probe. BSD-derived stacks drop on open ports
    /// and RST on closed; everywhere else behaves like generic ACK.
    Maimon,
}

impl RawTcpKind {
    pub fn flags(self) -> u8 {
        match self {
            RawTcpKind::Syn => TcpFlags::SYN,
            RawTcpKind::Fin => TcpFlags::FIN,
            RawTcpKind::Null => 0,
            RawTcpKind::Xmas => TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
            RawTcpKind::Ack => TcpFlags::ACK,
            RawTcpKind::Window => TcpFlags::ACK,
            RawTcpKind::Maimon => TcpFlags::FIN | TcpFlags::ACK,
        }
    }

    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            RawTcpKind::Syn => "SYN",
            RawTcpKind::Fin => "FIN",
            RawTcpKind::Null => "NULL",
            RawTcpKind::Xmas => "Xmas",
            RawTcpKind::Ack => "ACK",
            RawTcpKind::Window => "Window",
            RawTcpKind::Maimon => "Maimon",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Response {
    SynAck,
    Rst { window: u16 },
    Other,
}

/// A probe awaiting its reply. The pending map is keyed by
/// `(remote_ip, remote_port)`; these extra fields let the receiver *correlate*
/// a reply to the exact probe (review #1) rather than trusting the source
/// ip+port alone — the same check the OS-fingerprint probe suite already does:
///   * `exp_src_port` — the local port we sent from. A genuine reply is
///     addressed back to it, so a packet whose TCP **destination** ≠ this is
///     cross-talk (another local socket, an injected/stray packet) and is
///     dropped instead of being mis-attributed to this port.
///   * `exp_ack` — for a layer-4 SYN probe we know our ISN, so a real SYN-ACK
///     must acknowledge `seq+1` (RFC 793). `None` for decoy/layer-3 or non-SYN
///     probes, where we don't emit/observe a known ISN → skip the ack check.
struct Pending {
    sender: mpsc::Sender<Response>,
    exp_src_port: u16,
    exp_ack: Option<u32>,
}

// Key: (remote_ip, remote_port) — works with both random and fixed source ports.
type PendingMap = Arc<Mutex<HashMap<(Ipv4Addr, u16), Pending>>>;

pub struct RawTcpScanner {
    tx4: Arc<Mutex<TransportSender>>,
    tx3: Option<Arc<Mutex<TransportSender>>>,
    pending: PendingMap,
    evasion: EvasionConfig,
    _rx_thread: thread::JoinHandle<()>,
    /// Persistent RTT EWMA (µs) + sample count, feeding the adaptive
    /// per-probe timeout so a filtered port on a fast LAN stops costing the
    /// full `--timeout` (the SYN slow-ramp fix).
    ewma_rtt_us: std::sync::atomic::AtomicU64,
    /// Smoothed RTT deviation (µs), Jacobson/Karels `rttvar`, feeding the
    /// `srtt + 4·rttvar` term of the adaptive per-probe timeout (review #12).
    ewma_rttvar_us: std::sync::atomic::AtomicU64,
    rtt_samples: std::sync::atomic::AtomicU64,
    /// Process-global `--max-rate` pacer (review #2). Built once and shared via
    /// the `Arc<RawTcpScanner>` across every concurrent host, so the aggregate
    /// send rate is a true global cap instead of per-host. `None` = unlimited.
    global_rate: Option<Arc<crate::rate::GlobalRateLimiter>>,
    /// Count of inbound ICMP destination-unreachable (type 3: admin-prohibited
    /// / frag-needed / port-unreach) packets — a rate-limit signal for the
    /// fast engine's congestion window (Fase 31 follow-up). Fed by a single
    /// shared best-effort ICMP reader thread; stays 0 if the ICMP channel
    /// couldn't be opened (no privilege / platform).
    icmp_unreach: Arc<AtomicU64>,
}

impl RawTcpScanner {
    pub fn new(evasion: EvasionConfig, max_rate: u32) -> Result<Self> {
        let (tx4, rx) = transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Tcp)))
            .map_err(|e| {
                anyhow!(
                    "failed to open raw TCP socket: {} — {}",
                    e,
                    crate::privilege::raw_privilege_hint()
                )
            })?;

        let tx3 = if evasion.needs_layer3() {
            let (tx, _rx) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))
                .map_err(|e| {
                    anyhow!(
                        "failed to open raw IP socket for evasion: {} — {}",
                        e,
                        crate::privilege::raw_privilege_hint()
                    )
                })?;
            Some(Arc::new(Mutex::new(tx)))
        } else {
            None
        };

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_rx = Arc::clone(&pending);
        let rx_thread = thread::spawn(move || receiver_loop(rx, pending_rx));

        // Best-effort ICMP listener (one shared thread, not per host → no
        // thread-per-host leak). Counts destination-unreachable as a rate-limit
        // signal for the cwnd. If the channel can't open, we just get no signal
        // and everything else behaves exactly as before.
        let icmp_unreach = Arc::new(AtomicU64::new(0));
        if let Ok((_itx, irx)) =
            transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
        {
            let ctr = Arc::clone(&icmp_unreach);
            thread::spawn(move || icmp_receiver_loop(irx, ctr));
        }

        Ok(Self {
            tx4: Arc::new(Mutex::new(tx4)),
            tx3,
            pending,
            evasion,
            _rx_thread: rx_thread,
            ewma_rtt_us: std::sync::atomic::AtomicU64::new(0),
            ewma_rttvar_us: std::sync::atomic::AtomicU64::new(0),
            rtt_samples: std::sync::atomic::AtomicU64::new(0),
            global_rate: crate::rate::GlobalRateLimiter::new(max_rate),
            icmp_unreach,
        })
    }

    /// Running count of inbound ICMP destination-unreachable packets (0 if the
    /// ICMP listener couldn't be opened). The fast engine reads the delta per
    /// wave to detect rate-limiting.
    fn icmp_unreach(&self) -> u64 {
        self.icmp_unreach.load(Ordering::Relaxed)
    }

    /// Mean observed RTT once a few replies have arrived; `None` while warming
    /// up so early probes keep the full timeout.
    fn mean_rtt(&self) -> Option<Duration> {
        if self.rtt_samples.load(Ordering::Relaxed) < 3 {
            return None;
        }
        let us = self.ewma_rtt_us.load(Ordering::Relaxed);
        (us != 0).then(|| Duration::from_micros(us))
    }

    /// Smoothed RTT variance (`rttvar`), once a few replies have arrived; pairs
    /// with `mean_rtt` to feed `adaptive_timeout`'s `srtt + 4·rttvar` (review
    /// #12). `None` while warming up.
    fn rtt_var(&self) -> Option<Duration> {
        if self.rtt_samples.load(Ordering::Relaxed) < 3 {
            return None;
        }
        Some(Duration::from_micros(self.ewma_rttvar_us.load(Ordering::Relaxed)))
    }

    fn record_rtt(&self, rtt: Duration) {
        let sample = rtt.as_micros().min(u64::MAX as u128) as u64;
        let prev = self.ewma_rtt_us.load(Ordering::Relaxed);
        // srtt EWMA (α=0.25) + rttvar EWMA (β=0.25) in one pass. The deviation
        // is measured against the *current* srtt before it is updated (RFC 6298).
        let (next_srtt, next_var) = if prev == 0 {
            (sample, sample / 2) // RFC 6298 initial rttvar = sample/2
        } else {
            let err = prev.abs_diff(sample);
            let prev_var = self.ewma_rttvar_us.load(Ordering::Relaxed);
            ((prev * 3 + sample) / 4, (prev_var * 3 + err) / 4)
        };
        self.ewma_rtt_us.store(next_srtt, Ordering::Relaxed);
        self.ewma_rttvar_us.store(next_var, Ordering::Relaxed);
        self.rtt_samples.fetch_add(1, Ordering::Relaxed);
    }

    pub fn probe(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        kind: RawTcpKind,
        timeout: Duration,
    ) -> (PortState, Option<Duration>) {
        // Timing evasion (technique 15): jitter between probes
        evasion::jitter_sleep(&self.evasion.jitter);

        // Per-probe rotation (technique 17): vary TTL, src port, padding
        let ev = if self.evasion.rotate {
            self.evasion.rotated()
        } else {
            self.evasion.clone()
        };

        let mut rng = rand::thread_rng();
        let src_port: u16 = ev
            .source_port
            .unwrap_or_else(|| rng.gen_range(40000..60000));
        let flags = ev.effective_flags(kind.flags());
        // Our ISN for the layer-4 path, and the basis for the SYN-ACK ack
        // correlation (review #1). Decoy/layer-3 sends pick their own ISN
        // internally, so there we can't predict the ack → exp_ack stays None.
        let seq: u32 = rng.gen();
        let exp_ack = (!ev.needs_layer3() && matches!(kind, RawTcpKind::Syn))
            .then_some(seq.wrapping_add(1));

        let (sender, receiver) = mpsc::channel::<Response>();
        {
            self.pending.lock().insert(
                (dst_ip, dst_port),
                Pending { sender, exp_src_port: src_port, exp_ack },
            );
        }

        // Global --max-rate pacing (review #2): block before the packet leaves
        // so the ceiling is enforced across every concurrent host scanner.
        if let Some(g) = &self.global_rate {
            g.acquire(1);
        }

        let send_ok = if ev.needs_layer3() {
            // Layer3 path — full IP control (TTL, fragmentation, decoys)
            if let Some(ref tx3) = self.tx3 {
                let mut tx = tx3.lock();
                evasion::send_with_decoys(
                    &mut tx,
                    src_ip,
                    dst_ip,
                    dst_port,
                    flags,
                    src_port,
                    &ev,
                )
            } else {
                false
            }
        } else {
            // Layer4 path — TCP-level evasion (source port, padding, bad checksum)
            let tcp = evasion::build_tcp_segment(
                src_ip,
                dst_ip,
                dst_port,
                flags,
                seq,
                src_port,
                &ev,
            );
            let mut tx = self.tx4.lock();
            let pkt = TcpPacket::new(&tcp).unwrap();
            tx.send_to(pkt, IpAddr::V4(dst_ip)).is_ok()
        };

        if TRACE_ENABLED.load(Ordering::Relaxed) {
            eprintln!(
                "[raw-tx] {}:{} flags=0x{:02x} src_port={} send_ok={}",
                dst_ip, dst_port, flags, src_port, send_ok
            );
        }

        let (state, rtt) = if !send_ok {
            (PortState::Filtered, None)
        } else {
            // Shrink the recv wait toward the observed RTT once we have a few
            // samples; early probes keep the full `timeout`. This is what
            // collapses the small-scan slow-ramp vs nmap (a filtered port no
            // longer blocks the whole base timeout on a fast LAN).
            let eff = crate::rate::adaptive_timeout(
                timeout,
                self.mean_rtt(),
                self.rtt_var(),
                crate::rate::timeout_floor(timeout),
            );
            let t0 = Instant::now();
            let recvd = receiver.recv_timeout(eff);
            // Real measured RTT for this probe (review #3) — fed to the EWMA and
            // returned so the caller reports it instead of a hardcoded 0.
            let rtt = if recvd.is_ok() {
                let e = t0.elapsed();
                self.record_rtt(e);
                Some(e)
            } else {
                None
            };
            let st = match recvd {
                Ok(Response::SynAck) => PortState::Open,
                Ok(Response::Rst { window }) => match kind {
                    RawTcpKind::Syn => PortState::Closed,
                    RawTcpKind::Fin | RawTcpKind::Null | RawTcpKind::Xmas => PortState::Closed,
                    RawTcpKind::Ack => PortState::Unfiltered,
                    // Window scan: open ports return RST with non-zero
                    // window on most stacks (Linux post-2.6, BSD, Solaris).
                    RawTcpKind::Window => {
                        if window > 0 { PortState::Open } else { PortState::Closed }
                    }
                    // Maimon (FIN+ACK): RST → closed; drop → open|filtered.
                    // Treat any RST as closed.
                    RawTcpKind::Maimon => PortState::Closed,
                },
                Ok(Response::Other) => PortState::Filtered,
                Err(_) => match kind {
                    RawTcpKind::Syn => PortState::Filtered,
                    RawTcpKind::Fin | RawTcpKind::Null | RawTcpKind::Xmas => PortState::OpenFiltered,
                    RawTcpKind::Ack => PortState::Filtered,
                    RawTcpKind::Window => PortState::Filtered,
                    RawTcpKind::Maimon => PortState::OpenFiltered,
                },
            };
            (st, rtt)
        };

        self.pending
            .lock()
            .remove(&(dst_ip, dst_port));
        (state, rtt)
    }

    /// Send a probe WITHOUT waiting for the reply, returning the channel the
    /// receiver thread will push the response onto. The `--fast-engine` burst
    /// path uses this (send all, then collect) instead of the per-probe
    /// send→block→next of `probe()`. Send half mirrors `probe()` exactly so
    /// the packets on the wire are identical.
    fn send_probe(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        kind: RawTcpKind,
    ) -> mpsc::Receiver<Response> {
        evasion::jitter_sleep(&self.evasion.jitter);
        let ev = if self.evasion.rotate {
            self.evasion.rotated()
        } else {
            self.evasion.clone()
        };
        let mut rng = rand::thread_rng();
        let src_port: u16 = ev
            .source_port
            .unwrap_or_else(|| rng.gen_range(40000..60000));
        let flags = ev.effective_flags(kind.flags());
        let seq: u32 = rng.gen();
        let exp_ack = (!ev.needs_layer3() && matches!(kind, RawTcpKind::Syn))
            .then_some(seq.wrapping_add(1));

        let (sender, receiver) = mpsc::channel::<Response>();
        {
            self.pending.lock().insert(
                (dst_ip, dst_port),
                Pending { sender, exp_src_port: src_port, exp_ack },
            );
        }

        if let Some(g) = &self.global_rate {
            g.acquire(1);
        }

        let send_ok = if ev.needs_layer3() {
            if let Some(ref tx3) = self.tx3 {
                let mut tx = tx3.lock();
                evasion::send_with_decoys(&mut tx, src_ip, dst_ip, dst_port, flags, src_port, &ev)
            } else {
                false
            }
        } else {
            let tcp = evasion::build_tcp_segment(src_ip, dst_ip, dst_port, flags, seq, src_port, &ev);
            let mut tx = self.tx4.lock();
            let pkt = TcpPacket::new(&tcp).unwrap();
            tx.send_to(pkt, IpAddr::V4(dst_ip)).is_ok()
        };
        if TRACE_ENABLED.load(Ordering::Relaxed) {
            eprintln!(
                "[raw-tx] {}:{} flags=0x{:02x} src_port={} send_ok={}",
                dst_ip, dst_port, flags, src_port, send_ok
            );
        }
        receiver
    }

    /// Remove a pending entry (fast path, after collecting or timing out).
    fn clear_pending(&self, dst_ip: Ipv4Addr, dst_port: u16) {
        self.pending.lock().remove(&(dst_ip, dst_port));
    }

    /// Fase 30 (Linux): the `sendmmsg(2)` burst path is only byte-for-byte
    /// equivalent to the per-probe path when evasion is *passive* — no
    /// per-probe timing jitter and no Layer-3/IP-header control (decoys, frag,
    /// TTL tricks, source spoof, IP options, rotation). Custom source port,
    /// padding and bad-checksum are baked into the TCP segment by
    /// `build_tcp_segment`, so they ride along unchanged and stay batch-safe.
    #[cfg(target_os = "linux")]
    fn batch_eligible(&self) -> bool {
        !self.evasion.needs_layer3()
            && matches!(self.evasion.jitter, crate::evasion::JitterMode::None)
    }

    /// Fase 30 (Linux): burst-send every probe in `ports` with a single
    /// `sendmmsg(2)` (per up-to-1024 probes) instead of one `send_to` syscall
    /// each. The send half mirrors `send_probe()`'s Layer4 branch exactly —
    /// same `build_tcp_segment` call, same pending-map insert keyed on
    /// `(dst_ip, port)` — so the packets on the wire and the reply demux are
    /// identical; only the syscall count drops. Returns the per-port receivers
    /// in the same shape the fast engine's collect loop already consumes.
    #[cfg(target_os = "linux")]
    fn send_probe_batch(
        &self,
        batch: &linux_batch::LinuxBatchSender,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        ports: &[u16],
        kind: RawTcpKind,
    ) -> Vec<(u16, mpsc::Receiver<Response>)> {
        let mut rng = rand::thread_rng();
        let ev = self.evasion.clone(); // passive — guaranteed by batch_eligible()
        let mut pairs: Vec<(u16, mpsc::Receiver<Response>)> = Vec::with_capacity(ports.len());
        let mut segs: Vec<Vec<u8>> = Vec::with_capacity(ports.len());
        for &p in ports {
            let src_port: u16 = ev.source_port.unwrap_or_else(|| rng.gen_range(40000..60000));
            let flags = ev.effective_flags(kind.flags());
            let seq: u32 = rng.gen();
            // batch_eligible() guarantees passive evasion → always layer-4, so a
            // SYN probe's ISN is known and the ack can be correlated (review #1).
            let exp_ack = matches!(kind, RawTcpKind::Syn).then_some(seq.wrapping_add(1));
            let seg = evasion::build_tcp_segment(src_ip, dst_ip, p, flags, seq, src_port, &ev);
            let (sender, receiver) = mpsc::channel::<Response>();
            self.pending.lock().insert(
                (dst_ip, p),
                Pending { sender, exp_src_port: src_port, exp_ack },
            );
            segs.push(seg);
            pairs.push((p, receiver));
        }
        // Global --max-rate pacing for the whole burst at once (review #2).
        if let Some(g) = &self.global_rate {
            g.acquire(segs.len());
        }
        let sent = batch.send_batch(dst_ip, &segs);
        if TRACE_ENABLED.load(Ordering::Relaxed) {
            eprintln!(
                "[raw-tx] sendmmsg burst {} → {} ports ({} queued)",
                dst_ip,
                ports.len(),
                sent
            );
        }
        pairs
    }
}

/// Fase 30 (Linux only): batched raw-send engine. A send-only `SOCK_RAW` /
/// `IPPROTO_TCP` socket with `IP_HDRINCL` OFF — so the kernel prepends the IP
/// header exactly like pnet's Layer4 sender — fed many probe segments per
/// `sendmmsg(2)` call (the kernel caps a batch at 1024 messages). Replies are
/// demuxed by the existing pnet receiver thread via the scanner's pending map;
/// this socket is never read from. Collapsing N `send_to` syscalls into ~N/1024
/// is the real throughput lever behind `--fast-engine` on Linux.
#[cfg(target_os = "linux")]
mod linux_batch {
    use std::io;
    use std::mem;
    use std::net::Ipv4Addr;
    use std::os::unix::io::RawFd;

    pub struct LinuxBatchSender {
        fd: RawFd,
    }

    impl LinuxBatchSender {
        pub fn new() -> io::Result<Self> {
            // SOCK_RAW + IPPROTO_TCP, IP_HDRINCL left off → we supply the TCP
            // segment and the kernel builds the IP header, matching the Layer4
            // path byte-for-byte.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // Enlarge the send buffer so a wide burst (e.g. full-65535) does not
            // hit ENOBUFS part-way; any shortfall still degrades safely to the
            // retransmit round.
            let bufsz: libc::c_int = 4 * 1024 * 1024;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &bufsz as *const _ as *const libc::c_void,
                    mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
            Ok(Self { fd })
        }

        /// Send every segment in `segments` to `dst` in as few `sendmmsg(2)`
        /// calls as the 1024-message kernel cap allows. Returns the number the
        /// kernel accepted; any shortfall is left to the caller's retransmit
        /// round (unsent ports simply surface as no-reply).
        pub fn send_batch(&self, dst: Ipv4Addr, segments: &[Vec<u8>]) -> usize {
            if segments.is_empty() {
                return 0;
            }
            // Destination address: for an IPPROTO_TCP raw socket the port field
            // is ignored (the real dst port lives in the TCP header); only the
            // address is used, for routing.
            let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = 0;
            addr.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());
            let addr_ptr = &mut addr as *mut libc::sockaddr_in as *mut libc::c_void;
            let addr_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

            // One single-buffer iovec + mmsghdr per segment. `iovecs` and
            // `segments` must outlive the syscalls below — both are alive for
            // the whole function, and the raw pointers into them are only read
            // by the kernel during each `sendmmsg`.
            let mut iovecs: Vec<libc::iovec> = segments
                .iter()
                .map(|s| libc::iovec {
                    iov_base: s.as_ptr() as *mut libc::c_void,
                    iov_len: s.len(),
                })
                .collect();
            let mut msgs: Vec<libc::mmsghdr> = iovecs
                .iter_mut()
                .map(|iov| {
                    let mut m: libc::mmsghdr = unsafe { mem::zeroed() };
                    m.msg_hdr.msg_name = addr_ptr;
                    m.msg_hdr.msg_namelen = addr_len;
                    m.msg_hdr.msg_iov = iov as *mut libc::iovec;
                    m.msg_hdr.msg_iovlen = 1;
                    m
                })
                .collect();

            let mut sent = 0usize;
            while sent < msgs.len() {
                let chunk = (msgs.len() - sent).min(1024);
                let n = unsafe {
                    libc::sendmmsg(self.fd, msgs[sent..].as_mut_ptr(), chunk as libc::c_uint, 0)
                };
                if n <= 0 {
                    break; // error or nothing accepted → leave the rest to retransmit
                }
                sent += n as usize;
                if (n as usize) < chunk {
                    break; // partial (send-buffer pressure) → stop; retransmit covers it
                }
            }
            sent
        }
    }

    impl Drop for LinuxBatchSender {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

/// Map a raw reply to a port state for a given scan kind (shared by `probe`'s
/// inline match and the fast engine).
fn response_to_state(resp: Response, kind: RawTcpKind) -> PortState {
    match resp {
        Response::SynAck => PortState::Open,
        Response::Rst { window } => match kind {
            RawTcpKind::Syn | RawTcpKind::Fin | RawTcpKind::Null | RawTcpKind::Xmas => {
                PortState::Closed
            }
            RawTcpKind::Ack => PortState::Unfiltered,
            RawTcpKind::Window => {
                if window > 0 { PortState::Open } else { PortState::Closed }
            }
            RawTcpKind::Maimon => PortState::Closed,
        },
        Response::Other => PortState::Filtered,
    }
}

/// No-reply state for a scan kind (SYN/ACK/Window → filtered; FIN/NULL/Xmas/
/// Maimon → open|filtered — same as `probe()`'s timeout arm).
fn no_reply_state(kind: RawTcpKind) -> PortState {
    match kind {
        RawTcpKind::Syn | RawTcpKind::Ack | RawTcpKind::Window => PortState::Filtered,
        RawTcpKind::Fin | RawTcpKind::Null | RawTcpKind::Xmas | RawTcpKind::Maimon => {
            PortState::OpenFiltered
        }
    }
}

/// Shared ICMP reader: bumps `counter` on every destination-unreachable
/// (type 3). One per scanner, detached; exits when the channel drops.
fn icmp_receiver_loop(mut rx: TransportReceiver, counter: Arc<AtomicU64>) {
    let mut iter = icmp_packet_iter(&mut rx);
    while let Ok((packet, _addr)) = iter.next() {
        if packet.get_icmp_type() == IcmpTypes::DestinationUnreachable {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn receiver_loop(mut rx: TransportReceiver, pending: PendingMap) {
    let mut iter = tcp_packet_iter(&mut rx);
    while let Ok((packet, addr)) = iter.next() {
        TRACE_RX_COUNT.fetch_add(1, Ordering::Relaxed);
        let remote_ip = match addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => continue,
        };
        let remote_port = packet.get_source();
        let kind = classify(packet.get_flags(), packet.get_window());

        if TRACE_ENABLED.load(Ordering::Relaxed) {
            eprintln!(
                "[raw-rx] {}:{} flags=0x{:02x} kind={:?}",
                remote_ip,
                remote_port,
                packet.get_flags(),
                kind
            );
        }

        let sender_opt = {
            let pend = pending.lock();
            pend.get(&(remote_ip, remote_port)).and_then(|p| {
                // Correlate to the exact probe (review #1): the reply must be
                // addressed back to the local port we sent from, and a genuine
                // SYN-ACK must acknowledge our ISN+1. A packet that matches the
                // (ip, port) key but fails either check is cross-talk from
                // another local socket or an injected/stray packet, and is
                // dropped rather than mis-reported as open/closed. This is the
                // same check tcp_probe_suite / tcp_fp already apply.
                if packet.get_destination() != p.exp_src_port {
                    return None;
                }
                if matches!(kind, Response::SynAck) {
                    if let Some(exp) = p.exp_ack {
                        if packet.get_acknowledgement() != exp {
                            return None;
                        }
                    }
                }
                Some(p.sender.clone())
            })
        };
        if let Some(s) = sender_opt {
            let _ = s.send(kind);
        }
    }
}

fn classify(flags: u8, window: u16) -> Response {
    if flags & TcpFlags::RST != 0 {
        Response::Rst { window }
    } else if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
        Response::SynAck
    } else {
        Response::Other
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_raw_tcp_scan(
    target: Target,
    ports: Arc<Vec<u16>>,
    kind: RawTcpKind,
    scanner: Arc<RawTcpScanner>,
    timeout: Duration,
    parallel: usize,
    host_timeout: Duration,
    show_closed: bool,
) -> HostResult {
    let start = Instant::now();
    // --host-timeout ceiling (lab v0.95.0 B1): each worker stops at this
    // deadline; ports not yet probed are simply omitted. 0 = off.
    let host_deadline = if host_timeout.is_zero() {
        None
    } else {
        Some(start + host_timeout)
    };
    let dst = match target.ip {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => {
            return HostResult {
                target,
                up: false,
                ports: vec![],
                elapsed: start.elapsed(),
                os: None,
                device: None,
                mac: None,
            };
        }
    };

    let src = match source_ipv4_for(dst) {
        Ok(s) => s,
        Err(_) => {
            return HostResult {
                target,
                up: false,
                ports: vec![],
                elapsed: start.elapsed(),
                os: None,
                device: None,
                mac: None,
            };
        }
    };

    let chunk = (ports.len() + parallel - 1) / parallel.max(1);
    let mut handles = Vec::new();
    let ports_vec = ports.clone();
    for chunk_idx in 0..parallel {
        let s_scanner = Arc::clone(&scanner);
        let s_ports = Arc::clone(&ports_vec);
        let begin = chunk_idx * chunk;
        let end = ((chunk_idx + 1) * chunk).min(s_ports.len());
        if begin >= end {
            continue;
        }
        let h = thread::spawn(move || {
            let max_retries = crate::scanner::max_retries();
            let mut results = Vec::with_capacity(end - begin);
            for &p in &s_ports[begin..end] {
                // --host-timeout: stop this worker once the ceiling is hit.
                if let Some(dl) = host_deadline {
                    if Instant::now() >= dl {
                        break;
                    }
                }
                // Retransmit on no-response before concluding Filtered/
                // OpenFiltered — the way nmap does (--max-retries). A single
                // dropped SYN (or a dropped RST on a stealth scan) over a
                // lossy or rate-limited path should not be reported as
                // filtered; a definitive reply (SYN-ACK / RST → Open / Closed
                // / Unfiltered) is terminal and never retried. The connect
                // path already does this (scanner.rs); the raw path did not.
                let (mut st, mut rtt) = s_scanner.probe(src, dst, p, kind, timeout);
                let mut attempt = 0u8;
                while matches!(st, PortState::Filtered | PortState::OpenFiltered)
                    && attempt < max_retries
                {
                    attempt += 1;
                    let (s2, r2) = s_scanner.probe(src, dst, p, kind, timeout);
                    st = s2;
                    rtt = r2;
                }
                crate::scan_stats::global().record_result(st);
                results.push(PortResult {
                    port: p,
                    state: st,
                    // Real per-probe RTT (review #3); 0 when the port never
                    // replied (filtered/no-response), as before.
                    rtt: rtt.unwrap_or(Duration::ZERO),
                    service: None,
                });
            }
            results
        });
        handles.push(h);
    }

    let mut all: Vec<PortResult> = Vec::new();
    for h in handles {
        if let Ok(v) = h.join() {
            all.extend(v);
        }
    }
    all.sort_by_key(|p| p.port);

    // Host-up is decided from the FULL result set, independent of what we
    // display, so keeping closed ports for the nmap-style "Not shown: N closed"
    // summary (lab bug N10) can't change host-up. Semantics are unchanged:
    //   SYN     → up iff ≥1 open port;
    //   stealth → up iff we probed something AND got any non-filtered reply
    //             (a RST counts — "responded" = up).
    let has_open = all.iter().any(|p| {
        matches!(p.state, PortState::Open | PortState::OpenFiltered | PortState::Unfiltered)
    });
    let any_response = all.iter().any(|p| !matches!(p.state, PortState::Filtered));
    let up = match kind {
        RawTcpKind::Syn => has_open,
        _ => !all.is_empty() && any_response,
    };

    // SYN scan is dense — plain-filtered stays hidden, but Closed are kept so
    // the report can summarise them ("Not shown: N closed"), unless --only-open
    // (show_closed=false). Stealth scans keep ALL states by default because the
    // Closed-vs-Filtered distinction is the whole point. Bug-04 / Bug-05 / N10.
    let interesting: Vec<PortResult> = all
        .into_iter()
        .filter(|p| match p.state {
            PortState::Open | PortState::OpenFiltered | PortState::Unfiltered => true,
            PortState::Filtered => !matches!(kind, RawTcpKind::Syn),
            PortState::Closed => show_closed,
        })
        .collect();

    HostResult {
        up,
        target,
        ports: interesting,
        elapsed: start.elapsed(),
        os: None,
        device: None,
        mac: None,
    }
}

/// `--fast-engine` raw TCP scan (Fase 30): an nsock/ultra_scan-style path that
/// decouples send from receive. Instead of `--max-parallel` OS threads each
/// doing a synchronous send→block→next (`run_raw_tcp_scan`), a single sender
/// bursts all probes, the existing receiver thread demuxes replies
/// asynchronously, and we poll-collect them within a window — then retransmit
/// the unanswered ports in waves (bounded by --max-retries). Same packets,
/// same state logic, far fewer threads.
///
/// v0.88.0 is the cross-platform restructure. The Linux `sendmmsg` batched
/// burst (collapsing N send syscalls into ~N/50) is the v0.88.1 step, to be
/// built + benchmarked on Kali. Opt-in until it beats the default path in lab.
#[allow(clippy::too_many_arguments)]
pub fn run_raw_tcp_fast(
    target: Target,
    ports: Arc<Vec<u16>>,
    kind: RawTcpKind,
    scanner: Arc<RawTcpScanner>,
    timeout: Duration,
    max_window: usize,
    min_rate: u32,
    host_timeout: Duration,
    show_closed: bool,
) -> HostResult {
    let start = Instant::now();
    // --host-timeout ceiling: a cooperative deadline checked at wave/round
    // boundaries so a fully-filtered full-port scan can't run for hours
    // (lab v0.95.0 B1). 0 = off.
    let host_deadline = if host_timeout.is_zero() {
        None
    } else {
        Some(start + host_timeout)
    };
    let dst = match target.ip {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => {
            return HostResult { target, up: false, ports: vec![], elapsed: start.elapsed(), os: None, device: None, mac: None };
        }
    };
    let src = match source_ipv4_for(dst) {
        Ok(s) => s,
        Err(_) => {
            return HostResult { target, up: false, ports: vec![], elapsed: start.elapsed(), os: None, device: None, mac: None };
        }
    };
    let max_retries = crate::scanner::max_retries();

    // Definitive states only (Open/Closed/Unfiltered); "Other" and no-reply are
    // left out so they get retransmitted, then mapped at finalize.
    let mut state: HashMap<u16, PortState> = HashMap::new();
    // Per-port measured RTT (review #3): the wave-relative time its reply was
    // collected, so finalize reports a real latency instead of a hardcoded 0.
    let mut rtts: HashMap<u16, Duration> = HashMap::new();
    let mut todo: Vec<u16> = ports.iter().copied().collect();

    // Fase 31 congestion control: bound how many probes are in flight at once
    // with a cwnd-style window (AIMD) instead of bursting every port. A
    // full-65535 burst used to outrun the single receiver / trip host RST
    // rate-limiting, dropping replies and spiking variance (v0.88.3 lab run).
    // The window ramps in slow-start, backs off when a *responding* host starts
    // dropping (so lost opens are recovered on the next gentler wave).
    // `--max-parallel` caps the window, `--min-rate` raises its floor. The
    // `--max-rate` packets/sec ceiling is now enforced *globally* by
    // `scanner.global_rate` inside the send path (review #2), not by a per-host
    // pacer here — so concurrent hosts share one aggregate cap.
    let cw_max = max_window.max(1);
    let cw_min = if min_rate > 0 {
        ((min_rate as usize) / 100).clamp(16.min(cw_max), cw_max)
    } else {
        16.min(cw_max)
    };
    let cw_init = (cw_max / 8).clamp(cw_min, cw_max);
    let mut cwnd = crate::rate::CongestionWindow::new(cw_init, cw_min, cw_max);
    // Silence-shrink (lab v0.95.0 B1): give the host a full `--timeout` on the
    // first wave to learn its RTT, but once it has answered *nothing* we stop
    // burning the full timeout on every subsequent wave — a filtered port stays
    // filtered whether we wait 150 ms or 1.5 s, so a silent full-port host
    // finishes in ~seconds instead of hours. The moment any reply arrives we
    // switch to the normal RTT-adaptive window.
    let mut host_replied = false;
    let mut waves_done = 0usize;

    // Fase 30 (Linux): when evasion is passive, swap the per-probe send loop
    // for a single `sendmmsg(2)` burst per wave (N sends → ~N/1024 syscalls) —
    // the real throughput lever. Built once per host, reused across waves/rounds.
    // Any other platform, or active evasion, keeps the per-probe path below.
    #[cfg(target_os = "linux")]
    let batch: Option<linux_batch::LinuxBatchSender> = if scanner.batch_eligible() {
        linux_batch::LinuxBatchSender::new().ok()
    } else {
        None
    };

    'rounds: for _ in 0..=max_retries {
        if todo.is_empty() {
            break;
        }
        // Send this round's ports in congestion-window-sized waves.
        let round_ports = todo.clone();
        let mut idx = 0usize;
        while idx < round_ports.len() {
            // --host-timeout: stop this host cleanly; unresolved ports are
            // finalized as no-reply (filtered) below.
            if let Some(dl) = host_deadline {
                if Instant::now() >= dl {
                    break 'rounds;
                }
            }
            let wsize = cwnd.window().max(1);
            let end = (idx + wsize).min(round_ports.len());
            let wave = &round_ports[idx..end];
            idx = end;

            // --max-rate is paced globally inside the send path now (review #2),
            // so there is no per-host wave pacer here.

            // ── burst the wave without waiting ──
            let burst_start = Instant::now();
            let icmp_before = scanner.icmp_unreach();
            #[cfg(target_os = "linux")]
            let mut pend: Vec<(u16, mpsc::Receiver<Response>)> = match batch {
                Some(ref b) => scanner.send_probe_batch(b, src, dst, wave, kind),
                None => {
                    let mut v = Vec::with_capacity(wave.len());
                    for &p in wave {
                        v.push((p, scanner.send_probe(src, dst, p, kind)));
                    }
                    v
                }
            };
            #[cfg(not(target_os = "linux"))]
            let mut pend: Vec<(u16, mpsc::Receiver<Response>)> = {
                let mut v = Vec::with_capacity(wave.len());
                for &p in wave {
                    v.push((p, scanner.send_probe(src, dst, p, kind)));
                }
                v
            };

            // ── collect: poll the channels until an ADAPTIVE window elapses ──
            // The window shrinks toward ~10×RTT once a few replies have been
            // seen (shared across hosts via the scanner's RTT EWMA). The loop
            // breaks early once every pending port has replied; a dropped/
            // filtered port never replies, so the adaptive window keeps a
            // firewalled wave from burning the full `--timeout`.
            let floor = crate::rate::timeout_floor(timeout);
            let eff = if host_replied {
                // Host answers → shrink toward ~10×RTT (+ rttvar headroom, #12).
                crate::rate::adaptive_timeout(timeout, scanner.mean_rtt(), scanner.rtt_var(), floor)
            } else if waves_done == 0 {
                // First wave: full timeout, a fair chance to reveal the RTT.
                timeout
            } else {
                // Host has answered nothing so far → don't burn the full timeout
                // on every wave; a filtered port won't become open by waiting.
                floor
            };
            waves_done += 1;
            let deadline = Instant::now() + eff;
            let mut rtt_recorded = false;
            let mut replies = 0usize;
            while Instant::now() < deadline && !pend.is_empty() {
                let mut still: Vec<(u16, mpsc::Receiver<Response>)> = Vec::with_capacity(pend.len());
                for (p, rx) in pend.into_iter() {
                    match rx.try_recv() {
                        Ok(resp) => {
                            scanner.clear_pending(dst, p);
                            replies += 1;
                            let elapsed = burst_start.elapsed();
                            // First reply ≈ host RTT for the wave → feed the EWMA.
                            if !rtt_recorded {
                                scanner.record_rtt(elapsed);
                                rtt_recorded = true;
                            }
                            let st = response_to_state(resp, kind);
                            // Only SYN-ACK / RST are terminal; "Other" → retransmit.
                            if matches!(st, PortState::Open | PortState::Closed | PortState::Unfiltered) {
                                state.insert(p, st);
                                // Per-port RTT for the reported latency (#3).
                                rtts.insert(p, elapsed);
                            }
                        }
                        Err(mpsc::TryRecvError::Empty) => still.push((p, rx)),
                        Err(mpsc::TryRecvError::Disconnected) => scanner.clear_pending(dst, p),
                    }
                }
                pend = still;
                if pend.is_empty() {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            for (p, _rx) in pend {
                scanner.clear_pending(dst, p);
            }

            // Feed the wave outcome to the congestion window: a high drop ratio
            // on a host that is answering → back off; a clean wave → grow.
            cwnd.feed(wave.len(), replies);
            // ICMP destination-unreachable arriving during this wave is a
            // direct rate-limit signal (admin-prohibited / frag / port-unreach)
            // → force a cwnd back-off regardless of the drop ratio (Fase 31
            // ICMP signal, #4). No-op if the ICMP listener isn't available.
            let icmp_after = scanner.icmp_unreach();
            if icmp_after > icmp_before {
                cwnd.force_backoff();
                if TRACE_ENABLED.load(Ordering::Relaxed) {
                    eprintln!(
                        "[raw-icmp] {} ICMP dest-unreachable (type 3) during wave \
                         → cwnd back-off to {}",
                        icmp_after - icmp_before,
                        cwnd.window()
                    );
                }
            }
            if replies > 0 {
                host_replied = true;
            }
        }
        todo = ports.iter().copied().filter(|p| !state.contains_key(p)).collect();
    }

    let mut all: Vec<PortResult> = ports
        .iter()
        .map(|&p| {
            let st = state.get(&p).copied().unwrap_or_else(|| no_reply_state(kind));
            crate::scan_stats::global().record_result(st);
            let rtt = rtts.get(&p).copied().unwrap_or(Duration::ZERO);
            PortResult { port: p, state: st, rtt, service: None }
        })
        .collect();
    all.sort_by_key(|p| p.port);

    // See run_raw_tcp_scan: host-up from the full set (unchanged semantics),
    // Closed kept for the "Not shown" summary unless --only-open (N10).
    let has_open = all.iter().any(|p| {
        matches!(p.state, PortState::Open | PortState::OpenFiltered | PortState::Unfiltered)
    });
    let any_response = all.iter().any(|p| !matches!(p.state, PortState::Filtered));
    let up = match kind {
        RawTcpKind::Syn => has_open,
        _ => !all.is_empty() && any_response,
    };
    let interesting: Vec<PortResult> = all
        .into_iter()
        .filter(|p| match p.state {
            PortState::Open | PortState::OpenFiltered | PortState::Unfiltered => true,
            PortState::Filtered => !matches!(kind, RawTcpKind::Syn),
            PortState::Closed => show_closed,
        })
        .collect();

    HostResult {
        up,
        target,
        ports: interesting,
        elapsed: start.elapsed(),
        os: None,
        device: None,
        mac: None,
    }
}
