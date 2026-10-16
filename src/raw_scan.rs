use crate::evasion::{self, EvasionConfig};
use crate::net_util::source_ipv4_for;
use crate::scanner::{HostResult, PortResult, PortState};
use crate::target::Target;
use anyhow::{anyhow, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::transport::{
    tcp_packet_iter, transport_channel,
    TransportChannelType::{Layer3, Layer4},
    TransportProtocol::Ipv4,
    TransportReceiver, TransportSender,
};
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
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

// Key: (remote_ip, remote_port) — works with both random and fixed source ports.
type PendingMap = Arc<Mutex<HashMap<(Ipv4Addr, u16), mpsc::Sender<Response>>>>;

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
    rtt_samples: std::sync::atomic::AtomicU64,
}

impl RawTcpScanner {
    pub fn new(evasion: EvasionConfig) -> Result<Self> {
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

        Ok(Self {
            tx4: Arc::new(Mutex::new(tx4)),
            tx3,
            pending,
            evasion,
            _rx_thread: rx_thread,
            ewma_rtt_us: std::sync::atomic::AtomicU64::new(0),
            rtt_samples: std::sync::atomic::AtomicU64::new(0),
        })
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

    fn record_rtt(&self, rtt: Duration) {
        let sample = rtt.as_micros().min(u64::MAX as u128) as u64;
        let prev = self.ewma_rtt_us.load(Ordering::Relaxed);
        let next = if prev == 0 { sample } else { (prev * 3 + sample) / 4 };
        self.ewma_rtt_us.store(next, Ordering::Relaxed);
        self.rtt_samples.fetch_add(1, Ordering::Relaxed);
    }

    pub fn probe(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        kind: RawTcpKind,
        timeout: Duration,
    ) -> PortState {
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

        let (sender, receiver) = mpsc::channel::<Response>();
        {
            self.pending
                .lock()
                .unwrap()
                .insert((dst_ip, dst_port), sender);
        }

        let send_ok = if ev.needs_layer3() {
            // Layer3 path — full IP control (TTL, fragmentation, decoys)
            if let Some(ref tx3) = self.tx3 {
                let mut tx = tx3.lock().unwrap();
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
                rng.gen(),
                src_port,
                &ev,
            );
            let mut tx = self.tx4.lock().unwrap();
            let pkt = TcpPacket::new(&tcp).unwrap();
            tx.send_to(pkt, IpAddr::V4(dst_ip)).is_ok()
        };

        if TRACE_ENABLED.load(Ordering::Relaxed) {
            eprintln!(
                "[raw-tx] {}:{} flags=0x{:02x} src_port={} send_ok={}",
                dst_ip, dst_port, flags, src_port, send_ok
            );
        }

        let state = if !send_ok {
            PortState::Filtered
        } else {
            // Shrink the recv wait toward the observed RTT once we have a few
            // samples; early probes keep the full `timeout`. This is what
            // collapses the small-scan slow-ramp vs nmap (a filtered port no
            // longer blocks the whole base timeout on a fast LAN).
            let eff = crate::rate::adaptive_timeout(
                timeout,
                self.mean_rtt(),
                crate::rate::timeout_floor(timeout),
            );
            let t0 = Instant::now();
            let recvd = receiver.recv_timeout(eff);
            if recvd.is_ok() {
                self.record_rtt(t0.elapsed());
            }
            match recvd {
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
            }
        };

        self.pending
            .lock()
            .unwrap()
            .remove(&(dst_ip, dst_port));
        state
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

        let (sender, receiver) = mpsc::channel::<Response>();
        {
            self.pending
                .lock()
                .unwrap()
                .insert((dst_ip, dst_port), sender);
        }

        let send_ok = if ev.needs_layer3() {
            if let Some(ref tx3) = self.tx3 {
                let mut tx = tx3.lock().unwrap();
                evasion::send_with_decoys(&mut tx, src_ip, dst_ip, dst_port, flags, src_port, &ev)
            } else {
                false
            }
        } else {
            let tcp = evasion::build_tcp_segment(src_ip, dst_ip, dst_port, flags, rng.gen(), src_port, &ev);
            let mut tx = self.tx4.lock().unwrap();
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
        self.pending.lock().unwrap().remove(&(dst_ip, dst_port));
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
            let seg = evasion::build_tcp_segment(src_ip, dst_ip, p, flags, rng.gen(), src_port, &ev);
            let (sender, receiver) = mpsc::channel::<Response>();
            self.pending.lock().unwrap().insert((dst_ip, p), sender);
            segs.push(seg);
            pairs.push((p, receiver));
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
            let pend = pending.lock().unwrap();
            pend.get(&(remote_ip, remote_port)).cloned()
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

pub fn run_raw_tcp_scan(
    target: Target,
    ports: Arc<Vec<u16>>,
    kind: RawTcpKind,
    scanner: Arc<RawTcpScanner>,
    timeout: Duration,
    parallel: usize,
) -> HostResult {
    let start = Instant::now();
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
                // Retransmit on no-response before concluding Filtered/
                // OpenFiltered — the way nmap does (--max-retries). A single
                // dropped SYN (or a dropped RST on a stealth scan) over a
                // lossy or rate-limited path should not be reported as
                // filtered; a definitive reply (SYN-ACK / RST → Open / Closed
                // / Unfiltered) is terminal and never retried. The connect
                // path already does this (scanner.rs); the raw path did not.
                let mut st = s_scanner.probe(src, dst, p, kind, timeout);
                let mut attempt = 0u8;
                while matches!(st, PortState::Filtered | PortState::OpenFiltered)
                    && attempt < max_retries
                {
                    attempt += 1;
                    st = s_scanner.probe(src, dst, p, kind, timeout);
                }
                crate::scan_stats::global().record_result(st);
                results.push(PortResult {
                    port: p,
                    state: st,
                    rtt: Duration::from_millis(0),
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

    // SYN scan is dense — drop Closed to avoid output spam.
    // Stealth scans (FIN/NULL/Xmas/ACK/Window/Maimon) keep ALL states
    // because the *distinction* between Closed (got RST) and Filtered
    // (no reply) is the whole point of those scans. Bug-04 / Bug-05.
    let drop_closed = matches!(kind, RawTcpKind::Syn);
    let interesting: Vec<PortResult> = all
        .into_iter()
        .filter(|p| match p.state {
            PortState::Open | PortState::OpenFiltered | PortState::Unfiltered => true,
            PortState::Filtered => !matches!(kind, RawTcpKind::Syn),
            PortState::Closed => !drop_closed,
        })
        .collect();
    let any_response = interesting
        .iter()
        .any(|p| !matches!(p.state, PortState::Filtered));

    HostResult {
        // For stealth scans, "host is up" includes "responded with RST"
        // (we got something back). Otherwise fall back to the old
        // "any interesting state" heuristic.
        up: !interesting.is_empty() && (matches!(kind, RawTcpKind::Syn) || any_response),
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
    max_rate: u32,
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
        Err(_) => {
            return HostResult { target, up: false, ports: vec![], elapsed: start.elapsed(), os: None, device: None, mac: None };
        }
    };
    let max_retries = crate::scanner::max_retries();

    // Definitive states only (Open/Closed/Unfiltered); "Other" and no-reply are
    // left out so they get retransmitted, then mapped at finalize.
    let mut state: HashMap<u16, PortState> = HashMap::new();
    let mut todo: Vec<u16> = ports.iter().copied().collect();

    // Fase 31 congestion control: bound how many probes are in flight at once
    // with a cwnd-style window (AIMD) instead of bursting every port. A
    // full-65535 burst used to outrun the single receiver / trip host RST
    // rate-limiting, dropping replies and spiking variance (v0.88.3 lab run).
    // The window ramps in slow-start, backs off when a *responding* host starts
    // dropping (so lost opens are recovered on the next gentler wave), and a
    // `--max-rate` pacer caps packets/sec. `--max-parallel` caps the window,
    // `--min-rate` raises its floor.
    let cw_max = max_window.max(1);
    let cw_min = if min_rate > 0 {
        ((min_rate as usize) / 100).clamp(16.min(cw_max), cw_max)
    } else {
        16.min(cw_max)
    };
    let cw_init = (cw_max / 8).clamp(cw_min, cw_max);
    let mut cwnd = crate::rate::CongestionWindow::new(cw_init, cw_min, cw_max);
    let mut pacer = crate::rate::RatePacer::new(max_rate);

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

    for _ in 0..=max_retries {
        if todo.is_empty() {
            break;
        }
        // Send this round's ports in congestion-window-sized waves.
        let round_ports = todo.clone();
        let mut idx = 0usize;
        while idx < round_ports.len() {
            let wsize = cwnd.window().max(1);
            let end = (idx + wsize).min(round_ports.len());
            let wave = &round_ports[idx..end];
            idx = end;

            // Honour --max-rate before putting this wave on the wire.
            pacer.pace(wave.len());

            // ── burst the wave without waiting ──
            let burst_start = Instant::now();
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
            let eff = crate::rate::adaptive_timeout(
                timeout,
                scanner.mean_rtt(),
                crate::rate::timeout_floor(timeout),
            );
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
                            // First reply ≈ host RTT for the wave → feed the EWMA.
                            if !rtt_recorded {
                                scanner.record_rtt(burst_start.elapsed());
                                rtt_recorded = true;
                            }
                            let st = response_to_state(resp, kind);
                            // Only SYN-ACK / RST are terminal; "Other" → retransmit.
                            if matches!(st, PortState::Open | PortState::Closed | PortState::Unfiltered) {
                                state.insert(p, st);
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
        }
        todo = ports.iter().copied().filter(|p| !state.contains_key(p)).collect();
    }

    let mut all: Vec<PortResult> = ports
        .iter()
        .map(|&p| {
            let st = state.get(&p).copied().unwrap_or_else(|| no_reply_state(kind));
            crate::scan_stats::global().record_result(st);
            PortResult { port: p, state: st, rtt: Duration::from_millis(0), service: None }
        })
        .collect();
    all.sort_by_key(|p| p.port);

    let drop_closed = matches!(kind, RawTcpKind::Syn);
    let interesting: Vec<PortResult> = all
        .into_iter()
        .filter(|p| match p.state {
            PortState::Open | PortState::OpenFiltered | PortState::Unfiltered => true,
            PortState::Filtered => !matches!(kind, RawTcpKind::Syn),
            PortState::Closed => !drop_closed,
        })
        .collect();
    let any_response = interesting.iter().any(|p| !matches!(p.state, PortState::Filtered));

    HostResult {
        up: !interesting.is_empty() && (matches!(kind, RawTcpKind::Syn) || any_response),
        target,
        ports: interesting,
        elapsed: start.elapsed(),
        os: None,
        device: None,
        mac: None,
    }
}
