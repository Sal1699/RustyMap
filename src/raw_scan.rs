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
        })
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
            match receiver.recv_timeout(timeout) {
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
            let mut results = Vec::with_capacity(end - begin);
            for &p in &s_ports[begin..end] {
                let st = s_scanner.probe(src, dst, p, kind, timeout);
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

    let interesting: Vec<PortResult> = all
        .into_iter()
        .filter(|p| {
            matches!(
                p.state,
                PortState::Open | PortState::OpenFiltered | PortState::Unfiltered
            )
        })
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
