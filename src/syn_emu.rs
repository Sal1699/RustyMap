//! Driver-less SYN-style scan.
//!
//! Real `--sS` requires raw sockets (root on Unix, Npcap on Windows). When
//! that path is not available, this module provides a close approximation:
//! a TCP socket with SO_LINGER=0 so that closing it sends RST instead of
//! the FIN/ACK teardown. The kernel still completes the handshake, so this
//! is **not** truly stealth — but it needs no driver and stays out of the
//! application layer (no read/write past the handshake).

use crate::rate::AdaptiveLimiter;
use crate::scanner::{HostResult, PortResult, PortState};
use crate::target::Target;
use futures::stream::{self, StreamExt};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpSocket;
use tokio::time::timeout;

fn make_socket(ip: IpAddr) -> std::io::Result<TcpSocket> {
    let domain = match ip {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let s = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    // SO_LINGER=0 → kernel emits RST on close instead of FIN/ACK teardown.
    // Avoids piling sockets into TIME_WAIT during fast scans.
    s.set_linger(Some(Duration::ZERO))?;
    s.set_nonblocking(true)?;

    #[cfg(unix)]
    let tokio_sock = {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        let raw = s.into_raw_fd();
        // SAFETY: we hand off ownership of the fd to tokio.
        unsafe { TcpSocket::from_raw_fd(raw) }
    };
    #[cfg(windows)]
    let tokio_sock = {
        use std::os::windows::io::{FromRawSocket, IntoRawSocket};
        let raw = s.into_raw_socket();
        // SAFETY: we hand off ownership of the socket to tokio.
        unsafe { TcpSocket::from_raw_socket(raw) }
    };
    Ok(tokio_sock)
}

async fn probe_one(ip: IpAddr, port: u16, t: Duration) -> (PortState, Duration, bool) {
    let sock = match make_socket(ip) {
        Ok(s) => s,
        Err(_) => return (PortState::Filtered, Duration::ZERO, false),
    };

    let addr = SocketAddr::new(ip, port);
    let t0 = Instant::now();
    let res = timeout(t, sock.connect(addr)).await;
    let rtt = t0.elapsed();

    match res {
        Ok(Ok(stream)) => {
            // Drop with SO_LINGER=0 → kernel emits RST. Closer to a real SYN
            // scan teardown than the default FIN/ACK exchange.
            drop(stream);
            (PortState::Open, rtt, false)
        }
        Ok(Err(e)) => {
            let st = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => PortState::Closed,
                _ => PortState::Filtered,
            };
            (st, rtt, false)
        }
        Err(_) => (PortState::Filtered, rtt, true),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_syn_emulated(
    target: Target,
    ports: Arc<Vec<u16>>,
    timeout_dur: Duration,
    parallel: usize,
    show_closed: bool,
    cancel: Arc<AtomicBool>,
    limiter: Option<Arc<AdaptiveLimiter>>,
    scan_delay: Duration,
) -> HostResult {
    let start = Instant::now();
    let ip = target.ip;

    let results: Vec<PortResult> = if let Some(lim) = limiter.as_ref() {
        let sem = lim.semaphore();
        let mut handles = Vec::with_capacity(ports.len());
        for port in ports.iter().copied() {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            if !scan_delay.is_zero() {
                tokio::time::sleep(scan_delay).await;
            }
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let cancel_task = Arc::clone(&cancel);
            let lim_task = Arc::clone(lim);
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                if cancel_task.load(Ordering::Relaxed) {
                    return PortResult {
                        port,
                        state: PortState::Filtered,
                        rtt: Duration::ZERO,
                        service: None,
                    };
                }
                let (state, rtt, timed_out) = probe_one(ip, port, timeout_dur).await;
                lim_task.record(timed_out, rtt);
                PortResult { port, state, rtt, service: None }
            }));
        }
        let mut out = Vec::with_capacity(handles.len());
        for h in handles {
            if let Ok(r) = h.await {
                out.push(r);
            }
        }
        out
    } else {
        stream::iter(ports.iter().copied())
            .map(|port| {
                let cancel = Arc::clone(&cancel);
                async move {
                    if !scan_delay.is_zero() {
                        tokio::time::sleep(scan_delay).await;
                    }
                    if cancel.load(Ordering::Relaxed) {
                        return PortResult {
                            port,
                            state: PortState::Filtered,
                            rtt: Duration::ZERO,
                            service: None,
                        };
                    }
                    let (state, rtt, _) = probe_one(ip, port, timeout_dur).await;
                    PortResult { port, state, rtt, service: None }
                }
            })
            .buffer_unordered(parallel)
            .collect()
            .await
    };

    let mut sorted = results;
    sorted.sort_by_key(|r| r.port);
    let kept: Vec<PortResult> = sorted
        .into_iter()
        .filter(|p| show_closed || p.state == PortState::Open)
        .collect();

    HostResult {
        up: kept.iter().any(|p| p.state == PortState::Open),
        target,
        ports: kept,
        elapsed: start.elapsed(),
        os: None,
        device: None,
        mac: None,
    }
}
