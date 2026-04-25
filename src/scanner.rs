use crate::rate::AdaptiveLimiter;
use crate::target::Target;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Global retry budget for the connect-scan path. Set by main from --max-retries.
static MAX_RETRIES: AtomicU8 = AtomicU8::new(0);

pub fn set_max_retries(n: u8) {
    MAX_RETRIES.store(n, Ordering::Relaxed);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    Unfiltered,
}

impl PortState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
            PortState::Unfiltered => "unfiltered",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    #[serde(skip)]
    #[allow(dead_code)]
    pub rtt: Duration,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub service: Option<crate::service_probe::ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub target: Target,
    pub up: bool,
    pub ports: Vec<PortResult>,
    #[serde(skip)]
    pub elapsed: Duration,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os: Option<crate::os_fp::OsGuess>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub device: Option<crate::device_fp::DeviceGuess>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mac: Option<[u8; 6]>,
}

#[allow(clippy::too_many_arguments)]
pub async fn tcp_connect_scan(
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
                    return PortResult { port, state: PortState::Filtered, rtt: Duration::from_millis(0), service: None };
                }
                let addr = SocketAddr::new(ip, port);
                let t0 = Instant::now();
                let res = timeout(timeout_dur, TcpStream::connect(addr)).await;
                let rtt = t0.elapsed();
                let (state, timed_out) = match res {
                    Ok(Ok(_s)) => (PortState::Open, false),
                    Ok(Err(e)) => (match e.kind() {
                        std::io::ErrorKind::ConnectionRefused => PortState::Closed,
                        _ => PortState::Filtered,
                    }, false),
                    Err(_) => (PortState::Filtered, true),
                };
                lim_task.record(timed_out, rtt);
                PortResult { port, state, rtt, service: None }
            }));
        }
        let mut out = Vec::with_capacity(handles.len());
        for h in handles {
            if let Ok(r) = h.await { out.push(r); }
        }
        out
    } else {
        stream::iter(ports.iter().copied())
            .map(|port| {
                let cancel = Arc::clone(&cancel);
                async move {
                if !scan_delay.is_zero() { tokio::time::sleep(scan_delay).await; }
                if cancel.load(Ordering::Relaxed) {
                    return PortResult { port, state: PortState::Filtered, rtt: Duration::from_millis(0), service: None };
                }
                let addr = SocketAddr::new(ip, port);
                let t0 = Instant::now();
                // Retry only on Filtered (timeout) up to MAX_RETRIES — closed
                // and open are terminal. Total attempts = 1 + MAX_RETRIES.
                let max_retries = MAX_RETRIES.load(Ordering::Relaxed);
                let mut attempt = 0u8;
                let mut state;
                loop {
                    let res = timeout(timeout_dur, TcpStream::connect(addr)).await;
                    state = match res {
                        Ok(Ok(_stream)) => PortState::Open,
                        Ok(Err(e)) => {
                            match e.kind() {
                                std::io::ErrorKind::ConnectionRefused => PortState::Closed,
                                _ => PortState::Filtered,
                            }
                        }
                        Err(_) => PortState::Filtered,
                    };
                    if state != PortState::Filtered || attempt >= max_retries {
                        break;
                    }
                    attempt += 1;
                }
                let rtt = t0.elapsed();
                PortResult { port, state, rtt, service: None }
                }
            })
            .buffer_unordered(parallel)
            .collect()
            .await
    };

    let mut ports_out: Vec<PortResult> = if show_closed {
        results
    } else {
        results.into_iter().filter(|r| r.state == PortState::Open).collect()
    };
    ports_out.sort_by_key(|r| r.port);

    HostResult {
        up: !ports_out.is_empty() || show_closed,
        target,
        ports: ports_out,
        elapsed: start.elapsed(),
        os: None,
        device: None,
        mac: None,
    }
}
