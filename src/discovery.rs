use crate::target::Target;
use futures::stream::{self, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Phase 1 host discovery: TCP ping on common ports.
/// Proper ICMP echo requires raw sockets and is deferred to Phase 2.
/// We probe a handful of high-value ports and mark host up if any responds
/// (either open or closed — both prove the host is alive).
const PROBE_PORTS: &[u16] = &[80, 443, 22, 445, 3389, 21, 25, 53, 139, 8080];

pub async fn tcp_ping(target: &Target, timeout_dur: Duration) -> bool {
    let ip = target.ip;
    let probes = stream::iter(PROBE_PORTS.iter().copied())
        .map(|port| async move {
            let addr = SocketAddr::new(ip, port);
            match timeout(timeout_dur, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => true, // open
                Ok(Err(e)) => matches!(e.kind(), std::io::ErrorKind::ConnectionRefused),
                Err(_) => false,
            }
        })
        .buffer_unordered(PROBE_PORTS.len());

    let results: Vec<bool> = probes.collect().await;
    results.into_iter().any(|up| up)
}

pub async fn discover_hosts(
    targets: Vec<Target>,
    timeout_dur: Duration,
    parallel: usize,
) -> Vec<Target> {
    stream::iter(targets)
        .map(|t| async move {
            let up = tcp_ping(&t, timeout_dur).await;
            (t, up)
        })
        .buffer_unordered(parallel)
        .filter_map(|(t, up)| async move { if up { Some(t) } else { None } })
        .collect()
        .await
}
