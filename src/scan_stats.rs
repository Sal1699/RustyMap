//! Runtime scan statistics — `--scan-stats`.
//!
//! Periodically prints a compact line of throughput / latency
//! numbers so the user can answer "is this scan stuck, or am I
//! just impatient?". Counters are kept as atomics so the scanner
//! threads update them lock-free; the reporter thread reads
//! them at a fixed cadence (default 5 seconds).
//!
//! Fields tracked:
//!
//!   - **probes_sent / probes_replied**: cumulative since scan start.
//!   - **probes_per_sec**: instantaneous rate over the last interval.
//!   - **rtt_avg_ms**: running average of replied-probe RTT.
//!   - **open_ports** / **filtered_ports**: classification counters.
//!   - **peak_parallel**: max simultaneous in-flight probes seen.
//!   - **memory_kb**: approximate RSS (Linux only via /proc/self/statm,
//!     0 elsewhere — we don't pull a heavy crate just for this).
//!
//! Output one line per interval:
//!
//!   `[stats] t=15s sent=12450 replied=11308 (rate 829/s) open=42 filt=1100 \
//!     rtt=24.6ms peak=192 mem=43MB`

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct ScanStats {
    pub probes_sent: AtomicU64,
    pub probes_replied: AtomicU64,
    pub open_ports: AtomicU64,
    pub filtered_ports: AtomicU64,
    pub rtt_sum_us: AtomicU64,
    pub rtt_count: AtomicU64,
    pub peak_parallel: AtomicUsize,
    pub current_parallel: AtomicUsize,
}

#[allow(dead_code)]
impl ScanStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_probe_sent(&self) {
        self.probes_sent.fetch_add(1, Ordering::Relaxed);
        let now = self.current_parallel.fetch_add(1, Ordering::Relaxed) + 1;
        // Update peak via compare-and-exchange loop (cheap on contention).
        let mut peak = self.peak_parallel.load(Ordering::Relaxed);
        while now > peak {
            match self.peak_parallel.compare_exchange_weak(
                peak, now, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }
    }

    pub fn record_probe_done(&self, replied: bool, rtt: Option<Duration>) {
        self.current_parallel.fetch_sub(1, Ordering::Relaxed);
        if replied {
            self.probes_replied.fetch_add(1, Ordering::Relaxed);
            if let Some(r) = rtt {
                self.rtt_sum_us.fetch_add(r.as_micros() as u64, Ordering::Relaxed);
                self.rtt_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_open(&self) { self.open_ports.fetch_add(1, Ordering::Relaxed); }
    pub fn record_filtered(&self) { self.filtered_ports.fetch_add(1, Ordering::Relaxed); }

    pub fn snapshot(&self, since_start: Duration) -> StatsSnapshot {
        let sent = self.probes_sent.load(Ordering::Relaxed);
        let replied = self.probes_replied.load(Ordering::Relaxed);
        let open = self.open_ports.load(Ordering::Relaxed);
        let filtered = self.filtered_ports.load(Ordering::Relaxed);
        let rtt_sum = self.rtt_sum_us.load(Ordering::Relaxed);
        let rtt_cnt = self.rtt_count.load(Ordering::Relaxed);
        let peak = self.peak_parallel.load(Ordering::Relaxed);
        let rate = if since_start.as_secs() > 0 {
            sent as f64 / since_start.as_secs_f64()
        } else {
            0.0
        };
        let rtt_avg_ms = if rtt_cnt > 0 {
            (rtt_sum as f64 / rtt_cnt as f64) / 1000.0
        } else {
            0.0
        };
        StatsSnapshot {
            elapsed: since_start,
            probes_sent: sent,
            probes_replied: replied,
            probes_per_sec: rate,
            open_ports: open,
            filtered_ports: filtered,
            rtt_avg_ms,
            peak_parallel: peak,
            memory_kb: read_rss_kb(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSnapshot {
    pub elapsed: Duration,
    pub probes_sent: u64,
    pub probes_replied: u64,
    pub probes_per_sec: f64,
    pub open_ports: u64,
    pub filtered_ports: u64,
    pub rtt_avg_ms: f64,
    pub peak_parallel: usize,
    pub memory_kb: u64,
}

impl StatsSnapshot {
    pub fn format_line(&self) -> String {
        let mem = if self.memory_kb > 0 {
            format!(" mem={}MB", self.memory_kb / 1024)
        } else {
            String::new()
        };
        format!(
            "[stats] t={}s sent={} replied={} (rate {:.0}/s) open={} filt={} rtt={:.1}ms peak={}{}",
            self.elapsed.as_secs(),
            self.probes_sent,
            self.probes_replied,
            self.probes_per_sec,
            self.open_ports,
            self.filtered_ports,
            self.rtt_avg_ms,
            self.peak_parallel,
            mem
        )
    }
}

/// Best-effort RSS reader. Returns 0 on platforms we don't support
/// (no Windows API call to avoid a dep).
#[cfg(target_os = "linux")]
fn read_rss_kb() -> u64 {
    use std::fs::read_to_string;
    let statm = match read_to_string("/proc/self/statm") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let parts: Vec<&str> = statm.split_whitespace().collect();
    if parts.len() < 2 {
        return 0;
    }
    let pages: u64 = parts[1].parse().unwrap_or(0);
    pages * 4 // page size in KiB on most x86_64 Linux
}

#[cfg(not(target_os = "linux"))]
fn read_rss_kb() -> u64 {
    0
}

/// Spawn a background reporter that prints a `[stats] …` line every
/// `interval` until `stop` flips true.
pub fn spawn_reporter(
    stats: Arc<ScanStats>,
    started: Instant,
    interval: Duration,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(interval);
        loop {
            t.tick().await;
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let snap = stats.snapshot(started.elapsed());
            eprintln!("{}", snap.format_line());
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn record_probe_sent_increments_counters_and_peak() {
        let s = ScanStats::new();
        s.record_probe_sent();
        s.record_probe_sent();
        s.record_probe_sent();
        assert_eq!(s.probes_sent.load(Ordering::Relaxed), 3);
        assert_eq!(s.peak_parallel.load(Ordering::Relaxed), 3);
        assert_eq!(s.current_parallel.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn record_probe_done_drains_current_parallel() {
        let s = ScanStats::new();
        s.record_probe_sent();
        s.record_probe_sent();
        s.record_probe_done(true, Some(Duration::from_millis(15)));
        assert_eq!(s.current_parallel.load(Ordering::Relaxed), 1);
        // Peak doesn't decrease even though current does
        assert_eq!(s.peak_parallel.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn snapshot_computes_rate_and_rtt_avg() {
        let s = ScanStats::new();
        for _ in 0..100 {
            s.record_probe_sent();
            s.record_probe_done(true, Some(Duration::from_millis(20)));
        }
        let snap = s.snapshot(Duration::from_secs(1));
        assert!((snap.probes_per_sec - 100.0).abs() < 1e-9);
        assert!((snap.rtt_avg_ms - 20.0).abs() < 0.01);
        assert_eq!(snap.probes_replied, 100);
    }

    #[test]
    fn snapshot_handles_no_replies() {
        let s = ScanStats::new();
        for _ in 0..5 {
            s.record_probe_sent();
            s.record_probe_done(false, None);
        }
        let snap = s.snapshot(Duration::from_secs(1));
        assert_eq!(snap.rtt_avg_ms, 0.0);
        assert_eq!(snap.probes_replied, 0);
    }

    #[test]
    fn format_line_starts_with_marker_and_includes_rate() {
        let s = ScanStats::new();
        s.record_probe_sent();
        s.record_probe_done(true, Some(Duration::from_millis(50)));
        let snap = s.snapshot(Duration::from_secs(1));
        let line = snap.format_line();
        assert!(line.starts_with("[stats]"));
        assert!(line.contains("sent=1"));
        assert!(line.contains("replied=1"));
    }

    #[test]
    fn open_and_filtered_counters_track() {
        let s = ScanStats::new();
        s.record_open();
        s.record_open();
        s.record_filtered();
        let snap = s.snapshot(Duration::from_secs(1));
        assert_eq!(snap.open_ports, 2);
        assert_eq!(snap.filtered_ports, 1);
    }

    #[tokio::test]
    async fn reporter_stops_when_flag_flips() {
        let stats = ScanStats::new();
        let started = Instant::now();
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_reporter(stats, started, Duration::from_millis(50), stop.clone());
        tokio::time::sleep(Duration::from_millis(120)).await;
        stop.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(handle.is_finished());
    }
}
