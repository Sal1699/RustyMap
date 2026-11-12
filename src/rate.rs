use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Adaptive concurrency controller.
///
/// Tracks timeout vs success ratio over a sliding window of the last N
/// observations and grows or shrinks the target parallelism accordingly.
/// Uses a tokio Semaphore as the underlying inflight-limiter; when the
/// target drops, we simply stop returning permits to the pool.
pub struct AdaptiveLimiter {
    sem: Arc<Semaphore>,
    target: AtomicUsize,
    min_parallel: usize,
    max_parallel: usize,
    successes: AtomicU64,
    timeouts: AtomicU64,
    total_rtt_ms: AtomicU64,
    /// Persistent EWMA of observed RTT in microseconds (NOT reset by
    /// `adjust()`, unlike `total_rtt_ms`). Drives `adaptive_timeout` so a
    /// filtered port on a fast LAN stops costing the full `--timeout`.
    ewma_rtt_us: AtomicU64,
    /// Smoothed mean RTT deviation (µs), Jacobson/Karels `rttvar`; feeds the
    /// `srtt + 4·rttvar` term of `adaptive_timeout` (review #12).
    ewma_rttvar_us: AtomicU64,
    rtt_samples: AtomicU64,
    verbose: bool,
}

/// How much headroom over the mean RTT to allow before calling a probe lost.
/// nmap uses `srtt + 4·rttvar`; a flat 10× mean is a stable, slightly
/// conservative floor we keep as a lower bound (see `adaptive_timeout`).
pub const RTT_TIMEOUT_MULT: u32 = 10;

/// nmap-style adaptive per-probe timeout (review #12). Until we have observed
/// real RTTs the full `base` (the user's `--timeout`) is used; once we have a
/// smoothed RTT the wait shrinks toward the larger of:
///   * `RTT_TIMEOUT_MULT × srtt` — the stable, slightly conservative proxy that
///     collapses a 1500 ms LAN wait to the floor, and
///   * `srtt + 4·rttvar` — Jacobson/Karels (RFC 6298): on a *jittery* link the
///     variance term widens the window so a late-but-real reply isn't dropped
///     as filtered.
/// Taking the **max** means the RFC term only ever *adds* headroom over the old
/// flat-10× behaviour — it can never tighten the window into a new
/// false-`filtered`, so it's safe on the hot path. Clamped to `[floor, base]`;
/// `rtt_var = None` reproduces the pre-#12 flat-10× result exactly.
pub fn adaptive_timeout(
    base: Duration,
    mean_rtt: Option<Duration>,
    rtt_var: Option<Duration>,
    floor: Duration,
) -> Duration {
    match mean_rtt {
        Some(rtt) if !rtt.is_zero() => {
            let flat = rtt.saturating_mul(RTT_TIMEOUT_MULT);
            let rfc = rtt.saturating_add(
                rtt_var.unwrap_or(Duration::ZERO).saturating_mul(4),
            );
            flat.max(rfc).clamp(floor.min(base), base)
        }
        _ => base,
    }
}

/// The per-probe timeout floor derived from the user's base timeout: one
/// tenth of it, bounded to a sane LAN range so `adaptive_timeout` never waits
/// absurdly little (missing a slow reply) nor as long as the full base.
pub fn timeout_floor(base: Duration) -> Duration {
    (base / 10).clamp(Duration::from_millis(50), Duration::from_millis(300))
}

impl AdaptiveLimiter {
    pub fn new(initial: usize, min_parallel: usize, max_parallel: usize, verbose: bool) -> Arc<Self> {
        let clamped = initial.clamp(min_parallel, max_parallel);
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(clamped)),
            target: AtomicUsize::new(clamped),
            min_parallel,
            max_parallel,
            successes: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            total_rtt_ms: AtomicU64::new(0),
            ewma_rtt_us: AtomicU64::new(0),
            ewma_rttvar_us: AtomicU64::new(0),
            rtt_samples: AtomicU64::new(0),
            verbose,
        })
    }

    /// Mean observed RTT, once at least a few replies have been seen.
    /// `None` until then so the scan uses the full base timeout while warming
    /// up. Reads the persistent EWMA, not the per-interval `total_rtt_ms`.
    pub fn mean_rtt(&self) -> Option<Duration> {
        if self.rtt_samples.load(Ordering::Relaxed) < 3 {
            return None;
        }
        let us = self.ewma_rtt_us.load(Ordering::Relaxed);
        if us == 0 {
            None
        } else {
            Some(Duration::from_micros(us))
        }
    }

    /// Smoothed RTT variance (`rttvar`), once a few replies have been seen;
    /// `None` while warming up. Pairs with [`mean_rtt`](Self::mean_rtt) to feed
    /// the `srtt + 4·rttvar` term of [`adaptive_timeout`] (review #12).
    pub fn rtt_var(&self) -> Option<Duration> {
        if self.rtt_samples.load(Ordering::Relaxed) < 3 {
            return None;
        }
        Some(Duration::from_micros(self.ewma_rttvar_us.load(Ordering::Relaxed)))
    }

    pub fn semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.sem)
    }

    #[allow(dead_code)]
    pub fn target(&self) -> usize {
        self.target.load(Ordering::Relaxed)
    }

    pub fn record(&self, timed_out: bool, rtt: Duration) {
        if timed_out {
            self.timeouts.fetch_add(1, Ordering::Relaxed);
        } else {
            self.successes.fetch_add(1, Ordering::Relaxed);
            self.total_rtt_ms.fetch_add(rtt.as_millis() as u64, Ordering::Relaxed);
            // Persistent RTT EWMA (α=0.25) in microseconds, surviving
            // `adjust()`. A racy load/store is fine for a timing heuristic.
            // Alongside it we track `rttvar` (mean deviation, β=0.25) so
            // `adaptive_timeout` can widen the window on a jittery link (#12).
            let sample = rtt.as_micros().min(u64::MAX as u128) as u64;
            let prev = self.ewma_rtt_us.load(Ordering::Relaxed);
            let (next_srtt, next_var) = if prev == 0 {
                (sample, sample / 2) // RFC 6298 initial rttvar = sample/2
            } else {
                let err = prev.abs_diff(sample); // deviation from current srtt
                let prev_var = self.ewma_rttvar_us.load(Ordering::Relaxed);
                ((prev * 3 + sample) / 4, (prev_var * 3 + err) / 4)
            };
            self.ewma_rtt_us.store(next_srtt, Ordering::Relaxed);
            self.ewma_rttvar_us.store(next_var, Ordering::Relaxed);
            self.rtt_samples.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Recompute and apply a new target parallelism based on observations
    /// since the last call. Safe to call from a single background task.
    pub fn adjust(&self) {
        let s = self.successes.swap(0, Ordering::Relaxed);
        let t = self.timeouts.swap(0, Ordering::Relaxed);
        let total = s + t;
        if total < 10 {
            return;
        }
        let ratio = t as f64 / total as f64;
        let cur = self.target.load(Ordering::Relaxed);

        let new = if ratio > 0.30 {
            (cur as f64 * 0.6) as usize
        } else if ratio > 0.15 {
            (cur as f64 * 0.85) as usize
        } else if ratio < 0.02 {
            (cur as f64 * 1.4) as usize
        } else if ratio < 0.05 {
            (cur as f64 * 1.15) as usize
        } else {
            cur
        };

        let new = new.clamp(self.min_parallel, self.max_parallel);
        if new == cur {
            return;
        }

        self.target.store(new, Ordering::Relaxed);
        if new > cur {
            self.sem.add_permits(new - cur);
        } else {
            let to_remove = cur - new;
            let sem = Arc::clone(&self.sem);
            tokio::spawn(async move {
                for _ in 0..to_remove {
                    if let Ok(p) = sem.acquire().await {
                        p.forget();
                    }
                }
            });
        }
        if self.verbose {
            eprintln!(
                "[adaptive] timeout_ratio={:.2} cur={} -> new={}",
                ratio, cur, new
            );
        }
        self.total_rtt_ms.store(0, Ordering::Relaxed);
    }

    pub fn spawn_adjuster(self: &Arc<Self>, interval_ms: u64) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_millis(interval_ms));
            t.tick().await;
            loop {
                t.tick().await;
                me.adjust();
            }
        });
    }
}

/// Minimum wall-clock span that `count` packets may occupy at `max_pps`
/// packets/second (`0` = unlimited → zero). Pure helper behind
/// [`GlobalRateLimiter`], split out so the pacing maths is unit-testable
/// without a clock.
pub fn min_send_span(max_pps: u32, count: usize) -> Duration {
    if max_pps == 0 || count == 0 {
        return Duration::ZERO;
    }
    let per = Duration::from_nanos(1_000_000_000 / max_pps as u64);
    per.saturating_mul(count as u32)
}

/// Process-global send-rate ceiling honouring `--max-rate` (packets/second),
/// shared by **all** concurrent host scans (review #2). The old per-host
/// `RatePacer` was built one-per-host, so with N hosts in flight the true
/// aggregate rate was up to `N × --max-rate`; a single shared limiter behind a
/// mutex gives a real global cap. It reserves each packet's slot by advancing a
/// shared "earliest next send" instant under the lock, then sleeps (lock
/// released) until that slot — so concurrent senders queue slots back-to-back
/// instead of each waiting out the other's sleep. `max_pps == 0` disables it
/// (constructor returns `None`, so the hot path skips the call entirely).
pub struct GlobalRateLimiter {
    max_pps: u32,
    next_at: parking_lot::Mutex<std::time::Instant>,
}

impl GlobalRateLimiter {
    pub fn new(max_pps: u32) -> Option<Arc<Self>> {
        if max_pps == 0 {
            return None;
        }
        Some(Arc::new(Self {
            max_pps,
            next_at: parking_lot::Mutex::new(std::time::Instant::now()),
        }))
    }

    /// Reserve `count` packet slots globally and block until the first is due.
    /// The reservation (advancing the shared instant) happens under the lock;
    /// the sleep happens after the lock is dropped.
    pub fn acquire(&self, count: usize) {
        if count == 0 {
            return;
        }
        let span = min_send_span(self.max_pps, count);
        let now = std::time::Instant::now();
        let start = {
            let mut next = self.next_at.lock();
            let start = if *next > now { *next } else { now };
            *next = start + span;
            start
        };
        let wait = start.saturating_duration_since(now);
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
    }
}

/// A TCP-style congestion window bounding how many probes the raw **fast
/// engine** keeps in flight at once. Before Fase 31 the fast engine burst
/// *every* port in one shot — on a full-65535 scan that outran the single
/// receiver and tripped host RST rate-limiting, dropping replies (lost
/// "open" results) and spiking variance (v0.88.3 lab run). The window ramps up
/// in slow-start, then AIMD: a wave that drops a large fraction of probes **on
/// a host that is otherwise answering** is read as congestion / rate-limiting
/// and halves the window (so the next, gentler wave recovers the lost opens);
/// a clean wave grows it. A silent/filtered host (no replies at all) is *not*
/// treated as congestion — the window keeps growing so a filtered sweep still
/// finishes fast. Clamped to `[min, max]`; `max` comes from `--max-parallel`
/// and `min` is raised by `--min-rate`.
pub struct CongestionWindow {
    cwnd: f64,
    ssthresh: f64,
    min: f64,
    max: f64,
    slow_start: bool,
}

impl CongestionWindow {
    pub fn new(initial: usize, min: usize, max: usize) -> Self {
        let min = (min.max(1)) as f64;
        let max = (max as f64).max(min);
        let cwnd = (initial as f64).clamp(min, max);
        Self { cwnd, ssthresh: max, min, max, slow_start: true }
    }

    /// How many probes to send in the next wave.
    pub fn window(&self) -> usize {
        self.cwnd.round().clamp(self.min, self.max) as usize
    }

    fn grow(&mut self) {
        if self.slow_start {
            self.cwnd *= 2.0;
            if self.cwnd >= self.ssthresh {
                self.slow_start = false;
            }
        } else {
            self.cwnd += 1.0;
        }
    }

    /// Multiplicative decrease (halve toward the floor) and leave slow-start.
    /// Driven by the drop-ratio branch of `feed`, and by the raw engine's ICMP
    /// destination-unreachable signal (#4) regardless of drop ratio.
    pub fn force_backoff(&mut self) {
        self.ssthresh = (self.cwnd / 2.0).max(self.min);
        self.cwnd = self.ssthresh;
        self.slow_start = false;
    }

    /// Feed the outcome of a wave: `sent` probes went out and `replies` of them
    /// got a definitive answer (the rest are drops this wave). See the struct
    /// doc for the policy.
    pub fn feed(&mut self, sent: usize, replies: usize) {
        if sent == 0 {
            return;
        }
        let drops = sent.saturating_sub(replies);
        let ratio = drops as f64 / sent as f64;
        if replies == 0 {
            // A wave with NO replies at all is filtered/silent, not congestion
            // — so grow, don't back off. Backing off here pinned the window at
            // the floor on a mostly-filtered host that had answered a few ports
            // (lab v0.95.0 .3: 1 open, rest filtered → cwnd collapsed → ~50 min
            // full-port). Congestion is a wave that WAS answering and then lost
            // a large fraction (the rate-limiting fingerprint) — handled below.
            self.grow();
        } else if ratio > 0.20 {
            // Mixed wave losing a large fraction → congestion / rate-limiting
            // on a responding host → multiplicative decrease to recover opens.
            self.force_backoff();
        } else if ratio < 0.05 {
            self.grow();
        }
        self.cwnd = self.cwnd.clamp(self.min, self.max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_timeout_uses_base_without_samples() {
        let base = Duration::from_millis(1500);
        assert_eq!(adaptive_timeout(base, None, None, timeout_floor(base)), base);
    }

    #[test]
    fn adaptive_timeout_collapses_on_fast_lan() {
        let base = Duration::from_millis(1500);
        let floor = timeout_floor(base); // 150ms
        // 0.3ms LAN RTT → 10× = 3ms, clamped up to the 150ms floor (not 1500).
        let eff = adaptive_timeout(base, Some(Duration::from_micros(300)), None, floor);
        assert_eq!(eff, floor);
        assert!(eff < base);
    }

    #[test]
    fn adaptive_timeout_rises_for_slow_wan() {
        let base = Duration::from_millis(1500);
        let floor = timeout_floor(base);
        // 80ms WAN RTT → 10× = 800ms, between floor and base.
        let eff = adaptive_timeout(base, Some(Duration::from_millis(80)), None, floor);
        assert_eq!(eff, Duration::from_millis(800));
    }

    #[test]
    fn adaptive_timeout_never_exceeds_base() {
        let base = Duration::from_millis(1500);
        let floor = timeout_floor(base);
        // 500ms RTT → 10× = 5s, capped at base.
        let eff = adaptive_timeout(base, Some(Duration::from_millis(500)), None, floor);
        assert_eq!(eff, base);
    }

    #[test]
    fn adaptive_timeout_rttvar_only_adds_headroom() {
        // #12: the `srtt + 4·rttvar` term must only ever *widen* the window.
        let base = Duration::from_millis(1500);
        let floor = timeout_floor(base);
        let srtt = Duration::from_millis(50); // 10× = 500ms (the flat term)
        // Low jitter: 4·rttvar (4×2ms=8ms) < 10×srtt → flat term wins, unchanged.
        let calm = adaptive_timeout(base, Some(srtt), Some(Duration::from_millis(2)), floor);
        assert_eq!(calm, Duration::from_millis(500));
        // High jitter: 4·rttvar (4×300ms=1200ms)+srtt=1250ms > 500ms flat → the
        // RFC term widens the window (fewer late replies dropped as filtered).
        let jittery =
            adaptive_timeout(base, Some(srtt), Some(Duration::from_millis(300)), floor);
        assert_eq!(jittery, Duration::from_millis(1250));
        assert!(jittery > calm, "rttvar must only add headroom, never remove it");
    }

    #[test]
    fn global_rate_limiter_off_when_zero() {
        assert!(GlobalRateLimiter::new(0).is_none());
        assert!(GlobalRateLimiter::new(1000).is_some());
    }

    #[test]
    fn global_rate_limiter_paces_aggregate() {
        // #2: 2000 pps → 0.5ms/packet. Reserving 20 slots must take at least a
        // few ms regardless of how the calls are grouped (first slot is free).
        // Generous lower bound so coarse OS sleep granularity can't flake it.
        let g = GlobalRateLimiter::new(2000).unwrap();
        g.acquire(0); // no-op must not panic or advance
        let t0 = std::time::Instant::now();
        for _ in 0..20 {
            g.acquire(1);
        }
        assert!(
            t0.elapsed() >= Duration::from_millis(5),
            "expected global pacing, took {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn timeout_floor_is_tenth_bounded() {
        assert_eq!(timeout_floor(Duration::from_millis(1500)), Duration::from_millis(150));
        // Tiny base → floored at 50ms.
        assert_eq!(timeout_floor(Duration::from_millis(200)), Duration::from_millis(50));
        // Huge base → capped at 300ms.
        assert_eq!(timeout_floor(Duration::from_millis(9000)), Duration::from_millis(300));
    }

    #[test]
    fn mean_rtt_none_until_three_samples() {
        let lim = AdaptiveLimiter::new(100, 4, 500, false);
        lim.record(false, Duration::from_millis(10));
        lim.record(false, Duration::from_millis(10));
        assert!(lim.mean_rtt().is_none());
        lim.record(false, Duration::from_millis(10));
        assert_eq!(lim.mean_rtt(), Some(Duration::from_millis(10)));
    }

    #[test]
    fn min_send_span_is_zero_when_unlimited() {
        assert_eq!(min_send_span(0, 10_000), Duration::ZERO);
        assert_eq!(min_send_span(1000, 0), Duration::ZERO);
    }

    #[test]
    fn min_send_span_scales_with_rate_and_count() {
        // 1000 pps → 1 ms/packet → 1000 packets span ~1 s.
        assert_eq!(min_send_span(1000, 1000), Duration::from_millis(1000));
        // 100 pps → 10 ms/packet → 50 packets span ~0.5 s.
        assert_eq!(min_send_span(100, 50), Duration::from_millis(500));
    }

    #[test]
    fn cwnd_slow_starts_and_clamps_to_max() {
        let mut w = CongestionWindow::new(64, 16, 512);
        assert_eq!(w.window(), 64);
        // Clean waves double the window (slow-start) up to max.
        w.feed(64, 64); // 64 -> 128
        assert_eq!(w.window(), 128);
        w.feed(128, 128); // -> 256
        assert_eq!(w.window(), 256);
        w.feed(256, 256); // -> 512 (max)
        assert_eq!(w.window(), 512);
        w.feed(512, 512); // stays clamped at max
        assert_eq!(w.window(), 512);
    }

    #[test]
    fn cwnd_backs_off_on_congestion_when_responsive() {
        let mut w = CongestionWindow::new(256, 16, 512);
        w.feed(256, 256); // responsive + clean → grows to 512
        assert_eq!(w.window(), 512);
        // A wave that drops most probes on a host that has been answering →
        // multiplicative decrease (~halve).
        w.feed(512, 100);
        assert!(w.window() < 512, "expected backoff, got {}", w.window());
        assert!(w.window() >= 16);
    }

    #[test]
    fn cwnd_does_not_collapse_on_fully_filtered_host() {
        // No probe ever replies → not congestion; the window must keep growing
        // so a filtered sweep finishes fast rather than crawling at the floor.
        let mut w = CongestionWindow::new(64, 16, 512);
        for _ in 0..4 {
            w.feed(64, 0);
        }
        assert_eq!(w.window(), 512);
    }

    #[test]
    fn cwnd_respects_min_floor() {
        let mut w = CongestionWindow::new(64, 50, 512);
        w.feed(64, 64); // responsive
        // Hammer it with MIXED congestion waves (some replies, heavy loss) —
        // the real back-off path — it must never drop below the floor.
        for _ in 0..20 {
            let win = w.window();
            w.feed(win, 1); // 1 reply, rest dropped → ratio high → MD
        }
        assert!(w.window() >= 50, "window {} fell below floor", w.window());
    }

    #[test]
    fn cwnd_force_backoff_halves_to_floor() {
        let mut w = CongestionWindow::new(400, 16, 512);
        let before = w.window();
        w.force_backoff();
        assert!(w.window() < before && w.window() >= 16);
        // Repeated forced backoff never goes below the floor.
        for _ in 0..10 {
            w.force_backoff();
        }
        assert!(w.window() >= 16);
    }

    #[test]
    fn cwnd_all_drop_wave_does_not_back_off() {
        // A mostly-filtered host that answered a few ports, then a wave of only
        // filtered ports (0 replies) must NOT collapse the window (lab .3).
        let mut w = CongestionWindow::new(64, 16, 512);
        w.feed(64, 10); // responsive wave → grows
        let before = w.window();
        for _ in 0..5 {
            w.feed(w.window(), 0); // all-filtered waves
        }
        assert!(
            w.window() >= before,
            "all-drop waves must not shrink the window ({} -> {})",
            before,
            w.window()
        );
    }
}
