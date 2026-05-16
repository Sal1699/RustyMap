//! Adaptive timing — RTT histogram + loss rate observer.
//!
//! Sits alongside the existing `rate::AdaptiveLimiter`. The limiter
//! controls *whether* to wait; this module decides *how long* the
//! wait should be based on what the network is telling us:
//!
//!   - **RTT trend rising** → back off (network is congested, or
//!     the target is throttling).
//!   - **Loss rate climbing** (probes timing out without a TCP
//!     RST / SYN-ACK / ICMP unreachable) → back off harder.
//!   - **Both indicators flat or improving** → step the per-host
//!     parallel cap back up to the user's `--max-parallel` ceiling.
//!
//! The math is deliberately simple — an EWMA on RTT and a sliding
//! window on loss percentage. We don't try to outsmart Cubic or
//! BBR. The goal is "don't be the obnoxious scanner that fires
//! 50k pps at a 10/100 switch and gets blackholed".
//!
//! Pure state machine — no IO, no globals. The scanner threads
//! call `.record(outcome, rtt_ms)` after each probe and read
//! `.suggested_parallel()` / `.suggested_extra_delay_ms()` to
//! pace the next batch.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeOutcome {
    Replied,    // SYN-ACK / RST / proper response
    Filtered,   // no answer within the timeout
    Errored,    // connect() error other than timeout
}

#[derive(Debug, Clone)]
pub struct AdaptiveState {
    pub rtt_ewma_ms: f64,
    pub loss_window: VecDeque<bool>, // true = lost (filtered/errored)
    pub window_size: usize,
    pub min_parallel: usize,
    pub max_parallel: usize,
    pub current_parallel: usize,
    pub base_delay_ms: u64,
    pub current_extra_delay_ms: u64,
    /// Count of consecutive "good" batches — drives the slow ramp
    /// back up to `max_parallel`.
    pub good_streak: u32,
}

#[allow(dead_code)]
impl AdaptiveState {
    pub fn new(max_parallel: usize, base_delay_ms: u64) -> Self {
        Self {
            rtt_ewma_ms: 0.0,
            loss_window: VecDeque::with_capacity(50),
            window_size: 50,
            min_parallel: (max_parallel / 8).max(4),
            max_parallel: max_parallel.max(4),
            current_parallel: max_parallel.max(4),
            base_delay_ms,
            current_extra_delay_ms: 0,
            good_streak: 0,
        }
    }

    pub fn record(&mut self, outcome: ProbeOutcome, rtt_ms: Option<u64>) {
        let lost = matches!(outcome, ProbeOutcome::Filtered | ProbeOutcome::Errored);
        if self.loss_window.len() >= self.window_size {
            self.loss_window.pop_front();
        }
        self.loss_window.push_back(lost);

        if let Some(rtt) = rtt_ms {
            // EWMA with α=0.2 (favours recent samples but stable)
            if self.rtt_ewma_ms == 0.0 {
                self.rtt_ewma_ms = rtt as f64;
            } else {
                self.rtt_ewma_ms = 0.8 * self.rtt_ewma_ms + 0.2 * rtt as f64;
            }
        }
    }

    /// Loss percentage over the sliding window (0.0 – 100.0).
    pub fn loss_pct(&self) -> f64 {
        if self.loss_window.is_empty() {
            return 0.0;
        }
        let lost = self.loss_window.iter().filter(|&&b| b).count();
        100.0 * lost as f64 / self.loss_window.len() as f64
    }

    /// Apply the policy and update `current_parallel` /
    /// `current_extra_delay_ms`. Call between batches.
    pub fn step(&mut self) {
        let loss = self.loss_pct();
        if loss >= 25.0 {
            // Severe — cut parallel in half, add 100ms extra delay
            self.current_parallel = (self.current_parallel / 2).max(self.min_parallel);
            self.current_extra_delay_ms = self.current_extra_delay_ms.saturating_add(100).min(2000);
            self.good_streak = 0;
        } else if loss >= 10.0 {
            // Moderate — minus 20%, add 25ms
            self.current_parallel =
                ((self.current_parallel as f32 * 0.8) as usize).max(self.min_parallel);
            self.current_extra_delay_ms = self.current_extra_delay_ms.saturating_add(25).min(1000);
            self.good_streak = 0;
        } else if self.rtt_ewma_ms > 500.0 {
            // RTT is bad even without loss — back off softly
            self.current_parallel = ((self.current_parallel as f32 * 0.9) as usize)
                .max(self.min_parallel);
            self.good_streak = 0;
        } else {
            // Good batch — count it and slowly ramp back up
            self.good_streak += 1;
            if self.good_streak >= 3 {
                self.current_parallel = (self.current_parallel + 4).min(self.max_parallel);
                if self.current_extra_delay_ms > 0 {
                    self.current_extra_delay_ms =
                        self.current_extra_delay_ms.saturating_sub(25);
                }
                self.good_streak = 0;
            }
        }
    }

    pub fn suggested_parallel(&self) -> usize {
        self.current_parallel
    }

    pub fn suggested_extra_delay(&self) -> Duration {
        Duration::from_millis(self.current_extra_delay_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn populate(state: &mut AdaptiveState, samples: &[(ProbeOutcome, Option<u64>)]) {
        for (o, r) in samples {
            state.record(*o, *r);
        }
    }

    #[test]
    fn record_grows_window_then_evicts() {
        let mut s = AdaptiveState::new(50, 0);
        s.window_size = 5;
        for _ in 0..10 {
            s.record(ProbeOutcome::Replied, Some(20));
        }
        assert!(s.loss_window.len() <= 5);
    }

    #[test]
    fn loss_pct_at_extremes() {
        let mut s = AdaptiveState::new(50, 0);
        for _ in 0..10 {
            s.record(ProbeOutcome::Filtered, None);
        }
        assert!((s.loss_pct() - 100.0).abs() < 1e-9);
        let mut s2 = AdaptiveState::new(50, 0);
        for _ in 0..10 {
            s2.record(ProbeOutcome::Replied, Some(10));
        }
        assert_eq!(s2.loss_pct(), 0.0);
    }

    #[test]
    fn rtt_ewma_seed_then_smooth() {
        let mut s = AdaptiveState::new(50, 0);
        s.record(ProbeOutcome::Replied, Some(100));
        assert!((s.rtt_ewma_ms - 100.0).abs() < 1e-9);
        s.record(ProbeOutcome::Replied, Some(200));
        // 0.8*100 + 0.2*200 = 120
        assert!((s.rtt_ewma_ms - 120.0).abs() < 1e-9);
    }

    #[test]
    fn step_high_loss_halves_parallel_and_adds_delay() {
        let mut s = AdaptiveState::new(64, 0);
        for _ in 0..50 {
            s.record(ProbeOutcome::Filtered, None);
        }
        s.step();
        assert_eq!(s.current_parallel, 32);
        assert!(s.current_extra_delay_ms > 0);
    }

    #[test]
    fn step_moderate_loss_softer_throttle() {
        let mut s = AdaptiveState::new(50, 0);
        s.window_size = 10;
        for i in 0..10 {
            // 10% loss
            if i == 0 {
                s.record(ProbeOutcome::Filtered, None);
            } else {
                s.record(ProbeOutcome::Replied, Some(20));
            }
        }
        s.step();
        assert!(s.current_parallel < 50);
        assert!(s.current_parallel > 25);
    }

    #[test]
    fn good_streak_ramps_back_up() {
        let mut s = AdaptiveState::new(64, 0);
        // Force a throttle first
        for _ in 0..50 {
            s.record(ProbeOutcome::Filtered, None);
        }
        s.step();
        let after_throttle = s.current_parallel;
        // Now feed good batches
        for _ in 0..50 {
            s.record(ProbeOutcome::Replied, Some(10));
        }
        // Need 3 steps to ramp up
        s.step();
        s.step();
        s.step();
        assert!(s.current_parallel > after_throttle);
    }

    #[test]
    fn parallel_never_goes_below_min() {
        let mut s = AdaptiveState::new(64, 0);
        for _ in 0..100 {
            for _ in 0..50 {
                s.record(ProbeOutcome::Filtered, None);
            }
            s.step();
        }
        assert!(s.current_parallel >= s.min_parallel);
    }

    #[test]
    fn high_rtt_alone_triggers_soft_backoff() {
        let mut s = AdaptiveState::new(50, 0);
        for _ in 0..30 {
            s.record(ProbeOutcome::Replied, Some(600));
        }
        let before = s.current_parallel;
        s.step();
        assert!(s.current_parallel < before);
    }
}
