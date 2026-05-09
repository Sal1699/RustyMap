//! Tiny helper for randomising the per-probe scan delay.
//!
//! Constant inter-probe spacing (`--scan-delay 500ms`) is a clear
//! mechanical signal — Suricata's `app-layer-event:tcp.dup_synack`
//! and Splunk's `stream:tcp` both have rules that flag exact-period
//! probe trains. Adding a `±N%` jitter window broadens the inter-
//! arrival distribution enough to look like real traffic.
//!
//! The jitter is symmetric around the configured base delay:
//!
//!   `delay ∈ [base * (1 - pct/100), base * (1 + pct/100)]`
//!
//! Pure RNG-driven — no timing IO, no global state. The caller
//! decides where in the scan loop to apply it.

use rand::Rng;

/// Compute the next sleep duration in ms given a base delay and a
/// jitter percent (0–100). Returns `base_ms` unchanged when either
/// `base_ms == 0` (no delay configured) or `pct == 0` (no jitter).
pub fn next_ms(base_ms: u64, pct: u8) -> u64 {
    if base_ms == 0 || pct == 0 {
        return base_ms;
    }
    let pct = pct.min(100) as i64;
    let base = base_ms as i64;
    let span = base * pct / 100;
    let lo = (base - span).max(0);
    let hi = base + span;
    let mut rng = rand::thread_rng();
    rng.gen_range(lo..=hi).max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_base_stays_zero() {
        for _ in 0..50 {
            assert_eq!(next_ms(0, 25), 0);
        }
    }

    #[test]
    fn zero_jitter_returns_base_unchanged() {
        for base in [10, 100, 999, 5_000] {
            assert_eq!(next_ms(base, 0), base);
        }
    }

    #[test]
    fn output_falls_within_pct_window() {
        let base: u64 = 1000;
        let pct: u8 = 30;
        let lo = (base as i64 - (base as i64) * pct as i64 / 100) as u64;
        let hi = base + (base * pct as u64) / 100;
        for _ in 0..200 {
            let v = next_ms(base, pct);
            assert!(v >= lo && v <= hi, "{} not in [{}, {}]", v, lo, hi);
        }
    }

    #[test]
    fn pct_above_100_clamped_to_100() {
        let base: u64 = 100;
        for _ in 0..100 {
            // With pct=200 (clamped to 100) the floor stays ≥ 0.
            let v = next_ms(base, 200);
            assert!(v <= base * 2);
        }
    }

    #[test]
    fn output_is_actually_randomised() {
        let mut seen: std::collections::HashSet<u64> = Default::default();
        for _ in 0..50 {
            seen.insert(next_ms(1000, 25));
        }
        // Across 50 draws with ±25% on a 1000ms base we expect many
        // distinct values (~500 possible outcomes), so > 5 unique
        // is a generous floor.
        assert!(seen.len() > 5, "got only {} unique values", seen.len());
    }
}
