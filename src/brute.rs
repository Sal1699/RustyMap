//! Credential bruteforce framework — common types, safety gates,
//! rate-limit, audit logging.
//!
//! Per-protocol adapters live in `src/brute_*.rs` and implement the
//! `BruteAdapter` trait. The framework here is responsible for:
//!
//!   - **Safety gates**. Without `--brute-confirm-authorized`,
//!     any bruteforce mode beyond `default-creds-only` is rejected.
//!   - **Rate-limit**. Default 1 attempt/sec to keep us under any
//!     reasonable lockout threshold; `--brute-rate N` overrides
//!     when the operator explicitly wants more.
//!   - **Stop on success**. Default true — kill the loop after the
//!     first hit so we don't burn the rest of the wordlist hunting
//!     for a second valid pair.
//!   - **Cap on total attempts** (`--brute-max-tries N`, default
//!     1000). Hard stop so a typo in the wordlist size can't blast
//!     a million-pair attempt at the target.
//!   - **Audit log**. Every attempt produces a `brute_attempt` event
//!     in `--audit-log`: target, user, pass redaction, success bit,
//!     latency.
//!
//! Read-only on RustyMap's side beyond the wire traffic; results
//! are dumped to stdout + audit log, never persisted automatically.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttemptOutcome {
    Success,
    Failed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteAttempt {
    pub user: String,
    pub pass: String,
    pub outcome: AttemptOutcome,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BruteConfig {
    pub target: SocketAddr,
    pub timeout: Duration,
    pub rate: u32,            // attempts/sec, default 1
    pub max_tries: usize,     // hard cap
    pub stop_on_success: bool,
    pub confirm_authorized: bool,
    pub default_creds_only: bool,
    pub form_spec: Option<String>, // free-text for http-form
    pub warn_internet_routable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BruteReport {
    pub protocol: String,
    pub target: String,
    pub tried: usize,
    pub successes: Vec<(String, String)>, // (user, pass) pairs
    pub attempts: Vec<BruteAttempt>,
    pub aborted_reason: Option<String>,
}

/// Implemented by every per-protocol module. Stateless — the
/// framework constructs an instance per `run()` so adapters can
/// hold connection state locally if they want.
#[async_trait]
pub trait BruteAdapter: Send + Sync {
    fn protocol(&self) -> &'static str;
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool>;
}

/// Pair source — provides (user, pass) tuples one at a time.
#[derive(Debug, Clone)]
pub enum PairSource {
    Fixed(Vec<(String, String)>),
    Cross { users: Vec<String>, passes: Vec<String> },
}

impl PairSource {
    pub fn len(&self) -> usize {
        match self {
            PairSource::Fixed(v) => v.len(),
            PairSource::Cross { users, passes } => users.len() * passes.len(),
        }
    }
    pub fn iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
        match self {
            PairSource::Fixed(v) => Box::new(v.iter().cloned()),
            PairSource::Cross { users, passes } => Box::new(
                users
                    .iter()
                    .flat_map(move |u| passes.iter().map(move |p| (u.clone(), p.clone()))),
            ),
        }
    }
}

/// Transport errors (connection refused/reset/timeout — often a server
/// throttling a burst of pre-auth connections) get this many retries on the
/// SAME pair before being recorded as an error, mirroring hydra's reconnect-
/// and-retry resilience. Retries do not count against `--brute-max-tries`.
///
/// The backoff between retries is exponential with jitter (see `run`). A burst
/// throttle such as OpenSSH `MaxStartups` clears over *seconds* as the server's
/// startup queue drains, so the attempt carrying the valid credential needs a
/// few well-spaced chances to land — the old 2 retries at 120/240 ms were far
/// too fast to outlast it (lab v0.100.7: ssh `--brute-userlist×--brute-passlist`
/// lost a cred hydra found; 11 of 16 connects errored under the server throttle
/// and the matching attempt was one of them).
const PAIR_ERROR_RETRIES: u32 = 4;

/// Run an adapter against a pair source under the safety policy.
pub async fn run<A: BruteAdapter>(
    adapter: A,
    cfg: BruteConfig,
    pairs: PairSource,
) -> Result<BruteReport> {
    // ── Gates ──
    if !cfg.confirm_authorized && !cfg.default_creds_only {
        return Err(anyhow!(
            "{} bruteforce refused without --brute-confirm-authorized. \
             Use --brute-default-creds-only for the ~200-pair vendor-default \
             list (much lower lockout risk).",
            adapter.protocol()
        ));
    }
    if cfg.warn_internet_routable {
        eprintln!(
            "[brute] WARNING: target {} appears routable on the public Internet. \
             Make sure you have written authorization.",
            cfg.target
        );
    }

    let mut report = BruteReport {
        protocol: adapter.protocol().into(),
        target: cfg.target.to_string(),
        ..Default::default()
    };

    let rate_delay = if cfg.rate == 0 {
        Duration::from_millis(0)
    } else {
        Duration::from_millis((1000 / cfg.rate.max(1)) as u64)
    };
    let counter = Arc::new(AtomicUsize::new(0));
    let max = cfg.max_tries.max(1);

    for (user, pass) in pairs.iter() {
        let count = counter.fetch_add(1, Ordering::Relaxed);
        if count >= max {
            report.aborted_reason = Some(format!("hit --brute-max-tries cap ({})", max));
            break;
        }
        let t0 = Instant::now();
        // A transport error (refused/reset/timeout) is not an auth verdict —
        // the server may be throttling rapid attempts. Retry the SAME pair a
        // few times before giving up, so a throttled/transient drop on the
        // attempt that carries the right credential isn't silently missed
        // (lab v0.100.5: ssh userlist×passlist missed a cred hydra found,
        // because the matching attempt hit a throttled connection). An
        // Ok(false) is a real auth failure and is never retried.
        let mut outcome = AttemptOutcome::Error;
        for retry in 0..=PAIR_ERROR_RETRIES {
            match adapter.try_one(&cfg, &user, &pass).await {
                Ok(true) => {
                    outcome = AttemptOutcome::Success;
                    break;
                }
                Ok(false) => {
                    outcome = AttemptOutcome::Failed;
                    break;
                }
                Err(_) => {
                    outcome = AttemptOutcome::Error;
                    if retry < PAIR_ERROR_RETRIES {
                        // Exponential backoff with jitter: 400ms, 800ms, 1.6s,
                        // 3s (+ up to 250ms). A burst throttle (e.g. OpenSSH
                        // MaxStartups) clears over seconds as the server's
                        // startup queue drains, so spacing the retries out gives
                        // the attempt carrying the valid credential real chances
                        // to land; the jitter avoids re-synchronising with the
                        // throttle window on every pair.
                        let backoff = (400u64 << retry).min(3000);
                        let jitter = rand::random::<u64>() % 250;
                        sleep(Duration::from_millis(backoff + jitter)).await;
                    }
                }
            }
        }
        let latency_ms = t0.elapsed().as_millis() as u64;
        let error = match outcome {
            AttemptOutcome::Error => Some("adapter error".to_string()),
            _ => None,
        };
        let attempt = BruteAttempt {
            user: user.clone(),
            pass: pass.clone(),
            outcome,
            latency_ms,
            error,
        };
        report.tried += 1;
        if matches!(outcome, AttemptOutcome::Success) {
            report.successes.push((user.clone(), pass.clone()));
            report.attempts.push(attempt);
            if cfg.stop_on_success {
                break;
            }
        } else {
            report.attempts.push(attempt);
        }
        if !rate_delay.is_zero() {
            sleep(rate_delay).await;
        }
    }
    Ok(report)
}

/// Attempts that ended in a transport error (connection refused/reset/timeout)
/// rather than a server auth verdict. A run where every attempt errored reached
/// no verdict at all — the target was down/filtered — so it must NOT be read as
/// "the credentials are wrong".
pub fn error_count(r: &BruteReport) -> usize {
    r.attempts
        .iter()
        .filter(|a| a.outcome == AttemptOutcome::Error)
        .count()
}

pub fn print_report(r: &BruteReport) {
    use colored::*;
    let errors = error_count(r);
    println!();
    let mut headline = format!(
        "Bruteforce against {} ({} adapter) — {} attempt(s), {} success(es)",
        r.target,
        r.protocol,
        r.tried,
        r.successes.len()
    );
    if errors > 0 {
        headline.push_str(&format!(", {} connection error(s)", errors));
    }
    println!("{}", headline.bold());
    for (u, p) in &r.successes {
        println!(
            "  {} {}:{}",
            "[+] HIT".red().bold(),
            u.bold(),
            p
        );
    }
    if let Some(reason) = &r.aborted_reason {
        println!("  {} {}", "[-] aborted:".yellow(), reason);
    }
    if r.successes.is_empty() && r.aborted_reason.is_none() {
        if r.tried > 0 && errors == r.tried {
            // Every attempt failed to connect — no auth verdict was reached.
            // Say so loudly: this is inconclusive, not "no valid credentials".
            println!(
                "  {}",
                format!(
                    "all {} attempt(s) failed to connect (refused/reset/timeout) — target \
                     down, filtered, or throttling. INCONCLUSIVE, not a clean 'no valid \
                     credentials'; verify the service is reachable and re-run.",
                    r.tried
                )
                .yellow()
                .bold()
            );
        } else if errors > 0 {
            println!(
                "  {}",
                format!(
                    "no valid pair found — but {} of {} attempt(s) errored on the wire and \
                     were NOT conclusively tested",
                    errors, r.tried
                )
                .yellow()
            );
        } else {
            println!("  {}", "no valid pair found".dimmed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct StubAdapter {
        valid_user: String,
        valid_pass: String,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl BruteAdapter for StubAdapter {
        fn protocol(&self) -> &'static str { "stub" }
        async fn try_one(&self, _cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(user == self.valid_user && pass == self.valid_pass)
        }
    }

    fn cfg(confirm: bool, default_only: bool) -> BruteConfig {
        BruteConfig {
            target: "127.0.0.1:0".parse().unwrap(),
            timeout: Duration::from_secs(1),
            rate: 0, // tests don't need pacing
            max_tries: 1000,
            stop_on_success: true,
            confirm_authorized: confirm,
            default_creds_only: default_only,
            form_spec: None,
            warn_internet_routable: false,
        }
    }

    #[tokio::test]
    async fn refuses_without_consent() {
        let stub = StubAdapter {
            valid_user: "admin".into(),
            valid_pass: "password".into(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let pairs = PairSource::Fixed(vec![("admin".into(), "password".into())]);
        let r = run(stub, cfg(false, false), pairs).await;
        assert!(r.is_err());
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("--brute-confirm-authorized"));
    }

    #[tokio::test]
    async fn default_creds_only_bypasses_consent() {
        let stub = StubAdapter {
            valid_user: "admin".into(),
            valid_pass: "admin".into(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let pairs = PairSource::Fixed(vec![("admin".into(), "admin".into())]);
        let r = run(stub, cfg(false, true), pairs).await.unwrap();
        assert_eq!(r.successes.len(), 1);
    }

    /// Errors `fail_first` times for the valid pair, then authenticates — to
    /// prove a transient transport error is retried, not recorded as a miss.
    struct FlakyAdapter {
        fail_first: AtomicUsize,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl BruteAdapter for FlakyAdapter {
        fn protocol(&self) -> &'static str { "flaky" }
        async fn try_one(&self, _cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_first.load(Ordering::Relaxed) > 0 {
                self.fail_first.fetch_sub(1, Ordering::Relaxed);
                return Err(anyhow!("transient transport error"));
            }
            Ok(user == "admin" && pass == "secret")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transport_error_is_retried_then_hits() {
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = FlakyAdapter {
            fail_first: AtomicUsize::new(1), // first attempt errors, retry succeeds
            calls: Arc::clone(&calls),
        };
        let pairs = PairSource::Fixed(vec![("admin".into(), "secret".into())]);
        let r = run(adapter, cfg(true, false), pairs).await.unwrap();
        assert_eq!(r.successes.len(), 1, "retry should recover the hit");
        assert_eq!(calls.load(Ordering::Relaxed), 2, "one error + one success");
    }

    #[tokio::test(start_paused = true)]
    async fn multiple_transport_errors_recover_within_retries() {
        // Models the lab throttle: the valid pair's connect is dropped several
        // times in a row before it finally lands. With PAIR_ERROR_RETRIES=4 the
        // framework must outlast a 3-error burst and still record the hit.
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = FlakyAdapter {
            fail_first: AtomicUsize::new(3), // 3 throttled drops, then success
            calls: Arc::clone(&calls),
        };
        let pairs = PairSource::Fixed(vec![("admin".into(), "secret".into())]);
        let r = run(adapter, cfg(true, false), pairs).await.unwrap();
        assert_eq!(r.successes.len(), 1, "4 retries should outlast a 3-error throttle");
        assert_eq!(calls.load(Ordering::Relaxed), 4, "3 errors + 1 success");
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_error_gives_up_after_retries() {
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = FlakyAdapter {
            fail_first: AtomicUsize::new(100), // always errors
            calls: Arc::clone(&calls),
        };
        let pairs = PairSource::Fixed(vec![("admin".into(), "secret".into())]);
        let r = run(adapter, cfg(true, false), pairs).await.unwrap();
        assert_eq!(r.successes.len(), 0);
        // 1 initial + PAIR_ERROR_RETRIES retries on the single pair.
        assert_eq!(calls.load(Ordering::Relaxed), (PAIR_ERROR_RETRIES + 1) as usize);
    }

    #[tokio::test]
    async fn stop_on_success_short_circuits() {
        let calls = Arc::new(AtomicUsize::new(0));
        let stub = StubAdapter {
            valid_user: "u1".into(),
            valid_pass: "p1".into(),
            calls: Arc::clone(&calls),
        };
        let pairs = PairSource::Cross {
            users: vec!["u1".into(), "u2".into(), "u3".into()],
            passes: vec!["p1".into(), "p2".into()],
        };
        let r = run(stub, cfg(true, false), pairs).await.unwrap();
        assert_eq!(r.successes.len(), 1);
        // Should have stopped at the first hit (u1:p1 is the very first pair)
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn max_tries_cap_enforced() {
        let calls = Arc::new(AtomicUsize::new(0));
        let stub = StubAdapter {
            valid_user: "never".into(),
            valid_pass: "matches".into(),
            calls: Arc::clone(&calls),
        };
        let mut c = cfg(true, false);
        c.max_tries = 3;
        let pairs = PairSource::Cross {
            users: vec!["a".into(), "b".into()],
            passes: vec!["x".into(), "y".into(), "z".into()],
        };
        let r = run(stub, c, pairs).await.unwrap();
        assert_eq!(r.tried, 3);
        assert!(r.aborted_reason.is_some());
    }

    #[test]
    fn error_count_distinguishes_transport_errors_from_auth_failures() {
        let mk = |o: AttemptOutcome| BruteAttempt {
            user: "u".into(),
            pass: "p".into(),
            outcome: o,
            latency_ms: 0,
            error: None,
        };
        let r = BruteReport {
            tried: 3,
            attempts: vec![
                mk(AttemptOutcome::Error),
                mk(AttemptOutcome::Failed),
                mk(AttemptOutcome::Error),
            ],
            ..Default::default()
        };
        // 2 of 3 errored → an all-errored run would equal `tried` and read as
        // inconclusive rather than "no valid credentials".
        assert_eq!(error_count(&r), 2);
    }

    #[test]
    fn pair_source_cross_yields_product() {
        let p = PairSource::Cross {
            users: vec!["a".into(), "b".into()],
            passes: vec!["x".into(), "y".into(), "z".into()],
        };
        assert_eq!(p.len(), 6);
        let all: Vec<_> = p.iter().collect();
        assert_eq!(all.len(), 6);
        assert!(all.contains(&("a".to_string(), "x".to_string())));
        assert!(all.contains(&("b".to_string(), "z".to_string())));
    }
}
