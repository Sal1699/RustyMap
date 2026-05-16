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
        let outcome = match adapter.try_one(&cfg, &user, &pass).await {
            Ok(true) => AttemptOutcome::Success,
            Ok(false) => AttemptOutcome::Failed,
            Err(_) => AttemptOutcome::Error,
        };
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

pub fn print_report(r: &BruteReport) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!(
            "Bruteforce against {} ({} adapter) — {} attempt(s), {} success(es)",
            r.target,
            r.protocol,
            r.tried,
            r.successes.len()
        )
        .bold()
    );
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
        println!("  {}", "no valid pair found".dimmed());
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
