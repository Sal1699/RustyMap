//! OWASP Top-10 active probes against discovered endpoints.
//!
//! Subset that's both safe (no destructive payloads, no auth
//! bruteforce) and signal-rich:
//!   - **A03 Injection — reflected XSS**: per-param send a token-
//!     wrapped `<svg/onload>` payload, look for the payload echoed
//!     unencoded in the response body.
//!   - **A03 Injection — error-based SQLi**: per-param send `'`,
//!     match common DB error fingerprints (MySQL, PostgreSQL, MSSQL,
//!     Oracle, SQLite). False-positive-low because we look for
//!     specific error strings, not just status changes.
//!   - **A04 Insecure Design — open redirect**: per-param send
//!     `https://evil.example.org/`, follow no redirects, check the
//!     response Location header echoes our value.
//!   - **A10 SSRF (best-effort)**: per-param send `http://127.0.0.1:1/`,
//!     match a connection-refused error string in the body. Limited
//!     because most apps don't expose backend errors verbatim.
//!
//! Each finding includes the param it triggered on and the evidence
//! snippet so reviewers can verify by hand.

use crate::web_crawl::Endpoint;
use anyhow::Result;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

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
    pub checks: Vec<&'static str>, // "xss", "sqli", "redirect", "ssrf"
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
            checks: vec!["xss", "sqli", "redirect", "ssrf"],
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
];

pub async fn probe(endpoints: &[Endpoint], cfg: &ProbeConfig) -> Result<Vec<OwaspFinding>> {
    let client = reqwest::Client::builder()
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
    let markers = [
        "connection refused",
        "failed to connect",
        "couldn't connect",
        "no route to host",
        "127.0.0.1:1",
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
        // Build a fresh query string with our payload on the target param.
        let mut pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let mut found = false;
        for (k, v) in pairs.iter_mut() {
            if k == param {
                *v = value.into();
                found = true;
            }
        }
        if !found {
            pairs.push((param.into(), value.into()));
        }
        // For form-discovered endpoints with no current query, add ours.
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
}
