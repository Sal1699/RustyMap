//! HTTP method enumeration — `nmap http-methods`-equivalent.
//!
//! Sends an `OPTIONS *` (and a path-specific `OPTIONS /`) to read the
//! advertised `Allow` header, then probes the dangerous-but-rare
//! methods (PUT, DELETE, MOVE, COPY, MKCOL, PROPFIND, TRACE, PATCH)
//! to see whether they're actually accepted — Allow can lie, and
//! some servers permit methods without listing them. Each probe
//! is **read-only**: PUT/DELETE/MOVE are sent against a non-existent
//! target path so they 404/405 cleanly without touching real files.
//!
//! Severity classification:
//!
//!   - **PUT enabled**: critical — full file upload, often RCE.
//!   - **DELETE enabled**: high — content deletion.
//!   - **MOVE / COPY enabled**: high — same as PUT in WebDAV combos.
//!   - **TRACE enabled**: medium — XST leak vector.
//!   - **PROPFIND / MKCOL enabled**: medium — WebDAV exposed.
//!   - **PATCH enabled**: info — modern APIs use it routinely.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodResult {
    pub method: String,
    pub status: u16,
    pub allowed: AllowedKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AllowedKind {
    Listed,    // appeared in Allow header
    Accepted,  // server returned 2xx on probe
    Redirect,  // server returned 3xx — a redirect is NOT method acceptance
    Refused,   // 4xx / 5xx on probe
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodsFinding {
    pub url: String,
    pub allow_header: Option<String>,
    pub results: Vec<MethodResult>,
}

const DANGEROUS: &[&str] = &["PUT", "DELETE", "MOVE", "COPY", "MKCOL", "PROPFIND", "TRACE", "PATCH"];

pub async fn enumerate(url: &str, dur: Duration) -> Result<MethodsFinding> {
    let client = reqwest::Client::builder()
        .timeout(dur)
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/http-methods")
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut finding = MethodsFinding {
        url: url.to_string(),
        allow_header: None,
        results: Vec::new(),
    };

    // OPTIONS request to /
    let opts = client.request(reqwest::Method::OPTIONS, url).send().await?;
    let allow = opts
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    finding.allow_header = allow.clone();

    let listed: std::collections::HashSet<String> = allow
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(|m| m.trim().to_uppercase())
                .filter(|m| !m.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // Probe each dangerous method against a fresh non-existent path
    // (random suffix to avoid hitting cached endpoints).
    let probe_path = format!(
        "{}/__rustymap_probe_{}__",
        url.trim_end_matches('/'),
        std::process::id()
    );
    for &m in DANGEROUS {
        // One probe per method (the old code sent two — wasteful + double
        // side effect). Classify from the single response.
        let probe = send_probe(&client, m, &probe_path).await;
        let status = probe.as_ref().ok().map(|(s, _)| *s);
        let allowed = classify(status, listed.contains(m));
        finding.results.push(MethodResult {
            method: m.to_string(),
            status: status.unwrap_or(0),
            allowed,
        });
    }
    Ok(finding)
}

async fn send_probe(
    client: &reqwest::Client,
    method: &str,
    url: &str,
) -> Result<(u16, String)> {
    let m = reqwest::Method::from_bytes(method.as_bytes())?;
    let resp = client.request(m, url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Ok((status, body))
}

/// Classify a dangerous-method probe. A 2xx is real acceptance; a method
/// advertised in the `Allow` header is a genuine signal even when the probe to
/// a non-existent path is inconclusive; a 3xx is a redirect, NOT acceptance
/// (lab bug N3/4.C flagged a 301 on PUT as critical); 4xx/5xx is a refusal.
fn classify(status: Option<u16>, listed: bool) -> AllowedKind {
    match status {
        Some(s) if (200..300).contains(&s) => AllowedKind::Accepted,
        _ if listed => AllowedKind::Listed,
        Some(s) if (300..400).contains(&s) => AllowedKind::Redirect,
        Some(s) if (400..600).contains(&s) => AllowedKind::Refused,
        _ => AllowedKind::Unknown,
    }
}

pub fn severity(method: &str) -> &'static str {
    match method {
        "PUT" => "critical",
        "DELETE" | "MOVE" | "COPY" => "high",
        "TRACE" | "PROPFIND" | "MKCOL" => "medium",
        _ => "info",
    }
}

/// Risk actually posed, given how the server answered. A method's inherent
/// severity only matters when the server *accepts* it — a PUT that comes
/// back 405/403 (Refused) or 404/422 (inconclusive) is not "critical", it
/// is blocked/rejected (lab bug 4.C: a 422 on PUT was flagged critical).
pub fn effective_severity(method: &str, allowed: AllowedKind) -> &'static str {
    match allowed {
        AllowedKind::Accepted | AllowedKind::Listed => severity(method),
        AllowedKind::Redirect | AllowedKind::Refused | AllowedKind::Unknown => "info",
    }
}

pub fn print_finding(f: &MethodsFinding) {
    use colored::*;
    println!();
    println!("{}", format!("HTTP methods on {}", f.url).bold());
    if let Some(a) = &f.allow_header {
        println!("  Allow header : {}", a);
    } else {
        println!("  Allow header : {}", "(absent)".dimmed());
    }
    for r in &f.results {
        let label = match r.allowed {
            AllowedKind::Accepted => "ACCEPTED".red().bold().to_string(),
            AllowedKind::Listed => "LISTED".yellow().to_string(),
            AllowedKind::Redirect => "REDIRECT".yellow().to_string(),
            AllowedKind::Refused => "REFUSED".green().to_string(),
            AllowedKind::Unknown => "UNKNOWN".dimmed().to_string(),
        };
        let sev = effective_severity(&r.method, r.allowed);
        println!(
            "  {:<10} {:<10} status={:<3} sev={}",
            r.method, label, r.status, sev
        );
    }
    let critical_hit = f.results.iter().any(|r|
        matches!(r.allowed, AllowedKind::Accepted) && severity(&r.method) == "critical");
    if critical_hit {
        println!("  {}", "PUT accepted — potential remote-write / RCE".red().bold());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_classifies_critical_methods() {
        assert_eq!(severity("PUT"), "critical");
        assert_eq!(severity("DELETE"), "high");
        assert_eq!(severity("TRACE"), "medium");
        assert_eq!(severity("PATCH"), "info");
        assert_eq!(severity("GET"), "info");
    }

    #[test]
    fn allow_header_parses_to_uppercase_set() {
        // Reproduces the parsing logic from enumerate()
        let allow = "GET, POST, PUT, options, Trace";
        let listed: std::collections::HashSet<String> = allow
            .split(',')
            .map(|m| m.trim().to_uppercase())
            .filter(|m| !m.is_empty())
            .collect();
        assert!(listed.contains("GET"));
        assert!(listed.contains("OPTIONS"));
        assert!(listed.contains("TRACE"));
        assert!(listed.contains("PUT"));
    }

    #[test]
    fn classify_redirect_is_not_accepted() {
        // lab N3/4.C: a 3xx redirect and a 4xx must never read as Accepted.
        assert_eq!(classify(Some(201), false), AllowedKind::Accepted);
        assert_eq!(classify(Some(301), false), AllowedKind::Redirect);
        assert_eq!(classify(Some(302), false), AllowedKind::Redirect);
        assert_eq!(classify(Some(405), false), AllowedKind::Refused);
        assert_eq!(classify(Some(422), false), AllowedKind::Refused);
        assert_eq!(classify(None, false), AllowedKind::Unknown);
        // Allow-header listing beats an inconclusive/redirect probe; 2xx wins over all.
        assert_eq!(classify(Some(301), true), AllowedKind::Listed);
        assert_eq!(classify(Some(200), true), AllowedKind::Accepted);
    }

    #[test]
    fn redirect_downgrades_effective_severity() {
        assert_eq!(effective_severity("PUT", AllowedKind::Accepted), "critical");
        assert_eq!(effective_severity("PUT", AllowedKind::Redirect), "info");
        assert_eq!(effective_severity("PUT", AllowedKind::Refused), "info");
    }
}
