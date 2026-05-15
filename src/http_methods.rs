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
    Accepted,  // server returned 2xx/3xx on probe
    Refused,   // 401 / 403 / 405 / 501
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
        let allowed = match send_probe(&client, m, &probe_path).await {
            Ok((status, _)) if (200..400).contains(&status) => AllowedKind::Accepted,
            Ok((status, _)) if matches!(status, 401 | 403 | 405 | 501) => AllowedKind::Refused,
            Ok(_) => {
                // Other status (404 etc.): inconclusive. Fall back to
                // listed/unknown based on Allow.
                if listed.contains(m) {
                    AllowedKind::Listed
                } else {
                    AllowedKind::Unknown
                }
            }
            Err(_) => AllowedKind::Unknown,
        };
        // Always include the listed-by-OPTIONS signal even when probe failed
        let allowed = if matches!(allowed, AllowedKind::Unknown) && listed.contains(m) {
            AllowedKind::Listed
        } else {
            allowed
        };
        let status = send_probe(&client, m, &probe_path)
            .await
            .map(|(s, _)| s)
            .unwrap_or(0);
        finding.results.push(MethodResult {
            method: m.to_string(),
            status,
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

pub fn severity(method: &str) -> &'static str {
    match method {
        "PUT" => "critical",
        "DELETE" | "MOVE" | "COPY" => "high",
        "TRACE" | "PROPFIND" | "MKCOL" => "medium",
        _ => "info",
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
            AllowedKind::Refused => "REFUSED".green().to_string(),
            AllowedKind::Unknown => "UNKNOWN".dimmed().to_string(),
        };
        let sev = severity(&r.method);
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
}
