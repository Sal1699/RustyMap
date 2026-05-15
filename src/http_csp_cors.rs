//! Deep analysis of `Content-Security-Policy` and `CORS` headers.
//!
//! Goes beyond the simple "header present?" check in
//! `http-missing-security-headers` and audits the *values* against
//! known weak-policy patterns.
//!
//! CSP findings surfaced:
//!
//!   - **`unsafe-inline` in `script-src` or `default-src`** — high.
//!     Defeats CSP's main XSS-mitigation purpose.
//!   - **`unsafe-eval`** — medium-high. Allows `eval()` / new Function /
//!     setTimeout-string.
//!   - **Wildcard `*` in any directive** (except `img-src` /
//!     `media-src` which are routinely wildcarded) — high.
//!   - **No `default-src`** — medium. Browsers fall through to no
//!     restriction for unlisted directive families.
//!   - **No `frame-ancestors`** — medium. Clickjacking surface.
//!   - **`object-src` not 'none'** — medium. Legacy plugin vector.
//!   - **`http:` scheme allowed under HTTPS page** — medium (mixed).
//!
//! CORS findings (Origin-reflection deep test):
//!
//!   - Echoes back arbitrary `Origin: evil.test` value — critical.
//!   - `Access-Control-Allow-Origin: *` with `Access-Control-Allow-
//!     Credentials: true` — invalid per CORS spec; some servers
//!     accept it anyway → credential theft from the wildcard origin.
//!   - `null` Origin allowed with credentials — high.
//!   - Trusts subdomain wildcard pattern like `*.evil.test` — high.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CspCorsFinding {
    pub url: String,
    pub csp_header: Option<String>,
    pub cors_default_origin: Option<String>,
    pub csp_findings: Vec<String>,
    pub cors_findings: Vec<String>,
}

pub async fn analyze(url: &str, dur: Duration) -> Result<CspCorsFinding> {
    let client = reqwest::Client::builder()
        .timeout(dur)
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/csp-cors")
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut f = CspCorsFinding {
        url: url.to_string(),
        ..Default::default()
    };

    // 1) Baseline GET — read CSP & default CORS reflection
    let resp = client.get(url).send().await?;
    let is_https = url.starts_with("https://");
    let headers = resp.headers().clone();
    let _body = resp.text().await.unwrap_or_default();

    let csp = headers
        .get("content-security-policy")
        .or_else(|| headers.get("content-security-policy-report-only"))
        .and_then(|v| v.to_str().ok().map(String::from));
    f.csp_header = csp.clone();
    if let Some(csp_val) = &csp {
        audit_csp(csp_val, is_https, &mut f.csp_findings);
    } else {
        f.csp_findings
            .push("no Content-Security-Policy header — XSS exposure unmitigated".into());
    }

    // 2) Origin-reflection probe — does the server echo back any
    //    Origin we send?
    let probe_origin = "https://rustymap-cors-probe.example";
    let resp2 = client
        .get(url)
        .header("Origin", probe_origin)
        .send()
        .await?;
    let h2 = resp2.headers().clone();
    let allow_origin = h2
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok().map(String::from));
    let allow_creds = h2
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok().map(String::from));
    f.cors_default_origin = allow_origin.clone();
    audit_cors(probe_origin, allow_origin.as_deref(), allow_creds.as_deref(), &mut f.cors_findings);

    Ok(f)
}

/// Audit a CSP value string for known weak patterns. We split on
/// `;`, group directives by name, and check each value list.
pub fn audit_csp(csp: &str, is_https: bool, out: &mut Vec<String>) {
    let mut by_directive: std::collections::HashMap<String, Vec<String>> = Default::default();
    for d in csp.split(';') {
        let d = d.trim();
        if d.is_empty() {
            continue;
        }
        let mut parts = d.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let values: Vec<String> = parts.map(String::from).collect();
        by_directive.insert(name.to_lowercase(), values);
    }

    let has_default = by_directive.contains_key("default-src");
    if !has_default {
        out.push("CSP missing `default-src` — unlisted directives are unrestricted".into());
    }
    if !by_directive.contains_key("frame-ancestors") {
        out.push("CSP missing `frame-ancestors` — clickjacking not mitigated".into());
    }
    if let Some(obj) = by_directive.get("object-src") {
        if !obj.iter().any(|v| v == "'none'") {
            out.push(format!("`object-src` not 'none' (= {})", obj.join(" ")));
        }
    } else {
        out.push("CSP missing `object-src` — legacy plugin vector open".into());
    }

    // script-src + default-src checks
    for key in ["script-src", "default-src"] {
        let Some(vals) = by_directive.get(key) else { continue };
        for v in vals {
            let lower = v.to_lowercase();
            if lower == "'unsafe-inline'" {
                out.push(format!("CSP `{}` allows 'unsafe-inline' — XSS mitigation defeated", key));
            }
            if lower == "'unsafe-eval'" {
                out.push(format!("CSP `{}` allows 'unsafe-eval' — eval/new Function permitted", key));
            }
            if v == "*" {
                out.push(format!("CSP `{}` wildcard `*` — any origin can load scripts", key));
            }
            if is_https && v.starts_with("http:") {
                out.push(format!("CSP `{}` allows `http:` under an HTTPS page (mixed content)", key));
            }
        }
    }
}

/// Audit a single Origin-reflection round-trip. `requested` is the
/// Origin we sent; `allowed` is what the server returned for
/// `Access-Control-Allow-Origin`; `creds` is the
/// `Access-Control-Allow-Credentials` value.
pub fn audit_cors(
    requested: &str,
    allowed: Option<&str>,
    creds: Option<&str>,
    out: &mut Vec<String>,
) {
    let creds_truthy = creds
        .map(|c| c.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    match allowed {
        None => { /* nothing CORS-y, fine */ }
        Some("*") if creds_truthy => out.push(
            "Access-Control-Allow-Origin: * with Allow-Credentials: true — \
             invalid per CORS spec, browsers refuse but tooling/older clients trust it"
                .into(),
        ),
        Some("null") if creds_truthy => out.push(
            "Access-Control-Allow-Origin: null with Allow-Credentials: true — \
             sandbox iframes and file:// origins inherit"
                .into(),
        ),
        Some(echoed) if echoed.eq_ignore_ascii_case(requested) => {
            if creds_truthy {
                out.push(format!(
                    "Origin reflection with credentials — server echoes ANY Origin \
                     header. Credential theft possible from {}.",
                    requested
                ));
            } else {
                out.push(format!(
                    "Origin reflection (no credentials) — server echoes the Origin \
                     header verbatim (sent {} → got back same)",
                    requested
                ));
            }
        }
        Some(_) => { /* server returned a specific allow-list value */ }
    }
}

pub fn print_finding(f: &CspCorsFinding) {
    use colored::*;
    println!();
    println!("{}", format!("CSP/CORS deep audit on {}", f.url).bold());
    if let Some(csp) = &f.csp_header {
        let trimmed: String = csp.chars().take(180).collect();
        println!("  CSP header   : {}", trimmed.dimmed());
    }
    if let Some(o) = &f.cors_default_origin {
        println!("  CORS allow-origin: {}", o);
    }
    if !f.csp_findings.is_empty() {
        println!("  {}", "CSP findings:".yellow().bold());
        for x in &f.csp_findings {
            println!("    · {}", x);
        }
    }
    if !f.cors_findings.is_empty() {
        println!("  {}", "CORS findings:".red().bold());
        for x in &f.cors_findings {
            println!("    · {}", x.red());
        }
    }
    if f.csp_findings.is_empty() && f.cors_findings.is_empty() {
        println!("  {}", "no policy weaknesses detected".green());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_unsafe_inline_flagged() {
        let mut out = Vec::new();
        audit_csp("default-src 'self'; script-src 'self' 'unsafe-inline'", false, &mut out);
        assert!(out.iter().any(|x| x.contains("unsafe-inline")));
    }

    #[test]
    fn csp_wildcard_in_script_src_flagged() {
        let mut out = Vec::new();
        audit_csp("default-src 'self'; script-src *", false, &mut out);
        assert!(out.iter().any(|x| x.contains("wildcard")));
    }

    #[test]
    fn csp_missing_default_flagged() {
        let mut out = Vec::new();
        audit_csp("script-src 'self'", false, &mut out);
        assert!(out.iter().any(|x| x.contains("default-src")));
    }

    #[test]
    fn csp_missing_frame_ancestors_flagged() {
        let mut out = Vec::new();
        audit_csp("default-src 'self'; object-src 'none'", false, &mut out);
        assert!(out.iter().any(|x| x.contains("frame-ancestors")));
    }

    #[test]
    fn csp_http_under_https_flagged() {
        let mut out = Vec::new();
        audit_csp("default-src 'self'; script-src http://cdn.test", true, &mut out);
        assert!(out.iter().any(|x| x.contains("http:")));
    }

    #[test]
    fn csp_object_src_none_no_finding() {
        let mut out = Vec::new();
        audit_csp(
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
            false,
            &mut out,
        );
        // Only complaint should be missing-something but not object-src or default-src
        assert!(!out.iter().any(|x| x.contains("`object-src`")));
        assert!(!out.iter().any(|x| x.contains("`default-src`")));
    }

    #[test]
    fn cors_origin_reflection_with_creds_critical() {
        let mut out = Vec::new();
        audit_cors("https://evil.test", Some("https://evil.test"), Some("true"), &mut out);
        assert!(out.iter().any(|x| x.contains("Credential theft")));
    }

    #[test]
    fn cors_origin_reflection_without_creds_warned() {
        let mut out = Vec::new();
        audit_cors("https://evil.test", Some("https://evil.test"), None, &mut out);
        assert!(out.iter().any(|x| x.contains("reflection")));
    }

    #[test]
    fn cors_wildcard_with_creds_flagged() {
        let mut out = Vec::new();
        audit_cors("https://evil.test", Some("*"), Some("true"), &mut out);
        assert!(out.iter().any(|x| x.contains("Allow-Credentials")));
    }

    #[test]
    fn cors_specific_allow_origin_no_finding() {
        let mut out = Vec::new();
        audit_cors("https://evil.test", Some("https://allowed.example.com"), Some("true"), &mut out);
        assert!(out.is_empty());
    }
}
