//! Fase 33 — modern web-scan helpers: deeper Content-Security-Policy / COOP /
//! COEP analysis, endpoint discovery from HTML/JS, leaked-secret detection in
//! page bodies, and reflection checks for SSTI / open-redirect probes. These
//! are pure functions (no I/O) so they are unit-tested here; `web_scan` feeds
//! them the fetched landing page.

use once_cell::sync::Lazy;
use regex::Regex;

/// Analyse the (lowercased) response headers for CSP / cross-origin isolation
/// weaknesses. Returns a list of human-readable issues; empty = looks fine.
pub fn analyze_csp(headers_lower: &str) -> Vec<String> {
    let mut out = Vec::new();
    let csp = header_value(headers_lower, "content-security-policy");
    match csp {
        None => out.push("no Content-Security-Policy".into()),
        Some(v) => {
            if v.contains("unsafe-inline") {
                out.push("CSP allows 'unsafe-inline' (XSS mitigation weakened)".into());
            }
            if v.contains("unsafe-eval") {
                out.push("CSP allows 'unsafe-eval'".into());
            }
            // A bare `*` (not `*.example.com`) in default/script-src is wide open.
            if Regex::new(r"(?:default-src|script-src)[^;]*\s\*(?:\s|;|$)")
                .unwrap()
                .is_match(&v)
            {
                out.push("CSP uses a wildcard (*) source".into());
            }
            if v.contains("script-src") && v.contains(" data:") {
                out.push("CSP permits data: script sources".into());
            }
            if !v.contains("frame-ancestors") {
                out.push("CSP has no frame-ancestors (clickjacking)".into());
            }
        }
    }
    if header_value(headers_lower, "cross-origin-opener-policy").is_none() {
        out.push("no Cross-Origin-Opener-Policy (COOP)".into());
    }
    if header_value(headers_lower, "cross-origin-embedder-policy").is_none() {
        out.push("no Cross-Origin-Embedder-Policy (COEP)".into());
    }
    out
}

fn header_value(headers_lower: &str, name: &str) -> Option<String> {
    for line in headers_lower.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

static RE_QUOTED_PATH: Lazy<Regex> = Lazy::new(|| {
    // "…/path" or 'https://…' string literals in HTML/JS.
    Regex::new(r#"["'](/[A-Za-z0-9_\-./]{2,}|https?://[^"'\s>]{4,})["']"#).unwrap()
});
static RE_FETCH: Lazy<Regex> = Lazy::new(|| {
    // fetch("…"), axios.get("…"), xhr.open("GET","…").
    Regex::new(r#"(?:fetch|axios\.\w+|\.open)\(\s*(?:["'][A-Z]+["']\s*,\s*)?["']([^"']+)["']"#)
        .unwrap()
});

/// Extract candidate endpoints / API paths from an HTML or JS body. Deduplicated
/// and capped; biased toward API-looking paths (containing `/`).
pub fn extract_endpoints(body: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    for cap in RE_QUOTED_PATH.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            push_endpoint(&mut seen, m.as_str());
        }
    }
    for cap in RE_FETCH.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            push_endpoint(&mut seen, m.as_str());
        }
    }
    seen.into_iter().take(40).collect()
}

fn push_endpoint(seen: &mut std::collections::BTreeSet<String>, raw: &str) {
    let s = raw.trim();
    // Skip static assets and noise; keep API/route-looking paths.
    let lower = s.to_lowercase();
    let is_asset = lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".gif")
        || lower.ends_with(".svg")
        || lower.ends_with(".css")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".ico");
    if is_asset || s.len() > 200 {
        return;
    }
    if s.starts_with('/') || s.starts_with("http") {
        seen.insert(s.to_string());
    }
}

/// Look for leaked secrets (API keys, tokens, private keys) in a page body,
/// reusing the shared mobile/web secret-pattern matcher. Returns pattern labels.
pub fn secrets_in_body(body: &str) -> Vec<String> {
    crate::mobile_secrets::scan_bytes("web", body.as_bytes())
        .into_iter()
        .map(|f| f.pattern)
        .collect()
}

/// SSTI reflection check: did a `7*7`-style probe get evaluated to `49` in the
/// response (and not merely echoed back as the literal expression)? Reserved
/// for the active-probe pass (the detection logic is unit-tested here).
#[allow(dead_code)]
pub fn ssti_reflected(body: &str, probe: &str) -> bool {
    body.contains("49") && !body.contains(probe)
}

/// Open-redirect check: does the `Location` header send the client to the
/// attacker-controlled host we injected? Reserved for the active-probe pass
/// (the detection logic is unit-tested here).
#[allow(dead_code)]
pub fn open_redirect_vulnerable(location: &str, payload_host: &str) -> bool {
    let l = location.trim().to_lowercase();
    let p = payload_host.to_lowercase();
    l.starts_with(&format!("http://{}", p))
        || l.starts_with(&format!("https://{}", p))
        || l.starts_with(&format!("//{}", p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_flags_unsafe_inline_and_missing_coop() {
        let h = "content-security-policy: default-src 'self' 'unsafe-inline'\r\n";
        let issues = analyze_csp(h);
        assert!(issues.iter().any(|i| i.contains("unsafe-inline")));
        assert!(issues.iter().any(|i| i.contains("COOP")));
        assert!(issues.iter().any(|i| i.contains("frame-ancestors")));
    }

    #[test]
    fn csp_missing_entirely() {
        let issues = analyze_csp("server: nginx\r\n");
        assert!(issues.iter().any(|i| i.contains("no Content-Security-Policy")));
    }

    #[test]
    fn csp_wildcard_flagged() {
        let h = "content-security-policy: default-src * ; frame-ancestors 'none'\r\ncross-origin-opener-policy: same-origin\r\ncross-origin-embedder-policy: require-corp\r\n";
        let issues = analyze_csp(h);
        assert!(issues.iter().any(|i| i.contains("wildcard")));
        // COOP/COEP present → not flagged.
        assert!(!issues.iter().any(|i| i.contains("COOP")));
    }

    #[test]
    fn endpoints_extracted_and_assets_skipped() {
        let body = r#"<a href="/admin/login">x</a><script>fetch("/api/v1/users");var i="/img/logo.png";</script>"#;
        let eps = extract_endpoints(body);
        assert!(eps.contains(&"/admin/login".to_string()));
        assert!(eps.contains(&"/api/v1/users".to_string()));
        assert!(!eps.iter().any(|e| e.ends_with(".png")));
    }

    #[test]
    fn ssti_reflection_logic() {
        // Evaluated (49 present, raw expression gone) → vulnerable.
        assert!(ssti_reflected("result is 49 here", "${7*7}"));
        // Echoed back literally → not a hit.
        assert!(!ssti_reflected("you sent ${7*7}", "${7*7}"));
    }

    #[test]
    fn open_redirect_logic() {
        assert!(open_redirect_vulnerable("http://evil.example/", "evil.example"));
        assert!(open_redirect_vulnerable("//evil.example/x", "evil.example"));
        assert!(!open_redirect_vulnerable("/local/path", "evil.example"));
    }
}
