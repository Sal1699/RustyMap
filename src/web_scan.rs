//! `--web-scan` — a focused modern web attack-surface assessment.
//!
//! A new RustyMap strength: for every open HTTP(S) port it runs one
//! cohesive pass and prints a consolidated report:
//!   - server / framework fingerprint (reuses `web_fp`),
//!   - **security-header grade** (A–F) with the specific gaps,
//!   - **WAF / CDN** detection from headers & cookies,
//!   - **sensitive-path prober** — a curated list of high-value exposures
//!     (`.env`, `.git`, Actuator, Swagger, backups, metrics, admin panels…),
//!   - insecure-cookie flags.
//!
//! HTTP(S) via `reqwest` (rustls) on a blocking thread; self-signed certs
//! are accepted since we're scanning, not trusting. The graders and the
//! path list are pure and unit-tested.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// One sensitive path to probe.
struct SensitivePath {
    path: &'static str,
    severity: &'static str,
    /// Case-insensitive substring that must appear in the body to confirm
    /// it's a real hit (guards against catch-all 200 pages). Empty = any 200.
    marker: &'static str,
    note: &'static str,
}

const SENSITIVE_PATHS: &[SensitivePath] = &[
    SensitivePath { path: "/.env", severity: "critical", marker: "=", note: "environment file — app secrets (DB/API keys)" },
    SensitivePath { path: "/.env.local", severity: "critical", marker: "=", note: "local environment file — app secrets" },
    SensitivePath { path: "/.env.production", severity: "critical", marker: "=", note: "production environment file — app secrets" },
    SensitivePath { path: "/.git/HEAD", severity: "high", marker: "ref:", note: "exposed git repo (source + history)" },
    SensitivePath { path: "/.git/config", severity: "high", marker: "[core]", note: "git config — remotes/credentials" },
    SensitivePath { path: "/.svn/entries", severity: "high", marker: "", note: "exposed SVN working copy" },
    SensitivePath { path: "/.ssh/id_rsa", severity: "critical", marker: "PRIVATE KEY", note: "exposed SSH private key" },
    SensitivePath { path: "/docker-compose.yml", severity: "high", marker: "services:", note: "docker-compose — service topology + secrets" },
    SensitivePath { path: "/actuator/env", severity: "high", marker: "propertySources", note: "Spring Actuator env dump" },
    SensitivePath { path: "/actuator/heapdump", severity: "critical", marker: "", note: "Spring Actuator heap dump — full memory (creds/tokens)" },
    SensitivePath { path: "/actuator/health", severity: "info", marker: "status", note: "Spring Actuator health endpoint" },
    SensitivePath { path: "/server-status", severity: "medium", marker: "Apache Server Status", note: "Apache mod_status info leak" },
    SensitivePath { path: "/metrics", severity: "medium", marker: "# HELP", note: "Prometheus metrics — host/app inventory" },
    SensitivePath { path: "/debug/pprof/", severity: "medium", marker: "pprof", note: "Go pprof debug endpoint" },
    SensitivePath { path: "/_profiler/", severity: "medium", marker: "Symfony", note: "Symfony profiler (requests/env)" },
    SensitivePath { path: "/telescope/requests", severity: "medium", marker: "Telescope", note: "Laravel Telescope (requests/queries)" },
    SensitivePath { path: "/swagger-ui/index.html", severity: "low", marker: "Swagger", note: "API docs (attack-surface map)" },
    SensitivePath { path: "/openapi.json", severity: "low", marker: "openapi", note: "OpenAPI spec" },
    SensitivePath { path: "/graphql", severity: "low", marker: "__schema", note: "GraphQL introspection enabled" },
    SensitivePath { path: "/.well-known/security.txt", severity: "info", marker: "Contact", note: "disclosure policy" },
    SensitivePath { path: "/robots.txt", severity: "info", marker: "Disallow", note: "robots.txt (hidden paths)" },
    SensitivePath { path: "/phpinfo.php", severity: "high", marker: "phpinfo()", note: "phpinfo — full PHP/env disclosure" },
    SensitivePath { path: "/.DS_Store", severity: "low", marker: "Bud1", note: "macOS .DS_Store — filename leak" },
    SensitivePath { path: "/backup.zip", severity: "high", marker: "PK", note: "downloadable backup archive" },
    SensitivePath { path: "/config.json", severity: "medium", marker: "{", note: "exposed config file" },
    SensitivePath { path: "/.aws/credentials", severity: "critical", marker: "aws_access_key", note: "AWS credentials file" },
    SensitivePath { path: "/wp-config.php.bak", severity: "critical", marker: "DB_PASSWORD", note: "WordPress config backup — DB creds" },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exposure {
    pub path: String,
    pub status: u16,
    pub severity: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebScanResult {
    pub port: u16,
    pub scheme: String,
    pub server: Option<String>,
    pub waf: Option<String>,
    pub sec_grade: char,
    pub sec_gaps: Vec<String>,
    pub exposures: Vec<Exposure>,
    pub cookie_issues: Vec<String>,
    /// Dangerous HTTP methods advertised by OPTIONS (PUT/DELETE/TRACE/…). New v0.82.
    #[serde(default)]
    pub risky_methods: Vec<String>,
    /// CORS misconfiguration description, if any. New v0.82.
    #[serde(default)]
    pub cors: Option<String>,
    /// Server returns 200 to random paths (catch-all) — marker-less path hits
    /// were suppressed to avoid false positives (v0.82 bug #6). New v0.82.
    #[serde(default)]
    pub catch_all: bool,
}

/// Grade the response's security headers A–F and list what's missing.
/// (Lowercased header blob in, so matching is case-insensitive.)
pub fn security_header_grade(headers_lower: &str) -> (char, Vec<String>) {
    let checks: &[(&str, &str)] = &[
        ("strict-transport-security", "HSTS (Strict-Transport-Security)"),
        ("content-security-policy", "Content-Security-Policy"),
        ("x-frame-options", "X-Frame-Options (clickjacking)"),
        ("x-content-type-options", "X-Content-Type-Options: nosniff"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
    ];
    let mut gaps = Vec::new();
    for (needle, label) in checks {
        if !headers_lower.contains(needle) {
            gaps.push((*label).to_string());
        }
    }
    let grade = match gaps.len() {
        0 => 'A',
        1 => 'B',
        2 => 'C',
        3 => 'D',
        4 => 'E',
        _ => 'F',
    };
    (grade, gaps)
}

/// Detect a WAF/CDN from headers (lowercased) and body.
pub fn detect_waf(headers_lower: &str, body_lower: &str) -> Option<&'static str> {
    let h = headers_lower;
    if h.contains("cf-ray") || h.contains("server: cloudflare") {
        return Some("Cloudflare");
    }
    if h.contains("x-sucuri-id") || h.contains("x-sucuri-cache") {
        return Some("Sucuri");
    }
    if h.contains("x-iinfo") || h.contains("incap_ses") || h.contains("visid_incap") {
        return Some("Imperva Incapsula");
    }
    if h.contains("akamaighost") || h.contains("x-akamai") {
        return Some("Akamai");
    }
    if h.contains("bigipserver") || h.contains("x-waf-event") {
        return Some("F5 BIG-IP");
    }
    if h.contains("x-amzn-") || h.contains("awselb") || h.contains("x-amz-cf-id") {
        return Some("AWS (ELB/CloudFront/WAF)");
    }
    if h.contains("x-served-by") && h.contains("fastly") {
        return Some("Fastly");
    }
    if h.contains("server: barracuda") || h.contains("barra_counter") {
        return Some("Barracuda");
    }
    if h.contains("mod_security") || h.contains("modsecurity") || body_lower.contains("mod_security") {
        return Some("ModSecurity");
    }
    if body_lower.contains("wordfence") {
        return Some("Wordfence");
    }
    None
}

/// Flag insecure Set-Cookie attributes from a (raw-case) header blob.
pub fn cookie_issues(headers_raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in headers_raw.lines() {
        let l = line.trim();
        if l.len() < 11 || !l[..11].eq_ignore_ascii_case("set-cookie:") {
            continue;
        }
        let ll = l.to_lowercase();
        let name = l[11..].trim().split('=').next().unwrap_or("cookie").trim().to_string();
        let mut missing = Vec::new();
        if !ll.contains("httponly") {
            missing.push("HttpOnly");
        }
        if !ll.contains("secure") {
            missing.push("Secure");
        }
        if !ll.contains("samesite") {
            missing.push("SameSite");
        }
        if !missing.is_empty() {
            out.push(format!("cookie '{}' missing {}", name, missing.join("+")));
        }
    }
    out
}

/// Dangerous HTTP methods present in an `Allow:` / OPTIONS header value.
pub fn dangerous_methods(allow_value: &str) -> Vec<String> {
    let up = allow_value.to_uppercase();
    ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
        .iter()
        .filter(|m| up.contains(**m))
        .map(|m| m.to_string())
        .collect()
}

/// CORS misconfiguration check. We sent `Origin: <probe_origin>`; inspect the
/// reflected `Access-Control-Allow-Origin` (`acao`) and `-Allow-Credentials`
/// (`acac`). Reflecting an arbitrary origin — especially with credentials — is
/// an account-takeover-class bug.
pub fn cors_issue(acao: &str, acac: &str, probe_origin: &str) -> Option<String> {
    let acao = acao.trim();
    let creds = acac.trim().eq_ignore_ascii_case("true");
    if acao == "*" {
        Some(if creds {
            "ACAO '*' WITH credentials (invalid + dangerous)".to_string()
        } else {
            "ACAO '*' (any origin may read responses)".to_string()
        })
    } else if !acao.is_empty() && acao.eq_ignore_ascii_case(probe_origin) {
        Some(if creds {
            format!("reflects arbitrary Origin ({}) WITH credentials — account-takeover risk", probe_origin)
        } else {
            format!("reflects arbitrary Origin ({})", probe_origin)
        })
    } else {
        None
    }
}

/// Blocking HTTP request (any method, optional Origin header) returning
/// (status, header-blob, body). status 0 on error.
fn http_req_blocking(
    url: &str,
    method: reqwest::Method,
    origin: Option<&str>,
    dur: Duration,
) -> (u16, String, String) {
    let client = match reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(dur)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("RustyMap/0.82 web-scan")
        .build()
    {
        Ok(c) => c,
        Err(_) => return (0, String::new(), String::new()),
    };
    let mut req = client.request(method, url);
    if let Some(o) = origin {
        req = req.header("Origin", o);
    }
    match req.send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let mut hdr = String::new();
            for (k, v) in resp.headers().iter() {
                hdr.push_str(k.as_str());
                hdr.push_str(": ");
                hdr.push_str(v.to_str().unwrap_or(""));
                hdr.push('\n');
            }
            let body = resp.text().unwrap_or_default();
            (status, hdr, body)
        }
        Err(_) => (0, String::new(), String::new()),
    }
}

/// Blocking HTTP GET returning (status, header-blob, body). status 0 on error.
fn http_get_blocking(url: &str, dur: Duration) -> (u16, String, String) {
    http_req_blocking(url, reqwest::Method::GET, None, dur)
}

/// Pull one header's value (case-insensitive) out of a `\n`-joined blob.
fn header_value(headers_lower: &str, name: &str) -> String {
    for line in headers_lower.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == name {
                return v.trim().to_string();
            }
        }
    }
    String::new()
}

/// Assess one web port. `sni` is the hostname for TLS + Host header.
pub async fn scan_port(ip: IpAddr, port: u16, sni: Option<String>, dur: Duration) -> Option<WebScanResult> {
    let scheme = if matches!(port, 443 | 8443 | 9443 | 4443) { "https" } else { "http" };
    let host = sni.clone().unwrap_or_else(|| ip.to_string());
    let base = format!("{}://{}:{}", scheme, host, port);

    // Landing page for headers / fingerprint / WAF.
    let base_c = base.clone();
    let (status, headers, body) =
        tokio::task::spawn_blocking(move || http_get_blocking(&format!("{}/", base_c), dur))
            .await
            .ok()?;
    if status == 0 {
        return None;
    }
    let hlow = headers.to_lowercase();
    let blow = body.to_lowercase();

    let server = headers
        .lines()
        .find(|l| l.to_lowercase().starts_with("server:"))
        .map(|l| l[7..].trim().to_string());
    let waf = detect_waf(&hlow, &blow).map(String::from);
    let (grade, gaps) = security_header_grade(&hlow);
    let cookie_issues = cookie_issues(&headers);

    // Soft-404 baseline (v0.82 bug #6): request a random path that should 404.
    // If it returns 200 the server is a catch-all (e.g. a router that answers
    // 200 to everything) — then marker-less path hits are suppressed so we
    // don't report phantom `.env`/`backup.zip` exposures.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let rand_path = format!("/rustymap-{:x}-notfound.xyz", nonce);
    let base_b = base.clone();
    let (bl_status, _bh, bl_body) =
        tokio::task::spawn_blocking(move || http_get_blocking(&format!("{}{}", base_b, rand_path), dur))
            .await
            .ok()?;
    let catch_all = bl_status == 200;
    let baseline_len = bl_body.len();

    // OPTIONS → advertised methods; flag dangerous ones (PUT/DELETE/TRACE/…).
    let base_o = base.clone();
    let (_os, ohdr, _ob) = tokio::task::spawn_blocking(move || {
        http_req_blocking(&format!("{}/", base_o), reqwest::Method::OPTIONS, None, dur)
    })
    .await
    .ok()?;
    let risky_methods = dangerous_methods(&header_value(&ohdr.to_lowercase(), "allow"));

    // CORS: does the app reflect an arbitrary Origin (optionally with creds)?
    const CORS_PROBE: &str = "https://rustymap-cors-probe.example";
    let base_cr = base.clone();
    let (_cs, chdr, _cb) = tokio::task::spawn_blocking(move || {
        http_req_blocking(&format!("{}/", base_cr), reqwest::Method::GET, Some(CORS_PROBE), dur)
    })
    .await
    .ok()?;
    let chl = chdr.to_lowercase();
    let cors = cors_issue(
        &header_value(&chl, "access-control-allow-origin"),
        &header_value(&chl, "access-control-allow-credentials"),
        CORS_PROBE,
    );

    // Sensitive-path prober (bounded, sequential to stay polite).
    let mut exposures = Vec::new();
    for sp in SENSITIVE_PATHS {
        let url = format!("{}{}", base, sp.path);
        let (st, _h, b) =
            tokio::task::spawn_blocking(move || http_get_blocking(&url, dur)).await.ok()?;
        if st != 200 {
            continue;
        }
        let hit = if !sp.marker.is_empty() {
            b.to_lowercase().contains(&sp.marker.to_lowercase())
        } else {
            // No content marker: trust only when the server isn't a catch-all
            // and the body differs meaningfully from the soft-404 baseline.
            !catch_all && b.len().abs_diff(baseline_len) > 64
        };
        if hit {
            exposures.push(Exposure {
                path: sp.path.to_string(),
                status: st,
                severity: sp.severity.to_string(),
                note: sp.note.to_string(),
            });
        }
    }

    Some(WebScanResult {
        port,
        scheme: scheme.to_string(),
        server,
        waf,
        sec_grade: grade,
        sec_gaps: gaps,
        exposures,
        cookie_issues,
        risky_methods,
        cors,
        catch_all,
    })
}

pub fn print_report(host: &str, results: &[WebScanResult]) {
    use colored::*;
    println!();
    println!("{}", format!("Web scan of {}", host).bold());
    if results.is_empty() {
        println!("  {}", "no reachable HTTP(S) service".dimmed());
        return;
    }
    for r in results {
        println!();
        println!("  {}://{}:{}", r.scheme, host, r.port);
        if let Some(s) = &r.server {
            println!("    Server        : {}", s);
        }
        if let Some(w) = &r.waf {
            println!("    WAF/CDN       : {}", w.yellow());
        }
        let g = format!("{}", r.sec_grade);
        let gc = match r.sec_grade {
            'A' => g.green(),
            'B' | 'C' => g.yellow(),
            _ => g.red(),
        };
        println!("    Sec-headers   : grade {}{}", gc, if r.sec_gaps.is_empty() { String::new() } else { format!(" (missing: {})", r.sec_gaps.join(", ")) });
        for c in &r.cookie_issues {
            println!("    {} {}", "cookie:".dimmed(), c.yellow());
        }
        if !r.risky_methods.is_empty() {
            println!("    HTTP methods  : {}", r.risky_methods.join(", ").yellow());
        }
        if let Some(c) = &r.cors {
            println!("    CORS          : {}", c.red());
        }
        if r.catch_all {
            println!("    {}", "note: server answers 200 to random paths (catch-all) — marker-less path hits suppressed".dimmed());
        }
        for e in &r.exposures {
            let line = format!("    [{}] {} — {} (HTTP {})", e.severity, e.path, e.note, e.status);
            match e.severity.as_str() {
                "critical" | "high" => println!("{}", line.red()),
                "medium" => println!("{}", line.yellow()),
                _ => println!("{}", line),
            }
        }
        if r.exposures.is_empty() {
            println!("    {}", "no sensitive paths exposed".dimmed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_a_when_all_present() {
        let h = "strict-transport-security: max-age=31536000\ncontent-security-policy: default-src 'self'\nx-frame-options: DENY\nx-content-type-options: nosniff\nreferrer-policy: no-referrer\npermissions-policy: geolocation=()\n";
        let (g, gaps) = security_header_grade(h);
        assert_eq!(g, 'A');
        assert!(gaps.is_empty());
    }

    #[test]
    fn grade_f_when_none() {
        let (g, gaps) = security_header_grade("server: nginx\n");
        assert_eq!(g, 'F');
        assert_eq!(gaps.len(), 6);
    }

    #[test]
    fn waf_detection() {
        assert_eq!(detect_waf("cf-ray: abc\nserver: cloudflare\n", ""), Some("Cloudflare"));
        assert_eq!(detect_waf("x-sucuri-id: 1\n", ""), Some("Sucuri"));
        assert_eq!(detect_waf("server: nginx\n", ""), None);
        assert_eq!(detect_waf("server: awselb/2.0\n", ""), Some("AWS (ELB/CloudFront/WAF)"));
    }

    #[test]
    fn cookie_flags_flagged() {
        let issues = cookie_issues("Set-Cookie: sid=abc; Path=/\nSet-Cookie: ok=1; Secure; HttpOnly; SameSite=Lax\n");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("sid"));
        assert!(issues[0].contains("HttpOnly"));
    }

    #[test]
    fn path_list_has_high_value_targets() {
        assert!(SENSITIVE_PATHS.iter().any(|s| s.path == "/.env" && s.severity == "critical"));
        assert!(SENSITIVE_PATHS.iter().any(|s| s.path == "/.git/HEAD"));
        // v0.82: the two previously marker-less (FP-prone) paths now have markers.
        assert!(SENSITIVE_PATHS.iter().all(|s| !(s.path == "/backup.zip" && s.marker.is_empty())));
        assert!(SENSITIVE_PATHS.iter().any(|s| s.path == "/actuator/heapdump" && s.severity == "critical"));
    }

    #[test]
    fn dangerous_methods_detected() {
        let m = dangerous_methods("GET, HEAD, POST, PUT, DELETE, OPTIONS");
        assert!(m.contains(&"PUT".to_string()));
        assert!(m.contains(&"DELETE".to_string()));
        assert!(!m.contains(&"GET".to_string()));
        assert!(dangerous_methods("GET, POST, HEAD").is_empty());
    }

    #[test]
    fn cors_wildcard_and_reflection() {
        assert_eq!(cors_issue("*", "", "https://evil.example"), Some("ACAO '*' (any origin may read responses)".to_string()));
        assert!(cors_issue("*", "true", "https://evil.example").unwrap().contains("WITH credentials"));
        assert!(cors_issue("https://evil.example", "true", "https://evil.example").unwrap().contains("account-takeover"));
        assert_eq!(cors_issue("https://trusted.app", "true", "https://evil.example"), None);
        assert_eq!(cors_issue("", "", "https://evil.example"), None);
    }

    #[test]
    fn header_value_case_insensitive_lookup() {
        let blob = "server: nginx\naccess-control-allow-origin: *\n";
        assert_eq!(header_value(blob, "access-control-allow-origin"), "*");
        assert_eq!(header_value(blob, "missing"), "");
    }
}
