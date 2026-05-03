//! HTTP path enumeration — gobuster-light built into the scanner.
//!
//! After a `--sV` scan finds an open HTTP port, this module GETs a
//! curated list of common-but-sensitive paths and flags every
//! 200/301/302/401/403 response. Two improvements over the typical
//! tool:
//!   1. Per-status classification (a 401 on /admin is more
//!      interesting than a 200 on /);
//!   2. Stops on persistent 4xx/5xx walls — many wifi captive
//!      portals return the same page for every path, which would
//!      otherwise produce 100 false positives.

use crate::scanner::{HostResult, PortState};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

/// Curated path list. Targets:
///   - Backup/config leaks (.git, .env, .DS_Store, web.config)
///   - Admin surfaces (admin, manager, phpMyAdmin, wp-admin)
///   - Framework defaults (actuator, swagger, console, _next)
///   - Cloud metadata that shouldn't be reachable from outside
///     (kept defensively even though it would only fire from a
///     compromised host — useful for SSRF audits)
const PATHS: &[&str] = &[
    "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/admin", "/admin/", "/admin/login", "/administrator/",
    "/login", "/login.php", "/wp-admin/", "/wp-login.php",
    "/manager/", "/manager/html", "/host-manager/",
    "/phpmyadmin/", "/pma/", "/phpMyAdmin/",
    "/server-status", "/server-info",
    "/.git/HEAD", "/.git/config", "/.gitignore", "/.svn/entries",
    "/.env", "/.env.local", "/.env.production", "/.env.dev",
    "/.DS_Store", "/web.config", "/composer.json", "/package.json",
    "/swagger.json", "/swagger-ui.html", "/swagger/", "/openapi.json",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/heapdump",
    "/api/", "/api/v1/", "/api/v2/", "/graphql", "/graphiql",
    "/console", "/console/", "/console/login", "/h2-console/",
    "/.kube/config", "/config.json", "/config.yml", "/settings.py",
    "/_next/static/", "/_nuxt/", "/__webpack_dev_server__/",
    "/jenkins/", "/gitea/", "/git/", "/forgejo/",
    "/grafana/login", "/prometheus/", "/kibana/",
    "/airflow/login", "/superset/login",
    "/portainer/", "/rancher/",
    "/.aws/credentials", "/.ssh/id_rsa", "/.bash_history",
    "/wp-content/uploads/", "/wp-json/wp/v2/users",
    "/owa/", "/ecp/", "/autodiscover/autodiscover.xml",
    "/citrix/", "/vpn/", "/remote/login",
];

#[derive(Debug, Clone)]
pub struct HttpFinding {
    pub url: String,
    pub status: u16,
    pub size: usize,
    pub note: &'static str,
}

fn classify(status: u16, path: &str) -> Option<&'static str> {
    match status {
        200 | 301 | 302 => match path {
            "/" => None, // boring
            p if p.contains(".git") || p.contains(".env") || p.contains(".aws") || p.contains(".ssh") => {
                Some("possible source/config leak")
            }
            p if p.contains("admin") || p.contains("manager") || p.contains("login") => {
                Some("admin surface")
            }
            p if p.contains("swagger") || p.contains("openapi") || p.contains("actuator") => {
                Some("API surface — verify auth")
            }
            p if p.contains("phpmyadmin") || p.contains("pma") => Some("phpMyAdmin"),
            p if p.contains("server-status") || p.contains("server-info") => Some("Apache info leak"),
            p if p.contains("autodiscover") || p.contains("/owa") || p.contains("/ecp") => {
                Some("Exchange surface")
            }
            _ => Some("reachable"),
        },
        401 | 403 => Some("auth-protected (worth follow-up)"),
        500..=599 => Some("server error — possible misconfig"),
        _ => None,
    }
}

/// Run the path enum against a single host's open HTTP ports.
/// Returns one finding per interesting response. Empty when nothing
/// stood out.
pub async fn scan_host(host: &HostResult, timeout_per_req: Duration) -> Result<Vec<HttpFinding>> {
    let mut out = Vec::new();
    let client = Client::builder()
        .timeout(timeout_per_req)
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/http-enum")
        .redirect(reqwest::redirect::Policy::none()) // we want to see 301/302 explicitly
        .build()?;

    let http_ports: Vec<u16> = host
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .filter(|p| matches!(p.port, 80 | 81 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888 | 9000 | 443))
        .map(|p| p.port)
        .collect();

    let host_str = host
        .target
        .hostname
        .clone()
        .unwrap_or_else(|| host.target.ip.to_string());

    for port in http_ports {
        let scheme = if port == 443 || port == 8443 { "https" } else { "http" };
        let base = format!("{}://{}:{}", scheme, host_str, port);

        // Wall-detection: if 5+ consecutive responses share the same
        // (status, length), assume captive portal / catch-all and stop.
        let mut wall: Option<(u16, usize)> = None;
        let mut wall_count: u32 = 0;
        const WALL_THRESHOLD: u32 = 5;

        for path in PATHS {
            let url = format!("{}{}", base, path);
            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let status = resp.status().as_u16();
            let body = resp.bytes().await.ok();
            let size = body.as_ref().map(|b| b.len()).unwrap_or(0);

            if let Some((w_status, w_size)) = wall {
                if w_status == status && (size as i64 - w_size as i64).abs() < 16 {
                    wall_count += 1;
                    if wall_count >= WALL_THRESHOLD {
                        out.push(HttpFinding {
                            url: format!("{}{}", base, "(suppressed: wall detected)"),
                            status,
                            size,
                            note: "stopped: same response shape repeats — likely captive portal",
                        });
                        break;
                    }
                    continue;
                }
            }
            wall = Some((status, size));
            wall_count = 0;

            if let Some(note) = classify(status, path) {
                out.push(HttpFinding {
                    url,
                    status,
                    size,
                    note,
                });
            }
        }
    }
    Ok(out)
}

pub fn print_findings(host_label: &str, findings: &[HttpFinding]) {
    use colored::*;
    if findings.is_empty() {
        return;
    }
    println!("\n-- HTTP enum: {} --", host_label.bold());
    for f in findings {
        let status_color = match f.status {
            200 | 301 | 302 => f.status.to_string().green(),
            401 | 403 => f.status.to_string().yellow(),
            500..=599 => f.status.to_string().red(),
            _ => f.status.to_string().normal(),
        };
        println!("  [{:>3}] {:<60} {} ({} bytes)", status_color, f.url, f.note.dimmed(), f.size);
    }
}
