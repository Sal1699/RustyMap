//! Executive summary auto-generator.
//!
//! Distils a `[HostResult]` slice into a one-paragraph narrative plus
//! a handful of headline numbers a non-technical reader can act on:
//!
//!   - Hosts up / total scanned and how long it took.
//!   - Total open ports and the top services exposed (sorted by
//!     count, top 5).
//!   - The most-exposed host (highest open-port count).
//!   - High-value-port flags (RDP / SMB / SSH / database ports
//!     reachable from the scan vantage point).
//!
//! Two render targets:
//!   - `render_text` — plain wrapped text for the terminal.
//!   - `render_markdown` — same content in MD, suitable to prepend
//!     to the existing `--oH` / `--oMd` reports.
//!
//! Pure function — no IO, no globals — so the report builders can
//! call it inline without ordering concerns.

use crate::scanner::{HostResult, PortState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub hosts_total: usize,
    pub hosts_up: usize,
    pub elapsed_secs: f64,
    pub open_ports_total: usize,
    pub top_services: Vec<(String, usize)>,
    pub most_exposed_host: Option<(String, usize)>,
    pub sensitive_exposures: Vec<String>,
}

/// (port, label, severity-tier 0=info 1=warn 2=high)
const SENSITIVE_PORTS: &[(u16, &str, u8)] = &[
    (22, "SSH", 0),
    (23, "Telnet (cleartext)", 2),
    (25, "SMTP", 0),
    (53, "DNS", 0),
    (80, "HTTP", 0),
    (110, "POP3 (cleartext)", 2),
    (139, "NetBIOS", 1),
    (143, "IMAP (cleartext)", 2),
    (389, "LDAP", 1),
    (443, "HTTPS", 0),
    (445, "SMB", 1),
    (1433, "MSSQL", 2),
    (1521, "Oracle DB", 2),
    (2375, "Docker API (no TLS)", 2),
    (2376, "Docker API (TLS)", 1),
    (3306, "MySQL", 2),
    (3389, "RDP", 2),
    (5432, "PostgreSQL", 2),
    (5900, "VNC", 2),
    (5985, "WinRM HTTP", 2),
    (5986, "WinRM HTTPS", 1),
    (6379, "Redis", 2),
    (8080, "HTTP-alt", 0),
    (9200, "Elasticsearch", 2),
    (11211, "Memcached", 2),
    (27017, "MongoDB", 2),
];

pub fn build(hosts: &[HostResult], elapsed_secs: f64) -> ExecutiveSummary {
    let hosts_total = hosts.len();
    let hosts_up = hosts.iter().filter(|h| h.up).count();

    let mut open_ports_total = 0usize;
    let mut svc_counts: HashMap<String, usize> = HashMap::new();
    let mut per_host_open: Vec<(String, usize)> = Vec::with_capacity(hosts_up);
    let mut sensitive: Vec<String> = Vec::new();

    for h in hosts {
        let mut host_open = 0usize;
        for p in &h.ports {
            if p.state == PortState::Open {
                open_ports_total += 1;
                host_open += 1;

                let svc_label = p
                    .service
                    .as_ref()
                    .and_then(|s| s.product.clone())
                    .unwrap_or_else(|| port_label(p.port));
                *svc_counts.entry(svc_label).or_insert(0) += 1;

                if let Some((_, label, sev)) = SENSITIVE_PORTS.iter().find(|(pp, _, _)| *pp == p.port) {
                    if *sev >= 1 {
                        sensitive.push(format!(
                            "{} on {}:{}",
                            label,
                            h.target.ip,
                            p.port
                        ));
                    }
                }
            }
        }
        if host_open > 0 {
            per_host_open.push((h.target.display(), host_open));
        }
    }

    let mut top_services: Vec<(String, usize)> = svc_counts.into_iter().collect();
    top_services.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top_services.truncate(5);

    per_host_open.sort_by(|a, b| b.1.cmp(&a.1));
    let most_exposed_host = per_host_open.into_iter().next();

    sensitive.sort();
    sensitive.dedup();

    ExecutiveSummary {
        hosts_total,
        hosts_up,
        elapsed_secs,
        open_ports_total,
        top_services,
        most_exposed_host,
        sensitive_exposures: sensitive,
    }
}

fn port_label(port: u16) -> String {
    SENSITIVE_PORTS
        .iter()
        .find(|(p, _, _)| *p == port)
        .map(|(_, l, _)| l.to_string())
        .unwrap_or_else(|| format!("port {}", port))
}

pub fn render_text(s: &ExecutiveSummary) -> String {
    let mut out = String::new();
    out.push_str("EXECUTIVE SUMMARY\n");
    out.push_str(&format!(
        "{} of {} host(s) responded in {:.2}s. {} open port(s) total.\n",
        s.hosts_up, s.hosts_total, s.elapsed_secs, s.open_ports_total
    ));
    if !s.top_services.is_empty() {
        let names: Vec<String> = s
            .top_services
            .iter()
            .map(|(name, n)| format!("{}×{}", name, n))
            .collect();
        out.push_str(&format!("Top services: {}.\n", names.join(", ")));
    }
    if let Some((host, n)) = &s.most_exposed_host {
        out.push_str(&format!("Most-exposed host: {} ({} open ports).\n", host, n));
    }
    if !s.sensitive_exposures.is_empty() {
        out.push_str(&format!(
            "Sensitive exposures ({}):\n",
            s.sensitive_exposures.len()
        ));
        for e in &s.sensitive_exposures {
            out.push_str(&format!("  · {}\n", e));
        }
    }
    out
}

#[allow(dead_code)]
pub fn render_markdown(s: &ExecutiveSummary) -> String {
    let mut out = String::new();
    out.push_str("## Executive summary\n\n");
    out.push_str(&format!(
        "**{} of {}** host(s) responded in **{:.2}s**. **{}** open port(s) discovered.\n\n",
        s.hosts_up, s.hosts_total, s.elapsed_secs, s.open_ports_total
    ));
    if !s.top_services.is_empty() {
        out.push_str("**Top services:**\n\n");
        for (name, n) in &s.top_services {
            out.push_str(&format!("- {} — {}\n", name, n));
        }
        out.push('\n');
    }
    if let Some((host, n)) = &s.most_exposed_host {
        out.push_str(&format!("**Most-exposed host:** `{}` ({} open ports).\n\n", host, n));
    }
    if !s.sensitive_exposures.is_empty() {
        out.push_str("**Sensitive exposures:**\n\n");
        for e in &s.sensitive_exposures {
            out.push_str(&format!("- `{}`\n", e));
        }
        out.push('\n');
    }
    out
}

pub fn print(s: &ExecutiveSummary) {
    use colored::*;
    println!();
    println!("{}", "EXECUTIVE SUMMARY".bold().underline());
    println!(
        "  {} of {} host(s) up in {:.2}s — {} open ports total",
        s.hosts_up.to_string().green(),
        s.hosts_total,
        s.elapsed_secs,
        s.open_ports_total.to_string().yellow()
    );
    if !s.top_services.is_empty() {
        let names: Vec<String> = s
            .top_services
            .iter()
            .map(|(n, c)| format!("{}×{}", n, c))
            .collect();
        println!("  Top services: {}", names.join(", "));
    }
    if let Some((host, n)) = &s.most_exposed_host {
        println!("  Most-exposed: {} ({} open)", host.bold(), n);
    }
    if !s.sensitive_exposures.is_empty() {
        println!("  {} sensitive exposure(s):", s.sensitive_exposures.len().to_string().red());
        for e in &s.sensitive_exposures {
            println!("    · {}", e.yellow());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::PortResult;
    use crate::target::Target;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn host_with(open_ports: &[u16], up: bool) -> HostResult {
        HostResult {
            target: Target { ip: Ipv4Addr::new(10, 0, 0, 1).into(), hostname: None },
            up,
            ports: open_ports
                .iter()
                .map(|&p| PortResult {
                    port: p,
                    state: PortState::Open,
                    rtt: Duration::from_millis(0),
                    service: None,
                })
                .collect(),
            elapsed: Duration::from_millis(0),
            os: None,
            device: None,
            mac: None,
        }
    }

    #[test]
    fn counts_hosts_and_ports() {
        let hosts = vec![
            host_with(&[22, 80, 443], true),
            host_with(&[], false),
        ];
        let s = build(&hosts, 5.0);
        assert_eq!(s.hosts_total, 2);
        assert_eq!(s.hosts_up, 1);
        assert_eq!(s.open_ports_total, 3);
        assert_eq!(s.elapsed_secs, 5.0);
    }

    #[test]
    fn flags_high_severity_ports_only() {
        let hosts = vec![host_with(&[22, 3389, 6379, 80], true)];
        let s = build(&hosts, 1.0);
        // SSH (sev 0) → not flagged; RDP + Redis (sev 2) → flagged.
        assert!(s.sensitive_exposures.iter().any(|e| e.contains("RDP")));
        assert!(s.sensitive_exposures.iter().any(|e| e.contains("Redis")));
        assert!(!s.sensitive_exposures.iter().any(|e| e.contains("SSH on")));
    }

    #[test]
    fn most_exposed_picked_correctly() {
        let mut h1 = host_with(&[22], true);
        h1.target = Target { ip: Ipv4Addr::new(1, 1, 1, 1).into(), hostname: None };
        let mut h2 = host_with(&[22, 80, 443, 3389], true);
        h2.target = Target { ip: Ipv4Addr::new(2, 2, 2, 2).into(), hostname: None };
        let s = build(&[h1, h2], 1.0);
        let (host, n) = s.most_exposed_host.unwrap();
        assert_eq!(n, 4);
        assert!(host.contains("2.2.2.2"));
    }

    #[test]
    fn markdown_render_includes_summary_and_exposures() {
        let hosts = vec![host_with(&[3389, 6379], true)];
        let s = build(&hosts, 1.0);
        let md = render_markdown(&s);
        assert!(md.contains("Executive summary"));
        assert!(md.contains("RDP"));
        assert!(md.contains("Redis"));
    }

    #[test]
    fn empty_scan_yields_zero_metrics() {
        let s = build(&[], 0.0);
        assert_eq!(s.hosts_total, 0);
        assert_eq!(s.open_ports_total, 0);
        assert!(s.most_exposed_host.is_none());
        assert!(s.sensitive_exposures.is_empty());
    }
}
