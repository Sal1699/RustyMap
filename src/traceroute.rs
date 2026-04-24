//! Traceroute via the system `tracert` (Windows) / `traceroute` (Unix).
//!
//! Going through the system tool keeps the implementation cross-platform
//! and dependency-free (no raw sockets, no Npcap requirement on Windows).
//! We parse the output to extract the hop IPs and surface them as a list
//! per target, so downstream consumers can render a topology graph.

use crate::target::Target;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    pub target: String,
    pub destination: Option<IpAddr>,
    pub hops: Vec<Hop>,
}

pub async fn trace(target: &Target, max_hops: u8) -> Result<TraceResult> {
    let target_s = target.ip.to_string();
    let max = max_hops.to_string();

    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("tracert");
        c.args(["-d", "-h", &max, "-w", "1500", &target_s]);
        c
    };
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("traceroute");
        c.args(["-n", "-w", "2", "-m", &max, &target_s]);
        c
    };

    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout).lines();

    let mut hops = Vec::new();
    while let Some(line) = reader.next_line().await? {
        if let Some(h) = parse_hop_line(&line) {
            hops.push(h);
        }
    }
    let _ = child.wait().await;

    Ok(TraceResult {
        target: target.display(),
        destination: Some(target.ip),
        hops,
    })
}

fn parse_hop_line(line: &str) -> Option<Hop> {
    let trimmed = line.trim();
    let mut parts = trimmed.split_whitespace();
    let first = parts.next()?;
    let ttl: u8 = first.parse().ok()?;

    // Find the first IP-shaped token (parenthesised or bare).
    let ip = trimmed
        .split(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':')
        .find_map(|tok| tok.parse::<IpAddr>().ok());
    Some(Hop { ttl, ip })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tracert_line() {
        // Windows tracert numeric (-d) format
        let h = parse_hop_line("  3   12 ms   11 ms   12 ms  10.0.0.1").unwrap();
        assert_eq!(h.ttl, 3);
        assert_eq!(h.ip, Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parses_traceroute_line() {
        // Unix traceroute -n format
        let h = parse_hop_line(" 1  10.0.0.1  0.412 ms  0.378 ms  0.345 ms").unwrap();
        assert_eq!(h.ttl, 1);
        assert_eq!(h.ip, Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn handles_no_response_hop() {
        let h = parse_hop_line(" 7  *  *  *").unwrap();
        assert_eq!(h.ttl, 7);
        assert!(h.ip.is_none());
    }

    #[test]
    fn ignores_header_lines() {
        assert!(parse_hop_line("traceroute to 1.1.1.1 (1.1.1.1), 30 hops max").is_none());
        assert!(parse_hop_line("Tracing route to 1.1.1.1 over a maximum of 30 hops").is_none());
    }

    #[test]
    fn render_dot_includes_scanner_node() {
        let traces = vec![TraceResult {
            target: "1.1.1.1".into(),
            destination: Some("1.1.1.1".parse().unwrap()),
            hops: vec![
                Hop { ttl: 1, ip: Some("10.0.0.1".parse().unwrap()) },
                Hop { ttl: 2, ip: Some("1.1.1.1".parse().unwrap()) },
            ],
        }];
        let dot = render_dot(&traces);
        assert!(dot.contains("digraph rustymap_topology"));
        assert!(dot.contains("\"scanner\" -> \"10.0.0.1\""));
        assert!(dot.contains("\"10.0.0.1\" -> \"1.1.1.1\""));
    }
}

/// Render a list of trace results as a Graphviz DOT graph.
pub fn render_dot(traces: &[TraceResult]) -> String {
    let mut out = String::new();
    out.push_str("digraph rustymap_topology {\n");
    out.push_str("    rankdir=LR;\n");
    out.push_str("    node [shape=box, style=rounded];\n");
    out.push_str("    \"scanner\" [shape=ellipse, style=filled, fillcolor=lightblue];\n");

    let mut seen_edges = std::collections::HashSet::new();
    for t in traces {
        let mut prev = "scanner".to_string();
        for hop in &t.hops {
            let label = match hop.ip {
                Some(ip) => ip.to_string(),
                None => format!("ttl{}-?", hop.ttl),
            };
            let key = format!("{}->{}", prev, label);
            if seen_edges.insert(key) {
                out.push_str(&format!("    \"{}\" -> \"{}\";\n", prev, label));
            }
            prev = label;
        }
        let dst_label = t
            .destination
            .map(|d| d.to_string())
            .unwrap_or_else(|| t.target.clone());
        out.push_str(&format!(
            "    \"{}\" [shape=box, style=\"rounded,filled\", fillcolor=palegreen];\n",
            dst_label
        ));
    }
    out.push_str("}\n");
    out
}
