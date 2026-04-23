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
