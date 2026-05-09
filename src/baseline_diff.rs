//! Diff a fresh scan against a previously-saved JSON baseline.
//!
//! The existing `--show-diff` machinery uses the SQLite db to find a
//! prior run. That works when the user kept `--db enabled`, but
//! doesn't help anyone who just wants to compare two flat JSON
//! exports (CI artefacts, hand-archived files, output from a
//! different machine). This module fills that gap:
//!
//!   `--diff-against PATH.json` reads the JSON file, computes:
//!   - **new hosts**   — present now, absent before
//!   - **gone hosts**  — present before, absent now
//!   - **new ports**   — port that's open now and was not open before
//!   - **closed ports** — port that was open before and isn't now
//!   - **state changes** — port present in both with a different state
//!
//! The baseline JSON is whatever `json_out::write_json` produced. We
//! deserialize the relevant subset to keep coupling low.

use crate::scanner::HostResult;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
struct BaselineDoc {
    #[serde(default)]
    hosts: Vec<BaselineHost>,
}

#[derive(Debug, Clone, Deserialize)]
struct BaselineHost {
    target: BaselineTarget,
    #[serde(default)]
    up: bool,
    #[serde(default)]
    ports: Vec<BaselinePort>,
}

#[derive(Debug, Clone, Deserialize)]
struct BaselineTarget {
    ip: String,
}

#[derive(Debug, Clone, Deserialize)]
struct BaselinePort {
    port: u16,
    #[serde(default)]
    state: String,
}

#[derive(Debug, Default)]
pub struct BaselineDiff {
    pub baseline_path: String,
    pub new_hosts: Vec<String>,
    pub gone_hosts: Vec<String>,
    pub new_open_ports: BTreeMap<String, Vec<u16>>,
    pub closed_ports: BTreeMap<String, Vec<u16>>,
    pub state_changes: BTreeMap<(String, u16), (String, String)>,
}

pub fn diff_against(baseline_path: &Path, current: &[HostResult]) -> Result<BaselineDiff> {
    let raw = std::fs::read_to_string(baseline_path)
        .with_context(|| format!("read baseline {}", baseline_path.display()))?;
    let doc: BaselineDoc = serde_json::from_str(&raw).context("parse baseline JSON")?;

    // Build maps keyed by IP for fast lookups.
    let mut baseline_hosts: HashMap<String, HashMap<u16, String>> = HashMap::new();
    let mut baseline_up: BTreeSet<String> = BTreeSet::new();
    for h in &doc.hosts {
        let ports: HashMap<u16, String> = h
            .ports
            .iter()
            .map(|p| (p.port, p.state.to_lowercase()))
            .collect();
        baseline_hosts.insert(h.target.ip.clone(), ports);
        if h.up {
            baseline_up.insert(h.target.ip.clone());
        }
    }

    let mut current_up: BTreeSet<String> = BTreeSet::new();
    let mut current_hosts: HashMap<String, HashMap<u16, String>> = HashMap::new();
    for h in current {
        let ip = h.target.ip.to_string();
        if h.up {
            current_up.insert(ip.clone());
        }
        let ports: HashMap<u16, String> = h
            .ports
            .iter()
            .map(|p| (p.port, p.state.as_str().to_lowercase()))
            .collect();
        current_hosts.insert(ip, ports);
    }

    let mut diff = BaselineDiff {
        baseline_path: baseline_path.display().to_string(),
        ..Default::default()
    };

    diff.new_hosts = current_up.difference(&baseline_up).cloned().collect();
    diff.gone_hosts = baseline_up.difference(&current_up).cloned().collect();

    for ip in current_up.intersection(&baseline_up) {
        let now = current_hosts.get(ip);
        let then = baseline_hosts.get(ip);
        let (now, then) = match (now, then) {
            (Some(a), Some(b)) => (a, b),
            _ => continue,
        };

        let mut new_open = Vec::new();
        let mut closed = Vec::new();
        let mut changes = Vec::new();
        let mut all_ports: BTreeSet<u16> = BTreeSet::new();
        all_ports.extend(now.keys());
        all_ports.extend(then.keys());
        for port in &all_ports {
            let now_s = now.get(port).cloned().unwrap_or_else(|| "absent".into());
            let then_s = then.get(port).cloned().unwrap_or_else(|| "absent".into());
            if now_s == then_s {
                continue;
            }
            match (was_open(&then_s), was_open(&now_s)) {
                (false, true) => new_open.push(*port),
                (true, false) => closed.push(*port),
                _ => changes.push((*port, then_s, now_s)),
            }
        }
        if !new_open.is_empty() {
            diff.new_open_ports.insert(ip.clone(), new_open);
        }
        if !closed.is_empty() {
            diff.closed_ports.insert(ip.clone(), closed);
        }
        for (port, from, to) in changes {
            diff.state_changes.insert((ip.clone(), port), (from, to));
        }
    }
    Ok(diff)
}

fn was_open(state: &str) -> bool {
    state == "open" || state == "open|filtered"
}

pub fn print(d: &BaselineDiff) {
    use colored::*;
    println!();
    println!("{}", format!("Baseline diff vs {}", d.baseline_path).bold());
    if d.new_hosts.is_empty()
        && d.gone_hosts.is_empty()
        && d.new_open_ports.is_empty()
        && d.closed_ports.is_empty()
        && d.state_changes.is_empty()
    {
        println!("  {}", "no changes since baseline".green());
        return;
    }
    if !d.new_hosts.is_empty() {
        println!("  {} new host(s):", d.new_hosts.len().to_string().green());
        for h in &d.new_hosts {
            println!("    + {}", h);
        }
    }
    if !d.gone_hosts.is_empty() {
        println!("  {} gone host(s):", d.gone_hosts.len().to_string().yellow());
        for h in &d.gone_hosts {
            println!("    - {}", h);
        }
    }
    if !d.new_open_ports.is_empty() {
        println!("  newly-open ports:");
        for (host, ports) in &d.new_open_ports {
            let s: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
            println!("    {} → {}", host, s.join(",").green());
        }
    }
    if !d.closed_ports.is_empty() {
        println!("  newly-closed ports:");
        for (host, ports) in &d.closed_ports {
            let s: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
            println!("    {} → {}", host, s.join(",").yellow());
        }
    }
    if !d.state_changes.is_empty() {
        println!("  state changes:");
        for ((host, port), (from, to)) in &d.state_changes {
            println!("    {}:{} {} → {}", host, port, from, to);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{PortResult, PortState};
    use crate::target::Target;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn host(ip: [u8; 4], up: bool, ports: &[(u16, PortState)]) -> HostResult {
        HostResult {
            target: Target { ip: Ipv4Addr::from(ip).into(), hostname: None, zone: None },
            up,
            ports: ports
                .iter()
                .map(|(p, s)| PortResult {
                    port: *p,
                    state: *s,
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

    fn write_baseline(tmpdir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
        let path = tmpdir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn detects_new_host() {
        let tmp = std::env::temp_dir();
        let baseline = write_baseline(
            &tmp,
            &format!("rm-baseline-{}-1.json", std::process::id()),
            r#"{"hosts":[{"target":{"ip":"10.0.0.1"},"up":true,"ports":[{"port":22,"state":"open"}]}]}"#,
        );
        let current = vec![
            host([10, 0, 0, 1], true, &[(22, PortState::Open)]),
            host([10, 0, 0, 2], true, &[(80, PortState::Open)]),
        ];
        let d = diff_against(&baseline, &current).unwrap();
        let _ = std::fs::remove_file(&baseline);
        assert!(d.new_hosts.iter().any(|h| h == "10.0.0.2"));
    }

    #[test]
    fn detects_new_open_port() {
        let tmp = std::env::temp_dir();
        let baseline = write_baseline(
            &tmp,
            &format!("rm-baseline-{}-2.json", std::process::id()),
            r#"{"hosts":[{"target":{"ip":"10.0.0.1"},"up":true,"ports":[{"port":22,"state":"open"}]}]}"#,
        );
        let current = vec![host([10, 0, 0, 1], true, &[(22, PortState::Open), (80, PortState::Open)])];
        let d = diff_against(&baseline, &current).unwrap();
        let _ = std::fs::remove_file(&baseline);
        assert_eq!(d.new_open_ports.get("10.0.0.1"), Some(&vec![80]));
    }

    #[test]
    fn detects_closed_port() {
        let tmp = std::env::temp_dir();
        let baseline = write_baseline(
            &tmp,
            &format!("rm-baseline-{}-3.json", std::process::id()),
            r#"{"hosts":[{"target":{"ip":"10.0.0.1"},"up":true,"ports":[{"port":22,"state":"open"},{"port":80,"state":"open"}]}]}"#,
        );
        let current = vec![host([10, 0, 0, 1], true, &[(22, PortState::Open)])];
        let d = diff_against(&baseline, &current).unwrap();
        let _ = std::fs::remove_file(&baseline);
        assert_eq!(d.closed_ports.get("10.0.0.1"), Some(&vec![80]));
    }

    #[test]
    fn no_changes_when_identical() {
        let tmp = std::env::temp_dir();
        let baseline = write_baseline(
            &tmp,
            &format!("rm-baseline-{}-4.json", std::process::id()),
            r#"{"hosts":[{"target":{"ip":"10.0.0.1"},"up":true,"ports":[{"port":22,"state":"open"}]}]}"#,
        );
        let current = vec![host([10, 0, 0, 1], true, &[(22, PortState::Open)])];
        let d = diff_against(&baseline, &current).unwrap();
        let _ = std::fs::remove_file(&baseline);
        assert!(d.new_hosts.is_empty());
        assert!(d.gone_hosts.is_empty());
        assert!(d.new_open_ports.is_empty());
        assert!(d.closed_ports.is_empty());
        assert!(d.state_changes.is_empty());
    }
}
