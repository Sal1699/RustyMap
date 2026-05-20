//! Per-user scan history — `~/.config/rustymap/history.jsonl`.
//!
//! Every successful scan appends one JSON object capturing:
//!   - timestamp (RFC 3339, local timezone)
//!   - the target string(s) the scan was launched against
//!   - hosts scanned / hosts up / open-port total
//!   - elapsed seconds
//!   - args (the full CLI line, joined with spaces) so the user can
//!     re-run with copy-paste
//!
//! `--history` prints the last N entries (default 20). `--history-clear`
//! truncates the file. We deliberately use append-only JSONL so the
//! file is corruption-resistant — a partial last line at most. Each
//! entry is independent so out-of-order writes don't matter.
//!
//! No PII beyond what the user typed on the CLI; keep it local-only.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: String,
    pub targets: Vec<String>,
    pub hosts_total: usize,
    pub hosts_up: usize,
    pub open_ports: usize,
    pub elapsed_secs: f64,
    pub args: String,
}

pub fn history_path() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(dir).join("rustymap").join("history.jsonl");
    }
    if let Some(home) = dirs_home() {
        // Cross-platform: ~/.config/rustymap on Unix, %APPDATA%\rustymap on Win.
        #[cfg(windows)]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                return PathBuf::from(appdata).join("rustymap").join("history.jsonl");
            }
        }
        return home.join(".config").join("rustymap").join("history.jsonl");
    }
    PathBuf::from("rustymap-history.jsonl")
}

fn dirs_home() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home));
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        return Some(PathBuf::from(profile));
    }
    None
}

pub fn append(entry: &HistoryEntry) -> Result<()> {
    let path = history_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let line = serde_json::to_string(entry).context("serialize history entry")?;
    writeln!(f, "{}", line)?;
    Ok(())
}

pub fn load(last_n: usize) -> Result<Vec<HistoryEntry>> {
    let path = history_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()),
    };
    let mut all: Vec<HistoryEntry> = Vec::new();
    for line in raw.lines() {
        if let Ok(e) = serde_json::from_str::<HistoryEntry>(line) {
            all.push(e);
        }
    }
    // Bug-14 (v0.66.4): the previous formula
    // `len - min(last_n-1, len)` always returned an empty slice for
    // last_n=1 (the very case `--explain last` cares about).
    // Correct math: split off at index `len - min(last_n, len)`.
    let take = all.len().saturating_sub(last_n.min(all.len()));
    Ok(all.split_off(take))
}

pub fn clear() -> Result<()> {
    let path = history_path();
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

pub fn print(entries: &[HistoryEntry]) {
    use colored::*;
    println!();
    println!("{}", format!("Scan history (last {})", entries.len()).bold());
    if entries.is_empty() {
        println!("  {}", "no scans recorded yet".dimmed());
        println!("  history file: {}", history_path().display());
        return;
    }
    for e in entries {
        println!(
            "  {} → {}  ({} up/{} total, {} open ports, {:.1}s)",
            e.timestamp.dimmed(),
            e.targets.join(",").bold(),
            e.hosts_up,
            e.hosts_total,
            e.open_ports,
            e.elapsed_secs
        );
        println!("    {} {}", "$".dimmed(), e.args);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_round_trips_through_json() {
        let e = HistoryEntry {
            timestamp: "2026-05-09T12:00:00+02:00".into(),
            targets: vec!["10.0.0.1".into()],
            hosts_total: 1,
            hosts_up: 1,
            open_ports: 3,
            elapsed_secs: 0.42,
            args: "rustymap 10.0.0.1 -sV".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: HistoryEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(back.targets, e.targets);
        assert_eq!(back.open_ports, e.open_ports);
        assert!((back.elapsed_secs - e.elapsed_secs).abs() < 1e-9);
    }

    #[test]
    fn append_then_load_returns_entries() {
        // Use a unique file in temp dir.
        let dir = std::env::temp_dir().join(format!("rustymap-hist-{}", std::process::id()));
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        // Pre-clear (defensive — prior failed run might have left state).
        let _ = clear();

        for i in 0..3 {
            let e = HistoryEntry {
                timestamp: format!("2026-05-09T12:00:0{}+02:00", i),
                targets: vec![format!("10.0.0.{}", i + 1)],
                hosts_total: 1,
                hosts_up: 1,
                open_ports: i,
                elapsed_secs: 0.1 * (i as f64),
                args: format!("rustymap 10.0.0.{}", i + 1),
            };
            append(&e).unwrap();
        }

        let loaded = load(10).unwrap();
        assert!(loaded.len() >= 3);
        let _ = clear();
        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
