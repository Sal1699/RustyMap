//! File-based scan checkpoint & resume.
//!
//! The existing `--resume ID` walks the SQLite db to recover an
//! interrupted scan. That works when `--db` was on, but doesn't help
//! someone running RustyMap without persistence (the common case for
//! ad-hoc scans). This module implements an orthogonal **file-based**
//! checkpoint:
//!
//!   `--checkpoint FILE.state` — every N completed targets, append
//!   the remaining work + accumulated results to FILE.state. On
//!   SIGINT, the file is flushed once more so the next run can pick
//!   up cleanly.
//!
//!   `--resume-from FILE.state` — read the file back, skip targets
//!   already finished, continue with the rest. Outputs (HTML / JSON
//!   / etc.) are written from the *complete* host list, including
//!   hosts that were finished in the prior session.
//!
//! State format: JSON. Keeps it human-readable (so the user can see
//! "yeah, 23/100 hosts done, ~30 min remaining") and lets us evolve
//! the schema incrementally with `serde(default)` on new fields.
//!
//! Atomic writes via `tmp + rename` to avoid leaving a half-written
//! state file if the process gets killed mid-flush.

use crate::scanner::HostResult;
use crate::target::Target;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanState {
    pub schema_version: u32,
    pub started_at: String,    // RFC 3339
    pub last_flushed_at: String,
    pub scan_type: String,     // human label
    pub ports: Vec<u16>,
    pub args_line: String,
    /// Targets that have already been processed (in any state).
    pub completed: Vec<HostResult>,
    /// Targets still pending — the scanner will pick up here.
    pub pending: Vec<Target>,
}

impl ScanState {
    pub fn new(
        scan_type: &str,
        ports: Vec<u16>,
        args_line: &str,
        all_targets: &[Target],
    ) -> Self {
        let now = chrono::Local::now().to_rfc3339();
        Self {
            schema_version: SCHEMA_VERSION,
            started_at: now.clone(),
            last_flushed_at: now,
            scan_type: scan_type.to_string(),
            ports,
            args_line: args_line.to_string(),
            completed: Vec::new(),
            pending: all_targets.to_vec(),
        }
    }

    /// Move a result from pending to completed by IP match.
    pub fn record(&mut self, result: HostResult) {
        self.pending.retain(|t| t.ip != result.target.ip);
        self.completed.push(result);
        self.last_flushed_at = chrono::Local::now().to_rfc3339();
    }

    pub fn progress(&self) -> (usize, usize) {
        let done = self.completed.len();
        let total = done + self.pending.len();
        (done, total)
    }
}

pub fn save(path: &Path, state: &ScanState) -> Result<()> {
    let tmp: PathBuf = {
        let mut p = path.to_path_buf();
        let mut name = p.file_name().unwrap_or_default().to_owned();
        name.push(".tmp");
        p.set_file_name(name);
        p
    };
    let body = serde_json::to_string_pretty(state).context("serialize ScanState")?;
    std::fs::write(&tmp, body).with_context(|| format!("write tmp {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn load(path: &Path) -> Result<ScanState> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let state: ScanState = serde_json::from_str(&raw)
        .context("parse ScanState — file may be from an older schema")?;
    if state.schema_version != SCHEMA_VERSION {
        // Forward-compatible: refuse instead of mis-resuming.
        anyhow::bail!(
            "incompatible schema: file v{}, this rustymap expects v{}",
            state.schema_version, SCHEMA_VERSION
        );
    }
    Ok(state)
}

pub fn print_progress(state: &ScanState) {
    use colored::*;
    let (done, total) = state.progress();
    let pct = if total == 0 { 0.0 } else { 100.0 * done as f64 / total as f64 };
    println!();
    println!("{}", format!("Resuming from {}", state.started_at).bold());
    println!(
        "  {} / {} hosts done ({:.1}%)",
        done.to_string().green(),
        total,
        pct
    );
    println!("  scan type: {} — ports: {} entries", state.scan_type, state.ports.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn target(octet: u8) -> Target {
        Target {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)),
            hostname: None,
            zone: None,
        }
    }

    fn host_result(octet: u8) -> HostResult {
        HostResult {
            target: target(octet),
            up: true,
            ports: vec![],
            elapsed: Duration::from_millis(0),
            os: None,
            device: None,
            mac: None,
        }
    }

    #[test]
    fn new_state_starts_with_all_pending() {
        let s = ScanState::new("connect", vec![80, 443], "rustymap …", &[target(1), target(2)]);
        assert_eq!(s.pending.len(), 2);
        assert!(s.completed.is_empty());
        assert_eq!(s.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn record_moves_result_from_pending_to_completed() {
        let mut s = ScanState::new("c", vec![80], "x", &[target(1), target(2)]);
        s.record(host_result(1));
        let (done, total) = s.progress();
        assert_eq!(done, 1);
        assert_eq!(total, 2);
        assert_eq!(s.pending.len(), 1);
        assert_eq!(s.pending[0].ip, target(2).ip);
    }

    #[test]
    fn save_and_load_round_trip() {
        let mut s = ScanState::new("connect", vec![22, 80], "rustymap host", &[target(1)]);
        s.record(host_result(1));
        let dir = std::env::temp_dir();
        let path = dir.join(format!("rustymap-resume-{}.state", std::process::id()));
        save(&path, &s).unwrap();
        let loaded = load(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded.completed.len(), 1);
        assert!(loaded.pending.is_empty());
        assert_eq!(loaded.scan_type, "connect");
    }

    #[test]
    fn load_rejects_wrong_schema_version() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("rustymap-resume-bad-{}.state", std::process::id()));
        let bad = r#"{
            "schema_version": 999,
            "started_at": "2026-05-09T00:00:00+00:00",
            "last_flushed_at": "2026-05-09T00:00:00+00:00",
            "scan_type": "x",
            "ports": [],
            "args_line": "",
            "completed": [],
            "pending": []
        }"#;
        std::fs::write(&path, bad).unwrap();
        let r = load(&path);
        let _ = std::fs::remove_file(&path);
        assert!(r.is_err());
    }

    #[test]
    fn progress_handles_empty_state() {
        let s = ScanState::new("c", vec![], "x", &[]);
        let (done, total) = s.progress();
        assert_eq!(done, 0);
        assert_eq!(total, 0);
    }
}
