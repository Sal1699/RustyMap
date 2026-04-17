use crate::ports::service_name;
use crate::scanner::{HostResult, PortState};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;

pub struct Db {
    conn: Connection,
}

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    elapsed_secs REAL NOT NULL,
    scan_type TEXT NOT NULL,
    target_spec TEXT NOT NULL,
    port_spec TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'complete'
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    hostname TEXT,
    up INTEGER NOT NULL,
    latency_secs REAL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL,
    service TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER,
    tag TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(ip, port, tag)
);
CREATE INDEX IF NOT EXISTS idx_tags_ip ON tags(ip);
"#;

impl Db {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open SQLite db")?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-8000;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn begin_scan(
        &mut self,
        started_at: &str,
        scan_type: &str,
        target_spec: &str,
        port_spec: &str,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO scans (started_at, elapsed_secs, scan_type, target_spec, port_spec, status)
             VALUES (?, 0, ?, ?, ?, 'in_progress')",
            params![started_at, scan_type, target_spec, port_spec],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn finalize_scan(&mut self, scan_id: i64, elapsed_secs: f64, status: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE scans SET elapsed_secs = ?, status = ? WHERE id = ?",
            params![elapsed_secs, status, scan_id],
        )?;
        Ok(())
    }

    pub fn insert_host(&mut self, scan_id: i64, host: &HostResult) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO hosts (scan_id, ip, hostname, up, latency_secs) VALUES (?, ?, ?, ?, ?)",
            params![
                scan_id,
                host.target.ip.to_string(),
                host.target.hostname,
                host.up as i32,
                host.elapsed.as_secs_f64(),
            ],
        )?;
        let host_id = tx.last_insert_rowid();
        for p in &host.ports {
            tx.execute(
                "INSERT INTO ports (host_id, port, protocol, state, service) VALUES (?, ?, 'tcp', ?, ?)",
                params![host_id, p.port as i64, p.state.as_str(), service_name(p.port)],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn last_scan_for_ip(&self, ip: &str, before_scan_id: i64) -> Result<Option<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT h.scan_id FROM hosts h
             WHERE h.ip = ? AND h.scan_id < ?
             ORDER BY h.scan_id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![ip, before_scan_id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(r.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn ports_for(&self, scan_id: i64, ip: &str) -> Result<Vec<(u16, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.port, p.state FROM ports p
             JOIN hosts h ON p.host_id = h.id
             WHERE h.scan_id = ? AND h.ip = ?
             ORDER BY p.port",
        )?;
        let out: Vec<(u16, String)> = stmt
            .query_map(params![scan_id, ip], |r| {
                let port: i64 = r.get(0)?;
                let state: String = r.get(1)?;
                Ok((port as u16, state))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(out)
    }

    pub fn add_tag(&mut self, ip: &str, port: Option<u16>, tag: &str, note: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO tags (ip, port, tag, note) VALUES (?, ?, ?, ?)",
            params![ip, port.map(|p| p as i64), tag, note],
        )?;
        Ok(())
    }

    pub fn list_scans(&self) -> Result<Vec<(i64, String, String, String, String, f64, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, started_at, scan_type, target_spec, port_spec, elapsed_secs, status
             FROM scans ORDER BY id DESC LIMIT 200",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))?
            .filter_map(|r| r.ok()).collect();
        Ok(rows)
    }

    pub fn hosts_for_scan(&self, scan_id: i64) -> Result<Vec<(i64, String, Option<String>, bool, f64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, hostname, up, latency_secs FROM hosts WHERE scan_id = ? ORDER BY ip",
        )?;
        let rows = stmt.query_map(params![scan_id], |r| {
            let up: i64 = r.get(3)?;
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, up != 0, r.get(4)?))
        })?.filter_map(|r| r.ok()).collect();
        Ok(rows)
    }

    pub fn ports_for_host(&self, host_id: i64) -> Result<Vec<(u16, String, String, Option<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT port, protocol, state, service FROM ports WHERE host_id = ? ORDER BY port",
        )?;
        let rows = stmt.query_map(params![host_id], |r| {
            let p: i64 = r.get(0)?;
            Ok((p as u16, r.get(1)?, r.get(2)?, r.get(3)?))
        })?.filter_map(|r| r.ok()).collect();
        Ok(rows)
    }

    pub fn list_tags(&self, ip_filter: Option<&str>) -> Result<Vec<(String, Option<u16>, String, Option<String>, String)>> {
        let (sql, needs_param) = if ip_filter.is_some() {
            ("SELECT ip, port, tag, note, created_at FROM tags WHERE ip = ? ORDER BY ip, port", true)
        } else {
            ("SELECT ip, port, tag, note, created_at FROM tags ORDER BY ip, port", false)
        };
        let mut stmt = self.conn.prepare(sql)?;
        let map = |r: &rusqlite::Row| -> rusqlite::Result<_> {
            let ip: String = r.get(0)?;
            let port: Option<i64> = r.get(1)?;
            let tag: String = r.get(2)?;
            let note: Option<String> = r.get(3)?;
            let created_at: String = r.get(4)?;
            Ok((ip, port.map(|p| p as u16), tag, note, created_at))
        };
        let rows: Vec<_> = if needs_param {
            stmt.query_map(params![ip_filter.unwrap()], map)?.filter_map(|r| r.ok()).collect()
        } else {
            stmt.query_map([], map)?.filter_map(|r| r.ok()).collect()
        };
        Ok(rows)
    }
}

pub struct PortDiff {
    #[allow(dead_code)]
    pub ip: String,
    pub new_open: Vec<u16>,
    pub closed_now: Vec<u16>,
    pub state_changes: Vec<(u16, String, String)>,
}

pub fn diff_host_vs_previous(
    db: &Db,
    current_scan_id: i64,
    ip: &str,
    current_state: &[(u16, PortState)],
) -> Result<Option<PortDiff>> {
    let prev_scan = match db.last_scan_for_ip(ip, current_scan_id)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let prev = db.ports_for(prev_scan, ip)?;
    let prev_map: std::collections::BTreeMap<u16, String> = prev.into_iter().collect();
    let cur_map: std::collections::BTreeMap<u16, String> = current_state
        .iter()
        .map(|(p, s)| (*p, s.as_str().to_string()))
        .collect();

    let mut new_open = Vec::new();
    let mut closed_now = Vec::new();
    let mut state_changes = Vec::new();

    for (port, cstate) in &cur_map {
        match prev_map.get(port) {
            None => {
                if cstate == "open" {
                    new_open.push(*port);
                }
            }
            Some(pstate) if pstate != cstate => {
                state_changes.push((*port, pstate.clone(), cstate.clone()));
            }
            _ => {}
        }
    }
    for (port, pstate) in &prev_map {
        if !cur_map.contains_key(port) && pstate == "open" {
            closed_now.push(*port);
        }
    }

    Ok(Some(PortDiff { ip: ip.into(), new_open, closed_now, state_changes }))
}
