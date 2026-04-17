use crate::cli::Cli;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

/// A compliance / scan profile loaded from a TOML file.
/// Any field set here overrides the corresponding CLI arg unless already set.
#[derive(Debug, Deserialize, Default)]
pub struct Profile {
    pub name: Option<String>,
    #[allow(dead_code)]
    pub description: Option<String>,
    pub ports: Option<String>,
    pub scan_type: Option<String>, // connect|syn|fin|null|xmas|ack|udp
    pub timing: Option<u8>,
    pub service_version: Option<bool>,
    pub os_fingerprint: Option<bool>,
    pub randomize_ports: Option<bool>,
    pub scan_delay_ms: Option<u64>,
    pub cve_db: Option<String>,
    pub script: Option<String>,
    pub adaptive: Option<bool>,
}

pub fn load(path: &str) -> Result<Profile> {
    let data = fs::read_to_string(path).with_context(|| format!("read {}", path))?;
    let p: Profile = toml::from_str(&data).context("parse profile TOML")?;
    Ok(p)
}

pub fn apply(cli: &mut Cli, p: &Profile) {
    if let Some(ports) = &p.ports { cli.ports = ports.clone(); }
    if let Some(t) = p.timing { cli.timing = t; }
    if p.service_version == Some(true) { cli.service_version = true; }
    if p.os_fingerprint == Some(true) { cli.os_fingerprint = true; }
    if p.randomize_ports == Some(true) { cli.randomize_ports = true; }
    if let Some(d) = p.scan_delay_ms { if cli.scan_delay_ms == 0 { cli.scan_delay_ms = d; } }
    if let Some(c) = &p.cve_db { if cli.cve_db.is_none() { cli.cve_db = Some(c.clone()); } }
    if let Some(s) = &p.script { if cli.script_path.is_none() { cli.script_path = Some(s.clone()); } }
    if p.adaptive == Some(true) { cli.adaptive = true; }
    if let Some(st) = &p.scan_type {
        match st.to_lowercase().as_str() {
            "connect" => cli.scan_connect = true,
            "syn" => cli.scan_syn = true,
            "fin" => cli.scan_fin = true,
            "null" => cli.scan_null = true,
            "xmas" => cli.scan_xmas = true,
            "ack" => cli.scan_ack = true,
            "udp" => cli.scan_udp = true,
            _ => {}
        }
    }
}

pub fn parse_duration(spec: &str) -> Option<std::time::Duration> {
    let s = spec.trim();
    if s.is_empty() { return None; }
    let (num, unit) = s.split_at(s.find(|c: char| c.is_alphabetic())?);
    let n: u64 = num.trim().parse().ok()?;
    let secs = match unit.trim() {
        "s" | "sec" => n,
        "m" | "min" => n * 60,
        "h" | "hr" | "hour" => n * 3600,
        "d" | "day" => n * 86400,
        _ => return None,
    };
    Some(std::time::Duration::from_secs(secs))
}
