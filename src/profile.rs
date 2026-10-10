use crate::cli::Cli;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

/// A compliance / scan profile loaded from a TOML file.
/// Any field set here overrides the corresponding CLI arg unless already set.
#[derive(Debug, Deserialize, Serialize, Default)]
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
    // Added for the built-in presets (Fase 28). All optional + serde-default
    // so pre-existing TOML profiles still parse unchanged.
    #[serde(default)]
    pub ssl_enum: Option<bool>,
    #[serde(default)]
    pub tls_grade: Option<bool>,
    #[serde(default)]
    pub web_scan: Option<bool>,
    #[serde(default)]
    pub aggressive: Option<bool>,
    #[serde(default)]
    pub all_ports: Option<bool>,
    #[serde(default)]
    pub top_ports: Option<u32>,
}

pub fn load(path: &str) -> Result<Profile> {
    let data = fs::read_to_string(path).with_context(|| format!("read {}", path))?;
    let p: Profile = toml::from_str(&data).context("parse profile TOML")?;
    Ok(p)
}

pub fn apply(cli: &mut Cli, p: &Profile) {
    if let Some(ports) = &p.ports { cli.ports = Some(ports.clone()); }
    if let Some(t) = p.timing { cli.timing = t; }
    if p.service_version == Some(true) { cli.service_version = true; }
    if p.os_fingerprint == Some(true) { cli.os_fingerprint = true; }
    if p.randomize_ports == Some(true) { cli.randomize_ports = true; }
    if let Some(d) = p.scan_delay_ms { if cli.scan_delay_ms == 0 { cli.scan_delay_ms = d; } }
    if let Some(c) = &p.cve_db { if cli.cve_db.is_none() { cli.cve_db = Some(c.clone()); } }
    if let Some(s) = &p.script { if cli.script_path.is_none() { cli.script_path = Some(s.clone()); } }
    if p.adaptive == Some(true) { cli.adaptive = true; }
    if p.ssl_enum == Some(true) { cli.ssl_enum = true; }
    if p.tls_grade == Some(true) { cli.tls_grade = true; }
    if p.web_scan == Some(true) { cli.web_scan = true; }
    if p.aggressive == Some(true) { cli.aggressive = true; }
    if p.all_ports == Some(true) { cli.all_ports = true; }
    if let Some(n) = p.top_ports { if cli.top_ports.is_none() { cli.top_ports = Some(n); } }
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

/// Build a `Profile` from the current CLI args. Only fields the
/// caller actually changed from clap defaults are written, so the
/// resulting TOML is compact and editable by hand.
pub fn from_cli(cli: &Cli, name: Option<&str>) -> Profile {
    let scan_type = if cli.scan_syn {
        Some("syn".into())
    } else if cli.scan_fin {
        Some("fin".into())
    } else if cli.scan_null {
        Some("null".into())
    } else if cli.scan_xmas {
        Some("xmas".into())
    } else if cli.scan_ack {
        Some("ack".into())
    } else if cli.scan_udp {
        Some("udp".into())
    } else {
        None
    };

    Profile {
        name: name.map(String::from),
        description: None,
        ports: cli.ports.clone(),
        scan_type,
        timing: if cli.timing != 3 { Some(cli.timing) } else { None },
        service_version: if cli.service_version { Some(true) } else { None },
        os_fingerprint: if cli.os_fingerprint { Some(true) } else { None },
        randomize_ports: if cli.randomize_ports { Some(true) } else { None },
        scan_delay_ms: if cli.scan_delay_ms != 0 { Some(cli.scan_delay_ms) } else { None },
        cve_db: cli.cve_db.clone(),
        script: cli.script_path.clone(),
        adaptive: if cli.adaptive { Some(true) } else { None },
        ssl_enum: if cli.ssl_enum { Some(true) } else { None },
        tls_grade: if cli.tls_grade { Some(true) } else { None },
        web_scan: if cli.web_scan { Some(true) } else { None },
        aggressive: if cli.aggressive { Some(true) } else { None },
        all_ports: if cli.all_ports { Some(true) } else { None },
        top_ports: cli.top_ports,
    }
}

/// Built-in named presets (Fase 28). `--profile <name>` resolves one of
/// these without a TOML file on disk; `--profile <path>` still loads a file.
/// Keep [`BUILTIN_PRESETS`] and this match in sync.
pub fn builtin(name: &str) -> Option<Profile> {
    let p = match name.to_lowercase().replace('_', "-").as_str() {
        "pentest-internal" => Profile {
            name: Some("pentest-internal".into()),
            description: Some(
                "Internal engagement: SYN scan + service/OS detection, aggressive timing".into(),
            ),
            scan_type: Some("syn".into()),
            service_version: Some(true),
            os_fingerprint: Some(true),
            timing: Some(4),
            adaptive: Some(true),
            ..Default::default()
        },
        "compliance-pci" => Profile {
            name: Some("compliance-pci".into()),
            description: Some(
                "PCI-DSS posture: all TCP ports, service detection, TLS protocol + cipher grade"
                    .into(),
            ),
            scan_type: Some("syn".into()),
            service_version: Some(true),
            ssl_enum: Some(true),
            tls_grade: Some(true),
            all_ports: Some(true),
            timing: Some(4),
            ..Default::default()
        },
        "bugbounty-web" => Profile {
            name: Some("bugbounty-web".into()),
            description: Some(
                "Web attack surface: connect scan of web ports + --web-scan + TLS grade".into(),
            ),
            scan_type: Some("connect".into()),
            ports: Some("80,443,3000,5000,8000,8008,8080,8081,8443,8888,9000".into()),
            service_version: Some(true),
            web_scan: Some(true),
            ssl_enum: Some(true),
            tls_grade: Some(true),
            timing: Some(3),
            ..Default::default()
        },
        "homelab-discover" => Profile {
            name: Some("homelab-discover".into()),
            description: Some(
                "Fast homelab sweep: SYN top-100 ports, aggressive timing, no deep probes".into(),
            ),
            scan_type: Some("syn".into()),
            top_ports: Some(100),
            timing: Some(4),
            adaptive: Some(true),
            ..Default::default()
        },
        _ => return None,
    };
    Some(p)
}

/// Name + one-line summary for every built-in preset, for `--guide` and
/// the `resolve` error message.
pub const BUILTIN_PRESETS: &[(&str, &str)] = &[
    ("pentest-internal", "SYN + -sV + -O, T4 adaptive — internal engagement"),
    ("compliance-pci", "all TCP ports + -sV + TLS grade, T4 — PCI-DSS posture"),
    ("bugbounty-web", "connect web ports + --web-scan + TLS grade, T3 — web surface"),
    ("homelab-discover", "SYN top-100, T4 adaptive — fast lab sweep"),
];

/// Resolve a `--profile` value: a built-in preset name when it matches one,
/// otherwise a path to a TOML profile file.
pub fn resolve(spec: &str) -> Result<Profile> {
    if let Some(p) = builtin(spec) {
        return Ok(p);
    }
    load(spec).with_context(|| {
        let names: Vec<&str> = BUILTIN_PRESETS.iter().map(|(n, _)| *n).collect();
        format!(
            "'{}' is neither a built-in preset ({}) nor a readable profile file",
            spec,
            names.join(", ")
        )
    })
}

pub fn save(path: &str, p: &Profile) -> Result<()> {
    let s = toml::to_string_pretty(p).context("serialize profile to TOML")?;
    fs::write(path, s).with_context(|| format!("write {}", path))?;
    Ok(())
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
