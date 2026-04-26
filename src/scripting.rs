use crate::scanner::HostResult;
use anyhow::{Context, Result};
use rhai::{Array, Dynamic, Engine, Map, Scope};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub script: String,
    pub host: String,
    pub port: Option<u16>,
    pub severity: String,
    pub message: String,
}

fn host_to_map(h: &HostResult) -> Map {
    let mut m = Map::new();
    m.insert("ip".into(), Dynamic::from(h.target.ip.to_string()));
    m.insert(
        "hostname".into(),
        match &h.target.hostname {
            Some(n) => Dynamic::from(n.clone()),
            None => Dynamic::UNIT,
        },
    );
    m.insert("up".into(), Dynamic::from(h.up));

    let ports: Array = h
        .ports
        .iter()
        .map(|p| {
            let mut pm = Map::new();
            pm.insert("port".into(), Dynamic::from(p.port as i64));
            pm.insert("state".into(), Dynamic::from(p.state.as_str().to_string()));
            if let Some(svc) = &p.service {
                let mut sm = Map::new();
                sm.insert(
                    "product".into(),
                    svc.product.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                );
                sm.insert(
                    "version".into(),
                    svc.version.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                );
                sm.insert(
                    "banner".into(),
                    svc.banner.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                );
                if let Some(tls) = &svc.tls {
                    let mut tm = Map::new();
                    tm.insert(
                        "negotiated".into(),
                        tls.negotiated.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                    );
                    tm.insert(
                        "subject".into(),
                        tls.subject.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                    );
                    tm.insert(
                        "issuer".into(),
                        tls.issuer.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                    );
                    tm.insert(
                        "not_after".into(),
                        tls.not_after.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                    );
                    tm.insert("self_signed".into(), Dynamic::from(tls.self_signed));
                    tm.insert("expired".into(), Dynamic::from(tls.expired));
                    if let Some(b) = tls.key_bits {
                        tm.insert("key_bits".into(), Dynamic::from(b as i64));
                    }
                    let sans: Array = tls.san.iter().cloned().map(Dynamic::from).collect();
                    tm.insert("san".into(), Dynamic::from(sans));
                    sm.insert("tls".into(), Dynamic::from(tm));
                }
                pm.insert("service".into(), Dynamic::from(sm));
            }
            Dynamic::from(pm)
        })
        .collect();
    m.insert("ports".into(), Dynamic::from(ports));

    if let Some(os) = &h.os {
        let mut om = Map::new();
        om.insert("family".into(), Dynamic::from(os.family.clone()));
        om.insert("confidence".into(), Dynamic::from(os.confidence as i64));
        m.insert("os".into(), Dynamic::from(om));
    }
    m
}

fn discover_scripts(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(path).with_context(|| format!("read_dir {:?}", path))? {
        let e = entry?;
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) == Some("rhai") {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

/// Extract the first non-empty comment line from a rhai script — used as
/// the "description" in --script-help. Comments start with `//`.
fn description_of(src: &str) -> String {
    for line in src.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("//") {
            let cleaned = rest.trim().trim_end_matches('.').to_string();
            if !cleaned.is_empty() {
                return cleaned;
            }
        } else if !l.is_empty() {
            // First non-comment line — no description available.
            return "(no description)".into();
        }
    }
    "(no description)".into()
}

/// Print the catalog of built-in and (optionally) user scripts.
pub fn print_help(user_path: Option<&str>) {
    use colored::*;
    println!(
        "\n{}\n",
        "RustyMap rhai scripts".bold().cyan()
    );
    println!("{}", "Built-in:".bold());
    for (name, src) in builtin_scripts() {
        println!(
            "  {:<22} {}",
            name.green().bold(),
            description_of(src)
        );
    }
    if let Some(path) = user_path {
        let p = Path::new(path);
        match discover_scripts(p) {
            Ok(scripts) if !scripts.is_empty() => {
                println!("\n{}", "User scripts:".bold());
                for sp in scripts {
                    let name = sp
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("script")
                        .to_string();
                    let desc = std::fs::read_to_string(&sp)
                        .map(|src| description_of(&src))
                        .unwrap_or_else(|_| "(unreadable)".into());
                    println!("  {:<22} {}", name.yellow().bold(), desc);
                }
            }
            _ => {}
        }
    }
    println!(
        "\n{}",
        "Run with --script PATH (or rely on built-ins, --no-builtin-scripts to opt out).".dimmed()
    );
}

/// Scripts baked into the binary at build time. Returns (name, source) pairs.
pub fn builtin_scripts() -> Vec<(&'static str, &'static str)> {
    vec![
        ("anonymous-ftp", include_str!("../scripts/anonymous-ftp.rhai")),
        ("cleartext-protocols", include_str!("../scripts/cleartext-protocols.rhai")),
        ("default-cred-likely", include_str!("../scripts/default-cred-likely.rhai")),
        ("dns-zone-transfer-hint", include_str!("../scripts/dns-zone-transfer-hint.rhai")),
        ("docker-api-exposed", include_str!("../scripts/docker-api-exposed.rhai")),
        ("elasticsearch-open", include_str!("../scripts/elasticsearch-open.rhai")),
        ("exposed-management", include_str!("../scripts/exposed-management.rhai")),
        ("http-admin-paths", include_str!("../scripts/http-admin-paths.rhai")),
        ("ipmi-exposed", include_str!("../scripts/ipmi-exposed.rhai")),
        ("jenkins-anonymous", include_str!("../scripts/jenkins-anonymous.rhai")),
        ("k8s-api-exposed", include_str!("../scripts/k8s-api-exposed.rhai")),
        ("mongodb-no-auth", include_str!("../scripts/mongodb-no-auth.rhai")),
        ("mqtt-anonymous", include_str!("../scripts/mqtt-anonymous.rhai")),
        ("mssql-default", include_str!("../scripts/mssql-default.rhai")),
        ("old-openssh", include_str!("../scripts/old-openssh.rhai")),
        ("redis-no-auth", include_str!("../scripts/redis-no-auth.rhai")),
        ("smb-exposed", include_str!("../scripts/smb-exposed.rhai")),
        ("snmp-public", include_str!("../scripts/snmp-public.rhai")),
        ("tls-cert-issues", include_str!("../scripts/tls-cert-issues.rhai")),
        ("tls-deprecated", include_str!("../scripts/tls-deprecated.rhai")),
        ("vnc-no-auth", include_str!("../scripts/vnc-no-auth.rhai")),
    ]
}

use std::sync::atomic::{AtomicBool, Ordering};
static SCRIPT_TRACE: AtomicBool = AtomicBool::new(false);

pub fn set_trace(on: bool) {
    SCRIPT_TRACE.store(on, Ordering::Relaxed);
}

fn trace_event(script: &str, host: &str, status: &str, detail: &str) {
    if !SCRIPT_TRACE.load(Ordering::Relaxed) {
        return;
    }
    // JSON Lines so the user can pipe stderr into jq.
    let now = chrono::Utc::now().to_rfc3339();
    eprintln!(
        "{{\"ts\":\"{}\",\"script\":\"{}\",\"host\":\"{}\",\"status\":\"{}\",\"detail\":{}}}",
        now,
        script,
        host,
        status,
        serde_json::to_string(detail).unwrap_or_else(|_| "\"\"".into())
    );
}

/// Run a list of (name, source) scripts against a host set.
pub fn run_inline(
    scripts: &[(&str, &str)],
    hosts: &[HostResult],
    script_args: &[(String, String)],
) -> Vec<Finding> {
    if scripts.is_empty() {
        return Vec::new();
    }
    let engine = Engine::new();
    let args_map: Map = script_args
        .iter()
        .map(|(k, v)| (k.clone().into(), Dynamic::from(v.clone())))
        .collect();
    let mut findings = Vec::new();

    for (name, src) in scripts {
        let ast = match engine.compile(*src) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("[script {}] parse error: {}", name, e);
                trace_event(name, "-", "parse_error", &e.to_string());
                continue;
            }
        };
        for h in hosts {
            if !h.up {
                continue;
            }
            let host_map = host_to_map(h);
            let mut scope = Scope::new();
            scope.push_dynamic("host", Dynamic::from(host_map));
            scope.push_dynamic("args", Dynamic::from(args_map.clone()));
            scope.push_dynamic("findings", Dynamic::from(Array::new()));
            let host_s = h.target.ip.to_string();
            trace_event(name, &host_s, "start", "");
            if let Err(e) = engine.run_ast_with_scope(&mut scope, &ast) {
                eprintln!("[script {} host {}] runtime error: {}", name, h.target.ip, e);
                trace_event(name, &host_s, "runtime_error", &e.to_string());
                continue;
            }
            let mut emitted = 0usize;
            if let Some(arr) = scope.get_value::<Array>("findings") {
                for v in arr {
                    if let Some(m) = v.try_cast::<Map>() {
                        let sev = m.get("severity").and_then(|d| d.clone().into_string().ok())
                            .unwrap_or_else(|| "info".into());
                        let msg = m.get("message").and_then(|d| d.clone().into_string().ok())
                            .unwrap_or_default();
                        let port = m.get("port").and_then(|d| d.as_int().ok()).map(|i| i as u16);
                        findings.push(Finding {
                            script: name.to_string(),
                            host: host_s.clone(),
                            port,
                            severity: sev,
                            message: msg,
                        });
                        emitted += 1;
                    }
                }
            }
            trace_event(name, &host_s, "done", &format!("{} finding(s)", emitted));
        }
    }
    findings
}

pub fn run_scripts(
    scripts_path: &str,
    hosts: &[HostResult],
    script_args: &[(String, String)],
) -> Result<Vec<Finding>> {
    let path = Path::new(scripts_path);
    let scripts = discover_scripts(path)?;
    if scripts.is_empty() {
        return Ok(vec![]);
    }

    let engine = Engine::new();
    let mut findings = Vec::new();
    let args_map: Map = script_args
        .iter()
        .map(|(k, v)| (k.clone().into(), Dynamic::from(v.clone())))
        .collect();

    for script_path in &scripts {
        let src = fs::read_to_string(script_path)
            .with_context(|| format!("read {:?}", script_path))?;
        let script_name = script_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("script")
            .to_string();

        let ast = match engine.compile(&src) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("[script {}] parse error: {}", script_name, e);
                continue;
            }
        };

        for h in hosts {
            if !h.up {
                continue;
            }
            let host_map = host_to_map(h);
            let mut scope = Scope::new();
            scope.push_dynamic("host", Dynamic::from(host_map));
            scope.push_dynamic("args", Dynamic::from(args_map.clone()));
            scope.push_dynamic("findings", Dynamic::from(Array::new()));

            if let Err(e) = engine.run_ast_with_scope(&mut scope, &ast) {
                eprintln!("[script {} host {}] runtime error: {}", script_name, h.target.ip, e);
                continue;
            }

            if let Some(arr) = scope.get_value::<Array>("findings") {
                for v in arr {
                    if let Some(m) = v.try_cast::<Map>() {
                        let sev = m.get("severity").and_then(|d| d.clone().into_string().ok())
                            .unwrap_or_else(|| "info".into());
                        let msg = m.get("message").and_then(|d| d.clone().into_string().ok())
                            .unwrap_or_default();
                        let port = m.get("port").and_then(|d| d.as_int().ok()).map(|i| i as u16);
                        findings.push(Finding {
                            script: script_name.clone(),
                            host: h.target.ip.to_string(),
                            port,
                            severity: sev,
                            message: msg,
                        });
                    }
                }
            }
        }
    }

    Ok(findings)
}

pub fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    println!("\n-- Script findings --");
    for f in findings {
        let loc = match f.port {
            Some(p) => format!("{}:{}", f.host, p),
            None => f.host.clone(),
        };
        println!("  [{}] {} ({}) — {}", f.severity, loc, f.script, f.message);
    }
}
