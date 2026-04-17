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

pub fn run_scripts(scripts_path: &str, hosts: &[HostResult]) -> Result<Vec<Finding>> {
    let path = Path::new(scripts_path);
    let scripts = discover_scripts(path)?;
    if scripts.is_empty() {
        return Ok(vec![]);
    }

    let engine = Engine::new();
    let mut findings = Vec::new();

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
