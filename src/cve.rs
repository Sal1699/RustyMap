use crate::scanner::HostResult;
use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// A CVE entry loadable from a JSON file.
///
/// product_regex/version_regex are case-insensitive regexes matched against the
/// -sV product and version strings. version_regex may be omitted to match any.
#[derive(Debug, Clone, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub product_regex: String,
    #[serde(default)]
    pub version_regex: Option<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
    pub description: String,
    #[serde(default)]
    pub reference: Option<String>,
}

fn default_severity() -> String { "medium".into() }

#[derive(Debug, Clone, Serialize)]
pub struct CveHit {
    pub host: String,
    pub port: u16,
    pub cve: String,
    pub severity: String,
    pub description: String,
    pub reference: Option<String>,
    pub matched_product: String,
    pub matched_version: Option<String>,
}

pub struct Compiled {
    entry: CveEntry,
    product_re: Regex,
    version_re: Option<Regex>,
}

fn compile_db(entries: Vec<CveEntry>) -> Vec<Compiled> {
    entries
        .into_iter()
        .filter_map(|e| {
            let p = format!("(?i){}", e.product_regex);
            let pr = Regex::new(&p).ok()?;
            let vr = e
                .version_regex
                .as_ref()
                .and_then(|v| Regex::new(&format!("(?i){}", v)).ok());
            Some(Compiled { entry: e, product_re: pr, version_re: vr })
        })
        .collect()
}

pub fn load_db(path: &str) -> Result<Vec<Compiled>> {
    let p = Path::new(path);
    let data = fs::read_to_string(p).with_context(|| format!("read {}", path))?;
    let entries: Vec<CveEntry> = serde_json::from_str(&data).context("parse CVE db")?;
    Ok(compile_db(entries))
}

pub fn correlate(db: &[Compiled], hosts: &[HostResult]) -> Vec<CveHit> {
    let mut out = Vec::new();
    for h in hosts {
        if !h.up { continue; }
        for port in &h.ports {
            let svc = match &port.service { Some(s) => s, None => continue };
            let product = svc.product.clone().unwrap_or_default();
            let version = svc.version.clone().unwrap_or_default();
            if product.is_empty() { continue; }
            for c in db {
                if !c.product_re.is_match(&product) { continue; }
                if let Some(vr) = &c.version_re {
                    if !vr.is_match(&version) { continue; }
                }
                out.push(CveHit {
                    host: h.target.ip.to_string(),
                    port: port.port,
                    cve: c.entry.id.clone(),
                    severity: c.entry.severity.clone(),
                    description: c.entry.description.clone(),
                    reference: c.entry.reference.clone(),
                    matched_product: product.clone(),
                    matched_version: if version.is_empty() { None } else { Some(version.clone()) },
                });
            }
        }
    }
    out
}

pub fn print_hits(hits: &[CveHit]) {
    if hits.is_empty() {
        println!("\nCVE correlation: no known CVEs matched.");
        return;
    }
    println!("\n-- CVE correlation --");
    for h in hits {
        let ver = h.matched_version.clone().unwrap_or_else(|| "?".into());
        println!(
            "  [{}] {}:{} {} {} — {}",
            h.severity.to_uppercase(), h.host, h.port, h.matched_product, ver, h.cve
        );
        println!("       {}", h.description);
        if let Some(r) = &h.reference { println!("       ref: {}", r); }
    }
}
