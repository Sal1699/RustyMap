//! Fase 36 — SARIF 2.1.0 export (`--sarif FILE`).
//!
//! SARIF (Static Analysis Results Interchange Format) is what CI systems —
//! GitHub code scanning, Azure DevOps, etc. — ingest to render findings inline.
//! We map each RustyMap finding (CVE hit, weak-TLS, script finding, exposed
//! service) to a SARIF `result`, and each open port to an informational
//! `note`, so a scan drops straight into a security dashboard.

use crate::compliance::Finding;
use crate::scanner::{HostResult, PortState};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

/// SARIF severity level for a finding, from its `kind`.
fn level_for(kind: &str) -> &'static str {
    let k = kind.to_lowercase();
    if k.contains("cve") || k.contains("critical") || k.contains("exploit") {
        "error"
    } else if k.contains("weak")
        || k.contains("deprecated")
        || k.contains("expired")
        || k.contains("exposed")
        || k.contains("vuln")
    {
        "warning"
    } else {
        "note"
    }
}

/// Build a SARIF 2.1.0 document (pretty JSON) for the scan.
pub fn to_sarif(hosts: &[HostResult], findings: &[Finding], version: &str) -> String {
    // Collect the distinct rule ids referenced, so the tool.driver.rules list
    // is well-formed (SARIF viewers key results to rules by id).
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut results: Vec<Value> = Vec::new();

    let mut add_rule = |rules: &mut BTreeMap<String, Value>, id: &str, desc: &str| {
        rules.entry(id.to_string()).or_insert_with(|| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": desc }
            })
        });
    };

    for f in findings {
        let id = if f.kind.trim().is_empty() { "finding" } else { f.kind.as_str() };
        add_rule(&mut rules, id, id);
        results.push(json!({
            "ruleId": id,
            "level": level_for(id),
            "message": { "text": f.detail },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": format!("host://{}", f.host) }
                }
            }]
        }));
    }

    // Open ports as informational notes (the inventory side of the scan).
    add_rule(&mut rules, "open-port", "An open TCP/UDP port was found");
    for h in hosts.iter().filter(|h| h.up) {
        for p in h.ports.iter().filter(|p| p.state == PortState::Open) {
            let svc = p
                .service
                .as_ref()
                .map(|s| s.display())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "open".to_string());
            let cat = crate::portdesc::category(p.port);
            results.push(json!({
                "ruleId": "open-port",
                "level": "note",
                "message": { "text": format!("port {} open ({}) [{}]", p.port, svc, cat) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": format!("host://{}", h.target.ip) }
                    }
                }]
            }));
        }
    }

    let rules_vec: Vec<Value> = rules.into_values().collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RustyMap",
                    "informationUri": "https://github.com/Sal1699/RustyMap",
                    "version": version,
                    "rules": rules_vec
                }
            },
            "results": results
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

pub fn write(path: &Path, hosts: &[HostResult], findings: &[Finding], version: &str) -> Result<()> {
    std::fs::write(path, to_sarif(hosts, findings, version))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_mapping() {
        assert_eq!(level_for("CVE-2021-44228"), "error");
        assert_eq!(level_for("weak-tls"), "warning");
        assert_eq!(level_for("exposed-service"), "warning");
        assert_eq!(level_for("info-banner"), "note");
    }

    #[test]
    fn sarif_is_valid_json_with_expected_shape() {
        let findings = vec![Finding::new("CVE-2017-0144", "192.168.1.31", "EternalBlue (SMBv1)")];
        let s = to_sarif(&[], &findings, "0.94.0");
        let v: Value = serde_json::from_str(&s).expect("valid JSON");
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "RustyMap");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "CVE-2017-0144");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
        // The referenced rule is declared.
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["id"] == "CVE-2017-0144"));
    }

    #[test]
    fn empty_scan_still_valid_sarif() {
        let s = to_sarif(&[], &[], "0.94.0");
        let v: Value = serde_json::from_str(&s).expect("valid JSON");
        assert_eq!(v["version"], "2.1.0");
        assert!(v["runs"][0]["results"].as_array().unwrap().is_empty());
    }
}
