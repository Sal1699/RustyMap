//! Suggest Metasploit modules matching scan findings.
//!
//! Two entry points, both **read-only**:
//!
//!   - `suggest_by_cve(client, "CVE-2021-44228")` → calls
//!     `module.search "cve:CVE-2021-44228"` and returns the matched
//!     module list with rank, type, and short description.
//!   - `suggest_for_findings(client, findings)` → for each finding
//!     whose `detail` mentions a CVE id, fan out the lookup, then
//!     return all hits keyed by finding.
//!
//! Output is ranked by MSF's own module rank (excellent → manual).
//! The caller decides whether to filter — we surface everything so
//! the operator can spot pre-auth options at a glance.

use crate::compliance::Finding;
use crate::msf_import::extract_cve_refs;
use crate::msf_rpc::{value_as_str, Client, Value};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleHit {
    pub fullname: String,
    pub kind: String,        // exploit / auxiliary / post / payload
    pub rank: Option<String>, // excellent / good / normal / average / low / manual
    pub disclosure: Option<String>,
    pub description: Option<String>,
}

pub async fn suggest_by_cve(client: &Client, cve: &str) -> Result<Vec<ModuleHit>> {
    let query = format!("cve:{}", cve);
    let resp = client
        .call("module.search", &[Value::from(query)])
        .await?;
    Ok(parse_search_result(&resp))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSuggestion {
    pub finding_kind: String,
    pub finding_host: String,
    pub cves: Vec<String>,
    pub hits: Vec<ModuleHit>,
}

pub async fn suggest_for_findings(
    client: &Client,
    findings: &[Finding],
) -> Result<Vec<FindingSuggestion>> {
    let mut out = Vec::new();
    let mut cve_cache: std::collections::HashMap<String, Vec<ModuleHit>> = Default::default();
    for f in findings {
        let cves = extract_cve_refs(&f.detail);
        if cves.is_empty() {
            continue;
        }
        let mut combined: Vec<ModuleHit> = Vec::new();
        for cve in &cves {
            let hits = if let Some(cached) = cve_cache.get(cve) {
                cached.clone()
            } else {
                let h = suggest_by_cve(client, cve).await.unwrap_or_default();
                cve_cache.insert(cve.clone(), h.clone());
                h
            };
            combined.extend(hits);
        }
        // Deduplicate by fullname
        combined.sort_by(|a, b| a.fullname.cmp(&b.fullname));
        combined.dedup_by(|a, b| a.fullname == b.fullname);
        out.push(FindingSuggestion {
            finding_kind: f.kind.clone(),
            finding_host: f.host.clone(),
            cves,
            hits: combined,
        });
    }
    Ok(out)
}

/// Decode the msgpack reply MSF's `module.search` returns. Shape is
/// a map with a `"modules"` array whose entries are themselves maps.
pub fn parse_search_result(resp: &Value) -> Vec<ModuleHit> {
    let map = match resp.as_map() {
        Some(m) => m,
        None => return Vec::new(),
    };
    let modules = match map.iter().find_map(|(k, v)| {
        let ks = value_as_str(k);
        if ks.as_deref() == Some("modules") {
            v.as_array()
        } else {
            None
        }
    }) {
        Some(arr) => arr,
        None => return Vec::new(),
    };
    modules
        .iter()
        .filter_map(parse_module_entry)
        .collect()
}

fn parse_module_entry(v: &Value) -> Option<ModuleHit> {
    let m = v.as_map()?;
    let get = |key: &str| -> Option<String> {
        m.iter().find_map(|(k, val)| {
            let ks = value_as_str(k);
            if ks.as_deref() == Some(key) {
                value_as_str(val)
            } else {
                None
            }
        })
    };
    let fullname = get("fullname").or_else(|| get("name"))?;
    let kind = get("type").unwrap_or_else(|| "unknown".into());
    Some(ModuleHit {
        fullname,
        kind,
        rank: get("rank"),
        disclosure: get("disclosure_date"),
        description: get("description"),
    })
}

pub fn print_suggestions(suggestions: &[FindingSuggestion]) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!("MSF suggestions — {} finding(s) with CVE refs", suggestions.len()).bold()
    );
    for sug in suggestions {
        println!(
            "  {} @ {} → CVEs: {}",
            sug.finding_kind.bold().yellow(),
            sug.finding_host,
            sug.cves.join(", ")
        );
        if sug.hits.is_empty() {
            println!("    {}", "no MSF modules matched".dimmed());
            continue;
        }
        // Fase 25 v0.67.0: also offer a copy-pasteable --msf-fire
        // invocation with RHOSTS already prefilled from the finding's
        // host. Operator skips the boilerplate when they decide to
        // run one of the suggested modules.
        for h in &sug.hits {
            let rank = h.rank.as_deref().unwrap_or("?");
            let rank_color = match rank {
                "excellent" | "great" => rank.green().bold().to_string(),
                "good" => rank.green().to_string(),
                "normal" => rank.cyan().to_string(),
                "average" => rank.yellow().to_string(),
                "low" | "manual" => rank.dimmed().to_string(),
                _ => rank.to_string(),
            };
            println!(
                "    {:<10} {:<10} {}",
                h.kind.dimmed(),
                rank_color,
                h.fullname
            );
            if let Some(d) = &h.description {
                let snip: String = d.chars().take(110).collect();
                println!("      {}", snip.dimmed());
            }
            let fire_line = build_fire_line(&h.fullname, &h.kind, &sug.finding_host);
            println!("      {} {}", "→".dimmed(), fire_line.cyan());
        }
    }
}

/// Build a runnable `--msf-fire ...` invocation for the operator to
/// copy. Pre-fills RHOSTS from the finding's host. For exploit-class
/// modules we also propose `--msf-fire-exploits` since `--msf-fire`
/// alone refuses those without the explicit flag.
pub fn build_fire_line(module: &str, kind: &str, host: &str) -> String {
    let exploit_flag = if kind == "exploit" {
        " --msf-fire-exploits"
    } else {
        ""
    };
    format!(
        "rustymap --msf-fire {} --msf-fire-confirm{} --msf-fire-opt RHOSTS={} --msf-url $MSF_URL --msf-token $MSF_TOKEN",
        module, exploit_flag, host
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_module_entry(
        fullname: &str,
        kind: &str,
        rank: Option<&str>,
        desc: Option<&str>,
    ) -> Value {
        let mut m: Vec<(Value, Value)> = vec![
            (Value::from("fullname"), Value::from(fullname)),
            (Value::from("type"), Value::from(kind)),
        ];
        if let Some(r) = rank {
            m.push((Value::from("rank"), Value::from(r)));
        }
        if let Some(d) = desc {
            m.push((Value::from("description"), Value::from(d)));
        }
        Value::Map(m)
    }

    #[test]
    fn parse_search_result_decodes_modules_array() {
        let resp = Value::Map(vec![(
            Value::from("modules"),
            Value::Array(vec![
                make_module_entry(
                    "exploit/multi/http/log4shell_header_injection",
                    "exploit",
                    Some("excellent"),
                    Some("Log4Shell"),
                ),
                make_module_entry(
                    "auxiliary/scanner/http/log4shell_scanner",
                    "auxiliary",
                    Some("normal"),
                    None,
                ),
            ]),
        )]);
        let hits = parse_search_result(&resp);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].fullname, "exploit/multi/http/log4shell_header_injection");
        assert_eq!(hits[0].rank.as_deref(), Some("excellent"));
        assert_eq!(hits[0].description.as_deref(), Some("Log4Shell"));
        assert_eq!(hits[1].kind, "auxiliary");
    }

    #[test]
    fn parse_search_result_handles_empty_modules() {
        let resp = Value::Map(vec![(Value::from("modules"), Value::Array(vec![]))]);
        assert!(parse_search_result(&resp).is_empty());
    }

    #[test]
    fn parse_search_result_handles_missing_modules_key() {
        let resp = Value::Map(vec![(Value::from("error"), Value::Boolean(true))]);
        assert!(parse_search_result(&resp).is_empty());
    }

    #[test]
    fn parse_module_entry_requires_fullname_or_name() {
        let entry = Value::Map(vec![
            (Value::from("name"), Value::from("aux/scanner/x")),
            (Value::from("type"), Value::from("auxiliary")),
        ]);
        let hit = parse_module_entry(&entry).unwrap();
        assert_eq!(hit.fullname, "aux/scanner/x");
        assert_eq!(hit.kind, "auxiliary");
    }

    #[test]
    fn parse_module_entry_returns_none_without_identity() {
        let entry = Value::Map(vec![(Value::from("type"), Value::from("post"))]);
        assert!(parse_module_entry(&entry).is_none());
    }

    #[test]
    fn fire_line_includes_rhosts_and_confirm() {
        let line = build_fire_line("auxiliary/scanner/smb/smb_ms17_010", "auxiliary", "10.0.0.5");
        assert!(line.contains("--msf-fire auxiliary/scanner/smb/smb_ms17_010"));
        assert!(line.contains("--msf-fire-confirm"));
        assert!(line.contains("RHOSTS=10.0.0.5"));
        // auxiliary modules don't need --msf-fire-exploits
        assert!(!line.contains("--msf-fire-exploits"));
    }

    #[test]
    fn fire_line_adds_exploits_flag_for_exploit_modules() {
        let line = build_fire_line("exploit/multi/http/log4shell", "exploit", "10.0.0.7");
        assert!(line.contains("--msf-fire-exploits"));
        assert!(line.contains("RHOSTS=10.0.0.7"));
    }
}
