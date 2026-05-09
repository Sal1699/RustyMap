//! MISP threat-intel sync + target matching.
//!
//! `--threat-intel-misp URL` queries a MISP instance's
//! `/events/restSearch` REST endpoint with the supplied API key,
//! pulls every Attribute (IoC) from the returned events, and caches
//! the relevant subset (IPs / domains / hashes / URLs) at
//! `~/.cache/rustymap/misp.json`.
//!
//! `--threat-intel-match` is honored *during a scan*: as targets are
//! resolved, each IP / hostname is looked up against the cached IoC
//! set; matches are surfaced as a finding the compliance evaluator
//! treats as critical (`threat_intel_match` kind).
//!
//! We deliberately keep the cache local so the scan can run offline
//! once the sync has happened — useful for air-gapped lab work.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MispCache {
    pub fetched_at_secs: u64,
    pub source: String,
    pub ips: HashSet<String>,
    pub domains: HashSet<String>,
    pub hashes: HashSet<String>,
    pub urls: HashSet<String>,
    /// IoC value → list of (event_id, category) so a match can show
    /// what the upstream context was.
    pub provenance: std::collections::HashMap<String, Vec<(String, String)>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMatch {
    pub host: String,
    pub ioc_type: &'static str,
    pub ioc_value: String,
    pub provenance: Vec<(String, String)>,
}

pub fn cache_path() -> PathBuf {
    let mut base = if let Ok(d) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(d)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache")
    } else if let Ok(profile) = std::env::var("USERPROFILE") {
        PathBuf::from(profile).join(".cache")
    } else {
        PathBuf::from(".")
    };
    base.push("rustymap");
    base.push("misp.json");
    base
}

#[derive(Debug, Clone, Deserialize)]
struct MispResponse {
    response: Vec<MispEvent>,
}

#[derive(Debug, Clone, Deserialize)]
struct MispEvent {
    #[serde(rename = "Event")]
    event: MispEventInner,
}

#[derive(Debug, Clone, Deserialize)]
struct MispEventInner {
    #[serde(default)]
    id: String,
    #[serde(rename = "Attribute", default)]
    attributes: Vec<MispAttribute>,
}

#[derive(Debug, Clone, Deserialize)]
struct MispAttribute {
    #[serde(rename = "type", default)]
    type_: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    category: String,
}

pub fn sync(misp_url: &str, api_key: &str, days: u32, verbose: bool) -> Result<MispCache> {
    if verbose {
        eprintln!("[threat-intel] querying {} for events from last {} days …", misp_url, days);
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/threat-intel")
        .build()?;

    let endpoint = format!(
        "{}/events/restSearch",
        misp_url.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "returnFormat": "json",
        "last": format!("{}d", days),
        "enforceWarninglist": true,
    });
    let resp = client
        .post(&endpoint)
        .header("Authorization", api_key)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .context("MISP /events/restSearch request")?;

    if !resp.status().is_success() {
        return Err(anyhow!("MISP returned HTTP {}", resp.status()));
    }
    let parsed: MispResponse = resp.json().context("parse MISP JSON")?;

    let mut cache = MispCache {
        fetched_at_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        source: misp_url.to_string(),
        ..Default::default()
    };

    for ev in &parsed.response {
        let event_id = ev.event.id.clone();
        for a in &ev.event.attributes {
            classify_attribute(&mut cache, &event_id, a);
        }
    }
    save(&cache).context("write MISP cache")?;
    if verbose {
        eprintln!(
            "[threat-intel] cached {} ips · {} domains · {} hashes · {} urls",
            cache.ips.len(),
            cache.domains.len(),
            cache.hashes.len(),
            cache.urls.len()
        );
    }
    Ok(cache)
}

fn classify_attribute(cache: &mut MispCache, event_id: &str, a: &MispAttribute) {
    if a.value.is_empty() {
        return;
    }
    let value = a.value.trim().to_lowercase();
    let provenance_entry = (event_id.to_string(), a.category.clone());

    let bucket: Option<&mut HashSet<String>> = match a.type_.as_str() {
        "ip-src" | "ip-dst" | "ip" => Some(&mut cache.ips),
        "domain" | "hostname" => Some(&mut cache.domains),
        "url" | "uri" => Some(&mut cache.urls),
        "md5" | "sha1" | "sha256" | "sha512" | "filename|md5" | "filename|sha256" => {
            Some(&mut cache.hashes)
        }
        _ => None,
    };

    if let Some(set) = bucket {
        set.insert(value.clone());
        cache
            .provenance
            .entry(value)
            .or_default()
            .push(provenance_entry);
    }
}

pub fn save(c: &MispCache) -> Result<()> {
    let p = cache_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&p, serde_json::to_string(c)?)?;
    Ok(())
}

pub fn load() -> MispCache {
    std::fs::read_to_string(cache_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Match a list of (ip, hostname?) tuples against the cache.
pub fn match_targets(cache: &MispCache, targets: &[(String, Option<String>)]) -> Vec<ThreatMatch> {
    let mut out = Vec::new();
    for (ip, hostname) in targets {
        let ip_lower = ip.to_lowercase();
        if cache.ips.contains(&ip_lower) {
            out.push(ThreatMatch {
                host: ip.clone(),
                ioc_type: "ip",
                ioc_value: ip_lower.clone(),
                provenance: cache.provenance.get(&ip_lower).cloned().unwrap_or_default(),
            });
        }
        if let Some(h) = hostname {
            let h_lower = h.to_lowercase();
            if cache.domains.contains(&h_lower) {
                out.push(ThreatMatch {
                    host: ip.clone(),
                    ioc_type: "domain",
                    ioc_value: h_lower.clone(),
                    provenance: cache.provenance.get(&h_lower).cloned().unwrap_or_default(),
                });
            }
        }
    }
    out
}

pub fn print(matches: &[ThreatMatch]) {
    use colored::*;
    if matches.is_empty() {
        return;
    }
    println!();
    println!(
        "{}",
        format!("Threat-intel match — {} hit(s)", matches.len())
            .red()
            .bold()
    );
    for m in matches {
        let prov: Vec<String> = m
            .provenance
            .iter()
            .map(|(eid, cat)| format!("event {} ({})", eid, cat))
            .collect();
        println!(
            "  · {} {} → {} [{}]",
            m.ioc_type, m.ioc_value, m.host, prov.join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_ip_attribute_lands_in_ips() {
        let mut c = MispCache::default();
        let a = MispAttribute {
            type_: "ip-dst".into(),
            value: "1.2.3.4".into(),
            category: "Network activity".into(),
        };
        classify_attribute(&mut c, "42", &a);
        assert!(c.ips.contains("1.2.3.4"));
        assert!(c.provenance.contains_key("1.2.3.4"));
    }

    #[test]
    fn classify_domain_lowercases() {
        let mut c = MispCache::default();
        let a = MispAttribute {
            type_: "domain".into(),
            value: "BAD.example.com".into(),
            category: "Network activity".into(),
        };
        classify_attribute(&mut c, "1", &a);
        assert!(c.domains.contains("bad.example.com"));
    }

    #[test]
    fn classify_hashes_into_hash_bucket() {
        let mut c = MispCache::default();
        for t in ["md5", "sha1", "sha256", "sha512"] {
            classify_attribute(
                &mut c,
                "x",
                &MispAttribute { type_: t.into(), value: format!("{}val", t), category: "Payload".into() },
            );
        }
        assert_eq!(c.hashes.len(), 4);
    }

    #[test]
    fn unknown_type_is_ignored() {
        let mut c = MispCache::default();
        classify_attribute(
            &mut c,
            "x",
            &MispAttribute { type_: "comment".into(), value: "asdf".into(), category: "x".into() },
        );
        assert!(c.ips.is_empty());
        assert!(c.domains.is_empty());
        assert!(c.urls.is_empty());
        assert!(c.hashes.is_empty());
    }

    #[test]
    fn match_targets_finds_ip_and_domain_hits() {
        let mut c = MispCache::default();
        c.ips.insert("10.0.0.1".into());
        c.domains.insert("evil.test".into());
        c.provenance.insert("10.0.0.1".into(), vec![("12".into(), "Network".into())]);
        let targets = vec![
            ("10.0.0.1".into(), Some("benign.test".into())),
            ("8.8.8.8".into(), Some("evil.test".into())),
        ];
        let m = match_targets(&c, &targets);
        assert_eq!(m.len(), 2);
        assert!(m.iter().any(|x| x.ioc_type == "ip" && x.host == "10.0.0.1"));
        assert!(m.iter().any(|x| x.ioc_type == "domain" && x.ioc_value == "evil.test"));
    }
}
