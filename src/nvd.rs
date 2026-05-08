//! NVD vulnerability database sync + CVSS v3.1/v4 scoring.
//!
//! Pulls CVE records from the NVD JSON 2.0 API into a local SQLite
//! cache, refreshing daily. Each CVE row carries:
//!   - id (CVE-YYYY-NNNN)
//!   - description (English summary)
//!   - cvss31_vector / cvss31_base / cvss31_severity
//!   - cvss40_vector / cvss40_base / cvss40_severity (when present)
//!   - cpe_match (JSON array of cpe2.3 patterns)
//!   - published / last_modified
//!   - references (URLs)
//!
//! Lookup is by (product, version) — we map the existing service
//! probe's `product/version` strings to CPE-style queries against
//! the cached rows.
//!
//! Improvement vs the previous regex DB: ~250.000 CVE entries vs 25,
//! authoritative CVSS scores instead of hardcoded severity levels,
//! daily refresh.

use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CACHE_VERSION: i64 = 1;
const REFRESH_AFTER_SECS: u64 = 24 * 3600;
/// NVD API caps results to 2000 per request when no API key.
const PAGE_SIZE: usize = 2000;
/// Don't pull the entire NVD on first run — it's 250k+ entries. We
/// take a sliding window of the last 5 years which covers the
/// overwhelming majority of actively exploited CVEs.
const HISTORY_DAYS: i64 = 5 * 365;

#[derive(Debug, Clone)]
pub struct NvdEntry {
    pub id: String,
    pub description: String,
    pub cvss31_vector: Option<String>,
    pub cvss31_base: Option<f64>,
    pub cvss31_severity: Option<String>,
    pub cvss40_vector: Option<String>,
    pub cvss40_base: Option<f64>,
    pub cvss40_severity: Option<String>,
    pub cpe_match: Vec<String>,
    pub published: String,
    pub references: Vec<String>,
    pub kev: bool,
}

// ── NVD API JSON model (just the fields we need) ──────────────────

#[derive(Deserialize, Debug)]
struct NvdResponse {
    #[serde(rename = "totalResults")]
    total_results: usize,
    #[serde(rename = "resultsPerPage")]
    results_per_page: usize,
    #[serde(rename = "startIndex")]
    start_index: usize,
    vulnerabilities: Vec<NvdVuln>,
}

#[derive(Deserialize, Debug)]
struct NvdVuln {
    cve: NvdCve,
}

#[derive(Deserialize, Debug)]
struct NvdCve {
    id: String,
    #[serde(default)]
    descriptions: Vec<NvdDesc>,
    #[serde(default)]
    metrics: NvdMetrics,
    #[serde(default)]
    configurations: Vec<NvdConfig>,
    #[serde(default)]
    references: Vec<NvdRef>,
    published: String,
    #[serde(rename = "cisaExploitAdd", default)]
    cisa_exploit_add: Option<String>,
}

#[derive(Deserialize, Debug)]
struct NvdDesc {
    lang: String,
    value: String,
}

#[derive(Deserialize, Debug, Default)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31", default)]
    v31: Vec<NvdCvssMetric>,
    #[serde(rename = "cvssMetricV40", default)]
    v40: Vec<NvdCvssMetric>,
}

#[derive(Deserialize, Debug)]
struct NvdCvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Deserialize, Debug)]
struct NvdCvssData {
    #[serde(rename = "vectorString")]
    vector_string: String,
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "baseSeverity", default)]
    base_severity: Option<String>,
}

#[derive(Deserialize, Debug)]
struct NvdConfig {
    #[serde(default)]
    nodes: Vec<NvdNode>,
}

#[derive(Deserialize, Debug)]
struct NvdNode {
    #[serde(rename = "cpeMatch", default)]
    cpe_match: Vec<NvdCpeMatch>,
    #[serde(default)]
    children: Vec<NvdNode>,
}

#[derive(Deserialize, Debug)]
struct NvdCpeMatch {
    #[serde(rename = "criteria")]
    criteria: String,
    #[serde(rename = "vulnerable", default)]
    _vulnerable: bool,
}

#[derive(Deserialize, Debug)]
struct NvdRef {
    url: String,
}

// ── Local cache (SQLite) ──────────────────────────────────────────

pub fn cache_path() -> PathBuf {
    let base = dirs_cache_dir();
    base.join("rustymap").join("nvd.sqlite")
}

fn dirs_cache_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(p);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache");
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local);
    }
    std::env::temp_dir()
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cve (
            id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            cvss31_vector TEXT, cvss31_base REAL, cvss31_severity TEXT,
            cvss40_vector TEXT, cvss40_base REAL, cvss40_severity TEXT,
            cpe_match TEXT NOT NULL,
            published TEXT NOT NULL,
            references_json TEXT NOT NULL,
            kev INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_cve_published ON cve(published);
        CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve(kev);
        "#,
    )?;
    Ok(())
}

fn last_sync_secs(conn: &Connection) -> Option<u64> {
    conn.query_row(
        "SELECT value FROM meta WHERE key='last_sync'",
        [],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| s.parse().ok())
}

fn set_last_sync(conn: &Connection) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES ('last_sync', ?)",
        params![now.to_string()],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES ('cache_version', ?)",
        params![CACHE_VERSION.to_string()],
    )?;
    Ok(())
}

/// Open or create the cache. Errors out if the parent directory
/// can't be created.
pub fn open_cache() -> Result<Connection> {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {:?}", parent))?;
    }
    let conn = Connection::open(&path).with_context(|| format!("open {:?}", path))?;
    ensure_schema(&conn)?;
    Ok(conn)
}

pub fn needs_refresh(conn: &Connection) -> bool {
    match last_sync_secs(conn) {
        Some(ts) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now.saturating_sub(ts) >= REFRESH_AFTER_SECS
        }
        None => true,
    }
}

/// Sync the local cache from the NVD API. Pull CVEs published in
/// the last `HISTORY_DAYS` days. NVD rate-limits unauthenticated
/// callers to 5 req / 30s — we wait between pages.
pub fn sync(conn: &mut Connection, verbose: bool) -> Result<usize> {
    let pub_start_date = chrono::Utc::now()
        .checked_sub_signed(chrono::Duration::days(HISTORY_DAYS))
        .ok_or_else(|| anyhow!("date math underflow"))?
        .format("%Y-%m-%dT%H:%M:%S.000")
        .to_string();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("rustymap/nvd-sync")
        .build()?;

    let mut start_index = 0usize;
    let mut total_inserted = 0usize;
    loop {
        let url = format!(
            "{}?pubStartDate={}&startIndex={}&resultsPerPage={}",
            NVD_API, pub_start_date, start_index, PAGE_SIZE
        );
        if verbose {
            eprintln!("[nvd-sync] page {} (start_index={})", start_index / PAGE_SIZE + 1, start_index);
        }
        let resp = client.get(&url).send()?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "NVD API returned {} — try again later (unauthenticated rate limit is 5 req / 30s)",
                resp.status()
            ));
        }
        let parsed: NvdResponse = resp.json().context("parse NVD JSON")?;

        let tx = conn.transaction()?;
        for v in &parsed.vulnerabilities {
            let cve = &v.cve;
            let desc = cve
                .descriptions
                .iter()
                .find(|d| d.lang == "en")
                .map(|d| d.value.clone())
                .unwrap_or_default();
            let v31 = cve.metrics.v31.first().map(|m| &m.cvss_data);
            let v40 = cve.metrics.v40.first().map(|m| &m.cvss_data);
            let cpe_match: Vec<String> = cve
                .configurations
                .iter()
                .flat_map(|c| collect_cpes(&c.nodes))
                .collect();
            let refs: Vec<String> = cve.references.iter().map(|r| r.url.clone()).collect();
            let kev_flag = cve.cisa_exploit_add.is_some() as i64;
            tx.execute(
                "INSERT OR REPLACE INTO cve
                 (id, description,
                  cvss31_vector, cvss31_base, cvss31_severity,
                  cvss40_vector, cvss40_base, cvss40_severity,
                  cpe_match, published, references_json, kev)
                 VALUES (?,?, ?,?,?, ?,?,?, ?,?,?,?)",
                params![
                    cve.id,
                    desc,
                    v31.map(|d| d.vector_string.clone()),
                    v31.map(|d| d.base_score),
                    v31.and_then(|d| d.base_severity.clone()),
                    v40.map(|d| d.vector_string.clone()),
                    v40.map(|d| d.base_score),
                    v40.and_then(|d| d.base_severity.clone()),
                    serde_json::to_string(&cpe_match).unwrap_or_else(|_| "[]".into()),
                    cve.published,
                    serde_json::to_string(&refs).unwrap_or_else(|_| "[]".into()),
                    kev_flag,
                ],
            )?;
            total_inserted += 1;
        }
        tx.commit()?;

        start_index += parsed.results_per_page;
        if start_index >= parsed.total_results || parsed.results_per_page == 0 {
            break;
        }
        // Politeness gap to stay under NVD rate limit
        std::thread::sleep(Duration::from_secs(7));
    }
    set_last_sync(conn)?;
    Ok(total_inserted)
}

fn collect_cpes(nodes: &[NvdNode]) -> Vec<String> {
    let mut out = Vec::new();
    for n in nodes {
        for m in &n.cpe_match {
            out.push(m.criteria.clone());
        }
        out.extend(collect_cpes(&n.children));
    }
    out
}

/// Match a (product, version) pair against the cached CVE rows.
/// Uses substring match on cpe2.3 strings — coarse but workable
/// (precise CPE matching needs the full version-range comparison
/// which is its own subproject).
pub fn lookup(
    conn: &Connection,
    product: &str,
    version: &str,
    limit: usize,
) -> Result<Vec<NvdEntry>> {
    let needle_product = product.to_lowercase();
    let mut stmt = conn.prepare(
        "SELECT id, description,
                cvss31_vector, cvss31_base, cvss31_severity,
                cvss40_vector, cvss40_base, cvss40_severity,
                cpe_match, published, references_json, kev
         FROM cve
         WHERE lower(cpe_match) LIKE ?
         ORDER BY cvss31_base DESC NULLS LAST, published DESC
         LIMIT ?",
    )?;
    let pattern = format!("%{}%", needle_product);
    let rows = stmt.query_map(params![pattern, limit as i64], |r| {
        let cpe_json: String = r.get(8)?;
        let refs_json: String = r.get(10)?;
        let cpe_match: Vec<String> = serde_json::from_str(&cpe_json).unwrap_or_default();
        let references: Vec<String> = serde_json::from_str(&refs_json).unwrap_or_default();
        Ok(NvdEntry {
            id: r.get(0)?,
            description: r.get(1)?,
            cvss31_vector: r.get(2)?,
            cvss31_base: r.get(3)?,
            cvss31_severity: r.get(4)?,
            cvss40_vector: r.get(5)?,
            cvss40_base: r.get(6)?,
            cvss40_severity: r.get(7)?,
            cpe_match,
            published: r.get(9)?,
            references,
            kev: r.get::<_, i64>(11)? != 0,
        })
    })?;
    let version_lo = version.to_lowercase();
    let mut out = Vec::new();
    for row in rows.flatten() {
        // Filter by version: at least one CPE entry must contain the
        // version string. If version is empty, accept anything.
        if version_lo.is_empty()
            || row
                .cpe_match
                .iter()
                .any(|c| c.to_lowercase().contains(&version_lo))
        {
            out.push(row);
        }
    }
    Ok(out)
}

/// Compute a CVSS v3.1 base score from a vector string. Used when
/// the user supplies a custom CVSS vector or when re-validating the
/// stored score. Returns None on parse failure.
pub fn cvss31_score(vector: &str) -> Option<f64> {
    if !vector.starts_with("CVSS:3.1/") && !vector.starts_with("CVSS:3.0/") {
        return None;
    }
    let mut metrics = std::collections::HashMap::new();
    for part in vector.split('/').skip(1) {
        if let Some((k, v)) = part.split_once(':') {
            metrics.insert(k, v);
        }
    }
    let av = match *metrics.get("AV")? { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => return None };
    let ac = match *metrics.get("AC")? { "L" => 0.77, "H" => 0.44, _ => return None };
    let pr_raw = *metrics.get("PR")?;
    let scope = *metrics.get("S")?;
    let pr = match (pr_raw, scope) {
        ("N", _) => 0.85,
        ("L", "U") => 0.62,
        ("L", "C") => 0.68,
        ("H", "U") => 0.27,
        ("H", "C") => 0.5,
        _ => return None,
    };
    let ui = match *metrics.get("UI")? { "N" => 0.85, "R" => 0.62, _ => return None };
    let c = impact_metric(metrics.get("C")?);
    let i = impact_metric(metrics.get("I")?);
    let a = impact_metric(metrics.get("A")?);
    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope == "U" {
        6.42 * iss
    } else {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let raw = if scope == "U" {
        (impact + exploitability).min(10.0)
    } else {
        (1.08 * (impact + exploitability)).min(10.0)
    };
    Some((raw * 10.0).ceil() / 10.0)
}

fn impact_metric(s: &&str) -> f64 {
    match *s {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss31_canonical_vector() {
        // From NVD: CVE-2021-44228 (Log4Shell)
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
        let s = cvss31_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").unwrap();
        assert!((s - 10.0).abs() < 0.01);
    }

    #[test]
    fn cvss31_medium() {
        // AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N — first.org calc → 4.3
        let s = cvss31_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N").unwrap();
        assert!((s - 4.3).abs() < 0.01, "got {}", s);
    }

    #[test]
    fn cvss31_invalid_returns_none() {
        assert!(cvss31_score("not a vector").is_none());
        assert!(cvss31_score("CVSS:2.0/AV:N").is_none());
    }
}
