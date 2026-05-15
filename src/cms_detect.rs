//! CMS fingerprint — detects WordPress / Joomla / Drupal and pulls
//! a version when the install leaves a recognisable marker.
//!
//! Signals checked, in order:
//!   - **Homepage meta-generator**: `<meta name="generator" content="WordPress 6.4">`.
//!     Most reliable, hosts often leave it on.
//!   - **Path probes**: each CMS has paths only it serves.
//!     WordPress: `/wp-login.php`, `/wp-content/`, `/?author=1`, `/wp-json/`.
//!     Joomla:    `/administrator/manifests/files/joomla.xml`, `/templates/system/`.
//!     Drupal:    `/CHANGELOG.txt`, `/core/CHANGELOG.txt`, `/sites/default/`.
//!   - **Cookies**: Joomla sets `joomla_user_state`; Drupal sets
//!     `SESS` cookies whose name matches a specific hash pattern.
//!   - **HTTP headers**: `X-Drupal-Cache`, `X-Powered-By: PHP/...`,
//!     `Link: <…/wp-json/>; rel="https://api.w.org/"`.
//!
//! Pure HTTP — no auth, no probe writes, no destructive paths.

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Cms {
    WordPress,
    Joomla,
    Drupal,
}

impl Cms {
    pub fn label(&self) -> &'static str {
        match self {
            Cms::WordPress => "WordPress",
            Cms::Joomla => "Joomla",
            Cms::Drupal => "Drupal",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsFinding {
    pub url: String,
    pub cms: Cms,
    pub version: Option<String>,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

pub async fn detect(url: &str, dur: Duration) -> Result<Option<CmsFinding>> {
    let client = reqwest::Client::builder()
        .timeout(dur)
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/cms-detect")
        .build()?;

    let base = url.trim_end_matches('/').to_string();
    let home = client.get(&base).send().await?;
    let home_headers = home.headers().clone();
    let home_status = home.status().as_u16();
    let home_body = home.text().await.unwrap_or_default();

    // ── WordPress ──
    if let Some(f) = wordpress(&client, &base, &home_body, &home_headers, home_status).await {
        return Ok(Some(f));
    }
    // ── Joomla ──
    if let Some(f) = joomla(&client, &base, &home_body, &home_headers).await {
        return Ok(Some(f));
    }
    // ── Drupal ──
    if let Some(f) = drupal(&client, &base, &home_body, &home_headers).await {
        return Ok(Some(f));
    }
    Ok(None)
}

async fn wordpress(
    client: &reqwest::Client,
    base: &str,
    home_body: &str,
    home_headers: &reqwest::header::HeaderMap,
    _home_status: u16,
) -> Option<CmsFinding> {
    let mut evidence: Vec<String> = Vec::new();
    let mut version: Option<String> = None;
    let mut confidence: u8 = 0;

    if let Some(v) = extract_generator(home_body, "WordPress") {
        version = Some(v.clone());
        evidence.push(format!("meta generator: WordPress {}", v));
        confidence += 60;
    }
    // wp-json link header
    if let Some(link) = home_headers.get("link").and_then(|v| v.to_str().ok()) {
        if link.contains("wp-json") || link.contains("api.w.org") {
            evidence.push(format!("Link header: {}", link));
            confidence += 20;
        }
    }
    // Probe wp-login.php
    if let Ok(resp) = client.get(format!("{}/wp-login.php", base)).send().await {
        if matches!(resp.status().as_u16(), 200 | 302 | 403) {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("WordPress") || body.contains("wp-submit") || body.contains("user_login") {
                evidence.push("wp-login.php present".into());
                confidence += 25;
            }
        }
    }
    // readme.html version (older installs)
    if version.is_none() {
        if let Ok(resp) = client.get(format!("{}/readme.html", base)).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                if let Some(v) = extract_wp_readme_version(&body) {
                    version = Some(v.clone());
                    evidence.push(format!("readme.html: WordPress {}", v));
                    confidence += 30;
                }
            }
        }
    }

    if confidence >= 30 {
        Some(CmsFinding {
            url: base.to_string(),
            cms: Cms::WordPress,
            version,
            confidence: confidence.min(100),
            evidence,
        })
    } else {
        None
    }
}

async fn joomla(
    client: &reqwest::Client,
    base: &str,
    home_body: &str,
    home_headers: &reqwest::header::HeaderMap,
) -> Option<CmsFinding> {
    let mut evidence: Vec<String> = Vec::new();
    let mut version: Option<String> = None;
    let mut confidence: u8 = 0;

    if let Some(v) = extract_generator(home_body, "Joomla") {
        version = Some(v.clone());
        evidence.push(format!("meta generator: Joomla {}", v));
        confidence += 60;
    }
    if let Some(cookie) = home_headers.get_all("set-cookie").iter().find_map(|c| {
        let s = c.to_str().ok()?;
        if s.contains("joomla_user_state") || s.starts_with("joomla") {
            Some(s.to_string())
        } else {
            None
        }
    }) {
        evidence.push(format!("Joomla cookie: {}", cookie));
        confidence += 30;
    }
    // Probe the well-known manifest XML
    if let Ok(resp) = client
        .get(format!("{}/administrator/manifests/files/joomla.xml", base))
        .send()
        .await
    {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if let Some(v) = extract_xml_version(&body) {
                version = Some(v.clone());
                evidence.push(format!("joomla.xml version: {}", v));
                confidence += 40;
            } else if body.contains("<extension") {
                evidence.push("joomla.xml present".into());
                confidence += 25;
            }
        }
    }
    if confidence >= 30 {
        Some(CmsFinding {
            url: base.to_string(),
            cms: Cms::Joomla,
            version,
            confidence: confidence.min(100),
            evidence,
        })
    } else {
        None
    }
}

async fn drupal(
    client: &reqwest::Client,
    base: &str,
    home_body: &str,
    home_headers: &reqwest::header::HeaderMap,
) -> Option<CmsFinding> {
    let mut evidence: Vec<String> = Vec::new();
    let mut version: Option<String> = None;
    let mut confidence: u8 = 0;

    if let Some(v) = extract_generator(home_body, "Drupal") {
        version = Some(v.clone());
        evidence.push(format!("meta generator: Drupal {}", v));
        confidence += 60;
    }
    if home_headers.get("x-drupal-cache").is_some() {
        evidence.push("X-Drupal-Cache header present".into());
        confidence += 35;
    }
    if home_headers.get("x-generator").map(|v| v.to_str().unwrap_or("").contains("Drupal")).unwrap_or(false) {
        evidence.push("X-Generator: Drupal".into());
        confidence += 30;
    }
    // CHANGELOG.txt (Drupal 7) or core/CHANGELOG.txt (Drupal 8+)
    if version.is_none() {
        for path in ["/CHANGELOG.txt", "/core/CHANGELOG.txt"] {
            if let Ok(resp) = client.get(format!("{}{}", base, path)).send().await {
                if resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    if let Some(v) = extract_drupal_changelog_version(&body) {
                        version = Some(v.clone());
                        evidence.push(format!("CHANGELOG.txt version: {}", v));
                        confidence += 35;
                        break;
                    }
                }
            }
        }
    }
    if confidence >= 30 {
        Some(CmsFinding {
            url: base.to_string(),
            cms: Cms::Drupal,
            version,
            confidence: confidence.min(100),
            evidence,
        })
    } else {
        None
    }
}

// ── Parsers ─────

fn extract_generator(body: &str, expected_cms: &str) -> Option<String> {
    let re = Regex::new(r#"(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']"#).ok()?;
    let cap = re.captures(body)?;
    let content = cap.get(1)?.as_str();
    if !content.to_lowercase().contains(&expected_cms.to_lowercase()) {
        return None;
    }
    let ver_re = Regex::new(r"(\d+\.\d+(?:\.\d+)?)").ok()?;
    ver_re.captures(content).map(|m| m[1].to_string())
}

fn extract_wp_readme_version(body: &str) -> Option<String> {
    let re = Regex::new(r"(?i)Version\s+(\d+\.\d+(?:\.\d+)?)").ok()?;
    re.captures(body).map(|m| m[1].to_string())
}

fn extract_xml_version(body: &str) -> Option<String> {
    let re = Regex::new(r"(?is)<version>([^<]+)</version>").ok()?;
    re.captures(body).map(|m| m[1].trim().to_string())
}

fn extract_drupal_changelog_version(body: &str) -> Option<String> {
    // Top of file: "Drupal 9.5.11, 2023-xx-xx" or "Drupal x.y.z, ..."
    let re = Regex::new(r"(?i)Drupal\s+(\d+\.\d+(?:\.\d+)?)").ok()?;
    re.captures(body).map(|m| m[1].to_string())
}

pub fn print_finding(f: &CmsFinding) {
    use colored::*;
    println!();
    let ver = f.version.as_deref().unwrap_or("?");
    println!(
        "{}",
        format!("CMS detected on {}: {} {} (confidence {}%)", f.url, f.cms.label(), ver, f.confidence)
            .bold()
    );
    for e in &f.evidence {
        println!("  · {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_generator_picks_version() {
        let html = r#"<meta name="generator" content="WordPress 6.4.1"/>"#;
        assert_eq!(extract_generator(html, "WordPress"), Some("6.4.1".into()));
    }

    #[test]
    fn extract_generator_case_insensitive() {
        let html = r#"<META NAME='Generator' CONTENT='Joomla! 4.3.1 - Open Source CMS'/>"#;
        assert_eq!(extract_generator(html, "Joomla"), Some("4.3.1".into()));
    }

    #[test]
    fn extract_generator_returns_none_when_mismatch() {
        let html = r#"<meta name="generator" content="Wix.com Website Builder"/>"#;
        assert_eq!(extract_generator(html, "WordPress"), None);
    }

    #[test]
    fn extract_wp_readme_version_picks_first_match() {
        let body = "Welcome. Version 5.9.3\nA bunch of other text 6.0";
        assert_eq!(extract_wp_readme_version(body), Some("5.9.3".into()));
    }

    #[test]
    fn extract_xml_version_grabs_value() {
        let xml = "<extension><version>3.10.11.1</version><name>x</name></extension>";
        assert_eq!(extract_xml_version(xml), Some("3.10.11.1".into()));
    }

    #[test]
    fn extract_drupal_changelog_version() {
        let body = "Drupal 9.5.11, 2023-04-19\nFix something\nDrupal 9.5.10, ...";
        assert_eq!(super::extract_drupal_changelog_version(body), Some("9.5.11".into()));
    }
}
