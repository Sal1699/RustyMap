//! Version → CVE matcher.
//!
//! Take a `(product, version)` banner — typically from `--sV` /
//! `nmap-service-probes` output — and look it up against the local
//! NVD cache populated by `--update-cve-db`. Returns matching CVEs
//! sorted by CVSS, with KEV (CISA Known-Exploited Vulnerabilities)
//! flagged separately.
//!
//! This is the glue between two existing modules: `src/nvd.rs`
//! (which already sync'd a full NVD JSON 2.0 history + has a
//! `lookup(product, version, limit)` API) and the wire side
//! (the user supplies `--cve-for "openssh 7.4p1"`).
//!
//! Read-only — pure local SQLite query, no network.

use crate::nvd::{self, NvdEntry};
use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct CveMatch {
    pub product: String,
    pub version: String,
    pub matches: Vec<NvdEntry>,
}

pub fn lookup(product: &str, version: &str, limit: usize) -> Result<CveMatch> {
    let conn = nvd::open_cache().context(
        "NVD cache not found at ~/.cache/rustymap/nvd.sqlite. \
         Run `rustymap --update-cve-db` first (downloads ~80 MB of NVD JSON)."
    )?;
    let entries = nvd::lookup(&conn, product, version, limit)?;
    Ok(CveMatch {
        product: product.to_string(),
        version: version.to_string(),
        matches: entries,
    })
}

/// Parse a banner like "openssh 7.4p1" or "nginx/1.18.0" into
/// (product, version). Returns `None` if no version-looking token
/// is present.
pub fn parse_banner(banner: &str) -> Option<(String, String)> {
    let trimmed = banner.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Split on '/' first (e.g. nginx/1.18.0).
    if let Some((p, v)) = trimmed.split_once('/') {
        let p = p.trim().to_string();
        let v = v.trim().split_whitespace().next()?.to_string();
        if !p.is_empty() && !v.is_empty() {
            return Some((p, v));
        }
    }
    // Otherwise split on whitespace.
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let product = parts[0].to_string();
    // Pick the first token that looks like a version (contains a digit
    // and a dot, or a digit + letter suffix like 7.4p1).
    let version = parts.iter().skip(1).find_map(|tok| {
        let has_digit = tok.chars().any(|c| c.is_ascii_digit());
        let has_separator = tok.contains('.') || tok.chars().any(|c| c == 'p' || c == '-');
        if has_digit && has_separator {
            Some(tok.to_string())
        } else {
            None
        }
    })?;
    Some((product, version))
}

pub fn print_match(m: &CveMatch) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!(
            "CVE matches for {} {} — {} entries",
            m.product, m.version, m.matches.len()
        )
        .bold()
    );
    if m.matches.is_empty() {
        println!(
            "  {}",
            "no NVD entries matched. Causes (in order of likelihood):"
                .yellow().bold()
        );
        println!("    1. Cache is empty or stale — run `rustymap --update-cve-db`");
        println!("    2. Product name differs from CPE convention — try lowercase, swap dashes/spaces");
        println!("       e.g. 'OpenSSH 7.4p1' → 'openssh:7.4p1', 'Apache httpd' → 'apache_http_server'");
        println!("    3. Version really has no published CVEs at the named match level");
        return;
    }
    for e in &m.matches {
        let sev = e
            .cvss31_severity
            .as_deref()
            .or(e.cvss40_severity.as_deref())
            .unwrap_or("?");
        let score = e
            .cvss31_base
            .or(e.cvss40_base)
            .map(|v| format!("{:.1}", v))
            .unwrap_or_else(|| "—".into());
        let kev = if e.kev { " KEV".red().bold().to_string() } else { String::new() };
        let sev_color = match sev {
            "CRITICAL" => sev.red().bold().to_string(),
            "HIGH" => sev.red().to_string(),
            "MEDIUM" => sev.yellow().to_string(),
            "LOW" => sev.dimmed().to_string(),
            _ => sev.into(),
        };
        let desc: String = e.description.chars().take(120).collect();
        println!(
            "  {:<16} {:<8} {:<5} {} {}",
            e.id, sev_color, score, desc.dimmed(), kev
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_banner_slash_form() {
        let b = parse_banner("nginx/1.18.0").unwrap();
        assert_eq!(b.0, "nginx");
        assert_eq!(b.1, "1.18.0");
    }

    #[test]
    fn parse_banner_space_form() {
        let b = parse_banner("openssh 7.4p1").unwrap();
        assert_eq!(b.0, "openssh");
        assert_eq!(b.1, "7.4p1");
    }

    #[test]
    fn parse_banner_with_extra_tokens() {
        // "Apache 2.4.41 (Ubuntu)"
        let b = parse_banner("Apache 2.4.41 (Ubuntu)").unwrap();
        assert_eq!(b.0, "Apache");
        assert_eq!(b.1, "2.4.41");
    }

    #[test]
    fn parse_banner_rejects_no_version() {
        assert!(parse_banner("Apache").is_none());
        assert!(parse_banner("").is_none());
        assert!(parse_banner("    ").is_none());
    }

    #[test]
    fn parse_banner_handles_no_separator_token() {
        // "ProFTPD 1.3.5e-rc1" — version has dash, still picks up.
        let b = parse_banner("ProFTPD 1.3.5e-rc1").unwrap();
        assert_eq!(b.1, "1.3.5e-rc1");
    }

    #[test]
    fn parse_banner_slash_no_version_part_returns_none() {
        // "nginx/" → empty version → fall through to space-split,
        // which also fails. None.
        assert!(parse_banner("nginx/").is_none());
    }
}
