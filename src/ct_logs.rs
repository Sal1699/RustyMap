//! Subdomain enumeration via Certificate Transparency logs.
//!
//! Queries https://crt.sh — public CT log mirror. Returns every name
//! ever issued a TLS cert under the supplied apex domain. Typically
//! 10-100x more subdomains than wordlist brute-force, with zero
//! probe traffic against the target. Limitations:
//!   - crt.sh is community-run, occasional rate limit / 5xx
//!   - returns historical names, some may no longer resolve
//!   - subject to crt.sh's coverage of the upstream CT logs
//!
//! Improvement vs nmap: nmap has no equivalent — passive recon
//! against CT logs is normally a separate tool (e.g. `subfinder`,
//! `assetfinder`, `crtsh`). Folding it into RustyMap's --dns-enum
//! gives "discover then immediately scan" in one command.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::time::Duration;

const CRT_SH_URL: &str = "https://crt.sh/?output=json&q=";

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

/// Fetch every subdomain that crt.sh knows for `apex`. Returns a
/// deduplicated, sorted list of fully-qualified names.
pub async fn fetch(apex: &str, timeout: Duration) -> Result<Vec<String>> {
    // crt.sh accepts a leading `%.` to wildcard-match subdomains.
    let url = format!("{}%25.{}", CRT_SH_URL, apex);
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("rustymap/ct-logs")
        .build()
        .context("build reqwest client")?;
    let resp = client
        .get(&url)
        .send()
        .await
        .context("crt.sh request failed (rate limit / 5xx?)")?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "crt.sh returned {} — try again in a minute or use --dns-wordlist",
            status
        ));
    }
    let entries: Vec<CrtShEntry> = resp.json().await.context("parse crt.sh JSON")?;

    // crt.sh's name_value can contain newline-separated SANs; split,
    // strip wildcards, lowercase, dedup.
    let mut out: BTreeSet<String> = BTreeSet::new();
    let apex_lo = apex.to_lowercase();
    for entry in entries {
        for raw in entry.name_value.split('\n') {
            let name = raw.trim().trim_start_matches("*.").to_lowercase();
            if name.is_empty() {
                continue;
            }
            if !name.ends_with(&apex_lo) {
                continue;
            }
            // Filter out the apex itself unless the user wants it
            if name == apex_lo {
                continue;
            }
            out.insert(name);
        }
    }
    Ok(out.into_iter().collect())
}
