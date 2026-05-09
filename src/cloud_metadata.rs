//! Cloud-instance metadata-service (IMDS) discovery.
//!
//! On every major IaaS provider a magic link-local address —
//! 169.254.169.254 — answers metadata HTTP requests from inside a
//! VM. The provider-specific paths and required headers differ:
//!
//!   - **AWS**: IMDSv2 needs a token first (PUT /latest/api/token,
//!     header `X-aws-ec2-metadata-token-ttl-seconds: 21600`), then
//!     GET requests carry `X-aws-ec2-metadata-token`. We try v2,
//!     fall back to v1 (`/latest/meta-data/`) when v2 doesn't answer.
//!   - **GCP**: GET `/computeMetadata/v1/` with header
//!     `Metadata-Flavor: Google`.
//!   - **Azure**: GET `/metadata/instance?api-version=2021-02-01` with
//!     header `Metadata: true`.
//!   - **OpenStack**: GET `/openstack/latest/meta_data.json`.
//!
//! Useful in two scenarios:
//!   1. You're running RustyMap from inside a cloud VM and want to
//!      confirm what's exposed to anyone who lands a SSRF on you.
//!   2. You suspect SSRF on a remote target — point the probe at the
//!      target by passing `--cloud-metadata-via http://target/proxy?u=`
//!      (the URL is treated as a prefix; we append the IMDS URL).

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const IMDS_HOST: &str = "169.254.169.254";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    OpenStack,
}

impl CloudProvider {
    pub fn label(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "AWS",
            CloudProvider::Gcp => "GCP",
            CloudProvider::Azure => "Azure",
            CloudProvider::OpenStack => "OpenStack",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImdsHit {
    pub provider_label: String,
    pub instance_id: Option<String>,
    pub region: Option<String>,
    pub iam_role: Option<String>,
    pub raw_excerpt: String,
    pub imds_v1_unprotected: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetadataReport {
    pub via_proxy: Option<String>,
    pub hits: Vec<ImdsHit>,
}

pub async fn probe(via_proxy: Option<&str>, dur: Duration) -> Result<MetadataReport> {
    let client = reqwest::Client::builder()
        .timeout(dur)
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/imds-probe")
        .build()?;

    let mut report = MetadataReport {
        via_proxy: via_proxy.map(String::from),
        hits: Vec::new(),
    };

    if let Some(hit) = probe_aws(&client, via_proxy).await {
        report.hits.push(hit);
    }
    if let Some(hit) = probe_gcp(&client, via_proxy).await {
        report.hits.push(hit);
    }
    if let Some(hit) = probe_azure(&client, via_proxy).await {
        report.hits.push(hit);
    }
    if let Some(hit) = probe_openstack(&client, via_proxy).await {
        report.hits.push(hit);
    }
    Ok(report)
}

fn build_url(via_proxy: Option<&str>, path: &str) -> String {
    match via_proxy {
        Some(prefix) => format!("{}{}", prefix, urlencoding(path)),
        None => format!("http://{}{}", IMDS_HOST, path),
    }
}

/// Minimal URL-encoder for the few characters that matter when we
/// append IMDS paths to a SSRF parameter (`?`, `&`, `:`, `/`).
/// We could pull `url::form_urlencoded` but it's overkill for this.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            ':' => out.push_str("%3A"),
            '/' => out.push_str("%2F"),
            '?' => out.push_str("%3F"),
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            _ => out.push(c),
        }
    }
    out
}

async fn probe_aws(client: &reqwest::Client, via: Option<&str>) -> Option<ImdsHit> {
    // Try IMDSv2 first.
    let token_url = build_url(via, "/latest/api/token");
    let token = client
        .put(&token_url)
        .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
        .send()
        .await
        .ok()
        .and_then(|r| if r.status().is_success() { Some(r) } else { None })
        .map(|r| async { r.text().await.ok() });
    let token = match token {
        Some(fut) => fut.await,
        None => None,
    };

    let mut hit = ImdsHit {
        provider_label: CloudProvider::Aws.label().into(),
        ..Default::default()
    };

    let id_url = build_url(via, "/latest/meta-data/instance-id");
    let mut req = client.get(&id_url);
    if let Some(t) = &token {
        req = req.header("X-aws-ec2-metadata-token", t);
    }
    let resp = req.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    if token.is_none() {
        hit.imds_v1_unprotected = true;
    }
    hit.instance_id = resp.text().await.ok();

    // Region.
    let region_url = build_url(via, "/latest/meta-data/placement/region");
    let mut req = client.get(&region_url);
    if let Some(t) = &token {
        req = req.header("X-aws-ec2-metadata-token", t);
    }
    if let Ok(r) = req.send().await {
        if r.status().is_success() {
            hit.region = r.text().await.ok();
        }
    }

    // IAM role name (security-credentials/<role>).
    let role_url = build_url(via, "/latest/meta-data/iam/security-credentials/");
    let mut req = client.get(&role_url);
    if let Some(t) = &token {
        req = req.header("X-aws-ec2-metadata-token", t);
    }
    if let Ok(r) = req.send().await {
        if r.status().is_success() {
            let role = r.text().await.unwrap_or_default();
            let role = role.lines().next().unwrap_or("").trim().to_string();
            if !role.is_empty() {
                hit.iam_role = Some(role);
            }
        }
    }

    hit.raw_excerpt = format!(
        "instance-id={:?} region={:?} iam-role={:?}",
        hit.instance_id, hit.region, hit.iam_role
    );
    Some(hit)
}

async fn probe_gcp(client: &reqwest::Client, via: Option<&str>) -> Option<ImdsHit> {
    let url = build_url(via, "/computeMetadata/v1/instance/?recursive=true&alt=json");
    let resp = client
        .get(&url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    if !body.contains("\"id\"") && !body.contains("\"hostname\"") {
        return None;
    }
    let mut hit = ImdsHit {
        provider_label: CloudProvider::Gcp.label().into(),
        ..Default::default()
    };
    hit.instance_id = json_field(&body, "id");
    hit.region = json_field(&body, "zone").map(|z| z.split('/').last().unwrap_or(&z).to_string());
    hit.iam_role = json_field(&body, "serviceAccounts");
    hit.raw_excerpt = body.chars().take(400).collect();
    Some(hit)
}

async fn probe_azure(client: &reqwest::Client, via: Option<&str>) -> Option<ImdsHit> {
    let url = build_url(via, "/metadata/instance?api-version=2021-02-01");
    let resp = client
        .get(&url)
        .header("Metadata", "true")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    if !body.contains("\"compute\"") && !body.contains("\"vmId\"") {
        return None;
    }
    let mut hit = ImdsHit {
        provider_label: CloudProvider::Azure.label().into(),
        ..Default::default()
    };
    hit.instance_id = json_field(&body, "vmId");
    hit.region = json_field(&body, "location");
    hit.raw_excerpt = body.chars().take(400).collect();
    Some(hit)
}

async fn probe_openstack(client: &reqwest::Client, via: Option<&str>) -> Option<ImdsHit> {
    let url = build_url(via, "/openstack/latest/meta_data.json");
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    if !body.contains("\"uuid\"") {
        return None;
    }
    let mut hit = ImdsHit {
        provider_label: CloudProvider::OpenStack.label().into(),
        ..Default::default()
    };
    hit.instance_id = json_field(&body, "uuid");
    hit.region = json_field(&body, "availability_zone");
    hit.raw_excerpt = body.chars().take(400).collect();
    Some(hit)
}

/// Naïve JSON value extractor — finds `"key": "value"` or `"key": <num>`
/// patterns. Avoids pulling a JSON parser for one-shot field reads.
fn json_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let i = body.find(&needle)?;
    let rest = &body[i + needle.len()..];
    let after_colon = rest.find(':').map(|j| &rest[j + 1..])?;
    let trimmed = after_colon.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let end = trimmed
            .find(|c: char| c == ',' || c == '}' || c == '\n')
            .unwrap_or(trimmed.len().min(64));
        let candidate = trimmed[..end].trim().to_string();
        if candidate.is_empty() {
            None
        } else {
            Some(candidate)
        }
    }
}

pub fn print_report(r: &MetadataReport) -> Result<()> {
    use colored::*;
    println!();
    let header = match &r.via_proxy {
        Some(p) => format!("Cloud-metadata probe via SSRF prefix {}", p),
        None => "Cloud-metadata probe (direct, 169.254.169.254)".into(),
    };
    println!("{}", header.bold());
    if r.hits.is_empty() {
        println!("  {}", "no IMDS endpoint responded".green());
        return Ok(());
    }
    for h in &r.hits {
        println!(
            "  {} {}",
            "[!]".red().bold(),
            format!("{} IMDS responding", h.provider_label).bold()
        );
        if let Some(id) = &h.instance_id {
            println!("    instance-id : {}", id);
        }
        if let Some(reg) = &h.region {
            println!("    region/zone : {}", reg);
        }
        if let Some(role) = &h.iam_role {
            println!("    iam-role    : {} (credential exposure!)", role.red());
        }
        if h.imds_v1_unprotected {
            println!("    {}", "IMDSv1 unprotected — SSRF can read credentials without a token".yellow());
        }
        if !h.raw_excerpt.is_empty() {
            let line: String = h.raw_excerpt.replace('\n', " ").chars().take(180).collect();
            println!("    excerpt     : {}", line);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_field_string_value() {
        let body = r#"{"id":"i-12345","region":"eu-west-1","tags":[]}"#;
        assert_eq!(json_field(body, "id").as_deref(), Some("i-12345"));
        assert_eq!(json_field(body, "region").as_deref(), Some("eu-west-1"));
    }

    #[test]
    fn json_field_numeric_value() {
        let body = r#"{"vmId":12345,"name":"vm"}"#;
        assert_eq!(json_field(body, "vmId").as_deref(), Some("12345"));
    }

    #[test]
    fn json_field_missing_returns_none() {
        let body = r#"{"id":"a"}"#;
        assert!(json_field(body, "absent").is_none());
    }

    #[test]
    fn build_url_direct_vs_proxy() {
        assert_eq!(
            build_url(None, "/latest/meta-data/"),
            "http://169.254.169.254/latest/meta-data/"
        );
        let v = build_url(Some("http://target/?u="), "/latest/meta-data/");
        assert!(v.starts_with("http://target/?u="));
        assert!(v.contains("%2F"));
    }
}

// Suppress unused-Result on the future-of-Option pattern in probe_aws.
#[allow(dead_code)]
fn _crate_used(_: anyhow::Error) {
    let _ = anyhow!("unused");
}
