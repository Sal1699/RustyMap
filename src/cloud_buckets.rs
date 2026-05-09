//! Public-bucket enumeration across S3, Google Cloud Storage, and
//! Azure Blob Storage.
//!
//! From a seed (apex domain or org name) we generate ~30 common
//! name permutations — `acme`, `acme-backup`, `backup-acme`,
//! `acme-prod`, `acme-uploads`, … — then probe each against:
//!
//!   - **S3**: `https://{bucket}.s3.amazonaws.com/`
//!   - **GCS**: `https://storage.googleapis.com/{bucket}/`
//!   - **Azure Blob**: `https://{account}.blob.core.windows.net/`
//!     (with `?comp=list` for container listing)
//!
//! Status codes & body markers tell us:
//!   - **PUBLIC_LIST** — bucket exists and content listing is public
//!     (highest severity — anyone can enumerate every object).
//!   - **EXISTS** — bucket exists but ACL blocks listing (still
//!     interesting because individual object names may be guessable).
//!   - **NOT_FOUND** — name doesn't exist (most candidates).
//!
//! Read-only — only HEAD/GET on the bucket root, no objects fetched
//! beyond the listing XML, and no writes.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Provider {
    S3,
    Gcs,
    Azure,
}

impl Provider {
    pub fn label(&self) -> &'static str {
        match self {
            Provider::S3 => "S3",
            Provider::Gcs => "GCS",
            Provider::Azure => "Azure",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BucketStatus {
    PublicList,
    Exists,
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketFinding {
    pub provider: Provider,
    pub name: String,
    pub url: String,
    pub status: BucketStatus,
    pub object_count_seen: Option<usize>,
}

/// Suffixes we tack onto a seed when generating candidate names.
/// Order is roughly "most likely first" so we can short-circuit when
/// the caller sets a low limit.
const SUFFIXES: &[&str] = &[
    "", "-backup", "-backups", "-prod", "-production", "-dev", "-development",
    "-test", "-staging", "-stage", "-uploads", "-static", "-assets",
    "-media", "-images", "-public", "-private", "-data", "-logs", "-archive",
    "-internal", "-files", "-temp", "-tmp", "-bak", "-cdn", "-config",
    "-secrets",
];

/// Generates the candidate bucket names from a seed.
/// If the seed is a domain (`acme.com`), we also try the apex without
/// dots (`acme`) and with dots replaced by dashes (`acme-com`).
pub fn permutations(seed: &str) -> Vec<String> {
    let mut bases: Vec<String> = vec![seed.to_string()];
    let lower = seed.to_lowercase();
    if lower.contains('.') {
        let no_dots = lower.replace('.', "");
        let dashed = lower.replace('.', "-");
        if let Some(label) = lower.split('.').next() {
            bases.push(label.to_string());
        }
        bases.push(no_dots);
        bases.push(dashed);
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for base in &bases {
        for sfx in SUFFIXES {
            let name = format!("{}{}", base, sfx);
            if is_valid_bucket_name(&name) && seen.insert(name.clone()) {
                out.push(name);
            }
        }
        // Also "{prefix}-{base}" variants for a few prefixes.
        for prefix in ["backup", "static", "assets", "data"] {
            let name = format!("{}-{}", prefix, base);
            if is_valid_bucket_name(&name) && seen.insert(name.clone()) {
                out.push(name);
            }
        }
    }
    out
}

/// S3 bucket-name rules (the strictest of the three providers): 3–63
/// chars, lowercase letters / digits / hyphens, no leading or trailing
/// hyphen, no consecutive dots.
fn is_valid_bucket_name(s: &str) -> bool {
    let len = s.len();
    if !(3..=63).contains(&len) {
        return false;
    }
    if s.starts_with('-') || s.ends_with('-') {
        return false;
    }
    s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub async fn enumerate(seed: &str, limit: usize, dur: Duration) -> Result<Vec<BucketFinding>> {
    let names = permutations(seed);
    let names: Vec<&String> = names.iter().take(limit).collect();
    let client = reqwest::Client::builder()
        .timeout(dur)
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/cloud-buckets")
        .build()?;

    let mut out = Vec::new();
    for name in names {
        if let Some(f) = probe_s3(&client, name).await {
            out.push(f);
        }
        if let Some(f) = probe_gcs(&client, name).await {
            out.push(f);
        }
        if let Some(f) = probe_azure(&client, name).await {
            out.push(f);
        }
    }
    Ok(out)
}

async fn probe_s3(client: &reqwest::Client, name: &str) -> Option<BucketFinding> {
    let url = format!("https://{}.s3.amazonaws.com/", name);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    classify_s3_like(&url, name, Provider::S3, status, &body)
}

async fn probe_gcs(client: &reqwest::Client, name: &str) -> Option<BucketFinding> {
    let url = format!("https://storage.googleapis.com/{}/", name);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    // GCS responds with similar XML idiom: <ListBucketResult> for
    // public listings, <Error><Code>AccessDenied</Code> for exists+
    // private, NoSuchBucket / 404 for absent.
    classify_s3_like(&url, name, Provider::Gcs, status, &body)
}

async fn probe_azure(client: &reqwest::Client, name: &str) -> Option<BucketFinding> {
    // Azure blob accounts are at {account}.blob.core.windows.net.
    // Listing all containers in an account requires SAS, so we hit
    // the storage account endpoint and let DNS / 400 patterns tell us
    // whether the account name is taken.
    let url = format!("https://{}.blob.core.windows.net/?comp=list", name);
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return None, // DNS NXDOMAIN means the account name isn't registered
    };
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let st = match status {
        200 if body.contains("<EnumerationResults") => BucketStatus::PublicList,
        // Azure returns 400 + InvalidQueryParameterValue / 403 +
        // AuthenticationFailed when the account exists but listing is
        // forbidden — still an existence signal worth surfacing.
        400 | 403 if body.contains("AuthenticationFailed")
            || body.contains("InvalidAuthenticationInfo")
            || body.contains("PublicAccessNotPermitted") =>
        {
            BucketStatus::Exists
        }
        _ => return None,
    };
    let object_count = if matches!(st, BucketStatus::PublicList) {
        Some(body.matches("<Container").count())
    } else {
        None
    };
    Some(BucketFinding {
        provider: Provider::Azure,
        name: name.to_string(),
        url,
        status: st,
        object_count_seen: object_count,
    })
}

fn classify_s3_like(
    url: &str,
    name: &str,
    provider: Provider,
    status: u16,
    body: &str,
) -> Option<BucketFinding> {
    let st = match status {
        200 if body.contains("<ListBucketResult") => BucketStatus::PublicList,
        403 if body.contains("AccessDenied") || body.contains("<Code>AccessDenied") => {
            BucketStatus::Exists
        }
        // NoSuchBucket / 404 / DNS resolution failure → absent
        404 => return None,
        301 | 307 if body.contains("PermanentRedirect") => BucketStatus::Exists,
        _ => return None,
    };
    let object_count = if matches!(st, BucketStatus::PublicList) {
        Some(body.matches("<Key>").count())
    } else {
        None
    };
    Some(BucketFinding {
        provider,
        name: name.to_string(),
        url: url.to_string(),
        status: st,
        object_count_seen: object_count,
    })
}

pub fn print_findings(seed: &str, findings: &[BucketFinding]) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!("Cloud-bucket scan for '{}' — {} hit(s)", seed, findings.len()).bold()
    );
    if findings.is_empty() {
        println!("  {}", "no public/existing buckets matched the permutations".green());
        return;
    }
    println!("  {:<8} {:<11} {:<40} {}", "PROV", "STATUS", "NAME", "URL");
    for f in findings {
        let label = match f.status {
            BucketStatus::PublicList => "PUBLIC_LIST".red().bold().to_string(),
            BucketStatus::Exists => "EXISTS".yellow().to_string(),
            BucketStatus::NotFound => "NOT_FOUND".dimmed().to_string(),
        };
        println!("  {:<8} {:<11} {:<40} {}", f.provider.label(), label, f.name, f.url);
        if let Some(n) = f.object_count_seen {
            println!("           └─ {} object/container(s) listed", n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutations_handles_apex_domain() {
        let names = permutations("acme.com");
        assert!(names.iter().any(|n| n == "acme"));
        assert!(names.iter().any(|n| n == "acme-backup"));
        assert!(names.iter().any(|n| n == "acme-com"));
        assert!(names.iter().any(|n| n == "acmecom"));
        assert!(names.iter().any(|n| n == "backup-acme"));
    }

    #[test]
    fn permutations_dedupes() {
        let names = permutations("acme");
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(names.len(), unique.len());
    }

    #[test]
    fn validates_bucket_names() {
        assert!(is_valid_bucket_name("acme"));
        assert!(is_valid_bucket_name("acme-prod-123"));
        assert!(!is_valid_bucket_name("ab")); // too short
        assert!(!is_valid_bucket_name("-acme")); // leading hyphen
        assert!(!is_valid_bucket_name("acme-")); // trailing hyphen
        assert!(!is_valid_bucket_name("ACME")); // uppercase
        assert!(!is_valid_bucket_name("acme_x")); // underscore
    }

    #[test]
    fn classify_s3_public_listing() {
        let body = "<?xml version=\"1.0\"?><ListBucketResult><Name>x</Name><Key>file.txt</Key><Key>img.png</Key></ListBucketResult>";
        let f = classify_s3_like("u", "x", Provider::S3, 200, body).unwrap();
        assert_eq!(f.status, BucketStatus::PublicList);
        assert_eq!(f.object_count_seen, Some(2));
    }

    #[test]
    fn classify_s3_access_denied_means_exists() {
        let body = "<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code></Error>";
        let f = classify_s3_like("u", "x", Provider::S3, 403, body).unwrap();
        assert_eq!(f.status, BucketStatus::Exists);
    }

    #[test]
    fn classify_s3_404_returns_none() {
        let f = classify_s3_like("u", "x", Provider::S3, 404, "<Error><Code>NoSuchBucket</Code></Error>");
        assert!(f.is_none());
    }
}
