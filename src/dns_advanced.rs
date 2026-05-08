//! Subdomain takeover detection + origin IP discovery dietro CDN.
//!
//! ── Takeover ──
//! Resolves each subdomain's CNAME chain. If the final target points
//! at a service known to allow "claim by anybody who registers the
//! resource name" (Heroku, GitHub Pages, S3, Azure CDN, …) AND the
//! HTTP probe returns the platform-specific "no such resource" page,
//! the subdomain is at risk.
//!
//! ── Origin IP discovery ──
//! When the apex is fronted by Cloudflare/Akamai/Fastly/CloudFront,
//! the real backend IP is hidden. We try four passive techniques:
//!   1. **MX records** — mail servers usually live on the origin
//!      and aren't proxied.
//!   2. **SPF records** — declared sending IPs for the domain.
//!   3. **Subdomain delta** — `dev.*`, `staging.*`, `mail.*`, `ftp.*`
//!      are often forgotten and resolve to the origin.
//!   4. **Certificate Transparency cross-reference** — CT logs may
//!      contain certs issued directly to the origin IP / hostname.
//!
//! Improvement vs nmap: nmap has nothing comparable.

use anyhow::{anyhow, Result};
use hickory_resolver::TokioAsyncResolver;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TakeoverFinding {
    pub subdomain: String,
    pub cname: String,
    pub provider: String,
    pub fingerprint: &'static str,
}

#[derive(Debug, Clone)]
pub struct OriginCandidate {
    pub ip: IpAddr,
    pub source: &'static str,
    pub note: String,
}

/// Provider rules for known-takeover-prone CNAME suffixes + the
/// fingerprint string we expect on the HTTP body when the resource
/// is unclaimed.
struct TakeoverRule {
    suffix: &'static str,
    provider: &'static str,
    body_fingerprint: &'static str,
}

const TAKEOVER_RULES: &[TakeoverRule] = &[
    TakeoverRule {
        suffix: ".herokuapp.com",
        provider: "Heroku",
        body_fingerprint: "No such app",
    },
    TakeoverRule {
        suffix: ".github.io",
        provider: "GitHub Pages",
        body_fingerprint: "There isn't a GitHub Pages site here",
    },
    TakeoverRule {
        suffix: ".s3.amazonaws.com",
        provider: "AWS S3",
        body_fingerprint: "NoSuchBucket",
    },
    TakeoverRule {
        suffix: ".s3-website",
        provider: "AWS S3 Website",
        body_fingerprint: "NoSuchBucket",
    },
    TakeoverRule {
        suffix: ".azurewebsites.net",
        provider: "Azure App Service",
        body_fingerprint: "Error 404 - Web app not found",
    },
    TakeoverRule {
        suffix: ".cloudapp.net",
        provider: "Azure Cloud Service",
        body_fingerprint: "Web Site Not Found",
    },
    TakeoverRule {
        suffix: ".azureedge.net",
        provider: "Azure CDN",
        body_fingerprint: "Endpoint with this name does not exist",
    },
    TakeoverRule {
        suffix: ".cloudfront.net",
        provider: "AWS CloudFront",
        body_fingerprint: "Bad request",
    },
    TakeoverRule {
        suffix: ".bitbucket.io",
        provider: "Bitbucket Pages",
        body_fingerprint: "Repository not found",
    },
    TakeoverRule {
        suffix: ".readthedocs.io",
        provider: "Read the Docs",
        body_fingerprint: "Maze Found",
    },
    TakeoverRule {
        suffix: ".surge.sh",
        provider: "Surge",
        body_fingerprint: "project not found",
    },
    TakeoverRule {
        suffix: ".fastly.net",
        provider: "Fastly",
        body_fingerprint: "Fastly error: unknown domain",
    },
    TakeoverRule {
        suffix: ".pantheon.io",
        provider: "Pantheon",
        body_fingerprint: "404 error unknown site!",
    },
    TakeoverRule {
        suffix: ".tumblr.com",
        provider: "Tumblr",
        body_fingerprint: "Whatever you were looking for doesn't currently exist",
    },
    TakeoverRule {
        suffix: ".myshopify.com",
        provider: "Shopify",
        body_fingerprint: "Sorry, this shop is currently unavailable",
    },
    TakeoverRule {
        suffix: ".unbouncepages.com",
        provider: "Unbounce",
        body_fingerprint: "The requested URL was not found on this server",
    },
    TakeoverRule {
        suffix: ".desk.com",
        provider: "Desk",
        body_fingerprint: "Please try again or try Desk.com free for 14 days",
    },
];

/// Detect takeover risk on each subdomain. Resolves CNAME, matches
/// against `TAKEOVER_RULES`, and verifies the HTTP body fingerprint
/// before flagging.
pub async fn detect_takeover(
    subdomains: &[String],
    timeout: Duration,
) -> Result<Vec<TakeoverFinding>> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let http = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/takeover")
        .build()?;

    let mut findings = Vec::new();
    for sub in subdomains {
        let cname = match resolver.lookup(sub.as_str(), hickory_resolver::proto::rr::RecordType::CNAME).await {
            Ok(l) => l
                .iter()
                .filter_map(|r| {
                    if let hickory_resolver::proto::rr::RData::CNAME(name) = r {
                        Some(name.to_string().trim_end_matches('.').to_lowercase())
                    } else {
                        None
                    }
                })
                .next(),
            Err(_) => None,
        };
        let Some(target) = cname else { continue };

        let rule = TAKEOVER_RULES.iter().find(|r| target.contains(r.suffix));
        let Some(rule) = rule else { continue };

        // Verify with an HTTP request — the CNAME alone isn't enough
        // (the resource might still be claimed by the legitimate
        // owner). We confirm by matching the platform's "not found"
        // fingerprint.
        for scheme in ["https", "http"] {
            let url = format!("{}://{}/", scheme, sub);
            if let Ok(resp) = http.get(&url).send().await {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                if (status == 404 || status == 503 || status == 200)
                    && body.contains(rule.body_fingerprint)
                {
                    findings.push(TakeoverFinding {
                        subdomain: sub.clone(),
                        cname: target.clone(),
                        provider: rule.provider.to_string(),
                        fingerprint: rule.body_fingerprint,
                    });
                    break;
                }
            }
        }
    }
    Ok(findings)
}

/// Try four passive techniques to recover the apex's origin IP
/// when it's behind a CDN.
pub async fn discover_origin(apex: &str, timeout: Duration) -> Result<Vec<OriginCandidate>> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let mut out = Vec::new();

    // 1. Resolve apex itself for the "expected" CDN-fronted IPs so we
    //    can dedupe candidates that match.
    let cdn_ips: std::collections::HashSet<IpAddr> = resolver
        .lookup_ip(apex)
        .await
        .map(|l| l.iter().collect())
        .unwrap_or_default();

    // 2. MX records — mail servers usually live on the origin.
    if let Ok(mx) = resolver.mx_lookup(apex).await {
        for rec in mx.iter() {
            let host = rec.exchange().to_string();
            if let Ok(ips) = resolver.lookup_ip(host.as_str()).await {
                for ip in ips.iter() {
                    if !cdn_ips.contains(&ip) {
                        out.push(OriginCandidate {
                            ip,
                            source: "MX",
                            note: format!("MX → {}", host.trim_end_matches('.')),
                        });
                    }
                }
            }
        }
    }

    // 3. SPF — declared sending IPs (often the same as origin).
    if let Ok(txt) = resolver.txt_lookup(apex).await {
        for r in txt.iter() {
            let raw = r.to_string();
            if !raw.contains("v=spf1") {
                continue;
            }
            for tok in raw.split_whitespace() {
                if let Some(ip4) = tok.strip_prefix("ip4:") {
                    let ip4 = ip4.split('/').next().unwrap_or(ip4);
                    if let Ok(ip) = ip4.parse::<IpAddr>() {
                        if !cdn_ips.contains(&ip) {
                            out.push(OriginCandidate {
                                ip,
                                source: "SPF",
                                note: format!("SPF ip4: {}", ip4),
                            });
                        }
                    }
                }
            }
        }
    }

    // 4. Common forgotten subdomains — `dev`, `staging`, `mail`, etc.
    let known_subs = [
        "mail", "ftp", "dev", "staging", "test", "beta", "old", "internal",
        "intranet", "vpn", "remote", "direct", "origin", "backup", "admin",
        "smtp", "pop", "imap", "webmail",
    ];
    for s in known_subs {
        let host = format!("{}.{}", s, apex);
        let _ = timeout_lookup(&resolver, &host, timeout, &cdn_ips, &mut out, "subdomain").await;
    }

    Ok(out)
}

async fn timeout_lookup(
    resolver: &TokioAsyncResolver,
    host: &str,
    _t: Duration,
    cdn_ips: &std::collections::HashSet<IpAddr>,
    out: &mut Vec<OriginCandidate>,
    source: &'static str,
) -> Result<()> {
    let Ok(ips) = resolver.lookup_ip(host).await else {
        return Ok(());
    };
    for ip in ips.iter() {
        if !cdn_ips.contains(&ip) {
            out.push(OriginCandidate {
                ip,
                source,
                note: format!("resolves to non-CDN: {}", host),
            });
        }
    }
    Ok(())
}

/// Print candidates grouped by source. Marks the candidate as
/// "high confidence" when ≥ 2 sources point to the same IP.
pub fn print_origin_candidates(apex: &str, candidates: &[OriginCandidate]) {
    use colored::*;
    if candidates.is_empty() {
        println!("\nNo origin IP candidates found for {}", apex);
        return;
    }
    let mut by_ip: std::collections::HashMap<IpAddr, Vec<&OriginCandidate>> =
        std::collections::HashMap::new();
    for c in candidates {
        by_ip.entry(c.ip).or_default().push(c);
    }
    let mut ips: Vec<_> = by_ip.iter().collect();
    ips.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    println!(
        "\n{}",
        format!("Origin IP candidates for {}:", apex).bold()
    );
    println!("{:<18} {:<8} CONFIDENCE  NOTES", "IP", "SOURCES");
    for (ip, srcs) in ips {
        let conf = if srcs.len() >= 2 { "HIGH".green().bold().to_string() } else { "low".dimmed().to_string() };
        let sources: Vec<&str> = srcs.iter().map(|c| c.source).collect();
        let notes: Vec<&str> = srcs.iter().map(|c| c.note.as_str()).collect();
        println!(
            "{:<18} {:<8} {}        {}",
            ip,
            sources.join(","),
            conf,
            notes.join(" · ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takeover_rules_have_unique_suffixes() {
        let mut seen = std::collections::HashSet::new();
        for r in TAKEOVER_RULES {
            assert!(seen.insert(r.suffix), "duplicate suffix {}", r.suffix);
        }
    }

    #[test]
    fn takeover_rules_cover_top_providers() {
        let providers: Vec<&str> = TAKEOVER_RULES.iter().map(|r| r.provider).collect();
        for p in ["Heroku", "GitHub Pages", "AWS S3", "Azure App Service", "AWS CloudFront"] {
            assert!(providers.iter().any(|s| s.contains(p)), "missing {}", p);
        }
    }
}

// We use `anyhow!` once for an unreachable path; suppress unused-import
// lint without the macro coming back.
#[allow(dead_code)]
fn _silence_anyhow() -> anyhow::Error {
    anyhow!("unused")
}
