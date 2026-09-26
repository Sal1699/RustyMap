//! Cloud / CDN fingerprinting from DNS resolution.
//!
//! Two complementary signals:
//!   - **CNAME chain**: the chain of CNAMEs a hostname unwinds to is
//!     the most reliable fingerprint. `*.cloudfront.net`,
//!     `*.s3.amazonaws.com`, `*.akamaiedge.net`, `*.fastly.net`,
//!     `*.azureedge.net`, `*.googleapis.com`, etc. each map cleanly
//!     to a single provider.
//!   - **Reverse-DNS / WHOIS-region heuristics**: when the CNAME is
//!     opaque (e.g. a custom host on top of a CDN), we look at the
//!     PTR of the resolved A record. AWS/EC2 PTRs end in
//!     `*.compute.amazonaws.com`, GCP PTRs in `*.googleusercontent.com`,
//!     Azure in `*.cloudapp.net`.
//!
//! Output: per host, a list of `(provider, service)` classifications.
//! A host can match more than one (e.g. CloudFront in front of an
//! S3 origin → CloudFront + S3).

use anyhow::Result;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Classification {
    pub provider: String,
    pub service: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloudFingerprint {
    pub host: String,
    pub cname_chain: Vec<String>,
    pub a_records: Vec<IpAddr>,
    pub ptr_records: Vec<String>,
    pub classifications: Vec<Classification>,
}

/// (suffix_match, provider, service)
const CNAME_RULES: &[(&str, &str, &str)] = &[
    // AWS family
    (".cloudfront.net", "AWS", "CloudFront CDN"),
    (".s3.amazonaws.com", "AWS", "S3"),
    (".s3-website", "AWS", "S3 static-website hosting"),
    ("amazonaws.com", "AWS", "AWS service endpoint"),
    (".elasticbeanstalk.com", "AWS", "Elastic Beanstalk"),
    (".elb.amazonaws.com", "AWS", "ELB load balancer"),
    (".execute-api.", "AWS", "API Gateway"),
    // GCP family
    (".googleusercontent.com", "GCP", "Compute Engine"),
    (".appspot.com", "GCP", "App Engine"),
    (".storage.googleapis.com", "GCP", "Cloud Storage"),
    (".run.app", "GCP", "Cloud Run"),
    (".firebaseapp.com", "GCP", "Firebase Hosting"),
    (".cloudfunctions.net", "GCP", "Cloud Functions"),
    // Azure family
    (".azureedge.net", "Azure", "Azure CDN (Microsoft)"),
    (".azurefd.net", "Azure", "Front Door"),
    (".cloudapp.net", "Azure", "Cloud Services / classic VM"),
    (".azurewebsites.net", "Azure", "App Service"),
    (".blob.core.windows.net", "Azure", "Blob Storage"),
    (".trafficmanager.net", "Azure", "Traffic Manager"),
    // Cloudflare
    (".cloudflare.net", "Cloudflare", "CDN"),
    (".cloudflareaccess.com", "Cloudflare", "Access (zero-trust)"),
    (".pages.dev", "Cloudflare", "Pages"),
    (".workers.dev", "Cloudflare", "Workers"),
    // Akamai
    (".akamaiedge.net", "Akamai", "Edge CDN"),
    (".akamai.net", "Akamai", "Akamai network"),
    (".akamaized.net", "Akamai", "Image Manager / static"),
    (".edgekey.net", "Akamai", "EdgeKey"),
    // Fastly
    (".fastly.net", "Fastly", "Edge CDN"),
    (".fastlylb.net", "Fastly", "load balancer"),
    // GitHub / Vercel / Netlify (PaaS)
    (".github.io", "GitHub", "Pages"),
    (".vercel.app", "Vercel", "edge hosting"),
    (".vercel-dns.com", "Vercel", "edge"),
    (".netlify.app", "Netlify", "edge hosting"),
    (".netlify.com", "Netlify", "edge"),
];

/// (suffix_match, provider, service) — applied to PTR records of
/// resolved A records.
const PTR_RULES: &[(&str, &str, &str)] = &[
    (".compute.amazonaws.com", "AWS", "EC2"),
    (".compute-1.amazonaws.com", "AWS", "EC2 (us-east-1)"),
    (".googleusercontent.com", "GCP", "Compute Engine"),
    (".cloudapp.net", "Azure", "VM"),
    (".cloudapp.azure.com", "Azure", "VM (ARM)"),
    (".linode.com", "Linode", "VM"),
    (".digitalocean.com", "DigitalOcean", "Droplet"),
    (".vultrusercontent.com", "Vultr", "VM"),
    (".hetzner.com", "Hetzner", "VM"),
    (".ovh.net", "OVH", "VM"),
    (".ovhcloud.com", "OVH", "VM"),
    (".akamaitechnologies.com", "Akamai", "Edge CDN"),
    (".deploy.static.akamaitechnologies.com", "Akamai", "Edge CDN"),
];

/// (CIDR, provider, service) — matched against the resolved A/AAAA records.
/// The big CDNs/clouds front their apex domains with plain A records in
/// their own IP space (no CNAME), so suffix matching alone misses them
/// (lab bug 4.A: google.com / Cloudflare went unidentified). These are the
/// well-known published edge ranges; not exhaustive (AWS/GCP publish huge
/// dynamic lists), but they catch the common cases.
const IP_RANGES: &[(&str, &str, &str)] = &[
    // Cloudflare
    ("104.16.0.0/13", "Cloudflare", "CDN"),
    ("172.64.0.0/13", "Cloudflare", "CDN"),
    ("162.158.0.0/15", "Cloudflare", "CDN"),
    ("173.245.48.0/20", "Cloudflare", "CDN"),
    ("103.21.244.0/22", "Cloudflare", "CDN"),
    ("141.101.64.0/18", "Cloudflare", "CDN"),
    ("108.162.192.0/18", "Cloudflare", "CDN"),
    ("190.93.240.0/20", "Cloudflare", "CDN"),
    ("188.114.96.0/20", "Cloudflare", "CDN"),
    ("198.41.128.0/17", "Cloudflare", "CDN"),
    ("131.0.72.0/22", "Cloudflare", "CDN"),
    // Google
    ("142.250.0.0/15", "Google", "Edge/Serving"),
    ("172.217.0.0/16", "Google", "Edge/Serving"),
    ("216.58.192.0/19", "Google", "Edge/Serving"),
    ("192.178.0.0/15", "Google", "Edge/Serving"),
    ("74.125.0.0/16", "Google", "Edge/Serving"),
    ("64.233.160.0/19", "Google", "Edge/Serving"),
    ("209.85.128.0/17", "Google", "Edge/Serving"),
    ("8.8.8.0/24", "Google", "Public DNS"),
    ("8.8.4.0/24", "Google", "Public DNS"),
    // AWS CloudFront (common edge blocks)
    ("13.32.0.0/15", "AWS", "CloudFront"),
    ("13.35.0.0/16", "AWS", "CloudFront"),
    ("52.84.0.0/15", "AWS", "CloudFront"),
    ("54.192.0.0/16", "AWS", "CloudFront"),
    ("99.84.0.0/16", "AWS", "CloudFront"),
    ("205.251.192.0/19", "AWS", "CloudFront"),
    // Fastly
    ("151.101.0.0/16", "Fastly", "CDN"),
    ("199.232.0.0/16", "Fastly", "CDN"),
    // Akamai
    ("23.0.0.0/12", "Akamai", "CDN"),
    ("23.32.0.0/11", "Akamai", "CDN"),
    ("23.192.0.0/11", "Akamai", "CDN"),
    ("104.64.0.0/10", "Akamai", "CDN"),
    ("184.24.0.0/13", "Akamai", "CDN"),
    ("2.16.0.0/13", "Akamai", "CDN"),
    ("96.16.0.0/15", "Akamai", "CDN"),
    ("96.6.0.0/15", "Akamai", "CDN"),
];

pub async fn fingerprint(host: &str, dur: Duration) -> Result<CloudFingerprint> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let mut fp = CloudFingerprint {
        host: host.to_string(),
        ..Default::default()
    };

    // CNAME chain — walk by repeating until we hit an A/AAAA terminus
    // or a max depth (protects against loops; opaque resolvers may
    // collapse the chain and only return the leaf).
    let mut current = host.to_string();
    for _ in 0..8 {
        let res = tokio::time::timeout(dur, resolver.lookup(current.as_str(), RecordType::CNAME)).await;
        let Ok(Ok(lookup)) = res else { break };
        let next: Option<String> = lookup
            .iter()
            .filter_map(|r| match r {
                RData::CNAME(n) => Some(n.to_string().trim_end_matches('.').to_lowercase()),
                _ => None,
            })
            .next();
        match next {
            Some(n) if n != current => {
                fp.cname_chain.push(n.clone());
                current = n;
            }
            _ => break,
        }
    }

    // A / AAAA.
    if let Ok(Ok(lookup)) = tokio::time::timeout(dur, resolver.lookup_ip(host)).await {
        for ip in lookup.iter() {
            fp.a_records.push(ip);
        }
    }

    // PTR for each unique IP (cap to 5).
    for ip in fp.a_records.iter().take(5) {
        if let Ok(Ok(rev)) = tokio::time::timeout(dur, resolver.reverse_lookup(*ip)).await {
            for r in rev.iter() {
                fp.ptr_records.push(r.to_string().trim_end_matches('.').to_lowercase());
            }
        }
    }

    classify(&mut fp);
    Ok(fp)
}

fn classify(fp: &mut CloudFingerprint) {
    let mut seen = std::collections::HashSet::new();

    // CNAME suffixes
    let mut chain_inputs: Vec<String> = fp.cname_chain.clone();
    chain_inputs.push(fp.host.to_lowercase());
    for name in &chain_inputs {
        for (suffix, provider, service) in CNAME_RULES {
            if name.contains(suffix) {
                let key = (*provider, *service);
                if seen.insert(key) {
                    fp.classifications.push(Classification {
                        provider: provider.to_string(),
                        service: service.to_string(),
                        evidence: format!("CNAME contains {}", suffix),
                    });
                }
            }
        }
    }

    // PTR suffixes
    for ptr in &fp.ptr_records {
        for (suffix, provider, service) in PTR_RULES {
            if ptr.ends_with(suffix) {
                let key = (*provider, *service);
                if seen.insert(key) {
                    fp.classifications.push(Classification {
                        provider: provider.to_string(),
                        service: service.to_string(),
                        evidence: format!("PTR ends with {}", suffix),
                    });
                }
            }
        }
    }

    // A/AAAA record IP ranges — catches apex domains fronted by a CDN/cloud
    // with a plain A record and no CNAME (lab bug 4.A).
    for ip in &fp.a_records {
        for (cidr, provider, service) in IP_RANGES {
            if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
                if net.contains(ip) {
                    let key = (*provider, *service);
                    if seen.insert(key) {
                        fp.classifications.push(Classification {
                            provider: provider.to_string(),
                            service: service.to_string(),
                            evidence: format!("IP {} in {}", ip, cidr),
                        });
                    }
                }
            }
        }
    }
}

pub fn print_report(fp: &CloudFingerprint) {
    use colored::*;
    println!();
    println!("{}", format!("Cloud fingerprint for {}", fp.host).bold());
    if !fp.cname_chain.is_empty() {
        println!("  CNAME chain : {}", fp.cname_chain.join(" → "));
    }
    if !fp.a_records.is_empty() {
        let ips: Vec<String> = fp.a_records.iter().map(|i| i.to_string()).collect();
        println!("  A records   : {}", ips.join(", "));
    }
    if !fp.ptr_records.is_empty() {
        println!("  PTR records : {}", fp.ptr_records.join(", "));
    }
    if fp.classifications.is_empty() {
        println!("  {}", "no cloud/CDN provider identified".dimmed());
    } else {
        println!("  {}", "providers detected:".cyan().bold());
        for c in &fp.classifications {
            println!(
                "    · {} ({}) — {}",
                c.provider.bold(),
                c.service,
                c.evidence
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cname_cloudfront_classified() {
        let mut fp = CloudFingerprint {
            host: "x.test".into(),
            cname_chain: vec!["d111111abcdef8.cloudfront.net".into()],
            ..Default::default()
        };
        classify(&mut fp);
        assert!(fp.classifications.iter().any(|c| c.provider == "AWS" && c.service.contains("CloudFront")));
    }

    #[test]
    fn ptr_ec2_classified() {
        let mut fp = CloudFingerprint {
            host: "x.test".into(),
            ptr_records: vec!["ec2-1-2-3-4.compute-1.amazonaws.com".into()],
            ..Default::default()
        };
        classify(&mut fp);
        assert!(fp.classifications.iter().any(|c| c.provider == "AWS" && c.service.contains("EC2")));
    }

    #[test]
    fn no_match_leaves_classifications_empty() {
        let mut fp = CloudFingerprint {
            host: "private.local".into(),
            cname_chain: vec!["intranet.private.local".into()],
            ptr_records: vec!["host-10-0-0-1.private.local".into()],
            ..Default::default()
        };
        classify(&mut fp);
        assert!(fp.classifications.is_empty());
    }

    #[test]
    fn dedupes_repeat_classifications() {
        let mut fp = CloudFingerprint {
            host: "img.acme.test".into(),
            cname_chain: vec![
                "acme.akamaiedge.net".into(),
                "extra.akamaiedge.net".into(),
            ],
            ..Default::default()
        };
        classify(&mut fp);
        let n = fp.classifications.iter().filter(|c| c.provider == "Akamai" && c.service.contains("Edge CDN")).count();
        assert_eq!(n, 1);
    }
}
