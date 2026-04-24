use anyhow::{anyhow, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use hickory_resolver::TokioAsyncResolver;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub ip: IpAddr,
    pub hostname: Option<String>,
}

impl Target {
    pub fn display(&self) -> String {
        match &self.hostname {
            Some(h) => format!("{} ({})", h, self.ip),
            None => self.ip.to_string(),
        }
    }
}

pub async fn expand_targets(specs: &[String], resolve: bool) -> Result<Vec<Target>> {
    let mut out = Vec::new();
    let resolver = if resolve {
        Some(TokioAsyncResolver::tokio_from_system_conf()?)
    } else {
        None
    };

    for spec in specs {
        expand_one(spec, resolver.as_ref(), &mut out).await?;
    }

    // deduplicate by IP
    out.sort_by_key(|t| t.ip);
    out.dedup_by_key(|t| t.ip);
    Ok(out)
}

async fn expand_one(
    spec: &str,
    resolver: Option<&TokioAsyncResolver>,
    out: &mut Vec<Target>,
) -> Result<()> {
    // CIDR
    if let Ok(net) = spec.parse::<IpNet>() {
        for ip in net.hosts() {
            out.push(Target { ip, hostname: None });
        }
        return Ok(());
    }

    // Direct IP
    if let Ok(ip) = spec.parse::<IpAddr>() {
        out.push(Target { ip, hostname: None });
        return Ok(());
    }

    // IPv4 range: 10.0.0.1-50 or 10.0.0.1-10.0.0.50
    if let Some(ips) = parse_ipv4_range(spec) {
        for ip in ips {
            out.push(Target {
                ip: IpAddr::V4(ip),
                hostname: None,
            });
        }
        return Ok(());
    }

    // Hostname
    if let Some(r) = resolver {
        let lookup = r.lookup_ip(spec).await.map_err(|e| {
            let raw = e.to_string();
            let hint = if raw.contains("unreachable") || raw.contains("10051") {
                " (DNS path unreachable — pass -n/--no-dns with IP targets, or check the resolver)"
            } else if raw.contains("NXDomain") || raw.contains("no records found") {
                " (domain does not exist)"
            } else if raw.contains("no record") {
                " (no A/AAAA records — try the FQDN, or check DNS)"
            } else {
                ""
            };
            anyhow!("DNS lookup failed for '{}': {}{}", spec, e, hint)
        })?;
        let mut any = false;
        for ip in lookup.iter() {
            out.push(Target {
                ip,
                hostname: Some(spec.to_string()),
            });
            any = true;
        }
        if !any {
            return Err(anyhow!("No A/AAAA records for '{}'", spec));
        }
        return Ok(());
    }

    Err(anyhow!(
        "Cannot parse target '{}' (DNS disabled — drop -n/--no-dns or use an IP/CIDR)",
        spec
    ))
}

fn parse_ipv4_range(spec: &str) -> Option<Vec<Ipv4Addr>> {
    let (lhs, rhs) = spec.split_once('-')?;
    let start: Ipv4Addr = lhs.parse().ok()?;

    let end: Ipv4Addr = if let Ok(full) = rhs.parse::<Ipv4Addr>() {
        full
    } else {
        // last octet shorthand
        let last: u8 = rhs.parse().ok()?;
        let [a, b, c, _] = start.octets();
        Ipv4Addr::new(a, b, c, last)
    };

    let s = u32::from(start);
    let e = u32::from(end);
    if e < s || (e - s) > 65535 {
        return None;
    }
    Some((s..=e).map(Ipv4Addr::from).collect())
}
