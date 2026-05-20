use anyhow::{anyhow, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use hickory_resolver::TokioAsyncResolver;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    /// IPv6 link-local zone identifier (interface name as typed,
    /// e.g. "eth0" or "Ethernet"). `None` for everything else.
    /// Resolved to a numeric scope id at connect time via
    /// `socket_addr_with_zone()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
}

impl Target {
    pub fn display(&self) -> String {
        let ip_str = match (&self.ip, &self.zone) {
            (IpAddr::V6(_), Some(z)) => format!("{}%{}", self.ip, z),
            _ => self.ip.to_string(),
        };
        match &self.hostname {
            Some(h) => format!("{} ({})", h, ip_str),
            None => ip_str,
        }
    }

    /// Build a SocketAddr ready to connect, resolving the zone-ID
    /// if the target is IPv6 link-local. `zone` is looked up via
    /// `if_nametoindex` (Unix) or `GetAdapterIndex` (Windows).
    /// Falls back to scope_id=0 if the lookup fails.
    #[allow(dead_code)]
    pub fn socket_addr_with_zone(&self, port: u16) -> SocketAddr {
        match self.ip {
            IpAddr::V4(_) => SocketAddr::new(self.ip, port),
            IpAddr::V6(v6) => {
                let scope = self
                    .zone
                    .as_deref()
                    .map(iface_to_scope_id)
                    .unwrap_or(0);
                SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope))
            }
        }
    }
}

/// Resolve a network-interface name to its numeric scope id.
/// Returns 0 if the platform-specific lookup fails — caller will get
/// a connection error if the link-local address actually needed it.
pub fn iface_to_scope_id(name: &str) -> u32 {
    // Numeric scope id pass-through, e.g. "%2" → 2.
    if let Ok(n) = name.parse::<u32>() {
        return n;
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        if let Ok(c) = CString::new(name) {
            // SAFETY: `if_nametoindex` reads a NUL-terminated C string.
            unsafe {
                let idx = libc::if_nametoindex(c.as_ptr());
                if idx > 0 {
                    return idx as u32;
                }
            }
        }
    }
    #[cfg(windows)]
    {
        // Windows uses adapter LUID/index — pnet exposes interface
        // listing with index info, which we already use elsewhere.
        for iface in pnet::datalink::interfaces() {
            if iface.name.eq_ignore_ascii_case(name) || iface.description.eq_ignore_ascii_case(name) {
                return iface.index as u32;
            }
        }
    }
    0
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
    // IPv6 link-local with zone-ID, e.g. "fe80::1%eth0" or
    // "fe80::1%eth0/64". We split off the "%zone" suffix before
    // parsing so the rest goes through the standard IpAddr/IpNet
    // paths, then re-attach the zone to every Target produced.
    let (clean, zone) = split_zone_id(spec);
    let zone_owned = zone.map(String::from);

    // CIDR
    if let Ok(net) = clean.parse::<IpNet>() {
        // IPv6 CIDR larger than /112 (~65k hosts) explodes — refuse
        // unless the caller already opted in via the broader
        // confirm-large path (caller's responsibility upstream).
        if let IpNet::V6(v6net) = &net {
            if v6net.prefix_len() < 112 {
                return Err(anyhow!(
                    "IPv6 CIDR /{} expands to {} addresses — refusing without an explicit list \
                     of hosts. Use a smaller prefix (≥/112) or an explicit address list.",
                    v6net.prefix_len(),
                    1u128 << (128 - v6net.prefix_len() as u32)
                ));
            }
        }
        for ip in net.hosts() {
            out.push(Target {
                ip,
                hostname: None,
                zone: zone_owned.clone(),
            });
        }
        return Ok(());
    }

    // Direct IP (with optional %zone already split off above)
    if let Ok(ip) = clean.parse::<IpAddr>() {
        out.push(Target {
            ip,
            hostname: None,
            zone: zone_owned,
        });
        return Ok(());
    }

    // IPv4 range: 10.0.0.1-50 or 10.0.0.1-10.0.0.50
    if let Some(ips) = parse_ipv4_range(clean) {
        for ip in ips {
            out.push(Target {
                ip: IpAddr::V4(ip),
                hostname: None,
                zone: None,
            });
        }
        return Ok(());
    }

    // Bug-13 (v0.66.4): refuse syntactically-malformed IPv4 (e.g.
    // "999.999.999.999") instead of letting it fall through to DNS
    // lookup where it may resolve to localhost or some captive-portal
    // default. If the spec looks like four dotted numeric segments,
    // it was meant to be an IP, so we treat it as a hard error.
    if clean.chars().filter(|c| *c == '.').count() == 3
        && clean.split('.').all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(anyhow!(
            "'{}' looks like an IPv4 address but has out-of-range octets \
             (each must be 0-255). Did you mean a different IP?",
            spec
        ));
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
                zone: None,
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

/// Split off the "%zone" suffix from an IPv6 spec. Handles both bare
/// addresses (`fe80::1%eth0`) and CIDR (`fe80::1%eth0/64`).
fn split_zone_id(spec: &str) -> (&str, Option<&str>) {
    if let Some(pct) = spec.find('%') {
        // The zone runs from '%' until either '/' (CIDR boundary)
        // or end. Anything past that goes back into the clean form.
        let (lhs, rhs) = spec.split_at(pct);
        let after_pct = &rhs[1..];
        if let Some(slash) = after_pct.find('/') {
            // Reassemble "<addr>/<prefix>" without the zone label.
            // We can't borrow a non-contiguous slice, so this branch
            // returns the zone but signals "needs caller to rebuild";
            // since we always return &str, the caller has to handle
            // CIDR-with-zone manually. Instead: we let the caller see
            // the lhs (just addr) for now and ignore the prefix —
            // simpler to refuse zone+CIDR combinations, which makes
            // little sense anyway (link-local /64 is the whole link).
            let _ = slash;
            return (lhs, Some(after_pct.split('/').next().unwrap_or("")));
        }
        (lhs, Some(after_pct))
    } else {
        (spec, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_zone_id_extracts_iface_name() {
        let (clean, zone) = split_zone_id("fe80::1%eth0");
        assert_eq!(clean, "fe80::1");
        assert_eq!(zone, Some("eth0"));
    }

    #[test]
    fn split_zone_id_passes_through_when_absent() {
        let (clean, zone) = split_zone_id("10.0.0.1");
        assert_eq!(clean, "10.0.0.1");
        assert_eq!(zone, None);
    }

    #[test]
    fn split_zone_id_handles_cidr_boundary() {
        let (clean, zone) = split_zone_id("fe80::%eth0/64");
        assert_eq!(clean, "fe80::");
        assert_eq!(zone, Some("eth0"));
    }

    #[test]
    fn iface_to_scope_id_passthrough_numeric() {
        assert_eq!(iface_to_scope_id("3"), 3);
    }

    #[test]
    fn iface_to_scope_id_returns_zero_for_unknown() {
        assert_eq!(iface_to_scope_id("definitely-not-a-real-iface-xyz"), 0);
    }

    #[test]
    fn target_display_includes_zone_for_v6_link_local() {
        let t = Target {
            ip: "fe80::1".parse().unwrap(),
            hostname: None,
            zone: Some("eth0".into()),
        };
        assert_eq!(t.display(), "fe80::1%eth0");
    }

    #[test]
    fn target_display_no_zone_for_v4() {
        let t = Target {
            ip: "10.0.0.1".parse().unwrap(),
            hostname: None,
            zone: Some("ignored".into()),
        };
        assert_eq!(t.display(), "10.0.0.1");
    }

    #[tokio::test]
    async fn expand_rejects_huge_ipv6_cidr() {
        let mut out = Vec::new();
        let r = expand_one("2001:db8::/64", None, &mut out).await;
        assert!(r.is_err(), "should refuse /64 IPv6 CIDR");
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("/64"), "{}", msg);
    }

    #[tokio::test]
    async fn expand_accepts_small_ipv6_cidr() {
        let mut out = Vec::new();
        expand_one("2001:db8::/126", None, &mut out).await.unwrap();
        // /126 has 4 addresses, hosts() yields the 2 usable ones
        assert!(!out.is_empty());
        assert!(out.iter().all(|t| matches!(t.ip, IpAddr::V6(_))));
    }

    #[tokio::test]
    async fn expand_carries_zone_to_target() {
        let mut out = Vec::new();
        expand_one("fe80::1%eth0", None, &mut out).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].zone.as_deref(), Some("eth0"));
        assert!(matches!(out[0].ip, IpAddr::V6(_)));
    }
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
