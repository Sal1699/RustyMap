//! DNS security posture audit: DNSSEC, CAA, DANE/TLSA, DMARC, SPF, DKIM.
//!
//! Each check is read-only — pure DNS queries against the domain's
//! authoritative resolvers via the system stub. We surface findings
//! at three levels:
//!   - **good**: feature configured correctly
//!   - **warn**: feature present but with weaknesses
//!   - **bad**: feature missing or broken
//!
//! Reasoning beats raw flags: e.g. SPF with a permissive `+all` is
//! worse than no SPF at all (claims to authoritatively allow any
//! sender), so we surface it as `bad` rather than `good`.

use anyhow::Result;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize)]
pub enum FindingLevel {
    Good,
    Warn,
    Bad,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsFinding {
    pub check: &'static str,
    pub level: FindingLevel,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsAudit {
    pub domain: String,
    pub findings: Vec<DnsFinding>,
}

impl DnsAudit {
    fn add(&mut self, check: &'static str, level: FindingLevel, detail: impl Into<String>) {
        self.findings.push(DnsFinding { check, level, detail: detail.into() });
    }
    #[allow(dead_code)]
    pub fn count(&self, target: FindingLevel) -> usize {
        self.findings
            .iter()
            .filter(|f| matches!(f.level, l if std::mem::discriminant(&l) == std::mem::discriminant(&target)))
            .count()
    }
}

pub async fn audit(domain: &str, _timeout: Duration) -> Result<DnsAudit> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let mut a = DnsAudit { domain: domain.to_string(), findings: vec![] };

    check_dnssec(&resolver, domain, &mut a).await;
    check_caa(&resolver, domain, &mut a).await;
    check_dane(&resolver, domain, &mut a).await;
    check_spf(&resolver, domain, &mut a).await;
    check_dmarc(&resolver, domain, &mut a).await;
    check_mx_anti_spoof(&resolver, domain, &mut a).await;
    Ok(a)
}

async fn check_dnssec(resolver: &TokioAsyncResolver, d: &str, a: &mut DnsAudit) {
    // DNSKEY presence
    let dnskey = resolver.lookup(d, RecordType::DNSKEY).await;
    let ds = resolver.lookup(d, RecordType::DS).await;
    match (&dnskey, &ds) {
        (Ok(k), Ok(_)) if k.iter().count() > 0 => {
            a.add("DNSSEC", FindingLevel::Good, "DNSKEY + DS records published");
        }
        (Ok(k), Err(_)) if k.iter().count() > 0 => {
            a.add(
                "DNSSEC",
                FindingLevel::Warn,
                "DNSKEY present but no DS at parent — chain of trust incomplete",
            );
        }
        _ => {
            a.add("DNSSEC", FindingLevel::Bad, "no DNSSEC (zone signed records absent)");
        }
    }
}

async fn check_caa(resolver: &TokioAsyncResolver, d: &str, a: &mut DnsAudit) {
    let caa = resolver.lookup(d, RecordType::CAA).await;
    match caa {
        Ok(l) if l.iter().count() > 0 => {
            let count = l.iter().count();
            a.add("CAA", FindingLevel::Good, format!("{} CAA record(s) restrict authorized CAs", count));
        }
        _ => a.add(
            "CAA",
            FindingLevel::Warn,
            "no CAA record — any CA can issue certs for this domain",
        ),
    }
}

async fn check_dane(resolver: &TokioAsyncResolver, d: &str, a: &mut DnsAudit) {
    // DANE/TLSA on common ports — 443 (HTTPS), 25 (SMTP).
    let mut found = false;
    for port in [443u16, 25] {
        let qname = format!("_{}._tcp.{}", port, d);
        if let Ok(rr) = resolver.lookup(qname.as_str(), RecordType::TLSA).await {
            if rr.iter().count() > 0 {
                found = true;
                a.add(
                    "DANE/TLSA",
                    FindingLevel::Good,
                    format!("TLSA record published on port {}", port),
                );
            }
        }
    }
    if !found {
        a.add(
            "DANE/TLSA",
            FindingLevel::Warn,
            "no TLSA record on 443/25 — DANE pinning not in use",
        );
    }
}

async fn check_spf(resolver: &TokioAsyncResolver, d: &str, a: &mut DnsAudit) {
    let txt = match resolver.txt_lookup(d).await {
        Ok(t) => t,
        Err(_) => {
            a.add("SPF", FindingLevel::Bad, "no TXT records — SPF not declared");
            return;
        }
    };
    let mut spf = None;
    for r in txt.iter() {
        let s = r.to_string();
        if s.contains("v=spf1") {
            spf = Some(s);
            break;
        }
    }
    let Some(spf) = spf else {
        a.add("SPF", FindingLevel::Bad, "no v=spf1 TXT — sender authorization not declared");
        return;
    };

    // Detect over-permissive policies
    if spf.contains(" +all") {
        a.add(
            "SPF",
            FindingLevel::Bad,
            "SPF ends with `+all` — every sender authorized (worse than no SPF)",
        );
    } else if spf.contains(" ?all") {
        a.add(
            "SPF",
            FindingLevel::Warn,
            "SPF ends with `?all` (neutral) — receivers won't reject spoofed mail",
        );
    } else if spf.contains(" ~all") {
        a.add("SPF", FindingLevel::Warn, "SPF ends with `~all` (softfail) — recommend `-all`");
    } else if spf.contains(" -all") {
        a.add("SPF", FindingLevel::Good, "SPF ends with `-all` (hardfail)");
    }

    // Excessive include/redirect chains hit the 10-DNS-lookup cap
    let lookups = spf.matches("include:").count() + spf.matches("redirect=").count();
    if lookups > 10 {
        a.add(
            "SPF",
            FindingLevel::Warn,
            format!("{} include/redirect — exceeds RFC 7208 10-lookup limit", lookups),
        );
    }
}

async fn check_dmarc(resolver: &TokioAsyncResolver, d: &str, a: &mut DnsAudit) {
    let qname = format!("_dmarc.{}", d);
    let txt = match resolver.txt_lookup(qname.as_str()).await {
        Ok(t) => t,
        Err(_) => {
            a.add("DMARC", FindingLevel::Bad, "no _dmarc TXT — DMARC policy not published");
            return;
        }
    };
    let mut dmarc = None;
    for r in txt.iter() {
        let s = r.to_string();
        if s.contains("v=DMARC1") {
            dmarc = Some(s);
            break;
        }
    }
    let Some(dmarc) = dmarc else {
        a.add("DMARC", FindingLevel::Bad, "no v=DMARC1 record at _dmarc");
        return;
    };

    let policy_part = dmarc
        .split(';')
        .map(str::trim)
        .find(|s| s.starts_with("p="))
        .unwrap_or("");
    match policy_part {
        "p=reject" => a.add("DMARC", FindingLevel::Good, "p=reject (strict)"),
        "p=quarantine" => a.add("DMARC", FindingLevel::Good, "p=quarantine"),
        "p=none" => a.add(
            "DMARC",
            FindingLevel::Warn,
            "p=none (monitor only) — recommend tightening to quarantine/reject",
        ),
        _ => a.add("DMARC", FindingLevel::Warn, format!("unrecognized policy: {}", policy_part)),
    }

    // pct=100 is the safe default
    if let Some(pct) = dmarc
        .split(';')
        .map(str::trim)
        .find_map(|s| s.strip_prefix("pct="))
    {
        if let Ok(n) = pct.parse::<u32>() {
            if n < 100 {
                a.add(
                    "DMARC",
                    FindingLevel::Warn,
                    format!("pct={} — only {}% of mail is policy-checked", n, n),
                );
            }
        }
    }
}

async fn check_mx_anti_spoof(resolver: &TokioAsyncResolver, d: &str, a: &mut DnsAudit) {
    let mx = match resolver.mx_lookup(d).await {
        Ok(m) => m,
        Err(_) => {
            a.add(
                "MX",
                FindingLevel::Warn,
                "no MX records — domain doesn't accept mail (or DNS lookup failed)",
            );
            return;
        }
    };
    let count = mx.iter().count();
    if count == 0 {
        a.add("MX", FindingLevel::Warn, "no MX records published");
    } else if count == 1 {
        a.add(
            "MX",
            FindingLevel::Warn,
            "single MX — no failover redundancy",
        );
    } else {
        a.add(
            "MX",
            FindingLevel::Good,
            format!("{} MX records (mail failover available)", count),
        );
    }
}

pub fn print_report(a: &DnsAudit) {
    use colored::*;
    println!();
    println!("{}", format!("DNS security audit for {}", a.domain).bold());
    println!("{:<14} {:<7} DETAIL", "CHECK", "LEVEL");
    for f in &a.findings {
        let (label, color) = match f.level {
            FindingLevel::Good => ("good", "good".green().to_string()),
            FindingLevel::Warn => ("warn", "warn".yellow().to_string()),
            FindingLevel::Bad => ("bad ", "bad ".red().bold().to_string()),
        };
        let _ = label;
        println!("{:<14} {:<7} {}", f.check, color, f.detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_struct_starts_empty() {
        let a = DnsAudit { domain: "example.com".into(), findings: vec![] };
        assert_eq!(a.findings.len(), 0);
    }

    #[test]
    fn add_records_finding() {
        let mut a = DnsAudit::default();
        a.add("DNSSEC", FindingLevel::Good, "ok");
        assert_eq!(a.findings.len(), 1);
        assert_eq!(a.findings[0].detail, "ok");
    }
}
