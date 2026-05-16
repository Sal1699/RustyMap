//! Metasploit workspace import — pushes RustyMap scan results into
//! an MSF workspace via `db.hosts` / `db.services` / `db.vulns`.
//!
//! After running this, `msfconsole`'s `workspace <name>` + `hosts` /
//! `services` / `vulns` commands return exactly what RustyMap saw.
//! Useful for handing off the discovery phase to MSF for the
//! exploitation phase.
//!
//! Mapping:
//!   - HostResult → db.host: {host, mac, name (hostname), os_name, os_flavor}
//!   - PortResult (open + service) → db.service: {host, port, proto,
//!     name, info (banner)}
//!   - compliance::Finding → db.vuln: {host, name (kind), info (detail),
//!     refs (any embedded CVE id)}
//!
//! Read-only on RustyMap's side — we just send POSTs to the user's
//! own msfrpcd. The MSF DB is the source of truth from this point.

use crate::compliance::Finding;
use crate::msf_rpc::{Client, Value};
use crate::scanner::{HostResult, PortState};
use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct ImportStats {
    pub hosts_pushed: usize,
    pub services_pushed: usize,
    pub vulns_pushed: usize,
    pub failures: Vec<String>,
}

pub async fn push(
    client: &Client,
    workspace: &str,
    hosts: &[HostResult],
    findings: &[Finding],
) -> Result<ImportStats> {
    let mut stats = ImportStats::default();

    for h in hosts {
        if !h.up {
            continue;
        }
        let ip = h.target.ip.to_string();
        let host_args = host_to_map(h, workspace);
        match client.call("db.report_host", &[Value::Map(host_args)]).await {
            Ok(_) => stats.hosts_pushed += 1,
            Err(e) => stats.failures.push(format!("host {}: {}", ip, e)),
        }

        for p in &h.ports {
            if p.state != PortState::Open {
                continue;
            }
            let svc_args = service_to_map(&ip, p, workspace);
            match client.call("db.report_service", &[Value::Map(svc_args)]).await {
                Ok(_) => stats.services_pushed += 1,
                Err(e) => stats
                    .failures
                    .push(format!("service {}:{}: {}", ip, p.port, e)),
            }
        }
    }

    for f in findings {
        let vuln_args = finding_to_vuln_map(f, workspace);
        match client.call("db.report_vuln", &[Value::Map(vuln_args)]).await {
            Ok(_) => stats.vulns_pushed += 1,
            Err(e) => stats.failures.push(format!("vuln {}: {}", f.kind, e)),
        }
    }
    Ok(stats)
}

/// Map a `HostResult` to the msgpack map MSF's `db.report_host`
/// expects. Standard keys: workspace, host, mac, name, os_name,
/// os_flavor, info, comments.
pub fn host_to_map(h: &HostResult, workspace: &str) -> Vec<(Value, Value)> {
    let mut m: HashMap<String, Value> = HashMap::new();
    m.insert("workspace".into(), Value::from(workspace.to_string()));
    m.insert("host".into(), Value::from(h.target.ip.to_string()));
    if let Some(mac) = h.mac {
        m.insert(
            "mac".into(),
            Value::from(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            )),
        );
    }
    if let Some(name) = &h.target.hostname {
        m.insert("name".into(), Value::from(name.clone()));
    }
    if let Some(os) = &h.os {
        m.insert("os_name".into(), Value::from(os.family.clone()));
        if !os.hints.is_empty() {
            m.insert("info".into(), Value::from(os.hints.join(" | ")));
        }
    }
    m.insert("comments".into(), Value::from("imported by rustymap".to_string()));
    map_to_vec(m)
}

pub fn service_to_map(
    host_ip: &str,
    p: &crate::scanner::PortResult,
    workspace: &str,
) -> Vec<(Value, Value)> {
    let mut m: HashMap<String, Value> = HashMap::new();
    m.insert("workspace".into(), Value::from(workspace.to_string()));
    m.insert("host".into(), Value::from(host_ip.to_string()));
    m.insert("port".into(), Value::from(p.port as i64));
    m.insert("proto".into(), Value::from("tcp".to_string()));
    m.insert("state".into(), Value::from("open".to_string()));
    if let Some(svc) = &p.service {
        if let Some(prod) = &svc.product {
            m.insert("info".into(), Value::from(prod.clone()));
            // Try to map product to MSF's service-name field
            let svc_name = guess_service_name(p.port, prod);
            m.insert("name".into(), Value::from(svc_name));
        }
    } else {
        m.insert("name".into(), Value::from(guess_service_name(p.port, "")));
    }
    map_to_vec(m)
}

pub fn finding_to_vuln_map(f: &Finding, workspace: &str) -> Vec<(Value, Value)> {
    let mut m: HashMap<String, Value> = HashMap::new();
    m.insert("workspace".into(), Value::from(workspace.to_string()));
    // `host` field expects an IP; the finding.host may be "ip:port".
    let host_only = f
        .host
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| f.host.clone());
    m.insert("host".into(), Value::from(host_only));
    m.insert("name".into(), Value::from(f.kind.clone()));
    m.insert("info".into(), Value::from(f.detail.clone()));
    // Detect embedded CVE ids in the detail string and pass them as refs.
    let refs = extract_cve_refs(&f.detail);
    if !refs.is_empty() {
        let arr: Vec<Value> = refs.into_iter().map(Value::from).collect();
        m.insert("refs".into(), Value::Array(arr));
    }
    map_to_vec(m)
}

fn guess_service_name(port: u16, product: &str) -> String {
    let p = product.to_lowercase();
    if p.contains("openssh") || port == 22 {
        return "ssh".into();
    }
    // Port-443 / 8443 / explicit "https" wins over the generic
    // http-server product detection — nginx on 443 is HTTPS.
    if port == 443 || port == 8443 || p.contains("https") {
        return "https".into();
    }
    if p.contains("apache") || p.contains("nginx") || p.contains("iis") || port == 80 || port == 8080 {
        return "http".into();
    }
    match port {
        21 => "ftp".into(),
        25 => "smtp".into(),
        53 => "dns".into(),
        110 => "pop3".into(),
        143 => "imap".into(),
        389 => "ldap".into(),
        445 => "smb".into(),
        587 => "submission".into(),
        993 => "imaps".into(),
        995 => "pop3s".into(),
        1433 => "ms-sql-s".into(),
        3306 => "mysql".into(),
        3389 => "rdp".into(),
        5432 => "postgresql".into(),
        5900 => "vnc".into(),
        6379 => "redis".into(),
        27017 => "mongodb".into(),
        _ => format!("tcp-{}", port),
    }
}

pub fn extract_cve_refs(s: &str) -> Vec<String> {
    let re = regex::Regex::new(r"(?i)CVE-\d{4}-\d{4,7}").unwrap();
    let mut out: Vec<String> = re
        .find_iter(s)
        .map(|m| m.as_str().to_uppercase())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn map_to_vec(m: HashMap<String, Value>) -> Vec<(Value, Value)> {
    m.into_iter().map(|(k, v)| (Value::from(k), v)).collect()
}

pub fn print_stats(workspace: &str, stats: &ImportStats) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!(
            "MSF import into workspace '{}' — {} host(s), {} service(s), {} vuln(s)",
            workspace, stats.hosts_pushed, stats.services_pushed, stats.vulns_pushed
        )
        .bold()
    );
    if !stats.failures.is_empty() {
        println!("  {}:", format!("{} failure(s)", stats.failures.len()).red());
        for f in &stats.failures {
            println!("    · {}", f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os_fp::OsGuess;
    use crate::scanner::{PortResult, PortState};
    use crate::target::Target;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn host_fixture() -> HostResult {
        HostResult {
            target: Target {
                ip: Ipv4Addr::new(10, 0, 0, 5).into(),
                hostname: Some("victim.lab".into()),
                zone: None,
            },
            up: true,
            ports: vec![PortResult {
                port: 22,
                state: PortState::Open,
                rtt: Duration::from_millis(0),
                service: None,
            }],
            elapsed: Duration::from_millis(0),
            os: Some(OsGuess {
                family: "Linux 5.15".into(),
                confidence: 80,
                ttl: Some(64),
                hints: vec!["ttl=64".into()],
            }),
            device: None,
            mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        }
    }

    #[test]
    fn host_map_includes_ip_mac_name_os() {
        let h = host_fixture();
        let m = host_to_map(&h, "engagement");
        let s: HashMap<String, &Value> = m
            .iter()
            .map(|(k, v)| (k.as_str().unwrap().to_string(), v))
            .collect();
        assert_eq!(s["host"].as_str().unwrap(), "10.0.0.5");
        assert_eq!(s["name"].as_str().unwrap(), "victim.lab");
        assert_eq!(s["os_name"].as_str().unwrap(), "Linux 5.15");
        assert_eq!(s["mac"].as_str().unwrap(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(s["workspace"].as_str().unwrap(), "engagement");
    }

    #[test]
    fn service_map_includes_port_and_proto() {
        let p = PortResult {
            port: 443,
            state: PortState::Open,
            rtt: Duration::from_millis(0),
            service: Some(crate::service_probe::ServiceInfo {
                product: Some("nginx 1.18".into()),
                version: None,
                extra: None,
                banner: None,
                tls: None,
            }),
        };
        let m = service_to_map("10.0.0.5", &p, "engagement");
        let s: HashMap<String, &Value> = m
            .iter()
            .map(|(k, v)| (k.as_str().unwrap().to_string(), v))
            .collect();
        assert_eq!(s["port"].as_i64().unwrap(), 443);
        assert_eq!(s["proto"].as_str().unwrap(), "tcp");
        assert_eq!(s["name"].as_str().unwrap(), "https");
        assert!(s["info"].as_str().unwrap().contains("nginx"));
    }

    #[test]
    fn finding_map_extracts_cve_refs() {
        let f = Finding::new(
            "tls_classic_vuln",
            "10.0.0.5:443",
            "Heartbleed (CVE-2014-0160) detected",
        );
        let m = finding_to_vuln_map(&f, "engagement");
        let s: HashMap<String, &Value> = m
            .iter()
            .map(|(k, v)| (k.as_str().unwrap().to_string(), v))
            .collect();
        // host field should drop the :port suffix
        assert_eq!(s["host"].as_str().unwrap(), "10.0.0.5");
        // refs array should contain CVE-2014-0160
        let refs = s["refs"].as_array().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].as_str().unwrap(), "CVE-2014-0160");
    }

    #[test]
    fn extract_cve_refs_dedupes_and_normalises_case() {
        let s = "cve-2021-44228 and CVE-2021-44228 and cve-2021-45046";
        let refs = extract_cve_refs(s);
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&"CVE-2021-44228".to_string()));
        assert!(refs.contains(&"CVE-2021-45046".to_string()));
    }

    #[test]
    fn guess_service_name_known_ports() {
        assert_eq!(guess_service_name(22, ""), "ssh");
        assert_eq!(guess_service_name(443, ""), "https");
        assert_eq!(guess_service_name(3306, ""), "mysql");
        assert_eq!(guess_service_name(9999, ""), "tcp-9999");
    }

    #[test]
    fn guess_service_name_product_overrides_port() {
        // Product hint mentions Apache; even on an unusual port we
        // should label http.
        assert_eq!(guess_service_name(9999, "Apache/2.4"), "http");
    }
}
