//! Target-aware flag recommendations — `--recommend HOST`.
//!
//! Performs a fast, focused TCP-connect probe over the union of
//! ports the recommender knows how to react to (~25 ports), then
//! prints the rustymap flags that would yield the most relevant
//! follow-up audit for what's actually open.
//!
//! The recommendation table is hand-curated:
//!
//!   - **22** → `--ssh-audit` + `--auth-audit` shortcut hint
//!   - **445/139** → `--smb-audit`
//!   - **3389** → `--rdp-audit`
//!   - **25/465/587** → `--smtp-audit` (+ `--dns-security` for the apex)
//!   - **80/443/8080/8443** → `--http-enum`, `--ssl-enum`, `--tls-grade`
//!   - **53** → `--dns-security DOMAIN`
//!   - **3306/5432/6379/27017/9200/1433/1521/11211** → flag as
//!     sensitive DB/cache exposure; suggest restricting at firewall
//!   - **5985/5986** → flag WinRM exposure
//!
//! Output: a copy-pasteable command line plus a brief rationale per
//! suggested flag. Designed for someone who's seen the target for
//! the first time and wants to know "what should I run next?"
//!
//! Read-only, single TCP-connect per port. Uses `tokio::net::TcpStream`
//! with a per-port timeout — no raw sockets, no privileges needed.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Default probe set when the caller didn't specify `-p`. Covers the
/// services the recommender knows how to react to plus the common
/// modern app/admin ports (Grafana, Jenkins, Kibana, etcd, K8s API,
/// Elasticsearch HTTPS, Vault, MinIO, etc.). Pass `-p` to widen.
const PROBE_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 465, 587, 631,
    636, 993, 995, 1433, 1521, 1883, 2049, 2375, 2376, 2379, 2380, 3000,
    3306, 3389, 4444, 5000, 5432, 5601, 5672, 5900, 5984, 5985, 5986, 6379,
    6443, 6984, 7000, 7474, 7777, 8000, 8060, 8080, 8081, 8088, 8123, 8200,
    8443, 8500, 8800, 8888, 9000, 9001, 9090, 9091, 9100, 9200, 9300, 9418,
    11211, 27017, 50000,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub host: String,
    pub open_ports: Vec<u16>,
    pub flags: Vec<String>,
    pub notes: Vec<String>,
    pub command_line: String,
}

pub async fn analyze(host: &str, dur: Duration) -> Result<Recommendation> {
    analyze_with_ports(host, dur, None).await
}

/// Same as `analyze` but lets the caller widen (or restrict) the probe
/// set. When `ports` is None we fall back to `PROBE_PORTS`. When the
/// caller passes a list (e.g. from `-p 1-65535`), we probe those — so
/// the recommender stops missing services on non-default ports.
pub async fn analyze_with_ports(
    host: &str,
    dur: Duration,
    ports: Option<&[u16]>,
) -> Result<Recommendation> {
    let ip: IpAddr = resolve(host)
        .await
        .with_context(|| format!("resolve {}", host))?;
    let probe_set: Vec<u16> = match ports {
        Some(p) if !p.is_empty() => p.to_vec(),
        _ => PROBE_PORTS.to_vec(),
    };
    let mut open = Vec::new();
    for &port in &probe_set {
        if probe_port(ip, port, dur).await {
            open.push(port);
        }
    }
    let (flags, notes) = derive_flags(&open, host);
    let probe_set_len = probe_set.len();
    let user_supplied = ports.map(|p| !p.is_empty()).unwrap_or(false);

    let mut cmd_args: Vec<String> = vec![host.to_string()];
    if !open.is_empty() {
        let p_spec: Vec<String> = open.iter().map(|p| p.to_string()).collect();
        cmd_args.push("-p".into());
        cmd_args.push(p_spec.join(","));
    }
    cmd_args.extend(flags.iter().cloned());

    let mut notes = notes;
    if !user_supplied {
        notes.push(format!(
            "Probed {} known service ports — add `-p RANGE` (e.g. `-p 1-65535`) \
             alongside --recommend to cover non-default services on this host.",
            probe_set_len
        ));
    }

    Ok(Recommendation {
        host: host.to_string(),
        open_ports: open,
        flags,
        notes,
        command_line: format!("rustymap {}", cmd_args.join(" ")),
    })
}

async fn resolve(host: &str) -> Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs = tokio::net::lookup_host((host, 0u16))
        .await?
        .next()
        .map(|sa| sa.ip())
        .ok_or_else(|| anyhow::anyhow!("no DNS result for {}", host))?;
    Ok(addrs)
}

async fn probe_port(ip: IpAddr, port: u16, dur: Duration) -> bool {
    let addr = std::net::SocketAddr::new(ip, port);
    matches!(timeout(dur, TcpStream::connect(addr)).await, Ok(Ok(_)))
}

/// Pure derivation step — kept separate from the network probe so
/// it can be unit-tested without listening sockets.
pub fn derive_flags(open: &[u16], host: &str) -> (Vec<String>, Vec<String>) {
    let set: HashSet<u16> = open.iter().copied().collect();
    let mut flags: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    let has_any_tls_port = [443u16, 465, 587, 993, 995, 8443, 5986]
        .iter()
        .any(|p| set.contains(p));
    let has_any_http = [80u16, 8080, 443, 8443].iter().any(|p| set.contains(p));

    if set.contains(&22) {
        flags.push("--ssh-audit".into());
        notes.push("SSH on 22 — KEX/cipher/host-key/MAC enum".into());
    }
    if set.contains(&445) || set.contains(&139) {
        flags.push("--smb-audit".into());
        notes.push("SMB on 445/139 — flag SMBv1 + signing-not-required".into());
    }
    if set.contains(&3389) {
        flags.push("--rdp-audit".into());
        notes.push("RDP on 3389 — flag legacy RDP / missing NLA (BlueKeep)".into());
    }
    if [25u16, 465, 587].iter().any(|p| set.contains(p)) {
        flags.push("--smtp-audit".into());
        notes.push("SMTP on 25/465/587 — STARTTLS + AUTH-mechanism audit".into());
    }
    if has_any_http {
        flags.push("--http-enum".into());
        notes.push("HTTP exposed — enumerate ~80 admin/leak paths".into());
    }
    if has_any_tls_port {
        flags.push("--ssl-enum".into());
        flags.push("--tls-grade".into());
        notes.push("TLS port(s) detected — protocol enum + A+/F grade".into());
    }
    if set.contains(&53) {
        if !host.parse::<IpAddr>().is_ok() {
            flags.push("--dns-security".into());
            flags.push(host.to_string());
            notes.push("DNS port 53 + hostname — full DNS-security audit".into());
        } else {
            notes.push("DNS port 53 — pass a hostname to enable --dns-security".into());
        }
    }
    if [5985u16, 5986].iter().any(|p| set.contains(p)) {
        notes.push(
            "WinRM on 5985/5986 — credential bruteforce target. Restrict at FW.".into(),
        );
    }
    let sensitive_dbs = [1433u16, 1521, 2375, 3306, 5432, 5900, 6379, 9200, 11211, 27017];
    let exposed_dbs: Vec<u16> = sensitive_dbs.iter().copied().filter(|p| set.contains(p)).collect();
    if !exposed_dbs.is_empty() {
        let names: Vec<String> = exposed_dbs.iter().map(|p| p.to_string()).collect();
        notes.push(format!(
            "Sensitive service(s) on {} — restrict to internal network",
            names.join(",")
        ));
    }
    if set.contains(&23) {
        notes.push("Telnet on 23 — replace with SSH; cleartext credentials".into());
    }
    if set.contains(&21) {
        notes.push("FTP on 21 — likely cleartext; consider SFTP/FTPS".into());
    }

    if flags.is_empty() && notes.is_empty() {
        notes.push("Nothing recommendable triggered — try a wider --top-ports run".into());
    }

    (flags, notes)
}

pub fn print(rec: &Recommendation) {
    use colored::*;
    println!();
    println!("{}", format!("Recommendations for {}", rec.host).bold());
    if rec.open_ports.is_empty() {
        println!("  {}", "no probe-set ports open".dimmed());
    } else {
        let s: Vec<String> = rec.open_ports.iter().map(|p| p.to_string()).collect();
        println!("  open ports: {}", s.join(", ").yellow());
    }
    if !rec.flags.is_empty() {
        println!();
        println!("  {}", "suggested flags:".cyan().bold());
        for f in &rec.flags {
            println!("    {}", f);
        }
    }
    if !rec.notes.is_empty() {
        println!();
        println!("  {}", "notes:".cyan().bold());
        for n in &rec.notes {
            println!("    · {}", n);
        }
    }
    println!();
    println!("  {}", "command:".cyan().bold());
    println!("    {}", rec.command_line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_only_yields_ssh_audit() {
        let (flags, notes) = derive_flags(&[22], "10.0.0.1");
        assert!(flags.contains(&"--ssh-audit".to_string()));
        assert!(notes.iter().any(|n| n.contains("SSH")));
    }

    #[test]
    fn https_yields_ssl_enum_and_tls_grade() {
        let (flags, _) = derive_flags(&[443], "host");
        assert!(flags.contains(&"--ssl-enum".to_string()));
        assert!(flags.contains(&"--tls-grade".to_string()));
    }

    #[test]
    fn db_exposure_flagged_in_notes_only() {
        let (flags, notes) = derive_flags(&[3306, 6379, 27017], "host");
        assert!(flags.is_empty(), "DB ports should produce notes only, not flags");
        assert!(notes.iter().any(|n| n.contains("3306")));
    }

    #[test]
    fn dns_with_hostname_pulls_dns_security_with_arg() {
        let (flags, _) = derive_flags(&[53], "example.com");
        assert!(flags.iter().any(|f| f == "--dns-security"));
        assert!(flags.iter().any(|f| f == "example.com"));
    }

    #[test]
    fn dns_with_ip_only_skips_dns_security_flag() {
        let (flags, notes) = derive_flags(&[53], "10.0.0.1");
        assert!(!flags.iter().any(|f| f == "--dns-security"));
        assert!(notes.iter().any(|n| n.contains("hostname")));
    }

    #[test]
    fn empty_open_set_produces_helpful_note() {
        let (flags, notes) = derive_flags(&[], "host");
        assert!(flags.is_empty());
        assert!(notes.iter().any(|n| n.contains("Nothing")));
    }
}
