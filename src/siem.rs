//! SIEM-friendly export of scan results.
//!
//! Four flavours, all line-oriented so the output streams cleanly
//! into a SIEM forwarder (filebeat / vector / rsyslog / NXLog):
//!
//!   - **CEF** (Common Event Format) — ArcSight, Splunk CIM
//!   - **LEEF** (Log Event Extended Format v2) — IBM QRadar
//!   - **ECS** (Elastic Common Schema, JSON) — Elastic / Beats
//!   - **Syslog** RFC 5424 — generic Unix forwarders
//!
//! One line per "event". An event today is either:
//!   - **port_state** — a host / port / state observation
//!   - **finding**    — a higher-level audit finding (TLS deprecated,
//!     SMB v1, weak SSH KEX, …) emitted by the audit-event taxonomy
//!     introduced in v0.46.
//!
//! Pure pure functions: builders take a `[HostResult]` slice and an
//! optional `[compliance::Finding]` slice (passed in by main.rs at
//! scan-end) and return a `String` ready to be written to disk.

use crate::compliance::Finding;
use crate::scanner::{HostResult, PortState};
use anyhow::Result;
use chrono::{DateTime, Local, SecondsFormat};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemFormat {
    Cef,
    Leef,
    Ecs,
    Syslog,
}

impl SiemFormat {
    pub fn parse(s: &str) -> Option<SiemFormat> {
        match s.to_lowercase().as_str() {
            "cef" => Some(SiemFormat::Cef),
            "leef" => Some(SiemFormat::Leef),
            "ecs" | "elastic" => Some(SiemFormat::Ecs),
            "syslog" | "rfc5424" => Some(SiemFormat::Syslog),
            _ => None,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            SiemFormat::Cef => "CEF",
            SiemFormat::Leef => "LEEF",
            SiemFormat::Ecs => "ECS",
            SiemFormat::Syslog => "Syslog",
        }
    }
}

const VENDOR: &str = "RustyMap";
const PRODUCT: &str = "rustymap";
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn render(format: SiemFormat, hosts: &[HostResult], findings: &[Finding]) -> String {
    let now = Local::now();
    let mut out = String::new();
    for h in hosts.iter().filter(|h| h.up) {
        for p in &h.ports {
            if p.state == PortState::Open {
                emit_port(&mut out, format, &now, h, p.port);
            }
        }
    }
    for f in findings {
        emit_finding(&mut out, format, &now, f);
    }
    out
}

pub fn write(format: SiemFormat, path: &Path, hosts: &[HostResult], findings: &[Finding]) -> Result<()> {
    let body = render(format, hosts, findings);
    std::fs::write(path, body)?;
    Ok(())
}

// ── Per-format emitters ───────────────────────────────────────────

fn emit_port(out: &mut String, fmt: SiemFormat, ts: &DateTime<Local>, h: &HostResult, port: u16) {
    let host = h.target.ip.to_string();
    let hostname = h.target.hostname.clone().unwrap_or_default();
    match fmt {
        SiemFormat::Cef => {
            // CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
            out.push_str(&format!(
                "{} CEF:0|{}|{}|{}|port_open|Open port observed|3|dst={} dpt={} dhost={} cs1Label=Scanner cs1={}\n",
                ts.to_rfc3339_opts(SecondsFormat::Secs, true),
                escape_cef(VENDOR),
                escape_cef(PRODUCT),
                PRODUCT_VERSION,
                host,
                port,
                escape_cef(&hostname),
                PRODUCT,
            ));
        }
        SiemFormat::Leef => {
            // LEEF:2.0|Vendor|Product|Version|EventID|delim|key=value...
            out.push_str(&format!(
                "{} LEEF:2.0|{}|{}|{}|port_open|^|dst=^{}^dstport=^{}^hostname=^{}\n",
                ts.to_rfc3339_opts(SecondsFormat::Secs, true),
                VENDOR, PRODUCT, PRODUCT_VERSION,
                host, port, hostname
            ));
        }
        SiemFormat::Ecs => {
            // Elastic Common Schema flat JSON.
            let json = serde_json::json!({
                "@timestamp": ts.to_rfc3339_opts(SecondsFormat::Millis, true),
                "ecs.version": "8.11.0",
                "event": { "kind": "event", "category": ["network"], "type": ["info"], "action": "port_open" },
                "destination": { "ip": host, "port": port, "domain": hostname },
                "observer": { "vendor": VENDOR, "product": PRODUCT, "version": PRODUCT_VERSION },
                "message": format!("{}:{} open", host, port),
            });
            out.push_str(&json.to_string());
            out.push('\n');
        }
        SiemFormat::Syslog => {
            // RFC 5424: <PRI>1 ts hostname app procid msgid - structured-data msg
            // PRI = facility(local0=16)*8 + severity(info=6) = 134
            out.push_str(&format!(
                "<134>1 {} {} {} - port_open - {}:{} open\n",
                ts.to_rfc3339_opts(SecondsFormat::Millis, true),
                hostname_or_ip(h),
                PRODUCT,
                host,
                port
            ));
        }
    }
}

fn emit_finding(out: &mut String, fmt: SiemFormat, ts: &DateTime<Local>, f: &Finding) {
    let severity = severity_for(&f.kind);
    match fmt {
        SiemFormat::Cef => {
            out.push_str(&format!(
                "{} CEF:0|{}|{}|{}|{}|{}|{}|src={} msg={}\n",
                ts.to_rfc3339_opts(SecondsFormat::Secs, true),
                escape_cef(VENDOR),
                escape_cef(PRODUCT),
                PRODUCT_VERSION,
                escape_cef(&f.kind),
                escape_cef(&f.kind.replace('_', " ")),
                severity,
                f.host,
                escape_cef(&f.detail),
            ));
        }
        SiemFormat::Leef => {
            out.push_str(&format!(
                "{} LEEF:2.0|{}|{}|{}|{}|^|src=^{}^msg=^{}^sev=^{}\n",
                ts.to_rfc3339_opts(SecondsFormat::Secs, true),
                VENDOR, PRODUCT, PRODUCT_VERSION,
                f.kind, f.host, f.detail, severity
            ));
        }
        SiemFormat::Ecs => {
            let json = serde_json::json!({
                "@timestamp": ts.to_rfc3339_opts(SecondsFormat::Millis, true),
                "ecs.version": "8.11.0",
                "event": {
                    "kind": "alert",
                    "category": ["host"],
                    "type": ["info"],
                    "action": f.kind,
                    "severity": severity,
                },
                "host": { "name": f.host },
                "observer": { "vendor": VENDOR, "product": PRODUCT, "version": PRODUCT_VERSION },
                "message": f.detail,
            });
            out.push_str(&json.to_string());
            out.push('\n');
        }
        SiemFormat::Syslog => {
            // Severity 4 = warning, 3 = error, 6 = info → map to PRI.
            let pri = 16 * 8 + (if severity >= 7 { 3 } else if severity >= 4 { 4 } else { 6 });
            out.push_str(&format!(
                "<{}>1 {} {} {} - {} - {} {}\n",
                pri,
                ts.to_rfc3339_opts(SecondsFormat::Millis, true),
                f.host,
                PRODUCT,
                f.kind,
                f.host,
                f.detail
            ));
        }
    }
}

fn hostname_or_ip(h: &HostResult) -> String {
    h.target.hostname.clone().unwrap_or_else(|| h.target.ip.to_string())
}

fn severity_for(kind: &str) -> u8 {
    // 0..=10 — CEF/LEEF tradition: 0 = info, 10 = catastrophic.
    match kind {
        "tls_classic_vuln" | "smb_v1" | "cve_critical" => 9,
        "tls_protocol_legacy" | "tls_no_modern" | "rdp_no_nla" | "smtp_clear_creds" => 7,
        "tls_weak_cipher" | "smb_no_signing" | "ssh_weak_kex" | "ssh_weak_cipher" => 6,
        "ssh_weak_mac" | "smtp_starttls_missing" => 5,
        "port_open_unrestricted" => 3,
        _ => 4,
    }
}

/// CEF requires backslash-escape of `=`, `\`, and `|` in the
/// extension keys/values. We intentionally don't escape inside the
/// header pipes — those characters can't legitimately appear in
/// vendor / product / signature names.
fn escape_cef(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::PortResult;
    use crate::target::Target;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn host(ip: [u8; 4], port: u16) -> HostResult {
        HostResult {
            target: Target { ip: Ipv4Addr::from(ip).into(), hostname: Some("h.test".into()) },
            up: true,
            ports: vec![PortResult { port, state: PortState::Open, rtt: Duration::from_millis(0), service: None }],
            elapsed: Duration::from_millis(0),
            os: None,
            device: None,
            mac: None,
        }
    }

    #[test]
    fn cef_line_starts_with_header() {
        let out = render(SiemFormat::Cef, &[host([10, 0, 0, 1], 22)], &[]);
        let line = out.lines().next().unwrap();
        assert!(line.contains("CEF:0|RustyMap|rustymap|"));
        assert!(line.contains("dst=10.0.0.1"));
        assert!(line.contains("dpt=22"));
    }

    #[test]
    fn leef_line_uses_caret_delimiter() {
        let out = render(SiemFormat::Leef, &[host([10, 0, 0, 2], 443)], &[]);
        assert!(out.contains("LEEF:2.0|"));
        assert!(out.contains("dstport=^443"));
    }

    #[test]
    fn ecs_line_is_valid_json() {
        let out = render(SiemFormat::Ecs, &[host([10, 0, 0, 3], 80)], &[]);
        let line = out.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["destination"]["port"], 80);
        assert_eq!(v["event"]["action"], "port_open");
    }

    #[test]
    fn syslog_line_has_priority_and_app() {
        let out = render(SiemFormat::Syslog, &[host([10, 0, 0, 4], 25)], &[]);
        let line = out.lines().next().unwrap();
        assert!(line.starts_with("<134>1 "));
        assert!(line.contains("rustymap"));
        assert!(line.contains("port_open"));
    }

    #[test]
    fn finding_severity_increases_for_critical_kinds() {
        assert!(severity_for("tls_classic_vuln") > severity_for("tls_weak_cipher"));
        assert!(severity_for("smb_v1") > severity_for("port_open_unrestricted"));
    }

    #[test]
    fn cef_escape_handles_pipe_equals_backslash() {
        let s = escape_cef(r"a=b|c\d");
        assert_eq!(s, r"a\=b\|c\\d");
    }

    #[test]
    fn finding_emits_in_each_format() {
        let f = vec![Finding::new("smb_v1", "10.0.0.5:445", "SMBv1 negotiated")];
        for fmt in [SiemFormat::Cef, SiemFormat::Leef, SiemFormat::Ecs, SiemFormat::Syslog] {
            let out = render(fmt, &[], &f);
            assert!(!out.is_empty(), "{:?}", fmt);
            assert!(out.contains("smb_v1"), "{:?}", fmt);
        }
    }

    #[test]
    fn parse_aliases() {
        assert_eq!(SiemFormat::parse("CEF"), Some(SiemFormat::Cef));
        assert_eq!(SiemFormat::parse("elastic"), Some(SiemFormat::Ecs));
        assert_eq!(SiemFormat::parse("rfc5424"), Some(SiemFormat::Syslog));
        assert!(SiemFormat::parse("nope").is_none());
    }
}
