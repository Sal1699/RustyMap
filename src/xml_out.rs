//! Nmap-compatible XML output (subset).
//!
//! Sticks to the elements and attributes that downstream consumers
//! (zenmap, msf db_import, vuln scanners) actually parse: nmaprun,
//! scaninfo, host/status/address/hostnames, ports/port/state/service,
//! runstats/finished/hosts. Skips OS class/cpe trees we don't compute.

use crate::ports::service_name;
use crate::scanner::{HostResult, PortState};
use anyhow::Result;
use std::fmt::Write;

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_xml_specials() {
        assert_eq!(escape("a&b"), "a&amp;b");
        assert_eq!(escape("<x>"), "&lt;x&gt;");
        assert_eq!(escape("\"x\""), "&quot;x&quot;");
        assert_eq!(escape("o'reilly"), "o&apos;reilly");
    }

    #[test]
    fn escape_handles_combined() {
        // & must be escaped first to avoid double-escaping the entity refs
        assert_eq!(escape("a & <b> & \"c\""), "a &amp; &lt;b&gt; &amp; &quot;c&quot;");
    }

    #[test]
    fn escape_is_identity_for_plain_text() {
        assert_eq!(escape("hello world"), "hello world");
        assert_eq!(escape("OpenSSH 7.4"), "OpenSSH 7.4");
    }
}

pub fn write_xml(
    path: &str,
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
    args_line: &str,
) -> Result<()> {
    let mut out = String::new();
    let start_ts = started_at.timestamp();
    let end_ts = started_at.timestamp() + elapsed_secs as i64;
    let scan_type_lower = scan_type.to_ascii_lowercase();

    writeln!(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(
        out,
        "<nmaprun scanner=\"rustymap\" args=\"{}\" start=\"{}\" version=\"{}\" xmloutputversion=\"1.05\">",
        escape(args_line),
        start_ts,
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(
        out,
        "  <scaninfo type=\"{}\" protocol=\"tcp\" numservices=\"{}\"/>",
        scan_type_lower,
        hosts.first().map(|h| h.ports.len()).unwrap_or(0)
    )?;
    writeln!(out, "  <verbose level=\"0\"/>")?;
    writeln!(out, "  <debugging level=\"0\"/>")?;

    let up_count = hosts.iter().filter(|h| h.up).count();

    for h in hosts {
        let addr_type = if h.target.ip.is_ipv4() { "ipv4" } else { "ipv6" };
        let status = if h.up { "up" } else { "down" };
        writeln!(
            out,
            "  <host starttime=\"{}\" endtime=\"{}\">",
            start_ts, end_ts
        )?;
        writeln!(
            out,
            "    <status state=\"{}\" reason=\"{}\"/>",
            status,
            if h.up { "syn-ack" } else { "no-response" }
        )?;
        writeln!(
            out,
            "    <address addr=\"{}\" addrtype=\"{}\"/>",
            h.target.ip, addr_type
        )?;
        writeln!(out, "    <hostnames>")?;
        if let Some(name) = &h.target.hostname {
            writeln!(
                out,
                "      <hostname name=\"{}\" type=\"PTR\"/>",
                escape(name)
            )?;
        }
        writeln!(out, "    </hostnames>")?;
        writeln!(out, "    <ports>")?;
        for p in &h.ports {
            let state_s = match p.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
                PortState::OpenFiltered => "open|filtered",
                PortState::Unfiltered => "unfiltered",
            };
            let reason_s = crate::output::reason_for(scan_type, p.state);
            writeln!(
                out,
                "      <port protocol=\"tcp\" portid=\"{}\">",
                p.port
            )?;
            writeln!(
                out,
                "        <state state=\"{}\" reason=\"{}\" reason_ttl=\"0\"/>",
                state_s, reason_s
            )?;
            let service = service_name(p.port).unwrap_or("unknown");
            let mut svc_attrs = format!("name=\"{}\"", escape(service));
            if let Some(svc) = &p.service {
                if let Some(prod) = &svc.product {
                    svc_attrs.push_str(&format!(" product=\"{}\"", escape(prod)));
                }
                if let Some(ver) = &svc.version {
                    svc_attrs.push_str(&format!(" version=\"{}\"", escape(ver)));
                }
                if let Some(banner) = &svc.banner {
                    svc_attrs.push_str(&format!(" extrainfo=\"{}\"", escape(banner)));
                }
            }
            writeln!(out, "        <service {} method=\"probed\"/>", svc_attrs)?;
            writeln!(out, "      </port>")?;
        }
        writeln!(out, "    </ports>")?;
        if let Some(os) = &h.os {
            writeln!(out, "    <os>")?;
            writeln!(
                out,
                "      <osmatch name=\"{}\" accuracy=\"{}\"/>",
                escape(&os.family),
                os.confidence
            )?;
            writeln!(out, "    </os>")?;
        }
        writeln!(
            out,
            "    <times srtt=\"0\" rttvar=\"0\" to=\"{}\"/>",
            (h.elapsed.as_micros()).min(1_000_000)
        )?;
        writeln!(out, "  </host>")?;
    }

    writeln!(out, "  <runstats>")?;
    writeln!(
        out,
        "    <finished time=\"{}\" elapsed=\"{:.2}\" summary=\"{} hosts scanned, {} up\" exit=\"success\"/>",
        end_ts,
        elapsed_secs,
        hosts.len(),
        up_count
    )?;
    writeln!(
        out,
        "    <hosts up=\"{}\" down=\"{}\" total=\"{}\"/>",
        up_count,
        hosts.len() - up_count,
        hosts.len()
    )?;
    writeln!(out, "  </runstats>")?;
    writeln!(out, "</nmaprun>")?;

    crate::file_out::write(path, out.as_bytes())?;
    Ok(())
}
