use crate::file_out;
use crate::ports::service_name;
use crate::scanner::{HostResult, PortState};
use anyhow::Result;
use colored::*;
use std::io::Write;

pub fn print_banner() {
    println!(
        "Starting RustyMap {} ( https://github.com/Sal1699/RustyMap ) at {}",
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format("%Y-%m-%d %H:%M %Z")
    );
}

pub fn reason_for(scan_type: &str, state: PortState) -> &'static str {
    match (scan_type, state) {
        ("Connect", PortState::Open) => "conn-established",
        ("Connect", PortState::Closed) => "conn-refused",
        ("Syn", PortState::Open) => "syn-ack",
        ("Syn", PortState::Closed) => "rst",
        ("Fin" | "Null" | "Xmas", PortState::Closed) => "rst",
        ("Fin" | "Null" | "Xmas", PortState::OpenFiltered) => "no-response",
        ("Ack", PortState::Unfiltered) => "rst",
        ("Udp", PortState::Open) => "udp-response",
        ("Udp", PortState::Closed) => "icmp-port-unreach",
        ("Udp", PortState::OpenFiltered) => "no-response",
        (_, PortState::Filtered) => "no-response",
        _ => "—",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_open_is_synack() {
        assert_eq!(reason_for("Syn", PortState::Open), "syn-ack");
    }

    #[test]
    fn connect_open_is_established() {
        assert_eq!(reason_for("Connect", PortState::Open), "conn-established");
    }

    #[test]
    fn closed_maps_per_scan_type() {
        assert_eq!(reason_for("Connect", PortState::Closed), "conn-refused");
        assert_eq!(reason_for("Syn", PortState::Closed), "rst");
        assert_eq!(reason_for("Udp", PortState::Closed), "icmp-port-unreach");
    }

    #[test]
    fn filtered_is_universal() {
        assert_eq!(reason_for("Connect", PortState::Filtered), "no-response");
        assert_eq!(reason_for("Syn", PortState::Filtered), "no-response");
        assert_eq!(reason_for("Udp", PortState::Filtered), "no-response");
    }

    #[test]
    fn ack_unfiltered_is_rst() {
        assert_eq!(reason_for("Ack", PortState::Unfiltered), "rst");
    }
}

pub fn print_host_with_reason(host: &HostResult, verbose: u8, scan_type: &str, show_reason: bool) {
    print_host_inner(host, verbose, scan_type, show_reason);
}

#[allow(dead_code)]
pub fn print_host(host: &HostResult, verbose: u8) {
    print_host_inner(host, verbose, "Connect", false);
}

fn print_host_inner(host: &HostResult, verbose: u8, scan_type: &str, show_reason: bool) {
    println!();
    println!(
        "RustyMap scan report for {}",
        host.target.display().bold()
    );

    if !host.up {
        println!("Host seems down. If it is really up, try --Pn");
        return;
    }

    let open_count = host.ports.iter().filter(|p| p.state == PortState::Open).count();
    let total = host.ports.len();
    let filtered = total - open_count - host.ports.iter().filter(|p| p.state == PortState::Closed).count();

    println!(
        "Host is up ({:.3}s latency).",
        host.elapsed.as_secs_f64()
    );

    if let Some(os) = &host.os {
        let ttl_s = os.ttl.map(|t| format!(" TTL={}", t)).unwrap_or_default();
        println!("OS guess: {} (confidence {}%{})", os.family, os.confidence, ttl_s);
        if verbose > 0 && !os.hints.is_empty() {
            println!("  hints: {}", os.hints.join(", "));
        }
    }

    if let Some(dev) = &host.device {
        let vendor_s = dev.vendor.as_deref().map(|v| format!(" · {}", v)).unwrap_or_default();
        let model_s = dev.model.as_deref().map(|m| format!(" {}", m)).unwrap_or_default();
        let fw_s = dev
            .firmware
            .as_deref()
            .map(|f| format!(" · firmware {}", f))
            .unwrap_or_default();
        println!(
            "Device: {}{}{}{} (confidence {}%)",
            dev.class.as_str().bold(),
            vendor_s,
            model_s,
            fw_s,
            dev.confidence
        );
        if verbose > 0 && !dev.hints.is_empty() {
            println!("  hints: {}", dev.hints.join(", "));
        }
    }

    if open_count == 0 && verbose == 0 {
        println!("All scanned ports are closed or filtered ({} filtered)", filtered);
        return;
    }

    if show_reason {
        println!("{:<10} {:<10} {:<18} {:<16} VERSION", "PORT", "STATE", "REASON", "SERVICE");
    } else {
        println!("{:<10} {:<10} {:<16} VERSION", "PORT", "STATE", "SERVICE");
    }
    for p in &host.ports {
        let port_s = format!("{}/tcp", p.port);
        let (state_s, colored_state) = match p.state {
            PortState::Open => ("open", "open".green().bold()),
            PortState::Closed => ("closed", "closed".red()),
            PortState::Filtered => ("filtered", "filtered".yellow()),
            PortState::OpenFiltered => ("open|filtered", "open|filtered".cyan()),
            PortState::Unfiltered => ("unfiltered", "unfiltered".magenta()),
        };
        let service = service_name(p.port).unwrap_or("unknown");
        let version = p.service.as_ref().map(|s| s.display()).unwrap_or_default();
        let _ = state_s;
        if show_reason {
            let reason = reason_for(scan_type, p.state);
            println!("{:<10} {:<10} {:<18} {:<16} {}", port_s, colored_state, reason, service, version);
        } else {
            println!("{:<10} {:<10} {:<16} {}", port_s, colored_state, service, version);
        }
        if let Some(svc) = &p.service {
            if let Some(tls) = &svc.tls {
                let mut line = format!("           tls: {}", tls.summary());
                if let Some(bits) = tls.key_bits {
                    line.push_str(&format!(" {}-bit", bits));
                }
                if !tls.san.is_empty() {
                    let preview: Vec<&str> = tls.san.iter().take(4).map(|s| s.as_str()).collect();
                    line.push_str(&format!(" SAN={}", preview.join(",")));
                    if tls.san.len() > 4 {
                        line.push_str(&format!(" (+{} more)", tls.san.len() - 4));
                    }
                }
                println!("{}", line);
                if verbose > 0 {
                    if let (Some(nb), Some(na)) = (&tls.not_before, &tls.not_after) {
                        println!("           cert validity: {} → {}", nb, na);
                    }
                    if let Some(iss) = &tls.issuer {
                        println!("           issuer: {}", iss);
                    }
                }
            }
        }
    }
}

pub fn print_summary(hosts: &[HostResult], elapsed_sec: f64) {
    let up = hosts.iter().filter(|h| h.up).count();
    let total = hosts.len();
    println!();
    println!(
        "RustyMap done: {} IP address{} ({} host{} up) scanned in {:.2} seconds",
        total,
        if total == 1 { "" } else { "es" },
        up,
        if up == 1 { "" } else { "s" },
        elapsed_sec
    );
}

pub fn write_normal(path: &str, hosts: &[HostResult], elapsed_sec: f64) -> Result<()> {
    let mut f = file_out::open(path)?;
    writeln!(
        f,
        "# RustyMap {} scan at {}",
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format("%Y-%m-%d %H:%M %Z")
    )?;
    for h in hosts {
        writeln!(f, "\nHost: {}", h.target.display())?;
        if !h.up {
            writeln!(f, "  Status: Down")?;
            continue;
        }
        writeln!(f, "  Status: Up (latency {:.3}s)", h.elapsed.as_secs_f64())?;
        if let Some(dev) = &h.device {
            let v = dev.vendor.as_deref().map(|v| format!(" · {}", v)).unwrap_or_default();
            writeln!(f, "  Device: {}{} (confidence {}%)", dev.class.as_str(), v, dev.confidence)?;
        }
        writeln!(f, "  PORT        STATE       SERVICE")?;
        for p in &h.ports {
            let state = match p.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
                PortState::OpenFiltered => "open|filtered",
                PortState::Unfiltered => "unfiltered",
            };
            let svc = service_name(p.port).unwrap_or("unknown");
            writeln!(f, "  {:<11} {:<13} {}", format!("{}/tcp", p.port), state, svc)?;
        }
    }
    let up = hosts.iter().filter(|h| h.up).count();
    writeln!(
        f,
        "\n# Done: {} hosts scanned, {} up, in {:.2}s",
        hosts.len(),
        up,
        elapsed_sec
    )?;
    Ok(())
}

pub fn write_grepable(path: &str, hosts: &[HostResult]) -> Result<()> {
    let mut f = file_out::open(path)?;
    writeln!(f, "# RustyMap grepable output")?;
    for h in hosts {
        let status = if h.up { "Up" } else { "Down" };
        write!(f, "Host: {} ({})\tStatus: {}", h.target.ip, h.target.hostname.as_deref().unwrap_or(""), status)?;
        if h.up && !h.ports.is_empty() {
            write!(f, "\tPorts: ")?;
            let parts: Vec<String> = h.ports.iter().map(|p| {
                let state = match p.state {
                    PortState::Open => "open",
                    PortState::Closed => "closed",
                    PortState::Filtered => "filtered",
                    PortState::OpenFiltered => "open|filtered",
                    PortState::Unfiltered => "unfiltered",
                };
                format!("{}/{}/tcp//{}", p.port, state, service_name(p.port).unwrap_or(""))
            }).collect();
            write!(f, "{}", parts.join(", "))?;
        }
        writeln!(f)?;
    }
    Ok(())
}
