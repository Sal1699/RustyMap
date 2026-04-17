use crate::ports::service_name;
use crate::scanner::{HostResult, PortState};
use anyhow::Result;
use colored::*;
use std::fs::File;
use std::io::Write;

pub fn print_banner() {
    println!(
        "Starting RustyMap 0.1.0 ( https://github.com/Sal1699/RustyMap ) at {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M %Z")
    );
}

pub fn print_host(host: &HostResult, verbose: u8) {
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

    if open_count == 0 && verbose == 0 {
        println!("All scanned ports are closed or filtered ({} filtered)", filtered);
        return;
    }

    println!("{:<10} {:<10} {:<16} {}", "PORT", "STATE", "SERVICE", "VERSION");
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
        println!("{:<10} {:<10} {:<16} {}", port_s, colored_state, service, version);
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
    let mut f = File::create(path)?;
    writeln!(
        f,
        "# RustyMap 0.1.0 scan at {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M %Z")
    )?;
    for h in hosts {
        writeln!(f, "\nHost: {}", h.target.display())?;
        if !h.up {
            writeln!(f, "  Status: Down")?;
            continue;
        }
        writeln!(f, "  Status: Up (latency {:.3}s)", h.elapsed.as_secs_f64())?;
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
    let mut f = File::create(path)?;
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
