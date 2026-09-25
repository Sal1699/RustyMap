use crate::file_out;
use crate::ports::service_name;
use crate::scanner::{HostResult, PortResult, PortState};
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

/// Format a 6-byte MAC as the canonical colon-separated uppercase hex.
fn fmt_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Estimate hop count from an observed TTL/hop-limit, the way nmap does:
/// assume the sender used the nearest standard initial TTL at or above
/// the observed value (64 for *nix/macOS, 128 for Windows, 255 for many
/// network appliances) and count how far it decremented in transit.
fn network_distance(ttl: u8) -> u8 {
    let initial: u16 = if ttl <= 64 {
        64
    } else if ttl <= 128 {
        128
    } else {
        255
    };
    (initial - ttl as u16) as u8
}

/// Per-port round-trip time in milliseconds, or an em dash when the scan
/// path did not record one (e.g. synthetic/cancelled probes).
fn fmt_rtt(rtt: std::time::Duration) -> String {
    if rtt.is_zero() {
        "—".to_string()
    } else {
        format!("{:.2}ms", rtt.as_secs_f64() * 1000.0)
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
    let closed_count = host.ports.iter().filter(|p| p.state == PortState::Closed).count();
    let filtered_count = host.ports.iter().filter(|p| p.state == PortState::Filtered).count();
    let open_filtered_count = host.ports.iter().filter(|p| p.state == PortState::OpenFiltered).count();
    let unfiltered_count = host.ports.iter().filter(|p| p.state == PortState::Unfiltered).count();
    let total = host.ports.len();
    let filtered = total - open_count - closed_count;

    // Prefer the fastest real probe RTT as the reported latency (what
    // nmap shows) over the scan wall-clock, which is inflated by
    // filtered-port timeouts. Fall back to host.elapsed (which the ARP
    // path already overrides with the true reply RTT for LAN hosts).
    let latency = host
        .ports
        .iter()
        .map(|p| p.rtt)
        .filter(|r| !r.is_zero())
        .min()
        .unwrap_or(host.elapsed);
    // Adaptive precision: sub-millisecond latencies would collapse to
    // "0.000s" at 3 decimals, so widen to 6 like nmap does.
    let lat = latency.as_secs_f64();
    let lat_str = if lat > 0.0 && lat < 0.001 {
        format!("{:.6}", lat)
    } else {
        format!("{:.3}", lat)
    };
    println!("Host is up ({}s latency).", lat_str);

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

    // MAC address (LAN scans): resolve the OUI vendor for context, the
    // same line nmap prints. host.mac is populated from the ARP sweep.
    if let Some(mac) = &host.mac {
        let vendor = crate::device_fp::vendor_from_mac(mac)
            .map(|v| format!(" ({})", v))
            .unwrap_or_default();
        println!("MAC Address: {}{}", fmt_mac(mac), vendor);
    }

    // Network distance derived from the fingerprinted TTL/hop-limit —
    // nmap prints this from its OS-detection probes; we get it for free
    // from the ping TTL already captured during host discovery.
    if let Some(os) = &host.os {
        if let Some(ttl) = os.ttl {
            let is_local = host.target.ip.is_loopback()
                || matches!(host.target.ip,
                    std::net::IpAddr::V4(v) if v.is_private() || v.is_link_local());
            let hops = network_distance(ttl);
            if hops == 0 {
                if is_local {
                    println!("Network Distance: 0 hops (directly connected)");
                } else {
                    // A remote host cannot really be 0 hops away — the
                    // observed TTL just happens to equal a standard initial
                    // value (64/128/255), so single-TTL distance estimation
                    // is indeterminate here (lab bug 5.A). Say so rather than
                    // claiming "directly connected".
                    println!(
                        "Network Distance: unknown (TTL {} sits at an initial-value boundary)",
                        ttl
                    );
                }
            } else {
                let unit = if hops == 1 { "hop" } else { "hops" };
                println!("Network Distance: {} {}", hops, unit);
            }
        }
    }

    // Split ports into what we list individually vs. what we collapse into
    // an nmap-style "Not shown" summary. Open ports are always listed;
    // non-open ports are listed only with -v or when there are few enough
    // to be useful, so the default report shows the signal (open services)
    // without a wall of closed/filtered rows — but their counts are never
    // hidden the way they used to be (lab bug 0.A: 10/13 ports invisible).
    let nonopen_count =
        closed_count + filtered_count + open_filtered_count + unfiltered_count;
    let list_nonopen = verbose >= 1 || nonopen_count <= 25;

    if nonopen_count > 0 && !list_nonopen {
        let mut parts: Vec<String> = Vec::new();
        if closed_count > 0 { parts.push(format!("{} closed", closed_count)); }
        if filtered_count > 0 { parts.push(format!("{} filtered", filtered_count)); }
        if open_filtered_count > 0 { parts.push(format!("{} open|filtered", open_filtered_count)); }
        if unfiltered_count > 0 { parts.push(format!("{} unfiltered", unfiltered_count)); }
        println!("Not shown: {} ({})", nonopen_count, parts.join(", "));
    }

    let shown: Vec<&PortResult> = host
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open || list_nonopen)
        .collect();

    if shown.is_empty() {
        if nonopen_count == 0 {
            println!("No probed ports yielded a state — likely all probes were dropped silently.");
        }
        // FIN/NULL/Xmas defeated by a Windows target: per RFC 793 Windows
        // RSTs even open ports, so every probe comes back Closed. Surface
        // the hint so "no open ports" isn't confused with "scan can't
        // enumerate this target type".
        if matches!(scan_type, "FIN" | "NULL" | "Xmas")
            && closed_count > 0
            && filtered_count == 0
            && open_filtered_count == 0
        {
            println!(
                "  hint: all-closed on {} scan typically means a Windows-family target — \
                 Windows RSTs FIN/NULL/Xmas probes per RFC 793 violation, so these scan \
                 types can't enumerate Windows. Try --sS or --sT.",
                scan_type
            );
        }
        let _ = filtered;
        return;
    }

    // RTT column is extra detail nmap does not print by default; show it
    // once the user asks for any verbosity. Columns are assembled
    // dynamically so REASON/RTT slot in without breaking alignment.
    let show_rtt = verbose >= 1;
    let mut header: Vec<String> = vec![
        format!("{:<10}", "PORT").bold().to_string(),
        format!("{:<14}", "STATE").bold().to_string(),
    ];
    if show_reason {
        header.push(format!("{:<18}", "REASON").bold().to_string());
    }
    if show_rtt {
        header.push(format!("{:<10}", "RTT").bold().to_string());
    }
    header.push(format!("{:<16}", "SERVICE").bold().to_string());
    header.push("VERSION".bold().to_string());
    println!("{}", header.join(" "));

    for p in shown.iter().copied() {
        let port_s = format!("{}/tcp", p.port);
        // Pad the plain text to width FIRST, then colorize, so the ANSI
        // escapes don't throw off column alignment.
        let state_plain = format!("{:<14}", p.state.as_str());
        let colored_state = match p.state {
            PortState::Open => state_plain.green().bold(),
            PortState::Closed => state_plain.red(),
            PortState::Filtered => state_plain.yellow(),
            PortState::OpenFiltered => state_plain.cyan(),
            PortState::Unfiltered => state_plain.magenta(),
        };
        let service = service_name(p.port).unwrap_or("unknown");
        let version = p.service.as_ref().map(|s| s.display()).unwrap_or_default();
        let mut cells: Vec<String> = vec![
            format!("{:<10}", port_s),
            colored_state.to_string(),
        ];
        if show_reason {
            cells.push(format!("{:<18}", reason_for(scan_type, p.state)));
        }
        if show_rtt {
            cells.push(format!("{:<10}", fmt_rtt(p.rtt)));
        }
        cells.push(format!("{:<16}", service));
        cells.push(version);
        println!("{}", cells.join(" "));
        // Raw service banner at -vv — the actual bytes we matched on,
        // more transparent than nmap's cooked service line.
        if verbose >= 2 {
            if let Some(svc) = &p.service {
                if let Some(b) = &svc.banner {
                    let first = b.lines().next().unwrap_or("").trim();
                    if !first.is_empty() {
                        let shown: String = first.chars().take(120).collect();
                        println!("           banner: {}", shown.dimmed());
                    }
                }
            }
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

    // Service Info rollup — one nmap-style line summarising OS, device
    // class and every distinct product detected across the open ports.
    let mut products: Vec<String> = Vec::new();
    for p in &host.ports {
        if let Some(svc) = &p.service {
            let d = svc.display();
            if !d.is_empty() && !products.contains(&d) {
                products.push(d);
            }
        }
    }
    let mut info_bits: Vec<String> = Vec::new();
    if let Some(os) = &host.os {
        let fam = os.family.trim();
        if !fam.is_empty() && !fam.eq_ignore_ascii_case("unknown") {
            info_bits.push(format!("OS: {}", fam));
        }
    }
    if let Some(dev) = &host.device {
        let class = dev.class.as_str();
        if !class.eq_ignore_ascii_case("unknown") {
            info_bits.push(format!("Device: {}", class));
        }
    }
    if !products.is_empty() {
        info_bits.push(format!("Services: {}", products.join(", ")));
    }
    if !info_bits.is_empty() {
        println!("Service Info: {}", info_bits.join("; "));
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
