//! Network interface listing.
//!
//! Like nmap's `--iflist` but with a route-to-target hint: when the
//! caller provides a target IP, we annotate which local interface
//! would be chosen for it, so users running multi-NIC machines can
//! tell at a glance which adapter the scanner will use.

use colored::*;
use pnet::datalink;
use std::net::IpAddr;

pub fn run(target_for_route: Option<IpAddr>) {
    let interfaces = datalink::interfaces();

    println!(
        "\n{:<22} {:<6} {:<6} {:<19} {}",
        "INTERFACE".bold(),
        "FLAG".bold(),
        "MTU".bold(),
        "MAC".bold(),
        "IPS".bold()
    );

    let route_iface = target_for_route.and_then(|t| match t {
        IpAddr::V4(v4) => crate::net_util::source_ipv4_for(v4)
            .ok()
            .map(IpAddr::V4),
        IpAddr::V6(_) => None,
    });

    for iface in &interfaces {
        let flags = format!(
            "{}{}{}{}",
            if iface.is_up() { "U" } else { "-" },
            if iface.is_loopback() { "L" } else { "-" },
            if iface.is_broadcast() { "B" } else { "-" },
            if iface.is_multicast() { "M" } else { "-" },
        );
        let mac = iface
            .mac
            .map(|m| m.to_string())
            .unwrap_or_else(|| "-".into());
        let ips: Vec<String> = iface.ips.iter().map(|i| i.to_string()).collect();
        let ips_s = if ips.is_empty() {
            "-".into()
        } else {
            ips.join(", ")
        };

        // Mark with arrow if this is the interface the kernel would
        // choose for the requested target.
        let routed_here = route_iface
            .map(|src| iface.ips.iter().any(|i| i.contains(src)))
            .unwrap_or(false);
        let marker = if routed_here {
            format!(" {}", "←".green().bold())
        } else {
            String::new()
        };

        println!(
            "{:<22} {:<6} {:<6} {:<19} {}{}",
            iface.name, flags, "auto", mac, ips_s, marker
        );
    }

    if target_for_route.is_some() && route_iface.is_some() {
        println!();
        println!(
            "{}",
            format!(
                "→ packets to {} would leave via the interface marked ←",
                target_for_route.unwrap()
            )
            .dimmed()
        );
    }

    println!();
    println!(
        "{}",
        "FLAGS: U=up L=loopback B=broadcast M=multicast"
            .dimmed()
    );
}
