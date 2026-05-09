//! Native SVG topology renderer — no Graphviz dependency.
//!
//! The existing `--topology FILE.dot` writes Graphviz DOT and leaves
//! the user to run `dot -Tsvg`. This module produces a finished SVG
//! directly, so the output is one self-contained file the user can
//! open in any browser without installing the Graphviz toolchain.
//!
//! Layout: hub-and-spoke. The scanning host (a labelled centre node)
//! sits at the canvas centre; up hosts are placed around a circle
//! sized to fit them all. Each host node carries its open ports as
//! coloured chips arranged radially:
//!   - **green** common services (80, 443, 22, 25, 53, 110, 143)
//!   - **amber** infra (445, 139, 3389, 5985)
//!   - **red**   sensitive databases (3306, 5432, 6379, 27017,
//!               9200, 1433, 1521, 11211, 5900)
//!
//! Plain SVG, no JS, no embedded fonts — renders identically in
//! Chrome, Firefox, ImageMagick, web reports.

use crate::scanner::{HostResult, PortState};
use std::f32::consts::PI;
use std::fmt::Write;

const CANVAS_W: f32 = 1000.0;
const CANVAS_H: f32 = 1000.0;
const CENTER_X: f32 = CANVAS_W / 2.0;
const CENTER_Y: f32 = CANVAS_H / 2.0;
const HOST_R: f32 = 32.0;
const PORT_CHIP_W: f32 = 50.0;
const PORT_CHIP_H: f32 = 16.0;

const RED_PORTS: &[u16] = &[1433, 1521, 3306, 5432, 5900, 6379, 9200, 11211, 27017, 2375];
const AMBER_PORTS: &[u16] = &[139, 389, 445, 1900, 3389, 5985, 5986];

fn port_color(port: u16) -> &'static str {
    if RED_PORTS.contains(&port) {
        "#e74c3c"
    } else if AMBER_PORTS.contains(&port) {
        "#f39c12"
    } else {
        "#27ae60"
    }
}

pub fn render(hosts: &[HostResult]) -> String {
    let up_hosts: Vec<&HostResult> = hosts.iter().filter(|h| h.up).collect();
    let n = up_hosts.len().max(1);

    let mut s = String::with_capacity(8 * 1024);
    let _ = writeln!(
        &mut s,
        r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" font-family="monospace" font-size="11">"##,
        CANVAS_W, CANVAS_H
    );
    let _ = writeln!(
        &mut s,
        r##"  <rect width="100%" height="100%" fill="#fafafa"/>"#
    );
    let _ = writeln!(
        &mut s,
        r##"  <text x="{:.1}" y="30" text-anchor="middle" font-size="18" font-weight="bold" fill="#333">RustyMap topology — {} host(s) up</text>"##,
        CENTER_X, up_hosts.len()
    );

    // Centre "scanner" node
    let _ = writeln!(
        &mut s,
        r##"  <circle cx="{cx:.1}" cy="{cy:.1}" r="20" fill="#2c3e50"/>
  <text x="{cx:.1}" y="{ty:.1}" text-anchor="middle" fill="white" font-size="10">scanner</text>"##,
        cx = CENTER_X,
        cy = CENTER_Y,
        ty = CENTER_Y + 4.0,
    );

    let radius = compute_ring_radius(n);
    for (i, h) in up_hosts.iter().enumerate() {
        let angle = (i as f32 / n as f32) * 2.0 * PI - PI / 2.0;
        let x = CENTER_X + radius * angle.cos();
        let y = CENTER_Y + radius * angle.sin();

        // Spoke
        let _ = writeln!(
            &mut s,
            r##"  <line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="#bdc3c7" stroke-width="1"/>"##,
            CENTER_X, CENTER_Y, x, y
        );

        // Host node
        let label = match &h.target.hostname {
            Some(name) => name.clone(),
            None => h.target.ip.to_string(),
        };
        let truncated = if label.len() > 18 { format!("{}…", &label[..17]) } else { label.clone() };
        let _ = writeln!(
            &mut s,
            r##"  <circle cx="{x:.1}" cy="{y:.1}" r="{r:.1}" fill="#3498db" stroke="#2980b9" stroke-width="2"/>
  <text x="{x:.1}" y="{ty:.1}" text-anchor="middle" fill="white" font-weight="bold">{label}</text>"##,
            x = x,
            y = y,
            r = HOST_R,
            ty = y + 4.0,
            label = xml_escape(&truncated),
        );

        // Open-port chips arranged in a small arc around the node.
        let open_ports: Vec<u16> = h
            .ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .map(|p| p.port)
            .collect();
        let chip_count = open_ports.len();
        for (j, port) in open_ports.iter().enumerate() {
            let chip_angle = angle + (j as f32 - (chip_count as f32 - 1.0) / 2.0) * 0.18;
            let chip_dist = HOST_R + 22.0;
            let cx = x + chip_dist * chip_angle.cos();
            let cy = y + chip_dist * chip_angle.sin();
            let color = port_color(*port);
            let _ = writeln!(
                &mut s,
                r##"  <rect x="{rx:.1}" y="{ry:.1}" width="{w}" height="{h}" rx="3" fill="{color}"/>
  <text x="{tx:.1}" y="{ty:.1}" text-anchor="middle" fill="white">{port}</text>"##,
                rx = cx - PORT_CHIP_W / 2.0,
                ry = cy - PORT_CHIP_H / 2.0,
                w = PORT_CHIP_W,
                h = PORT_CHIP_H,
                color = color,
                tx = cx,
                ty = cy + 4.0,
                port = port,
            );
        }
    }

    // Legend
    let _ = writeln!(&mut s, r##"  <g transform="translate(20, 940)">
    <rect width="14" height="14" rx="3" fill="#27ae60"/>
    <text x="20" y="11" fill="#333">common services</text>
    <rect x="160" width="14" height="14" rx="3" fill="#f39c12"/>
    <text x="180" y="11" fill="#333">infra (SMB/RDP/LDAP/WinRM)</text>
    <rect x="430" width="14" height="14" rx="3" fill="#e74c3c"/>
    <text x="450" y="11" fill="#333">sensitive (DB / cache / Docker / VNC)</text>
  </g>"##);

    let _ = writeln!(&mut s, "</svg>");
    s
}

fn compute_ring_radius(n: usize) -> f32 {
    // Keep node-to-node arc length ≥ ~3× host radius so chips don't
    // overlap. radius = n * desired_arc / (2π).
    let desired_arc = HOST_R * 3.5;
    let r = (n as f32 * desired_arc) / (2.0 * PI);
    r.max(160.0).min(380.0)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn write(path: &std::path::Path, hosts: &[HostResult]) -> std::io::Result<()> {
    std::fs::write(path, render(hosts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::PortResult;
    use crate::target::Target;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn host(ip: [u8; 4], ports: &[u16]) -> HostResult {
        HostResult {
            target: Target { ip: Ipv4Addr::from(ip).into(), hostname: None },
            up: true,
            ports: ports
                .iter()
                .map(|&p| PortResult {
                    port: p,
                    state: PortState::Open,
                    rtt: Duration::from_millis(0),
                    service: None,
                })
                .collect(),
            elapsed: Duration::from_millis(0),
            os: None,
            device: None,
            mac: None,
        }
    }

    #[test]
    fn render_includes_svg_envelope_and_hosts() {
        let svg = render(&[host([10, 0, 0, 1], &[80, 443])]);
        assert!(svg.starts_with("<?xml"));
        assert!(svg.contains("<svg"));
        assert!(svg.contains("10.0.0.1"));
        assert!(svg.contains(">80<"));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn port_colors_classified_correctly() {
        assert_eq!(port_color(80), "#27ae60");
        assert_eq!(port_color(445), "#f39c12");
        assert_eq!(port_color(3306), "#e74c3c");
    }

    #[test]
    fn xml_escape_handles_specials() {
        assert_eq!(xml_escape("<x&y>"), "&lt;x&amp;y&gt;");
    }

    #[test]
    fn ring_radius_grows_with_host_count_then_caps() {
        let r1 = compute_ring_radius(3);
        let r10 = compute_ring_radius(10);
        let r1000 = compute_ring_radius(1000);
        assert!(r10 > r1);
        assert!(r1000 <= 380.0);
    }
}
