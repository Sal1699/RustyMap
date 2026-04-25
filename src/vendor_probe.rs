//! Deep vendor/model/firmware probe for HTTP-reachable devices.
//!
//! When a host has 80/8080/443/etc. open, this module does a short HTTP
//! GET and pattern-matches the response against known signatures for
//! common IP cameras, routers, printers, NAS, and IoT gateways. The
//! output is merged into the existing `DeviceGuess` populated by
//! `device_fp::classify`.

use once_cell::sync::Lazy;
use regex::Regex;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Output of a vendor-focused HTTP probe.
#[derive(Debug, Default, Clone)]
pub struct VendorHint {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub title: Option<String>,
    pub server: Option<String>,
}

impl VendorHint {
    pub fn is_useful(&self) -> bool {
        self.vendor.is_some()
            || self.model.is_some()
            || self.firmware.is_some()
            || self.title.is_some()
            || self.server.is_some()
    }
}

/// HTTP-ish ports we try in priority order. Keeping the list short keeps
/// the probe cheap — the scanner will still have hit these in --sV.
pub const HTTP_PORTS: &[u16] = &[80, 8080, 8000, 8443, 443, 81, 8081, 8888];

static TITLE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)<title[^>]*>\s*([^<\n\r]{1,200})\s*</title>").unwrap());
static SERVER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?im)^\s*Server:\s*([^\r\n]{1,200})").unwrap());
static POWERED_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?im)^\s*X-Powered-By:\s*([^\r\n]{1,200})").unwrap());

/// Per-vendor firmware regex. Each pattern is meant to match body text or
/// response headers of the vendor's admin page.
struct FwRule {
    vendor: &'static str,
    vendor_marker: Regex,
    firmware: Option<Regex>,
    model: Option<Regex>,
}

static FW_RULES: Lazy<Vec<FwRule>> = Lazy::new(|| {
    vec![
        // Hikvision — title often "Web Service" or body reveals serial/model/firmware
        FwRule {
            vendor: "Hikvision",
            vendor_marker: Regex::new(r"(?i)hikvision|DS-[A-Z0-9]+|App-webs/").unwrap(),
            firmware: Some(Regex::new(r"(?i)(?:firmwareVersion|build)\s*[:=]?\s*V?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(DS-[A-Z0-9]+[A-Z0-9-]*)").unwrap()),
        },
        // Dahua
        FwRule {
            vendor: "Dahua",
            vendor_marker: Regex::new(r"(?i)dahua|DH[_-][A-Z0-9]+|webs\s*200 OK").unwrap(),
            firmware: Some(Regex::new(r"(?i)(?:version|build)[:=]\s*([\d.]+(?:\s*build\s*[\d.]+)?)").unwrap()),
            model: Some(Regex::new(r"(?i)(DH[-_][A-Z0-9-]+|IPC-[A-Z0-9-]+|HDW[0-9A-Z-]+)").unwrap()),
        },
        // Axis Communications
        FwRule {
            vendor: "Axis Communications",
            vendor_marker: Regex::new(r"(?i)\baxis\b(?:\s*communications)?|AxisCom|axis.*network camera").unwrap(),
            firmware: Some(Regex::new(r"(?i)version[:=\s]+([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(AXIS\s+[A-Z0-9]+[A-Z0-9-]*)").unwrap()),
        },
        // Reolink
        FwRule {
            vendor: "Reolink",
            vendor_marker: Regex::new(r"(?i)reolink").unwrap(),
            firmware: Some(Regex::new(r"(?i)firmware[:=\s]+v?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(RLC-[A-Z0-9-]+|RLN[0-9-]+)").unwrap()),
        },
        // Foscam
        FwRule {
            vendor: "Foscam",
            vendor_marker: Regex::new(r"(?i)foscam").unwrap(),
            firmware: Some(Regex::new(r"(?i)firmware[:=\s]+v?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(FI[0-9A-Z-]+)").unwrap()),
        },
        // HP printers / iLO
        FwRule {
            vendor: "HP",
            vendor_marker: Regex::new(r"(?i)hp-chaisoe|hp http server|hewlett[- ]packard|laserjet|deskjet|officejet|iLO").unwrap(),
            firmware: Some(Regex::new(r"(?i)(?:firmware|version)[:=\s]+v?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(LaserJet\s+[A-Z0-9]+|DeskJet\s+[A-Z0-9-]+|OfficeJet\s+[A-Z0-9-]+|iLO\s*\d+)").unwrap()),
        },
        // Brother printers
        FwRule {
            vendor: "Brother",
            vendor_marker: Regex::new(r"(?i)brother").unwrap(),
            firmware: Some(Regex::new(r"(?i)firmware[:=\s]+v?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(MFC-[A-Z0-9-]+|HL-[A-Z0-9-]+|DCP-[A-Z0-9-]+)").unwrap()),
        },
        // Canon
        FwRule {
            vendor: "Canon",
            vendor_marker: Regex::new(r"(?i)canon").unwrap(),
            firmware: Some(Regex::new(r"(?i)version[:=\s]+([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(imageRUNNER\s+[A-Z0-9-]+|MX[0-9-]+|TR[0-9-]+|PIXMA\s+[A-Z0-9-]+)").unwrap()),
        },
        // Epson
        FwRule {
            vendor: "Epson",
            vendor_marker: Regex::new(r"(?i)epson").unwrap(),
            firmware: None,
            model: Some(Regex::new(r"(?i)(EcoTank\s+[A-Z0-9-]+|WF-[A-Z0-9-]+|XP-[A-Z0-9-]+|ET-[A-Z0-9-]+)").unwrap()),
        },
        // MikroTik / RouterOS
        FwRule {
            vendor: "MikroTik",
            vendor_marker: Regex::new(r"(?i)mikrotik|routeros").unwrap(),
            firmware: Some(Regex::new(r"(?i)routeros[\s:=]+v?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(RB[0-9A-Z-]+|CRS[0-9A-Z-]+|hEX|hAP|CCR[0-9A-Z-]+)").unwrap()),
        },
        // Ubiquiti UniFi / EdgeOS
        FwRule {
            vendor: "Ubiquiti",
            vendor_marker: Regex::new(r"(?i)ubiquiti|unifi|edgeos|edgeswitch|ubnt").unwrap(),
            firmware: Some(Regex::new(r"(?i)(?:version|build)[:=\s]+v?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(U[A-Z]{1,3}-[A-Z0-9-]+|EdgeRouter\s+[A-Z0-9-]+)").unwrap()),
        },
        // TP-Link
        FwRule {
            vendor: "TP-Link",
            vendor_marker: Regex::new(r"(?i)tp-link|tplink|tplinkcloud|archer\s+[a-z0-9]").unwrap(),
            firmware: Some(Regex::new(r"(?i)firmware[:=\s]+v?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(Archer\s+[A-Z0-9-]+|TL-[A-Z0-9-]+|Deco\s+[A-Z0-9-]+)").unwrap()),
        },
        // Netgear
        FwRule {
            vendor: "Netgear",
            vendor_marker: Regex::new(r"(?i)netgear").unwrap(),
            firmware: Some(Regex::new(r"(?i)firmware\s*version[:=\s]+v?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(R[0-9]{3,4}[A-Z]*|Orbi\s+[A-Z0-9]+|Nighthawk\s+[A-Z0-9-]+|GS[0-9A-Z-]+)").unwrap()),
        },
        // ASUS
        FwRule {
            vendor: "ASUS",
            vendor_marker: Regex::new(r"(?i)\basus\b|asuswrt").unwrap(),
            firmware: Some(Regex::new(r"(?i)firmware\s*version[:=\s]+([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(RT-[A-Z0-9]+|AX[0-9]+|AC[0-9]+|ZenWiFi[\s-][A-Z0-9]+)").unwrap()),
        },
        // Synology DSM
        FwRule {
            vendor: "Synology",
            vendor_marker: Regex::new(r"(?i)synology|diskstation|dsm\s+\d").unwrap(),
            firmware: Some(Regex::new(r"(?i)dsm\s+v?([\d.]+(?:-[\d.]+)?)").unwrap()),
            model: Some(Regex::new(r"(?i)(DS[0-9]+[a-z]+[+]?|RS[0-9]+[a-z]+[+]?)").unwrap()),
        },
        // QNAP
        FwRule {
            vendor: "QNAP",
            vendor_marker: Regex::new(r"(?i)qnap|qts\s+\d").unwrap(),
            firmware: Some(Regex::new(r"(?i)qts[\s:=]+v?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(TS-[0-9A-Z-]+|TVS-[0-9A-Z-]+)").unwrap()),
        },
        // Cisco IOS / ASA
        FwRule {
            vendor: "Cisco",
            vendor_marker: Regex::new(r"(?i)cisco(?:\s+ios|\s+asa|\s+systems)?").unwrap(),
            firmware: Some(Regex::new(r"(?i)(?:version|release)\s+([\d.(]+\d+[.)]\w*)").unwrap()),
            model: Some(Regex::new(r"(?i)(ASA\s*[0-9]+|C[0-9]{4}[A-Z-]*|WS-C[0-9A-Z-]+)").unwrap()),
        },
        // Fortinet
        FwRule {
            vendor: "Fortinet",
            vendor_marker: Regex::new(r"(?i)fortigate|fortinet|fortios").unwrap(),
            firmware: Some(Regex::new(r"(?i)fortios\s+v?([\d.]+)").unwrap()),
            model: Some(Regex::new(r"(?i)(FortiGate-?[0-9A-Z-]+)").unwrap()),
        },
        // pfSense / OPNsense
        FwRule {
            vendor: "pfSense",
            vendor_marker: Regex::new(r"(?i)pfsense").unwrap(),
            firmware: Some(Regex::new(r"(?i)pfsense\s+([\d.]+)").unwrap()),
            model: None,
        },
        FwRule {
            vendor: "OPNsense",
            vendor_marker: Regex::new(r"(?i)opnsense").unwrap(),
            firmware: Some(Regex::new(r"(?i)opnsense\s+([\d.]+)").unwrap()),
            model: None,
        },
    ]
});

fn first_match(re: &Regex, body: &str) -> Option<String> {
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
}

fn parse_response(body: &str) -> VendorHint {
    let title = first_match(&TITLE_RE, body);
    let server = first_match(&SERVER_RE, body).or_else(|| first_match(&POWERED_RE, body));
    let mut hint = VendorHint {
        title,
        server,
        ..Default::default()
    };

    // Vendor-specific matching. First rule to match vendor_marker wins.
    for rule in FW_RULES.iter() {
        if rule.vendor_marker.is_match(body) {
            hint.vendor = Some(rule.vendor.to_string());
            if let Some(fw) = &rule.firmware {
                if let Some(v) = first_match(fw, body) {
                    hint.firmware = Some(v);
                }
            }
            if let Some(md) = &rule.model {
                if let Some(v) = first_match(md, body) {
                    hint.model = Some(v);
                }
            }
            break;
        }
    }

    // Fall back: derive vendor from Server header if we didn't match a rule
    if hint.vendor.is_none() {
        if let Some(s) = &hint.server {
            if s.contains("nginx") || s.contains("Apache") || s.contains("Microsoft-IIS") {
                // generic web server — don't fake a vendor
            } else if s.contains("lighttpd") {
                // same, generic
            } else if s.contains("uhttpd") || s.contains("GoAhead") || s.contains("lighttpd-1.") {
                // embedded server — no hint
            } else {
                // Unknown proprietary server header — surface it anyway
                hint.vendor = Some(s.trim().to_string());
            }
        }
    }

    hint
}

async fn fetch_once(ip: IpAddr, port: u16, dur: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
    let req = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: RustyMap/vendor-probe\r\nAccept: */*\r\n\r\n",
        ip
    );
    timeout(dur, stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::with_capacity(4096);
    // Read up to 8 KiB or a timeout — enough to see <title>, Server, and a few model strings.
    let mut total = 0usize;
    let mut tmp = [0u8; 2048];
    while total < 8192 {
        match timeout(dur, stream.read(&mut tmp)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                total += n;
            }
            Ok(Err(_)) => break,
        }
    }
    if buf.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Probe the host over HTTP on the first HTTP-ish port we can reach.
/// Only called when the scanner has at least one HTTP port open.
pub async fn probe(ip: IpAddr, open_ports: &[u16], dur: Duration) -> Option<VendorHint> {
    for p in HTTP_PORTS {
        if !open_ports.contains(p) {
            continue;
        }
        if let Some(body) = fetch_once(ip, *p, dur).await {
            let hint = parse_response(&body);
            if hint.is_useful() {
                return Some(hint);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_title() {
        let body = "HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n<html><title>Hikvision Web Service</title></html>";
        let h = parse_response(body);
        assert_eq!(h.title.as_deref(), Some("Hikvision Web Service"));
        assert_eq!(h.vendor.as_deref(), Some("Hikvision"));
    }

    #[test]
    fn extracts_server_header() {
        let body = "HTTP/1.1 200 OK\r\nServer: HP-ChaiSOE/1.0\r\n\r\n<html></html>";
        let h = parse_response(body);
        assert_eq!(h.server.as_deref(), Some("HP-ChaiSOE/1.0"));
        assert_eq!(h.vendor.as_deref(), Some("HP"));
    }

    #[test]
    fn extracts_mikrotik_version() {
        let body = "HTTP/1.1 200 OK\r\n\r\n<body>RouterOS v7.11.2 — RB5009UG+S+IN</body>";
        let h = parse_response(body);
        assert_eq!(h.vendor.as_deref(), Some("MikroTik"));
        assert_eq!(h.firmware.as_deref(), Some("7.11.2"));
        assert_eq!(h.model.as_deref(), Some("RB5009UG"));
    }

    #[test]
    fn no_match_returns_empty_useful() {
        let body = "HTTP/1.0 404 Not Found\r\n\r\n";
        let h = parse_response(body);
        // No title, no server, no vendor — nothing useful.
        assert!(!h.is_useful());
    }
}
