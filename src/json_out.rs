use crate::portdesc;
use crate::ports::service_name;
use crate::scanner::{HostResult, PortState};
use anyhow::Result;
use serde::Serialize;
#[allow(unused_imports)]
use std::fs::File;
use std::io::Write;

#[derive(Serialize)]
struct JsonPort {
    port: u16,
    protocol: &'static str,
    state: &'static str,
    service: &'static str,
    /// Plain-language description of the service (rich output parity).
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'static str>,
    /// Exposure-risk tier for an open port: "high" | "warn" | "info".
    #[serde(skip_serializing_if = "Option::is_none")]
    risk: Option<&'static str>,
    /// Application CPE 2.3 string, when `-sV` detected a product (feeds
    /// downstream CVE correlation). Absent for ports without a product.
    #[serde(skip_serializing_if = "Option::is_none")]
    cpe: Option<String>,
    // ── v0.117.0: the -sV detail the JSON used to drop entirely ──
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<String>,
    /// First banner line (trimmed/truncated), when captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    banner: Option<String>,
    /// One-line TLS summary, when the port spoke TLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<String>,
    /// Per-port probe RTT in milliseconds, when recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    rtt_ms: Option<f64>,
}

#[derive(Serialize)]
struct JsonHost {
    ip: String,
    hostname: Option<String>,
    up: bool,
    latency_secs: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_class: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    firmware: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_confidence: Option<u8>,
    // ── v0.117.0: OS guess, MAC and hop distance the JSON used to drop ──
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_confidence: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_ttl: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_cpe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    distance_hops: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac_vendor: Option<String>,
    ports: Vec<JsonPort>,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    tool: &'a str,
    version: &'a str,
    schema: u32,
    started_at: String,
    elapsed_secs: f64,
    scan_type: &'a str,
    hosts_total: usize,
    hosts_up: usize,
    hosts: Vec<JsonHost>,
}

/// Map one scan result to its JSON shape (shared by the full report and the
/// JSON-lines writer).
fn host_to_json(h: &HostResult) -> JsonHost {
    JsonHost {
        ip: h.target.ip.to_string(),
        hostname: h.target.hostname.clone(),
        up: h.up,
        latency_secs: h.elapsed.as_secs_f64(),
        device_class: h.device.as_ref().map(|d| d.class.as_str()),
        vendor: h.device.as_ref().and_then(|d| d.vendor.clone()),
        model: h.device.as_ref().and_then(|d| d.model.clone()),
        firmware: h.device.as_ref().and_then(|d| d.firmware.clone()),
        device_confidence: h.device.as_ref().map(|d| d.confidence),
        os: h.os.as_ref().map(|o| o.family.clone()),
        os_confidence: h.os.as_ref().map(|o| o.confidence),
        os_ttl: h.os.as_ref().and_then(|o| o.ttl),
        os_cpe: h.os.as_ref().map(|o| crate::cpe::from_family(&o.family, None).raw),
        distance_hops: h.os.as_ref().and_then(|o| o.ttl).map(crate::output::network_distance),
        mac: h.mac.as_ref().map(crate::output::fmt_mac),
        mac_vendor: h
            .mac
            .as_ref()
            .and_then(|m| crate::device_fp::vendor_from_mac(m).map(|v| v.to_string())),
        ports: h
            .ports
            .iter()
            .map(|p| {
                // Enrich open ports with the same description + risk the rich
                // console shows, so the JSON carries the verdict too.
                let desc = if p.state == PortState::Open {
                    portdesc::describe(p.port)
                } else {
                    None
                };
                JsonPort {
                    port: p.port,
                    protocol: "tcp",
                    state: p.state.as_str(),
                    service: service_name(p.port).unwrap_or("unknown"),
                    note: desc.map(|d| d.text),
                    risk: desc.map(|d| match d.risk {
                        portdesc::Risk::High => "high",
                        portdesc::Risk::Warn => "warn",
                        portdesc::Risk::Info => "info",
                    }),
                    cpe: p.service.as_ref().and_then(|s| {
                        s.product
                            .as_deref()
                            .map(|prod| crate::cpe::from_service(prod, s.version.as_deref()).raw)
                    }),
                    product: p.service.as_ref().and_then(|s| s.product.clone()),
                    version: p.service.as_ref().and_then(|s| s.version.clone()),
                    extra: p.service.as_ref().and_then(|s| s.extra.clone()),
                    banner: p.service.as_ref().and_then(|s| {
                        s.banner.as_ref().and_then(|b| {
                            let line: String = b.lines().next().unwrap_or("").trim().chars().take(200).collect();
                            (!line.is_empty()).then_some(line)
                        })
                    }),
                    tls: p.service.as_ref().and_then(|s| s.tls.as_ref().map(|t| t.summary())),
                    rtt_ms: {
                        let ms = p.rtt.as_secs_f64() * 1000.0;
                        (ms > 0.0).then_some((ms * 100.0).round() / 100.0)
                    },
                }
            })
            .collect(),
    }
}

/// JSON-lines (ndjson): one compact JSON object per host, newline-separated —
/// stream-friendly for log pipelines / jq (Fase 36). Fase 36 closure.
pub fn to_jsonl_string(hosts: &[HostResult]) -> Result<String> {
    let mut out = String::new();
    for h in hosts {
        out.push_str(&serde_json::to_string(&host_to_json(h))?);
        out.push('\n');
    }
    Ok(out)
}

pub fn to_json_string(
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
) -> Result<String> {
    let up = hosts.iter().filter(|h| h.up).count();
    let mapped: Vec<JsonHost> = hosts.iter().map(host_to_json).collect();

    let report = JsonReport {
        tool: "rustymap",
        version: env!("CARGO_PKG_VERSION"),
        schema: 1,
        started_at: started_at.to_rfc3339(),
        elapsed_secs,
        scan_type,
        hosts_total: hosts.len(),
        hosts_up: up,
        hosts: mapped,
    };

    Ok(serde_json::to_string_pretty(&report)?)
}

pub fn write_json(path: &str, json: &str) -> Result<()> {
    let mut f = crate::file_out::open_writer(path)?;
    f.write_all(json.as_bytes())?;
    f.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::PortState;
    use crate::scanner::PortResult;
    use crate::target::Target;

    fn host_with_ports(ip: [u8; 4], ports: Vec<u16>) -> HostResult {
        HostResult {
            target: Target { ip: std::net::IpAddr::V4(ip.into()), hostname: None, zone: None },
            up: true,
            ports: ports
                .into_iter()
                .map(|p| PortResult {
                    port: p,
                    state: PortState::Open,
                    rtt: std::time::Duration::from_millis(1),
                    service: None,
                })
                .collect(),
            elapsed: std::time::Duration::from_millis(1),
            os: None,
            device: None,
            mac: None,
        }
    }

    #[test]
    fn json_output_serializes_open_ports() {
        // Bug-10 regression: --oJ used to drop the port list. This test
        // ensures every Open port in HostResult is emitted in the JSON.
        let h = host_with_ports([192, 168, 1, 1], vec![22, 80, 443, 3306]);
        let json = to_json_string(
            std::slice::from_ref(&h),
            "Connect",
            chrono::Local::now(),
            0.1,
        )
        .unwrap();
        assert!(json.contains("\"ports\": ["), "missing ports array");
        for p in [22, 80, 443, 3306] {
            assert!(
                json.contains(&format!("\"port\": {}", p)),
                "port {} missing from JSON: {}",
                p, json
            );
        }
    }

    #[test]
    fn json_carries_sv_os_mac_distance_detail() {
        use crate::os_fp::OsGuess;
        use crate::service_probe::ServiceInfo;
        let mut h = host_with_ports([10, 0, 0, 5], vec![80]);
        h.ports[0].service = Some(ServiceInfo {
            product: Some("nginx".into()),
            version: Some("1.25.3".into()),
            extra: Some("Ubuntu".into()),
            banner: Some("Server: nginx 1.25.3\r\nextra".into()),
            ..Default::default()
        });
        h.os = Some(OsGuess {
            family: "Linux 5.x".into(),
            confidence: 92,
            ttl: Some(64),
            hints: vec![],
        });
        h.mac = Some([0x00, 0x0c, 0x29, 0x11, 0x22, 0x33]);
        let json = to_jsonl_string(std::slice::from_ref(&h)).unwrap();
        // -sV detail the JSON used to drop entirely:
        assert!(json.contains("\"product\":\"nginx\""), "product missing: {json}");
        assert!(json.contains("\"version\":\"1.25.3\""), "version missing");
        assert!(json.contains("\"extra\":\"Ubuntu\""), "extra missing");
        assert!(json.contains("\"banner\":\"Server: nginx 1.25.3\""), "banner first-line missing");
        assert!(json.contains("\"cpe\":\"cpe:2.3:a:nginx:nginx:1.25.3"), "app cpe missing");
        // host OS / MAC / hop distance:
        assert!(json.contains("\"os\":\"Linux 5.x\""), "os missing");
        assert!(json.contains("\"os_confidence\":92"), "os_confidence missing");
        assert!(json.contains("\"os_cpe\":\"cpe:2.3:o:linux:linux_kernel"), "os_cpe missing");
        assert!(json.contains("\"distance_hops\":0"), "distance missing"); // ttl 64 → 0 hops
        assert!(json.contains("\"mac\":\"00:0C:29:11:22:33\""), "mac missing");
    }

    #[test]
    fn jsonl_one_object_per_host() {
        let hosts = vec![
            host_with_ports([10, 0, 0, 1], vec![80, 443]),
            host_with_ports([10, 0, 0, 2], vec![22]),
        ];
        let jsonl = to_jsonl_string(&hosts).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2, "one line per host");
        for line in &lines {
            // Each line is a standalone valid JSON object with an ip.
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
            assert!(v["ip"].is_string());
            assert!(v["ports"].is_array());
        }
        assert!(lines[0].contains("10.0.0.1"));
        assert!(lines[1].contains("10.0.0.2"));
    }

    #[test]
    fn json_output_serializes_multi_host_ports() {
        let h1 = host_with_ports([10, 0, 0, 1], vec![80]);
        let h2 = host_with_ports([10, 0, 0, 2], vec![443, 22]);
        let json = to_json_string(&[h1, h2], "Connect", chrono::Local::now(), 0.1).unwrap();
        assert!(json.contains("\"port\": 80"));
        assert!(json.contains("\"port\": 443"));
        assert!(json.contains("\"port\": 22"));
    }
}
