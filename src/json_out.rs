use crate::ports::service_name;
use crate::scanner::HostResult;
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

pub fn to_json_string(
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
) -> Result<String> {
    let up = hosts.iter().filter(|h| h.up).count();
    let mapped: Vec<JsonHost> = hosts
        .iter()
        .map(|h| JsonHost {
            ip: h.target.ip.to_string(),
            hostname: h.target.hostname.clone(),
            up: h.up,
            latency_secs: h.elapsed.as_secs_f64(),
            device_class: h.device.as_ref().map(|d| d.class.as_str()),
            vendor: h.device.as_ref().and_then(|d| d.vendor.clone()),
            model: h.device.as_ref().and_then(|d| d.model.clone()),
            firmware: h.device.as_ref().and_then(|d| d.firmware.clone()),
            device_confidence: h.device.as_ref().map(|d| d.confidence),
            ports: h
                .ports
                .iter()
                .map(|p| JsonPort {
                    port: p.port,
                    protocol: "tcp",
                    state: p.state.as_str(),
                    service: service_name(p.port).unwrap_or("unknown"),
                })
                .collect(),
        })
        .collect();

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
    let mut f = crate::file_out::open(path)?;
    f.write_all(json.as_bytes())?;
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
    fn json_output_serializes_multi_host_ports() {
        let h1 = host_with_ports([10, 0, 0, 1], vec![80]);
        let h2 = host_with_ports([10, 0, 0, 2], vec![443, 22]);
        let json = to_json_string(&[h1, h2], "Connect", chrono::Local::now(), 0.1).unwrap();
        assert!(json.contains("\"port\": 80"));
        assert!(json.contains("\"port\": 443"));
        assert!(json.contains("\"port\": 22"));
    }
}
