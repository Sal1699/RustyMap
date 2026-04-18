use crate::ports::service_name;
use crate::scanner::HostResult;
use anyhow::Result;
use serde::Serialize;
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
    let mut f = File::create(path)?;
    f.write_all(json.as_bytes())?;
    Ok(())
}
