use crate::db::PortDiff;
use crate::ports::service_name;
use crate::scanner::HostResult;
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use tera::{Context as TeraCtx, Tera};

const DEFAULT_HTML: &str = include_str!("../templates/report.html.tera");
const DEFAULT_MD: &str = include_str!("../templates/report.md.tera");

#[derive(Serialize)]
struct PortView {
    port: u16,
    protocol: &'static str,
    state: &'static str,
    service: &'static str,
}

#[derive(Serialize)]
struct DiffView {
    new_open: Vec<u16>,
    closed_now: Vec<u16>,
    state_changes: Vec<(u16, String, String)>,
}

#[derive(Serialize)]
struct HostView {
    ip: String,
    hostname: Option<String>,
    up: bool,
    latency_secs: f64,
    open_count: usize,
    device_class: Option<&'static str>,
    vendor: Option<String>,
    model: Option<String>,
    firmware: Option<String>,
    device_confidence: Option<u8>,
    ports: Vec<PortView>,
    diff: Option<DiffView>,
}

#[derive(Serialize)]
struct ReportCtx {
    tool: &'static str,
    version: &'static str,
    scan_type: String,
    started_at: String,
    elapsed_secs: f64,
    hosts_total: usize,
    hosts_up: usize,
    open_ports_total: usize,
    hosts: Vec<HostView>,
}

fn to_view(hosts: &[HostResult], diffs: &HashMap<String, PortDiff>) -> Vec<HostView> {
    hosts
        .iter()
        .map(|h| {
            let ports: Vec<PortView> = h
                .ports
                .iter()
                .map(|p| PortView {
                    port: p.port,
                    protocol: "tcp",
                    state: p.state.as_str(),
                    service: service_name(p.port).unwrap_or("unknown"),
                })
                .collect();
            let open_count = ports.iter().filter(|p| p.state == "open").count();
            let ip_s = h.target.ip.to_string();
            let diff = diffs.get(&ip_s).map(|d| DiffView {
                new_open: d.new_open.clone(),
                closed_now: d.closed_now.clone(),
                state_changes: d.state_changes.clone(),
            });
            HostView {
                ip: ip_s,
                hostname: h.target.hostname.clone(),
                up: h.up,
                latency_secs: h.elapsed.as_secs_f64(),
                open_count,
                device_class: h.device.as_ref().map(|d| d.class.as_str()),
                vendor: h.device.as_ref().and_then(|d| d.vendor.clone()),
                model: h.device.as_ref().and_then(|d| d.model.clone()),
                firmware: h.device.as_ref().and_then(|d| d.firmware.clone()),
                device_confidence: h.device.as_ref().map(|d| d.confidence),
                ports,
                diff,
            }
        })
        .collect()
}

fn build_ctx(
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
    diffs: &HashMap<String, PortDiff>,
) -> ReportCtx {
    let views = to_view(hosts, diffs);
    let hosts_up = views.iter().filter(|h| h.up).count();
    let open_ports_total = views.iter().map(|h| h.open_count).sum();
    ReportCtx {
        tool: "RustyMap",
        version: env!("CARGO_PKG_VERSION"),
        scan_type: scan_type.to_string(),
        started_at: started_at.to_rfc3339(),
        elapsed_secs,
        hosts_total: views.len(),
        hosts_up,
        open_ports_total,
        hosts: views,
    }
}

fn render(template_str: &str, ctx: &ReportCtx, name: &str) -> Result<String> {
    let mut tera = Tera::default();
    tera.add_raw_template(name, template_str)
        .context("failed to parse template")?;
    let mut tctx = TeraCtx::new();
    tctx.insert("tool", &ctx.tool);
    tctx.insert("version", &ctx.version);
    tctx.insert("scan_type", &ctx.scan_type);
    tctx.insert("started_at", &ctx.started_at);
    tctx.insert("elapsed_secs", &ctx.elapsed_secs);
    tctx.insert("hosts_total", &ctx.hosts_total);
    tctx.insert("hosts_up", &ctx.hosts_up);
    tctx.insert("open_ports_total", &ctx.open_ports_total);
    tctx.insert("hosts", &ctx.hosts);
    tera.render(name, &tctx).context("failed to render template")
}

pub fn write_html(
    path: &str,
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
    diffs: &HashMap<String, PortDiff>,
) -> Result<()> {
    let ctx = build_ctx(hosts, scan_type, started_at, elapsed_secs, diffs);
    let out = render(DEFAULT_HTML, &ctx, "report.html")?;
    crate::file_out::write(path, out.as_bytes())?;
    Ok(())
}

pub fn write_markdown(
    path: &str,
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
    diffs: &HashMap<String, PortDiff>,
) -> Result<()> {
    let ctx = build_ctx(hosts, scan_type, started_at, elapsed_secs, diffs);
    let out = render(DEFAULT_MD, &ctx, "report.md")?;
    crate::file_out::write(path, out.as_bytes())?;
    Ok(())
}

pub fn write_custom(
    template_path: &str,
    out_path: &str,
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
    diffs: &HashMap<String, PortDiff>,
) -> Result<()> {
    let tpl = fs::read_to_string(template_path)
        .with_context(|| format!("failed to read template {}", template_path))?;
    let ctx = build_ctx(hosts, scan_type, started_at, elapsed_secs, diffs);
    let out = render(&tpl, &ctx, "custom")?;
    crate::file_out::write(out_path, out.as_bytes())?;
    Ok(())
}
