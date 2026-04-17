use crate::ports::service_name;
use crate::scanner::HostResult;
use anyhow::{Context, Result};
use serde::Serialize;
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
struct HostView {
    ip: String,
    hostname: Option<String>,
    up: bool,
    latency_secs: f64,
    open_count: usize,
    ports: Vec<PortView>,
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

fn to_view(hosts: &[HostResult]) -> Vec<HostView> {
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
            HostView {
                ip: h.target.ip.to_string(),
                hostname: h.target.hostname.clone(),
                up: h.up,
                latency_secs: h.elapsed.as_secs_f64(),
                open_count,
                ports,
            }
        })
        .collect()
}

fn build_ctx(
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
) -> ReportCtx {
    let views = to_view(hosts);
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
) -> Result<()> {
    let ctx = build_ctx(hosts, scan_type, started_at, elapsed_secs);
    let out = render(DEFAULT_HTML, &ctx, "report.html")?;
    fs::write(path, out)?;
    Ok(())
}

pub fn write_markdown(
    path: &str,
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
) -> Result<()> {
    let ctx = build_ctx(hosts, scan_type, started_at, elapsed_secs);
    let out = render(DEFAULT_MD, &ctx, "report.md")?;
    fs::write(path, out)?;
    Ok(())
}

pub fn write_custom(
    template_path: &str,
    out_path: &str,
    hosts: &[HostResult],
    scan_type: &str,
    started_at: chrono::DateTime<chrono::Local>,
    elapsed_secs: f64,
) -> Result<()> {
    let tpl = fs::read_to_string(template_path)
        .with_context(|| format!("failed to read template {}", template_path))?;
    let ctx = build_ctx(hosts, scan_type, started_at, elapsed_secs);
    let out = render(&tpl, &ctx, "custom")?;
    fs::write(out_path, out)?;
    Ok(())
}
