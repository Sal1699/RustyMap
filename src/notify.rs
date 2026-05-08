//! Webhook notifications for scan summaries.
//!
//! Posts a one-shot summary to a webhook URL after the scan completes.
//! Two flavours, auto-detected from the URL scheme:
//!
//!   ntfy://topic        → POST to https://ntfy.sh/<topic>
//!   ntfy://host/topic   → POST to https://<host>/<topic> (self-hosted)
//!   slack://hook-url    → POST to https://hooks.slack.com/<rest>
//!   any https://...     → generic POST with JSON body
//!
//! Improvement over ad-hoc notification: built into `--every` so a
//! scheduled scan can wake you up only on critical findings instead
//! of pushing every run.

use crate::scanner::HostResult;
use anyhow::{anyhow, Result};
use serde_json::json;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Summary<'a> {
    pub hosts_total: usize,
    pub hosts_up: usize,
    pub open_ports: usize,
    pub elapsed_secs: f64,
    pub critical_findings: Vec<String>,
    pub _hosts: &'a [HostResult],
}

impl<'a> Summary<'a> {
    pub fn build(hosts: &'a [HostResult], elapsed: f64, findings: &[(String, String, String)]) -> Self {
        let hosts_up = hosts.iter().filter(|h| h.up).count();
        let open_ports = hosts
            .iter()
            .map(|h| h.ports.iter().filter(|p| matches!(p.state, crate::scanner::PortState::Open)).count())
            .sum();
        // critical_findings = severity == critical/high entries
        let critical: Vec<String> = findings
            .iter()
            .filter(|(sev, _, _)| matches!(sev.as_str(), "critical" | "high"))
            .map(|(sev, host, msg)| format!("[{}] {} — {}", sev, host, msg))
            .collect();
        Self {
            hosts_total: hosts.len(),
            hosts_up,
            open_ports,
            elapsed_secs: elapsed,
            critical_findings: critical,
            _hosts: hosts,
        }
    }

    pub fn to_text(&self) -> String {
        let mut out = format!(
            "RustyMap scan: {}/{} up · {} open ports · {:.1}s",
            self.hosts_up, self.hosts_total, self.open_ports, self.elapsed_secs
        );
        if !self.critical_findings.is_empty() {
            out.push_str(&format!("\n\n{} critical/high findings:\n", self.critical_findings.len()));
            for f in self.critical_findings.iter().take(10) {
                out.push_str(&format!("• {}\n", f));
            }
            if self.critical_findings.len() > 10 {
                out.push_str(&format!("…and {} more", self.critical_findings.len() - 10));
            }
        }
        out
    }
}

pub async fn send(spec: &str, summary: &Summary<'_>) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("rustymap/notify")
        .build()?;

    if let Some(rest) = spec.strip_prefix("ntfy://") {
        // ntfy://topic  or  ntfy://host/topic
        let url = if rest.contains('/') {
            format!("https://{}", rest)
        } else {
            format!("https://ntfy.sh/{}", rest)
        };
        let priority = if summary.critical_findings.is_empty() {
            "default"
        } else {
            "high"
        };
        let resp = client
            .post(&url)
            .header("Title", "RustyMap scan summary")
            .header("Priority", priority)
            .body(summary.to_text())
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("ntfy returned {}", resp.status()));
        }
        return Ok(());
    }

    if let Some(rest) = spec.strip_prefix("slack://") {
        // Slack expects {"text": "..."} JSON
        let url = if rest.starts_with("hooks.slack.com") || rest.starts_with("https://") {
            rest.trim_start_matches("https://").to_string()
        } else {
            rest.to_string()
        };
        let full = format!("https://{}", url.trim_start_matches("https://"));
        let resp = client
            .post(&full)
            .json(&json!({ "text": summary.to_text() }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Slack webhook returned {}", resp.status()));
        }
        return Ok(());
    }

    if spec.starts_with("https://") || spec.starts_with("http://") {
        // Generic webhook — JSON body
        let resp = client
            .post(spec)
            .json(&json!({
                "summary": summary.to_text(),
                "hosts_up": summary.hosts_up,
                "hosts_total": summary.hosts_total,
                "open_ports": summary.open_ports,
                "elapsed_secs": summary.elapsed_secs,
                "critical_findings": summary.critical_findings,
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("webhook returned {}", resp.status()));
        }
        return Ok(());
    }

    Err(anyhow!(
        "--notify expects ntfy://, slack://, or https:// scheme; got '{}'",
        spec
    ))
}
