//! Webhook notifications for scan summaries.
//!
//! Posts a one-shot summary to a webhook URL after the scan completes.
//! Schemes auto-detected from the URL prefix:
//!
//!   ntfy://topic            → POST to https://ntfy.sh/<topic>
//!   ntfy://host/topic       → POST to https://<host>/<topic>
//!   slack://hook-url        → POST {"text": "..."} to Slack
//!   discord://hook-url      → POST {"content": "..."} to Discord
//!   teams://hook-url        → POST MessageCard JSON to Teams
//!   jira://user:tok@host/PROJ → POST issue create to Jira REST v2
//!   any https://...         → generic POST with JSON body
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

    if let Some(rest) = spec.strip_prefix("discord://") {
        // Discord webhook expects {"content": "..."} (also supports
        // "embeds": [...] but a plain message is enough for a scan
        // summary). Discord enforces 2000-char limit on content.
        let url = if rest.starts_with("https://") || rest.starts_with("http://") {
            rest.to_string()
        } else {
            format!("https://{}", rest)
        };
        let mut text = summary.to_text();
        if text.len() > 1900 {
            text.truncate(1900);
            text.push_str("\n…");
        }
        let resp = client
            .post(&url)
            .json(&json!({ "content": text, "username": "RustyMap" }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Discord webhook returned {}", resp.status()));
        }
        return Ok(());
    }

    if let Some(rest) = spec.strip_prefix("teams://") {
        // Microsoft Teams "Office 365 connector" expects a
        // MessageCard JSON. The classic schema is the most widely
        // supported across Teams channels and Power Automate hooks.
        let url = if rest.starts_with("https://") || rest.starts_with("http://") {
            rest.to_string()
        } else {
            format!("https://{}", rest)
        };
        let theme_color = if summary.critical_findings.is_empty() {
            "00B050"
        } else {
            "C0392B"
        };
        let resp = client
            .post(&url)
            .json(&json!({
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": "RustyMap scan summary",
                "themeColor": theme_color,
                "title": "RustyMap scan summary",
                "text": summary.to_text(),
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Teams webhook returned {}", resp.status()));
        }
        return Ok(());
    }

    if let Some(rest) = spec.strip_prefix("jira://") {
        // jira://user:token@host/PROJECTKEY[?type=Issue|Bug|...]
        // POSTs to https://host/rest/api/2/issue with HTTP Basic auth.
        let parsed = parse_jira_spec(rest)
            .ok_or_else(|| anyhow!("jira:// spec must be user:token@host/PROJECTKEY"))?;
        let url = format!("https://{}/rest/api/2/issue", parsed.host);
        let resp = client
            .post(&url)
            .basic_auth(&parsed.user, Some(&parsed.token))
            .json(&json!({
                "fields": {
                    "project": { "key": parsed.project_key },
                    "summary": format!(
                        "RustyMap scan: {}/{} up · {} open · {} critical",
                        summary.hosts_up, summary.hosts_total,
                        summary.open_ports, summary.critical_findings.len()
                    ),
                    "description": summary.to_text(),
                    "issuetype": { "name": parsed.issue_type },
                }
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Jira returned {}", resp.status()));
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
        "--notify expects ntfy:// | slack:// | discord:// | teams:// | jira:// | https:// scheme; got '{}'",
        spec
    ))
}

#[derive(Debug, PartialEq, Eq)]
struct JiraSpec {
    user: String,
    token: String,
    host: String,
    project_key: String,
    issue_type: String,
}

fn parse_jira_spec(s: &str) -> Option<JiraSpec> {
    // user:token@host/PROJECT[?type=Bug]
    let (creds, rest) = s.split_once('@')?;
    let (user, token) = creds.split_once(':')?;
    let (host_path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (host, project) = host_path.split_once('/')?;
    if user.is_empty() || token.is_empty() || host.is_empty() || project.is_empty() {
        return None;
    }
    let issue_type = query
        .split('&')
        .filter_map(|kv| kv.strip_prefix("type="))
        .next()
        .unwrap_or("Task")
        .to_string();
    Some(JiraSpec {
        user: user.to_string(),
        token: token.to_string(),
        host: host.to_string(),
        project_key: project.to_string(),
        issue_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jira_spec_parses_basic() {
        let s = parse_jira_spec("alice:tok123@jira.example.com/SEC").unwrap();
        assert_eq!(s.user, "alice");
        assert_eq!(s.token, "tok123");
        assert_eq!(s.host, "jira.example.com");
        assert_eq!(s.project_key, "SEC");
        assert_eq!(s.issue_type, "Task");
    }

    #[test]
    fn jira_spec_parses_with_issue_type() {
        let s = parse_jira_spec("u:t@h.test/P?type=Bug").unwrap();
        assert_eq!(s.issue_type, "Bug");
    }

    #[test]
    fn jira_spec_rejects_missing_pieces() {
        assert!(parse_jira_spec("u:t@host/").is_none()); // missing project
        assert!(parse_jira_spec(":t@host/P").is_none()); // missing user
        assert!(parse_jira_spec("u:@host/P").is_none()); // missing token
        assert!(parse_jira_spec("u@host/P").is_none()); // missing colon
    }
}
