//! Container & orchestrator surface discovery.
//!
//! Probes the well-known endpoints of the container ecosystem against
//! a single host. Matches against documented response shapes —
//! presence of a specific JSON field or HTTP header proves the
//! service identity even when the responder hides its banner.
//!
//! Probes (HTTP/HTTPS GETs, no auth, no writes):
//!
//!   - **Docker remote API** (TCP 2375 plain, 2376 TLS):
//!     `GET /info`. Confirms via `Containers`/`Images` JSON fields.
//!   - **Kubernetes API server** (TCP 6443/8443):
//!     `GET /version`. Confirms via `gitVersion` field.
//!   - **Kubelet read-only port** (TCP 10255):
//!     `GET /pods`. Confirms via `apiVersion`/`kind` Pod fields.
//!   - **Kubelet authenticated port** (TCP 10250):
//!     `GET /metrics` and `GET /healthz`. 401 means present-but-locked,
//!     200 means anonymous metrics exposed.
//!   - **etcd v2** (TCP 2379/2380):
//!     `GET /version`. Confirms via `etcdserver`/`etcdcluster` fields.
//!   - **Consul** (TCP 8500):
//!     `GET /v1/agent/self`. Confirms via `Config`/`Stats` fields.
//!
//! Each finding includes a tier — UNAUTHED, AUTHED, or LOCKED — to
//! help the user prioritise. UNAUTHED on an internet-routable host
//! is critical (full container/cluster takeover surface).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExposureTier {
    Unauthed,
    Authed,
    Locked,
}

impl ExposureTier {
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            ExposureTier::Unauthed => "UNAUTHED",
            ExposureTier::Authed => "AUTHED",
            ExposureTier::Locked => "LOCKED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerFinding {
    pub service: String,
    pub host: String,
    pub port: u16,
    pub url: String,
    pub tier: ExposureTier,
    pub evidence: String,
}

pub async fn scan(host: &str, dur: Duration) -> Result<Vec<ContainerFinding>> {
    let client = reqwest::Client::builder()
        .timeout(dur)
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/container-scan")
        .build()?;

    let mut out = Vec::new();
    if let Some(f) = probe_docker(&client, host, 2375, false).await {
        out.push(f);
    }
    if let Some(f) = probe_docker(&client, host, 2376, true).await {
        out.push(f);
    }
    for (port, scheme) in [(6443u16, "https"), (8443u16, "https")] {
        if let Some(f) = probe_kube_api(&client, host, port, scheme).await {
            out.push(f);
        }
    }
    if let Some(f) = probe_kubelet_ro(&client, host).await {
        out.push(f);
    }
    if let Some(f) = probe_kubelet_authed(&client, host).await {
        out.push(f);
    }
    for port in [2379u16, 2380] {
        if let Some(f) = probe_etcd(&client, host, port).await {
            out.push(f);
        }
    }
    if let Some(f) = probe_consul(&client, host).await {
        out.push(f);
    }
    Ok(out)
}

async fn probe_docker(client: &reqwest::Client, host: &str, port: u16, tls: bool) -> Option<ContainerFinding> {
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{}://{}:{}/info", scheme, host, port);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if (status == 200 || status == 401) && (body.contains("\"Containers\"") || body.contains("\"DockerRootDir\"") || status == 401) {
        let tier = if status == 200 {
            ExposureTier::Unauthed
        } else {
            ExposureTier::Locked
        };
        let snippet = body.chars().take(120).collect::<String>().replace('\n', " ");
        return Some(ContainerFinding {
            service: if tls { "Docker (TLS)".into() } else { "Docker (no TLS)".into() },
            host: host.to_string(),
            port,
            url,
            tier,
            evidence: snippet,
        });
    }
    None
}

async fn probe_kube_api(client: &reqwest::Client, host: &str, port: u16, scheme: &str) -> Option<ContainerFinding> {
    let url = format!("{}://{}:{}/version", scheme, host, port);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if (status == 200 || status == 401 || status == 403) && (body.contains("\"gitVersion\"") || status == 401 || status == 403) {
        let tier = match status {
            200 => ExposureTier::Unauthed,
            _ => ExposureTier::Locked,
        };
        let snippet = body.chars().take(120).collect::<String>().replace('\n', " ");
        return Some(ContainerFinding {
            service: "Kubernetes API".into(),
            host: host.to_string(),
            port,
            url,
            tier,
            evidence: snippet,
        });
    }
    None
}

async fn probe_kubelet_ro(client: &reqwest::Client, host: &str) -> Option<ContainerFinding> {
    let url = format!("http://{}:10255/pods", host);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if status == 200 && (body.contains("\"kind\":\"PodList\"") || body.contains("apiVersion")) {
        let snippet = body.chars().take(120).collect::<String>().replace('\n', " ");
        return Some(ContainerFinding {
            service: "Kubelet (read-only port)".into(),
            host: host.to_string(),
            port: 10255,
            url,
            tier: ExposureTier::Unauthed,
            evidence: snippet,
        });
    }
    None
}

async fn probe_kubelet_authed(client: &reqwest::Client, host: &str) -> Option<ContainerFinding> {
    let url = format!("https://{}:10250/metrics", host);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let tier = match status {
        200 if body.contains("kubelet_") => ExposureTier::Unauthed,
        401 | 403 => ExposureTier::Locked,
        _ => return None,
    };
    let snippet = body.chars().take(120).collect::<String>().replace('\n', " ");
    Some(ContainerFinding {
        service: "Kubelet (authenticated port)".into(),
        host: host.to_string(),
        port: 10250,
        url,
        tier,
        evidence: snippet,
    })
}

async fn probe_etcd(client: &reqwest::Client, host: &str, port: u16) -> Option<ContainerFinding> {
    let url = format!("https://{}:{}/version", host, port);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if status == 200 && body.contains("etcdserver") {
        let snippet = body.chars().take(120).collect::<String>().replace('\n', " ");
        return Some(ContainerFinding {
            service: "etcd".into(),
            host: host.to_string(),
            port,
            url,
            tier: ExposureTier::Unauthed,
            evidence: snippet,
        });
    }
    None
}

async fn probe_consul(client: &reqwest::Client, host: &str) -> Option<ContainerFinding> {
    let url = format!("http://{}:8500/v1/agent/self", host);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if (status == 200 || status == 401 || status == 403)
        && (body.contains("\"Config\"") || body.contains("\"DataCenter\"") || status >= 400)
    {
        let tier = if status == 200 { ExposureTier::Unauthed } else { ExposureTier::Locked };
        let snippet = body.chars().take(120).collect::<String>().replace('\n', " ");
        return Some(ContainerFinding {
            service: "Consul".into(),
            host: host.to_string(),
            port: 8500,
            url,
            tier,
            evidence: snippet,
        });
    }
    None
}

pub fn print_findings(host: &str, findings: &[ContainerFinding]) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!("Container/orchestrator scan for {} — {} responder(s)", host, findings.len()).bold()
    );
    if findings.is_empty() {
        println!("  {}", "no container/orchestrator surface detected".dimmed());
        return;
    }
    for f in findings {
        let tier_label = match f.tier {
            ExposureTier::Unauthed => "UNAUTHED".red().bold().to_string(),
            ExposureTier::Authed => "AUTHED".yellow().to_string(),
            ExposureTier::Locked => "LOCKED".green().to_string(),
        };
        println!("  {:<10} {} :{} → {}", tier_label, f.service, f.port, f.url);
        if !f.evidence.is_empty() {
            println!("    evidence: {}", f.evidence.dimmed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_labels_have_distinct_strings() {
        assert_ne!(ExposureTier::Unauthed.label(), ExposureTier::Authed.label());
        assert_ne!(ExposureTier::Unauthed.label(), ExposureTier::Locked.label());
        assert_eq!(ExposureTier::Unauthed.label(), "UNAUTHED");
    }

    #[test]
    fn finding_serializes_round_trip() {
        let f = ContainerFinding {
            service: "Docker (no TLS)".into(),
            host: "10.0.0.1".into(),
            port: 2375,
            url: "http://10.0.0.1:2375/info".into(),
            tier: ExposureTier::Unauthed,
            evidence: r#"{"Containers":3}"#.into(),
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: ContainerFinding = serde_json::from_str(&s).unwrap();
        assert_eq!(back.tier, ExposureTier::Unauthed);
        assert_eq!(back.port, 2375);
    }
}
