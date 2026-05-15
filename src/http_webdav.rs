//! WebDAV exposure & vulnerability check.
//!
//! Sends a `PROPFIND` against the supplied URL. A response of
//! **207 Multi-Status** plus XML body containing `<D:multistatus>` /
//! `<a:multistatus>` confirms WebDAV is enabled. We then read the
//! `Allow` and `DAV` response headers to figure out which WebDAV
//! verbs are exposed.
//!
//! Beyond detection, we flag two known-bad patterns:
//!
//!   - **IIS 6.0 PROPFIND auth-bypass / RCE (CVE-2017-7269)**:
//!     IIS 6.0 `httpext.dll` mishandled overlong PROPFIND request
//!     headers. Surface a warning whenever the `Server:` header
//!     advertises IIS 6.0 AND WebDAV responds.
//!   - **Anonymous-writable WebDAV**: when both PROPFIND succeeds
//!     unauthenticated AND the Allow header lists PUT, MOVE or COPY,
//!     the share is a remote-write target.
//!
//! Read-only. PUT etc. are not actually issued — we trust the Allow
//! header for that bit.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDavFinding {
    pub url: String,
    pub enabled: bool,
    pub dav_compliance: Option<String>,
    pub allow_header: Option<String>,
    pub server_header: Option<String>,
    pub findings: Vec<String>,
}

pub async fn probe(url: &str, dur: Duration) -> Result<WebDavFinding> {
    let client = reqwest::Client::builder()
        .timeout(dur)
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/webdav")
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut f = WebDavFinding {
        url: url.to_string(),
        enabled: false,
        dav_compliance: None,
        allow_header: None,
        server_header: None,
        findings: Vec::new(),
    };

    let req = client
        .request(reqwest::Method::from_bytes(b"PROPFIND")?, url)
        .header("Depth", "0")
        .header("Content-Type", "application/xml")
        .body(
            r#"<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:"><D:prop>
<D:displayname/><D:resourcetype/>
</D:prop></D:propfind>"#,
        )
        .send();
    let resp = match req.await {
        Ok(r) => r,
        Err(_) => return Ok(f),
    };
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    f.server_header = headers.get("server").and_then(|v| v.to_str().ok().map(String::from));
    f.dav_compliance = headers.get("dav").and_then(|v| v.to_str().ok().map(String::from));
    f.allow_header = headers.get("allow").and_then(|v| v.to_str().ok().map(String::from));

    let xml_marker = body.contains("multistatus") || body.contains("D:response");
    f.enabled = status == 207 || (f.dav_compliance.is_some() && xml_marker);

    classify(&mut f);
    Ok(f)
}

fn classify(f: &mut WebDavFinding) {
    if !f.enabled {
        return;
    }
    f.findings.push("WebDAV enabled (PROPFIND returned multi-status / DAV header present)".into());

    if let Some(server) = &f.server_header {
        let s = server.to_lowercase();
        if s.contains("microsoft-iis/6.0") {
            f.findings.push(
                "Server: Microsoft-IIS/6.0 + WebDAV — vulnerable to CVE-2017-7269 \
                 (PROPFIND overlong header auth bypass / RCE)"
                    .into(),
            );
        }
        if s.contains("iis/5") || s.contains("iis/6") {
            f.findings.push(
                "Legacy IIS WebDAV — historically vulnerable to multiple authentication \
                 bypasses; recommend disabling the WebDAV module entirely"
                    .into(),
            );
        }
    }

    if let Some(allow) = &f.allow_header {
        let upper = allow.to_uppercase();
        let writable: Vec<&str> = ["PUT", "MOVE", "COPY", "DELETE", "MKCOL", "PROPPATCH"]
            .iter()
            .copied()
            .filter(|m| upper.contains(m))
            .collect();
        if !writable.is_empty() {
            f.findings.push(format!(
                "Write methods advertised in Allow: {} — anonymous write potentially possible",
                writable.join(", ")
            ));
        }
    }
}

pub fn print_finding(f: &WebDavFinding) {
    use colored::*;
    println!();
    println!("{}", format!("WebDAV probe on {}", f.url).bold());
    if !f.enabled {
        println!("  {}", "WebDAV not enabled (PROPFIND not honoured)".green());
        return;
    }
    if let Some(s) = &f.server_header {
        println!("  server     : {}", s);
    }
    if let Some(d) = &f.dav_compliance {
        println!("  DAV class  : {}", d);
    }
    if let Some(a) = &f.allow_header {
        println!("  Allow      : {}", a);
    }
    for finding in &f.findings {
        println!("  {} {}", "·".yellow(), finding.yellow());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_flags_iis6_webdav() {
        let mut f = WebDavFinding {
            url: "http://x.test/".into(),
            enabled: true,
            dav_compliance: Some("1,2".into()),
            allow_header: Some("OPTIONS, GET, HEAD, PUT".into()),
            server_header: Some("Microsoft-IIS/6.0".into()),
            findings: Vec::new(),
        };
        classify(&mut f);
        assert!(f.findings.iter().any(|x| x.contains("CVE-2017-7269")));
    }

    #[test]
    fn classify_flags_anonymous_write_path() {
        let mut f = WebDavFinding {
            url: "http://x.test/".into(),
            enabled: true,
            dav_compliance: Some("1".into()),
            allow_header: Some("OPTIONS, PROPFIND, PUT, DELETE, MOVE".into()),
            server_header: Some("nginx/1.20.0".into()),
            findings: Vec::new(),
        };
        classify(&mut f);
        assert!(f.findings.iter().any(|x| x.contains("PUT")));
        assert!(f.findings.iter().any(|x| x.contains("MOVE")));
    }

    #[test]
    fn classify_no_findings_when_disabled() {
        let mut f = WebDavFinding {
            url: "http://x.test/".into(),
            enabled: false,
            dav_compliance: None,
            allow_header: None,
            server_header: None,
            findings: Vec::new(),
        };
        classify(&mut f);
        assert!(f.findings.is_empty());
    }

    #[test]
    fn classify_clean_modern_webdav_only_enabled_note() {
        let mut f = WebDavFinding {
            url: "http://x.test/".into(),
            enabled: true,
            dav_compliance: Some("1".into()),
            allow_header: Some("OPTIONS, PROPFIND".into()),
            server_header: Some("nginx".into()),
            findings: Vec::new(),
        };
        classify(&mut f);
        assert_eq!(f.findings.len(), 1);
        assert!(f.findings[0].contains("WebDAV enabled"));
    }
}
