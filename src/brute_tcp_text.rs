//! Bruteforce adapters for plain-text TCP protocols: FTP,
//! HTTP-basic, HTTP-form, Telnet.
//!
//! All four share a "send → read prompt → send → read result"
//! pattern. We keep them in one file to share helpers.
//!
//! - **FTP** (RFC 959): `USER name` → 331 or 530 → `PASS pass` →
//!   230 (success) / 530 (failure).
//! - **HTTP-basic**: GET with `Authorization: Basic` header, look
//!   at status 200/302 = success, 401 = fail.
//! - **HTTP-form**: POST a form with the supplied user/pass field
//!   names + a "fail string" the operator passes in `--brute-form-spec`.
//! - **Telnet**: Read banner, look for "login:" prompt, send user,
//!   look for "Password:" prompt, send pass, then look for the
//!   absence of an error string.

use crate::brute::{BruteAdapter, BruteConfig};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ── FTP ────────────────────────────────────────────────────────────

pub struct FtpAdapter;

#[async_trait]
impl BruteAdapter for FtpAdapter {
    fn protocol(&self) -> &'static str { "ftp" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let stream = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;
        let mut s = BufReader::new(stream);
        let _ = read_line(&mut s, cfg.timeout).await; // banner

        timeout(cfg.timeout, s.write_all(format!("USER {}\r\n", user).as_bytes())).await??;
        let resp = read_line(&mut s, cfg.timeout).await?;
        if !resp.starts_with("331") && !resp.starts_with("230") {
            return Ok(false);
        }
        if resp.starts_with("230") {
            // Server accepted without password (anonymous-style).
            return Ok(true);
        }
        timeout(cfg.timeout, s.write_all(format!("PASS {}\r\n", pass).as_bytes())).await??;
        let resp = read_line(&mut s, cfg.timeout).await?;
        Ok(resp.starts_with("230"))
    }
}

// ── HTTP basic ─────────────────────────────────────────────────────

pub struct HttpBasicAdapter {
    pub url: String,
}

#[async_trait]
impl BruteAdapter for HttpBasicAdapter {
    fn protocol(&self) -> &'static str { "http-basic" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let client = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("rustymap/brute-http-basic")
            .build()?;
        let resp = client
            .get(&self.url)
            .basic_auth(user, Some(pass))
            .send()
            .await?;
        let status = resp.status().as_u16();
        // 401 = wrong creds; 200/204/302 = accepted; 403 = wrong but
        // server didn't 401 (some apps misbehave). We treat anything
        // other than 401 / 407 as success.
        Ok(matches!(status, 200 | 201 | 204 | 301 | 302 | 303 | 307 | 308))
    }
}

// ── HTTP form ──────────────────────────────────────────────────────

pub struct HttpFormAdapter {
    pub url: String,
    pub user_field: String,
    pub pass_field: String,
    pub fail_marker: String,
}

#[async_trait]
impl BruteAdapter for HttpFormAdapter {
    fn protocol(&self) -> &'static str { "http-form" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let client = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .cookie_store(true)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent("rustymap/brute-http-form")
            .build()?;
        let mut form = std::collections::HashMap::new();
        form.insert(self.user_field.clone(), user.to_string());
        form.insert(self.pass_field.clone(), pass.to_string());
        let resp = client.post(&self.url).form(&form).send().await?;
        let body = resp.text().await.unwrap_or_default();
        // Success = the configured fail-marker is *not* present in
        // the response body. Forms vary too much to be smarter without
        // per-app rules.
        Ok(!body.contains(&self.fail_marker))
    }
}

/// Parse `--brute-form-spec`. Format:
///   `url=https://.../login,user=username,pass=password,fail=Invalid`
pub fn parse_form_spec(spec: &str) -> Result<HttpFormAdapter> {
    let mut url = None;
    let mut user_field = "username".to_string();
    let mut pass_field = "password".to_string();
    let mut fail_marker = "Invalid".to_string();
    for kv in spec.split(',') {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow!("--brute-form-spec entry '{}' missing '='", kv))?;
        match k.trim() {
            "url" => url = Some(v.trim().to_string()),
            "user" => user_field = v.trim().to_string(),
            "pass" => pass_field = v.trim().to_string(),
            "fail" => fail_marker = v.trim().to_string(),
            other => return Err(anyhow!("--brute-form-spec unknown key '{}'", other)),
        }
    }
    let url = url.ok_or_else(|| anyhow!("--brute-form-spec requires url=..."))?;
    Ok(HttpFormAdapter { url, user_field, pass_field, fail_marker })
}

// ── Telnet ─────────────────────────────────────────────────────────

pub struct TelnetAdapter;

#[async_trait]
impl BruteAdapter for TelnetAdapter {
    fn protocol(&self) -> &'static str { "telnet" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let stream = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;
        let mut s = BufReader::new(stream);
        // Drain until we see "login:" or similar prompt, max ~4KB.
        let banner = read_until_prompt(&mut s, &["login:", "Username:", "User:"], cfg.timeout, 4096).await?;
        if banner.is_empty() {
            return Ok(false);
        }
        timeout(cfg.timeout, s.write_all(format!("{}\r\n", user).as_bytes())).await??;
        let after_user = read_until_prompt(&mut s, &["Password:", "password:"], cfg.timeout, 4096).await?;
        if after_user.is_empty() {
            return Ok(false);
        }
        timeout(cfg.timeout, s.write_all(format!("{}\r\n", pass).as_bytes())).await??;
        // Read the next chunk and decide. Failure markers: "incorrect",
        // "denied", "failed", "Authentication failure", "Login incorrect"
        let mut buf = vec![0u8; 4096];
        let n = match timeout(cfg.timeout, tokio::io::AsyncReadExt::read(&mut s, &mut buf)).await {
            Ok(Ok(n)) => n,
            _ => return Ok(false),
        };
        let body = String::from_utf8_lossy(&buf[..n]).to_lowercase();
        let failed = body.contains("incorrect")
            || body.contains("denied")
            || body.contains("failed")
            || body.contains("authentication failure")
            || body.contains("invalid login");
        Ok(!failed && n > 0)
    }
}

// ── shared helpers ─────────────────────────────────────────────────

async fn read_line<R: AsyncBufReadExt + Unpin>(r: &mut R, dur: std::time::Duration) -> Result<String> {
    let mut line = String::new();
    timeout(dur, r.read_line(&mut line)).await??;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

async fn read_until_prompt<R: AsyncBufReadExt + Unpin>(
    r: &mut R,
    needles: &[&str],
    dur: std::time::Duration,
    cap: usize,
) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = std::time::Instant::now() + dur;
    while out.len() < cap {
        let remaining = match deadline.checked_duration_since(std::time::Instant::now()) {
            Some(r) => r,
            None => break,
        };
        let n = match timeout(remaining, r.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            _ => break,
        };
        out.extend_from_slice(&buf[..n]);
        let s = String::from_utf8_lossy(&out);
        if needles.iter().any(|n| s.contains(n)) {
            return Ok(s.to_string());
        }
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_form_spec_full() {
        let f = parse_form_spec("url=https://x.test/login,user=u,pass=p,fail=Bad").unwrap();
        assert_eq!(f.url, "https://x.test/login");
        assert_eq!(f.user_field, "u");
        assert_eq!(f.pass_field, "p");
        assert_eq!(f.fail_marker, "Bad");
    }

    #[test]
    fn parse_form_spec_defaults_when_optional_missing() {
        let f = parse_form_spec("url=https://x.test/login").unwrap();
        assert_eq!(f.user_field, "username");
        assert_eq!(f.pass_field, "password");
        assert_eq!(f.fail_marker, "Invalid");
    }

    #[test]
    fn parse_form_spec_rejects_missing_url() {
        let r = parse_form_spec("user=u,pass=p");
        assert!(r.is_err());
    }

    #[test]
    fn parse_form_spec_rejects_unknown_key() {
        let r = parse_form_spec("url=https://x.test,whatever=foo");
        assert!(r.is_err());
    }

    #[test]
    fn parse_form_spec_rejects_no_equals() {
        let r = parse_form_spec("url=https://x.test,user");
        assert!(r.is_err());
    }

    #[test]
    fn adapters_advertise_distinct_protocol_strings() {
        assert_eq!(FtpAdapter.protocol(), "ftp");
        assert_eq!(
            HttpBasicAdapter { url: "x".into() }.protocol(),
            "http-basic"
        );
        assert_eq!(
            HttpFormAdapter {
                url: "x".into(),
                user_field: "u".into(),
                pass_field: "p".into(),
                fail_marker: "Bad".into(),
            }
            .protocol(),
            "http-form"
        );
        assert_eq!(TelnetAdapter.protocol(), "telnet");
    }
}
