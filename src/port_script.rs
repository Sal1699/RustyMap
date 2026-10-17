//! `--port-script <CMD>` — run an external script/command of ANY language
//! against every open port (user request #5).
//!
//! For each open port on each up host, we spawn `CMD <ip> <port> <proto>` with
//! `RUSTYMAP_IP` / `RUSTYMAP_PORT` / `RUSTYMAP_PROTO` in the environment, bound
//! each invocation by a timeout, and turn non-empty stdout into a finding (so
//! it flows into the report, SARIF and the exit code). This is the
//! language-agnostic counterpart to the built-in Rhai scripts: the user drops
//! in a `.sh`/`.py`/binary (shebang or a real executable) and it runs per port.
//!
//! Safety rails: opt-in (the flag itself), no shell (CMD is executed directly,
//! so there is no shell-injection surface), stderr suppressed, stdout bounded,
//! and a per-invocation timeout that kills a hung script.

use crate::compliance::Finding;
use crate::scanner::{HostResult, PortState};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Collapse whitespace and bound external output to one tidy finding string
/// (char-safe truncation).
pub fn summarize_output(raw: &str) -> String {
    let joined = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX: usize = 300;
    if joined.chars().count() > MAX {
        let truncated: String = joined.chars().take(MAX).collect();
        format!("{}…", truncated)
    } else {
        joined
    }
}

/// Run `script` once per OPEN port across the up hosts. Returns the findings
/// (also printed as it goes). Each invocation is bounded by `timeout`.
pub fn run(hosts: &[HostResult], script: &str, timeout: Duration) -> Vec<Finding> {
    let mut findings = Vec::new();
    for h in hosts.iter().filter(|h| h.up) {
        let ip = h.target.ip.to_string();
        for p in h.ports.iter().filter(|p| p.state == PortState::Open) {
            if let Some(raw) = run_one(script, &ip, p.port, h.target.hostname.as_deref(), timeout) {
                let s = summarize_output(&raw);
                if !s.is_empty() {
                    println!("  [port-script] {}:{} → {}", ip, p.port, s);
                    findings.push(Finding::new(
                        "port-script",
                        ip.clone(),
                        format!("{}:{} {}", ip, p.port, s),
                    ));
                }
            }
        }
    }
    findings
}

/// Spawn one invocation and collect its stdout within `timeout`.
fn run_one(
    script: &str,
    ip: &str,
    port: u16,
    hostname: Option<&str>,
    timeout: Duration,
) -> Option<String> {
    let mut cmd = Command::new(script);
    cmd.arg(ip)
        .arg(port.to_string())
        .arg("tcp")
        .env("RUSTYMAP_IP", ip)
        .env("RUSTYMAP_PORT", port.to_string())
        .env("RUSTYMAP_PROTO", "tcp")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(h) = hostname {
        if !h.is_empty() {
            cmd.env("RUSTYMAP_HOST", h);
        }
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] --port-script: cannot run '{}': {}", script, e);
            return None;
        }
    };
    // Drain stdout on a thread so a chatty script can't deadlock on a full pipe.
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.take(64 * 1024).read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                let _ = child.kill();
                break;
            }
        }
    }
    let _ = child.wait();
    let out = reader.join().unwrap_or_default();
    Some(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_collapses_whitespace() {
        assert_eq!(summarize_output("  foo\n  bar \t baz \n"), "foo bar baz");
        assert_eq!(summarize_output(""), "");
    }

    #[test]
    fn summarize_bounds_length_char_safe() {
        let long = "x".repeat(500);
        let s = summarize_output(&long);
        assert_eq!(s.chars().count(), 301); // 300 + the ellipsis
        assert!(s.ends_with('…'));
        // Multibyte input must not panic and stays char-safe.
        let multi = "àèì".repeat(200); // 600 chars
        let s2 = summarize_output(&multi);
        assert!(s2.chars().count() <= 301);
    }
}
