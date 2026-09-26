//! FTP bounce scan (nmap's `-b`).
//!
//! Abuses the FTP `PORT` command on a *relay* FTP server: we tell the
//! relay to open a data connection to `target:port`, then issue `LIST`.
//! The relay's reply reveals whether the connection succeeded — so the
//! scan appears to originate from the FTP server, not from us. Modern
//! servers refuse cross-host `PORT` (`500`/`501`/`502`) so this mostly
//! flags *misconfigured* relays, which is exactly the finding.
//!
//! Plain TCP (talks only to the relay), so no privileges are needed.

use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Parsed relay spec: `[user:pass@]host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
}

/// Parse `[user:pass@]host[:port]` (defaults: anonymous / port 21).
pub fn parse_relay(spec: &str) -> Relay {
    let (creds, hostpart) = match spec.rsplit_once('@') {
        Some((c, h)) => (Some(c), h),
        None => (None, spec),
    };
    let (user, pass) = match creds {
        Some(c) => match c.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (c.to_string(), String::new()),
        },
        None => ("anonymous".to_string(), "rustymap@example.com".to_string()),
    };
    // Host may be an IPv6 literal in [..]; keep it simple for IPv4/hostnames.
    let (host, port) = match hostpart.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() && !h.is_empty() => {
            (h.to_string(), p.parse().unwrap())
        }
        _ => (hostpart.to_string(), 21u16),
    };
    Relay { host, port, user, pass }
}

/// FTP `PORT` command directing the relay at `target:port`.
pub fn port_command(target: Ipv4Addr, port: u16) -> String {
    let o = target.octets();
    format!(
        "PORT {},{},{},{},{},{}\r\n",
        o[0], o[1], o[2], o[3], port >> 8, port & 0xff
    )
}

/// Result of one bounced port probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BounceState {
    Open,
    Closed,
    /// Relay refused the cross-host PORT command (not exploitable).
    Blocked,
    Unknown,
}

impl BounceState {
    pub fn label(&self) -> &'static str {
        match self {
            BounceState::Open => "open",
            BounceState::Closed => "closed",
            BounceState::Blocked => "relay blocked bounce",
            BounceState::Unknown => "unknown",
        }
    }
}

/// Interpret the relay's reply to the data-transfer command.
pub fn interpret(reply: &str) -> BounceState {
    let code = reply.trim_start();
    if code.starts_with("150") || code.starts_with("125") || code.starts_with("226") {
        BounceState::Open
    } else if code.starts_with("425") || code.starts_with("426") || code.starts_with("421") {
        BounceState::Closed
    } else if code.starts_with("50") {
        // 500/501/502 — PORT/LIST rejected outright.
        BounceState::Blocked
    } else {
        BounceState::Unknown
    }
}

async fn read_reply(s: &mut TcpStream, dur: Duration) -> Result<String> {
    let mut buf = vec![0u8; 1024];
    let n = timeout(dur, s.read(&mut buf)).await??;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

async fn cmd(s: &mut TcpStream, line: &str, dur: Duration) -> Result<String> {
    timeout(dur, s.write_all(line.as_bytes())).await??;
    read_reply(s, dur).await
}

/// Run the bounce scan of `target`'s `ports` through the FTP `relay`.
pub async fn scan(
    relay: &Relay,
    target: Ipv4Addr,
    ports: &[u16],
    dur: Duration,
) -> Result<Vec<(u16, BounceState)>> {
    let addr: SocketAddr = format!("{}:{}", relay.host, relay.port)
        .parse()
        .or_else(|_| -> Result<SocketAddr> {
            // Fall back to DNS via std resolver.
            use std::net::ToSocketAddrs;
            (relay.host.as_str(), relay.port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow!("cannot resolve relay {}", relay.host))
        })?;

    let mut s = timeout(dur, TcpStream::connect(addr)).await??;
    let _greeting = read_reply(&mut s, dur).await?;
    let ur = cmd(&mut s, &format!("USER {}\r\n", relay.user), dur).await?;
    if ur.starts_with("530") {
        return Err(anyhow!("relay rejected USER: {}", ur.trim()));
    }
    // 331 = need password; 230 = already logged in.
    if ur.starts_with("331") {
        let pr = cmd(&mut s, &format!("PASS {}\r\n", relay.pass), dur).await?;
        if !pr.starts_with("230") {
            return Err(anyhow!("relay login failed: {}", pr.trim()));
        }
    }

    let mut out = Vec::with_capacity(ports.len());
    for &port in ports {
        let pr = cmd(&mut s, &port_command(target, port), dur).await?;
        if !pr.starts_with("200") {
            // Relay won't accept the cross-host PORT — bounce is blocked.
            out.push((port, BounceState::Blocked));
            continue;
        }
        let lr = cmd(&mut s, "LIST\r\n", dur).await?;
        out.push((port, interpret(&lr)));
    }
    let _ = timeout(dur, s.write_all(b"QUIT\r\n")).await;
    Ok(out)
}

pub fn print_report(relay: &Relay, target: IpAddr, results: &[(u16, BounceState)]) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!("FTP bounce scan of {} via relay {}:{}", target, relay.host, relay.port).bold()
    );
    let blocked = results.iter().all(|(_, s)| *s == BounceState::Blocked);
    if blocked {
        println!(
            "  {}",
            "relay refuses cross-host PORT — not bounce-exploitable (good)".dimmed()
        );
        return;
    }
    for (port, state) in results {
        let line = format!("  {}/tcp  {}", port, state.label());
        match state {
            BounceState::Open => println!("{}", line.green()),
            BounceState::Blocked => {}
            _ => println!("{}", line),
        }
    }
    if results.iter().any(|(_, s)| *s == BounceState::Open) {
        println!(
            "  {}",
            "relay is an OPEN bounce proxy — misconfiguration (report it)".yellow()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_relay_forms() {
        assert_eq!(
            parse_relay("ftp.example.com"),
            Relay { host: "ftp.example.com".into(), port: 21, user: "anonymous".into(), pass: "rustymap@example.com".into() }
        );
        let r = parse_relay("bob:secret@10.0.0.9:2121");
        assert_eq!(r.host, "10.0.0.9");
        assert_eq!(r.port, 2121);
        assert_eq!(r.user, "bob");
        assert_eq!(r.pass, "secret");
    }

    #[test]
    fn port_command_encodes_octets_and_port() {
        // 10.0.2.15 port 8080 → 8080 = 0x1F90 → 31,144
        assert_eq!(
            port_command(Ipv4Addr::new(10, 0, 2, 15), 8080),
            "PORT 10,0,2,15,31,144\r\n"
        );
        assert_eq!(
            port_command(Ipv4Addr::new(192, 168, 1, 1), 21),
            "PORT 192,168,1,1,0,21\r\n"
        );
    }

    #[test]
    fn interpret_reply_codes() {
        assert_eq!(interpret("150 Opening data connection"), BounceState::Open);
        assert_eq!(interpret("226 Transfer complete"), BounceState::Open);
        assert_eq!(interpret("425 Can't open data connection"), BounceState::Closed);
        assert_eq!(interpret("500 Illegal PORT command"), BounceState::Blocked);
        assert_eq!(interpret("502 Command not implemented"), BounceState::Blocked);
        assert_eq!(interpret("331 whatever"), BounceState::Unknown);
    }
}
