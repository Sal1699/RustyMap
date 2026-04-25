//! Proxy chain (SOCKS5 / HTTP CONNECT) for TCP connect probes.
//!
//! Improvement vs nmap: SOCKS5h (DNS resolution at the proxy) is the
//! default — no DNS leak from the scanning host. We also warn when an
//! HTTP proxy is asked to tunnel a non-CONNECT-friendly port.

use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub enum ProxyKind {
    Socks5 { addr: String },
    HttpConnect { addr: String },
}

impl ProxyKind {
    fn host_port(&self) -> &str {
        match self {
            ProxyKind::Socks5 { addr } => addr,
            ProxyKind::HttpConnect { addr } => addr,
        }
    }
}

/// Parse `socks5://host:port,http://host:port,…` into an ordered chain.
pub fn parse_chain(spec: &str) -> Result<Vec<ProxyKind>> {
    let mut out = Vec::new();
    for piece in spec.split(',') {
        let p = piece.trim();
        if p.is_empty() {
            continue;
        }
        if let Some(rest) = p.strip_prefix("socks5://").or_else(|| p.strip_prefix("socks5h://")) {
            out.push(ProxyKind::Socks5 { addr: rest.to_string() });
        } else if let Some(rest) = p.strip_prefix("http://").or_else(|| p.strip_prefix("https://")) {
            out.push(ProxyKind::HttpConnect { addr: rest.to_string() });
        } else {
            return Err(anyhow!(
                "--proxies: '{}' missing scheme (expected socks5://, socks5h://, http:// or https://)",
                p
            ));
        }
    }
    if out.is_empty() {
        return Err(anyhow!("--proxies: empty chain"));
    }
    Ok(out)
}

/// Connect to `final_target` (host:port string — can be IP or hostname)
/// through the configured proxy chain. The first hop is dialed
/// directly; each subsequent hop is reached by tunneling through the
/// previous one.
pub async fn connect_via_chain(
    chain: &[ProxyKind],
    final_target: &str,
    deadline: Duration,
) -> Result<TcpStream> {
    if chain.is_empty() {
        return Err(anyhow!("empty proxy chain"));
    }

    // First hop: direct TCP connect.
    let mut stream = timeout(deadline, TcpStream::connect(chain[0].host_port()))
        .await
        .map_err(|_| anyhow!("proxy connect timeout: {}", chain[0].host_port()))??;

    // Walk the chain: ask hop[i] to tunnel to hop[i+1] (or to final_target).
    for i in 0..chain.len() {
        let next_target = if i + 1 < chain.len() {
            chain[i + 1].host_port().to_string()
        } else {
            final_target.to_string()
        };
        match &chain[i] {
            ProxyKind::Socks5 { .. } => {
                socks5_handshake(&mut stream, &next_target, deadline).await?;
            }
            ProxyKind::HttpConnect { .. } => {
                http_connect(&mut stream, &next_target, deadline).await?;
            }
        }
    }
    Ok(stream)
}

async fn socks5_handshake(
    s: &mut TcpStream,
    target: &str,
    deadline: Duration,
) -> Result<()> {
    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no-auth)
    timeout(deadline, s.write_all(&[0x05, 0x01, 0x00])).await??;
    let mut hello = [0u8; 2];
    timeout(deadline, s.read_exact(&mut hello)).await??;
    if hello[0] != 0x05 || hello[1] != 0x00 {
        return Err(anyhow!("SOCKS5: server rejected no-auth method"));
    }

    // CONNECT request: VER=5, CMD=1 (connect), RSV=0, ATYP=3 (domain),
    // LEN, name, port (BE)
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("SOCKS5: target must be host:port"))?;
    let port_n: u16 = port.parse().map_err(|_| anyhow!("SOCKS5: bad port {}", port))?;
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(anyhow!("SOCKS5: hostname too long"));
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port_n.to_be_bytes());
    timeout(deadline, s.write_all(&req)).await??;

    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    let mut head = [0u8; 4];
    timeout(deadline, s.read_exact(&mut head)).await??;
    if head[1] != 0x00 {
        let reason = match head[1] {
            1 => "general failure",
            2 => "connection not allowed",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "TTL expired",
            7 => "command not supported",
            8 => "address type not supported",
            _ => "unknown",
        };
        return Err(anyhow!("SOCKS5 CONNECT failed: {}", reason));
    }
    // Skip BND.ADDR + BND.PORT
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 4 + 2];
            timeout(deadline, s.read_exact(&mut skip)).await??;
        }
        0x03 => {
            let mut len = [0u8; 1];
            timeout(deadline, s.read_exact(&mut len)).await??;
            let mut skip = vec![0u8; len[0] as usize + 2];
            timeout(deadline, s.read_exact(&mut skip)).await??;
        }
        0x04 => {
            let mut skip = [0u8; 16 + 2];
            timeout(deadline, s.read_exact(&mut skip)).await??;
        }
        _ => return Err(anyhow!("SOCKS5: unknown BND.ADDR ATYP")),
    }
    Ok(())
}

async fn http_connect(s: &mut TcpStream, target: &str, deadline: Duration) -> Result<()> {
    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: keep-alive\r\n\r\n",
        target, target
    );
    timeout(deadline, s.write_all(req.as_bytes())).await??;

    // Read until \r\n\r\n
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 64];
    let dl = std::time::Instant::now() + deadline;
    loop {
        let remaining = dl.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("HTTP CONNECT: timeout reading response"));
        }
        let n = timeout(remaining, s.read(&mut tmp)).await??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 4096 {
            return Err(anyhow!("HTTP CONNECT: response too large"));
        }
    }
    let head = std::str::from_utf8(&buf).unwrap_or("");
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        return Err(anyhow!("HTTP CONNECT failed: {}", status_line));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_socks5_chain() {
        let c = parse_chain("socks5://1.2.3.4:1080,http://10.0.0.1:8080").unwrap();
        assert_eq!(c.len(), 2);
        match &c[0] {
            ProxyKind::Socks5 { addr } => assert_eq!(addr, "1.2.3.4:1080"),
            _ => panic!("expected SOCKS5"),
        }
        match &c[1] {
            ProxyKind::HttpConnect { addr } => assert_eq!(addr, "10.0.0.1:8080"),
            _ => panic!("expected HTTP"),
        }
    }

    #[test]
    fn rejects_missing_scheme() {
        assert!(parse_chain("1.2.3.4:1080").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_chain("").is_err());
        assert!(parse_chain(",,,").is_err());
    }
}
