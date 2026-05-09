//! SSH-2.0 server audit — banner + KEXINIT algorithm enumeration.
//!
//! We speak just enough SSH transport-layer protocol (RFC 4253) to
//! receive the server's first KEXINIT message, which advertises every
//! algorithm the server is willing to negotiate. Then we score:
//!   - kex algorithms   (DH group1/group14-sha1 → bad)
//!   - host-key types   (ssh-rsa with SHA-1 → warn, ssh-dss → bad)
//!   - ciphers          (3des-cbc, *-cbc with no etm@ MAC → warn,
//!                       arcfour → bad)
//!   - MACs             (hmac-md5*, hmac-sha1* without etm → warn)
//!
//! No keys exchanged, no auth attempted — read-only banner + 1
//! handshake message. Closes the connection cleanly afterwards.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshAudit {
    pub banner: String,
    pub kex: Vec<String>,
    pub host_keys: Vec<String>,
    pub ciphers_c2s: Vec<String>,
    pub ciphers_s2c: Vec<String>,
    pub macs_c2s: Vec<String>,
    pub macs_s2c: Vec<String>,
    pub findings: Vec<String>,
}

impl SshAudit {
    pub fn has_weakness(&self) -> bool {
        !self.findings.is_empty()
    }
}

const CLIENT_BANNER: &[u8] = b"SSH-2.0-RustyMap_audit\r\n";
const MSG_KEXINIT: u8 = 20;

pub async fn audit(ip: IpAddr, port: u16, dur: Duration) -> Result<SshAudit> {
    let addr = SocketAddr::new(ip, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await??;

    // Read server banner — up to one CRLF, max 255 bytes per RFC 4253.
    let banner = read_banner(&mut s, dur).await?;
    if !banner.starts_with("SSH-2.0") && !banner.starts_with("SSH-1.99") {
        // SSH-1.x speakers exist but are obsolete and we don't try to
        // talk to them; just record the banner.
        let mut a = SshAudit { banner: banner.clone(), ..Default::default() };
        a.findings.push(format!("non-SSH-2.0 banner: {}", banner));
        return Ok(a);
    }

    // Send our banner so the server proceeds to KEXINIT.
    timeout(dur, s.write_all(CLIENT_BANNER)).await??;

    // Read the next packet — should be KEXINIT.
    let payload = read_packet(&mut s, dur).await?;
    if payload.is_empty() || payload[0] != MSG_KEXINIT {
        return Err(anyhow!("expected SSH_MSG_KEXINIT, got {:?}", payload.first()));
    }

    // KEXINIT layout (after msg-type + 16-byte cookie):
    //   name-list kex
    //   name-list host_key
    //   name-list cipher c→s
    //   name-list cipher s→c
    //   name-list mac c→s
    //   name-list mac s→c
    //   name-list compression c→s
    //   name-list compression s→c
    //   name-list languages c→s
    //   name-list languages s→c
    let mut p = SshParser::new(&payload[1 + 16..]);
    let kex = p.name_list()?;
    let host_keys = p.name_list()?;
    let ciphers_c2s = p.name_list()?;
    let ciphers_s2c = p.name_list()?;
    let macs_c2s = p.name_list()?;
    let macs_s2c = p.name_list()?;

    let mut a = SshAudit {
        banner,
        kex,
        host_keys,
        ciphers_c2s,
        ciphers_s2c,
        macs_c2s,
        macs_s2c,
        findings: Vec::new(),
    };
    classify(&mut a);
    Ok(a)
}

async fn read_banner(s: &mut TcpStream, dur: Duration) -> Result<String> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    for _ in 0..512 {
        let n = match timeout(dur, s.read(&mut byte)).await {
            Ok(Ok(n)) => n,
            _ => break,
        };
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            buf.truncate(buf.len() - 2);
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Read one binary packet per RFC 4253 §6 (no MAC yet — pre-key).
async fn read_packet(s: &mut TcpStream, dur: Duration) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    timeout(dur, s.read_exact(&mut len)).await??;
    let pkt_len = u32::from_be_bytes(len) as usize;
    if pkt_len < 1 || pkt_len > 35_000 {
        return Err(anyhow!("bogus SSH packet length {}", pkt_len));
    }
    let mut rest = vec![0u8; pkt_len];
    timeout(dur, s.read_exact(&mut rest)).await??;
    let pad_len = rest[0] as usize;
    if pad_len + 1 > rest.len() {
        return Err(anyhow!("padding overruns packet"));
    }
    let payload_end = rest.len() - pad_len;
    Ok(rest[1..payload_end].to_vec())
}

struct SshParser<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> SshParser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }
    fn u32(&mut self) -> Result<u32> {
        if self.off + 4 > self.buf.len() {
            return Err(anyhow!("short read"));
        }
        let v = u32::from_be_bytes([
            self.buf[self.off],
            self.buf[self.off + 1],
            self.buf[self.off + 2],
            self.buf[self.off + 3],
        ]);
        self.off += 4;
        Ok(v)
    }
    fn name_list(&mut self) -> Result<Vec<String>> {
        let len = self.u32()? as usize;
        if self.off + len > self.buf.len() {
            return Err(anyhow!("name-list overruns"));
        }
        let s = std::str::from_utf8(&self.buf[self.off..self.off + len])
            .unwrap_or("")
            .to_string();
        self.off += len;
        if s.is_empty() {
            Ok(vec![])
        } else {
            Ok(s.split(',').map(|s| s.to_string()).collect())
        }
    }
}

fn classify(a: &mut SshAudit) {
    // ── KEX ─────
    let weak_kex: &[(&str, &str)] = &[
        ("diffie-hellman-group1-sha1", "DH group 1 (1024-bit) — broken"),
        ("diffie-hellman-group14-sha1", "DH group 14 with SHA-1"),
        ("diffie-hellman-group-exchange-sha1", "GEX with SHA-1"),
        ("rsa1024-sha1", "RSA-1024 with SHA-1"),
    ];
    for (alg, why) in weak_kex {
        if a.kex.iter().any(|k| k == alg) {
            a.findings.push(format!("KEX {}: {}", alg, why));
        }
    }

    // ── Host-key ─────
    if a.host_keys.iter().any(|k| k == "ssh-dss") {
        a.findings.push("host-key ssh-dss (DSA) — deprecated".into());
    }
    if a.host_keys.iter().any(|k| k == "ssh-rsa") && !a.host_keys.iter().any(|k| k == "rsa-sha2-256" || k == "rsa-sha2-512") {
        a.findings.push("host-key ssh-rsa only — relies on SHA-1, OpenSSH 8.8 disables".into());
    }

    // ── Ciphers ─────
    let weak_ciphers: &[(&str, &str)] = &[
        ("3des-cbc", "3DES-CBC — Sweet32 (CVE-2016-2183)"),
        ("blowfish-cbc", "Blowfish-CBC — Sweet32"),
        ("cast128-cbc", "CAST128-CBC — Sweet32"),
        ("arcfour", "RC4 — broken"),
        ("arcfour128", "RC4-128 — broken"),
        ("arcfour256", "RC4-256 — broken"),
        ("aes128-cbc", "AES-128-CBC — vulnerable to plaintext-recovery if no etm@"),
        ("aes192-cbc", "AES-192-CBC — vulnerable to plaintext-recovery if no etm@"),
        ("aes256-cbc", "AES-256-CBC — vulnerable to plaintext-recovery if no etm@"),
    ];
    for ciphers in [&a.ciphers_c2s, &a.ciphers_s2c] {
        for (alg, why) in weak_ciphers {
            if ciphers.iter().any(|c| c == alg) {
                a.findings.push(format!("cipher {}: {}", alg, why));
            }
        }
    }

    // ── MACs ─────
    let weak_macs: &[(&str, &str)] = &[
        ("hmac-md5", "HMAC-MD5"),
        ("hmac-md5-96", "HMAC-MD5-96"),
        ("hmac-sha1-96", "HMAC-SHA1-96 (truncated)"),
        ("hmac-ripemd160", "HMAC-RIPEMD160"),
    ];
    for macs in [&a.macs_c2s, &a.macs_s2c] {
        for (alg, why) in weak_macs {
            if macs.iter().any(|m| m == alg) {
                a.findings.push(format!("MAC {}: {}", alg, why));
            }
        }
    }
    a.findings.sort();
    a.findings.dedup();
}

pub fn print_report(host: &str, port: u16, a: &SshAudit) {
    use colored::*;
    println!();
    println!("{}", format!("SSH audit for {}:{}", host, port).bold());
    println!("  banner   : {}", a.banner);
    println!("  KEX      : {}", a.kex.join(", "));
    println!("  host-key : {}", a.host_keys.join(", "));
    println!("  ciphers  : {}", a.ciphers_s2c.join(", "));
    println!("  MACs     : {}", a.macs_s2c.join(", "));
    if a.findings.is_empty() {
        println!("  {}", "no weaknesses detected".green());
    } else {
        println!("  {}", "weaknesses:".yellow().bold());
        for f in &a.findings {
            println!("    · {}", f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_flags_dh_group1() {
        let mut a = SshAudit::default();
        a.kex = vec!["diffie-hellman-group1-sha1".into(), "curve25519-sha256".into()];
        classify(&mut a);
        assert!(a.findings.iter().any(|f| f.contains("group 1")));
    }

    #[test]
    fn classify_flags_3des_and_rc4() {
        let mut a = SshAudit::default();
        a.ciphers_s2c = vec!["3des-cbc".into(), "arcfour256".into(), "aes128-gcm@openssh.com".into()];
        classify(&mut a);
        assert!(a.findings.iter().any(|f| f.contains("3des-cbc")));
        assert!(a.findings.iter().any(|f| f.contains("arcfour256")));
    }

    #[test]
    fn classify_clean_modern_set() {
        let mut a = SshAudit::default();
        a.kex = vec!["curve25519-sha256@libssh.org".into()];
        a.host_keys = vec!["ssh-ed25519".into(), "rsa-sha2-512".into()];
        a.ciphers_s2c = vec!["chacha20-poly1305@openssh.com".into()];
        a.macs_s2c = vec!["hmac-sha2-256-etm@openssh.com".into()];
        classify(&mut a);
        assert!(a.findings.is_empty(), "got {:?}", a.findings);
    }

    #[test]
    fn parser_reads_name_list() {
        // 4-byte length 0x000B + "aaa,bbb,ccc"
        let buf = b"\x00\x00\x00\x0baaa,bbb,ccc";
        let mut p = SshParser::new(buf);
        let names = p.name_list().unwrap();
        assert_eq!(names, vec!["aaa", "bbb", "ccc"]);
    }
}
