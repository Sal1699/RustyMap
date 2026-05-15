//! SSL/TLS ChangeCipherSpec injection — CVE-2014-0224.
//!
//! Vulnerable openssl < 1.0.1h accepts a `ChangeCipherSpec` record
//! sent **before** the handshake has produced master-secret material.
//! On a patched stack the server replies with a fatal alert
//! (`unexpected_message`, code 10) or simply tears the connection
//! down.
//!
//! We hand-roll a minimal TLS 1.0 ClientHello (no rustls — we need
//! to inject the early CCS), wait for the ServerHello / Certificate
//! flight, then send a CCS record. The server's reply tells us:
//!
//!   - **No alert / handshake continues** → vulnerable.
//!   - **Alert level=fatal, description=10 (unexpected_message)** →
//!     patched.
//!   - **Connection torn down** → patched (most modern stacks).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CcsStatus {
    Vulnerable,
    Patched,
    Unknown,
    NotTls,
}

impl CcsStatus {
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            CcsStatus::Vulnerable => "VULNERABLE",
            CcsStatus::Patched => "PATCHED",
            CcsStatus::Unknown => "UNKNOWN",
            CcsStatus::NotTls => "NOT_TLS",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcsFinding {
    pub host: String,
    pub port: u16,
    pub status: CcsStatus,
    pub alert_desc: Option<u8>,
}

pub async fn probe(ip: IpAddr, port: u16, dur: Duration) -> Result<CcsFinding> {
    let addr = SocketAddr::new(ip, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await??;

    // Send a TLS 1.0 ClientHello with one common cipher (RSA-AES128-SHA).
    let hello = client_hello(0x0301);
    timeout(dur, s.write_all(&hello)).await??;

    // Drain the ServerHello flight. We don't parse it — just collect
    // bytes until we see a handshake type 0x0e (ServerHelloDone) or
    // 1 second of silence.
    let drain_ok = drain_until_hello_done(&mut s, dur).await;
    if !drain_ok {
        return Ok(CcsFinding {
            host: ip.to_string(),
            port,
            status: CcsStatus::NotTls,
            alert_desc: None,
        });
    }

    // Inject an early ChangeCipherSpec.
    //   record header: type=0x14, ver=0x0301, len=0x0001
    //   payload:       0x01
    let ccs: [u8; 6] = [0x14, 0x03, 0x01, 0x00, 0x01, 0x01];
    timeout(dur, s.write_all(&ccs)).await??;

    // Read the next record. Patched servers send an alert.
    let mut buf = [0u8; 16];
    let read = timeout(dur, s.read(&mut buf)).await;
    let (status, alert) = match read {
        Ok(Ok(0)) => (CcsStatus::Patched, None), // socket closed cleanly
        Ok(Ok(n)) if n >= 7 && buf[0] == 0x15 => {
            // Alert record. Description is at offset 6 (record header
            // [type, ver(2), len(2)] then [level, description]).
            let desc = buf[6];
            (CcsStatus::Patched, Some(desc))
        }
        Ok(Ok(_)) => (CcsStatus::Vulnerable, None),
        Err(_) | Ok(Err(_)) => {
            // Read timed out — server didn't object to the CCS, which
            // is consistent with the vulnerable behaviour, but we
            // can't be sure. Call it Unknown to avoid false positives.
            (CcsStatus::Unknown, None)
        }
    };

    Ok(CcsFinding {
        host: ip.to_string(),
        port,
        status,
        alert_desc: alert,
    })
}

/// Build a minimal TLS ClientHello at the requested version.
pub fn client_hello(version: u16) -> Vec<u8> {
    let v_hi = (version >> 8) as u8;
    let v_lo = (version & 0xff) as u8;
    let mut ch = Vec::with_capacity(80);
    // Record layer header — length placeholder
    ch.extend_from_slice(&[0x16, v_hi, v_lo, 0, 0]);
    let body_off = ch.len();
    // Handshake header — type 0x01 (ClientHello), length placeholder
    ch.extend_from_slice(&[0x01, 0, 0, 0]);
    // client_version
    ch.extend_from_slice(&[v_hi, v_lo]);
    // random (32B fixed for reproducibility)
    ch.extend_from_slice(&[0xab; 32]);
    // session_id_len = 0
    ch.push(0x00);
    // cipher_suites: TLS_RSA_WITH_AES_128_CBC_SHA (0x002F),
    //                TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A)
    ch.extend_from_slice(&[0x00, 0x04, 0x00, 0x2f, 0x00, 0x0a]);
    // compression methods: null
    ch.extend_from_slice(&[0x01, 0x00]);
    // patch handshake-body length
    let hs_len = (ch.len() - body_off - 4) as u32;
    ch[body_off + 1] = ((hs_len >> 16) & 0xff) as u8;
    ch[body_off + 2] = ((hs_len >> 8) & 0xff) as u8;
    ch[body_off + 3] = (hs_len & 0xff) as u8;
    // patch record-layer length
    let rec_len = (ch.len() - 5) as u16;
    ch[3] = (rec_len >> 8) as u8;
    ch[4] = (rec_len & 0xff) as u8;
    ch
}

/// Read bytes until we see a ServerHelloDone (handshake type 0x0e)
/// inside a handshake record, or hit `dur` without seeing one.
async fn drain_until_hello_done(s: &mut TcpStream, dur: Duration) -> bool {
    let deadline = std::time::Instant::now() + dur;
    let mut buf = vec![0u8; 4096];
    loop {
        let remaining = match deadline.checked_duration_since(std::time::Instant::now()) {
            Some(r) => r,
            None => return false,
        };
        let n = match timeout(remaining, s.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => return false,
        };
        if n == 0 {
            return false;
        }
        // Look for handshake records (type 0x16) carrying 0x0e
        // (ServerHelloDone). Crude scan — sufficient because 0x0e
        // is a rare byte in early TLS records and we don't care
        // about false alarms here: if we mis-trigger we just send
        // the CCS slightly early, which still elicits the same
        // diagnostic alert from a patched server.
        if buf[..n].iter().any(|&b| b == 0x0e) {
            return true;
        }
    }
}

pub fn print_finding(f: &CcsFinding) {
    use colored::*;
    println!();
    let label = match f.status {
        CcsStatus::Vulnerable => "VULNERABLE".red().bold().to_string(),
        CcsStatus::Patched => "PATCHED".green().to_string(),
        CcsStatus::Unknown => "UNKNOWN".yellow().to_string(),
        CcsStatus::NotTls => "NOT_TLS".dimmed().to_string(),
    };
    let alert = f
        .alert_desc
        .map(|d| format!(" (alert desc={})", d))
        .unwrap_or_default();
    println!(
        "{}",
        format!("CCS injection (CVE-2014-0224) on {}:{} → {}{}", f.host, f.port, label, alert).bold()
    );
    if matches!(f.status, CcsStatus::Vulnerable) {
        println!("  {}", "openssl < 1.0.1h — patch or replace urgently".red());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_record_layer_starts_with_handshake_type() {
        let ch = client_hello(0x0301);
        assert_eq!(ch[0], 0x16);     // TLS handshake record
        assert_eq!(ch[1], 0x03);     // TLS major
        assert_eq!(ch[2], 0x01);     // TLS 1.0 minor
        // Length field at [3..5] should equal ch.len() - 5
        let len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
        assert_eq!(len, ch.len() - 5);
    }

    #[test]
    fn client_hello_handshake_header_type_is_client_hello() {
        let ch = client_hello(0x0301);
        assert_eq!(ch[5], 0x01); // ClientHello
    }

    #[test]
    fn client_hello_advertises_two_cipher_suites() {
        let ch = client_hello(0x0301);
        let needle = [0x00, 0x2f, 0x00, 0x0a];
        assert!(ch.windows(4).any(|w| w == needle));
    }

    #[test]
    fn ccs_status_labels_distinct() {
        assert_ne!(CcsStatus::Vulnerable.label(), CcsStatus::Patched.label());
        assert_ne!(CcsStatus::Patched.label(), CcsStatus::Unknown.label());
        assert_eq!(CcsStatus::NotTls.label(), "NOT_TLS");
    }
}
