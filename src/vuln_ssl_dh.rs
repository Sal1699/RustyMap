//! TLS Diffie-Hellman parameter audit — Logjam (CVE-2015-4000) and
//! related export-grade weakness.
//!
//! Send a TLS 1.0 ClientHello advertising **only** DHE_EXPORT
//! cipher suites. A server that's accepting DHE_EXPORT is the
//! classic Logjam server: with a < 1024-bit DH prime it can be
//! downgraded into 512-bit DH then number-field-sieved offline.
//!
//! We then send a second ClientHello with standard DHE cipher
//! suites and parse the ServerKeyExchange for the *actual* DH
//! prime length. Severity tiers:
//!
//!   - **< 1024 bits**: critical (Logjam practical).
//!   - **< 2048 bits**: warn (precomputable by nation-states).
//!   - **EXPORT-DHE accepted**: critical (downgrade attack surface).
//!   - **No DHE accepted**: clean.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DhSeverity {
    Critical,
    High,
    Medium,
    Info,
    Clean,
}

impl DhSeverity {
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            DhSeverity::Critical => "CRITICAL",
            DhSeverity::High => "HIGH",
            DhSeverity::Medium => "MEDIUM",
            DhSeverity::Info => "INFO",
            DhSeverity::Clean => "CLEAN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhFinding {
    pub host: String,
    pub port: u16,
    pub export_dhe_accepted: bool,
    pub dh_prime_bits: Option<u16>,
    pub severity: DhSeverity,
    pub note: String,
}

pub async fn probe(ip: IpAddr, port: u16, dur: Duration) -> Result<DhFinding> {
    let addr = SocketAddr::new(ip, port);

    // Step 1 — try ONLY export DHE cipher suites.
    let export_accepted = {
        let mut s = match timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                return Ok(DhFinding {
                    host: ip.to_string(),
                    port,
                    export_dhe_accepted: false,
                    dh_prime_bits: None,
                    severity: DhSeverity::Info,
                    note: "TCP connect refused/timed out".into(),
                });
            }
        };
        let hello = client_hello_with_ciphers(&[
            0x0014, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
            0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES_CBC_SHA — pre-RFC 5246 weak
            0x0019, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
            0x0017, // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
        ]);
        timeout(dur, s.write_all(&hello)).await??;
        let mut buf = [0u8; 16];
        match timeout(dur, s.read(&mut buf)).await {
            Ok(Ok(n)) if n >= 6 => {
                // Handshake record (0x16) carrying ServerHello means
                // the server agreed to one of our export ciphers.
                buf[0] == 0x16
            }
            _ => false,
        }
    };

    // Step 2 — full DHE cipher suite list, capture ServerKeyExchange
    // bytes and decode the DH prime length.
    let dh_bits = {
        let mut s = match timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(finalize(ip, port, export_accepted, None)),
        };
        let hello = client_hello_with_ciphers(&[
            0x0033, // DHE_RSA_WITH_AES_128_CBC_SHA
            0x0039, // DHE_RSA_WITH_AES_256_CBC_SHA
            0x0067, // DHE_RSA_WITH_AES_128_CBC_SHA256
            0x006b, // DHE_RSA_WITH_AES_256_CBC_SHA256
            0x009e, // DHE_RSA_WITH_AES_128_GCM_SHA256
            0x009f, // DHE_RSA_WITH_AES_256_GCM_SHA384
        ]);
        if timeout(dur, s.write_all(&hello)).await.is_err() {
            return Ok(finalize(ip, port, export_accepted, None));
        }
        capture_dh_prime_bits(&mut s, dur).await
    };

    Ok(finalize(ip, port, export_accepted, dh_bits))
}

fn finalize(ip: IpAddr, port: u16, export: bool, bits: Option<u16>) -> DhFinding {
    let (severity, note) = match (export, bits) {
        (true, _) => (
            DhSeverity::Critical,
            "Logjam: server accepts DHE_EXPORT cipher suites".into(),
        ),
        (false, Some(b)) if b < 1024 => (
            DhSeverity::Critical,
            format!("DH prime {} bits — Logjam practical", b),
        ),
        (false, Some(b)) if b < 2048 => (
            DhSeverity::High,
            format!("DH prime {} bits — pre-computable by well-resourced attackers", b),
        ),
        (false, Some(b)) if b < 3072 => (
            DhSeverity::Medium,
            format!("DH prime {} bits — meets NIST-2031 minimum but no margin", b),
        ),
        (false, Some(b)) => (
            DhSeverity::Clean,
            format!("DH prime {} bits — strong", b),
        ),
        (false, None) => (
            DhSeverity::Info,
            "no DHE cipher negotiated (ECDHE-only or RSA-only stack)".into(),
        ),
    };
    DhFinding {
        host: ip.to_string(),
        port,
        export_dhe_accepted: export,
        dh_prime_bits: bits,
        severity,
        note,
    }
}

/// Drain TLS records looking for a `ServerKeyExchange` (handshake
/// type 0x0c). When found, decode the DH prime length from the first
/// 2-byte big-endian length prefix in the message body.
async fn capture_dh_prime_bits(s: &mut TcpStream, dur: Duration) -> Option<u16> {
    let deadline = std::time::Instant::now() + dur;
    let mut buf = vec![0u8; 8192];
    let mut acc: Vec<u8> = Vec::with_capacity(16384);
    loop {
        let remaining = deadline.checked_duration_since(std::time::Instant::now())?;
        let n = match timeout(remaining, s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None,
        };
        acc.extend_from_slice(&buf[..n]);
        if let Some(bits) = scan_for_ske_dh_prime(&acc) {
            return Some(bits);
        }
        if acc.len() > 64 * 1024 {
            return None; // hit our cap
        }
    }
}

/// Look for a ServerKeyExchange handshake-message (type 0x0c) and
/// pull the dh_p length from the start of its body.
pub fn scan_for_ske_dh_prime(buf: &[u8]) -> Option<u16> {
    // Walk record-by-record looking for handshake records (type 0x16).
    let mut p = 0usize;
    while p + 5 <= buf.len() {
        let rtype = buf[p];
        let rlen = u16::from_be_bytes([buf[p + 3], buf[p + 4]]) as usize;
        if rtype != 0x16 || p + 5 + rlen > buf.len() {
            // Either not a handshake or we don't have the whole record yet.
            return None;
        }
        let body = &buf[p + 5..p + 5 + rlen];
        // Walk the handshake messages inside this record.
        let mut q = 0usize;
        while q + 4 <= body.len() {
            let mtype = body[q];
            let mlen = ((body[q + 1] as usize) << 16)
                | ((body[q + 2] as usize) << 8)
                | (body[q + 3] as usize);
            if q + 4 + mlen > body.len() {
                break;
            }
            if mtype == 0x0c {
                // ServerKeyExchange. First field is dh_p: opaque<1..2^16-1>
                let payload = &body[q + 4..q + 4 + mlen];
                if payload.len() < 2 {
                    return None;
                }
                let p_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                // Bit-length of dh_p: 8 * byte-length minus leading zero bits.
                if payload.len() < 2 + p_len || p_len == 0 {
                    return None;
                }
                let first = payload[2];
                let leading_zeros = first.leading_zeros();
                let bits = (p_len as u32 * 8).saturating_sub(leading_zeros);
                return Some(bits as u16);
            }
            q += 4 + mlen;
        }
        p += 5 + rlen;
    }
    None
}

fn client_hello_with_ciphers(suites: &[u16]) -> Vec<u8> {
    let mut ch = Vec::with_capacity(80 + suites.len() * 2);
    // record header
    ch.extend_from_slice(&[0x16, 0x03, 0x01, 0, 0]);
    let body_off = ch.len();
    // handshake header
    ch.extend_from_slice(&[0x01, 0, 0, 0]);
    ch.extend_from_slice(&[0x03, 0x01]); // client_version TLS 1.0
    ch.extend_from_slice(&[0xab; 32]);   // random
    ch.push(0x00);                       // session id len
    let cs_len = (suites.len() as u16 * 2).to_be_bytes();
    ch.extend_from_slice(&cs_len);
    for s in suites {
        ch.extend_from_slice(&s.to_be_bytes());
    }
    ch.extend_from_slice(&[0x01, 0x00]); // compression methods
    // patch lengths
    let hs_len = (ch.len() - body_off - 4) as u32;
    ch[body_off + 1] = ((hs_len >> 16) & 0xff) as u8;
    ch[body_off + 2] = ((hs_len >> 8) & 0xff) as u8;
    ch[body_off + 3] = (hs_len & 0xff) as u8;
    let rec_len = (ch.len() - 5) as u16;
    ch[3] = (rec_len >> 8) as u8;
    ch[4] = (rec_len & 0xff) as u8;
    ch
}

pub fn print_finding(f: &DhFinding) {
    use colored::*;
    println!();
    let label = match f.severity {
        DhSeverity::Critical => "CRITICAL".red().bold().to_string(),
        DhSeverity::High => "HIGH".red().to_string(),
        DhSeverity::Medium => "MEDIUM".yellow().to_string(),
        DhSeverity::Info => "INFO".dimmed().to_string(),
        DhSeverity::Clean => "CLEAN".green().to_string(),
    };
    let bits = f.dh_prime_bits.map(|b| format!("{}", b)).unwrap_or_else(|| "—".into());
    println!(
        "{}",
        format!(
            "DH params on {}:{} → {}  (export-dhe={}, prime={} bits)",
            f.host, f.port, label, f.export_dhe_accepted, bits
        )
        .bold()
    );
    println!("  {}", f.note);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(handshake_msg: &[u8]) -> Vec<u8> {
        let mut out = vec![0x16, 0x03, 0x01];
        let len = (handshake_msg.len() as u16).to_be_bytes();
        out.extend_from_slice(&len);
        out.extend_from_slice(handshake_msg);
        out
    }

    #[test]
    fn scan_extracts_2048_bit_dh_prime() {
        // ServerKeyExchange message: type 0x0c, length 258 (2-byte len prefix + 256-byte modulus)
        let mut ske = vec![0x0c, 0x00, 0x01, 0x02];
        ske.extend_from_slice(&256u16.to_be_bytes());
        // First byte non-zero high bit → full 2048 bits used.
        ske.push(0xff);
        ske.extend(std::iter::repeat(0x00).take(255));
        let rec = make_record(&ske);
        let bits = scan_for_ske_dh_prime(&rec);
        assert_eq!(bits, Some(2048));
    }

    #[test]
    fn scan_extracts_512_bit_dh_prime() {
        // 64-byte prime → 512 bits if high bit set
        let mut ske = vec![0x0c, 0x00, 0x00, 0x42];
        ske.extend_from_slice(&64u16.to_be_bytes());
        ske.push(0x80); // leading_zeros = 0 → 64*8 = 512
        ske.extend(std::iter::repeat(0x00).take(63));
        let rec = make_record(&ske);
        assert_eq!(scan_for_ske_dh_prime(&rec), Some(512));
    }

    #[test]
    fn scan_handles_no_ske_in_buf() {
        let bytes = make_record(&[0x02, 0x00, 0x00, 0x46]); // ServerHello, not SKE
        assert_eq!(scan_for_ske_dh_prime(&bytes), None);
    }

    #[test]
    fn finalize_classifies_export_critical() {
        let f = finalize("1.2.3.4".parse().unwrap(), 443, true, Some(512));
        assert_eq!(f.severity, DhSeverity::Critical);
    }

    #[test]
    fn finalize_classifies_strong_clean() {
        let f = finalize("1.2.3.4".parse().unwrap(), 443, false, Some(4096));
        assert_eq!(f.severity, DhSeverity::Clean);
    }

    #[test]
    fn finalize_classifies_no_dhe_info() {
        let f = finalize("1.2.3.4".parse().unwrap(), 443, false, None);
        assert_eq!(f.severity, DhSeverity::Info);
    }

    #[test]
    fn finalize_classifies_logjam_practical() {
        let f = finalize("1.2.3.4".parse().unwrap(), 443, false, Some(768));
        assert_eq!(f.severity, DhSeverity::Critical);
    }

    #[test]
    fn finalize_classifies_2048_high() {
        let f = finalize("1.2.3.4".parse().unwrap(), 443, false, Some(1024));
        assert_eq!(f.severity, DhSeverity::High);
    }
}
