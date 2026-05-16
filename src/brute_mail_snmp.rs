//! Bruteforce adapters for SMTP / POP3 / IMAP / SNMP.
//!
//! - **SMTP AUTH PLAIN**: connect → EHLO → AUTH PLAIN <base64(\0user\0pass)>.
//!   235 = success, 535 = failure.
//! - **POP3 USER/PASS**: connect → +OK banner → USER user → +OK →
//!   PASS pass → +OK = success.
//! - **IMAP LOGIN**: connect → * OK banner → tag LOGIN user pass →
//!   tag OK Logged in.
//! - **SNMP community-string**: UDP/161, send a minimal SNMPv1 GET
//!   for sysName.0. Any well-formed response → community valid;
//!   timeout → invalid. Reuses the BER encode path duplicated here
//!   so `brute_mail_snmp.rs` stays self-contained.

use crate::brute::{BruteAdapter, BruteConfig};
use anyhow::Result;
use async_trait::async_trait;
use base64::Engine as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

// ── SMTP AUTH PLAIN ────────────────────────────────────────────────

pub struct SmtpAdapter;

#[async_trait]
impl BruteAdapter for SmtpAdapter {
    fn protocol(&self) -> &'static str { "smtp" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let stream = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;
        let mut s = BufReader::new(stream);
        let _ = read_line(&mut s, cfg.timeout).await; // banner
        timeout(cfg.timeout, s.write_all(b"EHLO rustymap.brute\r\n")).await??;
        // Drain EHLO multi-line reply (250-…\r\n until 250 sp).
        for _ in 0..32 {
            let l = read_line(&mut s, cfg.timeout).await.unwrap_or_default();
            if l.starts_with("250 ") || l.is_empty() {
                break;
            }
        }
        // AUTH PLAIN
        let blob = format!("\0{}\0{}", user, pass);
        let b64 = base64::engine::general_purpose::STANDARD.encode(blob.as_bytes());
        timeout(cfg.timeout, s.write_all(format!("AUTH PLAIN {}\r\n", b64).as_bytes())).await??;
        let resp = read_line(&mut s, cfg.timeout).await?;
        Ok(resp.starts_with("235"))
    }
}

// ── POP3 USER/PASS ─────────────────────────────────────────────────

pub struct Pop3Adapter;

#[async_trait]
impl BruteAdapter for Pop3Adapter {
    fn protocol(&self) -> &'static str { "pop3" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let stream = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;
        let mut s = BufReader::new(stream);
        let banner = read_line(&mut s, cfg.timeout).await?;
        if !banner.starts_with("+OK") {
            return Ok(false);
        }
        timeout(cfg.timeout, s.write_all(format!("USER {}\r\n", user).as_bytes())).await??;
        let l = read_line(&mut s, cfg.timeout).await?;
        if !l.starts_with("+OK") {
            return Ok(false);
        }
        timeout(cfg.timeout, s.write_all(format!("PASS {}\r\n", pass).as_bytes())).await??;
        let l = read_line(&mut s, cfg.timeout).await?;
        Ok(l.starts_with("+OK"))
    }
}

// ── IMAP LOGIN ─────────────────────────────────────────────────────

pub struct ImapAdapter;

#[async_trait]
impl BruteAdapter for ImapAdapter {
    fn protocol(&self) -> &'static str { "imap" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let stream = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;
        let mut s = BufReader::new(stream);
        let banner = read_line(&mut s, cfg.timeout).await?;
        if !banner.contains("OK") {
            return Ok(false);
        }
        // Tag + LOGIN. Quote arguments to handle special chars.
        let user_q = imap_quote(user);
        let pass_q = imap_quote(pass);
        timeout(
            cfg.timeout,
            s.write_all(format!("a001 LOGIN {} {}\r\n", user_q, pass_q).as_bytes()),
        )
        .await??;
        let l = read_line(&mut s, cfg.timeout).await?;
        Ok(l.starts_with("a001 OK"))
    }
}

fn imap_quote(s: &str) -> String {
    // Plain alphanumeric → unquoted; anything else → quoted with
    // backslash-escapes for `"` and `\`.
    if s.chars().all(|c| c.is_ascii_alphanumeric()) && !s.is_empty() {
        return s.to_string();
    }
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

// ── SNMP community-string ──────────────────────────────────────────

pub struct SnmpAdapter;

#[async_trait]
impl BruteAdapter for SnmpAdapter {
    fn protocol(&self) -> &'static str { "snmp" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let _ = user; // ignored — SNMPv1 has no username field
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let pkt = build_snmp_get(pass);
        sock.send_to(&pkt, cfg.target).await?;
        let mut buf = vec![0u8; 1024];
        match timeout(cfg.timeout, sock.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => Ok(true),
            _ => Ok(false),
        }
    }
}

/// Build a minimal SNMPv1 GET for sysName.0 with the supplied
/// community string. Cut-down version of the encoder used in
/// `src/snmp_enum.rs`.
pub fn build_snmp_get(community: &str) -> Vec<u8> {
    fn ber_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(body.len() + 4);
        out.push(tag);
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else {
            out.push(0x81);
            out.push(body.len() as u8);
        }
        out.extend_from_slice(body);
        out
    }
    fn enc_int(v: i64) -> Vec<u8> {
        let mut bytes = v.to_be_bytes().to_vec();
        while bytes.len() > 1 {
            let lead = bytes[0];
            let next_msb = bytes[1] & 0x80 != 0;
            if (lead == 0 && !next_msb) || (lead == 0xff && next_msb) {
                bytes.remove(0);
            } else {
                break;
            }
        }
        ber_tlv(0x02, &bytes)
    }
    // OID 1.3.6.1.2.1.1.5.0 = sysName.0
    let oid = ber_tlv(0x06, &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]);
    let mut varbind = oid;
    varbind.extend_from_slice(&ber_tlv(0x05, &[])); // NULL
    let varbind = ber_tlv(0x30, &varbind);
    let varbinds = ber_tlv(0x30, &varbind);

    let mut pdu = enc_int(0x1234); // request-id
    pdu.extend_from_slice(&enc_int(0));
    pdu.extend_from_slice(&enc_int(0));
    pdu.extend_from_slice(&varbinds);
    let pdu = ber_tlv(0xa0, &pdu); // GET_REQUEST

    let mut msg = enc_int(0); // version SNMPv1
    msg.extend_from_slice(&ber_tlv(0x04, community.as_bytes()));
    msg.extend_from_slice(&pdu);
    ber_tlv(0x30, &msg)
}

// ── shared helper ──────────────────────────────────────────────────

async fn read_line<R: AsyncBufReadExt + Unpin>(r: &mut R, dur: std::time::Duration) -> Result<String> {
    let mut line = String::new();
    timeout(dur, r.read_line(&mut line)).await??;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_snmp_get_starts_with_sequence() {
        let pkt = build_snmp_get("public");
        assert_eq!(pkt[0], 0x30); // SEQUENCE
        // Contains the community string somewhere
        let needle = b"public";
        assert!(pkt.windows(needle.len()).any(|w| w == needle));
        // Contains the OID prefix 2B 06 01 02 01 01 05 00
        let oid_needle = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00];
        assert!(pkt.windows(oid_needle.len()).any(|w| w == oid_needle));
    }

    #[test]
    fn imap_quote_passes_alnum_through() {
        assert_eq!(imap_quote("alice"), "alice");
        assert_eq!(imap_quote("user123"), "user123");
    }

    #[test]
    fn imap_quote_quotes_special_chars() {
        assert_eq!(imap_quote("a b"), "\"a b\"");
        assert_eq!(imap_quote("p@ss"), "\"p@ss\"");
        assert_eq!(imap_quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(imap_quote("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn adapters_advertise_distinct_protocols() {
        assert_eq!(SmtpAdapter.protocol(), "smtp");
        assert_eq!(Pop3Adapter.protocol(), "pop3");
        assert_eq!(ImapAdapter.protocol(), "imap");
        assert_eq!(SnmpAdapter.protocol(), "snmp");
    }
}
