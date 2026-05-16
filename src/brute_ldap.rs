//! LDAP simple-bind bruteforce adapter.
//!
//! Connects to TCP/389 (default) or 636 (LDAPS — out of scope for
//! this adapter, see TODO), sends a BindRequest with the candidate
//! credentials as a Simple authentication choice, and inspects the
//! resultCode in the response:
//!
//!   - **resultCode 0 (success)** → valid credentials.
//!   - **resultCode 49 (invalidCredentials)** → wrong password.
//!   - **resultCode 50 / 53** → bind rejected (account disabled,
//!     server unwilling, …) — treat as failure for our purposes.
//!
//! Reuses the BER encoder layout from `src/ldap_enum.rs`. The DN
//! string can be a full DN (`cn=admin,dc=example,dc=org`) or just a
//! username — Active Directory accepts both `user@domain` and
//! `domain\user` shapes.

use crate::brute::{BruteAdapter, BruteConfig};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_SEQUENCE: u8 = 0x30;
const APP_BIND_REQUEST: u8 = 0x60;
const APP_BIND_RESPONSE: u8 = 0x61;
const CTX_SIMPLE_AUTH: u8 = 0x80;

pub struct LdapAdapter;

#[async_trait]
impl BruteAdapter for LdapAdapter {
    fn protocol(&self) -> &'static str { "ldap" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let mut s = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;
        let req = build_bind(1, user, pass);
        timeout(cfg.timeout, s.write_all(&req)).await??;
        let pkt = read_ldap_message(&mut s, cfg.timeout).await?;
        Ok(parse_bind_result_code(&pkt) == Some(0))
    }
}

pub fn build_bind(msg_id: i64, dn: &str, password: &str) -> Vec<u8> {
    fn ber_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(body.len() + 4);
        out.push(tag);
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else if body.len() < 256 {
            out.push(0x81);
            out.push(body.len() as u8);
        } else {
            out.push(0x82);
            out.push((body.len() >> 8) as u8);
            out.push(body.len() as u8);
        }
        out.extend_from_slice(body);
        out
    }
    fn enc_int(v: i64) -> Vec<u8> {
        let mut bytes = v.to_be_bytes().to_vec();
        while bytes.len() > 1 {
            let lead = bytes[0];
            let nm = bytes[1] & 0x80 != 0;
            if (lead == 0 && !nm) || (lead == 0xff && nm) {
                bytes.remove(0);
            } else {
                break;
            }
        }
        ber_tlv(TAG_INTEGER, &bytes)
    }

    let mut inner = enc_int(3); // LDAPv3
    inner.extend_from_slice(&ber_tlv(TAG_OCTET_STRING, dn.as_bytes()));
    inner.extend_from_slice(&ber_tlv(CTX_SIMPLE_AUTH, password.as_bytes()));
    let req = ber_tlv(APP_BIND_REQUEST, &inner);

    let mut msg = enc_int(msg_id);
    msg.extend_from_slice(&req);
    ber_tlv(TAG_SEQUENCE, &msg)
}

async fn read_ldap_message(s: &mut TcpStream, dur: std::time::Duration) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    timeout(dur, s.read_exact(&mut hdr)).await??;
    let mut len_extra: Vec<u8> = Vec::new();
    let body_len = if hdr[1] & 0x80 == 0 {
        hdr[1] as usize
    } else {
        let n = (hdr[1] & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(anyhow!("invalid LDAP length form"));
        }
        let mut buf = vec![0u8; n];
        timeout(dur, s.read_exact(&mut buf)).await??;
        len_extra = buf.clone();
        buf.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize)
    };
    let mut body = vec![0u8; body_len];
    timeout(dur, s.read_exact(&mut body)).await??;
    let mut full = vec![hdr[0], hdr[1]];
    full.extend_from_slice(&len_extra);
    full.extend_from_slice(&body);
    Ok(full)
}

/// Parse the LDAPResult's resultCode out of a BindResponse packet.
pub fn parse_bind_result_code(pkt: &[u8]) -> Option<u8> {
    // LDAPMessage SEQUENCE { messageID, protocolOp }
    if pkt.is_empty() || pkt[0] != TAG_SEQUENCE {
        return None;
    }
    let mut p = 1usize;
    // skip length
    if pkt[p] & 0x80 != 0 {
        p += 1 + (pkt[p] & 0x7f) as usize;
    } else {
        p += 1;
    }
    // messageID INTEGER
    if p >= pkt.len() || pkt[p] != TAG_INTEGER {
        return None;
    }
    p += 1;
    let mid_len = pkt[p] as usize;
    p += 1 + mid_len;

    // BindResponse [APPLICATION 1]
    if p >= pkt.len() || pkt[p] != APP_BIND_RESPONSE {
        return None;
    }
    p += 1;
    // resp body length
    if pkt[p] & 0x80 != 0 {
        p += 1 + (pkt[p] & 0x7f) as usize;
    } else {
        p += 1;
    }
    // resultCode is the first field of LDAPResult — ENUMERATED (tag 0x0a)
    if p + 1 >= pkt.len() || pkt[p] != 0x0a {
        return None;
    }
    let code_len = pkt[p + 1] as usize;
    if code_len == 0 || p + 1 + code_len >= pkt.len() {
        return None;
    }
    Some(pkt[p + 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_bind_starts_with_sequence_and_contains_bind_request() {
        let pkt = build_bind(1, "cn=admin,dc=lab", "secret");
        assert_eq!(pkt[0], TAG_SEQUENCE);
        assert!(pkt.contains(&APP_BIND_REQUEST));
        // version integer "3" should appear
        let needle = [TAG_INTEGER, 0x01, 0x03];
        assert!(pkt.windows(3).any(|w| w == needle));
    }

    #[test]
    fn build_bind_embeds_dn_and_password() {
        let pkt = build_bind(2, "admin", "passw0rd");
        let s = String::from_utf8_lossy(&pkt);
        assert!(s.contains("admin"));
        assert!(s.contains("passw0rd"));
    }

    #[test]
    fn parse_bind_result_code_success_is_zero() {
        // Synthetic minimal BindResponse: SEQUENCE { 02 01 01, 61 07 0a 01 00 04 00 04 00 }
        let pkt: Vec<u8> = vec![
            0x30, 0x0c, // SEQUENCE len=12
            0x02, 0x01, 0x01, // messageID = 1
            0x61, 0x07, // BindResponse, len=7
            0x0a, 0x01, 0x00, // resultCode = 0 (success)
            0x04, 0x00, // matchedDN ""
            0x04, 0x00, // diagnosticMessage ""
        ];
        assert_eq!(parse_bind_result_code(&pkt), Some(0));
    }

    #[test]
    fn parse_bind_result_code_invalid_credentials_is_49() {
        let pkt: Vec<u8> = vec![
            0x30, 0x0c,
            0x02, 0x01, 0x01,
            0x61, 0x07,
            0x0a, 0x01, 0x31, // 0x31 = 49 invalidCredentials
            0x04, 0x00,
            0x04, 0x00,
        ];
        assert_eq!(parse_bind_result_code(&pkt), Some(49));
    }

    #[test]
    fn parse_bind_result_code_rejects_malformed() {
        assert!(parse_bind_result_code(&[]).is_none());
        assert!(parse_bind_result_code(&[0xff, 0x00]).is_none());
    }
}
