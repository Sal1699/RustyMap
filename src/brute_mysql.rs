//! MySQL bruteforce — `mysql_native_password` auth (the legacy
//! `OLD_PASSWORD` is dead; `caching_sha2_password` from 8.0+ is
//! handled best-effort, see below).
//!
//! Protocol summary:
//!
//!   1. Server sends a v10 Handshake packet:
//!      `proto-ver=10 | server-version\0 | thread-id(4) | salt1(8) |
//!       filler\0 | capability-lower(2) | charset(1) | status(2) |
//!       capability-upper(2) | auth-data-length(1) | reserved(10) |
//!       salt2(N) | auth-plugin-name\0`
//!      We extract the 20-byte salt (salt1 || salt2 without NULs).
//!   2. Client sends HandshakeResponse41 with:
//!      `client-cap(4) | max-pkt(4) | charset(1) | filler(23) |
//!       user\0 | auth-data-len(1) | auth-data(20) | db\0(optional) |
//!       plugin-name\0`
//!   3. Server replies OK (0x00) or ERR (0xff). Auth-switch (0xfe)
//!      mid-flow is treated as failure — we're not chaining plugins.
//!
//! Auth-data for native password:
//!   `SHA1(password) XOR SHA1(salt || SHA1(SHA1(password)))`

use crate::brute::{BruteAdapter, BruteConfig};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

pub struct MysqlAdapter;

#[async_trait]
impl BruteAdapter for MysqlAdapter {
    fn protocol(&self) -> &'static str { "mysql" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let mut s = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;

        // 1) Read Handshake v10
        let (seq, body) = read_packet(&mut s, cfg.timeout).await?;
        if body.is_empty() || body[0] != 10 {
            return Err(anyhow!("not a MySQL v10 handshake"));
        }
        let salt = extract_salt(&body)?;
        let scramble = mysql_native_scramble(pass.as_bytes(), &salt);

        // 2) Send HandshakeResponse41
        let resp = build_handshake_response(user, &scramble);
        write_packet(&mut s, seq.wrapping_add(1), &resp, cfg.timeout).await?;

        // 3) Read OK / ERR
        let (_seq, body) = read_packet(&mut s, cfg.timeout).await?;
        match body.first() {
            Some(&0x00) => Ok(true),
            Some(&0xff) => Ok(false),
            Some(&0xfe) => Ok(false), // auth-switch — different plugin, treat as failure
            _ => Ok(false),
        }
    }
}

/// Read one MySQL packet header (3 bytes length + 1 byte sequence)
/// then the payload.
async fn read_packet(s: &mut TcpStream, dur: std::time::Duration) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 4];
    timeout(dur, s.read_exact(&mut hdr)).await??;
    let len = (hdr[0] as usize) | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    let seq = hdr[3];
    let mut body = vec![0u8; len];
    timeout(dur, s.read_exact(&mut body)).await??;
    Ok((seq, body))
}

async fn write_packet(s: &mut TcpStream, seq: u8, body: &[u8], dur: std::time::Duration) -> Result<()> {
    let len = body.len();
    let hdr = [
        (len & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        ((len >> 16) & 0xff) as u8,
        seq,
    ];
    timeout(dur, s.write_all(&hdr)).await??;
    timeout(dur, s.write_all(body)).await??;
    Ok(())
}

/// Walk the v10 handshake body extracting the 20-byte salt
/// (salt1 + salt2). Returns the 20 raw bytes (without the trailing
/// NULs the server places between them).
pub fn extract_salt(body: &[u8]) -> Result<[u8; 20]> {
    // Layout offsets:
    //   [0]       proto version (10)
    //   [1..]     server version string + NUL
    //   then       thread-id (4) | salt1 (8) | filler(0x00) | cap-lo(2) |
    //              charset(1) | status(2) | cap-hi(2) | auth-len(1) |
    //              reserved(10) | salt2(>=12) | NUL | plugin-name NUL
    let mut p = 1usize;
    while p < body.len() && body[p] != 0 {
        p += 1;
    }
    if p + 1 + 4 + 8 + 1 > body.len() {
        return Err(anyhow!("handshake too short"));
    }
    p += 1; // skip NUL
    p += 4; // thread-id
    let salt1 = &body[p..p + 8];
    p += 8;
    p += 1; // filler NUL
    if p + 2 + 1 + 2 + 2 + 1 + 10 > body.len() {
        return Err(anyhow!("handshake truncated before salt2"));
    }
    p += 2 + 1 + 2 + 2; // cap-lo + charset + status + cap-hi
    let auth_len = body[p] as usize;
    p += 1;
    p += 10; // reserved
    // salt2 length = max(12, auth_len - 8 - 1) per docs; we read 12 and
    // trim trailing NUL.
    if p + 12 > body.len() {
        return Err(anyhow!("handshake truncated in salt2"));
    }
    let salt2_len = 12.min(body.len() - p).max(0);
    let _ = auth_len;
    let salt2 = &body[p..p + salt2_len];

    let mut out = [0u8; 20];
    out[..8].copy_from_slice(salt1);
    out[8..8 + salt2_len.min(12)].copy_from_slice(&salt2[..salt2_len.min(12)]);
    Ok(out)
}

/// Compute the 20-byte scramble for `mysql_native_password`:
///   SHA1(password) XOR SHA1(salt || SHA1(SHA1(password)))
pub fn mysql_native_scramble(password: &[u8], salt: &[u8; 20]) -> [u8; 20] {
    if password.is_empty() {
        return [0u8; 20];
    }
    let h1: [u8; 20] = Sha1::digest(password).into();
    let h2: [u8; 20] = Sha1::digest(h1).into();
    let mut hasher = Sha1::new();
    hasher.update(salt);
    hasher.update(h2);
    let h3: [u8; 20] = hasher.finalize().into();

    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = h1[i] ^ h3[i];
    }
    out
}

pub fn build_handshake_response(user: &str, scramble: &[u8; 20]) -> Vec<u8> {
    let capabilities: u32 = CLIENT_LONG_PASSWORD
        | CLIENT_PROTOCOL_41
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH;
    let max_packet: u32 = 16_777_215;
    let charset: u8 = 0x21; // utf8_general_ci

    let mut body: Vec<u8> = Vec::with_capacity(64 + user.len());
    body.extend_from_slice(&capabilities.to_le_bytes());
    body.extend_from_slice(&max_packet.to_le_bytes());
    body.push(charset);
    body.extend_from_slice(&[0u8; 23]); // filler
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.push(20); // auth-data length
    body.extend_from_slice(scramble);
    body.extend_from_slice(b"mysql_native_password\0");
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_password_yields_zero_scramble() {
        let salt = [0u8; 20];
        assert_eq!(mysql_native_scramble(b"", &salt), [0u8; 20]);
    }

    #[test]
    fn scramble_is_deterministic() {
        let salt = *b"AAAAAAAAAAAAAAAAAAAA";
        let a = mysql_native_scramble(b"secret", &salt);
        let b = mysql_native_scramble(b"secret", &salt);
        assert_eq!(a, b);
    }

    #[test]
    fn scramble_differs_per_password() {
        let salt = *b"AAAAAAAAAAAAAAAAAAAA";
        let a = mysql_native_scramble(b"alice", &salt);
        let b = mysql_native_scramble(b"alic3", &salt);
        assert_ne!(a, b);
    }

    #[test]
    fn scramble_differs_per_salt() {
        let s1: [u8; 20] = [1; 20];
        let s2: [u8; 20] = [2; 20];
        let a = mysql_native_scramble(b"alice", &s1);
        let b = mysql_native_scramble(b"alice", &s2);
        assert_ne!(a, b);
    }

    #[test]
    fn build_handshake_response_contains_user_and_plugin_name() {
        let scramble = [0u8; 20];
        let resp = build_handshake_response("alice", &scramble);
        let s = String::from_utf8_lossy(&resp);
        assert!(s.contains("alice"));
        assert!(s.contains("mysql_native_password"));
    }

    #[test]
    fn build_handshake_response_starts_with_capabilities_le() {
        let scramble = [0u8; 20];
        let resp = build_handshake_response("u", &scramble);
        let caps = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert!(caps & CLIENT_PROTOCOL_41 != 0);
        assert!(caps & CLIENT_PLUGIN_AUTH != 0);
    }

    #[test]
    fn extract_salt_walks_synthetic_handshake() {
        // Build a minimal handshake: proto=10, server-version "8.0\0",
        // thread-id 0x12345678, salt1 = AAAAAAAA, filler 0, cap-lo, charset,
        // status, cap-hi, auth-len=21, reserved(10), salt2 12-byte
        let mut body = vec![10u8];
        body.extend_from_slice(b"8.0\0");
        body.extend_from_slice(&0x12345678u32.to_le_bytes());
        body.extend_from_slice(b"AAAAAAAA");
        body.push(0x00);
        body.extend_from_slice(&[0x0f, 0x80]); // cap-lo
        body.push(0x21); // charset
        body.extend_from_slice(&[0x02, 0x00]); // status
        body.extend_from_slice(&[0x0f, 0x82]); // cap-hi
        body.push(21); // auth-len
        body.extend_from_slice(&[0u8; 10]); // reserved
        body.extend_from_slice(b"BBBBBBBBBBBB"); // salt2 12 bytes

        let salt = extract_salt(&body).unwrap();
        assert_eq!(&salt[..8], b"AAAAAAAA");
        assert_eq!(&salt[8..], b"BBBBBBBBBBBB");
    }
}
