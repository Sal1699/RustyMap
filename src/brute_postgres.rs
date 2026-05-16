//! PostgreSQL bruteforce — supports the two common pre-SCRAM auth
//! flavours: cleartext and md5.
//!
//! Flow (Postgres frontend/backend protocol v3.0):
//!
//!   1. Client sends StartupMessage with `user` + `database` (and
//!      we set `database = postgres` as the default fallback).
//!   2. Server replies with an AuthenticationRequest. We handle:
//!        - `R 0`  = AuthenticationOk (rare — no auth required)
//!        - `R 3`  = AuthenticationCleartextPassword
//!        - `R 5 + 4-byte salt`  = AuthenticationMD5Password
//!        - `R 10 …` = SASL/SCRAM (modern PG, NOT IMPLEMENTED here —
//!                    returns false so the caller can detect)
//!   3. Client sends PasswordMessage with:
//!        - cleartext: raw password
//!        - md5: `"md5" + md5_hex(md5_hex(password + user) + salt)`
//!   4. Server replies AuthenticationOk (success) or ErrorResponse
//!      (failure). We read just enough to distinguish.

use crate::brute::{BruteAdapter, BruteConfig};
use anyhow::Result;
use async_trait::async_trait;
use md5::{Digest, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct PostgresAdapter {
    pub database: String,
}

impl Default for PostgresAdapter {
    fn default() -> Self {
        Self { database: "postgres".into() }
    }
}

#[async_trait]
impl BruteAdapter for PostgresAdapter {
    fn protocol(&self) -> &'static str { "postgres" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let mut s = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;

        // 1) StartupMessage
        let startup = build_startup(user, &self.database);
        timeout(cfg.timeout, s.write_all(&startup)).await??;

        // 2) Read AuthenticationRequest (type 'R' = 0x52)
        let (msg_type, body) = read_message(&mut s, cfg.timeout).await?;
        if msg_type != b'R' || body.len() < 4 {
            return Ok(false);
        }
        let auth_type = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        match auth_type {
            0 => return Ok(true), // AuthenticationOk — no password needed
            3 => {
                // Cleartext password
                let pkt = build_password_msg(pass.as_bytes());
                timeout(cfg.timeout, s.write_all(&pkt)).await??;
            }
            5 => {
                // MD5 with 4-byte salt
                if body.len() < 8 {
                    return Ok(false);
                }
                let salt = &body[4..8];
                let hash_hex = md5_pg_response(user, pass, salt);
                let pkt = build_password_msg(hash_hex.as_bytes());
                timeout(cfg.timeout, s.write_all(&pkt)).await??;
            }
            10 => {
                // SASL — out of scope. Treat as "can't decide" =
                // false so the bruteforce moves on.
                return Ok(false);
            }
            _ => return Ok(false),
        }

        // 3) Read next message — 'R 0' (AuthenticationOk) = success.
        let (msg_type, body) = read_message(&mut s, cfg.timeout).await?;
        if msg_type == b'R' && body.len() >= 4 {
            let code = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            return Ok(code == 0);
        }
        Ok(false)
    }
}

/// Build a v3.0 StartupMessage. Length-prefixed (4B big-endian),
/// version 196608 (= 3.0 << 16), then null-terminated key/value
/// pairs, terminated by an extra NUL.
pub fn build_startup(user: &str, database: &str) -> Vec<u8> {
    let mut params: Vec<u8> = Vec::new();
    for (k, v) in &[("user", user), ("database", database), ("application_name", "rustymap")] {
        params.extend_from_slice(k.as_bytes());
        params.push(0);
        params.extend_from_slice(v.as_bytes());
        params.push(0);
    }
    params.push(0); // final terminator

    let total = 4 + 4 + params.len();
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&(total as u32).to_be_bytes());
    pkt.extend_from_slice(&196608u32.to_be_bytes()); // protocol v3.0
    pkt.extend_from_slice(&params);
    pkt
}

/// Build a PasswordMessage ('p'). The body is the password bytes
/// followed by a NUL terminator.
pub fn build_password_msg(password: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(password.len() + 1);
    body.extend_from_slice(password);
    body.push(0);
    let mut pkt = Vec::with_capacity(1 + 4 + body.len());
    pkt.push(b'p');
    pkt.extend_from_slice(&((4 + body.len()) as u32).to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}

/// MD5 challenge response per PG docs §55.2.4:
///   `"md5" + md5_hex( md5_hex(password + user) + salt )`
pub fn md5_pg_response(user: &str, pass: &str, salt: &[u8]) -> String {
    let mut h1 = Md5::new();
    h1.update(pass.as_bytes());
    h1.update(user.as_bytes());
    let inner_hex = format!("{:x}", h1.finalize());

    let mut h2 = Md5::new();
    h2.update(inner_hex.as_bytes());
    h2.update(salt);
    format!("md5{:x}", h2.finalize())
}

/// Read one Postgres message: type byte + 4-byte length (includes
/// the length field itself, not the type byte) + body.
async fn read_message(s: &mut TcpStream, dur: std::time::Duration) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    timeout(dur, s.read_exact(&mut hdr)).await??;
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if len < 4 || len > 65536 {
        return Err(anyhow::anyhow!("bogus PG message length {}", len));
    }
    let mut body = vec![0u8; len - 4];
    timeout(dur, s.read_exact(&mut body)).await??;
    Ok((hdr[0], body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_startup_layout() {
        let pkt = build_startup("alice", "postgres");
        // Length field comes first (big-endian)
        let len = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]) as usize;
        assert_eq!(len, pkt.len());
        // Protocol version 3.0 = 196608
        assert_eq!(&pkt[4..8], &196608u32.to_be_bytes());
        // Must contain "user", "alice", "database", "postgres"
        let s = String::from_utf8_lossy(&pkt);
        assert!(s.contains("user"));
        assert!(s.contains("alice"));
        assert!(s.contains("database"));
        assert!(s.contains("postgres"));
        // Must end in NUL terminator
        assert_eq!(*pkt.last().unwrap(), 0);
    }

    #[test]
    fn build_password_msg_has_p_prefix() {
        let pkt = build_password_msg(b"secret");
        assert_eq!(pkt[0], b'p');
        let len = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]) as usize;
        // 4 (length itself) + 6 (secret) + 1 (NUL)
        assert_eq!(len, 11);
        // Body ends with NUL
        assert_eq!(*pkt.last().unwrap(), 0);
    }

    #[test]
    fn md5_pg_response_matches_known_vector() {
        // Reference vector — compute md5("md5" + md5(md5("password" + "alice") + salt))
        // We re-derive here to make the test self-consistent rather
        // than depending on an external golden value.
        let user = "alice";
        let pass = "password";
        let salt: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

        let inner = {
            let mut h = Md5::new();
            h.update(pass.as_bytes());
            h.update(user.as_bytes());
            format!("{:x}", h.finalize())
        };
        let expected = {
            let mut h = Md5::new();
            h.update(inner.as_bytes());
            h.update(salt);
            format!("md5{:x}", h.finalize())
        };
        assert_eq!(md5_pg_response(user, pass, &salt), expected);
    }

    #[test]
    fn md5_pg_response_differs_per_password() {
        let salt = b"\x01\x02\x03\x04";
        let a = md5_pg_response("alice", "p1", salt);
        let b = md5_pg_response("alice", "p2", salt);
        assert_ne!(a, b);
        assert!(a.starts_with("md5"));
        assert!(b.starts_with("md5"));
    }

    #[test]
    fn md5_pg_response_differs_per_salt() {
        let a = md5_pg_response("alice", "p1", b"\x01\x02\x03\x04");
        let b = md5_pg_response("alice", "p1", b"\x05\x06\x07\x08");
        assert_ne!(a, b);
    }
}
