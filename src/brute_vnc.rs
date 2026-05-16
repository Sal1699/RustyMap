//! VNC bruteforce — RFB 3.x challenge-response DES.
//!
//! RFB authentication (security type 2, "VNC Authentication") is
//! the classic per-password protocol:
//!
//!   1. Client connects, server sends `RFB 003.NNN\n` greeting.
//!   2. Client echoes the same version (we use `RFB 003.008\n`).
//!   3. Server sends `[count][types…]` (or 4-byte security type on
//!      pre-3.7 builds).
//!   4. Client picks `0x02` (VNC Authentication).
//!   5. Server sends a 16-byte random challenge.
//!   6. Client DES-encrypts the challenge with a key derived from
//!      the password (left-padded with `\0` to 8 bytes if shorter,
//!      truncated to 8 bytes if longer). **The password bits are
//!      bit-reversed inside each byte** — a famous VNC quirk that
//!      bites every implementation once.
//!   7. Server replies with 4-byte status: 0 = OK, 1 = FAILED.
//!
//! No username field — only the password matters. We ignore the
//! `user` argument of `try_one`.

use crate::brute::{BruteAdapter, BruteConfig};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use des::cipher::{BlockEncrypt, KeyInit};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct VncAdapter;

#[async_trait]
impl BruteAdapter for VncAdapter {
    fn protocol(&self) -> &'static str { "vnc" }
    async fn try_one(&self, cfg: &BruteConfig, _user: &str, pass: &str) -> Result<bool> {
        let mut s = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;

        // 1) Greeting — 12 bytes "RFB 003.NNN\n"
        let mut hello = [0u8; 12];
        timeout(cfg.timeout, s.read_exact(&mut hello)).await??;
        if !hello.starts_with(b"RFB ") {
            return Err(anyhow!("not an RFB server"));
        }
        // 2) Echo back our preferred version
        timeout(cfg.timeout, s.write_all(b"RFB 003.008\n")).await??;

        // 3) Security types: 1 byte count + N bytes types
        let mut type_count = [0u8; 1];
        timeout(cfg.timeout, s.read_exact(&mut type_count)).await??;
        if type_count[0] == 0 {
            return Ok(false); // server bailed (e.g. unsupported)
        }
        let mut types = vec![0u8; type_count[0] as usize];
        timeout(cfg.timeout, s.read_exact(&mut types)).await??;
        if !types.contains(&0x02) {
            return Ok(false); // VNC auth not offered
        }
        // 4) Pick VNC auth
        timeout(cfg.timeout, s.write_all(&[0x02u8])).await??;

        // 5) 16-byte challenge
        let mut challenge = [0u8; 16];
        timeout(cfg.timeout, s.read_exact(&mut challenge)).await??;

        // 6) Encrypt challenge with the VNC-style password key
        let response = vnc_encrypt(pass, &challenge);
        timeout(cfg.timeout, s.write_all(&response)).await??;

        // 7) Status
        let mut status = [0u8; 4];
        timeout(cfg.timeout, s.read_exact(&mut status)).await??;
        Ok(status == [0, 0, 0, 0])
    }
}

/// Build the 8-byte VNC password key: pad/truncate to 8 bytes, then
/// reverse the bit order inside each byte.
pub fn vnc_key(password: &str) -> [u8; 8] {
    let mut k = [0u8; 8];
    let bytes = password.as_bytes();
    for (i, &b) in bytes.iter().take(8).enumerate() {
        k[i] = bit_reverse(b);
    }
    k
}

fn bit_reverse(b: u8) -> u8 {
    let mut x = b;
    x = ((x & 0xF0) >> 4) | ((x & 0x0F) << 4);
    x = ((x & 0xCC) >> 2) | ((x & 0x33) << 2);
    x = ((x & 0xAA) >> 1) | ((x & 0x55) << 1);
    x
}

/// Encrypt the 16-byte challenge as two DES ECB blocks under the
/// VNC-style key.
pub fn vnc_encrypt(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let key = vnc_key(password);
    let cipher = des::Des::new_from_slice(&key).expect("8-byte key");
    let mut out = [0u8; 16];
    out.copy_from_slice(challenge);
    let (lo, hi) = out.split_at_mut(8);
    let mut b1: [u8; 8] = lo.try_into().unwrap();
    let mut b2: [u8; 8] = hi.try_into().unwrap();
    cipher.encrypt_block((&mut b1).into());
    cipher.encrypt_block((&mut b2).into());
    out[..8].copy_from_slice(&b1);
    out[8..].copy_from_slice(&b2);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_reverse_known_vectors() {
        assert_eq!(bit_reverse(0b00000001), 0b10000000);
        assert_eq!(bit_reverse(0b11110000), 0b00001111);
        assert_eq!(bit_reverse(0b10101010), 0b01010101);
        assert_eq!(bit_reverse(0x00), 0x00);
        assert_eq!(bit_reverse(0xff), 0xff);
    }

    #[test]
    fn vnc_key_pads_short_password_with_zero() {
        let k = vnc_key("ab");
        // "ab" reversed-bits: 'a'=0x61 → 0x86, 'b'=0x62 → 0x46
        assert_eq!(k[0], 0x86);
        assert_eq!(k[1], 0x46);
        // Remaining bytes are zero
        for i in 2..8 {
            assert_eq!(k[i], 0x00);
        }
    }

    #[test]
    fn vnc_key_truncates_long_password() {
        let k = vnc_key("12345678extra");
        // Only first 8 bytes encoded
        assert_eq!(k.len(), 8);
        // '1'=0x31 → reversed 0x8C
        assert_eq!(k[0], 0x8c);
    }

    #[test]
    fn vnc_encrypt_produces_16_bytes() {
        let challenge = [0u8; 16];
        let out = vnc_encrypt("password", &challenge);
        assert_eq!(out.len(), 16);
        // Zero plaintext encrypts to non-zero ciphertext
        assert_ne!(out, [0u8; 16]);
    }

    #[test]
    fn vnc_encrypt_deterministic() {
        let challenge = *b"AAAAAAAAAAAAAAAA";
        let a = vnc_encrypt("test1234", &challenge);
        let b = vnc_encrypt("test1234", &challenge);
        assert_eq!(a, b);
    }

    #[test]
    fn vnc_encrypt_different_keys_different_output() {
        let challenge = *b"AAAAAAAAAAAAAAAA";
        let a = vnc_encrypt("password", &challenge);
        let b = vnc_encrypt("Password", &challenge);
        assert_ne!(a, b);
    }
}
