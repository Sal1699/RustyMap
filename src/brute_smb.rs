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
//!   3. Session Setup ANDX with NTLMSSP AUTHENTICATE (Type 3), echoing the
//!      server-assigned UID from step 2 and carrying our computed NTLMv2
//!      response. Old servers like Samba 3.0.20 require the UID to correlate
//!      the Type-3 with the challenge they issued — sending UID 0 makes auth
//!      fail for every credential (lab BRUTE-1).
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

        // The server assigns a UID in its CHALLENGE reply; the AUTHENTICATE
        // must echo it so the server can correlate the Type-3 with the
        // challenge it issued. Omitting it (UID 0) makes old servers such as
        // Samba 3.0.20 reject every credential (lab BRUTE-1).
        let server_uid = parse_uid(&setup1_resp).unwrap_or(0);

        // 3) Session Setup with NTLMSSP AUTHENTICATE
        let nt_response = compute_ntlmv2(user, &self.domain, pass, &server_challenge, &target_info);
        let setup2 = build_session_setup_ntlmssp_authenticate(user, &self.domain, &nt_response, server_uid);
        timeout(cfg.timeout, s.write_all(&setup2)).await??;
        let setup2_resp = read_nbt(&mut s, cfg.timeout).await?;
        // Opt-in protocol diagnostics: `RUSTYMAP_SMB_DEBUG=1` dumps the
        // challenge reply, the AUTHENTICATE we sent, and the server's reply
        // (hex) plus parsed status/action, to pin down a lab mismatch (e.g. the
        // Samba 3.0.20 guest-mapping false positive) from exact bytes instead of
        // another blind guess.
        if std::env::var_os("RUSTYMAP_SMB_DEBUG").is_some() {
            let hx = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
            let status = parse_nt_status(&setup2_resp)
                .map(|s| format!("0x{:08x}", s))
                .unwrap_or_else(|| "none".into());
            let action = parse_setup_action(&setup2_resp)
                .map(|a| format!("0x{:04x}", a))
                .unwrap_or_else(|| "none".into());
            eprintln!(
                "[smb-debug] {}:{} uid=0x{:04x} status={} action={} guest={}",
                user, pass, server_uid, status, action,
                setup_granted_guest(&setup2_resp)
            );
            eprintln!("[smb-debug]   challenge-resp({}B)={}", setup1_resp.len(), hx(&setup1_resp));
            eprintln!("[smb-debug]   auth-req({}B)={}", setup2.len(), hx(&setup2));
            eprintln!("[smb-debug]   auth-resp({}B)={}", setup2_resp.len(), hx(&setup2_resp));
        }
        // SUCCESS (0) → creds valid; any NT_STATUS error → these creds failed
        // (LOGON_FAILURE / WRONG_PASSWORD / NO_SUCH_USER / …). An unparseable
        // reply is a wire/protocol error, not an auth verdict → Err so the
        // framework can retry rather than brand it "wrong password".
        match parse_nt_status(&setup2_resp) {
            // Status 0 is SUCCESS — but Samba's `map to guest` (Metasploitable
            // 2's config) grants a GUEST session with status 0 for an unknown
            // user / bad password. That is NOT authentication of the submitted
            // credential: the response's Action field carries SMB_SETUP_GUEST.
            // crackmapexec/hydra reject it; we must too, or every wrong cred
            // reads as a hit (lab v0.100.10: root:wrong false positive).
            Some(0x0000_0000) if !setup_granted_guest(&setup2_resp) => Ok(true),
            Some(_) => Ok(false),
            None => Err(anyhow!("unparseable SMB Session Setup reply from {}", cfg.target)),
        }
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
    wrap_session_setup(&ntlmssp, 0)
}

fn build_session_setup_ntlmssp_authenticate(user: &str, domain: &str, nt_response: &[u8], uid: u16) -> Vec<u8> {
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

    // Wrap in Session Setup ANDX, echoing the server-assigned UID.
    wrap_session_setup(&ntlmssp, uid)
}

/// Wrap a GSS/NTLMSSP security blob in an SMB_COM_SESSION_SETUP_ANDX request
/// (WordCount 12, extended security). `uid` is echoed into the SMB header so a
/// follow-up AUTHENTICATE correlates with the server's challenge; it is 0 for
/// the first (NEGOTIATE) round. Shared by both session-setup builders so the
/// parameter block can't drift between them.
fn wrap_session_setup(security_blob: &[u8], uid: u16) -> Vec<u8> {
    let blob_len = security_blob.len() as u16;
    let trailing: &[u8] = &[0x00]; // pad byte; native OS/LanMan strings left empty
    let byte_count = (blob_len as usize + trailing.len()) as u16;

    // Parameter block (24 bytes = WordCount 12).
    let mut params: Vec<u8> = Vec::with_capacity(24);
    params.push(0xff); // AndXCommand = none
    params.push(0x00); // AndXReserved
    params.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
    params.extend_from_slice(&0xffffu16.to_le_bytes()); // MaxBufferSize
    params.extend_from_slice(&0x0002u16.to_le_bytes()); // MaxMpxCount
    params.extend_from_slice(&0x0001u16.to_le_bytes()); // VcNumber
    params.extend_from_slice(&0u32.to_le_bytes()); // SessionKey
    params.extend_from_slice(&blob_len.to_le_bytes()); // SecurityBlobLength
    params.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    // Capabilities — CAP_UNICODE|CAP_NT_SMBS|CAP_STATUS32|CAP_LEVEL_II_OPLOCKS
    // plus CAP_EXTENDED_SECURITY (0x80000000), which the old code omitted so
    // the server never treated the blob as NTLMSSP.
    params.extend_from_slice(&0x8000_00d4u32.to_le_bytes());

    let mut pkt = smb_header_for(0x73, 0xc807, uid);
    pkt.push(12); // WordCount
    pkt.extend_from_slice(&params);
    pkt.extend_from_slice(&byte_count.to_le_bytes()); // ByteCount = blob + trailing
    pkt.extend_from_slice(security_blob);
    pkt.extend_from_slice(trailing);
    patch_nbt_length(&mut pkt);
    pkt
}

fn smb_header_for(command: u8, flags2: u16, uid: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(36);
    pkt.extend_from_slice(&[0u8; 4]); // NBT length placeholder
    pkt.extend_from_slice(b"\xffSMB");
    pkt.push(command);
    pkt.extend_from_slice(&[0u8; 4]); // NT_STATUS
    pkt.push(0x18); // flags
    pkt.extend_from_slice(&flags2.to_le_bytes()); // flags2
    pkt.extend_from_slice(&[0u8; 2]); // PIDHigh
    pkt.extend_from_slice(&[0u8; 8]); // SecuritySignature
    pkt.extend_from_slice(&[0u8; 2]); // Reserved
    pkt.extend_from_slice(&[0u8; 2]); // TID
    pkt.extend_from_slice(&0x4b2fu16.to_le_bytes()); // PIDLow
    pkt.extend_from_slice(&uid.to_le_bytes()); // UID (echo server-assigned)
    pkt.extend_from_slice(&0x5ec5u16.to_le_bytes()); // MID
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

/// UID from an SMB1 response header (offset 28, little-endian). The server
/// assigns this in its CHALLENGE reply; the AUTHENTICATE request must echo it
/// so the server can correlate the Type-3 message with the challenge.
pub fn parse_uid(body: &[u8]) -> Option<u16> {
    if body.len() < 30 || &body[0..4] != b"\xffSMB" {
        return None;
    }
    Some(u16::from_le_bytes([body[28], body[29]]))
}

/// SessionSetupAndX response Action field (offset 37, little-endian), or None
/// if the reply is too short / not SMB. Action sits right after the AndX
/// prologue: header(32) + WordCount(1) + AndXCommand(1) + AndXReserved(1) +
/// AndXOffset(2) → offset 37.
pub fn parse_setup_action(body: &[u8]) -> Option<u16> {
    if body.len() < 39 || &body[0..4] != b"\xffSMB" {
        return None;
    }
    Some(u16::from_le_bytes([body[37], body[38]]))
}

/// Was the SessionSetupAndX response a GUEST mapping rather than real auth?
/// The Action field's bit 0 is `SMB_SETUP_GUEST`: the server granted a guest
/// session (e.g. Samba `map to guest`) instead of authenticating the submitted
/// credential, so a hit must require this bit CLEAR. NOTE: not every server
/// signals a guest mapping here (lab: Samba 3.0.20 still false-positived with
/// this check) — see the `RUSTYMAP_SMB_DEBUG` diagnostics in `try_one`.
pub fn setup_granted_guest(body: &[u8]) -> bool {
    parse_setup_action(body).map_or(false, |a| a & 0x0001 != 0)
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

    #[test]
    fn parse_uid_reads_header_field() {
        // \xffSMB(4) + cmd(1) + status(4) + flags(1) + flags2(2) + pidhigh(2)
        // + sig(8) + reserved(2) + tid(2) + pidlow(2) = offset 28, then UID(2).
        let mut body = vec![0u8; 30];
        body[0..4].copy_from_slice(b"\xffSMB");
        body[28] = 0x34;
        body[29] = 0x12;
        assert_eq!(parse_uid(&body), Some(0x1234));
    }

    #[test]
    fn parse_uid_rejects_non_smb() {
        // Long enough to pass the length guard, but not an SMB reply.
        assert_eq!(parse_uid(&[0x11u8; 40]), None);
    }

    #[test]
    fn authenticate_echoes_server_uid() {
        // UID sits at SMB offset 28..30, i.e. packet offset 32..34 after the
        // 4-byte NBT prefix. Regression guard for lab BRUTE-1 (UID 0 → auth
        // fails on Samba 3.0.20 for every credential).
        let resp = compute_ntlmv2("u", "", "p", &[0u8; 8], b"");
        let pkt = build_session_setup_ntlmssp_authenticate("u", "", &resp, 0xBEEF);
        assert_eq!(&pkt[32..34], &0xBEEFu16.to_le_bytes());
    }

    #[test]
    fn negotiate_session_setup_has_uid_zero() {
        let pkt = build_session_setup_ntlmssp_negotiate();
        assert_eq!(&pkt[32..34], &0u16.to_le_bytes());
    }

    #[test]
    fn wrap_session_setup_structure() {
        // ByteCount must cover the blob + trailing pad, and Capabilities must
        // advertise CAP_EXTENDED_SECURITY (both were wrong before BRUTE-1).
        let blob = b"NTLMSSP\0some-blob-bytes";
        let pkt = wrap_session_setup(blob, 0x1234);
        assert_eq!(&pkt[32..34], &0x1234u16.to_le_bytes(), "UID echoed");
        let bp = pkt.windows(8).position(|w| w == b"NTLMSSP\0").unwrap();
        let bc = u16::from_le_bytes([pkt[bp - 2], pkt[bp - 1]]) as usize;
        assert_eq!(bc, pkt.len() - bp, "ByteCount = blob + trailing pad");
        let caps = u32::from_le_bytes([pkt[bp - 6], pkt[bp - 5], pkt[bp - 4], pkt[bp - 3]]);
        assert!(caps & 0x8000_0000 != 0, "CAP_EXTENDED_SECURITY must be set");
    }

    #[test]
    fn guest_bit_detected_in_setup_response() {
        // header(32) + WordCount + AndXCommand + AndXReserved + AndXOffset(2)
        // → Action at 37..39. Bit 0 set = SMB_SETUP_GUEST.
        let mut body = vec![0u8; 40];
        body[0..4].copy_from_slice(b"\xffSMB");
        body[37] = 0x01; // Action = guest
        assert!(setup_granted_guest(&body), "guest bit set → not a real auth");
        body[37] = 0x00;
        assert!(!setup_granted_guest(&body), "guest bit clear → real auth");
    }

    #[test]
    fn guest_check_safe_on_short_reply() {
        // Too short to hold an Action field → treat as non-guest (the status
        // was already SUCCESS); never panic on a truncated reply.
        assert!(!setup_granted_guest(b"\xffSMBshort"));
    }

    #[test]
    fn parse_setup_action_reads_offset() {
        let mut body = vec![0u8; 40];
        body[0..4].copy_from_slice(b"\xffSMB");
        body[37] = 0x05;
        body[38] = 0x00;
        assert_eq!(parse_setup_action(&body), Some(0x0005));
        assert_eq!(parse_setup_action(b"short"), None);
    }
}
