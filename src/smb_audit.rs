//! SMB version + signing audit — parses the SMB Negotiate Protocol
//! Response.
//!
//! We try a native **SMB2 NEGOTIATE** (`0xfe`-headed, with a 3.1.1
//! preauth-integrity negotiate context, exactly as nmap/smbclient do)
//! first, and fall back to the legacy **SMBv1 multi-dialect negotiate**
//! (`0xff`-headed) only if that is refused:
//!   - SMB2+ servers respond with a 0xfe-headed packet (SMB2 SYNC
//!     header) — we parse the SecurityMode flags to learn whether
//!     signing is enabled and whether it's *required*.
//!   - SMB1-only servers (old NAS / embedded) reject the SMB2 probe;
//!     the SMB1 fallback then draws a 0xff-headed answer, which alone
//!     is a finding (SMBv1 is deprecated, EternalBlue targets it).
//!
//! Why SMB2-first: modern Windows (10/11, notably **24H2**) has SMB1
//! fully removed and RSTs a legacy `\xffSMB` negotiate outright
//! (lab v0.100.1 BUG-1: Win11 24H2 reset the connection on :139 and
//! :445 while nmap/crackmapexec succeeded). Leading with the SMB2
//! negotiate is what those tools do and what modern hosts expect.
//!
//! No authentication, no shares listed — just the negotiate. The
//! connection is closed before the session-setup phase.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmbAudit {
    pub dialect: String,
    pub smbv1_supported: bool,
    pub smb2_dialect_revision: Option<u16>,
    pub signing_enabled: bool,
    pub signing_required: bool,
    pub findings: Vec<String>,
}

impl SmbAudit {
    pub fn has_weakness(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// SMBv1 NegotiateProtocolRequest with both SMB1 dialects and SMB2 wildcard.
/// Layout:
///   NetBIOS session header: 0x00 + 24-bit length
///   SMB header (32B):
///     0xff S M B
///     command 0x72 (NEGOTIATE)
///     status (4B = 0)
///     flags 0x18, flags2 0xc853
///     PIDHigh 0x0000
///     security_features (8B)
///     reserved (2B)
///     TID/PID/UID/MID (8B)
///   SMB body: word_count(0) byte_count(LE 16) + dialect strings
const NEGOTIATE_REQUEST: &[u8] = &[
    // NetBIOS header (length filled in below)
    0x00, 0x00, 0x00, 0x00,
    // SMB header
    0xff, 0x53, 0x4d, 0x42,           // Protocol: \xffSMB
    0x72,                             // Command: NEGOTIATE
    0x00, 0x00, 0x00, 0x00,           // Status: 0
    0x18,                             // Flags
    0x53, 0xc8,                       // Flags2 (UNICODE | NT_STATUS | EXT_SEC | LONG_NAMES …)
    0x00, 0x00,                       // PIDHigh
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SecurityFeatures
    0x00, 0x00,                       // Reserved
    0x00, 0x00,                       // TID
    0x2f, 0x4b,                       // PID
    0x00, 0x00,                       // UID
    0xc5, 0x5e,                       // MID
    // SMB body
    0x00,                             // WordCount = 0
    0x62, 0x00,                       // ByteCount = 0x62 (98)
    // Dialects (each is 0x02 + null-terminated ASCII)
    0x02, b'P', b'C', b' ', b'N', b'E', b'T', b'W', b'O', b'R', b'K', b' ',
        b'P', b'R', b'O', b'G', b'R', b'A', b'M', b' ', b'1', b'.', b'0', 0x00,
    0x02, b'L', b'A', b'N', b'M', b'A', b'N', b'1', b'.', b'0', 0x00,
    0x02, b'W', b'i', b'n', b'd', b'o', b'w', b's', b' ', b'f', b'o', b'r',
        b' ', b'W', b'o', b'r', b'k', b'g', b'r', b'o', b'u', b'p', b's',
        b' ', b'3', b'.', b'1', b'a', 0x00,
    0x02, b'L', b'M', b'1', b'.', b'2', b'X', b'0', b'0', 0x00,
    0x02, b'L', b'A', b'N', b'M', b'A', b'N', b'2', b'.', b'1', 0x00,
    0x02, b'N', b'T', b' ', b'L', b'M', b' ', b'0', b'.', b'1', b'2', 0x00,
    0x02, b'S', b'M', b'B', b' ', b'2', b'.', b'0', b'0', b'2', 0x00,
    0x02, b'S', b'M', b'B', b' ', b'2', b'.', b'?', b'?', b'?', 0x00,
];

/// Native SMB2 NEGOTIATE request (158 bytes after the 4-byte NetBIOS header),
/// offering dialects 2.0.2 / 2.1 / 3.0 / 3.0.2 / 3.1.1 with the mandatory
/// SMB2_PREAUTH_INTEGRITY_CAPABILITIES negotiate context that 3.1.1 requires.
/// This is what modern Windows expects — the legacy `\xffSMB` negotiate above
/// is RST'd by Win10/11 (SMB1 removed). NetBIOS length is patched at send time.
const SMB2_NEGOTIATE_REQUEST: &[u8] = &[
    // NetBIOS session header (length patched in `negotiate_once`)
    0x00, 0x00, 0x00, 0x00,
    // ── SMB2 SYNC header (64 bytes) ──
    0xFE, 0x53, 0x4D, 0x42,                         // ProtocolId "\xfeSMB"
    0x40, 0x00,                                     // StructureSize = 64
    0x00, 0x00,                                     // CreditCharge = 0
    0x00, 0x00, 0x00, 0x00,                         // Status (reserved) = 0
    0x00, 0x00,                                     // Command = 0x0000 NEGOTIATE
    0x01, 0x00,                                     // CreditRequest = 1
    0x00, 0x00, 0x00, 0x00,                         // Flags = 0
    0x00, 0x00, 0x00, 0x00,                         // NextCommand = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId = 0
    0x00, 0x00, 0x00, 0x00,                         // Reserved (ProcessId) = 0
    0x00, 0x00, 0x00, 0x00,                         // TreeId = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (16B) = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ── NEGOTIATE request (fixed 36 bytes) ──
    0x24, 0x00,                                     // StructureSize = 36
    0x05, 0x00,                                     // DialectCount = 5
    0x01, 0x00,                                     // SecurityMode = SIGNING_ENABLED
    0x00, 0x00,                                     // Reserved
    0x00, 0x00, 0x00, 0x00,                         // Capabilities = 0
    // ClientGuid (16B) — fixed, non-zero
    b'R', b'u', b's', b't', b'y', b'M', b'a', b'p',
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x70, 0x00, 0x00, 0x00,                         // NegotiateContextOffset = 112
    0x01, 0x00,                                     // NegotiateContextCount = 1
    0x00, 0x00,                                     // Reserved2
    // ── Dialects (5 × 2B) ──
    0x02, 0x02,                                     // SMB 2.0.2
    0x10, 0x02,                                     // SMB 2.1
    0x00, 0x03,                                     // SMB 3.0
    0x02, 0x03,                                     // SMB 3.0.2
    0x11, 0x03,                                     // SMB 3.1.1
    // Padding to 8-byte alignment (offset 110 → 112)
    0x00, 0x00,
    // ── Negotiate context: SMB2_PREAUTH_INTEGRITY_CAPABILITIES @ offset 112 ──
    0x01, 0x00,                                     // ContextType = 0x0001
    0x26, 0x00,                                     // DataLength = 38
    0x00, 0x00, 0x00, 0x00,                         // Reserved
    0x01, 0x00,                                     // HashAlgorithmCount = 1
    0x20, 0x00,                                     // SaltLength = 32
    0x01, 0x00,                                     // HashAlgorithms[0] = SHA-512
    // Salt (32B)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub async fn audit(ip: IpAddr, port: u16, dur: Duration) -> Result<SmbAudit> {
    let addr = SocketAddr::new(ip, port);

    // SMB2 first (modern Windows/Samba). Only if that is refused do we try the
    // legacy SMB1 multi-dialect negotiate — Win10/11 RST the SMB1 packet, so
    // leading with SMB1 (the pre-v0.100.2 behaviour) reset the connection and
    // produced a false "firewall reject" on perfectly healthy SMB3 hosts
    // (lab v0.100.1 BUG-1: Win11 24H2).
    let smb2_err = match negotiate_once(addr, SMB2_NEGOTIATE_REQUEST, dur)
        .await
        .and_then(|body| build_audit(&body))
    {
        Ok(a) => return Ok(a),
        Err(e) => e,
    };

    // Fallback: SMB1 multi-dialect negotiate for genuinely SMB1-only servers.
    match negotiate_once(addr, NEGOTIATE_REQUEST, dur)
        .await
        .and_then(|body| build_audit(&body))
    {
        Ok(a) => Ok(a),
        Err(smb1_err) => Err(anyhow!(
            "{}:{} refused both the SMB2 and SMB1 negotiate (SMB2: {}; SMB1: {}) — \
             port filtered, a non-SMB service, or a host that dropped the probe",
            ip, port, smb2_err, smb1_err
        )),
    }
}

/// One negotiate round-trip: connect, patch the NetBIOS length into `req`,
/// send it, and return the response body (everything after the 4-byte NetBIOS
/// header). Errors are phrased as verdicts so the caller can chain attempts.
async fn negotiate_once(addr: SocketAddr, req: &[u8], dur: Duration) -> Result<Vec<u8>> {
    let mut s = timeout(dur, TcpStream::connect(addr)).await??;

    let mut req = req.to_vec();
    let body_len = (req.len() - 4) as u32;
    req[1] = ((body_len >> 16) & 0xff) as u8;
    req[2] = ((body_len >> 8) & 0xff) as u8;
    req[3] = (body_len & 0xff) as u8;
    timeout(dur, s.write_all(&req)).await??;

    // Read NetBIOS header (4B) then the body. A host that accepts the TCP
    // connect and then RSTs the negotiate becomes a clear verdict here rather
    // than a bare I/O error (lab bug: "bogus SMB response length 1").
    let mut nbhdr = [0u8; 4];
    timeout(dur, s.read_exact(&mut nbhdr))
        .await
        .map_err(|_| anyhow!("no SMB negotiate reply within timeout"))?
        .map_err(|e| anyhow!("peer dropped the SMB negotiate ({})", e))?;
    // A NetBIOS session message has message-type 0x00; anything else — or an
    // implausible body length — means the peer isn't speaking SMB here.
    let resp_len =
        (((nbhdr[1] as u32) << 16) | ((nbhdr[2] as u32) << 8) | (nbhdr[3] as u32)) as usize;
    if nbhdr[0] != 0x00 || resp_len < 32 || resp_len > 8192 {
        return Err(anyhow!(
            "not a valid SMB negotiate (NetBIOS type=0x{:02x}, len={})",
            nbhdr[0], resp_len
        ));
    }
    let mut body = vec![0u8; resp_len];
    timeout(dur, s.read_exact(&mut body)).await??;
    Ok(body)
}

/// Parse a negotiate response body into a classified `SmbAudit`.
fn build_audit(body: &[u8]) -> Result<SmbAudit> {
    let mut a = SmbAudit::default();
    parse(body, &mut a)?;
    classify(&mut a);
    Ok(a)
}

fn parse(body: &[u8], a: &mut SmbAudit) -> Result<()> {
    if body.len() < 4 {
        return Err(anyhow!("body too short"));
    }
    if &body[0..4] == b"\xfeSMB" {
        // SMB2 SYNC header: 64 bytes. Then NEGOTIATE Response body
        // begins at offset 64.
        a.dialect = "SMB2+".into();
        if body.len() < 64 + 6 {
            return Ok(());
        }
        // Negotiate Response body layout (offset relative to body start):
        //   structure_size (2B)        @ 64
        //   security_mode (2B)         @ 66
        //   dialect_revision (2B)      @ 68
        //   …
        let security_mode = u16::from_le_bytes([body[66], body[67]]);
        let dialect_rev = u16::from_le_bytes([body[68], body[69]]);
        a.smb2_dialect_revision = Some(dialect_rev);
        a.dialect = format_dialect(dialect_rev);
        a.signing_enabled = security_mode & 0x0001 != 0;
        a.signing_required = security_mode & 0x0002 != 0;
        // SMB2 dialect 0x02ff is the special wildcard meaning "let's
        // re-negotiate" — server's saying it speaks SMB2 but wants
        // us to send a SMB2 NEGOTIATE next. For our purposes it
        // confirms SMB2+.
        Ok(())
    } else if &body[0..4] == b"\xffSMB" {
        // SMB1 NEGOTIATE Response.
        a.dialect = "SMBv1".into();
        a.smbv1_supported = true;
        // SMB1 NT-LM-0.12 response body starts at offset 32 (header)
        // + 1 (word_count). word_count = 17 for NTLM 0.12.
        // SecurityMode is at offset 33 + 4 = 37 (after dialect_index).
        if body.len() >= 38 {
            let sec_mode = body[37];
            a.signing_enabled = sec_mode & 0x04 != 0;
            a.signing_required = sec_mode & 0x08 != 0;
        }
        Ok(())
    } else {
        Err(anyhow!("not an SMB response"))
    }
}

fn format_dialect(rev: u16) -> String {
    match rev {
        0x0202 => "SMB 2.0.2".into(),
        0x0210 => "SMB 2.1".into(),
        0x0300 => "SMB 3.0".into(),
        0x0302 => "SMB 3.0.2".into(),
        0x0311 => "SMB 3.1.1".into(),
        0x02ff => "SMB2 wildcard (re-negotiate)".into(),
        _ => format!("SMB2 dialect 0x{:04x}", rev),
    }
}

fn classify(a: &mut SmbAudit) {
    if a.smbv1_supported {
        a.findings.push(
            "SMBv1 enabled — disable per MS17-010 (EternalBlue family) advisory".into(),
        );
    }
    if !a.signing_required {
        if a.signing_enabled {
            a.findings.push(
                "SMB signing enabled but not required — relay attacks possible".into(),
            );
        } else {
            a.findings
                .push("SMB signing disabled — NTLM relay trivially succeeds".into());
        }
    }
}

pub fn print_report(host: &str, port: u16, a: &SmbAudit) {
    use colored::*;
    println!();
    println!("{}", format!("SMB audit for {}:{}", host, port).bold());
    println!("  dialect : {}", a.dialect);
    println!("  signing : enabled={} required={}", a.signing_enabled, a.signing_required);
    if a.findings.is_empty() {
        println!("  {}", "no weaknesses detected".green());
    } else {
        println!("  {}", "weaknesses:".yellow().bold());
        for f in &a.findings {
            println!("    · {}", f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_smbv1_flagged() {
        let mut a = SmbAudit { smbv1_supported: true, signing_required: true, ..Default::default() };
        classify(&mut a);
        assert!(a.findings.iter().any(|f| f.contains("SMBv1")));
    }

    #[test]
    fn classify_no_signing_flagged() {
        let mut a = SmbAudit { signing_enabled: false, signing_required: false, ..Default::default() };
        classify(&mut a);
        assert!(a.findings.iter().any(|f| f.contains("relay")));
    }

    #[test]
    fn classify_clean_modern_smb3() {
        let mut a = SmbAudit {
            dialect: "SMB 3.1.1".into(),
            smb2_dialect_revision: Some(0x0311),
            signing_enabled: true,
            signing_required: true,
            ..Default::default()
        };
        classify(&mut a);
        assert!(a.findings.is_empty(), "{:?}", a.findings);
    }

    #[test]
    fn smb2_negotiate_request_well_formed() {
        let r = SMB2_NEGOTIATE_REQUEST;
        assert_eq!(&r[4..8], b"\xfeSMB", "SMB2 protocol id");
        assert_eq!(u16::from_le_bytes([r[8], r[9]]), 64, "header StructureSize");
        assert_eq!(u16::from_le_bytes([r[16], r[17]]), 0x0000, "NEGOTIATE command");
        assert_eq!(u16::from_le_bytes([r[68], r[69]]), 36, "body StructureSize");
        assert_eq!(u16::from_le_bytes([r[70], r[71]]), 5, "DialectCount");
        assert_eq!(
            u32::from_le_bytes([r[96], r[97], r[98], r[99]]),
            112,
            "NegotiateContextOffset points past the dialects + padding"
        );
        assert_eq!(u16::from_le_bytes([r[104], r[105]]), 0x0202, "first dialect 2.0.2");
        assert_eq!(u16::from_le_bytes([r[112], r[113]]), 0x0311, "last dialect 3.1.1");
        // Preauth context begins at byte 116 (SMB2 offset 112).
        assert_eq!(u16::from_le_bytes([r[116], r[117]]), 0x0001, "PREAUTH_INTEGRITY ctx");
        assert_eq!(r.len() - 4, 158, "SMB2 message length (excl. NetBIOS)");
    }

    #[test]
    fn dialect_label_known_codes() {
        assert_eq!(format_dialect(0x0311), "SMB 3.1.1");
        assert_eq!(format_dialect(0x0202), "SMB 2.0.2");
        assert!(format_dialect(0x9999).contains("0x9999"));
    }
}
