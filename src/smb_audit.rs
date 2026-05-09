//! SMB version + signing audit — parses the SMB Negotiate Protocol
//! Response.
//!
//! We send a SMBv1 NegotiateProtocolRequest listing both SMB1 and
//! SMB2 dialects. The server picks the highest it supports:
//!   - SMB2+ servers respond with a 0xfe-headed packet (SMB2 SYNC
//!     header) — we parse the SecurityMode flags to learn whether
//!     signing is enabled and whether it's *required*.
//!   - SMB1-only servers respond with a 0xff-headed packet — that
//!     answer alone is a finding (SMBv1 is deprecated, EternalBlue
//!     family targets it).
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

pub async fn audit(ip: IpAddr, port: u16, dur: Duration) -> Result<SmbAudit> {
    let addr = SocketAddr::new(ip, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await??;

    // Patch NetBIOS length = body_len.
    let mut req = NEGOTIATE_REQUEST.to_vec();
    let body_len = (req.len() - 4) as u32;
    req[1] = ((body_len >> 16) & 0xff) as u8;
    req[2] = ((body_len >> 8) & 0xff) as u8;
    req[3] = (body_len & 0xff) as u8;

    timeout(dur, s.write_all(&req)).await??;

    // Read NetBIOS header (4B) then the body.
    let mut nbhdr = [0u8; 4];
    timeout(dur, s.read_exact(&mut nbhdr)).await??;
    let resp_len = (((nbhdr[1] as u32) << 16) | ((nbhdr[2] as u32) << 8) | (nbhdr[3] as u32)) as usize;
    if resp_len < 32 || resp_len > 4096 {
        return Err(anyhow!("bogus SMB response length {}", resp_len));
    }
    let mut body = vec![0u8; resp_len];
    timeout(dur, s.read_exact(&mut body)).await??;

    let mut a = SmbAudit::default();
    parse(&body, &mut a)?;
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
    fn dialect_label_known_codes() {
        assert_eq!(format_dialect(0x0311), "SMB 3.1.1");
        assert_eq!(format_dialect(0x0202), "SMB 2.0.2");
        assert!(format_dialect(0x9999).contains("0x9999"));
    }
}
