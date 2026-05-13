//! SMB pre-auth deep enumeration via NTLMSSP CHALLENGE.
//!
//! Builds on `smb_audit::audit` (which does the dialect negotiation)
//! by going one step further: send an SMBv1 Session Setup ANDX
//! request carrying an NTLMSSP **NEGOTIATE** (Type 1) blob. A
//! domain-joined Windows host or Samba server responds with an
//! NTLMSSP **CHALLENGE** (Type 2) packet packed with identifying
//! information:
//!
//!   - NetBIOS computer name
//!   - NetBIOS domain
//!   - DNS computer FQDN
//!   - DNS domain
//!   - DNS forest
//!   - Server version (major.minor.build) — fingerprints Windows
//!     edition / Samba release
//!
//! Read-only — we never send the CHALLENGE response, so no auth
//! attempt is made. The whole exchange is the same one a Windows
//! client does before it has any credentials to try.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SmbDeepInfo {
    pub host: String,
    pub port: u16,
    pub netbios_computer: Option<String>,
    pub netbios_domain: Option<String>,
    pub dns_computer: Option<String>,
    pub dns_domain: Option<String>,
    pub dns_forest: Option<String>,
    pub os_version: Option<String>,
    pub timestamp_filetime: Option<u64>,
}

const NTLMSSP_SIG: &[u8] = b"NTLMSSP\0";

pub async fn deep_enum(host: IpAddr, port: u16, dur: Duration) -> Result<Option<SmbDeepInfo>> {
    let addr = SocketAddr::new(host, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await??;

    // 1) SMBv1 NEGOTIATE — reuse the canonical packet from smb_audit.
    let neg = build_smbv1_negotiate();
    timeout(dur, s.write_all(&neg)).await??;
    let _neg_resp = read_nbt_response(&mut s, dur).await?; // discarded

    // 2) Session Setup ANDX with NTLMSSP Type 1 (NEGOTIATE).
    let setup = build_session_setup_ntlmssp();
    timeout(dur, s.write_all(&setup)).await??;
    let setup_resp = read_nbt_response(&mut s, dur).await?;
    let chal = match locate_ntlmssp_challenge(&setup_resp) {
        Some(c) => c,
        None => return Ok(None),
    };

    let info = parse_challenge(chal, host, port);
    Ok(Some(info))
}

fn build_smbv1_negotiate() -> Vec<u8> {
    // Equivalent of the canonical request: NetBIOS header + SMB header
    // + dialect list listing "NT LM 0.12" so the server responds with
    // SMBv1 (otherwise SMBv2 servers downgrade and we can still
    // continue with NTLMSSP in v2). Same as smb_audit module but
    // duplicated here to keep modules orthogonal.
    let mut pkt: Vec<u8> = Vec::with_capacity(80);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NetBIOS hdr length filled later
    // SMB header
    pkt.extend_from_slice(b"\xffSMB"); // protocol
    pkt.push(0x72); // command NEGOTIATE
    pkt.extend_from_slice(&[0, 0, 0, 0]); // status
    pkt.push(0x18); // flags
    pkt.extend_from_slice(&[0x53, 0xc8]); // flags2
    pkt.extend_from_slice(&[0, 0]); // PIDhigh
    pkt.extend_from_slice(&[0; 8]); // signature
    pkt.extend_from_slice(&[0, 0]); // reserved
    pkt.extend_from_slice(&[0, 0]); // tid
    pkt.extend_from_slice(&[0x2f, 0x4b]); // pid
    pkt.extend_from_slice(&[0, 0]); // uid
    pkt.extend_from_slice(&[0xc5, 0x5e]); // mid
    // body
    pkt.push(0x00); // word_count
    pkt.extend_from_slice(&[0x0c, 0x00]); // byte_count = 12
    pkt.push(0x02);
    pkt.extend_from_slice(b"NT LM 0.12\x00");

    // Patch NetBIOS length = total - 4 (NBT header itself)
    let body_len = (pkt.len() - 4) as u32;
    pkt[1] = ((body_len >> 16) & 0xff) as u8;
    pkt[2] = ((body_len >> 8) & 0xff) as u8;
    pkt[3] = (body_len & 0xff) as u8;
    pkt
}

fn build_session_setup_ntlmssp() -> Vec<u8> {
    // Session Setup ANDX (cmd 0x73) with extended security on. Body
    // carries an NTLMSSP NEGOTIATE blob (Type 1) requesting unicode +
    // NTLM v2 + version-info echo back. The exact byte sequence is
    // well-known from impacket and other open-source tools.
    let ntlmssp: Vec<u8> = vec![
        // Signature
        b'N', b'T', b'L', b'M', b'S', b'S', b'P', 0,
        // Type = 1 (NEGOTIATE)
        0x01, 0x00, 0x00, 0x00,
        // Flags: NEGOTIATE_UNICODE | OEM | TARGET | NTLM | LM_KEY | NTLM2 |
        //        ALWAYS_SIGN | EXTENDED_SECURITY | TARGET_INFO | VERSION |
        //        UNICODE | 128 | 56
        0x07, 0x82, 0x08, 0xa2,
        // DomainName fields (length/maxLen/offset)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // WorkstationName fields
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Version (major=10, minor=0, build=19041, reserved, NTLM revision=15)
        0x0a, 0x00, 0x00, 0x00, 0xa1, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
    ];

    let mut body: Vec<u8> = Vec::with_capacity(64 + ntlmssp.len());
    // Session Setup ANDX has word_count = 12, byte_count = variable.
    body.push(12); // word_count
    // AndXCommand=0xFF, AndXReserved=0, AndXOffset, MaxBufferSize, MaxMpxCount,
    // VcNumber, SessionKey, SecurityBlobLength, Reserved, Capabilities
    body.extend_from_slice(&[
        0xff, 0x00, // AndXCommand / Reserved
        0x00, 0x00, // AndXOffset (patched? we leave 0 — server tolerates)
        0xff, 0xff, // MaxBufferSize
        0x02, 0x00, // MaxMpxCount
        0x01, 0x00, // VcNumber
        0x00, 0x00, 0x00, 0x00, // SessionKey
    ]);
    let sec_blob_len = ntlmssp.len() as u16;
    body.extend_from_slice(&sec_blob_len.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved
    body.extend_from_slice(&0xd4_u32.to_le_bytes()); // Capabilities (ext sec + unicode + nt status)

    // byte_count
    body.extend_from_slice(&sec_blob_len.to_le_bytes());
    body.extend_from_slice(&ntlmssp);
    body.extend_from_slice(b"\x00"); // padding for native OS / lan-man strings (skipped)

    // SMB header — copy from negotiate, change command to 0x73
    let mut pkt = build_smbv1_negotiate();
    // Strip the negotiate body — header is 32B + 4B NBT = 36B
    pkt.truncate(36);
    pkt[8] = 0x73; // command = Session Setup ANDX
    // Reset flags2 to include extended security (0xC853 → 0xC807 puts ext-sec bit)
    pkt[15] = 0x07;
    pkt[14] = 0xc8;
    pkt.extend_from_slice(&body);
    // Patch NetBIOS length
    let body_len = (pkt.len() - 4) as u32;
    pkt[1] = ((body_len >> 16) & 0xff) as u8;
    pkt[2] = ((body_len >> 8) & 0xff) as u8;
    pkt[3] = (body_len & 0xff) as u8;
    pkt
}

async fn read_nbt_response(s: &mut TcpStream, dur: Duration) -> Result<Vec<u8>> {
    let mut nbt = [0u8; 4];
    timeout(dur, s.read_exact(&mut nbt)).await??;
    let len = (((nbt[1] as u32) << 16) | ((nbt[2] as u32) << 8) | (nbt[3] as u32)) as usize;
    if len == 0 || len > 65535 {
        return Err(anyhow!("bogus NBT length {}", len));
    }
    let mut body = vec![0u8; len];
    timeout(dur, s.read_exact(&mut body)).await??;
    Ok(body)
}

/// The NTLMSSP CHALLENGE blob is embedded inside a GSSAPI wrapper
/// inside the Session Setup response body. We don't parse the
/// containing structures — we just scan for the `NTLMSSP\0` magic
/// and treat what follows as a Type 2 message.
fn locate_ntlmssp_challenge(body: &[u8]) -> Option<&[u8]> {
    let pos = body.windows(NTLMSSP_SIG.len()).position(|w| w == NTLMSSP_SIG)?;
    let slice = &body[pos..];
    // Type field is at offset 8 — must be 2 (CHALLENGE)
    if slice.len() < 12 {
        return None;
    }
    let msg_type = u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]);
    if msg_type != 2 {
        return None;
    }
    Some(slice)
}

fn read_u16(b: &[u8], p: usize) -> Option<u16> {
    if p + 2 > b.len() { return None; }
    Some(u16::from_le_bytes([b[p], b[p+1]]))
}

fn read_u32(b: &[u8], p: usize) -> Option<u32> {
    if p + 4 > b.len() { return None; }
    Some(u32::from_le_bytes([b[p], b[p+1], b[p+2], b[p+3]]))
}

fn parse_challenge(blob: &[u8], host: IpAddr, port: u16) -> SmbDeepInfo {
    let mut info = SmbDeepInfo {
        host: host.to_string(),
        port,
        ..Default::default()
    };

    // CHALLENGE layout (offsets relative to blob start):
    //   0..8   "NTLMSSP\0"
    //   8..12  msg type = 2
    //   12..14 TargetName length
    //   14..16 TargetName maxLen
    //   16..20 TargetName offset
    //   20..24 Flags
    //   24..32 Challenge (8B)
    //   32..40 Reserved
    //   40..42 TargetInfo length
    //   42..44 TargetInfo maxLen
    //   44..48 TargetInfo offset
    //   48..56 Version (major.minor.build + reserved)
    if blob.len() < 56 {
        return info;
    }

    // Server version: bytes 48..52 → major / minor / build / reserved
    let major = blob[48];
    let minor = blob[49];
    let build = u16::from_le_bytes([blob[50], blob[51]]);
    if major != 0 || minor != 0 || build != 0 {
        info.os_version = Some(format!("Windows {}.{} build {}", major, minor, build));
    }

    let target_info_len = read_u16(blob, 40).unwrap_or(0) as usize;
    let target_info_off = read_u32(blob, 44).unwrap_or(0) as usize;
    if target_info_len > 0
        && target_info_off + target_info_len <= blob.len()
    {
        parse_target_info(&blob[target_info_off..target_info_off + target_info_len], &mut info);
    }

    info
}

/// TargetInfo is a series of AV-pairs:
///   - 2B AvId
///   - 2B AvLen
///   - AvLen bytes value (UTF-16LE strings or FILETIME)
/// Terminated by AvId=0.
fn parse_target_info(av: &[u8], info: &mut SmbDeepInfo) {
    let mut p = 0usize;
    while p + 4 <= av.len() {
        let id = read_u16(av, p).unwrap_or(0);
        let len = read_u16(av, p + 2).unwrap_or(0) as usize;
        p += 4;
        if id == 0 {
            break;
        }
        if p + len > av.len() {
            break;
        }
        let value = &av[p..p + len];
        p += len;
        match id {
            1 => info.netbios_computer = Some(decode_utf16le(value)),
            2 => info.netbios_domain = Some(decode_utf16le(value)),
            3 => info.dns_computer = Some(decode_utf16le(value)),
            4 => info.dns_domain = Some(decode_utf16le(value)),
            5 => info.dns_forest = Some(decode_utf16le(value)),
            7 => {
                // FILETIME (8 bytes, LE)
                if value.len() == 8 {
                    let mut ts: u64 = 0;
                    for i in 0..8 {
                        ts |= (value[i] as u64) << (8 * i);
                    }
                    info.timestamp_filetime = Some(ts);
                }
            }
            _ => {}
        }
    }
}

fn decode_utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn print_finding(f: &SmbDeepInfo) {
    use colored::*;
    println!();
    println!("{}", format!("SMB deep info on {}:{}", f.host, f.port).bold());
    if let Some(s) = &f.netbios_computer {
        println!("  NetBIOS host  : {}", s);
    }
    if let Some(s) = &f.netbios_domain {
        println!("  NetBIOS domain: {}", s);
    }
    if let Some(s) = &f.dns_computer {
        println!("  DNS hostname  : {}", s);
    }
    if let Some(s) = &f.dns_domain {
        println!("  DNS domain    : {}", s);
    }
    if let Some(s) = &f.dns_forest {
        println!("  DNS forest    : {}", s);
    }
    if let Some(s) = &f.os_version {
        println!("  OS version    : {}", s.yellow());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_ntlmssp_challenge_finds_magic_with_type2() {
        let mut blob = vec![0u8; 60];
        let needle = b"NTLMSSP\0";
        let pos = 4;
        blob[pos..pos + needle.len()].copy_from_slice(needle);
        // Set msg type = 2 at offset+8
        blob[pos + 8] = 0x02;
        let found = locate_ntlmssp_challenge(&blob);
        assert!(found.is_some());
        assert_eq!(&found.unwrap()[0..8], needle);
    }

    #[test]
    fn locate_ntlmssp_challenge_rejects_wrong_type() {
        let mut blob = vec![0u8; 60];
        let needle = b"NTLMSSP\0";
        blob[..needle.len()].copy_from_slice(needle);
        blob[8] = 0x01; // NEGOTIATE, not CHALLENGE
        assert!(locate_ntlmssp_challenge(&blob).is_none());
    }

    #[test]
    fn decode_utf16le_round_trips_ascii() {
        let s = "HOSTNAME";
        let mut b = Vec::new();
        for c in s.encode_utf16() {
            b.extend_from_slice(&c.to_le_bytes());
        }
        assert_eq!(decode_utf16le(&b), s);
    }

    #[test]
    fn parse_target_info_extracts_av_pairs() {
        // Build a synthetic AV-pair stream: AvId 1 (NetBIOS computer) +
        // UTF-16LE "PC1", then terminator AvId 0.
        let s = "PC1";
        let mut av: Vec<u8> = Vec::new();
        av.extend_from_slice(&1u16.to_le_bytes());
        av.extend_from_slice(&(s.encode_utf16().count() as u16 * 2).to_le_bytes());
        for c in s.encode_utf16() {
            av.extend_from_slice(&c.to_le_bytes());
        }
        av.extend_from_slice(&0u16.to_le_bytes());
        av.extend_from_slice(&0u16.to_le_bytes());

        let mut info = SmbDeepInfo::default();
        parse_target_info(&av, &mut info);
        assert_eq!(info.netbios_computer.as_deref(), Some("PC1"));
    }
}
