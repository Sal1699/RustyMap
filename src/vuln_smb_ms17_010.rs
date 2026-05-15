//! SMB MS17-010 / EternalBlue vulnerability indicator (CVE-2017-0143
//! through CVE-2017-0148).
//!
//! Send a SMBv1 NEGOTIATE → Session Setup → Tree Connect to
//! `\\<host>\IPC$`, then a TRANS2 SESSION_SETUP (subcommand 0x000E)
//! and inspect the NT_STATUS in the reply. The signal:
//!
//!   - **0xC0000205 STATUS_INSUFF_SERVER_RESOURCES** → patch missing,
//!     vulnerable host (the trans2 handler tries to allocate the
//!     pool the exploit later sprays).
//!   - **0xC0000002 STATUS_NOT_IMPLEMENTED** → patched: the missing
//!     subcommand is rejected cleanly.
//!   - **0xC000000D STATUS_INVALID_PARAMETER** → patched (newer
//!     reply for the same probe).
//!
//! Read-only: we never send the exploit follow-up, just the probe
//! that triggers the diagnostic status. This is exactly what nmap's
//! `smb-vuln-ms17-010.nse` does.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Ms17010Status {
    Vulnerable,
    Patched,
    Unknown,
    NotSmb,
}

impl Ms17010Status {
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            Ms17010Status::Vulnerable => "VULNERABLE",
            Ms17010Status::Patched => "PATCHED",
            Ms17010Status::Unknown => "UNKNOWN",
            Ms17010Status::NotSmb => "NOT_SMB",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ms17010Finding {
    pub host: String,
    pub port: u16,
    pub status: Ms17010Status,
    pub nt_status: Option<u32>,
}

const STATUS_INSUFF_SERVER_RESOURCES: u32 = 0xC0000205;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC0000002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;

pub async fn probe(host: IpAddr, port: u16, dur: Duration) -> Result<Ms17010Finding> {
    let addr = SocketAddr::new(host, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await??;

    // ── SMBv1 NEGOTIATE ──
    let neg = smbv1_negotiate();
    timeout(dur, s.write_all(&neg)).await??;
    let neg_resp = read_nbt(&mut s, dur).await?;
    if !smb_signature_ok(&neg_resp) {
        return Ok(Ms17010Finding {
            host: host.to_string(),
            port,
            status: Ms17010Status::NotSmb,
            nt_status: None,
        });
    }

    // ── Session Setup ANDX (anonymous, no NTLM) ──
    let setup = smbv1_session_setup_anon();
    timeout(dur, s.write_all(&setup)).await??;
    let setup_resp = read_nbt(&mut s, dur).await?;
    let user_id = parse_uid(&setup_resp).unwrap_or(0);

    // ── Tree Connect ANDX to \\<ip>\IPC$ ──
    let tcon = smbv1_tree_connect_ipc(user_id, &host.to_string());
    timeout(dur, s.write_all(&tcon)).await??;
    let tcon_resp = read_nbt(&mut s, dur).await?;
    let tree_id = parse_tid(&tcon_resp).unwrap_or(0);

    // ── TRANS2 SESSION_SETUP subcommand (0x000E) — the probe ──
    let trans2 = smbv1_trans2_session_setup(user_id, tree_id);
    timeout(dur, s.write_all(&trans2)).await??;
    let probe_resp = read_nbt(&mut s, dur).await?;
    let nt_status = parse_nt_status(&probe_resp);

    let status = match nt_status {
        Some(STATUS_INSUFF_SERVER_RESOURCES) => Ms17010Status::Vulnerable,
        Some(STATUS_NOT_IMPLEMENTED) | Some(STATUS_INVALID_PARAMETER) => Ms17010Status::Patched,
        Some(_) => Ms17010Status::Unknown,
        None => Ms17010Status::Unknown,
    };

    Ok(Ms17010Finding {
        host: host.to_string(),
        port,
        status,
        nt_status,
    })
}

// ── Packet builders ───────────────────────────────────────────────

fn smb_header(command: u8, flags2: u16, tid: u16, uid: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(32);
    h.extend_from_slice(b"\xffSMB");
    h.push(command);
    h.extend_from_slice(&[0u8; 4]); // status
    h.push(0x18);                    // flags
    h.extend_from_slice(&flags2.to_le_bytes());
    h.extend_from_slice(&[0u8; 2]);  // PID high
    h.extend_from_slice(&[0u8; 8]);  // signature
    h.extend_from_slice(&[0u8; 2]);  // reserved
    h.extend_from_slice(&tid.to_le_bytes());
    h.extend_from_slice(&[0x2f, 0x4b]); // pid
    h.extend_from_slice(&uid.to_le_bytes());
    h.extend_from_slice(&[0xc5, 0x5e]); // mid
    h
}

fn wrap_nbt(smb: Vec<u8>) -> Vec<u8> {
    let body_len = smb.len() as u32;
    let mut out = Vec::with_capacity(4 + smb.len());
    out.push(0x00);
    out.push(((body_len >> 16) & 0xff) as u8);
    out.push(((body_len >> 8) & 0xff) as u8);
    out.push((body_len & 0xff) as u8);
    out.extend(smb);
    out
}

fn smbv1_negotiate() -> Vec<u8> {
    let mut pkt = smb_header(0x72, 0xc853, 0, 0);
    pkt.push(0x00); // word_count
    pkt.extend_from_slice(&[0x0c, 0x00]); // byte_count = 12
    pkt.push(0x02);
    pkt.extend_from_slice(b"NT LM 0.12\x00");
    wrap_nbt(pkt)
}

fn smbv1_session_setup_anon() -> Vec<u8> {
    // Anonymous, no security blob, no NTLM. Matches the layout used
    // by the original Microsoft probe scripts.
    let mut pkt = smb_header(0x73, 0xc853, 0, 0);
    pkt.push(13); // word_count
    pkt.extend_from_slice(&[
        0xff, 0x00, // AndXCommand / Reserved
        0x00, 0x00, // AndXOffset
        0xff, 0xff, // MaxBuffer
        0x02, 0x00, // MaxMpx
        0x01, 0x00, // VC
        0x00, 0x00, 0x00, 0x00, // SessionKey
        0x00, 0x00, // ANSI pass len
        0x00, 0x00, // Unicode pass len
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x40, 0x00, 0x00, 0x00, // Capabilities (NT status + Unicode)
    ]);
    // ByteCount + strings: "" username, "" workgroup, "rustymap" os, "rustymap" lan
    let strings = b"\x00rustymap\x00rustymap\x00";
    pkt.extend_from_slice(&(strings.len() as u16).to_le_bytes());
    pkt.extend_from_slice(strings);
    wrap_nbt(pkt)
}

fn smbv1_tree_connect_ipc(uid: u16, target_ip: &str) -> Vec<u8> {
    let mut pkt = smb_header(0x75, 0xc853, 0, uid);
    pkt.push(4); // word_count
    pkt.extend_from_slice(&[0xff, 0x00, 0x00, 0x00]); // AndX / Reserved / Offset
    pkt.extend_from_slice(&0x0000u16.to_le_bytes()); // Flags
    pkt.extend_from_slice(&0x0001u16.to_le_bytes()); // Password length = 1 (just a NUL)

    let path = format!("\\\\{}\\IPC$", target_ip);
    let path_bytes = path.as_bytes();
    let service = b"?????";

    // ByteCount = 1 (password) + path + NUL + service + NUL
    let bc = 1 + path_bytes.len() + 1 + service.len() + 1;
    pkt.extend_from_slice(&(bc as u16).to_le_bytes());
    pkt.push(0x00); // password (NUL)
    pkt.extend_from_slice(path_bytes);
    pkt.push(0x00);
    pkt.extend_from_slice(service);
    pkt.push(0x00);
    wrap_nbt(pkt)
}

/// TRANS2 SESSION_SETUP — subcommand 0x000E. Vulnerable hosts return
/// STATUS_INSUFF_SERVER_RESOURCES; patched return NOT_IMPLEMENTED /
/// INVALID_PARAMETER.
fn smbv1_trans2_session_setup(uid: u16, tid: u16) -> Vec<u8> {
    let mut pkt = smb_header(0x32, 0xc807, tid, uid); // 0x32 = TRANS2
    // TRANS2 has word_count = 15 + setup_count*2; we use setup_count=1
    // for the SESSION_SETUP subcommand.
    pkt.push(15);
    pkt.extend_from_slice(&0u16.to_le_bytes()); // TotalParameterCount
    pkt.extend_from_slice(&0u16.to_le_bytes()); // TotalDataCount
    pkt.extend_from_slice(&0u16.to_le_bytes()); // MaxParameterCount
    pkt.extend_from_slice(&0u16.to_le_bytes()); // MaxDataCount
    pkt.push(0x00); // MaxSetupCount
    pkt.push(0x00); // Reserved
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Flags
    pkt.extend_from_slice(&0u32.to_le_bytes()); // Timeout
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    pkt.extend_from_slice(&0u16.to_le_bytes()); // ParameterCount
    pkt.extend_from_slice(&0x004au16.to_le_bytes()); // ParameterOffset
    pkt.extend_from_slice(&0u16.to_le_bytes()); // DataCount
    pkt.extend_from_slice(&0x004au16.to_le_bytes()); // DataOffset
    pkt.push(0x01); // SetupCount
    pkt.push(0x00); // Reserved3
    pkt.extend_from_slice(&0x000eu16.to_le_bytes()); // Subcommand = SESSION_SETUP
    pkt.extend_from_slice(&0x0000u16.to_le_bytes()); // ByteCount
    wrap_nbt(pkt)
}

// ── Parsers ───────────────────────────────────────────────────────

async fn read_nbt(s: &mut TcpStream, dur: Duration) -> Result<Vec<u8>> {
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

fn smb_signature_ok(body: &[u8]) -> bool {
    body.len() >= 4 && &body[0..4] == b"\xffSMB"
}

fn parse_nt_status(body: &[u8]) -> Option<u32> {
    if body.len() < 9 || &body[0..4] != b"\xffSMB" {
        return None;
    }
    // Status field is at offset 5..9 (after \xffSMB + command byte at 4)
    Some(u32::from_le_bytes([body[5], body[6], body[7], body[8]]))
}

fn parse_uid(body: &[u8]) -> Option<u16> {
    if body.len() < 30 || &body[0..4] != b"\xffSMB" {
        return None;
    }
    Some(u16::from_le_bytes([body[28], body[29]]))
}

fn parse_tid(body: &[u8]) -> Option<u16> {
    if body.len() < 26 || &body[0..4] != b"\xffSMB" {
        return None;
    }
    Some(u16::from_le_bytes([body[24], body[25]]))
}

pub fn print_finding(f: &Ms17010Finding) {
    use colored::*;
    println!();
    let nt = f.nt_status.map(|s| format!("0x{:08X}", s)).unwrap_or_else(|| "—".into());
    let label = match f.status {
        Ms17010Status::Vulnerable => "VULNERABLE".red().bold().to_string(),
        Ms17010Status::Patched => "PATCHED".green().to_string(),
        Ms17010Status::Unknown => "UNKNOWN".yellow().to_string(),
        Ms17010Status::NotSmb => "NOT_SMB".dimmed().to_string(),
    };
    println!(
        "{}",
        format!("MS17-010 probe on {}:{} → {}  (NT_STATUS {})", f.host, f.port, label, nt).bold()
    );
    if matches!(f.status, Ms17010Status::Vulnerable) {
        println!(
            "  {}",
            "Patch MS17-010 immediately. Family: EternalBlue / EternalRomance / \
             EternalSynergy / EternalChampion (CVE-2017-0143…0148)"
                .red()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb_negotiate_starts_with_nbt_and_smb_signature() {
        let pkt = smbv1_negotiate();
        // NBT header: 4 bytes; smb sig at offset 4..8
        assert_eq!(pkt[0], 0x00);
        assert_eq!(&pkt[4..8], b"\xffSMB");
        // Command byte at offset 8 (NBT+SMB sig+command) = 0x72 NEGOTIATE
        assert_eq!(pkt[8], 0x72);
    }

    #[test]
    fn trans2_subcommand_is_session_setup() {
        let pkt = smbv1_trans2_session_setup(0xAABB, 0xCCDD);
        // The subcommand word sits inside the SMB body. We locate it by
        // scanning for the 0x0e 0x00 little-endian pattern which we
        // emit only once.
        let needle = [0x0e, 0x00];
        let count = pkt.windows(2).filter(|w| *w == needle).count();
        assert!(count >= 1, "subcommand 0x000E should appear in the packet");
    }

    #[test]
    fn parse_nt_status_extracts_le_word() {
        let body = b"\xffSMBx\x05\x02\x00\xC0";
        assert_eq!(parse_nt_status(body), Some(0xC0000205));
    }

    #[test]
    fn parse_nt_status_rejects_non_smb() {
        assert_eq!(parse_nt_status(b"junk"), None);
        assert_eq!(parse_nt_status(b""), None);
    }

    #[test]
    fn smb_signature_ok_recognises_marker() {
        assert!(smb_signature_ok(b"\xffSMBdata"));
        assert!(!smb_signature_ok(b"\xfeSMBdata"));
        assert!(!smb_signature_ok(b"\xff"));
    }
}
