//! Microsoft SQL Server bruteforce via TDS 7.4 SQL Server
//! Authentication (cleartext-mode + the password-obfuscation
//! `swap-nibbles ⊕ 0xA5` step every TDS client uses).
//!
//! Flow per [MS-TDS] §3.3:
//!
//!   1. Send `PRELOGIN` packet (type=0x12) with a tiny option list
//!      (version 0x09000000, encryption 0x02 = NOT_SUP, instance "",
//!      threadid). Server replies with its options and an encryption
//!      preference — we ignore the preference and proceed with
//!      cleartext Login7 because we're only verifying credentials.
//!   2. Send `LOGIN7` (type=0x10) with the credentials. The password
//!      field is obfuscated: each byte's nibbles are swapped, then
//!      the byte is XOR'd with 0xA5. Despite the look, this is NOT
//!      encryption — it's a wire-format quirk.
//!   3. Server replies with either:
//!      - `LOGINACK` (token 0xAD) → success
//!      - `ERROR` (token 0xAA) with NTSTATUS / message → bad creds
//!
//! TDS over TCP/1433. Cleartext flow only — SSPI/NTLM SSO out of
//! scope here.

use crate::brute::{BruteAdapter, BruteConfig};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct MssqlAdapter {
    pub database: String,
}

impl Default for MssqlAdapter {
    fn default() -> Self {
        Self { database: "master".into() }
    }
}

#[async_trait]
impl BruteAdapter for MssqlAdapter {
    fn protocol(&self) -> &'static str { "mssql" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let mut s = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;

        // 1) PRELOGIN
        let prelogin = build_prelogin();
        timeout(cfg.timeout, s.write_all(&prelogin)).await??;
        let _prelogin_resp = read_tds_packet(&mut s, cfg.timeout).await?;

        // 2) LOGIN7
        let login = build_login7(user, pass, &self.database);
        timeout(cfg.timeout, s.write_all(&login)).await??;

        // 3) Server response — scan tokens for LOGINACK (0xAD) /
        //    ERROR (0xAA). Multiple packets may be needed if the
        //    server returns a large environment-change block, but
        //    one read usually suffices for auth result.
        let resp = read_tds_packet(&mut s, cfg.timeout).await?;
        Ok(classify_login_response(&resp))
    }
}

// ── PRELOGIN ──

pub fn build_prelogin() -> Vec<u8> {
    // Body: option list, each {token(1) offset(2) length(2)} terminated
    // by 0xFF, then the per-option data.
    //   0x00 VERSION  (6 bytes: 4 maj/min/build, 2 subbuild)
    //   0x01 ENCRYPTION (1 byte: 2 = NOT_SUP)
    //   0x02 INSTOPT (var: NUL-terminated instance name, empty here)
    //   0x03 THREADID (4 bytes)
    //   0xFF terminator
    let mut header_offsets = Vec::new();
    let mut data = Vec::new();

    // 4 options, header size = 4*(1+2+2) + 1 terminator = 21
    let header_size: u16 = 4 * 5 + 1;
    // VERSION at offset header_size, length 6
    let mut off = header_size;
    header_offsets.push((0x00u8, off, 6u16));
    data.extend_from_slice(&[0x09, 0x00, 0x00, 0x00, 0x00, 0x00]); // version 9.0.0.0
    off += 6;
    header_offsets.push((0x01u8, off, 1u16));
    data.push(0x02); // encryption = NOT_SUP
    off += 1;
    header_offsets.push((0x02u8, off, 1u16));
    data.push(0x00); // instance = ""
    off += 1;
    header_offsets.push((0x03u8, off, 4u16));
    data.extend_from_slice(&(std::process::id() as u32).to_be_bytes());
    let _ = off;

    let mut body = Vec::with_capacity(header_size as usize + data.len());
    for (tok, o, len) in &header_offsets {
        body.push(*tok);
        body.extend_from_slice(&o.to_be_bytes());
        body.extend_from_slice(&len.to_be_bytes());
    }
    body.push(0xff);
    body.extend_from_slice(&data);

    wrap_tds_packet(0x12, &body)
}

// ── LOGIN7 ──

pub fn build_login7(user: &str, password: &str, database: &str) -> Vec<u8> {
    let user_u: Vec<u8> = user.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let pass_obf: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .map(obfuscate_byte)
        .collect();
    let host_u: Vec<u8> = "rustymap".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let app_u: Vec<u8> = "RustyMap".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let srv_u: Vec<u8> = Vec::new();
    let lib_u: Vec<u8> = "rustymap-tds".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let lang_u: Vec<u8> = Vec::new();
    let db_u: Vec<u8> = database.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    // Fixed-length header is 36 bytes (Length thru ClientPID) +
    // 8 offset/length pairs of 4 bytes each = 36 + 8*4 = 68 bytes
    // header + ClientID(6) + offset/length tables for the variable
    // strings = larger.
    //
    // We use the canonical layout: 86-byte fixed prefix, then the
    // string offset table (each entry 2-byte offset + 2-byte length,
    // 10 entries = 40 bytes), then ClientID(6), then SSPI offset(4),
    // then variable strings.
    //
    // For simplicity (and matching the impacket reference) we lay out:
    //   fixed (94 bytes): Length, TDSVersion, PacketSize, Version,
    //                     ClientPID, ConnectionID, OptionFlags1-3,
    //                     TypeFlags, ClientTimeZone, ClientLCID,
    //                     offset table (10 entries of 4 bytes),
    //                     ClientID(6 bytes), SSPI offset(4),
    //                     SSPI length(2) — actually MS-TDS specifies
    //                     fixed = 86 bytes.
    //
    // We follow [MS-TDS] §2.2.6.3 LOGIN7. Hand-construct with care.

    let strings: [&[u8]; 9] = [
        &host_u,      // ibHostName
        &user_u,      // ibUserName
        &pass_obf,    // ibPassword
        &app_u,       // ibAppName
        &srv_u,       // ibServerName
        &[],          // unused
        &lib_u,       // ibCltIntName
        &lang_u,      // ibLanguage
        &db_u,        // ibDatabase
    ];

    let header_size: usize = 4 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 4 + 4 + 4
                            + 9 * 4   // 9 (offset/length) pairs
                            + 6       // ClientID
                            + 4       // SSPI offset/length (LE 4 bytes)
                            + 4       // ibAtchDBFile + cchAtchDBFile
                            + 4       // ibChangePassword + cchChangePassword
                            + 4;      // cbSSPILong
    // wait — the canonical layout is more delicate. Let me follow the
    // approach impacket uses: build with fixed-offset layout.

    // Reference layout from MS-TDS LOGIN7 §2.2.6.3 (we omit the ChangePassword
    // and SSPI long fields beyond their 4-byte zeros):
    //   bytes 0-3:   Length (back-patched)
    //   4-7:         TDSVersion = 0x74000004 (TDS 7.4)
    //   8-11:        PacketSize = 4096
    //   12-15:       ClientProgVer = 0x07000000
    //   16-19:       ClientPID
    //   20-23:       ConnectionID = 0
    //   24:          OptionFlags1 = 0xE0 (default DB / language / charset / FloatType / DumpLoad)
    //   25:          OptionFlags2 = 0x03 (Init lang fatal, ODBC on)
    //   26:          TypeFlags = 0x00
    //   27:          OptionFlags3 = 0x00
    //   28-31:       ClientTimeZone = 0
    //   32-35:       ClientLCID = 0
    //   36-85:       OffsetTable: 9 string entries × 4 bytes + 14 bytes
    //                            (ClientID 6 + SSPIoff/len 4 + AtchDB off/len 4)
    //   86…:         variable strings
    //
    // Total fixed header = 86 bytes.
    let _ = header_size;

    let fixed_size: u16 = 86;
    let mut header = Vec::with_capacity(86);
    header.extend_from_slice(&[0u8; 4]); // Length placeholder
    header.extend_from_slice(&0x74000004u32.to_le_bytes()); // TDSVersion 7.4
    header.extend_from_slice(&4096u32.to_le_bytes());       // PacketSize
    header.extend_from_slice(&0x07000000u32.to_le_bytes()); // ClientProgVer
    header.extend_from_slice(&(std::process::id() as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // ConnectionID
    header.push(0xE0);
    header.push(0x03);
    header.push(0x00);
    header.push(0x00);
    header.extend_from_slice(&0u32.to_le_bytes()); // ClientTimeZone
    header.extend_from_slice(&0u32.to_le_bytes()); // ClientLCID

    // Build the variable-data section + offset table
    let mut var_data: Vec<u8> = Vec::new();
    let mut offsets: Vec<(u16, u16)> = Vec::new(); // (offset, count-in-chars)
    let mut cursor: u16 = fixed_size;
    for s in &strings {
        offsets.push((cursor, (s.len() / 2) as u16));
        var_data.extend_from_slice(s);
        cursor += s.len() as u16;
    }

    // Append the 9 offset/length pairs (36 bytes)
    for (off, len) in &offsets {
        header.extend_from_slice(&off.to_le_bytes());
        header.extend_from_slice(&len.to_le_bytes());
    }
    // ClientID (6 bytes MAC)
    header.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    // ibSSPI / cbSSPI
    header.extend_from_slice(&cursor.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    // ibAtchDBFile / cchAtchDBFile
    header.extend_from_slice(&cursor.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(header.len(), fixed_size as usize);

    // Concatenate header + variable data
    let mut body = Vec::with_capacity(header.len() + var_data.len());
    body.extend_from_slice(&header);
    body.extend_from_slice(&var_data);
    // Patch the length field with the total size
    let total = body.len() as u32;
    body[0..4].copy_from_slice(&total.to_le_bytes());

    wrap_tds_packet(0x10, &body)
}

/// MS-TDS password obfuscation: swap nibbles, XOR 0xA5.
pub fn obfuscate_byte(b: u8) -> u8 {
    let swapped = (b >> 4) | (b << 4);
    swapped ^ 0xA5
}

// ── TDS framing ──

pub fn wrap_tds_packet(packet_type: u8, body: &[u8]) -> Vec<u8> {
    // Header is 8 bytes: type, status, length(2), spid(2), packetid(1), window(1)
    let total = 8 + body.len();
    let mut out = Vec::with_capacity(total);
    out.push(packet_type);
    out.push(0x01); // status = END_OF_MESSAGE
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // SPID
    out.push(0x01); // packet id
    out.push(0x00); // window
    out.extend_from_slice(body);
    out
}

async fn read_tds_packet(s: &mut TcpStream, dur: std::time::Duration) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 8];
    timeout(dur, s.read_exact(&mut hdr)).await??;
    let total = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if total < 8 || total > 65536 {
        return Err(anyhow!("bogus TDS packet length {}", total));
    }
    let mut body = vec![0u8; total - 8];
    timeout(dur, s.read_exact(&mut body)).await??;
    Ok(body)
}

/// Scan the body of the server's response. Token-stream rules:
///   0xAD = LOGINACK → success
///   0xAA = ERROR    → bad credentials (or other server-side error)
///   0xFD = DONE     → terminates the stream
/// Multiple tokens may precede LOGINACK in a successful response
/// (ENVCHANGE 0xE3, INFO 0xAB, etc.); we just look for AD vs AA.
pub fn classify_login_response(body: &[u8]) -> bool {
    let mut p = 0usize;
    while p < body.len() {
        let token = body[p];
        match token {
            0xAD => return true,           // LOGINACK
            0xAA => return false,          // ERROR
            // Tokens with a 2-byte length prefix that we can skip
            0xAB | 0xE3 | 0xAE | 0xAC | 0xA9 => {
                if p + 3 > body.len() {
                    return false;
                }
                let len = u16::from_le_bytes([body[p + 1], body[p + 2]]) as usize;
                p += 3 + len;
            }
            // DONE / DONEINPROC / DONEPROC are fixed 13 bytes
            0xFD | 0xFE | 0xFF => {
                if p + 13 > body.len() {
                    return false;
                }
                p += 13;
            }
            _ => return false, // unknown / unexpected
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscate_known_vector() {
        // Nmap mssql-brute uses the same algorithm. 'p' = 0x70 →
        // swap → 0x07 → XOR 0xA5 → 0xA2.
        assert_eq!(obfuscate_byte(b'p'), 0xA2);
        // '\0' = 0x00 → swap 0x00 → XOR 0xA5 → 0xA5
        assert_eq!(obfuscate_byte(0x00), 0xA5);
        // 0xFF → swap 0xFF → XOR 0xA5 → 0x5A
        assert_eq!(obfuscate_byte(0xFF), 0x5A);
    }

    #[test]
    fn obfuscate_round_trip_via_double_application() {
        // The TDS obfuscation is NOT involutive in general, but the
        // operation `swap_nibbles(b ^ 0xA5) ^ 0xA5` reverses it.
        for b in [0u8, 1, 0x5A, 0xA5, 0xff] {
            let enc = obfuscate_byte(b);
            // Decode: XOR 0xA5 then swap nibbles
            let xored = enc ^ 0xA5;
            let dec = (xored >> 4) | (xored << 4);
            assert_eq!(dec, b, "round-trip failed for {:#x}", b);
        }
    }

    #[test]
    fn prelogin_packet_starts_with_type_and_status() {
        let p = build_prelogin();
        assert_eq!(p[0], 0x12);
        assert_eq!(p[1], 0x01);
        let len = u16::from_be_bytes([p[2], p[3]]) as usize;
        assert_eq!(len, p.len());
    }

    #[test]
    fn prelogin_body_contains_version_option() {
        let p = build_prelogin();
        // First option token after the 8-byte TDS header should be 0x00 (VERSION)
        assert_eq!(p[8], 0x00);
    }

    #[test]
    fn login7_packet_type_and_tds_version() {
        let p = build_login7("alice", "secret", "master");
        assert_eq!(p[0], 0x10);
        // TDS version 0x74000004 at offset 8+4 (after 8-byte header + Length)
        let tds_ver = u32::from_le_bytes([p[12], p[13], p[14], p[15]]);
        assert_eq!(tds_ver, 0x74000004);
    }

    #[test]
    fn login7_obfuscates_password() {
        let p = build_login7("u", "p", "db");
        // 'p' in UTF-16LE is two bytes: 0x70 0x00. Obfuscated:
        // 0x70 → 0xA2, 0x00 → 0xA5.
        let needle = [0xA2u8, 0xA5];
        assert!(p.windows(2).any(|w| w == needle));
    }

    #[test]
    fn classify_loginack_success() {
        // Synthetic LOGINACK token preceded by a single ENVCHANGE
        // ENVCHANGE: 0xE3 [len LE u16] [body of len bytes]
        let mut body: Vec<u8> = vec![0xE3, 0x05, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        body.push(0xAD); // LOGINACK — we hit this and return true
        assert!(classify_login_response(&body));
    }

    #[test]
    fn classify_error_token_means_failure() {
        let body = vec![0xAA, 0x00, 0x00, 0x00];
        assert!(!classify_login_response(&body));
    }

    #[test]
    fn classify_empty_stream_means_failure() {
        assert!(!classify_login_response(&[]));
    }
}
