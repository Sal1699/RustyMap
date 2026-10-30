//! Microsoft SQL Server bruteforce via TDS 7.4 SQL Server
//! Authentication (cleartext-mode credentials + the password-
//! obfuscation `swap-nibbles ⊕ 0xA5` step every TDS client applies).
//!
//! Flow per [MS-TDS] §3.3:
//!
//!   1. Send `PRELOGIN` (type=0x12) advertising **ENCRYPTION = ON**
//!      (0x01 = "encryption supported, use it"). Modern SQL Server
//!      (2016+/2022) always encrypts the login; advertising ON makes the
//!      server encrypt the WHOLE session, so the login response and all
//!      later traffic stay inside TLS — no mid-stream switch back to
//!      cleartext to trip over (advertising OFF negotiates *login-only*
//!      encryption, where the reply comes back in cleartext and a plain
//!      TLS read chokes on it). A legacy server with no cert replies
//!      NOT_SUP (0x02), for which we fall back to a cleartext LOGIN7.
//!   2. **TLS**, with a twist unique to TDS: during the handshake each
//!      TLS record is wrapped in a TDS `0x12` (PRELOGIN) packet. Once
//!      the handshake completes that framing stops — the LOGIN7 packet
//!      is handed to TLS as application data and the TLS records go on
//!      the wire raw (the TDS packet lives *inside* the encryption).
//!      We drive rustls' low-level `ClientConnection` by hand to switch
//!      framing at exactly the right point.
//!   3. Send `LOGIN7` (type=0x10) with the credentials over TLS. The
//!      password nibbles are swapped then XOR'd with 0xA5 — a wire
//!      quirk, NOT encryption.
//!   4. Server replies (encrypted) with either:
//!      - `LOGINACK` (token 0xAD) → success
//!      - `ERROR` (token 0xAA) with NTSTATUS / message → bad creds
//!
//! The reply is read defensively: normally it is TLS application data we
//! decrypt through rustls, but if the server did a login-only negotiation
//! and answered in cleartext we parse the raw TDS packet instead.
//!
//! TDS over TCP/1433. SQL Server Authentication only — Windows/SSPI
//! (NTLM/Kerberos) SSO is out of scope. `RUSTYMAP_MSSQL_DEBUG=1` traces
//! the negotiated encryption byte, the first post-login bytes on the wire
//! (TLS record vs cleartext TDS), and the login-response head.

use crate::brute::{BruteAdapter, BruteConfig};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::io::{Read, Write};
use std::sync::Arc;
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
        let debug = std::env::var_os("RUSTYMAP_MSSQL_DEBUG").is_some();
        let mut s = timeout(cfg.timeout, TcpStream::connect(cfg.target)).await??;

        // 1) PRELOGIN — advertise ENCRYPT_ON so the server encrypts the
        //    whole session (modern SQL Server rejects a cleartext login).
        let prelogin = build_prelogin();
        timeout(cfg.timeout, s.write_all(&prelogin)).await??;
        let prelogin_resp = read_tds_packet(&mut s, cfg.timeout).await?;
        let enc = parse_prelogin_encryption(&prelogin_resp);
        if debug {
            eprintln!("[mssql] server PRELOGIN ENCRYPTION = {:#04x}", enc);
        }

        let login = build_login7(user, pass, &self.database);

        // 2) Legacy no-encryption server → cleartext LOGIN7 (old path).
        if enc == ENCRYPT_NOT_SUP {
            if debug {
                eprintln!("[mssql] server NOT_SUP → cleartext LOGIN7");
            }
            timeout(cfg.timeout, s.write_all(&login)).await??;
            let resp = read_tds_packet(&mut s, cfg.timeout).await?;
            return Ok(classify_login_response(&resp));
        }

        // 3) TLS path: tunnel the handshake in TDS 0x12 packets, then
        //    send LOGIN7 as TLS application data and read the reply.
        let mut conn = tls_client_connection(&cfg.target.ip().to_string())?;
        tds_tls_handshake(&mut s, &mut conn, cfg.timeout).await?;
        if debug {
            eprintln!("[mssql] TLS handshake complete → LOGIN7 over TLS");
        }
        tls_send_app(&mut s, &mut conn, &login, cfg.timeout).await?;
        let resp = read_login_response(&mut s, &mut conn, cfg.timeout, debug).await?;
        if debug {
            let n = resp.len().min(48);
            let head: String = resp[..n].iter().map(|b| format!("{:02x}", b)).collect();
            eprintln!("[mssql] login resp {} body-bytes; head={}", resp.len(), head);
        }
        Ok(classify_login_response(&resp))
    }
}

// ── PRELOGIN ──

pub fn build_prelogin() -> Vec<u8> {
    // Body: option list, each {token(1) offset(2) length(2)} terminated
    // by 0xFF, then the per-option data.
    //   0x00 VERSION  (6 bytes: 4 maj/min/build, 2 subbuild)
    //   0x01 ENCRYPTION (1 byte: 1 = ON → encrypt the whole session)
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
    data.push(ENCRYPT_ON); // encryption = ON → server encrypts the whole session
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

// ── TDS-over-TLS ──
//
// SQL Server 2016+ encrypts the login. The TLS handshake records are
// each carried inside a TDS 0x12 (PRELOGIN) packet; after the handshake
// the TDS LOGIN7 packet is sent as TLS application data (raw TLS records
// on the wire). We drive rustls' low-level ClientConnection by hand so
// we own the framing switch precisely.

// PRELOGIN ENCRYPTION option values (MS-TDS). We advertise ON so the
// server encrypts the whole session (login response included); it
// replies ON (0x01) / REQ (0x03) — both "session encrypted" — or
// NOT_SUP (0x02) for a legacy server with no cert (cleartext fallback).
const ENCRYPT_ON: u8 = 0x01;
const ENCRYPT_NOT_SUP: u8 = 0x02;

/// Parse the server's PRELOGIN response body (TDS header already
/// stripped) and return its ENCRYPTION byte — the 1-byte value of
/// option token 0x01. Option offsets are relative to the body start.
/// Returns `ENCRYPT_NOT_SUP` if the option is absent/malformed.
pub fn parse_prelogin_encryption(body: &[u8]) -> u8 {
    let mut p = 0usize;
    while p + 5 <= body.len() {
        let token = body[p];
        if token == 0xFF {
            break;
        }
        let off = u16::from_be_bytes([body[p + 1], body[p + 2]]) as usize;
        let len = u16::from_be_bytes([body[p + 3], body[p + 4]]) as usize;
        if token == 0x01 && len >= 1 && off < body.len() {
            return body[off];
        }
        p += 5;
    }
    ENCRYPT_NOT_SUP
}

/// A rustls ClientConnection that accepts any server certificate — SQL
/// Server ships a self-signed cert by default and we're only checking a
/// password, not trusting the channel.
fn tls_client_connection(ip: &str) -> Result<rustls::ClientConnection> {
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
                 SignatureScheme::ED25519, SignatureScheme::RSA_PSS_SHA256,
                 SignatureScheme::RSA_PKCS1_SHA384, SignatureScheme::RSA_PKCS1_SHA512]
        }
    }
    let provider = rustls::crypto::ring::default_provider();
    let conf = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("rustls config: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Accept))
        .with_no_client_auth();
    let name = ServerName::try_from(ip.to_string()).map_err(|e| anyhow!("sni: {}", e))?;
    rustls::ClientConnection::new(Arc::new(conf), name).map_err(|e| anyhow!("rustls client: {}", e))
}

/// Drive the TLS handshake with each flight wrapped in a TDS 0x12 packet.
async fn tds_tls_handshake(
    sock: &mut TcpStream,
    conn: &mut rustls::ClientConnection,
    dur: std::time::Duration,
) -> Result<()> {
    loop {
        // Flush any pending handshake output as one TDS 0x12 packet.
        if conn.wants_write() {
            let mut out = Vec::new();
            while conn.wants_write() {
                conn.write_tls(&mut out)?;
            }
            if !out.is_empty() {
                timeout(dur, sock.write_all(&wrap_tds_packet(0x12, &out))).await??;
            }
        }
        if !conn.is_handshaking() {
            return Ok(());
        }
        // Read the next server flight (one TDS packet) and feed rustls.
        let body = read_tds_packet(sock, dur).await?;
        let mut cur = std::io::Cursor::new(&body[..]);
        while (cur.position() as usize) < body.len() {
            let n = conn.read_tls(&mut cur)?;
            if n == 0 {
                break;
            }
            conn.process_new_packets().map_err(|e| anyhow!("tls: {}", e))?;
        }
        conn.process_new_packets().map_err(|e| anyhow!("tls: {}", e))?;
    }
}

/// Send plaintext (a full TDS packet) as TLS application data — raw TLS
/// records on the wire, no more TDS 0x12 framing.
async fn tls_send_app(
    sock: &mut TcpStream,
    conn: &mut rustls::ClientConnection,
    plaintext: &[u8],
    dur: std::time::Duration,
) -> Result<()> {
    conn.writer().write_all(plaintext).map_err(|e| anyhow!("tls writer: {}", e))?;
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out)?;
    }
    if !out.is_empty() {
        timeout(dur, sock.write_all(&out)).await??;
    }
    Ok(())
}

/// Read the server's login response. With full-session encryption (we
/// advertise ENCRYPT_ON) the reply is TLS application data we decrypt
/// through rustls. As a safety net — in case the server negotiated
/// login-only encryption and answered in cleartext — we peek the first
/// byte off the socket: a TLS record (`0x14`–`0x17`, version `0x03xx`)
/// goes to rustls; a raw TDS packet (type byte such as `0x04`) is parsed
/// directly. Either way we return the token-stream body with the 8-byte
/// TDS header stripped.
async fn read_login_response(
    sock: &mut TcpStream,
    conn: &mut rustls::ClientConnection,
    dur: std::time::Duration,
    debug: bool,
) -> Result<Vec<u8>> {
    // First chunk off the socket decides the framing.
    let mut first = [0u8; 8192];
    let n = timeout(dur, sock.read(&mut first)).await??;
    if n == 0 {
        return Err(anyhow!("server closed before the TDS login response"));
    }
    if debug {
        let h: String = first[..n.min(16)].iter().map(|b| format!("{:02x}", b)).collect();
        let kind = if is_tls_record(&first[..n]) { "TLS record" } else { "cleartext TDS" };
        eprintln!("[mssql] post-login first {} socket bytes ({}); head={}", n, kind, h);
    }

    if !is_tls_record(&first[..n]) {
        // Login-only negotiation: the reply is a raw cleartext TDS packet.
        let mut plain = first[..n].to_vec();
        loop {
            if let Some(body) = take_tds_packet(&plain) {
                return Ok(body);
            }
            let mut buf = [0u8; 8192];
            let m = timeout(dur, sock.read(&mut buf)).await??;
            if m == 0 {
                return finish_partial(&plain);
            }
            plain.extend_from_slice(&buf[..m]);
        }
    }

    // Full-session encryption: decrypt the TLS records through rustls.
    let mut plain: Vec<u8> = Vec::new();
    let mut pending = first[..n].to_vec();
    loop {
        // Feed any socket bytes we are holding into rustls.
        if !pending.is_empty() {
            let mut cur = std::io::Cursor::new(&pending[..]);
            while (cur.position() as usize) < pending.len() {
                let rd = conn.read_tls(&mut cur)?;
                if rd == 0 {
                    break;
                }
                conn.process_new_packets().map_err(|e| anyhow!("tls: {}", e))?;
            }
            pending.clear();
        }
        // Drain whatever plaintext rustls now holds.
        loop {
            let mut tmp = [0u8; 4096];
            match conn.reader().read(&mut tmp) {
                Ok(0) => break,
                Ok(k) => plain.extend_from_slice(&tmp[..k]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(anyhow!("tls reader: {}", e)),
            }
        }
        if let Some(body) = take_tds_packet(&plain) {
            return Ok(body);
        }
        // Pull more TLS records off the socket.
        let mut buf = [0u8; 8192];
        let m = timeout(dur, sock.read(&mut buf)).await??;
        if m == 0 {
            return finish_partial(&plain);
        }
        pending.extend_from_slice(&buf[..m]);
    }
}

/// True if the buffer looks like the start of a TLS record: a content
/// type of `0x14` (ChangeCipherSpec) … `0x17` (ApplicationData) followed
/// by a `0x03xx` protocol version. A cleartext TDS packet starts with a
/// TDS type byte (e.g. `0x04` TABULAR_RESULT) that never falls in that
/// range, so the two are unambiguous.
fn is_tls_record(buf: &[u8]) -> bool {
    buf.len() >= 3 && (0x14..=0x17).contains(&buf[0]) && buf[1] == 0x03
}

/// If `plain` holds a complete TDS packet (8-byte header, big-endian
/// length at `[2..4]`), return its body with the header stripped.
fn take_tds_packet(plain: &[u8]) -> Option<Vec<u8>> {
    if plain.len() >= 8 {
        let total = u16::from_be_bytes([plain[2], plain[3]]) as usize;
        if total >= 8 && plain.len() >= total {
            return Some(plain[8..total].to_vec());
        }
    }
    None
}

/// The peer closed mid-response: salvage the body if we at least have a
/// TDS header, otherwise report the truncation.
fn finish_partial(plain: &[u8]) -> Result<Vec<u8>> {
    if plain.len() >= 8 {
        Ok(plain[8..].to_vec())
    } else {
        Err(anyhow!("server closed before the TDS login response"))
    }
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

    #[test]
    fn prelogin_advertises_encrypt_on() {
        // The client advertises ENCRYPT_ON so a modern server encrypts the
        // whole session (login response included), not just the login
        // packet — otherwise the reply comes back in cleartext and the
        // TLS read path chokes on it.
        let p = build_prelogin();
        assert_eq!(parse_prelogin_encryption(&p[8..]), ENCRYPT_ON);
    }

    #[test]
    fn is_tls_record_distinguishes_tls_from_cleartext_tds() {
        assert!(is_tls_record(&[0x17, 0x03, 0x03, 0x00, 0x20])); // TLS ApplicationData
        assert!(is_tls_record(&[0x16, 0x03, 0x01, 0x00])); // TLS Handshake
        assert!(!is_tls_record(&[0x04, 0x01, 0x00, 0x2b])); // cleartext TDS response
        assert!(!is_tls_record(&[0x17])); // too short to decide
    }

    #[test]
    fn take_tds_packet_needs_the_full_declared_length() {
        // Header declares total = 12 (0x000c BE at [2..4]); 4 body bytes.
        let pkt = vec![0x04, 0x01, 0x00, 0x0c, 0, 0, 1, 0, 0xAD, 0xBB, 0xCC, 0xDD];
        assert_eq!(take_tds_packet(&pkt), Some(vec![0xAD, 0xBB, 0xCC, 0xDD]));
        assert_eq!(take_tds_packet(&pkt[..10]), None); // body not fully arrived
        assert_eq!(take_tds_packet(&[0x04, 0x01]), None); // not even a header
    }

    #[test]
    fn parse_prelogin_encryption_reads_server_byte() {
        // One option: ENCRYPTION (0x01) at offset 6, len 1, value 0x03 (REQ).
        // 5-byte option entry + 0xFF terminator = 6 bytes; data at index 6.
        let body = vec![0x01, 0x00, 0x06, 0x00, 0x01, 0xFF, 0x03];
        assert_eq!(parse_prelogin_encryption(&body), 0x03);
    }

    #[test]
    fn parse_prelogin_encryption_absent_defaults_not_sup() {
        // Only a VERSION option (0x00), no ENCRYPTION → NOT_SUP default.
        let body = vec![0x00, 0x00, 0x06, 0x00, 0x06, 0xFF, 9, 0, 0, 0, 0, 0];
        assert_eq!(parse_prelogin_encryption(&body), ENCRYPT_NOT_SUP);
    }
}
