//! Binary-protocol service probes for `-sV` (lab bug B2).
//!
//! The text-banner probe engine in `service_probe` covers everything
//! that speaks a line-oriented protocol (SSH, HTTP, SMTP, FTP, …), but
//! three of the most common Windows/enterprise ports are pure binary
//! protocols that never emit a printable banner:
//!
//!   - **445 / 139  SMB**   — needs an SMB2 NEGOTIATE (for the dialect)
//!                            and an SMBv1 SESSION SETUP carrying an
//!                            NTLMSSP NEGOTIATE (for the OS build,
//!                            hostname and domain — pre-auth, no creds).
//!   - **135  MSRPC**       — needs a DCE/RPC BIND to the endpoint
//!                            mapper; a BIND_ACK/BIND_NAK confirms it.
//!   - **902  VMware authd** — actually emits a `220 VMware
//!                            Authentication Daemon` text banner, so it
//!                            is handled by the NULL probe + a signature
//!                            in `service_probe`, not here.
//!
//! Everything here is plain TCP (tokio), so it runs without raw-socket
//! privileges and is testable on any host that exposes 445/135.

use crate::service_probe::ServiceInfo;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Dispatch a binary probe by port. Returns `None` for ports we don't
/// have a binary probe for (the caller then falls back to text probes).
pub async fn probe(ip: IpAddr, port: u16, dur: Duration) -> Option<ServiceInfo> {
    match port {
        445 | 139 => smb(ip, port, dur).await,
        135 => msrpc(ip, port, dur).await,
        3389 => rdp(ip, port, dur).await,
        _ => None,
    }
}

// ─────────────────────────────── RDP ───────────────────────────────

/// Build an RDP (X.224) Connection Request carrying an RDP Negotiation
/// Request that offers standard RDP + TLS + CredSSP (NLA).
fn rdp_negotiation_request() -> Vec<u8> {
    // TPKT(4) + X.224 CR(7) + RDP nego request(8) = 19 bytes.
    vec![
        0x03, 0x00, 0x00, 0x13, // TPKT: version 3, length 0x0013 = 19
        0x0E, // X.224 length indicator (14)
        0xE0, // CR — Connection Request
        0x00, 0x00, // dst ref
        0x00, 0x00, // src ref
        0x00, // class / options
        0x01, 0x00, 0x08, 0x00, // RDP nego req: type=1, flags=0, length=8
        0x03, 0x00, 0x00, 0x00, // requestedProtocols = TLS(1) | CredSSP(2)
    ]
}

/// Parse the RDP Negotiation Response. Returns the negotiated security
/// layer, or `None` if the buffer isn't a valid TPKT/X.224 RDP reply.
fn parse_rdp_response(buf: &[u8]) -> Option<&'static str> {
    // Must be a TPKT (0x03 0x00 …).
    if buf.len() < 11 || buf[0] != 0x03 || buf[1] != 0x00 {
        return None;
    }
    // X.224 Connection Confirm has type 0xD0 at offset 5.
    if buf[5] != 0xD0 {
        // Still a TPKT → it is RDP, just no negotiation response.
        return Some("standard RDP security (no negotiation response)");
    }
    // RDP Negotiation Response starts at offset 11: type(1) flags(1) len(2)
    // selectedProtocol(4, LE). Type 2 = response, type 3 = failure.
    if buf.len() >= 19 && buf[11] == 0x02 {
        let proto = u32::from_le_bytes([buf[15], buf[16], buf[17], buf[18]]);
        return Some(match proto {
            0 => "standard RDP security (no TLS/NLA)",
            1 => "TLS required",
            2 => "CredSSP / NLA required",
            8 => "RDSTLS",
            _ => "negotiated (mixed)",
        });
    }
    if buf.len() >= 12 && buf[11] == 0x03 {
        return Some("negotiation failure (legacy RDP only)");
    }
    Some("RDP (X.224 confirmed)")
}

async fn rdp(ip: IpAddr, port: u16, dur: Duration) -> Option<ServiceInfo> {
    let addr = SocketAddr::new(ip, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
    timeout(dur, s.write_all(&rdp_negotiation_request())).await.ok()?.ok()?;
    let mut buf = vec![0u8; 64];
    let n = match timeout(dur, s.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    buf.truncate(n);
    let security = parse_rdp_response(&buf)?;
    Some(ServiceInfo {
        product: Some("Microsoft Terminal Services (RDP)".to_string()),
        version: None,
        extra: Some(security.to_string()),
        banner: Some("RDP".to_string()),
        tls: None,
    })
}

// ─────────────────────────────── SMB ───────────────────────────────

/// SMB service probe: negotiate the dialect (SMB2) and, when the host
/// answers an SMBv1 session-setup, harvest the NTLMSSP CHALLENGE for the
/// OS build / hostname / domain (delegated to `smb_deep`).
async fn smb(ip: IpAddr, port: u16, dur: Duration) -> Option<ServiceInfo> {
    let dialect = smb2_dialect(ip, port, dur).await;
    let deep = crate::smb_deep::deep_enum(ip, port, dur).await.ok().flatten();

    if dialect.is_none() && deep.is_none() {
        return None;
    }

    let mut extras: Vec<String> = Vec::new();
    if let Some(d) = dialect {
        // Render as "dialect 3.0.2" so it doesn't duplicate the "SMB"
        // that already appears in the product name.
        extras.push(format!("dialect {}", d.trim_start_matches("SMB ")));
    }

    let mut product = "SMB".to_string();
    let mut version: Option<String> = None;

    if let Some(d) = &deep {
        if let Some(osv) = &d.os_version {
            // NTLMSSP version field is populated by Windows and Samba →
            // strong signal that this is a Windows-family SMB stack.
            product = "Microsoft Windows SMB".to_string();
            version = Some(osv.clone());
        }
        if let Some(h) = &d.netbios_computer {
            extras.push(format!("host: {}", h));
        }
        if let Some(dom) = &d.netbios_domain {
            extras.push(format!("workgroup: {}", dom));
        }
        if let Some(dns) = &d.dns_domain {
            extras.push(format!("domain: {}", dns));
        }
    }

    let banner = if extras.is_empty() {
        Some("SMB".to_string())
    } else {
        Some(format!("SMB ({})", extras.join(", ")))
    };

    Some(ServiceInfo {
        product: Some(product),
        version,
        extra: if extras.is_empty() { None } else { Some(extras.join("; ")) },
        banner,
        tls: None,
    })
}

/// Build an SMB2 NEGOTIATE request offering dialects 2.0.2 → 3.0.2.
/// (We deliberately omit 3.1.1 so we don't have to attach the
/// pre-auth-integrity / encryption negotiate contexts it requires; every
/// SMB3 server also accepts a 3.0.2 negotiation, so the reported dialect
/// is a lower bound, which is honest.)
fn smb2_negotiate_request() -> Vec<u8> {
    let dialects: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];

    // SMB2 sync header (64 bytes).
    let mut smb: Vec<u8> = Vec::with_capacity(64 + 44);
    smb.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // ProtocolId
    smb.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    smb.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    smb.extend_from_slice(&0u32.to_le_bytes()); // Status
    smb.extend_from_slice(&0u16.to_le_bytes()); // Command = NEGOTIATE (0)
    smb.extend_from_slice(&0u16.to_le_bytes()); // CreditRequest
    smb.extend_from_slice(&0u32.to_le_bytes()); // Flags
    smb.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    smb.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    smb.extend_from_slice(&0u32.to_le_bytes()); // Reserved (ProcessId)
    smb.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    smb.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    smb.extend_from_slice(&[0u8; 16]); // Signature

    // NEGOTIATE request body.
    smb.extend_from_slice(&36u16.to_le_bytes()); // StructureSize (fixed 36)
    smb.extend_from_slice(&(dialects.len() as u16).to_le_bytes()); // DialectCount
    smb.extend_from_slice(&0x0001u16.to_le_bytes()); // SecurityMode = SIGNING_ENABLED
    smb.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    smb.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    smb.extend_from_slice(&[0u8; 16]); // ClientGuid
    smb.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime / (context fields, unused)
    for d in dialects {
        smb.extend_from_slice(&d.to_le_bytes());
    }

    // NetBIOS session-service header: 0x00 + 24-bit big-endian length.
    let mut pkt = Vec::with_capacity(4 + smb.len());
    let len = smb.len() as u32;
    pkt.push(0x00);
    pkt.push(((len >> 16) & 0xFF) as u8);
    pkt.push(((len >> 8) & 0xFF) as u8);
    pkt.push((len & 0xFF) as u8);
    pkt.extend_from_slice(&smb);
    pkt
}

/// Map an SMB2 `DialectRevision` value to a human label.
fn dialect_label(rev: u16) -> &'static str {
    match rev {
        0x0202 => "SMB 2.0.2",
        0x0210 => "SMB 2.1",
        0x0300 => "SMB 3.0",
        0x0302 => "SMB 3.0.2",
        0x0311 => "SMB 3.1.1",
        0x02FF => "SMB 2+ (wildcard negotiate)",
        _ => "SMB (unknown dialect)",
    }
}

/// Parse the `DialectRevision` from an SMB2 NEGOTIATE response buffer
/// (including the 4-byte NetBIOS header). Returns `None` if the buffer
/// is not a well-formed SMB2 response.
fn parse_smb2_dialect(buf: &[u8]) -> Option<&'static str> {
    // NBSS(4) + SMB2 header(64) + body. ProtocolId at offset 4.
    if buf.len() < 74 {
        return None;
    }
    if &buf[4..8] != [0xFE, b'S', b'M', b'B'] {
        return None;
    }
    // Command (offset 4+12 = 16) must be NEGOTIATE (0).
    let command = u16::from_le_bytes([buf[16], buf[17]]);
    if command != 0 {
        return None;
    }
    // Body: StructureSize(2) @68, SecurityMode(2) @70, DialectRevision(2) @72.
    let rev = u16::from_le_bytes([buf[72], buf[73]]);
    Some(dialect_label(rev))
}

/// Open a connection, send an SMB2 negotiate, and return the negotiated
/// dialect label. `None` on any failure (closed / non-SMB / SMBv1-only).
async fn smb2_dialect(ip: IpAddr, port: u16, dur: Duration) -> Option<&'static str> {
    let addr = SocketAddr::new(ip, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
    let req = smb2_negotiate_request();
    timeout(dur, s.write_all(&req)).await.ok()?.ok()?;

    // Read the 4-byte NBSS header first, then the exact payload length.
    let mut nbt = [0u8; 4];
    timeout(dur, s.read_exact(&mut nbt)).await.ok()?.ok()?;
    let len = (((nbt[1] as usize) << 16) | ((nbt[2] as usize) << 8) | nbt[3] as usize).min(65535);
    if len < 70 {
        return None;
    }
    let mut body = vec![0u8; len];
    timeout(dur, s.read_exact(&mut body)).await.ok()?.ok()?;

    // Re-assemble [NBSS header || body] so offsets match parse_smb2_dialect.
    let mut full = Vec::with_capacity(4 + body.len());
    full.extend_from_slice(&nbt);
    full.extend_from_slice(&body);
    parse_smb2_dialect(&full)
}

// ────────────────────────────── MSRPC ──────────────────────────────

/// EPM (endpoint mapper) interface UUID e1af8308-5d1f-11c9-91a4-08002b14a0fa,
/// DCE-encoded (Data1/2/3 little-endian, Data4 as-is).
const EPM_UUID: [u8; 16] = [
    0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11, 0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14, 0xA0, 0xFA,
];
/// NDR transfer syntax UUID 8a885d04-1ceb-11c9-9fe8-08002b104860.
const NDR_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];

/// Build a DCE/RPC BIND PDU binding the endpoint-mapper interface.
fn dcerpc_bind_request() -> Vec<u8> {
    // Bind body first, so we can compute frag_length.
    let mut body: Vec<u8> = Vec::with_capacity(56);
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
    body.push(1); // num_ctx_items
    body.push(0); // reserved
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    // context 0
    body.extend_from_slice(&0u16.to_le_bytes()); // context_id
    body.push(1); // num_transfer_syntaxes
    body.push(0); // reserved
    body.extend_from_slice(&EPM_UUID); // abstract syntax UUID
    body.extend_from_slice(&3u16.to_le_bytes()); // interface version major = 3
    body.extend_from_slice(&0u16.to_le_bytes()); // interface version minor = 0
    body.extend_from_slice(&NDR_UUID); // transfer syntax UUID
    body.extend_from_slice(&2u32.to_le_bytes()); // transfer syntax version = 2

    let frag_len = (16 + body.len()) as u16;

    let mut pkt: Vec<u8> = Vec::with_capacity(frag_len as usize);
    pkt.push(5); // rpc_vers
    pkt.push(0); // rpc_vers_minor
    pkt.push(11); // PDU type = bind
    pkt.push(0x03); // pfc_flags = FIRST_FRAG | LAST_FRAG
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // packed_drep (LE / ASCII / IEEE)
    pkt.extend_from_slice(&frag_len.to_le_bytes()); // frag_length
    pkt.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pkt.extend_from_slice(&1u32.to_le_bytes()); // call_id
    pkt.extend_from_slice(&body);
    pkt
}

/// Return `true` if `buf` is a DCE/RPC BIND response (bind_ack / bind_nak).
fn is_dcerpc_response(buf: &[u8]) -> bool {
    // rpc_vers==5 and PDU type is bind_ack(12) or bind_nak(13) or fault(3).
    buf.len() >= 16 && buf[0] == 5 && matches!(buf[2], 12 | 13 | 3)
}

async fn msrpc(ip: IpAddr, port: u16, dur: Duration) -> Option<ServiceInfo> {
    let addr = SocketAddr::new(ip, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
    let req = dcerpc_bind_request();
    timeout(dur, s.write_all(&req)).await.ok()?.ok()?;

    let mut buf = vec![0u8; 256];
    let n = match timeout(dur, s.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    buf.truncate(n);
    if !is_dcerpc_response(&buf) {
        return None;
    }
    let accepted = buf[2] == 12; // bind_ack
    Some(ServiceInfo {
        product: Some("Microsoft Windows RPC".to_string()),
        version: None,
        extra: Some(
            if accepted {
                "DCE/RPC endpoint mapper, bind accepted".to_string()
            } else {
                "DCE/RPC endpoint mapper".to_string()
            },
        ),
        banner: Some("MSRPC (DCE/RPC)".to_string()),
        tls: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb2_negotiate_has_valid_framing() {
        let pkt = smb2_negotiate_request();
        // NBSS message type byte
        assert_eq!(pkt[0], 0x00);
        // NBSS length == payload length
        let nbss_len = ((pkt[1] as usize) << 16) | ((pkt[2] as usize) << 8) | pkt[3] as usize;
        assert_eq!(nbss_len, pkt.len() - 4);
        // SMB2 magic
        assert_eq!(&pkt[4..8], &[0xFE, b'S', b'M', b'B']);
        // Command NEGOTIATE at header offset 12 (buffer offset 16)
        assert_eq!(u16::from_le_bytes([pkt[16], pkt[17]]), 0);
        // 4 dialects offered — DialectCount at body offset 2 (buffer 70).
        assert_eq!(u16::from_le_bytes([pkt[70], pkt[71]]) as usize, 4);
    }

    #[test]
    fn parse_dialect_reads_revision() {
        // Craft a minimal SMB2 negotiate response: NBSS(4)+header(64)+body.
        let mut buf = vec![0u8; 80];
        buf[0] = 0x00;
        let len = (buf.len() - 4) as u32;
        buf[1] = ((len >> 16) & 0xFF) as u8;
        buf[2] = ((len >> 8) & 0xFF) as u8;
        buf[3] = (len & 0xFF) as u8;
        buf[4..8].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        // Command NEGOTIATE (0) at offset 16 already zero.
        // DialectRevision 0x0311 at offset 72.
        buf[72] = 0x11;
        buf[73] = 0x03;
        assert_eq!(parse_smb2_dialect(&buf), Some("SMB 3.1.1"));
    }

    #[test]
    fn parse_dialect_rejects_non_smb() {
        let buf = vec![0u8; 80];
        assert_eq!(parse_smb2_dialect(&buf), None);
    }

    #[test]
    fn dialect_labels_cover_known_revisions() {
        assert_eq!(dialect_label(0x0202), "SMB 2.0.2");
        assert_eq!(dialect_label(0x0302), "SMB 3.0.2");
        assert_eq!(dialect_label(0x0311), "SMB 3.1.1");
    }

    #[test]
    fn dcerpc_bind_layout() {
        let pkt = dcerpc_bind_request();
        assert_eq!(pkt[0], 5); // rpc_vers
        assert_eq!(pkt[2], 11); // bind PDU
        assert_eq!(pkt[3], 0x03); // first+last frag
        let frag_len = u16::from_le_bytes([pkt[8], pkt[9]]) as usize;
        assert_eq!(frag_len, pkt.len());
        // EPM UUID present in the context list
        assert!(pkt.windows(16).any(|w| w == EPM_UUID));
        assert!(pkt.windows(16).any(|w| w == NDR_UUID));
    }

    #[test]
    fn rdp_request_is_valid_tpkt() {
        let pkt = rdp_negotiation_request();
        assert_eq!(pkt.len(), 19);
        assert_eq!(pkt[0], 0x03); // TPKT version
        assert_eq!(pkt[3], 0x13); // length 19
        assert_eq!(pkt[5], 0xE0); // X.224 CR
        assert_eq!(pkt[11], 0x01); // RDP nego request type
    }

    #[test]
    fn rdp_response_parses_security_layer() {
        // TPKT + X.224 CC + nego response, selectedProtocol = 2 (CredSSP/NLA).
        let mut buf = vec![0u8; 19];
        buf[0] = 0x03;
        buf[1] = 0x00;
        buf[5] = 0xD0; // Connection Confirm
        buf[11] = 0x02; // nego response
        buf[15] = 0x02; // selectedProtocol = CredSSP
        assert_eq!(parse_rdp_response(&buf), Some("CredSSP / NLA required"));
        // Non-TPKT → not RDP.
        assert_eq!(parse_rdp_response(&[0u8; 19]), None);
    }

    #[test]
    fn dcerpc_response_detection() {
        let mut ack = vec![0u8; 20];
        ack[0] = 5;
        ack[2] = 12; // bind_ack
        assert!(is_dcerpc_response(&ack));
        ack[2] = 13; // bind_nak
        assert!(is_dcerpc_response(&ack));
        ack[0] = 4; // wrong rpc version
        assert!(!is_dcerpc_response(&ack));
    }
}
