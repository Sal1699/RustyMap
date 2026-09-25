//! Full TLS cipher-suite enumeration (sslscan-style).
//!
//! rustls only negotiates a fixed set of modern suites and reports the one
//! it agreed on, so `tls_enum` could only ever show a single cipher per
//! version (lab bug #26/#27). This module works at the protocol level: it
//! offers the server a list of candidate suites in a hand-crafted
//! ClientHello, reads which one the server picked from the ServerHello,
//! removes it, and repeats until the server refuses — enumerating the full
//! accepted set, including the weak suites (3DES/SWEET32, RC4, CBC, export)
//! that a modern TLS library would never offer.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Candidate TLS 1.0–1.2 cipher suites: (id, name, weak?). `weak` flags
/// suites an auditor cares about — SWEET32 (3DES), RC4, CBC-mode MACs,
/// export/NULL. Ordered strong-first so a healthy server's preferred suite
/// surfaces early.
const SUITES: &[(u16, &str, bool)] = &[
    (0xC02B, "ECDHE_ECDSA_AES_128_GCM_SHA256", false),
    (0xC02C, "ECDHE_ECDSA_AES_256_GCM_SHA384", false),
    (0xC02F, "ECDHE_RSA_AES_128_GCM_SHA256", false),
    (0xC030, "ECDHE_RSA_AES_256_GCM_SHA384", false),
    (0xCCA8, "ECDHE_RSA_CHACHA20_POLY1305", false),
    (0xCCA9, "ECDHE_ECDSA_CHACHA20_POLY1305", false),
    (0x009C, "RSA_AES_128_GCM_SHA256", false),
    (0x009D, "RSA_AES_256_GCM_SHA384", false),
    (0x009E, "DHE_RSA_AES_128_GCM_SHA256", false),
    (0x009F, "DHE_RSA_AES_256_GCM_SHA384", false),
    // CBC-mode (weak: Lucky13 / padding-oracle class)
    (0xC027, "ECDHE_RSA_AES_128_CBC_SHA256", true),
    (0xC028, "ECDHE_RSA_AES_256_CBC_SHA384", true),
    (0xC023, "ECDHE_ECDSA_AES_128_CBC_SHA256", true),
    (0xC013, "ECDHE_RSA_AES_128_CBC_SHA", true),
    (0xC014, "ECDHE_RSA_AES_256_CBC_SHA", true),
    (0x003C, "RSA_AES_128_CBC_SHA256", true),
    (0x003D, "RSA_AES_256_CBC_SHA256", true),
    (0x002F, "RSA_AES_128_CBC_SHA", true),
    (0x0035, "RSA_AES_256_CBC_SHA", true),
    (0x0033, "DHE_RSA_AES_128_CBC_SHA", true),
    (0x0039, "DHE_RSA_AES_256_CBC_SHA", true),
    // SWEET32 / legacy stream — always weak
    (0x000A, "RSA_3DES_EDE_CBC_SHA (SWEET32)", true),
    (0xC012, "ECDHE_RSA_3DES_EDE_CBC_SHA (SWEET32)", true),
    (0x0016, "DHE_RSA_3DES_EDE_CBC_SHA (SWEET32)", true),
    (0x0005, "RSA_RC4_128_SHA (RC4)", true),
    (0x0004, "RSA_RC4_128_MD5 (RC4)", true),
    (0x0003, "RSA_RC4_40_MD5 (export)", true),
    (0x0000, "NULL_MD5", true),
];

/// One enumerated, accepted cipher suite.
#[derive(Debug, Clone)]
pub struct Cipher {
    pub name: String,
    pub weak: bool,
}

fn u16b(v: u16) -> [u8; 2] {
    [(v >> 8) as u8, (v & 0xff) as u8]
}

/// Build a ClientHello at `ver` (0x0301/0x0302/0x0303) offering `suites`,
/// with the extensions real servers need to negotiate ECDHE suites (SNI,
/// supported_groups, ec_point_formats, signature_algorithms). TLS 1.3
/// suites are offered under a 1.2 record with the supported_versions
/// extension so 1.3-only servers still answer.
fn client_hello(ver: u16, suites: &[u16], sni: Option<&str>) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);
    body.extend_from_slice(&u16b(0x0303)); // client_version (max) = TLS 1.2
    body.extend_from_slice(&[0xa5; 32]); // random
    body.push(0); // session_id len

    let mut cs = Vec::new();
    for s in suites {
        cs.extend_from_slice(&u16b(*s));
    }
    body.extend_from_slice(&u16b(cs.len() as u16));
    body.extend_from_slice(&cs);
    body.extend_from_slice(&[0x01, 0x00]); // 1 compression method: null

    // ── extensions ──
    let mut ext = Vec::new();
    // SNI
    if let Some(host) = sni {
        let hb = host.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&u16b((hb.len() + 3) as u16)); // server_name_list len
        sni_ext.push(0x00); // name_type host_name
        sni_ext.extend_from_slice(&u16b(hb.len() as u16));
        sni_ext.extend_from_slice(hb);
        ext.extend_from_slice(&u16b(0x0000)); // ext type SNI
        ext.extend_from_slice(&u16b(sni_ext.len() as u16));
        ext.extend_from_slice(&sni_ext);
    }
    // supported_groups: x25519, secp256r1, secp384r1
    let groups: [u16; 3] = [0x001d, 0x0017, 0x0018];
    let mut g = Vec::new();
    g.extend_from_slice(&u16b((groups.len() * 2) as u16));
    for gr in groups {
        g.extend_from_slice(&u16b(gr));
    }
    ext.extend_from_slice(&u16b(0x000a));
    ext.extend_from_slice(&u16b(g.len() as u16));
    ext.extend_from_slice(&g);
    // ec_point_formats: uncompressed
    ext.extend_from_slice(&u16b(0x000b));
    ext.extend_from_slice(&u16b(0x0002));
    ext.extend_from_slice(&[0x01, 0x00]);
    // signature_algorithms
    let sigs: [u16; 6] = [0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601];
    let mut sa = Vec::new();
    sa.extend_from_slice(&u16b((sigs.len() * 2) as u16));
    for s in sigs {
        sa.extend_from_slice(&u16b(s));
    }
    ext.extend_from_slice(&u16b(0x000d));
    ext.extend_from_slice(&u16b(sa.len() as u16));
    ext.extend_from_slice(&sa);
    // NOTE: no supported_versions extension — this is a legacy (≤1.2)
    // negotiation. Offering TLS 1.3 there without a key_share draws a
    // handshake_failure. TLS 1.3 cipher info comes from the rustls probe.

    body.extend_from_slice(&u16b(ext.len() as u16));
    body.extend_from_slice(&ext);

    // handshake header
    let mut hs = Vec::with_capacity(body.len() + 4);
    hs.push(0x01); // ClientHello
    let l = body.len() as u32;
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&body);

    // record header (record version = requested legacy ver for compat)
    let mut rec = Vec::with_capacity(hs.len() + 5);
    rec.push(0x16);
    rec.extend_from_slice(&u16b(ver));
    rec.extend_from_slice(&u16b(hs.len() as u16));
    rec.extend_from_slice(&hs);
    rec
}

/// Parse the selected cipher suite from a ServerHello response, or None if
/// the server sent an Alert / didn't produce a ServerHello.
fn server_hello_suite(buf: &[u8]) -> Option<u16> {
    // record: type(1) ver(2) len(2) | handshake: type(1) len(3) ...
    if buf.len() < 44 || buf[0] != 0x16 || buf[5] != 0x02 {
        return None;
    }
    // ServerHello body starts at 9: version(2) random(32) session_id_len(1)
    let sid_len = *buf.get(43)? as usize;
    let cipher_off = 44 + sid_len;
    let hi = *buf.get(cipher_off)?;
    let lo = *buf.get(cipher_off + 1)?;
    Some(((hi as u16) << 8) | lo as u16)
}

async fn offer(ip: IpAddr, port: u16, ver: u16, suites: &[u16], sni: Option<&str>, dur: Duration) -> Option<u16> {
    let ch = client_hello(ver, suites, sni);
    let addr = SocketAddr::new(ip, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
    timeout(dur, s.write_all(&ch)).await.ok()?.ok()?;
    // ServerHello can trail the record header; read enough to cover the
    // cipher field even with a long session id.
    let mut buf = vec![0u8; 2048];
    let mut got = 0usize;
    loop {
        let n = timeout(dur, s.read(&mut buf[got..])).await.ok()?.ok()?;
        if n == 0 {
            break;
        }
        got += n;
        // Once we have the record header, read until the full handshake
        // record is in hand — the cipher field sits after a session id
        // that can be up to 32 bytes, so a short read misses it.
        if got >= 5 {
            let rec_len = ((buf[3] as usize) << 8) | buf[4] as usize;
            if got >= 5 + rec_len {
                break;
            }
        }
        if got == buf.len() {
            break;
        }
    }
    server_hello_suite(&buf[..got])
}

/// Enumerate every cipher suite the server at `ip:port` accepts for the
/// given legacy protocol version. Repeats the offer, removing each picked
/// suite, until the server stops negotiating.
pub async fn enumerate(ip: IpAddr, port: u16, ver: u16, sni: Option<&str>, dur: Duration) -> Vec<Cipher> {
    let mut remaining: Vec<u16> = SUITES.iter().map(|(id, _, _)| *id).collect();
    let mut out = Vec::new();
    // Bounded by the suite count; each round removes at least one.
    for _ in 0..SUITES.len() {
        if remaining.is_empty() {
            break;
        }
        let picked = match offer(ip, port, ver, &remaining, sni, dur).await {
            Some(id) => id,
            None => break,
        };
        // Guard against a server echoing a suite we didn't offer.
        let Some(pos) = remaining.iter().position(|&x| x == picked) else {
            break;
        };
        remaining.remove(pos);
        if let Some((_, name, weak)) = SUITES.iter().find(|(id, _, _)| *id == picked) {
            out.push(Cipher { name: (*name).to_string(), weak: *weak });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_well_formed() {
        let ch = client_hello(0x0303, &[0x009c, 0xc02f], Some("example.com"));
        assert_eq!(ch[0], 0x16); // handshake record
        assert_eq!(ch[5], 0x01); // ClientHello
        // record length matches body
        let rec_len = ((ch[3] as usize) << 8) | ch[4] as usize;
        assert_eq!(rec_len, ch.len() - 5);
    }

    #[test]
    fn parse_selected_suite() {
        // record hdr(5) + hs type(1)+len(3) + ver(2)+random(32)+sid_len(1)=0
        // then cipher 0x009c
        let mut buf = vec![0x16, 0x03, 0x03, 0x00, 0x00];
        buf.extend_from_slice(&[0x02, 0x00, 0x00, 0x26]); // ServerHello, len
        buf.extend_from_slice(&[0x03, 0x03]); // version
        buf.extend_from_slice(&[0u8; 32]); // random
        buf.push(0x00); // session_id len
        buf.extend_from_slice(&[0x00, 0x9c]); // cipher
        assert_eq!(server_hello_suite(&buf), Some(0x009c));
    }
}
