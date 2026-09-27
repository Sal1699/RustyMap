//! JARM — active TLS server fingerprint (Salesforce, 2020).
//!
//! Sends 10 deliberately-crafted TLS ClientHellos (different versions,
//! cipher orderings, GREASE, ALPN and supported_versions permutations) and
//! records, for each, the server's *chosen* cipher + version and its
//! response extensions. Those are folded into the canonical 62-hex-char
//! JARM hash: 30 chars encoding cipher/version per probe + a 32-char
//! SHA-256 truncation of the concatenated ALPN/extension material.
//!
//! Servers that behave identically get identical JARMs, so it clusters
//! stacks/CDNs/malware C2 the same way across the internet.
//!
//! Implemented from the published algorithm (salesforce/jarm). The
//! deterministic pieces — cipher-order transforms, the cipher/version
//! coding tables and the hash assembly — are unit-tested. The exact
//! 62-char value should still be **cross-checked against a reference
//! (jarm.online) on the lab**, since it can't be byte-validated here.

use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// The canonical JARM "ALL" cipher list, in wire order.
const ALL: &[u16] = &[
    0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045,
    0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024,
    0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301, 0xcc14, 0xc007, 0xc012, 0xc013,
    0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304,
    0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0x0035, 0x003d, 0x0041, 0x00ba, 0x0084, 0x00c0,
    0x0007, 0x0004, 0x0005,
];

/// "NO1.3" list — ALL minus the TLS 1.3 suites (0x13xx).
fn no13() -> Vec<u16> {
    ALL.iter().copied().filter(|c| (*c & 0xff00) != 0x1300).collect()
}

/// Numerically-ordered lookup table used to code a chosen cipher into two
/// hex chars (its 1-based index). Must stay a stable, agreed ordering.
const CODE_TABLE: &[u16] = &[
    0x0004, 0x0005, 0x0007, 0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039, 0x003c, 0x003d, 0x0041,
    0x0045, 0x0067, 0x006b, 0x0084, 0x0088, 0x009a, 0x009c, 0x009d, 0x009e, 0x009f, 0x00ba, 0x00be,
    0x00c0, 0x00c4, 0xc007, 0xc008, 0xc009, 0xc00a, 0xc011, 0xc012, 0xc013, 0xc014, 0xc023, 0xc024,
    0xc027, 0xc028, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xc060, 0xc061, 0xc072, 0xc073, 0xc076, 0xc077,
    0xc09c, 0xc09d, 0xc09e, 0xc09f, 0xc0a2, 0xc0a3, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af, 0xcc13, 0xcc14,
    0xcca8, 0xcca9, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
];

/// Code a chosen cipher into a two-hex-char token (`"00"` if none).
pub fn cipher_code(cipher: Option<u16>) -> String {
    match cipher {
        None => "00".to_string(),
        Some(c) => {
            let idx = CODE_TABLE.iter().position(|&x| x == c).map(|p| p + 1).unwrap_or(0);
            format!("{:02x}", idx & 0xff)
        }
    }
}

/// Code a negotiated version into one char, exactly as Salesforce JARM's
/// `version_byte`: index `"abcdef"` by the **last hex nibble** of the
/// version (0x0303 → index 3 → 'd', 0x0301 → 'b', 0x0304 → 'e'), NOT by
/// `nibble-1` (lab bug B21: RustyMap was one letter low on every probe).
pub fn version_code(ver: Option<u16>) -> char {
    match ver {
        None => '0',
        Some(v) => {
            let idx = (v & 0x000f) as usize; // 0x0303 -> 3
            if idx < 6 {
                "abcdef".as_bytes()[idx] as char
            } else {
                '0'
            }
        }
    }
}

/// Cipher-order transforms (JARM `cipher_mung`).
pub fn mung(ciphers: &[u16], order: Order) -> Vec<u16> {
    let n = ciphers.len();
    match order {
        Order::Forward => ciphers.to_vec(),
        Order::Reverse => ciphers.iter().rev().copied().collect(),
        Order::BottomHalf => {
            if n % 2 == 1 {
                ciphers[n / 2 + 1..].to_vec()
            } else {
                ciphers[n / 2..].to_vec()
            }
        }
        Order::TopHalf => {
            let mut out = Vec::new();
            if n % 2 == 1 {
                out.push(ciphers[n / 2]);
            }
            let rev = mung(ciphers, Order::Reverse);
            out.extend(mung(&rev, Order::BottomHalf));
            out
        }
        Order::MiddleOut => {
            let mid = n / 2;
            let mut out = Vec::new();
            if n % 2 == 1 {
                out.push(ciphers[mid]);
                for i in 1..=mid {
                    out.push(ciphers[mid + i]);
                    out.push(ciphers[mid - i]);
                }
            } else {
                for i in 1..=mid {
                    out.push(ciphers[mid - 1 + i]);
                    out.push(ciphers[mid - i]);
                }
            }
            out
        }
    }
}

#[derive(Clone, Copy)]
pub enum Order {
    Forward,
    Reverse,
    TopHalf,
    BottomHalf,
    MiddleOut,
}

#[derive(Clone, Copy)]
enum Support {
    None,
    V12,
    V13,
}

/// One JARM probe definition.
struct Probe {
    version: u16, // ClientHello legacy/record version
    no13: bool,
    order: Order,
    grease: bool,
    rare_alpn: bool,
    support: Support,
    /// Emit the extension blocks in reverse order (JARM's 9th parameter).
    ext_reverse: bool,
}

fn probes() -> Vec<Probe> {
    use Order::*;
    use Support::*;
    vec![
        Probe { version: 0x0303, no13: false, order: Forward, grease: false, rare_alpn: false, support: V12, ext_reverse: true },
        Probe { version: 0x0303, no13: false, order: Reverse, grease: false, rare_alpn: false, support: V12, ext_reverse: false },
        Probe { version: 0x0303, no13: false, order: TopHalf, grease: false, rare_alpn: false, support: None, ext_reverse: false },
        Probe { version: 0x0303, no13: false, order: BottomHalf, grease: false, rare_alpn: true, support: None, ext_reverse: false },
        Probe { version: 0x0303, no13: false, order: MiddleOut, grease: true, rare_alpn: true, support: None, ext_reverse: true },
        Probe { version: 0x0302, no13: false, order: Forward, grease: false, rare_alpn: false, support: None, ext_reverse: false },
        Probe { version: 0x0304, no13: false, order: Forward, grease: false, rare_alpn: false, support: V13, ext_reverse: true },
        Probe { version: 0x0304, no13: false, order: Reverse, grease: false, rare_alpn: false, support: V13, ext_reverse: false },
        Probe { version: 0x0304, no13: true, order: Forward, grease: false, rare_alpn: true, support: None, ext_reverse: false },
        Probe { version: 0x0304, no13: false, order: MiddleOut, grease: true, rare_alpn: false, support: V13, ext_reverse: true },
    ]
}

fn u16b(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

const GREASE: u16 = 0x0a0a;

fn build_hello(p: &Probe, sni: &str) -> Vec<u8> {
    let mut ciphers: Vec<u16> = if p.no13 { no13() } else { ALL.to_vec() };
    ciphers = mung(&ciphers, p.order);

    let mut body = Vec::new();
    body.extend_from_slice(&u16b(if p.version == 0x0304 { 0x0303 } else { p.version })); // legacy version
    body.extend_from_slice(&[0x11u8; 32]); // random
    body.push(0x00); // session id len

    // cipher suites (+ GREASE prefix)
    let mut cs = Vec::new();
    if p.grease {
        cs.extend_from_slice(&u16b(GREASE));
    }
    for c in &ciphers {
        cs.extend_from_slice(&u16b(*c));
    }
    body.extend_from_slice(&u16b(cs.len() as u16));
    body.extend_from_slice(&cs);
    body.push(0x01); // compression len
    body.push(0x00);

    // Build each extension as its own TLV block so we can emit them in
    // reverse order for the probes that require it (JARM's 9th parameter).
    let block = |etype: u16, payload: &[u8]| -> Vec<u8> {
        let mut b = Vec::with_capacity(payload.len() + 4);
        b.extend_from_slice(&u16b(etype));
        b.extend_from_slice(&u16b(payload.len() as u16));
        b.extend_from_slice(payload);
        b
    };
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    if p.grease {
        blocks.push(block(GREASE, &[]));
    }
    // SNI
    let hb = sni.as_bytes();
    let mut sni_pl = Vec::new();
    sni_pl.extend_from_slice(&u16b((hb.len() + 3) as u16));
    sni_pl.push(0x00);
    sni_pl.extend_from_slice(&u16b(hb.len() as u16));
    sni_pl.extend_from_slice(hb);
    blocks.push(block(0x0000, &sni_pl));
    // extended_master_secret
    blocks.push(block(0x0017, &[]));
    // supported_groups
    blocks.push(block(0x000a, &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]));
    // ec_point_formats
    blocks.push(block(0x000b, &[0x02, 0x01, 0x00]));
    // session_ticket
    blocks.push(block(0x0023, &[]));
    // ALPN
    let protos: &[&str] = if p.rare_alpn {
        &["http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq"]
    } else {
        &["h2", "http/1.1"]
    };
    let mut list = Vec::new();
    for pr in protos {
        list.push(pr.len() as u8);
        list.extend_from_slice(pr.as_bytes());
    }
    let mut alpn_pl = Vec::new();
    alpn_pl.extend_from_slice(&u16b(list.len() as u16));
    alpn_pl.extend_from_slice(&list);
    blocks.push(block(0x0010, &alpn_pl));
    // signature_algorithms
    blocks.push(block(
        0x000d,
        &[0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01],
    ));
    // key_share (x25519)
    let mut ks_pl = Vec::new();
    ks_pl.extend_from_slice(&u16b(0x0024)); // client_shares length
    ks_pl.extend_from_slice(&u16b(0x001d));
    ks_pl.extend_from_slice(&u16b(0x0020));
    ks_pl.extend_from_slice(&[0x22u8; 32]);
    blocks.push(block(0x0033, &ks_pl));
    // psk_key_exchange_modes
    blocks.push(block(0x002d, &[0x01, 0x01]));
    // supported_versions (JARM: 1.2 → {1.0,1.1,1.2}; 1.3 → {1.0,1.1,1.2,1.3})
    match p.support {
        Support::V12 => blocks.push(block(0x002b, &[0x06, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03])),
        Support::V13 => blocks.push(block(0x002b, &[0x08, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x03, 0x04])),
        Support::None => {}
    }

    if p.ext_reverse {
        blocks.reverse();
    }
    let ext: Vec<u8> = blocks.concat();
    body.extend_from_slice(&u16b(ext.len() as u16));
    body.extend_from_slice(&ext);

    // handshake header
    let mut hs = Vec::with_capacity(body.len() + 4);
    hs.push(0x01);
    let l = body.len();
    hs.push((l >> 16) as u8);
    hs.push((l >> 8) as u8);
    hs.push(l as u8);
    hs.extend_from_slice(&body);

    // record
    let mut rec = Vec::with_capacity(hs.len() + 5);
    rec.push(0x16);
    rec.extend_from_slice(&u16b(if p.version == 0x0304 { 0x0301 } else { p.version }));
    rec.extend_from_slice(&u16b(hs.len() as u16));
    rec.extend_from_slice(&hs);
    rec
}

/// Parsed JARM-relevant facts from a ServerHello.
struct HelloReply {
    cipher: Option<u16>,
    version: Option<u16>,
    /// Concatenated extension-type material folded into the JARM hash.
    ext_material: String,
}

fn parse_reply(buf: &[u8]) -> Option<HelloReply> {
    if buf.len() < 44 || buf[0] != 0x16 || buf[5] != 0x02 {
        return None; // not a ServerHello
    }
    // JARM codes the ServerHello's *legacy* version field (0x0303 for both
    // 1.2 and 1.3 on modern servers) — it does NOT follow the
    // supported_versions extension (lab bug B21).
    let ver = u16::from_be_bytes([buf[9], buf[10]]);
    let mut i = 9 + 2 + 32;
    if i >= buf.len() {
        return None;
    }
    let sid = buf[i] as usize;
    i += 1 + sid;
    if i + 3 > buf.len() {
        return None;
    }
    let cipher = u16::from_be_bytes([buf[i], buf[i + 1]]);
    i += 2 + 1; // cipher + compression

    // Hash material, in JARM's format: the negotiated ALPN protocol string
    // followed by the server's extension types as hyphen-joined hex.
    let mut alpn = String::new();
    let mut types: Vec<String> = Vec::new();
    if i + 2 <= buf.len() {
        let etot = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
        i += 2;
        let end = (i + etot).min(buf.len());
        while i + 4 <= end {
            let etype = u16::from_be_bytes([buf[i], buf[i + 1]]);
            let elen = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
            types.push(format!("{:04x}", etype));
            if etype == 0x0010 && elen >= 3 && i + 4 + 3 + (buf[i + 6] as usize) <= buf.len() {
                let plen = buf[i + 6] as usize; // ALPN: listlen(2) protolen(1) proto…
                alpn = String::from_utf8_lossy(&buf[i + 7..i + 7 + plen]).into_owned();
            }
            i += 4 + elen;
        }
    }
    let material = format!("{}{}", alpn, types.join("-"));
    Some(HelloReply { cipher: Some(cipher), version: Some(ver), ext_material: material })
}

async fn run_probe(ip: IpAddr, port: u16, ch: &[u8], dur: Duration) -> Option<HelloReply> {
    let mut s = timeout(dur, TcpStream::connect(SocketAddr::new(ip, port))).await.ok()?.ok()?;
    timeout(dur, s.write_all(ch)).await.ok()?.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(dur, s.read(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    parse_reply(&buf)
}

/// Assemble the 62-char JARM from the 10 per-probe (cipher, version, ext)
/// tuples. `None` for a probe that didn't answer.
pub fn assemble(replies: &[(Option<u16>, Option<u16>, String)]) -> String {
    let mut coded = String::new();
    let mut material = String::new();
    for (cipher, version, ext) in replies {
        coded.push_str(&cipher_code(*cipher));
        coded.push(version_code(*version));
        material.push_str(ext);
    }
    // All-empty → canonical all-zero JARM.
    if replies.iter().all(|(c, _, _)| c.is_none()) {
        return "0".repeat(62);
    }
    let digest = Sha256::digest(material.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}{}", coded, &hex[..32])
}

/// Run the full JARM against a host:port. Returns the 62-char fingerprint.
pub async fn fingerprint(ip: IpAddr, port: u16, sni: Option<&str>, dur: Duration) -> String {
    let host = sni.map(String::from).unwrap_or_else(|| ip.to_string());
    let mut replies: Vec<(Option<u16>, Option<u16>, String)> = Vec::with_capacity(10);
    for p in probes() {
        let ch = build_hello(&p, &host);
        match run_probe(ip, port, &ch, dur).await {
            Some(r) => replies.push((r.cipher, r.version, r.ext_material)),
            None => replies.push((None, None, String::new())),
        }
    }
    assemble(&replies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mung_reverse_and_halves() {
        let c = [1u16, 2, 3, 4, 5];
        assert_eq!(mung(&c, Order::Reverse), vec![5, 4, 3, 2, 1]);
        // odd len: bottom half drops the middle
        assert_eq!(mung(&c, Order::BottomHalf), vec![4, 5]);
        // middle-out on odd starts at the middle then alternates outward
        assert_eq!(mung(&c, Order::MiddleOut), vec![3, 4, 2, 5, 1]);
    }

    #[test]
    fn cipher_and_version_coding() {
        assert_eq!(cipher_code(None), "00");
        assert_eq!(cipher_code(Some(0x0004)), "01"); // first in the table
        assert_eq!(cipher_code(Some(0x1305)), format!("{:02x}", CODE_TABLE.len()));
        assert_eq!(version_code(None), '0');
        // pyjarm indexes "abcdef" by the last version nibble directly.
        assert_eq!(version_code(Some(0x0303)), 'd'); // TLS 1.2 legacy
        assert_eq!(version_code(Some(0x0304)), 'e'); // TLS 1.3
        assert_eq!(version_code(Some(0x0301)), 'b'); // TLS 1.0
        assert_eq!(version_code(Some(0x0302)), 'c'); // TLS 1.1
    }

    #[test]
    fn assemble_all_empty_is_zero_jarm() {
        let empty: Vec<(Option<u16>, Option<u16>, String)> =
            (0..10).map(|_| (None, None, String::new())).collect();
        let j = assemble(&empty);
        assert_eq!(j, "0".repeat(62));
        assert_eq!(j.len(), 62);
    }

    #[test]
    fn assemble_nonempty_is_62_chars() {
        let mut r: Vec<(Option<u16>, Option<u16>, String)> =
            (0..10).map(|_| (None, None, String::new())).collect();
        r[0] = (Some(0xc02f), Some(0x0303), "002b0033".to_string());
        let j = assemble(&r);
        assert_eq!(j.len(), 62);
        assert_ne!(j, "0".repeat(62));
        // first probe coded, rest zeros before the hash
        assert!(j.starts_with(&cipher_code(Some(0xc02f))));
    }

    #[test]
    fn build_hello_is_tls_record() {
        let p = &probes()[0];
        let ch = build_hello(p, "example.com");
        assert_eq!(ch[0], 0x16); // handshake record
        assert_eq!(ch[5], 0x01); // ClientHello
        assert!(ch.windows(11).any(|w| w == b"example.com"));
    }
}
