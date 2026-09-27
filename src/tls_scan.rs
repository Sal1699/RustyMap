//! `--tls-scan` — HTTPS/TLS deep scan.
//!
//! New HTTPS-focused functionality on top of the existing cipher
//! enumeration / cert probe:
//!   - **TLS version matrix** — which of TLS 1.0 / 1.1 / 1.2 / 1.3 the
//!     server actually negotiates (legacy versions are a finding);
//!   - **ALPN** — whether the server offers HTTP/2 / HTTP/1.1 (h2/http/1.1);
//!   - **HSTS** — Strict-Transport-Security presence, max-age, and the
//!     includeSubDomains / preload directives.
//!
//! The raw ClientHello/ServerHello handling is self-contained (rustls
//! can't offer 1.0/1.1), and the parser is unit-tested. HSTS is read with
//! a blocking HTTPS GET (rustls, self-signed accepted).

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsScanResult {
    pub port: u16,
    /// (version label, supported) for 1.0/1.1/1.2/1.3.
    pub versions: Vec<(String, bool)>,
    pub alpn: Vec<String>,
    pub hsts: Option<String>,
}

fn u16b(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

/// A broad cipher list so servers of every era will answer.
const CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, // TLS 1.3
    0xc02f, 0xc030, 0xc02b, 0xc02c, // ECDHE-RSA/ECDSA AES-GCM
    0xc013, 0xc014, 0xc009, 0xc00a, // ECDHE CBC
    0x009c, 0x009d, 0x002f, 0x0035, // RSA AES
    0x000a, // 3DES (legacy, coaxes old servers)
];

/// Build a ClientHello. When `tls13` is set, advertise legacy 0x0303 plus a
/// supported_versions extension offering only 1.3; otherwise offer `ver`
/// the classic way (no supported_versions) so we test that exact version.
pub fn build_client_hello(ver: u16, sni: Option<&str>, alpn: &[&str], tls13: bool) -> Vec<u8> {
    let mut hs = Vec::new();
    let client_ver: u16 = if tls13 { 0x0303 } else { ver };
    hs.extend_from_slice(&u16b(client_ver));
    hs.extend_from_slice(&[0x11u8; 32]); // client random
    hs.push(0x00); // session id len

    // cipher suites
    hs.extend_from_slice(&u16b((CIPHERS.len() * 2) as u16));
    for c in CIPHERS {
        hs.extend_from_slice(&u16b(*c));
    }
    hs.push(0x01); // compression methods len
    hs.push(0x00); // null

    // ── extensions ──
    let mut ext = Vec::new();
    if let Some(host) = sni {
        let hb = host.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&u16b((hb.len() + 3) as u16));
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&u16b(hb.len() as u16));
        sni_ext.extend_from_slice(hb);
        ext.extend_from_slice(&u16b(0x0000));
        ext.extend_from_slice(&u16b(sni_ext.len() as u16));
        ext.extend_from_slice(&sni_ext);
    }
    // supported_groups + ec_point_formats (needed for ECDHE)
    ext.extend_from_slice(&u16b(0x000a));
    ext.extend_from_slice(&u16b(0x0008));
    ext.extend_from_slice(&u16b(0x0006));
    ext.extend_from_slice(&u16b(0x001d)); // x25519
    ext.extend_from_slice(&u16b(0x0017)); // secp256r1
    ext.extend_from_slice(&u16b(0x0018)); // secp384r1
    ext.extend_from_slice(&u16b(0x000b));
    ext.extend_from_slice(&u16b(0x0002));
    ext.extend_from_slice(&[0x01, 0x00]);
    // signature_algorithms
    ext.extend_from_slice(&u16b(0x000d));
    ext.extend_from_slice(&u16b(0x0008));
    ext.extend_from_slice(&u16b(0x0006));
    ext.extend_from_slice(&[0x04, 0x03, 0x08, 0x04, 0x04, 0x01]);
    // ALPN
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for p in alpn {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        let mut alpn_ext = Vec::new();
        alpn_ext.extend_from_slice(&u16b(list.len() as u16));
        alpn_ext.extend_from_slice(&list);
        ext.extend_from_slice(&u16b(0x0010));
        ext.extend_from_slice(&u16b(alpn_ext.len() as u16));
        ext.extend_from_slice(&alpn_ext);
    }
    if tls13 {
        // supported_versions: offer only TLS 1.3.
        ext.extend_from_slice(&u16b(0x002b));
        ext.extend_from_slice(&u16b(0x0003));
        ext.push(0x02);
        ext.extend_from_slice(&u16b(0x0304));
        // key_share (x25519, 32 bytes) so 1.3 servers proceed.
        let mut ks = Vec::new();
        ks.extend_from_slice(&u16b(0x001d));
        ks.extend_from_slice(&u16b(0x0020));
        ks.extend_from_slice(&[0x22u8; 32]);
        let mut ks_ext = Vec::new();
        ks_ext.extend_from_slice(&u16b(ks.len() as u16));
        ks_ext.extend_from_slice(&ks);
        ext.extend_from_slice(&u16b(0x0033));
        ext.extend_from_slice(&u16b(ks_ext.len() as u16));
        ext.extend_from_slice(&ks_ext);
    }

    hs.extend_from_slice(&u16b(ext.len() as u16));
    hs.extend_from_slice(&ext);

    // handshake header: type(1)=ClientHello + 3-byte length
    let mut handshake = Vec::new();
    handshake.push(0x01);
    let l = hs.len();
    handshake.push((l >> 16) as u8);
    handshake.push((l >> 8) as u8);
    handshake.push(l as u8);
    handshake.extend_from_slice(&hs);

    // TLS record: type 0x16 (handshake), version, length
    let rec_ver = if tls13 { 0x0303 } else { ver };
    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&u16b(rec_ver));
    rec.extend_from_slice(&u16b(handshake.len() as u16));
    rec.extend_from_slice(&handshake);
    rec
}

/// Parsed ServerHello facts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerHello {
    /// Negotiated version (0x0304 if a supported_versions ext says 1.3).
    pub version: u16,
    pub alpn: Option<String>,
}

/// Parse a TLS response. Returns the ServerHello, or `None` if the server
/// sent an Alert / not a handshake (i.e. version unsupported).
pub fn parse_server_hello(buf: &[u8]) -> Option<ServerHello> {
    if buf.len() < 6 {
        return None;
    }
    // Record must be handshake (0x16); 0x15 = alert = unsupported.
    if buf[0] != 0x16 {
        return None;
    }
    // handshake starts at 5; type 2 = ServerHello.
    if buf.len() < 44 || buf[5] != 0x02 {
        return None;
    }
    // ServerHello body starts at 9: legacy_version(2) + random(32) ...
    let mut version = u16::from_be_bytes([buf[9], buf[10]]);
    let mut i = 9 + 2 + 32; // after legacy_version + random
    if i >= buf.len() {
        return Some(ServerHello { version, alpn: None });
    }
    let sid_len = buf[i] as usize;
    i += 1 + sid_len;
    i += 2; // cipher suite
    i += 1; // compression
    // extensions
    let mut alpn = None;
    if i + 2 <= buf.len() {
        let ext_total = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
        i += 2;
        let end = (i + ext_total).min(buf.len());
        while i + 4 <= end {
            let etype = u16::from_be_bytes([buf[i], buf[i + 1]]);
            let elen = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
            i += 4;
            if i + elen > end {
                break;
            }
            let data = &buf[i..i + elen];
            match etype {
                0x002b if elen >= 2 => {
                    // supported_versions (server) → the real negotiated version.
                    version = u16::from_be_bytes([data[0], data[1]]);
                }
                0x0010 if elen >= 5 => {
                    // ALPN: list len(2), proto len(1), proto.
                    let plen = data[2] as usize;
                    if 3 + plen <= data.len() {
                        alpn = Some(String::from_utf8_lossy(&data[3..3 + plen]).into_owned());
                    }
                }
                _ => {}
            }
            i += elen;
        }
    }
    Some(ServerHello { version, alpn })
}

fn version_label(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "unknown",
    }
}

async fn send_client_hello(ip: IpAddr, port: u16, ch: &[u8], dur: Duration) -> Option<Vec<u8>> {
    let mut s = timeout(dur, TcpStream::connect(SocketAddr::new(ip, port))).await.ok()?.ok()?;
    timeout(dur, s.write_all(ch)).await.ok()?.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(dur, s.read(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    Some(buf)
}

/// HSTS via a blocking HTTPS GET.
fn hsts_blocking(host: &str, port: u16, dur: Duration) -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(dur)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let resp = client.get(format!("https://{}:{}/", host, port)).send().ok()?;
    resp.headers()
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Deep-scan one TLS port.
pub async fn scan_port(ip: IpAddr, port: u16, sni: Option<&str>, dur: Duration) -> Option<TlsScanResult> {
    // Version matrix: 1.0/1.1/1.2 the classic way, 1.3 via supported_versions.
    let mut versions = Vec::new();
    let mut any = false;
    for (ver, tls13) in [(0x0301u16, false), (0x0302, false), (0x0303, false), (0x0304, true)] {
        let ch = build_client_hello(ver, sni, &[], tls13);
        let want = if tls13 { 0x0304 } else { ver };
        let ok = match send_client_hello(ip, port, &ch, dur).await {
            Some(buf) => parse_server_hello(&buf).map(|sh| sh.version == want).unwrap_or(false),
            None => false,
        };
        if ok {
            any = true;
        }
        versions.push((version_label(want).to_string(), ok));
    }
    if !any {
        return None; // not a TLS service
    }

    // ALPN negotiation (readable in the 1.2 ServerHello).
    let alpn_ch = build_client_hello(0x0303, sni, &["h2", "http/1.1"], false);
    let alpn = match send_client_hello(ip, port, &alpn_ch, dur).await {
        Some(buf) => parse_server_hello(&buf).and_then(|sh| sh.alpn).map(|a| vec![a]).unwrap_or_default(),
        None => Vec::new(),
    };

    // HSTS (best-effort, HTTP over TLS).
    let host = sni.map(String::from).unwrap_or_else(|| ip.to_string());
    let hsts = tokio::task::spawn_blocking(move || hsts_blocking(&host, port, dur)).await.ok().flatten();

    Some(TlsScanResult { port, versions, alpn, hsts })
}

pub fn print_report(host: &str, results: &[TlsScanResult]) {
    use colored::*;
    println!();
    println!("{}", format!("TLS/HTTPS scan of {}", host).bold());
    if results.is_empty() {
        println!("  {}", "no TLS service on the probed ports".dimmed());
        return;
    }
    for r in results {
        println!();
        println!("  port {}", r.port);
        for (label, ok) in &r.versions {
            let legacy = matches!(label.as_str(), "TLS 1.0" | "TLS 1.1" | "SSL 3.0");
            let mark = if *ok {
                if legacy { format!("{} (deprecated!)", "yes").red().to_string() } else { "yes".green().to_string() }
            } else {
                "no".dimmed().to_string()
            };
            println!("    {:<8}: {}", label, mark);
        }
        if r.alpn.is_empty() {
            println!("    ALPN    : {}", "none advertised (HTTP/1.1 assumed)".dimmed());
        } else {
            let h2 = if r.alpn.iter().any(|a| a == "h2") { " — HTTP/2 supported".green().to_string() } else { String::new() };
            println!("    ALPN    : {}{}", r.alpn.join(", "), h2);
        }
        match &r.hsts {
            Some(h) => {
                let preload = if h.to_lowercase().contains("preload") { " +preload" } else { "" };
                let subs = if h.to_lowercase().contains("includesubdomains") { " +includeSubDomains" } else { "" };
                println!("    HSTS    : {}{}{}", h.green(), subs, preload);
            }
            None => println!("    HSTS    : {}", "absent — add Strict-Transport-Security".yellow()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_a_tls_handshake_record() {
        let ch = build_client_hello(0x0303, Some("example.com"), &["h2", "http/1.1"], false);
        assert_eq!(ch[0], 0x16); // handshake record
        assert_eq!(&ch[1..3], &[0x03, 0x03]); // record version
        assert_eq!(ch[5], 0x01); // ClientHello
        // ALPN protocol id "h2" appears somewhere in the extensions.
        assert!(ch.windows(2).any(|w| w == b"h2"));
        assert!(ch.windows(11).any(|w| w == b"example.com"));
    }

    #[test]
    fn tls13_client_hello_offers_supported_versions() {
        let ch = build_client_hello(0x0303, None, &[], true);
        // supported_versions ext type 0x002b present.
        assert!(ch.windows(2).any(|w| w == [0x00, 0x2b]));
    }

    #[test]
    fn parse_server_hello_reads_version_and_alpn() {
        // Minimal ServerHello record: handshake, type 2, legacy 0x0303,
        // 32 random, sid len 0, cipher, compression, extensions with ALPN h2.
        let mut sh_body = Vec::new();
        sh_body.extend_from_slice(&[0x03, 0x03]); // legacy version
        sh_body.extend_from_slice(&[0u8; 32]); // random
        sh_body.push(0x00); // sid len
        sh_body.extend_from_slice(&[0xc0, 0x2f]); // cipher
        sh_body.push(0x00); // compression
        // extensions: ALPN (0x0010): total len, then list len(2)+plen(1)+"h2"
        let alpn = [0x00u8, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2'];
        sh_body.extend_from_slice(&u16b(alpn.len() as u16));
        sh_body.extend_from_slice(&alpn);
        // handshake header
        let mut hs = vec![0x02u8, (sh_body.len() >> 16) as u8, (sh_body.len() >> 8) as u8, sh_body.len() as u8];
        hs.extend_from_slice(&sh_body);
        // record header
        let mut rec = vec![0x16u8, 0x03, 0x03];
        rec.extend_from_slice(&u16b(hs.len() as u16));
        rec.extend_from_slice(&hs);

        let parsed = parse_server_hello(&rec).unwrap();
        assert_eq!(parsed.version, 0x0303);
        assert_eq!(parsed.alpn.as_deref(), Some("h2"));
    }

    #[test]
    fn parse_rejects_alert() {
        // Alert record (0x15) → version unsupported → None.
        assert!(parse_server_hello(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]).is_none());
    }
}
