//! Fase 35 — JA3 / JA4 TLS client fingerprints.
//!
//! JA3 (MD5 of `version,ciphers,extensions,curves,point-formats`) and JA4
//! (`t<ver><sni><nciph><next><alpn>_<sha256-12 ciphers>_<sha256-12 exts>`) are
//! the de-facto fingerprints TLS-aware IDS/bot-detection uses to tell a real
//! browser from a scanner. This module computes both and ships a small DB of
//! real-browser profiles, so an operator can see the canonical fingerprints to
//! mimic or to compare against a captured handshake.
//!
//! GREASE code points (0x?a?a) are excluded from both, per spec. The ClientHello
//! that rustls/reqwest emits for our *own* TLS probes is library-controlled, so
//! active on-the-wire mimicry is out of scope here (documented); this is the
//! computation + reference layer.

use md5::Md5;
use sha2::{Digest, Sha256};

fn is_grease(v: u16) -> bool {
    // GREASE values are 0x0a0a, 0x1a1a, … 0xfafa.
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn join_dash(vals: &[u16]) -> String {
    vals.iter()
        .filter(|v| !is_grease(**v))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// A TLS client's observable ClientHello shape, GREASE included (filtered on
/// formatting).
#[derive(Debug, Clone)]
pub struct ClientHelloShape {
    pub tls_version: u16, // the legacy record version field, e.g. 0x0303
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub curves: Vec<u16>,
    pub point_formats: Vec<u8>,
    pub has_sni: bool,
    pub alpn: Vec<String>, // in offer order; e.g. ["h2","http/1.1"]
}

/// The canonical JA3 string: `ver,ciphers,exts,curves,formats`.
pub fn ja3_string(s: &ClientHelloShape) -> String {
    let formats = s
        .point_formats
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!(
        "{},{},{},{},{}",
        s.tls_version,
        join_dash(&s.ciphers),
        join_dash(&s.extensions),
        join_dash(&s.curves),
        formats
    )
}

/// JA3 = MD5(ja3_string), lowercase hex.
pub fn ja3_hash(s: &ClientHelloShape) -> String {
    format!("{:x}", Md5::digest(ja3_string(s).as_bytes()))
}

fn sha256_12(input: &str) -> String {
    let d = Sha256::digest(input.as_bytes());
    let hex = format!("{:x}", d);
    hex[..12].to_string()
}

/// JA4 (TLS-over-TCP client), per the FoxIO spec shape:
/// `t<ver2><sni><nciph2><next2><alpn2>_<ciphers12>_<exts12>`.
pub fn ja4(s: &ClientHelloShape) -> String {
    let ver = match s.tls_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let sni = if s.has_sni { "d" } else { "i" };
    let ciphers: Vec<u16> = s.ciphers.iter().copied().filter(|v| !is_grease(*v)).collect();
    let exts: Vec<u16> = s.extensions.iter().copied().filter(|v| !is_grease(*v)).collect();
    let nciph = format!("{:02}", ciphers.len().min(99));
    let next = format!("{:02}", exts.len().min(99));
    let alpn = match s.alpn.first() {
        Some(a) if a.len() >= 2 => {
            let b = a.as_bytes();
            format!("{}{}", b[0] as char, b[b.len() - 1] as char)
        }
        _ => "00".to_string(),
    };
    // JA4 sorts the cipher and extension lists before hashing.
    let mut cs = ciphers.clone();
    cs.sort_unstable();
    let mut es = exts.clone();
    es.sort_unstable();
    let cs_hex = cs.iter().map(|v| format!("{:04x}", v)).collect::<Vec<_>>().join(",");
    let es_hex = es.iter().map(|v| format!("{:04x}", v)).collect::<Vec<_>>().join(",");
    format!(
        "t{}{}{}{}{}_{}_{}",
        ver,
        sni,
        nciph,
        next,
        alpn,
        sha256_12(&cs_hex),
        sha256_12(&es_hex)
    )
}

/// A named real-browser fingerprint profile.
pub struct BrowserProfile {
    pub name: &'static str,
    pub shape: fn() -> ClientHelloShape,
}

fn chrome_shape() -> ClientHelloShape {
    ClientHelloShape {
        tls_version: 0x0303,
        ciphers: vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
        extensions: vec![
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012,
            0x0033, 0x002d, 0x002b, 0x001b, 0x0015,
        ],
        curves: vec![0x001d, 0x0017, 0x0018],
        point_formats: vec![0],
        has_sni: true,
        alpn: vec!["h2".into(), "http/1.1".into()],
    }
}

fn firefox_shape() -> ClientHelloShape {
    ClientHelloShape {
        tls_version: 0x0303,
        ciphers: vec![
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
        extensions: vec![
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x0022, 0x0033, 0x002b,
            0x000d, 0x002d, 0x001c, 0x0015,
        ],
        curves: vec![0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
        point_formats: vec![0],
        has_sni: true,
        alpn: vec!["h2".into(), "http/1.1".into()],
    }
}

fn safari_shape() -> ClientHelloShape {
    ClientHelloShape {
        tls_version: 0x0303,
        ciphers: vec![
            0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a,
            0xc009, 0xc014, 0xc013, 0x0035, 0x002f,
        ],
        extensions: vec![
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033,
            0x002d, 0x002b, 0x001b,
        ],
        curves: vec![0x001d, 0x0017, 0x0018, 0x0019],
        point_formats: vec![0],
        has_sni: true,
        alpn: vec!["h2".into(), "http/1.1".into()],
    }
}

pub const BROWSERS: &[BrowserProfile] = &[
    BrowserProfile { name: "chrome", shape: chrome_shape },
    BrowserProfile { name: "firefox", shape: firefox_shape },
    BrowserProfile { name: "safari", shape: safari_shape },
];

pub fn profile(name: &str) -> Option<&'static BrowserProfile> {
    let n = name.to_lowercase();
    BROWSERS.iter().find(|b| b.name == n)
}

/// Print the JA3 + JA4 of one browser profile, or of all when `name` is
/// `all`/`list`.
pub fn report(name: &str) {
    let want_all = matches!(name.to_lowercase().as_str(), "all" | "list" | "");
    for b in BROWSERS {
        if !want_all && b.name != name.to_lowercase() {
            continue;
        }
        let shape = (b.shape)();
        println!("{}:", b.name);
        println!("  JA3  : {}", ja3_hash(&shape));
        println!("  JA3s : {}", ja3_string(&shape));
        println!("  JA4  : {}", ja4(&shape));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0xc02b));
    }

    #[test]
    fn ja3_string_excludes_grease_and_formats_fields() {
        let s = ClientHelloShape {
            tls_version: 0x0303,
            ciphers: vec![0x0a0a, 0x1301, 0x1302],
            extensions: vec![0x0000, 0x0a0a, 0x0017],
            curves: vec![0x001d, 0x0017],
            point_formats: vec![0],
            has_sni: true,
            alpn: vec!["h2".into()],
        };
        // 0x0303 = 771, 0x1301 = 4865, 0x1302 = 4866, 0x17 ext=23, curves 29-23.
        assert_eq!(ja3_string(&s), "771,4865-4866,0-23,29-23,0");
    }

    #[test]
    fn ja3_hash_is_md5_hex() {
        let shape = chrome_shape();
        let h = ja3_hash(&shape);
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // Deterministic.
        assert_eq!(h, ja3_hash(&chrome_shape()));
    }

    #[test]
    fn ja4_shape_and_determinism() {
        let shape = chrome_shape();
        let j = ja4(&shape);
        assert!(j.starts_with("t13d") || j.starts_with("t12d"), "got {}", j);
        // t<ver><sni><nc><ne><alpn>_<12>_<12>
        let parts: Vec<&str> = j.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
        assert_eq!(j, ja4(&chrome_shape()));
    }

    #[test]
    fn profiles_present_and_distinct() {
        assert!(profile("chrome").is_some());
        assert!(profile("firefox").is_some());
        assert!(profile("safari").is_some());
        assert!(profile("nope").is_none());
        // Different browsers → different JA3.
        let c = ja3_hash(&chrome_shape());
        let f = ja3_hash(&firefox_shape());
        assert_ne!(c, f);
    }
}
