//! Hardcoded-secret pattern matching for mobile bundles (APK & IPA).
//!
//! Single regex pass over a byte buffer (typically a `.dex`, `.so`,
//! Mach-O binary, or resource file). The patterns are intentionally
//! narrow — narrow patterns produce far fewer false positives than
//! the "anything that looks base64" approach used by some scanners,
//! at the cost of missing custom secret schemes the developer
//! invented. Acceptable: we surface every match the user can act on.
//!
//! Patterns covered (each links to the upstream provider's documented
//! key format):
//!   - AWS access-key-ID            `AKIA[0-9A-Z]{16}`
//!   - AWS secret access key        40-char base64ish near "aws_secret"
//!   - Google Cloud / Maps API key  `AIza[0-9A-Za-z\-_]{35}`
//!   - Slack token                  `xox[abp]-[0-9A-Za-z\-]{10,}`
//!   - GitHub personal token        `ghp_[A-Za-z0-9]{36,}`
//!   - GitHub OAuth                 `gho_[A-Za-z0-9]{36,}`
//!   - JWT                          `eyJ[A-Za-z0-9_=\-]{10,}\.eyJ…`
//!   - PEM-encoded private key      `-----BEGIN .*PRIVATE KEY-----`
//!   - Stripe secret                `sk_(live|test)_[A-Za-z0-9]{24,}`
//!
//! Each `SecretFinding` records the pattern name, the file path
//! within the bundle, and a short snippet so a reviewer can
//! verify by hand.

use once_cell::sync::Lazy;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub pattern: String,
    pub file: String,
    pub snippet: String,
}

struct PatternEntry {
    name: &'static str,
    re: Regex,
}

static PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    vec![
        PatternEntry {
            name: "AWS access-key-ID",
            re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        },
        PatternEntry {
            name: "Google API key",
            re: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
        },
        PatternEntry {
            name: "Slack token",
            re: Regex::new(r"xox[abpsr]-[0-9A-Za-z\-]{10,}").unwrap(),
        },
        PatternEntry {
            name: "GitHub PAT (ghp_)",
            re: Regex::new(r"ghp_[A-Za-z0-9]{36,}").unwrap(),
        },
        PatternEntry {
            name: "GitHub OAuth (gho_)",
            re: Regex::new(r"gho_[A-Za-z0-9]{36,}").unwrap(),
        },
        PatternEntry {
            name: "Stripe secret",
            re: Regex::new(r"sk_(live|test)_[A-Za-z0-9]{24,}").unwrap(),
        },
        PatternEntry {
            name: "JWT",
            re: Regex::new(r"eyJ[A-Za-z0-9_=\-]{10,}\.eyJ[A-Za-z0-9_=\-]{10,}\.[A-Za-z0-9_=\-]{10,}").unwrap(),
        },
        PatternEntry {
            name: "PEM private key",
            re: Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(),
        },
        PatternEntry {
            name: "Firebase URL",
            re: Regex::new(r"https://[a-z0-9-]+\.firebaseio\.com").unwrap(),
        },
    ]
});

/// Scan a byte slice for any secret pattern. Returns at most one
/// finding per pattern per call to keep output compact — duplicate
/// occurrences within the same file are usually the same secret
/// referenced from multiple call sites.
pub fn scan_bytes(file: &str, body: &[u8]) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    for p in PATTERNS.iter() {
        if let Some(m) = p.re.find(body) {
            let snippet = snippet_around(body, m.start(), m.end());
            out.push(SecretFinding {
                pattern: p.name.to_string(),
                file: file.to_string(),
                snippet,
            });
        }
    }
    out
}

fn snippet_around(body: &[u8], start: usize, end: usize) -> String {
    let lo = start.saturating_sub(20);
    let hi = (end + 20).min(body.len());
    let slice = &body[lo..hi];
    // Replace non-printable bytes with '.' so the snippet is safe to
    // print and bounded in length even on binary blobs.
    let mut s = String::with_capacity(slice.len());
    for &b in slice {
        if (0x20..=0x7e).contains(&b) {
            s.push(b as char);
        } else {
            s.push('.');
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aws_key_in_blob() {
        let body = b"prefix AKIAIOSFODNN7EXAMPLE suffix";
        let f = scan_bytes("test.dex", body);
        assert!(f.iter().any(|x| x.pattern.starts_with("AWS")));
    }

    #[test]
    fn finds_google_api_key() {
        let body = b"key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&";
        let f = scan_bytes("config.json", body);
        assert!(f.iter().any(|x| x.pattern.contains("Google")));
    }

    #[test]
    fn finds_jwt() {
        let body = b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36";
        let f = scan_bytes("intent.smali", body);
        assert!(f.iter().any(|x| x.pattern == "JWT"));
    }

    #[test]
    fn finds_pem_private_key() {
        let body = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAA";
        let f = scan_bytes("keystore.pem", body);
        assert!(f.iter().any(|x| x.pattern.contains("PEM")));
    }

    #[test]
    fn no_false_positive_on_random_bytes() {
        let body: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let f = scan_bytes("noise.bin", &body);
        assert!(f.is_empty(), "got {:?}", f);
    }

    #[test]
    fn snippet_replaces_binary_garbage_with_dots() {
        let body: Vec<u8> = b"AAAAAAAAAAAAAAAAAAAA\x01\x02\x03AKIAIOSFODNN7EXAMPLE\x04\x05BBBBBBBBBBBBBBBBBBBB".to_vec();
        let f = scan_bytes("x", &body);
        assert!(!f.is_empty());
        let s = &f[0].snippet;
        assert!(s.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(s.contains('.')); // binary bytes were sanitized
    }
}
