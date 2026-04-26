//! Runtime loaders for nmap's data files.
//!
//! These let users bring their own copy of `nmap-os-db` and
//! `nmap-service-probes` (both GPLv2 — incompatible with our MIT
//! source) without us bundling the data. The parser is tolerant:
//! anything that doesn't fit our model is silently skipped, so a
//! single bad line never breaks a scan.
//!
//! From `nmap-os-db` we only consume the human-readable blocks
//! (`Fingerprint`, `Class`, `CPE`) — implementing nmap's full
//! TCP/IP probe engine would be a project on its own. The labels we
//! lift improve OS-family naming; the actual TTL/banner heuristics
//! stay in `os_fp.rs`.
//!
//! From `nmap-service-probes` we consume `match` lines, which are
//! literally `regex → product/version/info` mappings — a perfect fit
//! for our existing `Signature` model. Anything Rust's regex crate
//! can't compile (Perl-only constructs) is dropped with a warning.

use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use regex::Regex;
use std::fs;
use std::path::Path;

// ── nmap-os-db ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OsDbEntry {
    /// Full fingerprint name e.g. "Linux 4.15 - 5.6"
    pub name: String,
    /// Vendor / family / version / device-type tuple from `Class` lines
    pub classes: Vec<String>,
    /// CPE strings from `CPE` lines
    pub cpe: Vec<String>,
}

static OS_DB: OnceCell<Vec<OsDbEntry>> = OnceCell::new();

pub fn load_os_db<P: AsRef<Path>>(path: P) -> Result<usize> {
    let body = fs::read_to_string(&path)
        .with_context(|| format!("read {:?}", path.as_ref()))?;
    let entries = parse_os_db(&body);
    let n = entries.len();
    let _ = OS_DB.set(entries);
    Ok(n)
}

pub fn os_db() -> Option<&'static [OsDbEntry]> {
    OS_DB.get().map(|v| v.as_slice())
}

fn parse_os_db(body: &str) -> Vec<OsDbEntry> {
    let mut out = Vec::new();
    let mut cur: Option<OsDbEntry> = None;
    for line in body.lines() {
        let l = line.trim_end();
        // Blank line = end of current entry
        if l.is_empty() {
            if let Some(e) = cur.take() {
                if !e.name.is_empty() {
                    out.push(e);
                }
            }
            continue;
        }
        if l.starts_with('#') {
            continue;
        }
        if let Some(rest) = l.strip_prefix("Fingerprint ") {
            if let Some(prev) = cur.take() {
                if !prev.name.is_empty() {
                    out.push(prev);
                }
            }
            cur = Some(OsDbEntry {
                name: rest.trim().to_string(),
                classes: Vec::new(),
                cpe: Vec::new(),
            });
        } else if let Some(rest) = l.strip_prefix("Class ") {
            if let Some(e) = cur.as_mut() {
                e.classes.push(rest.trim().to_string());
            }
        } else if let Some(rest) = l.strip_prefix("CPE ") {
            if let Some(e) = cur.as_mut() {
                // strip the trailing " auto" marker if present
                let cleaned = rest.split_whitespace().next().unwrap_or("").to_string();
                if !cleaned.is_empty() {
                    e.cpe.push(cleaned);
                }
            }
        }
        // Skip everything else (SEQ/OPS/WIN/T1..T7/IE/U1 — the binary
        // probe-response data we can't use without implementing nmap's
        // probe engine).
    }
    if let Some(e) = cur.take() {
        if !e.name.is_empty() {
            out.push(e);
        }
    }
    out
}

/// Best-effort: find an OS DB entry whose name overlaps with `banner`.
/// Returns the curated nmap fingerprint label so callers can swap it in
/// for our coarser family guess.
pub fn match_banner_to_os(banner: &str) -> Option<&'static OsDbEntry> {
    let db = os_db()?;
    let lo = banner.to_lowercase();
    // Match against well-known tokens; we don't try to be clever, just
    // find any entry whose name appears whole-word in the banner.
    db.iter().find(|e| {
        let name_lo = e.name.to_lowercase();
        // Check the leading token (e.g. "Linux", "FreeBSD", "VMware")
        if let Some(first) = name_lo.split_whitespace().next() {
            if first.len() > 2 && lo.contains(first) {
                return true;
            }
        }
        false
    })
}

// ── nmap-service-probes ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ServiceMatch {
    /// Nmap service name (e.g. "http", "ssh"). Kept for future use
    /// (UI hints / per-service filtering); not consumed today.
    #[allow(dead_code)]
    pub service: String,
    pub regex: Regex,
    pub product: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
}

static SERVICE_PROBES: OnceCell<Vec<ServiceMatch>> = OnceCell::new();

pub fn load_service_probes<P: AsRef<Path>>(path: P) -> Result<(usize, usize)> {
    let body = fs::read_to_string(&path)
        .with_context(|| format!("read {:?}", path.as_ref()))?;
    let (entries, skipped) = parse_service_probes(&body);
    let n = entries.len();
    let _ = SERVICE_PROBES.set(entries);
    Ok((n, skipped))
}

pub fn service_probes() -> Option<&'static [ServiceMatch]> {
    SERVICE_PROBES.get().map(|v| v.as_slice())
}

/// Parse `match`/`softmatch` lines from nmap-service-probes. Returns
/// (compiled_count, skipped_count). Skips Perl-regex constructs the
/// Rust regex crate can't handle (lookahead, backrefs in the regex
/// itself, named groups with Perl syntax, …).
fn parse_service_probes(body: &str) -> (Vec<ServiceMatch>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in body.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let prefix = if let Some(s) = l.strip_prefix("match ") {
            s
        } else if let Some(s) = l.strip_prefix("softmatch ") {
            s
        } else {
            continue;
        };
        match parse_match_line(prefix) {
            Some(m) => out.push(m),
            None => skipped += 1,
        }
    }
    (out, skipped)
}

/// Parse one `match` body: `<service> m|<pattern>|<flags> [p/.../][v/.../][i/.../]…`
fn parse_match_line(line: &str) -> Option<ServiceMatch> {
    // First whitespace-separated token = service name.
    let mut iter = line.splitn(2, char::is_whitespace);
    let service = iter.next()?.to_string();
    let rest = iter.next()?;
    // Expect `m<delim>...<delim>[flags]`
    let rest = rest.trim_start();
    if !rest.starts_with('m') {
        return None;
    }
    let after_m = &rest[1..];
    let delim = after_m.chars().next()?;
    // Nmap uses non-alphanumeric delimiters (|, =, %, /, #). Reject
    // letters/digits to avoid mis-parsing typo'd lines as valid.
    if delim.is_alphanumeric() {
        return None;
    }
    let body = &after_m[delim.len_utf8()..];
    let close = body.find(delim)?;
    let pattern = &body[..close];
    let after = &body[close + delim.len_utf8()..];
    // Read optional single-char flags ("i" for case-insensitive, "s" for dotall)
    let mut idx = 0usize;
    let mut case_insensitive = false;
    for c in after.chars() {
        match c {
            'i' => case_insensitive = true,
            's' => { /* dotall — Rust regex supports via (?s) */ }
            ' ' | '\t' => break,
            _ => break,
        }
        idx += c.len_utf8();
    }
    let tail = after[idx..].trim_start();

    // Compile regex (prepend (?i)/(?s) flags if needed)
    let mut full = String::new();
    if case_insensitive {
        full.push_str("(?i)");
    }
    full.push_str(pattern);
    let regex = Regex::new(&full).ok()?;

    // Parse trailing fields: p/.../, v/.../, i/.../
    let mut product = None;
    let mut version = None;
    let mut info = None;
    let mut t = tail;
    while !t.is_empty() {
        let key = t.chars().next().unwrap();
        if !matches!(key, 'p' | 'v' | 'i' | 'o' | 'd' | 'h' | 'c') {
            break;
        }
        let after_key = &t[1..];
        let kdelim = after_key.chars().next()?;
        if kdelim.is_alphanumeric() {
            break;
        }
        let body2 = &after_key[kdelim.len_utf8()..];
        let kclose = body2.find(kdelim)?;
        let val = &body2[..kclose];
        let next_off = 1 + kdelim.len_utf8() + kclose + kdelim.len_utf8();
        t = t[next_off..].trim_start();
        match key {
            'p' => product = Some(val.to_string()),
            'v' => version = Some(val.to_string()),
            'i' => info = Some(val.to_string()),
            _ => {}
        }
    }

    Some(ServiceMatch {
        service,
        regex,
        product,
        version,
        info,
    })
}

/// Apply nmap-style $1, $2 backrefs against a captures iterator.
fn substitute(template: &str, caps: &regex::Captures) -> String {
    let mut out = String::new();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            if let Some(d) = chars.peek() {
                if d.is_ascii_digit() {
                    let idx = d.to_digit(10).unwrap() as usize;
                    chars.next();
                    if let Some(m) = caps.get(idx) {
                        out.push_str(m.as_str());
                    }
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

/// Run the loaded probes against `data` and return the first match's
/// (product, version, info) — all three optional. None if no probe matched.
pub fn match_loaded_probes(
    data: &str,
) -> Option<(Option<String>, Option<String>, Option<String>)> {
    let probes = service_probes()?;
    for p in probes {
        if let Some(caps) = p.regex.captures(data) {
            let product = p.product.as_ref().map(|t| substitute(t, &caps));
            let version = p.version.as_ref().map(|t| substitute(t, &caps));
            let info = p.info.as_ref().map(|t| substitute(t, &caps));
            return Some((product, version, info));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_os_db_block() {
        let body = "\
Fingerprint Linux 4.15 - 5.6
Class Linux | Linux | 4.X | general purpose
Class Linux | Linux | 5.X | general purpose
CPE cpe:/o:linux:linux_kernel:4 auto
CPE cpe:/o:linux:linux_kernel:5
SEQ(SP=100-110%GCD=1-6)
OPS(O1=M5B4ST11NW7)

Fingerprint FreeBSD 13.0-RELEASE
Class FreeBSD | FreeBSD | 13.X | general purpose
CPE cpe:/o:freebsd:freebsd:13.0
";
        let entries = parse_os_db(body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "Linux 4.15 - 5.6");
        assert_eq!(entries[0].classes.len(), 2);
        assert_eq!(entries[0].cpe.len(), 2);
        assert_eq!(entries[1].name, "FreeBSD 13.0-RELEASE");
    }

    #[test]
    fn parses_service_match_line() {
        let m = parse_match_line(
            r#"http m|^HTTP/1\.[01] .*\r\nServer: ([\w.-]+)/([\d.]+)|s p/$1/ v/$2/"#,
        )
        .unwrap();
        assert_eq!(m.service, "http");
        assert_eq!(m.product.as_deref(), Some("$1"));
        assert_eq!(m.version.as_deref(), Some("$2"));
        let caps = m
            .regex
            .captures("HTTP/1.1 200 OK\r\nServer: nginx/1.27.0\r\n")
            .unwrap();
        assert_eq!(caps.get(1).unwrap().as_str(), "nginx");
        assert_eq!(caps.get(2).unwrap().as_str(), "1.27.0");
        assert_eq!(substitute(m.product.as_ref().unwrap(), &caps), "nginx");
        assert_eq!(substitute(m.version.as_ref().unwrap(), &caps), "1.27.0");
    }

    #[test]
    fn skips_unparseable_match_lines() {
        let body = "\
match ssh m|^SSH-([\\d.]+)-(\\S+)| p/$1/ v/$2/
match weird m|broken
match invalid mzfoozinvalid p/$1/
";
        let (good, skipped) = parse_service_probes(body);
        assert_eq!(good.len(), 1);
        assert_eq!(good[0].service, "ssh");
        assert!(skipped >= 1);
    }

    #[test]
    fn case_insensitive_flag_works() {
        let m = parse_match_line(r#"http m|server: nginx|i"#).unwrap();
        assert!(m.regex.is_match("HTTP/1.1 200 OK\r\nSERVER: NGINX\r\n"));
    }
}
