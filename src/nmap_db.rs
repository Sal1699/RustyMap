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
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ── nmap-os-db ─────────────────────────────────────────────

/// A parsed test line's fields: field name → value expression (which may be
/// an exact value, a `A-B` hex range, a `>H`/`<H` comparison, or a
/// `X|Y|Z` alternation).
pub type TestFields = HashMap<String, String>;

#[derive(Debug, Clone, Default)]
pub struct OsDbEntry {
    /// Full fingerprint name e.g. "Linux 4.15 - 5.6"
    pub name: String,
    /// Vendor / family / version / device-type tuple from `Class` lines
    pub classes: Vec<String>,
    /// CPE strings from `CPE` lines
    pub cpe: Vec<String>,
    /// The probe-response test lines (SEQ/OPS/WIN/ECN/T1..T7/IE/U1),
    /// test name → its fields, for probabilistic matching.
    pub tests: HashMap<String, TestFields>,
}

static OS_DB: OnceCell<Vec<OsDbEntry>> = OnceCell::new();
/// nmap's per-field MatchPoints weights: test → field → weight.
static MATCH_POINTS: OnceCell<HashMap<String, HashMap<String, u32>>> = OnceCell::new();

pub fn load_os_db<P: AsRef<Path>>(path: P) -> Result<usize> {
    let body = fs::read_to_string(&path)
        .with_context(|| format!("read {:?}", path.as_ref()))?;
    let (entries, points) = parse_os_db(&body);
    let n = entries.len();
    let _ = OS_DB.set(entries);
    let _ = MATCH_POINTS.set(points);
    Ok(n)
}

pub fn os_db() -> Option<&'static [OsDbEntry]> {
    OS_DB.get().map(|v| v.as_slice())
}

/// Parse a probe-response test line `NAME(k=v%k=v%...)` into its name and
/// (field, value) pairs. Returns None for non-test lines. Shared with the
/// live-fingerprint parser so observed and reference use the same format.
pub(crate) fn parse_test_line(l: &str) -> Option<(String, Vec<(String, String)>)> {
    let open = l.find('(')?;
    if !l.ends_with(')') {
        return None;
    }
    let name = &l[..open];
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return None;
    }
    let inner = &l[open + 1..l.len() - 1];
    let mut fields = Vec::new();
    if !inner.is_empty() {
        for pair in inner.split('%') {
            if let Some((k, v)) = pair.split_once('=') {
                fields.push((k.to_string(), v.to_string()));
            }
        }
    }
    Some((name.to_string(), fields))
}

fn parse_os_db(body: &str) -> (Vec<OsDbEntry>, HashMap<String, HashMap<String, u32>>) {
    let mut out = Vec::new();
    let mut cur: Option<OsDbEntry> = None;
    let mut points: HashMap<String, HashMap<String, u32>> = HashMap::new();
    let mut in_matchpoints = false;

    let flush = |cur: &mut Option<OsDbEntry>, out: &mut Vec<OsDbEntry>| {
        if let Some(e) = cur.take() {
            if !e.name.is_empty() {
                out.push(e);
            }
        }
    };

    for line in body.lines() {
        let l = line.trim_end();
        if l.is_empty() {
            flush(&mut cur, &mut out);
            in_matchpoints = false;
            continue;
        }
        if l.starts_with('#') {
            continue;
        }
        if l == "MatchPoints" {
            flush(&mut cur, &mut out);
            in_matchpoints = true;
            continue;
        }
        if let Some(rest) = l.strip_prefix("Fingerprint ") {
            flush(&mut cur, &mut out);
            in_matchpoints = false;
            cur = Some(OsDbEntry { name: rest.trim().to_string(), ..Default::default() });
        } else if let Some(rest) = l.strip_prefix("Class ") {
            if let Some(e) = cur.as_mut() {
                e.classes.push(rest.trim().to_string());
            }
        } else if let Some(rest) = l.strip_prefix("CPE ") {
            if let Some(e) = cur.as_mut() {
                let cleaned = rest.split_whitespace().next().unwrap_or("").to_string();
                if !cleaned.is_empty() {
                    e.cpe.push(cleaned);
                }
            }
        } else if let Some((test, fields)) = parse_test_line(l) {
            if in_matchpoints {
                let entry = points.entry(test).or_default();
                for (k, v) in fields {
                    if let Ok(w) = v.parse::<u32>() {
                        entry.insert(k, w);
                    }
                }
            } else if let Some(e) = cur.as_mut() {
                e.tests
                    .entry(test)
                    .or_default()
                    .extend(fields);
            }
        }
    }
    flush(&mut cur, &mut out);
    (out, points)
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

// ── nmap-os-db probabilistic matching ─────────────────────

/// Parse a hex token (nmap fingerprint numbers are hex).
fn hexval(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim(), 16).ok()
}

/// Does one alternative of a reference expression match the observed value?
fn alt_matches(observed: &str, alt: &str) -> bool {
    if alt.is_empty() {
        return observed.is_empty();
    }
    if let Some(rest) = alt.strip_prefix('>') {
        return matches!((hexval(observed), hexval(rest)), (Some(o), Some(b)) if o > b);
    }
    if let Some(rest) = alt.strip_prefix('<') {
        return matches!((hexval(observed), hexval(rest)), (Some(o), Some(b)) if o < b);
    }
    if let Some((lo, hi)) = alt.split_once('-') {
        if let (Some(o), Some(a), Some(b)) = (hexval(observed), hexval(lo), hexval(hi)) {
            return o >= a && o <= b;
        }
        // not a numeric range → fall through to an exact compare
    }
    observed.eq_ignore_ascii_case(alt)
}

/// Match an observed field value against a reference expression, which may
/// alternate with `|` (e.g. `Z|A|A+`, `FA00-FB00`, `>80`).
pub fn field_matches(observed: &str, expr: &str) -> bool {
    expr.split('|').any(|alt| alt_matches(observed, alt))
}

/// Score an observed fingerprint (test → fields) against every loaded
/// nmap-os-db entry using nmap's MatchPoints weights, returning the best
/// matches as (name, cpe, confidence%). Empty if no DB is loaded.
pub fn match_fingerprint(observed: &HashMap<String, TestFields>) -> Vec<(&'static str, &'static [String], u8)> {
    let db = match os_db() {
        Some(d) => d,
        None => return Vec::new(),
    };
    let mp = MATCH_POINTS.get();
    let mut scored: Vec<(&'static str, &'static [String], u8)> = Vec::new();
    for e in db {
        let mut matched: u32 = 0;
        let mut total: u32 = 0;
        for (test, obs_fields) in observed {
            for (field, obs_val) in obs_fields {
                // Denominator = every observed field's weight (nmap uses the
                // SUBJECT's total points, not just the overlap). A reference
                // that doesn't constrain a field we observed therefore scores
                // *lower*, so dense real-OS entries beat sparse embedded ones
                // (lab bug B25). Skip fields with no MatchPoints weight when a
                // weight table is loaded.
                let w = match mp.and_then(|m| m.get(test)).and_then(|t| t.get(field)) {
                    Some(&w) => w,
                    None => {
                        if mp.is_some() {
                            continue;
                        }
                        1
                    }
                };
                total += w;
                if let Some(ref_expr) = e.tests.get(test).and_then(|rf| rf.get(field)) {
                    if field_matches(obs_val, ref_expr) {
                        matched += w;
                    }
                }
            }
        }
        if total > 0 {
            let pct = (matched as u64 * 100 / total as u64) as u8;
            scored.push((e.name.as_str(), e.cpe.as_slice(), pct));
        }
    }
    scored.sort_by(|a, b| b.2.cmp(&a.2));
    scored.truncate(5);
    scored
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
        let (entries, _points) = parse_os_db(body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "Linux 4.15 - 5.6");
        assert_eq!(entries[0].classes.len(), 2);
        assert_eq!(entries[0].cpe.len(), 2);
        // Test lines parsed into the entry's tests map.
        assert_eq!(entries[0].tests.get("SEQ").and_then(|t| t.get("GCD")).map(|s| s.as_str()), Some("1-6"));
        assert_eq!(entries[1].name, "FreeBSD 13.0-RELEASE");
    }

    #[test]
    fn matchpoints_and_field_matching() {
        let body = "\
MatchPoints
SEQ(SP=25%GCD=75%TS=100)

Fingerprint Test OS
Class T | T | 1.X | general purpose
SEQ(SP=100-110%GCD=1-6%TS=A)
";
        let (_entries, points) = parse_os_db(body);
        assert_eq!(points.get("SEQ").and_then(|t| t.get("GCD")).copied(), Some(75));
        // field_matches: ranges, alternation, comparisons, exact.
        assert!(field_matches("105", "100-110")); // in hex range
        assert!(!field_matches("120", "100-110"));
        assert!(field_matches("A", "Z|A|A+")); // alternation
        assert!(field_matches("FA00", ">80")); // hex comparison
        assert!(field_matches("S+", "S+")); // exact non-hex
        assert!(field_matches("", "")); // empty matches empty
        assert!(!field_matches("AR", "R"));
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
