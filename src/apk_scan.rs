//! Static analysis of an Android APK.
//!
//! APKs are zip archives. We pull out `AndroidManifest.xml` (Android
//! Binary XML — AXML), parse only its string-pool to enumerate
//! permissions and component class names, then scan the rest of the
//! archive (classes.dex, resources, native .so) for hardcoded
//! secrets and SSL-pinning library references.
//!
//! Scope intentionally narrow:
//!   - **Permissions** — strings beginning with `android.permission.`
//!     surfaced as `dangerous` when they fall in the runtime-prompt
//!     set (READ_SMS, ACCESS_FINE_LOCATION, RECORD_AUDIO, …).
//!   - **Component class names** — anything matching
//!     `[a-z0-9_.]+\.[A-Z][A-Za-z0-9_]+` plus an `Activity`,
//!     `Service`, `Receiver`, or `Provider` suffix.
//!   - **Manifest flags** — heuristically detected by string
//!     presence: `debuggable`, `allowBackup`, `usesCleartextTraffic`,
//!     `cleartextTrafficPermitted`. Surfaces a finding when the
//!     attribute appears (the AXML value-decode would need a full
//!     parser; for triage the *presence* of the attribute is enough
//!     to warrant a manual look).
//!   - **SSL pinning** — looks for `okhttp3/CertificatePinner`,
//!     `TrustKit`, `network_security_config` references in the dex
//!     and resource paths.
//!   - **Hardcoded secrets** — see `mobile_secrets`.
//!
//! No code execution, no instrumentation. Pure file reads.

use crate::mobile_secrets::{scan_bytes, SecretFinding};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApkReport {
    pub path: String,
    pub package_hint: Option<String>,
    pub permissions: Vec<String>,
    pub dangerous_permissions: Vec<String>,
    pub components: Vec<String>,
    pub flags_present: Vec<String>,
    pub network_security_config: Option<String>,
    pub pinning_libraries: Vec<String>,
    pub secrets: Vec<SecretFinding>,
}

const DANGEROUS_PERMS: &[&str] = &[
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.QUERY_ALL_PACKAGES",
];

const SUSPICIOUS_FLAG_NAMES: &[&str] = &[
    "debuggable",
    "allowBackup",
    "usesCleartextTraffic",
    "cleartextTrafficPermitted",
    "testOnly",
    "exported",
];

const PINNING_MARKERS: &[(&str, &str)] = &[
    ("okhttp3/CertificatePinner", "OkHttp CertificatePinner"),
    ("com/datatheorem/android/trustkit", "TrustKit"),
    ("network_security_config", "Network Security Config (XML)"),
    ("javax/net/ssl/X509TrustManager", "X509TrustManager (custom)"),
    ("io/grpc/okhttp/OkHttpChannelBuilder", "gRPC + OkHttp"),
];

pub fn scan(path: &Path) -> Result<ApkReport> {
    let mut report = ApkReport {
        path: path.display().to_string(),
        ..Default::default()
    };
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("read APK as zip")?;

    let mut all_strings: HashSet<String> = HashSet::new();

    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        let name = entry.name().to_string();

        // Read entry into memory — APKs are usually < 100 MiB so this
        // is fine. We cap at 50 MiB per entry to avoid OOM on weird
        // ones.
        let mut buf = Vec::new();
        entry.take(50 * 1024 * 1024).read_to_end(&mut buf).ok();

        if name == "AndroidManifest.xml" {
            let strings = parse_axml_string_pool(&buf);
            for s in strings {
                all_strings.insert(s);
            }
        } else if name.starts_with("res/xml/") && name.ends_with(".xml") {
            // Network Security Config and other resource XML are
            // also AXML-encoded; pull strings the same way so we
            // can spot pinning references.
            let strings = parse_axml_string_pool(&buf);
            for s in strings {
                if s.contains("pin-set") || s.contains("network-security-config") {
                    report.network_security_config = Some(name.clone());
                }
            }
        }

        // Secret + pinning scan against every entry's bytes.
        for f in scan_bytes(&name, &buf) {
            // De-dupe by (pattern, file).
            if !report.secrets.iter().any(|x| x.pattern == f.pattern && x.file == f.file) {
                report.secrets.push(f);
            }
        }
        for (needle, lib) in PINNING_MARKERS {
            if buf.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                let s = lib.to_string();
                if !report.pinning_libraries.contains(&s) {
                    report.pinning_libraries.push(s);
                }
            }
        }
    }

    classify_strings(&all_strings, &mut report);
    Ok(report)
}

fn classify_strings(strings: &HashSet<String>, report: &mut ApkReport) {
    let mut perms: Vec<String> = strings
        .iter()
        .filter(|s| s.starts_with("android.permission.") || s.starts_with("com.android.permission."))
        .cloned()
        .collect();
    perms.sort();
    report.permissions = perms.clone();
    report.dangerous_permissions = perms
        .into_iter()
        .filter(|p| DANGEROUS_PERMS.contains(&p.as_str()))
        .collect();

    // Component class names — Java-style identifiers ending in
    // Activity / Service / Receiver / Provider (the four exported
    // component types).
    let mut comps: Vec<String> = strings
        .iter()
        .filter(|s| {
            s.contains('.')
                && !s.starts_with("android.")
                && (s.ends_with("Activity")
                    || s.ends_with("Service")
                    || s.ends_with("Receiver")
                    || s.ends_with("Provider"))
        })
        .cloned()
        .collect();
    comps.sort();
    comps.dedup();
    report.components = comps;

    // Heuristic package hint — first dotted name with no spaces and
    // no upper-case letters in the first label.
    report.package_hint = strings
        .iter()
        .filter(|s| {
            let dots = s.matches('.').count();
            (2..=6).contains(&dots)
                && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
                && !s.starts_with("android.")
        })
        .min_by_key(|s| s.len())
        .cloned();

    for flag in SUSPICIOUS_FLAG_NAMES {
        if strings.iter().any(|s| s == flag) {
            report.flags_present.push(flag.to_string());
        }
    }
}

/// Minimal Android Binary XML string-pool extractor.
///
/// Layout (LE, all sizes in bytes):
///   - **XML header chunk** at offset 0: u16 type(0x0003), u16
///     header_size(8), u32 chunk_size.
///   - **String-pool chunk** starts at offset 8: u16 type(0x0001),
///     u16 header_size(28), u32 chunk_size, u32 string_count, u32
///     style_count, u32 flags (bit 0x100 = UTF-8), u32 strings_start,
///     u32 styles_start.
///   - String offsets table follows the header (string_count × u32).
///   - String data is at chunk_offset + strings_start; each entry's
///     length-prefix differs by encoding (UTF-8: u8/u16, UTF-16: u16/u32).
fn parse_axml_string_pool(buf: &[u8]) -> Vec<String> {
    if buf.len() < 16 {
        return Vec::new();
    }
    // Verify XML chunk magic.
    if u16::from_le_bytes([buf[0], buf[1]]) != 0x0003 {
        return Vec::new();
    }
    let pool_off = 8usize;
    if pool_off + 28 > buf.len() {
        return Vec::new();
    }
    if u16::from_le_bytes([buf[pool_off], buf[pool_off + 1]]) != 0x0001 {
        return Vec::new();
    }
    let string_count =
        u32::from_le_bytes([buf[pool_off + 8], buf[pool_off + 9], buf[pool_off + 10], buf[pool_off + 11]]) as usize;
    let flags = u32::from_le_bytes([
        buf[pool_off + 16],
        buf[pool_off + 17],
        buf[pool_off + 18],
        buf[pool_off + 19],
    ]);
    let strings_start = u32::from_le_bytes([
        buf[pool_off + 20],
        buf[pool_off + 21],
        buf[pool_off + 22],
        buf[pool_off + 23],
    ]) as usize;
    let utf8 = (flags & 0x100) != 0;
    let offsets_start = pool_off + 28;
    let strings_data_off = pool_off + strings_start;

    let mut out = Vec::with_capacity(string_count.min(8192));
    for i in 0..string_count.min(65536) {
        let op = offsets_start + i * 4;
        if op + 4 > buf.len() {
            break;
        }
        let off = u32::from_le_bytes([buf[op], buf[op + 1], buf[op + 2], buf[op + 3]]) as usize;
        let p = strings_data_off + off;
        if p >= buf.len() {
            break;
        }
        let parsed = if utf8 {
            decode_utf8_entry(buf, p)
        } else {
            decode_utf16_entry(buf, p)
        };
        if let Some(s) = parsed {
            out.push(s);
        }
    }
    out
}

fn decode_utf8_entry(buf: &[u8], mut p: usize) -> Option<String> {
    // First length is the UTF-16 length (we ignore it). Either 1 or 2
    // bytes — high bit on the first byte signals 2-byte form.
    if p >= buf.len() {
        return None;
    }
    if buf[p] & 0x80 != 0 {
        if p + 2 > buf.len() {
            return None;
        }
        p += 2;
    } else {
        p += 1;
    }
    if p >= buf.len() {
        return None;
    }
    // Second length is the UTF-8 byte length (same 1/2-byte scheme).
    let len = if buf[p] & 0x80 != 0 {
        if p + 2 > buf.len() {
            return None;
        }
        let v = (((buf[p] & 0x7f) as usize) << 8) | buf[p + 1] as usize;
        p += 2;
        v
    } else {
        let v = buf[p] as usize;
        p += 1;
        v
    };
    if p + len > buf.len() {
        return None;
    }
    std::str::from_utf8(&buf[p..p + len]).ok().map(String::from)
}

fn decode_utf16_entry(buf: &[u8], p: usize) -> Option<String> {
    if p + 2 > buf.len() {
        return None;
    }
    let lw = u16::from_le_bytes([buf[p], buf[p + 1]]);
    let (len, hdr) = if lw & 0x8000 != 0 {
        if p + 4 > buf.len() {
            return None;
        }
        let extra = u16::from_le_bytes([buf[p + 2], buf[p + 3]]);
        ((((lw & 0x7fff) as usize) << 16) | extra as usize, 4)
    } else {
        (lw as usize, 2)
    };
    let bytes_needed = len.checked_mul(2)?;
    if p + hdr + bytes_needed > buf.len() {
        return None;
    }
    let units: Vec<u16> = buf[p + hdr..p + hdr + bytes_needed]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

pub fn print_report(r: &ApkReport) {
    use colored::*;
    println!();
    println!("{}", format!("APK static scan: {}", r.path).bold());
    if let Some(pkg) = &r.package_hint {
        println!("  package hint        : {}", pkg);
    }
    println!(
        "  permissions         : {} ({} dangerous)",
        r.permissions.len(),
        r.dangerous_permissions.len()
    );
    if !r.dangerous_permissions.is_empty() {
        for p in &r.dangerous_permissions {
            println!("    {} {}", "·".red(), p);
        }
    }
    if !r.components.is_empty() {
        println!("  components          : {} class names", r.components.len());
        for c in r.components.iter().take(20) {
            println!("    · {}", c);
        }
        if r.components.len() > 20 {
            println!("    … {} more", r.components.len() - 20);
        }
    }
    if !r.flags_present.is_empty() {
        println!("  manifest flag refs  : {}", r.flags_present.join(", ").yellow());
    }
    if let Some(nsc) = &r.network_security_config {
        println!("  pinning config      : {} (network_security_config / pin-set)", nsc.green());
    }
    if !r.pinning_libraries.is_empty() {
        println!("  pinning libraries   : {}", r.pinning_libraries.join(", ").green());
    }
    if r.secrets.is_empty() {
        println!("  secrets             : {}", "none detected".green());
    } else {
        println!("  {}", format!("secrets ({} finding(s)):", r.secrets.len()).red().bold());
        for s in &r.secrets {
            println!("    · [{}] {} — {}", s.pattern, s.file, s.snippet);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_min_axml(strings: &[&str]) -> Vec<u8> {
        // Build a tiny AXML with just an XML chunk header + a UTF-8
        // string pool. Real AXML has more chunks, but our parser only
        // touches the string pool.
        let utf8_flag = 0x100u32;
        let n = strings.len() as u32;
        let header_size = 28u32;
        let offsets_size = n * 4;
        let mut data = Vec::new();
        let mut offsets: Vec<u32> = Vec::new();
        for s in strings {
            offsets.push(data.len() as u32);
            // Length is small (< 128), one-byte each form.
            // The "u16 length" precedes the "u8 length" in UTF-8 mode.
            data.push(s.len() as u8); // u16 length placeholder (we ignore it on parse)
            data.push(s.len() as u8); // u8 length
            data.extend_from_slice(s.as_bytes());
            data.push(0); // terminator
        }
        let strings_start = header_size + offsets_size;
        let chunk_size = strings_start + data.len() as u32;
        let mut out = Vec::new();
        // XML chunk header (8B)
        out.extend_from_slice(&0x0003u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&(8u32 + chunk_size).to_le_bytes());
        // String pool chunk header (28B)
        out.extend_from_slice(&0x0001u16.to_le_bytes());
        out.extend_from_slice(&28u16.to_le_bytes());
        out.extend_from_slice(&chunk_size.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // styles
        out.extend_from_slice(&utf8_flag.to_le_bytes());
        out.extend_from_slice(&strings_start.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // styles_start
        // Offsets
        for o in &offsets {
            out.extend_from_slice(&o.to_le_bytes());
        }
        out.extend_from_slice(&data);
        out
    }

    #[test]
    fn parses_synthetic_axml_string_pool() {
        let axml = build_min_axml(&[
            "android.permission.INTERNET",
            "com.example.MyActivity",
            "debuggable",
        ]);
        let strings = parse_axml_string_pool(&axml);
        assert!(strings.contains(&"android.permission.INTERNET".to_string()));
        assert!(strings.contains(&"com.example.MyActivity".to_string()));
        assert!(strings.contains(&"debuggable".to_string()));
    }

    #[test]
    fn classify_picks_dangerous_permissions() {
        let mut report = ApkReport::default();
        let strings: HashSet<String> = vec![
            "android.permission.INTERNET".to_string(),
            "android.permission.READ_SMS".to_string(),
            "android.permission.CAMERA".to_string(),
        ].into_iter().collect();
        classify_strings(&strings, &mut report);
        assert_eq!(report.permissions.len(), 3);
        assert_eq!(report.dangerous_permissions.len(), 2); // SMS + CAMERA
    }

    #[test]
    fn classify_picks_components() {
        let mut report = ApkReport::default();
        let strings: HashSet<String> = vec![
            "com.example.MainActivity".to_string(),
            "com.example.SyncService".to_string(),
            "com.example.BootReceiver".to_string(),
            "com.example.SomeProvider".to_string(),
            "com.example.NotAComponent".to_string(),
        ].into_iter().collect();
        classify_strings(&strings, &mut report);
        assert_eq!(report.components.len(), 4);
    }

    #[test]
    fn classify_extracts_flag_presence() {
        let mut report = ApkReport::default();
        let strings: HashSet<String> = vec![
            "debuggable".to_string(),
            "allowBackup".to_string(),
        ].into_iter().collect();
        classify_strings(&strings, &mut report);
        assert!(report.flags_present.contains(&"debuggable".to_string()));
        assert!(report.flags_present.contains(&"allowBackup".to_string()));
    }
}
