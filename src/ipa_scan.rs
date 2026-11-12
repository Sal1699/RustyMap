//! Static analysis of an iOS IPA bundle.
//!
//! IPAs are zip archives shaped as `Payload/<name>.app/…`. We pull
//! `Info.plist` (auto-detect binary/XML via the `plist` crate),
//! parse the App Transport Security block + URL schemes + bundle
//! identity, then sweep every entry for the same secrets and pinning
//! markers we look for in APKs.
//!
//! Findings:
//!   - **ATS exceptions** — `NSAllowsArbitraryLoads = true`,
//!     per-domain `NSExceptionAllowsInsecureHTTPLoads`, low minimum
//!     TLS version. Each is a regression from Apple's secure default.
//!   - **URL schemes** — registered handlers (`CFBundleURLSchemes`)
//!     can be hijacked by malicious apps that register the same
//!     scheme; we list them so the reviewer can decide whether deep
//!     links should require Universal Links instead.
//!   - **SSL pinning** — TrustKit / NSURLSessionDelegate pinning
//!     references in the main binary or the Info.plist
//!     `TSKConfiguration` key.
//!   - **Hardcoded secrets** — see `mobile_secrets`.
//!   - **Mach-O hardening** — parses the main binary's header: arch, PIE
//!     (ASLR), FairPlay encryption (cryptid), code-signature presence, and
//!     an `__RESTRICT` anti-debug segment.
//!   - **Entitlements** — slices the cleartext plist out of the signed
//!     `embedded.mobileprovision` (CMS) and flags `get-task-allow`
//!     (debuggable), `aps-environment`, and notable capabilities.
//!
//! Pure file reads, no execution.

use crate::mobile_secrets::{scan_bytes, SecretFinding};
use anyhow::{anyhow, Context, Result};
use plist::Value;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpaReport {
    pub path: String,
    pub bundle_id: Option<String>,
    pub display_name: Option<String>,
    pub version: Option<String>,
    pub min_os: Option<String>,
    pub url_schemes: Vec<String>,
    pub ats_findings: Vec<String>,
    pub pinning_libraries: Vec<String>,
    pub secrets: Vec<SecretFinding>,
    pub macho: Option<MachOInfo>,
    pub entitlements: Vec<String>,
}

/// Security-relevant flags read from the main Mach-O executable's header.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MachOInfo {
    pub arch: String,
    pub pie: bool,            // MH_PIE — ASLR for the main executable
    pub encrypted: bool,      // LC_ENCRYPTION_INFO cryptid != 0 (App Store FairPlay)
    pub code_signature: bool, // LC_CODE_SIGNATURE present
    pub restrict: bool,       // __RESTRICT segment (anti-debug)
}

const PINNING_MARKERS: &[(&[u8], &str)] = &[
    (b"TrustKit", "TrustKit"),
    (b"TSKConfigurationKey", "TrustKit (config key)"),
    (b"NSPinnedDomains", "NSPinnedDomains (iOS 14+)"),
    (b"SecTrustEvaluate", "SecTrustEvaluate (custom verifier)"),
    (b"didReceiveChallenge", "URLSession didReceiveChallenge (custom)"),
];

pub fn scan(path: &Path) -> Result<IpaReport> {
    let mut report = IpaReport {
        path: path.display().to_string(),
        ..Default::default()
    };
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("read IPA as zip")?;

    let mut info_plist_bytes: Option<Vec<u8>> = None;
    let mut macho_bytes: Option<Vec<u8>> = None;
    let mut provision_bytes: Option<Vec<u8>> = None;

    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        let name = entry.name().to_string();

        let mut buf = Vec::new();
        entry.take(50 * 1024 * 1024).read_to_end(&mut buf).ok();

        // The Info.plist sits at Payload/<App>.app/Info.plist
        if name.starts_with("Payload/") && name.ends_with(".app/Info.plist") {
            info_plist_bytes = Some(buf.clone());
        }
        // The signed provisioning profile carries the entitlements plist.
        if name.ends_with(".app/embedded.mobileprovision") {
            provision_bytes = Some(buf.clone());
        }
        // The main executable is the top-level file inside the .app (no further
        // "/" after ".app/") whose first bytes are a Mach-O magic.
        if macho_bytes.is_none() {
            if let Some(rest) = name.split(".app/").nth(1) {
                if !rest.contains('/') && is_macho_magic(&buf) {
                    macho_bytes = Some(buf.clone());
                }
            }
        }

        for f in scan_bytes(&name, &buf) {
            if !report.secrets.iter().any(|x| x.pattern == f.pattern && x.file == f.file) {
                report.secrets.push(f);
            }
        }
        for (needle, lib) in PINNING_MARKERS {
            if buf.windows(needle.len()).any(|w| w == *needle) {
                let s = lib.to_string();
                if !report.pinning_libraries.contains(&s) {
                    report.pinning_libraries.push(s);
                }
            }
        }
    }

    let plist_bytes = info_plist_bytes
        .ok_or_else(|| anyhow!("Info.plist not found inside Payload/*.app/"))?;
    parse_info_plist(&plist_bytes, &mut report);
    if let Some(mb) = &macho_bytes {
        report.macho = parse_macho(mb);
    }
    if let Some(pb) = &provision_bytes {
        report.entitlements = parse_mobileprovision(pb);
    }
    Ok(report)
}

fn is_macho_magic(b: &[u8]) -> bool {
    if b.len() < 4 {
        return false;
    }
    matches!(
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE | 0xCAFE_BABE | 0xCAFE_BABF
    )
}

/// Parse the main Mach-O image's security flags. Fat/universal binaries are
/// followed to their first architecture slice; iOS slices are little-endian.
fn parse_macho(bytes: &[u8]) -> Option<MachOInfo> {
    if bytes.len() < 8 {
        return None;
    }
    match u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) {
        0xCAFE_BABE => {
            // 32-bit fat: fat_arch[0].offset is a big-endian u32 at byte 16.
            let off = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
            bytes.get(off..).and_then(parse_thin_macho)
        }
        0xCAFE_BABF => {
            // 64-bit fat: fat_arch_64[0].offset is a big-endian u64 at byte 16.
            if bytes.len() < 24 {
                return None;
            }
            let mut o = [0u8; 8];
            o.copy_from_slice(&bytes[16..24]);
            bytes.get(u64::from_be_bytes(o) as usize..).and_then(parse_thin_macho)
        }
        _ => parse_thin_macho(bytes),
    }
}

fn parse_thin_macho(b: &[u8]) -> Option<MachOInfo> {
    if b.len() < 28 {
        return None;
    }
    let is64 = match u32::from_le_bytes([b[0], b[1], b[2], b[3]]) {
        0xFEED_FACF => true,
        0xFEED_FACE => false,
        _ => return None, // not a little-endian Mach-O (all iOS slices are LE)
    };
    let cputype = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let ncmds = u32::from_le_bytes([b[16], b[17], b[18], b[19]]);
    // mach_header layout: … ncmds@16, sizeofcmds@20, flags@24 (then reserved@28
    // for 64-bit). flags carries MH_PIE.
    let flags = u32::from_le_bytes([b[24], b[25], b[26], b[27]]);
    let arch = match cputype {
        0x0100_000C => "arm64",
        0x0000_000C => "armv7",
        0x0100_0007 => "x86_64",
        0x0000_0007 => "x86",
        _ => "unknown",
    }
    .to_string();
    let mut info = MachOInfo {
        arch,
        pie: flags & 0x0020_0000 != 0, // MH_PIE
        ..Default::default()
    };
    let mut off = if is64 { 32 } else { 28 };
    for _ in 0..ncmds {
        if off + 8 > b.len() {
            break;
        }
        let cmd = u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
        let cmdsize =
            u32::from_le_bytes([b[off + 4], b[off + 5], b[off + 6], b[off + 7]]) as usize;
        if cmdsize < 8 {
            break;
        }
        match cmd {
            0x1D => info.code_signature = true, // LC_CODE_SIGNATURE
            0x21 | 0x2C => {
                // LC_ENCRYPTION_INFO[_64]: cryptid is the 3rd u32 after the header.
                if off + 20 <= b.len() {
                    let cryptid =
                        u32::from_le_bytes([b[off + 16], b[off + 17], b[off + 18], b[off + 19]]);
                    info.encrypted = cryptid != 0;
                }
            }
            0x01 | 0x19 => {
                // LC_SEGMENT[_64]: segname is 16 bytes at off+8.
                if off + 24 <= b.len() && b[off + 8..off + 24].starts_with(b"__RESTRICT") {
                    info.restrict = true;
                }
            }
            _ => {}
        }
        off += cmdsize;
    }
    Some(info)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Slice the cleartext entitlements plist out of the signed (CMS/PKCS7)
/// `embedded.mobileprovision` and flag the security-relevant keys.
fn parse_mobileprovision(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let start = match find_subslice(bytes, b"<?xml").or_else(|| find_subslice(bytes, b"<plist")) {
        Some(s) => s,
        None => return out,
    };
    let end = match find_subslice(&bytes[start..], b"</plist>") {
        Some(e) => start + e + "</plist>".len(),
        None => return out,
    };
    let value = match Value::from_reader(std::io::Cursor::new(&bytes[start..end])) {
        Ok(v) => v,
        Err(_) => return out,
    };
    let ent = match value
        .as_dictionary()
        .and_then(|d| d.get("Entitlements"))
        .and_then(|v| v.as_dictionary())
    {
        Some(e) => e,
        None => return out,
    };
    if let Some(true) = ent.get("get-task-allow").and_then(|v| v.as_boolean()) {
        out.push(
            "get-task-allow = true — app is debuggable (dev/ad-hoc build; must be false for App Store)"
                .into(),
        );
    }
    if let Some(aps) = ent.get("aps-environment").and_then(|v| v.as_string()) {
        out.push(format!("aps-environment = {} (push notifications)", aps));
    }
    for key in [
        "keychain-access-groups",
        "com.apple.security.application-groups",
        "com.apple.developer.associated-domains",
        "com.apple.developer.networking.vpn.api",
        "com.apple.developer.networking.HotspotConfiguration",
        "com.apple.developer.default-data-protection",
    ] {
        if ent.get(key).is_some() {
            out.push(format!("entitlement: {}", key));
        }
    }
    out
}

fn parse_info_plist(bytes: &[u8], report: &mut IpaReport) {
    let value = match Value::from_reader(std::io::Cursor::new(bytes)) {
        Ok(v) => v,
        Err(e) => {
            report
                .ats_findings
                .push(format!("Info.plist parse failed: {}", e));
            return;
        }
    };
    let dict = match value.as_dictionary() {
        Some(d) => d,
        None => return,
    };

    report.bundle_id = dict
        .get("CFBundleIdentifier")
        .and_then(|v| v.as_string())
        .map(String::from);
    report.display_name = dict
        .get("CFBundleDisplayName")
        .or_else(|| dict.get("CFBundleName"))
        .and_then(|v| v.as_string())
        .map(String::from);
    report.version = dict
        .get("CFBundleShortVersionString")
        .and_then(|v| v.as_string())
        .map(String::from);
    report.min_os = dict
        .get("MinimumOSVersion")
        .and_then(|v| v.as_string())
        .map(String::from);

    if let Some(types) = dict.get("CFBundleURLTypes").and_then(|v| v.as_array()) {
        for t in types {
            if let Some(d) = t.as_dictionary() {
                if let Some(arr) = d.get("CFBundleURLSchemes").and_then(|v| v.as_array()) {
                    for s in arr {
                        if let Some(s) = s.as_string() {
                            report.url_schemes.push(s.to_string());
                        }
                    }
                }
            }
        }
    }

    if let Some(ats) = dict.get("NSAppTransportSecurity").and_then(|v| v.as_dictionary()) {
        audit_ats(ats, report);
    }
    if dict.get("TSKConfiguration").is_some() {
        if !report.pinning_libraries.iter().any(|s| s.contains("TrustKit")) {
            report.pinning_libraries.push("TrustKit (TSKConfiguration in Info.plist)".into());
        }
    }
    // iOS 14+ NSPinnedDomains.
    if dict.get("NSPinnedDomains").is_some()
        && !report.pinning_libraries.iter().any(|s| s.contains("NSPinnedDomains"))
    {
        report.pinning_libraries.push("NSPinnedDomains (iOS 14+)".into());
    }
}

fn audit_ats(ats: &plist::Dictionary, report: &mut IpaReport) {
    if let Some(true) = ats
        .get("NSAllowsArbitraryLoads")
        .and_then(|v| v.as_boolean())
    {
        report.ats_findings.push(
            "NSAllowsArbitraryLoads = true — ATS effectively disabled, all HTTP allowed".into(),
        );
    }
    if let Some(true) = ats
        .get("NSAllowsArbitraryLoadsForMedia")
        .and_then(|v| v.as_boolean())
    {
        report
            .ats_findings
            .push("NSAllowsArbitraryLoadsForMedia = true — AVFoundation bypasses ATS".into());
    }
    if let Some(true) = ats
        .get("NSAllowsArbitraryLoadsInWebContent")
        .and_then(|v| v.as_boolean())
    {
        report.ats_findings.push(
            "NSAllowsArbitraryLoadsInWebContent = true — WKWebView bypasses ATS".into(),
        );
    }
    if let Some(domains) = ats
        .get("NSExceptionDomains")
        .and_then(|v| v.as_dictionary())
    {
        for (host, cfg) in domains {
            let cfg_dict = match cfg.as_dictionary() {
                Some(d) => d,
                None => continue,
            };
            if let Some(true) = cfg_dict
                .get("NSExceptionAllowsInsecureHTTPLoads")
                .and_then(|v| v.as_boolean())
            {
                report.ats_findings.push(format!(
                    "{}: NSExceptionAllowsInsecureHTTPLoads = true (cleartext HTTP allowed)",
                    host
                ));
            }
            if let Some(min) = cfg_dict
                .get("NSExceptionMinimumTLSVersion")
                .and_then(|v| v.as_string())
            {
                if min == "TLSv1.0" || min == "TLSv1.1" {
                    report.ats_findings.push(format!(
                        "{}: NSExceptionMinimumTLSVersion = {} (deprecated)",
                        host, min
                    ));
                }
            }
            if let Some(false) = cfg_dict
                .get("NSExceptionRequiresForwardSecrecy")
                .and_then(|v| v.as_boolean())
            {
                report.ats_findings.push(format!(
                    "{}: NSExceptionRequiresForwardSecrecy = false (PFS waived)",
                    host
                ));
            }
        }
    }
}

pub fn print_report(r: &IpaReport) {
    use colored::*;
    println!();
    println!("{}", format!("IPA static scan: {}", r.path).bold());
    if let Some(b) = &r.bundle_id {
        println!("  bundle id     : {}", b);
    }
    if let Some(n) = &r.display_name {
        println!("  display name  : {}", n);
    }
    if let Some(v) = &r.version {
        println!("  version       : {}", v);
    }
    if let Some(m) = &r.min_os {
        println!("  min iOS       : {}", m);
    }
    if !r.url_schemes.is_empty() {
        println!("  URL schemes   : {}", r.url_schemes.join(", "));
    }
    if r.ats_findings.is_empty() {
        println!("  ATS           : {}", "default policy enforced".green());
    } else {
        println!("  {}", format!("ATS exceptions ({}):", r.ats_findings.len()).yellow().bold());
        for f in &r.ats_findings {
            println!("    · {}", f);
        }
    }
    if !r.pinning_libraries.is_empty() {
        println!("  pinning       : {}", r.pinning_libraries.join(", ").green());
    }
    if let Some(m) = &r.macho {
        let yn = |b: bool| if b { "yes" } else { "no" };
        println!(
            "  mach-O        : {} · PIE {} · encrypted {} · signed {}{}",
            m.arch,
            yn(m.pie),
            yn(m.encrypted),
            yn(m.code_signature),
            if m.restrict { " · __RESTRICT" } else { "" }
        );
        if !m.pie {
            println!("    {}", "no PIE — ASLR disabled for the main binary".yellow());
        }
    }
    if !r.entitlements.is_empty() {
        println!(
            "  {}",
            format!("entitlements ({}):", r.entitlements.len()).yellow().bold()
        );
        for e in &r.entitlements {
            println!("    · {}", e);
        }
    }
    if r.secrets.is_empty() {
        println!("  secrets       : {}", "none detected".green());
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
    use plist::Value;

    fn dict_from_pairs(pairs: Vec<(&str, Value)>) -> plist::Dictionary {
        let mut d = plist::Dictionary::new();
        for (k, v) in pairs {
            d.insert(k.into(), v);
        }
        d
    }

    #[test]
    fn ats_flags_arbitrary_loads_true() {
        let mut report = IpaReport::default();
        let ats = dict_from_pairs(vec![("NSAllowsArbitraryLoads", Value::Boolean(true))]);
        audit_ats(&ats, &mut report);
        assert!(report.ats_findings.iter().any(|f| f.contains("ATS effectively disabled")));
    }

    #[test]
    fn ats_flags_per_domain_insecure_http() {
        let mut report = IpaReport::default();
        let inner = dict_from_pairs(vec![(
            "NSExceptionAllowsInsecureHTTPLoads",
            Value::Boolean(true),
        )]);
        let domains =
            dict_from_pairs(vec![("legacy.example.com", Value::Dictionary(inner))]);
        let ats = dict_from_pairs(vec![("NSExceptionDomains", Value::Dictionary(domains))]);
        audit_ats(&ats, &mut report);
        assert!(report
            .ats_findings
            .iter()
            .any(|f| f.contains("legacy.example.com") && f.contains("Insecure")));
    }

    #[test]
    fn ats_flags_low_tls_version() {
        let mut report = IpaReport::default();
        let inner = dict_from_pairs(vec![(
            "NSExceptionMinimumTLSVersion",
            Value::String("TLSv1.0".into()),
        )]);
        let domains = dict_from_pairs(vec![("api.example.com", Value::Dictionary(inner))]);
        let ats = dict_from_pairs(vec![("NSExceptionDomains", Value::Dictionary(domains))]);
        audit_ats(&ats, &mut report);
        assert!(report.ats_findings.iter().any(|f| f.contains("TLSv1.0")));
    }

    #[test]
    fn ats_clean_default_produces_no_findings() {
        let mut report = IpaReport::default();
        let ats = dict_from_pairs(vec![]);
        audit_ats(&ats, &mut report);
        assert!(report.ats_findings.is_empty());
    }

    fn macho_header_64(cputype: u32, flags: u32, ncmds: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&0xFEED_FACFu32.to_le_bytes()); // MH_MAGIC_64
        h.extend_from_slice(&cputype.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        h.extend_from_slice(&2u32.to_le_bytes()); // filetype MH_EXECUTE
        h.extend_from_slice(&ncmds.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // sizeofcmds
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // reserved (64-bit)
        h
    }

    #[test]
    fn parse_macho_thin64_pie_and_arch() {
        let info = parse_macho(&macho_header_64(0x0100_000C, 0x0020_0000, 0)).expect("parse");
        assert_eq!(info.arch, "arm64");
        assert!(info.pie);
        assert!(!info.code_signature);
    }

    #[test]
    fn parse_macho_rejects_non_macho() {
        assert!(parse_macho(b"PK\x03\x04 not a mach-o binary").is_none());
    }

    #[test]
    fn parse_macho_reads_code_signature_and_encryption() {
        let mut h = macho_header_64(0x0100_000C, 0, 2); // no PIE, 2 load commands
        // LC_CODE_SIGNATURE (0x1D), cmdsize 16.
        h.extend_from_slice(&0x1Du32.to_le_bytes());
        h.extend_from_slice(&16u32.to_le_bytes());
        h.extend_from_slice(&[0u8; 8]);
        // LC_ENCRYPTION_INFO_64 (0x2C), cmdsize 24, cryptid = 1.
        h.extend_from_slice(&0x2Cu32.to_le_bytes());
        h.extend_from_slice(&24u32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // cryptoff
        h.extend_from_slice(&0u32.to_le_bytes()); // cryptsize
        h.extend_from_slice(&1u32.to_le_bytes()); // cryptid
        h.extend_from_slice(&0u32.to_le_bytes()); // pad
        let info = parse_macho(&h).expect("parse");
        assert!(info.code_signature);
        assert!(info.encrypted);
        assert!(!info.pie);
    }

    #[test]
    fn parse_macho_follows_fat_to_first_slice() {
        let mut f = Vec::new();
        f.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes()); // fat magic
        f.extend_from_slice(&1u32.to_be_bytes()); // nfat_arch
        f.extend_from_slice(&0x0100_000Cu32.to_be_bytes()); // cputype
        f.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        f.extend_from_slice(&32u32.to_be_bytes()); // offset = 32
        f.extend_from_slice(&0u32.to_be_bytes()); // size
        f.extend_from_slice(&0u32.to_be_bytes()); // align
        while f.len() < 32 {
            f.push(0);
        }
        f.extend_from_slice(&macho_header_64(0x0100_000C, 0x0020_0000, 0));
        let info = parse_macho(&f).expect("fat→thin");
        assert_eq!(info.arch, "arm64");
        assert!(info.pie);
    }

    #[test]
    fn mobileprovision_entitlements_sliced_from_cms() {
        let plist = r#"<?xml version="1.0"?><plist version="1.0"><dict><key>Entitlements</key><dict><key>get-task-allow</key><true/><key>aps-environment</key><string>development</string></dict></dict></plist>"#;
        let mut blob = vec![0x30, 0x82, 0x01, 0x00]; // fake CMS/DER prefix
        blob.extend_from_slice(plist.as_bytes());
        blob.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // trailing signature noise
        let findings = parse_mobileprovision(&blob);
        assert!(findings.iter().any(|f| f.contains("get-task-allow")));
        assert!(findings.iter().any(|f| f.contains("aps-environment")));
    }
}
