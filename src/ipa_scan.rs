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
//!
//! Pure file reads, no execution, no entitlement parsing (those
//! live in the embedded provisioning profile, which is signed CMS
//! and out of scope for v1).

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

    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        let name = entry.name().to_string();

        let mut buf = Vec::new();
        entry.take(50 * 1024 * 1024).read_to_end(&mut buf).ok();

        // The Info.plist sits at Payload/<App>.app/Info.plist
        if name.starts_with("Payload/") && name.ends_with(".app/Info.plist") {
            info_plist_bytes = Some(buf.clone());
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
    Ok(report)
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
}
