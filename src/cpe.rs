//! CPE 2.3 (Common Platform Enumeration) string generator.
//!
//! Turn an OS family + version into the standard NIST CPE 2.3 URI:
//!
//!   `cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*`
//!   `cpe:2.3:o:microsoft:windows_10:21h2:*:*:*:*:*:*:*`
//!   `cpe:2.3:o:apple:macos:13.4:*:*:*:*:*:*:*`
//!   `cpe:2.3:o:freebsd:freebsd:13.2:*:*:*:*:*:*:*`
//!
//! This is the format NVD uses for `cpe_match` entries, so emitting
//! CPE makes the `src/nvd.rs` lookup straight-through: scan host →
//! infer OS → emit CPE → query NVD for CVEs targeting that CPE.
//!
//! 11 fields after `cpe:2.3:`:
//!   part / vendor / product / version / update / edition / language /
//!   sw_edition / target_sw / target_hw / other
//!
//! We fill `part = o` (operating system), best-effort vendor and
//! product mapped from the family, version from the supplied string,
//! and `*` (any) for the rest. Per CPE 2.3 §6.2 the field values are
//! lowercased and `:` / whitespace inside a field is replaced by `_`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cpe {
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub raw: String,
}

/// Produce a CPE 2.3 string from a free-text family and an optional
/// version. The family text is matched against a small canonical
/// table; unknown families produce a placeholder `vendor:product`.
pub fn from_family(family: &str, version: Option<&str>) -> Cpe {
    let lower = family.to_lowercase();
    let (vendor, product) = if lower.contains("windows") {
        ("microsoft", windows_product(&lower))
    } else if lower.contains("linux") {
        ("linux", "linux_kernel".to_string())
    } else if lower.contains("freebsd") {
        ("freebsd", "freebsd".to_string())
    } else if lower.contains("openbsd") {
        ("openbsd", "openbsd".to_string())
    } else if lower.contains("netbsd") {
        ("netbsd", "netbsd".to_string())
    } else if lower.contains("macos") || lower.contains("os x") || lower.contains("darwin") {
        ("apple", "macos".to_string())
    } else if lower.contains("ios-xe") || lower.contains("ios xe") {
        ("cisco", "ios_xe".to_string())
    } else if lower.contains("cisco") || lower.contains("ios") {
        ("cisco", "ios".to_string())
    } else if lower.contains("solaris") {
        ("oracle", "solaris".to_string())
    } else if lower.contains("android") {
        ("google", "android".to_string())
    } else if lower.contains("printer") {
        ("generic", "printer_firmware".to_string())
    } else {
        ("unknown", normalize_field(&lower))
    };

    let ver = version
        .map(normalize_field)
        .unwrap_or_else(|| "*".to_string());
    let raw = format!(
        "cpe:2.3:o:{}:{}:{}:*:*:*:*:*:*:*",
        vendor, product, ver
    );
    Cpe {
        part: "o".into(),
        vendor: vendor.into(),
        product,
        version: ver,
        raw,
    }
}

fn windows_product(family_lower: &str) -> String {
    // Match common Windows generation labels.
    if family_lower.contains("server 2022") {
        "windows_server_2022".into()
    } else if family_lower.contains("server 2019") {
        "windows_server_2019".into()
    } else if family_lower.contains("server 2016") {
        "windows_server_2016".into()
    } else if family_lower.contains("server 2012 r2") {
        "windows_server_2012_r2".into()
    } else if family_lower.contains("server 2012") {
        "windows_server_2012".into()
    } else if family_lower.contains("server 2008") {
        "windows_server_2008".into()
    } else if family_lower.contains("server") {
        "windows_server".into()
    } else if family_lower.contains("11") {
        "windows_11".into()
    } else if family_lower.contains("10") {
        "windows_10".into()
    } else if family_lower.contains("8.1") {
        "windows_8.1".into()
    } else if family_lower.contains("8") {
        "windows_8".into()
    } else if family_lower.contains("xp") {
        "windows_xp".into()
    } else if family_lower.contains("7") {
        "windows_7".into()
    } else {
        "windows".into()
    }
}

/// Lower-case, replace `:` / space / tab with `_`, strip leading/
/// trailing whitespace. Per CPE 2.3 §6.2 the colon character is
/// reserved as field separator, so any value with `:` would corrupt
/// the URI without normalisation.
pub fn normalize_field(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .chars()
        .map(|c| match c {
            ':' | ' ' | '\t' => '_',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_with_version() {
        let c = from_family("Linux 5.10", Some("5.10.0"));
        assert_eq!(c.vendor, "linux");
        assert_eq!(c.product, "linux_kernel");
        assert_eq!(c.version, "5.10.0");
        assert_eq!(c.raw, "cpe:2.3:o:linux:linux_kernel:5.10.0:*:*:*:*:*:*:*");
    }

    #[test]
    fn windows_10_picks_correct_product() {
        let c = from_family("Windows 10 build 19042", Some("21H2"));
        assert_eq!(c.vendor, "microsoft");
        assert_eq!(c.product, "windows_10");
        assert_eq!(c.version, "21h2");
    }

    #[test]
    fn windows_server_2019() {
        let c = from_family("Windows Server 2019", None);
        assert_eq!(c.product, "windows_server_2019");
        assert_eq!(c.version, "*");
    }

    #[test]
    fn macos_via_darwin() {
        let c = from_family("Darwin 22.4 (macOS Ventura)", Some("13.4"));
        assert_eq!(c.vendor, "apple");
        assert_eq!(c.product, "macos");
        assert!(c.raw.contains("13.4"));
    }

    #[test]
    fn freebsd_basic() {
        let c = from_family("FreeBSD", Some("13.2"));
        assert_eq!(c.raw, "cpe:2.3:o:freebsd:freebsd:13.2:*:*:*:*:*:*:*");
    }

    #[test]
    fn cisco_ios_distinct_from_ios_xe() {
        let c1 = from_family("Cisco IOS 15.1", None);
        let c2 = from_family("Cisco IOS-XE 17.6", None);
        assert_eq!(c1.product, "ios");
        assert_eq!(c2.product, "ios_xe");
    }

    #[test]
    fn unknown_family_uses_placeholder() {
        let c = from_family("something weird", None);
        assert_eq!(c.vendor, "unknown");
        assert!(c.product.contains("something"));
        assert!(c.raw.starts_with("cpe:2.3:o:unknown:"));
    }

    #[test]
    fn normalize_replaces_separators() {
        assert_eq!(normalize_field("RHEL 8.4"), "rhel_8.4");
        assert_eq!(normalize_field("X:Y"), "x_y");
        assert_eq!(normalize_field("  spaces  "), "spaces");
    }
}
