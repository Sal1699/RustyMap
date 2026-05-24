//! CPE 2.3 version comparator for CVE matching.
//!
//! Fase 25 (v0.67.0): the previous matcher in `nvd::lookup` did a
//! literal substring scan on the cached CPE strings. That fails on
//! every banner with a distro suffix ("2.4.59-1ubuntu1"), every
//! product whose banner name doesn't match the CPE vendor:product
//! ("Apache httpd" → CPE uses "apache:http_server"), and every CPE
//! version-range entry where the literal version doesn't appear at
//! all (e.g. cpe:2.3:a:vendor:product:*:* with versionStartIncluding).
//!
//! This module replaces it with:
//!   - `normalize_version()` — strip distro suffixes, peel off
//!     OpenSSH-style p1/p2 tags, handle build metadata.
//!   - `product_aliases()` — map free-text banner products to one
//!     or more (vendor, product) CPE coordinates.
//!   - `version_compare()` — semver-aware ordering that handles
//!     mixed-length tuples (1.18 vs 1.18.0) and alphanumeric tails
//!     ("7.4p1" vs "7.4p2").
//!   - `cpe_string_matches()` — parse a cpe2.3 string and decide
//!     whether a (vendor, product, version) tuple satisfies it,
//!     including `*` and `-` wildcards.
//!
//! Comparator is intentionally pure — no DB / no IO — so the rest of
//! the CVE pipeline can stay testable.

use std::cmp::Ordering;

/// Strip distro / vendor packaging tails so the version compares
/// against upstream CPE values. Examples:
///   `2.4.59-1ubuntu1`     → `2.4.59`
///   `1.18.0+deb11u3`      → `1.18.0`
///   `2.4.41 (Ubuntu)`     → `2.4.41`
///   `7.4p1`               → `7.4p1` (kept — CPE often encodes the p as `p1`)
///   `7.4p1-debian-10+deb` → `7.4p1`
pub fn normalize_version(raw: &str) -> String {
    let raw = raw.trim();
    // Cut at first whitespace — "2.4.41 (Ubuntu)" → "2.4.41"
    let head = raw.split_whitespace().next().unwrap_or(raw);
    // Cut distro suffixes after the first dash that isn't part of a
    // recognised upstream pattern. OpenSSH "p1" sticks to the version
    // (it isn't dash-separated), so the dash split works for most
    // distro tags.
    let head = head.split('-').next().unwrap_or(head);
    // Cut Debian-style "+deb11u3" build metadata.
    let head = head.split('+').next().unwrap_or(head);
    head.to_string()
}

/// Map a banner product name to one or more (vendor, product) CPE
/// coordinates. Returns `[]` when the banner name already looks like
/// a single-token product that's likely to be its own CPE product.
/// In that case the caller falls back to a substring match on the
/// product string alone.
pub fn product_aliases(banner_product: &str) -> Vec<(&'static str, &'static str)> {
    let lo = banner_product.trim().to_lowercase();
    // Strip a few common prefixes / suffixes
    let lo = lo.trim_start_matches("the ").trim_end_matches(" httpd").to_string();
    match lo.as_str() {
        // Web servers
        "openssh" => vec![("openbsd", "openssh")],
        "openssh_server" | "ssh server" => vec![("openbsd", "openssh")],
        "apache" | "apache http server" | "httpd" => vec![("apache", "http_server")],
        "nginx" => vec![("nginx", "nginx"), ("f5", "nginx")],
        "iis" | "microsoft-iis" | "microsoft iis" => vec![("microsoft", "internet_information_server")],
        "lighttpd" => vec![("lighttpd", "lighttpd")],
        "caddy" => vec![("caddyserver", "caddy")],
        // Databases
        "mysql" => vec![("mysql", "mysql"), ("oracle", "mysql")],
        "mariadb" => vec![("mariadb", "mariadb")],
        "postgresql" | "postgres" => vec![("postgresql", "postgresql")],
        "mongodb" => vec![("mongodb", "mongodb")],
        "redis" => vec![("redis", "redis")],
        "memcached" => vec![("memcached", "memcached")],
        "elasticsearch" => vec![("elastic", "elasticsearch"), ("elasticsearch", "elasticsearch")],
        "microsoft sql server" | "mssql" => vec![("microsoft", "sql_server")],
        "oracle" | "oracle database" => vec![("oracle", "database_server")],
        // Mail
        "postfix" => vec![("postfix", "postfix")],
        "sendmail" => vec![("sendmail", "sendmail")],
        "exim" => vec![("exim", "exim")],
        "dovecot" => vec![("dovecot", "dovecot")],
        "cyrus" | "cyrus imapd" => vec![("cmu", "cyrus_imapd")],
        // FTP
        "proftpd" => vec![("proftpd", "proftpd")],
        "vsftpd" => vec![("beasts", "vsftpd")],
        "pure-ftpd" => vec![("pureftpd", "pure-ftpd")],
        // Misc
        "samba" => vec![("samba", "samba")],
        "vnc" | "tightvnc" => vec![("tightvnc", "tightvnc")],
        "realvnc" => vec![("realvnc", "vnc")],
        "isc bind" | "bind" => vec![("isc", "bind")],
        _ => Vec::new(),
    }
}

/// Compare two version strings semver-style with tolerance for
/// alphanumeric tails. `7.4p1` < `7.4p2`, `1.18` == `1.18.0`,
/// `2.4.59` < `2.4.59.1`.
pub fn version_compare(a: &str, b: &str) -> Ordering {
    let a_parts = split_version(a);
    let b_parts = split_version(b);
    let n = a_parts.len().max(b_parts.len());
    for i in 0..n {
        let av = a_parts.get(i).copied().unwrap_or(VPart::Num(0));
        let bv = b_parts.get(i).copied().unwrap_or(VPart::Num(0));
        match av.partial_cmp(&bv).unwrap_or(Ordering::Equal) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// A single version token. Numbers compare numerically; alphanumeric
/// tails like `p1` compare lexically AFTER numbers (so 7.4 < 7.4p1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VPart<'a> {
    Num(u64),
    Tag(&'a str),
}

impl<'a> PartialOrd for VPart<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (VPart::Num(a), VPart::Num(b)) => a.partial_cmp(b),
            (VPart::Tag(a), VPart::Tag(b)) => a.partial_cmp(b),
            // A pure number ranks BELOW the same-prefix version with a
            // tag: 7.4 < 7.4p1, so (Num, Tag) → Less.
            (VPart::Num(_), VPart::Tag(_)) => Some(Ordering::Less),
            (VPart::Tag(_), VPart::Num(_)) => Some(Ordering::Greater),
        }
    }
}

fn split_version(v: &str) -> Vec<VPart<'_>> {
    let mut out = Vec::new();
    for chunk in v.split('.') {
        // Split each dot-chunk into [number][alpha-tail].
        let mut digit_end = 0;
        for (i, c) in chunk.char_indices() {
            if !c.is_ascii_digit() {
                break;
            }
            digit_end = i + c.len_utf8();
        }
        let (num_part, tag_part) = chunk.split_at(digit_end);
        if !num_part.is_empty() {
            if let Ok(n) = num_part.parse::<u64>() {
                out.push(VPart::Num(n));
            }
        }
        if !tag_part.is_empty() {
            out.push(VPart::Tag(tag_part));
        }
    }
    out
}

/// Decide whether a (vendor, product, version) tuple satisfies a
/// cpe2.3 string. CPE shape:
///   `cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:...`
/// Wildcards: `*` (any) and `-` (not applicable / not specified).
/// Returns false on parse errors so we don't accidentally over-match.
///
/// v0.67.2: the matcher now honors the `update` field (parts[6])
/// because NVD splits OpenSSH-style "7.4p1" into version="7.4",
/// update="p1" — without checking the update field every OpenSSH
/// CVE was missed. Logic:
///   - cpe_update == "*"/"-": accept any target whose numeric
///     prefix or full version compares Equal to cpe_version.
///   - cpe_update != wildcard: target must equal cpe_version+cpe_update
///     under the version comparator.
pub fn cpe_string_matches(cpe: &str, vendor: &str, product: &str, version: &str) -> bool {
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() < 7 || parts[0] != "cpe" || parts[1] != "2.3" {
        return false;
    }
    let cpe_vendor = parts[3].to_lowercase();
    let cpe_product = parts[4].to_lowercase();
    let cpe_version = parts[5];
    let cpe_update = parts[6];
    let vendor = vendor.to_lowercase();
    let product = product.to_lowercase();
    if cpe_vendor != "*" && cpe_vendor != "-" && cpe_vendor != vendor {
        return false;
    }
    if cpe_product != "*" && cpe_product != "-" && cpe_product != product {
        return false;
    }
    if cpe_version == "*" || cpe_version == "-" {
        return true;
    }
    let norm_target = normalize_version(version);
    let norm_cpe_v = normalize_version(cpe_version);
    if cpe_update == "*" || cpe_update == "-" {
        // Any update accepted — accept exact equality OR the numeric
        // prefix of the target matching the CPE version.
        if version_compare(&norm_cpe_v, &norm_target) == Ordering::Equal {
            return true;
        }
        let (num_prefix, _tail) = split_version_head_tail(&norm_target);
        if !num_prefix.is_empty() && version_compare(&norm_cpe_v, &num_prefix) == Ordering::Equal {
            return true;
        }
        false
    } else {
        // Specific update required (e.g. "p1"). Combine and compare
        // against the full target.
        let combined = format!("{}{}", norm_cpe_v, cpe_update);
        version_compare(&combined, &norm_target) == Ordering::Equal
    }
}

/// Split a normalized version into ("digits.digits...", "alphanumeric-tail").
/// `"7.4p1"` → `("7.4", "p1")`, `"2.4.59"` → `("2.4.59", "")`,
/// `"1.3.5e"` → `("1.3.5", "e")`.
fn split_version_head_tail(v: &str) -> (String, String) {
    let bytes = v.as_bytes();
    let mut i = 0;
    while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
        i += 1;
    }
    (v[..i].trim_end_matches('.').to_string(), v[i..].to_string())
}

/// Best-effort match: try every (vendor, product) alias for the
/// banner-supplied product, falling back to a substring scan on the
/// CPE if no alias is registered. Returns true on the first hit.
pub fn cpe_matches_banner(cpe: &str, banner_product: &str, version: &str) -> bool {
    let aliases = product_aliases(banner_product);
    for (vendor, product) in &aliases {
        if cpe_string_matches(cpe, vendor, product, version) {
            return true;
        }
    }
    if aliases.is_empty() {
        // Unmapped product — fall back to lowercase substring scan, but
        // still require the version to be the normalized form.
        let lo = cpe.to_lowercase();
        let needle_product = banner_product.trim().to_lowercase();
        if !lo.contains(&needle_product) {
            return false;
        }
        let nv = normalize_version(version);
        // Either the normalized version appears, OR the CPE has a
        // wildcard version (handled by parsing).
        if lo.contains(&nv) {
            return true;
        }
        // Parse the CPE to check for `*`/`-` version wildcards.
        let parts: Vec<&str> = cpe.split(':').collect();
        if parts.len() >= 6 && (parts[5] == "*" || parts[5] == "-") {
            return true;
        }
        return false;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    #[test]
    fn normalize_strips_distro_suffixes() {
        assert_eq!(normalize_version("2.4.59-1ubuntu1"), "2.4.59");
        assert_eq!(normalize_version("1.18.0+deb11u3"), "1.18.0");
        assert_eq!(normalize_version("2.4.41 (Ubuntu)"), "2.4.41");
        assert_eq!(normalize_version("7.4p1-debian-10"), "7.4p1");
        assert_eq!(normalize_version("  1.2.3  "), "1.2.3");
    }

    #[test]
    fn version_compare_handles_mixed_length() {
        assert_eq!(version_compare("1.18", "1.18.0"), Equal);
        assert_eq!(version_compare("1.18.1", "1.18.0"), Greater);
        assert_eq!(version_compare("2.4.59", "2.4.59.1"), Less);
        assert_eq!(version_compare("0.9", "1.0"), Less);
    }

    #[test]
    fn version_compare_handles_openssh_p_tags() {
        assert_eq!(version_compare("7.4", "7.4p1"), Less);
        assert_eq!(version_compare("7.4p1", "7.4p2"), Less);
        assert_eq!(version_compare("7.4p1", "7.4p1"), Equal);
        assert_eq!(version_compare("7.4p2", "7.4p1"), Greater);
    }

    #[test]
    fn aliases_cover_common_banners() {
        assert_eq!(product_aliases("OpenSSH"), vec![("openbsd", "openssh")]);
        assert_eq!(
            product_aliases("Apache httpd"),
            vec![("apache", "http_server")]
        );
        assert_eq!(
            product_aliases("nginx").len(),
            2,
            "nginx maps to both nginx:nginx and f5:nginx"
        );
        assert!(product_aliases("Some Unknown Product").is_empty());
    }

    #[test]
    fn cpe_string_matches_exact_version() {
        let cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*";
        assert!(cpe_string_matches(cpe, "nginx", "nginx", "1.18.0"));
        assert!(!cpe_string_matches(cpe, "nginx", "nginx", "1.18.1"));
    }

    #[test]
    fn cpe_string_matches_wildcard_version() {
        let cpe = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*";
        assert!(cpe_string_matches(cpe, "apache", "http_server", "2.4.59"));
        assert!(cpe_string_matches(cpe, "apache", "http_server", "anything"));
    }

    #[test]
    fn cpe_string_matches_wildcard_vendor_product() {
        let cpe = "cpe:2.3:a:*:nginx:1.18.0:*:*:*:*:*:*:*";
        assert!(cpe_string_matches(cpe, "f5", "nginx", "1.18.0"));
    }

    #[test]
    fn cpe_string_rejects_wrong_product() {
        let cpe = "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*";
        assert!(!cpe_string_matches(cpe, "apache", "http_server", "9.0.50"));
    }

    #[test]
    fn cpe_matches_banner_uses_aliases() {
        let cpe = "cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:*:*:*";
        assert!(cpe_matches_banner(cpe, "Apache httpd", "2.4.59"));
        // distro suffix tolerated via normalize
        assert!(cpe_matches_banner(cpe, "Apache httpd", "2.4.59-1ubuntu1"));
    }

    #[test]
    fn cpe_matches_banner_falls_back_to_substring() {
        // No alias for "weird-thing" → falls back to substring on cpe.
        let cpe = "cpe:2.3:a:vendor:weird-thing:0.1.0:*:*:*:*:*:*:*";
        assert!(cpe_matches_banner(cpe, "weird-thing", "0.1.0"));
        assert!(!cpe_matches_banner(cpe, "weird-thing", "9.9.9"));
    }

    #[test]
    fn cpe_matches_banner_normalizes_openssh_version() {
        let cpe_full = "cpe:2.3:a:openbsd:openssh:7.4p1:*:*:*:*:*:*:*";
        // Banner: "OpenSSH 7.4p1" — alias hits, version exact.
        assert!(cpe_matches_banner(cpe_full, "OpenSSH", "7.4p1"));
        // Banner: bare "7.4" → does NOT satisfy 7.4p1 CPE (different
        // upstream release — 7.4 GA vs 7.4p1 with bugfix patches).
        assert!(!cpe_matches_banner(cpe_full, "OpenSSH", "7.4"));
    }

    #[test]
    fn cpe_string_matches_split_version_and_update() {
        // NVD's canonical OpenSSH CPE puts the "p1" tag in the update
        // slot, not the version slot. v0.67.2 regression coverage.
        let cpe = "cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*";
        // Banner "7.4p1" must satisfy: combined ver+update = "7.4p1".
        assert!(cpe_string_matches(cpe, "openbsd", "openssh", "7.4p1"));
        // Banner "7.4" must NOT match — different release.
        assert!(!cpe_string_matches(cpe, "openbsd", "openssh", "7.4"));
        // Banner "7.4p2" must NOT match.
        assert!(!cpe_string_matches(cpe, "openbsd", "openssh", "7.4p2"));
    }

    #[test]
    fn cpe_string_matches_wildcard_update_accepts_prefix() {
        // CPE with version="7.4" + update="*" must accept any 7.4*
        // banner including "7.4", "7.4p1", "7.4p2".
        let cpe = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*";
        assert!(cpe_string_matches(cpe, "openbsd", "openssh", "7.4"));
        assert!(cpe_string_matches(cpe, "openbsd", "openssh", "7.4p1"));
        assert!(cpe_string_matches(cpe, "openbsd", "openssh", "7.4p9"));
        // But NOT 7.5.
        assert!(!cpe_string_matches(cpe, "openbsd", "openssh", "7.5"));
    }

    #[test]
    fn split_head_tail_extracts_alpha_tag() {
        assert_eq!(split_version_head_tail("7.4p1"), ("7.4".to_string(), "p1".to_string()));
        assert_eq!(split_version_head_tail("2.4.59"), ("2.4.59".to_string(), "".to_string()));
        assert_eq!(split_version_head_tail("1.3.5e"), ("1.3.5".to_string(), "e".to_string()));
        assert_eq!(split_version_head_tail("1.0rc1"), ("1.0".to_string(), "rc1".to_string()));
    }

    #[test]
    fn cpe_matches_banner_handles_iis_alias() {
        let cpe = "cpe:2.3:a:microsoft:internet_information_server:10.0:*:*:*:*:*:*:*";
        assert!(cpe_matches_banner(cpe, "Microsoft-IIS", "10.0"));
        assert!(cpe_matches_banner(cpe, "IIS", "10.0"));
    }

    #[test]
    fn split_version_handles_pure_numbers_and_alpha_tails() {
        let p = split_version("7.4p1");
        assert_eq!(p.len(), 3);
        assert_eq!(p[0], VPart::Num(7));
        assert_eq!(p[1], VPart::Num(4));
        assert_eq!(p[2], VPart::Tag("p1"));
    }

    #[test]
    fn version_compare_real_world_vectors() {
        // 30+ assertions covering CVEs we've seen in the wild.
        // OpenSSH
        assert_eq!(version_compare("7.4", "8.0"), Less);
        assert_eq!(version_compare("8.0p1", "8.0p2"), Less);
        assert_eq!(version_compare("9.6p1", "9.6p1"), Equal);
        // nginx
        assert_eq!(version_compare("1.18.0", "1.24.0"), Less);
        assert_eq!(version_compare("1.18", "1.18.0"), Equal);
        assert_eq!(version_compare("1.27.1", "1.27.0"), Greater);
        // Apache HTTP
        assert_eq!(version_compare("2.4.59", "2.4.62"), Less);
        assert_eq!(version_compare("2.4.59", "2.4.59"), Equal);
        assert_eq!(version_compare("2.2.34", "2.4.0"), Less);
        // MySQL / MariaDB
        assert_eq!(version_compare("5.7.36", "8.0.0"), Less);
        assert_eq!(version_compare("10.5.12", "10.6.0"), Less);
        // PostgreSQL
        assert_eq!(version_compare("13.4", "14.0"), Less);
        // Redis
        assert_eq!(version_compare("6.2.6", "7.0.0"), Less);
        // PHP
        assert_eq!(version_compare("8.1.0", "8.1.10"), Less);
        // Tomcat
        assert_eq!(version_compare("9.0.50", "9.0.65"), Less);
        // Exim
        assert_eq!(version_compare("4.94.2", "4.95"), Less);
        // BIND
        assert_eq!(version_compare("9.16.27", "9.18.0"), Less);
        // ProFTPD
        assert_eq!(version_compare("1.3.5e", "1.3.6"), Less);
        // vsftpd
        assert_eq!(version_compare("2.3.4", "3.0.0"), Less);
        // Samba
        assert_eq!(version_compare("4.13.0", "4.13.17"), Less);
        // Postfix
        assert_eq!(version_compare("3.5.13", "3.6.0"), Less);
        // 1-digit comparisons
        assert_eq!(version_compare("1", "2"), Less);
        assert_eq!(version_compare("10", "9"), Greater);
        // Padding zeros
        assert_eq!(version_compare("1.0.0.0", "1.0.0"), Equal);
        assert_eq!(version_compare("1.2.3.4", "1.2.3.5"), Less);
        // Mixed digits / tags
        assert_eq!(version_compare("1.0a", "1.0b"), Less);
        assert_eq!(version_compare("1.0rc1", "1.0"), Greater); // rc tag > pure
        assert_eq!(version_compare("1.0", "1.0.1"), Less);
        // CVE-2017-7494 SambaCry vector
        assert_eq!(version_compare("4.5.10", "4.5.0"), Greater);
        // Log4j 2.x
        assert_eq!(version_compare("2.14.1", "2.15.0"), Less);
        assert_eq!(version_compare("2.17.1", "2.17.2"), Less);
    }
}
