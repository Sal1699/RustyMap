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

impl Cpe {
    /// nmap-style URI binding — `cpe:/<part>:<vendor>:<product>[:<version>]`.
    /// This is the form nmap writes inside the `<cpe>` elements of its XML
    /// output (zenmap / Metasploit `db_import` read this binding), as opposed
    /// to the 2.3 formatted-string in [`Cpe::raw`]. The trailing version is
    /// omitted when unknown (`*`) so the URI stays well-formed.
    pub fn uri_binding(&self) -> String {
        let mut s = format!("cpe:/{}:{}:{}", self.part, self.vendor, self.product);
        if self.version != "*" {
            s.push(':');
            s.push_str(&self.version);
        }
        s
    }
}

/// Produce an **application** CPE 2.3 string (`part = a`) from a detected
/// service product name (as emitted by `src/service_probe.rs`) plus an
/// optional version. This is the service-level counterpart to
/// [`from_family`]: it lets a scan feed `src/cpe_match.rs` / `src/nvd.rs`
/// application-level CVE lookups for the software on each open port, not just
/// the host OS. A recognised product maps to its canonical NVD/nmap
/// `vendor:product`; anything unrecognised gets `a:*:<product>:*` (vendor =
/// any), which is still a valid, matchable CPE rather than a dropped result.
pub fn from_service(product: &str, version: Option<&str>) -> Cpe {
    let lower = product.to_lowercase();
    let (vendor, product_cpe) = service_vendor_product(&lower);
    let ver = version
        .map(normalize_field)
        .unwrap_or_else(|| "*".to_string());
    let raw = format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", vendor, product_cpe, ver);
    Cpe {
        part: "a".into(),
        vendor: vendor.into(),
        product: product_cpe,
        version: ver,
        raw,
    }
}

/// Map a lower-cased service product string to a canonical CPE
/// `(vendor, product)`. Ordered so a more specific product name wins over a
/// generic substring it contains (Redpanda before "kafka"; Grafana
/// Loki/Tempo/Mimir before "grafana"; OpenResty before "nginx"). The chosen
/// vendor/product follow the dominant NVD / nmap-service-probes spelling for
/// each so the emitted CPE actually matches public CVE data.
fn service_vendor_product(p: &str) -> (&'static str, String) {
    const MAP: &[(&str, &str, &str)] = &[
        // (distinctive substring, vendor, product)
        ("tomcat", "apache", "tomcat"),
        ("openresty", "openresty", "openresty"),
        ("httpd", "apache", "http_server"),
        ("nginx", "nginx", "nginx"),
        ("lighttpd", "lighttpd", "lighttpd"),
        ("iis", "microsoft", "iis"),
        ("caddy", "caddyserver", "caddy"),
        ("traefik", "traefik", "traefik"),
        ("mariadb", "mariadb", "mariadb"),
        ("mysql", "oracle", "mysql"),
        ("postgresql", "postgresql", "postgresql"),
        ("sql server", "microsoft", "sql_server"),
        ("redis", "redis", "redis"),
        ("mongodb", "mongodb", "mongodb"),
        ("memcached", "memcached", "memcached"),
        ("elasticsearch", "elastic", "elasticsearch"),
        ("kibana", "elastic", "kibana"),
        ("jetty", "eclipse", "jetty"),
        ("couchdb", "apache", "couchdb"),
        ("cassandra", "apache", "cassandra"),
        ("redpanda", "redpanda", "redpanda"), // before "kafka" (Kafka-compatible)
        ("kafka", "apache", "kafka"),
        ("zookeeper", "apache", "zookeeper"),
        ("jenkins", "jenkins", "jenkins"),
        ("gitlab", "gitlab", "gitlab"),
        ("gitea", "gitea", "gitea"),
        ("loki", "grafana", "loki"),   // before "grafana"
        ("tempo", "grafana", "tempo"), // before "grafana"
        ("mimir", "grafana", "mimir"), // before "grafana"
        ("grafana", "grafana", "grafana"),
        ("prometheus", "prometheus", "prometheus"),
        ("influxdb", "influxdata", "influxdb"),
        ("vault", "hashicorp", "vault"),
        ("consul", "hashicorp", "consul"),
        ("nomad", "hashicorp", "nomad"),
        ("neo4j", "neo4j", "neo4j"),
        ("jellyfin", "jellyfin", "jellyfin"),
        ("kubernetes", "kubernetes", "kubernetes"),
        ("docker", "docker", "docker"),
        ("openssh", "openbsd", "openssh"),
    ];
    for (needle, vendor, product) in MAP {
        if p.contains(needle) {
            return (vendor, (*product).to_string());
        }
    }
    ("*", normalize_field(p))
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

    #[test]
    fn service_cpe_maps_common_products() {
        // part is always `a`, vendor/product follow NVD canonical spelling.
        let a = from_service("Apache httpd", Some("2.4.59"));
        assert_eq!(a.part, "a");
        assert_eq!(a.raw, "cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:*:*:*");
        assert_eq!(from_service("nginx", None).vendor, "nginx");
        assert_eq!(from_service("MySQL", None).vendor, "oracle");
        assert_eq!(from_service("MariaDB", None).vendor, "mariadb");
        assert_eq!(from_service("Elasticsearch", None).product, "elasticsearch");
        assert_eq!(from_service("Microsoft SQL Server", None).product, "sql_server");
        assert_eq!(from_service("OpenSSH", Some("9.6p1")).vendor, "openbsd");
    }

    #[test]
    fn service_cpe_specific_wins_over_generic_substring() {
        // "Apache Tomcat" must not fall into apache:http_server, and a
        // Kafka-compatible product must not be mislabelled apache:kafka.
        assert_eq!(from_service("Apache Tomcat", None).product, "tomcat");
        let rp = from_service("Redpanda (Kafka-compatible)", None);
        assert_eq!((rp.vendor.as_str(), rp.product.as_str()), ("redpanda", "redpanda"));
        // Grafana Loki is its own product, not grafana:grafana.
        assert_eq!(from_service("Grafana Loki", None).product, "loki");
        // OpenResty wins over the "nginx" it mentions.
        assert_eq!(from_service("OpenResty (nginx fork)", None).vendor, "openresty");
    }

    #[test]
    fn service_cpe_unknown_uses_any_vendor() {
        let c = from_service("Totally Bespoke Daemon", None);
        assert_eq!(c.vendor, "*");
        assert_eq!(c.raw, "cpe:2.3:a:*:totally_bespoke_daemon:*:*:*:*:*:*:*:*");
    }

    #[test]
    fn uri_binding_matches_nmap_form() {
        // With a version, and without (version omitted when unknown).
        let withv = from_service("Apache httpd", Some("2.4.59"));
        assert_eq!(withv.uri_binding(), "cpe:/a:apache:http_server:2.4.59");
        let nov = from_service("nginx", None);
        assert_eq!(nov.uri_binding(), "cpe:/a:nginx:nginx");
        // OS binding too (the `<osclass>` form).
        let os = from_family("Linux 5.10", Some("5.10.0"));
        assert_eq!(os.uri_binding(), "cpe:/o:linux:linux_kernel:5.10.0");
    }
}
