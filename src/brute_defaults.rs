//! Curated vendor-default credential list for the `--brute-default-
//! creds-only` safe mode.
//!
//! ~120 well-known pairs covering router/switch/printer/IoT vendor
//! defaults plus a handful of database / management-tool defaults
//! that vendors still ship enabled. Deliberately small: more pairs
//! means more lockout risk, and the "default-creds-only" mode is
//! the bypass for the consent gate, so we keep the surface tight.
//!
//! Source: hand-pulled from SecLists `Passwords/Default-Credentials/`
//! + vendor manuals. Each entry compiled in — no external file
//! loader by design (the consent bypass should not be extendable
//! at runtime, otherwise it becomes a freeform bruteforce).

pub fn default_pairs() -> Vec<(String, String)> {
    DEFAULTS
        .iter()
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .collect()
}

/// (username, password)
const DEFAULTS: &[(&str, &str)] = &[
    // ── Generic admin defaults (most common) ──
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "changeme"),
    ("admin", "default"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "admin"),
    ("root", ""),
    ("root", "changeme"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("guest", ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("administrator", "Pass@word1"),
    ("administrator", "P@ssw0rd"),
    // ── Cisco ──
    ("cisco", "cisco"),
    ("admin", "cisco"),
    ("enable", "cisco"),
    // ── Juniper / Mikrotik / Fortinet ──
    ("admin", "Juniper"),
    ("admin", "Mikrotik"),
    ("admin", ""),                  // Mikrotik factory-default
    ("admin", "fortinet"),
    // ── Ubiquiti / TP-Link / D-Link / Netgear ──
    ("ubnt", "ubnt"),
    ("admin", "ubnt"),
    ("admin", "admin"),             // TP-Link
    ("admin", "tplink"),
    ("admin", "tp-link"),
    ("admin", "D-Link"),
    ("admin", "Netgear"),
    ("admin", "1234"),              // Linksys legacy
    // ── Hikvision / Dahua / Axis cameras ──
    ("admin", "12345"),
    ("admin", "888888"),
    ("admin", "hikvision"),
    ("888888", "888888"),
    ("admin", "Admin@123"),
    ("root", "pass"),
    // ── Lights-out / IPMI ──
    ("ADMIN", "ADMIN"),             // Supermicro
    ("admin", "calvin"),            // iDRAC default
    ("root", "calvin"),
    ("USERID", "PASSW0RD"),         // IBM IMM/RSA
    ("HPiLO", "password"),
    ("Administrator", "password"),  // HP iLO new install
    // ── Switches / SNMP ──
    ("public", ""),
    ("private", ""),
    ("manager", ""),
    ("operator", ""),
    // ── Printers ──
    ("admin", ""),
    ("admin", "1111"),
    ("user", "1234"),
    // ── Databases ──
    ("sa", ""),
    ("sa", "sa"),
    ("sa", "password"),
    ("sa", "Pa$$w0rd"),
    ("postgres", ""),
    ("postgres", "postgres"),
    ("postgres", "password"),
    ("mysql", ""),
    ("mysql", "mysql"),
    ("root", ""),                   // MySQL fresh install
    ("admin", ""),                  // MongoDB legacy
    ("oracle", "oracle"),
    ("system", "manager"),          // Oracle
    ("sys", "change_on_install"),
    ("scott", "tiger"),
    // ── App / dev defaults ──
    ("tomcat", "tomcat"),
    ("admin", "tomcat"),
    ("manager", "manager"),
    ("admin", "manager"),
    ("jenkins", "jenkins"),
    ("admin", "jenkins"),
    ("kibana", "kibana"),
    ("elastic", "changeme"),
    ("elastic", ""),
    ("grafana", "admin"),
    ("admin", "grafana"),
    ("airflow", "airflow"),
    ("admin", "airflow"),
    // ── FTP common ──
    ("anonymous", ""),
    ("anonymous", "anonymous@"),
    ("ftp", ""),
    ("ftp", "ftp"),
    ("anonymous", "guest@"),
    // ── VNC / screen ──
    ("", "password"),
    ("", "vnc"),
    // ── Telnet appliances ──
    ("admin", "Zte521"),
    ("admin", "Aa12345"),
    ("admin", "epicrouter"),
    // ── Windows lab fixtures ──
    ("Administrator", ""),
    ("Administrator", "P@ssword"),
    ("Administrator", "Password1"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_non_empty_and_bounded() {
        let v = default_pairs();
        assert!(v.len() >= 80, "list too small ({}); risk of insufficient coverage", v.len());
        assert!(v.len() <= 300, "list too large ({}); lockout risk", v.len());
    }

    #[test]
    fn list_contains_classic_defaults() {
        let v = default_pairs();
        assert!(v.iter().any(|(u, p)| u == "admin" && p == "admin"));
        assert!(v.iter().any(|(u, p)| u == "root" && p == "toor"));
        assert!(v.iter().any(|(u, p)| u == "cisco" && p == "cisco"));
        assert!(v.iter().any(|(u, p)| u == "ubnt" && p == "ubnt"));
    }

    #[test]
    fn list_includes_blank_password_variants() {
        let v = default_pairs();
        let blank_pw = v.iter().filter(|(_, p)| p.is_empty()).count();
        // Many vendor factory defaults ship with a blank password; we
        // want a meaningful sample but not a flood.
        assert!(blank_pw >= 5);
        assert!(blank_pw <= 30);
    }
}
