//! Plain-language service descriptions + exposure-risk hints for the
//! professional ("rich") output style.
//!
//! Turns a bare port number into a one-line note a human can act on: what the
//! service is, and whether finding it open is a concern. This is what makes
//! RustyMap's default output *descriptive* rather than just an nmap-style
//! `PORT STATE SERVICE` table — the reader sees "3306 MySQL — database, must
//! not be internet-facing" instead of having to know port 3306 by heart.
//!
//! Kept deliberately separate from `ports::service_name` (which gives the
//! short service label for the SERVICE column) and from
//! `exec_summary::SENSITIVE_PORTS` (which drives the scan-wide findings
//! footer). This table is the single source for the per-row NOTE column and
//! the inline risk glyph.

/// Exposure-risk tier for a service found open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Normal service; its presence is not itself a concern.
    Info,
    /// Worth attention — legacy, or sensitive if reachable from untrusted nets.
    Warn,
    /// High concern — cleartext credentials, or a datastore/admin surface that
    /// should never face an untrusted network.
    High,
}

impl Risk {
    /// Coloured/plain glyph for the NOTE column. The caller strips colour via
    /// the global `colored` override, so this only picks the symbol.
    pub fn glyph(self) -> &'static str {
        match self {
            Risk::Info => "·",
            Risk::Warn => "⚠",
            Risk::High => "‼",
        }
    }
}

/// A port's human description plus its exposure risk.
#[derive(Debug, Clone, Copy)]
pub struct Desc {
    pub text: &'static str,
    pub risk: Risk,
}

/// Look up the description + risk for a port. `None` when we have nothing
/// useful to say (the row then shows no NOTE).
pub fn describe(port: u16) -> Option<Desc> {
    use Risk::*;
    let (text, risk) = match port {
        // ── Remote access / shells ──
        22 => ("SSH — remote admin; audit KEX/cipher with --ssh-audit", Info),
        23 => ("Telnet — cleartext login; replace with SSH", High),
        512 => ("rexec — cleartext remote exec; disable", High),
        513 => ("rlogin — cleartext login; disable", High),
        514 => ("rsh/syslog — cleartext; disable rsh", High),
        3389 => ("RDP — remote desktop; check NLA, BlueKeep (--rdp-audit)", High),
        5900 | 5901 | 5902 => ("VNC — remote desktop; often weak/no auth", High),
        5985 => ("WinRM (HTTP) — remote mgmt; cleartext transport", High),
        5986 => ("WinRM (HTTPS) — remote mgmt over TLS", Warn),

        // ── Web / app ──
        80 => ("HTTP — web service; enumerate with --web-scan", Info),
        443 => ("HTTPS — web over TLS; grade with --tls-grade", Info),
        8080 | 8000 | 8888 => ("HTTP-alt — app/admin server; enumerate", Info),
        8008 => ("HTTP-alt — app/admin server", Info),
        8443 => ("HTTPS-alt — app/admin over TLS", Info),
        8081 => ("HTTP-alt — proxy/app (often management)", Info),
        3000 => ("HTTP app — dev/Grafana/Node; may lack auth", Warn),
        5000 => ("HTTP app — dev/Flask/UPnP; may lack auth", Warn),
        9000 => ("HTTP — PHP-FPM/SonarQube/admin; may lack auth", Warn),
        9090 => ("HTTP — Prometheus/Cockpit/admin console", Warn),
        9001 => ("HTTP/app — Supervisor/Tor/admin", Warn),
        7001 => ("WebLogic admin — frequent RCE target", High),
        4444 => ("often Metasploit/meterpreter default; verify", Warn),

        // ── File sharing ──
        21 => ("FTP — often cleartext; prefer SFTP/FTPS", High),
        69 => ("TFTP — no auth; config/firmware exposure", High),
        111 => ("RPCbind — maps RPC services; enum with --sR", Warn),
        135 => ("MSRPC endpoint mapper — Windows RPC; enumeration surface", Warn),
        137 => ("NetBIOS name service — host/domain info leak", Warn),
        138 => ("NetBIOS datagram — legacy Windows networking", Info),
        139 => ("NetBIOS session — legacy SMB; exposes shares", Warn),
        445 => ("SMB — file sharing; check SMBv1/signing (--smb-audit)", Warn),
        2049 => ("NFS — network file system; check exports", Warn),
        873 => ("rsync — file sync; often no auth on modules", Warn),
        548 => ("AFP — Apple file sharing", Info),

        // ── Databases / caches ──
        1433 => ("MSSQL — database; must not face untrusted nets", High),
        1521 => ("Oracle DB — database; restrict to app tier", High),
        3306 => ("MySQL/MariaDB — database; restrict to app tier", High),
        5432 => ("PostgreSQL — database; restrict to app tier", High),
        6379 => ("Redis — cache/db; often no auth, RCE-prone", High),
        11211 => ("Memcached — cache; no auth, amplification risk", High),
        27017 | 27018 => ("MongoDB — database; historically open by default", High),
        9200 | 9300 => ("Elasticsearch — datastore/API; often no auth", High),
        5984 | 6984 => ("CouchDB — database/API; check auth", High),
        7000 | 9042 => ("Cassandra — database; restrict access", High),
        2379 | 2380 => ("etcd — cluster key-value store; secrets exposure", High),
        8500 => ("Consul — service mesh/KV; check ACLs", High),
        5672 | 15672 => ("RabbitMQ — message broker; check default creds", Warn),
        9092 => ("Kafka — message broker; restrict access", Warn),

        // ── Mail ──
        25 => ("SMTP — mail transfer; check open relay / STARTTLS", Info),
        465 => ("SMTPS — mail submission over TLS", Info),
        587 => ("SMTP submission — check AUTH/STARTTLS", Info),
        110 => ("POP3 — cleartext mail; prefer POP3S/995", High),
        143 => ("IMAP — cleartext mail; prefer IMAPS/993", High),
        993 => ("IMAPS — mail over TLS", Info),
        995 => ("POP3S — mail over TLS", Info),

        // ── DNS / directory / auth ──
        53 => ("DNS — resolver/zone; check recursion & AXFR", Info),
        389 => ("LDAP — directory; cleartext, prefer LDAPS/636", Warn),
        636 => ("LDAPS — directory over TLS", Info),
        88 => ("Kerberos — auth; AS-REP/kerberoast surface", Warn),
        464 => ("Kerberos password change", Info),
        749 => ("Kerberos admin", Warn),

        // ── Management / monitoring ──
        161 | 162 => ("SNMP — device mgmt; weak community strings leak info", High),
        623 => ("IPMI/BMC — out-of-band mgmt; cipher-0/auth bypass", High),
        10250 => ("Kubelet API — node control; RCE if unauth", High),
        10255 => ("Kubelet read-only — leaks pod/secret metadata", High),
        2375 => ("Docker API (no TLS) — root-equivalent RCE", High),
        2376 => ("Docker API (TLS) — restrict client certs", Warn),
        6443 => ("Kubernetes API server — cluster control plane", High),
        9100 => ("Prometheus node_exporter / JetDirect (printer)", Info),

        // ── VPN / tunneling ──
        500 | 4500 => ("IKE/IPsec VPN — check aggressive mode", Info),
        1194 => ("OpenVPN", Info),
        1723 => ("PPTP VPN — obsolete, weak crypto", High),
        1701 => ("L2TP VPN", Info),

        // ── Directory/misc infra ──
        179 => ("BGP — routing; must not be externally reachable", High),
        6000..=6009 => ("X11 — display server; often unauthenticated", High),
        631 => ("IPP/CUPS — printing; admin interface", Info),
        515 => ("LPD — line printer daemon", Info),
        9418 => ("Git daemon — anonymous repo access", Warn),
        3268 | 3269 => ("Global Catalog (AD LDAP) — directory", Warn),
        1883 | 8883 => ("MQTT — IoT message broker; check auth/ACL", Warn),
        5060 | 5061 => ("SIP — VoIP signaling", Info),
        554 => ("RTSP — streaming/camera; check auth", Warn),
        102 => ("Siemens S7 (ICS) — PLC; must be isolated", High),
        502 => ("Modbus (ICS) — PLC; no auth, must be isolated", High),
        20000 => ("DNP3 (ICS/SCADA) — must be isolated", High),
        47808 => ("BACnet (building automation)", Warn),

        _ => return None,
    };
    Some(Desc { text, risk })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_high_risk_db() {
        let d = describe(3306).unwrap();
        assert_eq!(d.risk, Risk::High);
        assert!(d.text.to_lowercase().contains("mysql"));
    }

    #[test]
    fn cleartext_is_high() {
        assert_eq!(describe(23).unwrap().risk, Risk::High); // telnet
        assert_eq!(describe(21).unwrap().risk, Risk::High); // ftp
    }

    #[test]
    fn web_is_info() {
        assert_eq!(describe(80).unwrap().risk, Risk::Info);
        assert_eq!(describe(443).unwrap().risk, Risk::Info);
    }

    #[test]
    fn unknown_port_has_no_desc() {
        assert!(describe(64999).is_none());
    }

    #[test]
    fn glyphs_distinct() {
        assert_ne!(Risk::Info.glyph(), Risk::Warn.glyph());
        assert_ne!(Risk::Warn.glyph(), Risk::High.glyph());
    }
}
