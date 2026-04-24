use anyhow::{anyhow, Result};
use std::collections::BTreeSet;

pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut set: BTreeSet<u16> = BTreeSet::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lhs, rhs)) = part.split_once('-') {
            let start: u32 = if lhs.is_empty() { 1 } else { lhs.parse()? };
            let end: u32 = if rhs.is_empty() { 65535 } else { rhs.parse()? };
            if start == 0 || end > 65535 || start > end {
                return Err(anyhow!("Invalid port range: {}", part));
            }
            for p in start..=end {
                set.insert(p as u16);
            }
        } else {
            let p: u32 = part.parse()?;
            if p == 0 || p > 65535 {
                return Err(anyhow!("Port out of range: {}", p));
            }
            set.insert(p as u16);
        }
    }

    if set.is_empty() {
        return Err(anyhow!("No ports specified"));
    }
    Ok(set.into_iter().collect())
}

/// Common service names for well-known ports. Returns None if unknown.
pub fn service_name(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("domain"),
        67 | 68 => Some("dhcp"),
        69 => Some("tftp"),
        80 => Some("http"),
        110 => Some("pop3"),
        111 => Some("rpcbind"),
        123 => Some("ntp"),
        135 => Some("msrpc"),
        137..=139 => Some("netbios"),
        143 => Some("imap"),
        161 | 162 => Some("snmp"),
        179 => Some("bgp"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("microsoft-ds"),
        465 => Some("smtps"),
        514 => Some("syslog"),
        587 => Some("submission"),
        631 => Some("ipp"),
        636 => Some("ldaps"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("ms-sql-s"),
        1521 => Some("oracle"),
        1723 => Some("pptp"),
        2049 => Some("nfs"),
        2375 | 2376 => Some("docker"),
        3000 => Some("node-dev"),
        3306 => Some("mysql"),
        3389 => Some("ms-wbt-server"),
        5060 | 5061 => Some("sip"),
        5432 => Some("postgresql"),
        5900..=5910 => Some("vnc"),
        5985 | 5986 => Some("winrm"),
        6379 => Some("redis"),
        6443 => Some("kubernetes"),
        7001 => Some("weblogic"),
        8000 | 8080 | 8008 => Some("http-alt"),
        8443 => Some("https-alt"),
        8888 => Some("http-alt"),
        9000 => Some("http-alt"),
        9090 => Some("prometheus"),
        9200 | 9300 => Some("elasticsearch"),
        11211 => Some("memcached"),
        27017 | 27018 => Some("mongodb"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
    }

    #[test]
    fn parse_list() {
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
    }

    #[test]
    fn parse_range() {
        assert_eq!(parse_ports("80-82").unwrap(), vec![80, 81, 82]);
    }

    #[test]
    fn parse_open_range_dash() {
        let v = parse_ports("-").unwrap();
        assert_eq!(v.len(), 65535);
        assert_eq!(v[0], 1);
        assert_eq!(v[v.len() - 1], 65535);
    }

    #[test]
    fn parse_dedup_and_sort() {
        assert_eq!(parse_ports("80,22,80,443,22").unwrap(), vec![22, 80, 443]);
    }

    #[test]
    fn parse_combined() {
        assert_eq!(parse_ports("22,80-82,443").unwrap(), vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn rejects_zero() {
        assert!(parse_ports("0").is_err());
    }

    #[test]
    fn rejects_overflow() {
        assert!(parse_ports("70000").is_err());
    }

    #[test]
    fn rejects_inverted_range() {
        assert!(parse_ports("100-50").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_ports(",,").is_err());
    }

    #[test]
    fn service_name_known() {
        assert_eq!(service_name(443), Some("https"));
        assert_eq!(service_name(22), Some("ssh"));
        assert_eq!(service_name(137), Some("netbios"));
    }

    #[test]
    fn service_name_unknown() {
        assert_eq!(service_name(12345), None);
    }
}
