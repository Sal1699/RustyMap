use anyhow::{anyhow, Result};
use std::collections::BTreeSet;

pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    // Bug-19 (v0.66.4): the previous `lhs.parse()?` propagated the
    // raw `ParseIntError` ("invalid digit found in string") which gave
    // the user no idea which flag was at fault. Wrap each numeric
    // parse with explicit context naming -p / --ports and showing the
    // offending token + spec.
    fn parse_port_num(token: &str, full_spec: &str) -> Result<u32> {
        token.parse::<u32>().map_err(|_| {
            anyhow!(
                "invalid port '{}' in -p/--ports '{}': expected a number (1-65535), a range like '22-1024', or comma-separated combinations",
                token, full_spec
            )
        })
    }
    let mut set: BTreeSet<u16> = BTreeSet::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lhs, rhs)) = part.split_once('-') {
            let start: u32 = if lhs.is_empty() { 1 } else { parse_port_num(lhs, spec)? };
            let end: u32 = if rhs.is_empty() { 65535 } else { parse_port_num(rhs, spec)? };
            if start == 0 || end > 65535 || start > end {
                return Err(anyhow!(
                    "invalid port range '{}' in -p/--ports '{}': must be 1-65535 and start ≤ end",
                    part, spec
                ));
            }
            for p in start..=end {
                set.insert(p as u16);
            }
        } else {
            let p: u32 = parse_port_num(part, spec)?;
            if p == 0 || p > 65535 {
                return Err(anyhow!(
                    "port '{}' out of range (1-65535) in -p/--ports '{}'",
                    p, spec
                ));
            }
            set.insert(p as u16);
        }
    }

    if set.is_empty() {
        return Err(anyhow!("-p/--ports '{}' produced an empty list", spec));
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
        // ── v0.112.0: fill common well-known ports that previously showed
        //    "unknown" in the SERVICE column (no -sV needed) ──
        88 => Some("kerberos"),
        102 => Some("iso-tsap"),      // Siemens S7 (ICS)
        500 => Some("isakmp"),
        502 => Some("modbus"),        // ICS
        548 => Some("afp"),
        554 => Some("rtsp"),
        623 => Some("asf-rmcp"),      // IPMI/BMC
        873 => Some("rsync"),
        902 | 912 => Some("vmware-auth"),
        1194 => Some("openvpn"),
        1434 => Some("ms-sql-m"),
        1883 => Some("mqtt"),
        1900 => Some("upnp"),         // SSDP
        2181 => Some("zookeeper"),
        2379 | 2380 => Some("etcd"),
        2404 => Some("iec-104"),      // ICS
        3268 | 3269 => Some("globalcat"),
        4786 => Some("cisco-smi"),    // Smart Install (RCE-prone)
        5353 => Some("mdns"),
        5355 => Some("llmnr"),
        5555 => Some("adb"),          // Android Debug Bridge
        5672 => Some("amqp"),
        5984 => Some("couchdb"),
        6000..=6009 => Some("x11"),
        8086 => Some("influxdb"),
        8291 => Some("winbox"),       // MikroTik RouterOS
        8883 => Some("secure-mqtt"),
        9042 => Some("cassandra"),
        9092 => Some("kafka"),
        9100 => Some("jetdirect"),
        10250 => Some("kubelet"),
        15672 => Some("rabbitmq-mgmt"),
        20000 => Some("dnp3"),        // ICS
        44818 => Some("ethernet-ip"), // ICS
        47808 => Some("bacnet"),
        // ── v0.116.0: more common/pentest ports that showed "unknown", plus
        //    ports portdesc already DESCRIBED while the SERVICE column stayed
        //    blank (512/513/515/543/544/749/990/992/1701/4500/7000/8500/
        //    9418/10255/62078) — SERVICE now names what the NOTE describes ──
        20 => Some("ftp-data"),
        43 => Some("whois"),
        79 => Some("finger"),
        113 => Some("ident"),
        119 => Some("nntp"),
        177 => Some("xdmcp"),
        427 => Some("svrloc"),         // Service Location Protocol
        464 => Some("kpasswd"),
        512 => Some("exec"),           // rexec (cleartext)
        513 => Some("login"),          // rlogin (cleartext)
        515 => Some("printer"),        // LPD
        543 => Some("klogin"),
        544 => Some("kshell"),
        749 => Some("kerberos-adm"),
        990 => Some("ftps"),
        992 => Some("telnets"),
        1080 => Some("socks"),
        1099 => Some("rmiregistry"),   // Java RMI (deserialization RCE)
        1701 => Some("l2tp"),
        1812 => Some("radius"),
        1813 => Some("radius-acct"),
        3128 => Some("squid-http"),    // proxy
        3260 => Some("iscsi"),
        4369 => Some("epmd"),          // Erlang Port Mapper (RabbitMQ/CouchDB)
        4500 => Some("ipsec-nat-t"),
        5000 => Some("upnp"),
        5222 => Some("xmpp-client"),
        5269 => Some("xmpp-server"),
        5601 => Some("kibana"),
        5666 => Some("nrpe"),          // Nagios NRPE
        6667 => Some("irc"),
        7000 => Some("cassandra"),     // inter-node
        7687 => Some("bolt"),          // Neo4j Bolt
        8009 => Some("ajp13"),         // Tomcat AJP (Ghostcat CVE-2020-1938)
        8081 => Some("http-alt"),
        8140 => Some("puppet"),
        8500 => Some("consul"),
        9418 => Some("git"),           // git:// daemon
        10000 => Some("webmin"),
        10255 => Some("kubelet-ro"),
        61616 => Some("activemq"),     // OpenWire (CVE-2023-46604 RCE)
        62078 => Some("iphone-sync"),  // iOS lockdownd
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

    #[test]
    fn service_name_v0_112_additions() {
        // Ports that used to show "unknown" now carry their well-known label.
        assert_eq!(service_name(902), Some("vmware-auth"));
        assert_eq!(service_name(912), Some("vmware-auth"));
        assert_eq!(service_name(88), Some("kerberos"));
        assert_eq!(service_name(502), Some("modbus"));
        assert_eq!(service_name(44818), Some("ethernet-ip"));
        assert_eq!(service_name(8291), Some("winbox"));
        assert_eq!(service_name(6000), Some("x11"));
        assert_eq!(service_name(6009), Some("x11"));
    }

    #[test]
    fn service_name_v0_116_additions() {
        assert_eq!(service_name(20), Some("ftp-data"));
        assert_eq!(service_name(79), Some("finger"));
        assert_eq!(service_name(1099), Some("rmiregistry"));
        assert_eq!(service_name(8009), Some("ajp13"));
        assert_eq!(service_name(10000), Some("webmin"));
        assert_eq!(service_name(61616), Some("activemq"));
        assert_eq!(service_name(3260), Some("iscsi"));
        assert_eq!(service_name(5601), Some("kibana"));
    }

    #[test]
    fn described_ports_also_have_a_service_name() {
        // Consistency: every port portdesc describes should also get a SERVICE
        // label, so the NOTE column never sits next to a bare "unknown".
        // (The inverse divergence v0.116.0 set out to close.)
        for p in [512u16, 513, 515, 543, 749, 990, 1701, 7000, 8500, 9418, 10255, 62078,
                  79, 113, 177, 427, 1099, 3128, 3260, 4369, 5601, 5666, 8009, 8140, 10000, 61616] {
            assert!(
                crate::portdesc::describe(p).is_none() || service_name(p).is_some(),
                "port {p} is described but has no service_name label"
            );
        }
    }
}
