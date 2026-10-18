use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// Determine the local IPv4 address that would be used to reach `dst`.
/// Uses the connectionless UDP-connect trick: no packets are sent,
/// but the kernel chooses a source address based on the routing table.
pub fn source_ipv4_for(dst: Ipv4Addr) -> Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(SocketAddr::new(IpAddr::V4(dst), 80))?;
    match sock.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(anyhow!("expected IPv4 local address")),
    }
}

/// Parse a MAC token (`aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff`) into bytes.
fn parse_mac(tok: &str) -> Option<[u8; 6]> {
    let norm = tok.replace('-', ":");
    let parts: Vec<&str> = norm.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            return None;
        }
        m[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(m)
}

/// Parse an OS neighbor/ARP table dump (`ip neigh`, `arp -a`, Windows `arp -a`)
/// into (IPv4, MAC) pairs. Format-agnostic: on each line it picks the first
/// IPv4 and the first MAC-looking token, so it works across the (many) layouts.
/// Incomplete/failed entries (no MAC) are skipped.
pub fn parse_neigh_table(output: &str) -> Vec<(Ipv4Addr, [u8; 6])> {
    let mut out = Vec::new();
    for line in output.lines() {
        let mut ip: Option<Ipv4Addr> = None;
        let mut mac: Option<[u8; 6]> = None;
        for tok in line.split(|c: char| c.is_whitespace() || c == '(' || c == ')') {
            if tok.is_empty() {
                continue;
            }
            if ip.is_none() {
                if let Ok(v) = tok.parse::<Ipv4Addr>() {
                    ip = Some(v);
                    continue;
                }
            }
            if mac.is_none() {
                if let Some(m) = parse_mac(tok) {
                    mac = Some(m);
                }
            }
        }
        if let (Some(i), Some(m)) = (ip, mac) {
            out.push((i, m));
        }
    }
    out
}

/// Read the OS neighbor table (post-scan it holds the MACs of hosts we just
/// talked to) as an IPv4→MAC map. Tries `ip neigh` (Linux), falls back to
/// `arp -a`. Empty on failure. Used as a `--sn` MAC fallback independent of
/// which discovery path ran.
pub fn neighbor_macs() -> HashMap<Ipv4Addr, [u8; 6]> {
    use std::process::Command;
    let text = Command::new("ip")
        .arg("neigh")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .or_else(|| {
            Command::new("arp")
                .arg("-a")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        })
        .unwrap_or_default();
    parse_neigh_table(&text).into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_neigh_linux() {
        let out = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n\
                   192.168.1.9 dev eth0  FAILED\n\
                   192.168.1.5 dev eth0 lladdr 11:22:33:44:55:66 STALE";
        let t = parse_neigh_table(out);
        assert_eq!(t.len(), 2); // the FAILED (no MAC) line is skipped
        assert!(t.contains(&("192.168.1.1".parse().unwrap(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])));
        assert!(t.contains(&("192.168.1.5".parse().unwrap(), [0x11, 0x22, 0x33, 0x44, 0x55, 0x66])));
    }

    #[test]
    fn parses_arp_a_dash_and_paren() {
        // BSD/Linux `arp -a` paren form + Windows dash form.
        let out = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0\n\
                   192.168.1.7  de-ad-be-ef-00-01  dynamic";
        let t = parse_neigh_table(out);
        assert!(t.contains(&("192.168.1.1".parse().unwrap(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])));
        assert!(t.contains(&("192.168.1.7".parse().unwrap(), [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])));
    }

    #[test]
    fn skips_incomplete() {
        assert!(parse_neigh_table("? (192.168.1.9) at <incomplete> on eth0").is_empty());
    }
}
