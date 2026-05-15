//! DHCP DISCOVER broadcast → harvest DHCP server replies.
//!
//! Builds a minimal DHCP DISCOVER (RFC 2131) and sends it to
//! 255.255.255.255:67. Every DHCP server on the local broadcast
//! domain answers with a DHCP OFFER carrying:
//!
//!   - **Server IP** (siaddr or option 54)
//!   - **Offered IP** (yiaddr)
//!   - **Subnet mask** (option 1)
//!   - **Router / gateway** (option 3)
//!   - **DNS servers** (option 6)
//!   - **Domain name** (option 15)
//!   - **Lease time** (option 51, seconds)
//!
//! Read-only — we DISCOVER but never REQUEST, so the lease never
//! gets bound. The offered IP is recycled by the server's normal
//! timeout.
//!
//! Binds 0.0.0.0:68 (the canonical DHCP client port). On systems
//! where 68 is privileged we fall back to ephemeral — most DHCP
//! servers reply to the source port we sent from, so the harvest
//! still works.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const DHCP_MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DhcpOffer {
    pub server_ip: Option<String>,
    pub offered_ip: Option<String>,
    pub subnet_mask: Option<String>,
    pub router: Option<String>,
    pub dns_servers: Vec<String>,
    pub domain_name: Option<String>,
    pub lease_seconds: Option<u32>,
    pub raw_options: Vec<(u8, Vec<u8>)>,
}

pub async fn discover(dur: Duration) -> Result<Vec<DhcpOffer>> {
    // Bind 0.0.0.0:68 first; fall back to ephemeral.
    let sock = match UdpSocket::bind("0.0.0.0:68").await {
        Ok(s) => s,
        Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
    };
    sock.set_broadcast(true)?;

    let xid: u32 = rand::random();
    let mac = pick_mac();
    let pkt = build_discover(xid, mac);

    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), 67));
    sock.send_to(&pkt, dst).await?;

    let deadline = Instant::now() + dur;
    let mut buf = vec![0u8; 1500];
    let mut offers: Vec<DhcpOffer> = Vec::new();
    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(r) => r,
            None => break,
        };
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _src))) => {
                if let Some(o) = parse_offer(&buf[..n], xid) {
                    offers.push(o);
                }
            }
            _ => break,
        }
    }
    Ok(offers)
}

fn pick_mac() -> [u8; 6] {
    // Pull the first non-loopback interface's MAC if available; fall
    // back to a fixed locally-administered prefix.
    for iface in pnet::datalink::interfaces() {
        if iface.is_loopback() {
            continue;
        }
        if let Some(mac) = iface.mac {
            let o = mac.octets();
            return [o[0], o[1], o[2], o[3], o[4], o[5]];
        }
    }
    [0x02, 0x00, 0xde, 0xad, 0xbe, 0xef]
}

/// Build a DHCP DISCOVER per RFC 2131 §2.
pub fn build_discover(xid: u32, mac: [u8; 6]) -> Vec<u8> {
    let mut buf = vec![0u8; 240];
    buf[0] = 1; // op = BOOTREQUEST
    buf[1] = 1; // htype = Ethernet
    buf[2] = 6; // hlen
    buf[3] = 0; // hops
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    // secs (8..10), flags (10..12)
    buf[10] = 0x80; // broadcast flag set so server replies to bcast
    // ciaddr (12..16), yiaddr (16..20), siaddr (20..24), giaddr (24..28)
    // chaddr (28..44) — first 6 bytes are our MAC
    buf[28..34].copy_from_slice(&mac);
    // sname (44..108), file (108..236) — zero
    // magic cookie
    buf[236..240].copy_from_slice(&DHCP_MAGIC);
    // Options: 53 = DHCP Message Type = 1 (DISCOVER)
    buf.extend_from_slice(&[0x35, 0x01, 0x01]);
    // 55 = Parameter Request List
    buf.extend_from_slice(&[0x37, 0x07, 1, 3, 6, 15, 28, 33, 51]);
    // 57 = Max DHCP Message Size = 1500
    buf.extend_from_slice(&[0x39, 0x02, 0x05, 0xdc]);
    // 61 = Client identifier
    buf.extend_from_slice(&[0x3d, 0x07, 0x01]);
    buf.extend_from_slice(&mac);
    // End option
    buf.push(0xff);
    buf
}

pub fn parse_offer(buf: &[u8], expected_xid: u32) -> Option<DhcpOffer> {
    if buf.len() < 240 || buf[0] != 2 {
        // op = BOOTREPLY required
        return None;
    }
    let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if xid != expected_xid {
        return None;
    }
    if &buf[236..240] != DHCP_MAGIC {
        return None;
    }

    let yiaddr = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let siaddr = Ipv4Addr::new(buf[20], buf[21], buf[22], buf[23]);

    let mut o = DhcpOffer {
        offered_ip: Some(yiaddr.to_string()),
        server_ip: if siaddr.is_unspecified() {
            None
        } else {
            Some(siaddr.to_string())
        },
        ..Default::default()
    };

    // Walk options starting at offset 240.
    let mut p = 240usize;
    while p < buf.len() {
        let code = buf[p];
        if code == 0xff {
            break;
        }
        if code == 0x00 {
            p += 1;
            continue;
        }
        if p + 2 > buf.len() {
            break;
        }
        let len = buf[p + 1] as usize;
        if p + 2 + len > buf.len() {
            break;
        }
        let data = &buf[p + 2..p + 2 + len];
        match code {
            1 if data.len() == 4 => {
                o.subnet_mask = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string());
            }
            3 if data.len() >= 4 => {
                o.router = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string());
            }
            6 => {
                for chunk in data.chunks_exact(4) {
                    o.dns_servers.push(
                        Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]).to_string(),
                    );
                }
            }
            15 => {
                o.domain_name = Some(String::from_utf8_lossy(data).trim_end_matches('\0').to_string());
            }
            51 if data.len() == 4 => {
                o.lease_seconds = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
            54 if data.len() == 4 => {
                // Server identifier overrides siaddr when present
                o.server_ip = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string());
            }
            _ => {
                o.raw_options.push((code, data.to_vec()));
            }
        }
        p += 2 + len;
    }
    Some(o)
}

pub fn print_offers(offers: &[DhcpOffer]) {
    use colored::*;
    println!();
    println!("{}", format!("DHCP discover — {} offer(s)", offers.len()).bold());
    if offers.is_empty() {
        println!("  {}", "no DHCP server replied (need broadcast-capable interface, root for port 68)".dimmed());
        return;
    }
    for (i, o) in offers.iter().enumerate() {
        println!(
            "  [{}] server={} offered={}",
            i,
            o.server_ip.as_deref().unwrap_or("?"),
            o.offered_ip.as_deref().unwrap_or("?").yellow()
        );
        if let Some(m) = &o.subnet_mask {
            println!("       mask     : {}", m);
        }
        if let Some(r) = &o.router {
            println!("       router   : {}", r);
        }
        if !o.dns_servers.is_empty() {
            println!("       dns      : {}", o.dns_servers.join(", "));
        }
        if let Some(d) = &o.domain_name {
            println!("       domain   : {}", d);
        }
        if let Some(l) = o.lease_seconds {
            let h = l / 3600;
            let m = (l / 60) % 60;
            println!("       lease    : {} ({}h {}m)", l, h, m);
        }
    }
    if offers.len() > 1 {
        println!(
            "  {}",
            "multiple DHCP servers responded — possible rogue server on the segment"
                .red()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_discover_carries_magic_cookie() {
        let pkt = build_discover(0x12345678, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert!(pkt.len() >= 244);
        assert_eq!(&pkt[236..240], &DHCP_MAGIC);
        // op = BOOTREQUEST
        assert_eq!(pkt[0], 1);
        // xid
        assert_eq!(&pkt[4..8], &[0x12, 0x34, 0x56, 0x78]);
        // chaddr first 6
        assert_eq!(&pkt[28..34], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        // option 53 = 1 (DISCOVER) in the options
        assert!(pkt[240..].windows(3).any(|w| w == [0x35, 0x01, 0x01]));
        // end-of-options
        assert_eq!(*pkt.last().unwrap(), 0xff);
    }

    #[test]
    fn parse_offer_extracts_fields() {
        // Build a synthetic DHCP OFFER: op=2, xid=0x11223344, magic,
        // yiaddr=10.0.0.42, server-id option=192.168.1.1, mask=255.255.255.0,
        // router=192.168.1.1, dns=8.8.8.8, lease=86400, end.
        let mut buf = vec![0u8; 240];
        buf[0] = 2; // BOOTREPLY
        buf[4..8].copy_from_slice(&0x11223344u32.to_be_bytes());
        buf[16..20].copy_from_slice(&[10, 0, 0, 42]); // yiaddr
        buf[20..24].copy_from_slice(&[192, 168, 1, 1]); // siaddr
        buf[236..240].copy_from_slice(&DHCP_MAGIC);
        // Options
        buf.extend_from_slice(&[0x35, 0x01, 0x02]); // DHCP type = OFFER
        buf.extend_from_slice(&[0x36, 0x04, 192, 168, 1, 1]); // server-id
        buf.extend_from_slice(&[0x01, 0x04, 255, 255, 255, 0]); // subnet
        buf.extend_from_slice(&[0x03, 0x04, 192, 168, 1, 1]); // router
        buf.extend_from_slice(&[0x06, 0x04, 8, 8, 8, 8]); // dns
        buf.extend_from_slice(&[0x33, 0x04, 0, 1, 0x51, 0x80]); // lease = 86400
        buf.push(0xff);

        let o = parse_offer(&buf, 0x11223344).unwrap();
        assert_eq!(o.offered_ip.as_deref(), Some("10.0.0.42"));
        assert_eq!(o.server_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(o.subnet_mask.as_deref(), Some("255.255.255.0"));
        assert_eq!(o.router.as_deref(), Some("192.168.1.1"));
        assert_eq!(o.dns_servers, vec!["8.8.8.8"]);
        assert_eq!(o.lease_seconds, Some(86400));
    }

    #[test]
    fn parse_offer_rejects_wrong_xid() {
        let mut buf = vec![0u8; 244];
        buf[0] = 2;
        buf[4..8].copy_from_slice(&0xAAAAu32.to_be_bytes());
        buf[236..240].copy_from_slice(&DHCP_MAGIC);
        assert!(parse_offer(&buf, 0x1234).is_none());
    }

    #[test]
    fn parse_offer_rejects_missing_magic() {
        let mut buf = vec![0u8; 240];
        buf[0] = 2;
        // magic absent — bytes [236..240] are zero
        assert!(parse_offer(&buf, 0).is_none());
    }
}
