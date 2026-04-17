use anyhow::{anyhow, Result};
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
