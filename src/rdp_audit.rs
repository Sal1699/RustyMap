//! RDP security-protocol audit (X.224 Connection Request → RDP_NEG_RSP).
//!
//! RDP wraps everything in TPKT (RFC 1006) + COTP. The very first
//! exchange (X.224 Connection Request) carries an RDP_NEG_REQ in the
//! cookie area listing the security protocols the client supports.
//! The server replies with RDP_NEG_RSP picking one — or RDP_NEG_FAILURE.
//!
//! Security protocols (PROTOCOL_*):
//!   0x00000000  PROTOCOL_RDP        Standard RDP (legacy, no TLS)
//!   0x00000001  PROTOCOL_SSL        TLS 1.0+ wrapping the RDP stream
//!   0x00000002  PROTOCOL_HYBRID     CredSSP (NLA on top of TLS)
//!   0x00000004  PROTOCOL_RDSTLS     RDS-TLS (Win Server 2012R2+)
//!   0x00000008  PROTOCOL_HYBRID_EX  Early User Authentication
//!
//! A server that accepts PROTOCOL_RDP on its own is vulnerable to
//! BlueKeep-class issues (CVE-2019-0708) and MITM. Modern RDP must
//! require at least PROTOCOL_HYBRID (NLA).

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RdpAudit {
    pub responded: bool,
    pub neg_failure_code: Option<u32>,
    pub selected_protocol: Option<u32>,
    pub protocol_name: Option<String>,
    pub findings: Vec<String>,
}

impl RdpAudit {
    pub fn has_weakness(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// X.224 Connection Request asking for RDP+TLS+CredSSP+HybridEx.
/// Layout (TPKT 4B + COTP variable + RDP_NEG_REQ 8B):
///   TPKT       : 0x03 0x00 LL LL                (total length)
///   COTP CR    : LL 0xE0 0x0000 0x0000 0x00     (length + CR + dst/src refs + class)
///   RDP_NEG_REQ: 0x01 0x00 0x08 0x00 RR RR RR RR (type, flags, len=8, requested protocols)
fn build_request() -> Vec<u8> {
    let neg_req: [u8; 8] = [
        0x01, 0x00, 0x08, 0x00, // type=NEG_REQ, flags, length=8 (LE)
        0x0b, 0x00, 0x00, 0x00, // PROTOCOL_RDP|SSL|HYBRID|HYBRID_EX (1|2|8 = 0x0b)
    ];
    let cotp_len: u8 = 6 + neg_req.len() as u8 - 1; // length is "remaining after this byte"
    let mut pkt = Vec::with_capacity(4 + 7 + 8);
    let total = 4u16 + 7 + neg_req.len() as u16;
    pkt.extend_from_slice(&[0x03, 0x00, (total >> 8) as u8, (total & 0xff) as u8]);
    pkt.push(cotp_len);
    pkt.push(0xE0);                         // CR
    pkt.extend_from_slice(&[0x00, 0x00]);   // dst-ref
    pkt.extend_from_slice(&[0x00, 0x00]);   // src-ref
    pkt.push(0x00);                         // class=0, no options
    pkt.extend_from_slice(&neg_req);
    pkt
}

pub async fn audit(ip: IpAddr, port: u16, dur: Duration) -> Result<RdpAudit> {
    let addr = SocketAddr::new(ip, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await??;
    let req = build_request();
    timeout(dur, s.write_all(&req)).await??;

    // Read TPKT header (4B) then the rest by length.
    let mut tpkt = [0u8; 4];
    timeout(dur, s.read_exact(&mut tpkt)).await??;
    if tpkt[0] != 0x03 {
        return Err(anyhow!("not a TPKT response (first byte 0x{:02x})", tpkt[0]));
    }
    let total = ((tpkt[2] as usize) << 8) | tpkt[3] as usize;
    if total < 11 || total > 1024 {
        return Err(anyhow!("bogus TPKT length {}", total));
    }
    let mut rest = vec![0u8; total - 4];
    timeout(dur, s.read_exact(&mut rest)).await??;

    let mut a = RdpAudit { responded: true, ..Default::default() };
    parse_response(&rest, &mut a);
    classify(&mut a);
    Ok(a)
}

fn parse_response(rest: &[u8], a: &mut RdpAudit) {
    // rest = COTP CC (Connection Confirm, var len) + optional RDP_NEG_RSP/FAILURE
    if rest.len() < 7 {
        return;
    }
    // COTP CC: len(1B) 0xD0 dst-ref(2) src-ref(2) class(1) [variable parameters]
    let cotp_len = rest[0] as usize;
    let cotp_total = cotp_len + 1; // length field doesn't count itself
    if rest.len() < cotp_total {
        return;
    }
    let trailer = &rest[cotp_total..];
    if trailer.len() < 8 {
        return;
    }
    let msg_type = trailer[0];
    // RDP_NEG_RSP type = 0x02, RDP_NEG_FAILURE type = 0x03
    match msg_type {
        0x02 => {
            // type | flags | length(LE,2) | selected_protocol(LE,4)
            let proto = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
            a.selected_protocol = Some(proto);
            a.protocol_name = Some(name_protocol(proto));
        }
        0x03 => {
            let code = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
            a.neg_failure_code = Some(code);
        }
        _ => {
            // No NEG response at all — server speaks legacy RDP only.
            a.selected_protocol = Some(0);
            a.protocol_name = Some("PROTOCOL_RDP (legacy, no NEG)".into());
        }
    }
}

fn name_protocol(p: u32) -> String {
    let mut names = Vec::new();
    if p == 0 {
        return "PROTOCOL_RDP (standard, no TLS)".into();
    }
    if p & 0x01 != 0 {
        names.push("SSL/TLS");
    }
    if p & 0x02 != 0 {
        names.push("CredSSP/NLA");
    }
    if p & 0x04 != 0 {
        names.push("RDSTLS");
    }
    if p & 0x08 != 0 {
        names.push("HybridEx (early user auth)");
    }
    names.join(" + ")
}

fn classify(a: &mut RdpAudit) {
    match a.selected_protocol {
        Some(0) => {
            a.findings.push(
                "RDP standard security selected — no TLS, vulnerable to MITM and BlueKeep-class issues (CVE-2019-0708)".into(),
            );
        }
        Some(p) if p & 0x02 == 0 => {
            // No CredSSP/NLA bit set
            a.findings.push(
                "NLA (CredSSP) not selected — pre-auth RDP path, weaker against credential bruteforce".into(),
            );
        }
        Some(_) => {}
        None => {
            if let Some(code) = a.neg_failure_code {
                a.findings.push(format!("server returned NEG_FAILURE 0x{:08x}", code));
            }
        }
    }
}

pub fn print_report(host: &str, port: u16, a: &RdpAudit) {
    use colored::*;
    println!();
    println!("{}", format!("RDP audit for {}:{}", host, port).bold());
    if let Some(name) = &a.protocol_name {
        println!("  selected: {}", name);
    }
    if let Some(code) = a.neg_failure_code {
        println!("  failure : 0x{:08x}", code);
    }
    if a.findings.is_empty() {
        println!("  {}", "no weaknesses detected".green());
    } else {
        println!("  {}", "weaknesses:".yellow().bold());
        for f in &a.findings {
            println!("    · {}", f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_protocol_combos() {
        assert!(name_protocol(0).contains("standard"));
        assert!(name_protocol(0x01).contains("SSL/TLS"));
        assert!(name_protocol(0x03).contains("CredSSP"));
        assert!(name_protocol(0x0b).contains("HybridEx"));
    }

    #[test]
    fn classify_legacy_rdp_flagged() {
        let mut a = RdpAudit { selected_protocol: Some(0), responded: true, ..Default::default() };
        classify(&mut a);
        assert!(a.findings.iter().any(|f| f.contains("BlueKeep")));
    }

    #[test]
    fn classify_tls_only_warns_no_nla() {
        let mut a = RdpAudit { selected_protocol: Some(0x01), responded: true, ..Default::default() };
        classify(&mut a);
        assert!(a.findings.iter().any(|f| f.contains("NLA")));
    }

    #[test]
    fn classify_clean_credssp() {
        let mut a = RdpAudit { selected_protocol: Some(0x02), responded: true, ..Default::default() };
        classify(&mut a);
        assert!(a.findings.is_empty(), "{:?}", a.findings);
    }

    #[test]
    fn build_request_size_and_header() {
        let r = build_request();
        assert_eq!(r[0], 0x03);
        assert_eq!(r[1], 0x00);
        let total = ((r[2] as usize) << 8) | r[3] as usize;
        assert_eq!(total, r.len());
    }
}
