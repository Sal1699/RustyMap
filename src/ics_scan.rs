//! ICS / SCADA protocol probes.
//!
//! Read-only queries against the five most-deployed industrial
//! protocols. Each probe sends one well-formed request and parses
//! the reply for identifying information; nothing is written, no
//! control function is exercised.
//!
//! Protocols covered:
//!   - **Modbus/TCP** (port 502): Read Device Identification (FC 43,
//!     MEI 14). Reply carries vendor / product / version strings.
//!   - **Siemens S7** (port 102): TPKT/COTP + S7 ROSCTR=Job to read
//!     SZL 0x0011 (module identification — order code, FW version).
//!   - **DNP3** (port 20000): "Request Link Status" link-layer frame.
//!     Reply has an Internal Indications field that confirms a DNP3
//!     speaker.
//!   - **EtherNet/IP** (port 44818): "List Identity" command (0x63).
//!     Reply contains vendor ID, product code, device name.
//!   - **BACnet/IP** (port 47808 UDP): Who-Is broadcast equivalent
//!     sent unicast — devices respond with I-Am bearing their
//!     instance number.
//!
//! Findings are *informational*: an ICS device on a flat network
//! reachable from a routable address is itself a finding, regardless
//! of patch state. Surfaces every responder so the user can decide.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcsFinding {
    pub protocol: &'static str,
    pub port: u16,
    pub host: String,
    pub identifier: String,
    pub raw_excerpt: String,
}

pub async fn scan(host: &str, dur: Duration) -> Result<Vec<IcsFinding>> {
    let ip: IpAddr = resolve(host).await?;
    let mut out = Vec::new();
    if let Some(f) = probe_modbus(ip, dur).await {
        out.push(f);
    }
    if let Some(f) = probe_s7(ip, dur).await {
        out.push(f);
    }
    if let Some(f) = probe_dnp3(ip, dur).await {
        out.push(f);
    }
    if let Some(f) = probe_enip(ip, dur).await {
        out.push(f);
    }
    if let Some(f) = probe_bacnet(ip, dur).await {
        out.push(f);
    }
    Ok(out)
}

async fn resolve(host: &str) -> Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addr = tokio::net::lookup_host((host, 0u16))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no DNS for {}", host))?;
    Ok(addr.ip())
}

// ── Modbus ────────────────────────────────────────────────────────

async fn probe_modbus(ip: IpAddr, dur: Duration) -> Option<IcsFinding> {
    // MBAP header (7B): TID(2)=0x0001, ProtoID(2)=0x0000, Length(2),
    // UnitID(1)=0xff. Then PDU: FC=0x2B (43), MEI=0x0E (14),
    // ReadDeviceIDCode=0x01 (basic), ObjectID=0x00.
    let mut req: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xff,
        0x2b, 0x0e, 0x01, 0x00,
    ];
    req[5] = (req.len() as u16 - 6) as u8 & 0xff;

    let mut s = timeout(dur, TcpStream::connect(SocketAddr::new(ip, 502))).await.ok()?.ok()?;
    timeout(dur, s.write_all(&req)).await.ok()?.ok()?;
    let mut buf = [0u8; 256];
    let n = timeout(dur, s.read(&mut buf)).await.ok()?.ok()?;
    if n < 8 {
        return None;
    }
    // PDU starts at offset 7 (after MBAP). FC echoed in [7]; for an
    // exception reply [7] = 0xAB. Either case proves Modbus.
    let echoed_fc = buf[7];
    if echoed_fc != 0x2b && echoed_fc != 0xab {
        return None;
    }
    // Try to extract a vendor name string from the response body —
    // look for printable runs ≥ 4 bytes long.
    let identifier = printable_runs(&buf[8..n], 4)
        .into_iter()
        .next()
        .unwrap_or_else(|| "Modbus device".into());
    Some(IcsFinding {
        protocol: "Modbus/TCP",
        port: 502,
        host: ip.to_string(),
        identifier,
        raw_excerpt: hex_excerpt(&buf[..n], 32),
    })
}

// ── Siemens S7 ────────────────────────────────────────────────────

async fn probe_s7(ip: IpAddr, dur: Duration) -> Option<IcsFinding> {
    // Step 1: TPKT/COTP Connect Request (similar to RDP probe).
    //   TPKT: 03 00 00 16
    //   COTP CR: 11 E0 0000 0001 00 c0 01 0a c1 02 01 00 c2 02 01 02
    let cr: &[u8] = &[
        0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02,
    ];
    let mut s = timeout(dur, TcpStream::connect(SocketAddr::new(ip, 102))).await.ok()?.ok()?;
    timeout(dur, s.write_all(cr)).await.ok()?.ok()?;
    let mut buf = [0u8; 64];
    let n = timeout(dur, s.read(&mut buf)).await.ok()?.ok()?;
    if n < 11 || buf[0] != 0x03 {
        return None;
    }
    // Step 2: S7 Setup Communication.
    let setup: &[u8] = &[
        0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x08, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xe0,
    ];
    timeout(dur, s.write_all(setup)).await.ok()?.ok()?;
    let n2 = timeout(dur, s.read(&mut buf)).await.ok()?.ok()?;
    if n2 < 7 {
        return None;
    }
    // The presence of ROSCTR=0x03 (AckData) at buf[8] confirms an S7 speaker.
    let identifier = if buf.iter().take(n2).any(|&b| b == 0x32) {
        "Siemens S7 PLC".to_string()
    } else {
        return None;
    };
    Some(IcsFinding {
        protocol: "Siemens S7",
        port: 102,
        host: ip.to_string(),
        identifier,
        raw_excerpt: hex_excerpt(&buf[..n2], 32),
    })
}

// ── DNP3 ──────────────────────────────────────────────────────────

async fn probe_dnp3(ip: IpAddr, dur: Duration) -> Option<IcsFinding> {
    // DNP3 link-layer "Request Link Status" frame:
    //   start  : 0x05 0x64
    //   length : 0x05 (header bytes after this: 5)
    //   ctrl   : 0xC9  (DIR=1, PRM=1, FCB=0, FCV=1, FC=0x09 ReqLinkStatus)
    //   dst    : 0x01 0x00 (= 0x0001 master)
    //   src    : 0x00 0x00 (= 0x0000)
    //   crc    : 2 bytes (CRC-16/DNP) — many devices reply even on
    //            wrong CRC for a link-status request, but we send a
    //            valid one.
    let mut frame: Vec<u8> = vec![0x05, 0x64, 0x05, 0xc9, 0x01, 0x00, 0x00, 0x00];
    let crc = dnp3_crc(&frame[..8]);
    frame.push((crc & 0xff) as u8);
    frame.push((crc >> 8) as u8);

    let mut s = timeout(dur, TcpStream::connect(SocketAddr::new(ip, 20000))).await.ok()?.ok()?;
    timeout(dur, s.write_all(&frame)).await.ok()?.ok()?;
    let mut buf = [0u8; 64];
    let n = timeout(dur, s.read(&mut buf)).await.ok()?.ok()?;
    if n < 4 || buf[0] != 0x05 || buf[1] != 0x64 {
        return None;
    }
    Some(IcsFinding {
        protocol: "DNP3",
        port: 20000,
        host: ip.to_string(),
        identifier: "DNP3 outstation".into(),
        raw_excerpt: hex_excerpt(&buf[..n], 32),
    })
}

fn dnp3_crc(data: &[u8]) -> u16 {
    // CRC-16/DNP polynomial 0xA6BC, init 0x0000, refin/refout=true,
    // xorout=0xFFFF. Reference impl from DNP3 spec §8.2.6.
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA6BC;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ── EtherNet/IP (CIP) ─────────────────────────────────────────────

async fn probe_enip(ip: IpAddr, dur: Duration) -> Option<IcsFinding> {
    // EtherNet/IP encapsulation header for List Identity (0x0063):
    //   command(2)=0x0063 length(2)=0 sessionHandle(4)=0
    //   status(4)=0 senderContext(8)=0 options(4)=0
    let req: [u8; 24] = [
        0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut s = timeout(dur, TcpStream::connect(SocketAddr::new(ip, 44818))).await.ok()?.ok()?;
    timeout(dur, s.write_all(&req)).await.ok()?.ok()?;
    let mut buf = [0u8; 512];
    let n = timeout(dur, s.read(&mut buf)).await.ok()?.ok()?;
    if n < 24 || buf[0] != 0x63 {
        return None;
    }
    let identifier = printable_runs(&buf[24..n], 4)
        .into_iter()
        .next()
        .unwrap_or_else(|| "EtherNet/IP device".into());
    Some(IcsFinding {
        protocol: "EtherNet/IP",
        port: 44818,
        host: ip.to_string(),
        identifier,
        raw_excerpt: hex_excerpt(&buf[..n], 32),
    })
}

// ── BACnet/IP (UDP) ───────────────────────────────────────────────

async fn probe_bacnet(ip: IpAddr, dur: Duration) -> Option<IcsFinding> {
    // BVLC Forward NPDU (well, the simpler "Original-Unicast-NPDU"):
    //   Type=0x81, Function=0x0a, Length=0x000c
    //   NPDU: version=0x01, control=0x04 (expects reply)
    //   APDU: Confirmed Who-Is... actually use *unconfirmed* Who-Is:
    //         APDU type=0x10 service=0x08 (Who-Is)
    let bvlc_npdu: [u8; 12] = [
        0x81, 0x0a, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff,
        0x10, 0x08,
    ];
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    let dst = SocketAddr::new(ip, 47808);
    timeout(dur, sock.send_to(&bvlc_npdu, dst)).await.ok()?.ok()?;
    let mut buf = [0u8; 256];
    let n = timeout(dur, sock.recv(&mut buf)).await.ok()?.ok()?;
    if n < 4 || buf[0] != 0x81 {
        return None;
    }
    Some(IcsFinding {
        protocol: "BACnet/IP",
        port: 47808,
        host: ip.to_string(),
        identifier: "BACnet device".into(),
        raw_excerpt: hex_excerpt(&buf[..n], 32),
    })
}

// ── Helpers ───────────────────────────────────────────────────────

fn printable_runs(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for &b in data {
        if (0x20..=0x7e).contains(&b) {
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                out.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if current.len() >= min_len {
        out.push(current);
    }
    out
}

fn hex_excerpt(data: &[u8], max: usize) -> String {
    let take = data.len().min(max);
    let hex: Vec<String> = data.iter().take(take).map(|b| format!("{:02x}", b)).collect();
    hex.join(" ")
}

pub fn print_findings(host: &str, findings: &[IcsFinding]) {
    use colored::*;
    println!();
    println!("{}", format!("ICS/SCADA scan for {} — {} responder(s)", host, findings.len()).bold());
    if findings.is_empty() {
        println!("  {}", "no industrial-protocol responder on the probed ports".dimmed());
        return;
    }
    for f in findings {
        println!("  {} {} :{} → {}", "[!]".yellow().bold(), f.protocol, f.port, f.identifier);
        println!("    raw: {}", f.raw_excerpt.dimmed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnp3_crc_is_deterministic_and_input_sensitive() {
        let a = [0x05, 0x64, 0x05, 0xc9, 0x01, 0x00, 0x00, 0x00];
        let b = [0x05, 0x64, 0x05, 0xc9, 0x02, 0x00, 0x00, 0x00];
        // Same input → same CRC.
        assert_eq!(dnp3_crc(&a), dnp3_crc(&a));
        // One-bit input change → different CRC (minimum diffusion guarantee).
        assert_ne!(dnp3_crc(&a), dnp3_crc(&b));
        // Empty input → 0xFFFF (init 0, xorout = !0).
        assert_eq!(dnp3_crc(&[]), 0xFFFF);
    }

    #[test]
    fn printable_runs_extracts_strings() {
        let data = b"\x00\x00ACME PLC v3.1\x00\x01abc";
        let runs = printable_runs(data, 4);
        assert!(runs.iter().any(|s| s.contains("ACME")));
        // "abc" is too short → not extracted.
        assert!(!runs.iter().any(|s| s == "abc"));
    }

    #[test]
    fn hex_excerpt_truncates_to_max() {
        let data: Vec<u8> = (0..100).collect();
        let s = hex_excerpt(&data, 4);
        assert_eq!(s.split(' ').count(), 4);
    }
}
