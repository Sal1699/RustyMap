//! SNMP v1 read-only enumeration.
//!
//! Tries a curated list of common community strings (`public`,
//! `private`, `community`, `cisco`, `manager`, plus any supplied
//! via `--snmp-community`) against UDP/161 and, on success, fetches
//! MIB-2 system OIDs:
//!
//!   - **sysDescr**   `1.3.6.1.2.1.1.1.0`
//!   - **sysName**    `1.3.6.1.2.1.1.5.0`
//!   - **sysLocation** `1.3.6.1.2.1.1.6.0`
//!   - **sysUpTime**  `1.3.6.1.2.1.1.3.0`
//!   - **sysContact** `1.3.6.1.2.1.1.4.0`
//!
//! Hand-rolled ASN.1 BER encode/decode for the SNMP PDU — light
//! enough to keep zero new deps. Read-only: no SET requests, no
//! GETBULK enumeration of arbitrary OID trees beyond the system MIB.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

// ── BER tags ─────────────────────────────────────────────────────
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
// SNMP context-specific tags
const TAG_GET_REQUEST: u8 = 0xA0;
const TAG_GET_RESPONSE: u8 = 0xA2;

// SNMP version
const VERSION_V1: i32 = 0;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SnmpFinding {
    pub host: String,
    pub community: String,
    pub sys_descr: Option<String>,
    pub sys_name: Option<String>,
    pub sys_location: Option<String>,
    pub sys_contact: Option<String>,
    pub sys_uptime_ticks: Option<u32>,
}

const COMMON_COMMUNITIES: &[&str] = &[
    "public", "private", "community", "cisco", "manager",
    "default", "router", "admin", "switch",
];

const OID_SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const OID_SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
const OID_SYS_LOCATION: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 6, 0];
const OID_SYS_CONTACT: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 4, 0];
const OID_SYS_UPTIME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];

pub async fn enumerate(
    host: IpAddr,
    extra_communities: &[String],
    dur: Duration,
) -> Result<Option<SnmpFinding>> {
    let mut tried: Vec<String> = COMMON_COMMUNITIES.iter().map(|s| s.to_string()).collect();
    for c in extra_communities {
        if !tried.contains(c) {
            tried.push(c.clone());
        }
    }

    for community in &tried {
        if let Some(found) = try_community(host, community, dur).await {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

async fn try_community(host: IpAddr, community: &str, dur: Duration) -> Option<SnmpFinding> {
    let sock = bind_for(host).await?;
    let dst = SocketAddr::new(host, 161);

    let mut f = SnmpFinding {
        host: host.to_string(),
        community: community.to_string(),
        ..Default::default()
    };

    // We make 5 GET requests; on the first failure we conclude the
    // community is wrong and bail out so callers can try the next.
    let request_id = (std::process::id() & 0x7fffffff) as i32;

    f.sys_descr = snmp_get(&sock, &dst, community, request_id, OID_SYS_DESCR, dur).await
        .and_then(|v| v.as_string());
    if f.sys_descr.is_none() {
        return None; // wrong community / not SNMPv1
    }
    f.sys_name = snmp_get(&sock, &dst, community, request_id + 1, OID_SYS_NAME, dur).await
        .and_then(|v| v.as_string());
    f.sys_location = snmp_get(&sock, &dst, community, request_id + 2, OID_SYS_LOCATION, dur).await
        .and_then(|v| v.as_string());
    f.sys_contact = snmp_get(&sock, &dst, community, request_id + 3, OID_SYS_CONTACT, dur).await
        .and_then(|v| v.as_string());
    f.sys_uptime_ticks = snmp_get(&sock, &dst, community, request_id + 4, OID_SYS_UPTIME, dur).await
        .and_then(|v| v.as_u32());
    Some(f)
}

async fn bind_for(host: IpAddr) -> Option<UdpSocket> {
    let bind = if host.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    UdpSocket::bind(bind).await.ok()
}

#[derive(Debug, Clone)]
enum SnmpValue {
    Integer(i64),
    OctetString(Vec<u8>),
    TimeTicks(u32),
    Other,
}

impl SnmpValue {
    fn as_string(&self) -> Option<String> {
        if let SnmpValue::OctetString(b) = self {
            Some(String::from_utf8_lossy(b).into_owned())
        } else {
            None
        }
    }
    fn as_u32(&self) -> Option<u32> {
        match self {
            SnmpValue::TimeTicks(t) => Some(*t),
            SnmpValue::Integer(i) => Some(*i as u32),
            _ => None,
        }
    }
}

async fn snmp_get(
    sock: &UdpSocket,
    dst: &SocketAddr,
    community: &str,
    request_id: i32,
    oid: &[u32],
    dur: Duration,
) -> Option<SnmpValue> {
    let pkt = build_get_request(community, request_id, oid);
    timeout(dur, sock.send_to(&pkt, dst)).await.ok()?.ok()?;
    let mut buf = vec![0u8; 4096];
    let (n, _src) = timeout(dur, sock.recv_from(&mut buf)).await.ok()?.ok()?;
    parse_get_response(&buf[..n], request_id)
}

// ── BER builder ───────────────────────────────────────────────────

fn ber_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

fn ber_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    ber_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn encode_integer(v: i64) -> Vec<u8> {
    // Two's-complement minimal encoding.
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 {
        let lead = bytes[0];
        let next_msb = bytes[1] & 0x80 != 0;
        if (lead == 0 && !next_msb) || (lead == 0xff && next_msb) {
            bytes.remove(0);
        } else {
            break;
        }
    }
    ber_tlv(TAG_INTEGER, &bytes)
}

fn encode_oid(arcs: &[u32]) -> Vec<u8> {
    let mut content = Vec::new();
    if arcs.len() >= 2 {
        content.push((arcs[0] * 40 + arcs[1]) as u8);
        for &a in &arcs[2..] {
            encode_subidentifier(&mut content, a);
        }
    }
    ber_tlv(TAG_OID, &content)
}

fn encode_subidentifier(out: &mut Vec<u8>, mut v: u32) {
    let mut stack: Vec<u8> = Vec::new();
    stack.push((v & 0x7f) as u8);
    v >>= 7;
    while v > 0 {
        stack.push(((v & 0x7f) as u8) | 0x80);
        v >>= 7;
    }
    stack.reverse();
    out.extend_from_slice(&stack);
}

fn build_get_request(community: &str, request_id: i32, oid: &[u32]) -> Vec<u8> {
    // VarBind: SEQUENCE { OID, NULL }
    let varbind = ber_tlv(
        TAG_SEQUENCE,
        &{
            let mut v = encode_oid(oid);
            v.extend_from_slice(&ber_tlv(TAG_NULL, &[]));
            v
        },
    );
    let varbind_list = ber_tlv(TAG_SEQUENCE, &varbind);

    // PDU: GET_REQUEST { request-id, error-status, error-index, varbind-list }
    let mut pdu_body = encode_integer(request_id as i64);
    pdu_body.extend_from_slice(&encode_integer(0)); // error-status = noError
    pdu_body.extend_from_slice(&encode_integer(0)); // error-index = 0
    pdu_body.extend_from_slice(&varbind_list);
    let pdu = ber_tlv(TAG_GET_REQUEST, &pdu_body);

    // Message: SEQUENCE { version, community, PDU }
    let mut msg_body = encode_integer(VERSION_V1 as i64);
    msg_body.extend_from_slice(&ber_tlv(TAG_OCTET_STRING, community.as_bytes()));
    msg_body.extend_from_slice(&pdu);
    ber_tlv(TAG_SEQUENCE, &msg_body)
}

// ── BER parser ────────────────────────────────────────────────────

struct BerCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BerCursor<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }

    fn read_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        if self.pos >= self.buf.len() { return None; }
        let tag = self.buf[self.pos];
        self.pos += 1;
        let len = self.read_length()?;
        if self.pos + len > self.buf.len() { return None; }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Some((tag, slice))
    }

    fn read_length(&mut self) -> Option<usize> {
        if self.pos >= self.buf.len() { return None; }
        let first = self.buf[self.pos];
        self.pos += 1;
        if first & 0x80 == 0 {
            return Some(first as usize);
        }
        let n = (first & 0x7f) as usize;
        if self.pos + n > self.buf.len() || n > 4 { return None; }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | self.buf[self.pos] as usize;
            self.pos += 1;
        }
        Some(len)
    }
}

fn parse_integer(buf: &[u8]) -> Option<i64> {
    if buf.is_empty() { return None; }
    let mut v: i64 = (buf[0] as i8) as i64;
    for &b in &buf[1..] {
        v = (v << 8) | b as i64;
    }
    Some(v)
}

fn parse_get_response(body: &[u8], expected_id: i32) -> Option<SnmpValue> {
    // Message envelope: SEQUENCE { version, community, PDU }
    let mut cur = BerCursor::new(body);
    let (msg_tag, msg_body) = cur.read_tlv()?;
    if msg_tag != TAG_SEQUENCE { return None; }
    let mut msg = BerCursor::new(msg_body);
    let (_, _ver) = msg.read_tlv()?;
    let (_, _community) = msg.read_tlv()?;
    let (pdu_tag, pdu_body) = msg.read_tlv()?;
    if pdu_tag != TAG_GET_RESPONSE { return None; }

    // PDU: request-id, error-status, error-index, varbind-list
    let mut pdu = BerCursor::new(pdu_body);
    let (_, rid_bytes) = pdu.read_tlv()?;
    let rid = parse_integer(rid_bytes)? as i32;
    if rid != expected_id { return None; }
    let (_, err_bytes) = pdu.read_tlv()?;
    let err = parse_integer(err_bytes)?;
    if err != 0 { return None; }
    let (_, _idx) = pdu.read_tlv()?;
    let (_, vb_list) = pdu.read_tlv()?;

    // VarBind list → first VarBind → OID, value
    let mut vb_cur = BerCursor::new(vb_list);
    let (_, vb) = vb_cur.read_tlv()?;
    let mut vb_inner = BerCursor::new(vb);
    let (_, _oid) = vb_inner.read_tlv()?;
    let (val_tag, val_bytes) = vb_inner.read_tlv()?;
    match val_tag {
        TAG_OCTET_STRING => Some(SnmpValue::OctetString(val_bytes.to_vec())),
        TAG_INTEGER => Some(SnmpValue::Integer(parse_integer(val_bytes)?)),
        0x43 => {
            // TimeTicks application tag
            let mut v: u32 = 0;
            for &b in val_bytes {
                v = (v << 8) | b as u32;
            }
            Some(SnmpValue::TimeTicks(v))
        }
        _ => Some(SnmpValue::Other),
    }
}

pub fn print_finding(host: &str, f: &SnmpFinding) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!("SNMP enum on {} (community: {})", host, f.community).bold()
    );
    if let Some(s) = &f.sys_descr {
        println!("  sysDescr   : {}", s);
    }
    if let Some(s) = &f.sys_name {
        println!("  sysName    : {}", s);
    }
    if let Some(s) = &f.sys_location {
        println!("  sysLocation: {}", s);
    }
    if let Some(s) = &f.sys_contact {
        println!("  sysContact : {}", s);
    }
    if let Some(t) = f.sys_uptime_ticks {
        let secs = t / 100;
        let days = secs / 86400;
        let h = (secs / 3600) % 24;
        let m = (secs / 60) % 60;
        let s = secs % 60;
        println!("  sysUpTime  : {}d {:02}:{:02}:{:02} ({} ticks)", days, h, m, s, t);
    }
    if f.community == "public" || f.community == "private" {
        println!("  {}", "default community in use — replace immediately".red());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_integer_zero_minimal() {
        // 0 → 02 01 00
        let v = encode_integer(0);
        assert_eq!(v, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn encode_integer_128_keeps_leading_zero() {
        // 128 → 02 02 00 80 (high bit set, need leading 0)
        let v = encode_integer(128);
        assert_eq!(v, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn encode_integer_negative_minimal() {
        // -1 → 02 01 FF
        let v = encode_integer(-1);
        assert_eq!(v, vec![0x02, 0x01, 0xff]);
    }

    #[test]
    fn encode_oid_1_3_6_1_matches_reference() {
        // 1.3.6.1 → 06 03 2B 06 01
        let v = encode_oid(&[1, 3, 6, 1]);
        assert_eq!(v, vec![0x06, 0x03, 0x2b, 0x06, 0x01]);
    }

    #[test]
    fn encode_oid_sysdescr_zero() {
        // 1.3.6.1.2.1.1.1.0 → 06 08 2B 06 01 02 01 01 01 00
        let v = encode_oid(OID_SYS_DESCR);
        assert_eq!(v, vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    }

    #[test]
    fn encode_oid_with_multibyte_subidentifier() {
        // 1.3.6.1.4.1.9 (Cisco enterprise) → 06 05 2B 06 01 04 01 09 actually
        // Test a value > 127 to exercise the multi-byte path: 1.2.840 (840 = 0x06 0x48)
        let v = encode_oid(&[1, 2, 840]);
        // 1*40+2 = 0x2A; 840 = 0x86 0x48 (multi-byte: bit 7 set on first)
        assert_eq!(v, vec![0x06, 0x03, 0x2a, 0x86, 0x48]);
    }

    #[test]
    fn ber_length_short_form() {
        let mut v = vec![];
        ber_length(&mut v, 5);
        assert_eq!(v, vec![5]);
    }

    #[test]
    fn ber_length_one_byte_long_form() {
        let mut v = vec![];
        ber_length(&mut v, 200);
        assert_eq!(v, vec![0x81, 200]);
    }

    #[test]
    fn ber_length_two_byte_long_form() {
        let mut v = vec![];
        ber_length(&mut v, 1000);
        assert_eq!(v, vec![0x82, 0x03, 0xe8]);
    }

    #[test]
    fn build_get_request_starts_with_sequence_and_version() {
        let pkt = build_get_request("public", 1, OID_SYS_DESCR);
        // First byte is SEQUENCE
        assert_eq!(pkt[0], TAG_SEQUENCE);
        // Inside the sequence, the first TLV should be the version integer (= 0)
        // After SEQUENCE tag + length-byte we hit the inner: 02 01 00
        let body_start = if pkt[1] < 0x80 { 2 } else { 2 + (pkt[1] & 0x7f) as usize };
        assert_eq!(pkt[body_start], TAG_INTEGER);
    }

    #[test]
    fn parse_integer_round_trips_small_values() {
        for v in [0i64, 1, 127, 128, 256, -1, -128, 1234567] {
            let encoded = encode_integer(v);
            // skip tag + length
            let body = &encoded[2..];
            assert_eq!(parse_integer(body), Some(v), "round-trip {} failed", v);
        }
    }
}
