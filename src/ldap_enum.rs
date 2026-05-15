//! LDAP anonymous bind + rootDSE enumeration.
//!
//! Connects to TCP/389 (LDAP) or TCP/636 (LDAPS), sends an anonymous
//! Bind request, then queries the rootDSE (empty base DN, scope=0,
//! filter=`(objectClass=*)`, attrs=*). The rootDSE exposes:
//!
//!   - `namingContexts`        — domain partitions (very useful for
//!                                Active Directory enumeration)
//!   - `supportedSASLMechanisms` — auth options
//!   - `supportedLDAPVersion`   — typically 3
//!   - `defaultNamingContext`   — AD primary DN
//!   - `dnsHostName`            — server's FQDN
//!   - `serverName`             — AD DSA DN
//!   - `domainFunctionality`    — AD forest/domain level
//!
//! Hand-rolled BER for the LDAP PDUs. No bind credentials needed,
//! all data is what AD/389ds exposes to unauthenticated callers.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ── BER tags ─────
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
#[allow(dead_code)]
const TAG_NULL: u8 = 0x05;
const TAG_ENUMERATED: u8 = 0x0a;
const TAG_SEQUENCE: u8 = 0x30;
#[allow(dead_code)]
const TAG_SET: u8 = 0x31;
// Application tags
const APP_BIND_REQUEST: u8 = 0x60;
const APP_BIND_RESPONSE: u8 = 0x61;
const APP_SEARCH_REQUEST: u8 = 0x63;
const APP_SEARCH_RESULT_ENTRY: u8 = 0x64;
const APP_SEARCH_RESULT_DONE: u8 = 0x65;
// Context-specific tags
const CTX_SIMPLE_AUTH: u8 = 0x80;
const CTX_FILTER_PRESENT: u8 = 0x87;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LdapFinding {
    pub host: String,
    pub port: u16,
    pub naming_contexts: Vec<String>,
    pub supported_sasl_mechanisms: Vec<String>,
    pub supported_ldap_versions: Vec<String>,
    pub default_naming_context: Option<String>,
    pub dns_host_name: Option<String>,
    pub server_name: Option<String>,
    pub domain_functionality: Option<String>,
    pub other_attrs: Vec<(String, Vec<String>)>,
}

pub async fn enumerate(host: IpAddr, port: u16, dur: Duration) -> Result<Option<LdapFinding>> {
    let addr = SocketAddr::new(host, port);
    let mut s = timeout(dur, TcpStream::connect(addr)).await??;

    // Step 1: anonymous bind (LDAPv3, empty DN, empty password).
    let bind = build_bind_anonymous(1);
    timeout(dur, s.write_all(&bind)).await??;

    let bind_resp = read_ldap_message(&mut s, dur).await?;
    if !is_bind_success(&bind_resp) {
        return Ok(None);
    }

    // Step 2: search rootDSE (empty base, scope=baseObject, filter=present(objectClass), attrs=*)
    let search = build_rootdse_search(2);
    timeout(dur, s.write_all(&search)).await??;

    let mut finding = LdapFinding {
        host: host.to_string(),
        port,
        ..Default::default()
    };
    loop {
        let resp = match read_ldap_message(&mut s, dur).await {
            Ok(b) => b,
            Err(_) => break,
        };
        if resp.is_empty() {
            break;
        }
        if let Some(entry) = parse_search_entry(&resp) {
            apply_entry(&mut finding, entry);
        }
        if resp.iter().any(|&b| b == APP_SEARCH_RESULT_DONE) {
            break;
        }
    }
    Ok(Some(finding))
}

// ── BER builder ─────

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

fn build_bind_anonymous(msg_id: i64) -> Vec<u8> {
    // BindRequest ::= [APPLICATION 0] SEQUENCE {
    //   version INTEGER (1..127),
    //   name LDAPDN (OCTET STRING),
    //   authentication CHOICE { simple [0] OCTET STRING, ... }
    // }
    let mut inner = encode_integer(3); // LDAPv3
    inner.extend_from_slice(&ber_tlv(TAG_OCTET_STRING, b"")); // empty DN
    inner.extend_from_slice(&ber_tlv(CTX_SIMPLE_AUTH, b"")); // empty password
    let req = ber_tlv(APP_BIND_REQUEST, &inner);

    // Wrap in LDAPMessage: SEQUENCE { messageID INTEGER, protocolOp }
    let mut msg = encode_integer(msg_id);
    msg.extend_from_slice(&req);
    ber_tlv(TAG_SEQUENCE, &msg)
}

fn build_rootdse_search(msg_id: i64) -> Vec<u8> {
    // SearchRequest ::= [APPLICATION 3] SEQUENCE {
    //   baseObject LDAPDN,
    //   scope ENUMERATED { baseObject(0), singleLevel(1), wholeSubtree(2) },
    //   derefAliases ENUMERATED,
    //   sizeLimit INTEGER,
    //   timeLimit INTEGER,
    //   typesOnly BOOLEAN,
    //   filter Filter,
    //   attributes AttributeSelection
    // }
    let mut body = ber_tlv(TAG_OCTET_STRING, b""); // empty base = rootDSE
    body.extend_from_slice(&ber_tlv(TAG_ENUMERATED, &[0u8])); // baseObject
    body.extend_from_slice(&ber_tlv(TAG_ENUMERATED, &[0u8])); // derefAliases = neverDerefAliases
    body.extend_from_slice(&encode_integer(0)); // sizeLimit
    body.extend_from_slice(&encode_integer(0)); // timeLimit
    body.extend_from_slice(&ber_tlv(0x01, &[0u8])); // typesOnly BOOLEAN = false (tag 1 universal primitive)
    // filter: present(objectClass) — tag [CONTEXT 7] primitive, value = attribute description
    body.extend_from_slice(&ber_tlv(CTX_FILTER_PRESENT, b"objectClass"));
    // attribute-selection: SEQUENCE of LDAPString — empty = no attributes,
    // but we want all operational attrs so add a single "+" entry plus "*"
    let mut attr_list = ber_tlv(TAG_OCTET_STRING, b"*");
    attr_list.extend_from_slice(&ber_tlv(TAG_OCTET_STRING, b"+"));
    body.extend_from_slice(&ber_tlv(TAG_SEQUENCE, &attr_list));

    let req = ber_tlv(APP_SEARCH_REQUEST, &body);
    let mut msg = encode_integer(msg_id);
    msg.extend_from_slice(&req);
    ber_tlv(TAG_SEQUENCE, &msg)
}

async fn read_ldap_message(s: &mut TcpStream, dur: Duration) -> Result<Vec<u8>> {
    // Read tag + length-encoding to know total size, then the rest.
    let mut hdr = [0u8; 2];
    timeout(dur, s.read_exact(&mut hdr)).await??;
    let mut total_len_bytes = vec![hdr[1]];
    let body_len = if hdr[1] & 0x80 == 0 {
        hdr[1] as usize
    } else {
        let n = (hdr[1] & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Ok(Vec::new());
        }
        let mut extra = vec![0u8; n];
        timeout(dur, s.read_exact(&mut extra)).await??;
        total_len_bytes.extend_from_slice(&extra);
        let mut len = 0usize;
        for &b in &extra {
            len = (len << 8) | b as usize;
        }
        len
    };
    let mut body = vec![0u8; body_len];
    timeout(dur, s.read_exact(&mut body)).await??;
    // Reconstruct the full TLV so downstream parsers see the whole packet.
    let mut full = vec![hdr[0]];
    full.extend_from_slice(&total_len_bytes);
    full.extend_from_slice(&body);
    Ok(full)
}

fn is_bind_success(packet: &[u8]) -> bool {
    let mut cur = BerCursor::new(packet);
    let (_, msg_body) = match cur.read_tlv() { Some(x) => x, None => return false };
    let mut inner = BerCursor::new(msg_body);
    let _ = inner.read_tlv(); // messageID
    let (resp_tag, resp_body) = match inner.read_tlv() { Some(x) => x, None => return false };
    if resp_tag != APP_BIND_RESPONSE {
        return false;
    }
    let mut r = BerCursor::new(resp_body);
    let (_, code_bytes) = match r.read_tlv() { Some(x) => x, None => return false };
    matches!(code_bytes, [0]) // resultCode = success(0)
}

// ── BER parser ─────

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
        let s = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Some((tag, s))
    }
    fn read_length(&mut self) -> Option<usize> {
        if self.pos >= self.buf.len() { return None; }
        let first = self.buf[self.pos];
        self.pos += 1;
        if first & 0x80 == 0 { return Some(first as usize); }
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

struct SearchEntry<'a> {
    #[allow(dead_code)]
    dn: &'a [u8],
    attrs: Vec<(&'a [u8], Vec<&'a [u8]>)>,
}

fn parse_search_entry<'a>(packet: &'a [u8]) -> Option<SearchEntry<'a>> {
    let mut cur = BerCursor::new(packet);
    let (_, msg_body) = cur.read_tlv()?;
    let mut inner = BerCursor::new(msg_body);
    let _ = inner.read_tlv()?; // messageID
    let (resp_tag, resp_body) = inner.read_tlv()?;
    if resp_tag != APP_SEARCH_RESULT_ENTRY {
        return None;
    }
    let mut r = BerCursor::new(resp_body);
    let (_, dn) = r.read_tlv()?;
    let (_, attr_list) = r.read_tlv()?;
    let mut attrs = Vec::new();
    let mut ac = BerCursor::new(attr_list);
    while let Some((_, attr)) = ac.read_tlv() {
        let mut a = BerCursor::new(attr);
        if let Some((_, name)) = a.read_tlv() {
            if let Some((_, values_set)) = a.read_tlv() {
                let mut vals = Vec::new();
                let mut vc = BerCursor::new(values_set);
                while let Some((_, v)) = vc.read_tlv() {
                    vals.push(v);
                }
                attrs.push((name, vals));
            }
        }
    }
    Some(SearchEntry { dn, attrs })
}

fn apply_entry(finding: &mut LdapFinding, entry: SearchEntry<'_>) {
    for (name, values) in entry.attrs {
        let key = std::str::from_utf8(name).unwrap_or("").to_string();
        let vals: Vec<String> = values
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect();
        match key.as_str() {
            "namingContexts" => finding.naming_contexts = vals,
            "supportedSASLMechanisms" => finding.supported_sasl_mechanisms = vals,
            "supportedLDAPVersion" => finding.supported_ldap_versions = vals,
            "defaultNamingContext" => finding.default_naming_context = vals.first().cloned(),
            "dnsHostName" => finding.dns_host_name = vals.first().cloned(),
            "serverName" => finding.server_name = vals.first().cloned(),
            "domainFunctionality" => finding.domain_functionality = vals.first().cloned(),
            _ => finding.other_attrs.push((key, vals)),
        }
    }
}

pub fn print_finding(f: &LdapFinding) {
    use colored::*;
    println!();
    println!("{}", format!("LDAP rootDSE on {}:{}", f.host, f.port).bold());
    if !f.supported_ldap_versions.is_empty() {
        println!("  LDAP version : {}", f.supported_ldap_versions.join(", "));
    }
    if let Some(d) = &f.dns_host_name {
        println!("  dnsHostName  : {}", d);
    }
    if let Some(s) = &f.server_name {
        println!("  serverName   : {}", s);
    }
    if let Some(c) = &f.default_naming_context {
        println!("  defaultNC    : {}", c);
    }
    if !f.naming_contexts.is_empty() {
        println!("  namingContexts ({}):", f.naming_contexts.len());
        for c in &f.naming_contexts {
            println!("    · {}", c);
        }
    }
    if !f.supported_sasl_mechanisms.is_empty() {
        println!("  SASL mechs   : {}", f.supported_sasl_mechanisms.join(", "));
    }
    if let Some(d) = &f.domain_functionality {
        println!("  AD forest fl : {}", d);
    }
    if f.naming_contexts.iter().any(|c| c.to_lowercase().contains("dc=")) {
        println!("  {}", "Active Directory detected (DN with dc= component)".yellow());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_bind_anonymous_starts_with_sequence() {
        let pkt = build_bind_anonymous(1);
        assert_eq!(pkt[0], TAG_SEQUENCE);
    }

    #[test]
    fn build_bind_anonymous_contains_app_bind_tag() {
        let pkt = build_bind_anonymous(1);
        assert!(pkt.contains(&APP_BIND_REQUEST));
    }

    #[test]
    fn build_bind_anonymous_uses_ldap_v3() {
        let pkt = build_bind_anonymous(7);
        // version INTEGER = 3 → 02 01 03 should appear in the encoding
        let needle = [TAG_INTEGER, 0x01, 0x03];
        assert!(pkt.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn build_rootdse_search_contains_filter_present_tag() {
        let pkt = build_rootdse_search(2);
        assert!(pkt.contains(&CTX_FILTER_PRESENT));
    }

    #[test]
    fn integer_encoding_minimal_form() {
        let v = encode_integer(3);
        assert_eq!(v, vec![TAG_INTEGER, 0x01, 0x03]);
    }
}
