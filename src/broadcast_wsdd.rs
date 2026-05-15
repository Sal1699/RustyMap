//! WS-Discovery (WSDD / WS-Discovery) multicast probe on
//! 239.255.255.250:3702.
//!
//! WSDD is Microsoft's modern replacement for NetBIOS-based browsing.
//! Every Windows host since Vista, plus most network-connected
//! printers, MFP devices, and IP cameras, answer a multicast
//! `Probe` request with their endpoint reference and the list of
//! services they expose (`wsdp:Device`, `pub:Computer`, `wprt:PrintDevice`,
//! `wscn:ScanDeviceType`, …).
//!
//! Single SOAP-over-UDP probe; replies are decoded by extracting
//! the printable strings inside `<wsa:Address>` and `<wsd:Types>`.
//! No XML parser dep — we use byte-substring search, which is
//! sufficient for the discovery use-case.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const WSDD_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const WSDD_PORT: u16 = 3702;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsddResponder {
    pub source: String,
    pub address: Option<String>,
    pub types: Vec<String>,
    pub raw_excerpt: String,
}

pub async fn discover(dur: Duration) -> Result<Vec<WsddResponder>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.set_multicast_loop_v4(false)?;
    sock.set_broadcast(true)?;

    let message_id = format!("urn:uuid:{:08x}-0000-0000-0000-rmprbeprobe", rand::random::<u32>());
    let probe = build_probe(&message_id);
    let dst = SocketAddr::V4(SocketAddrV4::new(WSDD_GROUP, WSDD_PORT));
    sock.send_to(probe.as_bytes(), dst).await?;

    let deadline = Instant::now() + dur;
    let mut by_src: HashMap<IpAddr, WsddResponder> = HashMap::new();
    let mut buf = vec![0u8; 8192];
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let r = timeout(remaining, sock.recv_from(&mut buf)).await;
        let Ok(Ok((n, src))) = r else { break };
        let body = String::from_utf8_lossy(&buf[..n]).into_owned();
        // ProbeMatches contains <wsa:Address> + <wsd:Types>
        if !body.contains("ProbeMatches") && !body.contains("Hello") {
            continue;
        }
        let entry = by_src.entry(src.ip()).or_insert(WsddResponder {
            source: src.ip().to_string(),
            address: None,
            types: Vec::new(),
            raw_excerpt: body.chars().take(160).collect(),
        });
        if entry.address.is_none() {
            entry.address = extract_tag(&body, "Address");
        }
        if let Some(types) = extract_tag(&body, "Types") {
            for t in types.split_whitespace() {
                let t = t.to_string();
                if !entry.types.contains(&t) {
                    entry.types.push(t);
                }
            }
        }
    }
    let mut out: Vec<WsddResponder> = by_src.into_values().collect();
    out.sort_by(|a, b| a.source.cmp(&b.source));
    Ok(out)
}

pub fn build_probe(message_id: &str) -> String {
    // Canonical WSDD Probe SOAP envelope. The structure is fixed —
    // only message-id rotates per call.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
 <soap:Header>
  <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
  <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
  <wsa:MessageID>{}</wsa:MessageID>
 </soap:Header>
 <soap:Body>
  <wsd:Probe/>
 </soap:Body>
</soap:Envelope>"#,
        message_id
    )
}

/// Pull the text between an opening `<…TAG>` and closing `</…TAG>`
/// pair. Tolerant to arbitrary-length namespace prefixes — both
/// `<wsa:Address>` and `<Address>` (plus `</wsa:Address>` /
/// `</Address>`) match. Returns inner text trimmed.
pub fn extract_tag(body: &str, tag: &str) -> Option<String> {
    // ── Find the opening tag ──
    let bare_open = format!("<{}>", tag);
    let ns_marker = format!(":{}>", tag); // e.g. ":Address>" — matches inside both open & close

    let mut content_start: Option<usize> = None;
    if let Some(p) = body.find(&bare_open) {
        content_start = Some(p + bare_open.len());
    }
    // Scan for ":TAG>" preceded by "<PREFIX" (with no '<' and no '/' in between)
    let mut pos = 0;
    while let Some(rel) = body[pos..].find(&ns_marker) {
        let idx = pos + rel;
        if let Some(lt) = body[..idx].rfind('<') {
            // Open tag iff the bytes between '<' and ':' are letters/digits only
            let prefix = &body[lt + 1..idx];
            if !prefix.is_empty()
                && !prefix.contains('/')
                && prefix.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                let candidate_end = idx + ns_marker.len();
                content_start = match content_start {
                    Some(prev) => Some(prev.min(candidate_end)),
                    None => Some(candidate_end),
                };
            }
        }
        pos = idx + ns_marker.len();
    }
    let content_start = content_start?;

    // ── Find the closing tag at or after content_start ──
    let close_bare = format!("</{}>", tag);
    let mut content_end: Option<usize> = None;
    if let Some(p) = body[content_start..].find(&close_bare) {
        content_end = Some(content_start + p);
    }
    let mut pos = content_start;
    while let Some(rel) = body[pos..].find(&ns_marker) {
        let idx = pos + rel;
        if let Some(lt) = body[..idx].rfind('<') {
            let prefix = &body[lt + 1..idx];
            // Close tag iff prefix begins with '/' and the rest is a valid
            // namespace prefix.
            if let Some(stripped) = prefix.strip_prefix('/') {
                if !stripped.is_empty()
                    && stripped.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    content_end = match content_end {
                        Some(prev) => Some(prev.min(lt)),
                        None => Some(lt),
                    };
                    break;
                }
            }
        }
        pos = idx + ns_marker.len();
    }
    let content_end = content_end?;
    if content_end < content_start {
        return None;
    }
    let inner = body[content_start..content_end].trim();
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

pub fn print_finding(responders: &[WsddResponder]) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!("WS-Discovery probe — {} responder(s)", responders.len()).bold()
    );
    if responders.is_empty() {
        println!("  {}", "no WSDD responders (no Windows hosts or multicast blocked)".dimmed());
        return;
    }
    for r in responders {
        println!("  {}", r.source.bold());
        if let Some(a) = &r.address {
            println!("    address : {}", a);
        }
        for t in &r.types {
            println!("    type    : {}", t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_probe_contains_canonical_tags() {
        let p = build_probe("urn:uuid:12345");
        assert!(p.contains("<wsa:To>"));
        assert!(p.contains("ws/2005/04/discovery/Probe"));
        assert!(p.contains("<wsd:Probe/>"));
        assert!(p.contains("12345"));
    }

    #[test]
    fn extract_tag_pulls_inner_text() {
        let body = r#"<soap:Envelope><wsa:Address>urn:uuid:host-1</wsa:Address></soap:Envelope>"#;
        let v = extract_tag(body, "Address");
        assert_eq!(v.as_deref(), Some("urn:uuid:host-1"));
    }

    #[test]
    fn extract_tag_handles_namespaceless_xml() {
        let body = r#"<Envelope><Types>pub:Computer wsdp:Device</Types></Envelope>"#;
        let v = extract_tag(body, "Types").unwrap();
        assert!(v.contains("Computer"));
        assert!(v.contains("Device"));
    }

    #[test]
    fn extract_tag_returns_none_when_absent() {
        let body = "<x/>";
        assert!(extract_tag(body, "Address").is_none());
    }

    #[test]
    fn extract_tag_trims_whitespace() {
        let body = "<wsa:Address>   value-x   </wsa:Address>";
        assert_eq!(extract_tag(body, "Address").as_deref(), Some("value-x"));
    }
}
