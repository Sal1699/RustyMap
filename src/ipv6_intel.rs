//! IPv6 address-structure intelligence — a RustyMap strength nmap lacks.
//!
//! An IPv6 address is not opaque like a v4 one: its 64-bit Interface
//! Identifier encodes *how the host got its address*, and often the
//! hardware itself. We decode:
//!
//!   - **EUI-64** IIDs → the embedded 48-bit MAC → NIC/vendor via the
//!     OUI table (`device_fp::vendor_from_mac`). This leaks the real
//!     hardware even through a firewall.
//!   - **Privacy / temporary** addresses (RFC 4941/8981) — random IID,
//!     universal/local bit clear → the host is deliberately hiding its MAC.
//!   - **Low-byte / manually configured** (`::1`, `::80`, `::443`) →
//!     hand-assigned server, not SLAAC.
//!   - Transition tech: **Teredo** (2001:0000::/32, embeds server+client
//!     IPv4), **6to4** (2002::/16, embeds the site's IPv4).
//!   - Scope/class: loopback, link-local, ULA, multicast, documentation.
//!
//! All pure logic — unit-tested, no sockets.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V6Kind {
    Unspecified,
    Loopback,
    LinkLocal,
    UniqueLocal,
    Multicast,
    Documentation,
    Teredo,
    SixToFour,
    /// Global unicast with an EUI-64 IID (embedded MAC).
    Eui64,
    /// Global/ULA unicast with a random IID (RFC 4941/8981 privacy).
    Privacy,
    /// Small, hand-picked IID (`::1`, `::dead:beef`, `::443`).
    LowByte,
    /// Global unicast, IID doesn't match a known pattern.
    GlobalManual,
}

impl V6Kind {
    pub fn label(&self) -> &'static str {
        match self {
            V6Kind::Unspecified => "unspecified (::)",
            V6Kind::Loopback => "loopback",
            V6Kind::LinkLocal => "link-local (fe80::/10)",
            V6Kind::UniqueLocal => "unique-local (fc00::/7)",
            V6Kind::Multicast => "multicast (ff00::/8)",
            V6Kind::Documentation => "documentation (2001:db8::/32)",
            V6Kind::Teredo => "Teredo tunnel (2001:0::/32)",
            V6Kind::SixToFour => "6to4 (2002::/16)",
            V6Kind::Eui64 => "SLAAC EUI-64 (embeds MAC)",
            V6Kind::Privacy => "privacy/temporary (RFC 4941 — MAC hidden)",
            V6Kind::LowByte => "low-byte / manually assigned",
            V6Kind::GlobalManual => "global unicast (manual/DHCPv6)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct V6Intel {
    pub kind: V6Kind,
    pub scope: &'static str,
    /// MAC recovered from an EUI-64 IID, if any.
    pub embedded_mac: Option<[u8; 6]>,
    /// Vendor for the embedded MAC (OUI lookup).
    pub vendor: Option<&'static str>,
    /// Embedded IPv4 for transition addresses (6to4 site / Teredo client).
    pub embedded_v4: Option<Ipv4Addr>,
    pub notes: Vec<String>,
}

/// Recover the 48-bit MAC from a EUI-64 interface identifier (the low 64
/// bits of the address). Returns `None` unless the `FF:FE` marker is
/// present in the middle of the IID.
pub fn eui64_to_mac(addr: Ipv6Addr) -> Option<[u8; 6]> {
    let o = addr.octets();
    let iid = &o[8..16];
    if iid[3] != 0xFF || iid[4] != 0xFE {
        return None;
    }
    Some([
        iid[0] ^ 0x02, // flip the universal/local bit back
        iid[1],
        iid[2],
        iid[5],
        iid[6],
        iid[7],
    ])
}

/// Analyse an IPv6 address into its structural intelligence.
pub fn analyze(addr: Ipv6Addr) -> V6Intel {
    let seg = addr.segments();
    let o = addr.octets();
    let mut notes = Vec::new();

    // Scope / special ranges first.
    if addr.is_unspecified() {
        return simple(V6Kind::Unspecified, "none");
    }
    if addr.is_loopback() {
        return simple(V6Kind::Loopback, "host");
    }
    if (seg[0] & 0xffc0) == 0xfe80 {
        let mut i = analyze_iid(addr, "link-local", Some(V6Kind::LinkLocal));
        i.notes.insert(0, "link-local — only reachable on the same L2 segment".into());
        return i;
    }
    if (seg[0] & 0xff00) == 0xff00 {
        notes.push(multicast_scope_note(seg[0]));
        return V6Intel { kind: V6Kind::Multicast, scope: "multicast", embedded_mac: None, vendor: None, embedded_v4: None, notes };
    }
    if (seg[0] & 0xfe00) == 0xfc00 {
        return analyze_iid(addr, "ULA", Some(V6Kind::UniqueLocal));
    }
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return simple(V6Kind::Documentation, "global");
    }
    if seg[0] == 0x2001 && seg[1] == 0x0000 {
        // Teredo: server IPv4 in bytes 4..8, client IPv4 (obfuscated) in 12..16.
        let server = Ipv4Addr::new(o[4], o[5], o[6], o[7]);
        let client = Ipv4Addr::new(o[12] ^ 0xff, o[13] ^ 0xff, o[14] ^ 0xff, o[15] ^ 0xff);
        notes.push(format!("Teredo server {} — client (behind NAT) {}", server, client));
        return V6Intel { kind: V6Kind::Teredo, scope: "global", embedded_mac: None, vendor: None, embedded_v4: Some(client), notes };
    }
    if seg[0] == 0x2002 {
        let v4 = Ipv4Addr::new(o[2], o[3], o[4], o[5]);
        notes.push(format!("6to4 — site IPv4 gateway {}", v4));
        return V6Intel { kind: V6Kind::SixToFour, scope: "global", embedded_mac: None, vendor: None, embedded_v4: Some(v4), notes };
    }

    // Global unicast → dissect the IID.
    analyze_iid(addr, "global", None)
}

/// Classify the interface identifier (low 64 bits) of a unicast address.
/// When `force_kind` is set (link-local / ULA — where the scope, not the
/// IID, defines the kind) the returned `kind` is preserved but the
/// embedded MAC / notes are still extracted from the IID. For global
/// unicast (`force_kind == None`) the IID pattern *is* the kind.
fn analyze_iid(addr: Ipv6Addr, scope: &'static str, force_kind: Option<V6Kind>) -> V6Intel {
    let o = addr.octets();
    let iid = &o[8..16];
    let mut notes = Vec::new();

    // EUI-64 (embedded MAC).
    if let Some(mac) = eui64_to_mac(addr) {
        let vendor = crate::device_fp::vendor_from_mac(&mac);
        notes.push(format!(
            "EUI-64 → MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}{}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            vendor.map(|v| format!(" ({})", v)).unwrap_or_default()
        ));
        notes.push("stable SLAAC address — trackable across networks".into());
        return V6Intel { kind: force_kind.unwrap_or(V6Kind::Eui64), scope, embedded_mac: Some(mac), vendor, embedded_v4: None, notes };
    }

    // Low-byte / manual: the top 6 bytes of the IID are zero.
    if iid[0] == 0 && iid[1] == 0 && iid[2] == 0 && iid[3] == 0 && iid[4] == 0 && iid[5] == 0 {
        let low = u16::from_be_bytes([iid[6], iid[7]]);
        let hint = match low {
            1 => " (gateway/first-host convention)",
            53 => " (looks like the DNS port)",
            80 | 443 | 8080 => " (port-numbered — hand-assigned server)",
            _ => "",
        };
        notes.push(format!("low-byte IID ::{:x}{} — manually configured, not SLAAC", low, hint));
        return V6Intel { kind: force_kind.unwrap_or(V6Kind::LowByte), scope, embedded_mac: None, vendor: None, embedded_v4: None, notes };
    }

    // Privacy/temporary: universal/local bit is CLEAR (locally administered)
    // and the IID isn't EUI-64 → random per RFC 4941/8981.
    let ul_local = (iid[0] & 0x02) == 0;
    if ul_local {
        notes.push("random IID, U/L bit local → RFC 4941 privacy address (MAC deliberately hidden)".into());
        return V6Intel { kind: force_kind.unwrap_or(V6Kind::Privacy), scope, embedded_mac: None, vendor: None, embedded_v4: None, notes };
    }

    notes.push("global unicast — no EUI-64/privacy/low-byte pattern (DHCPv6 or opaque SLAAC RFC 7217)".into());
    V6Intel { kind: force_kind.unwrap_or(V6Kind::GlobalManual), scope, embedded_mac: None, vendor: None, embedded_v4: None, notes }
}

fn simple(kind: V6Kind, scope: &'static str) -> V6Intel {
    V6Intel { kind, scope, embedded_mac: None, vendor: None, embedded_v4: None, notes: Vec::new() }
}

fn multicast_scope_note(first: u16) -> String {
    let scope = (first & 0x000f) as u8;
    let s = match scope {
        1 => "interface-local",
        2 => "link-local",
        5 => "site-local",
        8 => "organization-local",
        0xe => "global",
        _ => "other",
    };
    format!("multicast, {} scope", s)
}

/// One-line human summary for scan output.
pub fn summary(addr: Ipv6Addr) -> String {
    let i = analyze(addr);
    let mut s = i.kind.label().to_string();
    if let Some(v) = i.vendor {
        s = format!("{} — {}", s, v);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn eui64_recovers_mac_and_flips_ul_bit() {
        // MAC 00:0c:29:ab:cd:ef → EUI-64 IID 020c:29ff:feab:cdef.
        let addr = a("2001:db8:0:0:020c:29ff:feab:cdef");
        // (2001:db8 is documentation, but analyze_iid still runs for EUI-64
        // detection paths; test the extractor directly.)
        let mac = eui64_to_mac(addr).unwrap();
        assert_eq!(mac, [0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn analyze_classifies_eui64_global() {
        let i = analyze(a("2607:f8b0:4005:80a:020c:29ff:feab:cdef"));
        assert_eq!(i.kind, V6Kind::Eui64);
        assert_eq!(i.embedded_mac, Some([0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef]));
    }

    #[test]
    fn analyze_privacy_address() {
        // Random IID, U/L bit clear (0x?? & 0x02 == 0), no FF:FE.
        let i = analyze(a("2607:f8b0:4005:80a:1c39:4a7b:9e01:2233"));
        assert_eq!(i.kind, V6Kind::Privacy);
        assert!(i.embedded_mac.is_none());
    }

    #[test]
    fn analyze_low_byte_manual() {
        let i = analyze(a("2607:f8b0:4005:80a::443"));
        assert_eq!(i.kind, V6Kind::LowByte);
        assert!(i.notes.iter().any(|n| n.contains("manually")));
    }

    #[test]
    fn analyze_transition_and_scopes() {
        assert_eq!(analyze(a("fe80::1")).kind, V6Kind::LinkLocal);
        assert_eq!(analyze(a("fd00::1234:5678:9abc:def0")).scope, "ULA");
        assert_eq!(analyze(a("ff02::1")).kind, V6Kind::Multicast);
        assert_eq!(analyze(a("2001:db8::1")).kind, V6Kind::Documentation);
        assert_eq!(analyze(a("::1")).kind, V6Kind::Loopback);
        // 6to4 embeds 192.0.2.1 → 2002:c000:0201::.
        let i = analyze(a("2002:c000:201::1"));
        assert_eq!(i.kind, V6Kind::SixToFour);
        assert_eq!(i.embedded_v4, Some(Ipv4Addr::new(192, 0, 2, 1)));
    }
}
