use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceInfo {
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra: Option<String>,
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tls: Option<crate::tls_probe::TlsInfo>,
}

impl ServiceInfo {
    pub fn display(&self) -> String {
        let mut parts = Vec::new();
        if let Some(p) = &self.product { parts.push(p.clone()); }
        if let Some(v) = &self.version { parts.push(v.clone()); }
        if let Some(e) = &self.extra { parts.push(format!("({})", e)); }
        parts.join(" ")
    }
    pub fn is_empty(&self) -> bool {
        self.product.is_none() && self.version.is_none() && self.banner.is_none() && self.tls.is_none()
    }
}

struct Probe {
    #[allow(dead_code)]
    name: &'static str,
    payload: &'static [u8],
    ports: &'static [u16],
}

struct Signature {
    regex: Regex,
    product: Option<&'static str>,
    version_group: Option<usize>,
    extra_group: Option<usize>,
    product_group: Option<usize>,
}

const NULL_PROBE: Probe = Probe { name: "null", payload: b"", ports: &[] };
const HTTP_PROBE: Probe = Probe {
    name: "http",
    payload: b"GET / HTTP/1.0\r\nUser-Agent: RustyMap/0.1\r\nHost: localhost\r\n\r\n",
    ports: &[80, 81, 591, 2480, 5357, 5985, 5986, 7000, 7070, 8000, 8008, 8080, 8081, 8443, 8888, 9000],
};
const TLS_PROBE: Probe = Probe {
    name: "tls",
    payload: &[
        0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03,
        0x52, 0x3a, 0x4f, 0x57, 0x52, 0x3a, 0x4f, 0x57, 0x52, 0x3a, 0x4f, 0x57,
        0x52, 0x3a, 0x4f, 0x57, 0x52, 0x3a, 0x4f, 0x57, 0x52, 0x3a, 0x4f, 0x57,
        0x52, 0x3a, 0x4f, 0x57, 0x52, 0x3a, 0x4f, 0x57, 0x00, 0x00, 0x02,
        0x00, 0x2f, 0x01, 0x00,
    ],
    ports: &[443, 465, 636, 993, 995, 8443],
};
const HELP_PROBE: Probe = Probe {
    name: "help",
    payload: b"HELP\r\n",
    ports: &[25, 587, 110, 143],
};

fn probes_for_port(port: u16) -> Vec<&'static Probe> {
    let mut out: Vec<&'static Probe> = vec![&NULL_PROBE];
    let mut matched = false;
    for p in [&HTTP_PROBE, &TLS_PROBE, &HELP_PROBE] {
        if p.ports.contains(&port) {
            out.push(p);
            matched = true;
        }
    }
    if !matched {
        // Unknown port: try HTTP probe as a generic fallback
        out.push(&HTTP_PROBE);
    }
    out
}

static SIGS: Lazy<Vec<Signature>> = Lazy::new(|| {
    vec![
        Signature {
            regex: Regex::new(r"^SSH-(\d+\.\d+)-([^\r\n ]+)").unwrap(),
            product: None, product_group: Some(2), version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)^220[- ].*?(ProFTPD|vsftpd|Pure-FTPd|FileZilla|Microsoft FTP)[^\r\n]*?(\d[\d.]+)?").unwrap(),
            product: None, product_group: Some(1), version_group: Some(2), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Apache[/ ]?([\d.]+)?\s*\(?([^)\r\n]*)\)?").unwrap(),
            product: Some("Apache httpd"), product_group: None, version_group: Some(1), extra_group: Some(2),
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*nginx/?([\d.]+)?").unwrap(),
            product: Some("nginx"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Microsoft-IIS/([\d.]+)").unwrap(),
            product: Some("Microsoft IIS"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*lighttpd/([\d.]+)").unwrap(),
            product: Some("lighttpd"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Caddy").unwrap(),
            product: Some("Caddy"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)^220[- ].*?(Postfix|Sendmail|Exim|Microsoft ESMTP)[^\r\n]*?(\d[\d.]*)?").unwrap(),
            product: None, product_group: Some(1), version_group: Some(2), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)^\+OK\s+(Dovecot|Cyrus|POP3)").unwrap(),
            product: None, product_group: Some(1), version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)^\* OK\s+([^\r\n]*?IMAP[^\r\n]*)").unwrap(),
            product: Some("IMAP"), product_group: None, version_group: None, extra_group: Some(1),
        },
        Signature {
            regex: Regex::new(r"\x00\x00\x00\x0a([\d.]+)-MariaDB").unwrap(),
            product: Some("MariaDB"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"\x00\x00\x00\x0a([\d.]+)").unwrap(),
            product: Some("MySQL"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"-ERR wrong number of arguments").unwrap(),
            product: Some("Redis"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)redis_version:([\d.]+)").unwrap(),
            product: Some("Redis"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"^\x16\x03[\x00-\x03]").unwrap(),
            product: Some("TLS/SSL"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)MongoDB").unwrap(),
            product: Some("MongoDB"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)SMB|samba").unwrap(),
            product: Some("SMB"), product_group: None, version_group: None, extra_group: None,
        },
    ]
});

fn match_signatures(data: &[u8]) -> Option<ServiceInfo> {
    let text = String::from_utf8_lossy(data);
    for s in SIGS.iter() {
        if let Some(c) = s.regex.captures(&text) {
            let product = s.product.map(String::from).or_else(|| {
                s.product_group.and_then(|g| c.get(g)).map(|m| m.as_str().to_string())
            });
            let version = s.version_group.and_then(|g| c.get(g)).map(|m| m.as_str().to_string());
            let extra = s.extra_group.and_then(|g| c.get(g)).map(|m| m.as_str().trim().to_string())
                .filter(|s| !s.is_empty());
            let banner = first_line(&text);
            return Some(ServiceInfo { product, version, extra, banner, tls: None });
        }
    }
    None
}

fn first_line(s: &str) -> Option<String> {
    let line: String = s.chars().take_while(|c| *c != '\n' && *c != '\r').take(200).collect();
    if line.trim().is_empty() { None } else { Some(line) }
}

pub async fn probe(
    ip: IpAddr,
    port: u16,
    timeout_dur: Duration,
    sni: Option<&str>,
) -> Option<ServiceInfo> {
    let addr = SocketAddr::new(ip, port);
    let mut best: Option<ServiceInfo> = None;
    for p in probes_for_port(port) {
        if let Some(info) = probe_once(addr, p, timeout_dur).await {
            if !info.is_empty() {
                best = Some(info);
                break;
            }
        }
    }
    if crate::tls_probe::likely_tls(port) {
        if let Some(tls) = crate::tls_probe::probe(ip, port, timeout_dur, sni).await {
            let mut info = best.unwrap_or_default();
            info.tls = Some(tls);
            return Some(info);
        }
    }
    best
}

async fn probe_once(addr: SocketAddr, p: &Probe, dur: Duration) -> Option<ServiceInfo> {
    let mut stream = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
    if !p.payload.is_empty() {
        timeout(dur, stream.write_all(p.payload)).await.ok()?.ok()?;
    }
    let mut buf = vec![0u8; 2048];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    if n == 0 { return None; }
    buf.truncate(n);
    if let Some(info) = match_signatures(&buf) {
        return Some(info);
    }
    Some(ServiceInfo {
        banner: first_line(&String::from_utf8_lossy(&buf)),
        ..Default::default()
    })
}
