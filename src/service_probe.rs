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
const RTSP_PROBE: Probe = Probe {
    name: "rtsp",
    payload: b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: RustyMap\r\n\r\n",
    ports: &[554, 8554],
};
// NOTE: RTMP (port 1935) requires a binary 1536-byte C0/C1 handshake
// before any text exchange — we don't implement it, so RTMP banners
// remain empty. Service identification on 1935 comes from CPE only.

fn probes_for_port(port: u16) -> Vec<&'static Probe> {
    let mut out: Vec<&'static Probe> = vec![&NULL_PROBE];
    let mut matched = false;
    for p in [&HTTP_PROBE, &TLS_PROBE, &HELP_PROBE, &RTSP_PROBE] {
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
        // RTSP — OPTIONS reply carries Server: <name>/<version>
        Signature {
            regex: Regex::new(r"(?i)^RTSP/[0-9.]+\s+\d+[^\r\n]*\r\n[\s\S]*?Server:\s*([^\r\n/]+)/?([\d.]+)?").unwrap(),
            product: None, product_group: Some(1), version_group: Some(2), extra_group: None,
        },
        // ── Web servers (additional patterns) ──
        Signature {
            regex: Regex::new(r"(?i)Server:\s*OpenResty/?([\d.]+)?").unwrap(),
            product: Some("OpenResty (nginx fork)"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Tengine/?([\d.]+)?").unwrap(),
            product: Some("Tengine (Alibaba nginx)"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Apache-Coyote/([\d.]+)").unwrap(),
            product: Some("Apache Tomcat"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Jetty\(([\d.]+)\)").unwrap(),
            product: Some("Eclipse Jetty"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Werkzeug/([\d.]+)").unwrap(),
            product: Some("Werkzeug (Python)"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*gunicorn/([\d.]+)").unwrap(),
            product: Some("Gunicorn"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*uvicorn").unwrap(),
            product: Some("Uvicorn (ASGI)"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*hypercorn-h11/([\d.]+)").unwrap(),
            product: Some("Hypercorn"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*envoy").unwrap(),
            product: Some("Envoy (proxy)"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*traefik/?([\d.]+)?").unwrap(),
            product: Some("Traefik"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Cowboy/?([\d.]+)?").unwrap(),
            product: Some("Cowboy (Erlang)"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Kestrel").unwrap(),
            product: Some("Kestrel (.NET)"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Caches / message queues ──
        Signature {
            regex: Regex::new(r"^(?:STAT|VERSION)\s+([\d.]+)").unwrap(),
            product: Some("memcached"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)RabbitMQ").unwrap(),
            product: Some("RabbitMQ"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)NATS").unwrap(),
            product: Some("NATS"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"\x00\x00\x00\x09\x03").unwrap(),
            product: Some("MQTT broker"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Databases ──
        Signature {
            regex: Regex::new(r"(?i)PostgreSQL").unwrap(),
            product: Some("PostgreSQL"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Microsoft SQL Server\s+([\d.]+)?").unwrap(),
            product: Some("Microsoft SQL Server"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)CouchDB").unwrap(),
            product: Some("Apache CouchDB"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r#"(?i)"version"\s*:\s*"([\d.]+)".*elasticsearch|elasticsearch.*version.*([\d.]+)"#).unwrap(),
            product: Some("Elasticsearch"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Cassandra/([\d.]+)").unwrap(),
            product: Some("Apache Cassandra"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)ZooKeeper").unwrap(),
            product: Some("ZooKeeper"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Container / orchestration ──
        Signature {
            regex: Regex::new(r"(?i)Docker/([\d.]+)").unwrap(),
            product: Some("Docker daemon"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)kube-apiserver").unwrap(),
            product: Some("Kubernetes API server"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)etcd-cluster|etcdserver").unwrap(),
            product: Some("etcd"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Monitoring / observability ──
        Signature {
            regex: Regex::new(r"(?i)Prometheus/([\d.]+)").unwrap(),
            product: Some("Prometheus"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Grafana/([\d.]+)").unwrap(),
            product: Some("Grafana"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Kibana/([\d.]+)").unwrap(),
            product: Some("Kibana"), product_group: None, version_group: Some(1), extra_group: None,
        },
        // ── DevOps surfaces ──
        Signature {
            regex: Regex::new(r"(?i)Jenkins/([\d.]+)").unwrap(),
            product: Some("Jenkins"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)GitLab(?:\sworkhorse)?").unwrap(),
            product: Some("GitLab"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Gitea/([\d.]+)").unwrap(),
            product: Some("Gitea"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Nexus/([\d.]+)").unwrap(),
            product: Some("Sonatype Nexus"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Artifactory/([\d.]+)").unwrap(),
            product: Some("JFrog Artifactory"), product_group: None, version_group: Some(1), extra_group: None,
        },
        // ── Remote access ──
        Signature {
            regex: Regex::new(r"(?i)RDP|MS-Term|Remote Desktop Services").unwrap(),
            product: Some("Microsoft RDP"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"^RFB\s+([\d.]+)\b").unwrap(),
            product: Some("VNC (RFB)"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)NX server|NoMachine").unwrap(),
            product: Some("NoMachine NX"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Hypervisor management ──
        // VMware Authentication Daemon (tcp/902) greets with a text 220
        // line the moment you connect — the NULL probe reads it and this
        // signature pulls out the daemon version (lab bug B2).
        Signature {
            regex: Regex::new(r"(?i)VMware Authentication Daemon Version\s*([\d.]+)").unwrap(),
            product: Some("VMware Authentication Daemon"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)VMware ESX(?:i)?\s*([\d.]+)?").unwrap(),
            product: Some("VMware ESXi"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Proxmox VE/?([\d.]+)?").unwrap(),
            product: Some("Proxmox VE"), product_group: None, version_group: Some(1), extra_group: None,
        },
        // ── ICS/SCADA ──
        Signature {
            regex: Regex::new(r"(?i)Siemens|Simatic|S7-").unwrap(),
            product: Some("Siemens SIMATIC (S7)"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Schneider Electric|Modicon").unwrap(),
            product: Some("Schneider Electric Modicon"), product_group: None, version_group: None, extra_group: None,
        },
        // ── IoT / embedded ──
        Signature {
            regex: Regex::new(r"(?i)Lua-CGI|GoAhead|uhttpd|micro_httpd").unwrap(),
            product: Some("embedded HTTP daemon"), product_group: None, version_group: None, extra_group: None,
        },
        // gSOAP — common on IP cameras / ONVIF devices; emits a Server header.
        Signature {
            regex: Regex::new(r"(?i)gSOAP/([\d.]+)").unwrap(),
            product: Some("gSOAP"), product_group: None, version_group: Some(1), extra_group: None,
        },
        // Classic small/embedded HTTP servers that DO carry a version.
        Signature {
            regex: Regex::new(r"(?i)Server:\s*mini_httpd/?([\d.]+)?").unwrap(),
            product: Some("mini_httpd"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*thttpd/?([\d.]+)?").unwrap(),
            product: Some("thttpd"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Boa/?([\d.]+)?").unwrap(),
            product: Some("Boa httpd"), product_group: None, version_group: Some(1), extra_group: None,
        },
        // dnsmasq occasionally fronts an HTTP/DHCP status page; the DNS
        // version.bind probe (port 53) is the primary path, this is a backstop.
        Signature {
            regex: Regex::new(r"(?i)dnsmasq[- ]?([\d.]+)?").unwrap(),
            product: Some("dnsmasq"), product_group: None, version_group: Some(1), extra_group: None,
        },
        // ── NewSQL / modern DBs ──
        Signature {
            regex: Regex::new(r"(?i)CockroachDB[\s/-]+v?([\d.]+)").unwrap(),
            product: Some("CockroachDB"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            // TiDB rides on the MySQL wire protocol; bytes 5..N of the
            // server-greeting include the literal version, e.g. "5.7.25-TiDB-v6.5.0"
            regex: Regex::new(r"(?i)([\d.]+-TiDB-v?[\d.]+)").unwrap(),
            product: Some("TiDB"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)YugabyteDB[\s/-]+v?([\d.]+)").unwrap(),
            product: Some("YugabyteDB"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*ClickHouse").unwrap(),
            product: Some("ClickHouse"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-ClickHouse-Server-Display-Name").unwrap(),
            product: Some("ClickHouse"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Scylla version\s+([\d.]+)").unwrap(),
            product: Some("ScyllaDB"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r#"(?i)"neo4j_version"\s*:\s*"([\d.]+)""#).unwrap(),
            product: Some("Neo4j"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-Influxdb-Version:\s*v?([\d.]+)").unwrap(),
            product: Some("InfluxDB"), product_group: None, version_group: Some(1), extra_group: None,
        },
        // ── Streaming / message brokers ──
        Signature {
            regex: Regex::new(r"(?i)Kafka(?:-Broker)?[\s/-]+v?([\d.]+)").unwrap(),
            product: Some("Apache Kafka"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Pulsar[\s/-]+v?([\d.]+)").unwrap(),
            product: Some("Apache Pulsar"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)RocketMQ").unwrap(),
            product: Some("Apache RocketMQ"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Observability stack ──
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Loki/?([\d.]+)?").unwrap(),
            product: Some("Grafana Loki"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Tempo").unwrap(),
            product: Some("Grafana Tempo"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Mimir").unwrap(),
            product: Some("Grafana Mimir"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)VictoriaMetrics/?([\d.]+)?").unwrap(),
            product: Some("VictoriaMetrics"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)thanos[\s/-]+v?([\d.]+)").unwrap(),
            product: Some("Thanos"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*opentelemetry-collector").unwrap(),
            product: Some("OpenTelemetry Collector"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Identity / auth ──
        Signature {
            regex: Regex::new(r"(?i)authelia_session|Authelia").unwrap(),
            product: Some("Authelia"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)authentik|goauthentik").unwrap(),
            product: Some("Authentik"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Keycloak[\s/-]+v?([\d.]+)").unwrap(),
            product: Some("Keycloak"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)/auth/realms/").unwrap(),
            product: Some("Keycloak"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)zitadel").unwrap(),
            product: Some("ZITADEL"), product_group: None, version_group: None, extra_group: None,
        },
        // ── HashiCorp stack ──
        Signature {
            regex: Regex::new(r"(?i)X-Vault-Server\s*([^\r\n]+)|Server:\s*Vault/?([\d.]+)?").unwrap(),
            product: Some("HashiCorp Vault"), product_group: None, version_group: Some(2), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-Consul-Index|Server:\s*Consul").unwrap(),
            product: Some("HashiCorp Consul"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-Nomad-Index|Server:\s*Nomad").unwrap(),
            product: Some("HashiCorp Nomad"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Modern proxies / runtimes ──
        Signature {
            regex: Regex::new(r"(?i)Server:\s*pingora").unwrap(),
            product: Some("Cloudflare Pingora"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Bun/?([\d.]+)?").unwrap(),
            product: Some("Bun"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Deno/?([\d.]+)?").unwrap(),
            product: Some("Deno"), product_group: None, version_group: Some(1), extra_group: None,
        },
        // ── Self-hosted / dashboards ──
        Signature {
            regex: Regex::new(r"(?i)Set-Cookie:\s*metabase\.SESSION|Metabase").unwrap(),
            product: Some("Metabase"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Set-Cookie:\s*session_apache_superset|Apache Superset").unwrap(),
            product: Some("Apache Superset"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-Apache-Airflow|Airflow").unwrap(),
            product: Some("Apache Airflow"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-Argocd-Username|argocd").unwrap(),
            product: Some("Argo CD"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Portainer").unwrap(),
            product: Some("Portainer"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-Pi-hole").unwrap(),
            product: Some("Pi-hole"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-Home-Assistant").unwrap(),
            product: Some("Home Assistant"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-Nextcloud-Status|Nc-Request-ID").unwrap(),
            product: Some("Nextcloud"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Synapse/?([\d.]+)?").unwrap(),
            product: Some("Matrix Synapse"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Mastodon|X-Request-Id.*?M:").unwrap(),
            product: Some("Mastodon"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Networking / mesh ──
        Signature {
            regex: Regex::new(r"(?i)Tailscale Derper|Server:\s*tailscale").unwrap(),
            product: Some("Tailscale (DERP relay)"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)headscale").unwrap(),
            product: Some("Headscale"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Backup / storage ──
        Signature {
            regex: Regex::new(r"(?i)Server:\s*restic|restic-server").unwrap(),
            product: Some("restic-server"), product_group: None, version_group: None, extra_group: None,
        },
        // ── LLM / AI inference servers (2023–2026) ──
        Signature {
            regex: Regex::new(r"(?i)Ollama is running|Server:\s*ollama").unwrap(),
            product: Some("Ollama (LLM server)"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r#"(?i)"object"\s*:\s*"list".*"owned_by".*vllm|Server:\s*vllm"#).unwrap(),
            product: Some("vLLM (OpenAI-compatible LLM)"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)text-generation-inference/([\d.]+)?").unwrap(),
            product: Some("HF Text Generation Inference"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)localai").unwrap(),
            product: Some("LocalAI"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Vector / search databases (2020–2026) ──
        Signature {
            regex: Regex::new(r#"(?i)"title"\s*:\s*"qdrant[^"]*".*"version"\s*:\s*"([\d.]+)"|Server:\s*qdrant"#).unwrap(),
            product: Some("Qdrant (vector DB)"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Meilisearch/?([\d.]+)?|X-Meili").unwrap(),
            product: Some("Meilisearch"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r#"(?i)weaviate.*"version"\s*:\s*"([\d.]+)"|Server:\s*weaviate"#).unwrap(),
            product: Some("Weaviate (vector DB)"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*typesense|X-Typesense").unwrap(),
            product: Some("Typesense"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Modern Redis-compatible caches ──
        Signature {
            regex: Regex::new(r"(?i)dragonfly_version|df_version|DragonflyDB").unwrap(),
            product: Some("DragonflyDB"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)keydb_version|KeyDB").unwrap(),
            product: Some("KeyDB"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)valkey_version|Valkey").unwrap(),
            product: Some("Valkey"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Streaming / messaging ──
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Redpanda|redpanda").unwrap(),
            product: Some("Redpanda (Kafka-compatible)"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Backends / BaaS (2021–2026) ──
        Signature {
            regex: Regex::new(r"(?i)PocketBase|Server:\s*pocketbase").unwrap(),
            product: Some("PocketBase"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*supabase|X-Supabase|supabase-js").unwrap(),
            product: Some("Supabase"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-Appwrite|appwrite").unwrap(),
            product: Some("Appwrite"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Self-hosted media / dashboards (2020–2026) ──
        Signature {
            regex: Regex::new(r"(?i)Immich|X-Immich").unwrap(),
            product: Some("Immich (photo server)"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Jellyfin/?([\d.]+)?|X-Jellyfin").unwrap(),
            product: Some("Jellyfin"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Uptime Kuma").unwrap(),
            product: Some("Uptime Kuma"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*n8n|X-N8n").unwrap(),
            product: Some("n8n (workflow automation)"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Object storage / edge ──
        Signature {
            regex: Regex::new(r"(?i)Server:\s*SeaweedFS/?([\d.]+)?").unwrap(),
            product: Some("SeaweedFS"), product_group: None, version_group: Some(1), extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Server:\s*Garage/?([\d.]+)?").unwrap(),
            product: Some("Garage (S3-compat store)"), product_group: None, version_group: Some(1), extra_group: None,
        },
        // ── Identity-aware proxies (zero-trust, 2020–2026) ──
        Signature {
            regex: Regex::new(r"(?i)oauth2[_-]proxy").unwrap(),
            product: Some("oauth2-proxy"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)X-Pomerium|Server:\s*pomerium").unwrap(),
            product: Some("Pomerium (zero-trust proxy)"), product_group: None, version_group: None, extra_group: None,
        },
        // ── Observability (next-gen) ──
        Signature {
            regex: Regex::new(r"(?i)SigNoz").unwrap(),
            product: Some("SigNoz (observability)"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)OpenObserve|Server:\s*openobserve").unwrap(),
            product: Some("OpenObserve"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)quickwit").unwrap(),
            product: Some("Quickwit (log search)"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Grafana Alloy|Server:\s*alloy").unwrap(),
            product: Some("Grafana Alloy (OTel collector)"), product_group: None, version_group: None, extra_group: None,
        },
        // ── PaaS control planes (2022–2026) ──
        Signature {
            regex: Regex::new(r"(?i)Coolify").unwrap(),
            product: Some("Coolify (self-hosted PaaS)"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)Dokploy").unwrap(),
            product: Some("Dokploy"), product_group: None, version_group: None, extra_group: None,
        },
        Signature {
            regex: Regex::new(r"(?i)CapRover").unwrap(),
            product: Some("CapRover"), product_group: None, version_group: None, extra_group: None,
        },
    ]
});

/// Extract a leading dotted version (optionally with an OpenSSH-style `pN`
/// suffix) from a token, e.g. "2017.75" or "8.9p1".
fn extract_ver(s: &str) -> Option<String> {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d[\d.]*(?:p\d+)?)").unwrap());
    RE.captures(s).and_then(|c| c.get(1)).map(|m| m.as_str().trim_end_matches('.').to_string())
}

/// Turn an SSH identification string into nmap-style product + version.
/// `SSH-2.0-OpenSSH_8.9p1` → ("OpenSSH", "8.9p1", "protocol 2.0");
/// `SSH-2.0-dropbear_2017.75` → ("Dropbear sshd", "2017.75", "protocol 2.0").
/// Unknown software keeps the raw token as the product so nothing is lost.
fn match_ssh(text: &str) -> Option<ServiceInfo> {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^SSH-(\d+\.\d+)-([^\r\n]+)").unwrap());
    let c = RE.captures(text)?;
    let proto = c.get(1).map(|m| m.as_str().to_string());
    let sw = c.get(2).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
    let name = sw.split(['_', '-', ' ']).next().unwrap_or(&sw);
    let (product, version) = match name.to_ascii_lowercase().as_str() {
        "openssh" => ("OpenSSH".to_string(), extract_ver(&sw)),
        "dropbear" => ("Dropbear sshd".to_string(), extract_ver(&sw)),
        "libssh" => ("libssh".to_string(), extract_ver(&sw)),
        "mikrotik" | "rosssh" => ("MikroTik RouterOS sshd".to_string(), extract_ver(&sw)),
        _ => (sw.clone(), None), // unknown: keep the whole token, no version guess
    };
    Some(ServiceInfo {
        product: Some(product),
        version,
        extra: proto.map(|p| format!("protocol {}", p)),
        banner: Some(format!("SSH-{}", c.get(1).map(|m| m.as_str()).unwrap_or(""))),
        tls: None,
    })
}

fn match_signatures(data: &[u8]) -> Option<ServiceInfo> {
    let text = String::from_utf8_lossy(data);
    // SSH is handled first with a dedicated normaliser (dropbear/OpenSSH/… →
    // clean product+version) instead of the generic raw-token capture.
    if let Some(info) = match_ssh(&text) {
        return Some(info);
    }
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
    // Fall back to user-loaded nmap-service-probes match rules.
    if let Some((product, version, info)) = crate::nmap_db::match_loaded_probes(&text) {
        if product.is_some() || version.is_some() || info.is_some() {
            return Some(ServiceInfo {
                product,
                version,
                extra: info,
                banner: first_line(&text),
                tls: None,
            });
        }
    }
    None
}

fn first_line(s: &str) -> Option<String> {
    let line: String = s.chars().take_while(|c| *c != '\n' && *c != '\r').take(200).collect();
    if line.trim().is_empty() { None } else { Some(line) }
}

/// Build a TCP DNS query for `version.bind` CHAOS TXT (RFC-style version
/// disclosure nmap uses to fingerprint resolvers). Includes the 2-byte TCP
/// length prefix.
fn build_dns_version_query() -> Vec<u8> {
    let mut msg: Vec<u8> = Vec::with_capacity(32);
    msg.extend_from_slice(&0x1a2bu16.to_be_bytes()); // transaction id
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, RD
    msg.extend_from_slice(&1u16.to_be_bytes());       // qdcount
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]);       // an/ns/ar counts = 0
    for label in ["version", "bind"] {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);                                      // root label
    msg.extend_from_slice(&16u16.to_be_bytes());      // qtype TXT
    msg.extend_from_slice(&3u16.to_be_bytes());       // qclass CHAOS
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&msg);
    out
}

/// Pull the TXT character-string out of a `version.bind` answer. `resp`
/// includes the 2-byte TCP length prefix. Locates the TXT/CHAOS answer RR
/// (TYPE=0x0010, CLASS=0x0003) and reads its single character-string. No full
/// DNS parse — version.bind replies are tiny and unambiguous.
fn parse_dns_version(resp: &[u8]) -> Option<String> {
    // Need header + at least a question; search for the answer RR signature.
    let marker = [0x00u8, 0x10, 0x00, 0x03]; // TYPE TXT, CLASS CHAOS
    // Skip the 2-byte TCP length prefix and 12-byte DNS header before scanning
    // so the question's qtype/qclass (same bytes) isn't mistaken for the answer.
    let start = 2 + 12;
    if resp.len() <= start {
        return None;
    }
    // The question section ends with its own qtype/qclass; find the SECOND
    // occurrence of the marker (first is the question) when present, else the
    // first after a plausible answer offset.
    let mut positions = Vec::new();
    let mut i = start;
    while i + 4 <= resp.len() {
        if resp[i..i + 4] == marker {
            positions.push(i);
        }
        i += 1;
    }
    // The answer marker is the last one (question comes first in the stream).
    let m = *positions.last()?;
    // After TYPE(2)+CLASS(2) at m..m+4: TTL(4), RDLENGTH(2), then RDATA.
    let rdata = m + 4 + 4 + 2;
    let txt_len_pos = rdata; // first RDATA byte = character-string length
    let l = *resp.get(txt_len_pos)? as usize;
    let sstart = txt_len_pos + 1;
    let send = sstart.checked_add(l)?;
    let bytes = resp.get(sstart..send)?;
    let s = String::from_utf8_lossy(bytes).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Map a version.bind string to a product + version (dnsmasq, BIND, …).
fn classify_dns_version(txt: &str) -> ServiceInfo {
    let lower = txt.to_lowercase();
    let product = if lower.contains("dnsmasq") {
        "dnsmasq"
    } else if lower.contains("unbound") {
        "Unbound"
    } else if lower.contains("powerdns") || lower.contains("pdns") {
        "PowerDNS"
    } else if lower.contains("knot") {
        "Knot DNS"
    } else if lower.contains("coredns") {
        "CoreDNS"
    } else if lower.contains("bind") || lower.contains("named") {
        "ISC BIND"
    } else if txt.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
        // `version.bind` CHAOS is BIND's native disclosure; a bare version
        // number (e.g. "9.16.1-Ubuntu") with no other keyword is almost
        // certainly BIND (or a BIND-compatible responder).
        "ISC BIND"
    } else {
        "DNS server"
    };
    let version = if product == "DNS server" { None } else { extract_ver(txt) };
    ServiceInfo {
        product: Some(product.to_string()),
        version,
        extra: Some("version.bind".to_string()),
        banner: Some(txt.to_string()),
        tls: None,
    }
}

/// TCP `version.bind` probe for port 53. Returns a populated `ServiceInfo` on
/// a TXT reply, else `None` (fall back to generic probing).
async fn dns_version_probe(addr: SocketAddr, dur: Duration) -> Option<ServiceInfo> {
    let mut stream = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
    let q = build_dns_version_query();
    timeout(dur, stream.write_all(&q)).await.ok()?.ok()?;
    let mut buf = vec![0u8; 1024];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };
    let txt = parse_dns_version(&buf[..n])?;
    Some(classify_dns_version(&txt))
}

pub async fn probe(
    ip: IpAddr,
    port: u16,
    timeout_dur: Duration,
    sni: Option<&str>,
    intensity: u8,
) -> Option<ServiceInfo> {
    let addr = SocketAddr::new(ip, port);

    // DNS (53) discloses its software via a CHAOS TXT `version.bind` query,
    // not a connect banner — this is how nmap names dnsmasq/BIND/etc. The
    // generic HTTP/null probes would otherwise leave it as a bare "domain".
    if port == 53 {
        if let Some(info) = dns_version_probe(addr, timeout_dur).await {
            return Some(info);
        }
    }

    // Binary-only protocols (SMB / MSRPC) never emit a printable banner,
    // so hand them to the dedicated binary probe first (lab bug B2).
    if let Some(info) = crate::binary_probe::probe(ip, port, timeout_dur).await {
        if !info.is_empty() {
            return Some(info);
        }
    }
    let mut best: Option<ServiceInfo> = None;
    for p in probes_for_port(port) {
        if let Some(info) = probe_once(addr, p, timeout_dur).await {
            if !info.is_empty() {
                best = Some(info);
                break;
            }
        }
    }
    // The TLS handshake adds a full RTT per port; gate it behind
    // intensity ≥ 7 (--version-intensity, default 5). Users who want it
    // every time can pass --version-intensity 7+ or --version-all.
    if intensity >= 7 && crate::tls_probe::likely_tls(port) {
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
    // Accumulate reads until we see the end of the HTTP headers, reach 8 KiB,
    // hit EOF, or run out of time. A single read often returned only a
    // partial response on slow hosts, leaving the Server/version line unseen
    // (lab bug B19). Allow up to 2× the per-op timeout overall for this.
    let deadline = std::time::Instant::now() + dur.saturating_mul(2);
    let mut data: Vec<u8> = Vec::with_capacity(2048);
    let mut tmp = vec![0u8; 2048];
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining.min(dur), stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                data.extend_from_slice(&tmp[..n]);
                if data.len() >= 8192 || data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            _ => break, // timeout / error → use whatever we have
        }
    }
    if data.is_empty() {
        return None;
    }
    if let Some(info) = match_signatures(&data) {
        return Some(info);
    }
    Some(ServiceInfo {
        banner: first_line(&String::from_utf8_lossy(&data)),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_openssh_normalised() {
        let info = match_ssh("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n").unwrap();
        assert_eq!(info.product.as_deref(), Some("OpenSSH"));
        assert_eq!(info.version.as_deref(), Some("8.9p1"));
        assert_eq!(info.extra.as_deref(), Some("protocol 2.0"));
    }

    #[test]
    fn ssh_dropbear_normalised() {
        let info = match_ssh("SSH-2.0-dropbear_2017.75\r\n").unwrap();
        assert_eq!(info.product.as_deref(), Some("Dropbear sshd"));
        assert_eq!(info.version.as_deref(), Some("2017.75"));
    }

    #[test]
    fn ssh_unknown_keeps_raw_token() {
        let info = match_ssh("SSH-2.0-WeirdSSH_1.0\r\n").unwrap();
        assert_eq!(info.product.as_deref(), Some("WeirdSSH_1.0"));
        assert!(info.version.is_none());
    }

    #[test]
    fn non_ssh_is_none() {
        assert!(match_ssh("220 ProFTPD\r\n").is_none());
    }

    #[test]
    fn dns_query_layout() {
        let q = build_dns_version_query();
        // 2-byte TCP length prefix matches the message length.
        let plen = u16::from_be_bytes([q[0], q[1]]) as usize;
        assert_eq!(plen, q.len() - 2);
        // qname version.bind present, qtype TXT (16), qclass CHAOS (3) at the tail.
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x10, 0x00, 0x03]);
        assert!(q.windows(7).any(|w| w == b"version"));
        assert!(q.windows(4).any(|w| w == b"bind"));
    }

    #[test]
    fn dns_parse_and_classify_dnsmasq() {
        let mut r: Vec<u8> = vec![0x00, 0x3c]; // TCP length prefix (value unused by parser)
        r.extend_from_slice(&[0x1a, 0x2b, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]); // header: qd=1 an=1
        // question: version.bind TXT CHAOS
        r.extend_from_slice(&[7]);
        r.extend_from_slice(b"version");
        r.extend_from_slice(&[4]);
        r.extend_from_slice(b"bind");
        r.extend_from_slice(&[0, 0x00, 0x10, 0x00, 0x03]);
        // answer: ptr, TXT, CHAOS, ttl, rdlength, char-string "dnsmasq-2.73"
        r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0, 0, 0, 0, 0x00, 0x0d, 0x0c]);
        r.extend_from_slice(b"dnsmasq-2.73");
        let txt = parse_dns_version(&r).expect("should extract TXT");
        assert_eq!(txt, "dnsmasq-2.73");
        let info = classify_dns_version(&txt);
        assert_eq!(info.product.as_deref(), Some("dnsmasq"));
        assert_eq!(info.version.as_deref(), Some("2.73"));
    }

    #[test]
    fn classify_bind() {
        let info = classify_dns_version("9.16.1-Ubuntu");
        assert_eq!(info.product.as_deref(), Some("ISC BIND"));
        assert_eq!(info.version.as_deref(), Some("9.16.1"));
    }
}
