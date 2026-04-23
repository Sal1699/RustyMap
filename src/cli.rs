use clap::{Parser, ValueEnum};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rustymap",
    version,
    about = "RustyMap - Rust port of nmap",
    long_about = "RustyMap is a network scanner written in Rust.\n\
                  Phase 1: TCP connect. Phase 2: SYN/FIN/NULL/Xmas/ACK/UDP + ICMP ping."
)]
pub struct Cli {
    /// Target specification: IP, hostname, CIDR (10.0.0.0/24), range (10.0.0.1-50)
    #[arg(num_args = 0..)]
    pub targets: Vec<String>,

    /// Port specification: 22, 1-1000, 22,80,443, or - for 1-65535
    #[arg(short = 'p', long = "ports", default_value = "1-1000")]
    pub ports: String,

    /// Scan all 65535 ports (shortcut for -p-)
    #[arg(long = "all-ports")]
    pub all_ports: bool,

    /// TCP connect scan (no privileges required)
    #[arg(long = "sT", group = "scan_type")]
    pub scan_connect: bool,

    /// TCP SYN (half-open) scan — raw socket, requires root/admin
    #[arg(long = "sS", group = "scan_type")]
    pub scan_syn: bool,

    /// TCP FIN scan
    #[arg(long = "sF", group = "scan_type")]
    pub scan_fin: bool,

    /// TCP NULL scan
    #[arg(long = "sN", group = "scan_type")]
    pub scan_null: bool,

    /// TCP Xmas scan
    #[arg(long = "sX", group = "scan_type")]
    pub scan_xmas: bool,

    /// TCP ACK scan (firewall mapping)
    #[arg(long = "sA", group = "scan_type")]
    pub scan_ack: bool,

    /// UDP scan
    #[arg(long = "sU", group = "scan_type")]
    pub scan_udp: bool,

    /// Idle (zombie) scan — spoofs probes via a zombie with incremental IP ID (root/admin)
    #[arg(long = "sI", value_name = "ZOMBIE[:PORT]", group = "scan_type")]
    pub scan_idle: Option<String>,

    /// Skip host discovery, scan all hosts as if up
    #[arg(long = "Pn")]
    pub skip_discovery: bool,

    /// Ping scan only (no port scan)
    #[arg(long = "sn")]
    pub ping_only: bool,

    /// ICMP echo ping for host discovery (raw, requires root/admin)
    #[arg(long = "PE")]
    pub ping_icmp: bool,

    /// Timing template 0-5 (0=paranoid, 5=insane)
    #[arg(short = 't', long = "timing", default_value_t = 3)]
    pub timing: u8,

    /// Max parallel connections
    #[arg(long = "max-parallel", default_value_t = 500)]
    pub max_parallel: usize,

    /// Connection timeout in milliseconds
    #[arg(long = "timeout", default_value_t = 1500)]
    pub timeout_ms: u64,

    /// Verbose output (-v, -vv)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Write normal output to file
    #[arg(long = "oN")]
    pub output_normal: Option<String>,

    /// Write grepable output to file
    #[arg(long = "oG")]
    pub output_grepable: Option<String>,

    /// Write JSON output to file (schema v1)
    #[arg(long = "oJ")]
    pub output_json: Option<String>,

    /// SQLite database path for persistent scan history (default: rustymap.db)
    #[arg(long = "db")]
    pub db_path: Option<String>,

    /// Disable writing to SQLite (by default scans are persisted)
    #[arg(long = "no-db")]
    pub no_db: bool,

    /// Show diff against previous scan of each host (requires --db)
    #[arg(long = "diff")]
    pub show_diff: bool,

    /// JSONL audit log path (records all actions with timestamps)
    #[arg(long = "audit-log")]
    pub audit_log: Option<String>,

    /// Add tag to ip (format: ip=tag or ip:port=tag), can repeat
    #[arg(long = "tag", value_name = "SPEC")]
    pub add_tags: Vec<String>,

    /// List all tags stored in db and exit
    #[arg(long = "list-tags")]
    pub list_tags: bool,

    /// Filter --list-tags by IP
    #[arg(long = "tag-ip")]
    pub tag_ip: Option<String>,

    /// Disable colored output
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Stampa la guida estesa con esempi e categorie
    #[arg(long = "guide")]
    pub guide: bool,

    /// Never do DNS resolution
    #[arg(short = 'n', long = "no-dns")]
    pub no_dns: bool,

    /// Enable adaptive rate limiting (auto-tune concurrency based on timeouts)
    #[arg(long = "adaptive")]
    pub adaptive: bool,

    /// Probe open ports for service/version info (banner grab + active probes)
    #[arg(long = "sV")]
    pub service_version: bool,

    /// Enable OS fingerprinting (TTL + port/banner heuristics)
    #[arg(short = 'O', long = "os")]
    pub os_fingerprint: bool,

    /// Run Rhai scripts from path (file or directory of *.rhai)
    #[arg(long = "script")]
    pub script_path: Option<String>,

    /// CVE DB JSON file to correlate against -sV results
    #[arg(long = "cve-db")]
    pub cve_db: Option<String>,

    /// Randomize port scan order (evasion)
    #[arg(long = "randomize-ports")]
    pub randomize_ports: bool,

    /// Delay in milliseconds between probes per host (evasion)
    #[arg(long = "scan-delay", default_value_t = 0)]
    pub scan_delay_ms: u64,

    /// Comma-separated decoy source IPs for raw scans (e.g. 10.0.0.5,10.0.0.6)
    #[arg(long = "decoys")]
    pub decoys: Option<String>,

    /// Fixed source port for raw scans (evasion, e.g. 53, 80, 88)
    #[arg(long = "source-port")]
    pub source_port: Option<u16>,

    /// Custom IP TTL for raw scan probes (default 64)
    #[arg(long = "ip-ttl")]
    pub ip_ttl: Option<u8>,

    /// Per-probe TTL jitter (±N). Randomizes IP TTL on every probe.
    #[arg(long = "ttl-jitter", default_value_t = 0)]
    pub ttl_jitter: u8,

    /// Before sending decoys, warm the firewall with benign SYNs from each decoy to 80/443.
    #[arg(long = "decoy-preping")]
    pub decoy_preping: bool,

    /// Append N random bytes to probe packets (evasion)
    #[arg(long = "data-length", default_value_t = 0)]
    pub data_length: usize,

    /// Fragment probe packets into tiny IP fragments (evasion)
    #[arg(short = 'f', long = "fragment")]
    pub fragment: bool,

    /// MTU for fragment size in bytes (default 8, must be multiple of 8)
    #[arg(long = "mtu")]
    pub mtu: Option<u16>,

    /// Send probes with bad TCP checksum (detect stateful firewalls/IDS)
    #[arg(long = "badsum")]
    pub bad_checksum: bool,

    /// Evasion preset: stealth, aggressive, paranoid
    #[arg(long = "evasion")]
    pub evasion_preset: Option<String>,

    /// TCP/IP stack fingerprint profile (windows11, linux6, macos, freebsd, android14)
    #[arg(long = "stack-profile")]
    pub stack_profile: Option<String>,

    /// Custom TCP flags (hex: 0x02, names: SYN,FIN,ECE,CWR)
    #[arg(long = "scanflags")]
    pub scanflags: Option<String>,

    /// Jitter between probes in ms (gaussian distribution)
    #[arg(long = "jitter", default_value_t = 0)]
    pub jitter_ms: u64,

    /// Rotate evasion parameters per probe (TTL, source port, padding)
    #[arg(long = "rotate-evasion")]
    pub rotate_evasion: bool,

    /// Use overlapping IP fragments (advanced evasion, technique 2)
    #[arg(long = "frag-overlap")]
    pub frag_overlap: bool,

    /// Vault file path (encrypted credentials store)
    #[arg(long = "vault", default_value = "rustymap-vault.json")]
    pub vault_path: String,

    /// Add credential to vault: name=user:secret:kind[:note]
    #[arg(long = "vault-add")]
    pub vault_add: Option<String>,

    /// List credentials in vault (prompts for password)
    #[arg(long = "vault-list")]
    pub vault_list: bool,

    /// Remove credential by name from vault
    #[arg(long = "vault-remove")]
    pub vault_remove: Option<String>,

    /// Load scan profile from TOML (e.g. profiles/pci-lite.toml)
    #[arg(long = "profile")]
    pub profile: Option<String>,

    /// Repeat scan every N[s|m|h|d] (scheduling mode)
    #[arg(long = "every")]
    pub every: Option<String>,

    /// Start the web dashboard (reads from --db) and exit
    #[arg(long = "serve")]
    pub serve: bool,

    /// Address to bind web UI (default 127.0.0.1:8088)
    #[arg(long = "serve-addr", default_value = "127.0.0.1:8088")]
    pub serve_addr: String,

    /// Download and install Npcap runtime (requires admin on Windows)
    #[arg(long = "install-npcap")]
    pub install_npcap: bool,

    /// Force --sS to use the driver-less SO_LINGER=0 emulation path
    /// (auto-selected on Windows when Npcap is missing).
    #[arg(long = "syn-emulated")]
    pub syn_emulated: bool,

    /// Resume an interrupted scan by id (auto-loads original targets/ports/scan-type).
    /// Use 'last' to pick the most recent in-progress scan.
    #[arg(long = "resume", value_name = "ID|last")]
    pub resume: Option<String>,

    /// Drop IPv6 addresses from the target list after DNS resolution
    #[arg(long = "ipv4-only", conflicts_with = "ipv6_only")]
    pub ipv4_only: bool,

    /// Drop IPv4 addresses from the target list after DNS resolution
    #[arg(long = "ipv6-only", conflicts_with = "ipv4_only")]
    pub ipv6_only: bool,

    /// Run a traceroute against each up host (uses system tracert/traceroute)
    #[arg(long = "traceroute")]
    pub traceroute: bool,

    /// Max hops for --traceroute (default 20)
    #[arg(long = "trace-hops", default_value_t = 20)]
    pub trace_hops: u8,

    /// Write a Graphviz DOT topology file from traceroute results
    #[arg(long = "topology", value_name = "FILE")]
    pub topology: Option<String>,

    /// Sniff DNS queries/responses on local network (requires admin + Npcap)
    #[arg(long = "dns-sniff")]
    pub dns_sniff: bool,

    /// Spoof DNS responses: domain=ip (can repeat). Requires admin + Npcap.
    #[arg(long = "dns-spoof", value_name = "DOMAIN=IP")]
    pub dns_spoof: Vec<String>,

    /// DNS subdomain enumeration via brute-force
    #[arg(long = "dns-enum")]
    pub dns_enum: Option<String>,

    /// Wordlist file for --dns-enum (default: built-in ~100 words)
    #[arg(long = "dns-wordlist")]
    pub dns_wordlist: Option<String>,

    /// Reverse-DNS sweep over CIDR (e.g. 10.0.0.0/24)
    #[arg(long = "dns-reverse", value_name = "CIDR")]
    pub dns_reverse: Option<String>,

    /// Self-update to the latest release from GitHub
    #[arg(long = "update")]
    pub self_update: bool,

    /// Check for a newer release without installing
    #[arg(long = "check-update")]
    pub check_update: bool,

    /// Network interface name for dns-sniff/dns-spoof
    #[arg(long = "iface")]
    pub iface: Option<String>,

    /// Write HTML report (default built-in template)
    #[arg(long = "oH")]
    pub output_html: Option<String>,

    /// Write Markdown report (default built-in template)
    #[arg(long = "oMd")]
    pub output_markdown: Option<String>,

    /// Custom Tera template path for report (requires --oT)
    #[arg(long = "template")]
    pub template_path: Option<String>,

    /// Write custom-templated report to file (requires --template)
    #[arg(long = "oT")]
    pub output_template: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScanType {
    Connect,
    Syn,
    Fin,
    Null,
    Xmas,
    Ack,
    Udp,
    Idle,
}

impl Cli {
    pub fn scan_type(&self) -> ScanType {
        if self.scan_syn { ScanType::Syn }
        else if self.scan_fin { ScanType::Fin }
        else if self.scan_null { ScanType::Null }
        else if self.scan_xmas { ScanType::Xmas }
        else if self.scan_ack { ScanType::Ack }
        else if self.scan_udp { ScanType::Udp }
        else if self.scan_idle.is_some() { ScanType::Idle }
        else { ScanType::Connect }
    }

    pub fn effective_ports(&self) -> String {
        if self.all_ports || self.ports == "-" {
            "1-65535".to_string()
        } else {
            self.ports.clone()
        }
    }

    pub fn timeout(&self) -> std::time::Duration {
        let base = self.timeout_ms;
        let scaled = match self.timing {
            0 => base * 5,
            1 => base * 3,
            2 => base * 2,
            3 => base,
            4 => base / 2,
            5 => base / 4,
            _ => base,
        };
        std::time::Duration::from_millis(scaled.max(100))
    }

    pub fn parallel(&self) -> usize {
        match self.timing {
            0 => 10,
            1 => 50,
            2 => 150,
            3 => self.max_parallel,
            4 => self.max_parallel * 2,
            5 => self.max_parallel * 4,
            _ => self.max_parallel,
        }
    }
}
