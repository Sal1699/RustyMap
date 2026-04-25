use clap::{Parser, ValueEnum};
use clap_complete::Shell;

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

    /// TCP Window scan — like ACK but examines RST window value
    #[arg(long = "sW", group = "scan_type")]
    pub scan_window: bool,

    /// TCP Maimon scan — FIN+ACK probe (BSD-derived stacks)
    #[arg(long = "sM", group = "scan_type")]
    pub scan_maimon: bool,

    /// List scan — resolve targets (with PTR/AAAA) and exit, no probing
    #[arg(long = "sL", group = "scan_type")]
    pub scan_list: bool,

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
    #[arg(short = 'D', long = "decoys")]
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

    /// Open a TUI results browser after the scan completes
    #[arg(long = "tui")]
    pub tui: bool,

    /// Exclude these IPs/CIDRs/ranges from scanning (can repeat, comma-list ok)
    #[arg(long = "exclude", value_name = "SPEC")]
    pub exclude: Vec<String>,

    /// File with one host/CIDR/range per line to exclude
    #[arg(long = "exclude-file", value_name = "FILE")]
    pub exclude_file: Option<String>,

    /// Aggressive scan: implies --sV -O --traceroute and runs scripts/ if present
    #[arg(short = 'A', long = "aggressive")]
    pub aggressive: bool,

    /// Scan the N most common ports (overrides -p when set)
    #[arg(long = "top-ports", value_name = "N")]
    pub top_ports: Option<usize>,

    /// Annotate each port with the reason for its state (syn-ack, conn-refused, no-response…)
    #[arg(long = "reason")]
    pub reason: bool,

    /// Randomize the host scan order
    #[arg(long = "randomize-hosts")]
    pub randomize_hosts: bool,

    /// Write all output formats with this filename prefix (.txt .gnmap .json .html .md)
    #[arg(long = "oA", value_name = "PREFIX")]
    pub output_all: Option<String>,

    /// Force reverse DNS lookup on every target IP (even those given as IPs)
    #[arg(short = 'R', long = "force-reverse-dns")]
    pub force_reverse_dns: bool,

    /// Give up on a host after N seconds (0 = no timeout)
    #[arg(long = "host-timeout", default_value_t = 0u64)]
    pub host_timeout_secs: u64,

    /// Print scan progress every N seconds (0 = off)
    #[arg(long = "stats-every", default_value_t = 0u64)]
    pub stats_every_secs: u64,

    /// Append this ASCII string as payload on probe packets (raw scans)
    #[arg(long = "data-string", value_name = "STR")]
    pub data_string: Option<String>,

    /// Append this hex blob as payload on probe packets (e.g. deadbeef)
    #[arg(long = "data-hex", value_name = "HEX")]
    pub data_hex: Option<String>,

    /// Pass an argument to Rhai scripts (e.g. --script-arg key=val, repeatable)
    #[arg(long = "script-arg", value_name = "KEY=VAL")]
    pub script_args: Vec<String>,

    /// List recorded scans from the SQLite database and exit
    #[arg(long = "list-scans")]
    pub list_scans: bool,

    /// Show only open ports (suppress closed/filtered even when -v is set)
    #[arg(long = "open")]
    pub only_open: bool,

    /// Read targets from a file (one per line, # comments ok)
    #[arg(long = "iL", alias = "input-list", value_name = "FILE")]
    pub input_list: Option<String>,

    /// Write nmap-compatible XML output to file
    #[arg(long = "oX", value_name = "FILE")]
    pub output_xml: Option<String>,

    /// Generate N random decoy source IPs (in addition to --decoys)
    #[arg(long = "decoy-random", value_name = "N", default_value_t = 0)]
    pub decoy_random: u8,

    /// Cap probe throughput to N packets/sec (0 = unlimited)
    #[arg(long = "max-rate", value_name = "PPS", default_value_t = 0)]
    pub max_rate: u32,

    /// Skip the CVE database baked into the binary (only use --cve-db)
    #[arg(long = "no-builtin-cves")]
    pub no_builtin_cves: bool,

    /// Skip the rhai scripts baked into the binary (only use --script)
    #[arg(long = "no-builtin-scripts")]
    pub no_builtin_scripts: bool,

    /// Print common usage recipes and exit
    #[arg(long = "examples")]
    pub examples: bool,

    /// Allow target lists larger than 4096 hosts without prompting
    #[arg(long = "confirm-large")]
    pub confirm_large: bool,

    /// Print shell completion script and exit (bash | zsh | fish | powershell | elvish)
    #[arg(long = "completions", value_name = "SHELL")]
    pub completions: Option<Shell>,

    /// Log every raw TCP send/recv (useful for debugging --sS on Linux)
    #[arg(long = "trace-raw")]
    pub trace_raw: bool,

    /// Bluetooth LE scan: listen for BLE advertisements for N seconds and exit
    #[arg(long = "ble-scan", value_name = "SECONDS")]
    pub ble_scan: Option<u64>,

    /// List network interfaces (with route-to-target hint when target given) and exit
    #[arg(long = "iflist")]
    pub iflist: bool,

    /// List built-in and user-provided rhai scripts with descriptions and exit
    #[arg(long = "script-help")]
    pub script_help: bool,

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
    Window,
    Maimon,
    List,
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
        else if self.scan_window { ScanType::Window }
        else if self.scan_maimon { ScanType::Maimon }
        else if self.scan_list { ScanType::List }
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
