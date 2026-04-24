# RustyMap

> λ Rust port of nmap for network exploration and security auditing.

Scan TCP/UDP, firewall evasion, OS fingerprinting, idle scan, service detection, CVE correlation, scripting (Rhai), Web UI, and more.

**[📥 Download · Sal1699.github.io/RustyMap](https://Sal1699.github.io/RustyMap/)**

---

## Download

| Platform | Architecture | File |
|---|---|---|
| Windows | x86_64 (MSVC) | [rustymap-windows-x86_64.zip](https://github.com/Sal1699/RustyMap/releases/latest/download/rustymap-windows-x86_64.zip) |
| Linux | x86_64 (glibc) | [rustymap-linux-x86_64.tar.gz](https://github.com/Sal1699/RustyMap/releases/latest/download/rustymap-linux-x86_64.tar.gz) |
| macOS | aarch64 (Apple Silicon) | [rustymap-macos-aarch64.tar.gz](https://github.com/Sal1699/RustyMap/releases/latest/download/rustymap-macos-aarch64.tar.gz) |

Checksums: [`SHA256SUMS.txt`](https://github.com/Sal1699/RustyMap/releases/latest) nella stessa release.

### One-liner install

**Linux / macOS**
```bash
curl -fsSL https://sal1699.github.io/RustyMap/install.sh | bash
```

**Windows (PowerShell)**
```powershell
iwr -useb https://sal1699.github.io/RustyMap/install.ps1 | iex
```

Options: `--prefix=<dir>` (sh) / `-Prefix <dir>` (ps1), `--version=v0.1.0` / `-Version v0.1.0`.

### Requirements

- **Windows**: [Npcap](https://npcap.com/) for real raw/SYN scans. Install via `rustymap.exe --install-npcap` (admin). `--sS` auto-falls-back to a SO_LINGER=0 emulation when Npcap is missing; force via `--syn-emulated`.
- **Linux**: `libpcap` (most distros already include it). Raw scans need `sudo` or `CAP_NET_RAW`.
- **macOS**: `libpcap` ships with the system. Raw scans need `sudo`.

### From source

```bash
git clone https://github.com/Sal1699/RustyMap.git
cd RustyMap
cargo build --release
./target/release/rustymap --guide
```

Requires Rust 1.70+ and `libpcap-dev` on Linux.

---

## Quick start

```bash
# TCP connect scan (no privileges)
rustymap --sT 10.0.0.0/24

# SYN stealth scan with Windows 11 fingerprint
rustymap --sS --evasion stealth --stack-profile windows11 10.0.0.5

# Full audit with HTML report + CVE correlation
rustymap --sS --sV -O --oH report.html --cve-db cves.json 10.0.0.0/24

# Idle (zombie) scan
rustymap --sI 192.168.1.250:80 10.0.0.5

# DNS subdomain enumeration
rustymap --dns-enum example.com

# Full command reference
rustymap --guide

# Copy-paste recipe book for common tasks
rustymap --examples
```

---

## Features

- **Scan types**: TCP connect (`--sT`), SYN (`--sS` + driver-less emulation fallback), FIN (`--sF`), NULL (`--sN`), Xmas (`--sX`), ACK (`--sA`), UDP (`--sU`), Idle/Zombie (`--sI`)
- **Host discovery**: ARP, ICMP echo (`--PE`), skip-discovery (`--Pn`), ping-only (`--sn`)
- **Firewall evasion**: fragmentation (with overlap), decoys (`-D`, `--decoy-random N`, `--decoy-preping`), custom TCP flags, stack profile emulation (Win11/Linux6/macOS/FreeBSD/Android14), jitter, per-probe rotation, bad checksum, padding, TTL jitter, custom payload (`--data-string`, `--data-hex`)
- **Evasion presets**: `--evasion stealth|aggressive|paranoid|ghost`
- **Service/version detection**: `--sV` with banner grab, active probes, and real TLS handshake (cert subject/issuer/SANs/expiry/key-bits on 443/465/636/853/993/995/5061/8443/9443)
- **OS fingerprinting + device class**: `-O` based on TTL + port/banner heuristics; auto-detects routers, IP cameras, printers, NAS, IoT
- **Output formats**: normal, grepable (`--oG`), JSON, HTML, Markdown, nmap-compatible XML (`--oX`), custom Tera templates; `-oA PREFIX` writes all six at once
- **Per-port reason**: `--reason` annotates each state with why (`syn-ack`, `rst`, `conn-refused`, `no-response`, `icmp-port-unreach`, …)
- **Database + diff**: SQLite history, `--diff` against previous scan, delta also embedded in HTML/Markdown reports
- **Scan resume**: `--resume <ID|last>` picks up an interrupted scan from the DB
- **Tags**: label hosts and ports for categorization
- **CVE correlation**: built-in 25-entry CVE regex DB baked into the binary; use `--cve-db` for custom; `--no-builtin-cves` to disable
- **Rhai scripting**: six built-in scripts (cleartext-protocols, default-cred-likely, old-openssh, smb-exposed, tls-cert-issues, tls-deprecated); `--script` for custom, `--script-arg K=V` for args
- **DNS tools**: enumeration with wildcard detection (`--dns-enum`), reverse sweep (`--dns-reverse`), sniffing (`--dns-sniff`), spoofing (`--dns-spoof`)
- **IPv6**: connect-scan, service probe, and TLS probe all work over v6. `--ipv4-only` / `--ipv6-only` filter after DNS resolution.
- **Traceroute + topology**: `--traceroute` wraps system tracert/traceroute; `--topology FILE` renders all paths as a Graphviz DOT graph
- **TUI browser**: `--tui` opens a two-pane ratatui UI for walking through scan results
- **Web UI**: `rustymap --serve` launches a local dashboard with scan history search
- **Target controls**: `--iL FILE`, `--exclude`, `--exclude-file`, `--top-ports N`, `--randomize-hosts`, `-R`/force-reverse-dns, `--host-timeout`, `--confirm-large` safety rail
- **Timing**: `-T0..T5` presets, `--max-rate PPS`, `--scan-delay`, `--adaptive` rate limiter, `--stats-every SEC` progress ticks
- **Credentials vault**: encrypted storage for pentest credentials
- **Scheduling**: `--every 1h` for recurring scans
- **Audit log**: JSONL log of every action with timestamps
- **Self-update**: `--check-update` / `--update` pulls the latest GitHub release

---

## License

MIT License. Use only on networks you are authorized to test.

_Rise and shine, Mr. Freeman..._
