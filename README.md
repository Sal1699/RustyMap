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
| macOS | x86_64 (Intel) | [rustymap-macos-x86_64.tar.gz](https://github.com/Sal1699/RustyMap/releases/latest/download/rustymap-macos-x86_64.tar.gz) |
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

- **Windows**: [Npcap](https://npcap.com/) for raw/SYN scans. Install via `rustymap.exe --install-npcap` (admin).
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

# Full command reference with examples
rustymap --guide
```

---

## Features

- **Scan types**: TCP connect (`--sT`), SYN (`--sS`), FIN (`--sF`), NULL (`--sN`), Xmas (`--sX`), ACK (`--sA`), UDP (`--sU`), Idle/Zombie (`--sI`)
- **Host discovery**: ARP, ICMP echo, skip-discovery mode, ping-only mode
- **Firewall evasion**: fragmentation (with overlap), decoys, custom TCP flags, stack profile emulation (Win11/Linux6/macOS/FreeBSD/Android14), jitter, per-probe rotation, bad checksum, padding
- **Evasion presets**: `--evasion stealth|aggressive|paranoid`
- **Service/version detection**: `--sV` with banner grab and active probes
- **OS fingerprinting**: `-O` based on TTL + port/banner heuristics
- **Output formats**: normal, grepable, JSON, HTML, Markdown, custom Tera templates
- **Database**: SQLite history with scan diffing
- **Tags**: label hosts and ports for categorization
- **CVE correlation**: match service banners against a CVE database JSON
- **Scripting**: Rhai scripts for custom rules
- **DNS tools**: enumeration (brute-force), sniffing, spoofing (admin + Npcap)
- **Web UI**: `rustymap --serve` launches a local dashboard
- **Credentials vault**: encrypted storage for pentest credentials
- **Scheduling**: `--every 1h` for recurring scans
- **Audit log**: JSONL log of every action with timestamps

---

## License

MIT License. Use only on networks you are authorized to test.

_Rise and shine, Mr. Freeman..._
