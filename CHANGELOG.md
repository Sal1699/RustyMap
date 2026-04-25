# Changelog

All notable changes to RustyMap are recorded here.
Versioning policy: `0.MINOR.PATCH` until the 1.0 stable cut. MINOR adds
functionality, PATCH fixes bugs or cleans up internals.

## [0.24.0] - 2026-04-25
- `--sW` TCP Window scan: ACK probe; classifies open/closed by the RST
  reply's TCP window value (open ports return non-zero on most stacks).
- `--sM` TCP Maimon scan: FIN+ACK probe; BSD-derived stacks drop on
  open ports and RST on closed.
- `--sL` list scan: resolve targets with PTR + family annotation, no
  probe traffic at all. Improves on nmap's `-sL` by also showing the
  reverse-DNS line and IPv4/IPv6 family for each address.
- `--iflist [TARGET]`: list local network interfaces with a route-to-
  target arrow when a target is given. Better than nmap's flat list —
  shows which adapter would be used for a specific destination.
- `--script-help`: print the catalog of built-in (and user) rhai
  scripts with the description parsed from each script's first comment
  line.

## [0.23.0] - 2026-04-24
- `--guide` reorganization: prepended a TOC and grouped all 16
  sections under 8 visual categories (ESSENTIALS, SCAN, EVASION &
  STEALTH, OUTPUT & PERSISTENCE, DNS & NETWORK INSPECTION,
  AUTOMATION & TOOLING, EXTENSIONS, MAINTENANCE) so 50+ flags are
  easier to navigate.
- TOC also surfaces a "rustymap --examples" tip at the top.

## [0.22.0] - 2026-04-24
- `--ble-scan SECONDS`: discover nearby Bluetooth LE devices and report
  address / RSSI / inferred class (phone, wearable, HID, …) / advertised
  services. Cross-platform: bluez D-Bus on Linux, WinRT on Windows,
  Core Bluetooth on macOS. Catches phones, smart watches, fitness
  trackers, and BLE IoT gadgets that never appear on the IP layer.
- Mobile device detection on the IP layer: 24 mobile-vendor OUIs
  (Xiaomi, Huawei, Motorola, Google Pixel, OnePlus, Oppo, Vivo, Nokia,
  NVIDIA Shield) classify hosts as `MobileDevice` when no typical
  desktop/server ports are open.
- ADB on port 5555 is now flagged as Android debug port (high
  confidence MobileDevice class).

## [0.21.0] - 2026-04-24
- Linux --sS diagnostics: when the raw TCP scanner runs a full scan and
  the receiver loop saw zero packets, print a platform-specific hint
  about iptables/conntrack dropping unsolicited SYN-ACK as INVALID, the
  exact `iptables -I INPUT ...` rule to allow it, and the --sT fallback.
- `--trace-raw`: log every raw TCP send/receive to stderr. Useful for
  confirming whether packets leave the NIC and whether replies come
  back — answers "kernel or network" when --sS returns only filtered.
- Privilege hint rewritten per-platform: Linux now surfaces the
  `setcap cap_net_raw,cap_net_admin=eip` durable fix alongside sudo,
  macOS explains BPF device ownership, Windows mentions --syn-emulated.

## [0.20.0] - 2026-04-24
- Deep vendor/model/firmware probe: when --sV is on and an HTTP-ish
  port (80/8080/8000/8443/443/81/8081/8888) is open, does a short GET /
  and pattern-matches against 19 vendor rules — Hikvision, Dahua, Axis,
  Reolink, Foscam, HP, Brother, Canon, Epson, MikroTik, Ubiquiti,
  TP-Link, Netgear, ASUS, Synology, QNAP, Cisco, Fortinet, pfSense,
  OPNsense. Extracts title, Server header, vendor name, model number,
  firmware version.
- `DeviceGuess.firmware` field added; surfaced in console output,
  HTML/Markdown reports, and JSON schema.

## [0.19.0] - 2026-04-24
- `--completions SHELL`: generate shell completion scripts (bash, zsh,
  fish, powershell, elvish). Pipe into the matching rc file:
  `rustymap --completions bash > /etc/bash_completion.d/rustymap`.

## [0.18.0] - 2026-04-24
- Safety rail: target lists larger than 4096 hosts are rejected unless
  `--confirm-large` is passed. Prevents accidental `-p- /16` scans that
  would eat hours.
- Better DNS failure hints: distinguishes unreachable resolver,
  NXDOMAIN, and missing A/AAAA, and suggests the right fix.

## [0.17.0] - 2026-04-24
- `--examples`: new recipe book of 16 copy-paste starting points for
  common recon/pentest tasks.
- `-D` alias for `--decoys` (nmap-standard short form).
- CHANGELOG.md now shipped with the repo.

## [0.16.0] - 2026-04-24
- Embed `data/cves.json` and all six scripts from `scripts/` in the binary
  via `include_str!`, so a fresh release works stand-alone with useful
  defaults.
- CVE correlation and built-in scripts now run automatically when the
  user doesn't pass `--cve-db` / `--script`.
- Opt-out flags: `--no-builtin-cves`, `--no-builtin-scripts`.
- Drop the explicit `rustls-pki-types` dependency (re-exported by
  `rustls::pki_types`).

## [0.15.1] - 2026-04-24
- Migrate `trust-dns-resolver` → `hickory-resolver 0.24` — closes
  RUSTSEC-2024-0421 (idna Punycode advisory).
- Add 30 unit tests covering `parse_ports`, `top_ports::top`,
  `traceroute::parse_hop_line`, `xml_out::escape`, `output::reason_for`.
- Fix: port 5101 duplicated in `TOP_200` (caught by the new test).
- Clippy cleanup: `ScanMeta` type alias, suppress too-many-args on
  `run_syn_emulated`, drop redundant `&ref` binding, switch to
  `.is_multiple_of()`.

## [0.15.0] - 2026-04-23
- `--iL FILE`: read targets from a file (one per line, # comments ok).
- `--oX FILE`: nmap-compatible XML output (subset of xmloutputversion
  1.05 schema). `-oA` also writes `.xml`.
- `--decoy-random N`: append N random non-private decoy IPs.
- `--max-rate PPS`: approximate per-host packet cap via
  `scan_delay = 1000/PPS ms` when no explicit delay was set.

## [0.14.0] - 2026-04-23
- `--stats-every SEC`: periodic scan progress events.
- `--data-string STR` / `--data-hex HEX`: custom payload on raw probes
  (overrides random padding from `--data-length`).
- `--script-arg KEY=VAL`: repeatable arguments forwarded to Rhai scripts
  as the global `args` map.
- `--list-scans`: dump the SQLite scan history and exit.
- `--open`: filter output to open ports only, even with `-v`.

## [0.13.0] - 2026-04-23
Major nmap parity batch:
- `--exclude SPEC` / `--exclude-file FILE`: drop IPs/CIDRs from targets.
- `-A` / `--aggressive`: shortcut for `--sV -O --traceroute` and
  auto-loads `scripts/`.
- `--top-ports N`: scan the N most common TCP ports.
- `--reason`: per-port reason annotation (`syn-ack`, `rst`,
  `conn-refused`, `no-response`, `icmp-port-unreach`, `udp-response`).
- `--randomize-hosts`: shuffle target order.
- `--oA PREFIX`: write all output formats with one flag.
- `-R` / `--force-reverse-dns`: PTR every target IP.
- `--host-timeout SEC`: per-host deadline (TCP connect path).

## [0.12.0] - 2026-04-23
- Rework `web/index.html`: live filter on scans list, colour-coded
  status badges, per-scan summary stats, hosts sorted by # open ports,
  mobile-friendly layout, HTML escaping on user-controlled fields.

## [0.11.0] - 2026-04-23
- `--tui`: two-pane ratatui results browser (host list + per-host
  detail with ports, services, TLS info). Navigate with ↑↓/jk/PgUp/PgDn,
  `q` or Esc to exit.

## [0.10.0] - 2026-04-23
- Surface scan diff in HTML/Markdown reports (`newly open`, `no-longer
  open`, per-port state transitions). Custom Tera templates can read
  `host.diff.{new_open, closed_now, state_changes}`.

## [0.9.0] - 2026-04-23
- `--traceroute`: shell out to system `tracert`/`traceroute`, parse the
  hop table, print it inline.
- `--topology FILE`: render all trace paths as a Graphviz DOT graph.
- `--trace-hops N`: max TTL (default 20).

## [0.8.0] - 2026-04-23
- `DnsEnumReport.base_a` / `base_aaaa` split explicitly; AAAA shows up
  in `--dns-enum` even when system routing hides v6.
- `--ipv4-only` / `--ipv6-only`: filter resolved targets per family.
- Connect-scan, service probe, and TLS probe were already
  `IpAddr`-generic and work transparently over IPv6.

## [0.7.0] - 2026-04-23
- `data/cves.json`: 25 well-known CVEs with regex matching (Heartbleed,
  Shellshock, vsftpd 2.3.4 backdoor, EternalBlue, BlueKeep, Log4Shell,
  regreSSHion, Spring4Shell, ProxyLogon, FortiOS CVE-2024-21762, …).
- `scripts/`: six rhai scripts — `smb-exposed`, `tls-deprecated`,
  `tls-cert-issues`, `cleartext-protocols`, `default-cred-likely`,
  `old-openssh`.
- Rhai engine now exposes `service.tls.{negotiated, subject, issuer,
  not_after, self_signed, expired, key_bits, san}` for cert-aware
  scripts.

## [0.6.0] - 2026-04-23
- Real TLS handshake on TLS-likely ports (443, 465, 636, 853, 993, 995,
  5061, 8443, 9443) via rustls, cert parsing via x509-parser. Surfaces
  negotiated protocol version, subject DN, issuer, SANs, validity,
  key bits, self-signed/expired flags.
- SNI uses the target hostname when known so vhost-fronted servers
  return their real cert.

## [0.5.0] - 2026-04-22
- `--resume <ID|last>`: pick up an interrupted scan from SQLite. Saved
  scan-type/targets/ports are reapplied; hosts already persisted are
  skipped; new results land under the same scan id.
- DB additions: `scan_meta`, `completed_hosts`, `latest_incomplete`.

## [0.4.0] - 2026-04-22
- `--sS` driver-less fallback on Windows when Npcap is missing: uses
  SO_LINGER=0 so `close()` emits RST instead of FIN/ACK teardown.
- `--syn-emulated`: force the emulated path explicitly.

## [0.3.1] - 2026-04-22
- Clean up all 20 clippy warnings: type aliases in `db.rs`, while-let
  conversions in raw packet receiver loops, `.clamp()` over
  `.min().max()`, `Default` derive on `JitterMode`, allow attrs for
  legitimately many-arg scan entry points.

## [0.3.0] - 2026-04-18
- Built-in self-updater: `--update` fetches the latest GitHub release,
  verifies the archive, and replaces the current binary in place.
- `--check-update`: read-only version check against the GitHub API.

## [0.2.0] - 2026-04-18
- Device classification (auto-detect routers, IP cameras, printers,
  NAS, IoT) via MAC OUI + port patterns + banner heuristics.
- DNS enum improvements: wildcard detection, AXFR, reverse DNS, CT
  logs awareness.
- Firewall evasion: TCP timestamps, decoy pre-ping, TTL jitter, new
  `ghost` preset.

## [0.1.1] - pre-0.2
- Windows console fix: enable VT processing and UTF-8 codepage on
  startup so colour output and unicode box-drawing render correctly.

## [0.1.0] - initial
Initial release: TCP connect, SYN (raw), FIN/NULL/Xmas, ACK, UDP,
idle-scan, ICMP ping, service probes, OS fingerprinting, SQLite
persistence, HTML/Markdown/JSON output, rhai scripting engine, CVE
correlation framework, web dashboard, evasion preset system.
