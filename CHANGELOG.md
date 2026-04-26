# Changelog

All notable changes to RustyMap are recorded here.
Versioning policy: `0.MINOR.PATCH` until the 1.0 stable cut. MINOR adds
functionality, PATCH fixes bugs or cleans up internals.

## [0.34.0] - 2026-04-26
- Service-probe SIGS grew from 50+ to 90+ rules. Added curated
  signatures for software actually deployed in 2025/26 networks
  (patterns cross-referenced against public nmap-service-probes
  PRs, HackTricks service-detection notes, and Wappalyzer
  fingerprints):
  - **NewSQL/modern DBs**: CockroachDB, TiDB, YugabyteDB, ClickHouse,
    ScyllaDB, Neo4j, InfluxDB
  - **Streaming/MQ**: Apache Kafka, Pulsar, RocketMQ
  - **Observability**: Grafana Loki, Tempo, Mimir, VictoriaMetrics,
    Thanos, OpenTelemetry Collector
  - **Identity/auth**: Authelia, Authentik, Keycloak, ZITADEL
  - **HashiCorp stack**: Vault, Consul, Nomad
  - **Modern proxies/runtimes**: Cloudflare Pingora, Bun, Deno
  - **Self-hosted dashboards**: Metabase, Superset, Airflow,
    Argo CD, Portainer, Pi-hole, Home Assistant, Nextcloud,
    Matrix Synapse, Mastodon
  - **Networking/mesh**: Tailscale DERP relay, Headscale
  - **Backup/storage**: restic-server
- Patterns improved over upstream nmap variants where Rust regex
  let us simplify (e.g. ClickHouse via X-ClickHouse-Server-Display-Name
  header is a single anchor; nmap chains 3 fallback regexes for the
  same).

## [0.33.0] - 2026-04-26
- IPv6 OS detection: `ping_ttl()` now auto-selects `ping -6` (Linux/
  Windows/macOS modern) and falls back to `ping6(1)` on older Linux.
  TTL_RE regex extended to also capture `hlim=`, `hop_limit=`, `hops=`
  formats emitted by the various ping(8) variants. The IPv4 family
  heuristic (TTL 64=*nix, 128=Windows, 255=network gear) maps 1-to-1
  to IPv6 hop-limit, so OS family guessing now works on both stacks.
- OS banner DB grew from 60+ to 100+ rules. Curated additions cover
  modern targets only — no Win 95/2000/XP, no Solaris ≤9, no IRIX:
  - Modern immutable Linux: Talos, Flatcar, Bottlerocket, Photon OS,
    NixOS
  - Pentest/desktop: Kali, Mint, Manjaro, Pop!_OS, EndeavourOS
  - Network/VPN appliances: VyOS, OpenVPN AS, WireGuard, Tailscale,
    Headscale, Sophos UTM, Amazon eero, OpenBMC, Vyatta
  - Container/k8s flavors: k3s, k0s, Rancher, OpenShift, Podman,
    CRI-O, containerd
  - Self-hosted services that define the host's role: Pi-hole,
    Home Assistant OS, Tasmota, ESPHome, OctoPrint, openHAB,
    Nextcloud, ownCloud, Vaultwarden, Bitwarden, Matrix Synapse,
    Mastodon, Forgejo, MinIO, Varnish, HAProxy, Linkerd, Wazuh,
    Graylog, Splunk

## [0.32.0] - 2026-04-26
- `--nmap-os-db FILE`: load nmap's nmap-os-db at runtime. Parser
  extracts `Fingerprint` / `Class` / `CPE` blocks (the binary
  TCP/IP probe data is skipped — implementing nmap's probe engine
  would be a project on its own). When a banner matches a curated
  fingerprint name, our family label is upgraded to nmap's exact
  string (e.g. "Linux 4.15 - 5.6") plus the CPE.
- `--nmap-service-probes FILE`: load nmap's nmap-service-probes.
  Parses `match` and `softmatch` lines as `Signature` rules.
  Rust regex handles ~80% of nmap's patterns out of the box; lines
  using Perl-only constructs (lookahead, named-group syntax) are
  silently skipped. Counter goes to stderr at startup.
- Both files stay on the user's disk — no GPLv2 contamination of
  the MIT source tree. Match rules append to our built-in SIGS, so
  user-loaded probes run only when our curated list missed.
- 4 new unit tests on the parsers → 51/51.

## [0.31.0] - 2026-04-26
- Built-in rhai script library grew from 6 to 21. The new scripts
  cover common NSE patterns most pentesters reach for first:
  - `anonymous-ftp` — FTP banner suggests anonymous login
  - `dns-zone-transfer-hint` — DNS port reachable, suggest AXFR test
  - `docker-api-exposed` — Docker daemon on 2375 (cleartext) / 2376
  - `elasticsearch-open` — ES/Kibana reachable without auth
  - `exposed-management` — flags 15 mgmt-plane ports (Vault, Consul,
    Nomad, WinRM, JBoss, GlassFish, ActiveMQ, Cockpit, Grafana, …)
  - `http-admin-paths` — HTTP banner exposes admin/login/manager
  - `ipmi-exposed` — IPMI 623, BMC console KVM-over-IP
  - `jenkins-anonymous` — Jenkins reachable, anyone-can-do-anything
    risk
  - `k8s-api-exposed` — k8s API/kubelet/etcd reachable
  - `mongodb-no-auth` — MongoDB without --auth
  - `mqtt-anonymous` — MQTT broker on 1883/8883/8083
  - `mssql-default` — MSSQL on 1433/1434
  - `redis-no-auth` — Redis without requirepass
  - `snmp-public` — SNMP exposed
  - `vnc-no-auth` — VNC RFB protocol weak by default
- All 15 new scripts run alongside the existing 6 — no flag needed.
  Disable with `--no-builtin-scripts`.

## [0.30.0] - 2026-04-26
- Built-in OS-fingerprint DB grew from 6 banner rules to 60+:
  Linux distros (Ubuntu/Debian/RHEL/Amazon/Alpine/Arch/Fedora/SUSE/
  Oracle/Rocky/Alma/OpenWrt/DD-WRT/Synology/QNAP/Raspbian), BSD
  family (FreeBSD/OpenBSD/NetBSD/DragonFly/pfSense/OPNsense), Windows
  variants (NT/2016/2019/2022/Exchange/IIS/HTTPAPI), Apple
  (macOS/Darwin/iOS), network gear (Cisco IOS/IOS-XE/IOS-XR/NX-OS/ASA/
  WLC, Juniper Junos, MikroTik RouterOS, Ubiquiti EdgeOS/UniFi,
  Fortinet FortiOS/FortiGate, Palo Alto PAN-OS/GlobalProtect,
  SonicWall, Citrix NetScaler, F5 BIG-IP, Check Point), hypervisors
  (ESXi/vSphere/vCenter/XenServer/Proxmox), commercial UNIX
  (Solaris/SmartOS/HP-UX/AIX/OS400/zOS), embedded RTOS
  (VxWorks/FreeRTOS/Contiki/RIOT), storage appliances (NetApp
  ONTAP/Dell Isilon/PowerStore).
- Port-pattern refinement gained 15+ new combos: Active Directory
  DC (88+389+445+636), Hyper-V host (2179), VMware mgmt (902/5480),
  MikroTik Winbox (8291), VPN endpoint (500+4500), L2TP/PPTP, ADB
  Android (5555), iOS lockdown (62078), Chromecast (8009/8008/8443),
  ICS protocols (S7/Modbus/DNP3/EtherNet-IP/BACnet), container
  runtimes (Docker 2375/76, Kubernetes 6443, kubelet 10250, etcd).
- Service-probe SIGS grew from 17 to 50+ rules: more web servers
  (OpenResty/Tengine/Tomcat/Jetty/Werkzeug/Gunicorn/Uvicorn/Hypercorn/
  Envoy/Traefik/Cowboy/Kestrel), caches/MQ (memcached/RabbitMQ/NATS/
  MQTT), DBs (PostgreSQL/MSSQL/CouchDB/Elasticsearch/Cassandra/
  ZooKeeper), container daemons (Docker/k8s API/etcd), monitoring
  (Prometheus/Grafana/Kibana), DevOps (Jenkins/GitLab/Gitea/Nexus/
  Artifactory), remote access (RDP/VNC/NoMachine), hypervisor mgmt
  (ESXi/Proxmox), ICS (Siemens/Modicon), embedded HTTP daemons.

Improvement vs nmap: nmap's nmap-os-db ships ~5000 fingerprints
under GPLv2 — incompatible with our MIT license. The expanded
built-in DBs are curated from public banner research and OUI lists.
For users who own a copy of nmap's DBs, --nmap-os-db FILE and
--nmap-service-probes FILE will arrive in a follow-up to load them
at runtime without source-tree contamination.

## [0.29.0] - 2026-04-26
- Web technology fingerprinting (Wappalyzer-style). New `web_fp`
  module re-examines the HTTP body+headers fetched by `vendor_probe`
  against ~30 detection rules covering:
  - **CMS**: WordPress, Drupal, Joomla, Magento, Shopify, Ghost
  - **Frameworks**: Next.js, Express, Django, Laravel, Rails, Spring
  - **JS libraries**: jQuery, React, Vue.js, Angular, Bootstrap (with
    version when extractable)
  - **CDN**: Cloudflare, Akamai, Fastly, AWS CloudFront
  - **Cloud / hosting**: AWS, Azure, Google Cloud
  - **Web servers**: Apache Tomcat, OpenResty, Caddy, Lighttpd
  - **Analytics**: Google Analytics, Matomo
  - **WAF**: ModSecurity, Sucuri
  Surfaces as a single `tech: …` line in `device.hints` so the
  console/HTML/JSON reports get a Wappalyzer-equivalent readout next
  to the cert and vendor info.
- 5 new web_fp tests → 47/47.

## [0.28.0] - 2026-04-25
Final nmap-parity batch — eight features:
- `--version-light` / `--version-all`: aliases for `--version-intensity 2`
  and `9` respectively.
- `--PP`: ICMP timestamp ping (type 13). Used as a fallback when `--PE`
  echo is filtered. Combine: `--PE --PP` tries echo then timestamp.
- `-e` / `--iface-scan`: bind scan to a specific NIC (used by `--PR` ARP
  and `--spoof-mac`).
- `--script-args-file FILE`: load `key=val` pairs from a file (one per
  line, `#` comments). Pairs append to anything from `--script-arg`.
- `--osscan-limit`: skip `-O` on hosts with no Open/Closed/Unfiltered
  ports — saves time on heavily-firewalled silent hosts.
- `--max-scan-delay MS`: clamps `--scan-delay` to a ceiling.
- `--proxies socks5://h:p,http://h:p,…`: tunnel every TCP-connect probe
  through a chain. New `proxy` module implements SOCKS5 (with SOCKS5h
  semantics — DNS resolution at the proxy, no leak from the scanner)
  and HTTP CONNECT. Hops walked in order; each tunnels to the next.
- `--spoof-mac MAC|VENDOR`: change the NIC's MAC before scanning. New
  `spoof_mac` module accepts a literal MAC, `random` (locally-administered),
  or a vendor alias (`vmware`/`vbox`/`qemu`/`apple`/`samsung`/`cisco`/
  `huawei`/`hp`/`intel`/`raspberry`) which generates a random MAC inside
  that vendor's OUI. Linux uses `ip link`, macOS uses `ifconfig`,
  Windows returns a clear error pointing at the registry workaround.

8 new unit tests (4 spoof_mac + 3 proxy + 1 retry path) → 42/42 green.

## [0.27.1] - 2026-04-25
- Clippy cleanup: drop redundant `unwrap()` after `is_some` guard in
  iflist; replace `None::<Regex>.unwrap_or_else(|| ...)` with the
  direct regex in vendor_probe (Foscam model rule); use VendorHint
  initializer instead of mutating after `Default::default()`; fix
  `print_literal` in -sL header.
- No behavior change. Build remains warning-free.

## [0.27.0] - 2026-04-25
- `-sO`: IP protocol scan. New `ip_proto_scan` module probes 15
  IANA-listed protocols (TCP/UDP/ICMP/IGMP/GRE/ESP/AH/OSPF/PIM/SCTP
  /L2TP/IPv6 etc.). Each result row includes the protocol name,
  RFC, and a one-line common-usage hint — turns a router scan into
  a quick reference.
- `-S IP` / `--source-ip`: source-address spoofing on raw scans.
  Improvement vs nmap: warns (does not error) when the spoofed IP
  is not in any local subnet — replies will go to that IP and
  never reach us, so it's only useful for blind probes / decoy
  padding.
- `--ip-options SPEC`: insert IPv4 options into the raw header.
  Accepts named forms (`record-route`, `timestamp`, `lsrr IP1,IP2`,
  `ssrr IP1,IP2`) plus raw hex. NOP-padded to a 4-byte boundary;
  IHL bumped automatically. EvasionConfig.is_active /
  needs_layer3 now also true when these are set.

## [0.26.0] - 2026-04-25
- `-d` / `--debug` (repeatable): tagged debug logging. Each line is
  prefixed with a category — `[net]`, `[probe]`, `[parse]`, `[scan]`,
  `[evasion]`, `[script]` — so you can filter with `2>&1 | rg '^\[probe\]'`.
- `--script-trace`: emit one JSON Line per script-host execution
  (start / done / parse_error / runtime_error). Pipeable into `jq`.
- `--append-output`: writers (`-oN`/`-oG`/`-oJ`/`-oH`/`-oMd`/`-oX`)
  append instead of truncating. Useful for cron-driven scans that
  build a single rolling artifact.
- `--max-retries N`: connect-scan retries filtered ports up to N times.
  Only reissues on Filtered (timeouts) — Open and Closed are terminal.

## [0.25.0] - 2026-04-25
- `-F` / `--fast`: alias for `--top-ports 100`. Trivial nmap-compat.
- `-r` / `--no-randomize-ports`: explicit override that disables port
  shuffling even when `--randomize-ports` is enabled by a profile.
- `--exclude-ports SPEC`: drop matching ports from the list. Accepts
  numeric ranges AND a small alias table covering pentester-friendly
  names: ssh, smb, rdp, web, http, https, mail, dns, ftp, ldap, vnc,
  telnet, vpn, db, ics. Improvement over nmap: nmap requires exact
  service names from /etc/services.
- `--version-intensity N` (0-9, default 5): probe aggressiveness.
  Below 7 the TLS deep-handshake is skipped — halving service-probe
  time on hosts with many TLS ports. Pass 7+ to bring it back.
- `--PR`: ARP discovery for LAN targets. New `arp_ping` module sends
  ARP requests via pnet datalink and listens for replies; on LAN this
  is dramatically faster than TCP/ICMP ping. Auto-detects when a
  target sits in the same /24 as a local interface.
- `--PS [PORTS]` / `--PA [PORTS]` / `--PU [PORTS]`: nmap-compatible
  ping aliases. Currently route through the existing TCP-ping
  discovery path (the port list is what differentiates them in
  practice; raw SYN/ACK/UDP probes for discovery are deferred).

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
