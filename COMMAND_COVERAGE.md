# RustyMap — Command Test Coverage

Tracks which commands have been **validated in the lab against a reference
tool** vs. still untested, so the "continue testing" effort is systematic
instead of ad-hoc. This is the companion to `LAB_VALIDATION.md` (the dated
run log) — that file records *runs*, this one records *coverage*.

**Legend:** ✅ lab-validated vs reference · 🟡 partial / synthetic-only · ⬜ not yet lab-tested

Keep this in sync as new areas get a documented lab run. Reference the
`VALIDATION_*.md` report in the notes when you flip a cell to ✅.

---

## Scan types

| Command | Status | Reference | Note |
|---------|--------|-----------|------|
| `--sT` connect | ✅ | nmap | perf + correctness, many runs |
| `--sS` SYN (raw) | ✅ | nmap | byte-level + speed (v0.82) |
| `--sU` UDP | 🟡 | nmap | open\|filtered over-report (B20) |
| `--sA` / `--sW` / `--sM` | 🟡 | nmap | synthetic; direct-LAN run pending |
| `--sF` / `--sN` / `--sX` | 🟡 | nmap | Windows-RST hint verified |
| `--sO` IP-proto | ✅ | nmap | 213× faster (v0.82) |
| `--sI` idle | 🟡 | — | zombie-IPID guard verified (N1) |
| `--sY` / `--sZ` SCTP | ✅ | nmap | label + -Pn imply (v0.82) |
| `-b` FTP bounce | ⬜ | — | needs an FTP relay |
| `--quic` | ✅ | curl --http3 | QUIC v1 on Cloudflare (N12) |

## Host discovery

| Command | Status | Reference | Note |
|---------|--------|-----------|------|
| `--sn` ping sweep | ✅ | nmap | + `--oG` output (L5) |
| `--Pn` skip discovery | ✅ | nmap | L4/L6 |
| `--PE` ICMP echo | ✅ | nmap | fallback verified |
| `--PR` ARP | ✅ | nmap | retransmit fix (v0.82) |
| `--PS`/`--PA`/`--PU`/`--PY`/`--PM`/`--PO`/`--PP` | 🟡 | nmap | aliases; spot-checked |
| broadcast `--dhcp`/`--mdns`/`--llmnr`/`--wsdd`/`--nbt` | ⬜ | avahi | 0 responders in VM (N5) — env |

## Detection

| Command | Status | Reference | Note |
|---------|--------|-----------|------|
| `-sV` service/version | ✅ | nmap | SSH/DNS/SMB/RPC identical |
| `-O` OS fingerprint | ✅ | `nmap -O -d` | byte-identical field set |
| `--nmap-os-db` match | ✅ | `nmap -O` | probabilistic scorer |
| device fingerprint | 🟡 | — | gateway fix v0.84; cam/printer ok (L bonus) |
| IPv6 address intel | ✅ | — | no nmap equivalent |

## TLS / auth audit

| Command | Status | Reference | Note |
|---------|--------|-----------|------|
| `--tls-scan` version matrix + JARM | ✅ | pyjarm | byte-identical |
| `--ssl-enum` cipher enum | ✅ | sslscan | :443 8/8; exotic suites added v0.84 (L2) |
| `--tls-grade` | 🟡 | sslscan | grade coherent; promote → Prod pending |
| `--ssh-audit` | ✅ | nmap ssh2-enum | superior (weakness analysis) (N6) |
| `--smb-audit` | 🟡 | — | reject-path only; live-SMB negotiate untested (L3) |
| `--smtp-audit` | ⬜ | — | needs a mail host |

## Vulnerability checks

| Command | Status | Reference | Note |
|---------|--------|-----------|------|
| `--vuln-ssl-ccs` | ✅ | — | clear PATCHED/VULN verdict (N3) |
| `--vuln-ssl-dh` | ✅ | — | ECDHE-only coherent (N3) |
| `--vuln-known-key` | ✅ | — | SPKI match (N3) |
| `--vuln-ms17-010` | 🟡 | — | RST on firewalled Win11 (N3) |
| `--shellshock` | ✅ | — | no-vuln verdict (N3) |
| `--webdav-probe` | ✅ | — | PROPFIND verdict (N3) |
| `--http-enum` / `--web-scan` | ✅ | — | catch-all FP fixed; soft-404 (N3/A2) |
| `--owasp-scan` / `--csp-cors` / `--cms-detect` | ⬜ | — | needs a web app target |

## Credential bruteforce (gated by `--brute-confirm-authorized`)

| Command | Status | Reference | Note |
|---------|--------|-----------|------|
| `--brute-protocol ssh` | ✅ | hydra | rate + gate verified (N7) |
| ftp/smtp/http-basic/http-form/smb/mssql/mysql/postgres/vnc/rdp/snmp/ldap/telnet | ⬜ | hydra | turnkey command pairs in **HYDRA_PARITY.md** (v0.86.0) — run on Kali |

## Metasploit

| Command | Status | Reference | Note |
|---------|--------|-----------|------|
| `--msf-ping` | ✅ | msfrpcd | connected (N8) |
| `--msf-suggest` / `--msf-suggest-cve` | ✅ | msfconsole | EternalBlue 3 modules (A3/N8) |
| `--msf-import` | ✅ | msfconsole | host+svc in workspace; auto-create v0.84 (L1) |
| `--msf-fire` | 🟡 | msfconsole | auxiliary fired; safety gate (N8) |

## Output / interop

| Command | Status | Reference | Note |
|---------|--------|-----------|------|
| `--oN` / `--oG` / `--oJ` / `--oX` | ✅ | xmllint / jq | valid + parseable (N9/L5) |
| `--output-style rich\|terse` | 🟡 | — | new v0.84; smoke-tested on localhost |
| JSON `note`/`risk` enrichment | 🟡 | — | new v0.84; needs lab spot-check |
| `--oH` / `--oMd` reports | 🟡 | — | v0.86.0 enriched with version + risk-note + OS; render spot-check on real data pending |
| `--oP` PDF report | ⬜ | — | render untested on real data |
| `--oS` SIEM (CEF/LEEF/ECS) | ⬜ | — | exporter untested |

## Evasion

| Command | Status | Reference | Note |
|---------|--------|-----------|------|
| `-f` frag / `-D` decoy / `--source-port` / `--ip-ttl` / `--data-length` | ✅ | nmap | identical (N1, 6/7) |
| `--badsum` | 🟡 | nmap | no-ARP-with-badsum (correct, differs) (N1) |
| `--spoof-mac` | 🟡 | nmap | keyword syntax differs (N1) |
| `--evasion` presets / `--stack-profile` | 🟡 | — | synthetic |

## Exit codes / UX (v0.83–v0.84)

| Command | Status | Reference | Note |
|---------|--------|-----------|------|
| exit 0/1/2/3/130 | ✅ | — | 3/3 scenarios (L4) |
| `--profile` presets | 🟡 | — | load verified; full-run spot-check pending |
| `--color` / CI auto-detect | ✅ | — | pipe strip + force (v0.83) |
| `-v`/`-vv`/`-vvv` | 🟡 | — | tiers wired; reason-at-`-v` new v0.84 |
| `--self-test` | 🟡 | — | new v0.84 smoke net |
| `--recommend` | 🟡 | — | lab-informed rebuild v0.84 |

## Not yet exercised at all (priority backlog for testing)

- **Specialized**: `--ics-scan` (Modbus/S7/DNP3), `--iot-discover` (0 responders in VM), `--container-scan`
- **Mobile**: `--apk-scan`, `--ipa-scan`
- **Cloud**: `--cloud-buckets`, `--cloud-metadata`, `--cloud-fingerprint`
- **DNS/web depth**: `--dns-security`, `--web-crawl`, `--owasp-scan`, subdomain-takeover
- **Reporting**: `--oH`/`--oMd`/`--oP`, `--compliance-report`, `--exec-summary` on real data
- **Workflow**: `--wizard`, `--webui`, `--tui`, `--baseline`/`--diff-against` at scale, `--threat-intel-misp`, vault

---

*Last updated: v0.86.0 (2026-10-10). Flip cells to ✅ only with a dated
`LAB_VALIDATION.md` row + a `VALIDATION_*.md` reference.*
