# RustyMap — Kali Test Roadmap

Consolidated, runnable test plan for the Kali lab: everything still to confirm
on real hardware, from the accumulated "needs Kali" items (v0.83→v0.86) to the
⬜ commands never exercised. Companion to `COMMAND_COVERAGE.md` (the status
matrix), `HYDRA_PARITY.md` (brute), and `LAB_VALIDATION.md` (the run log).

**Flag syntax reminder:** scan/detection/output flags are DOUBLE-dash
(`--sS --sV --sL --sn --Pn --sO --oN --oX`…). Real short flags only:
`-A -O -F -p -v -D -f -S -e -n -t -d -b -r -R`.

## Prep

```sh
# 1) Ottieni/aggiorna il repo su Kali e builda v0.86.0
#    Prima volta: clona. Già clonato: il clone fallisce (|| true) e si prosegue.
cd ~
git clone https://github.com/Sal1699/RustyMap.git 2>/dev/null || true
cd RustyMap || { echo "ERRORE: clone/clone-path non trovato"; }
git fetch origin --tags
git checkout v0.86.0            # versione esatta sotto test (oppure: git pull origin main)
cargo build --release          # ./target/release/rustymap (qualche minuto)
RM=./target/release/rustymap
$RM --version                  # deve stampare: rustymap 0.86.0

# Lab targets (adjust to your /24)
ROUTER=192.168.1.1     # TIM gateway (TLS 1.2, ~13 ports)
SERVER=192.168.1.31    # SSH+DNS+HTTPS+rsync+8080
WIN=192.168.1.64       # Win11, SMB firewalled
NET=192.168.1.0/24
```

Reference tools: `nmap 7.9x`, `sslscan`, `testssl.sh`, `hydra`,
`crackmapexec`, `dig`/`dnsrecon`, `curl --http3`, `msfconsole`+`msfrpcd`.

**How to record:** write `VALIDATION_0.86.md` with the results, add a dated row
to `LAB_VALIDATION.md`, and flip the matching `COMMAND_COVERAGE.md` cells
⬜→🟡→✅. One `sudo` note: raw scans (`--sS/--sU/-O`/stealth/idle) need root.

---

## P0 — Confirm the recent fixes (must-pass regressions, v0.83→v0.86)

| # | Command | Expect | Compare |
|---|---------|--------|---------|
| 0.1 | `sudo $RM --sS -F $NET --progress` | **live determinate bar** with real %/ETA (ports done/total); hidden if piped | eyeball |
| 0.2 | `sudo $RM --sS -F $SERVER --scan-stats 2` | `[stats]` lines with **non-zero** sent/replied/open/filtered | — |
| 0.3 | `$RM --ssl-enum $ROUTER -p 443,8443` | enumerates ECDHE **+ DHE/RSA/CBC + exotic (ARIA/CAMELLIA/CCM/SEED)**; near sslscan count | `sslscan $ROUTER:8443` |
| 0.4 | `$RM --smb-audit $WIN` | clear per-port verdict: "firewall reject"/"RST", not "bogus length" | — |
| 0.5 | `$RM --ssl-enum $ROUTER; echo $?` | exit **1** (findings: weak/deprecated TLS) | — |
| 0.6 | `$RM --sS --INVALID $SERVER; echo $?` | exit **3** (config error) | — |
| 0.7 | `$RM --sn --oG up.gnmap $NET` | gnmap "Host: … Status: Up" for live hosts | `nmap -sn -oG` |
| 0.8 | `$RM $ROUTER -p 1-1000 --sS` | device line should NOT say "Synology NAS" for the TIM gateway | — |
| 0.9 | `$RM --msf-import lab --msf-url http://127.0.0.1:55553/api/ --msf-token T $SERVER -sV` (ws NOT pre-created) | auto-creates `lab`, pushes host+service+vuln | `msfconsole: workspace lab; hosts; services` |
| 0.10 | `$RM --oH r.html --oMd r.md $SERVER -sV` then open both | tables show **Version + risk-Note + OS**; HTML risk colours | eyeball |
| 0.11 | `sudo $RM --sS 2001:db8::1 -p 80` on a dual-stack host with no rule | zero-reply hint suggests **`ip6tables`** (not iptables) | — |
| 0.12 | `sudo $RM --sS -F $SERVER` on a lossy/rate-limited host | fewer false-`filtered` than a single-probe run (retransmit) | `nmap -sS` |

---

## P1 — Untested high-value features (⬜ → validate)

### Service / OS / TLS depth
| Command | Expect | Compare |
|---------|--------|---------|
| `$RM --smtp-audit $MAILHOST -p 25,465,587` | STARTTLS + AUTH mechanisms | `nmap --script smtp-*` |
| `sudo $RM --sA $SERVER -p 1-1000` | filtered vs unfiltered (firewall ruleset map) | `nmap -sA` |
| `sudo $RM --sW $SERVER -p 1-1000` | window-scan open/closed | `nmap -sW` |
| `sudo $RM --sM $SERVER -p 1-1000` | Maimon results | `nmap -sM` |
| `sudo $RM --sO $SERVER` | IP-protocol list | `nmap -sO` |

### Web depth (needs a real web app — e.g. DVWA/Juice Shop)
| Command | Expect | Compare |
|---------|--------|---------|
| `$RM --web-scan $WEBAPP -p 80,443,8080` | header grade + WAF/CDN + the 49 sensitive paths (v0.85) + CORS | `nikto`, manual |
| `$RM --owasp-scan $WEBAPP` | XSS/SQLi/open-redirect/SSRF probe findings | `nikto`/`zap` |
| `$RM --csp-cors $WEBAPP` | CSP + CORS misconfig verdict | manual |
| `$RM --cms-detect $WEBAPP` | CMS fingerprint (WP/Joomla/Drupal) | `whatweb` |
| `$RM --web-crawl $WEBAPP --crawl-depth 2` | BFS crawl, robots.txt, cookies | manual |
| `$RM --web-scan --evasion ghost $WEBAPP` | HTTP probes rotate a **browser UA** (not "RustyMap") | check WAF/server log |

### DNS
| Command | Expect | Compare |
|---------|--------|---------|
| `$RM --dns-security example.com` | DNSSEC/CAA/DANE/DMARC/SPF audit | `dig`, `dnsrecon` |
| `$RM --dns-enum example.com --dns-wordlist big.txt` | subdomain enum | `dnsrecon -t brt` |

### Bruteforce → see `HYDRA_PARITY.md`
Run all 13 adapters vs hydra; confirm same creds found (or both none),
rate-limit honoured, no hang. Flip COMMAND_COVERAGE brute cells per adapter.

### Metasploit end-to-end (msfrpcd + msfdb up)
| Command | Expect |
|---------|--------|
| `$RM --msf-ping --msf-url … --msf-token T` | connected version line |
| `$RM --sV --msf-suggest --msf-url … $WIN` | CVE→modules with pre-filled RHOSTS |
| `$RM --msf-fire <aux_module> --msf-fire-confirm --msf-url …` | fires with the interactive safety gate |

---

## P2 — Specialized (need a matching target; otherwise confirm clean "no target" handling)

| Command | Needs | Expect |
|---------|-------|--------|
| `sudo $RM --sI $ZOMBIE:80 -p 1-1000 $SERVER` | a zombie host w/ incremental IPID | idle-scan results, no packets from your IP |
| `$RM -b $FTPRELAY $SERVER -p 1-100` | an FTP server allowing PORT | FTP-bounce scan |
| `$RM --ics-scan $PLC` | Modbus/S7/DNP3/EnIP/BACnet device | ICS protocol probe |
| `$RM --iot-discover $NET` | mDNS/SSDP/CoAP devices | responders (0 in a VM — env) |
| `$RM --container-scan $DOCKERHOST` | exposed Docker/K8s/etcd/Consul | API probe |
| `$RM --apk-scan app.apk` | an APK file | static AXML/secret analysis |
| `$RM --ipa-scan app.ipa` | an IPA file | plist/secret analysis |
| `$RM --cloud-fingerprint example.com` | — | CDN/cloud classification |
| `$RM --cloud-buckets company` | — | public S3/GCS/Azure bucket enum |
| `$RM --cloud-metadata-via $SSRF_URL` | an SSRF primitive | IMDS probe |
| `sudo $RM --quic cloudflare.com` | — | QUIC v1 (RFC 9000) — re-confirm (passed v0.82) |
| broadcast: `sudo $RM --dhcp` / `--mdns` / `--llmnr` / `--wsdd` | non-VM NIC | responders (0 if multicast blocked — env) |

---

## P3 — Output / workflow / reporting

| Command | Expect | Compare |
|---------|--------|---------|
| `$RM --oP report.pdf $SERVER -sV` | valid PDF renders | open it |
| `$RM --siem-format cef --siem-out out.cef $SERVER -sV` | valid CEF; also try `leef`/`ecs`/`syslog` | a CEF parser |
| `$RM --compliance pci-dss --compliance-report pci.md $NET` | control citations + findings + remediation | read it |
| `$RM $SERVER -sV --exec-summary` | executive summary block | — |
| `$RM --sT --db lab.db $NET` then later `$RM --sT --db lab.db --diff-against <prev.json> $NET` | diff: newly-open / closed / changed | — |
| `$RM --threat-intel-misp <url> --threat-intel-match $NET` | MISP IoC match on scan targets | — |
| `$RM --wizard` | interactive scan-builder emits a VALID command (regression-check: must use `--sV` not `-sV`) | run the emitted cmd |
| `$RM --serve` | web UI serves on localhost | browser |
| `$RM $SERVER --tui` | TUI renders results | eyeball |

---

## P4 — Aggiornamento & manutenzione (self-update + data-sync)

Richiedono rete (GitHub release, feed NVD / CISA KEV / ExploitDB / Nuclei).

> ⚠ **`--update`/`--check-update` sono TARATI sulle GitHub *Release*, non sui
> tag.** L'ultima Release pubblicata è **v0.68.0** (le versioni successive sono
> solo tag git — CI di release bloccata dal billing). Quindi su un binario
> recente `--update` dice *"Already up to date (latest: v0.68.0)"* e **NON**
> porta a v0.86.0. Per aggiornare Kali usa il flusso **git + cargo** del Prep
> (`git fetch --tags && git checkout v0.86.0 && cargo build --release`). Perché
> `--update` torni utile vanno pubblicate le Release con gli asset
> (`rustymap-linux-x86_64.tar.gz`) buildati su Kali — vedi nota sotto.

| Command | Expect | Note |
|---------|--------|------|
| `$RM --check-update` | riporta se esiste una release GitHub più recente (o "up to date") | read-only, sicuro |
| `$RM --update-cve-db` | sync NVD JSON 2.0 (ultimi 5 anni) → `~/.cache/rustymap/nvd.sqlite`; stampa conteggio | poi `$RM --cve-db ~/.cache/rustymap/nvd.sqlite --sV $SERVER` usa il DB scaricato |
| `$RM --update-exploit-refs` | sync KEV + ExploitDB + Nuclei → `exploit_refs.json`; stampa conteggi | — |
| `$RM --inspect-exploit-cache CVE-2021-44228` | voce di cache per Log4Shell (sempre in KEV) → badge `[KEV]` presente | sanity dei feed scaricati |
| `$RM --update` | scarica+installa l'ultima release da GitHub, **sostituisce il binario** | ⚠ fallo per ULTIMO (rimpiazza l'eseguibile sotto test); verifica poi `$RM --version` |

> `--install-npcap` è solo-Windows (su Kali non serve: i raw-socket girano come root nativamente).

**Ordine consigliato:** `--check-update` → `--update-cve-db` / `--update-exploit-refs` → `--inspect-exploit-cache` (conferma i feed) → `--update` alla fine.

---

## Done criteria

- `VALIDATION_0.86.md` written with P0 results (all must pass) + whatever P1/P2/P3 you reach.
- `LAB_VALIDATION.md` dated row added.
- `COMMAND_COVERAGE.md` cells flipped ⬜→✅ (with the VALIDATION ref) for each confirmed command.
- Any bug found → triage in the report, fix in a `0.86.x` patch, re-run.
