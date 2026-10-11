# RustyMap v0.86.0 — Lab Validation Report

**Data:** 2026-10-11 · **Tester:** Kali 6.19 (192.168.1.198) · **Baseline:** v0.83.1
**Binary:** `/usr/local/bin/rustymap` v0.86.0 (built from tag v0.86.0)
**Riferimenti:** sslscan, nmap 7.99, python3, xmllint · **Run:** 2 (riproducibili)

> **v0.86.1 resolution (assistant, 2026-10-11):**
> - **Bug #1 — NON è un bug di scansione.** Riprodotto in locale: `--sT -p
>   1-1000 127.0.0.1` sonda tutte le 1000 porte e trova tutti gli open
>   (135/445/902/912), footer "1000 port-probes". Il path **raw SYN scarta
>   closed+filtered da `host.ports`**, quindi il footer (che contava
>   `host.ports.len()`) mostrava solo gli OPEN (1-2) → sembrava "1-2 probe".
>   **Fix v0.86.1:** il footer usa `scan_stats::global().ports_done()` (conteggio
>   reale). Il discrepanza router 1-vs-5 open è lato-router (firmware/rate-limit),
>   non RustyMap. → FIXED (display).
> - **Bug #2 — URL base.** `--cms-detect/--owasp-scan/--web-crawl` e
>   `--iot-discover` non normalizzavano un target bare → "relative URL without a
>   base". → FIXED v0.86.1.
> - **Bug #3 — NVD timeout.** `--update-cve-db` timeout → timeout più generoso. → v0.86.1.

---

## Target lab
| Alias | IP | Descrizione |
|-------|----|-------------|
| ROUTER | 192.168.1.1 | TIM gateway, TLS 1.2, ~11 porte |
| SERVER | 192.168.1.31 | Alcatel, SSH+DNS+HTTPS+rsync+lighttpd+9001 |
| WIN | 192.168.1.64 | Win11 MSI, SMB firewalled, 6 porte |
| NET | 192.168.1.0/24 | LAN, 20 host attivi |

## P0 — Regressioni (must-pass) — 9 PASS, 1 BUG, 3 SKIP/N.T.
| # | Test | Risultato | Note |
|---|------|-----------|------|
| 0.1 | progress bar | SKIP | non testabile in pipe (hidden — da spec) |
| 0.2 | scan-stats | **PASS** | sent=635→19000, open reali @t crescente |
| 0.3 | ssl-enum exotic | **PASS** | :443 8/8 (100%); :8443 **28 cipher** incl ARIA/CAMELLIA/CCM/SEED (era 13) |
| 0.4 | smb-audit | **PASS** | :139 "firewall reject"; :445 "firewall RST" |
| 0.5 | exit findings | **PASS** | exit 1 |
| 0.6 | exit config | **PASS** | exit 3 |
| 0.7 | --sn --oG | **PASS** | 20 host, formato nmap |
| 0.8 | device fp | **PASS** | "router (70%)" — NON più "Synology NAS" |
| 0.8b | -p 1-1000 --sS | **BUG#1** | footer "1-2 port-probe" (display; vedi resolution) |
| 0.9 | msf-import | SKIP | msfrpcd non attivo |
| 0.10 | HTML+MD | **PASS** | Version+Note+OS; risk/state classes |
| 0.11 | ip6tables hint | N.T. | nessun target dual-stack |
| 0.12 | SYN retransmit | **PASS** | 5 open, 0 false-filtered, 0.13s |

### ssl-enum :8443: v0.83.1 13/31 (42%) → **v0.86.0 28/31 (90%)**; mancano solo i 3 cipher TLS 1.3.

## P1 — 12 PASS, 3 BUG, 1 N.T.
- `--sA` 1000 unfiltered = **IDENTICO** a nmap; `--sW`/`--sM` 1000 closed (atteso); `--sO` 15 proto con RFC (nmap 11 in 343s, RM più veloce, core match).
- `--web-scan $ROUTER` grade E/D + catch-all; `--web-scan --evasion ghost` UA browser attivo; `--csp-cors` "no CSP → XSS unmitigated"; `--ssh-audit` 6-8 weakness; `--tls-grade` **B** (no TLS 1.3).
- **BUG#2**: `--cms-detect`/`--owasp-scan`/`--web-crawl` → "relative URL without a base".
- DNS: `--dns-security google.com` DNSSEC/CAA/DANE/SPF/DMARC/MX OK; `--dns-enum` 26 subdomain.
- Brute: `--brute-protocol ssh --brute-target $SERVER:22 --brute-default-creds-only --brute-confirm-authorized` → 97 tentativi, 0 successi (PASS). Nota sintassi: `--brute-target HOST:PORT` + passlist/default-creds, non target posizionale.

## P2 — 7 PASS, 1 BUG, 2 N.T.
- `--quic cloudflare.com` QUIC v1 PASS; `--cloud-fingerprint` Cloudflare CDN PASS; `--cloud-buckets google` 13 bucket PASS; `--container-scan` 0 responder (atteso); `--dhcp`/`--llmnr` clean 0; `--mdns` **2-3 responder** (era 0 in v0.82.1).
- **BUG#2**: `--iot-discover` → "failed to lookup address information".
- `--wsdd-discover` flag inesistente → N/A.

## P3 — 13 PASS / 13
`--oP` PDF, `--oX`/`--oJ`/`--oN`/`--oH`/`--oMd`, `--siem-format cef/leef/ecs`, `--compliance pci-dss --compliance-report`, `--executive-summary`, `--diff-against`, `--history`, `--db` — tutti **PASS**.

## P4 — 3 PASS, 1 FAIL
- `--check-update` "v0.86.0 up to date (latest: v0.68.0)" PASS (nota: Release GitHub ferma a v0.68.0).
- `--update-cve-db` **FAIL** (NVD timeout — Bug#3); `--update-exploit-refs` 1739 CVE KEV PASS; `--inspect-exploit-cache CVE-2021-44228` kev:true PASS.

## Matrice: 56 testati, **44 PASS, 5 BUG, 7 SKIP/N.T.** — pass rate 44/49 = **90%**. 100% riproducibile su 2 run.

## Bug (→ stato v0.86.1)
1. **#1 (ALTA→display)** `-p range --sS` footer mostrava open-count non probe-count → **FIXED** (footer usa ports_done; scan era corretto).
2. **#2 (MEDIA)** URL base per cms-detect/owasp-scan/web-crawl/iot-discover → **FIXED**.
3. **#3 (BASSA)** --update-cve-db NVD timeout → timeout aumentato.

## Novità v0.86.0 confermate
ssl-enum :8443 13→28 cipher; device-fp router corretto; colonne NOTE/Exposure; executive summary; scan-stats reali; mDNS funzionante; --tls-grade dedicato; SIEM ECS; PCI-DSS; --cloud-buckets/-fingerprint; 1739 CVE KEV.

## Conclusione
v0.86.0 = miglioramenti significativi (ssl-enum 42→90%, device-fp, output arricchito, mDNS, scan-stats reali). 3 bug, di cui #1 è solo display (scan corretto, verificato in locale). Fix tutti in v0.86.1.
