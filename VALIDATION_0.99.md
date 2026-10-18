# VALIDATION — v0.99.0 (script 607 + --port-script + --sn + maturità)

**Data:** 2026-10-17/18 · **Lab:** Kali 6.19, home /24 (router TIM, 18+ host) ·
**Build:** v0.99.0 (73d9623) · **Piano:** [KALI_ROADMAP_v0.99.md](KALI_ROADMAP_v0.99.md).

Giro di validazione del lavoro v0.95→v0.99. Esito: tutto PASS tranne 2 FP e il
display MAC di `--sn`; fix in **v0.99.1**.

## Esiti
| Step | Feature | Esito |
|---|---|---|
| 1 | Script engine 607 | PASS (conteggio 607, sweep -sV pulito) — **2 FP** (sotto) |
| 2 | `--port-script` | **PASS** (gira solo su porte aperte; `[port-script] .31:22 → SSH-2.0-dropbear…`) |
| 3 | `--sn` arricchito | **PARZIALE** — PTR/JSONL ok; MAC/latenza vuoti (SN-1/2) |
| 4A | Maturità promosse | `--sV`/`--tls-grade`/`--ssh-audit` PASS; **`-O` sbaglia** (OS-1) |
| 4B | Maturità pending | `--cve-for` PASS (25 CVE vs NVD); `--smb-audit` solo reject-path (host firewallato) |
| 5 | Congestion/hang | PASS — `--host-timeout` esatto (.64 120.35s); silence-shrink ok; fast 1.39× più lento ma σ bassa su /24 |
| 6 | SARIF + JSONL | **PASS** (SARIF 2.1.0 6 results; JSONL 1 riga/host) |

## Bug trovati → fix v0.99.1
| # | Sev | Descrizione | Fix |
|---|---|---|---|
| FP-2 | MED | `[high] default-cred-likely: Tomcat` su lighttpd:8080 | 8080 ora scatta SOLO con marker positivo Tomcat/-sV (regola v0.87.1) |
| FP-1 | LOW | `Tech: Django, Django` su router TIM | regola web_fp Django duplicata + marker generico `csrftoken` → rimosso il duplicato + marker Django-specifici |
| SN-1 | MED | `--sn` MAC sempre `-` | fallback su tabella neighbor OS (`ip neigh`/`arp -a`) via `net_util::neighbor_macs` |
| SN-2 | LOW | `--sn` latenza sempre `-` | best-effort da `arp_rtt` (resta `-` se la discovery non-ARP non la misura) |
| OS-1 | MED | `-O` AP → "VirtualBox Slirp NAT 88%" | **`-O` declassato a Beta** (match senza `--nmap-os-db` inaffidabile; emit resta byte-identica) |

## Decisioni maturità
- **`--cve-for` → Production** (validato vs NVD).
- **`--smb-audit` resta Beta** (il .64 era firewallato: validato ancora solo il reject-path, non un negotiate SMB vivo).
- **`-O` → Beta** (vedi OS-1 — demotion onesta, coerente con la convenzione "divergenza su target reale = scendi di tier").

## Note perf (#8/#9, dati reali)
`hyperfine` /24 (nmap killato al 3° run): RM default 655.68s ±179 (media più
bassa, varianza alta); RM fast 910.44s ±55 (più lento ma stabile). Su /24 pieno
di host filtrati domina il per-host timeout → **conferma: fast NON va promosso a
default** (1.39× più lento di media), e il tuning #8/#9 va fatto sul comportamento
timeout per-host, non sull'engine. Decisione fast=opt-in confermata dai numeri.

## Residui per i prossimi giri
- Rifare lo sweep script dopo v0.99.1 per confermare 0 FP (FP-1/FP-2 chiusi).
- `-O`: validare il match con `--nmap-os-db` caricato su hardware eterogeneo → eventuale ri-promozione.
- `--smb-audit`: serve un host SMB vivo non firewallato per il negotiate.
- `--sn` MAC: verificare che il fallback `ip neigh` popoli i MAC sul /24.
