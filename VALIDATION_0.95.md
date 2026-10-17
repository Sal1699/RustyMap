# VALIDATION — v0.89.0 → v0.95.0 (Fasi 31→37, giro unico)

**Data:** 2026-10-16/17 · **Lab:** Kali 6.19, 18 host live su 192.168.1.0/24
(router TIM Technicolor) · **Riferimento:** nmap + hyperfine · **Piano:**
[KALI_TEST_v0.89-0.95.md](KALI_TEST_v0.89-0.95.md).

Un solo giro per tutte le fasi feature. Esito: **32→37 PASS, 31 PASS con
caveat** (hang full-port su host filtrati). I fix sono in **v0.95.1**.

## Esito per fase
| Fase | Feature | Esito |
|---|---|---|
| 31 | congestion control | **PASS con caveat** — fast stabile+consistente su host responsivi (σ bassa, open-count identico su 3 run); hang su host completamente filtrati in full-port (B1/B3) |
| 32 | -sV dietro TLS | **PASS** — lighttpd 1.4.35 / nginx 1.24.0 estratti *attraverso* TLS; `--nmap-service-probes` carica 9504 regole; +Dropbear/dnsmasq/rsync/SMB/VMware |
| 33 | web-scan moderno | **PASS** — tech-fp (jQuery/Bootstrap/lighttpd/nginx), CSP unsafe-inline/eval + frame-ancestors, **CORS arbitrary-Origin su .1:8443**, cookie senza Secure+SameSite su .10, catch-all FP soppressi |
| 34 | mobile-discover | **PARZIALE** — fallback corretto su non-mobile/irraggiungibili; nessun Android con ADB-WiFi in lab per validare il positivo; iPad .137 aveva 62078 al SYN ma offline al mobile-discover (stato host) |
| 35 | evasione | **PASS** — JA3/JA4 distinti e consistenti per chrome/firefox/safari; `--evasion ghost --frag-random-order` gira, stessi open dei run normali |
| 36 | SARIF | **PASS** — SARIF 2.1.0 valido su tutti i 18 host, results = porte open con categoria |
| 37 | speed + DNS cache | **PASS** — `--sL -R` /24 in ~1.0s (cache ok); 8/10 bench migliorati, 1 regressione = rumore (B4) |

## Bug trovati → risoluzione (v0.95.1)
| # | Sev | Descrizione | Fix v0.95.1 |
|---|---|---|---|
| B1 | MED | full-port SYN si inchioda per ore su host completamente filtrati (no tetto tempo); .3/.10/.85/.134 killati dopo 11h+ | **`--host-timeout` ora cablato nel path raw** (deadline cooperativa a ogni wave/porta) **+ silence-shrink** nel fast engine (dopo la 1ª wave senza risposte usa il floor, non il full timeout) → host filtrato finisce in secondi |
| B3 | MED | `--max-rate`/`--min-rate` non fermano l'hang | by design cappano il *rate*, non il *tempo* → `--host-timeout` è il tetto di tempo (ora attivo sul raw) |
| B2 | LOW | `--legacy-engine` rimosso in v0.88.4 rompe gli script | **ri-aggiunto** come opt-out esplicito (forza per-probe; vince su --fast-engine) |
| B4 | LOW | bench `port_expand 1-65535` +26.7% | **non è codice**: il `parse_ports` del bench è una copia inline isolata e `benches/` non è toccato da v0.89.0 → rumore Criterion durante le scansioni-lunghe concorrenti; annotato in PERFORMANCE.md |
| B5 | INFO | `--sL` double-dash vs `-sL` nmap | voluto: i flag scan-type di RustyMap sono double-dash (`-sL` confliggerebbe col parsing short di clap) |

## Promozione --fast-engine a default
31.1 conferma stabilità/consistenza su host responsivi, ma l'hang (B1/B3) era il
blocco. Con v0.95.1 (`--host-timeout` sul raw + silence-shrink) il blocco è
rimosso. **Promozione ancora in attesa**: rieseguire i casi full-port di v0.95.0
con v0.95.1 (host filtrati con/ senza `--host-timeout`) e confermare che
l'hang è sparito → poi si ri-promuove il fast a default (con `--legacy-engine`
come opt-out, già pronto).

## Lato sicurezza (rete lab — osservato, il tool funziona su rete reale)
CORS arbitrary-Origin (.1:8443), SMB/MSRPC/NetBIOS esposti (.64/.85/.134),
rsync+MQTT esposti (.31), Dropbear SSH 2017.75 vecchio (.31), RTSP+cert
self-signed (camere .34/.226), nginx 1.24.0 → CVE-2023-44487 (.198),
cookie senza Secure+SameSite (.10). CVE correlate (EternalBlue/Zerologon su SMB,
Rapid-Reset su nginx) = *unconfirmed* (serve conferma versione) — corretto non
intestarsele.
