# RustyMap v0.87.0 — Kali Test Roadmap (Fase 29: motore script 117→307)

Test plan dedicato alla release v0.87.0, **dall'installazione dell'update** ai
test del motore script. Companion: `KALI_TEST_ROADMAP.md` (piano generale),
`COMMAND_COVERAGE.md`, `LAB_VALIDATION.md`.

> Scan raw (`--sS/--sU/-O`/stealth/idle) = **root**. Gli altri no.

---

## 0. Installazione / aggiornamento a v0.87.0

```sh
# clona se manca, altrimenti aggiorna
cd ~
git clone https://github.com/Sal1699/RustyMap.git 2>/dev/null || true
cd RustyMap
git fetch origin --tags
git checkout v0.87.0                 # oppure: git pull origin main
cargo build --release                # qualche minuto
# allinea il binario su PATH (altrimenti `rustymap` resta vecchio)
install -m 0755 target/release/rustymap "$(command -v rustymap || echo /usr/local/bin/rustymap)"
rustymap --version                   # DEVE stampare: rustymap 0.87.0
```

Se `cargo build` fallisce per dipendenze di sistema → `apt install build-essential pkg-config libssl-dev` e ritenta.

Variabili lab:
```sh
ROUTER=192.168.1.1 ; SERVER=192.168.1.31 ; CAM=192.168.1.226 ; NET=192.168.1.0/24
```

---

## S0 — Smoke del motore script

| # | Comando | Atteso |
|---|---------|--------|
| S0.1 | `rustymap --script-catalog /tmp/cat.json` | stampa **"307 scripts exported"** |
| S0.2 | `rustymap --script-help \| head -40` | lista built-in con `@name` |
| S0.3 | `grep -oE '"category": *"[a-z-]+"' /tmp/cat.json \| sort \| uniq -c \| sort -rn` | http~98, vuln~32, db~28, ics~8, ssh~7… |

## S1 — Catalogo & selezione (NOTA: queste filtrano il CATALOGO, non la run)

> `--script-category`/`--script-tag` mostrano/filtrano il **catalogo** (modalità
> probe-only: elencano, NON scansionano). Il subset a runtime non è ancora
> cablato — vedi "Limitazione nota" in fondo.

| # | Comando | Atteso |
|---|---------|--------|
| S1.1 | `rustymap --script-category ics --script-catalog /tmp/ics.json` | solo script ICS (modbus/s7/dnp3/bacnet/ethernetip/iec104/profinet/niagara) |
| S1.2 | `rustymap --script-tag http --script-catalog /tmp/http.json` | solo script taggati http |
| S1.3 | `rustymap --script-category db --script-catalog /tmp/db.json` | oracle/db2/cassandra/cockroach/clickhouse/hbase… |
| S1.4 | esporta `.md`: `rustymap --script-catalog /tmp/cat.md` | catalogo leggibile Markdown |

## S2 — Esecuzione built-in durante lo scan

I built-in auto-partono **solo in triage** (host nudo / `--sV` / `-A`), non su
port-scan raw espliciti, e si **saltano** su sweep >8 host (opt-in a scala).

| # | Comando | Atteso |
|---|---------|--------|
| S2.1 | `rustymap $ROUTER --sV` | i built-in girano; compaiono finding (http/banner/exposure) |
| S2.2 | `sudo rustymap --sS -F $ROUTER` | **nessuno** script (port-scan raw esplicito) → veloce |
| S2.3 | `sudo rustymap --sS -F $ROUTER --force-scripts` | forza i built-in anche sul raw |
| S2.4 | `rustymap $NET --sV` | sweep >8 host → messaggio "scripts skipped (opt-in at scale)" |
| S2.5 | `rustymap $NET --sV --force-scripts` | forza i built-in sullo sweep |
| S2.6 | `rustymap $ROUTER --sV --no-builtin-scripts` | nessuno script |

## S3 — Spot-check dei NUOVI script su target reali

Scegli target che espongono i servizi e verifica che lo script giusto scatti
(confronta un paio con `nmap --script`).

| Target tipico | Script nuovi attesi | Confronto nmap |
|---|---|---|
| Router/gateway | `http-*` panel detect, banner, `netbios-*`, `msrpc-epmap-exposed` | `nmap --script http-title,banner` |
| IP camera ($CAM) | `rtsp-*`, `http-*`, banner | `nmap -p554 --script rtsp-*` |
| Server SSH/FTP/SMTP | `ssh-dropbear/cisco/…`, `ftp-vsftpd/proftpd/…`, `smtp-postfix/exim/…` | `nmap --script ssh2-enum-algos,ftp-*,smtp-*` |
| Host con Tomcat/Jenkins/GitLab | `http-tomcat-manager`, `http-jenkins-script`, `http-gitlab-detect` | `nmap --script http-*` |
| PLC/ICS (se presente) | `modbus-exposed`, `s7comm-exposed`, `dnp3-exposed` | `nmap --script modbus-discover,s7-info` |
| Legacy (telnet/tftp/finger) | `telnet-*`, `tftp-service`, `finger-exposed` | — |

**Da registrare per ciascuno:** lo script scatta? Il finding è corretto o
falso-positivo? Severità sensata?

## S4 — Controllo falsi-positivi (gli script detect sono euristici)

| # | Comando | Atteso |
|---|---------|--------|
| S4.1 | `rustymap <host-con-pochi-servizi> --sV` | **pochi/zero** finding spuri; nessun panel-detect su host senza quel servizio |
| S4.2 | `rustymap <catch-all-router> --sV` | gli `http-*` marker-based NON devono scattare a raffica su una pagina catch-all |

## S5 — Performance con 307 script

| # | Comando | Atteso |
|---|---------|--------|
| S5.1 | `time rustymap $SERVER --sV --force-scripts` | tempo ragionevole su 1 host (decine di secondi max) |
| S5.2 | `time rustymap $NET --sV` | sweep NON esegue i 307 su 20 host (skip opt-in) → resta veloce |

## S6 — Regressione rapida v0.86.1 (deve restare OK)

| # | Comando | Atteso |
|---|---------|--------|
| S6.1 | `sudo rustymap --sS -p 1-1000 $ROUTER` | footer **"1000 port-probes"** (reale) |
| S6.2 | `rustymap --cms-detect $ROUTER` | niente "relative URL" (prova http://) |
| S6.3 | `rustymap --iot-discover $NET` | errore chiaro "single host, not a CIDR" (exit 3) |

---

## Limitazione nota (candidato v0.87.1)
`--script-category`/`--script-tag` oggi filtrano **solo il catalogo** (probe-only).
NON subsettano gli script che girano durante una scansione — a runtime girano
tutti i built-in (triage/sweep logic). Se vuoi `rustymap --script-category ics
$TARGET` che **esegua** solo gli ICS, è un piccolo fix da cablare in
`run_inline` (filtro per categoria/tag) → patch v0.87.1.

## Done criteria
- `VALIDATION_0.87.md` scritto con gli esiti S0–S6.
- Riga in `LAB_VALIDATION.md`; celle script in `COMMAND_COVERAGE.md` ⬜→✅.
- Bug trovati → triage + patch `0.87.x`.
