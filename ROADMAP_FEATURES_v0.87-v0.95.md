# RustyMap — Roadmap feature v0.87 → v0.95 (verso/oltre la parità nmap)

Nove fasi di profondità tecnica decise dopo il recap di posizionamento vs nmap
(v0.86.1). Chiudono i gap onesti con nmap (engine raw, congestion control,
service-probe DB) e allargano i differenziatori (script, web, mobile, evasion,
report, velocità). **Vengono PRIMA del taglio v1.0** (Fase 26 = portfolio
polish, resta l'ultima). Una release MINOR per fase, in ordine.

> Le fasi 24/25/27/28 sono fatte; 29→37 sono queste; 26 (v1.0) chiude.
> Companion: `ROADMAP.md` (indice + path v1.0), `COMMAND_COVERAGE.md`,
> `KALI_TEST_ROADMAP.md`.

## Quadro sintetico

| Fase | Release | Tema | Priorità utente |
|------|---------|------|------|
| 29 | v0.87.0 | Script engine → ≥300 (port logica NSE) | core (1) |
| 30 | v0.88.0 | Motore pacchetti nativo ad alto throughput | core (2) |
| 31 | v0.89.0 | Congestion control / rate-limiting | core (3) |
| 32 | v0.90.0 | Service-probe DB → parità nmap | core (4) |
| 33 | v0.91.0 | Web-scan moderno | +(5) |
| 34 | v0.92.0 | Mobile iOS/Android (app + device) | +(6) |
| 35 | v0.93.0 | Firewall-evasion & camuffamento | +(7) |
| 36 | v0.94.0 | Report + dettaglio output base | +(8) |
| 37 | v0.95.0 | Ottimizzazione velocità | +(9) |
| 26 | **v1.0.0** | Portfolio polish + taglio stabile | al tuo ok |

**Dipendenze:** 30 → 31 → 37 sono un blocco unico (engine → congestion →
velocità): la 37 raccoglie i frutti di 30+31. Le altre sono indipendenti.

---

## Fase 29 — Script engine ≥300 (v0.87.0)

**Obiettivo:** da 117 a **≥300** script Rhai, ri-adattando la *logica* degli
NSE più usati (il codice NSE è Lua/GPLv2: si porta la logica, non si copia).

**Deliverable:**
- ~180 nuovi script nelle famiglie che contano: `http-*` (title, headers,
  methods, robots, enum, default-creds), `ssl-*`, `smb-*`, `dns-*`, `ssh-*`,
  `ftp-*`, `snmp-*`, `smtp-*`.
- Tassonomia stile NSE: categorie (safe/intrusive/vuln/auth/brute/discovery) +
  tag/metadata (`// @category:`), selezione `--script cat:vuln`/`tag:http`.
- `--script-help <nome>`, tutti passano `all_builtin_scripts_parse`, ognuno
  con un test di trigger sintetico.

**Riferimento:** NSE (`nmap --script`). **Rischio:** qualità > quantità; ogni
script validato in lab. **Licenza:** riscrivere la logica, mai copiare Lua.

## Fase 30 — Motore pacchetti nativo (v0.88.0)

**Obiettivo:** engine raw ad alto throughput che avvicini nmap, togliendo il
collo di bottiglia del ciclo probe→wait→probe sincrono.

**Deliverable:**
- **Linux:** TX/RX via `AF_PACKET` (ring buffer `PACKET_MMAP`) + syscall batch
  `sendmmsg`/`recvmmsg`; send e receive **disaccoppiati** (invio a raffica, un
  solo thread demux delle risposte) come nsock/ultra_scan di nmap.
- **Windows:** resta **Npcap** (il driver kernel non è sostituibile — onestà),
  ma invio in batch e ricezione ottimizzata.
- Fallback trasparente al path attuale (`pnet`) se le primitive mancano.
- Bench `benches/` vs nmap su SYN -F / 1-1000 / full-65535.

**Riferimento:** nmap `nsock` + `ultra_scan`. **Rischio:** il più invasivo,
tocca il core raw; va dietro una feature-flag finché non batte il path attuale
in lab. **NON** ricrea Npcap (è un driver firmato), ricrea il *motore* sopra.

## Fase 31 — Congestion control / rate-limiting (v0.89.0)

**Obiettivo:** modello timing adattivo tipo nmap **ma più rapido**: parte
aggressivo e rallenta solo quando serve.

**Deliverable:**
- Rilevamento rate-limit: drop ripetuti + ICMP type-3/code-13 (admin
  prohibited) / code-4 → **backoff** della finestra di congestione.
- Finestra dinamica (cwnd-like) sul numero di probe in volo, con AIMD;
  `--min-rate`/`--max-rate` onorati davvero.
- Chiude il "router perde open sotto flood" visto in lab (v0.86.0): su host
  che rate-limitano, rallenta e recupera gli open invece di marcarli filtered.

**Riferimento:** nmap congestion control. **Dipende da:** Fase 30 (serve il
motore async per misurare drop/RTT in modo pulito).

## Fase 32 — Service-probe DB → parità nmap (v0.90.0)

**Obiettivo:** parità con `nmap-service-probes`.

**Deliverable:**
- Parser runtime di `nmap-service-probes` via flag `--nmap-service-probes`
  (stesso modello di `--nmap-os-db`: file GPLv2 fornito dall'utente) — match,
  soft-match, rarity, port/ssl mapping.
- Ampliamento del set built-in (porting dei probe più comuni).
- **`-sV` dietro TLS** (HTTPS/RTSP/rsync su 443/8443): chiude il gap residuo
  (lighttpd-on-443 ecc.) con una pipeline probe-over-TLS.

**Riferimento:** `nmap -sV` + `nmap-service-probes`. **Licenza:** come os-db,
il file lo porta l'utente.

## Fase 33 — Web-scan moderno (v0.91.0)

**Obiettivo:** `--web-scan` più funzionale e moderno.

**Deliverable:**
- Tech-fingerprint stile Wappalyzer (framework/CMS/lib/versione da
  header+body+JS).
- Scoperta endpoint: parsing JS per URL/API, `/robots`, sitemap, GraphQL
  introspection, OpenAPI.
- Più check: SSTI, path-traversal, deserialization hint, open-redirect,
  secrets in JS, security.txt, analyzer CSP/COOP/COEP.
- Opzionale: screenshot headless (dietro feature-flag, coerente con la scelta
  "no headless di default").

## Fase 34 — Mobile iOS/Android (v0.92.0)

**Obiettivo:** ampliare app **e** dispositivi mobile (oggi solo APK/IPA static).

**Deliverable:**
- **Device in rete:** ADB (5555), iOS lockdownd (62078), mDNS
  `_airplay`/`_raop`/`_companion-link`, fingerprint OS mobile.
- **Static più profondo:** permessi pericolosi, tracker/SDK noti,
  cert/signing, `usesCleartextTraffic`, componenti esportati, deep-link,
  secret regex estese.
- (Da decidere con te: solo analisi file app, o anche scansione dei
  dispositivi — il deliverable copre entrambi.)

## Fase 35 — Firewall-evasion & camuffamento (v0.93.0)

**Obiettivo:** nuove tecniche di evasione/stealth oltre le attuali.

**Deliverable:**
- **JA3/JA4 client mimicry**: ClientHello TLS che imita browser reali (non solo
  lo UA — v0.85 — ma il fingerprint di handshake).
- Frammentazione avanzata (più MTU, overlap, ord. casuale), decoy "intelligenti"
  (host vivi reali), timing anti-IDS, IP options/source-route estese.
- Mimicry di stack OS a livello pacchetto completo (oltre `--stack-profile`).

**Riferimento:** nmap `-f/-D/--spoof-mac/--badsum` + oltre.

## Fase 36 — Report + output base (v0.94.0)

**Obiettivo:** report più dettagliati e output di default più ricco.

**Deliverable:**
- HTML interattivo (filtri, grafici severità, topologia navigabile), diff
  visuale tra scan.
- Output base: più "evidence" (banner/probe match mostrati), timeline fasi,
  raggruppamento per categoria di servizio, riepilogo rischio in testa.
- Export aggiuntivi (SARIF per CI, forse JSON-lines streaming).

## Fase 37 — Ottimizzazione velocità (v0.95.0)

**Obiettivo:** il più veloce possibile, consolidando 30+31.

**Deliverable:**
- Profiling (flamegraph) dei path caldi; lock-free dove serve; tuning
  parallelismo/hostgroup; riuso connessioni; cache DNS/probe.
- **Regression gate**: release bloccata se >10% più lenta di nmap su uno
  scenario del bench (SYN /24, full-TCP /24, -sV 50 host, -O 10 host).
- Numeri finali in `PERFORMANCE.md`.

---

## Dopo le 9 fasi → Fase 26 (v1.0.0)
Portfolio polish + taglio stabile (README, docs site, esempi, feature-freeze,
contratto SemVer). Solo al tuo ok esplicito. A quel punto RustyMap sarà un
superset di nmap maturo e veloce, non più solo "feature-completo".
