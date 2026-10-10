# RustyMap — Roadmap verso v1.0

> Stato: **v0.83.1** (2026-10-10). Le fasi tecniche del roadmap v0.66+ sono
> chiuse: **Fase 24** (maturity tiers), **Fase 25** (vuln-intel), **Fase 27**
> (bench + PERFORMANCE.md), **Fase 28** (UX: exit code, preset `--profile`,
> color/CI, verbosità). Resta **Fase 26 = portfolio polish + taglio v1.0**,
> più la chiusura del loop di validazione in lab e un backlog tecnico mirato.

## Principi guida (decisi, non rinegoziabili senza motivo)

- **Niente nuova ampiezza prima del v1.0.** Nuovi protocolli / adapter brute /
  script Rhai solo se emerge un caso d'uso concreto in lab (direttiva
  2026-05-16). Profondità e affidabilità, non più feature.
- **SemVer:** si resta su `0.x.y` fino al taglio stabile; `0 → 1` **solo** al
  v1.0. MINOR = qualcosa di aggiunto, PATCH = fix. Ogni release ha release
  notes in chiaro.
- **Ogni modifica alla CLI tocca `src/guide.rs` nello stesso commit.**
- **Validazione prima della fiducia:** una feature passa a "Production" solo
  dopo un run documentato in lab contro un tool di riferimento
  (nmap/sslscan/hydra/msfconsole). Le release binarie si buildano a mano su
  Kali (CI bloccata da billing).

---

## Fase L — Chiusura loop di validazione lab  →  v0.83.x (PATCH)

Prima di toccare altro, confermare su Kali i fix già spediti ma non ancora
validati su hardware reale. Ogni bug trovato → patch release mirata.

**Da ri-verificare (home /24 + Win11 + router + server):**
- [ ] `--msf-import <ws> <target> --msf-url …` end-to-end vs `msfrpcd` vivo →
      host/service/vuln atterrano in `workspace <ws>` (v0.83.0)
- [ ] `--ssl-enum` elenca DHE/RSA/CBC sul router/server (non più solo ECDHE) vs
      sslscan (v0.83.0)
- [ ] `--smb-audit` su Win11 firewallato → verdetto "firewall reject" chiaro
      (non più "bogus SMB response length 1") (v0.83.0)
- [ ] Exit code: scan con finding reale (CVE/TLS) → exit `1`; config error → `3`
      (v0.83.0)
- [ ] `--sn --oG up.gnmap <range>` → lista host-up nei file (v0.83.1)
- [ ] Ri-conferma i 3 fix v0.82.1 (p 1-1000 esatto, web-scan no .env FP,
      --msf-suggest EternalBlue) ancora OK dopo le modifiche 0.83.x

**Definition of done:** `VALIDATION_0.83.md` scritto, riga di log in
`LAB_VALIDATION.md`, feature toccate promosse a Production nella matrice.

---

## Fase M — Backlog tecnico mirato  →  v0.84.x–v0.8x (MINOR, solo se il lab lo giustifica)

Gap noti e documentati come "deferred/partial". Si affrontano **solo** se
servono davvero nel lab, uno alla volta, con validazione.

- [ ] **`-sV` HTTPS-dietro-TLS:** estrazione versione dall'header `Server` su
      443/8443 (oggi lighttpd/nginx su 443 solo per nome); stessa logica per
      RTSP e rsync wrapped. *(gap più sentito)*
- [ ] **SMB NTLM info su Windows moderni:** session-setup SMBv2 per leggere
      dominio/hostname/OS build quando SMBv1 è off (oggi solo dialetto).
- [ ] **Throughput SYN grezzo** sugli host molto responsivi: capire se e quanto
      avvicinarsi al motore pcap di nmap (misurare prima, non assumere).
- [ ] **IPv6 raw UX:** rilevare il drop conntrack e suggerire/automatizzare la
      regola iptables invece di "zero packets"; chiarire closed vs filtered.
- [ ] Minori: B12 Slirp 902/16012, B20 UDP over-report `open|filtered`,
      B19 banner HTTP vuoto su host lenti.

**Regola:** ogni item entra in roadmap solo con un caso d'uso lab scritto. Se
non serve, resta deferred — non è un debito, è una scelta.

---

## Fase 26 — Portfolio polish + taglio v1.0  →  v1.0.0 (MAJOR, al tuo via)

Il lavoro che trasforma "tool da lab" in "progetto pubblico presentabile".
Richiede il tuo ok esplicito al feature-freeze.

### 26.1 — Documentazione
- [ ] **README** riscritto: pitch in una riga, matrice feature vs nmap,
      install per OS (Windows/Kali/macOS), quickstart, 5-6 esempi reali
- [ ] Asciinema/GIF di un paio di scansioni (discovery, `-A`, `--tls-scan`)
- [ ] `docs/` strutturata (o mdBook): guida per feature, formato output,
      scrittura di script Rhai, note su privilegi/root
- [ ] Gallery di esempi (`examples/`): profili, script Rhai, invocazioni tipo

### 26.2 — Qualità del codice
- [ ] `cargo clippy -- -D warnings` pulito (azzerare i dead-code warning noti)
- [ ] `cargo audit` sulle dipendenze (CVE), `cargo deny` opzionale
- [ ] MSRV dichiarata in `Cargo.toml` + testata
- [ ] Pass finale di naming CLI: coerenza `--sX`/`--PX`, raggruppamento
      `--help`, nessun flag orfano non documentato
- [ ] `--guide` riletto end-to-end vs `--help` (nessun drift residuo)

### 26.3 — Progetto / community
- [ ] `LICENSE` (confermare, es. GPLv2-compat vista la nmap-os-db) + header
- [ ] `SECURITY.md` (uso etico/autorizzato), `CONTRIBUTING.md`, issue template
- [ ] **CI release:** sbloccare GitHub Actions (billing) *oppure* documentare
      ufficialmente il build manuale su Kali come processo di release
- [ ] Binari multi-OS allegati alla release (Windows/Linux/macOS)

### 26.4 — Impegni di stabilità v1.0
- [ ] Feature-freeze: nessuna nuova feature dopo il freeze fino al tag
- [ ] Contratto SemVer post-1.0 (cosa è "breaking": flag CLI, formati output,
      schema JSON/XML)
- [ ] CHANGELOG con sezione `[1.0.0]` che narra la storia 0.1→1.0
- [ ] Tag **v1.0.0** + release notes di lancio

**Definition of done v1.0:** un utente nuovo installa dal README in <5 min,
clippy/audit puliti, docs navigabili, tutte le feature a tier Production o
esplicitamente marcate Beta/Alpha, zero drift guida/CLI, stabilità dichiarata.

---

## Post-1.0 — Backlog (NON prima del v1.0)

Esplicitamente fuori scope finché non c'è il taglio stabile:
- Nuovi protocolli / adapter brute / script Rhai (solo su caso d'uso)
- REST API / modalità server
- Espansioni TUI / WebUI
- Distribuzione via package manager (cargo install, AUR, brew, apt)

---

## Quadro sintetico

| Fase | Release | Tema | Gate |
|------|---------|------|------|
| L | v0.83.x | Chiusura validazione lab | run Kali documentato |
| M | v0.84.x+ | Backlog tecnico mirato | solo con caso d'uso lab |
| 26 | **v1.0.0** | Portfolio polish + taglio stabile | **tuo ok al freeze** |
| — | post-1.0 | Backlog ampiezza | dopo v1.0 |

Ordine operativo: **L → (M se serve) → 26**. La Fase M è opzionale e
"pull-based" (entra roba solo se il lab la chiede); se il lab è pulito, si può
saltare dritti alla Fase 26 quando dai il via al v1.0.
