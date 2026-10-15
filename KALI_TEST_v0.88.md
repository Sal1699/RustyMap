# RustyMap v0.88.0 — Kali Test Roadmap (Fase 30: --fast-engine)

Valida il nuovo motore raw `--fast-engine` (burst-send + poll-collect async),
dall'installazione al confronto throughput. Il flag è **opt-in**: il path raw
di default è invariato, quindi l'obiettivo è decidere **se promuoverlo a
default** (vince in throughput mantenendo la stessa correttezza).

> `--fast-engine` agisce solo sugli scan raw TCP: `--sS/--sA/--sW/--sF/--sN/
> --sX/--sM`. NON su `--sU` (UDP) né `--sT` (connect). Tutti = **root**.
> Serve `hyperfine` (`apt install hyperfine`) per i bench.

---

## 0. Update a v0.88.0

```sh
cd ~ ; git clone https://github.com/Sal1699/RustyMap.git 2>/dev/null || true
cd RustyMap && git fetch origin --tags && git checkout v0.88.0 && cargo build --release
install -m 0755 target/release/rustymap "$(command -v rustymap || echo /usr/local/bin/rustymap)"
rustymap --version   # → rustymap 0.88.0
RM=rustymap
ROUTER=192.168.1.1 ; SERVER=192.168.1.31 ; CAM=192.168.1.226 ; NET=192.168.1.0/24
```

---

## F0 — Smoke

| # | Comando | Atteso |
|---|---------|--------|
| F0.1 | `sudo $RM --sS --fast-engine -F $SERVER` | banner `[fast-engine] experimental raw engine active`; scan completa, exit 0/1 |
| F0.2 | `sudo $RM --sS --fast-engine -F $NET` | sweep /24 completa senza hang/panic |
| F0.3 | `$RM --help | grep fast-engine` | la riga del flag c'è |

## F1 — Correttezza: fast == default (CRITICO per promuoverlo)

Per ogni scan, confronta gli stati porta **con e senza** `--fast-engine`: devono
coincidere (open/closed/filtered). Poi confronta con nmap.

| # | Default | Fast | Atteso |
|---|---------|------|--------|
| F1.1 | `sudo $RM --sS -p 1-1000 $SERVER` | `… --fast-engine` | **stessi** open/closed/filtered |
| F1.2 | `sudo $RM --sS -F $ROUTER` | `… --fast-engine` | stessi open; vs `nmap -sS -F $ROUTER` |
| F1.3 | `sudo $RM --sS -p 1-65535 $SERVER` | `… --fast-engine` | stessi open; vs `nmap -sS -p- $SERVER` |
| F1.4 | `sudo $RM --sA -p 1-1000 $SERVER` | `… --fast-engine` | stessi unfiltered/filtered (vs `nmap -sA`) |
| F1.5 | `sudo $RM --sW -p 1-1000 $SERVER` | `… --fast-engine` | stessi open/closed |
| F1.6 | `sudo $RM --sF $SERVER` / `--sN` / `--sX` | `… --fast-engine` | stessi closed/open\|filtered |
| F1.7 | `sudo $RM --sM -p 1-1000 $SERVER` | `… --fast-engine` | stessi |
| F1.8 | host lossy/rate-limited ($ROUTER) `--sS -p 1-1000` | `… --fast-engine` | fast NON deve perdere open che il default trova (retransmit) |

**Verdetto F1:** fast è promuovibile solo se **tutti** i confronti coincidono.

## F2 — Throughput (hyperfine: fast vs default vs nmap)

> **v0.88.1 fix da verificare qui:** in v0.88.0 il fast engine aspettava l'intero
> `--timeout` a ogni round sulle porte filtered (il loop esce in anticipo solo
> quando *tutte* le pending rispondono, e una porta filtered non risponde mai).
> v0.88.1 rende la finestra di collect **adattiva** (~10×RTT, come il path
> default). Atteso: su sweep filtered (`-F /24`, `$ROUTER`) il fast ora
> **affianca** il default invece di restare indietro. Open/closed erano già a
> posto (uscita anticipata). Se il fast è ancora molto più lento del default su
> host firewallati → riportamelo.

```sh
hyperfine -w1 -r5 \
  "sudo $RM --sS -F $NET --no-builtin-scripts" \
  "sudo $RM --sS --fast-engine -F $NET --no-builtin-scripts" \
  "sudo nmap -sS -F -n $NET"
```
Ripeti per: `--sS -p 1-1000 $SERVER`, `--sS -p 1-65535 $SERVER`,
`--sS -F` su host singolo responsivo (CAM/SERVER), `--sA -p 1-1000 $SERVER`.

| Scenario | default | fast | nmap | fast vince? |
|----------|---------|------|------|-------------|
| SYN -F /24 | | | | |
| SYN 1-1000 host | | | | |
| SYN full-65535 host | | | | |
| SYN -F host responsivo | | | | |
| ACK 1-1000 | | | | |

**Osserva anche:** numero thread (fast ~2 vs default fino a `--max-parallel`) —
`ps -T -p $(pgrep -n rustymap) | wc -l` durante lo scan.

## F3 — Edge / robustezza

| # | Comando | Atteso |
|---|---------|--------|
| F3.1 | `sudo $RM --sS --fast-engine --max-retries 0 -p 1-1000 $SERVER` | nessun retransmit; più veloce, forse più filtered |
| F3.2 | `sudo $RM --sS --fast-engine --max-retries 5 -p 1-1000 $ROUTER` | meno falsi-filtered su host lossy |
| F3.3 | `sudo $RM --sS --fast-engine --evasion ghost -F $SERVER` | evasion (frag/decoy/jitter) rispettata, no crash |
| F3.4 | `sudo $RM --sS --fast-engine -p 1-65535 $NET` | /24 × 65535: no hang, memoria stabile |
| F3.5 | `sudo $RM --sS --fast-engine -F <host down>` | "host seems down", exit pulito |

## F4 — Regressione (non-raw: deve restare OK)

| # | Comando | Atteso |
|---|---------|--------|
| F4.1 | `rustymap $ROUTER --sV` | 307 script, 0 FP catch-all (v0.87.1 hold) |
| F4.2 | `rustymap --script-category ics --script-catalog /tmp/c.json` | 8 of 307 (v0.87.1 hold) |
| F4.3 | `sudo rustymap --sS -p 1-1000 $ROUTER` (default) | footer "1000 port-probes" (v0.86.1 hold) |
| F4.4 | `rustymap --cms-detect $ROUTER` / `--iot-discover $NET` | http:// / errore CIDR (v0.86.1 hold) |

---

## Decisione post-test
- **F1 tutti PASS + F2 fast ≥ default** → promuovi `--fast-engine` a default (prossima patch) e procedi con la **prossima release** (batch Linux `sendmmsg`/AF_PACKET per il vero salto throughput).
- **F2 fast ≈ default senza sendmmsg** → atteso: il win vero arriva con il batch `sendmmsg`; tieni il flag opt-in, implementiamo il batch e ri-benchiamo.
- **F1 divergenze** → bug nel motore fast: riportami quali porte differiscono (quali stati) e fix in 0.88.x.

## Done criteria
`VALIDATION_0.88.md` (tabella F1 coincidenze + numeri F2) + riga `LAB_VALIDATION.md` + decisione promuovi/attendi-sendmmsg.
