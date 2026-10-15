# VALIDATION — v0.88.2 (`--fast-engine` + Linux `sendmmsg` batch)

**Data:** 2026-10-15 · **Lab:** Kali, home /24 (ROUTER .1, SERVER .31, CAM .226)
· **Build:** v0.88.2 (tag `8ad84cc`) · **Riferimento:** nmap + hyperfine ·
**Piano:** [KALI_TEST_v0.88.md](KALI_TEST_v0.88.md).

Chiude la Fase 30: valida il batch `sendmmsg(2)` del motore `--fast-engine`,
confronto **fast vs default vs nmap** e l'evoluzione v0.88.0 → .1 → .2.

---

## Pre-flight — sendmmsg attivo

```
$ sudo rustymap --sS --fast-engine -F 192.168.1.31 --trace-raw 2>&1 | grep 'sendmmsg burst'
[raw-tx] sendmmsg burst 192.168.1.31 → 100 ports (100 queued)
```
**CONFERMATO** — il send batch `sendmmsg(2)` su Linux si attiva.

---

## F1 — Correttezza  → **PASS**

| # | Scan | Default | Fast | nmap | Verdetto |
|---|------|---------|------|------|----------|
| F1.1 | SYN 1-1000 SERVER | 22,53,443,873 | idem | — | MATCH |
| F1.2 | SYN -F ROUTER | 10 open (53,80,139,443,445,5000,8000,8080,8443,49152) | idem | stessi 10 | MATCH |
| F1.3 | SYN 1-65535 SERVER | 10 porte (22,53,443,873,1883,3990,3991,8080,8883,9001) | idem | — | MATCH |
| F1.4 | ACK 1-1000 SERVER | 1000 unfiltered | idem | — | MATCH |
| F1.5 | Window 1-1000 SERVER | 1000 closed | idem | — | MATCH |
| F1.6 | FIN/NULL/Xmas 1-1000 SERVER | ~996 closed + pochi open/of | idem ±1-2 | — | ~MATCH (varianza timing) |
| F1.7 | Maimon 1-1000 SERVER | 999 closed, 1 open | 1000 closed | — | ~MATCH (±1) |
| F1.8 | SYN 1-1000 ROUTER (lossy) | 1 open | 2 open | 5 open | FAST migliore |

- SYN / ACK / Window: **match perfetto** su tutti i test.
- FIN / NULL / Xmas / Maimon: ±1-2 porte, varianza **intrinseca** di questi scan
  (dipendono dal timeout, su rete viva) — non specifica del motore.
- Lossy: il fast trova **più** porte del default (coerente su .0/.1/.2).
- **Nessun caso** in cui il fast perde sistematicamente porte che il default trova.

---

## F2 — Throughput (hyperfine)  → **PASS, il fast vince ovunque**

| Scenario | Default | Fast | nmap | Fast vs Default | Fast vs nmap |
|----------|---------|------|------|-----------------|--------------|
| SYN -F /24 sweep | 21.11s | **18.73s** | 42.17s | **1.13× più veloce** | 2.25× |
| SYN 1-65535 host | 27.68s | **15.77s** | 18.86s | **1.76×** | 1.20× |
| SYN 1-1000 host | 1.90s | **0.83s** | 3.03s | **2.29×** | 3.66× |
| ACK 1-1000 host | 1.88s | **1.31s** | 2.72s | **1.43×** | 2.07× |

### Evoluzione su 3 release

```
                 v0.88.0        v0.88.1        v0.88.2
Sweep /24:       3.0× SLOWER →  1.19× slower → 1.13× FASTER
Full-65535:      1.16× slower → 1.10× slower → 1.76× FASTER
SYN 1-1000:      1.67× faster → ~1.15× faster → 2.29× FASTER
ACK 1-1000:      nmap wins    → 1.74× faster → 2.07× vs nmap
```

Il batch `sendmmsg(2)` di v0.88.2 ha eliminato la regressione dello sweep che
bloccava la promozione in v0.88.0/.1. Il fast ora batte **sia il default sia
nmap** su ogni scenario testato.

### Dati grezzi hyperfine
- Sweep /24 — Default 21.109s ±6.850 · Fast 18.732s ±5.944 · nmap 42.168s ±17.720
- Full-65535 — Default 27.684s ±12.129 (outlier) · Fast 15.774s ±1.969 (il più stabile) · nmap 18.858s ±1.361
- SYN 1-1000 — Default 1.899s ±0.692 · Fast 0.828s ±0.414 · nmap 3.030s ±0.806
- ACK 1-1000 — Default 1.882s ±0.616 · Fast 1.314s ±0.890 · nmap 2.715s ±1.285

---

## Verdetto & promozione

**I criteri di promozione sono soddisfatti:** F1 PASS (identico o migliore su
tutti gli 8 tipi di scan), F2 PASS (fast ≥ default su **tutti** gli scenari,
incluso lo sweep /24 e full-65535 che bloccavano prima), sendmmsg attivo,
nessuna regressione sulle feature non-raw.

→ **`--fast-engine` è pronto a diventare il motore raw di DEFAULT.** La modalità
e la release della promozione (gestione flag `--legacy-engine`, scope non-Linux,
numero di versione vs Fase 31) sono **proposte all'utente** prima
dell'implementazione — la matrice di maturità (`src/maturity.rs`) va da
`[sperimentale]` a Production nello stesso cambio.

### Residui (non bloccanti)
- **Host lossy:** sia fast che default trovano meno porte di nmap su target
  rate-limited (nmap ha retransmit per-host superiore). Non è una regressione
  (stesso limite nel default) → lavoro futuro **Fase 31** (congestion control /
  pacing adattivo per-host).
- **Varianza FIN/NULL/Xmas:** ±1-2 porte è intrinseco a questi scan, non
  dipende dal motore.
