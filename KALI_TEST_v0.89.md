# RustyMap v0.89.0 — Kali Test Roadmap (Fase 31: congestion control)

Valida la finestra di congestione (cwnd AIMD) + il rate pacer del
`--fast-engine`. Obiettivo centrale: **il full-port col fast ora deve essere
STABILE** (niente più σ≈19s / bimodale 12–48s di v0.88.3) e **recuperare gli
open sotto flood** sugli host che rate-limitano. Serve `hyperfine`.

> La cwnd agisce SOLO sul `--fast-engine` (raw TCP). Il path di default
> (per-probe) e il connect (`--adaptive`) sono invariati. Tutti gli scan raw =
> **root**.

## 0. Update a v0.89.0
```sh
cd ~/RustyMap && git fetch origin --tags && git checkout v0.89.0 && cargo build --release
sudo install -m 0755 target/release/rustymap /usr/local/bin/rustymap
rustymap --version   # → rustymap 0.89.0
RM=rustymap ; ROUTER=192.168.1.1 ; SERVER=192.168.1.31 ; NET=192.168.1.0/24
```

## C0 — Smoke
| # | Comando | Atteso |
|---|---------|--------|
| C0.1 | `sudo $RM --sS --fast-engine -F $SERVER` | scan completa, exit 0/1 |
| C0.2 | `$RM --help \| grep -E "min-rate\|max-rate"` | entrambe le righe presenti |
| C0.3 | `sudo $RM --sS --fast-engine --max-rate 2000 --min-rate 200 -p 1-1000 $SERVER` | parsa + completa |

## C1 — Stabilità full-port (IL test chiave vs v0.88.3)
Ripeti il full-65535 col fast, **stesso run**, più ripetizioni, e guarda la σ.
```sh
hyperfine -w1 -r5 \
  "sudo $RM --sS --fast-engine -p 1-65535 $SERVER" \
  "sudo $RM --sS --legacy-engine -p 1-65535 $SERVER" \
  "sudo nmap -sS -p- -n $SERVER"
```
| Verdetto | Criterio |
|---|---------|
| **PASS** | fast **stabile** (σ piccola, no range 12–48s) e ~alla pari del legacy; nmap come controllo (se nmap oscilla 2×, run rumoroso → ripeti) |
| FAIL | fast ancora bimodale/σ alta → riportami i numeri (serve alzare cwnd max o rivedere la soglia AIMD) |

## C2 — Recupero open sotto rate-limit (ROUTER lossy)
```sh
for i in 1 2 3; do sudo $RM --sS --fast-engine -p 1-1000 $ROUTER | grep -c open; done
for i in 1 2 3; do sudo $RM --sS --legacy-engine -p 1-1000 $ROUTER | grep -c open; done
sudo nmap -sS -p 1-1000 -n $ROUTER | grep -c open   # riferimento
```
Atteso: il fast con cwnd recupera **≥** gli open del legacy e si avvicina a nmap
(il backoff rallenta e ripesca gli open persi nel flood). Conferma col trace che
la cwnd fa backoff su host che risponde:
`sudo $RM --sS --fast-engine -p 1-1000 $ROUTER --trace-raw 2>&1 | grep sendmmsg | head`.

## C3 — `--max-rate` è un tetto reale
```sh
# ~1000 pps: 65535 porte dovrebbero metterci ALMENO ~65s
time sudo $RM --sS --fast-engine --max-rate 1000 -p 1-65535 $SERVER
```
Atteso: durata ≳ (porte / max-rate); senza `--max-rate` è molto più veloce.

## C4 — `--min-rate` (floor della cwnd)
```sh
sudo $RM --sS --fast-engine --min-rate 5000 -p 1-65535 $ROUTER   # host lossy
```
Atteso: su host che rate-limita, con `--min-rate` alto il fast NON collassa a
cwnd minima (resta più veloce, a costo di qualche open perso) → trade-off
regolabile dall'utente.

## C5 — Regressione (quello che già funzionava)
| # | Comando | Atteso |
|---|---------|--------|
| C5.1 | `--fast-engine -F $NET` sweep | ~veloce come v0.88.2 (cwnd ≥ 100 porte/host → 1 wave) |
| C5.2 | `--fast-engine -p 1-1000 $SERVER` vs `--legacy-engine` | stessi open/closed/filtered |
| C5.3 | SYN/ACK/Window correttezza fast == legacy | invariata (F1 di VALIDATION_0.88.2/0.88.3) |

## Decisione post-test
- **C1 PASS (fast stabile) + C2 PASS (recupera open) + C5 nessuna regressione**
  → `--fast-engine` è candidato a **ri-promozione a default** (rifare il flip di
  v0.88.3 ma stavolta con la cwnd). Bench fast-vs-legacy-vs-nmap **nello stesso
  run** per decidere.
- Se la cwnd **over-backs-off** su host firewallati-ma-responsivi (full-port
  lento) → segnalamelo: si alza la soglia AIMD o si lega il backoff al
  recupero-su-retransmit invece che al drop-ratio puro.

## Done criteria
`VALIDATION_0.89.md` (tabella C1 σ + C2 open-count + C3/C4 effetto rate) + riga
`LAB_VALIDATION.md` + decisione ri-promozione sì/no.
