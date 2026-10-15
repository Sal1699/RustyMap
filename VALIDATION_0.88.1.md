# VALIDATION — v0.88.1 (`--fast-engine` adaptive collect window)

**Data:** 2026-10-15 · **Lab:** home /24 (Kali, root) · **Riferimento:** nmap +
hyperfine · **Piano:** [KALI_TEST_v0.88.md](KALI_TEST_v0.88.md) (F1 correttezza,
F2 throughput).

Valida la fix di v0.88.1 — finestra di *collect* adattiva per il motore
`--fast-engine` — confrontando **fast vs default vs nmap** e **v0.88.0 vs
v0.88.1**. Il flag resta **opt-in**; l'obiettivo del run era decidere se
promuoverlo a default.

---

## F2 — Throughput (fast vs default)

| Scenario | v0.88.0 fast vs default | v0.88.1 fast vs default | Esito |
|---|---|---|---|
| SYN `-F` /24 sweep | 3.0× più lento | **1.19× più lento** | regressione quasi chiusa |
| SYN full-65535 host | 1.16× più lento | **1.10× più lento** | leggero miglioramento |
| ACK 1-1000 host | 1.16× più lento (vinceva nmap) | **1.74× più veloce del default**, 1.45× di nmap | da perdente a vincitore |
| SYN 1-1000 host | 1.67× più veloce | ~1.15× più veloce (alta varianza, bench concorrenti) | confermato più veloce |

**Lettura:** v0.88.1 ha eliminato la regressione critica dello sweep /24
(3× → 1.19×). Il fast ora **batte** il default su ACK e SYN 1-1000, ma resta
ancora **leggermente sotto** il default sui due scan più rappresentativi: lo
sweep SYN `-F` /24 (1.19×) e il full-65535 (1.10×).

### Scan stealth — probes/s (solo fast-engine)

| Scan | v0.88.0 | v0.88.1 | Miglioramento |
|---|---|---|---|
| FIN | 203 p/s | 565 p/s | 2.8× |
| NULL | 215 p/s | 517 p/s | 2.4× |
| Xmas | 216 p/s | 622 p/s | 2.9× |

La finestra adattiva triplica quasi il rate dei probe FIN/NULL/Xmas (questi scan
vedono soprattutto porte senza risposta → prima pagavano l'intero `--timeout`
a ogni round).

---

## F1.8 — Host lossy (correttezza su router rate-limited)

| Engine | v0.88.0 | v0.88.1 | nmap |
|---|---|---|---|
| Default | 1 porta (53) | 1 porta (53) | 53,80,139,443,445 |
| Fast | 2 porte (53,80) | **3 porte (53,139,445)** | 53,80,139,443,445 |

Il fast v0.88.1 è un **superset** del default (`{53,139,445} ⊇ {53}`): non perde
nessuna porta che il default trova → il criterio F1.8 ("il fast non deve perdere
open che il default trova") è **rispettato**. Il fast è anzi nettamente migliore
del default sul lossy (3/5 vs 1/5).

**Gap residuo (non una regressione del fast):** sia fast che default mancano
porte che nmap trova (fast 3/5, default 1/5, nmap 5/5). È un problema di
retransmit/timing su host lossy/rate-limited, condiviso dai due path →
**candidato Fase 31 (congestion control / rate-limiting)**, non un difetto
introdotto dal fast-engine.

---

## Verdetto

v0.88.1 è un **chiaro passo avanti** e chiude il problema bloccante di v0.88.0:

- Sweep /24: **3× → 1.19× più lento** (quasi al pari del default)
- ACK: **da perdente a vincitore** (1.74× vs default)
- FIN/NULL/Xmas: **probes/s ~2.4–2.9×**
- Lossy: correttezza **3/5 vs 2/5** (e superset del default)

## Decisione — `--fast-engine` resta OPT-IN (promozione a default NON ancora)

Il criterio di promozione (KALI_TEST_v0.88.md) è **"F1 tutti PASS + F2 fast ≥
default"**. Non è ancora pienamente soddisfatto:

1. **F2 non uniforme.** Il fast è ≥ default su ACK/SYN-1000/stealth, ma è ancora
   **sotto** il default sui due scan di punta — SYN `-F` /24 (1.19×) e
   full-65535 (1.10×). Promuoverlo ora renderebbe il 19% più lento lo scan più
   comune (lo sweep SYN). Soglia **vicina ma non raggiunta**.
2. **F1.1–F1.7 non nel run.** Questo estratto copre F1.8 (lossy) + F2; la parità
   `fast == default` su open/closed/filtered per host normali/full-port
   (F1.1–F1.7) va **confermata** prima di rendere il fast il path di default per
   tutti.
3. **Lo step che chiude il gap è il prossimo.** Il batch Linux
   `sendmmsg`/`AF_PACKET`-ring collassa N send syscall in ~N/50 → mira
   esattamente al residuo di sweep/full-port. La mossa disciplinata: **landare
   `sendmmsg`, ri-benchare; se il fast diventa ≥ default anche sullo sweep E
   F1.1–F1.7 confermano la correttezza → promuovere a default in quella
   release.**

Coerente col ramo previsto dal piano: *"F2 fast ≈ default senza sendmmsg → tieni
il flag opt-in; il win vero arriva col batch sendmmsg."*

## Prossimi passi

- [ ] **Confermare F1.1–F1.7** (fast == default: stessi open/closed/filtered su
      host responsivo, `-p 1-1000`, full-65535, `--sA`/`--sW`/`--sM`,
      `--sF`/`--sN`/`--sX`).
- [ ] **Fase 30 — batch `sendmmsg`/`AF_PACKET`-ring** (da scrivere+benchare su
      Kali): obiettivo fast ≥ default anche su sweep /24 e full-65535.
- [ ] Ri-bench F2 post-sendmmsg → **decisione promozione** a default.
- [ ] (Fase 31) retransmit/congestion tuning sul lossy → recuperare le porte che
      oggi sfast/default mancano vs nmap (fast 3/5 → 5/5).
