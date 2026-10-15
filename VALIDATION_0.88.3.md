# VALIDATION — v0.88.3 (fast engine as default) → reverted to opt-in in v0.88.4

**Data:** 2026-10-15 · **Lab:** Kali, home /24 (ROUTER .1, SERVER .31) ·
**Build:** v0.88.3 (tag `c9abe90`) · **Riferimento:** nmap + hyperfine.

Run che ha testato il flip a default del fast engine. **Esito: nessuna
regressione di codice, ma il fast manca di congestion control sul full-port
sotto carico → si decide di rimettere il fast OPT-IN (v0.88.4) fino alla Fase
31.** La raccomandazione del report Kali ("regressione introdotta dal refactor")
è stata **confutata** (vedi sotto), ma la postura conservativa viene adottata lo
stesso.

---

## Pre-flight — PASS
- `--version` → 0.88.3; `--sS -F SERVER --trace-raw` → `sendmmsg burst … 100
  queued` (fast di default confermato).
- `--sS --legacy-engine` → `[legacy-engine] … per-probe path` (opt-out OK).
- `--help` mostra `--fast-engine [DEPRECATED]` + `--legacy-engine`.

## F1 — Correttezza  → PASS
- F1.1/F1.3 SYN: fast == legacy. F1.4 ACK, idem.
- **F1.2 SYN -F ROUTER: fast trova 10 porte (= nmap), legacy solo 7** (manca
  8000/8443/49152) → il fast è più accurato.
- F1.5/F1.7 Window/Maimon: **il LEGACY** mostra 2 "open" spurie (22,873) che
  tutte le versioni precedenti davano closed → quirk del path legacy
  (timing-dependent), NON del fast. Non bloccante.
- Nessun caso in cui il fast perde porte che il legacy trova.

## F2 — Throughput: il confronto cross-run NON è valido

Il report concludeva "regressione 2× sul full-port introdotta dal refactor".
**Falso, e dimostrabile:** `git diff v0.88.2 v0.88.3` →

- `src/raw_scan.rs` (tutto il fast engine **e** il legacy `run_raw_tcp_scan`):
  **diff vuoto**. Zero modifiche al motore.
- Unico cambiamento funzionale: il boolean di dispatch in `main.rs`
  (`use_fast = !args.legacy_engine`) + il flag nuovo + stringhe.

Quindi il binario del path fast in v0.88.3 **è identico** al `--fast-engine` di
v0.88.2, e il legacy **è identico** al default di v0.88.2. Una regressione di
codice è impossibile. I numeri diversi sono **ambiente/rumore**, provato dai
dati stessi del report (binari immutati che "cambiano" tra i due run):

| | v0.88.2 run | v0.88.3 run |
|---|---|---|
| nmap sweep /24 (controllo, binario identico) | 42.2s ±17.7 | **85.0s ±76.1** (fino a 207s) |
| legacy sweep (codice identico) | 21.1s | 11.3s |
| legacy full-65535 (codice identico) | 27.7s | 12.8s |
| fast full-65535 (codice identico) | 15.8s ±2.0 | 34.1s ±19 (best-case 12.4s) |

nmap (stesso identico binario) raddoppia con varianza enorme → l'ambiente del
run v0.88.3 era molto più rumoroso. I vincitori *within-run* dei due run si
contraddicono (v0.88.2: fast vince; v0.88.3: legacy vince) con lo **stesso
codice** → benchmark dominato dalla varianza.

### Il segnale reale (preesistente, non una regressione)
Within-run v0.88.3 il fast è **instabile sul full-65535** (σ=19, 12.4–48.7s)
mentre il legacy è stabile (σ=0.3). Causa plausibile: il burst `sendmmsg` di
65535 SYN quasi istantaneo → ~65k RST di ritorno in blocco → il singolo
receiver / il rate-limit RST dell'host **perde** risposte → round di retransmit
→ varianza. Il legacy, pacing per-probe, non satura. **Esisteva già in v0.88.2**
(stesso codice; nel run quieto non si è manifestato). È una lacuna di
**congestion control** = dominio della **Fase 31**.

---

## Decisione (utente): fast torna OPT-IN in v0.88.4

- **Nessun revert di codice del motore** (non c'è regressione). Il flip del
  default è però invertito: il **default torna al path per-probe (stabile)**, il
  **`--fast-engine` torna opt-in**, `--legacy-engine` (introdotto in v0.88.3)
  viene rimosso → postura CLI = v0.88.2.
- **Motivo:** un default non deve poter essere 2.6× più lento/instabile sul
  full-port sotto carico. Il fast resta disponibile (opt-in) e vince su
  sweep/SYN; verrà ri-promosso quando la **Fase 31 (congestion control,
  v0.89.0)** avrà aggiunto l'in-flight window/pacing che irrobustisce il burst
  sui range grandi.

### Metodo per i bench futuri (lezione)
Confrontare fast/legacy/nmap **solo nello stesso run/sessione** (mai cross-run o
cross-giorno), host "caldo", più ripetizioni; usare nmap come controllo — se il
controllo si muove di 2×, il run non è comparabile.
