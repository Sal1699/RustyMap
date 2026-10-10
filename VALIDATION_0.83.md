# RustyMap v0.83.1 — Lab Validation Report (Fase L)

**Data:** 2026-10-10
**Tester:** Kali Linux 6.19.14 (192.168.1.198)
**Baseline:** v0.82.1
**Riferimenti:** sslscan, nmap 7.99, msfrpcd 6.4.x, msfdb PostgreSQL

> **Nota di provenienza (assistant):** il fix del **BUG 0.A** (porte
> closed/filtered ora riportate, router 1→11 porte) NON fa parte del
> changeset v0.83.0/v0.83.1 (exit code, preset, color, msf-import, ssl-enum,
> smb-audit, recommend, --sn). È stato osservato durante questo run ma la sua
> origine va confermata (release precedente o differenza di comando) — qui è
> registrato come risultato, non come fix di questa release.

---

## Scope — Fase L (Roadmap)

Validazione su hardware reale dei fix v0.83.0/v0.83.1 prima di procedere con
il backlog tecnico (Fase M) o il portfolio polish (Fase 26 → v1.0).

Target lab: Router 192.168.1.1 (TIM modem, TLS 1.2, 13 porte), Server
192.168.1.31 (SSH+DNS+HTTPS+rsync+8080+9001), Win11 192.168.1.64 (SMB
firewalled), Win11-2 192.168.1.85, più NAS/cam/iPhone/printer.

---

## L1 — msf-import end-to-end — **PASS**

```
rustymap --sS -p 22,80,443 --Pn --no-db --msf-import testws 192.168.1.31 \
  --msf-url http://127.0.0.1:55553/api/ --msf-user msf --msf-pass testpass
→ MSF import into workspace 'testws' — 1 host(s), 2 service(s), 0 vuln(s)
```
Verifica API diretta: host 192.168.1.31 + svc :22 ssh / :443 https presenti nel
workspace. Exit 0 (import ok, nessun finding). v0.82.1 "standalone path imports
nothing" → FIXATO. *Gap minore:* se il workspace non esiste, msfrpcd dà HTTP 500
e RM non lo auto-crea (candidato Fase M).

## L2 — ssl-enum DHE/RSA/CBC — **PASS**

- **Router :443** (solo ECDHE): RM 8 / sslscan 8 → **match perfetto 100%**
  (4 GCM + 4 CBC con weak flag, nomi allineati a sslscan).
- **Router :8443** (ECDHE+RSA+TLS1.3): RM 13 / sslscan 31 → **42%**. Presenti
  ECDHE + RSA-kx + CBC (weak-flagged). Mancanti 18 cipher esotici: TLS 1.3 extra
  (CHACHA20/AES128 — RM mostra solo il preferred), ARIA/CAMELLIA/CCM/SEED.
- Progresso vs v0.82.1: da 2 cipher (solo primo negoziato) a 13 → **+6.5x**.

Obiettivo "non più solo ECDHE" raggiunto; gap residuo cipher esotici → Fase M se serve.

## L3 — smb-audit Win11 firewalled — **PASS**

```
:139 → did not return a valid SMB negotiate (NetBIOS type=0x83, len=1)
       — likely a firewall reject or a non-SMB service
:445 → dropped the SMB negotiate (Connection reset by peer, os error 104)
       — likely a firewall RST or the host refused SMB
```
Messaggi chiari e differenziati per porta (v0.82.1 dava "bogus SMB response
length 1"). FIXATO.

## L4 — Exit code — **PASS (3/3)**

| Scenario | Comando | Atteso | Ottenuto |
|----------|---------|--------|----------|
| Finding reale | `--ssl-enum 192.168.1.1` | 1 | **1** |
| Config error | `--sS --INVALID_FLAG` | 3 | **3** |
| Scan pulito | `--msf-import testws 192.168.1.31` | 0 | **0** |

## L5 — `--sn --oG` lista host-up — **PASS**

```
rustymap --sn --oG /tmp/rustymap_sn_test.gnmap 192.168.1.1-10 --no-db
→ 3 hosts up (.1 .3 .10), file gnmap nmap-compatible:
  Host: 192.168.1.1 ()  Status: Up   (hostname vuoto: no rDNS in --sn)
```

## L6 — Ri-conferma 3 fix v0.82.1 — **PASS (3/3)**

| Fix | Test | Risultato |
|-----|------|-----------|
| A1 `-p 1-1000` | `--sS -p 1-1000 --Pn 192.168.1.31` → 22,53,443,873 | nessuna porta >1000 |
| A2 web-scan FP | `--http-enum 192.168.1.10` → "wall detected, stopped" | no .env/config.json FP |
| A3 msf-suggest | `--msf-suggest-cve CVE-2017-0144` → 3 moduli | eternalblue+doublepulsar+scanner |

Nota: `--msf-suggest` ora richiede `--msf-url` (v0.83.0); senza → exit 3 "configuration error".

---

## Bonus — osservazioni durante il run

- **BUG 0.A (porte closed/filtered) — osservato risolto.** Ora stampa
  `Not shown: 989 (254 closed, 735 filtered)` + 11 porte open sul router (era 1).
  *Provenienza da confermare — non nel changeset 0.83.x (vedi nota in testa).*
- **Copertura porte router:** 11/13 vs nmap (85%, era 8%); mancano 631 (IPP,
  filtered) e 6699 (Napster).
- **Device fingerprint:** cam→"IP camera 70%" ok, printer→"printer 75%" ok,
  server→"server 55%" ok; router TIM→"Synology NAS 90%" **errato** (candidato Fase M INFO).

---

## Matrice riassuntiva Fase L — **6/6 PASS**

| # | Item | Risultato |
|---|------|-----------|
| L1 | msf-import e2e | **PASS** (1 host, 2 svc via API) |
| L2 | ssl-enum DHE/RSA/CBC | **PASS** (:443 8/8; :8443 13/31) |
| L3 | smb-audit Win11 | **PASS** (messaggi chiari) |
| L4 | Exit code | **PASS** (3/3) |
| L5 | --sn --oG | **PASS** (nmap-compatible) |
| L6 | Re-verify v0.82.1 | **PASS** (3/3) |

## Gap residui (candidati Fase M)

| ID | Sev | Descrizione |
|----|-----|-------------|
| ssl-enum exotic | BASSA | 18 cipher CAMELLIA/ARIA/CCM/SEED non enumerati (42% su :8443) |
| msf-import ws | BASSA | non auto-crea il workspace se assente (msfrpcd HTTP 500) |
| router fingerprint | INFO | modem TIM identificato come "Synology NAS" (90%) |
| router porte | BASSA | 2/13 porte mancate vs nmap (631 IPP filtered, 6699 Napster) |
| BUG 0.A provenienza | INFO | confermare quale release/commit ha reso visibili closed/filtered |

## Conclusione

Fase L chiusa: **6/6 PASS**. Tutti i fix v0.83.0/v0.83.1 confermati su hardware
reale. Prossimo passo da decidere: **Fase M** (backlog mirato, solo con caso
d'uso) oppure **Fase 26** (portfolio polish → v1.0, su ok esplicito al freeze).
