# RustyMap — Test Roadmap v0.82 (RustyMap vs nmap, comandi completi)

Piano di test per **v0.82.0**. Copia i comandi così come sono (zsh-safe).
**PARTE A** ri-valida ciò che 0.82 ha cambiato — i 6 bug + web + Metasploit —
confrontando col comportamento che falliva in 0.81. **PARTE B** è il
testa-a-testa completo (tempi con hyperfine). Logga in `LAB_VALIDATION.md`.

---

## SETUP — una volta

```zsh
cd ~/RustyMap && git pull && cargo build --release
sudo install -m755 target/release/rustymap /usr/local/bin/rustymap
rustymap --version      # DEVE dire 0.82.0
sudo apt install -y nmap hyperfine ldnsutils
```

### Variabili del lab (i tuoi host reali del run 0.81 — adatta se cambiano)
```zsh
ROUTER=192.168.1.1      # TIM/Vantiva modem (53,80,443,445,8080…)
SERVER=192.168.1.31     # Alcatel-Lucent AP / OpenWrt (22,53,443,8080…)
CAM=192.168.1.34        # Reolink IP camera (80,443,554,1935,8000,9000)
WIN=192.168.1.64        # Windows 11 (135,139,445,902,912,5357)
LINUX=192.168.1.148     # Linux/printer (139,445,515)
DNS=192.168.1.1         # un resolver (router)
NET=192.168.1.0/24
OSDB=/usr/share/nmap/nmap-os-db
```

### Regole
- Raw (`--sS/--sF/…/--sY/-O`) = **sudo**. Testo (`--sV/--web-scan/--msf-*`) = no root.
- Ratio = nmap / RustyMap (>1 → RustyMap più veloce).
- PASS = combacia o la divergenza è compresa e annotata.

---

# PARTE A — Ri-validazione fix v0.82.0 (PRIORITÀ)

## A1 — Script opt-in → port-scan raw di nuovo veloci (bug #1/#4 + residuo A1)
Pre-0.82: `--sS -F` su host responsivi era 25-64× più lento (gli script
giravano su ogni scan). Ora gli script auto partono SOLO su scan di default o
`-sV`/`-A`, non sui port-scan raw espliciti.

```zsh
# Il test che prima falliva di brutto (CAM era 64× lento):
sudo hyperfine -w1 -r5 "rustymap --sS -F $CAM"    "nmap -sS -F $CAM"
sudo hyperfine -w1 -r5 "rustymap --sS -F $SERVER" "nmap -sS -F $SERVER"
sudo hyperfine -w1 -r5 "rustymap --sS -p 1-1000 $ROUTER" "nmap -sS -p 1-1000 $ROUTER"
```
**PASS:** il gap su `-F` deve **crollare** (da 25-64× a ~pari). Verifica il
comportamento degli script (il cuore del fix):
```zsh
rustymap --sS -F $CAM        2>&1 | grep -ci finding   # 0 → script NON auto su scan raw
rustymap $CAM                2>&1 | grep -ci finding   # >0 → triage default LI esegue
rustymap --sV -F $CAM        2>&1 | grep -ci finding   # >0 → -sV LI esegue
rustymap --sS -F --force-scripts $CAM 2>&1 | grep -ci finding  # >0 → override
```
**PASS:** 0 sul `--sS` nudo, >0 su default/`-sV`/`--force-scripts`.

Bug #1 (porte fuori range): con gli script spenti sul raw scan, `-p 1-1000`
non deve più "trovare" 1935/8000/9000.
```zsh
sudo rustymap --sS -p 1-1000 $CAM | grep -oE "^[0-9]+"   # solo porte <=1000
```

## A2 — Label SCTP `/sctp` (bug #2)
```zsh
sudo rustymap --sY -p 132,9899,3868 $HOST 2>&1 | grep -E "/sctp|/tcp"
```
**PASS:** le porte compaiono come `132/sctp`, non `132/tcp`.

## A3 — SCTP senza `--Pn` non dice più "Host seems down" (bug #3)
```zsh
sudo rustymap --sY -p 132,9899 $SERVER          # senza --Pn: ora implica -Pn, deve scansionare
sudo rustymap --sY -p 132,9899 --Pn $SERVER     # identico
sudo nmap -sY -p 132,9899 $SERVER
```
**PASS:** stampa "[i] SctpInit scan implies -Pn (…)" e produce stati porta
(filtered/open/closed), **non** "Host seems down".

## A4 — ARP trova più host (bug #5)
```zsh
sudo rustymap --PR $NET 2>&1 | grep -c "report for"
sudo nmap -PR -sn $NET   2>&1 | grep -c "report for"
```
**PASS:** il conteggio RustyMap si avvicina a nmap (prima 14 vs 18). Se ancora
sotto, rilancia 2-3 volte: i device in sleep rispondono a round diversi.

## A5 — web-scan: niente falsi positivi + nuove feature (bug #6 + web)
```zsh
rustymap --web-scan $ROUTER      # router che risponde 200 a tutto
rustymap --web-scan $CAM
```
**PASS:**
- **niente** più `.env`/`backup.zip`/`config.json` fasulli sul ROUTER; se il
  server è catch-all compare la nota "answers 200 to random paths …";
- nuove righe se presenti: **HTTP methods** (PUT/DELETE/TRACE), **CORS**
  (reflection/`*`), e i path nuovi (actuator/heapdump, graphql, ssh-key…).
Confronto path:
```zsh
nmap -p80,443 --script http-enum,http-methods $ROUTER
```

## A6 — Metasploit `--msf-suggest` (nuovo)
Serve msfrpcd attivo: `msfrpcd -P <pass> -a 127.0.0.1` (o token).
```zsh
rustymap -sV --msf-suggest \
  --msf-url https://127.0.0.1:55553 --msf-token "$MSF_TOKEN" --msf-insecure $SERVER
```
**PASS:** dopo lo scan stampa, per ogni CVE correlato, i moduli MSF trovati +
una riga `use …; set RHOSTS <host>` pronta. Read-only (non lancia nulla).
Confronto: in msfconsole `search cve:<CVE>`.

---

# PARTE B — Testa-a-testa completo (tempi)

## B1 — Discovery
```zsh
sudo hyperfine -w1 -r3 "rustymap --sn $NET" "nmap -sn $NET"
sudo rustymap --PR $NET | sort ;  sudo nmap -PR -sn $NET | grep report
```

## B2 — SYN / connect (il focus velocità)
```zsh
sudo hyperfine -w1 -r5 "rustymap --sS -F $CAM"          "nmap -sS -F $CAM"
sudo hyperfine -w1 -r5 "rustymap --sS -F $WIN"          "nmap -sS -F $WIN"
sudo hyperfine -w1 -r3 "rustymap --sS -p 1-65535 $CAM"  "nmap -sS -p 1-65535 $CAM"
hyperfine     -w1 -r5 "rustymap --sT -F $SERVER"        "nmap -sT -F $SERVER"
# set porte identico?
sudo rustymap --sS -p 1-65535 $CAM | grep -oE "^[0-9]+" | sort > /tmp/rm.txt
sudo nmap -sS -p 1-65535 $CAM | grep -oE "^[0-9]+/tcp" | cut -d/ -f1 | sort > /tmp/nm.txt
diff /tmp/rm.txt /tmp/nm.txt && echo "OK stesso set"
```

## B3 — UDP / FIN / NULL / Xmas / ACK / Window / Maimon
```zsh
sudo rustymap --sU --top-ports 20 $ROUTER ;  sudo nmap -sU --top-ports 20 $ROUTER
for S in sF sN sX sA sW sM; do
  echo "== --$S =="; sudo rustymap --$S -p 1-1000 $SERVER | tail -5
  sudo nmap -$S -p 1-1000 $SERVER | tail -5
done
```

## B4 — IP-protocol / SCTP
```zsh
sudo hyperfine -w1 -r3 "rustymap --sO $SERVER" "nmap -sO $SERVER"   # RM era 30× più veloce
sudo rustymap --sY -p 132,9899 $SERVER ;  sudo nmap -sY -p 132,9899 $SERVER
```

## B5 — Service version / OS / Aggressive
```zsh
hyperfine -w1 -r3 "rustymap --sV -F $SERVER" "nmap -sV -F $SERVER"
rustymap --sV -p 22,53,80,443,445 $SERVER ;  nmap -sV -p 22,53,80,443,445 $SERVER
sudo hyperfine -w1 -r3 "rustymap -O $SERVER" "nmap -O $SERVER"
sudo hyperfine -w1 -r3 "rustymap -A $SERVER" "nmap -A $SERVER"
```
**PASS -sV:** SSH/DNS/gSOAP/SMB/RPC come 0.81; TLS/RTSP/rsync restano gap noti.
**PASS -O:** auto-load os-db + famiglia corretta (Win11 più preciso di nmap).

## B6 — Timing templates
```zsh
for T in 3 4 5; do sudo hyperfine -w1 -r2 "rustymap --sS -F -t $T $CAM" "nmap -sS -F -T$T $CAM"; done
```
**PASS:** con gli script ora fuori dal raw scan, i template dovrebbero incidere
di più che in 0.81 (dove l'overhead script dominava).

---

# PARTE C — Feature solo-RustyMap
```zsh
rustymap --tls-scan $CAM             # matrice TLS/ALPN/HSTS/JARM/cert
rustymap --web-scan $ROUTER          # header grade + WAF + methods + CORS + path
rustymap --recommend $SERVER         # flag suggeriti
rustymap --detect-preview --sS -A $SERVER
```

---

## Matrice da compilare (manda a me)

| Test | RustyMap 0.82 | nmap | Ratio | 0.81 era | PASS? |
|------|---------------|------|-------|----------|-------|
| A1 `--sS -F` CAM | _s_ | _s_ | _×_ | 64× lento | gap crollato? |
| A1 `--sS -F` SERVER | _s_ | _s_ | _×_ | 25× lento | |
| A1 script su `--sS` | _0?_ | — | — | giravano | 0 finding? |
| A1 `-p 1-1000` CAM | _porte_ | — | — | includeva >1000 | solo <=1000? |
| A2 SCTP label | _/sctp?_ | — | — | /tcp | corretto? |
| A3 SCTP senza --Pn | _scansiona?_ | — | — | "Host down" | ok? |
| A4 ARP count | _n_ | _n_ | — | 14 vs 18 | più vicino? |
| A5 web-scan ROUTER | _FP?_ | — | — | .env/backup FP | FP spariti? |
| A6 --msf-suggest | _moduli?_ | search | — | assente | stampa moduli? |
| B4 -sO | _s_ | _s_ | _×_ | 30× RM | regge? |

## Cosa mandarmi per ogni anomalia
(a) output RustyMap `-v`, (b) output nmap, (c) tipo/OS reale target. Priorità:
**A1** (il `-F` è tornato veloce e NON perde porte?), **A5** (web-scan FP
spariti?), **A2/A3** (SCTP label+discovery), **A6** (msf-suggest end-to-end).
