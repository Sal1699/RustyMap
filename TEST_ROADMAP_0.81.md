# RustyMap — Test Roadmap v0.81 (RustyMap vs nmap, comandi completi)

Lista **super-dettagliata** di comandi appaiati RustyMap ⇄ nmap. Copia così come
sono (zsh-safe). **PARTE A** valida i 6 fix di v0.81.0 (priorità di questa
tornata). **PARTE B** è il confronto testa-a-testa completo (tempi con
hyperfine). Logga gli esiti in `LAB_VALIDATION.md`.

---

## SETUP — una volta

```zsh
# Aggiorna RustyMap (ora sei su main → git pull funziona)
cd ~/RustyMap && git pull && cargo build --release
sudo install -m755 target/release/rustymap /usr/local/bin/rustymap
rustymap --version      # DEVE dire 0.81.0

# Tool di riferimento
sudo apt install -y nmap hyperfine sslscan whatweb nikto wafw00f ldnsutils

# nmap-os-db presente? (serve a -O; v0.81 lo auto-carica)
ls -la /usr/share/nmap/nmap-os-db
```

### Variabili del lab (adatta ai TUOI host, poi tienile fisse)
```zsh
HOST=192.168.1.1        # host responsivo (il router va benissimo)
ROUTER=192.168.1.1      # gateway / apparato di rete
LINUX=192.168.1.15      # Linux generico
WIN=192.168.1.20        # Windows 10/11
DNS=192.168.1.1         # un server DNS (router/pi-hole/bind)
NET=192.168.1.0/24      # una /24 che possiedi
HOSTS="192.168.1.1 192.168.1.15 192.168.1.20"   # set piccolo eterogeneo
PUB=scanme.nmap.org     # target pubblico autorizzato
LOCAL=127.0.0.1
OSDB=/usr/share/nmap/nmap-os-db
```

### Regole
- Raw (`--sS/--sF/--sN/--sX/--sA/--sW/--sM/--sU/--sY/--sZ/--sO/-O`) = **sudo**.
- Testo (`--sV/--sT/--web-scan/--tls-scan/--quic/-b/script`) = **no root**.
- Ratio nelle tabelle = nmap / RustyMap (>1 → RustyMap più veloce).
- PASS = combacia o la divergenza è compresa e annotata.

---

# PARTE A — Validazione dei 6 fix v0.81.0 (PRIORITÀ)

## A1 — SYN/connect adaptive timeout (il fix headline)
Pre-0.81: 1-1000 era ~35× più lento di nmap, top-100 ~10×. Ora il timeout
per-porta si restringe verso ~10×RTT (floor 50-300ms) invece del fisso 1500ms.

```zsh
# Piccolo range (era il peggiore) — misura col cronometro
sudo hyperfine -w1 -r5 "rustymap --sS -p 1-1000 $HOST" "nmap -sS -p 1-1000 $HOST"
# Top-100
sudo hyperfine -w1 -r5 "rustymap --sS -F $HOST"       "nmap -sS -F $HOST"
# Full 65535 (RustyMap era già competitivo)
sudo hyperfine -w1 -r3 "rustymap --sS -p 1-65535 $HOST" "nmap -sS -p 1-65535 $HOST"
# Connect scan (stesso adattamento via limiter)
sudo hyperfine -w1 -r3 "rustymap --sT -p 1-1000 $HOST"  "nmap -sT -p 1-1000 $HOST"
```
**PASS:** il gap su 1-1000 e `-F` deve **crollare** (da 10-35× a pochi ×, idealmente
≈ pari). **CRITICO:** confronta le PORTE trovate — devono essere identiche a prima
del fix (il timeout più corto non deve perdere porte filtered lente).
```zsh
# Verifica che non si perdano porte vs il vecchio comportamento
sudo rustymap --sS -p 1-1000 $HOST | sort > /tmp/rm_fast.txt
sudo rustymap --sS -p 1-1000 --timeout 1500 --max-retries 2 $HOST | sort > /tmp/rm_slow.txt
diff /tmp/rm_fast.txt /tmp/rm_slow.txt && echo "OK: stesso set porte"
sudo nmap -sS -p 1-1000 $HOST   # terza opinione sul set
```

## A2 — `-sV` version detection
```zsh
# SSH — atteso prodotto+versione, non "ssh"
rustymap --sV -p 22 $LINUX ;  nmap -sV -p 22 $LINUX
#   RustyMap atteso: "OpenSSH 8.9p1 (protocol 2.0)" o "Dropbear sshd 2017.75"

# DNS/53 — nuovo probe version.bind: atteso dnsmasq/BIND + versione
rustymap --sV -p 53 $DNS ;    nmap -sV -p 53 $DNS
nmap -p 53 --script dns-nsid,dns-recursion $DNS      # riferimento versione DNS
#   verifica manuale della stessa query:
dig @"$DNS" version.bind chaos txt +short

# HTTP server embedded / gSOAP (se hai una IP-cam o router con web)
rustymap --sV -p 80,443 $ROUTER ;  nmap -sV -p 80,443 $ROUTER
```
**PASS:** SSH → prodotto riconosciuto (Dropbear/OpenSSH) + versione + "protocol
2.0"; DNS → dnsmasq/BIND/Unbound/… con versione = `dig version.bind`. **NOTA
onesta:** servizi dietro **HTTPS** (es. lighttpd su 443) restano name-only — gap
noto e documentato (manca il probe HTTP-su-TLS), non è una regressione.

## A3 — SCTP non si inchioda più (B28)
```zsh
# Deve rispondere in fretta (filtered), NON andare in timeout infinito
time sudo rustymap --sY -p 132,9899,3868,2905 $HOST
sudo hyperfine -w1 -r3 "rustymap --sY -p 132,9899,3868,2905 $HOST" "nmap -sY -p 132,9899,3868,2905 $HOST"
# COOKIE-ECHO scan
sudo rustymap --sZ -p 132,9899 $HOST ;  sudo nmap -sZ -p 132,9899 $HOST
```
**PASS:** RustyMap termina entro ~N×timeout (non resta appeso); porte mute =
`filtered`; se l'host ha SCTP, open/closed coerenti con nmap.

## A4 — Script NON auto-eseguiti sugli sweep
```zsh
# Sweep /24: atteso messaggio "[scripts] N hosts up — built-in scripts skipped on sweeps"
sudo rustymap --sS $NET 2>&1 | grep -i "scripts skipped"
# Forzarli sullo sweep
sudo rustymap --sS --force-scripts $NET 2>&1 | grep -iE "finding|scripts"
# Host singolo: gli script AUTO partono ancora (≤8 host)
rustymap --sT -F $HOST 2>&1 | grep -iE "finding|\[script"
```
**PASS:** sweep → nota di skip + scan molto più rapido; `--force-scripts` → girano;
host singolo → girano in automatico come prima.

## A5 — `-O` auto-carica nmap-os-db (basta "server 55%")
```zsh
# SENZA --nmap-os-db: deve stampare "[nmap-os-db] auto-loaded N fingerprints from ..."
sudo rustymap -O -v $HOST 2>&1 | grep -E "nmap-os-db|OS:"
sudo nmap -O $HOST 2>&1 | grep -E "OS details|Running|Aggressive"
# Confronto con caricamento esplicito (deve essere identico)
sudo rustymap -O -v --nmap-os-db $OSDB $HOST 2>&1 | grep -E "OS:"
```
**PASS:** compare la riga di auto-load; `OS: <nome> (NN%)` dalla DB (non più
"server 55%"); stessa famiglia di `nmap -O`.

---

# PARTE B — Confronto testa-a-testa completo

## B1 — Host discovery
```zsh
sudo hyperfine -w1 -r3 "rustymap --sn $NET"     "nmap -sn $NET"       # ping sweep
sudo rustymap --PR $NET | sort ;  sudo nmap -PR -sn $NET | grep report  # ARP
sudo rustymap --PE $HOST       ;  sudo nmap -PE -sn $HOST               # ICMP echo
sudo rustymap --PS 22,80,443 $HOST ; sudo nmap -PS22,80,443 -sn $HOST   # TCP SYN ping
```
**PASS:** stesso insieme di host "up"; `--sn` non fa port scan.

## B2 — TCP SYN scan (tempi + correttezza)
```zsh
sudo hyperfine -w1 -r5 "rustymap --sS -F $HOST"          "nmap -sS -F $HOST"
sudo hyperfine -w1 -r5 "rustymap --sS --top-ports 1000 $HOST" "nmap -sS --top-ports 1000 $HOST"
sudo hyperfine -w1 -r3 "rustymap --sS -p 1-65535 $HOST"  "nmap -sS -p 1-65535 $HOST"
# set porte identico?
sudo rustymap --sS -p 1-65535 $HOST | grep -oE "^[0-9]+" | sort > /tmp/rm.txt
sudo nmap -sS -p 1-65535 $HOST | grep -oE "^[0-9]+/tcp" | cut -d/ -f1 | sort > /tmp/nm.txt
diff /tmp/rm.txt /tmp/nm.txt && echo "OK stesso set"
```

## B3 — TCP connect scan (no root)
```zsh
hyperfine -w1 -r5 "rustymap --sT -F $HOST"  "nmap -sT -F $HOST"
hyperfine -w1 -r3 "rustymap --sT -p 1-10000 $HOST"  "nmap -sT -p 1-10000 $HOST"
```

## B4 — UDP scan
```zsh
sudo hyperfine -w1 -r3 "rustymap --sU --top-ports 20 $HOST" "nmap -sU --top-ports 20 $HOST"
sudo rustymap --sU -p 53,123,161,500,1900 $HOST
sudo nmap    -sU -p 53,123,161,500,1900 $HOST
```
**PASS:** porte chiuse → `closed` (non tutte open|filtered); confronta open.

## B5 — FIN / NULL / Xmas (stealth)
```zsh
sudo rustymap --sF -p 1-1000 $HOST ;  sudo nmap -sF -p 1-1000 $HOST
sudo rustymap --sN -p 1-1000 $HOST ;  sudo nmap -sN -p 1-1000 $HOST
sudo rustymap --sX -p 1-1000 $HOST ;  sudo nmap -sX -p 1-1000 $HOST
```
**PASS:** open|filtered vs closed coerenti con nmap.

## B6 — ACK / Window / Maimon (firewall mapping)
```zsh
sudo rustymap --sA -p 1-1000 $ROUTER ;  sudo nmap -sA -p 1-1000 $ROUTER
sudo rustymap --sW -p 1-1000 $HOST   ;  sudo nmap -sW -p 1-1000 $HOST
sudo rustymap --sM -p 1-1000 $HOST   ;  sudo nmap -sM -p 1-1000 $HOST
```
**PASS:** ACK → filtered/unfiltered; Window → open/closed; Maimon → closed.

## B7 — SCTP / IP-proto / idle
```zsh
sudo rustymap --sY -p 132,9899,3868 $HOST ;  sudo nmap -sY -p 132,9899,3868 $HOST
sudo rustymap --sO $HOST                   ;  sudo nmap -sO $HOST
sudo rustymap --sI "$ROUTER:80" $LINUX --experimental-confirm ; sudo nmap -sI $ROUTER $LINUX
```

## B8 — Service version (-sV)
```zsh
hyperfine -w1 -r3 "rustymap --sV -F $HOST" "nmap -sV -F $HOST"
rustymap --sV -p 22,53,80,443,445,3389 $HOST
nmap    -sV -p 22,53,80,443,445,3389 $HOST
```
**PASS:** stesso servizio; confronta il **dettaglio versione** (A2).

## B9 — OS detection (-O)
```zsh
sudo hyperfine -w1 -r3 "rustymap -O $HOST" "nmap -O $HOST"
sudo rustymap -O -v $HOST 2>&1 | grep -E "nmap-os-db|OS:"
sudo nmap    -O $HOST 2>&1 | grep -E "OS details|Running"
```

## B10 — Aggressive (-A)
```zsh
sudo hyperfine -w1 -r3 "rustymap -A $HOST" "nmap -A $HOST"
```
**PASS:** RustyMap più veloce; **verifica a parità di lavoro** — confronta porte
+ versioni + OS + script prodotti, non solo il tempo.

## B11 — Script
```zsh
# singolo host: auto
rustymap --sT -F $HOST
# catalogo
rustymap --script-list | head -30
# confronto con NSE default
nmap -sC -F $HOST
```

## B12 — Timing templates
```zsh
for T in 0 2 3 4 5; do
  echo "== -T$T =="
  sudo hyperfine -w1 -r2 "rustymap --sS -F -t $T $HOST" "nmap -sS -F -T$T $HOST"
done
```

---

# PARTE C — Feature che nmap NON ha (solo RustyMap)
```zsh
rustymap --tls-scan $HOST            # matrice TLS + ALPN + HSTS + JARM + cert
rustymap --tls-scan cloudflare.com | grep -m1 JARM
rustymap --web-scan $ROUTER          # security-header grade + WAF/CDN + path
rustymap --quic cloudflare.com       # QUIC/HTTP-3 versions
rustymap -v 2001:db8::1234           # IPv6 address intel (EUI-64→MAC)
rustymap --recommend $HOST           # suggerisce i flag del prossimo scan
rustymap --detect-preview --sS -A $HOST   # cosa rileverebbe un IDS/SIEM
```

# PARTE D — Formati di output (confronto parsabilità)
```zsh
rustymap --sT -F $HOST -oN out.nmap -oG out.grep -oJ out.json -oX out.xml
rustymap --sT -F $HOST --oMd out.md --oH out.html
nmap    -sT -F $HOST -oN n.nmap -oG n.grep -oX n.xml
```

---

## Matrice da compilare (manda a me)

| Test | RustyMap | nmap | Ratio | Note |
|------|----------|------|-------|------|
| A1 SYN 1-1000 | _s_ | _s_ | _×_ | gap crollato? stesse porte? |
| A1 SYN -F | _s_ | _s_ | _×_ | |
| A1 SYN full | _s_ | _s_ | _×_ | |
| A2 -sV 22 (SSH) | _prod/ver_ | _prod/ver_ | — | versione estratta? |
| A2 -sV 53 (DNS) | _prod/ver_ | _prod/ver_ | — | = dig version.bind? |
| A3 SCTP | _s_ | _s_ | _×_ | niente hang? filtered? |
| A4 sweep | skip? | — | — | messaggio presente? |
| A5 -O | _OS NN%_ | _OS_ | — | auto-load? famiglia ok? |
| B4 UDP | | | | closed corretti? |
| B10 -A | _s_ | _s_ | _×_ | a parità di lavoro? |

## Cosa mandarmi per ogni anomalia
(a) output RustyMap **con `-v`**, (b) output nmap/tool corrispondente, (c)
tipo/OS reale del target. Priorità: **A1** (il gap SYN è sparito e NON perde
porte?), **A3** (SCTP non appende), **A2 DNS** (dnsmasq/BIND+versione).
