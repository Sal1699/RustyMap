# RustyMap — Test Roadmap v0.77 (RustyMap vs nmap, comandi inclusi)

Piano di test **completo e dettagliato** per confrontare RustyMap 0.77.0 con
nmap (e i tool di riferimento). Copre tutte le aggiunte fino a v0.77.0:

- **NUOVO in 0.77**: matching **probabilistico nmap-os-db completo**
  (`--nmap-os-db`, ~6500 firme, pesi MatchPoints) → OS+% come nmap.
- Riga **SEQ piena** (SP/GCD/ISR/TI/CI/II/TS) e blocco 16-campi (T1-T7,
  ECN, IE con CD/DFI, U1 con IPL/UN/RIPL/RID/RIPCK/RUCK/RUD).
- Fix v0.76: **B12** retry connect, **B19** banner HTTP, **B20** UDP closed.
- `-sV` binario (SMB/MSRPC/RDP/VMware), nuovi scan (`-b`, `--quic`, ACK/Win/
  Maimon/proto/idle/SCTP), `--web-scan`, `--tls-scan` (matrice/ALPN/HSTS/
  **JARM byte-identico**/certificato), apparato **IPv6** completo, 101 script.

Logga ogni esito in `LAB_VALIDATION.md`. Copia i comandi **così come sono**
(zsh-safe: variabili, niente `<...>`).

---

## SETUP — eseguire una volta

### Variabili del lab
```zsh
WIN=192.168.1.20        # Windows 10/11
WSRV=192.168.1.21       # Windows Server / Domain Controller
LINUX=192.168.1.15      # Linux generico
ROUTER=192.168.1.1      # router / apparato di rete
ESXI=192.168.1.30       # VMware ESXi (opzionale)
WEB=192.168.1.40        # host con web app (HTTP+HTTPS)
NAT=10.0.2.2            # gateway NAT VirtualBox (stack Slirp)
V6=2001:db8::1234       # host IPv6 dual-stack (adatta)
V6PREFIX=2001:db8:abcd:1::   # prefisso /64 per lo sweep
PUB=scanme.nmap.org     # target pubblico autorizzato
LOCAL=127.0.0.1         # localhost (utile per OS-fp: molte porte chiuse)
OSDB=/usr/share/nmap/nmap-os-db   # DB firme nmap (o ~/nmap-os-db)
```

### Aggiorna RustyMap su Kali (build da sorgente — la CI è bloccata)
```zsh
cd ~/RustyMap && git fetch --tags && git checkout main && git pull
cargo build --release
sudo install -m755 target/release/rustymap "$(command -v rustymap || echo /usr/local/bin/rustymap)"
rustymap --version    # deve dire 0.77.0
```

### nmap-os-db (per il Tier 3)
```zsh
ls -la /usr/share/nmap/nmap-os-db || sudo apt install -y nmap
# oppure l'ultima dal repo: curl -fsSL https://raw.githubusercontent.com/nmap/nmap/master/nmap-os-db -o ~/nmap-os-db
```

### Tool di riferimento
```zsh
sudo apt install -y nmap sslscan whatweb nikto wafw00f ldnsutils
pip install jarm   # per il confronto JARM (o usa https://jarm.online)
```

### Regole
- **Solo target autorizzati.** Pubblico = `scanme.nmap.org`. Il resto solo sui
  tuoi host.
- Raw socket (`-O`, `--sS`, `--sU`, suite secondaria) = **root**.
- `-sV`, `--web-scan`, `--tls-scan`, `--quic`, `-b` = **nessun privilegio**.
- Gli hint di `-O` (blocco fingerprint, SEQ, ISN, OS-db, IPv6 intel) → **`-v`**.
- PASS = combacia con nmap/riferimento **oppure** la divergenza è compresa e
  annotata.

---

## TIER 0 — Regressione core + fix recenti

| ID | RustyMap | nmap / verifica | PASS |
|----|----------|-----------------|------|
| 0.1 | `rustymap "$PUB"` | `nmap "$PUB"` | stesse porte open |
| 0.2 | `sudo rustymap --sS -p 1-1000 "$LINUX"` | `sudo nmap -sS -p 1-1000 "$LINUX"` | stesso set open/closed |
| 0.3 | **B12**: `sudo rustymap --sT -p 1-20000 "$NAT"` | `sudo nmap -sT -p 1-20000 "$NAT"` | ora trova anche le porte lente/Slirp (902/16012) — 7/7, non 5/7 |
| 0.4 | **B12 retry**: `rustymap --max-retries 0 --sT "$NAT"` vs default | — | col default (2) trova più porte lente del `--max-retries 0` |
| 0.5 | **B19**: `rustymap --sV -p80 "$PUB"` | `nmap -sV -p80 "$PUB"` | banner Apache/versione non vuoto anche se lento |
| 0.6 | **B20**: `sudo rustymap --sU -p 53,111,123,161,500 "$LINUX"` | `sudo nmap -sU -p 53,111,123,161,500 "$LINUX"` | le porte chiuse ora → **closed** (non più tutte open|filtered) |
| 0.7 | `rustymap 127.0.0.1` | — | completa <1s, nessun hang |

---

## TIER 1 — `-sV` su protocolli binari

### 1.1 SMB (445) — dialetto + OS/host/dominio
```zsh
rustymap --sV -p445 "$WSRV"
nmap    -sV -p445 "$WSRV"
nmap -p445 --script smb-protocols,smb-os-discovery,smb2-security-mode "$WSRV"
```
**PASS:** dialetto = max di `smb-protocols`; su host SMBv1/NTLM aggiunge host/
workgroup/dominio/OS-build = `smb-os-discovery`. Su Win10/11 SMBv1-off → solo
dialetto (come nmap senza script).

### 1.2 MSRPC (135)
```zsh
rustymap --sV -p135 "$WIN";  nmap -sV -p135 "$WIN"
```
**PASS:** entrambi "Microsoft Windows RPC"; RustyMap aggiunge "bind accepted".

### 1.3 RDP (3389) — livello sicurezza
```zsh
rustymap --sV -p3389 "$WIN"
nmap -p3389 --script rdp-enum-encryption "$WIN"
```
**PASS:** "Microsoft Terminal Services (RDP)" + standard/TLS/**CredSSP-NLA** =
`rdp-enum-encryption`.

### 1.4 VMware authd (902) + 1.5 Negativo Linux + 1.6 Regressione banner
```zsh
rustymap --sV -p902 "$ESXI";           nmap -sV -p902 "$ESXI"
rustymap --sV -p135,445,3389 "$LINUX"  # atteso: closed/filtered, NIENTE FP
rustymap --sV -p22,80,443 "$PUB";      nmap -sV -p22,80,443 "$PUB"
```

---

## TIER 2 — OS detection: blocco fingerprint 16-campi + SEQ pieno (root)

Riferimento gold: `sudo nmap -O -d` stampa il fingerprint grezzo
`SEQ/OPS/WIN/ECN/T1..T7/IE/U1`.

### 2.1 Blocco completo vs nmap -O -d
```zsh
sudo rustymap -O -v "$LOCAL"    # cerca la riga "nmap-fp: SEQ(...) T2..U1"
sudo nmap    -O -d "$LOCAL"
```
**Confronto campo per campo:**
- **SEQ**: `SP` `GCD` `ISR` (ora in **hex** come nmap) + `TI` `CI` `II` `TS`.
  SP/ISR sono campionari → nmap li dà come range; RustyMap deve cadere **nel
  range** di nmap, non identico. GCD/TI/CI/II/TS devono combaciare.
- **T1-T7/ECN**: `R`/`DF`/`T→TG`/`W`/`S`/`A`/`O`/`F`/`RD`/`Q`/`CC` (tutti
  calcolati) → devono combaciare con nmap `-d`.
- **IE**: `R`/`DFI`/`T`/`CD` (nuovi DFI e CD).
- **U1**: `R`/`DF`/`T`/`IPL`/`UN`/`RIPL`/`RID`/`RIPCK`/`RUCK`/`RUD` (nuovi
  campi quoted).

### 2.2 U1/IE quoted — verifica mirata
```zsh
sudo rustymap -O -v "$LOCAL" 2>&1 | grep -oE "U1\([^)]*\)|IE\([^)]*\)"
sudo nmap    -O -d "$LOCAL" 2>&1 | grep -oE "U1\([^)]*\)|IE\([^)]*\)"
```
**PASS:** `RIPL=G`/`RID=G`/`RIPCK=G`/`RUCK=G`/`RUD=G` quando la copia quotata è
integra (come nmap); `DFI` e `CD` combaciano.

### 2.3 ISN / TCP Sequence Prediction
```zsh
sudo rustymap -O -v "$LINUX";  sudo nmap -O -v "$LINUX"
```
**PASS:** classe coerente (randomized↔difficile, incremental/constant↔debole).

### 2.4 Slirp NAT + guard RST kernel
```zsh
sudo rustymap -O -v "$NAT";  sudo nmap -O -d "$NAT"
```
**PASS:** RustyMap identifica lo Slirp; T5-T7 non danno più falsi R=N.

---

## TIER 3 — ⭐ Matching probabilistico nmap-os-db (root, il pezzo nuovo)

Carica il DB reale e confronta **nome OS + percentuale** con nmap.

### 3.1 Match con DB caricato
```zsh
sudo rustymap -O -v --nmap-os-db "$OSDB" "$LINUX"
sudo nmap    -O "$LINUX"
```
All'avvio RustyMap deve stampare `[nmap-os-db] loaded ~6500 fingerprints ...`.
**Cosa guardare in RustyMap:**
- riga `OS: <nome> (NN%)` — il match ≥85% (nome dal DB, non dall'euristica);
- hint `nmap-os-db cpe: cpe:/o:...`;
- hint `nmap-os-db also: <2 runner-up con %>`;
- se <85%: hint `nmap-os-db guesses: <top-3 con %>`.

**Confronto con nmap:** `OS details:` / `Aggressive OS guesses:` di nmap.
**PASS:** stessa **famiglia** e versione entro una minor; le percentuali nello
stesso ordine di grandezza; il CPE combacia.

### 3.2 Matrice multi-OS (ripeti su ogni tipo)
```zsh
for H in "$WIN" "$LINUX" "$ROUTER" "$NAT"; do
  echo "=== $H ==="
  sudo rustymap -O -v --nmap-os-db "$OSDB" "$H" 2>&1 | grep -E "OS:|nmap-os-db"
  sudo nmap -O "$H" 2>&1 | grep -E "OS details|Aggressive OS guesses|Running"
done
```
**PASS:** per ogni host, RustyMap+DB e nmap concordano sulla famiglia. Annota i
casi dove RustyMap dà % più bassa (probe mancanti OPS/WIN/T1 → meno punti).

### 3.3 Senza DB (regressione euristica)
```zsh
sudo rustymap -O -v "$LINUX"    # senza --nmap-os-db
```
**PASS:** usa ancora lo scorer euristico a 100 firme (famiglia+versione), la
riga OS non deve rompersi quando il DB non è caricato.

### 3.4 Nota onesta da verificare
RustyMap **non** invia i probe OPS/WIN/T1 completi → il match usa SEQ+T2-T7+
ECN+IE+U1. Se il match % è più basso di nmap ma la **famiglia** è giusta, è
atteso. Se la famiglia è **sbagliata**, incolla il blocco `nmap-fp:` + il
`nmap -O -d`: potrebbe servire tarare soglia/pesi o aggiungere OPS/WIN.

---

## TIER 4 — Nuovi tipi di scan

```zsh
# ACK / Window / Maimon (firewall mapping)
sudo rustymap --sA -p 1-1000 "$ROUTER";  sudo nmap -sA -p 1-1000 "$ROUTER"
sudo rustymap --sW -p 1-1000 "$LINUX";   sudo nmap -sW -p 1-1000 "$LINUX"
sudo rustymap --sM -p 1-1000 "$LINUX";   sudo nmap -sM -p 1-1000 "$LINUX"
# IP protocol / SCTP / idle
sudo rustymap --sO "$LINUX";             sudo nmap -sO "$LINUX"
sudo rustymap --sY -p 80,443 "$LINUX";   sudo nmap -sY -p 80,443 "$LINUX"
sudo rustymap --sI "$ROUTER:80" "$LINUX" --experimental-confirm;  sudo nmap -sI "$ROUTER" "$LINUX"
# FTP bounce (no root)
rustymap -b anonymous@"$LINUX" -p 22,80,445 "$WEB"
# QUIC / HTTP-3 (no root)
rustymap --quic cloudflare.com;          curl --http3 -sI https://cloudflare.com | head -1
```
**PASS:** ACK→unfiltered/filtered come nmap; Window→open/closed; Maimon→closed;
`-sO` stessi protocolli; FTP bounce → "relay blocked" o open/closed; QUIC →
versioni (v1/v2), nmap non ha scan QUIC.

---

## TIER 5 — `--web-scan` (no root)

```zsh
rustymap --web-scan "$WEB"
whatweb "http://$WEB/";  wafw00f "http://$WEB/";  nikto -host "http://$WEB/"
nmap -p80,443 --script http-headers,http-enum,http-git "$WEB"
```
**PASS:** grade security-header + gap coerenti; WAF/CDN = `wafw00f`; i path
esposti (.env/.git/actuator/…) compaiono anche in nikto/`http-enum`.

---

## TIER 6 — `--tls-scan` (matrice/ALPN/HSTS/JARM/cert, no root)

```zsh
rustymap --tls-scan "$WEB"
```
### 6.1 Matrice TLS + ALPN + HSTS
```zsh
sslscan --no-ciphersuites "$WEB":443
openssl s_client -connect "$WEB":443 -alpn h2,http/1.1 </dev/null 2>/dev/null | grep -i ALPN
curl -sI "https://$WEB/" | grep -i strict-transport-security
```
**PASS:** yes/no per TLS 1.0-1.3 = sslscan (1.0/1.1 marcate deprecate); ALPN h2
= openssl; HSTS = curl.

### 6.2 JARM — deve essere BYTE-IDENTICO al riferimento
```zsh
for H in cloudflare.com google.com httpd.apache.org microsoft.com; do
  echo "=== $H ==="
  rustymap --tls-scan "$H" | grep -m1 JARM
  python3 -c "import jarm.scanner.scanner as s; print('pyjarm:', s.Scanner.scan('$H',443)[0])"
done
```
**PASS:** l'hash a 62 char di RustyMap = pyjarm (già verificato 4/4 su questi;
se un char differisce, incollameli).

### 6.3 Certificato (flag di debolezza)
```zsh
rustymap --tls-scan self-signed.badssl.com    # atteso: ! self-signed
rustymap --tls-scan expired.badssl.com        # atteso: ! certificate EXPIRED
openssl s_client -connect "$WEB":443 -servername "$WEB" </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```
**PASS:** subject/issuer/SAN/scadenza = openssl; flag scaduto/self-signed/
chiave<2048/SHA1/wildcard corretti.

---

## TIER 7 — IPv6 (il punto di forza)

### 7.1 Address intel (ogni target IPv6)
```zsh
rustymap -v "$V6"               # riga "IPv6 address intel:" + note
ip -6 neigh | grep "$V6"        # confronta il MAC estratto con quello reale
```
Casi: SLAAC EUI-64 (MAC+vendor byte-identico al reale), privacy RFC 4941 (MAC
nascosto), `::1`/`::443` manuale, `fe80::` link-local, `ff02::1` multicast.

### 7.2 Transizione / mapped (calcolo puro, subito)
```zsh
rustymap "64:ff9b::c000:0201"   # atteso: NAT64 → 192.0.2.1
rustymap "::ffff:192.0.2.5"     # atteso: IPv4-mapped
```

### 7.3 OS fingerprint IPv6 + sweep /64
```zsh
sudo rustymap -O -v -6 "$V6";  sudo nmap -O -6 "$V6"
rustymap --ipv6-sweep "$V6PREFIX"
```
**PASS:** stessa famiglia OS; lo sweep trova gli host con IID comuni (::1/::53/
::80/::443/vanity).

---

## TIER 8 — Script (101 built-in) — spot check

```zsh
ls ~/RustyMap/scripts/*.rhai | wc -l          # 101
rustymap --script ollama-exposed,http-env-exposed,http-git-exposed "$WEB"
rustymap --script rdp-exposed,http-actuator-exposed,http-swagger-exposed "$WEB"
```
**PASS:** finding coerenti; confronta i path con `nmap --script http-enum` /
nikto.

---

## Matrice riassuntiva — PASS in una riga

| # | Feature | Comando RustyMap | Riferimento | PASS |
|---|---------|------------------|-------------|------|
| 0.3 | B12 connect lente | `sudo rustymap --sT -p1-20000 "$NAT"` | `nmap -sT` | trova 902/16012 |
| 0.6 | B20 UDP closed | `sudo rustymap --sU` | `nmap -sU` | chiuse = closed |
| 1.x | -sV binario | `rustymap --sV -p135,445,3389,902` | `nmap -sV`+script | prodotto+dettaglio |
| 2.1 | 16-campi | `sudo rustymap -O -v` | `sudo nmap -O -d` | tutti i campi |
| 2.2 | U1/IE quoted | `sudo rustymap -O -v` | `nmap -O -d` | RIPL/RID/RIPCK/RUCK/RUD/CD/DFI |
| **3.1** | **nmap-os-db match** | `sudo rustymap -O -v --nmap-os-db "$OSDB"` | `nmap -O` | **OS+% = OS details** |
| 4.x | nuovi scan | `--sA/--sW/--sM/--sO/--sY/--sI/-b/--quic` | `nmap -s*`/curl | stessi stati |
| 5 | web scan | `rustymap --web-scan` | whatweb/nikto/wafw00f | header/WAF/path |
| 6.2 | JARM | `rustymap --tls-scan` | pyjarm/jarm.online | **hash identico** |
| 6.3 | certificato | `rustymap --tls-scan` | openssl x509 | subject/SAN/flag |
| 7.1 | IPv6 intel | `rustymap -v "$V6"` | ip -6 neigh | EUI-64→MAC reale |

## Cosa mandarmi per ogni FAIL
Incolla: (a) output RustyMap **con `-v`**, (b) l'output nmap/tool
corrispondente, (c) tipo/OS reale del target. Priorità di questa tornata:
1. **Tier 3** — `OS: <nome> (NN%)` di RustyMap accanto a `OS details` di nmap su
   Linux/Windows/router (verifica del nuovo matcher nmap-os-db).
2. **Tier 2.2** — righe `U1(...)`/`IE(...)` vs `nmap -O -d` (nuovi campi quoted).
3. **SEQ** — che SP/ISR cadano nel **range** di nmap e GCD/TI/CI/II/TS combacino.
