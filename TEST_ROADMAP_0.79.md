# RustyMap — Test Roadmap v0.79 (RustyMap vs nmap, comandi inclusi)

Piano di test **completo** per validare RustyMap **0.79.0** su Kali contro nmap
(e i tool di riferimento). Copia i comandi **così come sono** (zsh-safe:
variabili, niente `<...>`). Logga ogni esito in `LAB_VALIDATION.md`.

## Cosa è cambiato da 0.77 (= cosa validare DAVVERO stavolta)

- ⭐ **0.78.0 — OPS / WIN / T1 ora EMESSI.** RustyMap invia le **6 SEQ probe
  distinte** di nmap (finestre+opzioni esatte) e stampa `OPS(O1..O6)`,
  `WIN(W1..W6)` e `T1(...)`. **La nota "onesta" 3.4 del doc 0.77 è OBSOLETA**:
  ora il field-set `-O` è *completo* come `nmap -O -d`, e sono i campi che nmap
  pesa di più → il match `--nmap-os-db` deve avvicinarsi molto alla % di nmap.
- **0.78.1 — B26:** `CI`/`II` (2–3 campioni) ora leggono **RI**, non più RD;
  `TI` (6 campioni) resta **RD**. Verifica mirata in Tier 2.
- ⭐ **0.79.0 — SEQ sampling band.** Sotto `-O -v` compare una nuova riga
  `SEQ sampling band: SP=lo-hi%ISR=lo-hi%TS=lo-hi` accanto al blocco `nmap-fp:`.
  È **solo display**: la SEQ line del fingerprint tiene i valori **puntuali**
  (quelli che il matcher confronta coi range nmap). Da verificare che il punto
  cada dentro la banda e che la banda abbracci il range di `nmap -O`.
- **0.79.0 — 117 script** built-in (erano 101): 16 nuovi da spot-check in Tier 8.

**Priorità di questa tornata:** Tier 2 (OPS/WIN/T1 + banda + B26) → Tier 3
(match os-db, ora deve salire) → Tier 8 (nuovi script).

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
LOCAL=127.0.0.1         # localhost (ottimo per OS-fp: molte porte chiuse)
OSDB=/usr/share/nmap/nmap-os-db   # DB firme nmap (o ~/nmap-os-db)
```

### Aggiorna RustyMap su Kali (build da sorgente — la CI è bloccata)
```zsh
cd ~/RustyMap && git fetch --tags
git checkout -- Cargo.lock 2>/dev/null   # scarta il lock rigenerato da build precedenti
git checkout v0.79.0
cargo build --release
sudo install -m755 target/release/rustymap "$(command -v rustymap || echo /usr/local/bin/rustymap)"
rustymap --version    # DEVE dire 0.79.0
```

### nmap-os-db (per il Tier 3)
```zsh
ls -la /usr/share/nmap/nmap-os-db || sudo apt install -y nmap
# oppure l'ultima dal repo:
# curl -fsSL https://raw.githubusercontent.com/nmap/nmap/master/nmap-os-db -o ~/nmap-os-db && OSDB=~/nmap-os-db
```

### Tool di riferimento
```zsh
sudo apt install -y nmap sslscan whatweb nikto wafw00f ldnsutils
pip install jarm   # per il confronto JARM (o usa https://jarm.online)
```

### Regole
- **Solo target autorizzati.** Pubblico = `scanme.nmap.org`; il resto solo sui
  tuoi host.
- Raw socket (`-O`, `--sS`, `--sU`, suite secondaria) = **root** (`sudo`).
- `-sV`, `--web-scan`, `--tls-scan`, `--quic`, `-b`, script = **nessun privilegio**.
- Gli hint di `-O` (blocco `nmap-fp:`, SEQ, banda, ISN, os-db, IPv6 intel) → **`-v`**.
- Sintassi scan-type RustyMap = **doppio trattino** (`--sS`, `--sU`, `--sA`…),
  nmap = singolo (`-sS`…). Non è un errore di battitura nei comandi sotto.
- PASS = combacia con nmap/riferimento **oppure** la divergenza è compresa e
  annotata.

---

## TIER 0 — Regressione core + fix recenti

| ID | RustyMap | nmap / verifica | PASS |
|----|----------|-----------------|------|
| 0.1 | `rustymap "$PUB"` | `nmap "$PUB"` | stesse porte open |
| 0.2 | `sudo rustymap --sS -p 1-1000 "$LINUX"` | `sudo nmap -sS -p 1-1000 "$LINUX"` | stesso set open/closed |
| 0.3 | `sudo rustymap --sT -p 1-20000 "$NAT"` | `sudo nmap -sT -p 1-20000 "$NAT"` | B12: trova anche le porte lente Slirp (902/16012) |
| 0.4 | `rustymap --max-retries 0 --sT "$NAT"` vs default | — | col default (2) trova più porte lente del `--max-retries 0` |
| 0.5 | `rustymap --sV -p80 "$PUB"` | `nmap -sV -p80 "$PUB"` | B19: banner/versione non vuoto anche se lento |
| 0.6 | `sudo rustymap --sU -p 53,111,123,161,500 "$LINUX"` | `sudo nmap -sU -p 53,111,123,161,500 "$LINUX"` | B20: le chiuse → **closed** (non più open\|filtered) |
| 0.7 | `rustymap 127.0.0.1` | — | completa <1s, nessun hang |

---

## TIER 1 — `-sV` su protocolli binari (no root)

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

## TIER 2 — ⭐ OS detection: blocco 16-campi COMPLETO (root)

Riferimento gold: `sudo nmap -O -d` stampa il fingerprint grezzo
`SEQ/OPS/WIN/ECN/T1..T7/IE/U1`. **Da 0.78.0 RustyMap emette tutti questi**,
inclusi OPS/WIN/T1 (prima mancanti).

### 2.1 Blocco completo vs nmap -O -d
```zsh
sudo rustymap -O -v "$LOCAL"    # cerca "nmap-fp:" + "SEQ sampling band:"
sudo nmap    -O -d "$LOCAL"
```
**Confronto campo per campo (devono combaciare con `nmap -d`):**
- **SEQ**: `SP` `GCD` `ISR` (hex) + `TI` `CI` `II` `TS`. SP/ISR/TS sono
  campionari (vedi 2.2). GCD/TI/CI/II devono combaciare.
- ⭐ **OPS** `O1..O6` — opzioni TCP del SYN/ACK per ognuna delle 6 probe
  (notazione M/N/W/S/T/L). **NUOVO**, confronta ciascuna O1..O6 con nmap.
- ⭐ **WIN** `W1..W6` — finestra SYN/ACK in hex per le 6 probe. **NUOVO.**
- ⭐ **T1** — `R/DF/T/W/S/A/F/O/RD/Q` della probe #1. **NUOVO.**
- **T2–T7 / ECN**: `R`/`DF`/`T→TG`/`W`/`S`/`A`/`O`/`F`/`RD`/`Q`/`CC`.
- **IE**: `R`/`DFI`/`T`/`CD`.
- **U1**: `R`/`DF`/`T`/`IPL`/`UN`/`RIPL`/`RID`/`RIPCK`/`RUCK`/`RUD`.

### 2.2 ⭐ SEQ sampling band (nuovo in 0.79) — il punto dev'essere nella banda
```zsh
sudo rustymap -O -v "$LINUX" 2>&1 | grep -E "nmap-fp:|SEQ sampling band:"
sudo nmap -O "$LINUX" 2>&1 | grep -iE "SP=|ISR=|OS details"
```
**PASS:**
- la riga `SEQ sampling band: SP=lo-hi% ISR=lo-hi% TS=lo-hi` compare;
- il valore **puntuale** di `SP`/`ISR` nel blocco `nmap-fp:` cade **dentro** la
  rispettiva banda lo-hi;
- la banda abbraccia (o si sovrappone a) il range che nmap usa per quell'OS.
  SP/ISR/TS non devono essere *identici* a nmap (sono campionari); il resto sì.

### 2.3 ⭐ B26 — CI/II leggono RI, TI resta RD
```zsh
sudo rustymap -O -v "$LOCAL" 2>&1 | grep -oE "TI=[A-Z]+|CI=[A-Z]+|II=[A-Z]+"
sudo nmap    -O -d "$LOCAL" 2>&1 | grep -oE "TI=[A-Z]+|CI=[A-Z]+|II=[A-Z]+"
```
**PASS:** `TI=RD` (o la classe che dà nmap su 6 campioni) ma **`CI`/`II` NON
sono RD** se hanno 2–3 campioni → devono leggere `RI` (o `I`/`RD` solo se nmap
stesso lo fa). Confronto diretto con la riga SEQ di nmap `-d`.

### 2.4 U1/IE quoted — verifica mirata
```zsh
sudo rustymap -O -v "$LOCAL" 2>&1 | grep -oE "U1\([^)]*\)|IE\([^)]*\)"
sudo nmap    -O -d "$LOCAL" 2>&1 | grep -oE "U1\([^)]*\)|IE\([^)]*\)"
```
**PASS:** `RIPL=G`/`RID=G`/`RIPCK=G`/`RUCK=G`/`RUD=G` con copia quotata integra
(come nmap); `DFI` e `CD` combaciano.

### 2.5 ISN / TCP Sequence Prediction + 2.6 Slirp NAT
```zsh
sudo rustymap -O -v "$LINUX";  sudo nmap -O -v "$LINUX"   # classe ISN coerente
sudo rustymap -O -v "$NAT";    sudo nmap -O -d "$NAT"     # Slirp: T5-T7 niente falsi R=N
```

---

## TIER 3 — ⭐ Matching probabilistico nmap-os-db (root)

Con OPS/WIN/T1 ora emessi (i campi più pesati), il match % **deve avvicinarsi a
nmap** rispetto alla 0.77.

### 3.1 Match con DB caricato
```zsh
sudo rustymap -O -v --nmap-os-db "$OSDB" "$LINUX"
sudo nmap    -O "$LINUX"
```
All'avvio RustyMap stampa `[nmap-os-db] loaded ~6500 fingerprints ...`.
**In RustyMap guarda:** riga `OS: <nome> (NN%)` (match dal DB), hint
`nmap-os-db cpe:`, `nmap-os-db also:` (runner-up), e se <85% `nmap-os-db guesses:`.
**Confronto:** `OS details:` / `Aggressive OS guesses:` di nmap.
**PASS:** stessa **famiglia** e versione entro una minor; % nello stesso ordine
di grandezza di nmap (ora attesa **più alta** della 0.77 grazie a OPS/WIN/T1).

### 3.2 Matrice multi-OS
```zsh
for H in "$WIN" "$LINUX" "$ROUTER" "$NAT"; do
  echo "=== $H ==="
  sudo rustymap -O -v --nmap-os-db "$OSDB" "$H" 2>&1 | grep -E "OS:|nmap-os-db"
  sudo nmap -O "$H" 2>&1 | grep -E "OS details|Aggressive OS guesses|Running"
done
```
**PASS:** per ogni host, RustyMap+DB e nmap concordano sulla famiglia.

### 3.3 Senza DB (regressione euristica)
```zsh
sudo rustymap -O -v "$LINUX"    # senza --nmap-os-db → scorer euristico 100 firme
```
**PASS:** la riga OS non si rompe quando il DB non è caricato.

---

## TIER 4 — Tipi di scan

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
**PASS:** ACK→unfiltered/filtered; Window→open/closed; Maimon→closed; `-sO`
stessi protocolli; FTP bounce → "relay blocked" o open/closed; QUIC → versioni
(v1/v2), nmap non ha scan QUIC.

---

## TIER 5 — `--web-scan` (no root)

```zsh
rustymap --web-scan "$WEB"
whatweb "http://$WEB/";  wafw00f "http://$WEB/";  nikto -host "http://$WEB/"
nmap -p80,443 --script http-headers,http-enum,http-git "$WEB"
```
**PASS:** grade security-header + gap coerenti; WAF/CDN = `wafw00f`; path esposti
(.env/.git/actuator/…) compaiono anche in nikto/`http-enum`.

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
**PASS:** yes/no per TLS 1.0-1.3 = sslscan (1.0/1.1 deprecate); ALPN h2 =
openssl; HSTS = curl.

### 6.2 JARM — BYTE-IDENTICO al riferimento
```zsh
for H in cloudflare.com google.com httpd.apache.org microsoft.com; do
  echo "=== $H ==="
  rustymap --tls-scan "$H" | grep -m1 JARM
  python3 -c "import jarm.scanner.scanner as s; print('pyjarm:', s.Scanner.scan('$H',443)[0])"
done
```
**PASS:** hash a 62 char di RustyMap = pyjarm (già 4/4 su questi; se un char
differisce, incollameli).

### 6.3 Certificato (flag di debolezza)
```zsh
rustymap --tls-scan self-signed.badssl.com    # atteso: ! self-signed
rustymap --tls-scan expired.badssl.com        # atteso: ! certificate EXPIRED
openssl s_client -connect "$WEB":443 -servername "$WEB" </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```
**PASS:** subject/issuer/SAN/scadenza = openssl; flag scaduto/self-signed/
chiave<2048/SHA1/wildcard corretti.

---

## TIER 7 — IPv6

### 7.1 Address intel (ogni target IPv6)
```zsh
rustymap -v "$V6"               # riga "IPv6 address intel:" + note
ip -6 neigh | grep "$V6"        # confronta il MAC estratto con quello reale
```
Casi: SLAAC EUI-64 (MAC+vendor byte-identico), privacy RFC 4941 (MAC nascosto),
`::1`/`::443` manuale, `fe80::` link-local, `ff02::1` multicast.

### 7.2 Transizione / mapped (calcolo puro)
```zsh
rustymap "64:ff9b::c000:0201"   # atteso: NAT64 → 192.0.2.1
rustymap "::ffff:192.0.2.5"     # atteso: IPv4-mapped
```

### 7.3 OS fingerprint IPv6 + sweep /64
```zsh
sudo rustymap -O -v -6 "$V6";  sudo nmap -O -6 "$V6"
rustymap --ipv6-sweep "$V6PREFIX"
```
**PASS:** stessa famiglia OS; lo sweep trova gli host con IID comuni
(::1/::53/::80/::443/vanity).

---

## TIER 8 — ⭐ Script (117 built-in) — spot check

```zsh
ls ~/RustyMap/scripts/*.rhai | wc -l          # 117
rustymap --script-list | head -40             # catalogo auto-generato
```
### 8.1 I 16 nuovi (0.79) — text/HTTP, no root
```zsh
# web / HTTP
rustymap --script http-trace-enabled,http-xmlrpc-exposed,http-phpinfo,docker-registry-exposed "$WEB"
rustymap --script sonarqube-exposed,mongo-express-exposed,arangodb-exposed,couchbase-exposed,nacos-exposed "$WEB"
rustymap --script jupyter-no-auth "$WEB"      # 8888 /api/contents 200 = no-auth RCE
# servizi vari
rustymap --script clamav-clamd,zookeeper-ruok,nats-info,telnet-exposed,rtsp-options "$LINUX"
rustymap --script smtp-starttls-check -p 25,587 "$LINUX"
```
### 8.2 Confronto di riferimento
```zsh
nmap -p80,443 --script http-enum "$WEB"       # path vs docker-registry/jupyter/…
nikto -host "http://$WEB/"
```
**PASS:** finding coerenti con i tool; nessun crash di parsing; gli script si
listano in `--script-list`.

---

## Matrice riassuntiva — PASS in una riga

| # | Feature | Comando RustyMap | Riferimento | PASS |
|---|---------|------------------|-------------|------|
| 0.3 | B12 connect lente | `sudo rustymap --sT -p1-20000 "$NAT"` | `nmap -sT` | trova 902/16012 |
| 0.6 | B20 UDP closed | `sudo rustymap --sU` | `nmap -sU` | chiuse = closed |
| 1.x | -sV binario | `rustymap --sV -p135,445,3389,902` | `nmap -sV`+script | prodotto+dettaglio |
| **2.1** | **16-campi completo** | `sudo rustymap -O -v` | `sudo nmap -O -d` | **+OPS/WIN/T1** |
| **2.2** | **SEQ sampling band** | `sudo rustymap -O -v` | `nmap -O` | punto dentro banda |
| **2.3** | **B26 CI/II=RI** | `sudo rustymap -O -v` | `nmap -O -d` | TI=RD, CI/II=RI |
| 2.4 | U1/IE quoted | `sudo rustymap -O -v` | `nmap -O -d` | RIPL/RID/…/CD/DFI |
| **3.1** | **os-db match (↑%)** | `sudo rustymap -O -v --nmap-os-db "$OSDB"` | `nmap -O` | OS+% ~ OS details |
| 4.x | tipi di scan | `--sA/--sW/--sM/--sO/--sY/--sI/-b/--quic` | `nmap -s*`/curl | stessi stati |
| 6.2 | JARM | `rustymap --tls-scan` | pyjarm | hash identico |
| 7.1 | IPv6 intel | `rustymap -v "$V6"` | ip -6 neigh | EUI-64→MAC reale |
| **8.1** | **16 script nuovi** | `rustymap --script <nuovi>` | http-enum/nikto | finding coerenti |

## Cosa mandarmi per ogni FAIL
Incolla: (a) output RustyMap **con `-v`**, (b) output nmap/tool corrispondente,
(c) tipo/OS reale del target. Priorità:
1. **Tier 2.1/2.2** — blocco `nmap-fp:` + `SEQ sampling band:` accanto a
   `nmap -O -d` (OPS/WIN/T1 nuovi + banda SP/ISR/TS).
2. **Tier 2.3** — righe `TI=/CI=/II=` vs nmap (fix B26).
3. **Tier 3.1/3.2** — `OS: <nome> (NN%)` vs `OS details` (la % ora deve salire).
4. **Tier 8.1** — i 16 script nuovi che sparano finding o crashano il parse.
