# RustyMap — Test Roadmap v0.75 (RustyMap vs nmap, comandi inclusi)

Piano di test **completo** per confrontare RustyMap con nmap (e i tool di
riferimento del settore) su tutto ciò che è stato aggiunto da v0.71 a v0.75:
`-sV` binario, engine OS a 16 campi, nuovi scan (`--sA/-sW/-sM/-sO/-sI/-sY/-sZ`,
FTP bounce, `--quic`), `--web-scan`, `--tls-scan` (matrice TLS + ALPN + HSTS +
JARM + certificato), e tutto l'apparato IPv6.

Logga ogni esito in `LAB_VALIDATION.md`. **Copia i comandi così come sono**
(sono zsh-safe: usano variabili, niente `<...>`).

---

## Setup — eseguilo una volta

```zsh
# --- adatta gli IP/host al tuo lab, poi incolla questo blocco ---
WIN=192.168.1.20        # Windows 10/11
WSRV=192.168.1.21       # Windows Server / Domain Controller (SMBv1 o dominio)
LINUX=192.168.1.15      # Linux generico
ROUTER=192.168.1.1      # router / apparato di rete
ESXI=192.168.1.30       # VMware ESXi (opzionale)
WEB=192.168.1.40        # host con web app (HTTP e HTTPS)
NAT=10.0.2.2            # gateway NAT di VirtualBox (stack Slirp)
V6=2001:db8::1234       # host IPv6 dual-stack (adatta)
V6PREFIX=2001:db8:abcd:1::   # prefisso /64 per lo sweep
PUB=scanme.nmap.org     # target pubblico autorizzato da Nmap
```

### Build su Kali (root)
```zsh
cd ~/RustyMap && git fetch --tags && git checkout v0.75.0 && cargo build --release
sudo install -m755 target/release/rustymap "$(command -v rustymap)"
rustymap --version   # deve stampare 0.75.0
```

### Tool di riferimento consigliati (per il confronto)
```zsh
sudo apt install -y nmap sslscan whatweb nikto ldnsutils 2>/dev/null
# testssl.sh: git clone --depth1 https://github.com/drwetter/testssl.sh
# jarm:       pip install jarm   (oppure usa https://jarm.online nel browser)
```

### Regole
- **Solo target autorizzati.** Pubblico = `scanme.nmap.org`. Tutto il resto
  solo sui **tuoi** host di lab.
- Raw socket (`-O`, `--sS`, `--sU`, suite secondaria) = **root**.
- `-sV`, `--web-scan`, `--tls-scan`, `--quic`, `-b` = **nessun privilegio**.
- Gli hint di `-O` (blocco fingerprint, ISN, IPv6 intel) compaiono con **`-v`**.
- PASS = combacia con nmap/riferimento **oppure** la divergenza è compresa e
  annotata.

---

## TIER 0 — Regressione core (deve restare allineato a nmap)

| ID | RustyMap | nmap | PASS |
|----|----------|------|------|
| 0.1 | `rustymap "$PUB"` | `nmap "$PUB"` | stesse porte open |
| 0.2 | `sudo rustymap --sS -p 1-1000 "$LINUX"` | `sudo nmap -sS -p 1-1000 "$LINUX"` | stesso set open/closed |
| 0.3 | `sudo rustymap --sU -p 53,123,161 "$LINUX"` | `sudo nmap -sU -p 53,123,161 "$LINUX"` | stessi stati UDP |
| 0.4 | `time rustymap --sT -p 1-1000 "$WEB"` vs `time nmap ...` | — | annota il wall-clock (atteso RustyMap più veloce) |

---

## TIER 1 — `-sV` su protocolli binari

### 1.1 SMB (445) — dialetto + OS/host/dominio
```zsh
rustymap --sV -p445 "$WSRV"
nmap    -sV -p445 "$WSRV"
nmap -p445 --script smb-protocols,smb-os-discovery,smb2-security-mode "$WSRV"
```
**Confronto:** dialetto RustyMap = max di `smb-protocols`; su host con SMBv1/NTLM
raggiungibile, host/workgroup/dominio/OS-build = `smb-os-discovery`.
**Atteso su Win10/11 (SMBv1 off):** solo dialetto (come nmap senza lo script).

### 1.2 MSRPC (135)
```zsh
rustymap --sV -p135 "$WIN"
nmap    -sV -p135 "$WIN"
```
**PASS:** entrambi "Microsoft Windows RPC"; RustyMap aggiunge "bind accepted".

### 1.3 RDP (3389) — con livello di sicurezza (NLA)
```zsh
rustymap --sV -p3389 "$WIN"
nmap -p3389 --script rdp-ntlm-info,rdp-enum-encryption "$WIN"
```
**PASS:** RustyMap "Microsoft Terminal Services (RDP)" + `standard/TLS/CredSSP-NLA`;
il livello combacia con `rdp-enum-encryption`.

### 1.4 VMware authd (902) — opzionale
```zsh
rustymap --sV -p902 "$ESXI"
nmap    -sV -p902 "$ESXI"
```
**PASS:** stessa versione demone (es. 1.10).

### 1.5 Negativo (nessun falso positivo)
```zsh
rustymap --sV -p135,445,3389 "$LINUX"
```
**PASS:** porte closed/filtered, nessun servizio Windows inventato.

### 1.6 Regressione banner testuali
```zsh
rustymap --sV -p22,80,443 "$PUB"
nmap    -sV -p22,80,443 "$PUB"
```
**PASS:** SSH/HTTP prodotto+versione coerenti (nota: `scanme` può andare in
timeout dal lab — riprova o usa un host locale).

---

## TIER 2 — OS detection (root, `-O -v`)

Riferimento gold: `sudo nmap -O -d` stampa il fingerprint grezzo
`SEQ/OPS/WIN/ECN/T1..T7/IE/U1`.

### 2.1 Blocco fingerprint a 16 campi
```zsh
sudo rustymap -O -v "$WIN"      # cerca "nmap-fp: SEQ(...) T2..U1"
sudo nmap    -O -d "$WIN"       # confronta campo per campo
```
**Confronto (per T2..T7/ECN/IE/U1):** `R`, `TTL→TG`, `W`, `DF`, `F`, e ora anche
`S`/`A`/`O`/`RD`/`Q`/`CC` (RustyMap li calcola). SEQ: `GCD`/`ISR`/`SP`/`TI`/`CI`/`TS`.
**PASS:** i campi combaciano con nmap `-d` (piccole divergenze su T5-T7 → vedi 2.4).

### 2.2 Match OS finale
```zsh
sudo rustymap -O -v --osscan-guess 5 "$LINUX"
sudo nmap    -O    --osscan-guess    "$LINUX"
```
Ripeti su `$WIN`, `$ROUTER`, `$ESXI`. **PASS:** stessa famiglia; versione entro una minor.

### 2.3 ISN / TCP Sequence Prediction
```zsh
sudo rustymap -O -v "$LINUX"    # riga "ISN: ..."
sudo nmap    -O -v "$LINUX"     # "TCP Sequence Prediction: Difficulty=..."
```
**PASS:** classe coerente (randomized↔difficile, incremental/constant↔debole).

### 2.4 VirtualBox Slirp NAT + guard RST kernel
```zsh
sudo rustymap -O -v "$NAT"      # atteso: "VirtualBox/QEMU Slirp NAT" + T5/T6/T7 R=Y
sudo nmap    -O -d "$NAT"
```
**PASS:** RustyMap identifica lo Slirp; con la guard RST attiva T5-T7 non danno più
falsi R=N. Se divergono, prova a togliere la guard (`--no-...`? attualmente
sempre-on su Linux) e annota.

### 2.5 Campi TCP moderni (TFO/MPTCP)
```zsh
sudo rustymap -O -v "$LINUX"    # se presente: "modern TCP: TCP Fast Open / Multipath TCP"
```
**PASS:** su kernel Linux recenti con TFO/MPTCP attivi la riga compare (nmap non
la mostra — è un plus, non un confronto).

---

## TIER 3 — Nuovi tipi di scan

### 3.1 ACK / Window / Maimon (mappatura firewall)
```zsh
sudo rustymap --sA -p 1-1000 "$ROUTER";  sudo nmap -sA -p 1-1000 "$ROUTER"
sudo rustymap --sW -p 1-1000 "$LINUX";   sudo nmap -sW -p 1-1000 "$LINUX"
sudo rustymap --sM -p 1-1000 "$LINUX";   sudo nmap -sM -p 1-1000 "$LINUX"
```
**PASS:** stessa classificazione unfiltered/filtered (ACK) e open/closed (Window).

### 3.2 IP protocol scan
```zsh
sudo rustymap --sO "$LINUX";  sudo nmap -sO "$LINUX"
```
**PASS:** stessi protocolli (ICMP/TCP/UDP/…) open|filtered.

### 3.3 SCTP
```zsh
sudo rustymap --sY -p 80,443,2905 "$LINUX";  sudo nmap -sY -p 80,443,2905 "$LINUX"
sudo rustymap --sZ -p 80,443,2905 "$LINUX";  sudo nmap -sZ -p 80,443,2905 "$LINUX"
```

### 3.4 Idle / zombie
```zsh
sudo rustymap --sI "$ROUTER:80" "$LINUX" --experimental-confirm
sudo nmap -sI "$ROUTER" "$LINUX"
```
**PASS:** stessi open (o entrambi falliscono se lo zombie ha IPID randomizzato).

### 3.5 FTP bounce (senza root)
```zsh
rustymap -b anonymous@"$LINUX" -p 22,80,445 "$WEB"
```
**PASS:** su relay moderno → "relay blocked bounce" (bene); su relay vulnerabile →
porte open/closed via bounce. (nmap: `nmap -b anonymous@"$LINUX" "$WEB"`.)

### 3.6 QUIC / HTTP-3 (senza root, moderno)
```zsh
rustymap --quic cloudflare.com
rustymap --quic "$WEB"
# riferimento: curl --http3 -sI https://cloudflare.com  (se hai curl con HTTP/3)
```
**PASS:** su server HTTP/3 elenca le versioni QUIC (v1/v2); nessun responder →
messaggio pulito. nmap **non** ha uno scan QUIC → è un punto di forza RustyMap.

---

## TIER 4 — Web scanning (`--web-scan`, senza root)

```zsh
rustymap --web-scan "$WEB"
# riferimenti:
whatweb "http://$WEB/"
nikto -host "http://$WEB/"
nmap -p80,443 --script http-headers,http-security-headers,http-enum,http-git "$WEB"
```
**Confronto:**
| Elemento RustyMap | Riferimento |
|---|---|
| grade security-header A-F + gap | `http-security-headers` / securityheaders.com |
| WAF/CDN rilevato | `whatweb` / `wafw00f "$WEB"` |
| path sensibili (.env/.git/actuator/…) | `nikto` / `http-enum` / `http-git` |
| flag cookie | header `Set-Cookie` (verifica manuale) |

**PASS:** i path esposti trovati da RustyMap compaiono anche in nikto/`http-enum`;
il WAF coincide con `wafw00f`; il grade riflette gli header mancanti reali.

---

## TIER 5 — HTTPS / TLS (`--tls-scan`, senza root)

```zsh
rustymap --tls-scan "$WEB"
```
Confronta ciascuna sezione con il tool di riferimento:

### 5.1 Matrice versioni TLS
```zsh
sslscan --no-ciphersuites "$WEB":443
nmap -p443 --script ssl-enum-ciphers "$WEB"        # elenca protocolli+cifrari
```
**PASS:** l'insieme "yes/no" per TLS 1.0/1.1/1.2/1.3 combacia con sslscan; 1.0/1.1
segnalate deprecate.

### 5.2 ALPN (HTTP/2)
```zsh
openssl s_client -connect "$WEB":443 -alpn h2,http/1.1 </dev/null 2>/dev/null | grep -i ALPN
```
**PASS:** stesso protocollo negoziato (se `openssl` mostra `h2`, RustyMap dice
"HTTP/2 supported").

### 5.3 HSTS
```zsh
curl -sI "https://$WEB/" | grep -i strict-transport-security
```
**PASS:** presenza/max-age/includeSubDomains/preload coerenti.

### 5.4 JARM (fingerprint attivo) — DA VALIDARE CONTRO RIFERIMENTO
```zsh
rustymap --tls-scan "$WEB" | grep JARM
# riferimento (scegline uno):
python3 -c "import jarm.scanner.scanner as s; print(s.Scanner.scan('$WEB',443))"
#   oppure incolla l'host su https://jarm.online
```
**PASS (importante):** il JARM di RustyMap deve essere **identico** a quello del
tool `jarm`/jarm.online. Prova almeno: 1 host **Cloudflare**, 1 **nginx**, 1
**Apache**, 1 **IIS**. **Se un carattere differisce, incollameli entrambi** —
correggo la permutazione/estensione.

### 5.5 Certificato
```zsh
openssl s_client -connect "$WEB":443 -servername "$WEB" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```
**PASS:** subject/issuer/SAN/scadenza combaciano con openssl; i flag
(scaduto/self-signed/chiave<2048/SHA1/wildcard) sono corretti. Test mirati:
```zsh
rustymap --tls-scan self-signed.badssl.com     # atteso: self-signed
rustymap --tls-scan expired.badssl.com         # atteso: EXPIRED
rustymap --tls-scan rsa2048.badssl.com         # chiave ok
```

---

## TIER 6 — IPv6 (il punto di forza)

### 6.1 Intel dell'indirizzo (ogni target IPv6)
```zsh
rustymap "$V6"                  # cerca la riga "IPv6 address intel:"
rustymap -v "$V6"               # con note (EUI-64→MAC→vendor, privacy, ecc.)
```
**PASS:** nmap **non** ha nulla di equivalente. Verifica manualmente:
```zsh
# host SLAAC EUI-64 → il MAC estratto deve combaciare col MAC reale:
ip -6 neigh | grep "$V6"        # confronta con "EUI-64 → MAC ..."
```
Casi da provare: un host **SLAAC EUI-64** (deve estrarre MAC+vendor), uno con
**privacy** (RFC 4941 → "MAC hidden"), un **::1/::443** manuale, un `fe80::`
link-local, un `ff02::1` multicast.

### 6.2 OS fingerprint IPv6
```zsh
sudo rustymap -O -v -6 "$V6"    # classify_v6 (window-scale/TS/SACK) + hop-limit
sudo nmap    -O -6 "$V6"
```
**PASS:** stessa famiglia OS.

### 6.3 Sweep /64 (discovery degli IID comuni)
```zsh
rustymap --ipv6-sweep "$V6PREFIX"
```
**PASS:** trova gli host con IID manuali comuni (::1/::53/::80/::443/vanity). nmap
non lo fa in questo modo; confronta con quello che sai essere vivo nel /64.

### 6.4 Transizione / mapped
```zsh
rustymap "64:ff9b::c000:0201"   # atteso: NAT64/DNS64 → 192.0.2.1
rustymap "::ffff:192.0.2.5"     # atteso: IPv4-mapped
```

---

## TIER 7 — Script (101 built-in) — spot check

```zsh
rustymap --list-scripts 2>/dev/null | wc -l     # ~101 (o conta i file scripts/)
rustymap --script ollama-exposed,http-env-exposed,rdp-exposed "$WEB"
rustymap --script http-git-exposed,http-swagger-exposed,http-actuator-exposed "$WEB"
```
**PASS:** gli script che matchano danno finding coerenti; confronta i path con
`nmap --script http-enum` / nikto (Tier 4).

---

## Matrice riassuntiva "PASS in una riga"

| Feature | Comando RustyMap | Riferimento | PASS |
|---|---|---|---|
| SMB dialetto/OS | `rustymap --sV -p445` | `nmap --script smb-*` | = dialetto/OS nmap |
| MSRPC/RDP/VMware | `rustymap --sV -p135,3389,902` | `nmap -sV` + script | prodotto+dettaglio |
| OS 16-campi | `sudo rustymap -O -v` | `sudo nmap -O -d` | R/TTL/W/DF/F/S/A/O/RD/Q/CC |
| ISN | `sudo rustymap -O -v` | `nmap -O -v` | classe = difficulty |
| Slirp+RST guard | `sudo rustymap -O -v "$NAT"` | `nmap -O -d` | Slirp id + T5-T7 R=Y |
| ACK/Win/Maimon | `--sA/--sW/--sM` | `nmap -sA/-sW/-sM` | stessa classificazione |
| SCTP/idle/proto | `--sY/--sZ/--sI/--sO` | `nmap -sY/-sZ/-sI/-sO` | stessi stati |
| FTP bounce | `rustymap -b` | `nmap -b` | open/closed o blocked |
| QUIC | `rustymap --quic` | curl --http3 | versioni QUIC (nmap n/a) |
| Web scan | `rustymap --web-scan` | whatweb/nikto/wafw00f | header/WAF/path |
| TLS matrix/ALPN/HSTS | `rustymap --tls-scan` | sslscan/openssl/curl | versioni/h2/HSTS |
| JARM | `rustymap --tls-scan` | jarm / jarm.online | **hash identico** |
| Certificato | `rustymap --tls-scan` | openssl x509 | subject/SAN/scadenza/flag |
| IPv6 intel | `rustymap -v "$V6"` | ip -6 neigh (MAC) | EUI-64→MAC corretto |
| IPv6 OS/sweep | `sudo rustymap -O -6` / `--ipv6-sweep` | `nmap -O -6` | famiglia / host vivi |

## Cosa mandarmi per ogni FAIL
Incolla: (a) output RustyMap **con `-v`**, (b) l'output del tool di riferimento
corrispondente, (c) tipo/OS reale del target. Priorità assolute da confermare:
1. **JARM** identico a jarm.online su Cloudflare/nginx/Apache/IIS.
2. Blocco `nmap-fp:` a 16 campi vs `nmap -O -d` (campi S/A/O/RD/Q/CC).
3. **EUI-64 → MAC** estratto = MAC reale (Tier 6.1).
