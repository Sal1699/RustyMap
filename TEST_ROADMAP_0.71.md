# RustyMap — Test Roadmap v0.71.0 (nuove aggiunte)

Piano di test **mirato alle due feature introdotte in v0.71.0**, da eseguire
back-to-back con **nmap 7.99** e confrontato campo per campo:

1. **B2 — `-sV` su protocolli binari**: SMB (445/139), MSRPC (135), VMware
   authd (902). *Plain TCP → nessun privilegio, testabile subito.*
2. **Suite OS secondaria**: T2–T7, ECN, ICMP-IE, UDP-U1 (`os_fp` +
   `tcp_probe_suite`). *Raw socket → richiede `sudo`.*

Logga ogni esito (soprattutto i FAIL e le divergenze) in `LAB_VALIDATION.md`.

---

## Setup — leggi prima di partire

### Regole zsh-safe (evita il `parse error near \n`)
Il vecchio `TEST_ROADMAP.md` usa segnaposto `<IP>` che **zsh interpreta come
redirezione** → errore di parsing. Qui si usano **variabili**. Modifica il
blocco sotto una volta sola, poi copia i comandi così come sono.

```zsh
# --- adatta questi IP al tuo lab, poi esegui questo blocco una volta ---
WIN10=192.168.1.20     # Windows 10/11 (SMBv1 OFF di default)
WSRV=192.168.1.21      # Windows Server / Domain Controller (o con SMBv1 ON)
SAMBA=192.168.1.22     # Linux con Samba (workgroup, SMBv1/NTLM attivo)
LINUX=192.168.1.15     # Linux generico, SENZA SMB
ROUTER=192.168.1.1     # router/embedded (TTL 64 o 255)
ESXI=192.168.1.30      # VMware ESXi (opzionale — salta se non ce l'hai)
PUB=scanme.nmap.org    # target pubblico autorizzato da Nmap
```

### Build della versione sotto test (su Kali, root)
```zsh
cd ~/RustyMap && git fetch --tags && git checkout v0.71.0 && cargo build --release
sudo install -m755 target/release/rustymap "$(command -v rustymap)"
rustymap --version   # deve stampare 0.71.0
```

### Cose da sapere
- **Tier 1 (B2)** non richiede root: `--sV` usa lo scan connect di default.
- **Tier 2 (suite)** richiede `sudo` **e** gira solo sotto `-O` **quando il
  probe T1 ha già ricevuto risposta** (host con almeno una porta open + raw
  socket disponibili).
- Il blocco diagnostico della suite e gli hint OS compaiono **solo con `-v`**
  (`verbose > 0`). Usa sempre `-O -v` nel Tier 2.
- **Riferimento gold per il confronto probe-per-probe**: `sudo nmap -O -d`
  stampa il fingerprint grezzo con le righe `SEQ/OPS/WIN/ECN/T1..T7/IE/U1`.
- PASS = combacia con nmap **oppure** la divergenza è compresa e annotata.

---

## TIER 1 — B2: `-sV` su protocolli binari (NO root)

### 1.1 — SMB, dialetto negoziato (445)
```zsh
rustymap --sV -p445 "$WIN10"
nmap    -sV -p445 "$WIN10"
nmap -p445 --script smb-protocols "$WIN10"      # elenca 2.02/2.10/3.00/3.02/3.11
```
**Confronto:**
| Campo | RustyMap | nmap (riferimento) |
|---|---|---|
| Dialetto | `SMB (dialect 3.0.2)` | dialetto **massimo** in `smb-protocols` |
| Porta/stato | `445/tcp open microsoft-ds` | `445/tcp open microsoft-ds` |

**PASS:** il dialetto RustyMap = **il più alto** elencato da `smb-protocols`
fino a 3.0.2 (RustyMap offre 2.0.2→3.0.2, quindi su un host solo-3.1.1
riporterà 3.0.2 come lower-bound: **annotalo, è atteso**, non un FAIL).

### 1.2 — SMB, OS build + host + dominio (host con NTLM/SMBv1 raggiungibile)
Target: `$WSRV` o `$SAMBA` (dove il percorso SMBv1 Session-Setup risponde).
```zsh
rustymap --sV -p445 "$WSRV"
nmap -p445 --script smb-os-discovery "$WSRV"
```
**Confronto:**
| RustyMap (`extra`/`version`) | nmap `smb-os-discovery` |
|---|---|
| `Microsoft Windows SMB` + `version` build | riga `OS:` (es. `Windows Server 2019 ... 17763`) |
| `host: NOME` | `NetBIOS computer name` |
| `workgroup: WG` | `NetBIOS domain name` / `Workgroup` |
| `domain: dom.local` | `Domain name` |

**PASS:** host/workgroup/dominio identici a nmap; il build OS combacia (stessa
major.minor.build).
**Atteso su Win10/11 con SMBv1 OFF:** RustyMap mostra **solo** il dialetto
(niente NTLM) — come nmap `smb-os-discovery` che lì fallisce. **Non è un FAIL.**

### 1.3 — SMB negativo (Linux senza SMB): niente falsi positivi
```zsh
rustymap --sV -p445 "$LINUX"
nmap    -sV -p445 "$LINUX"
```
**PASS:** entrambi riportano `445` **closed/filtered**; RustyMap **non** deve
inventare "SMB".

### 1.4 — SMB su NetBIOS (139)
```zsh
rustymap --sV -p139 "$WSRV"
nmap    -sV -p139 "$WSRV"
```
**PASS:** RustyMap gestisce 139 come 445 (dialetto/NTLM), coerente con nmap.

### 1.5 — MSRPC endpoint mapper (135)
```zsh
rustymap --sV -p135 "$WIN10"
nmap    -sV -p135 "$WIN10"
```
**Confronto:**
| RustyMap | nmap |
|---|---|
| `msrpc  Microsoft Windows RPC (DCE/RPC endpoint mapper, bind accepted)` | `msrpc  Microsoft Windows RPC` |

**PASS:** entrambi dicono **"Microsoft Windows RPC"**. Il bind DCE/RPC deve
essere accettato (`bind accepted`).

### 1.6 — MSRPC negativo (135 chiuso su non-Windows)
```zsh
rustymap --sV -p135 "$LINUX"
```
**PASS:** `135` closed/filtered; nessun "Windows RPC" fasullo.

### 1.7 — VMware Authentication Daemon (902) *(opzionale — solo se hai ESXi)*
```zsh
rustymap --sV -p902 "$ESXI"
nmap    -sV -p902 "$ESXI"
```
**Confronto:** RustyMap `VMware Authentication Daemon <ver>` ↔ nmap
`VMware Authentication Daemon 1.10 (Uses VNC, SOAP)`.
**PASS:** stessa versione del demone (es. `1.10`).

### 1.8 — REGRESSIONE: `-sV` testuale non deve essersi rotto
Il probe binario è inserito **prima** del loop testuale solo per 135/139/445;
verifica che SSH/HTTP/TLS restino invariati.
```zsh
rustymap --sV -p22,80,443 "$PUB"
nmap    -sV -p22,80,443 "$PUB"
```
**PASS:** banner SSH/HTTP e prodotto/versione coerenti con nmap (es. su
`scanme`: `OpenSSH ... Ubuntu`, `Apache httpd 2.4.x`). Nessuna regressione.

---

## TIER 2 — Suite OS secondaria T2–T7 / ECN / IE / U1 (ROOT)

Comando base per **tutti** i test di questo tier:
```zsh
sudo rustymap -O -v "$WIN10"    # cerca le righe "secondary probes:" e "probe signal:"
sudo nmap    -O -d "$WIN10"     # riferimento: stampa il fingerprint grezzo T1..T7/ECN/IE/U1
```

### 2.1 — T2–T7 probe-per-probe vs fingerprint nmap
RustyMap emette, dentro `hints`, una riga:
`secondary probes: T2(R=N) T3(R=Y TTL=64 W=0 DF=N F=AR) T4(...) T5(...) T6(...) T7(...) ECN(...) U1(...) IE(...)`

nmap `-d` emette righe tipo:
`T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)`

**Mappa dei campi da confrontare (per ogni probe T2..T7):**
| RustyMap | nmap | Regola di PASS |
|---|---|---|
| `R=Y/N` | `R=Y/N` | **devono coincidere** per ogni probe |
| `TTL=n` | `TG=hh` (esadecimale) | `n` arrotondato a 64/128/255 = `TG` (es. TTL 64 ↔ TG=40) |
| `W=n` | `W=hhhh` | stesso valore (nmap in hex) |
| `DF=Y/N` | `DF=Y/N` | devono coincidere |
| `F=...` | `F=...` | stesse lettere flag (es. `AR` = ACK+RST) |
| *(non emesso)* | `S= A= O= RD= Q=` | **RustyMap non calcola** questi 5 → non confrontare |

**PASS:** per ciascun probe, `R`, `TTL→TG`, `W`, `DF`, `F` combaciano con nmap.
Divergenze su T5/T6/T7 → vedi 2.7 (RST del kernel locale).

### 2.2 — TTL "mode" multi-probe vs TG di nmap
RustyMap usa la **moda** dei TTL di tutti i responder (`observed_ttl`) al posto
del singolo ping.
```zsh
sudo rustymap -O -v "$LINUX"   # atteso observed TTL = 64
sudo rustymap -O -v "$ROUTER"  # atteso 64 o 255 a seconda del gear
```
**PASS:** il TTL iniziale scelto da RustyMap = il `TG` che nmap deriva dalle
sue righe T-probe (64→Linux/BSD/macOS, 128→Windows, 255→network device).

### 2.3 — Negoziazione ECN
```zsh
sudo rustymap -O -v "$WIN10"   # nota "probe signal: ECN negotiated" se moderno
sudo nmap    -O -d "$WIN10"    # confronta la riga ECN(...)
```
**PASS:** se nmap mostra `ECN(R=Y...CC=Y)` (stack moderno: Win10+, Linux 4+,
BSD/macOS recenti), RustyMap deve riportare `ECN(R=Y ...)` + nota
"ECN negotiated". Se nmap `ECN(R=N)` → RustyMap `ECN(R=N)`.

### 2.4 — RST su porta chiusa (T5)
```zsh
sudo rustymap -O -v "$WIN10"   # nota "closed port answers RST" oppure "closed-port SYN dropped"
sudo nmap    -O -d "$WIN10"    # confronta T5(R=Y%...F=AR) vs T5(R=N)
```
**PASS:** `closed port answers RST` ↔ nmap `T5(R=Y...F=AR)`;
`closed-port SYN dropped (filtered)` ↔ nmap `T5(R=N)`.

### 2.5 — UDP U1 (ICMP port-unreachable)
```zsh
sudo rustymap -O -v "$LINUX"   # nota "UDP closed port returns ICMP unreachable" + U1(R=Y...)
sudo nmap    -O -d "$LINUX"    # confronta la riga U1(...)
```
**PASS:** se il target risponde con ICMP-3 alla UDP verso porta chiusa,
entrambi `U1(R=Y)`. **Nota limite:** RustyMap non quota ancora l'IP interno né
i campi RIPL/RID/RIPCK di nmap → confronta solo la **presenza** (R=Y/N).

### 2.6 — ICMP echo (IE)
```zsh
sudo rustymap -O -v "$LINUX"   # IE(R=Y TTL=n DF=Y/N)
sudo nmap    -O -d "$LINUX"    # riga IE(...)
```
**PASS:** `IE(R=Y)` e TTL coerente col TG; DF coerente. Se ICMP è filtrato:
entrambi `IE(R=N)`.

### 2.7 — Caveat RST del kernel locale (importante, da annotare)
Su Kali/Linux **il kernel della macchina che scansiona** può emettere un RST
verso le risposte inattese ai probe T5–T7, "sporcando" il risultato. nmap si
protegge con la propria gestione; RustyMap **no** (ancora).
**Come verificare la divergenza:**
```zsh
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP   # sopprime i RST locali
sudo rustymap -O -v "$WIN10"                                  # ri-esegui
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP   # ripristina
```
**PASS/annotazione:** se i risultati T5–T7 migliorano/cambiano dopo il DROP,
documenta che la suite è affidabile solo con la regola attiva → è la conferma
del limite noto (da chiudere lato codice in futuro).

---

## TIER 3 — Integrazione & accuratezza OS

### 3.1 — Match OS finale vs "OS details" di nmap (per tipo di target)
```zsh
sudo rustymap -O -v --osscan-guess 5 "$WIN10"
sudo nmap    -O    --osscan-guess    "$WIN10"
```
Ripeti per `$LINUX`, `$ROUTER`, `$ESXI`.
**Confronto:**
| Target | Atteso RustyMap (`os_db`) | Atteso nmap "OS details" |
|---|---|---|
| `$WIN10` | `Microsoft Windows 10/11` (conf ≥80) | `Windows 10 21H2 - 22H2` / simile |
| `$LINUX` | `Linux 5.X`/`6.X` | `Linux 5.x` |
| `$ROUTER` | famiglia coerente (RouterOS/embedded/…) | idem |
| `$ESXI` | *(no firma dedicata)* → famiglia da banner | `VMware ESXi` |

**PASS:** stessa **famiglia**; versione entro una minor; se RustyMap sbaglia,
annota TTL/window/WS osservati (riga `tcp-fp:`) così affino `os_db.rs`.

### 3.2 — ISN vs "TCP Sequence Prediction" di nmap
```zsh
sudo rustymap -O -v "$LINUX"   # riga "ISN: randomized — good (Difficulty: hard)"
sudo nmap    -O -v "$LINUX"    # "TCP Sequence Prediction: Difficulty=... (Good luck!)"
```
**PASS:** classe coerente — `randomized`↔Difficulty alta; `incremental`/
`constant`↔Difficulty bassa (stack vecchi/embedded).

### 3.3 — `-A` completo back-to-back
```zsh
time sudo rustymap -A "$WIN10"
time sudo nmap    -A "$WIN10"
```
**PASS:** RustyMap copre porte+`-sV`(inclusi SMB/MSRPC binari)+`-O`+traceroute;
i servizi binari 135/445 ora sono popolati dove nmap usa gli script `smb-*`.
Annota il wall-clock (atteso: SYN 1.4–7× più veloce, ma `-O` con suite può
aggiungere qualche secondo per host).

### 3.4 — Costo temporale della suite
```zsh
time sudo rustymap -O "$WIN10"       # con suite
time sudo rustymap -O "$LINUX"       # host con porta chiusa nota → più probe
```
**PASS/annotazione:** overhead ragionevole (i probe silenziosi vanno in timeout
a ~700 ms l'uno). Se un `-O` su molti host è troppo lento, segnalalo.

---

## Matrice riassuntiva "cosa mi aspetto"

| Feature | Comando chiave | PASS in una riga |
|---|---|---|
| SMB dialetto | `rustymap --sV -p445` | = max dialetto `smb-protocols` |
| SMB OS/host | `rustymap --sV -p445` (SMBv1/NTLM) | = `smb-os-discovery` |
| MSRPC | `rustymap --sV -p135` | = "Microsoft Windows RPC" |
| VMware authd | `rustymap --sV -p902` | = versione demone nmap |
| Regressione -sV | `rustymap --sV -p22,80,443` | banner invariati |
| Suite T2–T7 | `sudo rustymap -O -v` | R/TTL→TG/W/DF/F = nmap `-d` |
| TTL mode | `sudo rustymap -O -v` | = TG nmap (64/128/255) |
| ECN/IE/U1 | `sudo rustymap -O -v` | presenza R=Y/N = nmap |
| OS match | `sudo rustymap -O -v` | stessa famiglia di nmap |
| ISN | `sudo rustymap -O -v` | classe = Difficulty nmap |

## Cosa mandarmi per l'affinamento
Per ogni FAIL/divergenza, incolla: (a) l'output RustyMap **con `-v`**, (b) la
riga nmap corrispondente (`--script smb-*` o `nmap -O -d`), (c) tipo/OS reale
del target. In particolare per la suite servono le righe `secondary probes:` +
`tcp-fp:` + il blocco `T1..U1` di nmap, così taro `os_db.rs` e i probe.
