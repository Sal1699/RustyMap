# RustyMap — Test Roadmap v0.82.1 (re-validazione + aree MAI testate)

**PARTE A** ri-valida i 3 fix di v0.82.1. **PARTE B** è nuova: copre tutto ciò
che NON abbiamo ancora testato nei giri precedenti (evasion, IPv6 end-to-end,
vuln, enumeration, broadcast, TLS/audit, brute, Metasploit end-to-end, interop
output, resume/diff, scala, QUIC/IoT/ICS, script live, FTP bounce). zsh-safe.
Logga in `LAB_VALIDATION.md`.

---

## SETUP

```zsh
cd ~/RustyMap && git pull && cargo build --release
sudo install -m755 target/release/rustymap /usr/local/bin/rustymap
rustymap --version   # 0.82.1
sudo apt install -y nmap hyperfine sslscan testssl.sh snmp avahi-utils \
  hydra metasploit-framework ldap-utils
```

### Lab (host reali)
```zsh
ROUTER=192.168.1.1; SERVER=192.168.1.31; CAM=192.168.1.34
WIN=192.168.1.64; LINUX=192.168.1.148; NET=192.168.1.0/24
V6=fe80::1          # un host IPv6 link-local sul tuo segmento (adatta)
V6PFX=2001:db8:abcd:1::   # prefisso /64 per lo sweep (adatta)
```
**Autorizzazione:** brute-force e vuln-check **solo** sui tuoi host. `-sI`/brute
rispettano i gate (`--experimental-confirm`, `--brute-confirm-authorized`).

---

# PARTE A — Re-validazione fix v0.82.1

```zsh
# #1 -p 1-1000 ora SEQUENZIALE (niente 1935/8000/9000)
sudo rustymap --sS -p 1-1000 $CAM | grep -oE "^[0-9]+"        # tutte <=1000
sudo rustymap --sS --top-ports 1000 $CAM | grep -oE "^[0-9]+" # QUI sì porte alte (freq)

# #2 web-scan: niente .env/config.json fasulli sul router catch-all
rustymap --web-scan $ROUTER | grep -iE "\.env|config\.json|catch-all"

# #3 --msf-suggest trova moduli (serve msfrpcd)
rustymap --msf-suggest-cve CVE-2017-0144 --msf-url https://127.0.0.1:55553 --msf-token "$T" --msf-insecure
#   atteso: trova exploit/windows/smb/ms17_010_eternalblue
```

---

# PARTE B — Aree MAI testate

## N1 — Evasion / firewall bypass (vs nmap)
```zsh
sudo rustymap --sS -f -p 1-1000 $ROUTER            ;  sudo nmap -sS -f -p 1-1000 $ROUTER        # frammentazione
sudo rustymap --sS -D 10.0.0.9,10.0.0.10 -p80,443 $ROUTER ; sudo nmap -sS -D 10.0.0.9,10.0.0.10 -p80,443 $ROUTER  # decoy
sudo rustymap --sS --source-port 53 -p80,443 $ROUTER ; sudo nmap -sS -g 53 -p80,443 $ROUTER     # source-port bypass
sudo rustymap --sS --data-length 64 -p80 $ROUTER   ;  sudo nmap -sS --data-length 64 -p80 $ROUTER
sudo rustymap --sS --ip-ttl 55 -p80 $ROUTER        ;  sudo nmap -sS --ttl 55 -p80 $ROUTER
sudo rustymap --sS --badsum -p80 $ROUTER           ;  sudo nmap -sS --badsum -p80 $ROUTER       # risposta a checksum errati
sudo rustymap --spoof-mac 0 -p80 $ROUTER           ;  sudo nmap -sS --spoof-mac 0 -p80 $ROUTER  # MAC random
sudo rustymap --sI "$ROUTER:80" $LINUX --experimental-confirm ; sudo nmap -sI $ROUTER $LINUX     # idle/zombie
```
**PASS:** stati porta coerenti con nmap; frag/decoy/source-port non cambiano il
risultato su host non-filtranti; `--badsum` → nessuna risposta da uno stack
corretto (conferma che il sistema scarta i checksum errati); idle scan trova le
stesse open se lo zombie ha IP-ID prevedibile.

## N2 — IPv6 end-to-end (vs nmap -6)
```zsh
rustymap -v "$V6"                       # IPv6 address intel (EUI-64→MAC)
ip -6 neigh | grep -i "$V6"             # confronta MAC reale
sudo rustymap --sS -6 -p 1-1000 "$V6"   ;  sudo nmap -6 -sS -p 1-1000 "$V6"
rustymap --sV -6 -p 22,80,443 "$V6"     ;  nmap -6 -sV -p 22,80,443 "$V6"
sudo rustymap -O -6 "$V6"               ;  sudo nmap -6 -O "$V6"
rustymap --ipv6-sweep "$V6PFX"          # trova IID comuni (::1/::53/::80/::443/vanity)
```
**PASS:** MAC EUI-64 = `ip -6 neigh`; stesse open di nmap -6; famiglia OS coerente.

## N3 — Vuln checks (vs nmap --script vuln)
```zsh
rustymap --vuln-ms17-010 $WIN          ;  nmap -p445 --script smb-vuln-ms17-010 $WIN
rustymap --vuln-ssl-dh $ROUTER         ;  nmap -p443 --script ssl-dh-params $ROUTER
rustymap --vuln-ssl-ccs $ROUTER        ;  nmap -p443 --script ssl-ccs-injection $ROUTER
rustymap --vuln-known-key $SERVER      ;  # chiavi SSH/host note deboli
rustymap --webdav-probe http://$ROUTER/ ; nmap -p80 --script http-webdav-scan $ROUTER
rustymap --shellshock http://$ROUTER/cgi-bin/ ; nmap -p80 --script http-shellshock $ROUTER
```
**PASS:** stesso verdetto vulnerable/not; su host patchati → entrambi "not vulnerable".

## N4 — Enumeration (SNMP / LDAP / RPC / SMB)
```zsh
rustymap --snmp-enum $ROUTER           ;  snmpwalk -v2c -c public $ROUTER system
rustymap --ldap-enum $SERVER           ;  nmap -p389 --script ldap-rootdse $SERVER
sudo rustymap --sR $LINUX              ;  rpcinfo -p $LINUX ; nmap -sV --script rpcinfo $LINUX
rustymap --smb-deep $WIN               ;  nmap -p445 --script smb-os-discovery,smb-enum-shares $WIN
```
**PASS:** SNMP sysDescr/OID = snmpwalk; LDAP rootDSE naming contexts = nmap;
RPC program list = rpcinfo; SMB host/domain/shares coerenti.

## N5 — Broadcast discovery (segmento LAN)
```zsh
sudo rustymap --dhcp-discover            # offerta DHCP (gateway/DNS/lease)
sudo rustymap --mdns-discover            ;  avahi-browse -at    # confronto mDNS
sudo rustymap --llmnr-probe              # host poisoning-vulnerabili (LLMNR)
sudo rustymap --wsdd-probe               # Windows/stampanti/cam via WS-Discovery
```
**PASS:** gli host/servizi trovati compaiono anche in `avahi-browse`/`nmap
--script broadcast-dhcp-discover`; WSDD elenca i device Windows reali.

## N6 — TLS cipher enum + audit (vs sslscan/testssl)
```zsh
rustymap --ssl-enum $ROUTER            ;  sslscan $ROUTER:443
rustymap --tls-grade $ROUTER           ;  testssl.sh --severity LOW https://$ROUTER
rustymap --ssh-audit $SERVER           ;  nmap -p22 --script ssh2-enum-algos $SERVER
rustymap --smb-audit $WIN              ;  nmap -p445 --script smb-security-mode $WIN
rustymap --rdp-audit $WIN              ;  nmap -p3389 --script rdp-enum-encryption $WIN
```
**PASS:** matrice cipher/protocolli = sslscan; grado coerente con testssl;
algos SSH/SMB-signing/RDP-NLA coerenti coi rispettivi script nmap.

## N7 — Brute-force (vs hydra) — SOLO tuoi host
```zsh
# default-creds (modalità corta, nessuna lista): veloce e a basso rischio
rustymap --brute-protocol ssh --brute-default-creds-only --brute-confirm-authorized $SERVER
# con liste (rate-limited): confronta con hydra
rustymap --brute-protocol ssh --brute-userlist users.txt --brute-passlist pass.txt \
  --brute-rate 4 --brute-confirm-authorized $SERVER
hydra -L users.txt -P pass.txt ssh://$SERVER -t 4
```
**PASS:** stessi hit (o stesso "nessun hit"); audit-log presente; rate rispettato.
Ripeti per `ftp`/`smb`/`mysql` se presenti nel lab.

## N8 — Metasploit end-to-end (oltre ping/suggest)
```zsh
rustymap -sV --msf-import lab --msf-url https://127.0.0.1:55553 --msf-token "$T" --msf-insecure $WIN
#   poi in msfconsole: workspace lab; hosts; services   → devono riflettere lo scan
rustymap --msf-fire auxiliary/scanner/smb/smb_version --msf-fire-confirm \
  --msf-fire-opt RHOSTS=$WIN --msf-url https://127.0.0.1:55553 --msf-token "$T" --msf-insecure
```
**PASS:** host/servizi importati visibili in msfconsole; il modulo auxiliary
gira e torna output. (Exploit-class solo con `--msf-fire-exploits`, a tuo rischio.)

## N9 — Interop output (XML/grep/JSON)
```zsh
rustymap --sV -F $SERVER -oX rm.xml -oG rm.grep -oJ rm.json -oN rm.nmap
# l'XML si importa negli strumenti che leggono nmap?
msfconsole -qx "workspace -a t; db_import rm.xml; hosts; exit"
xmllint --noout rm.xml && echo "XML ben formato"
jq . rm.json >/dev/null && echo "JSON valido"
```
**PASS:** `db_import` accetta l'XML (o si annota la differenza di schema vs nmap);
XML/JSON validi; grep/nmap formati paragonabili all'output nmap `-oG/-oX`.

## N10 — Resume / diff / history
```zsh
rustymap --sS -p 1-65535 $CAM -oJ base.json      # baseline
# (interrompi con Ctrl-C a metà) poi:
rustymap --resume last
rustymap --sS -p 1-65535 $CAM -oJ now.json
rustymap --diff-against base.json $CAM           # delta porte
rustymap --history 20                            # ultimi scan
```
**PASS:** resume riprende dallo stato salvato; diff elenca porte nuove/chiuse;
history mostra gli scan passati.

## N11 — Scala & robustezza
```zsh
sudo hyperfine -w1 -r2 "rustymap --sS $NET" "nmap -sS $NET"      # /24 top-1000
sudo hyperfine -w1 -r1 "rustymap --sS -p 1-65535 $NET" "nmap -sS -p- $NET"  # /24 full (lungo!)
ulimit -n 256; rustymap --all-ports $CAM; ulimit -n 1024        # fd cap non deve crashare
sudo rustymap --sS --randomize-hosts $NET                        # ordine host randomizzato
```
**PASS:** nessun crash/leak fd; memoria ragionevole; `--all-ports` rispetta il
cap fd; i tempi su /24 restano competitivi.

## N12 — QUIC / IoT / ICS / origin / cloud
```zsh
rustymap --quic cloudflare.com         ;  curl --http3 -sI https://cloudflare.com | head -1
rustymap --iot-discover $CAM            # mDNS/SSDP/CoAP sulla cam
rustymap --ics-scan $LINUX             # Modbus/S7/DNP3 (se hai PLC/sim)
rustymap --container-scan $SERVER      # Docker/K8s/etcd (se presenti)
rustymap --origin-discovery example.com  # origin dietro CDN (target pubblico tuo)
```
**PASS:** QUIC → versioni v1/v2; IoT/ICS/container → finding solo se il servizio
esiste (niente falsi positivi); origin-discovery filtra loopback/reserved.

## N13 — Script engine live (vs nmap --script)
```zsh
rustymap --script-list | wc -l                   # 117
rustymap --sV --script http-git-exposed,http-env-exposed,ssl-cert $ROUTER
nmap -p80,443 --script http-git,ssl-cert $ROUTER
rustymap --sV --script redis-no-auth,mongodb-no-auth $SERVER
```
**PASS:** i finding combaciano con gli script nmap equivalenti; nessun crash di parsing.

## N14 — FTP bounce (-b)
```zsh
rustymap -b anonymous@$LINUX -p 21,22,80,445 $SERVER   # se c'è un FTP che fa da relay
```
**PASS:** "relay blocked" su FTP moderno, oppure stati porta via bounce su un FTP vulnerabile.

---

## Matrice da compilare (manda a me)

| Area | Comando chiave | Riferimento | PASS? |
|------|----------------|-------------|-------|
| A (fix 0.82.1) | `-p 1-1000` / web-scan / msf-suggest | — | 3/3? |
| N1 evasion | `--sS -f/-D/--source-port/--sI` | nmap | stati = nmap |
| N2 IPv6 | `--sS -6` / `-O -6` | nmap -6 | open+OS = nmap |
| N3 vuln | `--vuln-ms17-010` ecc. | nmap --script vuln | stesso verdetto |
| N4 enum | `--snmp-enum/--ldap-enum/--sR/--smb-deep` | snmpwalk/rpcinfo/nmap | dati coerenti |
| N5 broadcast | `--dhcp/--mdns/--llmnr/--wsdd` | avahi/nmap | stessi device |
| N6 TLS/audit | `--ssl-enum/--tls-grade/--ssh-audit` | sslscan/testssl | matrice = ref |
| N7 brute | `--brute-protocol ssh` | hydra | stessi hit |
| N8 MSF e2e | `--msf-import/--msf-fire` | msfconsole | import+fire ok |
| N9 interop | `-oX` → `db_import` | msfconsole | importa? |
| N11 scala | `--sS $NET` /24 | nmap | no crash, tempi |

## Priorità di questa tornata
1. **N3 vuln** + **N6 TLS/audit** (feature mai confrontate con nmap-script/sslscan).
2. **N1 evasion** (frag/decoy/source-port — mai validati).
3. **N7 brute** vs hydra + **N8 MSF end-to-end** (import/fire).
4. **N2 IPv6** end-to-end.
Mandami per ciascuno: output RustyMap `-v` + output tool di riferimento + tipo host.
