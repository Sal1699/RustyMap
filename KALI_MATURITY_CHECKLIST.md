# RustyMap — Maturity promotion checklist (verso v1.0)

Guida per maturare le **24 feature non-Production** (13 Beta + 11 Alpha) verso
Production. Regola di promozione (da `LAB_VALIDATION.md`): **una feature sale a
Production solo con UN'osservazione di accordo col tool di riferimento su un
target reale** — i test sintetici non bastano. Le promozioni si **propongono**
(matrice `src/maturity.rs`), l'utente conferma.

Host di riferimento (dal giro v0.95.0): SERVER=.31, ROUTER=.1, CAM=.34/.226,
WIN=.64/.134, KALI-VM=.198.

---

## A. Candidati a promozione IMMEDIATA (accordo già registrato in `LAB_VALIDATION.md`)
Questi hanno già un'osservazione di accordo col reference in run precedenti —
basta la tua conferma e li promuovo (niente nuovo run necessario, ma un
re-check veloce non fa male).

| Feature | Evidenza registrata | Re-check veloce |
|---|---|---|
| `--sV` | SSH/DNS/SMB/RPC identici a nmap (v0.82.0) + lighttpd-behind-TLS (v0.95.0) | `rustymap --sV $SERVER` vs `nmap -sV $SERVER` |
| `-O` | blocco 16-field byte-identico a `nmap -O` su Kali (parity work v0.75→0.79) | `sudo rustymap -O $SERVER` vs `sudo nmap -O $SERVER` |
| `--tls-grade` | match vs sslscan su :443 (Fase L v0.83) | `rustymap --tls-grade $ROUTER` vs `testssl.sh` |
| `--ssh-audit` | weakness-analysis vs riferimento (v0.82.1) | `rustymap --ssh-audit $SERVER` vs `ssh-audit $SERVER` |

> `--smb-audit` RESTA Beta: validato solo il reject-path, non un negotiate
> riuscito su SMB vivo → serve il run sotto.

---

## B. Beta → serve un run di conferma su target reale
| Feature | Comando RustyMap | Riferimento | Criterio Production |
|---|---|---|---|
| `--smb-audit` | `rustymap --smb-audit $WIN` | `nmap --script smb2-security-mode $WIN` | dialetto+signing concordano su SMB vivo |
| `--cve-for` | `rustymap --cve-for "OpenSSH 7.4p1"` ecc. (20 CPE reali) | NVD web | ≥18/20 corretti, zero FP grossolani |
| `--brute-protocol ftp` | `rustymap --brute-protocol ftp --brute-target $H ...` | `hydra ftp://` | stessi hit (usa `HYDRA_PARITY.md`) |
| `--brute-protocol ssh` | idem ssh | `hydra ssh://` | stessi hit |
| `--brute-protocol smb` | idem smb | `hydra smb://` / crackmapexec | stessi hit |
| `--brute-protocol mysql` | idem mysql | `hydra mysql://` | stessi hit |
| `--brute-protocol postgres` | idem postgres | `hydra postgres://` | stessi hit (MD5; SCRAM = limite noto) |
| `--brute-protocol ldap` | idem ldap | `hydra ldap://` | stessi hit (simple-bind) |
| `--brute-protocol vnc` | idem vnc | `hydra vnc://` | stessi hit (RFB 3.x) |

> Il brute richiede `--brute-confirm-authorized` + un target TUO. `HYDRA_PARITY.md`
> ha le coppie di comandi pronte per tutti e 13 gli adapter.

---

## C. Alpha → limiti noti; promozione solo se il run supera il limite documentato
| Feature | Comando | Nota / cosa confermare |
|---|---|---|
| `--brute-protocol rdp` | vs Windows RDP reale | positivi SUGGESTIVI (manca pubKeyAuth); i negativi/NTSTATUS sono affidabili → resta Alpha salvo validazione pubKeyAuth |
| `--brute-protocol mssql` | vs SQL Server reale | mai validato su istanza vera (TDS 7.4) |
| `--apk-scan` | APK reali con leak noti | FP dei pattern secret; APK offuscati |
| `--ipa-scan` | IPA reali | solo Info.plist; no mach-O entitlements |
| `--threat-intel-sync` | feed MISP pubblico e2e | pull-only, no dedup |
| `--osdb-submit` | endpoint di test | attenzione leak su reti sensibili |
| `--sI` | zombie con IPID prevedibile | OS moderni = IPID random → spesso N/A |
| `--os-fp-v6` | host dual-stack | DB v6 più sottile del v4 |
| `--owasp-probes` | web app di test | alto FP; ZAP/sqlmap fanno meglio |
| `--ics-scan` | PLC reale (non solo Conpot) | read-only in produzione |
| `--web-crawl` | sito reale | lento vs ZAP, no JS-rendered |

---

## Flusso
1. Lanci i comandi della sezione che vuoi maturare, confronti col riferimento.
2. Mi mandi gli esiti (anche solo "A tutti PASS", o la tabella).
3. Io **propongo** le promozioni `src/maturity.rs` (Beta/Alpha→Production) per
   quelle che hanno superato, le applico col tuo ok, e aggiorno
   `LAB_VALIDATION.md`.
4. A fine giro: le feature restano o Production o esplicitamente Beta/Alpha
   con nota → uno dei criteri di DoD del v1.0.
