# RustyMap — Kali validation roadmap (v0.95.0 → v0.99.0)

Sequenza unica di comandi, dall'aggiornamento alla validazione di tutto il
lavoro di questa tornata: script engine 607, `--port-script`, `--sn` arricchito,
promozioni maturità, fix hang (v0.95.1/.2), nuovi output. Esegui dall'alto in
basso; ogni passo dice **cosa aspettarti**.

> Gli scan raw (`--sS`/`-O`/stealth) = **root**. `--sV`/`--web-scan`/script/
> `--port-script`/`--sn` = no privilegi. Serve `hyperfine` per i bench.

## 0) Aggiornamento + build + install
```sh
cd ~/RustyMap
git fetch origin --tags
git checkout v0.99.0
cargo build --release
sudo install -m 0755 target/release/rustymap "$(command -v rustymap || echo /usr/local/bin/rustymap)"
rustymap --version          # → rustymap 0.99.0

# variabili comode (adatta ai tuoi IP reali)
RM=rustymap
SERVER=192.168.1.31 ; ROUTER=192.168.1.1 ; CAM=192.168.1.34
WIN=192.168.1.64 ; NET=192.168.1.0/24
```
**Atteso:** build pulita, `rustymap 0.99.0`.

---

## 1) Script engine 607 — sweep falsi-positivi (#6, stile v0.87→v0.87.1)
```sh
# conteggio script caricati
$RM --script-catalog /tmp/cat.json >/dev/null 2>&1 ; grep -c '"name"' /tmp/cat.json
# → circa 607

# sweep -sV su host con web/servizi: cerca detector che NON dovrebbero scattare
sudo $RM --sV $ROUTER $SERVER $CAM -p 1-1000 2>&1 | tee /tmp/sweep.txt
grep -iE "detected|exposed|banner" /tmp/sweep.txt

# su un host web "catch-all" (router): verifica che i detector http NON spammino
$RM --sV --web-scan $ROUTER -p 80,443,8080
```
**Atteso:** i detector scattano SOLO sui servizi reali (soft-404 sopprime i
catch-all). **Riportami** ogni finding palesemente sbagliato (es. "Jellyfin" su
una telecamera) — li sistemo in una patch come feci per v0.87.1. Occhio ai
marker generici tightened: `ray`/`axis`/`plane`/`outline`.

---

## 2) `--port-script` — script esterno per porta aperta (#5)
```sh
# script di esempio (qualsiasi linguaggio: shebang)
cat > /tmp/grab.sh <<'EOS'
#!/bin/sh
# $1=ip $2=port $3=proto ; env RUSTYMAP_IP/PORT/PROTO/HOST
printf 'banner: '; timeout 2 bash -c "exec 3<>/dev/tcp/$1/$2; head -c 80 <&3" 2>/dev/null
EOS
chmod +x /tmp/grab.sh

sudo $RM --sS -p 21,22,80,443 --port-script /tmp/grab.sh $SERVER
```
**Atteso:** per ogni porta aperta compare una riga `[port-script] IP:PORT → …`
con l'output dello script; errori dello script finiscono soppressi (stderr) e un
programma che si impianta viene ucciso a `--timeout`.

---

## 3) `--sn` arricchito — inventory discovery (#7)
```sh
sudo $RM --sn $NET                       # ARP on-LAN → MAC+vendor+latenza+PTR
$RM --sn $NET --oJL /tmp/hosts.jsonl ; head -3 /tmp/hosts.jsonl
```
**Atteso:** tabella `ADDRESS FAM LATENCY MAC HOSTNAME/VENDOR`; i telefoni/tablet
mostrano il vendor mobile; `--oJL` scrive 1 oggetto JSON per host (hostname+mac
inclusi).

---

## 4) Maturazione Beta/Alpha → Production (#1, vedi KALI_MATURITY_CHECKLIST.md)
```sh
# Sezione A già promossa in v0.97.0: verifica rapida che reggano
sudo $RM -O $SERVER ; sudo nmap -O -n $SERVER | head
$RM --sV $SERVER | head ; nmap -sV -n $SERVER | head
$RM --tls-grade $ROUTER ; $RM --ssh-audit $SERVER

# Sezione B (serve 1 run di conferma): brute vs hydra (usa HYDRA_PARITY.md), su TUOI target
$RM --smb-audit $WIN
$RM --cve-for "OpenSSH 9.6p1"   # e altri CPE reali: confronta con NVD
```
**Atteso:** concordanza col tool di riferimento. Mandami "A regge + B: X/Y
concordi" e **propongo le promozioni** `src/maturity.rs` per quelle passate.

---

## 5) Congestion control / hang-fix re-conferma (v0.95.1/.2) + bench (#8 input)
```sh
# host filtrato muto: deve finire in SECONDI (silence-shrink), non ore
time sudo $RM --sS --fast-engine -p 1-65535 $CAM
# host filtrato ma responsivo SENZA --host-timeout (era ~50min → ora ≲1min)
time sudo $RM --sS --fast-engine -p 1-65535 $ROUTER
# tetto esplicito rispettato
time sudo $RM --sS --fast-engine --host-timeout 120 -p 1-65535 $WIN

# bench default (per-probe) vs fast vs nmap — dati per la decisione #8/#9
hyperfine -w1 -r5 \
  "sudo $RM --sS -F $NET --no-builtin-scripts" \
  "sudo $RM --sS --fast-engine -F $NET --no-builtin-scripts" \
  "sudo nmap -sS -F -n $NET"
```
**Atteso:** nessun hang; `--host-timeout` esatto; numeri hyperfine → me li mandi
e decidiamo i tuning di "velocità di default" (#8/#9).

---

## 6) Nuovi output — SARIF + JSON-lines (Fase 36)
```sh
$RM --sV --sarif /tmp/scan.sarif $SERVER ; jq '.version, (.runs[0].results|length)' /tmp/scan.sarif
$RM --sV --oJL /tmp/scan.jsonl $SERVER ; wc -l /tmp/scan.jsonl
```
**Atteso:** SARIF `"2.1.0"` + results>0; JSONL 1 riga per host.

---

## 7) Esiti → prossimi passi
Mandami: (1) FP degli script, (2) esito `--port-script`, (3) concordanze
maturazione, (4) numeri hyperfine. Con quelli:
- fixo gli FP script in una patch (v0.99.x),
- promuovo le feature maturate,
- decido i tuning #8/#9 sui numeri reali,
- e restano da fare #2 (HTML interattivo), #3 (nmap-service-probes send), #4
  (ICMP rate-limit) quando vuoi.

v1.0 **NON** si taglia finché non lo dici tu.
