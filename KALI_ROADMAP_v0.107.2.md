# Kali roadmap — Alpha→Production promotions & open-bug sweep (from v0.107.2)

Goal: close the remaining validation gap. v0.106.2→v0.107.1 (engine + minori)
already PASSed the lab (16/17). What's left is **(1)** two re-checks for the
v0.107.2 fixes, **(2)** validating the 7 `--experimental-confirm` **Alpha**
features so they can be promoted to Production, and **(3)** reproducing the open
inventory bugs so the fixes can be prioritised.

## Setup

```sh
git pull && cargo build --release
export RM="sudo ./target/release/rustymap"      # raw scans need root
export RMU="./target/release/rustymap"           # unprivileged
DVWA=http://127.0.0.1:8080                        # DVWA base URL
DVWACOOKIE="PHPSESSID=xxxx; security=low"
SERVER=10.0.0.x ; V6=fe80::x%eth0 ; IFACE=eth0
```
`$RMU --version` → `rustymap 0.107.2`.

### Infra matrix — some promotions NEED external targets
| Test | Needs | If missing |
|------|-------|-----------|
| P1 rdp | a real **Windows host with NLA** | BLOCKED — stays Alpha |
| P2 ipa | a real **signed `.ipa`** (+ embedded.mobileprovision) | BLOCKED — stays Alpha |
| P3 os-fp-v6 | **≥2 IPv6 hosts of different OS** (Linux/Win/mac/BSD) | partial |
| P4 owasp / P5 crawl | **DVWA** (or similar) | — (you have it) |
| P7 misp | a **MISP instance** + API key | BLOCKED — optional |

---

## TIER 1 — v0.107.2 regression re-checks (quick)

### R1 — N11 blind-SQLi reaches the server now
```sh
$RMU --owasp-scan "$DVWA/vulnerabilities/sqli/" --web-cookie "$DVWACOOKIE" \
     --owasp-checks sqli --no-robots --crawl-depth 0 --experimental-confirm
```
**PASS if** a **blind/time-based** SQLi finding now appears (the `SLEEP` delay),
not just the error-based one that already worked — i.e. the `action="#"` form no
longer swallows the payload in the fragment.

### R2 — N10 `-sS` shows the closed-port summary
```sh
$RM --sS -p 1-1000 $SERVER
```
**PASS if** output now has an nmap-style `Not shown: N closed ports` line (and
lists them individually under `-v`), and open-port results are unchanged.

---

## TIER 2 — Alpha → Production validation (the core)

For each: run it, and if the **PROMOTE-IF** holds on a real target, it's ready
to move off `--experimental-confirm`.

### P1 — `--brute-protocol rdp`  (needs Windows+NLA)
```sh
RUSTYMAP_RDP_DEBUG=1 $RMU --brute-protocol rdp --brute-target $WIN \
  --brute-userlist users.txt --brute-passlist pass.txt --brute-confirm-authorized
hydra -L users.txt -P pass.txt rdp://$WIN            # reference
```
**PROMOTE IF** a valid credential returns a **HIT** (server pubKeyAuth in the
reply) and wrong creds are cleanly rejected (NTSTATUS), matching hydra. The
CredSSP channel-binding crypto is the unvalidated part — this is the only test
that confirms it end-to-end.

### P2 — `--ipa-scan`  (needs a real signed .ipa)
```sh
$RMU --ipa-scan /path/real-app.ipa --experimental-confirm
otool -hv <extracted Mach-O> ; codesign -dv <app>    # cross-check
```
**PROMOTE IF** on a *real* IPA the Mach-O fields (arch / PIE / FairPlay-encrypted
/ code-signature / __RESTRICT) and the `embedded.mobileprovision` entitlements
match reality (earlier lab used a plist-only synthetic IPA).

### P3 — `--os-fp-v6`  (needs real v6 hosts)
```sh
$RM --os-fp-v6 $V6                 # single host
$RM --os-fp-v6-multi $V6 --os-fp-v6-ports 22,80,443
# compare to ground truth / nmap -6 -O $V6
```
**PROMOTE IF** the OS **family** is correct on ≥2 hosts of different OSes
(Linux/Windows/mac/BSD). It's intentionally coarser than v4 (no full S1–S12
suite), so family-level correctness is the bar, not exact version.

### P4 — `--owasp-scan`  (DVWA — full check set)
```sh
$RMU --owasp-scan "$DVWA/" --web-cookie "$DVWACOOKIE" \
  --owasp-checks xss,sqli,cmdi,lfi,redirect --crawl-depth 1 --experimental-confirm
```
**PROMOTE IF** it finds DVWA's known vulns (reflected XSS, error+blind SQLi,
command injection, LFI) with a **tolerable false-positive rate**. Note per-check
which are found/missed and any FPs — that list decides promotion vs stay-Alpha.

### P5 — `--web-crawl`  (DVWA)
```sh
$RMU --web-crawl "$DVWA/" --web-cookie "$DVWACOOKIE" --crawl-depth 2 --crawl-max-urls 100
```
**PROMOTE IF** it discovers the expected endpoints/forms, honours robots, and —
crucially — does **not** hit `/logout.php` and kill the session (that's bug N1;
this test doubles as the N1 repro).

### P6 — `--osdb-submit`  (any fingerprinted host)
```sh
$RM -O $SERVER --osdb-submit "$SERVER:ubuntu-22.04" --osdb-submit-out /tmp/pack.txt
cat /tmp/pack.txt
```
**PROMOTE IF** the pack is complete. **Expected to expose bug N2** — the pack
currently omits the `-O`/`-sV` data. If so, mark N2 CONFIRMED (don't promote).

### P7 — `--threat-intel-misp`  (needs a MISP instance — optional)
```sh
$RMU --threat-intel-misp https://misp.local --misp-api-key $KEY --misp-days 30 \
     --threat-intel-match --sV $SERVER
```
**PROMOTE IF** it pulls IoCs and flags a matching host/attribute. Skip if no MISP.

---

## TIER 3 — Open-bug reproduction (capture evidence → prioritise fixes)

Quick repros so the fixes can be scoped. For each, note CONFIRMED/NOT-REPRO + paste output.

| Bug | Sev | Repro |
|-----|-----|-------|
| 0.B | HIGH | `$RMU --sT -p 80 nonexistent.invalid` → should WARN "resolved to loopback". Decide: warn (now) vs refuse. |
| N1 | MED | covered by P5 (crawler + `/logout.php`). |
| N5 | LOW | `$RM -sV -p 3306 $SERVER --oX /tmp/o.xml` then `xmllint --noout /tmp/o.xml` → expect a parse error on MySQL extrainfo. |
| N6 | INFO | `$RMU --ssh-audit $SERVER` when SSH is on a non-22 port → confirm it only probes :22. |
| 4.C | LOW | `$RMU --web-scan <host returning 301>` → confirm a 301 is flagged "ACCEPTED critical". |
| 5.D | LOW | `$RMU --vuln-ssl-ccs -p 443 <TLS host>` → confirm bogus "port not TLS". |
| N8 | LOW | crawl a site that 302s off-scope → confirm cookies sent off-scope. |
| N12 | INFO | `$RM --sT -p 80 'fe80::1%eth0'` → confirm "0 targets expanded" (repro the parser/scope issue). |

---

## Results log (fill + paste back)

```
Tier 1: R1(N11) [ ]  R2(N10) [ ]
Tier 2: P1 rdp [ ]  P2 ipa [ ]  P3 os-fp-v6 [ ]  P4 owasp [ ]  P5 crawl [ ]  P6 osdb [ ]  P7 misp [ ]
        (mark PROMOTE / STAY-ALPHA / BLOCKED-no-target)
Tier 3: 0.B [ ]  N1 [ ]  N5 [ ]  N6 [ ]  4.C [ ]  5.D [ ]  N8 [ ]  N12 [ ]
        (CONFIRMED / NOT-REPRO)

Notes (ID → result, paste output):
```
