# Kali roadmap — from v0.108.0

What changed since the v0.107.2 run: N11 blind-SQLi fixed, 0.B hardened to
refuse-by-default (+`--scan-loopback`), and `--owasp-scan` / `--web-crawl`
promoted to Production. So this roadmap is: **(1)** re-check the v0.108.0 fixes,
**(2)** finally characterise **1.A UDP** (the last ALTA correctness gap) so it
can be fixed, **(3)** the 5 remaining Alpha promotions (infra-gated), **(4)** the
N12 diagnostic + the low open bugs.

## Setup

```sh
git pull && cargo build --release
export RM="sudo ./target/release/rustymap"
export RMU="./target/release/rustymap"
DVWA=http://127.0.0.1:8080 ; DVWACOOKIE="PHPSESSID=xxxx; security=low"
MSF2=172.17.0.2 ; GW=10.0.2.2 ; SERVER=10.0.0.x ; V6=fe80::x%eth0 ; IFACE=eth0
```
`$RMU --version` → `rustymap 0.108.0`.

---

## TIER 1 — v0.108.0 fix re-checks (quick, high-value)

### R1 — N11: blind/time-based SQLi now fires
```sh
$RMU --owasp-scan "$DVWA/vulnerabilities/sqli_blind/" --web-cookie "$DVWACOOKIE" \
     --owasp-checks sqli --no-robots --crawl-depth 0 --experimental-confirm
```
**PASS if** a finding `A03 Blind SQLi (time-based)` appears (the `1' AND SLEEP(5)`
payload now delays the response). This is the completion of the v0.107.2
fragment fix — the whole point of N11.

### R2 — 0.B: named host → loopback is REFUSED by default
```sh
$RMU -p 80 nonexistent.invalid.test        # a name your resolver catch-alls to 127.0.0.1
$RMU -p 80 --scan-loopback nonexistent.invalid.test
$RMU -p 80 localhost                         # still allowed (explicit)
```
**PASS if**: the first **refuses** (`✗ refusing to scan … loopback`, no scan);
the second **scans** with a `⚠ warning`; `localhost` still scans silently.

### R3 — owasp-scan / web-crawl run WITHOUT `--experimental-confirm`
```sh
$RMU --owasp-scan "$DVWA/" --web-cookie "$DVWACOOKIE" --owasp-checks sqli --crawl-depth 0
$RMU --web-crawl  "$DVWA/" --web-cookie "$DVWACOOKIE" --crawl-depth 1
```
**PASS if** both run with **no** gate error (now Production). A gate rejection = regression.

---

## TIER 2 — 1.A UDP disambiguation (the last ALTA gap)

The open bug: RustyMap can't always tell **open** (service replied) from
**open|filtered** (silence) because many UDP services only answer a
protocol-specific payload. Closed (ICMP port-unreach) already matches nmap.
Goal here is to **characterise exactly which open ports RM under-reports**, so
the fix (add the right UDP payloads) is targeted.

### U1 — top-ports sweep, RM vs nmap
```sh
sudo nmap -sU --top-ports 25 $MSF2      > /tmp/nmap_udp.txt
$RM --sU --top-ports 25 $MSF2           > /tmp/rm_udp.txt
diff <(grep -E '/udp' /tmp/nmap_udp.txt) <(grep -E '/udp' /tmp/rm_udp.txt)
```
**Capture** every port where nmap says `open` but RM says `open|filtered` — that
delta is the payload gap.

### U2 — known-open services (DNS/rpcbind/NTP/NetBIOS/SNMP)
```sh
sudo nmap -sU -p 53,111,123,137,161 $MSF2 $GW
$RM        --sU -p 53,111,123,137,161 $MSF2 $GW
```
**Record** per port: RM label vs nmap label. For each `open` nmap finds that RM
calls `open|filtered`, note the service — I'll add that protocol's probe payload.

*(No PASS/FAIL — this tier is data collection to drive the 1.A fix.)*

---

## TIER 3 — Remaining Alpha → Production (infra-gated)

5 left. Most need a target you may not have — mark `BLOCKED-no-target` and they
stay Alpha without penalty.

| Test | Needs | Run | PROMOTE IF |
|------|-------|-----|-----------|
| rdp | Windows+NLA | `RUSTYMAP_RDP_DEBUG=1 $RMU --brute-protocol rdp --brute-target $WIN --brute-userlist u.txt --brute-passlist p.txt --brute-confirm-authorized` | HIT on valid creds, clean reject on wrong, matches hydra |
| ipa | real signed `.ipa` | `$RMU --ipa-scan app.ipa --experimental-confirm` | Mach-O fields + entitlements + secrets match `otool`/`codesign` |
| os-fp-v6 | ≥2 v6 hosts, diff OS | `$RM --os-fp-v6 $V6` ; `$RM --os-fp-v6-multi $V6` | correct OS **family** on ≥2 hosts |
| threat-intel-misp | MISP + key | `$RMU --threat-intel-misp https://misp.local --misp-api-key $K --threat-intel-match --sV $SERVER` | pulls IoCs and flags a match |
| osdb-submit | any fp'd host | `$RM -O $SERVER --osdb-submit "$SERVER:label" --osdb-submit-out /tmp/p.txt` | pack complete (note if it still omits a prior `-O/-sV` inventory — bug N2) |

---

## TIER 4 — N12 diagnostic + low open bugs

### N12 — is it an expansion bug or the raw-v6 guard?
```sh
$RM  --sS -p 80 "$V6"       # expect the #13 "raw TCP … no IPv6 … use --sT" guard
$RMU --sT -p 22,80 "$V6"    # connect scan supports v6
```
**Report which:** if `--sT` expands + scans the `%iface` host → N12 was just the
raw-v6 guard masking it (not a real bug, close it); if `--sT` ALSO says 0 targets
→ it's a genuine parse/scope bug and I'll fix the expansion.

### Low bugs (confirm / capture, only if a target exists)
| Bug | Run |
|-----|-----|
| 5.D | `$RMU --vuln-ssl-ccs -p 443 <TLS host>` → confirm bogus "port not TLS" |
| N8  | crawl a site that 302s off-scope → confirm cookies sent off-scope |
| N7  | `$RMU --web-crawl <dir-listing URL>` → confirm no vuln forms seeded |
| N6  | `$RMU --ssh-audit <host with SSH on :2222>` → still only probes :22 (now with a message) |

---

## Results log (fill + paste back)

```
Tier 1: R1 N11 [ ]  R2 0.B [ ]  R3 ungated [ ]
Tier 2: U1 (paste the open vs open|filtered delta)      U2 (per-port labels)
Tier 3: rdp [ ]  ipa [ ]  os-fp-v6 [ ]  misp [ ]  osdb [ ]   (PROMOTE / STAY / BLOCKED)
Tier 4: N12 [--sS guard? / --sT works?]   5.D [ ]  N8 [ ]  N7 [ ]  N6 [ ]

Notes (ID → result, paste output):
```
