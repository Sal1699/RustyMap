# Kali roadmap — validate everything fixed since the v0.108.0 testing

Spans **v0.108.1 → v0.108.4** (the last lab run was on v0.108.0, 2026-11-14).
Six fixes to re-validate, then the still-pending items. Most touch Linux-only or
network behaviour that can't be reproduced on the Windows dev box, so they're
all first-time lab checks.

## Setup

```sh
git pull && cargo build --release
export RM="sudo ./target/release/rustymap"
export RMU="./target/release/rustymap"
DVWA=http://127.0.0.1:8080 ; DVWACOOKIE="PHPSESSID=xxxx; security=low"
MSF2=172.17.0.2 ; GW=10.0.2.2 ; V6=fe80::x%eth0 ; IFACE=eth0
```
`$RMU --version` → `rustymap 0.108.4`.

---

## TIER 1 — the six fixes since v0.108.0

### V1 — N12 (v0.108.1): IPv6 link-local no longer dropped by discovery
```sh
$RMU --sT -p 22,80 "$V6"      # connect scan (v6-capable)
$RM  --sT -p 22,80 "$V6"      # with discovery (default on)
```
**PASS if** the host is now scanned (not "0 IP addresses"). Root cause was
`discover_hosts` dropping a link-local host that `tcp_ping` couldn't reach; it's
now kept (on-link by definition). **FAIL** = still 0 targets/results.

### V2 — 1.A (v0.108.1): new UDP payloads (TFTP / mDNS / SIP)
```sh
# on a host that actually runs one of these (e.g. a tftpd, an avahi/mDNS
# responder, or a SIP UA):
$RM  --sU -p 69,5353,5060 <host>
sudo nmap -sU -p 69,5353,5060 <host>
```
**PASS if** a listening service on 69/5353/5060 is now `open` (was
`open|filtered`), matching nmap. If you have no such service, note N/A — the
payloads can't be exercised without a listener.

### V3 — N6 (v0.108.2): audit a service on a non-standard port
```sh
# e.g. SSH relocated to 2222:
$RMU --ssh-audit -p 2222 <host-with-ssh-on-2222>
```
**PASS if** the SSH audit actually runs on 2222 (KEX/cipher/MAC report), instead
of the old "no open port matched the standard ports (SSH:22)". A dedicated
`--smb/-rdp/-smtp-audit -p <port>` behaves the same; `--auth-audit` stays
standard-ports-only.

### V4 — N8 (v0.108.2): crawler never leaves the seed host on a redirect
```sh
# Point the crawler at a page that 302s to a different host:
$RMU --web-crawl "$DVWA/" --web-cookie "$DVWACOOKIE" --crawl-depth 2 -v
```
**PASS if** no off-host URL is fetched/crawled and the session holds. (Hard to
force in a flat lab — if nothing 302s off-host, note N/A; the policy is provably
host-scoped either way.)

### V5 — N2 (v0.108.3): richer `--osdb-submit` pack
```sh
$RM --osdb-submit "$MSF2:Metasploitable2" --osdb-submit-out /tmp/pack.txt --experimental-confirm
cat /tmp/pack.txt
```
**PASS if** (with no `-p`) the pack now reflects a **top-100** scan — more "Open
ports" / "Service banners" than the old 15-port peek — and includes a
`Closed ports (sample):` line (the fingerprint baseline). `-p-` still gives a
maximal pack.

### V6 — v0.108.4 code-scan cleanup: regression sanity
The scan cleanups are behaviour-preserving; just confirm nothing regressed:
```sh
$RMU --iot-discover $MSF2            # mDNS/DNS-SD label extraction (iot_discover cleanup)
$RMU --brute-protocol mssql --brute-target <mssql-host> --brute-pair sa:<pass> --brute-confirm-authorized
```
**PASS if** IoT/mDNS service labels still parse, and the MSSQL brute still HITs on
valid creds (the `drop(cur)` removal must not have changed the TLS-read loop).

---

## TIER 2 — still pending (not from this span, but open)

| Item | Needs | Check |
|------|-------|-------|
| 5.D confirm | a TLS service | `$RMU --vuln-ssl-ccs -p 443 <tls host>` → must say `n/a (modern TLS …)` or a real VULN/PATCHED verdict, **not** `port not TLS` (already fixed in code, lab-unconfirmed) |
| Alpha: rdp | Windows+NLA | `--brute-protocol rdp …` → PROMOTE if HIT matches hydra |
| Alpha: ipa | real signed `.ipa` | `--ipa-scan app.ipa` → PROMOTE if Mach-O/entitlements match otool/codesign |
| Alpha: os-fp-v6 | ≥2 v6 hosts diff OS | `--os-fp-v6 $V6` → PROMOTE if family correct on ≥2 |
| Alpha: threat-intel-misp | MISP instance | `--threat-intel-misp … --threat-intel-match` → PROMOTE if match flagged |
| Alpha: osdb-submit | (self) | N2 now richer — consider for promotion once V5 passes |

---

## Results log (fill + paste back)

```
Tier 1: V1 N12 [ ]  V2 UDP [ ]  V3 N6 [ ]  V4 N8 [ ]  V5 N2 [ ]  V6 cleanup [ ]
        (PASS / FAIL / N-A-no-target)
Tier 2: 5.D [ ]   rdp [ ]  ipa [ ]  os-fp-v6 [ ]  misp [ ]  osdb [ ]

Notes (ID → result, paste output):
```
