# Kali validation roadmap — v0.106.2 → v0.107.1

Covers the 3-update code-review batch (engine hot-path → minori → tests) plus the
Alpha items still pending from v0.102.0–v0.106.0. Run top-to-bottom: **Tier 1 is
the highest-risk** (raw scan engine, only Windows-unit-tested so far).

## Setup

```sh
git pull && cargo build --release          # CI is billing-blocked → build here
export RM="sudo ./target/release/rustymap"  # raw scans need root/CAP_NET_RAW
export RMU="./target/release/rustymap"       # unprivileged paths

# fill in from your lab:
SERVER=10.0.0.x     # host with several OPEN + CLOSED ports (e.g. SSH+HTTP)
ROUTER=10.0.0.1     # filtered-heavy host
WIN=10.0.0.x        # Windows host (RDP/NLA, OS-fp)
V6=fe80::x%eth0     # an IPv6-reachable host
DVWA=10.0.0.x       # DVWA / deliberately-vulnerable web app
IFACE=eth0          # scanning interface
```

`$RM --version` must print `rustymap 0.107.1` before you start.

---

## TIER 1 — Engine hot-path (v0.106.2) — HIGHEST PRIORITY

All raw-socket; the regression to hunt is **a genuine reply being dropped →
ports that are really open/closed showing up as `filtered`**.

### A1 — #1 reply correlation: parity with nmap (the gate)
```sh
$RM --sS -p 1-1000 $SERVER
sudo nmap -sS -p 1-1000 $SERVER
```
**PASS if** the open/closed port sets are identical to nmap. **FAIL** if any
port nmap reports `open`/`closed` is `filtered` in RustyMap (→ correlation is
over-dropping). Repeat on `$ROUTER` and one more host.

### A2 — #1 correlation under the trace (see replies get matched)
```sh
$RM --sS -p 22,80,443,8080 --trace-raw $SERVER 2>&1 | grep -E "raw-(tx|rx)"
```
**PASS if** for every `[raw-rx] …SynAck` on an open port you also get that port
reported `open` (i.e. the rx packet was matched, not dropped). A SynAck in the
trace with the port ending up `filtered` = **FAIL**.

### A3 — #1 stealth scans still classify correctly
```sh
$RM --sF -p 1-200 $SERVER ; sudo nmap -sF -p 1-200 $SERVER
$RM --sA -p 1-200 $SERVER ; sudo nmap -sA -p 1-200 $SERVER
```
**PASS if** open|filtered / unfiltered / closed states match nmap (the ack check
is SYN-only, so stealth scans must be unaffected).

### A4 — #2 global `--max-rate` is a true aggregate cap
```sh
time $RM --sS -p 1-100 --max-rate 50 $SERVER $ROUTER $WIN
```
300 probes total at 50 pps **globally** ≈ ~6 s. **PASS if** wall-time ≈
(total_ports / max-rate), NOT ~1/N of it. Optional hard proof:
```sh
sudo tcpdump -i $IFACE -w /tmp/rm.pcap "tcp[tcpflags] & tcp-syn != 0" &
$RM --sS -p 1-1000 --max-rate 100 $SERVER $ROUTER $WIN ; sudo pkill tcpdump
tcpdump -r /tmp/rm.pcap 2>/dev/null | wc -l   # ÷ wall-seconds ≈ 100, not 300
```

### A5 — #3 real per-port RTT
```sh
$RM --sS -p 22,80,443 -v $SERVER
ping -c3 $SERVER
```
**PASS if** the latency/RTT shown for open ports is non-zero and in the same
ballpark as `ping` (was hardcoded `0.00s` before). 

### A6 — #12 adaptive timeout: fast LAN + no new false-filtered
```sh
time $RM --sS -p 1-1000 $ROUTER        # filtered-heavy host must finish fast
```
**PASS if** it finishes in seconds (filtered ports don't burn the full
`--timeout`) AND A1 already showed no new `filtered` vs nmap. Optional jitter
test (affects the whole NIC — revert after!):
```sh
sudo tc qdisc add dev $IFACE root netem delay 40ms 30ms
$RM --sS -p 1-200 $SERVER ; sudo nmap -sS -p 1-200 $SERVER   # states must match
sudo tc qdisc del dev $IFACE root netem
```

### A7 — #13 IPv6 is explicit, `--sT` works
```sh
$RM --sS -p 80 $V6        # expect the warning, host reported down
$RMU --sT -p 80 $V6       # connect scan must work on IPv6
```
**PASS if** `--sS` prints `[!] raw TCP scans … do not support IPv6 … Use --sT`
and `--sT` scans the v6 host normally.

---

## TIER 2 — Minori (v0.107.0)

### B1 — #15 fancy-regex fallback (recovered service probes)
```sh
# how many service-probe lines use backrefs/lookaround (regex-crate rejects them):
grep -cE '\\[1-9]|\(\?[=!<]' /usr/share/nmap/nmap-service-probes
$RM --sV -p 1-1000 $SERVER ; sudo nmap -sV -p 1-1000 $SERVER
```
**PASS if** `-sV` product/version strings match nmap with **no regression**, and
(bonus) a service whose nmap match line uses a backref now resolves where it
previously showed name-only.

### B2 — #16 KEV / exploit tagging on CVE output
```sh
$RMU --update-exploit-refs                       # sync CISA KEV + ExploitDB + Nuclei (needs internet)
$RMU --inspect-exploit-cache CVE-2021-44228      # sanity: KEV-flagged > 0, Log4Shell shows "kev": true
$RM --sV $DVWA                                   # or any host with an old/known-vuln service
```
**PASS if** inspect reports a non-zero `KEV-flagged` count and the Log4Shell
anchor shows `"kev": true`; and any correlated CVE that is a KEV entry prints
`⚠ KNOWN-EXPLOITED` with an `exploits:` summary line. Without the sync, the scan
still runs with no marker (no crash).

### B3 — #9 `--spoof-mac` restores the original MAC on exit
```sh
ip link show $IFACE | grep ether                 # note the ORIGINAL MAC
$RM --sS -p 80 -e $IFACE --spoof-mac random $SERVER
#   → "[spoof-mac] $IFACE now uses …"  then on exit  "[spoof-mac] restored $IFACE to <original>"
ip link show $IFACE | grep ether                 # must equal the ORIGINAL
```
**PASS if** the MAC is back to the original after the scan exits. (Ctrl-C /
SIGKILL mid-scan is the documented best-effort gap — don't count that as FAIL.)

### B4 — #8 default DB path
```sh
cd /tmp/emptydir && $RMU --sL -n 192.0.2.0/30    # no ./rustymap.db here
ls ~/.local/share/rustymap/rustymap.db           # should now exist
touch ./rustymap.db && $RMU --sL -n 192.0.2.0/30 # with a cwd db present it keeps using ./rustymap.db
$RMU --db /tmp/explicit.db --sL -n 192.0.2.0/30 && ls /tmp/explicit.db
```
**PASS if**: per-user dir created when no cwd db; `./rustymap.db` honored when present; `--db` override honored.

### B5 — #10 parking_lot smoke (no deadlock/regression)
```sh
time $RM --sS -p- $SERVER         # full 65535-port scan must complete normally
```
**PASS if** it completes with sane results (the lock change must not deadlock or
change output).

---

## TIER 3 — Build & test suite (v0.107.1)

### C1 — tests pass on Linux
```sh
cargo test 2>&1 | tail -5
```
**PASS if** 0 failures. Expect ~708 unit (Linux may be +1 vs Windows) + 4
integration (`tests/cli.rs`). Confirm `parsers_never_panic_on_random_input`,
`compiled_re_falls_back_to_fancy_for_backrefs`, and the 4 `cli` tests are green.

### C2 — release build clean
```sh
cargo build --release 2>&1 | tail -3
```
**PASS if** it finishes with no errors (note the warning count).

---

## TIER 4 — Carried-over Alpha validations (still pending)

These shipped earlier and stay **Alpha** until validated here.

| ID | Ver | What | Command sketch | PASS if |
|----|-----|------|----------------|---------|
| D1 | v0.102.0 | 1.A UDP vs nmap | `$RM --sU -p 53,123,161 $SERVER` vs `nmap -sU` | state/service parity |
| D2 | v0.103.0 | owasp LFI + blind-SQLi | `$RMU --owasp-scan --owasp-checks lfi,sqli <DVWA url>` | LFI signatures + blind-SQLi timing hits on DVWA |
| D3 | v0.104.0 | ipa Mach-O parse | `$RMU --apk-scan <app.ipa>` (real signed .ipa) | arch/PIE/encrypted/code-sig/provision parsed correctly |
| D4 | v0.105.0 | os-fp-v6 | `$RM -O -6 $V6` vs `nmap -O -6 $V6` | v6 OS class matches family |
| D5 | v0.106.0 | rdp CredSSP pubKeyAuth | `$RM --brute-protocol rdp --brute-confirm-authorized $WIN` + `RUSTYMAP_RDP_DEBUG=1` | HIT on valid creds, reject on wrong (vs hydra) |

---

## Results log (fill + paste back)

```
Tier 1 (engine):  A1 [ ]  A2 [ ]  A3 [ ]  A4 [ ]  A5 [ ]  A6 [ ]  A7 [ ]
Tier 2 (minori):  B1 [ ]  B2 [ ]  B3 [ ]  B4 [ ]  B5 [ ]
Tier 3 (build):   C1 [ ]  C2 [ ]
Tier 4 (carried): D1 [ ]  D2 [ ]  D3 [ ]  D4 [ ]  D5 [ ]

Notes / failures (ID → what happened, paste output):
```
