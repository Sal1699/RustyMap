# RustyMap — Kali Test Roadmap (v0.100.1)

Consolidated, runnable test plan for the Kali lab: **everything still to confirm
on real hardware** at the current head. Ordered by priority — P0 is the freshly
shipped code, P1 are the maturity promotions that get us toward v1.0 with the
hosts you already have, P2/P3 need a specific target, P4 is perf/regression.

Companion docs: `KALI_MATURITY_CHECKLIST.md` (tier-promotion detail),
`COMMAND_COVERAGE.md` (status matrix), `HYDRA_PARITY.md` (brute cross-check),
`LAB_VALIDATION.md` (the dated run log).

**Flag syntax reminder:** scan/detection/output flags are DOUBLE-dash
(`--sS --sV --sL --sn --Pn --sO --oN --oX --oH --oJL`…). Real short flags only:
`-A -O -F -p -v -D -f -S -e -n -t -d -b -r -R`.

## Prep

```sh
cd ~
git clone https://github.com/Sal1699/RustyMap.git 2>/dev/null || true
cd RustyMap
git fetch origin --tags
git checkout v0.100.1          # or: git pull origin main
cargo build --release
RM=./target/release/rustymap
$RM --version                  # must print: rustymap 0.100.1
cargo test 2>&1 | tail -1      # must print: 658 passed; 0 failed

# Lab targets (adjust to your /24)
ROUTER=192.168.1.1     # TIM gateway — OpenWrt-ish, TLS 1.2, rate-limits full-port
SERVER=192.168.1.31    # SSH+DNS+HTTPS+rsync+8080
WIN=192.168.1.64       # Win11 (SMB)
NET=192.168.1.0/24
```

Reference tools: `nmap 7.9x`, `sslscan`, `testssl.sh`, `hydra`,
`crackmapexec`, `ssh-audit`, `dig`/`dnsrecon`, `tcpdump`. Raw scans
(`--sS/--sU/-O`/stealth/`--fast-engine`) need `sudo`.

**How to record:** write `VALIDATION_0.100.1.md`, add a dated row to
`LAB_VALIDATION.md`, flip the matching `COMMAND_COVERAGE.md` cells. Any bug →
triage in the report, fix in a `0.100.x` patch, re-run.

---

## P0 — Fresh code in v0.100.1 (must-pass)

| # | Command | Expect | How to verify |
|---|---------|--------|---------------|
| 0.1 | `sudo $RM --fast-engine -p- $ROUTER` | the fast engine **does not flood/stall** against a rate-limiting host; completes in minutes | `sudo tcpdump -ni <if> 'icmp[icmptype]==3'` in another shell — you should see type-3 packets AND the scan slow down (cwnd back-off), not keep hammering |
| 0.2 | compare 0.1 cwnd behaviour with `--trace-raw` if available | back-off visible when ICMP type-3 arrives | eyeball the wave cadence |
| 0.3 | `sudo $RM -p- $NET --oH report.html` | `report.html` is **small** (was ~4.1 MB for 20 hosts at v0.100.0), one row per *open/open-filtered/unfiltered* port only | `ls -lh report.html` |
| 0.4 | open `report.html` in a browser | filter bar (host/service search + "only open"), risk filter (all/warn+/high), high/warn summary all work; each host shows **"+N closed/filtered port(s) scanned, not shown"** | eyeball + click |
| 0.5 | `$RM --oH report.html $SERVER -sV` then diff summary counts vs `--oN` | open-port **counts unchanged** by the trim; summary still correct | compare |

> ICMP back-off is fail-safe: if the ICMP socket can't open you simply get no
> back-off signal and behaviour is identical to v0.100.0. It only runs on
> `--fast-engine` (opt-in). On a host that does **not** rate-limit you won't see
> type-3 — that's expected, test 0.1 against the gateway that choked at v0.95.0.

---

## P1 — Maturity promotions you can do with the current lab (→ v1.0)

Goal: move features from Beta/Alpha → Production. Rule stays: **one observed
agreement with the reference tool on a real target = promote; one divergence =
stay/demote.** Propose the tier change, don't silently flip it.

### Beta → Production (highest value, targets on hand)

| Feature | Command | Promote when | Compare |
|---------|---------|--------------|---------|
| **`-O`** (1–2 more hosts) | `sudo $RM -O --nmap-os-db /usr/share/nmap/nmap-os-db $SERVER` and one more **different** box | family+CPE match nmap's `-O` on ≥2 heterogeneous hosts (OpenWrt router already PASS 2026-10-22) | `nmap -O` |
| **`--smb-audit`** | `$RM --smb-audit $WIN` (SMB actually reachable, not firewalled) | real dialect+signing verdict matches, not just the reject-path | `crackmapexec smb $WIN`, `nmap --script smb2-security-mode` |
| **`--brute-protocol ssh`** | `$RM --brute-protocol ssh --brute-user admin --brute-pass-list rockyou-top.txt $SERVER` | finds the same cred as hydra (or both none), rate-limit honoured, no hang | `hydra -l admin -P … ssh://$SERVER` |
| **`--brute-protocol ftp`** | same shape vs an FTP server | matches hydra | `hydra … ftp://` |
| **`--brute-protocol mysql`** | vs a MySQL instance | matches hydra | `hydra … mysql://` |
| **`--brute-protocol postgres`** | vs Postgres (MD5 auth, not SCRAM) | matches hydra | `hydra … postgres://` |
| **`--brute-protocol smb`** | vs Samba/Win | matches | `crackmapexec` |
| **`--brute-protocol ldap`** | vs an LDAP simple-bind | matches | `hydra … ldap://` |
| **`--brute-protocol vnc`** | vs an RFB 3.x server | matches | `hydra … vnc://` |

→ Full brute matrix in `HYDRA_PARITY.md`; flip each adapter cell as it passes.

### Already-Production re-confirmations (quick, keeps the tier honest)

| Command | Expect | Compare |
|---------|--------|---------|
| `$RM --sV $SERVER -p 22,53,443,445` | SSH/DNS/TLS/SMB products match nmap | `nmap -sV` |
| `$RM --ssh-audit $SERVER` | KEX/cipher/MAC list matches | `ssh-audit $SERVER` |
| `$RM --tls-grade $ROUTER -p 443,8443` | A+/F grade + PoC lines near sslscan | `sslscan`, `testssl.sh` |
| `$RM --cve-for "OpenSSH 9.6p1"` | 25 CVEs incl. CVE-2024-6387 | NVD |

---

## P2 — Alpha features that need a specific target

Promote when the matching target exists; otherwise just confirm clean
"no target / graceful" handling. All Alpha ⇒ still behind `--experimental-confirm`.

| Feature | Needs | Command | Expect |
|---------|-------|---------|--------|
| `--brute-protocol rdp` | real Windows RDP | `$RM --brute-protocol rdp --experimental-confirm …` | negative NTSTATUS reliable; positives only *suggestive* — validate manually |
| `--brute-protocol mssql` | real SQL Server | `$RM --brute-protocol mssql --experimental-confirm …` | TDS 7.4 auth works vs a real instance |
| `--mobile-discover` (positive) | an Android (ADB 5555) or iOS (62078) device | `$RM --mobile-discover $PHONE` | correct classify + exit 1 (lab only ever hit the fallback) |
| `--apk-scan` | a real/obfuscated `.apk` | `$RM --apk-scan app.apk` | perms/exported/cleartext/pinning/secrets/trackers; check secret FP rate |
| `--ipa-scan` | a real `.ipa` | `$RM --ipa-scan app.ipa` | Info.plist findings |
| `--ics-scan` | a real PLC (or Conpot) | `$RM --ics-scan $PLC` | Modbus/S7/DNP3/EnIP/BACnet probe — read-only |
| `--os-fp-v6` | IPv6 hosts | `sudo $RM --os-fp-v6 $V6HOST` | IPv6 OS guess; DB coverage thinner than v4 |
| `--sI` idle | zombie w/ incremental IPID | `sudo $RM --sI $ZOMBIE:80 $SERVER` | results, no packets from your IP (modern OSes randomize IPID → may not work) |
| `--threat-intel-sync` | a MISP instance | `$RM --threat-intel-sync <url> --threat-intel-match $NET` | IoC match on targets |
| `--owasp-scan` | DVWA / Juice Shop | `$RM --owasp-scan http://$WEBAPP/ --experimental-confirm` | XSS/SQLi/redirect/SSRF — expect high FP, compare ZAP/sqlmap |
| `--web-crawl` | a real web app | `$RM --web-crawl $WEBAPP --crawl-depth 2` | BFS + robots.txt + cookies (slow; no JS apps) |

---

## P3 — Newer features not yet lab-exercised

| # | Command | Expect | Note |
|---|---------|--------|------|
| 3.1 | `$RM --port-script ./probe.sh $SERVER -sV` | runs `probe.sh` once per **open** port (IP+port as args), stdout → a finding; opt-in, per-port timeout honoured, audited | v0.98.0 — never run on Kali. Write a 2-line `probe.sh` (e.g. `echo "$1:$2 hello"`) |
| 3.2 | `$RM --nmap-service-probes /usr/share/nmap/nmap-service-probes -sV $SERVER` | DB-probe **replay** names products the built-ins miss | v0.100.0 PASS once (Dropbear/dnsmasq/…); re-confirm on more services |
| 3.3 | **script FP sweep** — `$RM $NET -sV --script-all` (or your usual script run) across diverse hosts | **no false positives** from the 607 Rhai scripts | v0.99.0 expanded 307→607; 2 FPs fixed in v0.99.1 — re-sweep like the v0.87→v0.87.1 pass to catch residual FPs on host types not yet seen |
| 3.4 | `$RM --oJL out.jsonl $NET -sV` | one valid JSON object per host per line | v0.96.0 — smoke only |

---

## P4 — Performance & regression gates

| # | Command | Expect | Note |
|---|---------|--------|------|
| 4.1 | re-bench `/24` raw sweep at v0.100.1 vs the v0.100.0 number | ≈ same ~7× nmap speed (host-parallel win intact) | v0.100.0 hit **655s→7.2s (~90×)** on 2026-10-23; make sure v0.100.1's ICMP thread didn't regress it |
| 4.2 | run the `PERFORMANCE.md` regression gate (`benches/lab_compare.rs` harness) | raw not >10% slower than nmap on SYN /24, full-TCP host, `-sV` ~50 hosts, `-O` ~10 hosts | the formal release gate from v0.95.0 |
| 4.3 | *(optional)* `sudo $RM --fast-engine -p- $SERVER` where $SERVER has 1 open + rest filtered, **no** `--host-timeout` | finishes in ≲1 min (was ~50 min pre-v0.95.2) | fast is opt-in, so low priority — but this was the last cwnd foot-gun |

---

## Out of scope on purpose (don't chase these to Production)

- **`--osdb-submit`** — stays Alpha: it leaks fingerprints to an external
  endpoint; promoting it would imply "safe to enable broadly", which it isn't.
- **`--sI`** / **`--owasp-scan`** / **`--web-crawl`** — honest Alpha: modern
  IPID randomization and dedicated tools (ZAP/sqlmap) mean these keep known
  limits even when they "work". Validate for *correctness*, leave the tier note.
- **`--update` / `--check-update`** — tied to GitHub **Releases**, and release
  CI is billing-blocked (last published Release = v0.68.0). On a git-built
  binary `--update` will say "up to date (v0.68.0)". Only `--check-update`
  (read-only) is worth a sanity run; real self-update needs published assets.

---

## Done criteria

- `VALIDATION_0.100.1.md` written: P0 all pass, plus whatever P1–P4 you reach.
- `LAB_VALIDATION.md` dated row added; `COMMAND_COVERAGE.md` cells flipped.
- Each tier promotion recorded in `maturity.rs` **only** after one real-target
  agreement (propose first). `-O` → Production once a 2nd heterogeneous host
  confirms the os-db match.
- Any bug → `0.100.x` patch, re-run the failing row.
