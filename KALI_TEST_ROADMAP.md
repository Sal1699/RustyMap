# RustyMap — Kali Test Roadmap (v0.100.16)

Everything still to validate on the Kali lab, in execution order, from the
v0.100.16 head. The network brute set is **done** (7/7 Production); what remains
is the fast-engine **ICMP back-off active path** (Phase A) and the **11 Alpha
features** (Phase B).

Companion: `KALI_ALPHA_SWEEP.md` (fuller per-Alpha notes), `HYDRA_PARITY.md`
(brute matrix), `LAB_VALIDATION.md` (dated run log).

## Prep

```sh
cd ~/RustyMap && git fetch origin --tags && git pull origin main   # main == v0.100.16 head
cargo build --release
RM=./target/release/rustymap
$RM --version                    # rustymap 0.100.16
cargo test 2>&1 | tail -1        # 675 passed; 0 failed

# adjust to your /24
ROUTER=192.168.1.1 ; SERVER=192.168.1.31 ; WIN=192.168.1.64 ; NET=192.168.1.0/24
```

Reference tools: `nmap`, `hydra`, `crackmapexec`, `sslscan`, `tcpdump`, `docker`,
`zaproxy`/`sqlmap`, `mobsf` (optional). Raw scans / `--fast-engine` / `-O` /
`--sI` / `--os-fp-v6` need `sudo`. **All Alpha features need `--experimental-confirm`.**

**How to record:** paste each run's output back to me; I harden + propose the tier
flip per feature. Keep a dated row in `LAB_VALIDATION.md`.

---

## Already validated — do NOT re-test

- **Brute 7/7 Production:** ftp / ssh / smb / mysql / postgres / ldap / vnc
  (vs hydra + crackmapexec on Metasploitable 2 / openldap / modern OpenSSH).
- **Detection Production:** `-O`, `--sV`, `--tls-grade`, `--cve-for`,
  `--ssh-audit`, `--smb-audit` (all lab-confirmed vs nmap/sslscan/NVD/CME).
- **Fast engine:** host-parallel /24 (~90× at v0.100.0), silence-shrink,
  HTML `--oH` trim, and the ICMP back-off **fail-safe** (0 type-3 → no-op).
- These are closed. The only engine item left is the ICMP back-off *active* path:

---

## Phase A — ICMP rate-limit back-off (active path)

The fast engine halves its congestion window when a target sends ICMP type-3
(destination-unreachable). v0.100.15 made it observable; it's never been
*triggered* in the lab (your /24 drops silently, never REJECTs). Make a target
REJECT, then watch the back-off fire.

```sh
# A1 — on a target host/VM (or your Kali's own IP), make a port range REJECT:
sudo iptables -A INPUT -p tcp --dport 7000:7100 -j REJECT --reject-with icmp-port-unreachable
# scan it with the fast engine + trace from another shell / host:
sudo $RM --fast-engine --sS -p 7000-7100 <target-ip> --trace-raw 2>&1 | grep raw-icmp
# cleanup:
sudo iptables -D INPUT -p tcp --dport 7000:7100 -j REJECT --reject-with icmp-port-unreachable
```
**Pass:** you see `[raw-icmp] N ICMP dest-unreachable (type 3) during wave → cwnd
back-off to W` lines (closes NEEDS-KALI #4). Zero lines = target DROPs not REJECTs,
or not root. Paste the `[raw-icmp]` lines.

---

## Phase B — Alpha features (11), ordered by how likely they promote

Legend: 🟢 Production candidate · 🟡 harden-then-maybe · 🔴 Alpha by design
(validate it runs; won't promote without new code / inherently limited).
Full per-feature notes in `KALI_ALPHA_SWEEP.md`.

### B1 🟢 `--brute-protocol mssql` — SQL Server
```sh
docker run -e 'ACCEPT_EULA=Y' -e 'MSSQL_SA_PASSWORD=Str0ng!Pass' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2022
$RM --brute-protocol mssql --brute-target 127.0.0.1:1433 --brute-pair 'sa:Str0ng!Pass' --experimental-confirm --brute-confirm-authorized
hydra -l sa -p 'Str0ng!Pass' mssql://127.0.0.1
```
**Pass → promote:** HIT = hydra. If it MISSES the correct cred → confirms the
cleartext-LOGIN7-vs-TLS gap; tell me and I implement TDS-over-TLS login.

### B2 🟡 `--ics-scan` — Modbus/S7/DNP3/EnIP/BACnet
```sh
docker run --rm -p 502:502 -p 102:102 -p 161:161/udp -p 47808:47808/udp honeynet/conpot
$RM --ics-scan 127.0.0.1 --experimental-confirm
nmap --script modbus-discover,s7-info -p 502,102 127.0.0.1
```
**Pass → promote:** fingerprints agree with nmap on a fresh Conpot.

### B3 🟡 `--os-fp-v6` — IPv6 OS fingerprint
```sh
ip -6 neigh                      # pick a reachable IPv6 host
sudo $RM --os-fp-v6-multi <ipv6-host> --os-fp-v6-ports 22,80,443 --experimental-confirm
nmap -6 -O <ipv6-host>
```
**Pass → promote:** OS family matches nmap on 1–2 hosts.

### B4 🟡 `--apk-scan` — Android APK static analysis
```sh
# grab a known-vulnerable APK (DIVA / InsecureBankv2)
$RM --apk-scan /path/diva.apk --experimental-confirm
```
**Report:** the findings (perms/exported/cleartext/secrets/trackers) vs the app's
known issues (or mobsf). I tune the secret-FP patterns; promote if low FP + matches.

### B5 🟡 `--ipa-scan` — iOS IPA static analysis
```sh
$RM --ipa-scan /path/app.ipa --experimental-confirm
```
**Gap:** only Info.plist parsed. Report output; I add mach-O/entitlements parsing.
Stays Alpha until that lands.

### B6 🟡 `--brute-protocol rdp` — RDP (needs a Windows RDP host)
```sh
$RM --brute-protocol rdp --brute-target $WIN:3389 --brute-pair 'Administrator:wrongpass' --experimental-confirm --brute-confirm-authorized
$RM --brute-protocol rdp --brute-target $WIN:3389 --brute-pair 'Administrator:<known-good>' --experimental-confirm --brute-confirm-authorized
hydra -l Administrator -p wrongpass rdp://$WIN
```
**Gap:** CredSSP pubKeyAuth not implemented → positives *suggestive*, negatives
reliable. Report both; I harden the NTSTATUS mapping. Likely stays Alpha.

### B7 🔴 `--owasp-scan` — web vuln probes (FP-heavy by design)
```sh
$RM --owasp-scan 'http://<dvwa>/' --web-crawl-cookie 'PHPSESSID=...; security=low' --experimental-confirm
```
Target: DVWA (Metasploitable 2) or pentest-ground.com. Reference: `zap-baseline.py`.
**Goal:** measure/reduce FP vs ZAP — not Production. Report the FP count.

### B8 🔴 `--web-crawl` — BFS crawler
```sh
$RM --web-crawl 'http://<target>/' --web-crawl-cookie 'PHPSESSID=...' --experimental-confirm
```
**Report:** does it stay in-scope + hold the session cookie? I fix cookie/CSRF.
Stays Alpha (no JS, slower than ZAP).

### B9 🔴 `--sI` — idle/zombie scan
```sh
nmap --script ipidseq $NET        # find a predictable-IPID zombie (old printer/IoT)
sudo $RM --sI <zombie>:80 -p 1-1000 $SERVER --experimental-confirm
nmap -sI <zombie> $SERVER
```
v0.100.16 fixed the gate (now actually requires `--experimental-confirm`). Likely
stays Alpha — predictable-IPID zombies are rare. Validate IF you find one.

### B10 🔴 `--threat-intel-misp` — MISP IoC pull + match (needs MISP)
```sh
# lab MISP (e.g. coolacid/misp-docker) + API key
$RM --threat-intel-misp https://<misp>/ --misp-api-key <KEY> --threat-intel-match --experimental-confirm <scan args>
```
**Report:** pulls IoCs + flags matches as findings. Needs infra; pull-only.

### B11 🔴 `--osdb-submit` — OS-fp submission pack (local, no target)
```sh
$RM --osdb-submit $SERVER:MyLabel --osdb-submit-out /tmp/pack.txt --experimental-confirm
```
Writes a pack to stdout / `-out` (does NOT auto-submit). Verify it describes the
fingerprint correctly. Stays Alpha by design (privacy-sensitive output).

---

## Results tracking

| Item | Ran? | RustyMap | Reference | Verdict |
|------|------|----------|-----------|---------|
| A1 ICMP back-off | ☐ | | tcpdump type-3 | |
| B1 mssql | ☐ | | hydra | |
| B2 ics | ☐ | | nmap scripts | |
| B3 os-fp-v6 | ☐ | | nmap -6 -O | |
| B4 apk | ☐ | | mobsf / known | |
| B5 ipa | ☐ | | — | |
| B6 rdp | ☐ | | hydra | |
| B7 owasp-scan | ☐ | | ZAP | |
| B8 web-crawl | ☐ | | — | |
| B9 sI | ☐ | | nmap -sI | |
| B10 threat-intel-misp | ☐ | | — | |
| B11 osdb-submit | ☐ | | — | |

## Done criteria

- Phase A: `[raw-icmp]` back-off observed against a REJECT target → NEEDS-KALI #4 closed.
- Phase B: each feature run once; paste output. I harden + propose the tier flip
  per feature (one real-target agreement with the reference = promote; divergence
  = fix or stay Alpha). Realistic promotions: mssql / ics / os-fp-v6 / maybe apk.
- Any bug → a `0.100.x` patch, re-run that row.
